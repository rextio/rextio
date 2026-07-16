"""Generation of the Python wrapper module that dispatches to native or fallback."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from rextio.analyzer.executable_identity import (
    class_construction_stability_reason,
    executable_ast_fingerprint,
    native_marker_identity_reason,
)
from rextio.analyzer.final_bindings import (
    BindingKind,
    ModuleBindings,
    build_module_bindings,
    definition_is_final,
)
from rextio.analyzer.models import FunctionAnalysis, ModuleAnalysis, TopLevelAnalysis
from rextio.codegen.native_names import native_function_name
from rextio.fallback.fallback_marker import GENERATED_PYTHON_HEADER
from rextio.fallback.module_copy import (
    fallback_module_name,
    native_top_level_fallback_module_name,
)
from rextio.runtime.boundary_fallback import DEFAULT_BOUNDARY_FALLBACK_THRESHOLD


_BUILTIN_CAPTURE_NAMES = (
    "AttributeError",
    "KeyError",
    "RuntimeError",
    "TypeError",
    "enumerate",
    "getattr",
    "globals",
    "hasattr",
    "isinstance",
    "list",
    "object",
    "set",
    "setattr",
    "type",
    "vars",
)


def render_wrapper_module(
    module: ModuleAnalysis,
    boundary_fallback_threshold: int = DEFAULT_BOUNDARY_FALLBACK_THRESHOLD,
) -> str:
    """Render the Python wrapper module source that dispatches to native or fallback."""
    accepted = sorted(
        [
            function
            for function in module.functions
            if function.is_native_candidate and function.accepted
        ],
        key=lambda function: function.qualname,
    )
    top_level = (
        module.top_level
        if module.top_level is not None
        and module.top_level.is_native_candidate
        and module.top_level.accepted
        else None
    )
    if not accepted and top_level is None:
        raise ValueError(f"module has no accepted native functions: {module.module_name}")
    # Resident-signature functions (opaque native-only values, plugin API 1.3)
    # have no Python boundary conversion, so they are NOT exported by the native
    # extension and must not get a native-dispatch wrapper — Python callers use
    # the plain fallback (the native form is reachable only native-to-native).
    dispatchable = [function for function in accepted if not function.has_resident_signature]
    dispatch_slots = {
        _function_node_key(function): f"_rextio_dispatch_slot_{index}"
        for index, function in enumerate(dispatchable)
    }
    factory_slots = {
        _function_node_key(function): f"_rextio_factory_slot_{index}"
        for index, function in enumerate(dispatchable)
    }
    fallback_slots = {
        _function_node_key(function): f"_rextio_fallback_slot_{index}"
        for index, function in enumerate(dispatchable)
    }
    native_slots = {
        _function_node_key(function): f"_rextio_native_slot_{index}"
        for index, function in enumerate(dispatchable)
    }

    source_tree = ast.parse(
        Path(module.file_path).read_text(encoding="utf-8"), filename=module.file_path
    )
    current_bindings = build_module_bindings(
        source_tree,
        module.module_name,
        project_mutations=module.project_mutations,
        trusted_annotation_targets=(
            module.module_bindings.trusted_annotation_targets
            if module.module_bindings is not None
            else ()
        ),
    )
    function_nodes = _function_nodes_from_tree(source_tree)
    dispatch_origins: dict[str, _FunctionNodeOrigin] = {}
    for function in dispatchable:
        key = _function_node_key(function)
        origin = function_nodes.get(key)
        if origin is None:
            raise ValueError(f"accepted native function was not found: {function.qualname}")
        _require_exact_wrapper_origin(module, function, origin, current_bindings)
        dispatch_origins[key] = origin
    fallback_name = fallback_module_name(module)
    import_prefix = (
        "." if "." in module.module_name or Path(module.file_path).name == "__init__.py" else ""
    )
    lines = [
        GENERATED_PYTHON_HEADER,
        "",
        # PEP 563: wrapper defs reproduce the user's annotations verbatim, but
        # names from the fallback namespace are not published until the wrapper
        # is fully constructed, and explicit __all__ may exclude annotation
        # dependencies. Eager evaluation would break the module with NameError
        # at import (council round 7); lazy (string) annotations never evaluate.
        "from __future__ import annotations",
        "",
        # Runtime helpers are aliased under _rextio_-prefixed names so a user
        # module that happens to export a public name like `native_disabled`
        # cannot clobber the dispatch helpers during terminal export publication
        # (council round 8).
        "from rextio.runtime.boundary_fallback import boundary_fallback_required as _rextio_boundary_fallback_required",
        "from rextio.runtime.flags import native_disabled as _rextio_native_disabled",
        "from rextio.runtime.flags import native_required as _rextio_native_required",
        "from rextio.runtime.native_loader import load_native_function as _rextio_load_native_function",
        "from rextio.runtime.original_registry import register_runtime_originals as _rextio_register_runtime_originals",
        "import types as _rextio_types",
        "",
    ]
    lines.extend(_render_builtin_captures())
    lines.append("")
    if top_level is not None:
        lines.append("import importlib as _rextio_importlib")
        lines.append("")
        lines.extend(_render_native_top_level_binding(top_level))
        lines.append("")
        lines.extend(
            _render_dynamic_fallback_selection(
                module,
                fallback_name,
                native_top_level_fallback_module_name(module),
                top_level,
                current_bindings,
            )
        )
    else:
        lines.extend(_fallback_module_import_lines(import_prefix, fallback_name))
        lines.append("_rextio_native_top_level_updates = {}")
    lines.append("")
    # Faithfully mirror the source module's public surface: its docstring, any
    # module-level names referenced by parameter defaults, and its __all__.
    lines.extend(_render_namespace_fidelity())
    lines.append("")
    # All generated dispatch objects live in one local bootstrap frame.  User
    # source is allowed to define/export *any* ``_rextio_*`` spelling, including
    # the old predictable factory and method-wrapper names.  Keeping factories,
    # native/fallback bindings, and method wrappers local makes those names
    # incapable of colliding with module globals.  The bootstrap publishes the
    # fallback/native source namespace only after every closure and method
    # replacement has been constructed, then installs top-level dispatch
    # functions last.
    lines.extend(_render_dispatch_bootstrap_header())
    bootstrap: list[str] = []
    if any(_is_method(function) for function in dispatchable):
        bootstrap.extend(_render_method_identity_helpers())
        bootstrap.append("")
    for function in dispatchable:
        node = dispatch_origins[_function_node_key(function)].node
        key = _function_node_key(function)
        bootstrap.extend(
            _render_fallback_binding(
                function,
                node,
                import_prefix,
                fallback_name,
                top_level is not None,
                fallback_slots[key],
            )
        )
    runtime_originals = [function for function in dispatchable if function.native_runtime_semantics]
    if runtime_originals:
        bootstrap.extend(
            [
                "_rextio_register_runtime_originals(",
                f"    {module.module_name!r},",
                "    {",
                *(
                    f"        {ordinal}: {fallback_slots[_function_node_key(function)]},"
                    for ordinal, function in enumerate(runtime_originals)
                ),
                "    },",
                ")",
            ]
        )
    bootstrap.append("")

    for function in dispatchable:
        bootstrap.extend(
            _render_native_binding(
                function,
                native_slots[_function_node_key(function)],
            )
        )
        bootstrap.append("")

    for function in dispatchable:
        node = dispatch_origins[_function_node_key(function)].node
        key = _function_node_key(function)
        bootstrap.extend(
            _render_wrapper_function(
                function,
                node,
                boundary_fallback_threshold,
                dispatch_slots[key],
                factory_slots[key],
                native_slots[key],
                fallback_slots[key],
            )
        )
        bootstrap.extend(
            _render_defaults_copy(
                function,
                node,
                dispatch_slots[key],
                fallback_slots[key],
            )
        )
        bootstrap.append("")

    for function in dispatchable:
        node = dispatch_origins[_function_node_key(function)].node
        bootstrap.extend(
            _render_fallback_replacement(
                function,
                node,
                dispatch_slots[_function_node_key(function)],
            )
        )
    bootstrap.append("")

    # Install fallback exports LAST.  An explicit ``__all__`` is allowed to
    # publish underscore-prefixed names, including every predictable
    # ``_rextio_*`` helper spelling.  By this point method installation and
    # wrapper construction are complete, and dispatch functions retain their
    # runtime dependencies in closures, so the public update can faithfully
    # overwrite any internal global without affecting execution.
    bootstrap.extend(_render_public_export_install())
    for function in dispatchable:
        if not _is_method(function):
            bootstrap.append(
                f"_rextio_builtin_globals()[{function.name!r}] = "
                f"{dispatch_slots[_function_node_key(function)]}"
            )
    lines.extend(f"    {line}" if line else "" for line in bootstrap)
    lines.append("")
    lines.append("_rextio_initialize_dispatch()")
    lines.append("")

    return "\n".join(lines)


def _render_namespace_fidelity() -> list[str]:
    """Mirror the source module's __doc__ and __all__ onto the wrapper.

    The wrapper imports the fallback module as one private module reference and
    publishes its selected names only after dispatch construction.  Mirror the
    docstring and ``__all__`` explicitly from that runtime module.  A runtime
    ``hasattr`` guard (not an AST scan of top-level assignments) also handles an
    ``__all__`` defined by control flow or an import - council round 10.
    Parameter defaults are handled separately by copying
    ``__defaults__``/``__kwdefaults__`` from the fallback function, so they are
    never reproduced as expressions here.
    """
    return [
        "__doc__ = _rextio_fallback_module.__doc__",
        'if _rextio_builtin_hasattr(_rextio_fallback_module, "__all__"):',
        "    __all__ = _rextio_builtin_list(_rextio_fallback_module.__all__)",
        "    _rextio_export_names = _rextio_builtin_list(__all__)",
        "else:",
        "    _rextio_export_names = [",
        "        name for name in _rextio_fallback_module.__dict__",
        "        if not name.startswith('_')",
        "    ]",
    ]


def _render_public_export_install() -> list[str]:
    """Render the terminal, collision-safe fallback namespace publication."""
    return [
        # The elided native-top-level fallback still owns the ``__globals__``
        # dictionaries of captured Python functions.  Publish reconciled source
        # values there only now, after every function/class identity was
        # captured and every method wrapper installed.
        "_rextio_builtin_vars(_rextio_fallback_module).update(_rextio_native_top_level_updates)",
        "_rextio_public_exports = {",
        "    name: _rextio_builtin_getattr(_rextio_fallback_module, name)",
        "    for name in _rextio_export_names",
        "}",
        "_rextio_builtin_globals().update(_rextio_public_exports)",
        # Native top-level values include private/helper-like source names that
        # explicit ``__all__`` does not publish.  Apply the complete mapping only
        # after closures and method installation are complete; all subsequent
        # internal work uses bootstrap locals, not these mutable globals.
        "_rextio_builtin_globals().update(_rextio_native_top_level_updates)",
    ]


def _render_dispatch_bootstrap_header() -> list[str]:
    """Open the isolated local scope used to construct every dispatch object."""
    captures = (
        "_rextio_fallback_module",
        "_rextio_types",
        "_rextio_boundary_fallback_required",
        "_rextio_native_disabled",
        "_rextio_native_required",
        "_rextio_load_native_function",
        "_rextio_register_runtime_originals",
        "_rextio_export_names",
        "_rextio_native_top_level_updates",
        *(f"_rextio_builtin_{name}" for name in _BUILTIN_CAPTURE_NAMES),
    )
    return [
        "def _rextio_initialize_dispatch(",
        *(f"    {capture}={capture}," for capture in captures),
        "):",
    ]


def _render_builtin_captures() -> list[str]:
    """Capture wrapper runtime primitives before importing fallback code.

    Terminal fallback export publication may publish user names such as
    ``list`` and ``getattr``.  Importing the fallback module may also mutate the
    process ``builtins`` module while it executes.  Wrapper correctness must not
    depend on either mutable namespace after that point, so retain each exact
    helper object under a private name first.
    """
    return [
        "import builtins as _rextio_builtins",
        *(f"_rextio_builtin_{name} = _rextio_builtins.{name}" for name in _BUILTIN_CAPTURE_NAMES),
    ]


def _render_method_identity_helpers() -> list[str]:
    """Render fail-loud runtime guards for native method installation."""
    return [
        "def _rextio_require_fallback_method(owner_path, method_name, expected_qualname, expected_firstlineno):",
        "    owner = _rextio_fallback_module",
        "    try:",
        "        namespace = _rextio_builtin_vars(owner)",
        "        for index, part in _rextio_builtin_enumerate(owner_path):",
        "            owner = namespace[part]",
        "            expected_owner_qualname = '.'.join(owner_path[:index + 1])",
        "            if (",
        "                _rextio_builtin_type(owner) is not _rextio_builtin_type",
        "                or _rextio_builtin_type.__getattribute__(owner, '__module__') != _rextio_fallback_module.__name__",
        "                or _rextio_builtin_type.__getattribute__(owner, '__qualname__') != expected_owner_qualname",
        "                or _rextio_builtin_type.__getattribute__(owner, '__bases__') != (_rextio_builtin_object,)",
        "            ):",
        "                raise _rextio_builtin_RuntimeError(",
        "                    f'fallback method owner identity mismatch: {expected_qualname}'",
        "                )",
        "            namespace = _rextio_builtin_type.__getattribute__(owner, '__dict__')",
        "        candidate = namespace[method_name]",
        "    except (_rextio_builtin_AttributeError, _rextio_builtin_KeyError, _rextio_builtin_TypeError):",
        "        raise _rextio_builtin_RuntimeError(",
        '            f"fallback method is missing: {expected_qualname}"',
        "        ) from None",
        '    code = _rextio_builtin_getattr(candidate, "__code__", None)',
        "    if (",
        "        not _rextio_builtin_isinstance(candidate, _rextio_types.FunctionType)",
        "        or candidate.__name__ != method_name",
        "        or candidate.__qualname__ != expected_qualname",
        "        or candidate.__module__ != _rextio_fallback_module.__name__",
        "        or _rextio_builtin_getattr(candidate, '__rextio_native__', None) is not True",
        "        or code is None",
        "        or code.co_firstlineno != expected_firstlineno",
        "    ):",
        "        raise _rextio_builtin_RuntimeError(",
        '            f"fallback method identity mismatch: {expected_qualname}"',
        "        )",
        "    return owner, candidate",
        "",
        "def _rextio_install_fallback_method(owner_path, method_name, expected_qualname, expected_firstlineno, replacement):",
        "    owner, _candidate = _rextio_require_fallback_method(",
        "        owner_path, method_name, expected_qualname, expected_firstlineno",
        "    )",
        "    _rextio_builtin_type.__setattr__(owner, method_name, replacement)",
    ]


def _fallback_module_import_lines(import_prefix: str, fallback_name: str) -> list[str]:
    if import_prefix == ".":
        return [f"from . import {fallback_name} as _rextio_fallback_module"]
    return [f"import {fallback_name} as _rextio_fallback_module"]


def _render_native_binding(
    function: FunctionAnalysis,
    binding: str | None = None,
) -> list[str]:
    binding = binding or _native_binding_name(function)
    return [
        f"{binding} = _rextio_load_native_function(",
        '    module_name="_rextio_native",',
        f'    function_name="{native_function_name(function.qualname)}",',
        ")",
    ]


def _render_native_top_level_binding(top_level: TopLevelAnalysis) -> list[str]:
    return [
        "_native___rextio_top_level__ = _rextio_load_native_function(",
        '    module_name="_rextio_native",',
        f'    function_name="{native_function_name(top_level.qualname)}",',
        ")",
    ]


def _render_dynamic_fallback_selection(
    module: ModuleAnalysis,
    fallback_name: str,
    native_fallback_name: str,
    top_level: TopLevelAnalysis,
    final_bindings: ModuleBindings,
) -> list[str]:
    terminal_value_names = tuple(
        sorted(
            name
            for name in top_level.assigned_types
            if (binding := final_bindings.entries.get(name)) is not None
            and binding.kind in {BindingKind.VALUE, BindingKind.AMBIGUOUS}
            and (
                final_bindings.wildcard_star_order is None
                or binding.order > final_bindings.wildcard_star_order
            )
        )
    )
    return [
        f'_REXTIO_FALLBACK_MODULE_NAME = "{fallback_name}"',
        f'_REXTIO_NATIVE_TOP_LEVEL_FALLBACK_MODULE_NAME = "{native_fallback_name}"',
        f"_REXTIO_NATIVE_TOP_LEVEL_FINAL_NAMES = {terminal_value_names!r}",
        "",
        "def _rextio_import_fallback_module(name):",
        "    if __package__:",
        '        return _rextio_importlib.import_module(f".{name}", __package__)',
        "    return _rextio_importlib.import_module(name)",
        "",
        "def _rextio_select_fallback_module():",
        "    if _rextio_native_disabled():",
        "        return _rextio_import_fallback_module(_REXTIO_FALLBACK_MODULE_NAME), {}",
        "    if _native___rextio_top_level__ is None:",
        "        if _rextio_native_required():",
        "            raise _rextio_builtin_RuntimeError(",
        f'                "native mode requires generated native top-level initializer: {top_level.qualname}"',
        "            )",
        "        return _rextio_import_fallback_module(_REXTIO_FALLBACK_MODULE_NAME), {}",
        "    module = _rextio_import_fallback_module(_REXTIO_NATIVE_TOP_LEVEL_FALLBACK_MODULE_NAME)",
        "    updates = _native___rextio_top_level__()",
        "    updates = {name: updates[name] for name in _REXTIO_NATIVE_TOP_LEVEL_FINAL_NAMES}",
        "    return module, updates",
        "",
        "_rextio_fallback_module, _rextio_native_top_level_updates = _rextio_select_fallback_module()",
    ]


def _render_wrapper_function(
    function: FunctionAnalysis,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    boundary_fallback_threshold: int,
    wrapper_binding: str,
    factory_binding: str,
    native_binding: str,
    fallback_binding: str,
) -> list[str]:
    signature = _signature(node)
    call_args = _call_args(node)
    prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
    # The public spelling exists only in the nested factory scope.  The outer
    # bootstrap stores the resulting object in an ordinal slot, so even a user
    # function named like an internal helper cannot shadow another capture.
    wrapper_name = function.name
    captures = (
        native_binding,
        fallback_binding,
        "_rextio_native_disabled",
        "_rextio_native_required",
        "_rextio_boundary_fallback_required",
        "_rextio_builtin_RuntimeError",
        "_rextio_builtin_set",
    )
    forbidden_locals = {
        wrapper_name,
        *(
            argument.arg
            for argument in (
                *node.args.posonlyargs,
                *node.args.args,
                *node.args.kwonlyargs,
                *((node.args.vararg,) if node.args.vararg else ()),
                *((node.args.kwarg,) if node.args.kwarg else ()),
            )
        ),
    }
    capture_locals: list[str] = []
    for index, _capture in enumerate(captures):
        candidate = f"_rextio_dispatch_capture_{index}"
        while candidate in forbidden_locals:
            candidate += "_"
        capture_locals.append(candidate)
        forbidden_locals.add(candidate)
    (
        native_capture,
        fallback_capture,
        disabled_capture,
        required_capture,
        threshold_capture,
        runtime_error_capture,
        set_capture,
    ) = capture_locals

    native_call_args = _native_call_args(function, node)
    native_call = f"{native_capture}({native_call_args})"
    fallback_call = f"{fallback_capture}({call_args})"
    if isinstance(node, ast.AsyncFunctionDef):
        native_call = f"await {native_call}"
        fallback_call = f"await {fallback_call}"
    native_return = native_call
    if not function.native_runtime_semantics and _is_set_type(_return_type_name(function, node)):
        native_return = f"{set_capture}({native_return})"
    # Plugin-routed functions are exempt from the boundary-fallback threshold:
    # flipping such a function to the fallback leg mid-run would silently change
    # its observable behavior (e.g. a native builtin float vs NumPy's float64
    # return, a documented per-leg divergence) after N calls (council round 8).
    # The exemption must match the `native-plugin` route predicate (claims OR
    # signature type keys): a claim-only function -- one that claims a core-typed
    # call site without plugin-typed params/returns -- has the same per-leg
    # divergence and must be exempt too (council round 15).
    is_plugin_routed = bool(function.plugin_claims or function.plugin_type_keys)
    threshold_gate = (
        ""
        if is_plugin_routed
        else _threshold_gate_lines(
            function,
            boundary_fallback_threshold,
            fallback_call,
            required_capture,
            threshold_capture,
        )
    )
    body = [
        f"{prefix} {wrapper_name}({signature}){_return_annotation(node)}:",
        f"    if {disabled_capture}():",
        f"        return {fallback_call}",
        f"    if {native_capture} is None:",
        f"        if {required_capture}():",
        f"            raise {runtime_error_capture}(",
        f'                "native mode requires generated native function: {function.qualname}"',
        "            )",
        f"        return {fallback_call}",
    ]
    if threshold_gate:
        body.extend(threshold_gate)
    body.append(f"    return {native_return}")
    rendered = [
        f"def {factory_binding}(",
        *(f"    {capture}," for capture in capture_locals),
        "):",
        *(f"    {line}" for line in body),
        f"    return {wrapper_name}",
        "",
        f"{wrapper_binding} = {factory_binding}(",
        *(f"    {capture}," for capture in captures),
        ")",
        f"{wrapper_binding}.__name__ = {function.name!r}",
        f"{wrapper_binding}.__qualname__ = {_local_qualname(function)!r}",
    ]
    return rendered


def _threshold_gate_lines(
    function: FunctionAnalysis,
    boundary_fallback_threshold: int,
    fallback_call: str,
    native_required: str = "_rextio_native_required",
    boundary_fallback_required: str = "_rextio_boundary_fallback_required",
) -> list[str]:
    return [
        (
            f'    if not {native_required}() and {boundary_fallback_required}("{function.qualname}", '
            f"{boundary_fallback_threshold}):"
        ),
        f"        return {fallback_call}",
    ]


def _render_defaults_copy(
    function: FunctionAnalysis,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    wrapper: str | None = None,
    fallback: str | None = None,
) -> list[str]:
    """Copy parameter defaults from the fallback function onto the wrapper.

    The wrapper signature carries no default expressions; instead the exact
    default OBJECTS are copied from the fallback function at runtime, so impure
    defaults are evaluated once (in the fallback module) and mutable defaults
    are the same object the source module would use (council round 9).
    """
    if not node.args.defaults and not any(node.args.kw_defaults):
        return []
    wrapper = wrapper or (
        function.name if not _is_method(function) else _wrapper_method_name(function)
    )
    fallback = fallback or _fallback_binding_name(function)
    lines: list[str] = []
    if node.args.defaults:
        lines.append(f"{wrapper}.__defaults__ = {fallback}.__defaults__")
    if any(default is not None for default in node.args.kw_defaults):
        lines.append(f"{wrapper}.__kwdefaults__ = {fallback}.__kwdefaults__")
    return lines


def _signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    # Default VALUES are never reproduced in the wrapper signature; they are
    # copied at runtime from the fallback function's __defaults__/__kwdefaults__
    # (see _render_defaults_copy). Reproducing default EXPRESSIONS re-evaluated
    # them at wrapper import (double side effects for impure defaults) and could
    # NameError when a default referenced a name absent from the wrapper
    # namespace (council round 9). The positional-only `/` marker IS emitted so
    # the wrapper rejects keyword use of positional-only params exactly as the
    # source does.
    parts: list[str] = []
    for arg in node.args.posonlyargs:
        parts.append(_render_arg(arg))
    if node.args.posonlyargs:
        parts.append("/")
    for arg in node.args.args:
        parts.append(_render_arg(arg))
    if node.args.vararg is not None:
        parts.append(f"*{_render_arg(node.args.vararg)}")
    if node.args.kwonlyargs:
        if node.args.vararg is None:
            parts.append("*")
        for arg in node.args.kwonlyargs:
            parts.append(_render_arg(arg))
    if node.args.kwarg is not None:
        parts.append(f"**{_render_arg(node.args.kwarg)}")
    return ", ".join(parts)


def _render_arg(arg: ast.arg) -> str:
    rendered = arg.arg
    if arg.annotation is not None:
        rendered += f": {ast.unparse(arg.annotation)}"
    return rendered


def _return_annotation(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    if node.returns is None:
        return ""
    return f" -> {ast.unparse(node.returns)}"


def _call_args(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    args = [arg.arg for arg in [*node.args.posonlyargs, *node.args.args]]
    if node.args.vararg is not None:
        args.append(f"*{node.args.vararg.arg}")
    args.extend(f"{arg.arg}={arg.arg}" for arg in node.args.kwonlyargs)
    if node.args.kwarg is not None:
        args.append(f"**{node.args.kwarg.arg}")
    return ", ".join(args)


def _native_call_args(
    function: FunctionAnalysis, node: ast.FunctionDef | ast.AsyncFunctionDef
) -> str:
    # All natively-supported argument types pass through the PyO3 boundary as-is.
    # (set[float] has no native lowering -- it stays on the Python fallback
    # or the runtime shim -- so no
    # element-type-specific conversion is required.)
    args = [arg.arg for arg in [*node.args.posonlyargs, *node.args.args]]
    if node.args.vararg is not None:
        args.append(f"*{node.args.vararg.arg}")
    args.extend(f"{arg.arg}={arg.arg}" for arg in node.args.kwonlyargs)
    if node.args.kwarg is not None:
        args.append(f"**{node.args.kwarg.arg}")
    return ", ".join(args)


def _is_set_type(type_name: str | None) -> bool:
    return type_name is not None and type_name.startswith("set[") and type_name.endswith("]")


def _return_type_name(
    function: FunctionAnalysis, node: ast.FunctionDef | ast.AsyncFunctionDef
) -> str | None:
    return _annotation_name(node.returns) or function.inferred_return_type


def _annotation_name(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    try:
        return ast.unparse(node).replace(" ", "")
    except Exception:
        return None


@dataclass(frozen=True)
class _FunctionNodeOrigin:
    node: ast.FunctionDef | ast.AsyncFunctionDef
    enclosing_class: ast.ClassDef | None = None


def _function_nodes_from_tree(tree: ast.Module) -> dict[str, _FunctionNodeOrigin]:
    nodes: dict[str, _FunctionNodeOrigin] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            nodes[node.name] = _FunctionNodeOrigin(node)
        elif isinstance(node, ast.ClassDef):
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    nodes[f"{node.name}.{child.name}"] = _FunctionNodeOrigin(child, node)
    return nodes


def _require_exact_wrapper_origin(
    module: ModuleAnalysis,
    function: FunctionAnalysis,
    origin: _FunctionNodeOrigin,
    current_bindings: ModuleBindings,
) -> None:
    """Reject a malformed accepted list before reading/installing fallback code."""
    analyzed_bindings = module.module_bindings
    if analyzed_bindings is None:
        raise ValueError(f"accepted function has no shared binding authority: {function.qualname}")
    node = origin.node
    if (node.lineno, node.col_offset) != (function.line, function.column):
        raise ValueError(
            f"accepted function origin does not match the source AST: {function.qualname}"
        )
    if (
        function.source_ast_fingerprint is None
        or executable_ast_fingerprint(node) != function.source_ast_fingerprint
    ):
        raise ValueError(
            f"accepted function source AST changed after analysis: {function.qualname}"
        )
    if module.project_mutations.target_is_mutated(function.qualname):
        raise ValueError(
            f"accepted function target was mutated during module execution: {function.qualname}"
        )
    marker_reason = native_marker_identity_reason(
        node, current_bindings, explicitly_marked=function.explicitly_marked
    ) or native_marker_identity_reason(
        node, analyzed_bindings, explicitly_marked=function.explicitly_marked
    )
    if marker_reason is not None:
        raise ValueError(
            f"accepted function native marker identity is unproven: "
            f"{function.qualname}: {marker_reason}"
        )
    if function.enclosing_class_name is None:
        if origin.enclosing_class is not None or not definition_is_final(
            current_bindings,
            function.name,
            BindingKind.FUNCTION,
            function.line,
            function.column,
        ):
            raise ValueError(
                f"accepted function is not its module's exact final binding: {function.qualname}"
            )
        return
    class_node = origin.enclosing_class
    if (
        class_node is None
        or class_node.name != function.enclosing_class_name
        or (class_node.lineno, class_node.col_offset)
        != (function.enclosing_class_line, function.enclosing_class_column)
        or not definition_is_final(
            current_bindings,
            class_node.name,
            BindingKind.CLASS,
            class_node.lineno,
            class_node.col_offset,
        )
    ):
        raise ValueError(
            f"accepted method does not belong to the exact final class: {function.qualname}"
        )
    class_reason = class_construction_stability_reason(
        class_node,
        current_bindings,
        project_mutations=module.project_mutations,
    ) or class_construction_stability_reason(
        class_node,
        analyzed_bindings,
        project_mutations=module.project_mutations,
    )
    if class_reason is not None:
        raise ValueError(
            f"accepted method class construction is unproven: {function.qualname}: {class_reason}"
        )
    outer_tree = ast.parse(
        Path(module.file_path).read_text(encoding="utf-8"), filename=module.file_path
    )
    class_bindings = build_module_bindings(
        ast.Module(body=class_node.body, type_ignores=[]),
        module.module_name,
        trusted_marker_sites=current_bindings.proven_marker_sites,
        trusted_annotation_targets=current_bindings.trusted_annotation_targets,
        trusted_function_bindings={
            statement.name: statement
            for statement in outer_tree.body
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
            and not statement.decorator_list
            and definition_is_final(
                current_bindings,
                statement.name,
                BindingKind.FUNCTION,
                statement.lineno,
                statement.col_offset,
            )
        },
    )
    if not definition_is_final(
        class_bindings,
        function.name,
        BindingKind.FUNCTION,
        function.line,
        function.column,
    ):
        raise ValueError(
            f"accepted method is not the class body's exact final binding: {function.qualname}"
        )


def _method_identity_args(
    function: FunctionAnalysis,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[str, str, str, int]:
    parts = _local_qualname(function).split(".")
    owner_path = tuple(parts[:-1])
    expected_line = min([node.lineno, *(decorator.lineno for decorator in node.decorator_list)])
    return repr(owner_path), parts[-1], ".".join(parts), expected_line


def _render_fallback_binding(
    function: FunctionAnalysis,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    import_prefix: str,
    fallback_name: str,
    dynamic_fallback: bool,
    binding: str | None = None,
) -> list[str]:
    binding = binding or _fallback_binding_name(function)
    lines: list[str]
    if _is_method(function):
        owner_path, method_name, expected_qualname, expected_line = _method_identity_args(
            function, node
        )
        lines = [
            f"{binding} = _rextio_require_fallback_method(",
            f"    {owner_path}, {method_name!r}, {expected_qualname!r}, {expected_line},",
            ")[1]",
        ]
    elif dynamic_fallback:
        lines = [f"{binding} = _rextio_fallback_module.{function.name}"]
    else:
        lines = [f"from {import_prefix}{fallback_name} import {function.name} as {binding}"]
    return lines


def _render_fallback_replacement(
    function: FunctionAnalysis,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    replacement: str | None = None,
) -> list[str]:
    replacement = replacement or (
        function.name if not _is_method(function) else _wrapper_method_name(function)
    )
    if _is_method(function):
        owner_path, method_name, expected_qualname, expected_line = _method_identity_args(
            function, node
        )
        return [
            "_rextio_install_fallback_method(",
            f"    {owner_path}, {method_name!r}, {expected_qualname!r}, {expected_line},",
            f"    {replacement},",
            ")",
        ]
    return [f"_rextio_fallback_module.{function.name} = {replacement}"]


def _function_node_key(function: FunctionAnalysis) -> str:
    return _local_qualname(function)


def _fallback_binding_name(function: FunctionAnalysis) -> str:
    # _rextio_-namespaced and underscore-prefixed to minimize ordinary user-name
    # collisions before terminal fallback export publication (council round 8).
    if not _is_method(function):
        return f"_rextio_fallback_fn_{function.name}"
    return f"_rextio_fallback_fn_{_local_qualname(function).replace('.', '_')}"


def _native_binding_name(function: FunctionAnalysis) -> str:
    if not _is_method(function):
        return f"_rextio_native_fn_{function.name}"
    return f"_rextio_native_fn_{_local_qualname(function).replace('.', '_')}"


def _wrapper_method_name(function: FunctionAnalysis) -> str:
    return f"_rextio_wrapper_{_local_qualname(function).replace('.', '_')}"


def _fallback_lookup(function: FunctionAnalysis) -> str:
    target = "_rextio_fallback_module"
    for item in _local_qualname(function).split("."):
        target = f"{target}.{item}"
    return target


def _is_method(function: FunctionAnalysis) -> bool:
    return "." in _local_qualname(function)


def _local_qualname(function: FunctionAnalysis) -> str:
    if function.module_name and function.qualname.startswith(f"{function.module_name}."):
        return function.qualname[len(function.module_name) + 1 :]
    return function.qualname
