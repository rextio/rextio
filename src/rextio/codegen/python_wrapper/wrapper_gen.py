"""Generation of the Python wrapper module that dispatches to native or fallback."""

from __future__ import annotations

import ast
from pathlib import Path

from rextio.analyzer.models import FunctionAnalysis, ModuleAnalysis, TopLevelAnalysis
from rextio.codegen.native_names import native_function_name, runtime_original_name
from rextio.fallback.fallback_marker import GENERATED_PYTHON_HEADER
from rextio.fallback.module_copy import (
    fallback_module_name,
    native_top_level_fallback_module_name,
)
from rextio.runtime.boundary_fallback import DEFAULT_BOUNDARY_FALLBACK_THRESHOLD


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

    source_tree = ast.parse(Path(module.file_path).read_text(encoding="utf-8"), filename=module.file_path)
    function_nodes = _function_nodes_from_tree(source_tree)
    fallback_name = fallback_module_name(module)
    import_prefix = "." if "." in module.module_name or Path(module.file_path).name == "__init__.py" else ""
    lines = [
        GENERATED_PYTHON_HEADER,
        "",
        # PEP 563: wrapper defs reproduce the user's annotations verbatim, but
        # the names they reference are only in this namespace by way of the
        # fallback star-import - which misses anything excluded by __all__ or
        # imported under an underscore alias. Eager evaluation then breaks the
        # whole module with NameError at import (council round 7); lazy
        # (string) annotations never evaluate.
        "from __future__ import annotations",
        "",
        # Runtime helpers are aliased under _rextio_-prefixed names so a user
        # module that happens to export a public name like `native_disabled`
        # cannot clobber the dispatch helpers via the fallback star-import
        # (council round 8).
        "from rextio.runtime.boundary_fallback import boundary_fallback_required as _rextio_boundary_fallback_required",
        "from rextio.runtime.flags import native_disabled as _rextio_native_disabled",
        "from rextio.runtime.flags import native_required as _rextio_native_required",
        "from rextio.runtime.native_loader import load_native_function as _rextio_load_native_function",
        "",
    ]
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
            )
        )
    else:
        lines.extend(_fallback_module_import_lines(import_prefix, fallback_name))
        lines.append(f"from {import_prefix}{fallback_name} import *  # noqa: F401,F403")
    lines.append("")
    # Faithfully mirror the source module's public surface: its docstring, any
    # module-level names referenced by parameter defaults (which the star-import
    # misses when they are private or excluded from __all__), and its __all__.
    lines.extend(_render_namespace_fidelity(source_tree))
    lines.append("")
    for function in accepted:
        lines.extend(_render_fallback_binding(function, import_prefix, fallback_name, top_level is not None))
    lines.append("")

    for function in accepted:
        lines.extend(_render_native_binding(function))
        lines.append("")

    for function in accepted:
        node = function_nodes[_function_node_key(function)]
        lines.extend(_render_wrapper_function(function, node, boundary_fallback_threshold))
        lines.extend(_render_defaults_copy(function, node))
        lines.append("")

    for function in accepted:
        lines.extend(_render_fallback_replacement(function))
    lines.append("")

    return "\n".join(lines)


def _render_namespace_fidelity(source_tree: ast.Module) -> list[str]:
    """Mirror the source module's __doc__ and __all__ onto the wrapper.

    ``from ._fallback import *`` only carries the fallback module's PUBLIC
    names, so the module docstring is lost and an explicit ``__all__`` is not
    propagated; mirror both from the fallback module reference. (Parameter
    defaults are handled separately by copying __defaults__/__kwdefaults__ from
    the fallback function - see _render_defaults_copy - so they are never
    reproduced as expressions here.)
    """
    lines = ['__doc__ = _rextio_fallback_module.__doc__']
    if _has_module_all(source_tree):
        lines.append("__all__ = list(_rextio_fallback_module.__all__)")
    return lines


def _has_module_all(tree: ast.Module) -> bool:
    for node in tree.body:
        if isinstance(node, ast.Assign):
            if any(isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets):
                return True
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id == "__all__":
                return True
    return False


def _fallback_module_import_lines(import_prefix: str, fallback_name: str) -> list[str]:
    if import_prefix == ".":
        return [f"from . import {fallback_name} as _rextio_fallback_module"]
    return [f"import {fallback_name} as _rextio_fallback_module"]


def _render_native_binding(function: FunctionAnalysis) -> list[str]:
    return [
        f"{_native_binding_name(function)} = _rextio_load_native_function(",
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
) -> list[str]:
    return [
        f'_REXTIO_FALLBACK_MODULE_NAME = "{fallback_name}"',
        f'_REXTIO_NATIVE_TOP_LEVEL_FALLBACK_MODULE_NAME = "{native_fallback_name}"',
        "",
        "def _rextio_import_fallback_module(name):",
        "    if __package__:",
        '        return _rextio_importlib.import_module(f".{name}", __package__)',
        "    return _rextio_importlib.import_module(name)",
        "",
        "def _rextio_public_names(module):",
        '    explicit = getattr(module, "__all__", None)',
        "    if explicit is not None:",
        "        return list(explicit)",
        "    return [name for name in module.__dict__ if not name.startswith('_')]",
        "",
        "def _rextio_apply_public_names(module):",
        "    globals().update({name: getattr(module, name) for name in _rextio_public_names(module)})",
        "",
        "def _rextio_select_fallback_module():",
        "    if _rextio_native_disabled():",
        "        return _rextio_import_fallback_module(_REXTIO_FALLBACK_MODULE_NAME)",
        "    if _native___rextio_top_level__ is None:",
        "        if _rextio_native_required():",
        "            raise RuntimeError(",
        f'                "native mode requires generated native top-level initializer: {top_level.qualname}"',
        "            )",
        "        return _rextio_import_fallback_module(_REXTIO_FALLBACK_MODULE_NAME)",
        "    module = _rextio_import_fallback_module(_REXTIO_NATIVE_TOP_LEVEL_FALLBACK_MODULE_NAME)",
        "    updates = _native___rextio_top_level__()",
        "    module.__dict__.update(updates)",
        "    globals().update(updates)",
        "    return module",
        "",
        "_rextio_fallback_module = _rextio_select_fallback_module()",
        "_rextio_apply_public_names(_rextio_fallback_module)",
    ]


def _render_wrapper_function(
    function: FunctionAnalysis,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    boundary_fallback_threshold: int,
) -> list[str]:
    signature = _signature(node)
    call_args = _call_args(node)
    native_call_args = _native_call_args(function, node)
    native_call = f"{_native_binding_name(function)}({native_call_args})"
    fallback_call = f"{_fallback_binding_name(function)}({call_args})"
    if isinstance(node, ast.AsyncFunctionDef):
        native_call = f"await {native_call}"
        fallback_call = f"await {fallback_call}"
    native_return = native_call
    if not function.native_runtime_semantics and _is_set_type(_return_type_name(function, node)):
        native_return = f"set({native_return})"
    prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
    wrapper_name = function.name if not _is_method(function) else _wrapper_method_name(function)
    # Plugin-routed functions are exempt from the boundary-fallback threshold:
    # flipping such a function to the fallback leg mid-run would silently change
    # its observable behavior (e.g. a native builtin float vs NumPy's float64
    # return, a documented per-leg divergence) after N calls (council round 8).
    threshold_gate = "" if function.plugin_type_keys else _threshold_gate_lines(
        function, boundary_fallback_threshold, fallback_call
    )
    body = [
        f"{prefix} {wrapper_name}({signature}){_return_annotation(node)}:",
        "    if _rextio_native_disabled():",
        f"        return {fallback_call}",
        f"    if {_native_binding_name(function)} is None:",
        "        if _rextio_native_required():",
        "            raise RuntimeError(",
        f'                "native mode requires generated native function: {function.qualname}"',
        "            )",
        f"        return {fallback_call}",
    ]
    if threshold_gate:
        body.extend(threshold_gate)
    body.append(f"    return {native_return}")
    return body


def _threshold_gate_lines(
    function: FunctionAnalysis, boundary_fallback_threshold: int, fallback_call: str
) -> list[str]:
    return [
        (
            f'    if not _rextio_native_required() and _rextio_boundary_fallback_required("{function.qualname}", '
            f"{boundary_fallback_threshold}):"
        ),
        f"        return {fallback_call}",
    ]


def _render_defaults_copy(
    function: FunctionAnalysis, node: ast.FunctionDef | ast.AsyncFunctionDef
) -> list[str]:
    """Copy parameter defaults from the fallback function onto the wrapper.

    The wrapper signature carries no default expressions; instead the exact
    default OBJECTS are copied from the fallback function at runtime, so impure
    defaults are evaluated once (in the fallback module) and mutable defaults
    are the same object the source module would use (council round 9).
    """
    if not node.args.defaults and not any(node.args.kw_defaults):
        return []
    wrapper = function.name if not _is_method(function) else _wrapper_method_name(function)
    fallback = _fallback_binding_name(function)
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


def _native_call_args(function: FunctionAnalysis, node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
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


def _return_type_name(function: FunctionAnalysis, node: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    return _annotation_name(node.returns) or function.inferred_return_type


def _annotation_name(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    try:
        return ast.unparse(node).replace(" ", "")
    except Exception:
        return None


def _function_nodes_from_tree(tree: ast.Module) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    nodes: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            nodes[node.name] = node
        elif isinstance(node, ast.ClassDef):
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    nodes[f"{node.name}.{child.name}"] = child
    return nodes


def _render_fallback_binding(
    function: FunctionAnalysis,
    import_prefix: str,
    fallback_name: str,
    dynamic_fallback: bool,
) -> list[str]:
    binding = _fallback_binding_name(function)
    lines: list[str]
    if _is_method(function):
        lines = [f"{binding} = {_fallback_lookup(function)}"]
    elif dynamic_fallback:
        lines = [f"{binding} = _rextio_fallback_module.{function.name}"]
    else:
        lines = [f"from {import_prefix}{fallback_name} import {function.name} as {binding}"]
    if function.native_runtime_semantics:
        lines.append(
            f'setattr(_rextio_fallback_module, "{runtime_original_name(function.qualname)}", {binding})'
        )
    return lines


def _render_fallback_replacement(function: FunctionAnalysis) -> list[str]:
    if _is_method(function):
        return [f"{_fallback_lookup(function)} = {_wrapper_method_name(function)}"]
    return [f"_rextio_fallback_module.{function.name} = {function.name}"]


def _function_node_key(function: FunctionAnalysis) -> str:
    return _local_qualname(function)


def _fallback_binding_name(function: FunctionAnalysis) -> str:
    # _rextio_-namespaced and underscore-prefixed so it is neither carried by
    # the fallback star-import nor collides with a user name (council round 8).
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
        return function.qualname[len(function.module_name) + 1:]
    return function.qualname
