"""Rust/PyO3 source generation from the Rextio IR."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import replace

from rextio.codegen.native_names import (
    native_function_name,
    native_function_name_collisions,
)
from rextio.exceptions import BUILTIN_EXCEPTION_TO_PYO3
from rextio.codegen.rust.checked_arith import (
    checked_arith_helpers as _checked_arith_helpers,
)
from rextio.codegen.rust.errors import RustCodegenError
from rextio.codegen.rust.keywords import RUST_RAWABLE_KEYWORDS
from rextio.codegen.rust.subprocess_client import render_subprocess_client
from rextio.codegen.rust.pyo3 import render_pyo3_module
from rextio.codegen.rust.external_runtime_guard import render_external_runtime_guard
from rextio.codegen.rust.rust_format import (
    block_always_returns as _block_always_returns,
)
from rextio.codegen.rust.rust_format import (
    default_return,
    render_literal,
    rust_string_literal,
    strip_expr_if_safe,
    strip_wrapping_parens,
)
from rextio.codegen.rust.rust_format import (
    indent as _indent,
)
from rextio.codegen.rust.type_map import rust_type
from rextio.analyzer.logging_format import python_logging_format_segments
from rextio.plugins.api import (
    LOWERING_BACKEND_STANDALONE_RUST,
    CallableMeta,
    ClaimExpr,
    ClaimSite,
    LoweredExpr,
    LoweringContext,
)
from rextio.plugins.capabilities import StandalonePluginContext, claim_plugin_type_keys
from rextio.ir.nodes import (
    AppendIR,
    AssignIR,
    BinaryOpIR,
    BlockIR,
    BreakIR,
    CallIR,
    ComprehensionGeneratorIR,
    CompareIR,
    ContinueIR,
    DictComprehensionIR,
    DictIR,
    DictSetIR,
    EffectCallIR,
    ExprIR,
    ForIR,
    FunctionIR,
    IfIR,
    IndexIR,
    ListComprehensionIR,
    ListIR,
    LiteralIR,
    ModuleIR,
    NameIR,
    NamedExprIR,
    ParamIR,
    PluginClaimIR,
    ReturnIR,
    SetComprehensionIR,
    SetIR,
    StatementIR,
    TargetIR,
    TryIR,
    TupleIR,
    TupleTargetIR,
    UnaryOpIR,
    WhileIR,
)
from rextio.ir.types import (
    type_from_string,
    RxtBool,
    RxtBytes,
    RxtDict,
    RxtFloat,
    RxtInt,
    RxtList,
    RxtNone,
    RxtOptional,
    RxtPluginType,
    RxtSet,
    RxtStr,
    RxtTuple,
    RxtType,
)
from rextio.source.external_linkage import ExternalRuntimeGuard


# `RustCodegenError` is imported from .errors above and re-exported here for
# backward compatibility (tests import `rextio.codegen.rust.generator`). No
# `__all__` is declared so this pure refactor leaves the module's wildcard-export
# surface exactly as it was before the split.


def _plugin_api_at_least(version: str, major: int, minor: int) -> bool:
    """Return True when a plugin-API version string is at least major.minor."""
    parts = version.split(".")
    try:
        ver_major = int(parts[0])
        ver_minor = int(parts[1]) if len(parts) > 1 else 0
    except (ValueError, IndexError):
        return False
    return (ver_major, ver_minor) >= (major, minor)


def generate_rust_module(
    module_ir: ModuleIR,
    boundary_call_return_types: dict[str, str] | None = None,
    plugin_providers: dict[str, object] | None = None,
    plugin_types_by_key: Mapping[str, RxtType] | None = None,
    external_runtime_guard: ExternalRuntimeGuard | None = None,
) -> str:
    """Generate the PyO3 extension-module Rust source for a lowered module.

    ``boundary_call_return_types`` maps the qualname of each fallback function
    reached through an in-process scalar boundary call (RXT075) to its return
    type; those calls lower to a run-time dispatch through
    ``rextio.runtime.boundary_call``.

    ``plugin_providers`` maps plugin ids to live lowering providers for
    plugin-claimed sites; ``plugin_types_by_key`` maps plugin type keys to
    their ``RxtPluginType`` so claim result types resolve during inference.
    Both are None/empty for plugin-free builds, which render exactly as before.
    """
    _require_unique_native_function_symbols(module_ir.functions)
    names_by_qualname = {
        function.qualname: rust_identifier(native_function_name(function.qualname))
        for function in module_ir.functions
    }
    names_by_module_and_name = {
        (function.module_name, function.name): names_by_qualname[function.qualname]
        for function in module_ir.functions
    }
    return_types_by_qualname = {
        function.qualname: function.return_type for function in module_ir.functions
    }
    used_helpers: set[str] = set()
    # Shared plugin collectors: `use` lines deduplicate as a set (sorted for
    # determinism at emission); helpers keep first-seen order via a dict.
    plugin_uses: set[str] = set()
    plugin_helpers: dict[str, None] = {}
    rendered = [
        (
            names_by_qualname[function.qualname],
            (
                _render_runtime_semantics_function(function)
                if function.native_runtime_semantics
                else _render_function(
                    function,
                    names_by_qualname,
                    names_by_module_and_name,
                    return_types_by_qualname,
                    mode="pyo3",
                    used_helpers=used_helpers,
                    boundary_call_return_types=boundary_call_return_types,
                    # An embedded helper — or a resident-signature native-only
                    # helper (opaque plugin values, plugin API 1.3) — compiles as
                    # a plain internal function: callable from native code, never
                    # a #[pyfunction] export.
                    pyo3_exported=not function.embedded and not _has_resident_signature(function),
                    plugin_providers=plugin_providers,
                    plugin_types_by_key=plugin_types_by_key,
                    plugin_uses=plugin_uses,
                    plugin_helpers=plugin_helpers,
                )
            ),
        )
        for function in module_ir.functions
    ]
    exported = [
        names_by_qualname[function.qualname]
        for function in module_ir.functions
        if not function.embedded and not _has_resident_signature(function)
    ]
    prelude: list[str] = []
    prelude.extend(sorted(plugin_uses))
    prelude.extend(plugin_helpers)
    prelude.extend(_checked_arith_helpers(used_helpers, "pyo3"))
    if external_runtime_guard is not None:
        prelude.append(render_external_runtime_guard(external_runtime_guard))
    return render_pyo3_module(
        rendered,
        exported_functions=exported,
        extra_prelude=prelude or None,
        module_initializers=(
            ["__rextio_verify_external_source(m.py())?;"]
            if external_runtime_guard is not None
            else None
        ),
    )


def _called_function_names(function: FunctionIR) -> set[str]:
    """Every call-target name in the function body (qualified or bare)."""
    names: set[str] = set()

    def walk(node: object) -> None:
        if isinstance(node, dict):
            if node.get("kind") == "call":
                target = node.get("function")
                if isinstance(target, str):
                    names.add(target)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(function.body.to_dict())
    return names


def _crate_excluded_qualnames(
    module_ir: ModuleIR,
    standalone: StandalonePluginContext | None = None,
) -> set[str]:
    """Functions with no pure-Rust crate form, closed over the native call graph.

    Seeds are runtime-shim, boundary-calling, and plugin-lowered functions
    that lack a resolved standalone capability for the active artifact profile
    (the first two need the Python interpreter; legacy plugin lowering emits
    PyO3-boundary code). Plugin API 1.4 functions that pass resolved capability
    coverage are kept. Any function that calls an excluded function - by
    qualname or by bare name within the same module, mirroring how the crate
    renderer resolves native calls - is excluded as well, to a fixed point.

    The bare-name match assumes a collected call-target string that equals an
    excluded function's name refers to that module-level function - the same
    assumption the renderer's ``names_by_module_and_name`` lookup makes. A
    same-named shadow could therefore over-exclude its caller; that bias is
    deliberate: an over-excluded function merely stays off the crate (still
    served by the wheel and the Python fallback), while an under-exclusion
    would emit a call to a function the crate never defines.
    """
    excluded = {
        function.qualname
        for function in module_ir.functions
        if function.native_runtime_semantics
        or function.has_boundary_calls
        or (
            function.plugin_lowered
            and (standalone is None or not standalone.is_capable(function.qualname))
        )
    }
    if not excluded:
        return excluded
    candidates = [function for function in module_ir.functions if function.qualname not in excluded]
    calls_by_qualname = {
        function.qualname: _called_function_names(function) for function in candidates
    }
    functions_by_qualname = {function.qualname: function for function in module_ir.functions}
    changed = True
    while changed:
        changed = False
        for function in candidates:
            if function.qualname in excluded:
                continue
            targets = calls_by_qualname[function.qualname]
            for excluded_qualname in excluded:
                dependency = functions_by_qualname[excluded_qualname]
                if excluded_qualname in targets or (
                    dependency.module_name == function.module_name and dependency.name in targets
                ):
                    excluded.add(function.qualname)
                    changed = True
                    break
    return excluded


def crate_emitted_qualnames(
    module_ir: ModuleIR,
    standalone: StandalonePluginContext | None = None,
) -> frozenset[str]:
    """Return qualnames that survive standalone transitive exclusion.

    Dependency injection for rust-crate / host-executable must use this set
    (or an equivalent post-exclusion filter), never the pre-exclusion capable
    set alone — a capable plugin function that calls an unsupported plugin
    function is excluded and must not inject crate dependencies.
    """
    excluded = _crate_excluded_qualnames(module_ir, standalone=standalone)
    return frozenset(
        function.qualname for function in module_ir.functions if function.qualname not in excluded
    )


def generate_rust_crate_module(
    module_ir: ModuleIR,
    delegated_return_types: dict[str, str] | None = None,
    python_command: str = "python3",
    nuitka_dispatcher: bool = False,
    *,
    plugin_providers: dict[str, object] | None = None,
    plugin_types_by_key: Mapping[str, RxtType] | None = None,
    standalone: StandalonePluginContext | None = None,
) -> str:
    """Generate the Rust-importable crate source for a lowered module.

    ``delegated_return_types`` maps the qualname of each fallback function the
    generated code delegates to the external CPython dispatcher to its return
    type; when non-empty the IPC client is appended and its calls are lowered to
    ``__rextio_call_python``.

    ``standalone`` carries resolved plugin API 1.4 capability for the exact
    rust-crate / host-executable profile. Plugin-lowered functions that pass
    coverage render with native Rust types only (no PyO3 boundary). Without a
    matching capability, legacy exclusion remains fail-closed and transitive.
    """
    delegated_return_types = delegated_return_types or {}
    # Embedded helpers are ordinary direct functions in crate mode;
    # runtime-shim functions and boundary-calling functions have no
    # pure-Rust crate form (both need the Python interpreter). The exclusion
    # is TRANSITIVE: a function whose native callee is excluded would render
    # a call to a function the crate does not emit, so it is excluded too.
    excluded = _crate_excluded_qualnames(module_ir, standalone=standalone)
    direct_functions = [
        function for function in module_ir.functions if function.qualname not in excluded
    ]
    _require_unique_native_function_symbols(direct_functions)
    if not direct_functions:
        raise RustCodegenError(
            "no direct Rust native functions are available for a Rust-importable crate"
        )
    names_by_qualname = {
        function.qualname: rust_identifier(native_function_name(function.qualname))
        for function in direct_functions
    }
    names_by_module_and_name = {
        (function.module_name, function.name): names_by_qualname[function.qualname]
        for function in direct_functions
    }
    return_types_by_qualname = {
        function.qualname: function.return_type for function in direct_functions
    }
    used_helpers: set[str] = set()
    plugin_uses: set[str] = set()
    plugin_helpers: dict[str, None] = {}
    rendered = [
        _render_function(
            function,
            names_by_qualname,
            names_by_module_and_name,
            return_types_by_qualname,
            mode="crate",
            used_helpers=used_helpers,
            delegated_return_types=delegated_return_types,
            plugin_providers=plugin_providers,
            plugin_types_by_key=plugin_types_by_key,
            plugin_uses=plugin_uses,
            plugin_helpers=plugin_helpers,
            standalone=standalone,
        )
        for function in direct_functions
    ]
    prelude: list[str] = []
    prelude.extend(sorted(plugin_uses))
    prelude.extend(plugin_helpers)
    return _render_importable_crate_module(
        rendered,
        used_helpers,
        include_ipc_client=bool(delegated_return_types),
        python_command=python_command,
        nuitka_dispatcher=nuitka_dispatcher,
        extra_prelude=prelude or None,
    )


def generate_rust_main_binary(
    module_ir: ModuleIR,
    entry_qualname: str,
    delegated_return_types: dict[str, str] | None = None,
    python_command: str = "python3",
    nuitka_dispatcher: bool = False,
    *,
    initializer_qualnames: tuple[str, ...] = (),
    plugin_providers: dict[str, object] | None = None,
    plugin_types_by_key: Mapping[str, RxtType] | None = None,
    standalone: StandalonePluginContext | None = None,
) -> str:
    """Generate a Rust *binary* crate source for an executable build.

    Reuses the Rust-importable crate module (no PyO3, `RextioError`-returning
    functions) and appends a ``fn main`` that calls the entrypoint with the
    process arguments and maps its result to an exit code. The entrypoint must be
    an accepted direct-native function with the shape ``(list[str]) -> int``
    (Python ``def main(argv: list[str]) -> int``): ``argv`` mirrors ``sys.argv``
    (program path at index 0), the returned ``int`` is the process exit code, and
    a returned ``RextioError`` is printed CPython-style (``TypeName: message``) to
    stderr with a non-zero exit.
    """
    entry = _resolve_main_entry(module_ir, entry_qualname)
    initializers = _resolve_main_initializers(module_ir, initializer_qualnames)
    crate_source = generate_rust_crate_module(
        module_ir,
        delegated_return_types,
        python_command,
        nuitka_dispatcher,
        plugin_providers=plugin_providers,
        plugin_types_by_key=plugin_types_by_key,
        standalone=standalone,
    )
    entry_name = rust_identifier(native_function_name(entry.qualname))
    initializer_calls: list[str] = []
    for initializer in initializers:
        initializer_name = rust_identifier(native_function_name(initializer.qualname))
        initializer_calls.extend(
            [
                f"    if let Err(err) = {initializer_name}() {{",
                "        // Initializers run before argv handling and the entrypoint.",
                '        eprintln!("{}", err);',
                "        std::process::exit(1);",
                "    }",
            ]
        )
    main_fn = "\n".join(
        [
            "fn main() {",
            *initializer_calls,
            "    // Mirror Python `sys.argv`: the program path at index 0, then args.",
            "    let argv: Vec<String> = match std::env::args_os()",
            "        .map(|arg| arg.into_string())",
            "        .collect::<Result<Vec<_>, _>>()",
            "    {",
            "        Ok(argv) => argv,",
            "        Err(_) => {",
            '            eprintln!("ValueError: command-line argument is not valid UTF-8");',
            "            std::process::exit(1);",
            "        }",
            "    };",
            f"    match {entry_name}(argv) {{",
            "        Ok(code) => std::process::exit(code as i32),",
            "        Err(err) => {",
            "            // `Display` renders `TypeName: message` (CPython-style).",
            '            eprintln!("{}", err);',
            "            std::process::exit(1);",
            "        }",
            "    }",
            "}",
        ]
    )
    return f"{crate_source}\n{main_fn}\n"


def _resolve_main_initializers(
    module_ir: ModuleIR,
    initializer_qualnames: tuple[str, ...],
) -> tuple[FunctionIR, ...]:
    """Validate standalone unit initializers while preserving planned order."""
    if len(set(initializer_qualnames)) != len(initializer_qualnames):
        raise RustCodegenError("Rust-main module initializer qualnames must be unique")
    functions = {function.qualname: function for function in module_ir.functions}
    resolved: list[FunctionIR] = []
    for qualname in initializer_qualnames:
        initializer = functions.get(qualname)
        if initializer is None:
            raise RustCodegenError(
                f"Rust-main module initializer '{qualname}' is missing from executable IR"
            )
        if (
            initializer.params
            or not isinstance(initializer.return_type, RxtNone)
            or initializer.native_runtime_semantics
            or initializer.embedded
            or initializer.plugin_lowered
        ):
            raise RustCodegenError(
                f"Rust-main module initializer '{qualname}' must be direct-native () -> None"
            )
        resolved.append(initializer)
    return tuple(resolved)


def _resolve_main_entry(module_ir: ModuleIR, entry_qualname: str) -> FunctionIR:
    """Return the entrypoint FunctionIR, or raise if it is missing or ill-typed."""
    runtime_matches = [
        function
        for function in module_ir.functions
        if function.qualname == entry_qualname and function.native_runtime_semantics
    ]
    if runtime_matches:
        raise RustCodegenError(
            f"Rust-main entrypoint '{entry_qualname}' cannot use Python runtime semantics (RXT080)"
        )
    embedding_matches = [
        function
        for function in module_ir.functions
        if function.qualname == entry_qualname and function.embedded
    ]
    if embedding_matches:
        raise RustCodegenError(
            f"Rust-main entrypoint '{entry_qualname}' cannot be an embedded helper function"
        )
    matches = [
        function
        for function in module_ir.functions
        if function.qualname == entry_qualname
        and not function.native_runtime_semantics
        and not function.embedded
    ]
    if not matches:
        raise RustCodegenError(
            f"Rust-main entrypoint '{entry_qualname}' is not an accepted direct-native function"
        )
    entry = matches[0]
    param_types = [param.type for param in entry.params]
    if not (
        len(param_types) == 1
        and isinstance(param_types[0], RxtList)
        and isinstance(param_types[0].item_type, RxtStr)
    ):
        raise RustCodegenError(
            f"Rust-main entrypoint '{entry_qualname}' must take a single list[str] argument (argv)"
        )
    if not isinstance(entry.return_type, RxtInt):
        raise RustCodegenError(
            f"Rust-main entrypoint '{entry_qualname}' must return int (the process exit code)"
        )
    return entry


def rust_identifier(value: str) -> str:
    """Return a valid Rust identifier for a name, escaping keywords as raw identifiers."""
    identifier = re.sub(r"[^0-9a-zA-Z_]", "_", value)
    if not identifier:
        raise RustCodegenError("empty Rust identifier")
    if identifier[0].isdigit():
        identifier = f"_{identifier}"
    # Carry a name that collides with a Rust keyword as a raw identifier so it
    # stays valid Rust (e.g. a Python local `match` -> `r#match`). The handful of
    # keywords `r#` cannot express (`crate`/`self`/`Self`/`super`) are rejected
    # upstream by the analyzer (RXT011), so they never reach here.
    if identifier in RUST_RAWABLE_KEYWORDS:
        return f"r#{identifier}"
    return identifier


def _require_unique_native_function_symbols(functions: list[FunctionIR]) -> None:
    """Defensively reject colliding symbols in caller-constructed module IR."""
    collisions = native_function_name_collisions(function.qualname for function in functions)
    if not collisions:
        return
    symbol, qualnames = collisions[0]
    rendered = ", ".join(repr(qualname) for qualname in qualnames)
    raise RustCodegenError(
        f"native Rust symbol collision: {rendered} all lower to '{symbol}'; "
        "rename one function or module so each native qualname is distinct after Rust mangling"
    )


def _render_runtime_semantics_function(function: FunctionIR) -> str:
    if function.runtime_fallback_module is None or len(function.runtime_attr_path) != 1:
        raise RustCodegenError(f"missing runtime fallback metadata for {function.qualname}")
    rust_name = rust_identifier(native_function_name(function.qualname))
    try:
        ordinal = int(function.runtime_attr_path[0])
    except ValueError:
        raise RustCodegenError(
            f"invalid runtime-original ordinal for {function.qualname}"
        ) from None
    if ordinal < 0:
        raise RustCodegenError(f"invalid runtime-original ordinal for {function.qualname}")
    return "\n".join(
        [
            "#[pyfunction(signature = (*args, **kwargs))]",
            f"fn {rust_name}(",
            "    py: Python<'_>,",
            "    args: &Bound<'_, PyTuple>,",
            "    kwargs: Option<&Bound<'_, PyDict>>,",
            ") -> PyResult<Py<PyAny>> {",
            "    rextio_call_python_runtime(",
            "        py,",
            f"        {rust_string_literal(function.runtime_fallback_module)},",
            f"        {ordinal},",
            "        args,",
            "        kwargs,",
            "    )",
            "}",
        ]
    )


# Map the renderer's internal error ``kind`` to the CPython exception type name a
# crate-mode ``RextioError`` carries (so a consumer can print a Python-style
# ``TypeName: message``). pyo3 mode uses the ``Py*`` exception types directly.
_CRATE_EXCEPTION_NAMES = {
    "key": "KeyError",
    "runtime": "RuntimeError",
    "unbound": "UnboundLocalError",
    "value": "ValueError",
}


def _crate_exception_name(kind: str) -> str:
    """Return the CPython exception type name for a renderer error ``kind``."""
    try:
        return _CRATE_EXCEPTION_NAMES[kind]
    except KeyError as exc:
        raise RustCodegenError(f"unmapped crate error kind: {kind}") from exc


def _render_importable_crate_module(
    function_sources: list[str],
    used_helpers: set[str],
    *,
    include_ipc_client: bool = False,
    python_command: str = "python3",
    nuitka_dispatcher: bool = False,
    extra_prelude: list[str] | None = None,
) -> str:
    lines = [
        "// Generated by Rextio. Do not edit manually.",
        "",
        # Generated function names are snake_case-violating (e.g. `app__f`) and a
        # given crate may not use every prelude import; silence those lints so a
        # clean build does not bury the success line in warnings.
        "#![allow(non_snake_case, unused_imports)]",
        "",
        "use base64::Engine;",
        "use sha2::Digest;",
        "use std::collections::HashMap;",
        "use std::collections::HashSet;",
        "",
    ]
    if extra_prelude:
        lines.extend(extra_prelude)
        lines.append("")
    lines.extend(
        [
            "#[derive(Debug, Clone, PartialEq, Eq)]",
            "pub struct RextioError {",
            "    // The CPython exception type name this error corresponds to (e.g.",
            '    // "OverflowError"), so a consumer can render a Python-style message.',
            "    kind: String,",
            "    message: String,",
            "}",
            "",
            "impl RextioError {",
            "    pub fn new(kind: impl Into<String>, message: impl Into<String>) -> Self {",
            "        Self { kind: kind.into(), message: message.into() }",
            "    }",
            "",
            "    pub fn kind(&self) -> &str {",
            "        &self.kind",
            "    }",
            "",
            "    pub fn message(&self) -> &str {",
            "        &self.message",
            "    }",
            "}",
            "",
            "impl std::fmt::Display for RextioError {",
            "    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {",
            "        // CPython-style `TypeName: message`.",
            '        write!(f, "{}: {}", self.kind, self.message)',
            "    }",
            "}",
            "",
            "impl std::error::Error for RextioError {}",
            "",
        ]
    )
    lines.extend(_checked_arith_helpers(used_helpers, "crate"))
    if include_ipc_client:
        lines.append(render_subprocess_client(python_command, nuitka_dispatcher=nuitka_dispatcher))
        lines.append("")
    for function_source in function_sources:
        lines.append(function_source)
        lines.append("")
    return "\n".join(lines)


class _FunctionRenderer:
    def __init__(
        self,
        function: FunctionIR,
        native_names_by_qualname: dict[str, str],
        native_names: dict[tuple[str, str], str],
        native_return_types: dict[str, RxtType],
        mode: str,
        used_helpers: set[str] | None = None,
        delegated_return_types: dict[str, str] | None = None,
        boundary_call_return_types: dict[str, str] | None = None,
        pyo3_exported: bool = True,
        plugin_providers: dict[str, object] | None = None,
        plugin_types_by_key: Mapping[str, RxtType] | None = None,
        plugin_uses: set[str] | None = None,
        plugin_helpers: dict[str, None] | None = None,
        standalone: StandalonePluginContext | None = None,
    ) -> None:
        self.function = function
        # Whether the pyo3-mode function is registered with the module. Embedded
        # helpers are internal-only: no `#[pyfunction]` wrapper is generated.
        self.pyo3_exported = pyo3_exported
        self.native_names_by_qualname = native_names_by_qualname
        self.native_names = native_names
        self.native_return_types = native_return_types
        self.mode = mode
        # qualname -> return-type name for calls delegated to the CPython
        # dispatcher (executable delegate mode); empty in every normal build.
        self.delegated_return_types = delegated_return_types or {}
        # qualname -> return-type name for in-process scalar boundary calls
        # to the Python fallback (RXT075); pyo3 mode only.
        self.boundary_call_return_types = boundary_call_return_types or {}
        self.declared = {param.name for param in function.params}
        self.variable_types = {param.name: param.type for param in function.params}
        # Resident (opaque, native-only — plugin API 1.3) parameters are passed
        # by shared reference (``&T``), so the caller keeps ownership and can
        # reuse the value or pass it again (safe native-to-native chaining). A
        # name in this set is therefore ALREADY a ``&T`` binding: re-passing it
        # native-to-native reborrows it rather than taking a fresh borrow.
        self._resident_param_names = frozenset(
            param.name
            for param in function.params
            if isinstance(param.type, RxtPluginType) and param.type.resident
        )
        self.maybe_bound_types: dict[str, RxtType] = {}
        self.temp_index = 0
        # Checked-arithmetic helper names (e.g. "add", "neg") used by this
        # function, recorded structurally so the module assembler emits exactly
        # the helpers that are referenced rather than scanning the rendered text.
        self.used_helpers = used_helpers if used_helpers is not None else set()
        # Plugin lowering (docs/specs/plugin-lowering.md): live providers by
        # plugin id, plugin types by key for claim result-type inference, and
        # module-shared collectors for `use` lines and helper items.
        self.plugin_providers = plugin_providers or {}
        self.plugin_types_by_key = plugin_types_by_key or {}
        self.plugin_uses = plugin_uses if plugin_uses is not None else set()
        self.plugin_helpers = plugin_helpers if plugin_helpers is not None else {}
        # Plugin API 1.4 standalone artifact capability for crate/executable.
        self.standalone = standalone

    def _standalone_capable(self) -> bool:
        """Whether this function may render plugin-lowered sites without PyO3."""
        return self.standalone is not None and self.standalone.is_capable(self.function.qualname)

    def render(self) -> str:
        if self.mode != "pyo3" and self.function.plugin_lowered and not self._standalone_capable():
            raise RustCodegenError(
                f"plugin-lowered function has no pure-Rust form: {self.function.qualname}"
            )
        # Register the module support OWNED by the plugin types in this
        # function's signature BEFORE the body renders, so a signature-only
        # accepted function (plugin-typed parameter/return, zero claims) still
        # emits the `use`/helper items its boundary conversion or named native
        # type references. Collecting first also means a helper that ALSO
        # arrives from a claim's LoweredExpr deduplicates to one item.
        # Standalone mode uses only profile-declared capability support.
        self._collect_signature_type_support()
        assigned_names = _assigned_names(self.function.body)
        # Only MATERIALIZED plugin types (with a boundary conversion) drive the
        # PyO3 boundary signature: they arrive as their PyO3 param type and
        # convert in the prologue, and return through the conversion expression.
        # RESIDENT plugin types (opaque, native-only — plugin API 1.3) have no
        # conversion: they render as their plain native Rust type in both the
        # ordinary function path and native-to-native calls, and such functions
        # are never PyO3-exported (see _render_pyo3_module).
        plugin_params = [
            param
            for param in self.function.params
            if isinstance(param.type, RxtPluginType) and not param.type.resident
        ]
        plugin_return = isinstance(self.function.return_type, RxtPluginType) and not (
            self.function.return_type.resident
        )
        rust_name = rust_identifier(native_function_name(self.function.qualname))
        prologue: list[str] = []
        if self.mode == "pyo3" and (plugin_params or plugin_return):
            # Plugin-typed boundary: the function takes the interpreter token
            # and a 'py lifetime; plugin params arrive as their PyO3 types and
            # convert to native values in the prologue; a plugin return leaves
            # as its PyO3 return type through the ReturnIR wrapping.
            param_parts = ["py: pyo3::Python<'py>"]
            for param in self.function.params:
                name = rust_identifier(param.name)
                if isinstance(param.type, RxtPluginType) and param.type.resident:
                    # A resident parameter has no boundary conversion; it is a
                    # native-only value passed by shared reference (`&T`). Such a
                    # function is never PyO3-exported, but it may still reach the
                    # pyo3 branch if it ALSO carries a materialized plugin param.
                    param_parts.append(f"{name}: &{param.type.native_rust}")
                elif isinstance(param.type, RxtPluginType):
                    # The prologue rebinds the converted native value under the
                    # same name (mut when reassigned); the signature parameter
                    # itself is consumed once and never needs mut.
                    param_parts.append(f"{name}: {param.type.param_rust}")
                    mut = "mut " if param.name in assigned_names else ""
                    prologue.append(
                        f"let {mut}{name} = {param.type.param_expr.format(param=name)};"
                    )
                else:
                    mut = "mut " if param.name in assigned_names else ""
                    param_parts.append(f"{mut}{name}: {rust_type(param.type)}")
            return_type = (
                self.function.return_type.return_rust
                if isinstance(self.function.return_type, RxtPluginType)
                else rust_type(self.function.return_type)
            )
            lines = [
                # `py` is part of the plugin conversion contract (return_expr
                # and param_expr may reference it); a function whose
                # conversions happen not to use it would otherwise warn.
                "#[allow(unused_variables)]",
                *(["#[pyfunction]"] if self.pyo3_exported else []),
                f"fn {rust_name}<'py>({', '.join(param_parts)}) -> PyResult<{return_type}> {{",
            ]
            lines.extend(f"{_indent(1)}{line}" for line in prologue)
        else:
            params = ", ".join(
                f"{'mut ' if param.name in assigned_names else ''}"
                f"{rust_identifier(param.name)}: {self._param_signature_rust(param)}"
                for param in self.function.params
            )
            return_type = rust_type(self.function.return_type)
            if self.mode == "pyo3":
                lines = [
                    *(["#[pyfunction]"] if self.pyo3_exported else []),
                    f"fn {rust_name}({params}) -> PyResult<{return_type}> {{",
                ]
            else:
                lines = [
                    f"pub fn {rust_name}({params}) -> Result<{return_type}, RextioError> {{",
                ]
        lines.extend(self.render_block(self.function.body, indent=1))
        if not _block_always_returns(self.function.body):
            lines.append(f"{_indent(1)}Ok({default_return(return_type)})")
        lines.append("}")
        return "\n".join(lines)

    def _collect_signature_type_support(self) -> None:
        """Merge module support owned by plugin types in this function's signature.

        Support is collected ONLY from plugin types that appear DIRECTLY as a
        parameter or the return type — an unused registered type contributes
        nothing. ``uses`` deduplicate through the module set; ``helpers``
        deduplicate by exact text through the insertion-ordered collector, so a
        type reused across parameter and return (or a helper that also arrives
        from a ``LoweredExpr``) is emitted exactly once. Ordering is
        deterministic: parameters in signature order, then the return type.

        In standalone (crate/executable) mode only profile-declared capability
        support is used — never host-extension PluginType uses/helpers.
        """
        signature_types: list[RxtType] = [param.type for param in self.function.params]
        signature_types.append(self.function.return_type)
        for signature_type in signature_types:
            if not isinstance(signature_type, RxtPluginType):
                continue
            if self.mode != "pyo3" and self.standalone is not None:
                plugin_id = signature_type.key.split("/", 1)[0]
                support = self.standalone.type_support(plugin_id, signature_type.key)
                if support is None:
                    raise RustCodegenError(
                        f"plugin type {signature_type.key!r} is not covered by the "
                        f"resolved standalone capability for {self.function.qualname}"
                    )
                self.plugin_uses.update(support.uses)
                for helper in support.helpers:
                    self.plugin_helpers.setdefault(helper)
                continue
            self.plugin_uses.update(signature_type.uses)
            for helper in signature_type.helpers:
                self.plugin_helpers.setdefault(helper)

    def render_block(self, block: BlockIR, indent: int) -> list[str]:
        lines: list[str] = []
        for statement in block.statements:
            lines.extend(self.render_statement(statement, indent))
        return lines

    def render_statement(self, statement: StatementIR, indent: int) -> list[str]:
        prefix = _indent(indent)
        if isinstance(statement, AssignIR):
            lines = self.named_expr_prelude(statement.value, indent)
            target = statement.target.id  # original name for bookkeeping
            emit = rust_identifier(target)  # escaped name for emission
            target_type = statement.target_type or self.infer_expr_type(statement.value)
            value = strip_expr_if_safe(
                statement.value,
                self.render_assignment_value(statement.value, target_type),
            )
            if target_type is not None:
                self.variable_types[target] = target_type
            if target in self.maybe_bound_types:
                return [*lines, f"{prefix}{emit} = Some({value});"]
            if target in self.declared:
                return [*lines, f"{prefix}{emit} = {value};"]
            self.declared.add(target)
            if statement.target_type is not None and _needs_local_type_annotation(
                statement.value, statement.target_type
            ):
                return [
                    *lines,
                    f"{prefix}let mut {emit}: {rust_type(statement.target_type)} = {value};",
                ]
            return [*lines, f"{prefix}let mut {emit} = {value};"]
        if isinstance(statement, DictSetIR):
            # Python evaluates the RHS value before the subscript key for
            # `d[k] = v`; bind the value first to preserve that order.
            value_tmp = self.next_temp("__rextio_value")
            lines = [
                *self.named_expr_prelude(statement.value, indent),
                f"{prefix}let {value_tmp} = "
                f"{strip_wrapping_parens(self.render_call_arg(statement.value))};",
                *self.named_expr_prelude(statement.key, indent),
            ]
            self.declared.add(statement.target.id)
            return [
                *lines,
                f"{prefix}{rust_identifier(statement.target.id)}.insert("
                f"{strip_wrapping_parens(self.render_call_arg(statement.key))}, {value_tmp});",
            ]
        if isinstance(statement, AppendIR):
            lines = self.named_expr_prelude(statement.value, indent)
            return [
                *lines,
                f"{prefix}{rust_identifier(statement.target.id)}.push("
                f"{strip_wrapping_parens(self.render_call_arg(statement.value))});",
            ]
        if isinstance(statement, EffectCallIR):
            lines = self.named_expr_prelude(statement.call, indent)
            return [*lines, f"{prefix}{self.render_call(statement.call)};"]
        if isinstance(statement, BreakIR):
            return [f"{prefix}break;"]
        if isinstance(statement, ContinueIR):
            return [f"{prefix}continue;"]
        if isinstance(statement, ReturnIR):
            if statement.value is None:
                # A bare `return` is Python `return None`. In an `Optional[T]`
                # function that is `Ok(None)` (the `Option` is `None`), not
                # `Ok(())` which would be a unit value and fail to compile against
                # the `Option<T>` return type.
                if isinstance(self.function.return_type, RxtOptional):
                    return [f"{prefix}return Ok(None);"]
                return [f"{prefix}return Ok(());"]
            lines = self.named_expr_prelude(statement.value, indent)
            value = strip_expr_if_safe(
                statement.value,
                self.render_expr_with_expected(statement.value, self.function.return_type),
            )
            if (
                self.mode == "pyo3"
                and isinstance(self.function.return_type, RxtPluginType)
                and not self.function.return_type.resident
            ):
                # A materialized plugin-typed return crosses the boundary through
                # the plugin's conversion expression (owned, newly allocated). A
                # resident return has no conversion: it is an internal native-only
                # value returned as-is to a native caller.
                value = self.function.return_type.return_expr.format(value=value)
            return [*lines, f"{prefix}return Ok({value});"]
        if isinstance(statement, IfIR):
            lines = self.named_expr_prelude(statement.condition, indent)
            condition = strip_wrapping_parens(self.render_expr(statement.condition))
            lines.append(f"{prefix}if {condition} {{")
            lines.extend(self.render_block(statement.body, indent + 1))
            if statement.orelse.statements:
                lines.append(f"{prefix}}} else {{")
                lines.extend(self.render_block(statement.orelse, indent + 1))
            lines.append(f"{prefix}}}")
            return lines
        if isinstance(statement, ForIR):
            lines = self.named_expr_prelude(statement.iterable, indent)
            iterable = self.render_iterable(statement.iterable)
            lines = [
                *lines,
                f"{prefix}for {self.render_loop_target(statement.target)} in {iterable} {{",
            ]
            self.declared.update(target_names(statement.target))
            # Bind the loop variable's type for the body so type-directed
            # rendering (e.g. checked integer arithmetic on `acc += x`) sees the
            # element type, mirroring the comprehension-generator path.
            self.bind_target_types(statement.target, self.iterable_target_types(statement.iterable))
            lines.extend(self.render_block(statement.body, indent + 1))
            lines.append(f"{prefix}}}")
            return lines
        if isinstance(statement, WhileIR):
            lines = self.named_expr_prelude(statement.condition, indent)
            condition = strip_wrapping_parens(self.render_expr(statement.condition))
            lines.append(f"{prefix}while {condition} {{")
            lines.extend(self.render_block(statement.body, indent + 1))
            lines.append(f"{prefix}}}")
            return lines
        if isinstance(statement, TryIR):
            return self.render_try(statement, indent)
        raise RustCodegenError(f"unsupported statement IR: {type(statement).__name__}")

    def render_try(self, statement: TryIR, indent: int) -> list[str]:
        """Render a ``try``/``except``/``finally`` statement.

        Python ``try`` semantics are modelled with immediately-invoked closures:
        the inner closure runs the ``try`` body (``?`` turns a Python exception
        into an ``Err``); a ``match`` dispatches to the first ``except`` handler
        whose built-in type matches (preserving Python's top-to-bottom order),
        re-raising otherwise. The whole try/except is itself a closure, so the
        ``finally`` body runs on every path before any pending error is
        propagated with ``?`` — matching Python's "finally always runs, then the
        exception continues" rule. The analyzer guarantees the restricted subset
        this relies on (built-in handlers only, no ``return`` and no
        ``break``/``continue`` targeting a loop outside the block, and no
        non-comprehension variable first-bound inside a block).
        """
        if self.mode != "pyo3":
            raise RustCodegenError(
                "native try/except is only supported in the pyo3 backend, "
                "not the importable Rust crate"
            )
        prefix = _indent(indent)
        outcome = self.next_temp("__rextio_try")
        err = f"{outcome}_err"
        inner = f"{outcome}_body"
        lines = [f"{prefix}let {outcome}: PyResult<()> = (|| -> PyResult<()> {{"]
        lines.append(f"{_indent(indent + 1)}let {inner}: PyResult<()> = (|| -> PyResult<()> {{")
        lines.extend(self.render_block(statement.body, indent + 2))
        lines.append(f"{_indent(indent + 2)}Ok(())")
        lines.append(f"{_indent(indent + 1)}}})();")
        lines.append(f"{_indent(indent + 1)}match {inner} {{")
        lines.append(f"{_indent(indent + 2)}Ok(()) => Ok(()),")
        lines.append(f"{_indent(indent + 2)}Err({err}) => {{")
        if statement.handlers:
            for position, handler in enumerate(statement.handlers):
                pyo3_exception = BUILTIN_EXCEPTION_TO_PYO3[handler.exception]
                guard = f"Python::attach(|py| {err}.is_instance_of::<{pyo3_exception}>(py))"
                keyword = "if" if position == 0 else "} else if"
                lines.append(f"{_indent(indent + 3)}{keyword} {guard} {{")
                lines.extend(self.render_block(handler.body, indent + 4))
                lines.append(f"{_indent(indent + 4)}Ok(())")
            lines.append(f"{_indent(indent + 3)}}} else {{")
            lines.append(f"{_indent(indent + 4)}Err({err})")
            lines.append(f"{_indent(indent + 3)}}}")
        else:
            lines.append(f"{_indent(indent + 3)}Err({err})")
        lines.append(f"{_indent(indent + 2)}}}")
        lines.append(f"{_indent(indent + 1)}}}")
        lines.append(f"{prefix}}})();")
        lines.extend(self.render_block(statement.finalbody, indent))
        lines.append(f"{prefix}{outcome}?;")
        return lines

    def render_iterable(self, expr: ExprIR) -> str:
        if isinstance(expr, NameIR):
            return f"{rust_identifier(expr.id)}.iter().cloned()"
        if isinstance(expr, CallIR) and expr.function == "enumerate" and len(expr.args) == 1:
            return (
                f"{self.render_expr(expr.args[0])}.iter().cloned().enumerate()"
                ".map(|(i, value)| (i as i64, value))"
            )
        if isinstance(expr, CallIR) and expr.function == "zip" and len(expr.args) == 2:
            return (
                f"{self.render_expr(expr.args[0])}.iter().cloned()"
                f".zip({self.render_expr(expr.args[1])}.iter().cloned())"
            )
        if isinstance(expr, CallIR) and expr.function == "reversed" and len(expr.args) == 1:
            return f"{self.render_expr(expr.args[0])}.iter().rev().cloned()"
        if (
            isinstance(expr, CallIR)
            and expr.function == "range"
            and len(expr.args) == 1
            and isinstance(expr.args[0], CallIR)
            and expr.args[0].function == "len"
            and len(expr.args[0].args) == 1
        ):
            # `range(len(x))` lowers the bound inline; mirror the value-position
            # `len` rule so a `str` counts code points (`.chars().count()`), not
            # the UTF-8 byte length `String::len` returns.
            inner = expr.args[0].args[0]
            if isinstance(self.infer_expr_type(inner), RxtStr):
                return f"0..({self.render_expr(inner)}.chars().count() as i64)"
            return f"0..({self.render_expr(inner)}.len() as i64)"
        if isinstance(expr, CallIR) and expr.function == "range" and len(expr.args) == 1:
            return f"0..{self.render_expr(expr.args[0])}"
        if isinstance(expr, CallIR) and expr.function == "range" and len(expr.args) == 2:
            return f"{self.render_expr(expr.args[0])}..{self.render_expr(expr.args[1])}"
        if isinstance(expr, CallIR) and expr.function == "range" and len(expr.args) == 3:
            return (
                f"({self.render_expr(expr.args[0])}..{self.render_expr(expr.args[1])})"
                f".step_by({strip_wrapping_parens(self.render_expr(expr.args[2]))} as usize)"
            )
        raise RustCodegenError("unsupported for-loop iterable")

    def render_loop_target(self, target: TargetIR) -> str:
        if isinstance(target, NameIR):
            return rust_identifier(target.id)
        if isinstance(target, TupleTargetIR):
            return f"({', '.join(rust_identifier(item.id) for item in target.items)})"
        raise RustCodegenError(f"unsupported loop target IR: {type(target).__name__}")

    def render_expr(self, expr: ExprIR) -> str:
        if isinstance(expr, LiteralIR):
            return render_literal(expr.value)
        if isinstance(expr, NameIR):
            if expr.id in self.maybe_bound_types:
                return self.render_maybe_bound_name(expr.id)
            return rust_identifier(expr.id)
        if isinstance(expr, ListIR):
            return f"vec![{', '.join(self.render_owned_expr(item) for item in expr.items)}]"
        if isinstance(expr, ListComprehensionIR):
            return self.render_list_comprehension(expr)
        if isinstance(expr, TupleIR):
            if len(expr.items) == 1:
                return f"({self.render_owned_expr(expr.items[0])},)"
            return f"({', '.join(self.render_owned_expr(item) for item in expr.items)})"
        if isinstance(expr, DictIR):
            if not expr.items:
                return "HashMap::new()"
            lines = ["{"]
            lines.append("    let mut map = HashMap::new();")
            for key, value in expr.items:
                lines.append(
                    f"    map.insert({strip_wrapping_parens(self.render_call_arg(key))}, "
                    f"{strip_wrapping_parens(self.render_owned_expr(value))});"
                )
            lines.append("    map")
            lines.append("}")
            return "\n".join(lines)
        if isinstance(expr, DictComprehensionIR):
            return self.render_dict_comprehension(expr)
        if isinstance(expr, SetIR):
            if not expr.items:
                return "HashSet::new()"
            lines = ["{"]
            lines.append("    let mut set = HashSet::new();")
            for item in expr.items:
                lines.append(
                    f"    set.insert({strip_wrapping_parens(self.render_call_arg(item))});"
                )
            lines.append("    set")
            lines.append("}")
            return "\n".join(lines)
        if isinstance(expr, SetComprehensionIR):
            return self.render_set_comprehension(expr)
        if isinstance(expr, BinaryOpIR):
            if expr.claim is not None:
                return self.render_plugin_claim(expr.claim, [expr.left, expr.right])
            checked = self.render_checked_int_binop(expr)
            if checked is None:
                checked = self.render_checked_float_binop(expr)
            if checked is not None:
                return checked
            op = {"and": "&&", "or": "||"}.get(expr.op, expr.op)
            return f"({self.render_expr(expr.left)} {op} {self.render_expr(expr.right)})"
        if isinstance(expr, UnaryOpIR):
            checked = self.render_checked_int_neg(expr)
            if checked is not None:
                return checked
            op = "!" if expr.op == "not" else expr.op
            return f"({op}{self.render_expr(expr.value)})"
        if isinstance(expr, CompareIR):
            if expr.claim is not None:
                return self.render_plugin_claim(
                    expr.claim,
                    [expr.left, *expr.comparators],
                )
            return self.render_compare(expr)
        if isinstance(expr, CallIR):
            return self.render_call(expr)
        if isinstance(expr, IndexIR):
            return self.render_index_expr(expr)
        if isinstance(expr, NamedExprIR):
            return self.render_named_expr(expr)
        raise RustCodegenError(f"unsupported expression IR: {type(expr).__name__}")

    def render_list_comprehension(self, expr: ListComprehensionIR) -> str:
        target = self.next_temp("__rextio_list")
        lines = ["{"]
        lines.append(f"    let mut {target} = Vec::new();")
        lines.extend(
            self.render_comprehension_generators(
                expr.generators,
                1,
                lambda indent: [
                    f"{_indent(indent)}{target}.push("
                    f"{strip_wrapping_parens(self.render_call_arg(expr.item))});"
                ],
            )
        )
        lines.append(f"    {target}")
        lines.append("}")
        return "\n".join(lines)

    def render_dict_comprehension(self, expr: DictComprehensionIR) -> str:
        target = self.next_temp("__rextio_dict")
        lines = ["{"]
        lines.append(f"    let mut {target} = HashMap::new();")
        lines.extend(
            self.render_comprehension_generators(
                expr.generators,
                1,
                lambda indent: [
                    f"{_indent(indent)}{target}.insert("
                    f"{strip_wrapping_parens(self.render_call_arg(expr.key))}, "
                    f"{strip_wrapping_parens(self.render_call_arg(expr.value))});"
                ],
            )
        )
        lines.append(f"    {target}")
        lines.append("}")
        return "\n".join(lines)

    def render_set_comprehension(self, expr: SetComprehensionIR) -> str:
        target = self.next_temp("__rextio_set")
        lines = ["{"]
        lines.append(f"    let mut {target} = HashSet::new();")
        lines.extend(
            self.render_comprehension_generators(
                expr.generators,
                1,
                lambda indent: [
                    f"{_indent(indent)}{target}.insert("
                    f"{strip_wrapping_parens(self.render_call_arg(expr.item))});"
                ],
            )
        )
        lines.append(f"    {target}")
        lines.append("}")
        return "\n".join(lines)

    def render_comprehension_generators(
        self,
        generators: list[ComprehensionGeneratorIR],
        index: int,
        render_leaf: Callable[[int], list[str]],
    ) -> list[str]:
        if index > len(generators):
            return render_leaf(index)
        generator = generators[index - 1]
        prefix = _indent(index)
        iterable = self.render_iterable(generator.iterable)
        lines = [f"{prefix}for {self.render_loop_target(generator.target)} in {iterable} {{"]
        saved_types = dict(self.variable_types)
        self.bind_target_types(generator.target, self.iterable_target_types(generator.iterable))
        if generator.conditions:
            condition = " && ".join(
                strip_wrapping_parens(self.render_expr(condition))
                for condition in generator.conditions
            )
            lines.append(f"{_indent(index + 1)}if {condition} {{")
            lines.extend(self.render_comprehension_generators(generators, index + 1, render_leaf))
            lines.append(f"{_indent(index + 1)}}}")
        else:
            lines.extend(self.render_comprehension_generators(generators, index + 1, render_leaf))
        self.variable_types = saved_types
        lines.append(f"{prefix}}}")
        return lines

    def iterable_target_types(self, expr: ExprIR) -> list[RxtType]:
        if isinstance(expr, CallIR) and expr.function == "enumerate" and len(expr.args) == 1:
            item_type = self.iterable_item_type(expr.args[0])
            return [RxtInt(), item_type] if item_type is not None else []
        if isinstance(expr, CallIR) and expr.function == "zip" and len(expr.args) == 2:
            item_types = [self.iterable_item_type(arg) for arg in expr.args]
            return [item for item in item_types if item is not None]
        if isinstance(expr, CallIR) and expr.function == "range":
            return [RxtInt()]
        item_type = self.iterable_item_type(expr)
        return [item_type] if item_type is not None else []

    def iterable_item_type(self, expr: ExprIR) -> RxtType | None:
        value_type = self.infer_expr_type(expr)
        if isinstance(value_type, (RxtList, RxtSet)):
            return value_type.item_type
        return None

    def bind_target_types(self, target: TargetIR, item_types: list[RxtType]) -> None:
        if isinstance(target, NameIR) and len(item_types) == 1:
            self.variable_types[target.id] = item_types[0]
            return
        if isinstance(target, TupleTargetIR) and len(target.items) == len(item_types):
            for item, item_type in zip(target.items, item_types, strict=True):
                self.variable_types[item.id] = item_type

    def render_named_expr(self, expr: NamedExprIR) -> str:
        target = expr.target.id  # original name for bookkeeping
        emit = rust_identifier(target)  # escaped name for emission
        value = strip_expr_if_safe(
            expr.value,
            self.render_call_arg(expr.value),
        )
        if target in self.maybe_bound_types:
            return f"{{ {emit} = Some({value}); {self.render_maybe_bound_name(target)} }}"
        return f"{{ {emit} = {value}; {emit}.clone() }}"

    def render_maybe_bound_name(self, name: str) -> str:
        # The diagnostic message keeps the original Python name; the emitted Rust
        # identifier is escaped (e.g. a keyword name -> `r#name`).
        message = rust_string_literal(f"local variable '{name}' referenced before assignment")
        return (
            f"{rust_identifier(name)}.clone().ok_or_else(|| "
            f"{self.error_new(message, kind='unbound')})?"
        )

    def error_new(self, message: str, *, kind: str = "value") -> str:
        if self.mode == "pyo3":
            exception = {
                "key": "PyKeyError",
                "runtime": "PyRuntimeError",
                "unbound": "PyUnboundLocalError",
                "value": "PyValueError",
            }.get(kind, "PyValueError")
            return f"pyo3::exceptions::{exception}::new_err({message})"
        return f'RextioError::new("{_crate_exception_name(kind)}", {message})'

    def error_from_to_string(self, value: str, *, kind: str = "value") -> str:
        return self.error_new(f"{value}.to_string()", kind=kind)

    def map_err_to_error(self, *, kind: str = "value") -> str:
        if self.mode == "pyo3":
            exception = {
                "runtime": "PyRuntimeError",
                "value": "PyValueError",
            }.get(kind, "PyValueError")
            return f".map_err(|err| pyo3::exceptions::{exception}::new_err(err.to_string()))?"
        return (
            f'.map_err(|err| RextioError::new("{_crate_exception_name(kind)}", err.to_string()))?'
        )

    def next_temp(self, prefix: str) -> str:
        self.temp_index += 1
        return f"{prefix}_{self.temp_index}"

    def named_expr_prelude(self, expr: ExprIR, indent: int) -> list[str]:
        bindings = self.collect_named_expr_bindings(expr)
        lines: list[str] = []
        for name, binding_type in bindings.items():
            if name in self.declared:
                self.variable_types[name] = self.variable_types.get(name, binding_type)
                continue
            self.declared.add(name)
            self.variable_types[name] = binding_type
            self.maybe_bound_types[name] = binding_type
            lines.append(
                f"{_indent(indent)}let mut {rust_identifier(name)}: Option<{rust_type(binding_type)}> = None;"
            )
        return lines

    def collect_named_expr_bindings(self, expr: ExprIR) -> dict[str, RxtType]:
        bindings: dict[str, RxtType] = {}
        scope = dict(self.variable_types)
        self.collect_named_expr_bindings_in_expr(expr, scope, scope, bindings)
        return bindings

    def collect_named_expr_bindings_in_expr(
        self,
        expr: ExprIR,
        scope: dict[str, RxtType],
        binding_scope: dict[str, RxtType],
        bindings: dict[str, RxtType],
    ) -> None:
        if isinstance(expr, NamedExprIR):
            self.collect_named_expr_bindings_in_expr(expr.value, scope, binding_scope, bindings)
            value_type = self.infer_expr_type_in_scope(expr.value, scope)
            if value_type is None:
                raise RustCodegenError("cannot infer assignment expression type")
            bindings.setdefault(expr.target.id, value_type)
            scope[expr.target.id] = value_type
            binding_scope[expr.target.id] = value_type
            return
        if isinstance(expr, BinaryOpIR):
            self.collect_named_expr_bindings_in_expr(expr.left, scope, binding_scope, bindings)
            self.collect_named_expr_bindings_in_expr(expr.right, scope, binding_scope, bindings)
            return
        if isinstance(expr, UnaryOpIR):
            self.collect_named_expr_bindings_in_expr(expr.value, scope, binding_scope, bindings)
            return
        if isinstance(expr, CompareIR):
            self.collect_named_expr_bindings_in_expr(expr.left, scope, binding_scope, bindings)
            for comparator in expr.comparators:
                self.collect_named_expr_bindings_in_expr(comparator, scope, binding_scope, bindings)
            return
        if isinstance(expr, CallIR):
            for arg in expr.args:
                self.collect_named_expr_bindings_in_expr(arg, scope, binding_scope, bindings)
            return
        if isinstance(expr, IndexIR):
            self.collect_named_expr_bindings_in_expr(expr.value, scope, binding_scope, bindings)
            self.collect_named_expr_bindings_in_expr(expr.index, scope, binding_scope, bindings)
            return
        if isinstance(expr, ListIR):
            for item in expr.items:
                self.collect_named_expr_bindings_in_expr(item, scope, binding_scope, bindings)
            return
        if isinstance(expr, TupleIR):
            for item in expr.items:
                self.collect_named_expr_bindings_in_expr(item, scope, binding_scope, bindings)
            return
        if isinstance(expr, DictIR):
            for key, value in expr.items:
                self.collect_named_expr_bindings_in_expr(key, scope, binding_scope, bindings)
                self.collect_named_expr_bindings_in_expr(value, scope, binding_scope, bindings)
            return
        if isinstance(expr, SetIR):
            for item in expr.items:
                self.collect_named_expr_bindings_in_expr(item, scope, binding_scope, bindings)
            return
        if isinstance(expr, ListComprehensionIR):
            self.collect_named_expr_bindings_in_comprehension(
                expr.generators,
                [expr.item],
                scope,
                binding_scope,
                bindings,
            )
            return
        if isinstance(expr, DictComprehensionIR):
            self.collect_named_expr_bindings_in_comprehension(
                expr.generators,
                [expr.key, expr.value],
                scope,
                binding_scope,
                bindings,
            )
            return
        if isinstance(expr, SetComprehensionIR):
            self.collect_named_expr_bindings_in_comprehension(
                expr.generators,
                [expr.item],
                scope,
                binding_scope,
                bindings,
            )

    def collect_named_expr_bindings_in_comprehension(
        self,
        generators: list[ComprehensionGeneratorIR],
        result_exprs: list[ExprIR],
        scope: dict[str, RxtType],
        binding_scope: dict[str, RxtType],
        bindings: dict[str, RxtType],
    ) -> None:
        comp_scope = dict(scope)
        for generator in generators:
            self.collect_named_expr_bindings_in_expr(
                generator.iterable,
                comp_scope,
                binding_scope,
                bindings,
            )
            item_types = self.iterable_target_types_in_scope(generator.iterable, comp_scope)
            self.bind_target_types_to_scope(generator.target, item_types, comp_scope)
            for condition in generator.conditions:
                self.collect_named_expr_bindings_in_expr(
                    condition,
                    comp_scope,
                    binding_scope,
                    bindings,
                )
        for result_expr in result_exprs:
            self.collect_named_expr_bindings_in_expr(
                result_expr,
                comp_scope,
                binding_scope,
                bindings,
            )

    def infer_expr_type_in_scope(
        self,
        expr: ExprIR,
        scope: dict[str, RxtType],
    ) -> RxtType | None:
        saved_types = self.variable_types
        self.variable_types = scope
        try:
            return self.infer_expr_type(expr)
        finally:
            self.variable_types = saved_types

    def iterable_target_types_in_scope(
        self,
        expr: ExprIR,
        scope: dict[str, RxtType],
    ) -> list[RxtType]:
        saved_types = self.variable_types
        self.variable_types = scope
        try:
            return self.iterable_target_types(expr)
        finally:
            self.variable_types = saved_types

    def bind_target_types_to_scope(
        self,
        target: TargetIR,
        item_types: list[RxtType],
        scope: dict[str, RxtType],
    ) -> None:
        if isinstance(target, NameIR) and len(item_types) == 1:
            scope[target.id] = item_types[0]
            return
        if isinstance(target, TupleTargetIR) and len(target.items) == len(item_types):
            for item, item_type in zip(target.items, item_types, strict=True):
                scope[item.id] = item_type

    def _index_error_expr(self) -> str:
        """Mode-aware constructor expression for a Python ``IndexError``."""
        if self.mode == "pyo3":
            return 'pyo3::exceptions::PyIndexError::new_err("list index out of range")'
        return 'RextioError::new("IndexError", "list index out of range")'

    def _key_error_expr(self, key: str) -> str:
        """Mode-aware constructor expression for a Python ``KeyError``."""
        if self.mode == "pyo3":
            return f"pyo3::exceptions::PyKeyError::new_err({key}.clone())"
        return f'RextioError::new("KeyError", format!("key not found: {{:?}}", {key}))'

    def render_checked_int_binop(self, expr: BinaryOpIR) -> str | None:
        """Render an i64 ``+``/``-``/``*``/``%`` as checked arithmetic, or ``None``.

        Returns ``None`` when the operator is not overflow-prone integer
        arithmetic (the caller then falls back to the plain rendering). When both
        operands are ``int``, the operation is lowered to a ``__rextio_checked_*``
        helper that raises ``OverflowError`` / ``ZeroDivisionError`` (PyO3) or
        returns ``RextioError`` (crate) instead of wrapping or panicking. Python
        ``int`` is arbitrary precision, so an i64 op that would wrap/overflow is an
        ``OverflowError`` (catchable via ``except Exception``) rather than the
        previous ``overflow-checks`` panic, which PyO3 surfaces as an uncatchable
        ``PanicException`` (a ``BaseException``); ``a % 0`` is a ``ZeroDivisionError``.
        The helper is a plain function call, so an operand sub-expression
        containing ``?`` propagates in function scope with no closure to leak into.
        """
        name = {"+": "add", "-": "sub", "*": "mul", "%": "rem"}.get(expr.op)
        if name is None:
            return None
        left_type = self.infer_expr_type(expr.left)
        right_type = self.infer_expr_type(expr.right)
        if not (isinstance(left_type, RxtInt) and isinstance(right_type, RxtInt)):
            return None
        left = strip_wrapping_parens(self.render_expr(expr.left))
        right = strip_wrapping_parens(self.render_expr(expr.right))
        self.used_helpers.add(name)
        return f"__rextio_checked_{name}({left}, {right})?"

    def render_checked_int_neg(self, expr: UnaryOpIR) -> str | None:
        """Render an i64 unary ``-`` as checked negation, or ``None``.

        ``-i64::MIN`` overflows (Python ``int`` is arbitrary precision, so
        ``-(-2**63) == 2**63``); route int negation through ``__rextio_checked_neg``
        so it raises ``OverflowError`` instead of an uncatchable panic.
        """
        if expr.op != "-":
            return None
        if not isinstance(self.infer_expr_type(expr.value), RxtInt):
            return None
        if isinstance(expr.value, LiteralIR) and expr.value.value == 2**63:
            return "i64::MIN"
        value = strip_wrapping_parens(self.render_expr(expr.value))
        self.used_helpers.add("neg")
        return f"__rextio_checked_neg({value})?"

    def render_checked_float_binop(self, expr: BinaryOpIR) -> str | None:
        """Render an f64 ``/`` or ``%`` with Python semantics, or ``None``.

        Python raises ``ZeroDivisionError`` for float division/modulo by zero
        (Rust returns inf/NaN), and float ``%`` is floored like the integer case
        (Rust ``%`` is truncated). Route both through helpers so the divide-by-zero
        is catchable and the modulo sign matches Python.
        """
        name = {"/": "fdiv", "%": "frem"}.get(expr.op)
        if name is None:
            return None
        left_type = self.infer_expr_type(expr.left)
        right_type = self.infer_expr_type(expr.right)
        if not (isinstance(left_type, RxtFloat) and isinstance(right_type, RxtFloat)):
            return None
        left = strip_wrapping_parens(self.render_expr(expr.left))
        right = strip_wrapping_parens(self.render_expr(expr.right))
        self.used_helpers.add(name)
        return f"__rextio_checked_{name}({left}, {right})?"

    def render_index_expr(self, expr: IndexIR) -> str:
        value_type = self.infer_expr_type(expr.value)
        if isinstance(value_type, RxtTuple):
            tuple_index = literal_int(expr.index)
            if tuple_index is None or tuple_index < 0 or tuple_index >= len(value_type.item_types):
                raise RustCodegenError("tuple index must be an in-range literal")
            return f"{self.render_expr(expr.value)}.{tuple_index}.clone()"
        if isinstance(value_type, RxtDict):
            mapping = self.next_temp("__rextio_map")
            key_tmp = self.next_temp("__rextio_key")
            key = strip_wrapping_parens(self.render_expr(expr.index))
            # Bind value and key to temporaries before the error closure. The key
            # expression may itself contain `?` (e.g. `m[xs[i]]`); evaluating it in
            # a let-binding keeps the `?` in function scope instead of leaking into
            # the `ok_or_else` closure body, which would not compile.
            return (
                f"{{ let {mapping} = &{self.render_expr(expr.value)}; "
                f"let {key_tmp} = {key}; "
                f"{mapping}.get(&{key_tmp}).cloned()"
                f".ok_or_else(|| {self._key_error_expr(key_tmp)})? }}"
            )
        # Sequence indexing preserves Python semantics:
        #   * a negative index counts from the end (`xs[-1]` is the last item),
        #   * an out-of-range index (after normalization) raises IndexError
        #     instead of panicking via an unchecked `[]`.
        # The sequence and index are bound to temporaries so neither sub-expression
        # is evaluated twice. The index is cast to i64 (absorbing any integer
        # operand type); negative normalization uses checked_add (cannot overflow
        # by construction, but this avoids any debug-build overflow panic and makes
        # it explicit). Bounds are checked in the i64 domain, so the final
        # `as usize` only runs for an in-range index — correct on every target
        # width (no reliance on usize truncation). `len() as i64` is exact because a
        # sequence length never exceeds `isize::MAX <= i64::MAX`.
        seq = self.next_temp("__rextio_seq")
        index = self.next_temp("__rextio_index")
        length = self.next_temp("__rextio_len")
        bound = self.next_temp("__rextio_bound")
        return (
            f"{{ let {seq} = &{self.render_expr(expr.value)}; "
            f"let {length} = {seq}.len() as i64; "
            f"let {index} = ({strip_wrapping_parens(self.render_expr(expr.index))}) as i64; "
            f"let {index} = if {index} < 0 {{ {index}.checked_add({length}) }} "
            f"else {{ Some({index}) }}; "
            f"(match {index} {{ "
            f"Some({bound}) if {bound} >= 0 && {bound} < {length} => "
            f"{seq}.get({bound} as usize).cloned(), "
            f"_ => None }})"
            f".ok_or_else(|| {self._index_error_expr()})? }}"
        )

    def render_compare(self, expr: CompareIR) -> str:
        if len(expr.ops) != len(expr.comparators):
            raise RustCodegenError("invalid comparison IR")
        left = expr.left
        parts: list[str] = []
        for op, comparator in zip(expr.ops, expr.comparators, strict=True):
            parts.append(f"({self.render_expr(left)} {op} {self.render_expr(comparator)})")
            left = comparator
        # A chained comparison `a < b < c` lowers to `(a < b) && (b < c)`, which
        # renders the shared middle operand `b` twice and so evaluates it twice
        # when the first comparison is true (CPython evaluates it once). Rust `&&`
        # preserves CPython's left-to-right short-circuit exactly, so for a pure,
        # deterministic operand the second evaluation yields the same value and
        # the only cost is redundant computation. The analyzer rejects any chained
        # comparison whose middle operand contains a call (see
        # `_validate_compare_types`), which is the only way a non-deterministic or
        # side-effecting operand could reach here, so the doubled evaluation is
        # always divergence-free by construction.
        return " && ".join(parts)

    def render_plugin_claim(
        self,
        claim: PluginClaimIR,
        operand_exprs: list[ExprIR],
        receiver_expr: ExprIR | None = None,
    ) -> str:
        """Render a plugin-claimed site by delegating to the plugin's ``lower()``.

        Core renders operand sub-expressions per ``claim.operand_mode`` and
        hands them to the claiming provider through a :class:`LoweringContext`;
        the plugin returns one Rust expression plus its support items
        (docs/specs/plugin-lowering.md section 3).

        * ``direct`` (default) — only classic direct child operands; never
          computes ``leaf_operands`` (no nested-fusion side effects for 1.1).
        * ``leaves`` — only non-literal leaves by LTR ``leaf_index``; never
          renders direct children (no nested plugin lower / intermediate
          arrays). Fail closed if the tree cannot be aligned safely.

        Codegen also enforces provider API version: ``api_version < 1.2``
        providers always receive a legacy :class:`ClaimSite` (empty 1.2
        metadata), never get ``leaf_operands``, and cannot use leaves-mode IR.
        """
        if self.mode != "pyo3" and not self._standalone_capable():
            raise RustCodegenError(
                f"plugin-lowered function has no pure-Rust form: {self.function.qualname}"
            )
        provider = self.plugin_providers.get(claim.plugin_id)
        if provider is None:
            raise RustCodegenError(
                f"no active lowering provider for plugin {claim.plugin_id!r} "
                f"(claimed site {claim.target!r} in {self.function.qualname})"
            )
        mode = claim.operand_mode
        if mode not in {"direct", "leaves"}:
            raise RustCodegenError(
                f"plugin {claim.plugin_id!r} claim on {claim.target!r} in "
                f"{self.function.qualname} has unsupported operand_mode {mode!r}; "
                "expected 'direct' or 'leaves'"
            )
        provider_api = str(getattr(provider, "api_version", "1.0") or "1.0")
        if claim.kind == "compare" and not _plugin_api_at_least(provider_api, 1, 5):
            # Defense in depth against stale/malformed IR or a provider version
            # drifting between analysis and codegen. Compare sites were not part
            # of the lowering contract before API 1.5 and must never be projected
            # onto an older provider merely because an IR claim exists.
            raise RustCodegenError(
                f"plugin {claim.plugin_id!r} (api_version {provider_api!r}) "
                f"cannot lower compare site {claim.target!r} in "
                f"{self.function.qualname}; compare lowering requires "
                "api_version >= 1.5"
            )
        is_api_12 = _plugin_api_at_least(provider_api, 1, 2)
        if not is_api_12:
            # Defense in depth: even if analysis projected 1.2 fields onto IR,
            # a legacy provider must not observe them or trigger leaf rendering.
            if mode == "leaves":
                raise RustCodegenError(
                    f"plugin {claim.plugin_id!r} (api_version {provider_api!r}) "
                    f"cannot lower site {claim.target!r} with operand_mode='leaves'; "
                    "leaves mode requires api_version >= 1.2"
                )
            operands = tuple(self._render_plugin_operand(arg) for arg in operand_exprs)
            leaf_operands: tuple[str, ...] = ()
            site = ClaimSite(
                kind=claim.kind,
                target=claim.target,
                operand_types=claim.operand_types,
                file_path="",
                line=0,
                column=0,
                rule_id=claim.rule_id,
                result_type=claim.result_type,
            )
        elif mode == "leaves":
            leaf_result = self._render_fusion_leaf_operands(claim.expression, operand_exprs)
            if leaf_result is None:
                raise RustCodegenError(
                    f"plugin {claim.plugin_id!r} claimed site {claim.target!r} with "
                    "operand_mode='leaves' but leaf operands could not be collected "
                    f"safely in {self.function.qualname}"
                )
            leaf_operands = leaf_result  # may be () for all-literal leaves-safe trees
            operands = ()
            site = ClaimSite(
                kind=claim.kind,
                target=claim.target,
                operand_types=claim.operand_types,
                file_path="",
                line=0,
                column=0,
                rule_id=claim.rule_id,
                result_type=claim.result_type,
                operand_literals=tuple(claim.operand_literals),
                keywords=tuple(claim.keywords),
                expression=claim.expression,
            )
        else:
            operands = tuple(self._render_plugin_operand(arg) for arg in operand_exprs)
            leaf_operands = ()
            site = ClaimSite(
                kind=claim.kind,
                target=claim.target,
                operand_types=claim.operand_types,
                file_path="",
                line=0,
                column=0,
                rule_id=claim.rule_id,
                result_type=claim.result_type,
                operand_literals=tuple(claim.operand_literals),
                keywords=tuple(claim.keywords),
                expression=claim.expression,
            )
        # Plugin API 1.3 receiver/callable metadata: only a >= 1.3 provider ever
        # observes them; a legacy provider always sees the pre-1.3 site shape.
        is_api_13 = _plugin_api_at_least(provider_api, 1, 3)
        receiver_binding: str | None = None
        ctx_receiver: str | None = None
        if is_api_13:
            resolved_callables = self._resolve_callable_symbols(claim.callables)
            site = replace(site, receiver=claim.receiver, callables=resolved_callables)
            if receiver_expr is not None:
                ctx_receiver, receiver_binding = self._render_claim_receiver(claim, receiver_expr)
        if self.mode == "pyo3":
            ctx = LoweringContext(
                operands=operands,
                target_language="rust",
                fresh_name=self.next_temp,
                leaf_operands=leaf_operands,
                receiver=ctx_receiver,
            )
        else:
            if self.standalone is None:
                raise RustCodegenError(
                    f"standalone lowering of {claim.target!r} in "
                    f"{self.function.qualname} requires a resolved StandalonePluginContext"
                )
            # Defense-in-depth: every plugin type on the claim must be covered,
            # not only signature plugin_type_keys (operand/result/receiver).
            claim_types = claim_plugin_type_keys(claim)
            if claim_types and not self.standalone.covers_type_keys(claim_types):
                raise RustCodegenError(
                    f"plugin claim {claim.target!r} in {self.function.qualname} uses "
                    f"plugin type keys {sorted(claim_types)} that are not covered by "
                    "the resolved standalone capability"
                )
            ctx = LoweringContext(
                operands=operands,
                target_language="rust",
                fresh_name=self.next_temp,
                leaf_operands=leaf_operands,
                receiver=ctx_receiver,
                backend=LOWERING_BACKEND_STANDALONE_RUST,
                artifact_profile=self.standalone.profile,
            )
        try:
            lowered = provider.lower(site, ctx)  # type: ignore[attr-defined]
        except Exception as exc:
            raise RustCodegenError(
                f"plugin {claim.plugin_id!r} lower() failed for claimed site "
                f"{claim.target!r} in {self.function.qualname}: {exc}"
            ) from exc
        if not isinstance(lowered, LoweredExpr):
            raise RustCodegenError(
                f"plugin {claim.plugin_id!r} lower() must return a LoweredExpr for "
                f"claimed site {claim.target!r} in {self.function.qualname}, "
                f"got {type(lowered).__name__}"
            )
        if self.mode != "pyo3" and self.standalone is not None:
            # Second codegen-time assertion: standalone emission may only use
            # profile-declared uses/helpers (never undeclared support).
            allowed_uses = self.standalone.allowed_uses_for(claim.plugin_id)
            allowed_helpers = self.standalone.allowed_helpers_for(claim.plugin_id)
            undeclared_uses = [use for use in lowered.uses if use not in allowed_uses]
            undeclared_helpers = [
                helper for helper in lowered.helpers if helper not in allowed_helpers
            ]
            if undeclared_uses or undeclared_helpers:
                raise RustCodegenError(
                    f"plugin {claim.plugin_id!r} lower() emitted undeclared "
                    f"standalone support for {claim.target!r} in "
                    f"{self.function.qualname}: uses={undeclared_uses!r}, "
                    f"helpers={undeclared_helpers!r}"
                )
        self.plugin_uses.update(lowered.uses)
        for helper in lowered.helpers:
            self.plugin_helpers.setdefault(helper)
        if receiver_binding is not None:
            # A non-safe receiver is bound to a single-use temporary evaluated
            # ONCE, before the operands (which appear inside ``lowered.rust``),
            # matching Python receiver-then-args evaluation order. The block is
            # itself an expression, so it composes anywhere the claim result does.
            return f"{{ {receiver_binding} ({lowered.rust}) }}"
        return f"({lowered.rust})"

    def _resolve_callable_symbols(
        self, callables: tuple["CallableMeta", ...]
    ) -> tuple["CallableMeta", ...]:
        """Fill ``native_symbol`` for callables that name a generated native helper.

        A callable's native symbol is set only when it is a proven accepted
        scalar native function (``accepts_native``) AND an accepted native helper
        was actually generated for its qualname in this module (present in
        ``native_names_by_qualname``). Every other callable keeps
        ``native_symbol=None`` — the plugin then falls back to the closed body or
        rejects (fail closed).
        """
        if not callables:
            return callables
        resolved: list[CallableMeta] = []
        for meta in callables:
            symbol = self.native_names_by_qualname.get(meta.qualname)
            if meta.accepts_native and symbol is not None:
                resolved.append(replace(meta, native_symbol=symbol))
            else:
                resolved.append(meta)
        return tuple(resolved)

    def _render_claim_receiver(
        self, claim: PluginClaimIR, receiver_expr: ExprIR
    ) -> tuple[str, str | None]:
        """Render a method claim's receiver, guaranteeing a single evaluation.

        Returns ``(ctx_receiver, binding)``. Core ALWAYS evaluates the receiver
        exactly once, in Python order, before the call operands:

        * a side-effect-free receiver (a plain local name — ``ReceiverMeta.is_safe``)
          is passed through as a bare reference, with no binding; and
        * any other receiver is bound to a fresh single-use temporary
          (``let __recv = <expr>;``) and the temporary name is handed to the
          provider, so a descriptor/``__getattr__``/``__getitem__``/call in the
          receiver runs exactly once.
        """
        rendered = strip_wrapping_parens(self.render_expr(receiver_expr))
        receiver_meta = claim.receiver
        if receiver_meta is not None and receiver_meta.is_safe:
            return rendered, None
        temp = self.next_temp("__rextio_recv")
        return temp, f"let {temp} = {rendered};"

    def _render_fusion_leaf_operands(
        self,
        expression: ClaimExpr | None,
        operand_exprs: list[ExprIR],
    ) -> tuple[str, ...] | None:
        """Render non-literal leaves in LTR ``leaf_index`` encounter order.

        Returns:
        * ``tuple[str, ...]`` on success, including ``()`` for a valid
          leaves-safe all-literal expression (no non-literal leaves).
        * ``None`` on alignment / index-sequence mismatch (fail closed).

        The LTR DFS encounter sequence of ``leaf_index`` values must be
        exactly ``0..n-1`` (no swaps, duplicates, or gaps). Nested plugin
        claims are never invoked — intermediate structure is walked without
        calling lower().
        """
        if expression is None:
            return None
        by_index: dict[int, ExprIR] = {}
        encounter: list[int] = []
        if not self._collect_leaves_by_index(expression, operand_exprs, by_index, encounter):
            return None
        # Encounter order itself must be 0..n-1 (not merely the set of keys).
        if encounter != list(range(len(encounter))):
            return None
        return tuple(self._render_plugin_operand(by_index[i]) for i in encounter)

    def _collect_leaves_by_index(
        self,
        expression: ClaimExpr,
        operand_exprs: list[ExprIR] | ExprIR,
        by_index: dict[int, ExprIR],
        encounter: list[int],
    ) -> bool:
        """Fill ``by_index`` / ``encounter`` from a ClaimExpr tree; False on mismatch."""
        if expression.kind == "literal":
            return True
        if expression.kind == "leaf":
            if expression.leaf_index is None:
                return False
            if expression.leaf_index in by_index:
                return False  # duplicate index
            if isinstance(operand_exprs, list):
                if len(operand_exprs) != 1:
                    return False
                ir_node: ExprIR = operand_exprs[0]
            else:
                ir_node = operand_exprs
            # Opaque/name leaves must be terminals in IR (no nested claim structure).
            if isinstance(ir_node, (BinaryOpIR, CallIR)):
                return False
            by_index[expression.leaf_index] = ir_node
            encounter.append(expression.leaf_index)
            return True
        if expression.kind == "binop":
            if len(expression.children) != 2:
                return False
            if isinstance(operand_exprs, list):
                if len(operand_exprs) != 2:
                    return False
                left_ir, right_ir = operand_exprs[0], operand_exprs[1]
            elif isinstance(operand_exprs, BinaryOpIR):
                left_ir, right_ir = operand_exprs.left, operand_exprs.right
            else:
                return False
            return self._collect_leaves_by_index(
                expression.children[0], left_ir, by_index, encounter
            ) and self._collect_leaves_by_index(
                expression.children[1], right_ir, by_index, encounter
            )
        if expression.kind == "call":
            # Root call: children align with positional args only.
            if isinstance(operand_exprs, list):
                if len(operand_exprs) != len(expression.children):
                    return False
                args = operand_exprs
            elif isinstance(operand_exprs, CallIR):
                if len(operand_exprs.args) != len(expression.children):
                    return False
                args = operand_exprs.args
            else:
                return False
            for child_expr, arg_ir in zip(expression.children, args, strict=True):
                if not self._collect_leaves_by_index(child_expr, arg_ir, by_index, encounter):
                    return False
            return True
        return False

    def render_call(self, expr: CallIR) -> str:
        if expr.claim is not None:
            return self.render_plugin_claim(expr.claim, expr.args, expr.receiver)
        if expr.function == "len" and len(expr.args) == 1:
            # CPython `len(str)` counts Unicode code points; Rust `String::len`
            # returns the UTF-8 byte length, so a `str` argument must use
            # `.chars().count()` to match (e.g. `len("é") == 1`, not 2). Other
            # sized types (bytes/list/set/dict) use `.len()` faithfully.
            if isinstance(self.infer_expr_type(expr.args[0]), RxtStr):
                return f"({self.render_expr(expr.args[0])}.chars().count() as i64)"
            return f"({self.render_expr(expr.args[0])}.len() as i64)"
        if expr.function == "abs" and len(expr.args) == 1:
            if isinstance(self.infer_expr_type(expr.args[0]), RxtInt):
                self.used_helpers.add("abs")
                return f"__rextio_checked_abs({strip_wrapping_parens(self.render_expr(expr.args[0]))})?"
            return f"({self.render_expr(expr.args[0])}).abs()"
        if expr.function in {"min", "max"} and len(expr.args) == 2:
            # Rust's f64::min/max are NOT CPython-equivalent on NaN: f64::min
            # returns the non-NaN operand, but CPython's min/max keep the first
            # operand whenever the comparison is False (which it always is when
            # either operand is NaN). So `min(nan, 1.0)` is `nan` in CPython but
            # `1.0` via f64::min -> a silent wrong value. Emit CPython's own
            # `b < a ? b : a` (min) / `b > a ? b : a` (max) form instead, binding
            # both operands to locals first so each is evaluated exactly once,
            # left-to-right, matching CPython argument evaluation. Integers have
            # no NaN, but the comparison form is equally correct, so use it for
            # both numeric types.
            cmp = "<" if expr.function == "min" else ">"
            a_tmp = self.next_temp(f"__rextio_{expr.function}_a")
            b_tmp = self.next_temp(f"__rextio_{expr.function}_b")
            return (
                f"{{ let {a_tmp} = {self.render_expr(expr.args[0])}; "
                f"let {b_tmp} = {self.render_expr(expr.args[1])}; "
                f"if {b_tmp} {cmp} {a_tmp} {{ {b_tmp} }} else {{ {a_tmp} }} }}"
            )
        if expr.function == "sum" and len(expr.args) == 1:
            arg_type = self.infer_expr_type(expr.args[0])
            if isinstance(arg_type, RxtList) and isinstance(arg_type.item_type, RxtInt):
                self.used_helpers.add("sum")
                return f"__rextio_checked_sum(&{self.render_expr(expr.args[0])})?"
            return f"({self.render_expr(expr.args[0])}).iter().cloned().sum()"
        if expr.function == "all" and len(expr.args) == 1:
            return f"({self.render_expr(expr.args[0])}).iter().copied().all(|value| value)"
        if expr.function == "any" and len(expr.args) == 1:
            return f"({self.render_expr(expr.args[0])}).iter().copied().any(|value| value)"
        if expr.function == "sorted" and len(expr.args) == 1:
            return self.render_sorted(expr.args[0])
        if expr.function == "reversed" and len(expr.args) == 1:
            return self.render_reversed(expr.args[0])
        if expr.function == "math.pi" and not expr.args:
            return "std::f64::consts::PI"
        if expr.function == "math.e" and not expr.args:
            return "std::f64::consts::E"
        if (
            expr.function
            in {
                "math.atan",
                "math.cos",
                "math.exp",
                "math.sin",
                "math.tan",
            }
            and len(expr.args) == 1
        ):
            method = expr.function.rsplit(".", 1)[1]
            return f"({self.render_expr(expr.args[0])}).{method}()"
        # Domain-error-prone math functions: CPython raises ValueError only for
        # an out-of-domain *input* (a nan/inf input returns nan/inf, not an
        # error), so validate the input before applying the operation rather
        # than checking the result for finiteness.
        if expr.function == "math.sqrt" and len(expr.args) == 1:
            self.used_helpers.add("mnonneg")
            return f"__rextio_checked_mnonneg({self.render_expr(expr.args[0])})?.sqrt()"
        if expr.function in {"math.acos", "math.asin"} and len(expr.args) == 1:
            method = expr.function.rsplit(".", 1)[1]
            self.used_helpers.add("munit")
            return f"__rextio_checked_munit({self.render_expr(expr.args[0])})?.{method}()"
        if expr.function in {"math.log10", "math.log2"} and len(expr.args) == 1:
            method = expr.function.rsplit(".", 1)[1]
            self.used_helpers.add("mpositive")
            return f"__rextio_checked_mpositive({self.render_expr(expr.args[0])})?.{method}()"
        if expr.function == "math.log":
            self.used_helpers.add("mpositive")
            if len(expr.args) == 1:
                return f"__rextio_checked_mpositive({self.render_expr(expr.args[0])})?.ln()"
            if len(expr.args) == 2:
                # `math.log(x, base)` also constrains the base: CPython raises
                # ValueError for base <= 0 and ZeroDivisionError for base == 1
                # (log(base) is 0). CPython evaluates BOTH argument expressions
                # left-to-right before any domain check, so bind both to locals
                # first — otherwise `mpositive(x)?` as the receiver would
                # short-circuit before `base` is even evaluated, dropping a
                # raising base's exception (e.g. `log(-1.0, a / 0.0)` would raise
                # ValueError natively where CPython raises ZeroDivisionError).
                # x's domain is then checked before the base's, matching CPython.
                self.used_helpers.add("mlogbase")
                x_tmp = self.next_temp("__rextio_log_x")
                base_tmp = self.next_temp("__rextio_log_base")
                return (
                    f"{{ let {x_tmp} = {self.render_expr(expr.args[0])}; "
                    f"let {base_tmp} = {self.render_expr(expr.args[1])}; "
                    f"__rextio_checked_mpositive({x_tmp})?"
                    f".log(__rextio_checked_mlogbase({base_tmp})?) }}"
                )
        if expr.function == "math.atan2" and len(expr.args) == 2:
            return f"({self.render_expr(expr.args[0])}).atan2({self.render_expr(expr.args[1])})"
        if expr.function in {"math.ceil", "math.floor", "math.trunc"} and len(expr.args) == 1:
            method = expr.function.rsplit(".", 1)[1]
            self.used_helpers.add("f2i")
            return f"__rextio_checked_f2i(({self.render_expr(expr.args[0])}).{method}())?"
        if expr.function in {"math.isfinite", "math.isinf", "math.isnan"} and len(expr.args) == 1:
            method = {
                "math.isfinite": "is_finite",
                "math.isinf": "is_infinite",
                "math.isnan": "is_nan",
            }[expr.function]
            return f"({self.render_expr(expr.args[0])}).{method}()"
        if expr.function.startswith("str.") or expr.function.startswith("bytes."):
            return self.render_string_or_bytes_method(expr)
        if expr.function.startswith("list."):
            return self.render_list_method(expr)
        if expr.function == "print":
            return self.render_format_macro("println!", expr.args, allow_empty=True)
        if expr.function in {"logging.debug", "logging.info", "logging.warning", "logging.error"}:
            macro = {
                "logging.debug": "log::debug!",
                "logging.info": "log::info!",
                "logging.warning": "log::warn!",
                "logging.error": "log::error!",
            }[expr.function]
            return self.render_logging_macro(macro, expr.args)
        if expr.function == "datetime.datetime.now.isoformat" and not expr.args:
            return self.render_naive_isoformat("chrono::Local::now().naive_local()")
        if expr.function == "datetime.datetime.utcnow.isoformat" and not expr.args:
            return self.render_naive_isoformat("chrono::Utc::now().naive_utc()")
        if expr.function == "datetime.datetime.now.timestamp" and not expr.args:
            return self.render_chrono_timestamp("chrono::Local::now()")
        if expr.function == "time.time" and not expr.args:
            return (
                "std::time::SystemTime::now()"
                ".duration_since(std::time::UNIX_EPOCH)"
                f"{self.map_err_to_error(kind='runtime')}"
                ".as_secs_f64()"
            )
        if expr.function == "hashlib.sha256.hexdigest" and len(expr.args) == 1:
            return f'format!("{{:x}}", sha2::Sha256::digest(&{strip_wrapping_parens(self.render_call_arg(expr.args[0]))}))'
        if expr.function == "base64.b64encode" and len(expr.args) == 1:
            return (
                "base64::engine::general_purpose::STANDARD"
                f".encode({strip_wrapping_parens(self.render_call_arg(expr.args[0]))}).into_bytes()"
            )
        rust_name = self.native_names_by_qualname.get(expr.function)
        if rust_name is None:
            rust_name = self.native_names.get((self.function.module_name, expr.function))
        if rust_name is not None:
            args = ", ".join(self._render_native_call_arg(arg) for arg in expr.args)
            return f"{rust_name}({args})?"
        if expr.function in self.delegated_return_types:
            return self._render_delegated_call(expr)
        if expr.function in self.boundary_call_return_types:
            return self._render_boundary_call(expr)
        raise RustCodegenError(f"unsupported call during Rust codegen: {expr.function}")

    def _render_delegated_call(self, expr: CallIR) -> str:
        """Render a call delegated to the external CPython dispatcher (Phase 2).

        Binds each argument to a temporary, serializes them to ``serde_json::Value``
        (``to_value`` rather than the ``json!`` macro, which would parse an argument
        block as a JSON object), sends the call through ``__rextio_call_python``,
        and converts the JSON result to the callee's Rust return type. The callee
        runs in real CPython, so the value matches CPython.
        """
        lines: list[str] = []
        json_values: list[str] = []
        to_value = (
            "serde_json::to_value(&{name})"
            '.map_err(|e| RextioError::new("RuntimeError", e.to_string()))?'
        )
        for arg in expr.args:
            arg_type = self.infer_expr_type(arg)
            if isinstance(arg, LiteralIR) and arg.value is None:
                # Only a literal `None` may skip evaluation: it has no effects and no
                # typed Rust rendering (a bare `let x = None;` would not infer).
                json_values.append("serde_json::Value::Null")
                continue
            name = self.next_temp("__rextio_darg")
            lines.append(f"let {name} = {strip_wrapping_parens(self.render_call_arg(arg))};")
            if isinstance(arg_type, RxtNone):
                # A non-literal `None`-typed argument (e.g. a delegated `-> None`
                # call) must still be EXECUTED for its side effects; the bound unit
                # value then serializes to JSON null (`to_value(&()) == Null`).
                # Short-circuiting it to `Value::Null` silently elided the callee.
                json_values.append(to_value.format(name=name))
                continue
            if isinstance(arg_type, RxtFloat):
                # serde_json serializes a non-finite float to JSON null silently;
                # guard it so a NaN/Inf argument is a clean error, never a silent
                # None on the Python side of the wire. INVARIANT: delegation only
                # authorizes a float arg the analyzer typed `float`, and a value the
                # generator can lower to a native `f64` is typed RxtFloat here too, so
                # the guard covers every non-finite float that can actually reach the
                # wire in the current subset (no native producer yields NaN/Inf yet).
                json_values.append(to_value.format(name=f"__rextio_finite({name})?"))
            else:
                json_values.append(to_value.format(name=name))
        json_args = ", ".join(json_values)
        lines.append(
            f'let __rextio_dj = __rextio_call_python("{expr.function}", vec![{json_args}])?;'
        )
        conversion = self._convert_json_value(
            "__rextio_dj", self.delegated_return_types[expr.function], expr.function
        )
        return "{ " + " ".join(lines) + " " + conversion + " }"

    def _render_boundary_call(self, expr: CallIR) -> str:
        """Render an in-process scalar boundary call to the Python fallback.

        Binds each argument to a temporary (evaluated once, in order), then
        attaches to the interpreter and dispatches through
        ``rextio.runtime.boundary_call.boundary_call``, which resolves the
        target with ``getattr`` at call time (honoring runtime replacement)
        and counts the crossing against this caller for the boundary
        threshold. The callee runs in real CPython, so the value - and any
        raised exception, which propagates as the same Python exception - is
        CPython-exact by construction.
        """
        if self.mode != "pyo3":
            raise RustCodegenError(
                "scalar boundary calls are only supported in the pyo3 backend, "
                "not the importable Rust crate"
            )
        lines: list[str] = []
        arg_exprs: list[str] = []
        for arg in expr.args:
            arg_type = self.infer_expr_type(arg)
            if isinstance(arg, LiteralIR) and arg.value is None:
                # A literal None needs no evaluation and has no typed Rust
                # rendering; pass the interpreter's None directly.
                arg_exprs.append("py.None()")
                continue
            name = self.next_temp("__rextio_barg")
            lines.append(f"let {name} = {strip_wrapping_parens(self.render_call_arg(arg))};")
            if isinstance(arg_type, RxtNone):
                # A non-literal None-typed argument (e.g. a None-returning
                # call) must still be EVALUATED for its side effects; the
                # bound unit value then crosses as Python None.
                arg_exprs.append(f"{{ let _ = {name}; py.None() }}")
                continue
            arg_exprs.append(name)
        if arg_exprs:
            args_tuple = "(" + ", ".join(arg_exprs) + ",)"
        else:
            args_tuple = "PyTuple::empty(py)"
        return_type_name = self.boundary_call_return_types[expr.function]
        caller = self.function.qualname
        target = expr.function
        call_stmt = (
            f'let __rextio_bval = __rextio_bhook.call1(("{caller}", "{target}", {args_tuple}))?;'
        )
        # Resolved per call: PyModule::import is a sys.modules hit after the
        # first import, and per-call resolution is what keeps monkeypatched
        # hook modules honored. If boundary calls ever show up hot in straight-
        # line code, a GILOnceCell cache is the follow-up - never a build-time
        # snapshot of the target function (that would break monkeypatching).
        prologue = (
            'let __rextio_bhook = PyModule::import(py, "rextio.runtime.boundary_call")?'
            '.getattr("boundary_call")?;'
        )
        extract = {
            "int": "__rextio_bval.extract::<i64>()",
            "float": "__rextio_bval.extract::<f64>()",
            "bool": "__rextio_bval.extract::<bool>()",
            "str": "__rextio_bval.extract::<String>()",
        }.get(return_type_name)
        if extract is not None:
            rust_ret = {
                "int": "i64",
                "float": "f64",
                "bool": "bool",
                "str": "String",
            }[return_type_name]
            closure = (
                f"Python::attach(|py| -> PyResult<{rust_ret}> {{ "
                f"{prologue} {call_stmt} {extract} }})?"
            )
            # Parenthesized so the block expression stays valid in
            # struct-literal-free positions such as a `for` header range bound
            # (`for i in 0..({ .. })` - a bare `{` there would be parsed as
            # the loop body).
            return "({ " + " ".join(lines) + " " + closure + " })"
        if return_type_name == "None":
            # Deliberately stricter than CPython: a callee whose `-> None`
            # annotation lies would otherwise make the native caller compute
            # with None while the fallback computes with the real value - a
            # SILENT divergence. Raising converts the annotation lie into a
            # loud error instead.
            err = f'pyo3::exceptions::PyTypeError::new_err("{target} was expected to return None")'
            closure = (
                "Python::attach(|py| -> PyResult<()> { "
                f"{prologue} {call_stmt} "
                f"if __rextio_bval.is_none() {{ Ok(()) }} else {{ Err({err}) }} }})?"
            )
            return "({ " + " ".join(lines) + " " + closure + " })"
        # The analyzer's _is_delegatable gate authorizes only immutable
        # scalars; reject anything else so a regression there is a clean
        # build failure rather than a silent aliasing-severing copy.
        raise RustCodegenError(f"boundary call return type is not supported: {return_type_name}")

    def _convert_json_value(self, value_var: str, type_name: str, qualname: str) -> str:
        """Rust expression converting the already-bound JSON ``value_var`` to a type."""
        err = (
            f'RextioError::new("TypeError", '
            f'"{qualname} returned a value not convertible to {type_name}")'
        )
        scalar = {"int": "as_i64", "float": "as_f64", "bool": "as_bool"}.get(type_name)
        if scalar is not None:
            return f"{value_var}.{scalar}().ok_or_else(|| {err})?"
        if type_name == "str":
            return f"{value_var}.as_str().map(|s| s.to_string()).ok_or_else(|| {err})?"
        if type_name == "None":
            # A None-returning delegated call is a statement; discard the result.
            return "()"
        # Only immutable scalars are delegatable wire types (the analyzer's
        # `_is_delegatable_return_type` enforces this). Reject anything else here too,
        # so if that gate ever regressed, a container return would be a clean build
        # failure rather than a silent by-value copy that severs CPython aliasing.
        raise RustCodegenError(f"delegated call return type is not supported: {type_name}")

    def render_sorted(self, expr: ExprIR) -> str:
        # `sorted` is only admitted for totally-ordered item types (int/bool/str);
        # `list[float]` is rejected to the Python fallback by the analyzer because
        # NaN ordering cannot match CPython, so `.sort()` (which requires `Ord`)
        # is always valid here.
        source = strip_wrapping_parens(self.render_call_arg(expr))
        return "\n".join(
            [
                "{",
                f"    let mut values = {source};",
                "    values.sort();",
                "    values",
                "}",
            ]
        )

    def render_reversed(self, expr: ExprIR) -> str:
        source = strip_wrapping_parens(self.render_call_arg(expr))
        return "\n".join(
            [
                "{",
                f"    let mut values = {source};",
                "    values.reverse();",
                "    values",
                "}",
            ]
        )

    def render_string_or_bytes_method(self, expr: CallIR) -> str:
        receiver = strip_wrapping_parens(self.render_call_arg(expr.args[0]))
        if expr.function == "str.lower" and len(expr.args) == 1:
            return f"{receiver}.to_lowercase()"
        if expr.function == "str.upper" and len(expr.args) == 1:
            return f"{receiver}.to_uppercase()"
        if expr.function == "str.encode" and len(expr.args) == 1:
            return f"{receiver}.as_bytes().to_vec()"
        if expr.function == "bytes.decode" and len(expr.args) == 1:
            # KNOWN LIMITATION (documented in docs/unsupported-features.md,
            # "Accepted Native Semantic Divergences"): on invalid UTF-8 this raises
            # ValueError, whereas CPython raises UnicodeDecodeError. UnicodeDecodeError
            # is a subclass of ValueError (so `except ValueError` still catches it).
            # A faithful UnicodeDecodeError is feasible but DEFERRED for alpha: the
            # inner native fn has no `py` token and `RextioError` only carries a
            # message, so it would require threading the decode-position data
            # (`str::from_utf8(...).valid_up_to()`) through to the wrapper boundary
            # where `py` is available. Valid UTF-8 decodes identically.
            return f"String::from_utf8({receiver}){self.map_err_to_error()}"
        if expr.function in {"str.startswith", "str.endswith"} and len(expr.args) == 2:
            method = "starts_with" if expr.function == "str.startswith" else "ends_with"
            value = strip_wrapping_parens(self.render_call_arg(expr.args[1]))
            return f"{receiver}.{method}(&{value})"
        if expr.function == "str.replace" and len(expr.args) == 3:
            old = strip_wrapping_parens(self.render_call_arg(expr.args[1]))
            new = strip_wrapping_parens(self.render_call_arg(expr.args[2]))
            return f"{receiver}.replace(&{old}, &{new})"
        raise RustCodegenError(
            f"unsupported string/bytes method during Rust codegen: {expr.function}"
        )

    def render_list_method(self, expr: CallIR) -> str:
        receiver = strip_wrapping_parens(self.render_call_arg(expr.args[0]))
        if expr.function == "list.copy" and len(expr.args) == 1:
            return receiver
        if expr.function == "list.count" and len(expr.args) == 2:
            recv_tmp = self.next_temp("__rextio_recv")
            needle = strip_wrapping_parens(self.render_call_arg(expr.args[1]))
            needle_tmp = self.next_temp("__rextio_needle")
            # Bind the receiver before the argument to preserve Python's
            # left-to-right evaluation order, and hoist the needle out of the
            # predicate closure (it may contain `?`, e.g. `xs.count(ys[i])`).
            # `filter` passes `&Item`, so `*item` is `&T` and matches `&needle`.
            return (
                f"{{ let {recv_tmp} = &{receiver}; "
                f"let {needle_tmp} = {needle}; "
                f"{recv_tmp}.iter().filter(|item| *item == &{needle_tmp}).count() as i64 }}"
            )
        if expr.function == "list.index" and len(expr.args) == 2:
            recv_tmp = self.next_temp("__rextio_recv")
            needle = strip_wrapping_parens(self.render_call_arg(expr.args[1]))
            needle_tmp = self.next_temp("__rextio_needle")
            # CPython's failure message interpolates the needle's repr
            # ("5 is not in list", "'x' is not in list", "[2] is not in
            # list"). float items never reach this direct lowering (marked ->
            # RXT080 shim, auto -> quiet rejection via the count/index NaN
            # identity guard); every other supported item type composes its
            # repr through the shared composer - including container needles
            # like list[list[int]].index.
            receiver_type = self.infer_expr_type(expr.args[0])
            item_type = receiver_type.item_type if isinstance(receiver_type, RxtList) else None
            needle_repr = self.render_repr_arg(item_type, needle_tmp)
            message = f'format!("{{}} is not in list", {needle_repr})'
            # `position` passes `Item` (`&T`), so the predicate compares `item`
            # (not `*item`) against `&needle`.
            return (
                f"{{ let {recv_tmp} = &{receiver}; "
                f"let {needle_tmp} = {needle}; "
                f"{recv_tmp}.iter().position(|item| item == &{needle_tmp})"
                ".map(|index| index as i64)"
                f".ok_or_else(|| {self.error_new(message)})? }}"
            )
        raise RustCodegenError(f"unsupported list method during Rust codegen: {expr.function}")

    def render_naive_isoformat(self, naive_expr: str) -> str:
        # CPython's datetime.now()/utcnow() are *naive*, so .isoformat() has NO
        # timezone offset (unlike chrono's to_rfc3339, which always appends one)
        # and emits the fractional part only when the microsecond is non-zero,
        # always as exactly 6 digits otherwise. Truncate the nanosecond clock to
        # microseconds (matching CPython's microsecond resolution) and format the
        # value explicitly rather than relying on chrono's offset-aware/variable
        # precision formatter.
        dt = self.next_temp("__rextio_dt")
        micros = self.next_temp("__rextio_us")
        base = self.next_temp("__rextio_iso")
        return "\n".join(
            [
                "{",
                f"    let {dt} = {naive_expr};",
                f"    let {micros} = chrono::Timelike::nanosecond(&{dt}) / 1000;",
                f'    let {base} = {dt}.format("%Y-%m-%dT%H:%M:%S").to_string();',
                f'    if {micros} == 0 {{ {base} }} else {{ format!("{{}}.{{:06}}", {base}, {micros}) }}',
                "}",
            ]
        )

    def render_chrono_timestamp(self, now_expr: str) -> str:
        # CPython datetime.now().timestamp() has microsecond resolution; truncate
        # the nanosecond clock to microseconds so the f64 matches CPython rather
        # than carrying extra sub-microsecond precision.
        return "\n".join(
            [
                "{",
                f"    let value = {now_expr};",
                "    value.timestamp() as f64 + value.timestamp_subsec_micros() as f64 / 1_000_000.0",
                "}",
            ]
        )

    def render_call_arg(self, expr: ExprIR) -> str:
        if isinstance(expr, NameIR):
            if expr.id in self.maybe_bound_types:
                return self.render_expr(expr)
            return f"{rust_identifier(expr.id)}.clone()"
        return self.render_expr(expr)

    def _param_signature_rust(self, param: ParamIR) -> str:
        """Render a parameter's Rust signature type.

        A resident (opaque, native-only — plugin API 1.3) parameter is passed by
        SHARED REFERENCE (``&T``): the caller keeps ownership, so the value can be
        reused or handed to another helper after the call (safe native-to-native
        chaining), and a resident type never needs to be ``Clone``. Every other
        parameter renders as its plain owned Rust type.
        """
        if isinstance(param.type, RxtPluginType) and param.type.resident:
            return f"&{param.type.native_rust}"
        return rust_type(param.type)

    def _render_native_call_arg(self, expr: ExprIR) -> str:
        """Render an argument to a native-to-native call.

        A resident plugin value (opaque, native-only — plugin API 1.3) is passed
        by SHARED REFERENCE so the caller keeps ownership: it is NEVER moved and
        NEVER cloned (a resident type need not implement ``Clone``). This holds
        for EVERY resident-valued argument expression, not just a bare name:

        * an owned resident LOCAL is borrowed (``&name``) so the producer keeps
          it and may reuse it after the call;
        * a resident PARAMETER is already a ``&T`` binding, so it is reborrowed
          by passing it through unchanged (never ``&&T``);
        * a resident-valued TEMPORARY — a plugin-produced value passed directly
          (``extend(rextio_graph.new(nodes), n)``) or a nested native helper
          call returning a resident value (``extend(extend(g, a), b)``) — is
          rendered once and its temporary borrowed (``&(...)``). The temporary
          lives to the end of the enclosing statement, so borrowing it is
          well-formed; it is evaluated exactly once, in order, with no clone and
          nothing to move.

        The ``&(...)`` wrapping parenthesizes the rendered expression so a
        trailing ``?`` (a native call renders ``helper(...)?``) or any complex
        expression binds to the borrow correctly. Every non-resident argument
        keeps the existing clone-on-name behaviour.
        """
        if isinstance(expr, NameIR):
            if expr.id not in self.maybe_bound_types:
                value_type = self.infer_expr_type(expr)
                if isinstance(value_type, RxtPluginType) and value_type.resident:
                    if expr.id in self._resident_param_names:
                        return rust_identifier(expr.id)
                    return f"&{rust_identifier(expr.id)}"
            return self.render_call_arg(expr)
        value_type = self.infer_expr_type(expr)
        if isinstance(value_type, RxtPluginType) and value_type.resident:
            return f"&({strip_wrapping_parens(self.render_expr(expr))})"
        return self.render_call_arg(expr)

    def _render_plugin_operand(self, expr: ExprIR) -> str:
        """Render a plugin-claim operand, borrowing plugin-typed names.

        A plugin-typed local is not a Rust ``Copy`` type, so render_call_arg
        would emit ``name.clone()`` -- and the plugin's snippet then borrows it
        (``&{operand}``), producing a clone-then-borrow that copies the whole
        array on every use (council round 8). The plugin owns the borrow/own
        decision in its own snippet, so we hand it the bare identifier and let
        it add ``&`` where needed; non-name operands render normally.
        """
        if isinstance(expr, NameIR) and expr.id not in self.maybe_bound_types:
            if isinstance(self.infer_expr_type(expr), RxtPluginType):
                return rust_identifier(expr.id)
        return self.render_call_arg(expr)

    def render_owned_expr(self, expr: ExprIR) -> str:
        if isinstance(expr, NameIR) and not self.is_copy_expr(expr):
            return self.render_call_arg(expr)
        return self.render_expr(expr)

    def render_assignment_value(self, expr: ExprIR, expected_type: RxtType | None) -> str:
        if isinstance(expr, NameIR) and not self.is_copy_expr(expr):
            return self.render_call_arg(expr)
        return self.render_expr_with_expected(expr, expected_type)

    def is_copy_expr(self, expr: ExprIR) -> bool:
        return is_copy_rust_type(self.infer_expr_type(expr))

    def render_expr_with_expected(self, expr: ExprIR, expected_type: RxtType | None) -> str:
        if isinstance(expected_type, RxtOptional):
            if isinstance(expr, LiteralIR) and expr.value is None:
                return "None"
            actual_type = self.infer_expr_type(expr)
            rendered = strip_expr_if_safe(expr, self.render_expr(expr))
            if same_type(actual_type, expected_type):
                return rendered
            if same_type(actual_type, expected_type.item_type):
                return f"Some({strip_expr_if_safe(expr, rendered)})"
            return rendered
        if (
            isinstance(expected_type, RxtNone)
            and isinstance(expr, LiteralIR)
            and expr.value is None
        ):
            return "()"
        return self.render_expr(expr)

    def infer_expr_type(self, expr: ExprIR) -> RxtType | None:
        if isinstance(expr, LiteralIR):
            if isinstance(expr.value, bool):
                return RxtBool()
            if isinstance(expr.value, int):
                return RxtInt()
            if isinstance(expr.value, float):
                return RxtFloat()
            if isinstance(expr.value, str):
                return RxtStr()
            if isinstance(expr.value, bytes):
                return RxtBytes()
            if expr.value is None:
                return RxtNone()
            return None
        if isinstance(expr, NameIR):
            return self.variable_types.get(expr.id)
        if isinstance(expr, ListIR):
            if not expr.items:
                return None
            item_type = self.infer_expr_type(expr.items[0])
            if item_type is None:
                return None
            return RxtList(item_type)
        if isinstance(expr, ListComprehensionIR):
            saved_types = dict(self.variable_types)
            self.bind_comprehension_generator_types(expr.generators)
            item_type = self.infer_expr_type(expr.item)
            self.variable_types = saved_types
            if item_type is None:
                return None
            return RxtList(item_type)
        if isinstance(expr, TupleIR):
            item_types: list[RxtType] = []
            for item in expr.items:
                item_type = self.infer_expr_type(item)
                if item_type is None:
                    return None
                item_types.append(item_type)
            return RxtTuple(tuple(item_types))
        if isinstance(expr, DictIR):
            if not expr.items:
                return None
            first_key, first_value = expr.items[0]
            key_type = self.infer_expr_type(first_key)
            value_type = self.infer_expr_type(first_value)
            if key_type is None or value_type is None:
                return None
            return RxtDict(key_type, value_type)
        if isinstance(expr, DictComprehensionIR):
            saved_types = dict(self.variable_types)
            self.bind_comprehension_generator_types(expr.generators)
            key_type = self.infer_expr_type(expr.key)
            value_type = self.infer_expr_type(expr.value)
            self.variable_types = saved_types
            if key_type is None or value_type is None:
                return None
            return RxtDict(key_type, value_type)
        if isinstance(expr, SetIR):
            if not expr.items:
                return None
            item_type = self.infer_expr_type(expr.items[0])
            if item_type is None:
                return None
            return RxtSet(item_type)
        if isinstance(expr, SetComprehensionIR):
            saved_types = dict(self.variable_types)
            self.bind_comprehension_generator_types(expr.generators)
            item_type = self.infer_expr_type(expr.item)
            self.variable_types = saved_types
            if item_type is None:
                return None
            return RxtSet(item_type)
        if isinstance(expr, BinaryOpIR):
            if expr.claim is not None:
                return self._claim_result_type(expr.claim)
            return self.infer_expr_type(expr.left)
        if isinstance(expr, UnaryOpIR):
            if expr.op == "not":
                return RxtBool()
            return self.infer_expr_type(expr.value)
        if isinstance(expr, CompareIR):
            if expr.claim is not None:
                return self._claim_result_type(expr.claim)
            return RxtBool()
        if isinstance(expr, IndexIR):
            value_type = self.infer_expr_type(expr.value)
            if isinstance(value_type, RxtList):
                return value_type.item_type
            if isinstance(value_type, RxtTuple):
                index = literal_int(expr.index)
                if index is not None and 0 <= index < len(value_type.item_types):
                    return value_type.item_types[index]
            if isinstance(value_type, RxtDict):
                return value_type.value_type
        if isinstance(expr, CallIR):
            return self.call_return_type(expr)
        if isinstance(expr, NamedExprIR):
            value_type = self.infer_expr_type(expr.value)
            if value_type is not None:
                self.variable_types[expr.target.id] = value_type
            return value_type
        return None

    def bind_comprehension_generator_types(
        self,
        generators: list[ComprehensionGeneratorIR],
    ) -> None:
        for generator in generators:
            self.bind_target_types(generator.target, self.iterable_target_types(generator.iterable))
            for condition in generator.conditions:
                self.infer_expr_type(condition)

    def _claim_result_type(self, claim: PluginClaimIR) -> RxtType | None:
        """Map a plugin claim's declared result type to an ``RxtType``, or None.

        A plugin type key resolves through ``plugin_types_by_key``; a core
        type name parses through ``type_from_string``; unknown/None stays None.
        """
        if claim.result_type is None:
            return None
        plugin_type = self.plugin_types_by_key.get(claim.result_type)
        if plugin_type is not None:
            return plugin_type
        try:
            return type_from_string(claim.result_type)
        except (ValueError, SyntaxError):
            return None

    def call_return_type(self, expr: CallIR) -> RxtType | None:
        if expr.claim is not None:
            return self._claim_result_type(expr.claim)
        if expr.function == "len":
            return RxtInt()
        if expr.function in {"all", "any"}:
            return RxtBool()
        if expr.function in {"sorted", "reversed"} and expr.args:
            return self.infer_expr_type(expr.args[0])
        if expr.function in {"abs", "min", "max"} and expr.args:
            return self.infer_expr_type(expr.args[0])
        if expr.function == "sum" and expr.args:
            arg_type = self.infer_expr_type(expr.args[0])
            if isinstance(arg_type, RxtList):
                return arg_type.item_type
            return None
        if expr.function in {
            "math.acos",
            "math.asin",
            "math.atan",
            "math.atan2",
            "math.cos",
            "math.exp",
            "math.log",
            "math.log10",
            "math.log2",
            "math.sin",
            "math.sqrt",
            "math.tan",
            "math.e",
            "math.pi",
        }:
            return RxtFloat()
        if expr.function in {"math.ceil", "math.floor", "math.trunc"}:
            return RxtInt()
        if expr.function in {"math.isfinite", "math.isinf", "math.isnan"}:
            return RxtBool()
        if expr.function in {"str.lower", "str.upper", "str.replace"}:
            return RxtStr()
        if expr.function in {"str.startswith", "str.endswith"}:
            return RxtBool()
        if expr.function == "str.encode":
            return RxtBytes()
        if expr.function == "bytes.decode":
            return RxtStr()
        if expr.function in {"list.copy"} and expr.args:
            return self.infer_expr_type(expr.args[0])
        if expr.function in {"list.count", "list.index"}:
            return RxtInt()
        if expr.function == "print" or expr.function.startswith("logging."):
            return RxtNone()
        if expr.function in {
            "datetime.datetime.now.isoformat",
            "datetime.datetime.utcnow.isoformat",
        }:
            return RxtStr()
        if expr.function in {
            "datetime.datetime.now.timestamp",
            "datetime.datetime.utcnow.timestamp",
            "time.time",
        }:
            return RxtFloat()
        if expr.function == "hashlib.sha256.hexdigest":
            return RxtStr()
        if expr.function == "base64.b64encode":
            return RxtBytes()
        if expr.function in self.delegated_return_types:
            # A delegated call's result type comes from the callee's annotation, so
            # a local assigned from it is typed correctly (e.g. its `print` formats
            # a `str` with `{}`, not Debug `{:?}`).
            return type_from_string(self.delegated_return_types[expr.function])
        if expr.function in self.boundary_call_return_types:
            # Same rule for in-process boundary calls.
            return type_from_string(self.boundary_call_return_types[expr.function])
        return self.native_return_types.get(expr.function)

    def render_format_macro(
        self,
        macro: str,
        args: list[ExprIR],
        *,
        allow_empty: bool,
    ) -> str:
        if not args:
            if allow_empty:
                return f"{macro}()"
            return f'{macro}("")'
        placeholders = " ".join(self.format_placeholder(arg) for arg in args)
        rendered_args = ", ".join(self.render_format_arg(arg) for arg in args)
        return f"{macro}({rust_string_literal(placeholders)}, {rendered_args})"

    def render_logging_macro(self, macro: str, args: list[ExprIR]) -> str:
        if len(args) > 1 and isinstance(args[0], LiteralIR) and isinstance(args[0].value, str):
            converted = python_logging_format_segments(args[0].value)
            if converted is not None:
                segments, specifiers = converted
                if len(specifiers) == len(args) - 1:
                    parts: list[str] = [segments[0]]
                    rendered_args: list[str] = []
                    for spec, arg, segment in zip(specifiers, args[1:], segments[1:], strict=True):
                        arg_type = self.infer_expr_type(arg)
                        rendered = strip_wrapping_parens(self.render_call_arg(arg))
                        if spec == "f":
                            # Analyzer admits only float for %f (CPython %f of
                            # a bool has no Rust cast - E0606 - and a large int
                            # would round through f64). The helper fixes the
                            # non-finite spelling: CPython prints "nan" where
                            # Rust {:.6} prints "NaN".
                            if not isinstance(arg_type, RxtFloat):
                                raise RustCodegenError(
                                    f"%{spec} logging argument must be float, got "
                                    f"{arg_type!r} (analyzer gate out of sync)"
                                )
                            self.used_helpers.add("fixed6")
                            parts.append("{}")
                            rendered_args.append(f"__rextio_fixed6({rendered})")
                        elif spec in {"d", "i"}:
                            # Analyzer admits int and bool ("%d" % True == "1").
                            if isinstance(arg_type, RxtBool):
                                rendered_args.append(f"(({rendered}) as i64)")
                            elif isinstance(arg_type, RxtInt):
                                rendered_args.append(rendered)
                            else:
                                raise RustCodegenError(
                                    f"%{spec} logging argument must be int or bool, "
                                    f"got {arg_type!r} (analyzer gate out of sync)"
                                )
                            parts.append("{}")
                        elif spec == "r":
                            # CPython repr semantics: quoted strings, True/False,
                            # float repr, and recursively composed containers.
                            parts.append("{}")
                            rendered_args.append(self.render_repr_arg(arg_type, rendered))
                        else:
                            # %s: str() semantics (same as print).
                            parts.append(self.format_placeholder(arg))
                            rendered_args.append(self.render_format_arg(arg))
                        parts.append(segment)
                    format_string = "".join(parts)
                    joined = ", ".join(rendered_args)
                    return f"{macro}({rust_string_literal(format_string)}, {joined})"
        return self.render_format_macro(macro, args, allow_empty=False)

    def render_format_arg(self, expr: ExprIR) -> str:
        """Render a print/logging argument with CPython str() semantics.

        A bool prints `True`/`False` (Rust Display gives `true`/`false`), a
        float prints CPython's repr (lowercase `nan`, `e+NN` exponents, `.0`
        suffix), containers compose their CPython repr recursively; str and
        int pass through (identical text).
        """
        expr_type = self.infer_expr_type(expr)
        rendered = strip_wrapping_parens(self.render_call_arg(expr))
        if isinstance(expr_type, (RxtInt, RxtStr)) or expr_type is None:
            return rendered
        if isinstance(expr_type, RxtOptional):
            # str() semantics: at runtime an Optional IS its payload (or
            # None), so a str payload prints BARE - only under repr (%r,
            # nested-in-container) is it quoted. Every other payload type has
            # str() == repr(). A nested Optional payload is rejected by the
            # analyzer in both spellings (Optional[Optional[str]] and
            # `str | None | None`); guard the invariant explicitly.
            if isinstance(expr_type.item_type, RxtOptional):
                raise RustCodegenError(
                    "nested Optional has no native text lowering (analyzer gate out of sync)"
                )
            payload = self.next_temp("__rextio_some")
            if isinstance(expr_type.item_type, RxtStr):
                inner = f"{payload}.clone()"
            else:
                inner = self.render_container_repr_leaf(expr_type.item_type, payload, by_ref=True)
            return (
                f"(match &({rendered}) {{ "
                f'None => "None".to_string(), '
                f"Some({payload}) => {inner} }})"
            )
        if isinstance(expr_type, (RxtBool, RxtFloat, RxtList, RxtTuple)):
            return self.render_repr_arg(expr_type, rendered)
        raise RustCodegenError(
            f"print/logging argument type {expr_type!r} has no CPython-exact "
            "native text form (analyzer gate out of sync)"
        )

    def render_repr_arg(self, expr_type: RxtType | None, rendered: str) -> str:
        """Return a Rust String expression producing CPython repr() text for a value.

        str() and repr() agree for every type here except str itself (print of
        a bare str has no quotes; a str inside a container or under %r is
        quoted), which `render_format_arg` handles by passing bare str args
        through directly.
        """
        if isinstance(expr_type, RxtInt) or expr_type is None:
            return rendered
        if isinstance(expr_type, RxtBool):
            return f'(if {rendered} {{ "True" }} else {{ "False" }})'
        if isinstance(expr_type, RxtFloat):
            self.used_helpers.add("repr_float")
            return f"__rextio_repr_float({rendered})"
        if isinstance(expr_type, RxtStr):
            self.used_helpers.add("repr_str")
            return f"__rextio_repr_str(&{rendered})"
        if isinstance(expr_type, (RxtList, RxtTuple, RxtOptional)):
            return self.render_container_repr(expr_type, rendered, by_ref=False)
        raise RustCodegenError(
            f"repr of type {expr_type!r} has no CPython-exact native lowering "
            "(analyzer gate out of sync)"
        )

    def render_container_repr(self, expr_type: RxtType, value: str, *, by_ref: bool) -> str:
        """Compose CPython repr text for list/tuple/Optional values recursively.

        ``by_ref`` marks ``value`` as a reference (loop items, Option payloads)
        so scalar leaves deref and string leaves borrow correctly. Ordered
        containers only: set/dict never reach codegen (order-observable,
        rejected by the analyzer).
        """
        if isinstance(expr_type, RxtList):
            item = self.next_temp("__rextio_item")
            parts = self.next_temp("__rextio_parts")
            inner = self.render_container_repr_leaf(expr_type.item_type, item, by_ref=True)
            return (
                f"{{ let mut {parts}: Vec<String> = Vec::new(); "
                f"for {item} in ({value}).iter() {{ {parts}.push({inner}); }} "
                f'format!("[{{}}]", {parts}.join(", ")) }}'
            )
        if isinstance(expr_type, RxtTuple):
            source = value if not by_ref else f"(*{value})"
            fields = [
                self.render_container_repr_leaf(item_type, f"({source}).{index}", by_ref=False)
                for index, item_type in enumerate(expr_type.item_types)
            ]
            if len(fields) == 1:
                return f'format!("({{}},)", {fields[0]})'
            placeholders = ", ".join("{}" for _ in fields)
            return f'format!("({placeholders})", {", ".join(fields)})'
        if isinstance(expr_type, RxtOptional):
            payload = self.next_temp("__rextio_some")
            inner = self.render_container_repr_leaf(expr_type.item_type, payload, by_ref=True)
            return (
                f'(match &({value}) {{ None => "None".to_string(), Some({payload}) => {inner} }})'
            )
        raise RustCodegenError(
            f"container repr of type {expr_type!r} is not composable (analyzer gate out of sync)"
        )

    def render_container_repr_leaf(self, expr_type: RxtType, value: str, *, by_ref: bool) -> str:
        if isinstance(expr_type, RxtInt):
            deref = f"(*{value})" if by_ref else value
            return f'format!("{{}}", {deref})'
        if isinstance(expr_type, RxtBool):
            deref = f"(*{value})" if by_ref else value
            return f'(if {deref} {{ "True" }} else {{ "False" }}).to_string()'
        if isinstance(expr_type, RxtFloat):
            self.used_helpers.add("repr_float")
            deref = f"(*{value})" if by_ref else value
            return f"__rextio_repr_float({deref})"
        if isinstance(expr_type, RxtStr):
            self.used_helpers.add("repr_str")
            borrow = value if by_ref else f"&{value}"
            return f"__rextio_repr_str({borrow})"
        if isinstance(expr_type, (RxtList, RxtTuple, RxtOptional)):
            return self.render_container_repr(expr_type, value, by_ref=by_ref)
        raise RustCodegenError(
            f"container element type {expr_type!r} has no CPython-exact repr "
            "(analyzer gate out of sync)"
        )

    def format_placeholder(self, expr: ExprIR) -> str:
        # Every accepted print/logging argument renders through
        # `render_format_arg` into CPython-exact text, so the placeholder is
        # always plain Display.
        return "{}"


def _render_function(
    function: FunctionIR,
    native_names_by_qualname: dict[str, str],
    native_names: dict[tuple[str, str], str],
    native_return_types: dict[str, RxtType],
    mode: str,
    used_helpers: set[str] | None = None,
    delegated_return_types: dict[str, str] | None = None,
    boundary_call_return_types: dict[str, str] | None = None,
    pyo3_exported: bool = True,
    plugin_providers: dict[str, object] | None = None,
    plugin_types_by_key: Mapping[str, RxtType] | None = None,
    plugin_uses: set[str] | None = None,
    plugin_helpers: dict[str, None] | None = None,
    standalone: StandalonePluginContext | None = None,
) -> str:
    return _FunctionRenderer(
        function,
        native_names_by_qualname,
        native_names,
        native_return_types,
        mode,
        used_helpers=used_helpers,
        delegated_return_types=delegated_return_types,
        boundary_call_return_types=boundary_call_return_types,
        pyo3_exported=pyo3_exported,
        plugin_providers=plugin_providers,
        plugin_types_by_key=plugin_types_by_key,
        plugin_uses=plugin_uses,
        plugin_helpers=plugin_helpers,
        standalone=standalone,
    ).render()


def _assigned_names(block: BlockIR) -> set[str]:
    names: set[str] = set()
    for statement in block.statements:
        if isinstance(statement, AssignIR):
            names.add(statement.target.id)
            names.update(_expr_assigned_names(statement.value))
        elif isinstance(statement, DictSetIR):
            names.add(statement.target.id)
            names.update(_expr_assigned_names(statement.key))
            names.update(_expr_assigned_names(statement.value))
        elif isinstance(statement, AppendIR):
            names.add(statement.target.id)
            names.update(_expr_assigned_names(statement.value))
        elif isinstance(statement, EffectCallIR):
            names.update(_expr_assigned_names(statement.call))
        elif isinstance(statement, ReturnIR):
            if statement.value is not None:
                names.update(_expr_assigned_names(statement.value))
        elif isinstance(statement, IfIR):
            names.update(_expr_assigned_names(statement.condition))
            names.update(_assigned_names(statement.body))
            names.update(_assigned_names(statement.orelse))
        elif isinstance(statement, ForIR):
            names.update(target_names(statement.target))
            names.update(_expr_assigned_names(statement.iterable))
            names.update(_assigned_names(statement.body))
            names.update(_assigned_names(statement.orelse))
        elif isinstance(statement, WhileIR):
            names.update(_expr_assigned_names(statement.condition))
            names.update(_assigned_names(statement.body))
            names.update(_assigned_names(statement.orelse))
        elif isinstance(statement, TryIR):
            names.update(_assigned_names(statement.body))
            names.update(_assigned_names(statement.finalbody))
            for handler in statement.handlers:
                names.update(_assigned_names(handler.body))
    return names


def _expr_assigned_names(expr: ExprIR) -> set[str]:
    if isinstance(expr, NamedExprIR):
        return {expr.target.id} | _expr_assigned_names(expr.value)
    if isinstance(expr, BinaryOpIR):
        return _expr_assigned_names(expr.left) | _expr_assigned_names(expr.right)
    if isinstance(expr, UnaryOpIR):
        return _expr_assigned_names(expr.value)
    if isinstance(expr, CompareIR):
        names = _expr_assigned_names(expr.left)
        for comparator in expr.comparators:
            names.update(_expr_assigned_names(comparator))
        return names
    if isinstance(expr, CallIR):
        names = set[str]()
        for arg in expr.args:
            names.update(_expr_assigned_names(arg))
        return names
    if isinstance(expr, IndexIR):
        return _expr_assigned_names(expr.value) | _expr_assigned_names(expr.index)
    if isinstance(expr, ListIR):
        names = set[str]()
        for item in expr.items:
            names.update(_expr_assigned_names(item))
        return names
    if isinstance(expr, TupleIR):
        names = set[str]()
        for item in expr.items:
            names.update(_expr_assigned_names(item))
        return names
    if isinstance(expr, DictIR):
        names = set[str]()
        for key, value in expr.items:
            names.update(_expr_assigned_names(key))
            names.update(_expr_assigned_names(value))
        return names
    if isinstance(expr, SetIR):
        names = set[str]()
        for item in expr.items:
            names.update(_expr_assigned_names(item))
        return names
    if isinstance(expr, ListComprehensionIR):
        return _comprehension_assigned_names(expr.generators, [expr.item])
    if isinstance(expr, DictComprehensionIR):
        return _comprehension_assigned_names(expr.generators, [expr.key, expr.value])
    if isinstance(expr, SetComprehensionIR):
        return _comprehension_assigned_names(expr.generators, [expr.item])
    return set()


def _comprehension_assigned_names(
    generators: list[ComprehensionGeneratorIR],
    result_exprs: list[ExprIR],
) -> set[str]:
    names: set[str] = set()
    for generator in generators:
        names.update(_expr_assigned_names(generator.iterable))
        for condition in generator.conditions:
            names.update(_expr_assigned_names(condition))
    for result_expr in result_exprs:
        names.update(_expr_assigned_names(result_expr))
    return names


def target_names(target: TargetIR) -> set[str]:
    """Return the set of names bound by an assignment target."""
    if isinstance(target, NameIR):
        return {target.id}
    if isinstance(target, TupleTargetIR):
        return {item.id for item in target.items}
    return set()


def literal_int(expr: ExprIR) -> int | None:
    """Return the integer value of an expression if it is an int literal, else None."""
    if (
        isinstance(expr, LiteralIR)
        and isinstance(expr.value, int)
        and not isinstance(expr.value, bool)
    ):
        return expr.value
    return None


def same_type(left: RxtType | None, right: RxtType | None) -> bool:
    """Report whether two optional Rextio types are equal."""
    if left is None or right is None:
        return False
    return left.to_dict() == right.to_dict()


def _has_resident_signature(function: FunctionIR) -> bool:
    """Whether a function's signature carries a resident (native-only) plugin type.

    Such a function has no valid Python boundary (a resident value has no
    conversion), so it is compiled as an internal native-only helper and never
    PyO3-exported (plugin API 1.3).
    """
    if isinstance(function.return_type, RxtPluginType) and function.return_type.resident:
        return True
    return any(
        isinstance(param.type, RxtPluginType) and param.type.resident for param in function.params
    )


def is_copy_rust_type(value_type: RxtType | None) -> bool:
    """Report whether a value type lowers to a Copy Rust type."""
    if isinstance(value_type, (RxtBool, RxtFloat, RxtInt, RxtNone)):
        return True
    if isinstance(value_type, RxtOptional):
        return is_copy_rust_type(value_type.item_type)
    if isinstance(value_type, RxtTuple):
        return all(is_copy_rust_type(item_type) for item_type in value_type.item_types)
    return False


def _needs_local_type_annotation(expr: ExprIR, target_type: RxtType) -> bool:
    return (
        (isinstance(expr, (DictIR, ListIR, SetIR)) and not expr.items)
        or (isinstance(expr, LiteralIR) and expr.value is None)
        or isinstance(target_type, RxtOptional)
    )
