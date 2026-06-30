"""Native/fallback boundary checks (RXT07x): which native↔fallback crossings are allowed or warned."""

from __future__ import annotations

from rextio.analyzer.common_calls import COMMON_DIRECT_RUST_CALLS
from rextio.analyzer.call_resolution import FunctionResolver
from rextio.analyzer.diagnostics import Diagnostic
from rextio.analyzer.import_policy import decision_for_target
from rextio.analyzer.models import CallSite, FunctionAnalysis, ModuleAnalysis, ProjectAnalysis

SUPPORTED_INTERNAL_CALLS = {
    "abs",
    "len",
    "max",
    "min",
    "range",
    "sum",
    "enumerate",
    "zip",
    "math.cos",
    "math.floor",
    "math.sin",
    "math.sqrt",
    *COMMON_DIRECT_RUST_CALLS,
}

BOUNDARY_DIAGNOSTIC_MESSAGES = {
    "RXT070": "Native function calls fallback-only function.",
    "RXT072": "Native dependency rejected, so caller must fall back.",
    "RXT073": "Native function call inside Python loop may erase speedup.",
    "RXT074": "Undecorated function depends on a runtime-shim native; mark it @rextio.native to opt in.",
}


def apply_boundary_checks(
    analysis: ProjectAnalysis,
    boundary_warnings: bool = True,
    native_jit_enabled: bool = False,
) -> None:
    """Apply the native/fallback boundary policy, attaching RXT07x diagnostics."""
    resolver = FunctionResolver(analysis)
    for function in analysis.native_candidates:
        function.accepted = not function.error_diagnostics

    changed = True
    while changed:
        changed = False
        for module in analysis.modules:
            for function in sorted(module.functions, key=lambda item: item.qualname):
                if not function.is_native_candidate or not function.accepted:
                    continue
                runtime_dependency = _first_runtime_dependency(module, function, resolver)
                if runtime_dependency is not None:
                    call, dependency = runtime_dependency
                    if function.explicitly_marked:
                        # An explicitly opted-in function inherits the runtime
                        # semantics shim required by its native dependency.
                        function.native_runtime_semantics = True
                        function.add_diagnostic(
                            _runtime_shim_propagation_diagnostic(function, dependency, call)
                        )
                    else:
                        # Auto-discovered functions are not silently promoted to
                        # the RXT080 shim through the call graph (P0-4); they fall
                        # back to Python unless explicitly marked @rextio.native.
                        function.accepted = False
                        function.add_diagnostic(
                            _runtime_shim_requires_marker_diagnostic(function, dependency, call)
                        )
                    changed = True
                    continue
                boundary_errors = _boundary_errors(
                    module,
                    function,
                    resolver,
                    native_jit_enabled=native_jit_enabled,
                )
                if boundary_errors:
                    for diagnostic in boundary_errors:
                        function.add_diagnostic(diagnostic)
                    function.accepted = False
                    changed = True

    if boundary_warnings:
        _add_python_loop_boundary_warnings(analysis, resolver)


def _boundary_errors(
    module: ModuleAnalysis,
    function: FunctionAnalysis,
    resolver: FunctionResolver,
    native_jit_enabled: bool = False,
) -> list[Diagnostic]:
    if function.native_runtime_semantics:
        return []
    diagnostics: list[Diagnostic] = []
    for call in function.calls:
        target = call.target
        resolved = resolver.resolve(module, target)
        if target in SUPPORTED_INTERNAL_CALLS or target.endswith(".append"):
            continue
        dependency = resolved.function
        if native_jit_enabled and dependency is not None and dependency.is_jit_candidate:
            continue
        if dependency is not None and not dependency.is_native_candidate:
            diagnostics.append(
                Diagnostic(
                    code="RXT070",
                    severity="error",
                    message=f"native function calls fallback-only function: {resolved.resolved_target}",
                    file_path=function.file_path,
                    line=call.line,
                    column=call.column,
                    function_name=function.qualname,
                    suggestion=(
                        "Mark the dependency as @rextio.native if it belongs to the supported subset, "
                        "or remove the call from the native function."
                    ),
                )
            )
            continue
        if dependency is not None and not dependency.accepted:
            diagnostics.append(
                Diagnostic(
                    code="RXT072",
                    severity="error",
                    message=f"native dependency rejected, so caller must fall back: {resolved.resolved_target}",
                    file_path=function.file_path,
                    line=call.line,
                    column=call.column,
                    function_name=function.qualname,
                    suggestion="Fix the rejected native dependency or keep this caller on fallback.",
                )
            )
            continue
        if dependency is not None:
            diagnostics.extend(_native_arg_type_errors(function, call, dependency))
            continue

        decision = decision_for_target(module, resolved.resolved_target)
        message, suggestion = _external_call_diagnostic_text(resolved.resolved_target, call.in_loop, decision)
        diagnostics.append(
            Diagnostic(
                code="RXT030",
                severity="error",
                message=message,
                file_path=function.file_path,
                line=call.line,
                column=call.column,
                function_name=function.qualname,
                suggestion=suggestion,
            )
        )
    return diagnostics


_SCALAR_PARAM_TYPES = {"int", "float", "bool", "str", "bytes"}


def _native_arg_type_errors(
    function: FunctionAnalysis,
    call: CallSite,
    dependency: FunctionAnalysis,
) -> list[Diagnostic]:
    """Reject native→native calls with literal args that mismatch scalar params.

    Rust has no implicit numeric coercion, so passing a literal of a different
    scalar type than the callee declares (e.g. ``g(1.2)`` where ``g(x: int)``,
    or ``g(1)`` where ``g(x: float)``) compiles to Rust that fails ``cargo build``
    with E0308. CPython accepts such calls, so the contract requires keeping the
    caller on the Python fallback rather than silently building broken native code.

    Only literal arguments (``call.arg_types`` entry not None) against scalar
    parameters are checked; non-literal arguments and non-scalar parameters
    (``Optional[...]``, ``list[...]``, etc.) are left to the existing passes.
    """
    param_types = list(dependency.signature_arg_types.values())
    diagnostics: list[Diagnostic] = []
    for index, arg_type in enumerate(call.arg_types):
        if arg_type is None or index >= len(param_types):
            continue
        param_type = param_types[index]
        if param_type not in _SCALAR_PARAM_TYPES or arg_type == param_type:
            continue
        diagnostics.append(
            Diagnostic(
                code="RXT010",
                severity="error",
                message=(
                    f"native call argument {index + 1} to {dependency.qualname} has "
                    f"type {arg_type} but the parameter is {param_type}; Rust has no "
                    "implicit scalar coercion, so this would emit native code that fails "
                    "to compile"
                ),
                file_path=function.file_path,
                line=call.line,
                column=call.column,
                function_name=function.qualname,
                suggestion=(
                    "Pass an argument whose type matches the native parameter exactly "
                    "(no int/float/bool mixing), or keep this caller on the Python fallback."
                ),
            )
        )
    return diagnostics


def _external_call_diagnostic_text(target: str, in_loop: bool, decision) -> tuple[str, str]:
    if decision is None:
        return (
            f"unsupported unresolved call in native function: {target}",
            "Native functions may call only accepted native functions and supported builtins.",
        )
    if decision.origin == "stdlib":
        return (
            f"unsupported standard-library call in native function: {target}",
            "Use a supported Rextio standard-library subset call or keep this function on fallback.",
        )
    if decision.policy == "plugin":
        plugin = decision.plugin or "<unconfigured>"
        return (
            f"plugin-managed external package call is not lowered by this build: {target}",
            (
                f"Ensure plugin {plugin!r} is active and provides a direct lowering rule for this call, "
                "or keep the function on fallback."
            ),
        )
    if decision.policy == "try-native":
        return (
            f"external package call requires experimental dependency lowering and remains fallback: {target}",
            _external_package_suggestion(in_loop, "dependency lowering is opt-in and not available for this call"),
        )
    if decision.policy == "analyze":
        return (
            f"external package call is analyze-only and remains fallback: {target}",
            _external_package_suggestion(in_loop, "switch this package to try-native only if it is pure Python and safe"),
        )
    return (
        f"external package call uses fallback import policy: {target}",
        _external_package_suggestion(in_loop, "add a Rextio plugin or explicit try-native package policy if needed"),
    )


def _external_package_suggestion(in_loop: bool, action: str) -> str:
    base = (
        f"{action}; otherwise keep this function on CPython/Nuitka fallback so Rextio does not "
        "silently transform third-party package code."
    )
    if not in_loop:
        return base
    return (
        f"{base} This call is inside a loop, so prefer function-level fallback, a package plugin, "
        "or a batch API refactor to avoid repeated Python/Rust boundary crossings."
    )


def _first_runtime_dependency(
    module: ModuleAnalysis,
    function: FunctionAnalysis,
    resolver: FunctionResolver,
) -> tuple[CallSite, FunctionAnalysis] | None:
    if function.native_runtime_semantics:
        return None
    for call in function.calls:
        dependency = resolver.resolve(module, call.target).function
        if dependency is None or not dependency.accepted or not dependency.native_runtime_semantics:
            continue
        return call, dependency
    return None


def _runtime_shim_propagation_diagnostic(
    function: FunctionAnalysis,
    dependency: FunctionAnalysis,
    call: CallSite,
) -> Diagnostic:
    return Diagnostic(
        code="RXT080",
        severity="warning",
        message=(
            "native function uses Python runtime semantics shim because it calls "
            f"runtime-backed native function: {dependency.qualname}"
        ),
        file_path=function.file_path,
        line=call.line,
        column=call.column,
        function_name=function.qualname,
        suggestion=(
            "Rextio will route this function through the Python runtime semantics "
            "shim so the native dependency can preserve Python object behavior."
        ),
    )


def _runtime_shim_requires_marker_diagnostic(
    function: FunctionAnalysis,
    dependency: FunctionAnalysis,
    call: CallSite,
) -> Diagnostic:
    return Diagnostic(
        code="RXT074",
        severity="error",
        message=(
            "auto-discovered function calls runtime-backed native function "
            f"{dependency.qualname}; it would require the Python runtime semantics "
            "shim, which is only applied to explicitly marked functions"
        ),
        file_path=function.file_path,
        line=call.line,
        column=call.column,
        function_name=function.qualname,
        suggestion=(
            "Add @rextio.native to this function to opt into the runtime semantics "
            "shim, or leave it on the Python fallback path."
        ),
    )


def _add_python_loop_boundary_warnings(
    analysis: ProjectAnalysis,
    resolver: FunctionResolver,
) -> None:
    for module in analysis.modules:
        for function in module.functions:
            if function.is_native_candidate and function.accepted:
                continue
            for call in function.calls:
                resolved = resolver.resolve(module, call.target)
                dependency = resolved.function
                if (
                    dependency is None
                    or not dependency.is_native_candidate
                    or not dependency.accepted
                    or not call.in_loop
                ):
                    continue
                if function.has_diagnostic("RXT073", call.line, call.column):
                    continue
                function.add_diagnostic(
                    Diagnostic(
                        code="RXT073",
                        severity="warning",
                        message=(
                            f"native function call inside Python loop may erase speedup: "
                            f"{call.target}"
                        ),
                        file_path=function.file_path,
                        line=call.line,
                        column=call.column,
                        function_name=function.qualname,
                        suggestion=(
                            "Move the loop into a native batch function. Supported batch loops include "
                            "for x in xs, for i, x in enumerate(xs), and for x, y in zip(xs, ys)."
                        ),
                    )
                )
