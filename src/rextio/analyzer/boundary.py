from __future__ import annotations

from rextio.analyzer.common_calls import COMMON_DIRECT_RUST_CALLS
from rextio.analyzer.call_resolution import FunctionResolver
from rextio.analyzer.diagnostics import Diagnostic
from rextio.analyzer.import_policy import decision_for_target
from rextio.analyzer.models import FunctionAnalysis, ModuleAnalysis, ProjectAnalysis

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
    "RXT071": "Possible excessive Python/Rust boundary crossing.",
    "RXT072": "Native dependency rejected, so caller must fall back.",
    "RXT073": "Native function call inside Python loop may erase speedup.",
}


def apply_boundary_checks(
    analysis: ProjectAnalysis,
    boundary_warnings: bool = True,
    native_jit_enabled: bool = False,
) -> None:
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
                runtime_diagnostic = _first_runtime_dependency(module, function, resolver)
                if runtime_diagnostic is not None:
                    function.native_runtime_semantics = True
                    function.add_diagnostic(runtime_diagnostic)
                    changed = True
                    continue
                diagnostic = _first_boundary_error(
                    module,
                    function,
                    resolver,
                    native_jit_enabled=native_jit_enabled,
                )
                if diagnostic is not None:
                    function.add_diagnostic(diagnostic)
                    function.accepted = False
                    changed = True

    if boundary_warnings:
        _add_python_loop_boundary_warnings(analysis, resolver)


def _first_boundary_error(
    module: ModuleAnalysis,
    function: FunctionAnalysis,
    resolver: FunctionResolver,
    native_jit_enabled: bool = False,
) -> Diagnostic | None:
    for call in function.calls:
        if function.native_runtime_semantics:
            return None
        target = call.target
        resolved = resolver.resolve(module, target)
        if target in SUPPORTED_INTERNAL_CALLS or target.endswith(".append"):
            continue
        dependency = resolved.function
        if native_jit_enabled and dependency is not None and dependency.is_jit_candidate:
            continue
        if dependency is not None and not dependency.is_native_candidate:
            return Diagnostic(
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
        if dependency is not None and not dependency.accepted:
            return Diagnostic(
                code="RXT072",
                severity="error",
                message=f"native dependency rejected, so caller must fall back: {resolved.resolved_target}",
                file_path=function.file_path,
                line=call.line,
                column=call.column,
                function_name=function.qualname,
                suggestion="Fix the rejected native dependency or keep this caller on fallback.",
            )
        if dependency is not None:
            continue

        decision = decision_for_target(module, resolved.resolved_target)
        message, suggestion = _external_call_diagnostic_text(resolved.resolved_target, call.in_loop, decision)
        return Diagnostic(
            code="RXT030",
            severity="error",
            message=message,
            file_path=function.file_path,
            line=call.line,
            column=call.column,
            function_name=function.qualname,
            suggestion=suggestion,
        )
    return None


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
) -> Diagnostic | None:
    if function.native_runtime_semantics:
        return None
    for call in function.calls:
        dependency = resolver.resolve(module, call.target).function
        if dependency is None or not dependency.accepted or not dependency.native_runtime_semantics:
            continue
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
    return None


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
