from __future__ import annotations

from rextio.analyzer.call_resolution import FunctionResolver
from rextio.analyzer.diagnostics import Diagnostic
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
}

BOUNDARY_DIAGNOSTIC_MESSAGES = {
    "RXT070": "Native function calls fallback-only function.",
    "RXT071": "Possible excessive Python/Rust boundary crossing.",
    "RXT072": "Native dependency rejected, so caller must fall back.",
    "RXT073": "Native function call inside Python loop may erase speedup.",
}


def apply_boundary_checks(analysis: ProjectAnalysis, boundary_warnings: bool = True) -> None:
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
                diagnostic = _first_boundary_error(module, function, resolver)
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
) -> Diagnostic | None:
    for call in function.calls:
        target = call.target
        resolved = resolver.resolve(module, target)
        if target in SUPPORTED_INTERNAL_CALLS or target.endswith(".append"):
            continue
        dependency = resolved.function
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

        return Diagnostic(
            code="RXT030",
            severity="error",
            message=(
                "unsupported external package or unresolved call in native function: "
                f"{resolved.resolved_target}"
            ),
            file_path=function.file_path,
            line=call.line,
            column=call.column,
            function_name=function.qualname,
            suggestion="Native functions may call only accepted native functions and supported builtins.",
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
