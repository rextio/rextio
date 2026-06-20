from __future__ import annotations

from rextio.analyzer.diagnostics import Diagnostic
from rextio.analyzer.models import FunctionAnalysis, ModuleAnalysis, ProjectAnalysis

SUPPORTED_BUILTINS = {"len", "range"}

BOUNDARY_DIAGNOSTIC_MESSAGES = {
    "RXT070": "Native function calls fallback-only function.",
    "RXT071": "Possible excessive Python/Rust boundary crossing.",
    "RXT072": "Native dependency rejected, so caller must fall back.",
    "RXT073": "Native function call inside Python loop may erase speedup.",
}


def apply_boundary_checks(analysis: ProjectAnalysis) -> None:
    for function in analysis.native_candidates:
        function.accepted = not function.error_diagnostics

    changed = True
    while changed:
        changed = False
        for module in analysis.modules:
            for function in sorted(module.functions, key=lambda item: item.qualname):
                if not function.is_native_candidate or not function.accepted:
                    continue
                diagnostic = _first_boundary_error(module, function)
                if diagnostic is not None:
                    function.add_diagnostic(diagnostic)
                    function.accepted = False
                    changed = True

    _add_python_loop_boundary_warnings(analysis)


def _first_boundary_error(module: ModuleAnalysis, function: FunctionAnalysis) -> Diagnostic | None:
    functions_by_name = module.functions_by_name
    for call in function.calls:
        target = call.target
        if target in SUPPORTED_BUILTINS:
            continue
        if target in functions_by_name:
            dependency = functions_by_name[target]
            if not dependency.is_native_candidate:
                return Diagnostic(
                    code="RXT070",
                    severity="error",
                    message=f"native function calls fallback-only function: {target}",
                    file_path=function.file_path,
                    line=call.line,
                    column=call.column,
                    function_name=function.qualname,
                    suggestion=(
                        "Mark the dependency as @rextio.native if it belongs to the supported subset, "
                        "or remove the call from the native function."
                    ),
                )
            if not dependency.accepted:
                return Diagnostic(
                    code="RXT072",
                    severity="error",
                    message=f"native dependency rejected, so caller must fall back: {target}",
                    file_path=function.file_path,
                    line=call.line,
                    column=call.column,
                    function_name=function.qualname,
                    suggestion="Fix the rejected native dependency or keep this caller on fallback.",
                )
            continue

        return Diagnostic(
            code="RXT030",
            severity="error",
            message=f"unsupported external package or unresolved call in native function: {target}",
            file_path=function.file_path,
            line=call.line,
            column=call.column,
            function_name=function.qualname,
            suggestion="Native functions may call only accepted native functions and supported builtins.",
        )
    return None


def _add_python_loop_boundary_warnings(analysis: ProjectAnalysis) -> None:
    for module in analysis.modules:
        accepted_native = {
            function.name
            for function in module.functions
            if function.is_native_candidate and function.accepted
        }
        if not accepted_native:
            continue
        for function in module.functions:
            if function.is_native_candidate and function.accepted:
                continue
            for call in function.calls:
                if call.target not in accepted_native or not call.in_loop:
                    continue
                if function.has_diagnostic("RXT071", call.line, call.column):
                    continue
                function.add_diagnostic(
                    Diagnostic(
                        code="RXT071",
                        severity="warning",
                        message=(
                            f"possible excessive Python/Rust boundary crossing: "
                            f"{call.target} is called inside a Python loop"
                        ),
                        file_path=function.file_path,
                        line=call.line,
                        column=call.column,
                        function_name=function.qualname,
                        suggestion="Move the loop into a native batch function.",
                    )
                )
