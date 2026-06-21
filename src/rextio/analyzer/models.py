from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from rextio.analyzer.diagnostics import Diagnostic


@dataclass(frozen=True)
class CallSite:
    target: str
    line: int
    column: int
    in_loop: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "line": self.line,
            "column": self.column,
            "in_loop": self.in_loop,
        }


@dataclass
class FunctionAnalysis:
    name: str
    qualname: str
    module_name: str
    file_path: str
    line: int
    column: int
    is_native_candidate: bool = False
    accepted: bool = False
    calls: list[CallSite] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    inferred_arg_types: dict[str, str] = field(default_factory=dict)
    inferred_return_type: str | None = None

    @property
    def error_diagnostics(self) -> list[Diagnostic]:
        return [diagnostic for diagnostic in self.diagnostics if diagnostic.severity == "error"]

    @property
    def warning_diagnostics(self) -> list[Diagnostic]:
        return [diagnostic for diagnostic in self.diagnostics if diagnostic.severity == "warning"]

    def has_diagnostic(self, code: str, line: int | None = None, column: int | None = None) -> bool:
        for diagnostic in self.diagnostics:
            if diagnostic.code != code:
                continue
            if line is not None and diagnostic.line != line:
                continue
            if column is not None and diagnostic.column != column:
                continue
            return True
        return False

    def add_diagnostic(self, diagnostic: Diagnostic) -> None:
        if self.has_diagnostic(diagnostic.code, diagnostic.line, diagnostic.column):
            return
        self.diagnostics.append(diagnostic)

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "qualname": self.qualname,
            "module_name": self.module_name,
            "file_path": self.file_path,
            "line": self.line,
            "column": self.column,
            "is_native_candidate": self.is_native_candidate,
            "accepted": self.accepted,
            "inferred_arg_types": dict(sorted(self.inferred_arg_types.items())),
            "inferred_return_type": self.inferred_return_type,
            "calls": [call.to_dict() for call in self.calls],
            "diagnostics": [diagnostic.to_dict() for diagnostic in self.diagnostics],
        }


@dataclass
class ModuleAnalysis:
    module_name: str
    file_path: str
    functions: list[FunctionAnalysis] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    imports: dict[str, str] = field(default_factory=dict)

    @property
    def functions_by_name(self) -> dict[str, FunctionAnalysis]:
        return {function.name: function for function in self.functions}

    def to_dict(self) -> dict[str, object]:
        return {
            "module_name": self.module_name,
            "file_path": self.file_path,
            "imports": dict(sorted(self.imports.items())),
            "functions": [function.to_dict() for function in self.functions],
            "diagnostics": [diagnostic.to_dict() for diagnostic in self.diagnostics],
        }


@dataclass
class ProjectAnalysis:
    project_root: Path
    modules: list[ModuleAnalysis] = field(default_factory=list)

    @property
    def native_candidates(self) -> list[FunctionAnalysis]:
        return sorted(
            [function for module in self.modules for function in module.functions if function.is_native_candidate],
            key=lambda function: function.qualname,
        )

    @property
    def accepted_native_functions(self) -> list[FunctionAnalysis]:
        return sorted(
            [function for function in self.native_candidates if function.accepted],
            key=lambda function: function.qualname,
        )

    @property
    def rejected_native_functions(self) -> list[FunctionAnalysis]:
        return sorted(
            [function for function in self.native_candidates if not function.accepted],
            key=lambda function: function.qualname,
        )

    @property
    def diagnostics(self) -> list[Diagnostic]:
        diagnostics: list[Diagnostic] = []
        for module in self.modules:
            diagnostics.extend(module.diagnostics)
            for function in module.functions:
                diagnostics.extend(function.diagnostics)
        return sorted(
            diagnostics,
            key=lambda diagnostic: (
                diagnostic.file_path,
                diagnostic.line or 0,
                diagnostic.column or 0,
                diagnostic.code,
            ),
        )

    @property
    def boundary_warnings(self) -> list[Diagnostic]:
        return [
            diagnostic
            for diagnostic in self.diagnostics
            if diagnostic.code in {"RXT071", "RXT073"} and diagnostic.severity == "warning"
        ]

    @property
    def has_error_diagnostics(self) -> bool:
        return any(diagnostic.severity == "error" for diagnostic in self.diagnostics)

    def module_for_function(self, function: FunctionAnalysis) -> ModuleAnalysis | None:
        for module in self.modules:
            if module.module_name == function.module_name:
                return module
        return None

    def to_dict(self) -> dict[str, object]:
        return {
            "project_root": str(self.project_root),
            "modules": [module.to_dict() for module in self.modules],
            "native_candidates": [function.qualname for function in self.native_candidates],
            "accepted_native": [function.qualname for function in self.accepted_native_functions],
            "rejected_native": [function.qualname for function in self.rejected_native_functions],
            "diagnostics": [diagnostic.to_dict() for diagnostic in self.diagnostics],
        }
