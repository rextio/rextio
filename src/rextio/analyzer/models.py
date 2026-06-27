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


@dataclass(frozen=True)
class ImportPolicyDecision:
    visible_name: str
    target: str
    package: str
    origin: str
    policy: str
    plugin: str | None = None
    max_depth: int = 0
    reason: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "visible_name": self.visible_name,
            "target": self.target,
            "package": self.package,
            "origin": self.origin,
            "policy": self.policy,
            "plugin": self.plugin,
            "max_depth": self.max_depth,
            "reason": self.reason,
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
    native_target_language: str | None = None
    native_runtime_semantics: bool = False
    imports: dict[str, str] = field(default_factory=dict)
    logger_names: tuple[str, ...] = ()

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
            "native_target_language": self.native_target_language,
            "native_runtime_semantics": self.native_runtime_semantics,
            "inferred_arg_types": dict(sorted(self.inferred_arg_types.items())),
            "inferred_return_type": self.inferred_return_type,
            "calls": [call.to_dict() for call in self.calls],
            "diagnostics": [diagnostic.to_dict() for diagnostic in self.diagnostics],
        }


@dataclass
class TopLevelAnalysis:
    name: str
    qualname: str
    module_name: str
    file_path: str
    line: int | None = None
    column: int | None = None
    is_native_candidate: bool = False
    accepted: bool = False
    assigned_types: dict[str, str] = field(default_factory=dict)
    export_value_type: str | None = None
    diagnostics: list[Diagnostic] = field(default_factory=list)

    @property
    def error_diagnostics(self) -> list[Diagnostic]:
        return [diagnostic for diagnostic in self.diagnostics if diagnostic.severity == "error"]

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
            "assigned_types": dict(sorted(self.assigned_types.items())),
            "export_value_type": self.export_value_type,
            "diagnostics": [diagnostic.to_dict() for diagnostic in self.diagnostics],
        }


@dataclass
class ModuleAnalysis:
    module_name: str
    file_path: str
    functions: list[FunctionAnalysis] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    imports: dict[str, str] = field(default_factory=dict)
    logger_names: tuple[str, ...] = ()
    import_policies: tuple[ImportPolicyDecision, ...] = ()
    top_level: TopLevelAnalysis | None = None

    @property
    def functions_by_name(self) -> dict[str, FunctionAnalysis]:
        return {function.name: function for function in self.functions}

    def to_dict(self) -> dict[str, object]:
        return {
            "module_name": self.module_name,
            "file_path": self.file_path,
            "imports": dict(sorted(self.imports.items())),
            "import_policies": [decision.to_dict() for decision in self.import_policies],
            "logger_names": list(self.logger_names),
            "functions": [function.to_dict() for function in self.functions],
            "top_level": self.top_level.to_dict() if self.top_level is not None else None,
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
    def native_top_levels(self) -> list[TopLevelAnalysis]:
        return sorted(
            [
                module.top_level
                for module in self.modules
                if module.top_level is not None and module.top_level.is_native_candidate
            ],
            key=lambda top_level: top_level.qualname,
        )

    @property
    def accepted_native_top_levels(self) -> list[TopLevelAnalysis]:
        return sorted(
            [top_level for top_level in self.native_top_levels if top_level.accepted],
            key=lambda top_level: top_level.qualname,
        )

    @property
    def rejected_native_top_levels(self) -> list[TopLevelAnalysis]:
        return sorted(
            [top_level for top_level in self.native_top_levels if not top_level.accepted],
            key=lambda top_level: top_level.qualname,
        )

    @property
    def diagnostics(self) -> list[Diagnostic]:
        diagnostics: list[Diagnostic] = []
        for module in self.modules:
            diagnostics.extend(module.diagnostics)
            for function in module.functions:
                diagnostics.extend(function.diagnostics)
            if module.top_level is not None:
                diagnostics.extend(module.top_level.diagnostics)
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
            "native_top_levels": [top_level.qualname for top_level in self.native_top_levels],
            "accepted_native_top_levels": [
                top_level.qualname for top_level in self.accepted_native_top_levels
            ],
            "rejected_native_top_levels": [
                top_level.qualname for top_level in self.rejected_native_top_levels
            ],
            "diagnostics": [diagnostic.to_dict() for diagnostic in self.diagnostics],
        }
