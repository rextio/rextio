from __future__ import annotations

from dataclasses import dataclass

from rextio.analyzer.models import FunctionAnalysis, ModuleAnalysis, ProjectAnalysis


@dataclass(frozen=True)
class ResolvedCall:
    raw_target: str
    resolved_target: str
    function: FunctionAnalysis | None


class FunctionResolver:
    def __init__(self, analysis: ProjectAnalysis) -> None:
        self.functions_by_qualname = {
            function.qualname: function
            for module in analysis.modules
            for function in module.functions
        }

    def resolve(self, module: ModuleAnalysis, raw_target: str) -> ResolvedCall:
        local_target = _local_qualname(module, raw_target)
        if local_target is not None and local_target in self.functions_by_qualname:
            return ResolvedCall(raw_target, local_target, self.functions_by_qualname[local_target])

        if raw_target in self.functions_by_qualname:
            return ResolvedCall(raw_target, raw_target, self.functions_by_qualname[raw_target])

        imported_target = _resolve_import_alias(module, raw_target)
        if imported_target in self.functions_by_qualname:
            return ResolvedCall(
                raw_target,
                imported_target,
                self.functions_by_qualname[imported_target],
            )

        return ResolvedCall(raw_target, imported_target, None)


def _local_qualname(module: ModuleAnalysis, raw_target: str) -> str | None:
    if "." in raw_target:
        return None
    if not module.module_name:
        return raw_target
    return f"{module.module_name}.{raw_target}"


def _resolve_import_alias(module: ModuleAnalysis, raw_target: str) -> str:
    head, separator, tail = raw_target.partition(".")
    imported = module.imports.get(head)
    if imported is None:
        return raw_target
    if separator:
        return f"{imported}.{tail}"
    return imported
