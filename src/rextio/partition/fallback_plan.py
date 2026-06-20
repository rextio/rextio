from __future__ import annotations

from dataclasses import dataclass

from rextio.analyzer.models import FunctionAnalysis, ModuleAnalysis, ProjectAnalysis


@dataclass(frozen=True)
class FallbackModulePlan:
    module: ModuleAnalysis
    accepted_native_functions: tuple[FunctionAnalysis, ...]

    @property
    def needs_wrapper(self) -> bool:
        return bool(self.accepted_native_functions)

    def to_dict(self) -> dict[str, object]:
        return {
            "module": self.module.module_name,
            "needs_wrapper": self.needs_wrapper,
            "accepted_native": [
                function.qualname for function in self.accepted_native_functions
            ],
        }


@dataclass(frozen=True)
class FallbackPlan:
    backend: str
    modules: tuple[FallbackModulePlan, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "backend": self.backend,
            "modules": [module.to_dict() for module in self.modules],
        }


def create_fallback_plan(analysis: ProjectAnalysis, backend: str) -> FallbackPlan:
    modules = []
    for module in sorted(analysis.modules, key=lambda item: item.module_name):
        accepted = tuple(
            sorted(
                (
                    function
                    for function in module.functions
                    if function.is_native_candidate and function.accepted
                ),
                key=lambda function: function.qualname,
            )
        )
        modules.append(FallbackModulePlan(module=module, accepted_native_functions=accepted))
    return FallbackPlan(backend=backend, modules=tuple(modules))

