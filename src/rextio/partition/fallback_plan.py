"""The fallback half of the build plan."""

from __future__ import annotations

from dataclasses import dataclass

from rextio.analyzer.models import (
    FunctionAnalysis,
    ModuleAnalysis,
    ProjectAnalysis,
    TopLevelAnalysis,
)


@dataclass(frozen=True)
class FallbackModulePlan:
    """The fallback plan for a single module."""

    module: ModuleAnalysis
    accepted_native_functions: tuple[FunctionAnalysis, ...]
    accepted_native_top_level: TopLevelAnalysis | None = None

    @property
    def needs_wrapper(self) -> bool:
        """Report whether the module needs a generated dispatch wrapper."""
        return bool(self.accepted_native_functions or self.accepted_native_top_level is not None)

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this plan."""
        return {
            "module": self.module.module_name,
            "needs_wrapper": self.needs_wrapper,
            "accepted_native": [
                function.qualname for function in self.accepted_native_functions
            ],
            "accepted_native_top_level": (
                self.accepted_native_top_level.qualname
                if self.accepted_native_top_level is not None
                else None
            ),
        }


@dataclass(frozen=True)
class FallbackPlan:
    """The fallback plan across modules."""

    backend: str
    modules: tuple[FallbackModulePlan, ...]

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this plan."""
        return {
            "backend": self.backend,
            "modules": [module.to_dict() for module in self.modules],
        }


def create_fallback_plan(analysis: ProjectAnalysis, backend: str) -> FallbackPlan:
    """Create the fallback plan for a project and backend."""
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
        accepted_top_level = (
            module.top_level
            if module.top_level is not None
            and module.top_level.is_native_candidate
            and module.top_level.accepted
            else None
        )
        modules.append(
            FallbackModulePlan(
                module=module,
                accepted_native_functions=accepted,
                accepted_native_top_level=accepted_top_level,
            )
        )
    return FallbackPlan(backend=backend, modules=tuple(modules))
