from __future__ import annotations

from dataclasses import dataclass

from rextio.analyzer.models import FunctionAnalysis, ProjectAnalysis, TopLevelAnalysis


@dataclass(frozen=True)
class NativePlan:
    accepted_functions: tuple[FunctionAnalysis, ...]
    rejected_functions: tuple[FunctionAnalysis, ...]
    jit_functions: tuple[FunctionAnalysis, ...] = ()
    accepted_top_levels: tuple[TopLevelAnalysis, ...] = ()
    rejected_top_levels: tuple[TopLevelAnalysis, ...] = ()

    @property
    def accepted_count(self) -> int:
        return len(self.accepted_functions) + len(self.accepted_top_levels)

    @property
    def rejected_count(self) -> int:
        return len(self.rejected_functions) + len(self.rejected_top_levels)

    @property
    def has_native_artifacts(self) -> bool:
        return bool(self.accepted_functions or self.accepted_top_levels)

    def to_dict(self) -> dict[str, object]:
        return {
            "accepted": [function.qualname for function in self.accepted_functions],
            "rejected": [function.qualname for function in self.rejected_functions],
            "jit": [function.qualname for function in self.jit_functions],
            "accepted_top_levels": [
                top_level.qualname for top_level in self.accepted_top_levels
            ],
            "rejected_top_levels": [
                top_level.qualname for top_level in self.rejected_top_levels
            ],
        }


def create_native_plan(analysis: ProjectAnalysis) -> NativePlan:
    return NativePlan(
        accepted_functions=tuple(analysis.accepted_native_functions),
        rejected_functions=tuple(analysis.rejected_native_functions),
        jit_functions=tuple(analysis.jit_candidates),
        accepted_top_levels=tuple(analysis.accepted_native_top_levels),
        rejected_top_levels=tuple(analysis.rejected_native_top_levels),
    )
