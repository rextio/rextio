from __future__ import annotations

from dataclasses import dataclass

from rextio.analyzer.models import FunctionAnalysis, ProjectAnalysis


@dataclass(frozen=True)
class NativePlan:
    accepted_functions: tuple[FunctionAnalysis, ...]
    rejected_functions: tuple[FunctionAnalysis, ...]

    @property
    def accepted_count(self) -> int:
        return len(self.accepted_functions)

    @property
    def rejected_count(self) -> int:
        return len(self.rejected_functions)

    def to_dict(self) -> dict[str, object]:
        return {
            "accepted": [function.qualname for function in self.accepted_functions],
            "rejected": [function.qualname for function in self.rejected_functions],
        }


def create_native_plan(analysis: ProjectAnalysis) -> NativePlan:
    return NativePlan(
        accepted_functions=tuple(analysis.accepted_native_functions),
        rejected_functions=tuple(analysis.rejected_native_functions),
    )

