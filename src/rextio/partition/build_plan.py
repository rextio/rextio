"""The overall build plan (native + fallback)."""

from __future__ import annotations

from dataclasses import dataclass

from rextio.analyzer.models import ProjectAnalysis
from rextio.partition.fallback_plan import FallbackPlan, create_fallback_plan
from rextio.partition.native_plan import NativePlan, create_native_plan


@dataclass(frozen=True)
class BuildPlan:
    """The full build plan: the native plan and the fallback plan."""

    analysis: ProjectAnalysis
    native: NativePlan
    fallback: FallbackPlan

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this plan."""
        return {
            "native": self.native.to_dict(),
            "fallback": self.fallback.to_dict(),
        }


def create_build_plan(analysis: ProjectAnalysis, fallback_backend: str) -> BuildPlan:
    """Create the build plan for a project and fallback backend."""
    return BuildPlan(
        analysis=analysis,
        native=create_native_plan(analysis),
        fallback=create_fallback_plan(analysis, fallback_backend),
    )
