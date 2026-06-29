"""Partitioning of a project into its native and fallback build plans."""

from __future__ import annotations

from rextio.partition.build_plan import BuildPlan, create_build_plan
from rextio.partition.fallback_plan import FallbackModulePlan, FallbackPlan
from rextio.partition.native_plan import NativePlan

__all__ = [
    "BuildPlan",
    "FallbackModulePlan",
    "FallbackPlan",
    "NativePlan",
    "create_build_plan",
]

