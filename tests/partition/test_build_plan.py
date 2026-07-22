from __future__ import annotations

from pathlib import Path

from rextio.analyzer.project_scanner import analyze_project
from rextio.artifacts.profiles import host_extension_profile
from rextio.partition import create_build_plan
from rextio.partition.classifier import classify_function


def test_build_plan_partitions_native_and_fallback_modules(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        """
import rextio

@rextio.native
def add(a: int, b: int) -> int:
    return a + b

def helper(xs: list[int]) -> int:
    return xs[0] + 1

@rextio.native
def rejected(xs: list[int]) -> int:
    return helper(xs)
""",
        encoding="utf-8",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")
    profile = host_extension_profile("aarch64-apple-darwin", python_fallback_backend="cpython")
    plan = create_build_plan(analysis, "cpython", artifact_profiles=(profile,))
    functions = {
        function.name: function for module in analysis.modules for function in module.functions
    }

    assert [function.qualname for function in plan.native.accepted_functions] == ["app.add"]
    assert [function.qualname for function in plan.native.rejected_functions] == ["app.rejected"]
    assert plan.fallback.backend == "cpython"
    assert plan.fallback.modules[0].needs_wrapper is True
    assert plan.artifact_profiles == (profile,)
    assert plan.to_dict()["artifact_profiles"] == [profile.to_dict()]
    assert plan.to_dict()["host_source_plan"]["availability"] == "available"
    assert classify_function(functions["add"]) == "native"
    assert classify_function(functions["helper"]) == "fallback"
    assert classify_function(functions["rejected"]) == "fallback"
