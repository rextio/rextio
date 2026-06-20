from __future__ import annotations

from pathlib import Path

from rextio.analyzer.project_scanner import analyze_project

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_pure_math_example_has_required_native_candidates() -> None:
    analysis = analyze_project(REPO_ROOT / "examples" / "pure_math")

    assert [function.qualname for function in analysis.accepted_native_functions] == [
        "pure_math.math_ops.count_positive",
        "pure_math.math_ops.dot_simple",
        "pure_math.math_ops.sum_squares",
    ]
    assert analysis.rejected_native_functions == []


def test_fastapi_scoring_keeps_framework_shell_in_fallback() -> None:
    analysis = analyze_project(REPO_ROOT / "examples" / "fastapi_scoring")

    assert [function.qualname for function in analysis.accepted_native_functions] == [
        "fastapi_scoring.scoring.compute_score"
    ]
    assert analysis.rejected_native_functions == []


def test_fallback_demo_has_native_score_and_boundary_warning() -> None:
    analysis = analyze_project(REPO_ROOT / "examples" / "fallback_demo")

    assert [function.qualname for function in analysis.accepted_native_functions] == [
        "fallback_demo.scoring.score_one"
    ]
    assert [diagnostic.code for diagnostic in analysis.boundary_warnings] == ["RXT071"]


def test_boundary_demo_shows_rejection_and_warning() -> None:
    analysis = analyze_project(REPO_ROOT / "examples" / "boundary_demo")
    diagnostics = {diagnostic.code for diagnostic in analysis.diagnostics}

    assert "boundary_demo.pipeline.square" in [
        function.qualname for function in analysis.accepted_native_functions
    ]
    assert "boundary_demo.pipeline.sum_squares" in [
        function.qualname for function in analysis.accepted_native_functions
    ]
    assert [function.qualname for function in analysis.rejected_native_functions] == [
        "boundary_demo.pipeline.compute_rejected"
    ]
    assert {"RXT070", "RXT071"}.issubset(diagnostics)
