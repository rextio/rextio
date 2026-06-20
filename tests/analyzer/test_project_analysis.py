from __future__ import annotations

from pathlib import Path

from rextio.analyzer.project_scanner import analyze_project


def write_module(root: Path, name: str, contents: str) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")
    return path


def diagnostic_codes(root: Path) -> set[str]:
    analysis = analyze_project(root)
    return {diagnostic.code for diagnostic in analysis.diagnostics}


def test_accepts_simple_native_to_native_calls(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "src/myapp/scoring.py",
        """
import rextio

@rextio.native
def square(x: float) -> float:
    return x * x

@rextio.native
def sum_squares(xs: list[float]) -> float:
    total = 0.0
    for x in xs:
        total = total + square(x)
    return total
""",
    )

    analysis = analyze_project(tmp_path)

    assert [function.qualname for function in analysis.accepted_native_functions] == [
        "myapp.scoring.square",
        "myapp.scoring.sum_squares",
    ]
    assert analysis.rejected_native_functions == []


def test_rejects_missing_type_annotations(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def bad(x):
    return x
""",
    )

    assert "RXT001" in diagnostic_codes(tmp_path)


def test_rejects_dynamic_features(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def bad(x: float) -> float:
    return getattr(x, "value")
""",
    )

    analysis = analyze_project(tmp_path)

    assert "RXT020" in {diagnostic.code for diagnostic in analysis.diagnostics}
    assert [function.qualname for function in analysis.rejected_native_functions] == ["app.bad"]


def test_rejects_native_to_fallback_calls(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

def helper(x: float) -> float:
    return x * x

@rextio.native
def compute(x: float) -> float:
    return helper(x)
""",
    )

    analysis = analyze_project(tmp_path)

    assert "RXT070" in {diagnostic.code for diagnostic in analysis.diagnostics}
    assert [function.qualname for function in analysis.rejected_native_functions] == ["app.compute"]


def test_rejects_unsupported_external_calls(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import math
import rextio

@rextio.native
def compute(x: float) -> float:
    return math.sqrt(x)
""",
    )

    analysis = analyze_project(tmp_path)

    assert "RXT030" in {diagnostic.code for diagnostic in analysis.diagnostics}
    assert [function.qualname for function in analysis.rejected_native_functions] == ["app.compute"]


def test_rejects_callers_of_rejected_native_dependencies(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def helper(x: float) -> float:
    return getattr(x, "value")

@rextio.native
def compute(x: float) -> float:
    return helper(x)
""",
    )

    analysis = analyze_project(tmp_path)
    diagnostics_by_function = {
        diagnostic.function_name: diagnostic.code for diagnostic in analysis.diagnostics
    }

    assert diagnostics_by_function["app.helper"] == "RXT020"
    assert diagnostics_by_function["app.compute"] == "RXT072"


def test_warns_for_python_loop_calling_native_function(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def score_one(x: float) -> float:
    return x * 2.0

def process_all(xs: list[float]) -> list[float]:
    out = []
    for x in xs:
        out.append(score_one(x))
    return out
""",
    )

    analysis = analyze_project(tmp_path)

    assert [function.qualname for function in analysis.accepted_native_functions] == ["app.score_one"]
    assert [diagnostic.code for diagnostic in analysis.boundary_warnings] == ["RXT071"]


def test_project_scanner_respects_rextioignore(tmp_path: Path) -> None:
    (tmp_path / ".rextioignore").write_text(
        """
# generated input
ignored_pkg/
*_generated.py
""",
        encoding="utf-8",
    )
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def accepted(x: int) -> int:
    return x
""",
    )
    write_module(
        tmp_path,
        "ignored_pkg/bad.py",
        """
import rextio

@rextio.native
def ignored(x):
    return x
""",
    )
    write_module(
        tmp_path,
        "also_generated.py",
        """
import rextio

@rextio.native
def ignored(x):
    return x
""",
    )

    analysis = analyze_project(tmp_path)

    assert [function.qualname for function in analysis.accepted_native_functions] == [
        "app.accepted"
    ]
    assert analysis.diagnostics == []
