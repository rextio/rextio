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

    analysis = analyze_project(tmp_path, native_marker="decorator")

    assert [function.qualname for function in analysis.accepted_native_functions] == [
        "myapp.scoring.square",
        "myapp.scoring.sum_squares",
    ]
    assert analysis.rejected_native_functions == []


def test_accepts_cross_module_native_to_native_calls(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "src/myapp/math_ops.py",
        """
import rextio

@rextio.native
def square(x: float) -> float:
    return x * x
""",
    )
    write_module(
        tmp_path,
        "src/myapp/scoring.py",
        """
import rextio

from .math_ops import square

@rextio.native
def score(x: float) -> float:
    return square(x) + 1.0
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    assert [function.qualname for function in analysis.accepted_native_functions] == [
        "myapp.math_ops.square",
        "myapp.scoring.score",
    ]
    assert analysis.rejected_native_functions == []


def test_auto_discovers_unmarked_typed_supported_functions(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
def square(x: float) -> float:
    return x * x

def sum_squares(xs: list[float]) -> float:
    total = 0.0
    for x in xs:
        total += square(x)
    return total

def fallback_only(xs):
    return xs
""",
    )

    analysis = analyze_project(tmp_path)

    assert [function.qualname for function in analysis.accepted_native_functions] == [
        "app.square",
        "app.sum_squares",
    ]
    assert analysis.rejected_native_functions == []
    assert analysis.diagnostics == []


def test_exempt_marker_prevents_auto_native_discovery(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.exempt
def keep_python(x: int) -> int:
    return x + 1

def add(a: int, b: int) -> int:
    return a + b
""",
    )

    analysis = analyze_project(tmp_path)

    assert [function.qualname for function in analysis.accepted_native_functions] == ["app.add"]
    assert "app.keep_python" not in [
        function.qualname for function in analysis.native_candidates
    ]
    assert analysis.diagnostics == []


def test_exempt_marker_takes_precedence_over_native_marker(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.exempt
@rextio.native
def keep_python(x: int) -> int:
    return x + 1
""",
    )

    analysis = analyze_project(tmp_path)

    assert analysis.native_candidates == []
    assert analysis.diagnostics == []


def test_native_call_to_exempt_function_is_rejected_as_fallback_boundary(
    tmp_path: Path,
) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.exempt
def helper(x: float) -> float:
    return x * x

@rextio.native
def compute(x: float) -> float:
    return helper(x)
""",
    )

    analysis = analyze_project(tmp_path)

    assert "RXT070" in {diagnostic.code for diagnostic in analysis.diagnostics}
    assert [function.qualname for function in analysis.rejected_native_functions] == [
        "app.compute"
    ]
    assert "app.helper" not in [function.qualname for function in analysis.native_candidates]


def test_decorator_policy_disables_auto_discovery(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
def add(a: int, b: int) -> int:
    return a + b
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    assert analysis.native_candidates == []
    assert analysis.diagnostics == []


def test_rejects_cross_module_native_to_fallback_calls(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "src/myapp/helpers.py",
        """
def adjust(x: float) -> float:
    return x + 1.0
""",
    )
    write_module(
        tmp_path,
        "src/myapp/scoring.py",
        """
import rextio

from .helpers import adjust

@rextio.native
def score(x: float) -> float:
    return adjust(x)
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    assert "RXT070" in {diagnostic.code for diagnostic in analysis.diagnostics}
    assert [function.qualname for function in analysis.rejected_native_functions] == [
        "myapp.scoring.score"
    ]


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

    analysis = analyze_project(tmp_path, native_marker="decorator")

    assert "RXT020" in {diagnostic.code for diagnostic in analysis.diagnostics}
    assert [function.qualname for function in analysis.rejected_native_functions] == ["app.bad"]


def test_rejects_unsupported_control_flow_syntax(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def bad(xs: list[int]) -> int:
    total = 0
    for x in xs:
        if x < 0:
            break
        total = total + x
    return total
""",
    )

    analysis = analyze_project(tmp_path)

    assert "RXT010" in {diagnostic.code for diagnostic in analysis.diagnostics}
    assert [function.qualname for function in analysis.rejected_native_functions] == ["app.bad"]


def test_rejects_unsupported_expression_syntax(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def walrus_bad(xs: list[int]) -> int:
    if (n := len(xs)) > 0:
        return n
    return 0

@rextio.native
def slice_bad(xs: list[int]) -> int:
    return xs[0:1][0]
""",
    )

    analysis = analyze_project(tmp_path)

    assert {diagnostic.code for diagnostic in analysis.diagnostics} == {"RXT010"}
    assert {function.qualname for function in analysis.rejected_native_functions} == {
        "app.slice_bad",
        "app.walrus_bad",
    }


def test_rejects_unsupported_literal_syntax(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def list_bad() -> list[int]:
    return [1, 2]

@rextio.native
def tuple_bad(x: int) -> int:
    pair = (x, x)
    return pair[0]

@rextio.native
def dict_bad(x: int) -> int:
    values = {"x": x}
    return x

@rextio.native
def set_bad(x: int) -> int:
    values = {x}
    return x
""",
    )

    analysis = analyze_project(tmp_path)

    assert {diagnostic.code for diagnostic in analysis.diagnostics} == {"RXT010"}
    assert {function.qualname for function in analysis.rejected_native_functions} == {
        "app.dict_bad",
        "app.list_bad",
        "app.set_bad",
        "app.tuple_bad",
    }


def test_rejects_unsupported_operator_syntax(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def pow_bad(x: int) -> int:
    return x ** 2

@rextio.native
def membership_bad(xs: list[int]) -> bool:
    return 1 in xs

@rextio.native
def identity_bad(x: int) -> bool:
    return x is None
""",
    )

    analysis = analyze_project(tmp_path)

    assert {diagnostic.code for diagnostic in analysis.diagnostics} == {"RXT010"}
    assert {function.qualname for function in analysis.rejected_native_functions} == {
        "app.identity_bad",
        "app.membership_bad",
        "app.pow_bad",
    }


def test_rejects_operations_with_unsafe_public_1_type_semantics(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def int_division_bad(x: int, y: int) -> int:
    return x / y

@rextio.native
def string_concat_bad(left: str, right: str) -> str:
    return left + right

@rextio.native
def mixed_numeric_bad(x: float, y: int) -> float:
    return x + y

@rextio.native
def int_truthiness_bad(x: int, y: int) -> bool:
    return x and y
""",
    )

    analysis = analyze_project(tmp_path)

    assert {diagnostic.code for diagnostic in analysis.diagnostics} == {"RXT010"}
    assert {function.qualname for function in analysis.rejected_native_functions} == {
        "app.int_truthiness_bad",
        "app.int_division_bad",
        "app.mixed_numeric_bad",
        "app.string_concat_bad",
    }


def test_rejects_inferred_type_mismatch_against_annotations(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def bad_return(x: int) -> int:
    return "wrong"

@rextio.native
def bad_local(x: int) -> int:
    total: int = 1.0
    return total

@rextio.native
def good_none(x: int) -> None:
    return None
""",
    )

    analysis = analyze_project(tmp_path)

    assert {diagnostic.code for diagnostic in analysis.diagnostics} == {"RXT010"}
    assert [function.qualname for function in analysis.accepted_native_functions] == [
        "app.good_none"
    ]
    assert {function.qualname for function in analysis.rejected_native_functions} == {
        "app.bad_local",
        "app.bad_return",
    }


def test_rejects_keyword_call_arguments(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def square(x: int) -> int:
    return x * x

@rextio.native
def keyword_bad(x: int) -> int:
    return square(x=x)
""",
    )

    analysis = analyze_project(tmp_path)

    assert "RXT010" in {diagnostic.code for diagnostic in analysis.diagnostics}
    assert [function.qualname for function in analysis.accepted_native_functions] == [
        "app.square"
    ]
    assert [function.qualname for function in analysis.rejected_native_functions] == [
        "app.keyword_bad"
    ]


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

    analysis = analyze_project(tmp_path, native_marker="decorator")

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
    assert [diagnostic.code for diagnostic in analysis.boundary_warnings] == ["RXT073"]


def test_warns_for_python_loop_calling_imported_native_function(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "src/myapp/math_ops.py",
        """
import rextio

@rextio.native
def score_one(x: float) -> float:
    return x * 2.0
""",
    )
    write_module(
        tmp_path,
        "src/myapp/pipeline.py",
        """
from .math_ops import score_one

def process_all(xs: list[float]) -> list[float]:
    out = []
    for x in xs:
        out.append(score_one(x))
    return out
""",
    )

    analysis = analyze_project(tmp_path)

    assert [function.qualname for function in analysis.accepted_native_functions] == [
        "myapp.math_ops.score_one"
    ]
    assert [diagnostic.code for diagnostic in analysis.boundary_warnings] == ["RXT073"]


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
