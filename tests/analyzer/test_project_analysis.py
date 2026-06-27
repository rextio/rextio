from __future__ import annotations

from pathlib import Path

from rextio.analyzer.project_scanner import analyze_project
from rextio.config.schema import ImportPackagePolicy, ImportsConfig
from rextio.plugins.models import RextioPlugin


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


def test_accepts_targeted_native_marker_for_active_target(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native(target="Rust")
def add(x: int, y: int) -> int:
    return x + y
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator", target_language="rust")

    assert [function.qualname for function in analysis.accepted_native_functions] == ["app.add"]
    assert analysis.accepted_native_functions[0].native_target_language == "rust"
    assert analysis.rejected_native_functions == []


def test_ignores_targeted_native_marker_for_inactive_target(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native(target="mojo")
def add(x: int, y: int) -> int:
    return x + y
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator", target_language="rust")

    assert analysis.native_candidates == []
    function = analysis.modules[0].functions_by_name["add"]
    assert function.native_target_language == "mojo"
    assert function.diagnostics == []


def test_accepts_targeted_native_marker_when_target_is_active(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native(target="mojo")
def add(x: int, y: int) -> int:
    return x + y
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator", target_language="mojo")

    assert [function.qualname for function in analysis.accepted_native_functions] == ["app.add"]
    assert analysis.accepted_native_functions[0].native_target_language == "mojo"


def test_rejects_invalid_native_marker_target(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native(target="cpp")
def add(x: int, y: int) -> int:
    return x + y
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    assert [function.qualname for function in analysis.rejected_native_functions] == ["app.add"]
    diagnostic = analysis.rejected_native_functions[0].error_diagnostics[0]
    assert diagnostic.code == "RXT010"
    assert "unsupported @rextio.native target" in diagnostic.message


def test_rejects_invalid_native_marker_arguments(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native(language="rust")
def add(x: int, y: int) -> int:
    return x + y
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    assert [function.qualname for function in analysis.rejected_native_functions] == ["app.add"]
    diagnostic = analysis.rejected_native_functions[0].error_diagnostics[0]
    assert diagnostic.code == "RXT010"
    assert "unsupported @rextio.native keyword" in diagnostic.message


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


def test_native_top_level_is_disabled_by_default(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
total: int = 41
""",
    )

    analysis = analyze_project(tmp_path)

    assert analysis.native_top_levels == []


def test_accepts_supported_native_top_level_when_enabled(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
total: int = 0
i: int = 0
while i < 5:
    total += i
    i += 1
""",
    )

    analysis = analyze_project(tmp_path, native_top_level=True)

    assert [top_level.qualname for top_level in analysis.accepted_native_top_levels] == [
        "app.__rextio_top_level__"
    ]
    top_level = analysis.accepted_native_top_levels[0]
    assert top_level.assigned_types == {"i": "int", "total": "int"}
    assert top_level.export_value_type == "int"


def test_rejects_mixed_type_native_top_level_exports(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
answer: int = 42
label: str = "ok"
""",
    )

    analysis = analyze_project(tmp_path, native_top_level=True)

    assert [top_level.qualname for top_level in analysis.rejected_native_top_levels] == [
        "app.__rextio_top_level__"
    ]
    assert "share one supported value type" in analysis.rejected_native_top_levels[0].error_diagnostics[0].message


def test_rejects_top_level_for_loop_to_preserve_module_scope(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
total: int = 0
for i in range(5):
    total += i
""",
    )

    analysis = analyze_project(tmp_path, native_top_level=True)

    assert [top_level.qualname for top_level in analysis.rejected_native_top_levels] == [
        "app.__rextio_top_level__"
    ]
    assert "top-level for loops" in analysis.rejected_native_top_levels[0].error_diagnostics[0].message


def test_auto_discovers_contextually_inferred_unannotated_functions(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
def add_one(x):
    return x + 1

def scale(x):
    return x * 2.0

def choose(flag):
    if flag:
        return "yes"
    return "no"

def sum_squares(xs):
    total = 0
    for x in xs:
        total += x * x
    return total

def fallback_only(x):
    return x
""",
    )

    analysis = analyze_project(tmp_path)

    assert [function.qualname for function in analysis.accepted_native_functions] == [
        "app.add_one",
        "app.choose",
        "app.scale",
        "app.sum_squares",
    ]
    by_name = {function.name: function for function in analysis.accepted_native_functions}
    assert by_name["add_one"].inferred_arg_types == {"x": "int"}
    assert by_name["add_one"].inferred_return_type == "int"
    assert by_name["scale"].inferred_arg_types == {"x": "float"}
    assert by_name["scale"].inferred_return_type == "float"
    assert by_name["choose"].inferred_arg_types == {"flag": "bool"}
    assert by_name["choose"].inferred_return_type == "str"
    assert by_name["sum_squares"].inferred_arg_types == {"xs": "list[int]"}
    assert by_name["sum_squares"].inferred_return_type == "int"
    assert "app.fallback_only" not in [function.qualname for function in analysis.native_candidates]
    assert analysis.diagnostics == []


def test_uses_sibling_pyi_signatures_for_native_discovery(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "src/stubbed/ops.py",
        """
def dot(xs, ys):
    total = 0.0
    for x, y in zip(xs, ys):
        total += x * y
    return total
""",
    )
    write_module(
        tmp_path,
        "src/stubbed/ops.pyi",
        """
def dot(xs: list[float], ys: list[float]) -> float: ...
""",
    )

    analysis = analyze_project(tmp_path)

    assert [function.qualname for function in analysis.accepted_native_functions] == [
        "stubbed.ops.dot",
    ]
    function = analysis.accepted_native_functions[0]
    assert function.inferred_arg_types == {"xs": "list[float]", "ys": "list[float]"}
    assert function.inferred_return_type == "float"
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


def test_uses_runtime_semantics_for_dynamic_features(tmp_path: Path) -> None:
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

    assert "RXT080" in {diagnostic.code for diagnostic in analysis.diagnostics}
    assert [function.qualname for function in analysis.accepted_native_functions] == ["app.bad"]
    assert analysis.accepted_native_functions[0].native_runtime_semantics is True


def test_auto_discovery_does_not_promote_dynamic_functions_to_runtime_shim(
    tmp_path: Path,
) -> None:
    # An undecorated function that relies on dynamic Python semantics must NOT be
    # auto-promoted to the RXT080 runtime-semantics shim. The shim is reserved
    # for functions a developer explicitly opts into with @rextio.native.
    write_module(
        tmp_path,
        "app.py",
        """
def read_attr(x: float) -> float:
    return getattr(x, "value")
""",
    )

    analysis = analyze_project(tmp_path)  # default auto-discovery mode

    assert [function.qualname for function in analysis.accepted_native_functions] == []
    assert "RXT080" not in {diagnostic.code for diagnostic in analysis.diagnostics}


def test_undecorated_caller_of_runtime_shim_is_not_promoted_via_boundary(
    tmp_path: Path,
) -> None:
    # An undecorated function that calls an explicitly-marked runtime-semantics
    # shim must not be silently promoted to the shim through the call graph; it
    # is rejected (stays on Python fallback) with an actionable RXT074 hint.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def shim(x: float) -> float:
    return getattr(x, "value")

def caller(x: float) -> float:
    return shim(x)
""",
    )

    analysis = analyze_project(tmp_path)

    accepted = {function.qualname for function in analysis.accepted_native_functions}
    assert accepted == {"app.shim"}
    assert "app.caller" in {function.qualname for function in analysis.rejected_native_functions}
    rxt074 = {diag.function_name for diag in analysis.diagnostics if diag.code == "RXT074"}
    assert "app.caller" in rxt074


def test_marked_caller_of_runtime_shim_is_still_promoted(tmp_path: Path) -> None:
    # The explicit-opt-in path is unchanged: a @rextio.native caller of a
    # runtime shim inherits runtime semantics (RXT080).
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def shim(x: float) -> float:
    return getattr(x, "value")

@rextio.native
def caller(x: float) -> float:
    return shim(x)
""",
    )

    analysis = analyze_project(tmp_path)

    accepted = {
        function.qualname: function.native_runtime_semantics
        for function in analysis.accepted_native_functions
    }
    assert accepted == {"app.shim": True, "app.caller": True}


def test_non_integer_list_index_is_rejected(tmp_path: Path) -> None:
    # Python requires int list indices; a float index is a TypeError, so Rextio
    # must reject it rather than silently truncate it to an int in native code.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def at_literal(xs: list[int]) -> int:
    return xs[1.9]

@rextio.native
def at_var(xs: list[int], j: float) -> int:
    return xs[j]
""",
    )

    analysis = analyze_project(tmp_path)

    assert analysis.accepted_native_functions == []
    rejected = {f.qualname for f in analysis.rejected_native_functions}
    assert {"app.at_literal", "app.at_var"} <= rejected


def test_undecorated_caller_of_imported_runtime_shim_is_rejected(tmp_path: Path) -> None:
    # The RXT074 boundary rule also applies across module boundaries.
    write_module(tmp_path, "src/pkg/__init__.py", "")
    write_module(
        tmp_path,
        "src/pkg/shim_mod.py",
        """
import rextio

@rextio.native
def shim(x: float) -> float:
    return getattr(x, "value")
""",
    )
    write_module(
        tmp_path,
        "src/pkg/caller_mod.py",
        """
from pkg.shim_mod import shim

def caller(x: float) -> float:
    return shim(x)
""",
    )

    analysis = analyze_project(tmp_path)

    assert "pkg.shim_mod.shim" in {f.qualname for f in analysis.accepted_native_functions}
    assert "pkg.caller_mod.caller" in {f.qualname for f in analysis.rejected_native_functions}
    assert "pkg.caller_mod.caller" in {
        diag.function_name for diag in analysis.diagnostics if diag.code == "RXT074"
    }


def test_transitive_undecorated_callers_of_runtime_shim_cascade_to_fallback(
    tmp_path: Path,
) -> None:
    # top -> mid -> shim. The project-wide boundary fixed point rejects mid
    # (RXT074), then rejects top because it depends on the now-rejected mid
    # (RXT072) — no undecorated function is silently promoted to the shim.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def shim(x: float) -> float:
    return getattr(x, "value")

def mid(x: float) -> float:
    return shim(x)

def top(x: float) -> float:
    return mid(x)
""",
    )

    analysis = analyze_project(tmp_path)

    assert {f.qualname for f in analysis.accepted_native_functions} == {"app.shim"}
    rejected = {f.qualname for f in analysis.rejected_native_functions}
    assert {"app.mid", "app.top"} <= rejected
    codes = {(diag.function_name, diag.code) for diag in analysis.diagnostics}
    assert ("app.mid", "RXT074") in codes
    assert ("app.top", "RXT072") in codes


def test_uses_runtime_semantics_for_object_async_generator_and_dynamic_attribute_native_features(
    tmp_path: Path,
) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

class Scoring:
    @rextio.native
    def score(self, x: int) -> int:
        return x + 1

@rextio.native
async def async_bad(x: int) -> int:
    return x

@rextio.native
def try_bad(x: int) -> int:
    try:
        return x
    except Exception:
        return 0

@rextio.native
def with_bad(x: int) -> int:
    with x:
        return x

@rextio.native
def generator_bad(x: int) -> int:
    yield x

@rextio.native
def dynamic_attr_bad(x: int) -> int:
    return x.value
""",
    )

    analysis = analyze_project(tmp_path)

    assert {diagnostic.code for diagnostic in analysis.diagnostics} == {"RXT080"}
    assert {function.qualname for function in analysis.accepted_native_functions} == {
        "app.Scoring.score",
        "app.async_bad",
        "app.dynamic_attr_bad",
        "app.generator_bad",
        "app.try_bad",
        "app.with_bad",
    }


def test_accepts_low_risk_control_flow_and_range_forms(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def total_until_negative(xs: list[int]) -> int:
    total = 0
    for x in xs:
        if x < 0:
            break
        if x == 0:
            continue
        total = total + x
    return total

@rextio.native
def stepped_total(n: int) -> int:
    total = 0
    for i in range(1, n, 2):
        total += i
    return total
""",
    )

    analysis = analyze_project(tmp_path)

    assert [function.qualname for function in analysis.accepted_native_functions] == [
        "app.stepped_total",
        "app.total_until_negative",
    ]
    assert analysis.rejected_native_functions == []


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


def test_rejects_remaining_unsupported_literal_syntax(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def list_ok() -> list[int]:
    return [1, 2]

@rextio.native
def tuple_ok(x: int) -> int:
    pair = (x, x)
    return pair[0]

@rextio.native
def dict_ok(x: int) -> int:
    values = {"x": x}
    return x

@rextio.native
def dict_value_bad(x: str) -> dict[str, int]:
    return {"x": x}

@rextio.native
def set_bad(x: int) -> int:
    values = {x}
    return x
""",
    )

    analysis = analyze_project(tmp_path)

    assert {diagnostic.code for diagnostic in analysis.diagnostics} == {"RXT010"}
    assert [function.qualname for function in analysis.accepted_native_functions] == [
        "app.dict_ok",
        "app.list_ok",
        "app.tuple_ok",
    ]
    assert {function.qualname for function in analysis.rejected_native_functions} == {
        "app.dict_value_bad",
        "app.set_bad",
    }


def test_accepts_fixed_tuples_limited_dicts_and_optional_types(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
from typing import Optional
import rextio

@rextio.native
def first_value(pair: tuple[int, float]) -> int:
    return pair[0]

@rextio.native
def make_pair(x: int, y: float) -> tuple[int, float]:
    return (x, y)

@rextio.native
def read_score(scores: dict[str, int], key: str) -> int:
    return scores[key]

@rextio.native
def build_weights() -> dict[str, float]:
    weights: dict[str, float] = {}
    weights["a"] = 1.5
    return weights

@rextio.native
def maybe(flag: bool, x: int) -> Optional[int]:
    if flag:
        return x
    return None

@rextio.native
def echo(value: int | None) -> int | None:
    if value is None:
        return None
    return value
""",
    )

    analysis = analyze_project(tmp_path)

    assert [function.qualname for function in analysis.accepted_native_functions] == [
        "app.build_weights",
        "app.echo",
        "app.first_value",
        "app.make_pair",
        "app.maybe",
        "app.read_score",
    ]
    assert analysis.rejected_native_functions == []


def test_rejects_mutated_mutable_collection_aliases_for_direct_rust(
    tmp_path: Path,
) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def alias_mutates(xs: list[int]) -> list[int]:
    ys = xs
    ys.append(1)
    return xs

@rextio.native
def container_capture_mutates(xs: list[int]) -> list[list[int]]:
    groups: list[list[int]] = [xs]
    xs.append(1)
    return groups
""",
    )

    analysis = analyze_project(tmp_path)
    rejected = {function.qualname: function for function in analysis.rejected_native_functions}

    assert set(rejected) == {"app.alias_mutates", "app.container_capture_mutates"}
    assert any(
        diagnostic.code == "RXT010" and "mutable collection aliases" in diagnostic.message
        for diagnostic in rejected["app.alias_mutates"].diagnostics
    )
    assert any(
        diagnostic.code == "RXT010" and "captured inside a container literal" in diagnostic.message
        for diagnostic in rejected["app.container_capture_mutates"].diagnostics
    )


def test_accepts_comprehensions_nested_lists_sets_dict_str_values_and_walrus(
    tmp_path: Path,
) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def inc(x: int) -> int:
    return x + 1

@rextio.native
def squares(xs: list[int]) -> list[int]:
    return [inc(x) for x in xs if x > 0]

@rextio.native
def flatten(rows: list[list[int]]) -> list[int]:
    return [x for row in rows for x in row]

@rextio.native
def nested(rows: list[list[int]]) -> list[list[int]]:
    return [[x + 1 for x in row] for row in rows]

@rextio.native
def labels(xs: list[str]) -> dict[str, str]:
    return {x: x for x in xs}

@rextio.native
def unique(xs: list[int]) -> set[int]:
    return {x for x in xs if x > 0}

@rextio.native
def unique_float(xs: list[float]) -> set[float]:
    return {x for x in xs if x > 0.0}

@rextio.native
def by_index(xs: list[int]) -> dict[int, float]:
    return {i: 1.5 for i, x in enumerate(xs) if x > 0}

@rextio.native
def flags(xs: list[int]) -> dict[bool, str]:
    return {x > 0: "seen" for x in xs}

@rextio.native
def last_positive(xs: list[int]) -> int:
    out = [y for x in xs if (y := x) > 0]
    return y
""",
    )

    analysis = analyze_project(tmp_path)

    assert [function.qualname for function in analysis.accepted_native_functions] == [
        "app.by_index",
        "app.flags",
        "app.flatten",
        "app.inc",
        "app.labels",
        "app.last_positive",
        "app.nested",
        "app.squares",
        "app.unique",
        "app.unique_float",
    ]
    assert analysis.rejected_native_functions == []


def test_rejects_unsupported_comprehension_edges(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def walrus_outside(xs: list[int]) -> int:
    if (n := len(xs)) > 0:
        return n
    return 0

@rextio.native
def walrus_rebind(xs: list[int]) -> list[int]:
    return [(x := x + 1) for x in xs]

@rextio.native
def dict_bad(xs: list[str]) -> dict[str, int]:
    return {x: x for x in xs}
""",
    )

    analysis = analyze_project(tmp_path)

    assert {diagnostic.code for diagnostic in analysis.diagnostics} == {"RXT010"}
    assert {function.qualname for function in analysis.rejected_native_functions} == {
        "app.dict_bad",
        "app.walrus_outside",
        "app.walrus_rebind",
    }


def test_rejects_unsupported_dict_and_optional_operations(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def float_key() -> dict[float, int]:
    return {1.5: 2}

@rextio.native
def dict_wrong_value(scores: dict[str, int]) -> dict[str, int]:
    scores["a"] = 1.5
    return scores

@rextio.native
def optional_arithmetic(value: int | None) -> int:
    return value + 1
""",
    )

    analysis = analyze_project(tmp_path)

    assert {diagnostic.code for diagnostic in analysis.diagnostics} == {"RXT003", "RXT010"}
    assert {function.qualname for function in analysis.rejected_native_functions} == {
        "app.dict_wrong_value",
        "app.float_key",
        "app.optional_arithmetic",
    }


def test_accepts_list_literals_and_append_for_supported_item_types(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def odds(n: int) -> list[int]:
    out: list[int] = []
    for i in range(n):
        if i == 0:
            continue
        out.append(i)
    return out

@rextio.native
def labels() -> list[str]:
    return ["ready", "set", "go"]
""",
    )

    analysis = analyze_project(tmp_path)

    assert [function.qualname for function in analysis.accepted_native_functions] == [
        "app.labels",
        "app.odds",
    ]
    assert analysis.rejected_native_functions == []


def test_accepts_enumerate_and_zip_batch_loops(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def indexed_offsets(xs: list[int]) -> list[int]:
    out: list[int] = []
    for i, x in enumerate(xs):
        out.append(i + x)
    return out

@rextio.native
def dot(xs: list[float], ys: list[float]) -> float:
    total = 0.0
    for x, y in zip(xs, ys):
        total += x * y
    return total
""",
    )

    analysis = analyze_project(tmp_path)

    assert [function.qualname for function in analysis.accepted_native_functions] == [
        "app.dot",
        "app.indexed_offsets",
    ]
    assert analysis.rejected_native_functions == []


def test_rejects_unsupported_enumerate_and_zip_forms(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def enumerate_without_unpack(xs: list[int]) -> int:
    total = 0
    for pair in enumerate(xs):
        total += 1
    return total

@rextio.native
def zip_wrong_arity(xs: list[int], ys: list[int]) -> int:
    total = 0
    for x, y, z in zip(xs, ys):
        total += x + y + z
    return total

@rextio.native
def zip_non_list(xs: list[int], n: int) -> int:
    total = 0
    for x, y in zip(xs, n):
        total += x
    return total
""",
    )

    analysis = analyze_project(tmp_path)

    assert {diagnostic.code for diagnostic in analysis.diagnostics} == {"RXT010"}
    assert {function.qualname for function in analysis.rejected_native_functions} == {
        "app.enumerate_without_unpack",
        "app.zip_non_list",
        "app.zip_wrong_arity",
    }


def test_rejects_ambiguous_empty_list_and_non_literal_range_step(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def ambiguous() -> list[int]:
    out = []
    return out

@rextio.native
def dynamic_step(n: int, step: int) -> int:
    total = 0
    for i in range(0, n, step):
        total += i
    return total
""",
    )

    analysis = analyze_project(tmp_path)

    assert {diagnostic.code for diagnostic in analysis.diagnostics} == {"RXT010"}
    assert {function.qualname for function in analysis.rejected_native_functions} == {
        "app.ambiguous",
        "app.dynamic_step",
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


def test_accepts_limited_builtins_and_math_calls(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import math
import rextio

@rextio.native
def compute(values: list[float], x: float) -> float:
    total: float = sum(values)
    return math.sqrt(x) + math.sin(x) + math.cos(x) + max(total, abs(x))

@rextio.native
def lower(x: float, y: float) -> int:
    return min(math.floor(x), math.floor(y))
""",
    )

    analysis = analyze_project(tmp_path)

    assert [function.qualname for function in analysis.accepted_native_functions] == [
        "app.compute",
        "app.lower",
    ]
    assert analysis.rejected_native_functions == []


def test_accepts_common_builtin_logging_and_datetime_calls(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import datetime as dt
import logging as log
import rextio

from logging import info

logger = log.getLogger(__name__)

@rextio.native
def observe(value: int) -> str:
    print("value", value)
    log.info("module %s", value)
    logger.warning("logger %s", value)
    info("imported %s", value)
    return dt.datetime.utcnow().isoformat()
""",
    )

    analysis = analyze_project(tmp_path)

    assert [function.qualname for function in analysis.accepted_native_functions] == ["app.observe"]
    assert analysis.modules[0].logger_names == ("logger",)
    assert analysis.rejected_native_functions == []


def test_accepts_expanded_stdlib_lowering_calls(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import base64
import hashlib
import json
import math
import statistics
import time
from datetime import datetime

def numeric(xs: list[float], flags: list[bool]) -> float:
    return (
        math.tan(xs[0])
        + math.asin(xs[1])
        + math.acos(xs[2])
        + math.atan(xs[3])
        + math.atan2(xs[0], xs[1])
        + math.exp(xs[0])
        + math.log(xs[1])
        + math.log(xs[1], math.e)
        + math.log2(xs[1])
        + math.log10(xs[1])
        + math.pi
        + statistics.mean(xs)
        + statistics.fmean(xs)
        + time.time()
        + datetime.utcnow().timestamp()
    )

def predicates(x: float, flags: list[bool]) -> bool:
    return math.isfinite(x) and not math.isnan(x) and not math.isinf(x) and any(flags) and all(flags)

def text(value: str) -> str:
    return value.strip().lower().replace("a", "b").upper()

def prefix_suffix(value: str) -> bool:
    return value.startswith("a") or value.endswith("z")

def list_ops(xs: list[int]) -> int:
    copied = xs.copy()
    total = copied.count(2) + copied.index(2)
    for value in reversed(sorted(copied)):
        total += value
    return total

def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()

def b64_roundtrip(value: str) -> str:
    encoded = base64.b64encode(value.encode())
    return base64.b64decode(encoded).decode()

def json_roundtrip(value: str) -> dict[str, int]:
    parsed: dict[str, int] = json.loads(value)
    return parsed

def json_dump(value: dict[str, int]) -> str:
    return json.dumps(value)
""",
    )

    analysis = analyze_project(tmp_path)

    assert [function.name for function in analysis.accepted_native_functions] == [
        "b64_roundtrip",
        "digest",
        "json_dump",
        "json_roundtrip",
        "list_ops",
        "numeric",
        "predicates",
        "prefix_suffix",
        "text",
    ]
    assert analysis.rejected_native_functions == []


def test_rejects_unsupported_external_calls(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import statistics
import rextio

@rextio.native
def compute(xs: list[float]) -> float:
    return statistics.median(xs)
""",
    )

    analysis = analyze_project(tmp_path)

    assert "RXT030" in {diagnostic.code for diagnostic in analysis.diagnostics}
    assert [function.qualname for function in analysis.rejected_native_functions] == ["app.compute"]


def test_records_import_origin_and_policy_decisions(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "src/myapp/helper.py",
        """
def local(x: float) -> float:
    return x
""",
    )
    write_module(
        tmp_path,
        "src/myapp/app.py",
        """
import math
import unknown_pkg
from .helper import local

def compute(x: float) -> float:
    return local(math.sqrt(x))
""",
    )

    analysis = analyze_project(tmp_path)

    module = next(module for module in analysis.modules if module.module_name == "myapp.app")
    decisions = {decision.visible_name: decision for decision in module.import_policies}
    assert decisions["math"].origin == "stdlib"
    assert decisions["math"].policy == "builtin"
    assert decisions["unknown_pkg"].origin == "external"
    assert decisions["unknown_pkg"].policy == "fallback"
    assert decisions["local"].origin == "project"
    assert decisions["local"].policy == "try-native"


def test_external_package_without_plugin_rejects_native_candidate_with_fallback_guidance(
    tmp_path: Path,
) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
from unknown_pkg import normalize

def compute(xs: list[float]) -> list[float]:
    out: list[float] = []
    for x in xs:
        out.append(normalize(x))
    return out
""",
    )

    analysis = analyze_project(tmp_path)

    assert [function.qualname for function in analysis.rejected_native_functions] == ["app.compute"]
    diagnostic = analysis.rejected_native_functions[0].error_diagnostics[0]
    assert diagnostic.code == "RXT030"
    assert "external package call uses fallback import policy" in diagnostic.message
    assert "inside a loop" in diagnostic.suggestion
    assert "batch API refactor" in diagnostic.suggestion


def test_try_native_external_package_policy_is_explicit_but_still_rejects_unknown_call(
    tmp_path: Path,
) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import safe_pkg

def compute(x: float) -> float:
    return safe_pkg.normalize(x)
""",
    )

    analysis = analyze_project(
        tmp_path,
        imports_config=ImportsConfig(
            packages={"safe_pkg": ImportPackagePolicy(policy="try-native", max_depth=1)}
        ),
    )

    diagnostic = analysis.rejected_native_functions[0].error_diagnostics[0]
    assert diagnostic.code == "RXT030"
    assert "experimental dependency lowering" in diagnostic.message
    assert "opt-in" in diagnostic.suggestion


def test_active_plugin_package_is_recorded_but_call_requires_lowering_rule(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import known_pkg

def compute(x: float) -> float:
    return known_pkg.normalize(x)
""",
    )

    analysis = analyze_project(
        tmp_path,
        active_plugins=(
            RextioPlugin(
                id="known-rust",
                name="Known package Rust plugin",
                target_language="rust",
                packages=("known_pkg",),
            ),
        ),
    )

    module = analysis.modules[0]
    assert module.import_policies[0].policy == "plugin"
    assert module.import_policies[0].plugin == "known-rust"
    diagnostic = analysis.rejected_native_functions[0].error_diagnostics[0]
    assert "plugin-managed external package call" in diagnostic.message


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

    assert diagnostics_by_function["app.helper"] == "RXT080"
    assert diagnostics_by_function["app.compute"] == "RXT080"
    assert {function.qualname for function in analysis.accepted_native_functions} == {
        "app.compute",
        "app.helper",
    }


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
    assert "enumerate(xs)" in analysis.boundary_warnings[0].suggestion
    assert "zip(xs, ys)" in analysis.boundary_warnings[0].suggestion


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


def test_jit_disabled_keeps_unmarked_helper_as_fallback_boundary(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

def helper(x: int) -> int:
    return x * 2

@rextio.native
def compute(x: int) -> int:
    return helper(x) + 1
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    assert analysis.jit_candidates == []
    assert [function.qualname for function in analysis.rejected_native_functions] == ["app.compute"]
    assert analysis.rejected_native_functions[0].error_diagnostics[0].code == "RXT070"


def test_jit_enabled_promotes_typed_scalar_helper_for_native_caller(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

def helper(x: int) -> int:
    return x * 2

@rextio.native
def compute(x: int) -> int:
    return helper(x) + 1
""",
    )

    analysis = analyze_project(
        tmp_path,
        native_marker="decorator",
        native_jit_enabled=True,
        jit_hot_threshold=2,
    )

    assert [function.qualname for function in analysis.accepted_native_functions] == ["app.compute"]
    assert [function.qualname for function in analysis.jit_candidates] == ["app.helper"]
    assert analysis.jit_candidates[0].jit_hot_threshold == 2
    assert "Cranelift JIT" in (analysis.jit_candidates[0].jit_reason or "")


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
