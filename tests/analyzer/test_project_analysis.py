from __future__ import annotations

from pathlib import Path

import pytest

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


def test_accepts_rust_keyword_identifier_via_raw_escaping(tmp_path: Path) -> None:
    # A Python local/parameter named after a Rust keyword is carried as a raw
    # identifier (`r#fn`), so the function stays native rather than falling back.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def f(match: int) -> int:
    fn = match
    return fn
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    assert [function.qualname for function in analysis.accepted_native_functions] == ["app.f"]
    assert analysis.rejected_native_functions == []


def test_rejects_non_raw_able_rust_keyword_identifier(tmp_path: Path) -> None:
    # `crate`/`self`/`Self`/`super` are the keywords a raw identifier cannot carry,
    # so they fall back with RXT011 instead of emitting uncompilable Rust.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def g(xs: list[int]) -> int:
    crate = len(xs)
    return crate
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    assert [function.qualname for function in analysis.rejected_native_functions] == ["app.g"]
    diagnostic = analysis.rejected_native_functions[0].error_diagnostics[0]
    assert diagnostic.code == "RXT011"
    assert "raw identifier" in diagnostic.message


def test_rejects_non_raw_able_rust_keyword_function_name(tmp_path: Path) -> None:
    # The function's own name is also checked: a root-package function named after a
    # non-raw-able keyword cannot be lowered.
    write_module(
        tmp_path,
        "__init__.py",
        """
import rextio

@rextio.native
def Self(x: int) -> int:
    return x + 1
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    assert [function.qualname for function in analysis.rejected_native_functions] == ["Self"]
    assert analysis.rejected_native_functions[0].error_diagnostics[0].code == "RXT011"


def test_rejects_non_ascii_and_underscore_function_names_without_crashing(tmp_path: Path) -> None:
    # A non-ASCII function name (silently mangled before) and an all-underscore name
    # (which `native_function_name` cannot sanitize and would crash on at root) are
    # rejected with RXT011 rather than mangled or crashing the analyzer.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def café(x: int) -> int:
    return x + 1
""",
    )
    write_module(
        tmp_path,
        "__init__.py",
        """
import rextio

@rextio.native
def _(x: int) -> int:
    return x + 1
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    rejected = {f.qualname for f in analysis.rejected_native_functions}
    assert "app.café" in rejected
    assert "_" in rejected
    assert all(
        f.error_diagnostics[0].code == "RXT011"
        for f in analysis.rejected_native_functions
        if f.qualname in {"app.café", "_"}
    )


def test_accepts_keyword_function_name_in_a_submodule(tmp_path: Path) -> None:
    # A sub-module function named after a keyword emits a module-prefixed Rust name
    # (`app__crate`), which is safe — it must NOT be over-rejected by the node.name
    # check (regression guard).
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def crate(x: int) -> int:
    return x + 1
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    assert [function.qualname for function in analysis.accepted_native_functions] == ["app.crate"]
    assert analysis.rejected_native_functions == []


def test_rejects_underscore_used_as_a_value_but_accepts_discard_loop(tmp_path: Path) -> None:
    # Rust `_` is a discard pattern: reading or assigning it is invalid, but an
    # unused `for _ in …` loop variable is fine.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def reads_underscore(xs: list[int]) -> int:
    _ = len(xs)
    return _

@rextio.native
def discard_loop(n: int) -> int:
    total = 0
    for _ in range(n):
        total = total + 1
    return total
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    assert [f.qualname for f in analysis.accepted_native_functions] == ["app.discard_loop"]
    assert [f.qualname for f in analysis.rejected_native_functions] == ["app.reads_underscore"]
    assert analysis.rejected_native_functions[0].error_diagnostics[0].code == "RXT011"


def test_rejects_non_raw_able_keyword_top_level_name(tmp_path: Path) -> None:
    # native_top_level emits top-level assignments through the same renderer, so a
    # non-raw-able keyword module variable must be rejected (a raw-able one like
    # `match` stays native, escaped to `r#match`).
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

crate = 5
value = crate + 1
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator", native_top_level=True)

    assert "RXT011" in {diagnostic.code for diagnostic in analysis.diagnostics}


def test_rejects_non_ascii_local_identifier(tmp_path: Path) -> None:
    # A non-ASCII local name is emitted verbatim as a Rust identifier; rather than
    # rely on cross-language identifier (XID/normalization) parity, keep the
    # function on Python fallback with RXT011.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def last_positive(xs: list[int]) -> int:
    out = [café for x in xs if (café := x) > 0]
    return café
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    assert [function.qualname for function in analysis.rejected_native_functions] == ["app.last_positive"]
    diagnostic = analysis.rejected_native_functions[0].error_diagnostics[0]
    assert diagnostic.code == "RXT011"
    assert "non-ASCII" in diagnostic.message


def test_rejects_reserved_internal_prefix_identifier(tmp_path: Path) -> None:
    # Codegen emits internal temporaries with the `__rextio` prefix (e.g.
    # `__rextio_min_a_1`). A user binding sharing that prefix could be shadowed by
    # a generated `let` inside an emitted block, silently changing behavior, so it
    # is kept on the Python fallback with RXT011 instead.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def compute(__rextio_min_a_1: int, y: int) -> int:
    return __rextio_min_a_1 + y
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    assert [function.qualname for function in analysis.rejected_native_functions] == ["app.compute"]
    diagnostic = analysis.rejected_native_functions[0].error_diagnostics[0]
    assert diagnostic.code == "RXT011"
    assert "__rextio" in diagnostic.message


def test_rejects_reserved_internal_prefix_function_name(tmp_path: Path) -> None:
    # A function whose own name shares the `__rextio` prefix is rejected too: the
    # synthetic native top-level function is named `__rextio_top_level__`, so a
    # user function sharing the prefix could collide once name-mangled.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def __rextio_helper(x: int) -> int:
    return x + 1
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    assert [function.qualname for function in analysis.rejected_native_functions] == ["app.__rextio_helper"]
    assert analysis.rejected_native_functions[0].error_diagnostics[0].code == "RXT011"


def test_rejects_reserved_internal_prefix_top_level_identifier(tmp_path: Path) -> None:
    # A native top-level emits module variables as `let` bindings into the same
    # scope as the generator's own `__rextio_*` temporaries, so a module variable
    # sharing the prefix could silently shadow one. It must be kept on fallback.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

__rextio_seed = 5
value = __rextio_seed + 1
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator", native_top_level=True)

    assert "RXT011" in {diagnostic.code for diagnostic in analysis.diagnostics}


def test_rejects_chained_comparison_with_call_middle_operand(tmp_path: Path) -> None:
    # `0 < marker(x) < 10` lowers to `(0 < marker(x)) && (marker(x) < 10)`,
    # calling the middle operand twice where CPython calls it once. The callee
    # could be non-deterministic or side-effecting (print/log), so this is a
    # silent divergence. The analyzer conservatively rejects any chained
    # comparison with a call as a middle operand (purity isn't known
    # syntactically) -> Python fallback. A chained comparison whose middle
    # operand is pure (here `x`) stays native.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def marker(x: int) -> int:
    return x * 2

@rextio.native
def between(x: int) -> bool:
    return 0 < marker(x) < 10

@rextio.native
def in_range(x: int, n: int) -> bool:
    return 0 <= x < n
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    assert [f.qualname for f in analysis.rejected_native_functions] == ["app.between"]
    accepted = {f.qualname for f in analysis.accepted_native_functions}
    assert {"app.marker", "app.in_range"} <= accepted
    assert "app.between" not in accepted


def test_rejects_native_sorted_of_floats(tmp_path: Path) -> None:
    # sorted(list[float]) cannot match CPython on NaN (floats have no total
    # order), so it is kept on the Python fallback; sorted(list[int]) is totally
    # ordered and stays native.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def sort_floats(xs: list[float]) -> list[float]:
    return sorted(xs)

@rextio.native
def sort_ints(xs: list[int]) -> list[int]:
    return sorted(xs)
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    assert [f.qualname for f in analysis.rejected_native_functions] == ["app.sort_floats"]
    assert [f.qualname for f in analysis.accepted_native_functions] == ["app.sort_ints"]


def test_rejects_float_container_comparison_and_count(tmp_path: Path) -> None:
    # Python container `==`/`!=`/`.count()`/`.index()` compares elements with
    # identity-or-equality; a NaN element is `is`-equal but not `==`-equal to
    # itself, so native Rust value comparison (`Vec<f64> == ...`) diverges. Keep
    # float-containing container comparisons and list[float].count/index off the
    # pure native path. int containers and scalar-float comparisons stay native.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def eq_floats(xs: list[float], ys: list[float]) -> bool:
    return xs == ys

@rextio.native
def eq_tuples(a: tuple[float, float], b: tuple[float, float]) -> bool:
    return a != b

@rextio.native
def eq_ints(xs: list[int], ys: list[int]) -> bool:
    return xs == ys

@rextio.native
def scalar_eq(xs: list[float]) -> bool:
    return xs[0] == 1.0

@rextio.native
def count_floats(xs: list[float]) -> int:
    return xs.count(1.0)

@rextio.native
def eq_nested(a: list[list[float]], b: list[list[float]]) -> bool:
    return a == b

@rextio.native
def count_nested(rows: list[list[float]], row: list[float]) -> int:
    return rows.count(row)

@rextio.native
def opt_scalar_is_none(x: float | None) -> bool:
    return x is None

@rextio.native
def opt_container_is_none(x: list[float] | None) -> bool:
    return x is None
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    rejected = {f.qualname for f in analysis.rejected_native_functions}
    diags = {
        f.qualname: {d.code for d in f.diagnostics}
        for f in (*analysis.accepted_native_functions, *analysis.rejected_native_functions)
    }

    def off_native(name: str) -> bool:
        # Never compiled to a divergent native comparison: either rejected to the
        # Python fallback (RXT010) or routed to the Python runtime shim (RXT080).
        return name in rejected or "RXT080" in diags.get(name, set())

    # Float-container `==`/`!=` falls back to Python (RXT010), including nested.
    assert "app.eq_floats" in rejected
    assert "app.eq_tuples" in rejected
    assert "app.eq_nested" in rejected
    # list.count/index on a float-containing element type (scalar or nested) is
    # kept off the pure native path.
    assert off_native("app.count_floats")
    assert off_native("app.count_nested")
    # int containers, scalar-float comparisons, and `x is None` on an optional
    # (scalar or container) float stay pure native -- `is None` never compares
    # elements, and a scalar Optional[float] compares faithfully.
    assert "app.eq_ints" not in rejected
    assert diags["app.eq_ints"] == set()
    assert "app.scalar_eq" not in rejected
    assert diags["app.scalar_eq"] == set()
    assert diags["app.opt_scalar_is_none"] == set()
    assert diags["app.opt_container_is_none"] == set()


def test_rejects_native_set_of_floats(tmp_path: Path) -> None:
    # A Rust set of f64 (lowered as Vec + `contains`) cannot reproduce CPython's
    # set semantics for NaN: CPython dedups the *same* NaN object by identity
    # (`{n, n}` has length 1) while f64 has no object identity. There is no
    # faithful native lowering, so set[float] is kept on the Python fallback
    # (float is excluded from SET_ITEM_TYPES); set[int] still compiles natively.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def unique_floats(xs: list[float]) -> set[float]:
    return {x for x in xs}

@rextio.native
def unique_ints(xs: list[int]) -> set[int]:
    return {x for x in xs}
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    rejected = {f.qualname for f in analysis.rejected_native_functions}
    accepted = {f.qualname for f in analysis.accepted_native_functions}
    assert "app.unique_floats" in rejected
    assert "app.unique_ints" in accepted


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


def test_runtime_semantics_shim_does_not_bypass_identifier_validation(tmp_path: Path) -> None:
    # The RXT080 runtime shim still emits `fn {name}`, so a root function named after a
    # non-raw-able keyword must be rejected (RXT011) instead of promoted to the shim and
    # emitting uncompilable Rust — for both the dynamic (sync) and async promotion paths.
    write_module(
        tmp_path,
        "__init__.py",
        """
import rextio

@rextio.native
def crate(x: int) -> int:
    return getattr(x, "value")

@rextio.native
async def super(x: int) -> int:
    return x + 1
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    rejected = {f.qualname for f in analysis.rejected_native_functions}
    assert {"crate", "super"} <= rejected
    assert all(
        f.error_diagnostics[0].code == "RXT011"
        for f in analysis.rejected_native_functions
        if f.qualname in {"crate", "super"}
    )
    assert not any(
        f.qualname in {"crate", "super"} for f in analysis.accepted_native_functions
    )


def test_runtime_shim_promotes_dynamic_function_with_unrepresentable_param_name(
    tmp_path: Path,
) -> None:
    # The shim signature is the generic `(py, args, kwargs)` and emits no parameter
    # identifiers, so a dynamic function with a representable *name* but an
    # unrepresentable *parameter* name (a non-raw-able keyword) must still be promoted
    # to the shim rather than over-rejected onto Python fallback — mirroring the async
    # path, which only validates the function name.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def compute(crate: object) -> object:
    return getattr(crate, "value")
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    assert [f.qualname for f in analysis.accepted_native_functions] == ["app.compute"]
    assert analysis.accepted_native_functions[0].native_runtime_semantics is True
    assert analysis.rejected_native_functions == []


def test_marked_method_runtime_shim_validates_the_method_name(tmp_path: Path) -> None:
    # The class-method RXT080 shim emits `fn {native_function_name(qualname)}(...)`
    # just like the module-level shim, so a method whose name cannot be lowered to a
    # Rust identifier (non-ASCII, all-underscore) must be rejected (RXT011) rather than
    # silently mangled. A representable method name with an unrepresentable *parameter*
    # name must still be accepted (the shim emits no parameter identifiers).
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

class Widget:
    @rextio.native
    def café(self, x: object) -> object:
        return getattr(x, "value")

    @rextio.native
    def _(self, x: object) -> object:
        return getattr(x, "value")

    @rextio.native
    def compute(self, crate: object) -> object:
        return getattr(crate, "value")
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    accepted = {f.qualname for f in analysis.accepted_native_functions}
    rejected = {
        f.qualname: f.error_diagnostics[0].code
        for f in analysis.rejected_native_functions
        if f.error_diagnostics
    }
    assert "app.Widget.compute" in accepted
    assert rejected.get("app.Widget.café") == "RXT011"
    assert rejected.get("app.Widget._") == "RXT011"
    # A rejected method must not be left flagged as a runtime-semantics shim: the
    # builder sets `native_runtime_semantics=True` before validating the name, and the
    # rejection path clears it (defense-in-depth against any consumer that reads the
    # flag without also checking `accepted`).
    rejected_flags = {
        f.qualname: f.native_runtime_semantics for f in analysis.rejected_native_functions
    }
    assert rejected_flags.get("app.Widget.café") is False
    assert rejected_flags.get("app.Widget._") is False


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


def test_requires_native_build_ignores_jit_only_projects(tmp_path: Path) -> None:
    # Embedding enabled, decorator-only, with an unmarked scalar helper: the helper
    # is an embedding *candidate* but there is no accepted native function to embed
    # it into, so no native artifact is produced and the build must not demand the
    # Rust toolchain.
    write_module(
        tmp_path,
        "app.py",
        """
def helper(x: float) -> float:
    return x * 2.0
""",
    )

    analysis = analyze_project(
        tmp_path,
        native_marker="decorator",
        native_jit_enabled=True,
    )

    assert analysis.jit_candidates  # the helper is a JIT candidate
    assert analysis.accepted_native_functions == []
    assert analysis.requires_native_build() is False


def test_requires_native_build_true_for_accepted_native(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def add(a: int, b: int) -> int:
    return a + b
""",
    )

    analysis = analyze_project(tmp_path)

    assert analysis.requires_native_build() is True


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
    ys: list[int] = []
    groups: list[list[int]] = [ys]
    ys.append(1)
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
        + time.time()
        + datetime.now().timestamp()
    )

def predicates(x: float, flags: list[bool]) -> bool:
    return math.isfinite(x) and not math.isnan(x) and not math.isinf(x) and any(flags) and all(flags)

def text(value: str) -> str:
    return value.lower().replace("a", "b").upper()

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

def b64_encode(value: str) -> bytes:
    return base64.b64encode(value.encode())
""",
    )

    analysis = analyze_project(tmp_path)

    assert [function.name for function in analysis.accepted_native_functions] == [
        "b64_encode",
        "digest",
        "list_ops",
        "numeric",
        "predicates",
        "prefix_suffix",
        "text",
    ]
    assert analysis.rejected_native_functions == []


def test_json_and_unfaithful_datetime_kept_off_native(tmp_path: Path) -> None:
    # serde_json is not CPython-`json`-compatible (separators/key order/ensure_ascii/
    # NaN/error types), `utcnow().timestamp()` interprets naive-UTC as local in
    # CPython (offset divergence), and `isoformat(timespec=...)` carries args we do
    # not reproduce -- all are kept off the pure native path. `now()/utcnow()
    # .isoformat()` (faithful naive formatter) and `now().timestamp()` stay native.
    write_module(
        tmp_path,
        "app.py",
        """
import json
import datetime
import rextio

@rextio.native
def dump(d: dict[str, int]) -> str:
    return json.dumps(d)

@rextio.native
def load(s: str) -> dict[str, int]:
    return json.loads(s)

@rextio.native
def utc_ts() -> float:
    return datetime.datetime.utcnow().timestamp()

@rextio.native
def iso_args() -> str:
    return datetime.datetime.now().isoformat(timespec="seconds")

@rextio.native
def now_iso() -> str:
    return datetime.datetime.now().isoformat()

@rextio.native
def now_ts() -> float:
    return datetime.datetime.now().timestamp()
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    pure_native = {
        f.qualname
        for f in analysis.accepted_native_functions
        if not any(d.code == "RXT080" for d in f.diagnostics)
    }
    # The four unfaithful forms are never compiled to native (rejected or shimmed).
    for name in ("app.dump", "app.load", "app.utc_ts", "app.iso_args"):
        assert name not in pure_native
    # The faithful datetime forms stay native.
    assert "app.now_iso" in pure_native
    assert "app.now_ts" in pure_native


def test_unfaithful_stdlib_kept_off_native(tmp_path: Path) -> None:
    # `statistics.mean`/`fmean` (naive native summation diverges from CPython's
    # exact/math.fsum), `base64.b64decode` (CPython discards non-alphabet chars),
    # and `str.strip` (Rust trim() differs on the C0 separators) are all kept off
    # the pure native path. `b64encode` and other str methods stay native.
    write_module(
        tmp_path,
        "app.py",
        """
import statistics
import base64
import rextio

@rextio.native
def mean_int(xs: list[int]) -> float:
    return statistics.mean(xs)

@rextio.native
def mean_float(xs: list[float]) -> float:
    return statistics.mean(xs)

@rextio.native
def fmean_float(xs: list[float]) -> float:
    return statistics.fmean(xs)

@rextio.native
def strip_it(s: str) -> str:
    return s.strip()

@rextio.native
def decode(s: str) -> bytes:
    return base64.b64decode(s)

@rextio.native
def encode(b: bytes) -> bytes:
    return base64.b64encode(b)

@rextio.native
def lower_it(s: str) -> str:
    return s.lower()
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    rejected = {f.qualname for f in analysis.rejected_native_functions}
    diags = {
        f.qualname: {d.code for d in f.diagnostics}
        for f in (*analysis.accepted_native_functions, *analysis.rejected_native_functions)
    }

    def off_native(name: str) -> bool:
        return name in rejected or "RXT080" in diags.get(name, set())

    for name in ("app.mean_int", "app.mean_float", "app.fmean_float", "app.strip_it", "app.decode"):
        assert off_native(name), name
    assert "app.encode" not in rejected and diags["app.encode"] == set()
    assert "app.lower_it" not in rejected and diags["app.lower_it"] == set()


def test_none_literal_positions_kept_off_native(tmp_path: Path) -> None:
    # A bare native `None` literal has no inferable `Option<T>` type in these
    # positions and would break the cargo build (E0282), so they are kept off the
    # native path: `print`/`logging` of None, and `None <op> None`. None in an
    # inferable position stays native: `return None` from `-> None` (-> `()`),
    # `x == None` against an Optional operand, and an Optional return.
    write_module(
        tmp_path,
        "app.py",
        """
from typing import Optional
import rextio

@rextio.native
def print_none() -> None:
    print(None)

@rextio.native
def cmp_none_none() -> bool:
    return None == None

@rextio.native
def ret_none_unit(x: int) -> None:
    return None

@rextio.native
def cmp_optional(x: Optional[int]) -> bool:
    return x == None

@rextio.native
def ret_optional(flag: bool, x: int) -> Optional[int]:
    if flag:
        return x
    return None
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    rejected = {f.qualname for f in analysis.rejected_native_functions}
    accepted = {f.qualname for f in analysis.accepted_native_functions}
    for name in ("app.print_none", "app.cmp_none_none"):
        assert name in rejected, name
    for name in ("app.ret_none_unit", "app.cmp_optional", "app.ret_optional"):
        assert name in accepted, name


def test_bare_none_local_and_tuple_none_kept_off_native(tmp_path: Path) -> None:
    # A bare `None` assigned to an unannotated local infers as the unit type `()`
    # and breaks any later use; a `None` tuple item lowers to a bare Rust `None`
    # with no inferable `Option<T>` (E0282). Both are kept off native. An
    # explicitly `Optional`-annotated local and an all-scalar tuple stay native.
    write_module(
        tmp_path,
        "app.py",
        """
from typing import Optional
import rextio

@rextio.native
def bare_local() -> Optional[int]:
    x = None
    return x

@rextio.native
def tuple_none() -> None:
    pair = (None,)
    return None

@rextio.native
def annotated_local() -> Optional[int]:
    y: Optional[int] = None
    return y

@rextio.native
def scalar_tuple() -> tuple[int, float]:
    return (1, 2.0)
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    rejected = {f.qualname for f in analysis.rejected_native_functions}
    accepted = {f.qualname for f in analysis.accepted_native_functions}
    for name in ("app.bare_local", "app.tuple_none"):
        assert name in rejected, name
    for name in ("app.annotated_local", "app.scalar_tuple"):
        assert name in accepted, name


def test_native_call_scalar_argument_type_mismatch_kept_off_native(tmp_path: Path) -> None:
    # Rust has no implicit scalar coercion, so a native caller passing a literal of
    # a different scalar type than the callee declares (float->int here) would emit
    # native code that fails to compile (E0308). The caller is kept on the Python
    # fallback (RXT010); the callee and a type-matching caller stay native.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def callee(x: int) -> int:
    return x

@rextio.native
def bad_caller() -> int:
    return callee(1.2)

@rextio.native
def good_caller() -> int:
    return callee(1)
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    rejected = {f.qualname for f in analysis.rejected_native_functions}
    accepted = {f.qualname for f in analysis.accepted_native_functions}
    assert "app.bad_caller" in rejected
    assert "app.callee" in accepted
    assert "app.good_caller" in accepted
    assert "RXT010" in {diagnostic.code for diagnostic in analysis.diagnostics}


def test_native_call_nonliteral_argument_type_mismatch_kept_off_native(tmp_path: Path) -> None:
    # A known local of the wrong scalar type is just as uncompilable as a literal
    # (float local -> int parameter is E0308). The caller's inferred argument types
    # (not only literal constants) must be validated against the callee signature.
    # A local whose type matches stays native.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def callee(x: int) -> int:
    return x

@rextio.native
def bad_caller() -> int:
    y = 1.2
    return callee(y)

@rextio.native
def good_caller(z: int) -> int:
    y = z
    return callee(y)
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    rejected = {f.qualname for f in analysis.rejected_native_functions}
    accepted = {f.qualname for f in analysis.accepted_native_functions}
    assert "app.bad_caller" in rejected
    assert "app.good_caller" in accepted
    assert "app.callee" in accepted


def test_native_call_arity_mismatch_kept_off_native(tmp_path: Path) -> None:
    # The lowered Rust inner function has a fixed arity and no default arguments, so
    # omitting a defaulted argument or passing an extra one is E0061. Both callers
    # are kept off native; a call with the exact arity stays native.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def with_default(x: int = 1) -> int:
    return x

@rextio.native
def one_param(x: int) -> int:
    return x

@rextio.native
def too_few() -> int:
    return with_default()

@rextio.native
def too_many() -> int:
    return one_param(1, 2)

@rextio.native
def exact() -> int:
    return one_param(1)
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    rejected = {f.qualname for f in analysis.rejected_native_functions}
    accepted = {f.qualname for f in analysis.accepted_native_functions}
    assert "app.too_few" in rejected
    assert "app.too_many" in rejected
    assert "app.exact" in accepted


def test_zero_parameter_callee_called_with_args_kept_off_native(tmp_path: Path) -> None:
    # A genuinely zero-parameter native callee has an empty signature, but its
    # lowered Rust inner function still has fixed (zero) arity. Calling it with an
    # argument would emit `app__callee(1)` -> E0061. Arity is checked against the
    # callee's true positional-parameter count (0), not the truthiness of the
    # signature map, so the caller is kept off native; a correct no-arg call stays.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def callee() -> int:
    return 1

@rextio.native
def bad_caller() -> int:
    return callee(1)

@rextio.native
def good_caller() -> int:
    return callee()
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    rejected = {f.qualname for f in analysis.rejected_native_functions}
    accepted = {f.qualname for f in analysis.accepted_native_functions}
    assert "app.bad_caller" in rejected
    assert "app.good_caller" in accepted
    assert "app.callee" in accepted


def test_keyword_only_parameter_callee_kept_off_native(tmp_path: Path) -> None:
    # A keyword-only parameter cannot be supplied through the native calling
    # convention (keyword call arguments are unsupported, and a positional argument
    # for a keyword-only parameter would silently diverge from CPython's TypeError),
    # so a native caller of such a function is kept on the Python fallback.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def kwonly(*, x: int) -> int:
    return x

@rextio.native
def bad_caller() -> int:
    return kwonly(1)
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    rejected = {f.qualname for f in analysis.rejected_native_functions}
    assert "app.bad_caller" in rejected


def test_nested_native_call_argument_type_is_resolved(tmp_path: Path) -> None:
    # An argument that is itself a native call resolves to the callee's return type
    # via the module return-type registry, so a mismatch (float result -> int param)
    # is rejected while a matching nested call (int result -> int param) stays native.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def take_int(x: int) -> int:
    return x

@rextio.native
def make_float() -> float:
    return 1.5

@rextio.native
def make_int() -> int:
    return 5

@rextio.native
def bad_caller() -> int:
    return take_int(make_float())

@rextio.native
def good_caller() -> int:
    return take_int(make_int())
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    rejected = {f.qualname for f in analysis.rejected_native_functions}
    accepted = {f.qualname for f in analysis.accepted_native_functions}
    assert "app.bad_caller" in rejected
    assert "app.good_caller" in accepted


def test_nested_call_to_inferred_return_sibling_stays_native(tmp_path: Path) -> None:
    # A nested call argument to a sibling whose return type is *inferred* (not
    # annotated) must resolve via the module return-type registry — which now also
    # carries inferred returns — so a matching nested call stays native instead of
    # being conservatively rejected by the undetermined-type backstop.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def producer():
    return 5

@rextio.native
def take_int(x: int) -> int:
    return x

@rextio.native
def caller() -> int:
    return take_int(producer())
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    accepted = {f.qualname for f in analysis.accepted_native_functions}
    assert "app.caller" in accepted
    assert "app.producer" in accepted
    assert "app.take_int" in accepted


def test_non_scalar_parameter_argument_mismatch_kept_off_native(tmp_path: Path) -> None:
    # A container or Optional parameter lowers to a concrete fixed Rust type that
    # admits no coercion from a scalar, so a scalar argument passed to a list/dict
    # or Optional parameter is rejected (E0308). A matching container argument, a
    # `None` argument to an Optional parameter, and an Optional-typed argument all
    # stay native.
    write_module(
        tmp_path,
        "app.py",
        """
from typing import Optional
import rextio

@rextio.native
def take_list(xs: list[int]) -> int:
    return 1

@rextio.native
def take_opt(x: Optional[int]) -> int:
    return 0

@rextio.native
def make_list() -> list[int]:
    return [1]

@rextio.native
def bad_scalar_to_list() -> int:
    return take_list(1)

@rextio.native
def bad_scalar_to_opt() -> int:
    return take_opt(1)

@rextio.native
def good_list() -> int:
    return take_list(make_list())

@rextio.native
def good_none_to_opt() -> int:
    return take_opt(None)
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    rejected = {f.qualname for f in analysis.rejected_native_functions}
    accepted = {f.qualname for f in analysis.accepted_native_functions}
    assert "app.bad_scalar_to_list" in rejected
    assert "app.bad_scalar_to_opt" in rejected
    assert "app.good_list" in accepted
    assert "app.good_none_to_opt" in accepted


def test_cross_module_nested_call_argument_is_resolved(tmp_path: Path) -> None:
    # A nested call argument targeting a function imported from another module is
    # resolved through the project resolver (which spans modules), so a matching
    # cross-module nested call stays native while a mismatched one is rejected —
    # closing the per-module registry's blind spot for imported callees.
    write_module(
        tmp_path,
        "pkg/lib.py",
        """
import rextio

@rextio.native
def make_int() -> int:
    return 1

@rextio.native
def make_float() -> float:
    return 1.5
""",
    )
    write_module(
        tmp_path,
        "pkg/main.py",
        """
import rextio
from pkg.lib import make_int, make_float

@rextio.native
def take_int(x: int) -> int:
    return x

@rextio.native
def good_caller() -> int:
    return take_int(make_int())

@rextio.native
def bad_caller() -> int:
    return take_int(make_float())
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    rejected = {f.qualname for f in analysis.rejected_native_functions}
    accepted = {f.qualname for f in analysis.accepted_native_functions}
    assert "pkg.main.good_caller" in accepted
    assert "pkg.main.bad_caller" in rejected


def test_locally_shadowed_import_nested_call_kept_off_native(tmp_path: Path) -> None:
    # When a local binding shadows an imported function of the same name, a nested
    # call `take_int(make_int())` does not actually reach the imported function (in
    # CPython the local shadows it). The argument must not be resolved to the
    # imported callee's return type — doing so would silently lower a call to the
    # wrong function. The caller is kept on the Python fallback.
    write_module(
        tmp_path,
        "pkg/lib.py",
        """
import rextio

@rextio.native
def make_int() -> int:
    return 1
""",
    )
    write_module(
        tmp_path,
        "pkg/main.py",
        """
import rextio
from pkg.lib import make_int

@rextio.native
def take_int(x: int) -> int:
    return x

@rextio.native
def shadowed() -> int:
    make_int = 2
    return take_int(make_int())
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    rejected = {f.qualname for f in analysis.rejected_native_functions}
    assert "pkg.main.shadowed" in rejected


def test_nested_call_to_rejected_callee_kept_off_native(tmp_path: Path) -> None:
    # A nested call argument whose callee is itself rejected (kept on the Python
    # fallback) must not contribute a typed return value that keeps the outer caller
    # native — the caller would then be lowered to call a function with no native
    # implementation. The resolved return type is trusted only for accepted,
    # non-shim callees; otherwise the caller falls back. Holds across modules and
    # within a module.
    write_module(
        tmp_path,
        "pkg/lib.py",
        """
import rextio

@rextio.native
def rejected_maker() -> int:
    return eval("1")
""",
    )
    write_module(
        tmp_path,
        "pkg/main.py",
        """
import rextio
from pkg.lib import rejected_maker

@rextio.native
def take_int(x: int) -> int:
    return x

@rextio.native
def cross_caller() -> int:
    return take_int(rejected_maker())

@rextio.native
def same_rejected() -> int:
    return eval("2")

@rextio.native
def same_caller() -> int:
    return take_int(same_rejected())
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    rejected = {f.qualname for f in analysis.rejected_native_functions}
    assert "pkg.main.cross_caller" in rejected
    assert "pkg.main.same_caller" in rejected


def test_builtin_nested_call_argument_stays_native(tmp_path: Path) -> None:
    # A nested call argument that is a supported builtin / standard-library call
    # (`len(...)`, `math.floor(...)`) is not a project function, so the boundary must
    # trust the locally-inferred argument type rather than discarding it — otherwise
    # a common, valid native call would be falsely rejected.
    write_module(
        tmp_path,
        "app.py",
        """
import math
import rextio

@rextio.native
def take_int(x: int) -> int:
    return x

@rextio.native
def via_len(xs: list[int]) -> int:
    return take_int(len(xs))

@rextio.native
def via_floor(y: float) -> int:
    return take_int(math.floor(y))
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    accepted = {f.qualname for f in analysis.accepted_native_functions}
    assert "app.via_len" in accepted
    assert "app.via_floor" in accepted


def test_shadowed_nested_call_variants_kept_off_native(tmp_path: Path) -> None:
    # The shadow detection is based on the function's local binding names (from the
    # AST), so it catches a shadow regardless of the bound value's type and for an
    # attribute-call receiver — while a comprehension target (which does not leak in
    # Python 3) must NOT be treated as a shadow.
    write_module(
        tmp_path,
        "pkg/lib.py",
        """
import rextio

@rextio.native
def make_int() -> int:
    return 1
""",
    )
    write_module(
        tmp_path,
        "pkg/main.py",
        """
import rextio
import pkg.lib as lib
from pkg.lib import make_int

@rextio.native
def take_int(x: int) -> int:
    return x

@rextio.native
def none_typed_shadow() -> int:
    make_int = take_int   # local binding (type None) shadows the import
    return take_int(make_int())

@rextio.native
def attr_receiver_shadow() -> int:
    lib = 2               # local shadows the module alias
    return take_int(lib.make_int())

@rextio.native
def comprehension_ok(xs: list[int]) -> int:
    ys = [v for v in xs]  # `v` is comprehension-scoped, does not leak
    return take_int(make_int())
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    by_name = {
        f.qualname: f
        for f in (*analysis.accepted_native_functions, *analysis.rejected_native_functions)
    }
    rejected = {f.qualname for f in analysis.rejected_native_functions}
    accepted = {f.qualname for f in analysis.accepted_native_functions}
    assert "pkg.main.none_typed_shadow" in rejected
    # The attribute access on a shadowed local forces the Python runtime-semantics
    # shim (RXT080), which runs real CPython and is therefore non-divergent — equally
    # contract-safe as a fallback. Either way it must be off the direct-native path.
    attr = by_name["pkg.main.attr_receiver_shadow"]
    assert (not attr.accepted) or attr.native_runtime_semantics
    assert "pkg.main.comprehension_ok" in accepted


def test_method_call_on_local_is_not_treated_as_shadow(tmp_path: Path) -> None:
    # A method call on an ordinary local / parameter (`xs.index(...)`) whose root
    # name is not an imported or sibling function must NOT be treated as a shadow —
    # it is a normal, valid nested call argument and the caller stays native. (The
    # shadow guard only fires when the root name is also a callable being shadowed.)
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def take_int(x: int) -> int:
    return x

@rextio.native
def via_param(xs: list[int]) -> int:
    return take_int(xs.index(5))

@rextio.native
def via_local() -> int:
    ys = [1, 2, 3]
    return take_int(ys.index(2))
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    accepted = {f.qualname for f in analysis.accepted_native_functions}
    assert "app.via_param" in accepted
    assert "app.via_local" in accepted


def test_shadow_via_container_param_and_walrus_comprehension_kept_off_native(
    tmp_path: Path,
) -> None:
    # A genuine shadow of an imported function is rejected regardless of the callee
    # parameter type (a container parameter's None-argument backstop would otherwise
    # miss it), and a PEP 572 walrus binding inside a comprehension — which leaks into
    # the enclosing function scope in Python 3 — is detected as a shadow.
    write_module(
        tmp_path,
        "pkg/lib.py",
        """
import rextio

@rextio.native
def make_int() -> int:
    return 1

@rextio.native
def make_list() -> list[int]:
    return [1]
""",
    )
    write_module(
        tmp_path,
        "pkg/main.py",
        """
import rextio
from pkg.lib import make_int, make_list

@rextio.native
def take_list(xs: list[int]) -> int:
    return 1

@rextio.native
def take_int(x: int) -> int:
    return x

@rextio.native
def container_param_shadow() -> int:
    make_list = 0
    return take_list(make_list())

@rextio.native
def walrus_comprehension_shadow(xs: list[int]) -> int:
    ys = [(make_int := 0) for x in xs]
    return take_int(make_int())
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    rejected = {f.qualname for f in analysis.rejected_native_functions}
    assert "pkg.main.container_param_shadow" in rejected
    assert "pkg.main.walrus_comprehension_shadow" in rejected


def test_direct_and_builtin_and_untyped_sibling_shadows_kept_off_native(
    tmp_path: Path,
) -> None:
    # The shadow check covers every call (direct calls, not only nested arguments) and
    # the complete set of callable names: a same-module function whether annotated,
    # unannotated, or forward-referenced, and supported builtins. A local that rebinds
    # any of those and then calls it must keep the function off the direct-native path.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def take_int(x: int) -> int:
    return x

@rextio.native
def direct_call_shadow() -> int:
    take_int = 0
    return take_int(1)

@rextio.native
def builtin_shadow() -> int:
    len = 0
    return len([1])

@rextio.native
def forward_untyped_sibling_shadow() -> int:
    make_thing = 0
    return take_int(make_thing())

@rextio.native
def make_thing():
    return 7
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    rejected = {f.qualname for f in analysis.rejected_native_functions}
    assert "app.direct_call_shadow" in rejected
    assert "app.builtin_shadow" in rejected
    assert "app.forward_untyped_sibling_shadow" in rejected


def test_walrus_in_nested_comprehension_is_not_over_collected(tmp_path: Path) -> None:
    # A PEP 572 walrus inside a NESTED comprehension is scoped to that inner
    # comprehension and does not leak into the function, so it must not be treated as
    # a shadow of an imported callable — the outer function stays native. A normal
    # builtin call (not shadowed) also stays native.
    write_module(
        tmp_path,
        "pkg/lib.py",
        """
import rextio

@rextio.native
def make_int() -> int:
    return 1
""",
    )
    write_module(
        tmp_path,
        "pkg/main.py",
        """
import rextio
from pkg.lib import make_int

@rextio.native
def take_int(x: int) -> int:
    return x

@rextio.native
def nested_comp_walrus(xs: list[int]) -> int:
    zs = [[(make_int := 0) for y in xs] for x in xs]
    return take_int(len(xs))
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    accepted = {f.qualname for f in analysis.accepted_native_functions}
    assert "pkg.main.nested_comp_walrus" in accepted


def test_method_call_on_param_named_like_a_callable_stays_native(tmp_path: Path) -> None:
    # An attribute call resolves to a native function only when its receiver is an
    # imported module (or a module logger). A method call on an ordinary parameter
    # whose name merely collides with a builtin or a same-module function
    # (`sum.index(...)`, `helper.index(...)`) is a genuine method call, not a shadow,
    # so the caller stays on the direct-native path.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def helper() -> int:
    return 1

@rextio.native
def take_int(x: int) -> int:
    return x

@rextio.native
def via_builtin_name(sum: list[int]) -> int:
    return take_int(sum.index(5))

@rextio.native
def via_sibling_name(helper: list[int]) -> int:
    return take_int(helper.index(5))
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    direct_native = {
        f.qualname
        for f in analysis.accepted_native_functions
        if not f.native_runtime_semantics
    }
    assert "app.via_builtin_name" in direct_native
    assert "app.via_sibling_name" in direct_native


def test_shadowed_stdlib_module_receiver_kept_off_direct_native(tmp_path: Path) -> None:
    # A `module.func(...)` standard-library call (possibly chained) lowers to a static
    # native call that ignores the receiver. A local that rebinds the module name
    # (`def f(math: float): math.sqrt(...)`, `def g(hashlib: bytes):
    # hashlib.sha256(...).hexdigest()`) must be kept off the direct-native path
    # (rejected or routed to the runtime shim), since CPython evaluates the call on
    # the local and raises AttributeError. A method call on a local merely named like
    # a module (`math.index(...)` where `math` is a list) is a genuine method and
    # stays native, as does a normal unshadowed `math.sqrt(x)`.
    write_module(
        tmp_path,
        "app.py",
        """
import hashlib
import math
import rextio

@rextio.native
def math_shadow(math: float) -> float:
    return math.sqrt(2.0)

@rextio.native
def hashlib_chain_shadow(hashlib: bytes) -> str:
    return hashlib.sha256(hashlib).hexdigest()

@rextio.native
def take_int(x: int) -> int:
    return x

@rextio.native
def module_named_list_method(math: list[int]) -> int:
    return take_int(math.index(5))

@rextio.native
def normal_math(x: float) -> float:
    return math.sqrt(x)
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    direct_native = {
        f.qualname
        for f in analysis.accepted_native_functions
        if not f.native_runtime_semantics
    }
    # The shadowed-module receivers must not be lowered as direct native calls.
    assert "app.math_shadow" not in direct_native
    assert "app.hashlib_chain_shadow" not in direct_native
    # The genuine method call and the unshadowed stdlib call stay native.
    assert "app.module_named_list_method" in direct_native
    assert "app.normal_math" in direct_native


def test_aliased_stdlib_module_shadow_kept_off_direct_native(tmp_path: Path) -> None:
    # A stdlib module imported under an alias and shadowed by a local of the same
    # alias must be kept off the direct-native path: the call resolves to the static
    # stdlib target, but the receiver (the alias) is the local. The check keys off the
    # source receiver name, not the resolved module name, so `import math as m;
    # def f(m: float): m.sqrt(...)` is rejected/shimmed, while a parameter named like
    # the canonical module whose alias is NOT shadowed stays native.
    write_module(
        tmp_path,
        "app.py",
        """
import hashlib as h
import math as m
import rextio

@rextio.native
def alias_math_shadow(m: float) -> float:
    return m.sqrt(4.0)

@rextio.native
def alias_hashlib_chain_shadow(h: bytes) -> str:
    return h.sha256(h).hexdigest()

@rextio.native
def alias_not_shadowed(math: float) -> float:
    return m.sqrt(math)
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    direct_native = {
        f.qualname
        for f in analysis.accepted_native_functions
        if not f.native_runtime_semantics
    }
    assert "app.alias_math_shadow" not in direct_native
    assert "app.alias_hashlib_chain_shadow" not in direct_native
    # The canonical module name as a parameter, with the alias `m` not shadowed, is a
    # normal stdlib call and stays native.
    assert "app.alias_not_shadowed" in direct_native


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

def helper(x: float) -> float:
    return x * 2.0

@rextio.native
def compute(x: float) -> float:
    return helper(x) + 1.0
""",
    )

    analysis = analyze_project(
        tmp_path,
        native_marker="decorator",
        native_jit_enabled=True,
    )

    assert [function.qualname for function in analysis.accepted_native_functions] == ["app.compute"]
    assert [function.qualname for function in analysis.jit_candidates] == ["app.helper"]
    assert "embedded" in (analysis.jit_candidates[0].jit_reason or "")


def test_integer_arithmetic_is_embedding_eligible(tmp_path: Path) -> None:
    # Embedded helpers lower through the ordinary checked native path, so int
    # arithmetic raises OverflowError like any other native function.
    write_module(
        tmp_path,
        "app.py",
        """
def helper(x: int) -> int:
    return x * 2
""",
    )

    analysis = analyze_project(
        tmp_path,
        native_marker="decorator",
        native_jit_enabled=True,
    )

    assert [function.qualname for function in analysis.jit_candidates] == ["app.helper"]


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


def test_rejects_for_else(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def for_else(xs: list[int]) -> int:
    total = 0
    for x in xs:
        total = total + x
    else:
        total = total + 100
    return total
""",
    )

    analysis = analyze_project(tmp_path)

    assert {diagnostic.code for diagnostic in analysis.diagnostics} == {"RXT010"}
    assert {function.qualname for function in analysis.rejected_native_functions} == {
        "app.for_else",
    }


def test_rejects_while_else(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def while_else(n: int) -> int:
    i = 0
    while i < n:
        i = i + 1
    else:
        i = i + 500
    return i
""",
    )

    analysis = analyze_project(tmp_path)

    assert {diagnostic.code for diagnostic in analysis.diagnostics} == {"RXT010"}
    assert {function.qualname for function in analysis.rejected_native_functions} == {
        "app.while_else",
    }


def test_rejects_is_comparison_on_non_none(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def identity_eq(a: str, b: str) -> bool:
    return a is b

@rextio.native
def identity_neq(a: int, b: int) -> bool:
    return a is not b
""",
    )

    analysis = analyze_project(tmp_path)

    assert {diagnostic.code for diagnostic in analysis.diagnostics} == {"RXT010"}
    assert {function.qualname for function in analysis.rejected_native_functions} == {
        "app.identity_eq",
        "app.identity_neq",
    }


def test_accepts_is_comparison_against_none(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def is_none(x: int | None) -> bool:
    return x is None

@rextio.native
def is_not_none(x: str | None) -> bool:
    return x is not None
""",
    )

    analysis = analyze_project(tmp_path)

    assert {function.qualname for function in analysis.accepted_native_functions} == {
        "app.is_none",
        "app.is_not_none",
    }
    assert analysis.diagnostics == []


def test_rejects_value_function_that_can_fall_through(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def maybe(x: int) -> int:
    if x > 0:
        return x
""",
    )

    analysis = analyze_project(tmp_path)

    assert {diagnostic.code for diagnostic in analysis.diagnostics} == {"RXT010"}
    assert {function.qualname for function in analysis.rejected_native_functions} == {
        "app.maybe",
    }


def test_accepts_value_function_returning_on_all_paths(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def both_paths(x: int) -> int:
    if x > 0:
        return x
    else:
        return -x

@rextio.native
def trailing_return(x: int) -> int:
    if x > 0:
        return x
    return 0
""",
    )

    analysis = analyze_project(tmp_path)

    assert {function.qualname for function in analysis.accepted_native_functions} == {
        "app.both_paths",
        "app.trailing_return",
    }
    assert analysis.diagnostics == []


def test_float_division_is_not_jit_eligible(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

def fdiv(a: float, b: float) -> float:
    return a / b

def fmul(a: float, b: float) -> float:
    return a * b

@rextio.native
def compute(a: float, b: float) -> float:
    return fdiv(a, b) + fmul(a, b)
""",
    )

    analysis = analyze_project(
        tmp_path,
        native_marker="decorator",
        native_jit_enabled=True,
    )

    # Both are embedding-eligible: embedded helpers lower through the checked
    # native path, so float `/` raises ZeroDivisionError like any native
    # function.
    assert [function.qualname for function in analysis.jit_candidates] == ["app.fdiv", "app.fmul"]


def test_rejects_len_on_scalar(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def len_scalar(x: int) -> int:
    return len(x)
""",
    )

    analysis = analyze_project(tmp_path)

    assert {diagnostic.code for diagnostic in analysis.diagnostics} == {"RXT010"}
    assert {function.qualname for function in analysis.rejected_native_functions} == {
        "app.len_scalar",
    }


def test_accepts_len_on_sized_types(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def len_list(xs: list[int]) -> int:
    return len(xs)

@rextio.native
def len_str(s: str) -> int:
    return len(s)
""",
    )

    analysis = analyze_project(tmp_path)

    assert {function.qualname for function in analysis.accepted_native_functions} == {
        "app.len_list",
        "app.len_str",
    }
    assert analysis.diagnostics == []


def test_accepts_native_try_except_finally(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def safe_mod(a: int, b: int) -> int:
    result = 0
    try:
        result = a % b
    except ZeroDivisionError:
        result = -1
    finally:
        result = result + 100
    return result
""",
    )

    analysis = analyze_project(tmp_path)

    assert [function.qualname for function in analysis.accepted_native_functions] == [
        "app.safe_mod"
    ]
    assert not analysis.accepted_native_functions[0].native_runtime_semantics
    assert analysis.diagnostics == []


def test_rejects_unsupported_try_shapes(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def try_else(xs: list[int]) -> int:
    total = 0
    try:
        total = xs[0]
    except IndexError:
        total = -1
    else:
        total = total + 1
    return total

@rextio.native
def except_as(xs: list[int]) -> int:
    out = 0
    try:
        out = xs[0]
    except IndexError as exc:
        out = -1
    return out

@rextio.native
def custom_handler(xs: list[int]) -> int:
    out = 0
    try:
        out = xs[0]
    except OSError:
        out = -1
    return out

@rextio.native
def return_in_try(xs: list[int]) -> int:
    try:
        return xs[0]
    except IndexError:
        return -1
""",
    )

    analysis = analyze_project(tmp_path)

    # Unsupported try shapes on an explicit @rextio.native function fall to the
    # safe RXT080 runtime shim (Python callback); the key property is that none
    # is compiled to native Rust try/except.
    assert {function.qualname for function in analysis.accepted_native_functions} == {
        "app.try_else",
        "app.except_as",
        "app.custom_handler",
        "app.return_in_try",
    }
    assert all(
        function.native_runtime_semantics
        for function in analysis.accepted_native_functions
    )


def test_reports_all_boundary_errors_per_function(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

def helper_a(x: int) -> int:
    return x

def helper_b(x: int) -> int:
    return x

@rextio.native
def caller(x: int) -> int:
    return helper_a(x) + helper_b(x)
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    rejected = {function.qualname: function for function in analysis.rejected_native_functions}
    assert "app.caller" in rejected
    # Both fallback-only calls are reported at once, not just the first.
    codes = [diagnostic.code for diagnostic in rejected["app.caller"].error_diagnostics]
    assert codes == ["RXT070", "RXT070"]


def test_rejects_except_star(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def grouped(xs: list[int]) -> int:
    out = 0
    try:
        out = xs[0]
    except* IndexError:
        out = -1
    return out
""",
    )

    analysis = analyze_project(tmp_path)

    assert {diagnostic.code for diagnostic in analysis.diagnostics} == {"RXT010"}
    assert {function.qualname for function in analysis.rejected_native_functions} == {
        "app.grouped",
    }


def test_accepts_comprehension_target_inside_try(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def totals(xs: list[int]) -> int:
    out = 0
    try:
        out = sum([y * 2 for y in xs])
    except ValueError:
        out = -1
    return out
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    # The comprehension target `y` is scoped to the comprehension and never
    # leaks, so it must not block native acceptance of the try block.
    accepted = {f.qualname: f for f in analysis.accepted_native_functions}
    assert "app.totals" in accepted
    assert not accepted["app.totals"].native_runtime_semantics


def test_rejects_parameter_collection_mutation(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def push(xs: list[int], v: int) -> int:
    xs.append(v)
    return len(xs)
""",
    )

    analysis = analyze_project(tmp_path)

    # Mutating a parameter list is not visible to the caller in native Rust
    # (the parameter is cloned), so it must reject instead of silently dropping
    # the side effect.
    assert {diagnostic.code for diagnostic in analysis.diagnostics} == {"RXT010"}
    assert {function.qualname for function in analysis.rejected_native_functions} == {
        "app.push",
    }


def test_rejects_loop_target_rebinding_existing_variable(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def rebind(n: int) -> int:
    x = 0
    for x in range(3):
        n = n + x
    return x
""",
    )

    analysis = analyze_project(tmp_path)

    # A Python loop variable leaks its final value, but a Rust loop binding is
    # scoped to the loop, so reusing an outer name would mis-compile.
    assert {diagnostic.code for diagnostic in analysis.diagnostics} == {"RXT010"}
    assert {function.qualname for function in analysis.rejected_native_functions} == {
        "app.rebind",
    }


def test_rejects_parameter_dict_and_subscript_mutation(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def set_key(d: dict[str, int]) -> int:
    d["k"] = 1
    return d["k"]

@rextio.native
def bump_index(xs: list[int], i: int, v: int) -> int:
    xs[i] += v
    return xs[i]
""",
    )

    analysis = analyze_project(tmp_path)

    # Both reject with RXT010, by two different rules: `set_key` (`d["k"] = 1`)
    # via the parameter-collection mutation check (it would not be visible to the
    # caller in native Rust), and `bump_index` (`xs[i] += v`) via the separate
    # "augmented assignment targets must be local names" check. Either way they
    # stay on the Python fallback.
    assert {function.qualname for function in analysis.rejected_native_functions} == {
        "app.set_key",
        "app.bump_index",
    }
    assert "RXT010" in {diagnostic.code for diagnostic in analysis.diagnostics}


def test_council24_rejects_unsafe_native_patterns(tmp_path: Path) -> None:
    # Whole-codebase council round 24: a batch of patterns that were accepted as
    # direct-native but emitted wrong or uncompilable Rust. Each is now kept off
    # the direct-native path (rejected to the Python fallback, or routed to the
    # RXT080 runtime shim), never silently mis-compiled.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

len = 5

@rextio.native
def non_bool_if(x: int) -> int:
    if x:
        return 1
    return 0

@rextio.native
def non_bool_while(x: int) -> int:
    while x:
        x = x - 1
    return x

@rextio.native
def str_index(s: str) -> str:
    return s[0]

@rextio.native
def multi_assign() -> int:
    a = b = 1
    return a + b

@rextio.native
def int_literal_too_big() -> int:
    return 100000000000000000000

@rextio.native
def dict_ordering(a: dict[str, int], b: dict[str, int]) -> bool:
    return a < b

@rextio.native
def len_of_tuple(t: tuple[int, float]) -> int:
    return len(t)

@rextio.native
def range_as_value(n: int) -> int:
    return range(n)

@rextio.native
def reads_module_global() -> int:
    return y

@rextio.native
def shadowed_builtin(xs: list[int]) -> int:
    return len(xs)

y = 4
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    rejected = {function.qualname for function in analysis.rejected_native_functions}
    assert {
        "app.non_bool_if",
        "app.non_bool_while",
        "app.str_index",
        "app.multi_assign",
        "app.int_literal_too_big",
        "app.dict_ordering",
        "app.len_of_tuple",
        "app.range_as_value",
        "app.reads_module_global",
        "app.shadowed_builtin",
    } <= rejected
    assert "RXT010" in {diagnostic.code for diagnostic in analysis.diagnostics}


def test_council24_rejects_block_scoped_binding_leak(tmp_path: Path) -> None:
    # A name first bound inside an if/while block and read after it leaks Rust
    # block scope (Python locals are function-scoped; the generated `let` is not),
    # so it must be kept off the direct-native path. A name bound at the function
    # body level (even from an un-inferred sibling call) and a name used only
    # inside its block must still be accepted.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def if_branch_leak(c: bool) -> int:
    if c:
        x = 1
    else:
        x = 2
    return x

@rextio.native
def while_block_leak(c: bool) -> int:
    while c:
        y = 1
        c = False
    return y

@rextio.native
def producer(xs: list[int]) -> int:
    return xs[0]

@rextio.native
def body_level_local(xs: list[int]) -> int:
    subtotal = producer(xs)
    return subtotal + xs[0]

@rextio.native
def used_inside_block(c: bool, n: int) -> int:
    total = 0
    if c:
        step = n
        total = total + step
    return total
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    rejected = {function.qualname for function in analysis.rejected_native_functions}
    accepted = {function.qualname for function in analysis.accepted_native_functions}
    assert {"app.if_branch_leak", "app.while_block_leak"} <= rejected
    assert {
        "app.producer",
        "app.body_level_local",
        "app.used_inside_block",
    } <= accepted


def test_council24_keeps_safe_native_forms(tmp_path: Path) -> None:
    # The council-24 guards must not over-reject: a bool-typed condition, a
    # `range` for-loop iterable, a bool ordering comparison (Rust `bool` is
    # ordered like Python), and `len(str)` (faithfully lowered to a code-point
    # count) all stay on the direct-native path.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def bool_if(x: int) -> int:
    if x > 0:
        return 1
    return 0

@rextio.native
def range_loop(n: int) -> int:
    total = 0
    for i in range(1, n, 2):
        total += i
    return total

@rextio.native
def bool_ordering(a: bool, b: bool) -> bool:
    return a < b

@rextio.native
def length_of_str(s: str) -> int:
    return len(s)
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    assert {function.qualname for function in analysis.accepted_native_functions} == {
        "app.bool_if",
        "app.range_loop",
        "app.bool_ordering",
        "app.length_of_str",
    }
    assert analysis.rejected_native_functions == []


def test_council25_module_shadow_covers_unpack_and_controlflow(tmp_path: Path) -> None:
    # Council 25: the module-global shadow collector must descend into tuple/list
    # unpacking and module-level control-flow bodies (a binding there still
    # shadows the builtin), but must NOT treat a value-less `AnnAssign` (which
    # binds nothing) as a shadow.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio
import math

sorted, other = (5, 0)

if True:
    abs = 7

math = 5

len: int

@rextio.native
def unpack_shadow(xs: list[int]) -> list[int]:
    return sorted(xs)

@rextio.native
def controlflow_shadow(x: int) -> int:
    return abs(x)

@rextio.native
def attr_shadow(x: float) -> float:
    return math.sqrt(x)

@rextio.native
def annotation_only_ok(xs: list[int]) -> int:
    return len(xs)
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    rejected = {f.qualname for f in analysis.rejected_native_functions}
    accepted = {f.qualname for f in analysis.accepted_native_functions}
    assert {
        "app.unpack_shadow",
        "app.controlflow_shadow",
        "app.attr_shadow",
    } <= rejected
    # `len: int` with no value binds nothing, so `len` is the builtin here.
    assert "app.annotation_only_ok" in accepted


def test_council25_accepts_i64_min_literal(tmp_path: Path) -> None:
    # `-9223372036854775808` is i64::MIN — a valid native literal — even though
    # its positive operand 2**63 exceeds i64::MAX. `-(2**63 + 1)` stays rejected.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def at_min() -> int:
    return -9223372036854775808

@rextio.native
def below_min() -> int:
    return -9223372036854775809
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")

    assert [f.qualname for f in analysis.accepted_native_functions] == ["app.at_min"]
    assert [f.qualname for f in analysis.rejected_native_functions] == ["app.below_min"]


def test_delegate_fallback_mode_records_delegated_calls(tmp_path: Path) -> None:
    # Rust-executable delegate mode: a direct-native function that calls a
    # project function living on the Python fallback is accepted (not RXT070) and
    # the callee is recorded for delegation to the external CPython dispatcher,
    # provided the callee's return type and the argument types are wire-serializable.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.exempt
def slugify(text: str) -> str:
    return text.lower()

@rextio.native
def main(argv: list[str]) -> int:
    x = slugify(argv[0])
    return len(x)
""",
    )

    normal = analyze_project(tmp_path, native_marker="decorator")
    delegated = analyze_project(tmp_path, native_marker="decorator", delegate_fallback=True)

    def _main(analysis):
        return next(f for m in analysis.modules for f in m.functions if f.name == "main")

    # Without delegation the native->fallback call is rejected (RXT070).
    assert not _main(normal).accepted
    assert "RXT070" in {d.code for d in _main(normal).error_diagnostics}

    # With delegation the caller is accepted and the callee is recorded.
    assert _main(delegated).accepted
    assert _main(delegated).delegated_call_targets == {"app.slugify"}


def test_delegate_fallback_rejects_incompatible_delegated_return_use(tmp_path: Path) -> None:
    # A delegated call's annotated return type must participate in the normal
    # expression type checks. This rejects `str + int` at check time instead of
    # accepting the native caller and later emitting Rust `String + integer`.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.exempt
def slugify(text: str) -> str:
    return text.lower()

@rextio.native
def main(argv: list[str]) -> int:
    slug = slugify(argv[0])
    return slug + 1
""",
    )

    delegated = analyze_project(tmp_path, native_marker="decorator", delegate_fallback=True)
    main = next(f for m in delegated.modules for f in m.functions if f.name == "main")

    assert not main.accepted
    assert main.delegated_call_targets == set()
    assert any("operator is not supported" in diagnostic.message for diagnostic in main.error_diagnostics)


def test_delegate_fallback_types_pyi_stub_returns_across_modules(tmp_path: Path) -> None:
    # A callee whose return type lives ONLY in a sibling `.pyi` stub must be typed
    # at cross-module call sites too: a type-incompatible use of its result is a
    # clean check-time rejection (never a Rust `String + integer` compile
    # failure), while a valid use stays accepted and delegated.
    write_module(
        tmp_path,
        "helpers.py",
        """
import rextio

@rextio.exempt
def slugify(text):
    return text.lower()
""",
    )
    (tmp_path / "helpers.pyi").write_text(
        "def slugify(text: str) -> str: ...\n", encoding="utf-8"
    )
    write_module(
        tmp_path,
        "app.py",
        """
import rextio
from helpers import slugify

@rextio.native
def main(argv: list[str]) -> int:
    return slugify(argv[0]) + 1
""",
    )

    delegated = analyze_project(tmp_path, native_marker="decorator", delegate_fallback=True)
    main = next(f for m in delegated.modules for f in m.functions if f.name == "main")
    assert not main.accepted
    assert any("operator is not supported" in d.message for d in main.error_diagnostics)

    # The same stub-typed callee used compatibly stays accepted and delegated.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio
from helpers import slugify

@rextio.native
def main(argv: list[str]) -> int:
    return len(slugify(argv[0]))
""",
    )
    delegated = analyze_project(tmp_path, native_marker="decorator", delegate_fallback=True)
    main = next(f for m in delegated.modules for f in m.functions if f.name == "main")
    assert main.accepted
    assert main.delegated_call_targets == {"helpers.slugify"}


def test_cross_module_native_call_results_are_typed(tmp_path: Path) -> None:
    # The project-wide return-type map must type CROSS-MODULE calls to accepted
    # native functions too (the most common real-project shape): a compatible use
    # stays accepted, and a type-incompatible use of the result is a check-time
    # rejection rather than a Rust compile failure.
    write_module(
        tmp_path,
        "utils.py",
        """
import rextio

@rextio.native
def bump(x: int) -> int:
    return x + 1
""",
    )
    write_module(
        tmp_path,
        "app.py",
        """
import rextio
from utils import bump

@rextio.native
def main(argv: list[str]) -> int:
    return bump(len(argv))

@rextio.native
def broken(argv: list[str]) -> str:
    return bump(len(argv)) + "!"
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")
    functions = {f.name: f for m in analysis.modules for f in m.functions}
    assert functions["main"].accepted
    assert not functions["broken"].accepted
    assert any(
        "operator is not supported" in d.message for d in functions["broken"].error_diagnostics
    )


def test_delegate_fallback_skips_untypeable_callee(tmp_path: Path) -> None:
    # Delegation never guesses: a fallback callee without a wire-serializable
    # return type stays a rejection (the caller remains on the Python fallback).
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.exempt
def opaque(text):
    return object()

@rextio.native
def main(argv: list[str]) -> int:
    opaque(argv[0])
    return 0
""",
    )

    delegated = analyze_project(tmp_path, native_marker="decorator", delegate_fallback=True)
    main = next(f for m in delegated.modules for f in m.functions if f.name == "main")
    assert not main.accepted
    assert main.delegated_call_targets == set()


def test_delegate_fallback_rejects_mutable_container_arg(tmp_path: Path) -> None:
    # A mutable-container argument crosses the JSON wire by value, so a callee's
    # in-place mutation would be silently lost. Such a call must NOT be delegated
    # (the caller stays a rejection), never silently miscompiled.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.exempt
def sum_and_grow(xs: list[int]) -> int:
    xs.append(0)
    return sum(xs)

@rextio.native
def main(argv: list[str]) -> int:
    xs: list[int] = [1, 2, 3]
    total = sum_and_grow(xs)
    return len(xs) + total
""",
    )

    delegated = analyze_project(tmp_path, native_marker="decorator", delegate_fallback=True)
    main = next(f for m in delegated.modules for f in m.functions if f.name == "main")
    assert not main.accepted
    assert main.delegated_call_targets == set()


def test_delegate_fallback_rejects_mutable_container_return(tmp_path: Path) -> None:
    # A delegated callee returning a mutable container is NOT delegated: the returned
    # value may alias persistent Python state, so a native caller mutating its
    # by-value copy would diverge from CPython silently. The caller is safely rejected
    # (RXT070) rather than built. This pins the exact annotated-alias silent-miscompile
    # repro from the round-4 council; the `typing.List[int]` return is normalized and
    # then rejected (the builtin `list[int]` form is covered separately below).
    write_module(
        tmp_path,
        "app.py",
        """
import rextio
from typing import List

_ITEMS: list[int] = []

@rextio.exempt
def get_items() -> List[int]:
    return _ITEMS

@rextio.exempt
def item_count() -> int:
    return len(_ITEMS)

@rextio.native
def main(argv: list[str]) -> int:
    xs: list[int] = get_items()
    xs.append(1)
    return item_count()
""",
    )

    delegated = analyze_project(tmp_path, native_marker="decorator", delegate_fallback=True)
    main = next(f for m in delegated.modules for f in m.functions if f.name == "main")
    # The mutable-list-returning callee is not delegated, so the caller is rejected
    # instead of silently mis-compiled (a native `xs.append(1)` on a by-value copy
    # would leave the aliased Python global unchanged: CPython 1, hybrid 0).
    assert not main.accepted
    assert "app.get_items" not in main.delegated_call_targets

    # The scalar-returning callee remains delegatable; only the container return is
    # what forces the rejection.
    from rextio.build.orchestrator import _delegated_return_types

    assert "app.get_items" not in _delegated_return_types(delegated)


@pytest.mark.parametrize(
    "return_annotation",
    [
        "list[int]",
        "List[int]",
        "dict[str, int]",
        "set[int]",
        "tuple[int, int]",
        "Optional[list[int]]",
        "Optional[List[int]]",  # capitalized inner: exercises recursive normalization
        "bytes",  # immutable but not a wire type; must stay rejected
    ],
)
def test_delegate_fallback_rejects_every_container_return_shape(
    tmp_path: Path, return_annotation: str
) -> None:
    # No container/optional-container/non-wire return shape may be delegated (a mutable
    # container crosses the wire by value, severing aliasing; bytes has no wire type).
    # Each keeps the caller on the Python fallback — a clean rejection, never a silent
    # divergence. Pins the scalar-only contract against a future `normalize_type_name`
    # or `_DELEGATABLE_SCALARS` change that could let a shape through.
    write_module(
        tmp_path,
        "app.py",
        f"""
import rextio
from typing import List, Optional

@rextio.exempt
def produce() -> {return_annotation}:
    raise NotImplementedError

@rextio.native
def main(argv: list[str]) -> int:
    produce()
    return 0
""",
    )

    delegated = analyze_project(tmp_path, native_marker="decorator", delegate_fallback=True)
    main = next(f for m in delegated.modules for f in m.functions if f.name == "main")
    assert not main.accepted
    # Nothing is delegated (the container-returning callee is not a wire type), and the
    # caller is rejected with a boundary diagnostic rather than silently built.
    assert main.delegated_call_targets == set()
    assert any(d.code == "RXT010" for d in main.error_diagnostics)


def test_numba_decorated_function_is_clean_external_fallback(tmp_path: Path) -> None:
    # A recognized numba decorator keeps the function on the Python fallback with
    # no auto-discovery and no RXT010 decorator noise, labeled for the report; a
    # plain typed sibling is still auto-discovered. All forms resolve through the
    # module's import map: attribute, from-import, alias, and call decorators.
    write_module(
        tmp_path,
        "app.py",
        """
import numba
from numba import njit
from numba import vectorize as vec

@numba.jit
def a(x: int) -> int:
    return x + 1

@njit(cache=True)
def b(x: int) -> int:
    return x + 2

@vec
def c(x: float) -> float:
    return x * 2.0

def plain(x: int) -> int:
    return x + 3
""",
    )

    analysis = analyze_project(tmp_path, native_marker="auto")
    functions = {f.name: f for m in analysis.modules for f in m.functions}

    for name in ("a", "b", "c"):
        function = functions[name]
        assert function.external_accelerator == "numba"
        assert not function.is_native_candidate
        assert function.error_diagnostics == []
    assert functions["plain"].accepted
    assert functions["plain"].external_accelerator is None


def test_user_decorator_sharing_a_numba_name_is_not_mislabeled(tmp_path: Path) -> None:
    # Recognition is import-resolved: a user-defined decorator merely NAMED `njit`
    # is not treated as an external accelerator.
    write_module(
        tmp_path,
        "app.py",
        """
def njit(func):
    return func

@njit
def helper(x: int) -> int:
    return x + 1
""",
    )

    analysis = analyze_project(tmp_path, native_marker="auto")
    helper = next(f for m in analysis.modules for f in m.functions if f.name == "helper")
    assert helper.external_accelerator is None


def test_numba_function_remains_delegatable_in_exe_mode(tmp_path: Path) -> None:
    # In the rust-exe delegate mode a numba-decorated fallback function with wire
    # types is delegated like any other fallback callee (the dispatcher simply
    # calls the numba dispatcher object in real CPython).
    write_module(
        tmp_path,
        "app.py",
        """
import rextio
from numba import njit

@njit
def scale(x: int) -> int:
    return x * 2

@rextio.native
def main(argv: list[str]) -> int:
    return scale(len(argv))
""",
    )

    delegated = analyze_project(tmp_path, native_marker="decorator", delegate_fallback=True)
    main = next(f for m in delegated.modules for f in m.functions if f.name == "main")
    assert main.accepted
    assert main.delegated_call_targets == {"app.scale"}


def test_native_marker_with_numba_decorator_is_rejected_loudly(tmp_path: Path) -> None:
    # An explicit @rextio.native combined with a numba decorator is a genuine
    # conflict: the native path must reject the unknown decorator rather than
    # silently compiling a function whose runtime object is a numba dispatcher.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio
import numba

@rextio.native
@numba.njit
def helper(x: int) -> int:
    return x + 1
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")
    helper = next(f for m in analysis.modules for f in m.functions if f.name == "helper")
    assert not helper.accepted
    assert helper.external_accelerator == "numba"
    assert any("decorator" in d.message for d in helper.error_diagnostics)


def test_project_local_numba_module_is_not_mislabeled(tmp_path: Path) -> None:
    # A PROJECT-LOCAL module named `numba` is the user's code: resolving
    # `@numba.njit` through it must not label the function as the external
    # Numba accelerator (recognition consults the project's module names).
    (tmp_path / "numba.py").write_text(
        "def njit(func):\n    return func\n", encoding="utf-8"
    )
    write_module(
        tmp_path,
        "app.py",
        """
import numba

@numba.njit
def helper(x: int) -> int:
    return x + 1
""",
    )

    analysis = analyze_project(tmp_path, native_marker="auto")
    helper = next(f for m in analysis.modules for f in m.functions if f.name == "helper")
    assert helper.external_accelerator is None

@pytest.mark.parametrize(
    ("shape", "source"),
    [
        (
            "guarded_import",
            """
try:
    from numba import njit
except ImportError:
    def njit(func):
        return func

@njit
def helper(x: int) -> int:
    return x + 1
""",
        ),
        (
            "star_import",
            """
from numba import *

@njit
def helper(x: int) -> int:
    return x + 1
""",
        ),
        (
            "class_method",
            """
import numba

class Kernels:
    @staticmethod
    @numba.njit
    def helper(x: int) -> int:
        return x + 1
""",
        ),
        (
            "conditional_import",
            """
if True:
    import numba

@numba.njit
def helper(x: int) -> int:
    return x + 1
""",
        ),
    ],
)
def test_source_scan_detects_indirect_numba_shapes(shape: str, source: str) -> None:
    # The build backends only have the generated source text: the scan must see
    # through the common optional-dependency guard (`try: from numba import
    # njit`), `from numba import *`, class-contained methods, and conditional
    # imports - otherwise Nuitka compiles the module and the accelerated
    # function dies at first call despite the failure being knowable here.
    from rextio.analyzer.native_marker import external_accelerator_for_source

    assert external_accelerator_for_source(source) == "numba", shape


def test_source_scan_ignores_local_decorator_without_numba_import() -> None:
    # A bare local `njit` stub with no numba import anywhere is user code.
    from rextio.analyzer.native_marker import external_accelerator_for_source

    source = """
def njit(func):
    return func

@njit
def helper(x: int) -> int:
    return x + 1
"""
    assert external_accelerator_for_source(source) is None

@pytest.mark.parametrize(
    ("shape", "body"),
    [
        ("for_loop", "    out: list[int] = []\n    for x in xs:\n        out.append(x)\n    return out\n"),
        ("comprehension", "    return [x for x in xs]\n"),
    ],
)
def test_set_iteration_is_rejected_to_fallback(shape: str, body: str, tmp_path: Path) -> None:
    # Iterating a set is order-observable: CPython's order is deterministic
    # within a process while Rust's HashSet seeds per instance (same call, same
    # elements, different order). No faithful lowering exists, so the function
    # must be rejected loudly instead of silently mis-compiling the order.
    write_module(
        tmp_path,
        "app.py",
        f"""
import rextio

@rextio.native
def f(xs: set[int]) -> list[int]:
{body}""",
    )
    analysis = analyze_project(tmp_path, native_marker="decorator")
    function = next(f for m in analysis.modules for f in m.functions)
    assert not function.accepted, shape
    assert any("iterating a set" in d.message for d in function.error_diagnostics), shape
    # Exactly ONE diagnostic: the dedicated message must not be followed by
    # the generic iterable rejection or name-scope cascades.
    assert len(function.error_diagnostics) == 1, [d.message for d in function.error_diagnostics]


def test_building_a_set_from_a_list_stays_native(tmp_path: Path) -> None:
    # Constructing a set (from an ordered iterable) observes no set order;
    # only iteration OUT of a set is rejected.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def f(xs: list[int]) -> set[int]:
    return {x for x in xs if x > 0}
""",
    )
    analysis = analyze_project(tmp_path, native_marker="decorator")
    function = next(f for m in analysis.modules for f in m.functions)
    assert function.accepted

def test_bytes_decode_direct_native_carries_divergence_note(tmp_path: Path) -> None:
    # bytes.decode() on the direct native path raises ValueError where CPython
    # raises UnicodeDecodeError (documented divergence): the function must
    # carry a non-rejecting RXT090 note so the divergence is visible at build
    # time, not only in the docs.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def dec(b: bytes) -> str:
    return b.decode()
""",
    )
    analysis = analyze_project(tmp_path, native_marker="decorator")
    function = next(f for m in analysis.modules for f in m.functions)
    assert function.accepted
    notes = [d for d in function.diagnostics if d.code == "RXT090"]
    assert len(notes) == 1
    assert notes[0].severity == "warning"
    assert "UnicodeDecodeError" in notes[0].message


def test_divergence_note_stripped_from_shim_and_fallback_functions(tmp_path: Path) -> None:
    # A shim (or rejected) function executes real CPython, so the decode
    # divergence cannot occur there and the note must not survive.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

@rextio.native
def dec(b: bytes) -> str:
    try:
        return b.decode()
    except UnicodeDecodeError:
        return "bad"
""",
    )
    analysis = analyze_project(tmp_path, native_marker="decorator")
    function = next(f for m in analysis.modules for f in m.functions)
    assert function.accepted
    assert function.native_runtime_semantics
    assert not [d for d in function.diagnostics if d.code == "RXT090"]

@pytest.mark.parametrize(
    ("shape", "source"),
    [
        (
            "local_import_nested",
            """
def run(values):
    from numba import njit

    @njit
    def inner(x):
        return x * 2

    return inner(values)
""",
        ),
        (
            "star_import_cuda",
            """
from numba import *

@cuda.jit
def f(x: int) -> int:
    return x
""",
        ),
        (
            "except_handler_import",
            """
try:
    import fast_numba as numba
except ImportError:
    import numba

@numba.njit
def f(x: int) -> int:
    return x
""",
        ),
    ],
)
def test_source_scan_walks_the_whole_tree(shape: str, source: str) -> None:
    # A deferred import inside a function body decorating a NESTED function,
    # `from numba import *` resolving the `cuda` submodule, and an import in
    # an except handler are all knowable at build time; missing them meant a
    # Nuitka-compiled module whose accelerated function dies at first call.
    from rextio.analyzer.native_marker import external_accelerator_for_source

    assert external_accelerator_for_source(source) == "numba", shape


def test_source_scan_ignores_project_local_numba_module() -> None:
    # The generated tree always contains every project module, so a top-level
    # `numba` name in the tree means the import resolves to the user's own
    # code: the build scans must not skip/block such modules (the analyzer
    # already had this guard; the build scans lacked it).
    from rextio.analyzer.native_marker import external_accelerator_for_source

    source = """
import numba

@numba.njit
def f(x: int) -> int:
    return x
"""
    assert external_accelerator_for_source(source, frozenset({"numba"})) is None
    assert external_accelerator_for_source(source, frozenset({"app"})) == "numba"

def test_source_scan_accelerator_binding_survives_scope_collisions() -> None:
    # The whole-tree walk flattens scopes: a nested `import local_numba as
    # numba` must not overwrite the top-level `import numba` binding that a
    # top-level @numba.njit resolves through - dropping it is UNDER-detection
    # (compiled module, first-call death), the unsafe direction.
    from rextio.analyzer.native_marker import external_accelerator_for_source

    source = """
import numba

@numba.njit
def kernel(x: int) -> int:
    return x * 2

def unrelated():
    import local_numba as numba
    return numba.helper()
"""
    assert external_accelerator_for_source(source, frozenset({"local_numba"})) == "numba"
    assert external_accelerator_for_source(source) == "numba"


def test_project_local_namespace_package_numba_is_recognized(tmp_path: Path) -> None:
    # A local `numba/` NAMESPACE package (no __init__.py) is still project
    # code; the tree-name derivation must include it.
    from rextio.analyzer.native_marker import project_module_names_for_tree

    (tmp_path / "numba").mkdir()
    (tmp_path / "numba" / "shim.py").write_text("def njit(f):\n    return f\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("import numba\n", encoding="utf-8")
    assert "numba" in project_module_names_for_tree(tmp_path)

@pytest.mark.parametrize(
    ("shape", "body"),
    [
        ("enumerate", "    total = 0\n    for i, x in enumerate(xs):\n        total = total + i\n    return total\n"),
        ("zip", "    total = 0\n    for a, b in zip(xs, xs):\n        total = total + a + b\n    return total\n"),
    ],
)
def test_enumerate_and_zip_over_sets_explain_the_real_reason(
    shape: str, body: str, tmp_path: Path
) -> None:
    # enumerate/zip over a set must report the actual reason (set iteration
    # order divergence) - never the generic "supports list variables only"
    # message - and exactly once.
    write_module(
        tmp_path,
        "app.py",
        f"""
import rextio

@rextio.native
def f(xs: set[int]) -> int:
{body}""",
    )
    analysis = analyze_project(tmp_path, native_marker="decorator")
    function = next(f for m in analysis.modules for f in m.functions)
    assert not function.accepted, shape
    messages = [d.message for d in function.error_diagnostics]
    # Every diagnostic is the dedicated set message (one per offending
    # argument) - no generic "list only" or name-scope cascade noise.
    assert messages and all("iterating a set" in m for m in messages), messages

@pytest.mark.parametrize(
    "body_import",
    [
        ("from statistics import mean", "mean(xs)"),
        ("from statistics import mean as avg", "avg(xs)"),
        ("from json import dumps", "float(len(dumps(xs)))"),
    ],
    ids=["from-import", "aliased", "json-dumps"],
)
def test_fidelity_calls_shim_regardless_of_import_form(
    body_import: tuple[str, str], tmp_path: Path
) -> None:
    # `statistics.mean` (attribute form) rides the RXT080 shim for marked
    # functions; every bare from-import spelling must behave identically -
    # import style must not change the documented behavior.
    import_line, call = body_import
    write_module(
        tmp_path,
        "app.py",
        f"""
import rextio
{import_line}

@rextio.native
def f(xs: list[float]) -> float:
    return {call}
""",
    )
    analysis = analyze_project(tmp_path, native_marker="decorator")
    function = next(f for m in analysis.modules for f in m.functions)
    assert function.accepted
    assert function.native_runtime_semantics


def test_local_function_named_mean_is_not_shim_promoted(tmp_path: Path) -> None:
    # A project-local `mean` does not resolve through imports to the fidelity
    # list: the marked caller is rejected loudly, not silently shimmed.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

def mean(xs):
    return 0.0

@rextio.native
def f(xs: list[float]) -> float:
    return mean(xs)
""",
    )
    analysis = analyze_project(tmp_path, native_marker="decorator")
    function = next(f for m in analysis.modules for f in m.functions if f.name == "f")
    assert not function.accepted
    assert not function.native_runtime_semantics

@pytest.mark.parametrize(
    ("shape", "prelude"),
    [
        ("def-shadow", "from statistics import mean\n\ndef mean(xs):\n    return 0.0\n"),
        ("class-shadow", "from statistics import mean\n\nclass mean:\n    pass\n"),
        ("assign-shadow", "from statistics import mean\n\nmean = len\n"),
    ],
)
def test_shadowed_fidelity_import_is_not_shim_promoted(
    shape: str, prelude: str, tmp_path: Path
) -> None:
    # A module-level def/class/assignment AFTER `from statistics import mean`
    # rebinds the name to PROJECT code: the marked caller must reject loudly
    # (the call resolves to the shadow at runtime, not to the stdlib).
    write_module(
        tmp_path,
        "app.py",
        f"""
import rextio
{prelude}
@rextio.native
def f(xs: list[float]) -> float:
    return mean(xs)
""",
    )
    analysis = analyze_project(tmp_path, native_marker="decorator")
    function = next(f for m in analysis.modules for f in m.functions if f.name == "f")
    assert not function.accepted, shape
    assert not function.native_runtime_semantics, shape


def test_reimport_after_def_restores_fidelity_shim(tmp_path: Path) -> None:
    # The binder ORDER decides: `def mean` followed by a re-import of the
    # stdlib name means the runtime binding IS statistics.mean, so the marked
    # caller rides the RXT080 shim exactly like an unshadowed from-import.
    write_module(
        tmp_path,
        "app.py",
        """
import rextio

def mean(xs):
    return 0.0

from statistics import mean

@rextio.native
def f(xs: list[float]) -> float:
    return mean(xs)
""",
    )
    analysis = analyze_project(tmp_path, native_marker="decorator")
    function = next(f for m in analysis.modules for f in m.functions if f.name == "f")
    assert function.accepted
    assert function.native_runtime_semantics

@pytest.mark.parametrize(
    ("shape", "prelude"),
    [
        ("walrus", "from statistics import mean\n\n(mean := len)\n"),
        ("relative-import", "from statistics import mean\nfrom .helpers import mean\n"),
        ("relative-star", "from statistics import mean\nfrom .helpers import *\n"),
        ("decorator-walrus", "from statistics import mean\n\n@(mean := staticmethod)\nclass C:\n    pass\n"),
        (
            "match-capture",
            "from statistics import mean\n\nmatch 1:\n    case mean:\n        pass\n",
        ),
        (
            "except-as",
            "from statistics import mean\ntry:\n    pass\nexcept ImportError as mean:\n    pass\n",
        ),
        (
            "trystar-handler-def",
            "from statistics import mean\ntry:\n    pass\nexcept* ValueError:\n    def mean(xs):\n        return 0.0\n",
        ),
    ],
)
def test_exotic_rebinders_block_fidelity_shim(shape: str, prelude: str, tmp_path: Path) -> None:
    # Any module-level rebinding of a fidelity name - a walrus or a relative
    # import (project code) - overrides the earlier stdlib import; the marked
    # caller must reject loudly instead of shim-promoting off the stale
    # binding.
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "helpers.py").write_text("def mean(xs):\n    return 0.0\n", encoding="utf-8")
    (pkg / "app.py").write_text(
        f"""
import rextio
{prelude}
@rextio.native
def f(xs: list[float]) -> float:
    return mean(xs)
""",
        encoding="utf-8",
    )
    analysis = analyze_project(tmp_path, native_marker="decorator")
    function = next(f for m in analysis.modules for f in m.functions if f.name == "f")
    assert not function.native_runtime_semantics, shape
    assert not function.accepted, shape
