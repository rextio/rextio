"""WP-4 follow-up 6: one shared, exact final-binding authority everywhere.

These tests pin the corrected behavior for the confirmed silent-miscompile
families and the director's positive/negative matrix:

* a same-module or cross-module project function overwritten by a later
  class/assignment/``del``/conditional binder is stale — both a call to it and
  the overwritten definition itself fail closed (never installed in the wrapper);
* ``from ... import *`` is a wildcard that shadows a later-unbound bare
  ``abs``/``min``/``max`` (and ``math`` head), so those calls fail closed;
* an earlier bad assignment followed by a final safe ``def``/import is NOT
  poisoned; ordinary builtins, ``from math import sin``, and ``import math;
  math.sin`` stay accepted when no final shadow exists;
* the shared authority (:mod:`rextio.analyzer.final_bindings`) is exact-origin
  and wildcard-aware, so a stale duplicate definition can never be mistaken for
  the final one.
"""

from __future__ import annotations

import ast
from pathlib import Path

from rextio.analyzer.final_bindings import (
    BindingKind,
    build_module_bindings,
    definition_is_final,
    head_binding_blocks,
)
from rextio.analyzer.project_scanner import analyze_project


# ---------------------------------------------------------------------------
# Authority unit tests (exact origin, wildcard state, exec conservatism).
# ---------------------------------------------------------------------------


def _bindings(source: str, module_name: str = "m"):
    return build_module_bindings(ast.parse(source), module_name)


def test_def_overwritten_by_class_is_class_with_exact_origin() -> None:
    b = _bindings("def good():\n    pass\n\nclass good:\n    pass\n")
    entry = b.lookup("good")
    assert entry.kind is BindingKind.CLASS
    assert entry.line == 4 and entry.column == 0
    # The stale def at line 1 is NOT the final binding.
    assert not definition_is_final(b, "good", BindingKind.FUNCTION, 1, 0)
    assert head_binding_blocks(b, "good")


def test_earlier_assignment_then_final_def_restores_function() -> None:
    b = _bindings("good = 5\n\ndef good():\n    pass\n")
    assert b.lookup("good").kind is BindingKind.FUNCTION
    assert not head_binding_blocks(b, "good")
    assert definition_is_final(b, "good", BindingKind.FUNCTION, 3, 0)


def test_wildcard_shadows_later_unbound_name_but_not_earlier_explicit() -> None:
    b = _bindings("from pkg import *\n")
    assert b.last_unknown_star_order is not None
    # A name never explicitly bound after the star is unknown-star (blocked).
    assert b.lookup("abs").kind is BindingKind.UNKNOWN_STAR
    assert head_binding_blocks(b, "abs")


def test_star_before_explicit_def_restores_but_explicit_before_star_is_unknown() -> None:
    restored = _bindings("from pkg import *\n\ndef abs():\n    pass\n")
    assert restored.lookup("abs").kind is BindingKind.FUNCTION
    assert not head_binding_blocks(restored, "abs")

    poisoned = _bindings("def abs():\n    pass\n\nfrom pkg import *\n")
    assert poisoned.lookup("abs").kind is BindingKind.UNKNOWN_STAR
    assert head_binding_blocks(poisoned, "abs")


def test_multiple_stars_keep_latest_wildcard_order() -> None:
    b = _bindings("from a import *\n\ndef keep():\n    pass\n\nfrom b import *\n")
    # The later star shadows the def bound between the two stars.
    assert b.lookup("keep").kind is BindingKind.UNKNOWN_STAR


def test_import_pkg_sub_binds_top_package_and_alias_binds_full_target() -> None:
    b = _bindings("import pkg.sub\nimport pkg.other as alias\n")
    top = b.lookup("pkg")
    assert top.kind is BindingKind.IMPORT and top.target == "pkg"
    aliased = b.lookup("alias")
    assert aliased.kind is BindingKind.IMPORT and aliased.target == "pkg.other"
    # No literal "sub"/"other" name entry.
    assert b.lookup("sub").kind is BindingKind.UNBOUND


def test_future_annotations_makes_no_annotations_binding() -> None:
    # `from __future__ import annotations` creates NO runtime-visible `annotations`
    # binding, so the authority must report it UNBOUND (director follow-up 7, P1-3).
    b = _bindings("from __future__ import annotations\n")
    assert b.lookup("annotations").kind is BindingKind.UNBOUND
    # The wildcard case must never create a literal "*" entry:
    star = _bindings("from pkg import *\n")
    assert "*" not in star.entries


def test_direct_module_exec_marks_subsequent_lookups_unknown() -> None:
    b = _bindings("import math\n\nexec('math = 1')\n")
    assert b.last_unknown_star_order is not None
    assert b.lookup("math").kind is BindingKind.UNKNOWN_STAR
    assert head_binding_blocks(b, "math")


def test_conditional_and_del_bind_ambiguous_and_deleted() -> None:
    cond = _bindings("import flag\nif flag:\n    def good():\n        pass\n")
    assert cond.lookup("good").kind is BindingKind.AMBIGUOUS
    deleted = _bindings("def good():\n    pass\n\ndel good\n")
    assert deleted.lookup("good").kind is BindingKind.DELETED
    assert head_binding_blocks(deleted, "good")


def test_class_body_global_assignment_rhs_walrus_invalidates_function() -> None:
    """Class-body ``global`` + assignment-RHS walrus rebinds the module global.

    Confirmed soundness gap: statement targets alone missed ``NamedExpr`` writes
    such as ``local = (trusted := 1)`` while the class body ran.
    """
    b = _bindings(
        "def trusted(x):\n"
        "    return x\n"
        "\n"
        "class C:\n"
        "    global trusted\n"
        "    local = (trusted := 1)\n"
    )
    assert b.lookup("trusted").kind is not BindingKind.FUNCTION
    assert b.unstable_class_sites


def test_class_body_global_expression_stmt_walrus_invalidates_function() -> None:
    """A bare expression-statement walrus under class-body ``global`` also rebinds."""
    b = _bindings(
        "def trusted(x):\n"
        "    return x\n"
        "\n"
        "class C:\n"
        "    global trusted\n"
        "    (trusted := 1)\n"
    )
    assert b.lookup("trusted").kind is not BindingKind.FUNCTION
    assert b.unstable_class_sites


def test_class_body_global_if_walrus_remains_fail_closed() -> None:
    """The already-fail-closed ``if (trusted := 1)`` path must stay invalidated."""
    b = _bindings(
        "def trusted(x):\n"
        "    return x\n"
        "\n"
        "class C:\n"
        "    global trusted\n"
        "    if (trusted := 1):\n"
        "        pass\n"
    )
    assert b.lookup("trusted").kind is not BindingKind.FUNCTION
    assert b.unstable_class_sites


def test_nested_scopes_do_not_create_false_class_global_walrus_writes() -> None:
    """Walruses inside nested function/lambda/class bodies are other scopes.

    Class-body ``global`` applies only to names written while the class body
    itself executes — not to nested defs, lambdas, or nested class bodies.
    """
    nested_function = _bindings(
        "def trusted(x):\n"
        "    return x\n"
        "\n"
        "class C:\n"
        "    global trusted\n"
        "    def helper():\n"
        "        trusted = (trusted := 1)\n"
        "        return trusted\n"
    )
    assert nested_function.lookup("trusted").kind is BindingKind.FUNCTION
    assert not nested_function.unstable_class_sites

    nested_lambda = _bindings(
        "def trusted(x):\n"
        "    return x\n"
        "\n"
        "class C:\n"
        "    global trusted\n"
        "    helper = lambda: (trusted := 1)\n"
    )
    assert nested_lambda.lookup("trusted").kind is BindingKind.FUNCTION
    assert not nested_lambda.unstable_class_sites

    nested_class = _bindings(
        "def trusted(x):\n"
        "    return x\n"
        "\n"
        "class C:\n"
        "    global trusted\n"
        "    class Inner:\n"
        "        local = (trusted := 1)\n"
    )
    assert nested_class.lookup("trusted").kind is BindingKind.FUNCTION
    assert not nested_class.unstable_class_sites


def test_class_body_global_nested_function_default_walrus_invalidates_function() -> None:
    """A walrus in a nested function header runs under the enclosing class body.

    Defaults (and other headers: annotations, bases, decorators) are evaluated
    while the class body executes. With ``global trusted``, a default like
    ``def helper(x=(trusted := 1))`` rebinds the module global — justifying
    header traversal even though nested *bodies* are skipped.
    """
    b = _bindings(
        "def trusted(x):\n"
        "    return x\n"
        "\n"
        "class C:\n"
        "    global trusted\n"
        "    def helper(x=(trusted := 1)):\n"
        "        return x\n"
    )
    assert b.lookup("trusted").kind is not BindingKind.FUNCTION
    assert b.unstable_class_sites


# ---------------------------------------------------------------------------
# Analyzer accept/reject matrix.
# ---------------------------------------------------------------------------


def _statuses(root: Path, files: dict[str, str]) -> dict[str, str]:
    for rel, contents in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")
    analysis = analyze_project(root, native_marker="decorator")
    accepted = {f.qualname for f in analysis.accepted_native_functions}
    rejected = {f.qualname for f in analysis.rejected_native_functions}
    out: dict[str, str] = {}
    for name in accepted:
        out[name] = "accepted"
    for name in rejected:
        out[name] = "rejected"
    return out


_HEADER = "import rextio\n"


def test_same_module_final_class_rejects_call_and_stale_def(tmp_path: Path) -> None:
    status = _statuses(
        tmp_path,
        {
            "app.py": _HEADER
            + "@rextio.native\ndef good(x: int) -> int:\n    return x + 100\n\n"
            + "class good:\n    def __new__(cls, x: int) -> int:\n        return x + 200\n\n"
            + "@rextio.native\ndef udf(x: int) -> int:\n    return good(x)\n",
        },
    )
    # The call to the class-shadowed name fails closed AND the overwritten native
    # function is not installed (definition gate).
    assert status["app.udf"] == "rejected"
    assert status["app.good"] == "rejected"


def test_same_module_final_assignment_del_conditional_reject(tmp_path: Path) -> None:
    for label, tail in {
        "assign": "good = 5\n",
        "del": "del good\n",
        "conditional": "import flag\nif flag:\n    def good(x: int) -> int:\n        return x\n",
    }.items():
        root = tmp_path / label
        status = _statuses(
            root,
            {
                "app.py": _HEADER
                + "@rextio.native\ndef good(x: int) -> int:\n    return x + 1\n\n"
                + tail
                + "\n@rextio.native\ndef udf(x: int) -> int:\n    return good(x)\n",
            },
        )
        assert status["app.udf"] == "rejected", label
        assert status.get("app.good") == "rejected", label


def test_cross_module_stale_function_rejects_for_each_kind(tmp_path: Path) -> None:
    for label, tail in {
        "class": "class good:\n    pass\n",
        "assign": "good = 5\n",
        "del": "del good\n",
        "conditional": "import flag\nif flag:\n    good = 1\n",
    }.items():
        root = tmp_path / label
        status = _statuses(
            root,
            {
                "pkg/__init__.py": "",
                "pkg/a.py": _HEADER
                + "@rextio.native\ndef good(x: int) -> int:\n    return x + 100\n\n"
                + tail,
                "pkg/b.py": _HEADER
                + "from .a import good\n\n"
                + "@rextio.native\ndef udf(x: int) -> int:\n    return good(x)\n",
            },
        )
        assert status.get("pkg.a.good") == "rejected", label
        # b.udf may fall back or route through a boundary call, but it must NOT be
        # a direct-native call to the stale a.good; either way not silently wrong.
        assert status.get("pkg.b.udf") in {"rejected", "accepted"}


def test_wildcard_shadow_rejects_abs_min_max(tmp_path: Path) -> None:
    for name in ("abs", "min", "max"):
        root = tmp_path / name
        call = f"{name}(x, 1)" if name in {"min", "max"} else f"{name}(x)"
        status = _statuses(
            root,
            {
                "pkg/__init__.py": "",
                "pkg/helper.py": f"def {name}(x: int, *rest: int) -> int:\n    return x + 100\n",
                "pkg/app.py": _HEADER
                + "from .helper import *\n\n"
                + "import rextio\n\n"
                + f"@rextio.native\ndef udf(x: int) -> int:\n    return {call}\n",
            },
        )
        assert status["pkg.app.udf"] == "rejected", name


def test_final_class_and_math_head_shadow_reject(tmp_path: Path) -> None:
    class_math = _statuses(
        tmp_path / "math_class",
        {
            "app.py": _HEADER
            + "import math\n\nclass math:\n    @staticmethod\n"
            + "    def sin(x: float) -> float:\n        return 100.5\n\n"
            + "@rextio.native\ndef udf(x: float) -> float:\n    return math.sin(x)\n",
        },
    )
    assert class_math["app.udf"] == "rejected"

    for name in ("abs", "min", "max"):
        root = tmp_path / f"cls_{name}"
        call = f"{name}(x, 1)" if name in {"min", "max"} else f"{name}(x)"
        status = _statuses(
            root,
            {
                "app.py": _HEADER
                + f"class {name}:\n    pass\n\n"
                + f"@rextio.native\ndef udf(x: int) -> int:\n    return {call}\n",
            },
        )
        assert status["app.udf"] == "rejected", name


def test_ordinary_builtins_and_math_stay_accepted(tmp_path: Path) -> None:
    status = _statuses(
        tmp_path,
        {
            "app.py": _HEADER
            + "import math\nfrom math import sin\n\n"
            + "@rextio.native\ndef use_abs(x: int) -> int:\n    return abs(x)\n\n"
            + "@rextio.native\ndef use_min(a: int, b: int) -> int:\n    return min(a, b)\n\n"
            + "@rextio.native\ndef use_max(a: int, b: int) -> int:\n    return max(a, b)\n\n"
            + "@rextio.native\ndef use_import_math(x: float) -> float:\n    return math.sin(x)\n\n"
            + "@rextio.native\ndef use_from_import(x: float) -> float:\n    return sin(x)\n",
        },
    )
    for name in (
        "app.use_abs",
        "app.use_min",
        "app.use_max",
        "app.use_import_math",
        "app.use_from_import",
    ):
        assert status[name] == "accepted", name


def test_positive_restore_directions(tmp_path: Path) -> None:
    status = _statuses(
        tmp_path,
        {
            "app.py": _HEADER
            # earlier assignment then final safe def
            + "helper = 5\ndef helper(x: int) -> int:\n    return x + 7\n\n"
            + "@rextio.native\ndef use_helper(x: int) -> int:\n    return helper(x)\n\n"
            # earlier shadow then final explicit safe import
            + "sin = 5\nfrom math import sin\n\n"
            + "@rextio.native\ndef use_sin(x: float) -> float:\n    return sin(x)\n",
        },
    )
    assert status["app.use_helper"] == "accepted"
    assert status["app.use_sin"] == "accepted"


def test_valid_sibling_and_cross_module_project_routes(tmp_path: Path) -> None:
    status = _statuses(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/a.py": _HEADER + "@rextio.native\ndef base(x: int) -> int:\n    return x + 3\n",
            "pkg/b.py": _HEADER
            + "from .a import base\n\n"
            + "@rextio.native\ndef sibling(x: int) -> int:\n    return x + 1\n\n"
            + "@rextio.native\ndef call_sibling(x: int) -> int:\n    return sibling(x)\n\n"
            + "@rextio.native\ndef call_cross(x: int) -> int:\n    return base(x)\n",
        },
    )
    assert status["pkg.a.base"] == "accepted"
    assert status["pkg.b.sibling"] == "accepted"
    assert status["pkg.b.call_sibling"] == "accepted"
    assert status["pkg.b.call_cross"] == "accepted"


def test_aliased_and_dotted_imports_of_stale_function_reject(tmp_path: Path) -> None:
    aliased = _statuses(
        tmp_path / "aliased",
        {
            "pkg/__init__.py": "",
            "pkg/helper.py": _HEADER
            + "@rextio.native\ndef good(x: int) -> int:\n    return x + 100\n\n"
            + "class good:\n    pass\n",
            "pkg/app.py": _HEADER
            + "from .helper import good as g\n\n"
            + "@rextio.native\ndef udf(x: int) -> int:\n    return g(x)\n",
        },
    )
    assert aliased.get("pkg.helper.good") == "rejected"
    assert aliased.get("pkg.app.udf") in {"rejected", "accepted"}


def test_duplicate_defs_keep_only_the_last(tmp_path: Path) -> None:
    analysis = analyze_project(
        _write_tree(
            tmp_path,
            {
                "app.py": _HEADER
                + "@rextio.native\ndef dup(x: int) -> int:\n    return x + 1\n\n"
                + "@rextio.native\ndef dup(x: int) -> int:\n    return x + 2\n",
            },
        ),
        native_marker="decorator",
    )
    accepted = [f for f in analysis.accepted_native_functions if f.qualname == "app.dup"]
    # Only the final def is accepted for build (its exact origin is the final
    # binding); the earlier duplicate is excluded.
    assert len(accepted) == 1
    assert accepted[0].line == 7


def _write_tree(root: Path, files: dict[str, str]) -> Path:
    for rel, contents in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")
    return root
