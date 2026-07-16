"""WP-4 follow-up 4, section 7: core shares the source-order final-binding model.

``_collect_imports`` (the module import map) and core call resolution must reflect
each name's FINAL source-order binding: an import shadowed by a later
def/class/assignment/``del`` no longer resolves to the import, a later restoring
import wins, and a same-module ``def abs``/``min``/``max`` sibling is the sibling
function — never the pure builtin. Otherwise core silently types/lowers a stale
math/builtin target Python never calls.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rextio.analyzer.project_scanner import analyze_project


def _write(root: Path, contents: str) -> None:
    path = root / "app.py"
    path.write_text(contents, encoding="utf-8")


def _status(root: Path, qualname: str) -> str:
    analysis = analyze_project(root, native_marker="decorator")
    accepted = {f.qualname for f in analysis.accepted_native_functions}
    if qualname in accepted:
        return "accepted"
    return "rejected-or-absent"


# An import shadowed by a later project def/class/assignment/del must NOT resolve
# to the stale import; the reference resolves to the (unresolvable) project name
# and the function fails closed rather than lowering a math call.
_SHADOWED_IMPORT = {
    "def_shadows_import": (
        "import rextio\nfrom math import sin\n\n"
        "def sin(x: float) -> float:\n    return x + 1.0\n\n"
        "@rextio.native\ndef udf(x: float) -> float:\n    return sin(x)\n"
    ),
    "class_shadows_import": (
        "import rextio\nfrom math import sin\n\n"
        "class sin:\n    pass\n\n"
        "@rextio.native\ndef udf(x: float) -> float:\n    return sin(x)\n"
    ),
    "assign_shadows_import": (
        "import rextio\nfrom math import sin\n\nsin = 5\n\n"
        "@rextio.native\ndef udf(x: float) -> float:\n    return sin(x)\n"
    ),
    "del_shadows_import": (
        "import rextio\nfrom math import sin\n\ndel sin\n\n"
        "@rextio.native\ndef udf(x: float) -> float:\n    return sin(x)\n"
    ),
}


@pytest.mark.parametrize("case", sorted(_SHADOWED_IMPORT))
def test_shadowed_import_does_not_resolve_to_stale_math(tmp_path: Path, case: str) -> None:
    _write(tmp_path, _SHADOWED_IMPORT[case])
    # `sin` is a project def -> a sibling call (accepted); anything else (class,
    # assignment, del) leaves it unresolved so `udf` fails closed. Either way it is
    # NEVER the stale math.sin, which would be accepted as a native math call.
    analysis = analyze_project(tmp_path, native_marker="decorator")
    accepted = {f.qualname for f in analysis.accepted_native_functions}
    if case == "def_shadows_import":
        assert "app.udf" in accepted  # resolves to the sibling def, still native
    else:
        assert "app.udf" not in accepted  # class/assign/del -> fail closed


def test_def_then_restoring_import_resolves_final_import(tmp_path: Path) -> None:
    # A later `from math import sin` overrides an earlier `def sin`: the final
    # binding is the import, so the math call is used and `udf` is accepted.
    _write(
        tmp_path,
        "import rextio\n\ndef sin(x: float) -> float:\n    return x + 1.0\n\n"
        "from math import sin\n\n"
        "@rextio.native\ndef udf(x: float) -> float:\n    return sin(x)\n",
    )
    assert _status(tmp_path, "app.udf") == "accepted"


def test_same_module_sibling_abs_is_the_sibling(tmp_path: Path) -> None:
    # `def abs` shadows the builtin for the whole module: `udf` calls the sibling,
    # so it stays native (typed by the sibling's return), never the builtin abs.
    _write(
        tmp_path,
        "import rextio\n\n"
        "@rextio.native\ndef abs(x: int) -> int:\n    return x + 100\n\n"
        "@rextio.native\ndef udf(x: int) -> int:\n    return abs(x)\n",
    )
    accepted = {
        f.qualname
        for f in analyze_project(tmp_path, native_marker="decorator").accepted_native_functions
    }
    assert {"app.abs", "app.udf"} <= accepted


def test_unshadowed_math_and_builtin_still_native(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "import rextio\nimport math\n\n"
        "@rextio.native\ndef a(x: float) -> float:\n    return math.sin(x)\n\n"
        "@rextio.native\ndef b(x: int) -> int:\n    return abs(x)\n",
    )
    accepted = {
        f.qualname
        for f in analyze_project(tmp_path, native_marker="decorator").accepted_native_functions
    }
    assert {"app.a", "app.b"} <= accepted
