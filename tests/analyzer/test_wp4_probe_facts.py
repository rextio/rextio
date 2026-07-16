"""WP-4 follow-up 4, section 8: accepted analyses retain probe analysis facts.

``validate_native_function`` records ``local_binding_names`` (and declared
schemas) on the probe; the finalized accepted ``FunctionAnalysis`` — on both the
explicit ``@rextio.native`` path and the auto-native path — must copy them so the
facts do not silently disappear (an observability / future re-claim hazard).
"""

from __future__ import annotations

from pathlib import Path

from rextio.analyzer.project_scanner import analyze_project

_KERNEL = """
{marker}def f(xs: list[int]) -> int:
    total = 0
    for y in xs:
        total = total + y
    zs = [w for w in xs]
    return total + len(zs)
"""


def _accepted_f(root: Path, marker: str):
    module = "import rextio\n\n\n" if marker else ""
    (root / "app.py").write_text(module + _KERNEL.format(marker=marker), encoding="utf-8")
    native_marker = "decorator" if marker else "auto"
    analysis = analyze_project(root, native_marker=native_marker)
    accepted = {f.qualname: f for f in analysis.accepted_native_functions}
    assert "app.f" in accepted
    return accepted["app.f"]


def test_explicit_native_retains_local_binding_names(tmp_path: Path) -> None:
    fn = _accepted_f(tmp_path, "@rextio.native\n")
    # Parameters plus every function-scope binding are retained; the comprehension
    # target `w` is intentionally NOT a function-scope binding (Python 3 scoping).
    assert {"xs", "total", "y", "zs"} <= fn.local_binding_names
    assert "w" not in fn.local_binding_names


def test_auto_native_retains_local_binding_names(tmp_path: Path) -> None:
    fn = _accepted_f(tmp_path, "")
    assert {"xs", "total", "y", "zs"} <= fn.local_binding_names
    assert "w" not in fn.local_binding_names
