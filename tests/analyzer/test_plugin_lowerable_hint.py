from __future__ import annotations

from pathlib import Path

from rextio.analyzer.models import FunctionAnalysis, ProjectAnalysis
from rextio.analyzer.project_scanner import analyze_project
from rextio.plugins.models import RextioPlugin


NUMBA_NUMPY_MODULE = """
import numba
import numpy as np

@numba.njit
def kernel(x: float) -> float:
    return x * 2.0

def plain(x: float) -> float:
    return x + 1.0
"""


def write_module(root: Path, name: str, contents: str) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")
    return path


def numpy_plugin(*, rules_provided: bool, packages: tuple[str, ...] = ("numpy",)) -> RextioPlugin:
    return RextioPlugin(
        id="rextio-numpy",
        name="NumPy to Rust",
        packages=packages,
        rules_provided=rules_provided,
        api_version="1.0" if rules_provided else None,
    )


def function_named(analysis: ProjectAnalysis, qualname: str) -> FunctionAnalysis:
    for module in analysis.modules:
        for function in module.functions:
            if function.qualname == qualname:
                return function
    raise AssertionError(f"function not found: {qualname}")


def hint_codes(function: FunctionAnalysis) -> list[str]:
    return [d.code for d in function.diagnostics if d.code == "RXT091"]


def test_rxt091_hint_on_covered_accelerated_function(tmp_path: Path) -> None:
    write_module(tmp_path, "src/myapp/mod.py", NUMBA_NUMPY_MODULE)
    analysis = analyze_project(tmp_path, active_plugins=(numpy_plugin(rules_provided=True),))

    kernel = function_named(analysis, "myapp.mod.kernel")
    assert hint_codes(kernel) == ["RXT091"]
    hint = next(d for d in kernel.diagnostics if d.code == "RXT091")
    assert hint.severity == "info"
    assert "rextio-numpy" in hint.message
    # Informational only: the function keeps its accelerator route.
    assert kernel.route == "fallback-accelerated:numba"
    assert kernel.native_status == "not-candidate"

    # Undecorated functions never get the hint.
    assert hint_codes(function_named(analysis, "myapp.mod.plain")) == []


def test_no_hint_without_rule_providing_plugin(tmp_path: Path) -> None:
    write_module(tmp_path, "src/myapp/mod.py", NUMBA_NUMPY_MODULE)
    analysis = analyze_project(tmp_path, active_plugins=(numpy_plugin(rules_provided=False),))
    assert hint_codes(function_named(analysis, "myapp.mod.kernel")) == []


def test_no_hint_when_coverage_does_not_match_imports(tmp_path: Path) -> None:
    write_module(tmp_path, "src/myapp/mod.py", NUMBA_NUMPY_MODULE)
    analysis = analyze_project(
        tmp_path,
        active_plugins=(numpy_plugin(rules_provided=True, packages=("pandas",)),),
    )
    assert hint_codes(function_named(analysis, "myapp.mod.kernel")) == []


def test_no_hint_without_plugins(tmp_path: Path) -> None:
    write_module(tmp_path, "src/myapp/mod.py", NUMBA_NUMPY_MODULE)
    analysis = analyze_project(tmp_path)
    assert hint_codes(function_named(analysis, "myapp.mod.kernel")) == []
