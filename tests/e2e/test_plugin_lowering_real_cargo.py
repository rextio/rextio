from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

from rextio.cli.main import main
from rextio.config.schema import RextioConfig
from rextio.plugins.api import (
    BoundaryConversion,
    Claimed,
    ClaimSite,
    CoverageDecl,
    LoweredExpr,
    NotCovered,
    PluginType,
    RuleRecord,
    RuleScope,
)
from rextio.plugins.models import RextioPlugin

np = pytest.importorskip("numpy")

F64_ARR1 = PluginType(
    key="rextio-numpy/f64-1d",
    annotations=("rextio_numpy_types.F64Arr1",),
    rust_type="ndarray::Array1<f64>",
    conversion=BoundaryConversion(
        param_rust="numpy::PyReadonlyArray1<'py, f64>",
        param_expr="{param}.as_array().to_owned()",
        return_rust="pyo3::Bound<'py, numpy::PyArray1<f64>>",
        return_expr="numpy::ToPyArray::to_pyarray(&{value}, py)",
    ),
)


class FakeNumpyLoweringPlugin:
    plugin_id = "rextio-numpy"
    api_version = "1.1"

    def to_rextio_plugin(self) -> RextioPlugin:
        return RextioPlugin(id="rextio-numpy", name="NumPy to Rust (e2e fake)")

    def covers(self) -> CoverageDecl:
        return CoverageDecl(packages=("numpy",))

    def describe(self, config: RextioConfig) -> tuple[RuleRecord, ...]:
        return (
            RuleRecord(
                id="rextio-numpy/dot-float64",
                provider="rextio-numpy",
                scope=RuleScope(kind="call", pattern="numpy.dot on float64 1-D arrays"),
                constraint="float64 1-D dot products lower to ndarray dot.",
                outcome="native",
                diagnostic_code="RXTP-NUMPY-002",
                guidance="Use float64 1-D arrays.",
                stability="experimental",
            ),
        )

    def type_vocabulary(self) -> tuple[PluginType, ...]:
        return (F64_ARR1,)

    def claim(self, site: ClaimSite, config: RextioConfig):
        if site.kind == "call" and site.target == "numpy.dot":
            return Claimed(rule_id="rextio-numpy/dot-float64", result_type="float")
        if site.kind == "binop" and site.target == "+":
            return Claimed(rule_id="rextio-numpy/dot-float64", result_type=F64_ARR1.key)
        return NotCovered()

    def lower(self, site: ClaimSite, ctx) -> LoweredExpr:
        if site.target == "numpy.dot":
            return LoweredExpr(rust=f"{ctx.operands[0]}.dot(&{ctx.operands[1]})")
        if site.target == "+":
            return LoweredExpr(rust=f"(&{ctx.operands[0]} + &{ctx.operands[1]})")
        raise AssertionError(f"unexpected lower target: {site.target}")

    def crate_dependencies(self):
        from rextio.plugins.api import CrateDependency

        return (
            CrateDependency(name="ndarray", version="=0.16.1"),
            CrateDependency(name="numpy", version="=0.29.0"),
        )


class _FakeEntryPoint:
    name = "rextio-numpy"

    def load(self) -> object:
        return FakeNumpyLoweringPlugin()


def test_real_cargo_plugin_lowered_numpy_kernels(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """End-to-end: plugin-lowered NumPy kernels compile with real cargo and run.

    The full pipeline — claim pass, plugin-typed PyO3 conversions, plugin
    lower() emission, pinned crate injection (ndarray + rust-numpy) — through
    ``rextio build`` and a runtime equivalence check against NumPy.
    """
    from rextio.plugins import loader as plugin_loader

    monkeypatch.setattr(plugin_loader, "_plugin_entry_points", lambda _eps: (_FakeEntryPoint(),))

    (tmp_path / "rextio.toml").write_text(
        """
[rust]
build_tool = "cargo"

[plugins]
enabled = ["rextio-numpy"]
""",
        encoding="utf-8",
    )
    # The annotation vocabulary module: plain runtime aliases, so the fallback
    # path and the wrapper signatures work without the plugin installed.
    source_root = tmp_path / "src"
    (source_root / "rextio_numpy_types").mkdir(parents=True)
    (source_root / "rextio_numpy_types" / "__init__.py").write_text(
        "import numpy\n\nF64Arr1 = numpy.ndarray\n", encoding="utf-8"
    )
    app = source_root / "np_app"
    app.mkdir()
    (app / "__init__.py").write_text("", encoding="utf-8")
    (app / "kernels.py").write_text(
        """
import numpy as np
from rextio_numpy_types import F64Arr1

def dot(a: F64Arr1, b: F64Arr1) -> float:
    return np.dot(a, b)

def add(a: F64Arr1, b: F64Arr1) -> F64Arr1:
    return a + b

def scaled_dot(a: F64Arr1, b: F64Arr1, factor: float) -> float:
    return np.dot(a, b) * factor
""",
        encoding="utf-8",
    )

    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])
    capsys.readouterr()
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )
    assert exit_code == 0, report
    assert report["native_build"]["status"] == "built"
    assert report["plugin_crate_dependencies"] == [
        {"plugin_id": "rextio-numpy", "name": "ndarray", "version": "=0.16.1", "features": []},
        {"plugin_id": "rextio-numpy", "name": "numpy", "version": "=0.29.0", "features": []},
    ]
    cargo_toml = (tmp_path / ".rextio" / "generated" / "rust" / "Cargo.toml").read_text(
        encoding="utf-8"
    )
    assert 'ndarray = "=0.16.1"' in cargo_toml
    assert 'numpy = "=0.29.0"' in cargo_toml

    monkeypatch.setenv("REXTIO_NATIVE_MODE", "native")
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    for module_name in ("_rextio_native", "np_app.kernels", "rextio_numpy_types"):
        sys.modules.pop(module_name, None)
    kernels = importlib.import_module("np_app.kernels")

    a = np.array([1.0, 2.0, 3.0])
    b = np.array([4.0, 5.0, 6.0])
    assert kernels.dot(a, b) == np.dot(a, b) == 32.0
    assert kernels.scaled_dot(a, b, 2.0) == np.dot(a, b) * 2.0
    added = kernels.add(a, b)
    assert isinstance(added, np.ndarray)
    np.testing.assert_array_equal(added, a + b)
    # The native module really served these calls (mode=native raises on
    # fallback), and the inputs were not mutated by the read-only borrows.
    np.testing.assert_array_equal(a, np.array([1.0, 2.0, 3.0]))

    for module_name in ("_rextio_native", "np_app.kernels", "rextio_numpy_types", "np_app"):
        sys.modules.pop(module_name, None)
