"""Codegen tests for plugin lowering (docs/specs/plugin-lowering.md, slice 3).

Cargo-free: small sources are analyzed with a fake lowering plugin, lowered to
IR with plugin type maps, and rendered through the Rust generator; assertions
run on the generated source text.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rextio.analyzer.project_scanner import analyze_project
from rextio.codegen.rust.cargo import render_cargo_toml
from rextio.codegen.rust.errors import RustCodegenError
from rextio.codegen.rust.generator import generate_rust_crate_module, generate_rust_module
from rextio.config.schema import RextioConfig
from rextio.ir.lowering import PluginTypeMaps, lower_project
from rextio.ir.types import RxtPluginType
from rextio.plugins.api import (
    BoundaryConversion,
    Claimed,
    ClaimSite,
    CrateDependency,
    LoweredExpr,
    LoweringContext,
    NotCovered,
    PluginType,
)
from rextio.plugins.models import (
    PluginCrateDependency,
    PluginProviderBinding,
    PluginRegistry,
    PluginTypeBinding,
    RextioPlugin,
)

PLUGIN_ID = "rextio-numpy"
F64_KEY = "rextio-numpy/f64-1d"

F64_ARR1 = PluginType(
    key=F64_KEY,
    annotations=("rextio_numpy.types.F64Arr1",),
    rust_type="ndarray::Array1<f64>",
    conversion=BoundaryConversion(
        param_rust="numpy::PyReadonlyArray1<'py, f64>",
        param_expr="{param}.as_array().to_owned()",
        return_rust="pyo3::Bound<'py, numpy::PyArray1<f64>>",
        return_expr="numpy::ToPyArray::to_pyarray(&{value}, py)",
    ),
)

RXT_F64 = RxtPluginType(
    key=F64_KEY,
    native_rust=F64_ARR1.rust_type,
    param_rust=F64_ARR1.conversion.param_rust,
    param_expr=F64_ARR1.conversion.param_expr,
    return_rust=F64_ARR1.conversion.return_rust,
    return_expr=F64_ARR1.conversion.return_expr,
)

TYPE_MAPS = PluginTypeMaps(
    by_key={F64_KEY: RXT_F64},
    by_spelling={"rextio_numpy.types.F64Arr1": RXT_F64},
)

TYPES_BY_KEY = {F64_KEY: RXT_F64}


class NumpyProvider:
    plugin_id = PLUGIN_ID
    api_version = "1.1"

    def claim(self, site: ClaimSite, config: RextioConfig):
        if site.kind == "call" and site.target == "numpy.dot":
            return Claimed(rule_id="rextio-numpy/dot-float64", result_type="float")
        if site.kind == "binop" and site.target == "+":
            return Claimed(rule_id="rextio-numpy/elementwise-float64", result_type=F64_KEY)
        return NotCovered()

    def lower(self, site: ClaimSite, ctx: LoweringContext) -> LoweredExpr:
        if site.kind == "call" and site.target == "numpy.dot":
            return LoweredExpr(
                rust=f"{ctx.operands[0]}.dot(&{ctx.operands[1]})",
                uses=("use ndarray::Array1;",),
            )
        if site.kind == "binop" and site.target == "+":
            return LoweredExpr(rust=f"(&{ctx.operands[0]} + &{ctx.operands[1]})")
        raise AssertionError(f"unexpected lowered site: {site}")


class BrokenLowerProvider(NumpyProvider):
    def lower(self, site: ClaimSite, ctx: LoweringContext) -> LoweredExpr:
        raise RuntimeError("boom")


def make_registry(provider: object) -> PluginRegistry:
    plugin = RextioPlugin(
        id=PLUGIN_ID,
        name=PLUGIN_ID,
        packages=("numpy",),
        rules_provided=True,
        api_version="1.1",
        lowering_provided=True,
    )
    return PluginRegistry(
        enabled=(PLUGIN_ID,),
        discovered=(plugin,),
        active=(plugin,),
        types=(PluginTypeBinding(plugin_id=PLUGIN_ID, plugin_type=F64_ARR1),),
        crate_dependencies=(
            PluginCrateDependency(
                plugin_id=PLUGIN_ID,
                dependency=CrateDependency(name="ndarray", version="=0.16.1"),
            ),
        ),
        providers=(PluginProviderBinding(plugin_id=PLUGIN_ID, provider=provider),),
    )


def write_module(root: Path, contents: str) -> None:
    path = root / "src" / "myapp" / "kernels.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")


def analyze_with_plugin(root: Path, provider: object):
    return analyze_project(
        root, plugin_registry=make_registry(provider), plugin_config=RextioConfig()
    )


DOT_MODULE = """
from rextio_numpy.types import F64Arr1
import numpy as np

def dot(a: F64Arr1, b: F64Arr1) -> float:
    return np.dot(a, b)
"""

ADD_MODULE = """
from rextio_numpy.types import F64Arr1

def add(a: F64Arr1, b: F64Arr1) -> F64Arr1:
    return a + b
"""


def test_claimed_call_lowers_through_plugin(tmp_path: Path) -> None:
    write_module(tmp_path, DOT_MODULE)
    analysis = analyze_with_plugin(tmp_path, NumpyProvider())
    module_ir = lower_project(analysis, plugin_types=TYPE_MAPS)
    assert [function.plugin_lowered for function in module_ir.functions] == [True]

    source = generate_rust_module(
        module_ir,
        plugin_providers={PLUGIN_ID: NumpyProvider()},
        plugin_types_by_key=TYPES_BY_KEY,
    )

    assert "#[pyfunction]" in source
    assert "<'py>" in source
    assert "py: pyo3::Python<'py>" in source
    assert "numpy::PyReadonlyArray1<'py, f64>" in source
    assert "a: numpy::PyReadonlyArray1<'py, f64>" in source
    assert "b: numpy::PyReadonlyArray1<'py, f64>" in source
    assert "let a = a.as_array().to_owned();" in source
    assert "let b = b.as_array().to_owned();" in source
    assert ".dot(&" in source
    assert "use ndarray::Array1;" in source
    assert "-> PyResult<f64>" in source


def test_plugin_typed_return_wraps_through_conversion(tmp_path: Path) -> None:
    write_module(tmp_path, ADD_MODULE)
    analysis = analyze_with_plugin(tmp_path, NumpyProvider())
    module_ir = lower_project(analysis, plugin_types=TYPE_MAPS)

    source = generate_rust_module(
        module_ir,
        plugin_providers={PLUGIN_ID: NumpyProvider()},
        plugin_types_by_key=TYPES_BY_KEY,
    )

    assert "PyResult<pyo3::Bound<'py, numpy::PyArray1<f64>>>" in source
    assert "numpy::ToPyArray::to_pyarray(&" in source
    # The claimed binop lowered through the plugin, not core arithmetic.
    assert "+ &" in source


def test_crate_mode_excludes_plugin_lowered_functions(tmp_path: Path) -> None:
    write_module(tmp_path, DOT_MODULE)
    analysis = analyze_with_plugin(tmp_path, NumpyProvider())
    module_ir = lower_project(analysis, plugin_types=TYPE_MAPS)

    with pytest.raises(RustCodegenError, match="no direct Rust native functions"):
        generate_rust_crate_module(module_ir)


def test_provider_lower_failure_is_a_codegen_error(tmp_path: Path) -> None:
    write_module(tmp_path, DOT_MODULE)
    analysis = analyze_with_plugin(tmp_path, BrokenLowerProvider())
    module_ir = lower_project(analysis, plugin_types=TYPE_MAPS)

    with pytest.raises(RustCodegenError, match="lower\\(\\) failed"):
        generate_rust_module(
            module_ir,
            plugin_providers={PLUGIN_ID: BrokenLowerProvider()},
            plugin_types_by_key=TYPES_BY_KEY,
        )


def test_missing_provider_is_a_codegen_error(tmp_path: Path) -> None:
    write_module(tmp_path, DOT_MODULE)
    analysis = analyze_with_plugin(tmp_path, NumpyProvider())
    module_ir = lower_project(analysis, plugin_types=TYPE_MAPS)

    with pytest.raises(RustCodegenError, match="no active lowering provider"):
        generate_rust_module(module_ir, plugin_types_by_key=TYPES_BY_KEY)


def test_cargo_toml_appends_pinned_plugin_dependencies() -> None:
    rendered = render_cargo_toml(
        extra_dependencies=(
            ("numpy", "=0.27.1", ("half",)),
            ("ndarray", "=0.16.1", ()),
        )
    )

    assert 'ndarray = "=0.16.1"' in rendered
    assert 'numpy = { version = "=0.27.1", features = ["half"] }' in rendered
    # Sorted by name: ndarray before numpy.
    assert rendered.index('ndarray = "=0.16.1"') < rendered.index('numpy = {')
    # The core dependency block is unchanged.
    assert 'pyo3 = { version = "0.29", features = ["extension-module"] }' in rendered


def test_cargo_toml_without_extras_is_unchanged() -> None:
    assert render_cargo_toml() == render_cargo_toml(extra_dependencies=())


def test_plugin_free_module_renders_without_plugin_artifacts(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        """
import rextio

@rextio.native
def square(x: float) -> float:
    return x * x
""",
        encoding="utf-8",
    )
    analysis = analyze_project(tmp_path)
    baseline = generate_rust_module(lower_project(analysis))
    with_plugin_args = generate_rust_module(
        lower_project(analysis, plugin_types=TYPE_MAPS),
        plugin_providers={PLUGIN_ID: NumpyProvider()},
        plugin_types_by_key=TYPES_BY_KEY,
    )

    assert baseline == with_plugin_args
    assert "ndarray" not in baseline
    assert "<'py>" not in baseline

SCALED_DOT_MODULE = """
from rextio_numpy.types import F64Arr1
import numpy as np

def scaled_dot(a: F64Arr1, b: F64Arr1, factor: float) -> float:
    return np.dot(a, b) * factor
"""


def test_claim_matching_distinguishes_nested_call_and_binop(tmp_path: Path) -> None:
    # Regression: `np.dot(a, b) * factor` puts the call and the enclosing
    # binop at the same (line, column). Matching claims on start position
    # alone rendered the float multiply through the plugin's dot lowering
    # (`(...).dot(&factor)`); span+kind matching keeps the multiply core.
    write_module(tmp_path, SCALED_DOT_MODULE)
    analysis = analyze_with_plugin(tmp_path, NumpyProvider())
    module_ir = lower_project(analysis, plugin_types=TYPE_MAPS)

    source = generate_rust_module(
        module_ir,
        plugin_providers={PLUGIN_ID: NumpyProvider()},
        plugin_types_by_key=TYPES_BY_KEY,
    )

    assert ".dot(&b" in source
    assert ") * factor" in source
    assert ".dot(&factor" not in source
