"""Codegen tests for plugin API 1.3 type-level module support (WP-6).

A signature-only accepted function (a plugin-typed parameter/return with zero
plugin claims) renders the plugin type's boundary conversion / named native
type, so the generated module MUST also emit the ``use``/``helper`` support that
DEFINES those symbols. Support is collected from the plugin types that appear
directly in each accepted function's signature, merged into the shared module
collectors, and deduplicated by exact text — including when the same helper also
arrives from a claim's ``LoweredExpr``. An unused registered type emits nothing.

Cargo-free: assertions run on the generated Rust source text with fully
qualified fake support.
"""

from __future__ import annotations

from pathlib import Path

from rextio.analyzer.project_scanner import analyze_project
from rextio.codegen.rust.generator import generate_rust_module
from rextio.config.schema import RextioConfig
from rextio.ir.lowering import PluginTypeMaps, lower_project
from rextio.ir.nodes import BlockIR, FunctionIR, LiteralIR, ModuleIR, ParamIR, ReturnIR
from rextio.ir.types import RxtFloat, RxtInt, RxtPluginType
from rextio.plugins.api import (
    BoundaryConversion,
    Claimed,
    ClaimSite,
    LoweredExpr,
    LoweringContext,
    NotCovered,
    PluginType,
)
from rextio.plugins.models import (
    PluginProviderBinding,
    PluginRegistry,
    PluginTypeBinding,
    RextioPlugin,
)

# --- fake support (distinctive so a match cannot be the ambient pyo3 prelude) --

SERIES_KEY = "rextio-pandas/series-f64"
SERIES_USE = "use pandas_rs::series::SeriesF64;"
SERIES_STRUCT = "pub struct RxtSeriesF64 { data: Vec<f64> }"
SERIES_EXTRACT = "fn __rxtpd_extract_series_f64(v: RxtSeriesF64) -> RxtSeriesF64 { v }"

SERIES = RxtPluginType(
    key=SERIES_KEY,
    native_rust="RxtSeriesF64",
    param_rust="RxtSeriesF64",
    param_expr="__rxtpd_extract_series_f64({param})",
    return_rust="RxtSeriesF64",
    return_expr="{value}",
    uses=(SERIES_USE,),
    helpers=(SERIES_STRUCT, SERIES_EXTRACT),
)

GRAPH_KEY = "rextio-nx/graph"
GRAPH_USE = "use nx_rs::graph::Graph;"
GRAPH_STRUCT = "pub struct RxtNxGraph { nodes: Vec<i64> }"

GRAPH = RxtPluginType(
    key=GRAPH_KEY,
    native_rust="RxtNxGraph",
    resident=True,
    uses=(GRAPH_USE,),
    helpers=(GRAPH_STRUCT,),
)

# A DIFFERENT plugin type whose helper shares a name with SERIES_EXTRACT but
# carries different text — used to prove core keeps both texts visible (the
# collision contract) rather than semantic/name-merging them.
SERIES_EXTRACT_ALT = "fn __rxtpd_extract_series_f64(v: RxtSeriesF64) -> RxtSeriesF64 { v.clone() }"

SERIES_ALT = RxtPluginType(
    key="rextio-pandas/series-f64-alt",
    native_rust="RxtSeriesF64",
    param_rust="RxtSeriesF64",
    param_expr="__rxtpd_extract_series_f64({param})",
    return_rust="RxtSeriesF64",
    return_expr="{value}",
    helpers=(SERIES_EXTRACT_ALT,),
)


def _function(
    name: str,
    params: list[ParamIR],
    return_type: object,
    body: BlockIR,
) -> FunctionIR:
    return FunctionIR(
        name=name,
        qualname=f"myapp.kernels.{name}",
        module_name="myapp.kernels",
        params=params,
        return_type=return_type,  # type: ignore[arg-type]
        body=body,
        plugin_lowered=True,
    )


def test_claimless_materialized_param_emits_support_exactly_once() -> None:
    # `series_probe(value: SeriesF64) -> float` is accepted with ZERO claims;
    # the signature renders the boundary conversion call, so the helper that
    # DEFINES it (and the named struct it references) must now resolve, once.
    probe = _function(
        "series_probe",
        [ParamIR(name="value", type=SERIES)],
        RxtFloat(),
        BlockIR(statements=[ReturnIR(LiteralIR(1.0))]),
    )
    source = generate_rust_module(ModuleIR(functions=[probe]))
    # The conversion call is rendered in the prologue ...
    assert "let value = __rxtpd_extract_series_f64(value);" in source
    # ... and now resolves against emitted, deduplicated support.
    assert source.count(SERIES_EXTRACT) == 1
    assert source.count(SERIES_STRUCT) == 1
    assert source.count(SERIES_USE) == 1


def test_resident_signature_emits_named_struct_support() -> None:
    # A resident type has ``conversion=None`` yet its signature renders the named
    # native type (`&RxtNxGraph`); the struct that defines it comes from the
    # type's helpers, not from any boundary conversion.
    consume = _function(
        "consume",
        [ParamIR(name="g", type=GRAPH)],
        RxtInt(),
        BlockIR(statements=[ReturnIR(LiteralIR(5))]),
    )
    source = generate_rust_module(ModuleIR(functions=[consume]))
    assert "g: &RxtNxGraph" in source
    assert source.count(GRAPH_STRUCT) == 1
    assert source.count(GRAPH_USE) == 1
    # A resident-signature function is internal-only, never #[pyfunction]-wrapped.
    assert "wrap_pyfunction!(myapp__kernels__consume" not in source


def test_unused_registered_type_emits_no_support() -> None:
    # A registered plugin type that appears in NO signature contributes nothing:
    # collection is driven by the signatures, not by the registry.
    pick = FunctionIR(
        name="pick",
        qualname="myapp.kernels.pick",
        module_name="myapp.kernels",
        params=[ParamIR(name="a", type=RxtInt())],
        return_type=RxtInt(),
        body=BlockIR(statements=[ReturnIR(LiteralIR(7))]),
    )
    source = generate_rust_module(
        ModuleIR(functions=[pick]),
        plugin_types_by_key={SERIES_KEY: SERIES, GRAPH_KEY: GRAPH},
    )
    assert SERIES_STRUCT not in source
    assert SERIES_EXTRACT not in source
    assert SERIES_USE not in source
    assert GRAPH_STRUCT not in source
    assert GRAPH_USE not in source


def test_parameter_and_return_reuse_stays_once_and_is_deterministic() -> None:
    # The same materialized type at BOTH the parameter and the return position
    # contributes its support once; the emission order is deterministic.
    roundtrip = _function(
        "roundtrip",
        [ParamIR(name="value", type=SERIES)],
        SERIES,
        BlockIR(statements=[ReturnIR(LiteralIR(1.0))]),
    )
    source = generate_rust_module(ModuleIR(functions=[roundtrip]))
    assert source.count(SERIES_STRUCT) == 1
    assert source.count(SERIES_EXTRACT) == 1
    assert source.count(SERIES_USE) == 1
    # Helpers keep first-seen (tuple) order.
    assert source.index(SERIES_STRUCT) < source.index(SERIES_EXTRACT)
    # Rendering is byte-for-byte stable across runs.
    assert generate_rust_module(ModuleIR(functions=[roundtrip])) == source


def test_return_only_materialized_support_is_collected() -> None:
    # A plugin type that appears ONLY in the return position (no parameter of
    # that type) still contributes its support: the return renders the boundary
    # conversion / named native type, so dropping return-type collection would
    # leave `-> PyResult<RxtSeriesF64>` referencing an undefined struct.
    make = FunctionIR(
        name="make_series",
        qualname="myapp.kernels.make_series",
        module_name="myapp.kernels",
        params=[],
        return_type=SERIES,
        body=BlockIR(statements=[]),
        plugin_lowered=True,
    )
    source = generate_rust_module(ModuleIR(functions=[make]))
    assert "-> PyResult<RxtSeriesF64>" in source
    assert source.count(SERIES_STRUCT) == 1
    assert source.count(SERIES_EXTRACT) == 1
    assert source.count(SERIES_USE) == 1


def test_differing_helper_texts_both_remain_visible() -> None:
    # Two distinct plugin types own a helper with the SAME name but DIFFERENT
    # text. Core deduplicates by exact text only — it must NOT semantic/name-
    # merge — so both texts stay visible and rustc fails loudly on the
    # duplicate definition under the existing collision contract (§3).
    left = _function(
        "left",
        [ParamIR(name="value", type=SERIES)],
        RxtFloat(),
        BlockIR(statements=[ReturnIR(LiteralIR(1.0))]),
    )
    right = _function(
        "right",
        [ParamIR(name="value", type=SERIES_ALT)],
        RxtFloat(),
        BlockIR(statements=[ReturnIR(LiteralIR(2.0))]),
    )
    source = generate_rust_module(ModuleIR(functions=[left, right]))
    assert SERIES_EXTRACT != SERIES_EXTRACT_ALT
    assert source.count(SERIES_EXTRACT) == 1
    assert source.count(SERIES_EXTRACT_ALT) == 1


# --- signature support merges/deduplicates against claim LoweredExpr support ---

PLUGIN_ID = "rextio-pandas"

SERIES_TYPE = PluginType(
    key=SERIES_KEY,
    annotations=("rextio_pandas.types.SeriesF64",),
    rust_type="RxtSeriesF64",
    conversion=BoundaryConversion(
        param_rust="RxtSeriesF64",
        param_expr="__rxtpd_extract_series_f64({param})",
        return_rust="RxtSeriesF64",
        return_expr="{value}",
    ),
    uses=(SERIES_USE,),
    helpers=(SERIES_STRUCT, SERIES_EXTRACT),
)

TYPE_MAPS = PluginTypeMaps(
    by_key={SERIES_KEY: SERIES},
    by_spelling={"rextio_pandas.types.SeriesF64": SERIES},
)


class PandasProvider:
    plugin_id = PLUGIN_ID
    api_version = "1.3"

    def claim(self, site: ClaimSite, config: RextioConfig) -> object:
        if site.kind == "call" and site.target == "rextio_pandas.series_sum":
            return Claimed(rule_id="rextio-pandas/series-sum", result_type="float")
        return NotCovered()

    def lower(self, site: ClaimSite, ctx: LoweringContext) -> LoweredExpr:
        # The claim emits the SAME extract helper the SeriesF64 type owns, so the
        # module sees it from both the signature and this LoweredExpr.
        if site.kind == "call" and site.target == "rextio_pandas.series_sum":
            return LoweredExpr(rust="0.0", helpers=(SERIES_EXTRACT,))
        raise AssertionError(f"unexpected lowered site: {site}")


def _registry(provider: object) -> PluginRegistry:
    plugin = RextioPlugin(
        id=PLUGIN_ID,
        name=PLUGIN_ID,
        packages=("rextio_pandas",),
        rules_provided=True,
        api_version="1.3",
        lowering_provided=True,
    )
    return PluginRegistry(
        enabled=(PLUGIN_ID,),
        discovered=(plugin,),
        active=(plugin,),
        types=(PluginTypeBinding(plugin_id=PLUGIN_ID, plugin_type=SERIES_TYPE),),
        providers=(PluginProviderBinding(plugin_id=PLUGIN_ID, provider=provider),),
    )


SUM_MODULE = """
import rextio_pandas as rextio_pandas
from rextio_pandas.types import SeriesF64


def total(value: SeriesF64) -> float:
    return rextio_pandas.series_sum(value)
"""


def test_signature_and_lowered_support_deduplicate_to_one(tmp_path: Path) -> None:
    path = tmp_path / "src" / "myapp" / "kernels.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(SUM_MODULE, encoding="utf-8")
    analysis = analyze_project(
        tmp_path, plugin_registry=_registry(PandasProvider()), plugin_config=RextioConfig()
    )
    module_ir = lower_project(analysis, plugin_types=TYPE_MAPS)
    source = generate_rust_module(
        module_ir,
        plugin_providers={PLUGIN_ID: PandasProvider()},
        plugin_types_by_key={SERIES_KEY: SERIES},
    )
    # The signature contributes the extract helper AND the claim's LoweredExpr
    # contributes an identical one; the module emits it exactly once.
    assert source.count(SERIES_EXTRACT) == 1
    assert source.count(SERIES_STRUCT) == 1
    assert source.count(SERIES_USE) == 1
    # The signature's boundary conversion still renders.
    assert "let value = __rxtpd_extract_series_f64(value);" in source
