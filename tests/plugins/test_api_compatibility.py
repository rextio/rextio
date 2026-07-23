"""Plugin API 1.1/1.2 source- and serialization-compatibility under 1.3 (WP-4).

The 1.3 metadata surfaces (receiver / callable / schema) are all optional and
defaulted, so a claim site, plugin claim, plugin type, or lowering context
built with only legacy fields keeps its EXACT pre-1.3 byte-shape, and providers
below api_version 1.3 never observe the new metadata.
"""

from __future__ import annotations

from rextio.analyzer.models import PluginClaim
from rextio.plugins.api import (
    PLUGIN_API_VERSION,
    BoundaryConversion,
    ClaimLiteral,
    ClaimSite,
    KeywordArg,
    LoweringContext,
    PluginType,
    ReceiverMeta,
)


def test_plugin_api_version_is_16() -> None:
    assert PLUGIN_API_VERSION == "1.6"


def test_legacy_claim_site_to_dict_shape_unchanged() -> None:
    # A 1.1 site (no literals/keywords/expression/receiver/callables) keeps the
    # exact legacy keys — no receiver/callables leak in.
    site = ClaimSite(
        kind="call",
        target="numpy.dot",
        operand_types=("rextio-numpy/f64-1d", "rextio-numpy/f64-1d"),
        file_path="",
        line=0,
        column=0,
    )
    assert site.to_dict() == {
        "kind": "call",
        "target": "numpy.dot",
        "operand_types": ["rextio-numpy/f64-1d", "rextio-numpy/f64-1d"],
        "file_path": "",
        "line": 0,
        "column": 0,
    }


def test_12_claim_site_to_dict_shape_unchanged() -> None:
    # A 1.2 site with literal/keyword metadata but no 1.3 fields keeps its shape.
    site = ClaimSite(
        kind="call",
        target="numpy.sum",
        operand_types=("rextio-numpy/f64-1d",),
        file_path="",
        line=0,
        column=0,
        operand_literals=(ClaimLiteral(is_literal=True, value=0),),
        keywords=(KeywordArg(name="axis", arg_type="int", literal=ClaimLiteral(True, 0)),),
    )
    data = site.to_dict()
    assert "receiver" not in data
    assert "callables" not in data
    assert data["operand_literals"] == [{"is_literal": True, "value_kind": "int", "value": 0}]


def test_legacy_plugin_claim_to_dict_shape_unchanged() -> None:
    claim = PluginClaim(
        plugin_id="rextio-numpy",
        rule_id="rextio-numpy/dot-float64",
        kind="call",
        target="numpy.dot",
        line=3,
        column=11,
        result_type="float",
        operand_types=("rextio-numpy/f64-1d", "rextio-numpy/f64-1d"),
        end_line=3,
        end_column=25,
    )
    data = claim.to_dict()
    # No 1.3 keys appear on a legacy claim.
    assert "receiver" not in data
    assert "callables" not in data
    assert data["result_type"] == "float"


def test_plugin_claim_carries_1_3_metadata_when_present() -> None:
    claim = PluginClaim(
        plugin_id="rextio-frame",
        rule_id="rextio-frame/total",
        kind="call",
        target="df.total",
        line=3,
        column=11,
        result_type="int",
        receiver=ReceiverMeta(arg_type="rextio-frame/frame", expr_kind="name", is_safe=True),
    )
    data = claim.to_dict()
    assert data["receiver"] == {
        "arg_type": "rextio-frame/frame",
        "expr_kind": "name",
        "is_safe": True,
        "schema": None,
    }


def test_materialized_plugin_type_serialization_unchanged() -> None:
    # A materialized (1.1/1.2) plugin type keeps its exact legacy byte-shape:
    # no ``resident`` key and a concrete conversion dict.
    plugin_type = PluginType(
        key="rextio-numpy/f64-1d",
        annotations=("rextio_numpy.types.F64Arr1",),
        rust_type="ndarray::Array1<f64>",
        conversion=BoundaryConversion(
            param_rust="numpy::PyReadonlyArray1<'py, f64>",
            param_expr="{param}.as_array().to_owned()",
            return_rust="pyo3::Bound<'py, numpy::PyArray1<f64>>",
            return_expr="numpy::ToPyArray::to_pyarray(&{value}, py)",
        ),
    )
    data = plugin_type.to_dict()
    assert "resident" not in data
    assert "device_value_metadata" not in data
    assert data["conversion"]["param_rust"] == "numpy::PyReadonlyArray1<'py, f64>"


def test_lowering_context_receiver_defaults_none() -> None:
    ctx = LoweringContext(operands=("a", "b"), target_language="rust", fresh_name=lambda p: p)
    assert ctx.receiver is None
    assert ctx.leaf_operands == ()
    assert ctx.device_authorization is None
