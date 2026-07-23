from __future__ import annotations

import ast
from pathlib import Path

import pytest

from rextio.analyzer.models import FunctionAnalysis, ProjectAnalysis
from rextio.analyzer.plugin_claims import ClaimEngine
from rextio.analyzer.project_scanner import analyze_project
from rextio.codegen.rust.generator import RustCodegenError, generate_rust_module
from rextio.config.schema import RextioConfig
from rextio.ir.lowering import PluginTypeMaps, lower_project
from rextio.ir.nodes import CallIR, CompareIR, ReturnIR
from rextio.ir.types import RxtPluginType
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


PLUGIN_ID = "rextio-array"
F64_KEY = f"{PLUGIN_ID}/f64-1d"
BOOL_KEY = f"{PLUGIN_ID}/bool-1d"

F64_TYPE = PluginType(
    key=F64_KEY,
    annotations=("rextio_array.types.F64Arr1",),
    rust_type="ndarray::Array1<f64>",
    conversion=BoundaryConversion(
        param_rust="numpy::PyReadonlyArray1<'py, f64>",
        param_expr="{param}.as_array().to_owned()",
        return_rust="pyo3::Bound<'py, numpy::PyArray1<f64>>",
        return_expr="numpy::ToPyArray::to_pyarray(&{value}, py)",
    ),
)
BOOL_TYPE = PluginType(
    key=BOOL_KEY,
    # API 1.5 result-only resident vocabulary: produced by the comparison and
    # consumed by `where`, but deliberately impossible to spell in source.
    annotations=(),
    rust_type="ndarray::Array1<bool>",
    conversion=None,
)

F64_IR = RxtPluginType(
    key=F64_KEY,
    native_rust=F64_TYPE.rust_type,
    param_rust=F64_TYPE.conversion.param_rust if F64_TYPE.conversion is not None else None,
    param_expr=F64_TYPE.conversion.param_expr if F64_TYPE.conversion is not None else None,
    return_rust=F64_TYPE.conversion.return_rust if F64_TYPE.conversion is not None else None,
    return_expr=F64_TYPE.conversion.return_expr if F64_TYPE.conversion is not None else None,
)
BOOL_IR = RxtPluginType(
    key=BOOL_KEY,
    native_rust=BOOL_TYPE.rust_type,
    resident=True,
)
TYPE_MAPS = PluginTypeMaps(
    by_key={F64_KEY: F64_IR, BOOL_KEY: BOOL_IR},
    by_spelling={
        "rextio_array.types.F64Arr1": F64_IR,
    },
)


class _CompareWhereProvider:
    plugin_id = PLUGIN_ID
    api_version = "1.5"

    def __init__(self) -> None:
        self.seen: list[ClaimSite] = []

    def claim(self, site: ClaimSite, config: RextioConfig):
        del config
        self.seen.append(site)
        if site.kind == "compare" and site.target == ">":
            if site.operand_types == (F64_KEY, "int"):
                return Claimed(rule_id=f"{PLUGIN_ID}/greater", result_type=BOOL_KEY)
        if site.kind == "call" and site.target == "numpy.where":
            if site.operand_types == (BOOL_KEY, F64_KEY, F64_KEY):
                return Claimed(rule_id=f"{PLUGIN_ID}/where", result_type=F64_KEY)
        return NotCovered()

    def lower(self, site: ClaimSite, ctx: LoweringContext) -> LoweredExpr:
        if site.kind == "compare":
            assert site.operand_types == (F64_KEY, "int")
            return LoweredExpr(
                rust=(
                    f"{ctx.operands[0]}.mapv(|value| "
                    f"value > ({ctx.operands[1]} as f64))"
                )
            )
        if site.kind == "call" and site.target == "numpy.where":
            assert site.operand_types == (BOOL_KEY, F64_KEY, F64_KEY)
            return LoweredExpr(
                rust=(
                    f"ndarray::Zip::from(&{ctx.operands[0]})"
                    f".and(&{ctx.operands[1]}).and(&{ctx.operands[2]})"
                    ".map_collect(|mask, yes, no| if *mask { *yes } else { *no })"
                )
            )
        raise AssertionError(f"unexpected site: {site}")


class _LegacyProvider(_CompareWhereProvider):
    api_version = "1.4"


def _registry(provider: object) -> PluginRegistry:
    plugin = RextioPlugin(
        id=PLUGIN_ID,
        name=PLUGIN_ID,
        packages=("numpy",),
        rules_provided=True,
        api_version=getattr(provider, "api_version", "1.5"),
        lowering_provided=True,
    )
    return PluginRegistry(
        enabled=(PLUGIN_ID,),
        discovered=(plugin,),
        active=(plugin,),
        types=(
            PluginTypeBinding(plugin_id=PLUGIN_ID, plugin_type=F64_TYPE),
            PluginTypeBinding(plugin_id=PLUGIN_ID, plugin_type=BOOL_TYPE),
        ),
        providers=(PluginProviderBinding(plugin_id=PLUGIN_ID, provider=provider),),
    )


def _write_module(root: Path) -> None:
    path = root / "src" / "myapp" / "kernels.py"
    path.parent.mkdir(parents=True)
    path.write_text(
        """
import numpy as np
from rextio_array.types import F64Arr1

def choose_positive(a: F64Arr1, fallback: F64Arr1) -> F64Arr1:
    return np.where(a > 0, a, fallback)
""",
        encoding="utf-8",
    )


def _function(analysis: ProjectAnalysis) -> FunctionAnalysis:
    return next(
        function
        for module in analysis.modules
        for function in module.functions
        if function.qualname == "myapp.kernels.choose_positive"
    )


def test_compare_result_type_flows_into_a_later_plugin_call(tmp_path: Path) -> None:
    provider = _CompareWhereProvider()
    _write_module(tmp_path)

    analysis = analyze_project(
        tmp_path,
        plugin_registry=_registry(provider),
        plugin_config=RextioConfig(),
    )
    function = _function(analysis)

    assert function.accepted is True
    assert [(claim.kind, claim.target, claim.result_type) for claim in function.plugin_claims] == [
        ("compare", ">", BOOL_KEY),
        ("call", "numpy.where", F64_KEY),
    ]
    where_claim = function.plugin_claims[1]
    assert where_claim.operand_types == (BOOL_KEY, F64_KEY, F64_KEY)
    serialized_claims = function.to_dict()["plugin_claims"]
    assert any(claim["kind"] == "compare" for claim in serialized_claims)


def test_result_only_compare_type_cannot_be_forged_by_source_annotation() -> None:
    engine = ClaimEngine(_registry(_CompareWhereProvider()), RextioConfig())
    direct = ast.parse("rextio_array.types.BoolArr1", mode="eval").body
    imported = ast.parse("BoolArr1", mode="eval").body

    assert engine.resolve_annotation(direct, {}) is None
    assert engine.resolve_annotation(
        imported,
        {"BoolArr1": "rextio_array.types.BoolArr1"},
    ) is None
    assert engine.is_plugin_type(BOOL_KEY) is True
    assert engine.is_resident_type(BOOL_KEY) is True


def test_compare_claim_reaches_ir_and_plugin_lowering_with_direct_operands(
    tmp_path: Path,
) -> None:
    provider = _CompareWhereProvider()
    _write_module(tmp_path)
    analysis = analyze_project(
        tmp_path,
        plugin_registry=_registry(provider),
        plugin_config=RextioConfig(),
    )

    module_ir = lower_project(analysis, plugin_types=TYPE_MAPS)
    statement = module_ir.functions[0].body.statements[0]
    assert isinstance(statement, ReturnIR)
    assert isinstance(statement.value, CallIR)
    compare = statement.value.args[0]
    assert isinstance(compare, CompareIR)
    assert compare.claim is not None
    assert compare.claim.kind == "compare"

    source = generate_rust_module(
        module_ir,
        plugin_providers={PLUGIN_ID: provider},
        plugin_types_by_key={F64_KEY: F64_IR, BOOL_KEY: BOOL_IR},
    )
    assert ".mapv(|value| value > (" in source
    assert "ndarray::Zip::from(&" in source


@pytest.mark.parametrize("drifted_api", ["1.4", "malformed"])
def test_codegen_rejects_stale_compare_ir_for_non_15_provider(
    tmp_path: Path,
    drifted_api: str,
) -> None:
    provider = _CompareWhereProvider()
    _write_module(tmp_path)
    analysis = analyze_project(
        tmp_path,
        plugin_registry=_registry(provider),
        plugin_config=RextioConfig(),
    )
    module_ir = lower_project(analysis, plugin_types=TYPE_MAPS)
    provider.api_version = drifted_api

    with pytest.raises(
        RustCodegenError,
        match="compare lowering requires api_version >= 1.5",
    ):
        generate_rust_module(
            module_ir,
            plugin_providers={PLUGIN_ID: provider},
            plugin_types_by_key={F64_KEY: F64_IR, BOOL_KEY: BOOL_IR},
        )


def test_pre_15_provider_is_never_offered_a_compare_site(tmp_path: Path) -> None:
    provider = _LegacyProvider()
    _write_module(tmp_path)

    analysis = analyze_project(
        tmp_path,
        plugin_registry=_registry(provider),
        plugin_config=RextioConfig(),
    )
    function = _function(analysis)

    assert function.accepted is False
    assert not any(site.kind == "compare" for site in provider.seen)
    assert not any(claim.kind == "compare" for claim in function.plugin_claims)
