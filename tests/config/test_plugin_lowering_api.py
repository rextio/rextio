from __future__ import annotations

from typing import Any

import pytest

from rextio.analyzer.diagnostics import Diagnostic
from rextio.config.schema import PluginConfig, RextioConfig
from rextio.plugins.api import (
    BoundaryConversion,
    Claimed,
    ClaimSite,
    CoverageDecl,
    CrateDependency,
    LoweredExpr,
    NotCovered,
    PluginType,
    Rejected,
    RuleRecord,
    RuleScope,
)
from rextio.plugins.loader import PluginError, load_plugin_registry
from rextio.plugins.models import RextioPlugin
from rextio.targets.models import TargetSpec


class FakeEntryPoint:
    def __init__(self, name: str, payload: Any) -> None:
        self.name = name
        self._payload = payload

    def load(self) -> Any:
        return self._payload


F64_ARR1 = PluginType(
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

NDARRAY_DEP = CrateDependency(name="ndarray", version="=0.16.1")


def make_rule(rule_id: str = "rextio-numpy/dot-float64") -> RuleRecord:
    return RuleRecord(
        id=rule_id,
        provider="rextio-numpy",
        scope=RuleScope(kind="call", pattern="numpy.dot on float64 1-D arrays"),
        constraint="c",
        outcome="native",
        diagnostic_code="RXTP-NUMPY-002",
        guidance="g",
        stability="experimental",
    )


class LoweringPlugin:
    plugin_id = "rextio-numpy"
    api_version = "1.1"

    def to_rextio_plugin(self) -> RextioPlugin:
        return RextioPlugin(id="rextio-numpy", name="NumPy to Rust")

    def covers(self) -> CoverageDecl:
        return CoverageDecl(packages=("numpy",))

    def describe(self, config: RextioConfig) -> tuple[RuleRecord, ...]:
        return (make_rule(),)

    def type_vocabulary(self) -> tuple[PluginType, ...]:
        return (F64_ARR1,)

    def claim(self, site: ClaimSite, config: RextioConfig):
        return Claimed(rule_id="rextio-numpy/dot-float64")

    def lower(self, claimed: ClaimSite, ctx: object) -> LoweredExpr:
        return LoweredExpr(rust="a.dot(&b)")

    def crate_dependencies(self) -> tuple[CrateDependency, ...]:
        return (NDARRAY_DEP,)


def load(*payloads: tuple[str, Any], enabled: tuple[str, ...] = ("rextio-numpy",)):
    return load_plugin_registry(
        PluginConfig(enabled=enabled),
        TargetSpec(),
        entry_points=tuple(FakeEntryPoint(name, payload) for name, payload in payloads),
    )


def test_lowering_plugin_loads_with_types_crates_and_provider() -> None:
    provider = LoweringPlugin()
    registry = load(("rextio-numpy", provider))

    plugin = registry.active[0]
    assert plugin.lowering_provided is True
    assert plugin.rules_provided is True
    assert [binding.plugin_type.key for binding in registry.types] == ["rextio-numpy/f64-1d"]
    assert registry.crate_dependencies[0].plugin_id == "rextio-numpy"
    assert registry.crate_dependencies[0].dependency == NDARRAY_DEP
    assert registry.providers[0].plugin_id == "rextio-numpy"
    assert registry.providers[0].provider is provider


def test_describe_only_plugin_has_no_lowering_surfaces() -> None:
    class DescribeOnly(LoweringPlugin):
        type_vocabulary = None  # type: ignore[assignment]
        claim = None  # type: ignore[assignment]
        lower = None  # type: ignore[assignment]
        crate_dependencies = None  # type: ignore[assignment]

    registry = load(("rextio-numpy", DescribeOnly()))
    assert registry.active[0].lowering_provided is False
    assert registry.types == ()
    assert registry.crate_dependencies == ()
    assert registry.providers == ()


@pytest.mark.parametrize("missing", ["claim", "lower", "type_vocabulary", "crate_dependencies"])
def test_partial_lowering_members_fail_load(missing: str) -> None:
    plugin = LoweringPlugin()
    setattr(plugin, missing, None)
    with pytest.raises(PluginError, match="arrive together"):
        load(("rextio-numpy", plugin))


def test_lowering_without_describe_fails_load() -> None:
    class NoDescribe:
        def claim(self, site: ClaimSite, config: RextioConfig):
            return NotCovered()

        def lower(self, claimed: ClaimSite, ctx: object) -> LoweredExpr:
            return LoweredExpr(rust="x")

    with pytest.raises(PluginError, match="lowering requires protocol v2"):
        load(("broken", NoDescribe()), enabled=())


def test_inactive_lowering_plugin_contributes_nothing() -> None:
    registry = load(("rextio-numpy", LoweringPlugin()), enabled=())
    assert registry.types == ()
    assert registry.crate_dependencies == ()
    assert registry.providers == ()


def test_type_key_must_be_plugin_namespaced() -> None:
    class BadKey(LoweringPlugin):
        def type_vocabulary(self) -> tuple[PluginType, ...]:
            return (
                PluginType(
                    key="core/f64-1d",
                    annotations=("rextio_numpy.types.F64Arr1",),
                    rust_type="ndarray::Array1<f64>",
                    conversion=F64_ARR1.conversion,
                ),
            )

    with pytest.raises(PluginError, match="must be namespaced 'rextio-numpy/'"):
        load(("rextio-numpy", BadKey()))


def test_type_without_annotations_fails_load() -> None:
    class NoSpelling(LoweringPlugin):
        def type_vocabulary(self) -> tuple[PluginType, ...]:
            return (
                PluginType(
                    key="rextio-numpy/f64-1d",
                    annotations=(),
                    rust_type="ndarray::Array1<f64>",
                    conversion=F64_ARR1.conversion,
                ),
            )

    with pytest.raises(PluginError, match="no annotation spellings"):
        load(("rextio-numpy", NoSpelling()))


def test_annotation_collision_across_plugins_fails_load() -> None:
    class OtherPlugin(LoweringPlugin):
        plugin_id = "rextio-other"

        def to_rextio_plugin(self) -> RextioPlugin:
            return RextioPlugin(id="rextio-other", name="Other")

        def describe(self, config: RextioConfig) -> tuple[RuleRecord, ...]:
            return ()

        def type_vocabulary(self) -> tuple[PluginType, ...]:
            return (
                PluginType(
                    key="rextio-other/f64-1d",
                    annotations=("rextio_numpy.types.F64Arr1",),  # collides
                    rust_type="ndarray::Array1<f64>",
                    conversion=F64_ARR1.conversion,
                ),
            )

        def crate_dependencies(self) -> tuple[CrateDependency, ...]:
            return ()

    with pytest.raises(PluginError, match="claimed by both"):
        load(
            ("rextio-numpy", LoweringPlugin()),
            ("rextio-other", OtherPlugin()),
            enabled=("rextio-numpy", "rextio-other"),
        )


def test_crate_pin_conflict_across_plugins_fails_load() -> None:
    class OtherPlugin(LoweringPlugin):
        plugin_id = "rextio-other"

        def to_rextio_plugin(self) -> RextioPlugin:
            return RextioPlugin(id="rextio-other", name="Other")

        def describe(self, config: RextioConfig) -> tuple[RuleRecord, ...]:
            return ()

        def type_vocabulary(self) -> tuple[PluginType, ...]:
            return ()

        def crate_dependencies(self) -> tuple[CrateDependency, ...]:
            return (CrateDependency(name="ndarray", version="=0.15.6"),)

    with pytest.raises(PluginError, match="pinned to =0.16.1 .* but to =0.15.6"):
        load(
            ("rextio-numpy", LoweringPlugin()),
            ("rextio-other", OtherPlugin()),
            enabled=("rextio-numpy", "rextio-other"),
        )


def test_matching_crate_pins_across_plugins_are_allowed() -> None:
    class OtherPlugin(LoweringPlugin):
        plugin_id = "rextio-other"

        def to_rextio_plugin(self) -> RextioPlugin:
            return RextioPlugin(id="rextio-other", name="Other")

        def describe(self, config: RextioConfig) -> tuple[RuleRecord, ...]:
            return ()

        def type_vocabulary(self) -> tuple[PluginType, ...]:
            return ()

    registry = load(
        ("rextio-numpy", LoweringPlugin()),
        ("rextio-other", OtherPlugin()),
        enabled=("rextio-numpy", "rextio-other"),
    )
    assert len(registry.crate_dependencies) == 2


@pytest.mark.parametrize("version", ["0.16.1", ">=0.16", "=0.16", "^0.16.1", ""])
def test_crate_dependency_requires_exact_pin(version: str) -> None:
    with pytest.raises(ValueError, match="exact version pin"):
        CrateDependency(name="ndarray", version=version)


def test_claim_results_are_distinct_types() -> None:
    assert Claimed(rule_id="rextio-numpy/x") != NotCovered()
    rejected = Rejected(
        diagnostic=Diagnostic(
            code="RXTP-NUMPY-010",
            severity="error",
            message="unsupported dtype",
            file_path="src/x.py",
            line=1,
            column=0,
        )
    )
    assert rejected.diagnostic.code == "RXTP-NUMPY-010"


def test_registry_to_dict_serializes_lowering_surfaces_without_providers() -> None:
    registry = load(("rextio-numpy", LoweringPlugin()))
    data = registry.to_dict()
    assert data["types"][0]["type"]["key"] == "rextio-numpy/f64-1d"
    assert data["crate_dependencies"] == [
        {"plugin_id": "rextio-numpy", "name": "ndarray", "version": "=0.16.1", "features": []}
    ]
    assert "providers" not in data


def test_lowering_members_require_api_1_1() -> None:
    # Council round-2 R5: a plugin declaring api_version 1.0 must not expose
    # the 1.1 lowering members.
    plugin = LoweringPlugin()
    plugin.api_version = "1.0"
    with pytest.raises(PluginError, match="requires api_version >= 1.1"):
        load(("rextio-numpy", plugin))


def test_duplicate_annotation_spelling_within_one_plugin_fails_load() -> None:
    # Council round-2 R14: cross-plugin collisions were caught, same-plugin
    # duplicates silently resolved first-wins.
    class DupSpelling(LoweringPlugin):
        def type_vocabulary(self) -> tuple[PluginType, ...]:
            second = PluginType(
                key="rextio-numpy/f64-other",
                annotations=("rextio_numpy.types.F64Arr1",),
                rust_type="ndarray::Array1<f64>",
                conversion=F64_ARR1.conversion,
            )
            return (F64_ARR1, second)

    with pytest.raises(PluginError, match="declares annotation .* on both"):
        load(("rextio-numpy", DupSpelling()))
