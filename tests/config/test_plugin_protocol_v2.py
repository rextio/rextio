from __future__ import annotations

from typing import Any

import pytest

from rextio.config.schema import EmbeddingConfig, PluginConfig, RextioConfig
from rextio.plugins.api import CoverageDecl, RuleRecord, RuleScope
from rextio.plugins.loader import PluginError, load_plugin_registry
from rextio.plugins.models import RextioPlugin
from rextio.targets.models import TargetSpec


class FakeEntryPoint:
    def __init__(self, name: str, payload: Any) -> None:
        self.name = name
        self._payload = payload

    def load(self) -> Any:
        return self._payload


def make_record(
    rule_id: str = "rextio-numpy/elementwise-float64",
    diagnostic_code: str | None = "RXTP-NUMPY-001",
    provider: str = "unset",
) -> RuleRecord:
    return RuleRecord(
        id=rule_id,
        provider=provider,
        scope=RuleScope(kind="call", pattern="numpy elementwise op on float64 arrays"),
        constraint="Only supported ndarray dtypes/shapes lower.",
        outcome="fallback",
        diagnostic_code=diagnostic_code,
        guidance="Use float64 arrays with supported operations.",
    )


class FakeV2Plugin:
    plugin_id = "rextio-numpy"
    api_version = "1.0"

    def __init__(
        self,
        records: tuple[RuleRecord, ...] | None = None,
        coverage: CoverageDecl | Any = None,
    ) -> None:
        self._records = records if records is not None else (make_record(),)
        self._coverage = coverage if coverage is not None else CoverageDecl(packages=("numpy",))
        self.described_with: RextioConfig | None = None

    def to_rextio_plugin(self) -> RextioPlugin:
        return RextioPlugin(id="rextio-numpy", name="NumPy to Rust")

    def covers(self) -> Any:
        return self._coverage

    def describe(self, config: RextioConfig) -> tuple[RuleRecord, ...]:
        self.described_with = config
        return self._records


def load_v2(plugin: Any, enabled: tuple[str, ...] = ("rextio-numpy",), **kwargs: Any):
    return load_plugin_registry(
        PluginConfig(enabled=enabled),
        TargetSpec(),
        entry_points=(FakeEntryPoint("rextio-numpy", plugin),),
        **kwargs,
    )


def test_v2_plugin_provides_rules_and_coverage() -> None:
    registry = load_v2(FakeV2Plugin())

    plugin = registry.active[0]
    assert plugin.rules_provided is True
    assert plugin.api_version == "1.0"
    assert plugin.packages == ("numpy",)  # merged from coverage
    assert [record.id for record in registry.rule_records] == [
        "rextio-numpy/elementwise-float64"
    ]
    # The loader stamps the provider with the plugin id regardless of input.
    assert registry.rule_records[0].provider == "rextio-numpy"
    assert registry.coverages[0].plugin_id == "rextio-numpy"
    assert registry.coverages[0].coverage.packages == ("numpy",)


def test_v2_describe_receives_full_config() -> None:
    provider = FakeV2Plugin()
    config = RextioConfig(embedding=EmbeddingConfig(enabled=True))
    load_v2(provider, full_config=config)
    assert provider.described_with is config


def test_v2_inactive_plugin_is_not_described() -> None:
    provider = FakeV2Plugin()
    registry = load_v2(provider, enabled=())
    assert provider.described_with is None
    assert registry.rule_records == ()
    assert registry.active == ()


def test_v1_plugin_keeps_loading_without_rules() -> None:
    registry = load_plugin_registry(
        PluginConfig(enabled=("plain",)),
        TargetSpec(),
        entry_points=(FakeEntryPoint("plain", {"target_language": "rust"}),),
    )
    assert registry.active[0].rules_provided is False
    assert registry.rule_records == ()


def test_v2_rejects_mismatched_plugin_id() -> None:
    plugin = FakeV2Plugin()
    plugin.plugin_id = "rextio-other"
    with pytest.raises(PluginError, match="mismatched plugin_id"):
        load_v2(plugin)


@pytest.mark.parametrize("api_version", ["2.0", "", None])
def test_v2_rejects_incompatible_api_version(api_version: str | None) -> None:
    plugin = FakeV2Plugin()
    plugin.api_version = api_version
    with pytest.raises(PluginError, match="api_version|plugin-API"):
        load_v2(plugin)


def test_v2_rejects_foreign_rule_id_namespace() -> None:
    plugin = FakeV2Plugin(records=(make_record(rule_id="core/sneaky"),))
    with pytest.raises(PluginError, match="must be namespaced"):
        load_v2(plugin)


@pytest.mark.parametrize("code", ["RXT091", "RXTP-numpy-001", "RXTP-NUMPY-1"])
def test_v2_rejects_malformed_diagnostic_codes(code: str) -> None:
    plugin = FakeV2Plugin(records=(make_record(diagnostic_code=code),))
    with pytest.raises(PluginError, match="must match RXTP-NUMPY-NNN"):
        load_v2(plugin)


def test_v2_rejects_wrong_plugin_code_segment() -> None:
    plugin = FakeV2Plugin(records=(make_record(diagnostic_code="RXTP-PANDAS-001"),))
    with pytest.raises(PluginError, match="plugin segment 'NUMPY'"):
        load_v2(plugin)


def test_v2_allows_silent_rules_without_codes() -> None:
    plugin = FakeV2Plugin(records=(make_record(diagnostic_code=None),))
    registry = load_v2(plugin)
    assert registry.rule_records[0].diagnostic_code is None


def test_v2_rejects_non_rule_record_entries() -> None:
    plugin = FakeV2Plugin(records=({"id": "rextio-numpy/x"},))  # type: ignore[arg-type]
    with pytest.raises(PluginError, match="must yield RuleRecord"):
        load_v2(plugin)


def test_v2_rejects_missing_covers() -> None:
    plugin = FakeV2Plugin()
    plugin.covers = None  # type: ignore[assignment]
    with pytest.raises(PluginError, match="no covers"):
        load_v2(plugin)


def test_v2_rejects_non_coverage_covers() -> None:
    plugin = FakeV2Plugin(coverage={"packages": ["numpy"]})
    with pytest.raises(PluginError, match="must return a CoverageDecl"):
        load_v2(plugin)


def test_v2_describe_exception_is_wrapped() -> None:
    class Exploding(FakeV2Plugin):
        def describe(self, config: RextioConfig) -> tuple[RuleRecord, ...]:
            raise RuntimeError("boom")

    with pytest.raises(PluginError, match="describe\\(\\) failed: boom"):
        load_v2(Exploding())
