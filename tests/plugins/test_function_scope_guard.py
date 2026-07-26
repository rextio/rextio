"""Plugin API 1.7: function-scope RAII guard contract (loader + API records)."""

from __future__ import annotations

from typing import Any

import pytest

from rextio.config.schema import PluginConfig, RextioConfig
from rextio.plugins.api import (
    PLUGIN_API_VERSION,
    BoundaryConversion,
    Claimed,
    ClaimSite,
    CoverageDecl,
    CrateDependency,
    LoweredExpr,
    PluginFunctionScopeContext,
    PluginFunctionScopeGuard,
    PluginType,
    RuleRecord,
    RuleScope,
    RextioFunctionScopeGuardPlugin,
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


SCALAR = PluginType(
    key="rextio-demo/scalar",
    annotations=("demo_types.Scalar",),
    rust_type="i64",
    conversion=BoundaryConversion(
        param_rust="i64",
        param_expr="{param}",
        return_rust="i64",
        return_expr="{value}",
    ),
)


def make_rule(rule_id: str = "rextio-demo/double") -> RuleRecord:
    return RuleRecord(
        id=rule_id,
        provider="rextio-demo",
        scope=RuleScope(kind="call", pattern="demo.double"),
        constraint="c",
        outcome="native",
        diagnostic_code="RXTP-DEMO-001",
        guidance="g",
        stability="experimental",
    )


class BaseLoweringPlugin:
    plugin_id = "rextio-demo"
    api_version = "1.6"

    def to_rextio_plugin(self) -> RextioPlugin:
        return RextioPlugin(id="rextio-demo", name="Demo")

    def covers(self) -> CoverageDecl:
        return CoverageDecl(packages=("demo",))

    def describe(self, config: RextioConfig) -> tuple[RuleRecord, ...]:
        return (make_rule(),)

    def type_vocabulary(self) -> tuple[PluginType, ...]:
        return (SCALAR,)

    def claim(self, site: ClaimSite, config: RextioConfig):
        return Claimed(rule_id="rextio-demo/double", result_type="int")

    def lower(self, claimed: ClaimSite, ctx: object) -> LoweredExpr:
        return LoweredExpr(rust="x * 2")

    def crate_dependencies(self) -> tuple[CrateDependency, ...]:
        return ()


class GuardPlugin(BaseLoweringPlugin):
    api_version = "1.7"

    def function_scope_guard(self, ctx: PluginFunctionScopeContext):
        return PluginFunctionScopeGuard(rust="DemoGuard::enter()")


def load(*payloads: tuple[str, Any], enabled: tuple[str, ...] = ("rextio-demo",)):
    return load_plugin_registry(
        PluginConfig(enabled=enabled),
        TargetSpec(),
        entry_points=tuple(FakeEntryPoint(name, payload) for name, payload in payloads),
    )


def test_plugin_api_version_is_17() -> None:
    assert PLUGIN_API_VERSION == "1.7"


def test_api_16_without_hook_loads_and_does_not_declare_scope_guard() -> None:
    registry = load(("rextio-demo", BaseLoweringPlugin()))
    plugin = registry.active[0]
    assert plugin.api_version == "1.6"
    assert plugin.lowering_provided is True
    assert plugin.function_scope_guard_declared is False
    assert plugin.artifact_capability_declared is False


def test_api_16_with_illegal_hook_fails_load() -> None:
    class Illegal(BaseLoweringPlugin):
        api_version = "1.6"

        def function_scope_guard(self, ctx):
            return None

    with pytest.raises(PluginError, match="api_version >= 1.7"):
        load(("rextio-demo", Illegal()))


def test_api_17_without_hook_loads_as_undeclared() -> None:
    class NoHook(BaseLoweringPlugin):
        api_version = "1.7"

    registry = load(("rextio-demo", NoHook()))
    assert registry.active[0].function_scope_guard_declared is False


def test_api_17_with_hook_declares_presence() -> None:
    registry = load(("rextio-demo", GuardPlugin()))
    plugin = registry.active[0]
    assert plugin.api_version == "1.7"
    assert plugin.function_scope_guard_declared is True
    assert plugin.to_dict()["function_scope_guard_declared"] is True


def test_false_function_scope_guard_declared_omitted_from_serialization() -> None:
    registry = load(("rextio-demo", BaseLoweringPlugin()))
    plugin = registry.active[0]
    assert plugin.function_scope_guard_declared is False
    data = plugin.to_dict()
    assert "function_scope_guard_declared" not in data
    from rextio.plugins.capabilities import declaration_presence

    rows = declaration_presence(registry.active)
    assert rows == [
        {
            "plugin_id": "rextio-demo",
            "api_version": "1.6",
            "artifact_capability_declared": False,
        }
    ]


def test_describe_only_provider_with_hook_fails_load() -> None:
    class DescribeOnly:
        plugin_id = "rextio-demo"
        api_version = "1.7"

        def to_rextio_plugin(self) -> RextioPlugin:
            return RextioPlugin(id="rextio-demo", name="Demo")

        def covers(self) -> CoverageDecl:
            return CoverageDecl(packages=("demo",))

        def describe(self, config: RextioConfig) -> tuple[RuleRecord, ...]:
            return (make_rule(),)

        def function_scope_guard(self, ctx):
            return None

    with pytest.raises(PluginError, match="lowering members"):
        load(("rextio-demo", DescribeOnly()))


def test_protocol_stub_inheritance_does_not_count_as_declaration() -> None:
    class ProtocolStub(BaseLoweringPlugin, RextioFunctionScopeGuardPlugin):
        api_version = "1.7"

    registry = load(("rextio-demo", ProtocolStub()))
    # Protocol-only inheritance must not set presence (no concrete body).
    assert registry.active[0].function_scope_guard_declared is False


def test_context_requires_unique_sorted_facts_and_backend_rules() -> None:
    ctx = PluginFunctionScopeContext(
        function_qualname="app.f",
        used_rule_ids=("rextio-demo/a", "rextio-demo/b"),
        used_type_keys=("rextio-demo/scalar",),
        backend="pyo3",
    )
    assert ctx.to_dict()["backend"] == "pyo3"
    with pytest.raises(ValueError, match="unique and sorted"):
        PluginFunctionScopeContext(
            function_qualname="app.f",
            used_rule_ids=("rextio-demo/b", "rextio-demo/a"),
            used_type_keys=(),
        )
    with pytest.raises(ValueError, match="unique and sorted"):
        PluginFunctionScopeContext(
            function_qualname="app.f",
            used_rule_ids=("rextio-demo/a", "rextio-demo/a"),
            used_type_keys=(),
        )
    with pytest.raises(ValueError, match="artifact_profile"):
        PluginFunctionScopeContext(
            function_qualname="app.f",
            used_rule_ids=(),
            used_type_keys=(),
            backend="standalone-rust",
        )


def test_guard_rejects_empty_support_shapes() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        PluginFunctionScopeGuard(rust="G", uses=("",))
