"""Plugin API 1.4: standalone artifact capability contract (loader + resolver)."""

from __future__ import annotations

from typing import Any

import pytest

from rextio.artifacts.models import ArtifactKind
from rextio.artifacts.profiles import host_executable_profile, rust_crate_profile
from rextio.config.schema import PluginConfig, RextioConfig
from rextio.plugins.api import (
    PLUGIN_API_VERSION,
    BoundaryConversion,
    Claimed,
    ClaimSite,
    CoverageDecl,
    CrateDependency,
    LoweredExpr,
    PluginArtifactCapability,
    PluginArtifactTypeSupport,
    PluginType,
    RuleRecord,
    RuleScope,
)
from rextio.plugins.capabilities import (
    build_standalone_plugin_context,
    coverage_for_function,
    function_is_standalone_capable,
    resolve_provider_artifact_capability,
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


F64 = PluginType(
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
    api_version = "1.3"

    def to_rextio_plugin(self) -> RextioPlugin:
        return RextioPlugin(id="rextio-demo", name="Demo")

    def covers(self) -> CoverageDecl:
        return CoverageDecl(packages=("demo",))

    def describe(self, config: RextioConfig) -> tuple[RuleRecord, ...]:
        return (make_rule(),)

    def type_vocabulary(self) -> tuple[PluginType, ...]:
        return (F64,)

    def claim(self, site: ClaimSite, config: RextioConfig):
        return Claimed(rule_id="rextio-demo/double", result_type="int")

    def lower(self, claimed: ClaimSite, ctx: object) -> LoweredExpr:
        return LoweredExpr(rust="x * 2")

    def crate_dependencies(self) -> tuple[CrateDependency, ...]:
        return ()


class CapabilityPlugin(BaseLoweringPlugin):
    api_version = "1.4"

    def artifact_capability(self, profile):
        if profile.kind is not ArtifactKind.RUST_CRATE:
            return None
        return PluginArtifactCapability(
            rule_ids=("rextio-demo/double",),
            types=(
                PluginArtifactTypeSupport(
                    type_key="rextio-demo/scalar",
                    uses=("use demo_support::Helper;",),
                    helpers=("fn helper() {}",),
                ),
            ),
            crate_dependencies=(CrateDependency(name="demo_crate", version="=1.2.3"),),
        )


def load(*payloads: tuple[str, Any], enabled: tuple[str, ...] = ("rextio-demo",)):
    return load_plugin_registry(
        PluginConfig(enabled=enabled),
        TargetSpec(),
        entry_points=tuple(FakeEntryPoint(name, payload) for name, payload in payloads),
    )


def test_plugin_api_version_is_15() -> None:
    assert PLUGIN_API_VERSION == "1.5"


def test_api_13_without_hook_loads_and_does_not_declare_capability() -> None:
    registry = load(("rextio-demo", BaseLoweringPlugin()))
    plugin = registry.active[0]
    assert plugin.api_version == "1.3"
    assert plugin.lowering_provided is True
    assert plugin.artifact_capability_declared is False


def test_api_13_with_illegal_hook_fails_load() -> None:
    class Illegal(BaseLoweringPlugin):
        api_version = "1.3"

        def artifact_capability(self, profile):
            return None

    with pytest.raises(PluginError, match="api_version >= 1.4"):
        load(("rextio-demo", Illegal()))


def test_api_14_without_hook_loads_as_undeclared() -> None:
    class NoHook(BaseLoweringPlugin):
        api_version = "1.4"

    registry = load(("rextio-demo", NoHook()))
    assert registry.active[0].artifact_capability_declared is False
    assert registry.active[0].lowering_provided is True


def test_api_14_with_hook_declares_capability_without_calling_it() -> None:
    calls: list[object] = []

    class Probe(CapabilityPlugin):
        def artifact_capability(self, profile):
            calls.append(profile)
            return super().artifact_capability(profile)

    registry = load(("rextio-demo", Probe()))
    assert registry.active[0].artifact_capability_declared is True
    assert calls == []


def test_capability_none_means_unsupported() -> None:
    plugin = CapabilityPlugin()
    profile = host_executable_profile("x86_64-unknown-linux-gnu")
    assert (
        resolve_provider_artifact_capability("rextio-demo", plugin, "1.4", profile) is None
    )


def test_capability_exact_profile_delivery() -> None:
    plugin = CapabilityPlugin()
    crate = rust_crate_profile("x86_64-unknown-linux-gnu")
    resolved = resolve_provider_artifact_capability("rextio-demo", plugin, "1.4", crate)
    assert resolved is not None
    assert resolved.rule_ids == ("rextio-demo/double",)
    assert resolved.type_keys() == frozenset({"rextio-demo/scalar"})
    assert resolved.crate_dependencies[0].name == "demo_crate"


def test_capability_malformed_return_fails_closed() -> None:
    class BadReturn(CapabilityPlugin):
        def artifact_capability(self, profile):
            return {"not": "a capability"}  # type: ignore[return-value]

    with pytest.raises(PluginError, match="must return PluginArtifactCapability"):
        resolve_provider_artifact_capability(
            "rextio-demo",
            BadReturn(),
            "1.4",
            rust_crate_profile("x86_64-unknown-linux-gnu"),
        )


def test_capability_throwing_hook_fails_closed() -> None:
    class Throws(CapabilityPlugin):
        def artifact_capability(self, profile):
            raise RuntimeError("boom")

    with pytest.raises(PluginError, match="artifact_capability\\(\\) failed"):
        resolve_provider_artifact_capability(
            "rextio-demo",
            Throws(),
            "1.4",
            rust_crate_profile("x86_64-unknown-linux-gnu"),
        )


def test_capability_partial_coverage_is_not_standalone_capable() -> None:
    capability = PluginArtifactCapability(
        rule_ids=("rextio-demo/double",),
        types=(PluginArtifactTypeSupport(type_key="rextio-demo/scalar"),),
    )
    assert (
        function_is_standalone_capable(
            claim_rule_ids=(("rextio-demo", "rextio-demo/double"),),
            plugin_type_keys=("rextio-demo/scalar", "rextio-demo/other"),
            capabilities={"rextio-demo": capability},
        )
        is False
    )
    assert (
        function_is_standalone_capable(
            claim_rule_ids=(("rextio-demo", "rextio-demo/missing"),),
            plugin_type_keys=("rextio-demo/scalar",),
            capabilities={"rextio-demo": capability},
        )
        is False
    )


def test_capability_full_coverage_is_standalone_capable() -> None:
    capability = PluginArtifactCapability(
        rule_ids=("rextio-demo/double",),
        types=(PluginArtifactTypeSupport(type_key="rextio-demo/scalar"),),
    )
    assert (
        function_is_standalone_capable(
            claim_rule_ids=(("rextio-demo", "rextio-demo/double"),),
            plugin_type_keys=("rextio-demo/scalar",),
            capabilities={"rextio-demo": capability},
        )
        is True
    )


def test_namespace_and_dependency_validation() -> None:
    class BadNamespace(CapabilityPlugin):
        def artifact_capability(self, profile):
            return PluginArtifactCapability(
                rule_ids=("other/double",),
                types=(PluginArtifactTypeSupport(type_key="rextio-demo/scalar"),),
            )

    with pytest.raises(PluginError, match="must be namespaced"):
        resolve_provider_artifact_capability(
            "rextio-demo",
            BadNamespace(),
            "1.4",
            rust_crate_profile("x86_64-unknown-linux-gnu"),
        )

    class CoreCrate(CapabilityPlugin):
        def artifact_capability(self, profile):
            return PluginArtifactCapability(
                rule_ids=("rextio-demo/double",),
                types=(PluginArtifactTypeSupport(type_key="rextio-demo/scalar"),),
                crate_dependencies=(CrateDependency(name="pyo3", version="=0.29.0"),),
            )

    with pytest.raises(PluginError, match="reserved by the core-generated manifest"):
        resolve_provider_artifact_capability(
            "rextio-demo",
            CoreCrate(),
            "1.4",
            rust_crate_profile("x86_64-unknown-linux-gnu"),
        )


def test_capability_serialization_is_deterministic() -> None:
    capability = PluginArtifactCapability(
        rule_ids=("rextio-demo/b", "rextio-demo/a"),
        types=(
            PluginArtifactTypeSupport(type_key="rextio-demo/z"),
            PluginArtifactTypeSupport(type_key="rextio-demo/a", uses=("use a;",)),
        ),
        crate_dependencies=(
            CrateDependency(name="zcrate", version="=1.0.0"),
            CrateDependency(name="acrate", version="=2.0.0"),
        ),
    )
    resolved = resolve_provider_artifact_capability(
        "rextio-demo",
        type(
            "P",
            (CapabilityPlugin,),
            {"artifact_capability": lambda self, profile: capability},
        )(),
        "1.4",
        rust_crate_profile("x86_64-unknown-linux-gnu"),
    )
    assert resolved is not None
    assert resolved.to_dict() == {
        "rule_ids": ["rextio-demo/a", "rextio-demo/b"],
        "types": [
            {"type_key": "rextio-demo/a", "uses": ["use a;"]},
            {"type_key": "rextio-demo/z"},
        ],
        "crate_dependencies": [
            {"name": "acrate", "version": "=2.0.0", "features": []},
            {"name": "zcrate", "version": "=1.0.0", "features": []},
        ],
    }


def test_build_standalone_context_from_registry() -> None:
    provider = CapabilityPlugin()
    registry = load(("rextio-demo", provider))
    profile = rust_crate_profile("x86_64-unknown-linux-gnu")

    class Fn:
        qualname = "app.double"
        accepted = True
        plugin_claims = [
            type(
                "C",
                (),
                {
                    "plugin_id": "rextio-demo",
                    "rule_id": "rextio-demo/double",
                    "result_type": "rextio-demo/scalar",
                    "operand_types": ("rextio-demo/scalar",),
                    "receiver": None,
                },
            )()
        ]
        plugin_type_keys = ["rextio-demo/scalar"]

    context = build_standalone_plugin_context(
        profile=profile, registry=registry, functions=(Fn(),)
    )
    assert context.is_capable("app.double")
    assert context.capability_for("rextio-demo") is not None
    assert any(d.qualname == "app.double" and d.supported for d in context.function_decisions)


def test_protocol_inheritance_without_hook_loads_as_api_13() -> None:
    """Legacy Protocol inheritance must not create a callable capability stub."""
    from typing import Protocol

    from rextio.plugins.api import RextioArtifactCapabilityPlugin, RextioLoweringPlugin
    from rextio.plugins.capabilities import provider_declares_artifact_capability

    class LegacyViaProtocol(RextioLoweringPlugin):
        plugin_id = "rextio-demo"
        api_version = "1.3"

        def to_rextio_plugin(self) -> RextioPlugin:
            return RextioPlugin(id="rextio-demo", name="Demo")

        def covers(self) -> CoverageDecl:
            return CoverageDecl(packages=("demo",))

        def describe(self, config: RextioConfig) -> tuple[RuleRecord, ...]:
            return (make_rule(),)

        def type_vocabulary(self) -> tuple[PluginType, ...]:
            return (F64,)

        def claim(self, site: ClaimSite, config: RextioConfig):
            return Claimed(rule_id="rextio-demo/double", result_type="int")

        def lower(self, claimed: ClaimSite, ctx: object) -> LoweredExpr:
            return LoweredExpr(rust="x * 2")

        def crate_dependencies(self) -> tuple[CrateDependency, ...]:
            return ()

    # Capability is a separate Protocol — legacy lowering inheritance has no stub.
    assert "artifact_capability" not in RextioLoweringPlugin.__dict__
    provider = LegacyViaProtocol()
    assert provider_declares_artifact_capability(provider) is False
    registry = load(("rextio-demo", provider))
    assert registry.active[0].api_version == "1.3"
    assert registry.active[0].artifact_capability_declared is False
    assert registry.active[0].lowering_provided is True

    # Even if a class inherits the capability Protocol stub without implementing
    # it, concrete-detection must treat the stub as absent.
    class StubOnlyCapability(LegacyViaProtocol, RextioArtifactCapabilityPlugin):
        api_version = "1.4"

    stub_provider = StubOnlyCapability()
    assert callable(getattr(stub_provider, "artifact_capability", None))
    assert provider_declares_artifact_capability(stub_provider) is False
    registry_stub = load(("rextio-demo", stub_provider))
    assert registry_stub.active[0].artifact_capability_declared is False
    assert issubclass(RextioArtifactCapabilityPlugin, Protocol)


def test_describe_only_provider_cannot_declare_artifact_capability() -> None:
    class DescribeOnly:
        plugin_id = "rextio-demo"
        api_version = "1.4"

        def to_rextio_plugin(self) -> RextioPlugin:
            return RextioPlugin(id="rextio-demo", name="Demo")

        def covers(self) -> CoverageDecl:
            return CoverageDecl(packages=("demo",))

        def describe(self, config: RextioConfig) -> tuple[RuleRecord, ...]:
            return (make_rule(),)

        def artifact_capability(self, profile):
            return None

    with pytest.raises(PluginError, match="only valid on lowering providers"):
        load(("rextio-demo", DescribeOnly()))


def test_stale_namespaced_rule_id_rejected_against_describe() -> None:
    class StaleRule(CapabilityPlugin):
        def artifact_capability(self, profile):
            if profile.kind is not ArtifactKind.RUST_CRATE:
                return None
            return PluginArtifactCapability(
                rule_ids=("rextio-demo/stale-but-namespaced",),
                types=(PluginArtifactTypeSupport(type_key="rextio-demo/scalar"),),
            )

    registry = load(("rextio-demo", StaleRule()))
    with pytest.raises(PluginError, match="unknown rule id"):
        build_standalone_plugin_context(
            profile=rust_crate_profile("x86_64-unknown-linux-gnu"),
            registry=registry,
            functions=(),
        )


def test_stale_namespaced_type_key_rejected_against_vocabulary() -> None:
    class StaleType(CapabilityPlugin):
        def artifact_capability(self, profile):
            if profile.kind is not ArtifactKind.RUST_CRATE:
                return None
            return PluginArtifactCapability(
                rule_ids=("rextio-demo/double",),
                types=(PluginArtifactTypeSupport(type_key="rextio-demo/stale-type"),),
            )

    registry = load(("rextio-demo", StaleType()))
    with pytest.raises(PluginError, match="unknown type key"):
        build_standalone_plugin_context(
            profile=rust_crate_profile("x86_64-unknown-linux-gnu"),
            registry=registry,
            functions=(),
        )


def test_claim_operand_result_types_required_for_capability() -> None:
    """Rule covered but claim operand/result plugin type omitted → denied."""
    capability = PluginArtifactCapability(
        rule_ids=("rextio-demo/double",),
        types=(PluginArtifactTypeSupport(type_key="rextio-demo/scalar"),),
    )
    # Signature keys empty; claim uses an uncovered operand type.
    from rextio.plugins.capabilities import analysis_function_is_standalone_capable

    claim = type(
        "C",
        (),
        {
            "plugin_id": "rextio-demo",
            "rule_id": "rextio-demo/double",
            "result_type": "rextio-demo/other",
            "operand_types": ("rextio-demo/other",),
            "receiver": None,
        },
    )()
    assert (
        analysis_function_is_standalone_capable(
            plugin_claims=(claim,),
            plugin_type_keys=(),
            capabilities={"rextio-demo": capability},
        )
        is False
    )


def test_hook_called_exactly_once_per_profile_with_consistent_output() -> None:
    calls: list[object] = []
    counter = {"n": 0}

    class Stateful(CapabilityPlugin):
        def artifact_capability(self, profile):
            calls.append(profile)
            counter["n"] += 1
            # Non-deterministic-looking raw return; resolver must canonicalize once.
            order = ("rextio-demo/double",) if counter["n"] % 2 else ("rextio-demo/double",)
            return PluginArtifactCapability(
                rule_ids=order,
                types=(
                    PluginArtifactTypeSupport(
                        type_key="rextio-demo/scalar",
                        uses=("use b;", "use a;", "use a;"),
                        helpers=("fn h1() {}", "fn h1() {}", "fn h2() {}"),
                    ),
                ),
                crate_dependencies=(
                    CrateDependency(name="demo_crate", version="=1.2.3"),
                    CrateDependency(name="demo_crate", version="=1.2.3"),
                ),
            )

    registry = load(("rextio-demo", Stateful()))
    profile = rust_crate_profile("x86_64-unknown-linux-gnu")

    class Fn:
        qualname = "app.double"
        accepted = True
        plugin_claims = [
            type(
                "C",
                (),
                {
                    "plugin_id": "rextio-demo",
                    "rule_id": "rextio-demo/double",
                    "result_type": "rextio-demo/scalar",
                    "operand_types": (),
                    "receiver": None,
                },
            )()
        ]
        plugin_type_keys = ["rextio-demo/scalar"]

    context = build_standalone_plugin_context(
        profile=profile, registry=registry, functions=(Fn(),)
    )
    assert len(calls) == 1
    # Re-serialize without re-calling the hook.
    first = context.to_dict()
    second = context.to_dict()
    assert first == second
    assert first["capable_functions"] == ["app.double"]
    assert first["function_decisions"][0]["supported"] is True
    cap = context.capability_for("rextio-demo")
    assert cap is not None
    assert cap.types[0].uses == ("use a;", "use b;")
    assert cap.types[0].helpers == ("fn h1() {}", "fn h2() {}")
    assert len(cap.crate_dependencies) == 1


def test_rejected_functions_not_in_capable_functions() -> None:
    provider = CapabilityPlugin()
    registry = load(("rextio-demo", provider))
    profile = rust_crate_profile("x86_64-unknown-linux-gnu")

    class Accepted:
        qualname = "app.ok"
        accepted = True
        plugin_claims = [
            type(
                "C",
                (),
                {
                    "plugin_id": "rextio-demo",
                    "rule_id": "rextio-demo/double",
                    "result_type": "rextio-demo/scalar",
                    "operand_types": (),
                    "receiver": None,
                },
            )()
        ]
        plugin_type_keys = ["rextio-demo/scalar"]

    class Rejected:
        qualname = "app.bad"
        accepted = False
        plugin_claims = [
            type(
                "C",
                (),
                {
                    "plugin_id": "rextio-demo",
                    "rule_id": "rextio-demo/double",
                    "result_type": "rextio-demo/scalar",
                    "operand_types": (),
                    "receiver": None,
                },
            )()
        ]
        plugin_type_keys = ["rextio-demo/scalar"]

    context = build_standalone_plugin_context(
        profile=profile, registry=registry, functions=(Accepted(), Rejected())
    )
    assert "app.ok" in context.capable_qualnames
    assert "app.bad" not in context.capable_qualnames
    report = context.to_dict()
    assert report["capable_functions"] == ["app.ok"]
    assert all(d["qualname"] != "app.bad" for d in report["function_decisions"])


def test_function_decisions_include_missing_coverage_reason() -> None:
    provider = CapabilityPlugin()
    registry = load(("rextio-demo", provider))
    profile = rust_crate_profile("x86_64-unknown-linux-gnu")

    class Partial:
        qualname = "app.partial"
        accepted = True
        plugin_claims = [
            type(
                "C",
                (),
                {
                    "plugin_id": "rextio-demo",
                    "rule_id": "rextio-demo/double",
                    "result_type": "rextio-demo/other",
                    "operand_types": ("rextio-demo/other",),
                    "receiver": None,
                },
            )()
        ]
        plugin_type_keys = []

    context = build_standalone_plugin_context(
        profile=profile, registry=registry, functions=(Partial(),)
    )
    assert not context.is_capable("app.partial")
    decision = next(d for d in context.function_decisions if d.qualname == "app.partial")
    assert decision.supported is False
    assert "rextio-demo/other" in decision.missing_type_keys
    assert decision.denial_reason is not None
    assert "missing type keys" in decision.denial_reason


def test_multi_plugin_denial_reports_all_missing_coverage() -> None:
    supported, missing_rules, missing_types, reason = coverage_for_function(
        claim_rule_ids=(
            ("rextio-alpha", "rextio-alpha/run"),
            ("rextio-beta", "rextio-beta/run"),
        ),
        plugin_type_keys=("rextio-alpha/value", "rextio-beta/value"),
        capabilities={
            "rextio-alpha": None,
            "rextio-beta": PluginArtifactCapability(),
        },
    )

    assert supported is False
    assert missing_rules == ("rextio-alpha/run", "rextio-beta/run")
    assert missing_types == ("rextio-alpha/value", "rextio-beta/value")
    assert reason is not None
    assert "rextio-alpha" in reason
    assert "rextio-beta/run" in reason
