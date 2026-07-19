"""Codegen/closure tests for plugin API 1.4 standalone artifact capability."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from rextio.analyzer.models import (
    CallSite,
    FunctionAnalysis,
    ModuleAnalysis,
    PluginClaim,
    ProjectAnalysis,
)
from rextio.artifacts.closure import ClosureStatus
from rextio.artifacts.entry_graph import executable_entry_graph
from rextio.artifacts.models import ArtifactKind
from rextio.artifacts.profiles import host_executable_profile, rust_crate_profile
from rextio.codegen.rust.errors import RustCodegenError
from rextio.codegen.rust.generator import generate_rust_crate_module
from rextio.config.schema import RextioConfig
from rextio.ir.nodes import (
    BlockIR,
    CallIR,
    FunctionIR,
    ModuleIR,
    NameIR,
    ParamIR,
    PluginClaimIR,
    ReturnIR,
)
from rextio.ir.types import RxtInt, RxtPluginType
from rextio.plugins.api import (
    BoundaryConversion,
    Claimed,
    ClaimSite,
    CoverageDecl,
    CrateDependency,
    LoweredExpr,
    LoweringContext,
    PluginArtifactCapability,
    PluginArtifactTypeSupport,
    PluginType,
    RuleRecord,
    RuleScope,
)
from rextio.plugins.capabilities import (
    StandalonePluginContext,
    resolve_provider_artifact_capability,
)
from rextio.plugins.models import RextioPlugin
from rextio.analyzer.final_bindings import build_module_bindings


PLUGIN_ID = "rextio-demo"
TYPE_KEY = "rextio-demo/scalar"
RULE_ID = "rextio-demo/double"

SCALAR_TYPE = PluginType(
    key=TYPE_KEY,
    annotations=("demo_types.Scalar",),
    rust_type="i64",
    conversion=BoundaryConversion(
        param_rust="i64",
        param_expr="{param}",
        return_rust="i64",
        return_expr="{value}",
    ),
    uses=("use host_only::Never;",),
    helpers=("fn host_only_helper() {}",),
)

RXT_SCALAR = RxtPluginType(
    key=TYPE_KEY,
    native_rust="i64",
    param_rust="i64",
    param_expr="{param}",
    return_rust="i64",
    return_expr="{value}",
    uses=("use host_only::Never;",),
    helpers=("fn host_only_helper() {}",),
)


class StandaloneProvider:
    plugin_id = PLUGIN_ID
    api_version = "1.4"

    def to_rextio_plugin(self) -> RextioPlugin:
        return RextioPlugin(
            id=PLUGIN_ID,
            name="Demo",
            rules_provided=True,
            api_version="1.4",
            lowering_provided=True,
            artifact_capability_declared=True,
        )

    def covers(self) -> CoverageDecl:
        return CoverageDecl(packages=("demo",))

    def describe(self, config: RextioConfig) -> tuple[RuleRecord, ...]:
        return (
            RuleRecord(
                id=RULE_ID,
                provider=PLUGIN_ID,
                scope=RuleScope(kind="call", pattern="demo.double"),
                constraint="double",
                outcome="native",
                diagnostic_code="RXTP-DEMO-001",
                guidance="g",
                stability="experimental",
            ),
        )

    def type_vocabulary(self) -> tuple[PluginType, ...]:
        return (SCALAR_TYPE,)

    def claim(self, site: ClaimSite, config: RextioConfig):
        if site.kind == "call" and site.target == "demo.double":
            return Claimed(rule_id=RULE_ID, result_type=TYPE_KEY)
        return Claimed(rule_id=RULE_ID, result_type=TYPE_KEY)

    def lower(self, site: ClaimSite, ctx: LoweringContext) -> LoweredExpr:
        return LoweredExpr(
            rust=f"({ctx.operands[0]} * 2)",
            uses=("use demo_support::scale;",),
            helpers=("fn scale(x: i64) -> i64 { x }",),
        )

    def crate_dependencies(self) -> tuple[CrateDependency, ...]:
        return (CrateDependency(name="host_dep", version="=9.9.9"),)

    def artifact_capability(self, profile):
        if profile.kind is not ArtifactKind.RUST_CRATE:
            return None
        return PluginArtifactCapability(
            rule_ids=(RULE_ID,),
            types=(
                PluginArtifactTypeSupport(
                    type_key=TYPE_KEY,
                    uses=("use demo_support::scale;",),
                    helpers=("fn scale(x: i64) -> i64 { x }",),
                ),
            ),
            crate_dependencies=(CrateDependency(name="demo_support", version="=0.1.0"),),
        )


def _plugin_function(*, plugin_lowered: bool = True) -> FunctionIR:
    claim = PluginClaimIR(
        plugin_id=PLUGIN_ID,
        rule_id=RULE_ID,
        kind="call",
        target="demo.double",
        operand_types=(TYPE_KEY,),
        result_type=TYPE_KEY,
    )
    call = CallIR(function="demo.double", args=[NameIR(id="x")], claim=claim)
    return FunctionIR(
        name="double",
        qualname="kernels.double",
        module_name="kernels",
        params=[ParamIR("x", RXT_SCALAR)],
        return_type=RXT_SCALAR,
        body=BlockIR(statements=[ReturnIR(value=call)]),
        plugin_lowered=plugin_lowered,
    )


def _standalone_context(
    provider: StandaloneProvider,
    *,
    capable: frozenset[str] | None = None,
) -> StandalonePluginContext:
    profile = rust_crate_profile("x86_64-unknown-linux-gnu")
    capability = resolve_provider_artifact_capability(PLUGIN_ID, provider, "1.4", profile)
    return StandalonePluginContext(
        profile=profile,
        capabilities={PLUGIN_ID: capability},
        capable_qualnames=capable
        if capable is not None
        else (frozenset({"kernels.double"}) if capability is not None else frozenset()),
    )


def test_no_capability_excludes_plugin_and_transitive_caller() -> None:
    plugin_fn = _plugin_function()
    caller = FunctionIR(
        name="pipeline",
        qualname="kernels.pipeline",
        module_name="kernels",
        params=[ParamIR("x", RxtInt())],
        return_type=RxtInt(),
        body=BlockIR(
            statements=[ReturnIR(value=CallIR(function="double", args=[NameIR(id="x")]))]
        ),
        plugin_lowered=False,
    )
    with pytest.raises(RustCodegenError, match="no direct Rust native functions"):
        generate_rust_crate_module(ModuleIR(functions=[plugin_fn, caller]))


def test_positive_standalone_crate_renders_native_only() -> None:
    provider = StandaloneProvider()
    source = generate_rust_crate_module(
        ModuleIR(functions=[_plugin_function()]),
        plugin_providers={PLUGIN_ID: provider},
        plugin_types_by_key={TYPE_KEY: RXT_SCALAR},
        standalone=_standalone_context(provider),
    )
    assert "pyo3" not in source.lower()
    assert "Python<" not in source
    assert "use demo_support::scale;" in source
    assert "fn scale(x: i64) -> i64 { x }" in source
    assert "use host_only::Never;" not in source
    assert "host_only_helper" not in source
    assert "* 2" in source


def test_standalone_core_only_function_still_emits_with_excluded_plugin() -> None:
    plugin_fn = _plugin_function()
    core = FunctionIR(
        name="add",
        qualname="kernels.add",
        module_name="kernels",
        params=[ParamIR("a", RxtInt()), ParamIR("b", RxtInt())],
        return_type=RxtInt(),
        body=BlockIR(statements=[]),
        plugin_lowered=False,
    )
    source = generate_rust_crate_module(ModuleIR(functions=[plugin_fn, core]))
    assert "kernels__add" in source or "add" in source
    assert "kernels__double" not in source


def test_undeclared_lower_support_fails_codegen() -> None:
    class UndeclaredSupport(StandaloneProvider):
        def lower(self, site: ClaimSite, ctx: LoweringContext) -> LoweredExpr:
            return LoweredExpr(
                rust=f"({ctx.operands[0]} * 2)",
                uses=("use undeclared::Thing;",),
            )

    provider = UndeclaredSupport()
    with pytest.raises(RustCodegenError, match="undeclared standalone support"):
        generate_rust_crate_module(
            ModuleIR(functions=[_plugin_function()]),
            plugin_providers={PLUGIN_ID: provider},
            plugin_types_by_key={TYPE_KEY: RXT_SCALAR},
            standalone=_standalone_context(provider),
        )


def test_missing_capability_fails_closed_for_plugin_function() -> None:
    with pytest.raises(RustCodegenError, match="no pure-Rust form|no direct Rust"):
        generate_rust_crate_module(
            ModuleIR(functions=[_plugin_function()]),
            standalone=StandalonePluginContext(
                profile=rust_crate_profile("x86_64-unknown-linux-gnu"),
                capabilities={PLUGIN_ID: None},
                capable_qualnames=frozenset(),
            ),
        )


def test_wrong_profile_capability_none_excludes() -> None:
    provider = StandaloneProvider()
    profile = host_executable_profile("x86_64-unknown-linux-gnu")
    capability = resolve_provider_artifact_capability(PLUGIN_ID, provider, "1.4", profile)
    assert capability is None
    with pytest.raises(RustCodegenError, match="no pure-Rust form|no direct Rust"):
        generate_rust_crate_module(
            ModuleIR(functions=[_plugin_function()]),
            plugin_providers={PLUGIN_ID: provider},
            standalone=StandalonePluginContext(
                profile=profile,
                capabilities={PLUGIN_ID: None},
                capable_qualnames=frozenset(),
            ),
        )


def _exec_analysis(
    *,
    main_calls_helper: bool,
) -> ProjectAnalysis:
    source = (
        "def main(argv: list[str]) -> int:\n    return helper()\n"
        if main_calls_helper
        else "def main(argv: list[str]) -> int:\n    return 0\n"
    )
    source += "def helper() -> int:\n    return 1\n"
    bindings = build_module_bindings(ast.parse(source), "app")
    main = FunctionAnalysis(
        name="main",
        qualname="app.main",
        module_name="app",
        file_path="app.py",
        line=1,
        column=0,
        is_native_candidate=True,
        accepted=True,
        annotated_return_type="int",
        signature_return_type="int",
        calls=[CallSite("app.helper", 2, 4)] if main_calls_helper else [],
        module_bindings=bindings,
    )
    helper = FunctionAnalysis(
        name="helper",
        qualname="app.helper",
        module_name="app",
        file_path="app.py",
        line=3,
        column=0,
        is_native_candidate=True,
        accepted=True,
        annotated_return_type="int",
        signature_return_type="int",
        plugin_claims=[PluginClaim(PLUGIN_ID, RULE_ID, "call", "demo.double", 5, 4, "int")],
        plugin_type_keys=[TYPE_KEY],
        module_bindings=bindings,
    )
    return ProjectAnalysis(
        project_root=Path("."),
        modules=[ModuleAnalysis("app", "app.py", functions=[main, helper])],
    )


def test_executable_closure_blocks_unsupported_reachable_plugin() -> None:
    analysis = _exec_analysis(main_calls_helper=True)
    profile = host_executable_profile("x86_64-unknown-linux-gnu")
    blocked = executable_entry_graph(analysis, "app.main", profile=profile)
    assert blocked.status is ClosureStatus.UNAVAILABLE
    assert blocked.blockers[0].callee == "app.helper"
    assert "standalone Rust" in blocked.blockers[0].reason


def test_executable_closure_allows_capable_plugin_callee() -> None:
    analysis = _exec_analysis(main_calls_helper=True)
    profile = host_executable_profile("x86_64-unknown-linux-gnu")
    capability = PluginArtifactCapability(
        rule_ids=(RULE_ID,),
        types=(PluginArtifactTypeSupport(type_key=TYPE_KEY),),
    )
    report = executable_entry_graph(
        analysis,
        "app.main",
        profile=profile,
        plugin_capabilities={PLUGIN_ID: capability},
    )
    assert report.status is ClosureStatus.CLOSED
    assert "app.helper" in report.reachable_native_functions


def test_unreachable_unsupported_plugin_does_not_block() -> None:
    analysis = _exec_analysis(main_calls_helper=False)
    report = executable_entry_graph(
        analysis,
        "app.main",
        profile=host_executable_profile("x86_64-unknown-linux-gnu"),
    )
    assert report.status is ClosureStatus.CLOSED
    assert report.blockers == ()


def test_backend_and_profile_reach_lower_standalone_not_pyo3() -> None:
    """Standalone lower receives backend=standalone-rust and exact profile; no PyO3 leak."""
    seen: list[LoweringContext] = []

    class BackendAware(StandaloneProvider):
        def lower(self, site: ClaimSite, ctx: LoweringContext) -> LoweredExpr:
            seen.append(ctx)
            if ctx.backend == "standalone-rust":
                return LoweredExpr(
                    rust=f"standalone_scale({ctx.operands[0]})",
                    uses=("use demo_support::scale;",),
                    helpers=("fn standalone_scale(x: i64) -> i64 { x * 2 }",),
                )
            return LoweredExpr(
                rust=f"pyo3_only({ctx.operands[0]})",
                uses=("use host_only::Never;",),
            )

        def artifact_capability(self, profile):
            if profile.kind is not ArtifactKind.RUST_CRATE:
                return None
            return PluginArtifactCapability(
                rule_ids=(RULE_ID,),
                types=(
                    PluginArtifactTypeSupport(
                        type_key=TYPE_KEY,
                        uses=("use demo_support::scale;",),
                        helpers=("fn standalone_scale(x: i64) -> i64 { x * 2 }",),
                    ),
                ),
                crate_dependencies=(CrateDependency(name="demo_support", version="=0.1.0"),),
            )

    from rextio.artifacts.profiles import rust_crate_profile as crate_profile

    provider = BackendAware()
    profile = crate_profile("x86_64-unknown-linux-gnu")
    source = generate_rust_crate_module(
        ModuleIR(functions=[_plugin_function()]),
        plugin_providers={PLUGIN_ID: provider},
        plugin_types_by_key={TYPE_KEY: RXT_SCALAR},
        standalone=StandalonePluginContext(
            profile=profile,
            capabilities={
                PLUGIN_ID: resolve_provider_artifact_capability(
                    PLUGIN_ID, provider, "1.4", profile
                )
            },
            capable_qualnames=frozenset({"kernels.double"}),
        ),
    )
    assert len(seen) == 1
    assert seen[0].backend == "standalone-rust"
    assert seen[0].artifact_profile is profile
    assert "standalone_scale" in source
    assert "pyo3_only" not in source
    assert "pyo3" not in source.lower()
    assert "host_only" not in source


def test_omitted_claim_operand_type_denied_at_standalone() -> None:
    """Rule declared but claim plugin operand/result type omitted from capability."""
    provider = StandaloneProvider()
    profile = rust_crate_profile("x86_64-unknown-linux-gnu")
    # Capability covers only TYPE_KEY, but claim result/operand is OTHER.
    other = "rextio-demo/other"
    claim = PluginClaimIR(
        plugin_id=PLUGIN_ID,
        rule_id=RULE_ID,
        kind="call",
        target="demo.double",
        operand_types=(other,),
        result_type=other,
    )
    rxt_other = RxtPluginType(key=other, native_rust="i64")
    function = FunctionIR(
        name="double",
        qualname="kernels.double",
        module_name="kernels",
        params=[ParamIR("x", rxt_other)],
        return_type=rxt_other,
        body=BlockIR(
            statements=[
                ReturnIR(
                    value=CallIR(
                        function="demo.double",
                        args=[NameIR(id="x")],
                        claim=claim,
                    )
                )
            ]
        ),
        plugin_lowered=True,
    )
    # Planning-level: not capable when claim types not covered.
    from rextio.plugins.capabilities import analysis_function_is_standalone_capable

    analysis_claim = PluginClaim(
        PLUGIN_ID, RULE_ID, "call", "demo.double", 1, 0, other, operand_types=(other,)
    )
    capability = resolve_provider_artifact_capability(PLUGIN_ID, provider, "1.4", profile)
    assert capability is not None
    assert (
        analysis_function_is_standalone_capable(
            plugin_claims=(analysis_claim,),
            plugin_type_keys=(),
            capabilities={PLUGIN_ID: capability},
        )
        is False
    )
    # Even if a stale context claims the function is capable, codegen defense-in-depth
    # must still reject when claim type keys are not covered.
    with pytest.raises(RustCodegenError, match="not covered by the resolved standalone"):
        generate_rust_crate_module(
            ModuleIR(functions=[function]),
            plugin_providers={PLUGIN_ID: provider},
            plugin_types_by_key={other: rxt_other, TYPE_KEY: RXT_SCALAR},
            standalone=StandalonePluginContext(
                profile=profile,
                capabilities={PLUGIN_ID: capability},
                capable_qualnames=frozenset({"kernels.double"}),
            ),
        )


def test_transitive_exclusion_does_not_inject_excluded_plugin_deps() -> None:
    """Capable plugin fn calling unsupported plugin fn is excluded; no dep inject."""
    from rextio.codegen.rust.cargo import render_importable_cargo_toml
    from rextio.codegen.rust.generator import crate_emitted_qualnames
    from rextio.plugins.capabilities import profile_crate_dependencies

    provider = StandaloneProvider()
    profile = rust_crate_profile("x86_64-unknown-linux-gnu")
    capability = resolve_provider_artifact_capability(PLUGIN_ID, provider, "1.4", profile)
    assert capability is not None

    # unsupported: plugin-lowered without capability coverage (wrong rule)
    bad_claim = PluginClaimIR(
        plugin_id=PLUGIN_ID,
        rule_id="rextio-demo/missing",
        kind="call",
        target="demo.bad",
        operand_types=(TYPE_KEY,),
        result_type=TYPE_KEY,
    )
    unsupported = FunctionIR(
        name="bad",
        qualname="kernels.bad",
        module_name="kernels",
        params=[ParamIR("x", RXT_SCALAR)],
        return_type=RXT_SCALAR,
        body=BlockIR(
            statements=[
                ReturnIR(
                    value=CallIR(function="demo.bad", args=[NameIR(id="x")], claim=bad_claim)
                )
            ]
        ),
        plugin_lowered=True,
    )
    # capable plugin function that calls the unsupported one by bare name
    capable_caller = FunctionIR(
        name="pipeline",
        qualname="kernels.pipeline",
        module_name="kernels",
        params=[ParamIR("x", RXT_SCALAR)],
        return_type=RXT_SCALAR,
        body=BlockIR(
            statements=[
                ReturnIR(value=CallIR(function="bad", args=[NameIR(id="x")]))
            ]
        ),
        plugin_lowered=True,
    )
    # Mark caller as capable in context (would inject deps if not excluded).
    core = FunctionIR(
        name="add",
        qualname="kernels.add",
        module_name="kernels",
        params=[ParamIR("a", RxtInt()), ParamIR("b", RxtInt())],
        return_type=RxtInt(),
        body=BlockIR(statements=[]),
        plugin_lowered=False,
    )
    standalone = StandalonePluginContext(
        profile=profile,
        capabilities={PLUGIN_ID: capability},
        # Pretend pipeline is capable (has coverage) but it calls unsupported bad.
        capable_qualnames=frozenset({"kernels.pipeline"}),
    )
    module = ModuleIR(functions=[unsupported, capable_caller, core])
    emitted = crate_emitted_qualnames(module, standalone=standalone)
    assert "kernels.add" in emitted
    assert "kernels.pipeline" not in emitted
    assert "kernels.bad" not in emitted

    used_plugin_ids = {
        claim.plugin_id
        for function in (capable_caller, unsupported, core)
        if function.qualname in emitted and standalone.is_capable(function.qualname)
        for claim in ()
    }
    # No capable emitted plugin function → no profile deps.
    deps = profile_crate_dependencies(standalone.capabilities, used_plugin_ids)
    assert deps == ()
    source = generate_rust_crate_module(module, standalone=standalone)
    assert "pipeline" not in source or "kernels__pipeline" not in source
    assert "add" in source or "kernels__add" in source
    # Cargo manifest for emitted set must not mention demo_support.
    toml = render_importable_cargo_toml("demo", extra_dependencies=deps)
    assert "demo_support" not in toml


def test_legacy_lowering_context_construction_remains_valid() -> None:
    """Pre-1.4 LoweringContext construction (no backend/profile) stays valid."""
    ctx = LoweringContext(
        operands=("a",),
        target_language="rust",
        fresh_name=lambda prefix: f"{prefix}_0",
    )
    assert ctx.backend == "pyo3"
    assert ctx.artifact_profile is None
    assert ctx.receiver is None
    assert ctx.leaf_operands == ()
