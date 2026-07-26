"""Codegen tests for plugin API 1.7 function-scope RAII guards."""

from __future__ import annotations

import pytest

from rextio.artifacts.models import ArtifactKind
from rextio.artifacts.profiles import rust_crate_profile
from rextio.codegen.rust.errors import RustCodegenError
from rextio.codegen.rust.generator import generate_rust_crate_module, generate_rust_module
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
    Claimed,
    ClaimSite,
    LoweredExpr,
    LoweringContext,
    NotCovered,
    PluginArtifactCapability,
    PluginArtifactTypeSupport,
    PluginFunctionScopeContext,
    PluginFunctionScopeGuard,
)
from rextio.plugins.capabilities import StandalonePluginContext
from rextio.plugins.function_scope import core_owned_guard_binding_name

PLUGIN_A = "rextio-alpha"
PLUGIN_B = "rextio-beta"
TYPE_A = f"{PLUGIN_A}/scalar"
TYPE_B = f"{PLUGIN_B}/scalar"
RULE_A = f"{PLUGIN_A}/double"
RULE_B = f"{PLUGIN_B}/triple"

RXT_A = RxtPluginType(
    key=TYPE_A,
    native_rust="i64",
    param_rust="i64",
    param_expr="{param}",
    return_rust="i64",
    return_expr="{value}",
)
RXT_B = RxtPluginType(
    key=TYPE_B,
    native_rust="i64",
    param_rust="i64",
    param_expr="{param}",
    return_rust="i64",
    return_expr="{value}",
)


class AlphaProvider:
    plugin_id = PLUGIN_A
    api_version = "1.7"
    calls: list[PluginFunctionScopeContext]

    def __init__(self) -> None:
        self.calls = []

    def claim(self, site: ClaimSite, config: RextioConfig):
        if site.kind == "call" and site.target == "alpha.double":
            return Claimed(rule_id=RULE_A, result_type=TYPE_A)
        return NotCovered()

    def lower(self, site: ClaimSite, ctx: LoweringContext) -> LoweredExpr:
        return LoweredExpr(rust=f"({ctx.operands[0]} * 2)")

    def function_scope_guard(self, ctx: PluginFunctionScopeContext):
        self.calls.append(ctx)
        return PluginFunctionScopeGuard(
            rust="AlphaGuard::enter()",
            uses=("use alpha_support::AlphaGuard;",),
            helpers=("struct AlphaGuard; impl AlphaGuard { fn enter() -> Self { Self } }",),
        )


class BetaProvider:
    plugin_id = PLUGIN_B
    api_version = "1.7"
    calls: list[PluginFunctionScopeContext]

    def __init__(self) -> None:
        self.calls = []

    def claim(self, site: ClaimSite, config: RextioConfig):
        if site.kind == "call" and site.target == "beta.triple":
            return Claimed(rule_id=RULE_B, result_type=TYPE_B)
        return NotCovered()

    def lower(self, site: ClaimSite, ctx: LoweringContext) -> LoweredExpr:
        return LoweredExpr(rust=f"({ctx.operands[0]} * 3)")

    def function_scope_guard(self, ctx: PluginFunctionScopeContext):
        self.calls.append(ctx)
        return PluginFunctionScopeGuard(rust="BetaGuard::enter()")


class LegacyProvider:
    plugin_id = PLUGIN_A
    api_version = "1.6"

    def claim(self, site: ClaimSite, config: RextioConfig):
        return Claimed(rule_id=RULE_A, result_type=TYPE_A)

    def lower(self, site: ClaimSite, ctx: LoweringContext) -> LoweredExpr:
        return LoweredExpr(rust=f"({ctx.operands[0]} * 2)")


class BrokenGuardProvider(AlphaProvider):
    def function_scope_guard(self, ctx: PluginFunctionScopeContext):
        return PluginFunctionScopeGuard(rust="let x = 1")


class ExceptionGuardProvider(AlphaProvider):
    def function_scope_guard(self, ctx: PluginFunctionScopeContext):
        raise RuntimeError("guard boom")


class TypeOnlyGuardProvider:
    plugin_id = PLUGIN_A
    api_version = "1.7"
    calls: list[PluginFunctionScopeContext]

    def __init__(self) -> None:
        self.calls = []

    def claim(self, site: ClaimSite, config: RextioConfig):
        return NotCovered()

    def lower(self, site: ClaimSite, ctx: LoweringContext) -> LoweredExpr:
        raise AssertionError("lower should not run for type-only usage")

    def function_scope_guard(self, ctx: PluginFunctionScopeContext):
        self.calls.append(ctx)
        return PluginFunctionScopeGuard(rust="TypeOnlyGuard::enter()")


class UnusedGuardProvider:
    plugin_id = "rextio-unused"
    api_version = "1.7"
    calls: int

    def __init__(self) -> None:
        self.calls = 0

    def claim(self, site: ClaimSite, config: RextioConfig):
        return NotCovered()

    def lower(self, site: ClaimSite, ctx: LoweringContext) -> LoweredExpr:
        raise AssertionError("unused")

    def function_scope_guard(self, ctx: PluginFunctionScopeContext):
        self.calls += 1
        return PluginFunctionScopeGuard(rust="UnusedGuard::enter()")


def _claimed_function(
    *,
    plugin_id: str = PLUGIN_A,
    rule_id: str = RULE_A,
    type_key: str = TYPE_A,
    rxt_type: RxtPluginType = RXT_A,
    target: str = "alpha.double",
    qualname: str = "kernels.double",
) -> FunctionIR:
    claim = PluginClaimIR(
        plugin_id=plugin_id,
        rule_id=rule_id,
        kind="call",
        target=target,
        operand_types=(type_key,),
        result_type=type_key,
    )
    call = CallIR(function=target, args=[NameIR(id="x")], claim=claim)
    return FunctionIR(
        name=qualname.rsplit(".", 1)[-1],
        qualname=qualname,
        module_name="kernels",
        params=[ParamIR("x", rxt_type)],
        return_type=rxt_type,
        body=BlockIR(statements=[ReturnIR(value=call)]),
        plugin_lowered=True,
    )


def _type_only_function() -> FunctionIR:
    return FunctionIR(
        name="identity",
        qualname="kernels.identity",
        module_name="kernels",
        params=[ParamIR("x", RXT_A)],
        return_type=RXT_A,
        body=BlockIR(statements=[ReturnIR(value=NameIR(id="x"))]),
        plugin_lowered=True,
    )


def _multi_plugin_function() -> FunctionIR:
    """beta.triple(alpha.double(x)) with both claims present."""
    alpha_claim = PluginClaimIR(
        plugin_id=PLUGIN_A,
        rule_id=RULE_A,
        kind="call",
        target="alpha.double",
        operand_types=(TYPE_A,),
        result_type=TYPE_A,
    )
    beta_claim = PluginClaimIR(
        plugin_id=PLUGIN_B,
        rule_id=RULE_B,
        kind="call",
        target="beta.triple",
        operand_types=(TYPE_A,),
        result_type=TYPE_B,
    )
    inner = CallIR(function="alpha.double", args=[NameIR(id="x")], claim=alpha_claim)
    outer = CallIR(function="beta.triple", args=[inner], claim=beta_claim)
    return FunctionIR(
        name="scale",
        qualname="kernels.scale",
        module_name="kernels",
        params=[ParamIR("x", RXT_A)],
        return_type=RXT_B,
        body=BlockIR(statements=[ReturnIR(value=outer)]),
        plugin_lowered=True,
    )


def test_legacy_provider_byte_identical_no_hook_output() -> None:
    module = ModuleIR(functions=[_claimed_function()])
    providers = {PLUGIN_A: LegacyProvider()}
    types = {TYPE_A: RXT_A}
    out1 = generate_rust_module(module, plugin_providers=providers, plugin_types_by_key=types)
    out2 = generate_rust_module(module, plugin_providers=providers, plugin_types_by_key=types)
    assert out1 == out2
    assert "plugin_scope_guard" not in out1
    assert "Guard::enter" not in out1


def test_guard_emitted_before_conversions_and_body() -> None:
    provider = AlphaProvider()
    out = generate_rust_module(
        ModuleIR(functions=[_claimed_function()]),
        plugin_providers={PLUGIN_A: provider},
        plugin_types_by_key={TYPE_A: RXT_A},
    )
    binding = core_owned_guard_binding_name(PLUGIN_A)
    guard_line = f"let {binding} = AlphaGuard::enter();"
    assert guard_line in out
    # Guard before param conversion and before lowered body multiply.
    guard_idx = out.index(guard_line)
    convert_idx = out.index("let x = x;")
    body_idx = out.index("* 2")
    assert guard_idx < convert_idx < body_idx
    assert "use alpha_support::AlphaGuard;" in out
    assert "struct AlphaGuard;" in out
    assert len(provider.calls) == 1
    ctx = provider.calls[0]
    assert ctx.function_qualname == "kernels.double"
    assert ctx.used_rule_ids == (RULE_A,)
    assert TYPE_A in ctx.used_type_keys
    assert ctx.backend == "pyo3"
    assert ctx.artifact_profile is None


def test_unused_provider_excluded() -> None:
    alpha = AlphaProvider()
    unused = UnusedGuardProvider()
    out = generate_rust_module(
        ModuleIR(functions=[_claimed_function()]),
        plugin_providers={PLUGIN_A: alpha, "rextio-unused": unused},
        plugin_types_by_key={TYPE_A: RXT_A},
    )
    assert "UnusedGuard" not in out
    assert unused.calls == 0
    assert alpha.calls


def test_multi_plugin_ordering_deterministic() -> None:
    alpha = AlphaProvider()
    beta = BetaProvider()
    out = generate_rust_module(
        ModuleIR(functions=[_multi_plugin_function()]),
        plugin_providers={PLUGIN_B: beta, PLUGIN_A: alpha},
        plugin_types_by_key={TYPE_A: RXT_A, TYPE_B: RXT_B},
    )
    a_bind = core_owned_guard_binding_name(PLUGIN_A)
    b_bind = core_owned_guard_binding_name(PLUGIN_B)
    a_idx = out.index(f"let {a_bind} = AlphaGuard::enter();")
    b_idx = out.index(f"let {b_bind} = BetaGuard::enter();")
    assert a_idx < b_idx


def test_type_only_usage_facts() -> None:
    provider = TypeOnlyGuardProvider()
    out = generate_rust_module(
        ModuleIR(functions=[_type_only_function()]),
        plugin_providers={PLUGIN_A: provider},
        plugin_types_by_key={TYPE_A: RXT_A},
    )
    binding = core_owned_guard_binding_name(PLUGIN_A)
    assert f"let {binding} = TypeOnlyGuard::enter();" in out
    assert provider.calls
    ctx = provider.calls[0]
    assert ctx.used_rule_ids == ()
    assert ctx.used_type_keys == (TYPE_A,)


def test_invalid_statement_like_guard_fails() -> None:
    with pytest.raises(RustCodegenError, match="statement-like|semicolon|single"):
        generate_rust_module(
            ModuleIR(functions=[_claimed_function()]),
            plugin_providers={PLUGIN_A: BrokenGuardProvider()},
            plugin_types_by_key={TYPE_A: RXT_A},
        )


def test_hook_exception_is_rust_codegen_error() -> None:
    with pytest.raises(RustCodegenError, match="guard boom"):
        generate_rust_module(
            ModuleIR(functions=[_claimed_function()]),
            plugin_providers={PLUGIN_A: ExceptionGuardProvider()},
            plugin_types_by_key={TYPE_A: RXT_A},
        )


def test_core_owned_names_are_collision_free_and_stable() -> None:
    assert core_owned_guard_binding_name("rextio-numpy") == (
        "__rextio_plugin_scope_guard_rextio_numpy"
    )
    assert core_owned_guard_binding_name("rextio-demo") == (
        "__rextio_plugin_scope_guard_rextio_demo"
    )
    assert core_owned_guard_binding_name("rextio.foo/bar") == (
        "__rextio_plugin_scope_guard_rextio_foo_bar"
    )


class StandaloneAlpha(AlphaProvider):
    def artifact_capability(self, profile):
        if profile.kind is not ArtifactKind.RUST_CRATE:
            return None
        return PluginArtifactCapability(
            rule_ids=(RULE_A,),
            types=(
                PluginArtifactTypeSupport(
                    type_key=TYPE_A,
                    uses=("use alpha_support::AlphaGuard;",),
                    helpers=("struct AlphaGuard; impl AlphaGuard { fn enter() -> Self { Self } }",),
                ),
            ),
        )

    def function_scope_guard(self, ctx: PluginFunctionScopeContext):
        self.calls.append(ctx)
        assert ctx.backend == "standalone-rust"
        assert ctx.artifact_profile is not None
        return PluginFunctionScopeGuard(
            rust="AlphaGuard::enter()",
            uses=("use alpha_support::AlphaGuard;",),
            helpers=("struct AlphaGuard; impl AlphaGuard { fn enter() -> Self { Self } }",),
        )


def test_standalone_allows_guard_when_capability_authorized() -> None:
    provider = StandaloneAlpha()
    profile = rust_crate_profile("x86_64-unknown-linux-gnu")
    capability = provider.artifact_capability(profile)
    standalone = StandalonePluginContext(
        profile=profile,
        capabilities={PLUGIN_A: capability},
        capable_qualnames=frozenset({"kernels.double"}),
    )
    out = generate_rust_crate_module(
        ModuleIR(functions=[_claimed_function()]),
        plugin_providers={PLUGIN_A: provider},
        plugin_types_by_key={TYPE_A: RXT_A},
        standalone=standalone,
    )
    binding = core_owned_guard_binding_name(PLUGIN_A)
    assert f"let {binding} = AlphaGuard::enter();" in out
    assert "use alpha_support::AlphaGuard;" in out
    assert provider.calls
    assert provider.calls[0].backend == "standalone-rust"


def test_standalone_undeclared_guard_support_fails() -> None:
    class BadStandalone(AlphaProvider):
        def artifact_capability(self, profile):
            if profile.kind is not ArtifactKind.RUST_CRATE:
                return None
            return PluginArtifactCapability(
                rule_ids=(RULE_A,),
                types=(PluginArtifactTypeSupport(type_key=TYPE_A),),
            )

        def function_scope_guard(self, ctx: PluginFunctionScopeContext):
            return PluginFunctionScopeGuard(
                rust="AlphaGuard::enter()",
                uses=("use alpha_support::AlphaGuard;",),
            )

    provider = BadStandalone()
    profile = rust_crate_profile("x86_64-unknown-linux-gnu")
    capability = provider.artifact_capability(profile)
    standalone = StandalonePluginContext(
        profile=profile,
        capabilities={PLUGIN_A: capability},
        capable_qualnames=frozenset({"kernels.double"}),
    )
    with pytest.raises(RustCodegenError, match="undeclared standalone support"):
        generate_rust_crate_module(
            ModuleIR(functions=[_claimed_function()]),
            plugin_providers={PLUGIN_A: provider},
            plugin_types_by_key={TYPE_A: RXT_A},
            standalone=standalone,
        )


def test_core_only_function_does_not_call_installed_guard_hooks() -> None:
    unused = UnusedGuardProvider()
    core = FunctionIR(
        name="add",
        qualname="kernels.add",
        module_name="kernels",
        params=[ParamIR("a", RxtInt()), ParamIR("b", RxtInt())],
        return_type=RxtInt(),
        body=BlockIR(statements=[]),
        plugin_lowered=False,
    )
    out = generate_rust_module(
        ModuleIR(functions=[core]),
        plugin_providers={"rextio-unused": unused},
    )
    assert "UnusedGuard" not in out
    assert unused.calls == 0
