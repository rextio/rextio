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
    ComprehensionGeneratorIR,
    DictIR,
    EffectCallIR,
    ExceptHandlerIR,
    FunctionIR,
    ListComprehensionIR,
    LiteralIR,
    ModuleIR,
    NameIR,
    ParamIR,
    PluginClaimIR,
    ReturnIR,
    TryIR,
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
from rextio.plugins.function_scope import (
    allocate_function_scope_guard_bindings,
    collect_function_plugin_usage,
    core_owned_guard_binding_name,
    validate_function_scope_guard,
)

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

# Exact fixed golden for the generated function body under a pre-1.7 / no-hook
# provider. Full-module prelude imports may evolve; the body region is the
# compatibility surface for the absent-hook invariant.
LEGACY_NO_HOOK_FUNCTION_GOLDEN = (
    "fn kernels__double<'py>(py: pyo3::Python<'py>, x: i64) -> PyResult<i64> {\n"
    "    let x = x;\n"
    "    return Ok((x * 2));\n"
    "}"
)


class AlphaProvider:
    plugin_id = PLUGIN_A
    api_version = "1.7"

    def __init__(self) -> None:
        self.calls: list[PluginFunctionScopeContext] = []

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

    def __init__(self) -> None:
        self.calls: list[PluginFunctionScopeContext] = []

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
    def __init__(self, rust: str) -> None:
        super().__init__()
        self._rust = rust

    def function_scope_guard(self, ctx: PluginFunctionScopeContext):
        return PluginFunctionScopeGuard(rust=self._rust)


class ExceptionGuardProvider(AlphaProvider):
    def function_scope_guard(self, ctx: PluginFunctionScopeContext):
        raise RuntimeError("guard boom")


class TypeOnlyGuardProvider:
    plugin_id = PLUGIN_A
    api_version = "1.7"

    def __init__(self) -> None:
        self.calls: list[PluginFunctionScopeContext] = []

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

    def __init__(self) -> None:
        self.calls = 0

    def claim(self, site: ClaimSite, config: RextioConfig):
        return NotCovered()

    def lower(self, site: ClaimSite, ctx: LoweringContext) -> LoweredExpr:
        raise AssertionError("unused")

    def function_scope_guard(self, ctx: PluginFunctionScopeContext):
        self.calls += 1
        return PluginFunctionScopeGuard(rust="UnusedGuard::enter()")


class CollidingIdProvider:
    """Providers whose ids sanitize identically under a naive mangler."""

    def __init__(self, plugin_id: str, rust: str) -> None:
        self.plugin_id = plugin_id
        self.api_version = "1.7"
        self._rust = rust

    def claim(self, site: ClaimSite, config: RextioConfig):
        if site.kind == "call" and site.target.endswith(".step"):
            return Claimed(rule_id=f"{self.plugin_id}/step", result_type="int")
        return NotCovered()

    def lower(self, site: ClaimSite, ctx: LoweringContext) -> LoweredExpr:
        return LoweredExpr(rust=f"({ctx.operands[0]} + 1)")

    def function_scope_guard(self, ctx: PluginFunctionScopeContext):
        return PluginFunctionScopeGuard(rust=self._rust)


def _claim(plugin_id: str, rule_id: str, target: str, type_key: str = TYPE_A) -> PluginClaimIR:
    return PluginClaimIR(
        plugin_id=plugin_id,
        rule_id=rule_id,
        kind="call",
        target=target,
        operand_types=(type_key,),
        result_type=type_key,
    )


def _claimed_function(
    *,
    plugin_id: str = PLUGIN_A,
    rule_id: str = RULE_A,
    type_key: str = TYPE_A,
    rxt_type: RxtPluginType = RXT_A,
    target: str = "alpha.double",
    qualname: str = "kernels.double",
) -> FunctionIR:
    claim = _claim(plugin_id, rule_id, target, type_key)
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
    alpha_claim = _claim(PLUGIN_A, RULE_A, "alpha.double", TYPE_A)
    beta_claim = _claim(PLUGIN_B, RULE_B, "beta.triple", TYPE_A)
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


def test_legacy_provider_matches_pre_feature_golden_snapshot() -> None:
    module = ModuleIR(functions=[_claimed_function()])
    out = generate_rust_module(
        module,
        plugin_providers={PLUGIN_A: LegacyProvider()},
        plugin_types_by_key={TYPE_A: RXT_A},
    )
    # Fixed golden for the function body (not merely dual-render equality).
    assert LEGACY_NO_HOOK_FUNCTION_GOLDEN in out
    assert "let __rextio_plugin_scope_guard_" not in out
    assert "Guard::enter" not in out
    # Determinism: second render must match the first byte-for-byte.
    assert out == generate_rust_module(
        module,
        plugin_providers={PLUGIN_A: LegacyProvider()},
        plugin_types_by_key={TYPE_A: RXT_A},
    )


def test_guard_emitted_before_conversions_and_body() -> None:
    provider = AlphaProvider()
    out = generate_rust_module(
        ModuleIR(functions=[_claimed_function()]),
        plugin_providers={PLUGIN_A: provider},
        plugin_types_by_key={TYPE_A: RXT_A},
    )
    binding = core_owned_guard_binding_name(PLUGIN_A, ordinal=0)
    guard_line = f"let {binding} = AlphaGuard::enter();"
    assert guard_line in out
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


def test_multi_plugin_ordering_and_ordinal_bindings() -> None:
    alpha = AlphaProvider()
    beta = BetaProvider()
    out = generate_rust_module(
        ModuleIR(functions=[_multi_plugin_function()]),
        plugin_providers={PLUGIN_B: beta, PLUGIN_A: alpha},
        plugin_types_by_key={TYPE_A: RXT_A, TYPE_B: RXT_B},
    )
    # Sorted plugin ids: rextio-alpha → ordinal 0, rextio-beta → ordinal 1.
    a_bind = core_owned_guard_binding_name(PLUGIN_A, ordinal=0)
    b_bind = core_owned_guard_binding_name(PLUGIN_B, ordinal=1)
    a_idx = out.index(f"let {a_bind} = AlphaGuard::enter();")
    b_idx = out.index(f"let {b_bind} = BetaGuard::enter();")
    assert a_idx < b_idx


def test_colliding_sanitized_plugin_ids_get_distinct_bindings() -> None:
    """rextio-a-b and rextio-a_b must not share a binding (shadow/early Drop)."""
    id_dash = "rextio-a-b"
    id_under = "rextio-a_b"
    bindings = allocate_function_scope_guard_bindings([id_under, id_dash])
    assert bindings[id_dash] != bindings[id_under]
    assert bindings == {
        id_dash: "__rextio_plugin_scope_guard_0",
        id_under: "__rextio_plugin_scope_guard_1",
    }

    # Codegen with two claims whose plugin ids collide under naive sanitization.
    dash_claim = PluginClaimIR(
        plugin_id=id_dash,
        rule_id=f"{id_dash}/step",
        kind="call",
        target="dash.step",
        operand_types=("int",),
        result_type="int",
    )
    under_claim = PluginClaimIR(
        plugin_id=id_under,
        rule_id=f"{id_under}/step",
        kind="call",
        target="under.step",
        operand_types=("int",),
        result_type="int",
    )
    # under(dash(x))
    inner = CallIR(function="dash.step", args=[NameIR(id="x")], claim=dash_claim)
    outer = CallIR(function="under.step", args=[inner], claim=under_claim)
    function = FunctionIR(
        name="both",
        qualname="kernels.both",
        module_name="kernels",
        params=[ParamIR("x", RxtInt())],
        return_type=RxtInt(),
        body=BlockIR(statements=[ReturnIR(value=outer)]),
        plugin_lowered=True,
    )
    out = generate_rust_module(
        ModuleIR(functions=[function]),
        plugin_providers={
            id_dash: CollidingIdProvider(id_dash, "DashGuard::enter()"),
            id_under: CollidingIdProvider(id_under, "UnderGuard::enter()"),
        },
    )
    assert "let __rextio_plugin_scope_guard_0 = DashGuard::enter();" in out
    assert "let __rextio_plugin_scope_guard_1 = UnderGuard::enter();" in out
    # Exactly one binding each — no rebinding/shadow of the first name.
    assert out.count("__rextio_plugin_scope_guard_0") == 1
    assert out.count("__rextio_plugin_scope_guard_1") == 1


def test_type_only_usage_facts() -> None:
    provider = TypeOnlyGuardProvider()
    out = generate_rust_module(
        ModuleIR(functions=[_type_only_function()]),
        plugin_providers={PLUGIN_A: provider},
        plugin_types_by_key={TYPE_A: RXT_A},
    )
    binding = core_owned_guard_binding_name(PLUGIN_A, ordinal=0)
    assert f"let {binding} = TypeOnlyGuard::enter();" in out
    assert provider.calls
    ctx = provider.calls[0]
    assert ctx.used_rule_ids == ()
    assert ctx.used_type_keys == (TYPE_A,)


def test_usage_walker_finds_dict_tuple_and_comprehension_claims() -> None:
    claim = _claim(PLUGIN_A, RULE_A, "alpha.double")
    claimed = CallIR(function="alpha.double", args=[NameIR(id="x")], claim=claim)
    # DictIR stores list[tuple[ExprIR, ExprIR]] — the old walker missed these.
    dict_expr = DictIR(items=[(LiteralIR(0), claimed)])
    function = FunctionIR(
        name="from_dict",
        qualname="kernels.from_dict",
        module_name="kernels",
        params=[ParamIR("x", RXT_A)],
        return_type=RXT_A,
        body=BlockIR(statements=[ReturnIR(value=dict_expr)]),
        plugin_lowered=True,
    )
    usage = collect_function_plugin_usage(function)
    assert PLUGIN_A in usage
    assert usage[PLUGIN_A][0] == (RULE_A,)

    # Comprehension generator iterable also nests claims.
    claim2 = _claim(PLUGIN_A, RULE_A, "alpha.double")
    gen = ComprehensionGeneratorIR(
        target=NameIR(id="y"),
        iterable=CallIR(function="alpha.double", args=[NameIR(id="x")], claim=claim2),
        conditions=[],
    )
    comp = ListComprehensionIR(item=NameIR(id="y"), generators=[gen])
    function2 = FunctionIR(
        name="from_comp",
        qualname="kernels.from_comp",
        module_name="kernels",
        params=[ParamIR("x", RXT_A)],
        return_type=RXT_A,
        body=BlockIR(statements=[ReturnIR(value=comp)]),
        plugin_lowered=True,
    )
    usage2 = collect_function_plugin_usage(function2)
    assert usage2[PLUGIN_A][0] == (RULE_A,)


def test_usage_walker_finds_try_handler_claims() -> None:
    claim = _claim(PLUGIN_A, RULE_A, "alpha.double")
    claimed = CallIR(function="alpha.double", args=[NameIR(id="x")], claim=claim)
    try_stmt = TryIR(
        body=BlockIR(statements=[]),
        handlers=(
            ExceptHandlerIR(
                exception="ValueError",
                body=BlockIR(statements=[EffectCallIR(call=claimed)]),
            ),
        ),
        finalbody=BlockIR(statements=[]),
    )
    function = FunctionIR(
        name="from_try",
        qualname="kernels.from_try",
        module_name="kernels",
        params=[ParamIR("x", RXT_A)],
        return_type=RXT_A,
        body=BlockIR(statements=[try_stmt, ReturnIR(value=NameIR(id="x"))]),
        plugin_lowered=True,
    )
    usage = collect_function_plugin_usage(function)
    assert usage[PLUGIN_A][0] == (RULE_A,)


@pytest.mark.parametrize(
    "rust",
    [
        "let x = 1",
        "Guard::enter(x)",
        "Guard::enter(1)",
        "panic!()",
        "unwrap()",
        "{ Guard::enter() }",
        "Guard::enter()?;",
        "Guard::enter()?",
        "a + b",
        "obj.method()",
        "x",
        "Guard::enter();",
        "std::mem::forget(g)",
    ],
)
def test_invalid_guard_expressions_rejected(rust: str) -> None:
    with pytest.raises(RustCodegenError, match="zero-argument path call"):
        generate_rust_module(
            ModuleIR(functions=[_claimed_function()]),
            plugin_providers={PLUGIN_A: BrokenGuardProvider(rust)},
            plugin_types_by_key={TYPE_A: RXT_A},
        )


def test_validate_accepts_only_zero_arg_path_calls() -> None:
    ok = validate_function_scope_guard(
        PLUGIN_A, "kernels.f", PluginFunctionScopeGuard(rust="tch::no_grad_guard()")
    )
    assert ok.rust == "tch::no_grad_guard()"
    ok2 = validate_function_scope_guard(
        PLUGIN_A, "kernels.f", PluginFunctionScopeGuard(rust="AlphaGuard::enter()")
    )
    assert ok2.rust == "AlphaGuard::enter()"
    with pytest.raises(RustCodegenError, match="zero-argument path call"):
        validate_function_scope_guard(
            PLUGIN_A, "kernels.f", PluginFunctionScopeGuard(rust="Guard::enter(x)")
        )


def test_hook_exception_is_rust_codegen_error() -> None:
    with pytest.raises(RustCodegenError, match="guard boom"):
        generate_rust_module(
            ModuleIR(functions=[_claimed_function()]),
            plugin_providers={PLUGIN_A: ExceptionGuardProvider()},
            plugin_types_by_key={TYPE_A: RXT_A},
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
    binding = core_owned_guard_binding_name(PLUGIN_A, ordinal=0)
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
