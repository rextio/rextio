"""Plugin API 1.2: fusion-aware lowering and 1.1 legacy compatibility."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from rextio.analyzer.project_scanner import analyze_project
from rextio.codegen.rust.generator import generate_rust_module
from rextio.config.schema import RextioConfig
from rextio.ir.lowering import PluginTypeMaps, lower_project
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

PLUGIN_ID = "rextio-numpy"
F64_KEY = "rextio-numpy/f64-1d"

F64_ARR1 = PluginType(
    key=F64_KEY,
    annotations=("rextio_numpy.types.F64Arr1",),
    rust_type="ndarray::Array1<f64>",
    conversion=BoundaryConversion(
        param_rust="numpy::PyReadonlyArray1<'py, f64>",
        param_expr="{param}.as_array().to_owned()",
        return_rust="pyo3::Bound<'py, numpy::PyArray1<f64>>",
        return_expr="numpy::ToPyArray::to_pyarray(&{value}, py)",
    ),
)

RXT_F64 = RxtPluginType(
    key=F64_KEY,
    native_rust=F64_ARR1.rust_type,
    param_rust=F64_ARR1.conversion.param_rust,
    param_expr=F64_ARR1.conversion.param_expr,
    return_rust=F64_ARR1.conversion.return_rust,
    return_expr=F64_ARR1.conversion.return_expr,
)

TYPE_MAPS = PluginTypeMaps(
    by_key={F64_KEY: RXT_F64},
    by_spelling={"rextio_numpy.types.F64Arr1": RXT_F64},
)
TYPES_BY_KEY = {F64_KEY: RXT_F64}


def _expr_depth(expr) -> int:
    if expr is None or expr.kind in {"leaf", "literal"}:
        return 0
    if not expr.children:
        return 1
    return 1 + max(_expr_depth(child) for child in expr.children)


class FusionProvider:
    """Claims multi-op trees as one fused lower; simple binops elementwise."""

    plugin_id = PLUGIN_ID
    api_version = "1.2"

    def __init__(self) -> None:
        self.lower_calls: list[tuple[str, tuple[str, ...], tuple[str, ...]]] = []

    def claim(self, site: ClaimSite, config: RextioConfig):
        if site.kind != "binop" or site.target not in {"+", "-", "*"}:
            return NotCovered()
        if site.expression is not None and _expr_depth(site.expression) >= 2:
            return Claimed(
                rule_id="rextio-numpy/fusion",
                result_type=F64_KEY,
                operand_mode="leaves",
            )
        return Claimed(rule_id="rextio-numpy/elementwise", result_type=F64_KEY)

    def lower(self, site: ClaimSite, ctx: LoweringContext) -> LoweredExpr:
        self.lower_calls.append((site.rule_id or "", ctx.operands, ctx.leaf_operands))
        if site.rule_id == "rextio-numpy/fusion":
            assert ctx.operands == ()
            leaves = ", ".join(f"&{leaf}" for leaf in ctx.leaf_operands)
            return LoweredExpr(
                rust=f"__rextio_numpy_fuse({leaves})",
                helpers=(
                    "fn __rextio_numpy_fuse(a: &ndarray::Array1<f64>, b: &ndarray::Array1<f64>, "
                    "c: &ndarray::Array1<f64>, d: &ndarray::Array1<f64>, e: &ndarray::Array1<f64>) "
                    "-> ndarray::Array1<f64> { a * b + c * d - e }",
                ),
            )
        # Elementwise path uses classic operands (direct mode).
        assert ctx.leaf_operands == ()
        op = {"+": "+", "-": "-", "*": "*"}.get(site.target, site.target)
        return LoweredExpr(rust=f"(&{ctx.operands[0]} {op} &{ctx.operands[1]})")


class Legacy11Provider:
    """API 1.1-shaped provider: only reads operands, ignores new fields."""

    plugin_id = PLUGIN_ID
    api_version = "1.1"

    def claim(self, site: ClaimSite, config: RextioConfig):
        if site.kind == "binop" and site.target in {"+", "-", "*"}:
            return Claimed(rule_id="rextio-numpy/elementwise", result_type=F64_KEY)
        if site.kind == "call" and site.target == "numpy.dot":
            return Claimed(rule_id="rextio-numpy/dot", result_type="float")
        return NotCovered()

    def lower(self, site: ClaimSite, ctx: LoweringContext) -> LoweredExpr:
        # Deliberately only use the 1.1 surface.
        if site.kind == "call":
            return LoweredExpr(rust=f"{ctx.operands[0]}.dot(&{ctx.operands[1]})")
        op = site.target
        return LoweredExpr(rust=f"(&{ctx.operands[0]} {op} &{ctx.operands[1]})")


class KeywordLowerProvider:
    """Claims keyword reductions and embeds literal metadata in the emission."""

    plugin_id = PLUGIN_ID
    api_version = "1.2"

    def __init__(self) -> None:
        self.seen_keywords: list[tuple] = []

    def claim(self, site: ClaimSite, config: RextioConfig):
        if site.kind == "call" and site.target == "numpy.sum":
            return Claimed(rule_id="rextio-numpy/sum", result_type="float")
        return NotCovered()

    def lower(self, site: ClaimSite, ctx: LoweringContext) -> LoweredExpr:
        self.seen_keywords.append(tuple((kw.name, kw.literal.to_dict()) for kw in site.keywords))
        if site.keywords:
            axis = site.keywords[0].literal
            return LoweredExpr(rust=f"{ctx.operands[0]}.sum_axis({axis.value!r})")
        return LoweredExpr(rust=f"{ctx.operands[0]}.sum()")


def make_registry(provider: object) -> PluginRegistry:
    plugin = RextioPlugin(
        id=PLUGIN_ID,
        name=PLUGIN_ID,
        packages=("numpy",),
        rules_provided=True,
        api_version=getattr(provider, "api_version", "1.2"),
        lowering_provided=True,
    )
    return PluginRegistry(
        enabled=(PLUGIN_ID,),
        discovered=(plugin,),
        active=(plugin,),
        types=(PluginTypeBinding(plugin_id=PLUGIN_ID, plugin_type=F64_ARR1),),
        providers=(PluginProviderBinding(plugin_id=PLUGIN_ID, provider=provider),),
    )


def write_module(root: Path, contents: str) -> None:
    path = root / "src" / "myapp" / "kernels.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")


def analyze_with(root: Path, provider: object):
    return analyze_project(
        root, plugin_registry=make_registry(provider), plugin_config=RextioConfig()
    )


FUSION_MODULE = """
from rextio_numpy.types import F64Arr1

def poly(a: F64Arr1, b: F64Arr1, c: F64Arr1, d: F64Arr1, e: F64Arr1) -> F64Arr1:
    return a * b + c * d - e
"""


def test_fusion_provider_lowers_multi_op_as_one_fused_call(tmp_path: Path) -> None:
    write_module(tmp_path, FUSION_MODULE)
    provider = FusionProvider()
    analysis = analyze_with(tmp_path, provider)
    module_ir = lower_project(analysis, plugin_types=TYPE_MAPS)
    # Outer claim must be leaves mode with expression mapping a,b,c,d,e.
    function = module_ir.functions[0]
    from rextio.ir.nodes import BinaryOpIR, ReturnIR

    body = function.body.statements[-1]
    assert isinstance(body, ReturnIR)
    assert isinstance(body.value, BinaryOpIR)
    assert body.value.claim is not None
    assert body.value.claim.operand_mode == "leaves"
    assert body.value.claim.expression is not None
    source = generate_rust_module(
        module_ir,
        plugin_providers={PLUGIN_ID: provider},
        plugin_types_by_key=TYPES_BY_KEY,
    )
    assert "__rextio_numpy_fuse(" in source
    fusion_lowers = [call for call in provider.lower_calls if call[0] == "rextio-numpy/fusion"]
    assert fusion_lowers, provider.lower_calls
    _rule, operands, leaf_operands = fusion_lowers[-1]
    assert operands == ()
    # Exact leaf order by leaf_index: a, b, c, d, e
    assert len(leaf_operands) == 5
    assert [op.replace(" ", "") for op in leaf_operands] == ["a", "b", "c", "d", "e"]


def test_legacy_api_11_provider_still_lowers_simple_patterns(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        """
from rextio_numpy.types import F64Arr1
import numpy as np

def add(a: F64Arr1, b: F64Arr1) -> F64Arr1:
    return a + b

def dot(a: F64Arr1, b: F64Arr1) -> float:
    return np.dot(a, b)
""",
    )
    provider = Legacy11Provider()
    analysis = analyze_with(tmp_path, provider)
    module_ir = lower_project(analysis, plugin_types=TYPE_MAPS)
    source = generate_rust_module(
        module_ir,
        plugin_providers={PLUGIN_ID: provider},
        plugin_types_by_key=TYPES_BY_KEY,
    )
    assert "+ &" in source or "&" in source
    assert ".dot(&" in source


def test_legacy_api_11_provider_lowers_multi_op_as_nested_elementwise(tmp_path: Path) -> None:
    """Without fusion rules, multi-op trees still lower via nested 1.1 claims."""
    write_module(tmp_path, FUSION_MODULE)
    provider = Legacy11Provider()
    analysis = analyze_with(tmp_path, provider)
    module_ir = lower_project(analysis, plugin_types=TYPE_MAPS)
    source = generate_rust_module(
        module_ir,
        plugin_providers={PLUGIN_ID: provider},
        plugin_types_by_key=TYPES_BY_KEY,
    )
    # Nested elementwise ops appear (no fusion helper).
    assert "__rextio_numpy_fuse" not in source
    assert "*" in source or "+ &" in source or "- &" in source


def test_keyword_literal_reaches_lower(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        """
from rextio_numpy.types import F64Arr1
import numpy as np

def reduce(a: F64Arr1) -> float:
    return np.sum(a, axis=0)
""",
    )
    provider = KeywordLowerProvider()
    analysis = analyze_with(tmp_path, provider)
    module_ir = lower_project(analysis, plugin_types=TYPE_MAPS)
    source = generate_rust_module(
        module_ir,
        plugin_providers={PLUGIN_ID: provider},
        plugin_types_by_key=TYPES_BY_KEY,
    )
    assert provider.seen_keywords == [(("axis", {"is_literal": True, "value_kind": "int", "value": 0}),)]
    assert "sum_axis(0)" in source


def test_legacy_11_cannot_claim_keyword_call(tmp_path: Path) -> None:
    """Greedy 1.1 provider must not claim np.dot(a, b=b); stays RXT010/fallback."""

    class Greedy11(Legacy11Provider):
        def claim(self, site: ClaimSite, config: RextioConfig):
            # Would wrongly accept keyword form if offered.
            if site.kind == "call" and site.target == "numpy.dot":
                return Claimed(rule_id="rextio-numpy/dot", result_type="float")
            return super().claim(site, config)

        def lower(self, site: ClaimSite, ctx: LoweringContext) -> LoweredExpr:
            raise AssertionError("1.1 provider must not lower keyword calls")

    write_module(
        tmp_path,
        """
from rextio_numpy.types import F64Arr1
import numpy as np

def bad(a: F64Arr1, b: F64Arr1) -> float:
    return np.dot(a, b=b)
""",
    )
    provider = Greedy11()
    analysis = analyze_with(tmp_path, provider)
    from rextio.analyzer.project_scanner import analyze_project as _ap  # noqa: F401

    function = None
    for module in analysis.modules:
        for fn in module.functions:
            if fn.name == "bad":
                function = fn
    assert function is not None
    assert function.plugin_claims == []
    assert function.accepted is False
    assert any(
        d.code == "RXT010" and "keyword" in d.message for d in function.diagnostics
    ) or function.native_status in {"not-candidate", "rejected"}


def test_leaves_mode_does_not_invoke_nested_direct_lower(tmp_path: Path) -> None:
    """Outer leaves fusion must not call nested direct providers (no marker helpers)."""

    class NestedMarkerProvider(FusionProvider):
        def lower(self, site: ClaimSite, ctx: LoweringContext) -> LoweredExpr:
            self.lower_calls.append((site.rule_id or "", ctx.operands, ctx.leaf_operands))
            if site.rule_id == "rextio-numpy/fusion":
                leaves = ", ".join(f"&{leaf}" for leaf in ctx.leaf_operands)
                return LoweredExpr(rust=f"__rextio_numpy_fuse({leaves})")
            # Nested direct elementwise: emit a distinctive helper if ever called.
            return LoweredExpr(
                rust=f"__rextio_nested_marker(&{ctx.operands[0]}, &{ctx.operands[1]})",
                helpers=(
                    "fn __rextio_nested_marker(a: &ndarray::Array1<f64>, "
                    "b: &ndarray::Array1<f64>) -> ndarray::Array1<f64> { a + b }",
                ),
                uses=("use rextio_nested_marker_use as _;",),
            )

    write_module(tmp_path, FUSION_MODULE)
    provider = NestedMarkerProvider()
    analysis = analyze_with(tmp_path, provider)
    module_ir = lower_project(analysis, plugin_types=TYPE_MAPS)
    source = generate_rust_module(
        module_ir,
        plugin_providers={PLUGIN_ID: provider},
        plugin_types_by_key=TYPES_BY_KEY,
    )
    assert "__rextio_numpy_fuse(" in source
    assert "__rextio_nested_marker" not in source
    assert "rextio_nested_marker_use" not in source
    # Only the outer fusion lower for the multi-op root should run for the
    # returned expression; elementwise lowers may exist if other sites were
    # claimed independently, but nested markers must not appear in the crate.
    fusion = [c for c in provider.lower_calls if c[0] == "rextio-numpy/fusion"]
    assert fusion
    assert fusion[-1][1] == ()  # operands empty in leaves mode
    assert len(fusion[-1][2]) == 5


def test_direct_mode_nested_lowering_unchanged(tmp_path: Path) -> None:
    """Direct-mode providers still nest-lower intermediate binops."""

    class DirectOnly(FusionProvider):
        def claim(self, site: ClaimSite, config: RextioConfig):
            if site.kind == "binop" and site.target in {"+", "-", "*"}:
                return Claimed(rule_id="rextio-numpy/elementwise", result_type=F64_KEY)
            return NotCovered()

    write_module(
        tmp_path,
        """
from rextio_numpy.types import F64Arr1

def add3(a: F64Arr1, b: F64Arr1, c: F64Arr1) -> F64Arr1:
    return a + b + c
""",
    )
    provider = DirectOnly()
    analysis = analyze_with(tmp_path, provider)
    module_ir = lower_project(analysis, plugin_types=TYPE_MAPS)
    source = generate_rust_module(
        module_ir,
        plugin_providers={PLUGIN_ID: provider},
        plugin_types_by_key=TYPES_BY_KEY,
    )
    assert "__rextio_numpy_fuse" not in source
    # Two nested elementwise lowers (inner a+b and outer +c).
    elementwise = [c for c in provider.lower_calls if c[0] == "rextio-numpy/elementwise"]
    assert len(elementwise) >= 2
    for _rule, operands, leaf_operands in elementwise:
        assert len(operands) == 2
        assert leaf_operands == ()


def test_leaf_index_swapped_duplicate_gap_fail_closed() -> None:
    """LTR DFS encounter sequence must be 0..n-1; swaps/dups/gaps fail."""
    from rextio.codegen.rust.errors import RustCodegenError
    from rextio.codegen.rust.generator import _FunctionRenderer
    from rextio.ir.nodes import NameIR, PluginClaimIR
    from rextio.plugins.api import ClaimExpr

    def make_renderer() -> _FunctionRenderer:
        from rextio.ir.nodes import BlockIR, FunctionIR, ParamIR

        fn = FunctionIR(
            name="f",
            qualname="app.f",
            module_name="app",
            params=[
                ParamIR(name="a", type=RXT_F64),
                ParamIR(name="b", type=RXT_F64),
            ],
            return_type=RXT_F64,
            body=BlockIR(statements=[]),
            plugin_lowered=True,
        )
        return _FunctionRenderer(
            fn,
            native_names_by_qualname={"app.f": "f"},
            native_names={("app", "f"): "f"},
            native_return_types={"app.f": RXT_F64},
            mode="pyo3",
            plugin_providers={PLUGIN_ID: FusionProvider()},
            plugin_types_by_key=TYPES_BY_KEY,
        )

    def claim_ir(expr: ClaimExpr) -> PluginClaimIR:
        return PluginClaimIR(
            plugin_id=PLUGIN_ID,
            rule_id="rextio-numpy/fusion",
            kind="binop",
            target="+",
            operand_types=(F64_KEY, F64_KEY),
            result_type=F64_KEY,
            expression=expr,
            operand_mode="leaves",
        )

    renderer = make_renderer()
    operands = [NameIR("a"), NameIR("b")]

    # Swapped: encounter order is 1 then 0.
    swapped = ClaimExpr(
        kind="binop",
        target="+",
        children=(
            ClaimExpr(kind="leaf", leaf_index=1, leaf_kind="name", result_type=F64_KEY),
            ClaimExpr(kind="leaf", leaf_index=0, leaf_kind="name", result_type=F64_KEY),
        ),
    )
    assert renderer._render_fusion_leaf_operands(swapped, operands) is None

    # Duplicate indexes.
    dup = ClaimExpr(
        kind="binop",
        target="+",
        children=(
            ClaimExpr(kind="leaf", leaf_index=0, leaf_kind="name", result_type=F64_KEY),
            ClaimExpr(kind="leaf", leaf_index=0, leaf_kind="name", result_type=F64_KEY),
        ),
    )
    assert renderer._render_fusion_leaf_operands(dup, operands) is None

    # Gap: 0 then 2.
    gap = ClaimExpr(
        kind="binop",
        target="+",
        children=(
            ClaimExpr(kind="leaf", leaf_index=0, leaf_kind="name", result_type=F64_KEY),
            ClaimExpr(kind="leaf", leaf_index=2, leaf_kind="name", result_type=F64_KEY),
        ),
    )
    assert renderer._render_fusion_leaf_operands(gap, operands) is None

    # Normal 0,1 succeeds with ordered leaves.
    ok = ClaimExpr(
        kind="binop",
        target="+",
        children=(
            ClaimExpr(kind="leaf", leaf_index=0, leaf_kind="name", result_type=F64_KEY),
            ClaimExpr(kind="leaf", leaf_index=1, leaf_kind="name", result_type=F64_KEY),
        ),
    )
    rendered = renderer._render_fusion_leaf_operands(ok, operands)
    assert rendered is not None
    assert [x.replace(" ", "") for x in rendered] == ["a", "b"]

    # Unknown operand_mode fails closed (not coerced to direct).
    bad = replace(claim_ir(ok), operand_mode="wat")
    with pytest.raises(RustCodegenError, match="unsupported operand_mode"):
        renderer.render_plugin_claim(bad, operands)


def test_all_literal_leaves_mode_succeeds_with_empty_leaf_operands() -> None:
    """All-literal leaves-safe tree is valid: leaf_operands=(), operands=()."""
    from rextio.codegen.rust.generator import _FunctionRenderer
    from rextio.ir.nodes import BlockIR, FunctionIR, LiteralIR, PluginClaimIR
    from rextio.plugins.api import ClaimExpr, ClaimLiteral

    class AllLiteralProvider:
        plugin_id = PLUGIN_ID
        api_version = "1.2"
        seen: list = []

        def lower(self, site: ClaimSite, ctx: LoweringContext) -> LoweredExpr:
            self.seen.append((ctx.operands, ctx.leaf_operands))
            return LoweredExpr(rust="0.0")

    provider = AllLiteralProvider()
    expr = ClaimExpr(
        kind="binop",
        target="+",
        children=(
            ClaimExpr(
                kind="literal",
                literal=ClaimLiteral(is_literal=True, value=1),
                result_type="int",
            ),
            ClaimExpr(
                kind="literal",
                literal=ClaimLiteral(is_literal=True, value=2),
                result_type="int",
            ),
        ),
    )
    claim = PluginClaimIR(
        plugin_id=PLUGIN_ID,
        rule_id="rextio-numpy/fusion",
        kind="binop",
        target="+",
        operand_types=("int", "int"),
        result_type="float",
        expression=expr,
        operand_mode="leaves",
    )
    fn = FunctionIR(
        name="f",
        qualname="app.f",
        module_name="app",
        params=[],
        return_type=RXT_F64,
        body=BlockIR(statements=[]),
        plugin_lowered=True,
    )
    renderer = _FunctionRenderer(
        fn,
        native_names_by_qualname={"app.f": "f"},
        native_names={("app", "f"): "f"},
        native_return_types={"app.f": RXT_F64},
        mode="pyo3",
        plugin_providers={PLUGIN_ID: provider},
        plugin_types_by_key=TYPES_BY_KEY,
    )
    rust = renderer.render_plugin_claim(claim, [LiteralIR(1), LiteralIR(2)])
    assert "0.0" in rust
    assert provider.seen == [((), ())]


def test_legacy_provider_cannot_observe_12_fields_or_leaf_rendering() -> None:
    """Hand-built IR with 1.2 metadata: api 1.1 provider gets legacy ClaimSite."""
    from rextio.codegen.rust.errors import RustCodegenError
    from rextio.codegen.rust.generator import _FunctionRenderer
    from rextio.ir.nodes import BlockIR, FunctionIR, NameIR, ParamIR, PluginClaimIR
    from rextio.plugins.api import ClaimExpr, ClaimLiteral, KeywordArg

    class LegacyObserver:
        plugin_id = PLUGIN_ID
        api_version = "1.1"
        sites: list[ClaimSite] = []
        ctxs: list = []

        def lower(self, site: ClaimSite, ctx: LoweringContext) -> LoweredExpr:
            self.sites.append(site)
            self.ctxs.append(ctx)
            return LoweredExpr(rust=f"(&{ctx.operands[0]} + &{ctx.operands[1]})")

    provider = LegacyObserver()
    expr = ClaimExpr(
        kind="binop",
        target="+",
        children=(
            ClaimExpr(kind="leaf", leaf_index=0, leaf_kind="name", result_type=F64_KEY),
            ClaimExpr(kind="leaf", leaf_index=1, leaf_kind="name", result_type=F64_KEY),
        ),
    )
    claim = PluginClaimIR(
        plugin_id=PLUGIN_ID,
        rule_id="rextio-numpy/elementwise",
        kind="binop",
        target="+",
        operand_types=(F64_KEY, F64_KEY),
        result_type=F64_KEY,
        operand_literals=(
            ClaimLiteral(is_literal=True, value=0),
            ClaimLiteral(),
        ),
        keywords=(KeywordArg(name="axis", literal=ClaimLiteral(is_literal=True, value=0)),),
        expression=expr,
        operand_mode="direct",
    )
    fn = FunctionIR(
        name="f",
        qualname="app.f",
        module_name="app",
        params=[
            ParamIR(name="a", type=RXT_F64),
            ParamIR(name="b", type=RXT_F64),
        ],
        return_type=RXT_F64,
        body=BlockIR(statements=[]),
        plugin_lowered=True,
    )
    renderer = _FunctionRenderer(
        fn,
        native_names_by_qualname={"app.f": "f"},
        native_names={("app", "f"): "f"},
        native_return_types={"app.f": RXT_F64},
        mode="pyo3",
        plugin_providers={PLUGIN_ID: provider},
        plugin_types_by_key=TYPES_BY_KEY,
    )
    renderer.render_plugin_claim(claim, [NameIR("a"), NameIR("b")])
    site = provider.sites[0]
    assert site.operand_literals == ()
    assert site.keywords == ()
    assert site.expression is None
    assert provider.ctxs[0].leaf_operands == ()
    assert len(provider.ctxs[0].operands) == 2

    # leaves-mode IR is rejected for legacy provider.
    leaves_claim = PluginClaimIR(
        plugin_id=PLUGIN_ID,
        rule_id="rextio-numpy/fusion",
        kind="binop",
        target="+",
        operand_types=(F64_KEY, F64_KEY),
        result_type=F64_KEY,
        expression=expr,
        operand_mode="leaves",
    )
    with pytest.raises(RustCodegenError, match="leaves mode requires api_version"):
        renderer.render_plugin_claim(leaves_claim, [NameIR("a"), NameIR("b")])


def test_subsumed_descendant_claims_not_lowered(tmp_path: Path) -> None:
    """Analysis may carry descendant claims; only outer leaves lower runs."""

    class Counting(FusionProvider):
        fresh_names: list[str] = []

        def lower(self, site: ClaimSite, ctx: LoweringContext) -> LoweredExpr:
            # Capture fresh-name allocation if any (fusion path should not need
            # nested lowers' fresh names).
            name = ctx.fresh_name("probe")
            self.fresh_names.append(name)
            return super().lower(site, ctx)

    write_module(tmp_path, FUSION_MODULE)
    provider = Counting()
    analysis = analyze_with(tmp_path, provider)
    function = None
    for module in analysis.modules:
        for fn in module.functions:
            if fn.name == "poly":
                function = fn
    assert function is not None
    # Multiple binop claims recorded (descendants + outer).
    assert len(function.plugin_claims) >= 3
    leaves_claims = [c for c in function.plugin_claims if c.operand_mode == "leaves"]
    assert len(leaves_claims) >= 1
    module_ir = lower_project(analysis, plugin_types=TYPE_MAPS)
    source = generate_rust_module(
        module_ir,
        plugin_providers={PLUGIN_ID: provider},
        plugin_types_by_key=TYPES_BY_KEY,
    )
    assert "__rextio_numpy_fuse(" in source
    fusion = [c for c in provider.lower_calls if c[0] == "rextio-numpy/fusion"]
    elementwise = [c for c in provider.lower_calls if c[0] == "rextio-numpy/elementwise"]
    # Only the effective outer leaves claim is lowered for the returned multi-op.
    assert len(fusion) == 1
    assert elementwise == []
    # One fresh name from the single outer lower probe (not nested counts).
    assert len(provider.fresh_names) == 1
