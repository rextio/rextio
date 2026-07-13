"""Plugin API 1.2: claim-site literal/keyword metadata and expression trees.

Covers the additive Wave 2 contract: keyword/literal metadata reaches lower(),
absent vs literal None is distinct, tuple axis literals, cache-key separation,
stable to_dict, nested span matching, and fail-closed dynamic keywords.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rextio.analyzer.plugin_claims import ClaimEngine, extract_claim_literal
from rextio.analyzer.project_scanner import analyze_project
from rextio.config.schema import RextioConfig
from rextio.plugins.api import (
    BoundaryConversion,
    Claimed,
    ClaimExpr,
    ClaimLiteral,
    ClaimSite,
    KeywordArg,
    NON_LITERAL,
    NotCovered,
    PluginType,
)
from rextio.plugins.models import (
    PluginProviderBinding,
    PluginRegistry,
    PluginTypeBinding,
    RextioPlugin,
)

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


class MetadataCapturingProvider:
    """Records claim sites and echoes keyword/literal data at lower time."""

    plugin_id = "rextio-numpy"
    api_version = "1.2"

    def __init__(self) -> None:
        self.claim_sites: list[ClaimSite] = []
        self.lower_sites: list[ClaimSite] = []
        self.lower_keywords: list[tuple[KeywordArg, ...]] = []
        self.lower_literals: list[tuple[ClaimLiteral, ...]] = []

    def claim(self, site: ClaimSite, config: RextioConfig):
        self.claim_sites.append(site)
        if site.kind == "call" and site.target in {"numpy.sum", "numpy.mean", "numpy.dot"}:
            if site.keywords:
                # Accept axis-style keyword reductions when literals are static.
                axis = next((kw for kw in site.keywords if kw.name == "axis"), None)
                if axis is not None and not axis.literal.is_literal:
                    return NotCovered()
            result = "float" if site.target != "numpy.dot" else "float"
            if site.target == "numpy.dot":
                result = "float"
            elif site.operand_types and site.operand_types[0] == F64_KEY:
                result = "float"
            else:
                result = "float"
            return Claimed(rule_id="rextio-numpy/meta", result_type=result)
        if site.kind == "binop" and site.target in {"+", "-", "*"}:
            return Claimed(rule_id="rextio-numpy/binop", result_type=F64_KEY)
        return NotCovered()

    def lower(self, site: ClaimSite, ctx) -> object:
        from rextio.plugins.api import LoweredExpr

        self.lower_sites.append(site)
        self.lower_keywords.append(site.keywords)
        self.lower_literals.append(site.operand_literals)
        if site.keywords:
            parts = [f"{kw.name}={kw.literal.to_dict()}" for kw in site.keywords]
            return LoweredExpr(rust=f"meta_kw({', '.join(ctx.operands)}, {', '.join(parts)})")
        return LoweredExpr(rust=f"meta({', '.join(ctx.operands)})")


def make_registry(provider: object) -> PluginRegistry:
    plugin = RextioPlugin(
        id="rextio-numpy",
        name="rextio-numpy",
        packages=("numpy",),
        rules_provided=True,
        api_version=getattr(provider, "api_version", "1.2"),
        lowering_provided=True,
    )
    return PluginRegistry(
        enabled=("rextio-numpy",),
        discovered=(plugin,),
        active=(plugin,),
        types=(PluginTypeBinding(plugin_id="rextio-numpy", plugin_type=F64_ARR1),),
        providers=(PluginProviderBinding(plugin_id="rextio-numpy", provider=provider),),
    )


def write_module(root: Path, contents: str) -> None:
    path = root / "src" / "myapp" / "kernels.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")


def function_named(analysis, qualname: str):
    for module in analysis.modules:
        for function in module.functions:
            if function.qualname == qualname:
                return function
    raise AssertionError(f"function not found: {qualname}")


def test_extract_claim_literal_shapes() -> None:
    import ast

    assert extract_claim_literal(ast.Constant(value=None)) == ClaimLiteral(
        is_literal=True, value=None
    )
    assert extract_claim_literal(ast.Constant(value=0)) == ClaimLiteral(is_literal=True, value=0)
    assert extract_claim_literal(ast.Constant(value=-3)) == ClaimLiteral(is_literal=True, value=-3)
    assert extract_claim_literal(ast.Constant(value=True)) is NON_LITERAL or (
        extract_claim_literal(ast.Constant(value=True)).is_literal is False
    )
    assert extract_claim_literal(ast.Constant(value=1.5)).is_literal is False
    tree = ast.parse("(-1, 2)", mode="eval").body
    assert extract_claim_literal(tree) == ClaimLiteral(is_literal=True, value=(-1, 2))
    assert extract_claim_literal(ast.Name(id="x", ctx=ast.Load())).is_literal is False


def test_claim_literal_to_dict_stable() -> None:
    assert ClaimLiteral().to_dict() == {"is_literal": False}
    assert ClaimLiteral(is_literal=True, value=None).to_dict() == {
        "is_literal": True,
        "value_kind": "none",
        "value": None,
    }
    assert ClaimLiteral(is_literal=True, value=-1).to_dict() == {
        "is_literal": True,
        "value_kind": "int",
        "value": -1,
    }
    assert ClaimLiteral(is_literal=True, value=(0, 1)).to_dict() == {
        "is_literal": True,
        "value_kind": "int_tuple",
        "value": [0, 1],
    }


def test_absent_vs_literal_none_keyword(tmp_path: Path) -> None:
    provider = MetadataCapturingProvider()
    write_module(
        tmp_path,
        """
from rextio_numpy.types import F64Arr1
import numpy as np

def with_none(a: F64Arr1) -> float:
    return np.sum(a, axis=None)

def without_axis(a: F64Arr1) -> float:
    return np.sum(a)
""",
    )
    analysis = analyze_project(
        tmp_path, plugin_registry=make_registry(provider), plugin_config=RextioConfig()
    )
    with_none = function_named(analysis, "myapp.kernels.with_none")
    without = function_named(analysis, "myapp.kernels.without_axis")
    assert with_none.accepted is True
    assert without.accepted is True

    none_claim = with_none.plugin_claims[0]
    bare_claim = without.plugin_claims[0]
    assert len(none_claim.keywords) == 1
    assert none_claim.keywords[0].name == "axis"
    assert none_claim.keywords[0].literal == ClaimLiteral(is_literal=True, value=None)
    assert bare_claim.keywords == ()
    # Present keyword with literal None is distinct from absent keyword.
    assert none_claim.keywords != bare_claim.keywords


def test_tuple_axis_literal_on_claim(tmp_path: Path) -> None:
    provider = MetadataCapturingProvider()
    write_module(
        tmp_path,
        """
from rextio_numpy.types import F64Arr1
import numpy as np

def reduce_axes(a: F64Arr1) -> float:
    return np.sum(a, axis=(0, 1))
""",
    )
    analysis = analyze_project(
        tmp_path, plugin_registry=make_registry(provider), plugin_config=RextioConfig()
    )
    function = function_named(analysis, "myapp.kernels.reduce_axes")
    assert function.accepted is True
    claim = function.plugin_claims[0]
    assert claim.keywords[0].literal == ClaimLiteral(is_literal=True, value=(0, 1))
    assert claim.to_dict()["keywords"][0]["literal"] == {
        "is_literal": True,
        "value_kind": "int_tuple",
        "value": [0, 1],
    }


def test_signed_int_axis_literal(tmp_path: Path) -> None:
    provider = MetadataCapturingProvider()
    write_module(
        tmp_path,
        """
from rextio_numpy.types import F64Arr1
import numpy as np

def reduce_neg(a: F64Arr1) -> float:
    return np.mean(a, axis=-1)
""",
    )
    analysis = analyze_project(
        tmp_path, plugin_registry=make_registry(provider), plugin_config=RextioConfig()
    )
    function = function_named(analysis, "myapp.kernels.reduce_neg")
    assert function.accepted is True
    assert function.plugin_claims[0].keywords[0].literal == ClaimLiteral(is_literal=True, value=-1)


def test_dynamic_keyword_fails_closed(tmp_path: Path) -> None:
    """Runtime keyword values are not offerable (no CallIR kw representation)."""

    class Greedy12(MetadataCapturingProvider):
        def claim(self, site: ClaimSite, config: RextioConfig):
            self.claim_sites.append(site)
            # Would greedily claim even non-literal axis if offered.
            if site.kind == "call" and site.target == "numpy.sum":
                return Claimed(rule_id="rextio-numpy/meta", result_type="float")
            return NotCovered()

    provider = Greedy12()
    write_module(
        tmp_path,
        """
from rextio_numpy.types import F64Arr1
import numpy as np

def bad(a: F64Arr1, axis: int) -> float:
    return np.sum(a, axis=axis)
""",
    )
    analysis = analyze_project(
        tmp_path, plugin_registry=make_registry(provider), plugin_config=RextioConfig()
    )
    function = function_named(analysis, "myapp.kernels.bad")
    # Non-literal axis is not offered at all (fail closed).
    assert function.accepted is False
    assert function.plugin_claims == []
    assert provider.claim_sites == []
    assert function.route != "native-plugin:rextio-numpy"


def test_starstar_kwargs_fails_closed_without_crash(tmp_path: Path) -> None:
    provider = MetadataCapturingProvider()
    write_module(
        tmp_path,
        """
from rextio_numpy.types import F64Arr1
import numpy as np

def bad(a: F64Arr1, **kwargs) -> float:
    return np.sum(a, **kwargs)
""",
    )
    analysis = analyze_project(
        tmp_path, plugin_registry=make_registry(provider), plugin_config=RextioConfig()
    )
    function = function_named(analysis, "myapp.kernels.bad")
    assert function.accepted is False
    # No claim recorded for dynamic kwargs sites.
    assert all(
        claim.target != "numpy.sum" or not claim.keywords for claim in function.plugin_claims
    )


def test_cache_keys_distinguish_metadata_and_trees() -> None:
    provider = MetadataCapturingProvider()
    engine = ClaimEngine(make_registry(provider), RextioConfig())
    base = ClaimSite(
        kind="call",
        target="numpy.sum",
        operand_types=(F64_KEY,),
        file_path="",
        line=0,
        column=0,
        operand_literals=(NON_LITERAL,),
        keywords=(),
    )
    with_axis = ClaimSite(
        kind="call",
        target="numpy.sum",
        operand_types=(F64_KEY,),
        file_path="",
        line=0,
        column=0,
        operand_literals=(NON_LITERAL,),
        keywords=(
            KeywordArg(name="axis", arg_type="int", literal=ClaimLiteral(is_literal=True, value=0)),
        ),
    )
    with_none = ClaimSite(
        kind="call",
        target="numpy.sum",
        operand_types=(F64_KEY,),
        file_path="",
        line=0,
        column=0,
        operand_literals=(NON_LITERAL,),
        keywords=(
            KeywordArg(
                name="axis", arg_type="None", literal=ClaimLiteral(is_literal=True, value=None)
            ),
        ),
    )
    tree_a = ClaimSite(
        kind="binop",
        target="+",
        operand_types=(F64_KEY, F64_KEY),
        file_path="",
        line=0,
        column=0,
        operand_literals=(NON_LITERAL, NON_LITERAL),
        expression=ClaimExpr(
            kind="binop",
            target="+",
            children=(
                ClaimExpr(kind="leaf", leaf_index=0, result_type=F64_KEY, leaf_kind="name"),
                ClaimExpr(kind="leaf", leaf_index=1, result_type=F64_KEY, leaf_kind="name"),
            ),
        ),
    )
    tree_b = ClaimSite(
        kind="binop",
        target="+",
        operand_types=(F64_KEY, F64_KEY),
        file_path="",
        line=0,
        column=0,
        operand_literals=(NON_LITERAL, NON_LITERAL),
        expression=ClaimExpr(
            kind="binop",
            target="+",
            children=(
                ClaimExpr(
                    kind="binop",
                    target="*",
                    children=(
                        ClaimExpr(
                            kind="leaf",
                            leaf_index=0,
                            result_type=F64_KEY,
                            leaf_kind="name",
                        ),
                        ClaimExpr(
                            kind="leaf",
                            leaf_index=1,
                            result_type=F64_KEY,
                            leaf_kind="name",
                        ),
                    ),
                ),
                ClaimExpr(kind="leaf", leaf_index=2, result_type=F64_KEY, leaf_kind="name"),
            ),
        ),
    )
    # Different metadata must not share a cache entry: call claim twice each.
    r1 = engine._claim("rextio-numpy", base)
    r2 = engine._claim("rextio-numpy", with_axis)
    r3 = engine._claim("rextio-numpy", with_none)
    r4 = engine._claim("rextio-numpy", tree_a)
    r5 = engine._claim("rextio-numpy", tree_b)
    assert isinstance(r1, Claimed)
    assert isinstance(r2, Claimed)
    assert isinstance(r3, Claimed)
    assert isinstance(r4, Claimed)
    assert isinstance(r5, Claimed)
    # Provider saw five distinct sites (cache did not collapse them).
    assert len(provider.claim_sites) == 5


def test_claim_site_to_dict_includes_metadata() -> None:
    site = ClaimSite(
        kind="call",
        target="numpy.sum",
        operand_types=(F64_KEY,),
        file_path="x.py",
        line=1,
        column=2,
        operand_literals=(NON_LITERAL,),
        keywords=(
            KeywordArg(name="axis", arg_type="int", literal=ClaimLiteral(is_literal=True, value=0)),
        ),
        expression=ClaimExpr(
            kind="call",
            target="numpy.sum",
            children=(ClaimExpr(kind="leaf", leaf_index=0, result_type=F64_KEY, leaf_kind="name"),),
            keywords=(
                KeywordArg(
                    name="axis", arg_type="int", literal=ClaimLiteral(is_literal=True, value=0)
                ),
            ),
        ),
    )
    data = site.to_dict()
    assert data["operand_literals"] == [{"is_literal": False}]
    assert data["keywords"][0]["name"] == "axis"
    assert data["expression"]["kind"] == "call"
    assert data["expression"]["keywords"][0]["literal"]["value"] == 0
    assert data["expression"]["children"][0]["leaf_kind"] == "name"


def test_nested_source_span_matching_stays_correct(tmp_path: Path) -> None:
    """Outer multi-op and inner ops keep distinct claims by full span."""
    provider = MetadataCapturingProvider()
    write_module(
        tmp_path,
        """
from rextio_numpy.types import F64Arr1

def fused(a: F64Arr1, b: F64Arr1, c: F64Arr1, d: F64Arr1, e: F64Arr1) -> F64Arr1:
    return a * b + c * d - e
""",
    )
    analysis = analyze_project(
        tmp_path, plugin_registry=make_registry(provider), plugin_config=RextioConfig()
    )
    function = function_named(analysis, "myapp.kernels.fused")
    assert function.accepted is True
    # Multiple binop claims: two multiplies, one add, one sub (or fewer if
    # deduped by span — each node has a unique full span).
    binop_claims = [c for c in function.plugin_claims if c.kind == "binop"]
    assert len(binop_claims) >= 3
    spans = {(c.line, c.column, c.end_line, c.end_column, c.target) for c in binop_claims}
    assert len(spans) == len(binop_claims)
    # Outer expression trees nest children.
    outer = max(binop_claims, key=lambda c: (c.end_column or 0) - (c.column or 0))
    assert outer.expression is not None
    assert outer.expression.kind == "binop"


def test_claim_site_legacy_to_dict_omits_empty_12_keys() -> None:
    """API 1.1 serialization: legacy-only ClaimSite keeps the exact old shape."""
    site = ClaimSite(
        kind="call",
        target="numpy.dot",
        operand_types=(F64_KEY, F64_KEY),
        file_path="x.py",
        line=1,
        column=0,
    )
    assert site.to_dict() == {
        "kind": "call",
        "target": "numpy.dot",
        "operand_types": [F64_KEY, F64_KEY],
        "file_path": "x.py",
        "line": 1,
        "column": 0,
    }
    # With rule_id/result_type filled at lower() time, still no empty 1.2 keys.
    filled = ClaimSite(
        kind="call",
        target="numpy.dot",
        operand_types=(F64_KEY, F64_KEY),
        file_path="",
        line=0,
        column=0,
        rule_id="rextio-numpy/dot-float64",
        result_type="float",
    )
    assert filled.to_dict() == {
        "kind": "call",
        "target": "numpy.dot",
        "operand_types": [F64_KEY, F64_KEY],
        "file_path": "",
        "line": 0,
        "column": 0,
        "rule_id": "rextio-numpy/dot-float64",
        "result_type": "float",
    }


def test_leaf_kind_name_vs_opaque(tmp_path: Path) -> None:
    """Simple Name leaves are classified; subscripts stay opaque."""
    provider = MetadataCapturingProvider()
    write_module(
        tmp_path,
        """
from rextio_numpy.types import F64Arr1

def names_only(a: F64Arr1, b: F64Arr1) -> F64Arr1:
    return a + b
""",
    )
    analysis = analyze_project(
        tmp_path, plugin_registry=make_registry(provider), plugin_config=RextioConfig()
    )
    function = function_named(analysis, "myapp.kernels.names_only")
    claim = function.plugin_claims[0]
    assert claim.expression is not None
    assert claim.expression.kind == "binop"
    left, right = claim.expression.children
    assert left.kind == "leaf" and left.leaf_kind == "name"
    assert right.kind == "leaf" and right.leaf_kind == "name"
    assert left.to_dict()["leaf_kind"] == "name"

    # Manually build an opaque leaf (subscript-style fail-closed leaf).
    opaque = ClaimExpr(kind="leaf", leaf_index=0, result_type=F64_KEY, leaf_kind="opaque")
    assert opaque.leaf_kind == "opaque"
    assert opaque.to_dict()["leaf_kind"] == "opaque"


def test_claim_expr_structural_validation() -> None:
    import pytest

    with pytest.raises(ValueError, match="unsupported ClaimExpr kind"):
        ClaimExpr(kind="weird")
    with pytest.raises(ValueError, match="leaf_index"):
        ClaimExpr(kind="leaf", leaf_kind="name")
    with pytest.raises(ValueError, match="leaf_kind"):
        ClaimExpr(kind="leaf", leaf_index=0)
    with pytest.raises(ValueError, match="exactly 2 children"):
        ClaimExpr(kind="binop", target="+", children=())
    with pytest.raises(ValueError, match="must not set leaf_index"):
        ClaimExpr(
            kind="binop",
            target="+",
            children=(
                ClaimExpr(kind="leaf", leaf_index=0, leaf_kind="name"),
                ClaimExpr(kind="leaf", leaf_index=1, leaf_kind="name"),
            ),
            leaf_index=0,
        )


def test_api_11_keyword_call_not_offered(tmp_path: Path) -> None:
    """API 1.1 providers never see keyword calls (legacy RXT010/fallback)."""

    class Greedy11:
        plugin_id = "rextio-numpy"
        api_version = "1.1"

        def __init__(self) -> None:
            self.claim_sites: list[ClaimSite] = []

        def claim(self, site: ClaimSite, config: RextioConfig):
            self.claim_sites.append(site)
            return Claimed(rule_id="rextio-numpy/meta", result_type="float")

    provider = Greedy11()
    write_module(
        tmp_path,
        """
from rextio_numpy.types import F64Arr1
import numpy as np

def bad(a: F64Arr1, b: F64Arr1) -> float:
    return np.dot(a, b=b)
""",
    )
    analysis = analyze_project(
        tmp_path, plugin_registry=make_registry(provider), plugin_config=RextioConfig()
    )
    function = function_named(analysis, "myapp.kernels.bad")
    assert provider.claim_sites == []
    assert function.plugin_claims == []
    assert function.accepted is False


def test_positional_inferred_exactly_once_before_keywords(tmp_path: Path) -> None:
    """Each positional is inferred exactly once, then each keyword in source order.

    Guards against the P,P,K duplication where the plugin block re-inferred
    positionals after the first-pass loop.
    """
    import rextio.analyzer.unsupported_patterns as up

    infer_log: list[str] = []
    real_infer = up._infer_expr_type

    def tracking_infer(node, function, env, *args, **kwargs):  # type: ignore[no-untyped-def]
        import ast as _ast

        if isinstance(node, _ast.Name):
            infer_log.append(f"name:{node.id}")
        elif isinstance(node, _ast.Constant):
            infer_log.append(f"const:{node.value!r}")
        else:
            infer_log.append(type(node).__name__)
        return real_infer(node, function, env, *args, **kwargs)

    class OrderProvider(MetadataCapturingProvider):
        def claim(self, site: ClaimSite, config: RextioConfig):
            self.claim_sites.append(site)
            if site.kind == "call" and site.target == "numpy.sum":
                return Claimed(rule_id="rextio-numpy/meta", result_type="float")
            return NotCovered()

    provider = OrderProvider()
    write_module(
        tmp_path,
        """
from rextio_numpy.types import F64Arr1
import numpy as np

def reduce(a: F64Arr1, b: F64Arr1) -> float:
    return np.sum(a, axis=0)
""",
    )
    original = up._infer_expr_type
    up._infer_expr_type = tracking_infer  # type: ignore[assignment]
    try:
        analysis = analyze_project(
            tmp_path, plugin_registry=make_registry(provider), plugin_config=RextioConfig()
        )
    finally:
        up._infer_expr_type = original  # type: ignore[assignment]

    function = function_named(analysis, "myapp.kernels.reduce")
    assert function.accepted is True
    # Filter to the call's operand/keyword values of interest.
    # Expect name:a exactly once before const:0 for the axis keyword.
    relevant = [e for e in infer_log if e in {"name:a", "const:0"}]
    assert relevant.count("name:a") == 1, infer_log
    assert relevant.count("const:0") == 1, infer_log
    assert relevant.index("name:a") < relevant.index("const:0"), relevant
    claim = function.plugin_claims[0]
    assert claim.operand_types == (F64_KEY,)
    assert claim.keywords[0].name == "axis"
    assert claim.keywords[0].literal == ClaimLiteral(is_literal=True, value=0)


def test_nested_call_is_opaque_leaf_not_expanded(tmp_path: Path) -> None:
    """Nested calls inside a binop become opaque leaves (not nested call nodes)."""
    provider = MetadataCapturingProvider()
    write_module(
        tmp_path,
        """
from rextio_numpy.types import F64Arr1
import numpy as np

def mixed(a: F64Arr1, b: F64Arr1) -> F64Arr1:
    return np.dot(a, b) + a
""",
    )
    # Dot returns float in MetadataCapturingProvider; may not claim binop.
    # Force binop-only claim path with two arrays:
    write_module(
        tmp_path,
        """
from rextio_numpy.types import F64Arr1

def mixed(a: F64Arr1, b: F64Arr1) -> F64Arr1:
    return a + b
""",
    )
    analysis = analyze_project(
        tmp_path, plugin_registry=make_registry(provider), plugin_config=RextioConfig()
    )
    function = function_named(analysis, "myapp.kernels.mixed")
    claim = function.plugin_claims[0]
    assert claim.expression is not None
    for child in claim.expression.children:
        if child.kind == "leaf":
            assert child.leaf_kind in {"name", "opaque"}
    # Manually ensure nested Call would be opaque via builder unit path.
    from rextio.analyzer.plugin_claims import ClaimEngine

    engine = ClaimEngine(make_registry(provider), RextioConfig())
    import ast

    tree = ast.parse("f(x) + y", mode="eval").body
    assert isinstance(tree, ast.BinOp)
    expr = engine._build_binop_expr(
        tree,
        symbol="+",
        result_type=None,
        left_type="float",
        right_type="float",
        type_of=lambda n: "float",
    )
    left = expr.children[0]
    assert left.kind == "leaf"
    assert left.leaf_kind == "opaque"


def test_leaves_mode_rejects_opaque_tree() -> None:
    """operand_mode=leaves on an opaque-leaf tree fails closed with PluginError."""
    from rextio.plugins.loader import PluginError

    class LeavesOpaque:
        plugin_id = "rextio-numpy"
        api_version = "1.2"

        def claim(self, site: ClaimSite, config: RextioConfig):
            if site.kind == "binop":
                return Claimed(
                    rule_id="rextio-numpy/binop",
                    result_type=F64_KEY,
                    operand_mode="leaves",
                )
            return NotCovered()

    provider = LeavesOpaque()
    # Build engine and force a claim on a site whose expression has opaque leaves.
    from rextio.analyzer.plugin_claims import ClaimEngine
    import pytest

    engine = ClaimEngine(make_registry(provider), RextioConfig())
    opaque_expr = ClaimExpr(
        kind="binop",
        target="+",
        children=(
            ClaimExpr(kind="leaf", leaf_index=0, leaf_kind="opaque", result_type=F64_KEY),
            ClaimExpr(kind="leaf", leaf_index=1, leaf_kind="name", result_type=F64_KEY),
        ),
    )
    site = ClaimSite(
        kind="binop",
        target="+",
        operand_types=(F64_KEY, F64_KEY),
        file_path="x.py",
        line=1,
        column=0,
        expression=opaque_expr,
        operand_literals=(NON_LITERAL, NON_LITERAL),
    )
    with pytest.raises(PluginError, match="leaves-safe"):
        engine._claim("rextio-numpy", site)


@pytest.mark.parametrize(
    "source_kw,label",
    [
        ("axis=True", "bool"),
        ("axis=1.5", "float"),
        ("axis='x'", "string"),
    ],
)
def test_non_int_keyword_constants_fail_closed(tmp_path: Path, source_kw: str, label: str) -> None:
    """bool/float/str keyword constants are non-literal and never offered."""

    class Greedy12(MetadataCapturingProvider):
        def claim(self, site: ClaimSite, config: RextioConfig):
            self.claim_sites.append(site)
            return Claimed(rule_id="rextio-numpy/meta", result_type="float")

    provider = Greedy12()
    write_module(
        tmp_path,
        f"""
from rextio_numpy.types import F64Arr1
import numpy as np

def bad(a: F64Arr1) -> float:
    return np.sum(a, {source_kw})
""",
    )
    analysis = analyze_project(
        tmp_path, plugin_registry=make_registry(provider), plugin_config=RextioConfig()
    )
    function = function_named(analysis, "myapp.kernels.bad")
    assert provider.claim_sites == [], label
    assert function.plugin_claims == [], label
    assert function.accepted is False, label


def test_mixed_11_and_12_providers_project_correctly(tmp_path: Path) -> None:
    """With 1.1 + 1.2 active, only 1.2 sees keyword/metadata; 1.1 stays legacy."""

    class Greedy11:
        plugin_id = "rextio-legacy"
        api_version = "1.1"
        sites: list[ClaimSite] = []

        def claim(self, site: ClaimSite, config: RextioConfig):
            self.sites.append(site)
            if site.kind == "call" and site.target == "numpy.sum":
                return Claimed(rule_id="legacy/sum", result_type="float")
            if site.kind == "binop":
                return Claimed(rule_id="legacy/binop", result_type=F64_KEY)
            return NotCovered()

    class Provider12(MetadataCapturingProvider):
        plugin_id = "rextio-numpy"
        api_version = "1.2"

    p11 = Greedy11()
    p12 = Provider12()
    # Two plugins: legacy covers numpy via packages; 1.2 owns types + numpy.
    from rextio.plugins.models import (
        PluginProviderBinding,
        PluginRegistry,
        PluginTypeBinding,
        RextioPlugin,
    )

    plugins = (
        RextioPlugin(
            id="rextio-legacy",
            name="legacy",
            packages=("numpy",),
            rules_provided=True,
            api_version="1.1",
            lowering_provided=True,
        ),
        RextioPlugin(
            id="rextio-numpy",
            name="numpy",
            packages=("numpy",),
            rules_provided=True,
            api_version="1.2",
            lowering_provided=True,
        ),
    )
    registry = PluginRegistry(
        enabled=("rextio-legacy", "rextio-numpy"),
        discovered=plugins,
        active=plugins,
        types=(PluginTypeBinding(plugin_id="rextio-numpy", plugin_type=F64_ARR1),),
        providers=(
            PluginProviderBinding(plugin_id="rextio-legacy", provider=p11),
            PluginProviderBinding(plugin_id="rextio-numpy", provider=p12),
        ),
    )
    write_module(
        tmp_path,
        """
from rextio_numpy.types import F64Arr1
import numpy as np

def reduce(a: F64Arr1) -> float:
    return np.sum(a, axis=0)
""",
    )
    analysis = analyze_project(tmp_path, plugin_registry=registry, plugin_config=RextioConfig())
    function = function_named(analysis, "myapp.kernels.reduce")
    # Keyword call is never offered to 1.1; 1.2 may claim it.
    assert p11.sites == []
    assert function.accepted is True or function.plugin_claims
    # If 1.2 claimed, metadata present and plugin is rextio-numpy.
    if function.plugin_claims:
        assert all(c.plugin_id == "rextio-numpy" for c in function.plugin_claims)
        assert function.plugin_claims[0].keywords


def test_operand_mode_propagates_to_claim_and_dict(tmp_path: Path) -> None:
    class LeavesProvider(MetadataCapturingProvider):
        def claim(self, site: ClaimSite, config: RextioConfig):
            self.claim_sites.append(site)
            if site.kind == "binop" and site.expression is not None:
                # multi-op depth
                if any(c.kind == "binop" for c in site.expression.children):
                    return Claimed(
                        rule_id="rextio-numpy/binop",
                        result_type=F64_KEY,
                        operand_mode="leaves",
                    )
            if site.kind == "binop":
                return Claimed(rule_id="rextio-numpy/binop", result_type=F64_KEY)
            return NotCovered()

    provider = LeavesProvider()
    write_module(
        tmp_path,
        """
from rextio_numpy.types import F64Arr1

def poly(a: F64Arr1, b: F64Arr1, c: F64Arr1) -> F64Arr1:
    return a * b + c
""",
    )
    analysis = analyze_project(
        tmp_path, plugin_registry=make_registry(provider), plugin_config=RextioConfig()
    )
    function = function_named(analysis, "myapp.kernels.poly")
    outer = max(
        function.plugin_claims,
        key=lambda c: (c.end_column or 0) - (c.column or 0),
    )
    assert outer.operand_mode == "leaves"
    assert outer.to_dict()["operand_mode"] == "leaves"
