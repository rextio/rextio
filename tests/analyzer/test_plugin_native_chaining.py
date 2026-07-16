"""Analyzer coverage for plugin API 1.3 resident values + native chaining.

A resident plugin type (``conversion=None``) is an opaque, native-only value:
it may be created by a claimed plugin expression, stored in locals, passed to
another claimed plugin expression, and passed across accepted native helper
calls without any Python round-trip. It must never cross an exported PyO3
boundary; those paths stay fail-closed (RXT092). Materialized plugin-typed
functions remain Python-facing entry points (native calls in stay RXT092).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rextio.analyzer.models import FunctionAnalysis, ProjectAnalysis
from rextio.analyzer.project_scanner import analyze_project
from rextio.config.schema import RextioConfig
from rextio.plugins.api import (
    BoundaryConversion,
    Claimed,
    ClaimSite,
    NotCovered,
    PluginType,
)
from rextio.plugins.loader import PluginError, load_plugin_registry
from rextio.plugins.models import (
    PluginProviderBinding,
    PluginRegistry,
    PluginTypeBinding,
    RextioPlugin,
)
from rextio.config.schema import PluginConfig
from rextio.targets.models import TargetSpec

GRAPH = PluginType(
    key="rextio-graph/graph",
    annotations=("rextio_graph.types.Graph",),
    rust_type="GraphData",
    conversion=None,
)

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


class GraphProvider:
    plugin_id = "rextio-graph"
    api_version = "1.3"

    def claim(self, site: ClaimSite, config: RextioConfig):
        if site.kind == "call" and site.target == "rextio_graph.new":
            return Claimed(rule_id="rextio-graph/new", result_type=GRAPH.key)
        if site.kind == "call" and site.target == "rextio_graph.push":
            return Claimed(rule_id="rextio-graph/push", result_type=GRAPH.key)
        if site.kind == "call" and site.target == "rextio_graph.node_total":
            return Claimed(rule_id="rextio-graph/node_total", result_type="int")
        return NotCovered()


class NumpyProvider:
    plugin_id = "rextio-numpy"
    api_version = "1.1"

    def claim(self, site: ClaimSite, config: RextioConfig):
        if site.kind == "call" and site.target == "numpy.dot":
            return Claimed(rule_id="rextio-numpy/dot-float64", result_type="float")
        return NotCovered()


def make_registry(*providers: object) -> PluginRegistry:
    plugins = []
    provider_bindings = []
    type_bindings = []
    packages_by_id = {"rextio-graph": ("rextio_graph",), "rextio-numpy": ("numpy",)}
    types_by_id = {"rextio-graph": GRAPH, "rextio-numpy": F64_ARR1}
    for provider in providers:
        plugin_id = str(getattr(provider, "plugin_id"))
        plugins.append(
            RextioPlugin(
                id=plugin_id,
                name=plugin_id,
                packages=packages_by_id[plugin_id],
                rules_provided=True,
                api_version=str(getattr(provider, "api_version")),
                lowering_provided=True,
            )
        )
        provider_bindings.append(PluginProviderBinding(plugin_id=plugin_id, provider=provider))
        type_bindings.append(
            PluginTypeBinding(plugin_id=plugin_id, plugin_type=types_by_id[plugin_id])
        )
    return PluginRegistry(
        enabled=tuple(plugin.id for plugin in plugins),
        discovered=tuple(plugins),
        active=tuple(plugins),
        types=tuple(type_bindings),
        providers=tuple(provider_bindings),
    )


def write_module(root: Path, contents: str) -> None:
    path = root / "src" / "myapp" / "kernels.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")


def analyze(root: Path, *providers: object) -> ProjectAnalysis:
    return analyze_project(
        root, plugin_registry=make_registry(*providers), plugin_config=RextioConfig()
    )


def function_named(analysis: ProjectAnalysis, qualname: str) -> FunctionAnalysis:
    for module in analysis.modules:
        for function in module.functions:
            if function.qualname == qualname:
                return function
    raise AssertionError(f"function not found: {qualname}")


CHAIN_MODULE = """
import rextio_graph as rextio_graph
from rextio_graph.types import Graph


def extend(g: Graph, n: int) -> Graph:
    return rextio_graph.push(g, n)


def build(nodes: list[int], extra: int) -> int:
    g = rextio_graph.new(nodes)
    g2 = extend(g, extra)
    return rextio_graph.node_total(g2)
"""


def test_resident_helper_is_accepted_native_only(tmp_path: Path) -> None:
    write_module(tmp_path, CHAIN_MODULE)
    analysis = analyze(tmp_path, GraphProvider())

    helper = function_named(analysis, "myapp.kernels.extend")
    assert helper.accepted is True
    assert helper.has_resident_signature is True
    assert helper.has_materialized_plugin_type is False
    assert helper.route == "native-plugin:rextio-graph"
    assert helper.signature_plugin_keys == {"g": GRAPH.key}
    assert helper.positional_param_names == ("g", "n")


def test_build_chains_resident_value_through_native_helper(tmp_path: Path) -> None:
    write_module(tmp_path, CHAIN_MODULE)
    analysis = analyze(tmp_path, GraphProvider())

    build = function_named(analysis, "myapp.kernels.build")
    assert build.accepted is True
    assert build.has_resident_signature is False
    # The native-to-native call into the resident helper is NOT rejected.
    assert [d.code for d in build.error_diagnostics] == []
    # And the chain is genuinely native-plugin routed.
    assert build.route == "native-plugin:rextio-graph"


REUSE_MODULE = """
import rextio_graph as rextio_graph
from rextio_graph.types import Graph


def extend(g: Graph, n: int) -> Graph:
    return rextio_graph.push(g, n)


def pair_total(a: Graph, b: Graph) -> int:
    return rextio_graph.node_total(a) + rextio_graph.node_total(b)


def build(nodes: list[int], a: int, b: int) -> int:
    g = rextio_graph.new(nodes)
    g2 = extend(g, a)
    g3 = extend(g, b)
    return (
        rextio_graph.node_total(g)
        + rextio_graph.node_total(g2)
        + rextio_graph.node_total(g3)
    )


def build_same_call(nodes: list[int]) -> int:
    g = rextio_graph.new(nodes)
    return pair_total(g, g)
"""


def test_resident_value_reused_across_native_calls_is_accepted(tmp_path: Path) -> None:
    write_module(tmp_path, REUSE_MODULE)
    analysis = analyze(tmp_path, GraphProvider())

    # A resident value produced once, passed by shared borrow into two separate
    # native helper calls, and then the ORIGINAL also consumed by a plugin claim
    # after both borrows — reuse is well-formed (no use-after-move), so the caller
    # stays native with no error diagnostics.
    build = function_named(analysis, "myapp.kernels.build")
    assert build.accepted is True
    assert [d.code for d in build.error_diagnostics] == []
    assert build.route == "native-plugin:rextio-graph"


DIRECT_MODULE = """
import rextio_graph as rextio_graph
from rextio_graph.types import Graph


def extend(g: Graph, n: int) -> Graph:
    return rextio_graph.push(g, n)


def build_direct(nodes: list[int], extra: int) -> int:
    return rextio_graph.node_total(extend(rextio_graph.new(nodes), extra))


def build_nested(nodes: list[int], a: int, b: int) -> int:
    g = rextio_graph.new(nodes)
    return rextio_graph.node_total(extend(extend(g, a), b))
"""


def test_direct_resident_temporary_arg_is_accepted(tmp_path: Path) -> None:
    write_module(tmp_path, DIRECT_MODULE)
    analysis = analyze(tmp_path, GraphProvider())

    # A plugin-produced resident value passed DIRECTLY into a native helper (no
    # intermediate local), and a nested native helper call whose resident result
    # feeds the outer helper — both are native-to-native chains with no boundary
    # crossing, accepted with no error diagnostics.
    direct = function_named(analysis, "myapp.kernels.build_direct")
    assert direct.accepted is True
    assert [d.code for d in direct.error_diagnostics] == []
    assert direct.route == "native-plugin:rextio-graph"

    nested = function_named(analysis, "myapp.kernels.build_nested")
    assert nested.accepted is True
    assert [d.code for d in nested.error_diagnostics] == []
    assert nested.route == "native-plugin:rextio-graph"


def test_resident_value_passed_twice_in_one_call_is_accepted(tmp_path: Path) -> None:
    write_module(tmp_path, REUSE_MODULE)
    analysis = analyze(tmp_path, GraphProvider())

    # The same resident local passed as BOTH arguments of one native call — two
    # shared borrows in one call are permitted by immutable-borrow semantics.
    same = function_named(analysis, "myapp.kernels.build_same_call")
    assert same.accepted is True
    assert [d.code for d in same.error_diagnostics] == []
    pair = function_named(analysis, "myapp.kernels.pair_total")
    assert pair.accepted is True
    assert pair.has_resident_signature is True
    assert pair.positional_param_names == ("a", "b")


def test_returning_resident_parameter_is_rejected_before_codegen(tmp_path: Path) -> None:
    # Immutable borrow cannot hand back a resident PARAMETER by value (the
    # fallback returns the caller's own object; the native leg would need an
    # owned copy). The plugin alias-escape check rejects returning the parameter
    # (or an alias of one) before codegen (RXT010) — a deterministic fallback,
    # never a cargo error. An undecorated function returning a resident param is
    # simply not a native candidate; a decorated one is rejected with the alias
    # diagnostic here (its resident signature would also bar export, RXT092).
    write_module(
        tmp_path,
        """
import rextio
import rextio_graph as rextio_graph
from rextio_graph.types import Graph


@rextio.native
def identity(g: Graph) -> Graph:
    return g


@rextio.native
def renamed(g: Graph) -> Graph:
    h = g
    return h
""",
    )
    analysis = analyze_project(
        tmp_path,
        native_marker="decorator",
        plugin_registry=make_registry(GraphProvider()),
        plugin_config=RextioConfig(),
    )
    for name in ("identity", "renamed"):
        function = function_named(analysis, f"myapp.kernels.{name}")
        assert function.accepted is False, name
        assert "RXT010" in function.rejection_codes, (name, function.diagnostics)
        assert any("alias" in d.message for d in function.error_diagnostics), name


def test_aliasing_resident_value_falls_back_not_silently_cloned(tmp_path: Path) -> None:
    # `g2 = g` on a resident value cannot alias a second owner without Clone (a
    # resident type need not implement it) or a move (which invalidates `g`).
    # Rather than emit a silent `.clone()`, the function deterministically leaves
    # the native path — no cargo-only clone requirement.
    write_module(
        tmp_path,
        """
import rextio_graph as rextio_graph
from rextio_graph.types import Graph


def build_alias(nodes: list[int]) -> int:
    g = rextio_graph.new(nodes)
    g2 = g
    return rextio_graph.node_total(g2)
""",
    )
    analysis = analyze(tmp_path, GraphProvider())
    build_alias = function_named(analysis, "myapp.kernels.build_alias")
    assert build_alias.accepted is False
    assert build_alias.native_status == "not-candidate"


def test_native_call_into_materialized_function_is_rxt092(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        """
from rextio_numpy.types import F64Arr1
import numpy as np


def kernel(a: F64Arr1, b: F64Arr1) -> float:
    return np.dot(a, b)


def caller(a: F64Arr1, b: F64Arr1) -> float:
    return kernel(a, b)
""",
    )
    analysis = analyze(tmp_path, NumpyProvider())
    caller = function_named(analysis, "myapp.kernels.caller")
    assert caller.accepted is False
    assert "RXT092" in caller.rejection_codes


def test_marked_resident_signature_is_rxt092(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        """
import rextio
import rextio_graph as rextio_graph
from rextio_graph.types import Graph


@rextio.native
def escape(nodes: list[int]) -> Graph:
    return rextio_graph.new(nodes)
""",
    )
    analysis = analyze(tmp_path, GraphProvider())
    escape = function_named(analysis, "myapp.kernels.escape")
    assert escape.accepted is False
    assert "RXT092" in escape.rejection_codes


def test_resident_argument_type_mismatch_keeps_caller_on_fallback(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        """
import rextio_graph as rextio_graph
from rextio_graph.types import Graph


def extend(g: Graph, n: int) -> Graph:
    return rextio_graph.push(g, n)


def bad(x: int, extra: int) -> int:
    g2 = extend(x, extra)
    return rextio_graph.node_total(g2)
""",
    )
    analysis = analyze(tmp_path, GraphProvider())
    bad = function_named(analysis, "myapp.kernels.bad")
    # Passing an int where the resident-typed parameter is expected keeps the
    # caller on the Python fallback (native-to-native signature compat).
    assert bad.accepted is False
    assert "RXT010" in bad.rejection_codes


# ---------------------------------------------------------------------------
# WP-4 follow-up 5: reject a FRESH resident alias through every binder.
#
# A resident value is an opaque, affine native value borrowed at each use site;
# the core has no reference representation for it. Binding a NEW owner to a bare
# resident value (`h = g`, `h := g`) would need a second owner — codegen's
# name-copy path emits `.clone()` on a type that need not implement `Clone`
# (E0599). The decision is centralized in `_reject_incompatible_rebinding`, so
# EVERY admitted binder (plain `Assign`, `AnnAssign`, walrus in ordinary
# expressions and comprehension scopes) rejects the alias identically (RXT092),
# while a fresh resident-producing plugin CALL bound to its first local, and
# immutable borrowing in a plugin consumer, stay native.
# ---------------------------------------------------------------------------


def test_plain_resident_alias_is_rejected(tmp_path: Path) -> None:
    # Control: the plain `Assign` alias `g2 = g` stays rejected (it left the
    # native path) — the same rule the walrus paths below must not diverge from.
    write_module(
        tmp_path,
        """
import rextio_graph as rextio_graph
from rextio_graph.types import Graph


def build_alias(nodes: list[int]) -> int:
    g = rextio_graph.new(nodes)
    g2 = g
    return rextio_graph.node_total(g2)
""",
    )
    build_alias = function_named(analyze(tmp_path, GraphProvider()), "myapp.kernels.build_alias")
    assert build_alias.accepted is False
    assert build_alias.native_status == "not-candidate"
    assert build_alias.route == "fallback-python"


def test_comprehension_filter_walrus_resident_alias_is_rejected(tmp_path: Path) -> None:
    # The EXACT reviewer reproducer: a comprehension-filter walrus aliases the
    # already-bound resident local `g` into the fresh local `h`. Pre-fix this was
    # accepted native-plugin and codegen emitted the equivalent of
    # `h = Some(g.clone())` (E0599 against a non-Clone resident type).
    write_module(
        tmp_path,
        """
import rextio_graph as rextio_graph
from rextio_graph.types import Graph


def alias(nodes: list[int]) -> int:
    g = rextio_graph.new(nodes)
    xs = [n for n in nodes if rextio_graph.node_total(h := g) > 0]
    return len(xs)
""",
    )
    alias = function_named(analyze(tmp_path, GraphProvider()), "myapp.kernels.alias")
    assert alias.accepted is False
    assert alias.native_status == "not-candidate"
    assert alias.route == "fallback-python"


def test_ordinary_expression_walrus_resident_alias_is_rejected(tmp_path: Path) -> None:
    # A walrus reached through an ORDINARY expression (a plugin-call argument, not
    # a comprehension) also cannot alias the resident local `g` into `h`.
    write_module(
        tmp_path,
        """
import rextio_graph as rextio_graph
from rextio_graph.types import Graph


def alias(nodes: list[int]) -> int:
    g = rextio_graph.new(nodes)
    return rextio_graph.node_total((h := g))
""",
    )
    alias = function_named(analyze(tmp_path, GraphProvider()), "myapp.kernels.alias")
    assert alias.accepted is False
    assert alias.native_status == "not-candidate"
    assert alias.route == "fallback-python"


def test_nested_comprehension_walrus_resident_alias_is_rejected(tmp_path: Path) -> None:
    # A nested comprehension whose element expression reaches the SAME binder
    # (the walrus `h := g` inside a plugin call in the comprehension body).
    write_module(
        tmp_path,
        """
import rextio_graph as rextio_graph
from rextio_graph.types import Graph


def alias(nodes: list[int]) -> int:
    g = rextio_graph.new(nodes)
    xs = [rextio_graph.node_total(h := g) for _n in nodes]
    return len(xs)
""",
    )
    alias = function_named(analyze(tmp_path, GraphProvider()), "myapp.kernels.alias")
    assert alias.accepted is False
    assert alias.native_status == "not-candidate"
    assert alias.route == "fallback-python"


def test_fresh_resident_constructor_binding_stays_native(tmp_path: Path) -> None:
    # A fresh resident value comes from a resident-producing plugin CALL (not a
    # bare Name), so its first local binding is valid and the immutable-borrow
    # consumer call stays native — the alias rule must not touch this.
    write_module(
        tmp_path,
        """
import rextio_graph as rextio_graph
from rextio_graph.types import Graph


def build(nodes: list[int]) -> int:
    g = rextio_graph.new(nodes)
    return rextio_graph.node_total(g)
""",
    )
    build = function_named(analyze(tmp_path, GraphProvider()), "myapp.kernels.build")
    assert build.accepted is True
    assert build.route == "native-plugin:rextio-graph"
    assert [d.code for d in build.error_diagnostics] == []


def test_marked_resident_alias_surfaces_rxt092_with_guidance(tmp_path: Path) -> None:
    # A hard, non-shimmable case (no runtime-fidelity call in the body) so the
    # centralized resident-alias rejection surfaces as RXT092 in the report with
    # the core-owned diagnostic and precise guidance, rather than an RXT080 shim.
    write_module(
        tmp_path,
        """
import rextio
import rextio_graph as rextio_graph
from rextio_graph.types import Graph


@rextio.native
def alias(g: Graph, k: int) -> int:
    h = g
    return k
""",
    )
    alias = function_named(analyze(tmp_path, GraphProvider()), "myapp.kernels.alias")
    assert alias.accepted is False
    assert alias.native_status == "rejected"
    assert alias.rejection_codes == ["RXT092"]
    (diagnostic,) = [d for d in alias.error_diagnostics if d.code == "RXT092"]
    assert "aliasing the resident plugin value 'g'" in diagnostic.message
    assert "borrowed at each use site" in diagnostic.message
    assert diagnostic.suggestion is not None
    assert "directly at each call site" in diagnostic.suggestion


def test_scalar_comprehension_walrus_stays_native(tmp_path: Path) -> None:
    # A scalar (non-resident) comprehension walrus is unaffected by the resident
    # alias rule and stays native — the rule keys strictly on resident types.
    write_module(
        tmp_path,
        """
def f(nodes: list[int]) -> int:
    xs = [(y := n) for n in nodes]
    return len(xs)
""",
    )
    f = function_named(analyze(tmp_path, GraphProvider()), "myapp.kernels.f")
    assert f.accepted is True
    assert "RXT092" not in {d.code for d in f.error_diagnostics}


def test_materialized_walrus_not_rejected_by_resident_rule(tmp_path: Path) -> None:
    # A materialized (boundary-converting) plugin value is NOT resident, so the
    # resident-alias rule never fires for it — its walrus behavior is unchanged
    # (no RXT092 attributable to the alias rule).
    write_module(
        tmp_path,
        """
from rextio_numpy.types import F64Arr1
import numpy as np


def f(a: F64Arr1) -> int:
    xs = [(b := a) for _n in range(3)]
    return len(xs)
""",
    )
    f = function_named(analyze(tmp_path, NumpyProvider()), "myapp.kernels.f")
    assert "RXT092" not in {d.code for d in f.error_diagnostics}


class SiteSensitiveGraphProvider:
    """A deterministic provider that keys its ``seed`` claim on site content.

    ``ClaimEngine._claim`` strips ``file_path``/``line``/``column`` from EVERY
    offered site before a provider sees it (providers must not depend on source
    location), so the observable, provider-visible metadata a peek must present
    faithfully is the site's CONTENT: ``operand_types``, ``operand_literals``, and
    the claim expression. This provider claims ``seed`` only when the offered
    site carries the literal argument the authoritative offer would carry. If the
    signature-inference peek offered a content-stripped site (empty
    ``operand_literals``, as the original zeroed peek did), it would infer a
    DIFFERENT verdict than the later authoritative offer — the exact divergence
    the peek must avoid. It records every site it is offered for ``seed``.
    """

    plugin_id = "rextio-graph"
    api_version = "1.3"

    def __init__(self, seed_value: int) -> None:
        self._seed_value = seed_value
        self.offered_seed_literals: list[tuple[object, ...]] = []
        self.offered_seed_positions: list[tuple[str, int, int]] = []

    def claim(self, site: ClaimSite, config: RextioConfig):
        if site.kind == "call" and site.target == "rextio_graph.seed":
            self.offered_seed_literals.append(
                tuple(lit.value if lit.is_literal else "<dynamic>" for lit in site.operand_literals)
            )
            self.offered_seed_positions.append((site.file_path, site.line, site.column))
            first = site.operand_literals[0] if site.operand_literals else None
            if first is not None and first.is_literal and first.value == self._seed_value:
                return Claimed(rule_id="rextio-graph/seed", result_type=GRAPH.key)
            return NotCovered()
        if site.kind == "call" and site.target == "rextio_graph.push":
            return Claimed(rule_id="rextio-graph/push", result_type=GRAPH.key)
        if site.kind == "call" and site.target == "rextio_graph.node_total":
            return Claimed(rule_id="rextio-graph/node_total", result_type="int")
        return NotCovered()


SEED_CHAIN_MODULE = """
import rextio_graph as rextio_graph
from rextio_graph.types import Graph


def extend(g: Graph, n: int) -> Graph:
    return rextio_graph.push(g, n)


def build(extra: int) -> int:
    g = rextio_graph.seed(3)
    g2 = extend(g, extra)
    return rextio_graph.node_total(g2)
"""


def test_peek_offers_authoritative_site_content_to_provider(tmp_path: Path) -> None:
    write_module(tmp_path, SEED_CHAIN_MODULE)
    provider = SiteSensitiveGraphProvider(seed_value=3)
    analysis = analyze(tmp_path, provider)

    build = function_named(analysis, "myapp.kernels.build")
    # `g` is typed resident (and the chain stays native) only because the
    # signature-inference peek offered the literal-bearing site — identical in
    # content to the later authoritative offer — to this deterministic provider.
    # A content-stripped peek (empty operand_literals) would have inferred
    # NotCovered, left `g` untyped, and forced the caller onto the fallback.
    assert build.accepted is True
    assert [d.code for d in build.error_diagnostics] == []
    assert build.route == "native-plugin:rextio-graph"
    # Every offer for seed() carried the real literal argument (never empty),
    # so the peek never inferred from a site different from the authoritative one.
    assert provider.offered_seed_literals
    assert all(literals == (3,) for literals in provider.offered_seed_literals)
    # And, as the engine guarantees for every provider, the source position is
    # uniformly stripped — a peek can neither leak nor depend on a fake location.
    assert all(pos == ("", 0, 0) for pos in provider.offered_seed_positions)


def test_loader_rejects_resident_type_below_api_13() -> None:
    class OldProvider:
        plugin_id = "rextio-graph"
        api_version = "1.2"

        def covers(self):
            from rextio.plugins.api import CoverageDecl

            return CoverageDecl(packages=("rextio_graph",))

        def describe(self, config: RextioConfig):
            return ()

        def type_vocabulary(self):
            return (GRAPH,)

        def claim(self, site: ClaimSite, config: RextioConfig):
            return NotCovered()

        def lower(self, site, ctx):
            raise AssertionError

        def crate_dependencies(self):
            return ()

        def to_rextio_plugin(self):
            return RextioPlugin(id="rextio-graph", name="graph")

    class _EntryPoint:
        name = "rextio-graph"
        dist = None

        def load(self):
            return OldProvider()

    with pytest.raises(PluginError, match="resident types require api_version >= 1.3"):
        load_plugin_registry(
            PluginConfig(enabled=("rextio-graph",)),
            TargetSpec(language="rust"),
            entry_points=(_EntryPoint(),),
        )


# --- resident rebinding type safety (WP-4 director follow-up 2, item 6) ------
#
# A resident value has a fixed Rust binding shape: a resident PARAMETER is an
# immutable shared borrow (``&T``), and a resident LOCAL owns one fixed resident
# type. Two rebindings the analyzer previously accepted generate uncompilable
# Rust (E0308): rebinding a resident parameter to an owned value, and rebinding a
# resident local to an incompatible type. Both are now rejected with RXT092 at
# analysis, before codegen. A same-resident-type local rebind stays accepted.

RESET_PARAM_REBIND = """
import rextio_graph as rextio_graph
from rextio_graph.types import Graph


def node_total(g: Graph) -> int:
    return rextio_graph.node_total(g)


def reset(g: Graph, nodes: list[int]) -> int:
    g = rextio_graph.new(nodes)
    return node_total(g)
"""


def test_rebinding_resident_parameter_is_rejected(tmp_path: Path) -> None:
    # Auto-discovered: the fix keeps the mis-compile off the native path — the
    # function is rejected and falls back instead of generating E0308 Rust.
    write_module(tmp_path, RESET_PARAM_REBIND)
    reset = function_named(analyze(tmp_path, GraphProvider()), "myapp.kernels.reset")
    assert reset.accepted is False
    assert reset.route == "fallback-python"


def _validate_one(src: str, engine: object) -> FunctionAnalysis:
    """Validate a single-function source directly and return its analysis.

    Exercises the core analysis verdict (``validate_native_function``) without
    the auto/marked routing, so the REJECTING diagnostic is observable — an
    auto-discovered function's probe rejection otherwise falls back silently, and
    a marked function with a plugin call is promoted to the RXT080 shim.
    """
    import ast

    from rextio.analyzer.unsupported_patterns import validate_native_function

    tree = ast.parse(src)
    node = tree.body[0]
    assert isinstance(node, ast.FunctionDef)
    function = FunctionAnalysis(
        name=node.name,
        qualname=f"myapp.kernels.{node.name}",
        module_name="myapp.kernels",
        file_path="myapp/kernels.py",
        line=node.lineno,
        column=node.col_offset,
        is_native_candidate=True,
        imports={"rextio_graph": "rextio_graph", "Graph": "rextio_graph.types.Graph"},
        claim_engine=engine,  # type: ignore[arg-type]
    )
    validate_native_function(node, function)
    return function


def test_rebinding_resident_local_to_incompatible_type_emits_rxt092(tmp_path: Path) -> None:
    # Rebinding a resident local to an incompatible type (int) is an unsafe
    # resident-chain ownership case, rejected with the RXT092 diagnostic.
    from rextio.analyzer.plugin_claims import ClaimEngine

    engine = ClaimEngine(make_registry(GraphProvider()), RextioConfig())
    src = (
        "def build(nodes: list[int]) -> int:\n"
        "    g = rextio_graph.new(nodes)\n"
        "    g = 1\n"
        "    return 7\n"
    )
    function = _validate_one(src, engine)
    assert function.accepted is False
    rebinding = [
        d for d in function.error_diagnostics if d.code == "RXT092" and "rebinding" in d.message
    ]
    assert rebinding, [(d.code, d.message) for d in function.error_diagnostics]


def test_rebinding_resident_parameter_emits_rxt092(tmp_path: Path) -> None:
    # Rebinding a resident parameter (an immutable shared borrow) to an owned
    # value is also RXT092. ``validate_native_function`` does not run the boundary
    # pass, so the only RXT092 here is the rebinding check (not a boundary escape).
    from rextio.analyzer.plugin_claims import ClaimEngine

    engine = ClaimEngine(make_registry(GraphProvider()), RextioConfig())
    src = (
        "def reset(g: Graph, nodes: list[int]) -> int:\n"
        "    g = rextio_graph.new(nodes)\n"
        "    return rextio_graph.node_total(g)\n"
    )
    function = _validate_one(src, engine)
    assert function.accepted is False
    rebinding = [
        d for d in function.error_diagnostics if d.code == "RXT092" and "rebinding" in d.message
    ]
    assert rebinding, [(d.code, d.message) for d in function.error_diagnostics]


SAFE_SAME_TYPE_REBIND = """
import rextio_graph as rextio_graph
from rextio_graph.types import Graph


def node_total(g: Graph) -> int:
    return rextio_graph.node_total(g)


def build(nodes: list[int]) -> int:
    g = rextio_graph.new(nodes)
    g = rextio_graph.new(nodes)
    return node_total(g)
"""


def test_same_resident_type_local_rebind_is_accepted(tmp_path: Path) -> None:
    # The rule is not merely name-based: rebinding a resident local to a fresh
    # value of the SAME resident type keeps its fixed Rust binding type and stays
    # accepted (the ``let mut`` reassignment compiles).
    write_module(tmp_path, SAFE_SAME_TYPE_REBIND)
    build = function_named(analyze(tmp_path, GraphProvider()), "myapp.kernels.build")
    assert build.accepted is True
    assert "RXT092" not in {d.code for d in build.error_diagnostics}
    assert build.route == "native-plugin:rextio-graph"
