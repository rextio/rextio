"""Codegen tests for plugin API 1.3 resident values + native chaining.

Cargo-free: a small source is analyzed with a fake resident-graph plugin,
lowered to IR with the resident plugin type map, and rendered through the Rust
generator. A resident (opaque, no-boundary) plugin value renders as its plain
native Rust type, its helper function is an internal non-exported ``fn``, and a
native-to-native call passes the resident value by shared reference (never
moved, never cloned), so the caller keeps ownership and can reuse it.
"""

from __future__ import annotations

from pathlib import Path

from rextio.analyzer.project_scanner import analyze_project
from rextio.codegen.rust.generator import generate_rust_module
from rextio.config.schema import RextioConfig
from rextio.ir.lowering import PluginTypeMaps, lower_project
from rextio.ir.types import RxtPluginType
from rextio.plugins.api import (
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

PLUGIN_ID = "rextio-graph"
GRAPH_KEY = "rextio-graph/graph"

GRAPH = PluginType(
    key=GRAPH_KEY,
    annotations=("rextio_graph.types.Graph",),
    rust_type="GraphData",
    conversion=None,
)

RXT_GRAPH = RxtPluginType(key=GRAPH_KEY, native_rust="GraphData", resident=True)

TYPE_MAPS = PluginTypeMaps(
    by_key={GRAPH_KEY: RXT_GRAPH},
    by_spelling={"rextio_graph.types.Graph": RXT_GRAPH},
)
TYPES_BY_KEY = {GRAPH_KEY: RXT_GRAPH}

STRUCT_HELPER = (
    "struct GraphData { nodes: Vec<i64> }\n"
    "impl GraphData {\n"
    "    fn new(nodes: &Vec<i64>) -> GraphData { GraphData { nodes: nodes.clone() } }\n"
    "    fn with_node(&self, n: i64) -> GraphData {\n"
    "        let mut v = self.nodes.clone(); v.push(n); GraphData { nodes: v }\n"
    "    }\n"
    "    fn count(&self) -> i64 { self.nodes.len() as i64 }\n"
    "}"
)


class GraphProvider:
    plugin_id = PLUGIN_ID
    api_version = "1.3"

    def claim(self, site: ClaimSite, config: RextioConfig):
        if site.kind == "call" and site.target == "rextio_graph.new":
            return Claimed(rule_id="rextio-graph/new", result_type=GRAPH_KEY)
        if site.kind == "call" and site.target == "rextio_graph.push":
            return Claimed(rule_id="rextio-graph/push", result_type=GRAPH_KEY)
        if site.kind == "call" and site.target == "rextio_graph.node_total":
            return Claimed(rule_id="rextio-graph/node_total", result_type="int")
        return NotCovered()

    def lower(self, site: ClaimSite, ctx: LoweringContext) -> LoweredExpr:
        if site.target == "rextio_graph.new":
            return LoweredExpr(rust=f"GraphData::new(&{ctx.operands[0]})", helpers=(STRUCT_HELPER,))
        if site.target == "rextio_graph.push":
            return LoweredExpr(
                rust=f"{ctx.operands[0]}.with_node({ctx.operands[1]})", helpers=(STRUCT_HELPER,)
            )
        if site.target == "rextio_graph.node_total":
            return LoweredExpr(rust=f"{ctx.operands[0]}.count()", helpers=(STRUCT_HELPER,))
        raise AssertionError(f"unexpected lowered site: {site}")


def make_registry(provider: object) -> PluginRegistry:
    plugin = RextioPlugin(
        id=PLUGIN_ID,
        name=PLUGIN_ID,
        packages=("rextio_graph",),
        rules_provided=True,
        api_version="1.3",
        lowering_provided=True,
    )
    return PluginRegistry(
        enabled=(PLUGIN_ID,),
        discovered=(plugin,),
        active=(plugin,),
        types=(PluginTypeBinding(plugin_id=PLUGIN_ID, plugin_type=GRAPH),),
        providers=(PluginProviderBinding(plugin_id=PLUGIN_ID, provider=provider),),
    )


def write_module(root: Path, contents: str) -> None:
    path = root / "src" / "myapp" / "kernels.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")


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


def _render(tmp_path: Path) -> str:
    write_module(tmp_path, CHAIN_MODULE)
    analysis = analyze_project(
        tmp_path, plugin_registry=make_registry(GraphProvider()), plugin_config=RextioConfig()
    )
    module_ir = lower_project(analysis, plugin_types=TYPE_MAPS)
    return generate_rust_module(
        module_ir,
        plugin_providers={PLUGIN_ID: GraphProvider()},
        plugin_types_by_key=TYPES_BY_KEY,
    )


def test_resident_helper_is_internal_non_exported_fn(tmp_path: Path) -> None:
    source = _render(tmp_path)
    # The resident helper takes the plain native Rust type by shared reference
    # (opaque, no boundary conversion, no interpreter token, no #[pyfunction])
    # and returns it owned.
    assert "g: &GraphData" in source
    assert "-> PyResult<GraphData>" in source
    assert "GraphData::new(&" in source
    # No materialized boundary machinery is emitted for the resident helper.
    assert "as_array" not in source
    assert "<'py>" not in source
    # The struct helper is emitted exactly once (deduplicated by exact text).
    assert source.count("struct GraphData") == 1


def test_resident_helper_is_not_pyo3_exported(tmp_path: Path) -> None:
    source = _render(tmp_path)
    # The exported entry `build` gets a #[pyfunction]; the resident helper does
    # not (it is reachable only native-to-native).
    assert "#[pyfunction]" in source
    # Only one function is registered with the module (build), not the helper.
    extend_name = "myapp__kernels__extend"
    build_name = "myapp__kernels__build"
    assert f"wrap_pyfunction!({build_name}" in source
    assert f"wrap_pyfunction!({extend_name}" not in source


def test_native_call_borrows_resident_value(tmp_path: Path) -> None:
    source = _render(tmp_path)
    # build calls the resident helper native-to-native, BORROWING the resident
    # local (`&g`), never moving it and never `.clone()` (a resident type need
    # not implement Clone). The caller keeps ownership of `g`.
    assert "myapp__kernels__extend(&g, extra.clone())?" in source
    assert "g.clone()" not in source
    # The final consumption crosses back to Python as a plain int.
    assert ".count()" in source
    assert "-> PyResult<i64>" in source


DIRECT_MODULE = """
import rextio_graph as rextio_graph
from rextio_graph.types import Graph


def extend(g: Graph, n: int) -> Graph:
    return rextio_graph.push(g, n)


def build_direct(nodes: list[int], extra: int) -> int:
    # A plugin-produced resident value is passed DIRECTLY into the native helper
    # as a temporary — there is no intermediate local to borrow.
    return rextio_graph.node_total(extend(rextio_graph.new(nodes), extra))


def build_nested(nodes: list[int], a: int, b: int) -> int:
    # A nested native helper call returns a resident value passed straight into
    # the OUTER native helper — the inner result is a resident temporary.
    g = rextio_graph.new(nodes)
    return rextio_graph.node_total(extend(extend(g, a), b))
"""


def test_native_call_borrows_resident_temporary_from_plugin(tmp_path: Path) -> None:
    # `extend(rextio_graph.new(nodes), extra)`: the plugin-produced resident
    # temporary is BORROWED into the native helper (`&(GraphData::new(...))`),
    # evaluated exactly once, never moved and never cloned. The pre-fix code
    # passed it by value (`extend((GraphData::new(...)), ...)`), a type error
    # against the `&GraphData` helper parameter — a fail-open codegen bug.
    source = _render_source(tmp_path, DIRECT_MODULE)
    assert "myapp__kernels__extend(&(GraphData::new(" in source
    assert "myapp__kernels__extend((GraphData::new(" not in source
    assert "g: &GraphData" in source


def test_native_call_borrows_nested_native_resident_result(tmp_path: Path) -> None:
    # `extend(extend(g, a), b)`: the inner native helper returns a resident value
    # rendered `helper(...)?`; it is borrowed into the outer helper as `&(...)`,
    # whose parentheses make the trailing `?` bind to the borrow correctly.
    source = _render_source(tmp_path, DIRECT_MODULE)
    assert "myapp__kernels__extend(&(myapp__kernels__extend(&g, " in source


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
    return rextio_graph.node_total(g) + rextio_graph.node_total(g2) + rextio_graph.node_total(g3)


def build_same_call(nodes: list[int]) -> int:
    g = rextio_graph.new(nodes)
    return pair_total(g, g)
"""


def _render_source(tmp_path: Path, contents: str) -> str:
    write_module(tmp_path, contents)
    analysis = analyze_project(
        tmp_path, plugin_registry=make_registry(GraphProvider()), plugin_config=RextioConfig()
    )
    module_ir = lower_project(analysis, plugin_types=TYPE_MAPS)
    return generate_rust_module(
        module_ir,
        plugin_providers={PLUGIN_ID: GraphProvider()},
        plugin_types_by_key=TYPES_BY_KEY,
    )


def test_resident_value_reused_after_native_helper_borrow(tmp_path: Path) -> None:
    # `g` is produced once, borrowed into TWO separate native-helper calls, and
    # then the ORIGINAL `g` is ALSO consumed by a plugin claim after both borrows.
    # Borrowing (not moving) makes this well-formed: `g` is never invalidated and
    # the graph is never cloned, so the producer keeps ownership throughout.
    source = _render_source(tmp_path, REUSE_MODULE)
    assert source.count("myapp__kernels__extend(&g, ") == 2
    # The original `g` is consumed directly (bare identifier, borrowed by the
    # plugin snippet's `.count()`), proving the value survives the helper borrows.
    assert "g.count()" in source
    assert "g.clone()" not in source


def test_resident_value_passed_twice_in_one_call(tmp_path: Path) -> None:
    # The same resident local is passed as BOTH arguments of one native call —
    # two shared borrows in a single call, which immutable-borrow semantics
    # permit (no move, no clone).
    source = _render_source(tmp_path, REUSE_MODULE)
    assert "myapp__kernels__pair_total(&g, &g)?" in source
    assert "g.clone()" not in source
    # Both resident parameters lower to shared references.
    assert "a: &GraphData" in source
    assert "b: &GraphData" in source
