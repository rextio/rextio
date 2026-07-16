"""End-to-end real-cargo proof of plugin API 1.3 resident values + chaining.

A resident (opaque, no-boundary) plugin value is constructed by a claimed
plugin expression, passed through one accepted native helper (native-to-native,
no Python round-trip), and consumed by another plugin claim whose result — a
plain ``int`` — is all that crosses back to Python. The generated extension
compiles with real cargo and runs. A companion negative case proves a resident
value cannot cross an exported PyO3 boundary (RXT092, fail closed).
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

from rextio.cli.main import main
from rextio.config.schema import RextioConfig
from rextio.plugins.api import (
    Claimed,
    ClaimSite,
    CoverageDecl,
    LoweredExpr,
    NotCovered,
    PluginType,
    RuleRecord,
    RuleScope,
)
from rextio.plugins.models import RextioPlugin

GRAPH = PluginType(
    key="rextio-graph/graph",
    annotations=("rextio_graph_types.Graph",),
    rust_type="GraphData",
    conversion=None,
)

# GraphData deliberately does NOT derive Clone: immutable-borrow chaining must
# never require a resident type to be Clone (the generated code borrows the value
# across native-to-native calls rather than moving or cloning it). If codegen
# ever emitted a `.clone()` on a resident value, this crate would fail to build.
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


class FakeGraphPlugin:
    plugin_id = "rextio-graph"
    api_version = "1.3"

    def to_rextio_plugin(self) -> RextioPlugin:
        return RextioPlugin(id="rextio-graph", name="Graph to Rust (e2e fake)")

    def covers(self) -> CoverageDecl:
        return CoverageDecl(packages=("rextio_graph",))

    def describe(self, config: RextioConfig) -> tuple[RuleRecord, ...]:
        return (
            RuleRecord(
                id="rextio-graph/new",
                provider="rextio-graph",
                scope=RuleScope(kind="call", pattern="rextio_graph.new"),
                constraint="Builds a resident graph from a node list.",
                outcome="native",
                diagnostic_code=None,
                guidance="Pass a list[int] of node ids.",
                stability="experimental",
            ),
            RuleRecord(
                id="rextio-graph/push",
                provider="rextio-graph",
                scope=RuleScope(kind="call", pattern="rextio_graph.push"),
                constraint="Returns a new resident graph with one extra node.",
                outcome="native",
                diagnostic_code=None,
                guidance="Pass a resident graph and an int node id.",
                stability="experimental",
            ),
            RuleRecord(
                id="rextio-graph/node_total",
                provider="rextio-graph",
                scope=RuleScope(kind="call", pattern="rextio_graph.node_total"),
                constraint="Consumes a resident graph, returning its node count.",
                outcome="native",
                diagnostic_code=None,
                guidance="Pass a resident graph.",
                stability="experimental",
            ),
        )

    def type_vocabulary(self) -> tuple[PluginType, ...]:
        return (GRAPH,)

    def claim(self, site: ClaimSite, config: RextioConfig):
        if site.kind == "call" and site.target == "rextio_graph.new":
            return Claimed(rule_id="rextio-graph/new", result_type=GRAPH.key)
        if site.kind == "call" and site.target == "rextio_graph.push":
            return Claimed(rule_id="rextio-graph/push", result_type=GRAPH.key)
        if site.kind == "call" and site.target == "rextio_graph.node_total":
            return Claimed(rule_id="rextio-graph/node_total", result_type="int")
        return NotCovered()

    def lower(self, site: ClaimSite, ctx) -> LoweredExpr:
        if site.target == "rextio_graph.new":
            return LoweredExpr(rust=f"GraphData::new(&{ctx.operands[0]})", helpers=(STRUCT_HELPER,))
        if site.target == "rextio_graph.push":
            return LoweredExpr(
                rust=f"{ctx.operands[0]}.with_node({ctx.operands[1]})", helpers=(STRUCT_HELPER,)
            )
        if site.target == "rextio_graph.node_total":
            return LoweredExpr(rust=f"{ctx.operands[0]}.count()", helpers=(STRUCT_HELPER,))
        raise AssertionError(f"unexpected lower target: {site.target}")

    def crate_dependencies(self):
        return ()


class _FakeEntryPoint:
    name = "rextio-graph"
    dist = None

    def load(self) -> object:
        return FakeGraphPlugin()


def _write_project(tmp_path: Path) -> Path:
    (tmp_path / "rextio.toml").write_text(
        """
[rust]
build_tool = "cargo"

[plugins]
enabled = ["rextio-graph"]
""",
        encoding="utf-8",
    )
    # The runtime graph package lives OUTSIDE the analyzed source root (like an
    # installed third-party package: numpy in the sibling numpy test), so the
    # analyzer treats ``rextio_graph.*`` as external plugin-covered calls rather
    # than project functions. Its Python implementation backs the fallback path.
    runtime = tmp_path / "runtime"
    pkg = runtime / "rextio_graph"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text(
        """
class Graph:
    def __init__(self, nodes):
        self.nodes = list(nodes)


def new(nodes):
    return Graph(nodes)


def push(g, n):
    g2 = Graph(g.nodes)
    g2.nodes.append(n)
    return g2


def node_total(g):
    return len(g.nodes)
""",
        encoding="utf-8",
    )
    # The annotation vocabulary is a plain runtime alias of the resident type,
    # resolved statically by the plugin vocabulary at analysis time and imported
    # only by the fallback at runtime.
    (runtime / "rextio_graph_types.py").write_text(
        "from rextio_graph import Graph\n", encoding="utf-8"
    )
    app = tmp_path / "src" / "graph_app"
    app.mkdir(parents=True)
    (app / "__init__.py").write_text("", encoding="utf-8")
    return app


CHAIN_SOURCE = """
import rextio_graph
from rextio_graph_types import Graph


def extend(g: Graph, n: int) -> Graph:
    return rextio_graph.push(g, n)


def pair_total(a: Graph, b: Graph) -> int:
    return rextio_graph.node_total(a) + rextio_graph.node_total(b)


def build(nodes: list[int], extra: int) -> int:
    g = rextio_graph.new(nodes)
    g2 = extend(g, extra)
    return rextio_graph.node_total(g2)


def build_direct(nodes: list[int], extra: int) -> int:
    # The plugin-produced resident value is passed DIRECTLY into the native
    # helper as a temporary (no intermediate local): `extend(new(...), extra)`.
    # Codegen must borrow the temporary (`&(...)`), never move or clone it.
    return rextio_graph.node_total(extend(rextio_graph.new(nodes), extra))


def build_nested(nodes: list[int], a: int, b: int) -> int:
    # A nested native helper call returns a resident temporary fed straight into
    # the OUTER native helper: `extend(extend(g, a), b)`.
    g = rextio_graph.new(nodes)
    return rextio_graph.node_total(extend(extend(g, a), b))


def build_reuse(nodes: list[int], a: int, b: int) -> int:
    # `g` is produced once, borrowed into TWO separate native helper calls, and
    # then the ORIGINAL `g` is ALSO consumed directly by a plugin claim after
    # those borrows — reuse after a borrow, not a use-after-move.
    g = rextio_graph.new(nodes)
    g2 = extend(g, a)
    g3 = extend(g, b)
    return (
        rextio_graph.node_total(g)
        + rextio_graph.node_total(g2)
        + rextio_graph.node_total(g3)
    )


def build_same_call(nodes: list[int]) -> int:
    # The same resident value is passed as BOTH arguments of one native call.
    g = rextio_graph.new(nodes)
    return pair_total(g, g)


def build_rebind(nodes: list[int], extra: int) -> int:
    # A resident LOCAL is rebound to a fresh value of the SAME resident type: the
    # `let mut` binding keeps its type, so this is accepted and compiles. (An
    # incompatible rebind or a resident-parameter rebind is rejected at analysis
    # with RXT092 — proven in tests/analyzer/test_plugin_native_chaining.py — so
    # accepted resident code can never reach an E0308 type mismatch here.)
    g = rextio_graph.new(nodes)
    g = rextio_graph.push(g, extra)
    return rextio_graph.node_total(g)
"""


def test_real_cargo_resident_chain_builds_and_runs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from rextio.plugins import loader as plugin_loader

    monkeypatch.setattr(plugin_loader, "_plugin_entry_points", lambda _eps: (_FakeEntryPoint(),))

    app = _write_project(tmp_path)
    (app / "kernels.py").write_text(CHAIN_SOURCE, encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path / "runtime"))

    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])
    capsys.readouterr()
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )
    assert exit_code == 0, report
    assert report["native_build"]["status"] == "built"

    lib_rs = (tmp_path / ".rextio" / "generated" / "rust" / "src" / "lib.rs").read_text(
        encoding="utf-8"
    )
    # The resident helper is an internal fn (never #[pyfunction]); its resident
    # parameters are BORROWED (`&GraphData`) and the value crosses native-to-native
    # calls by shared reference — never moved, never `.clone()`d (GraphData is not
    # even Clone), so the caller may reuse it.
    assert "-> PyResult<GraphData>" in lib_rs
    assert "struct GraphData" in lib_rs
    assert "g: &GraphData" in lib_rs
    assert "a: &GraphData" in lib_rs and "b: &GraphData" in lib_rs
    assert "graph_app__kernels__extend(&" in lib_rs
    assert "graph_app__kernels__pair_total(&" in lib_rs
    assert "wrap_pyfunction!(graph_app__kernels__extend" not in lib_rs
    assert "wrap_pyfunction!(graph_app__kernels__pair_total" not in lib_rs
    assert "wrap_pyfunction!(graph_app__kernels__build" in lib_rs
    # A plugin-produced resident TEMPORARY passed directly into the native helper
    # is borrowed (`&(GraphData::new(...))`), never moved (the pre-fix by-value
    # form `extend((GraphData::new(...))` would not compile against `&GraphData`).
    assert "graph_app__kernels__extend(&(GraphData::new(" in lib_rs
    assert "graph_app__kernels__extend((GraphData::new(" not in lib_rs
    # A nested native helper's resident result is borrowed into the outer helper;
    # the `&(...)` parentheses bind the trailing `?` to the borrow.
    assert "graph_app__kernels__extend(&(graph_app__kernels__extend(&" in lib_rs

    def _call_all(kernels: object) -> dict[str, int]:
        return {
            "build": kernels.build([10, 20, 30], 99),
            "build_empty": kernels.build([], 1),
            "direct": kernels.build_direct([10, 20, 30], 99),
            "nested": kernels.build_nested([10, 20, 30], 1, 2),
            "reuse": kernels.build_reuse([10, 20, 30], 1, 2),
            "same_call": kernels.build_same_call([10, 20, 30]),
            "rebind": kernels.build_rebind([10, 20, 30], 99),
        }

    def _fresh_kernels() -> object:
        for module_name in (
            "_rextio_native",
            "graph_app.kernels",
            "rextio_graph",
            "rextio_graph_types",
        ):
            sys.modules.pop(module_name, None)
        return importlib.import_module("graph_app.kernels")

    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))

    # Native leg (mode=native raises on any fallback): the compiled resident chain
    # serves every call, and only the final ints cross back to Python.
    monkeypatch.setenv("REXTIO_NATIVE_MODE", "native")
    native_results = _call_all(_fresh_kernels())

    # Fallback leg (pure-Python graph package): the SAME kernels on the Python
    # fallback. The native results must equal the fallback results — not just a
    # set of hard-coded native values — proving the resident chain is behavior
    # compatible with the fallback it accelerates.
    monkeypatch.setenv("REXTIO_NATIVE_MODE", "fallback")
    fallback_results = _call_all(_fresh_kernels())

    assert native_results == fallback_results
    assert native_results == {
        "build": 4,
        "build_empty": 1,
        "direct": 4,
        "nested": 5,
        "reuse": 11,
        "same_call": 6,
        "rebind": 4,
    }

    for module_name in (
        "_rextio_native",
        "graph_app.kernels",
        "rextio_graph",
        "rextio_graph_types",
    ):
        sys.modules.pop(module_name, None)


def test_real_cargo_resident_boundary_escape_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A resident value cannot cross an exported PyO3 boundary — fail closed."""
    from rextio.plugins import loader as plugin_loader

    monkeypatch.setattr(plugin_loader, "_plugin_entry_points", lambda _eps: (_FakeEntryPoint(),))

    app = _write_project(tmp_path)
    # `escape` is explicitly marked @rextio.native and returns a resident value:
    # a request for a Python-callable native export that cannot honor a resident
    # boundary. It must be rejected (RXT092) and stay on the Python fallback.
    (app / "kernels.py").write_text(
        CHAIN_SOURCE
        + """

import rextio


@rextio.native
def escape(nodes: list[int]) -> Graph:
    return rextio_graph.new(nodes)
""",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path / "runtime"))

    exit_code = main(["check", str(tmp_path)])
    capsys.readouterr()
    assert exit_code == 0
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "check.json").read_text(encoding="utf-8")
    )
    functions = {
        function["qualname"]: function
        for module in report["modules"]
        for function in module["functions"]
    }
    escape = functions["graph_app.kernels.escape"]
    assert escape["native_status"] == "rejected"
    assert "RXT092" in escape["rejection_codes"]
    # The positive chain in the same module is still accepted.
    assert functions["graph_app.kernels.build"]["native_status"] == "accepted"


# WP-4 follow-up 5: a fresh resident ALIAS through any binder is rejected before
# Cargo. Aliasing an already-bound resident value into a new local/walrus target
# would need a second owner — codegen's name-copy emits `.clone()` on GraphData,
# which is deliberately NOT Clone (E0599). The fix fails closed at analysis
# (RXT092), so the alias never reaches codegen and the valid resident constructor
# + immutable-borrow chain still compiles and runs.
ALIAS_REPRODUCER_SOURCE = """
import rextio_graph
from rextio_graph_types import Graph
import rextio


def good(nodes: list[int]) -> int:
    # Valid resident constructor + immutable borrow (the chain the alias fix must
    # keep compiling and executing).
    g = rextio_graph.new(nodes)
    return rextio_graph.node_total(g)


@rextio.native
def alias_param(g: Graph, k: int) -> int:
    # Aliasing a resident PARAMETER into a fresh local has no core reference
    # representation. The body carries no runtime-fidelity call, so this is NOT
    # shimmable and the centralized resident-alias rejection surfaces as a hard
    # RXT092 in the report rather than being masked by an RXT080 shim.
    h = g
    return k


def alias_walrus(nodes: list[int]) -> int:
    # The exact reviewer reproducer: a comprehension-filter walrus aliases the
    # already-bound resident local `g` into `h`. Pre-fix this was accepted as
    # native-plugin and codegen emitted the equivalent of `h = Some(g.clone())`,
    # so Cargo failed E0599 against the non-Clone GraphData. It now leaves the
    # native path, so the crate builds.
    g = rextio_graph.new(nodes)
    xs = [n for n in nodes if rextio_graph.node_total(h := g) > 0]
    return len(xs)
"""


def test_real_cargo_resident_alias_is_rejected_before_cargo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from rextio.plugins import loader as plugin_loader

    monkeypatch.setattr(plugin_loader, "_plugin_entry_points", lambda _eps: (_FakeEntryPoint(),))

    app = _write_project(tmp_path)
    (app / "kernels.py").write_text(ALIAS_REPRODUCER_SOURCE, encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path / "runtime"))

    # Route/rejection evidence (fast, no toolchain): the marked resident-parameter
    # alias is a HARD RXT092 rejection; the unmarked walrus reproducer leaves the
    # native path; the valid constructor/borrow chain stays accepted native.
    assert main(["check", str(tmp_path)]) == 0
    capsys.readouterr()
    check_report = json.loads(
        (tmp_path / ".rextio" / "reports" / "check.json").read_text(encoding="utf-8")
    )
    functions = {
        function["qualname"]: function
        for module in check_report["modules"]
        for function in module["functions"]
    }
    alias_param = functions["graph_app.kernels.alias_param"]
    assert alias_param["native_status"] == "rejected"
    assert alias_param["rejection_codes"] == ["RXT092"]
    assert alias_param["route"] == "fallback-python"

    alias_walrus = functions["graph_app.kernels.alias_walrus"]
    assert alias_walrus["native_status"] != "accepted"
    assert alias_walrus["route"] == "fallback-python"

    good = functions["graph_app.kernels.good"]
    assert good["native_status"] == "accepted"
    assert good["route"] == "native-plugin:rextio-graph"

    # Real-cargo proof: the crate builds (pre-fix the accepted walrus alias would
    # have emitted a GraphData `.clone()` and failed Cargo E0599), and no resident
    # `.clone()` is generated. The valid chain compiles and executes native; the
    # rejected aliases execute on the Python fallback.
    assert main(["build", str(tmp_path), "--fallback=cpython"]) == 0
    capsys.readouterr()
    build_report = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )
    assert build_report["native_build"]["status"] == "built", build_report

    lib_rs = (tmp_path / ".rextio" / "generated" / "rust" / "src" / "lib.rs").read_text(
        encoding="utf-8"
    )
    # The valid resident constructor + borrow is native-exported; the rejected
    # aliases are NOT native (never wrapped as pyfunctions). The GraphData value
    # itself is never cloned — only the constructor's inner `Vec<i64>` is (the
    # struct helper's `nodes.clone()`), never a `GraphData` binding.
    assert "wrap_pyfunction!(graph_app__kernels__good" in lib_rs
    assert "GraphData::new" in lib_rs
    assert "wrap_pyfunction!(graph_app__kernels__alias_walrus" not in lib_rs
    assert "wrap_pyfunction!(graph_app__kernels__alias_param" not in lib_rs

    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))

    def _purge_modules() -> None:
        # Drop the compiled/runtime modules AND every ``graph_app`` submodule (the
        # generated package, its kernels, and its fallback module) so a sibling
        # real-cargo test's cached ``graph_app`` package cannot shadow this one.
        for module_name in list(sys.modules):
            if module_name in ("_rextio_native", "rextio_graph", "rextio_graph_types") or (
                module_name == "graph_app" or module_name.startswith("graph_app.")
            ):
                sys.modules.pop(module_name, None)

    def _fresh_kernels() -> object:
        _purge_modules()
        return importlib.import_module("graph_app.kernels")

    # The valid chain runs native and equals the fallback; the rejected walrus
    # alias runs correctly on the Python fallback (all node_totals > 0, so the
    # comprehension keeps every node).
    monkeypatch.setenv("REXTIO_NATIVE_MODE", "native")
    native_good = _fresh_kernels().good([10, 20, 30])
    monkeypatch.setenv("REXTIO_NATIVE_MODE", "fallback")
    fallback_kernels = _fresh_kernels()
    assert native_good == fallback_kernels.good([10, 20, 30]) == 3
    assert fallback_kernels.alias_walrus([10, 20, 30]) == 3

    _purge_modules()
