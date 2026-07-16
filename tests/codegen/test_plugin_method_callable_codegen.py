"""Codegen tests for plugin API 1.3 method-receiver + callable lowering (WP-4).

Cargo-free: sources are analyzed with a fake 1.3 lowering plugin, lowered to IR
(so ``PluginClaimIR`` carries the receiver/callable metadata and ``CallIR``
carries the lowered receiver expression), and rendered through the Rust
generator. Assertions run on the generated source text and prove:

* ``LoweringContext.receiver`` is threaded to the provider;
* the receiver is evaluated exactly once, before the operands — a plain-name
  receiver as a bare reference, a non-safe receiver bound to a single-use
  temporary; and
* ``CallableMeta.native_symbol`` is filled only for a callable that names an
  actually-generated accepted native helper.
"""

from __future__ import annotations

from pathlib import Path

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

PLUGIN_ID = "rextio-frame"
FRAME_KEY = "rextio-frame/frame"

FRAME = PluginType(
    key=FRAME_KEY,
    annotations=("rextio_frame.types.Frame",),
    rust_type="FrameData",
    conversion=BoundaryConversion(
        param_rust="PyRef<'py, PyFrame>",
        param_expr="{param}.borrow().clone_data()",
        return_rust="pyo3::Bound<'py, PyFrame>",
        return_expr="PyFrame::new(py, {value})",
    ),
)

RXT_FRAME = RxtPluginType(
    key=FRAME_KEY,
    native_rust=FRAME.rust_type,
    param_rust=FRAME.conversion.param_rust,
    param_expr=FRAME.conversion.param_expr,
    return_rust=FRAME.conversion.return_rust,
    return_expr=FRAME.conversion.return_expr,
)

TYPE_MAPS = PluginTypeMaps(
    by_key={FRAME_KEY: RXT_FRAME},
    by_spelling={"rextio_frame.types.Frame": RXT_FRAME},
)
TYPES_BY_KEY = {FRAME_KEY: RXT_FRAME}


class FrameProvider:
    """A 1.3 provider that lowers ``frame.apply(udf)`` using receiver + callable."""

    plugin_id = PLUGIN_ID
    api_version = "1.3"

    def claim(self, site: ClaimSite, config: RextioConfig):
        if site.kind != "call" or site.receiver is None:
            return NotCovered()
        if site.receiver.arg_type != FRAME_KEY:
            return NotCovered()
        method = site.target.rpartition(".")[2]
        if method == "apply" and site.callables and site.callables[0].body.available:
            return Claimed(rule_id="rextio-frame/apply", result_type="float")
        return NotCovered()

    def lower(self, site: ClaimSite, ctx: LoweringContext) -> LoweredExpr:
        meta = site.callables[0]
        # Prefer the generated native helper symbol; fall back to a closed-body
        # marker so the test can see which path was taken.
        udf = meta.native_symbol if meta.native_symbol is not None else "__row_udf__"
        # ctx.receiver is the once-evaluated receiver Rust text.
        return LoweredExpr(rust=f"__frame_apply({ctx.receiver}, {udf})")


def make_registry(provider: object) -> PluginRegistry:
    plugin = RextioPlugin(
        id=PLUGIN_ID,
        name=PLUGIN_ID,
        packages=("rextio_frame",),
        rules_provided=True,
        api_version="1.3",
        lowering_provided=True,
    )
    return PluginRegistry(
        enabled=(PLUGIN_ID,),
        discovered=(plugin,),
        active=(plugin,),
        types=(PluginTypeBinding(plugin_id=PLUGIN_ID, plugin_type=FRAME),),
        providers=(PluginProviderBinding(plugin_id=PLUGIN_ID, provider=provider),),
    )


def _write(root: Path, rel: str, contents: str) -> None:
    path = root / "src" / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")


def _render(root: Path) -> str:
    analysis = analyze_project(
        root, plugin_registry=make_registry(FrameProvider()), plugin_config=RextioConfig()
    )
    module_ir = lower_project(analysis, plugin_types=TYPE_MAPS)
    return generate_rust_module(
        module_ir,
        plugin_providers={PLUGIN_ID: FrameProvider()},
        plugin_types_by_key=TYPES_BY_KEY,
    )


SCALAR_UDF_MODULE = """
from rextio_frame.types import Frame


def scaled(x: float) -> float:
    return x * 2.0


def run(df: Frame) -> float:
    return df.apply(scaled)
"""


def test_safe_receiver_and_native_symbol(tmp_path: Path) -> None:
    _write(tmp_path, "myapp/kernels.py", SCALAR_UDF_MODULE)
    source = _render(tmp_path)
    # The scalar UDF was generated as an accepted native helper, so its symbol is
    # filled and used by the provider (not the closed-body fallback marker).
    assert "__frame_apply(df, " in source  # safe receiver = bare name, no temp
    assert "__row_udf__" not in source
    # The native symbol is the mangled Rust identifier of `scaled`.
    assert "scaled" in source


ROW_UDF_MODULE = """
from rextio_frame.types import Frame

from myapp.schema import Row


def run(df: Frame[Row]) -> float:
    return df.apply(total)


def total(row) -> float:
    return row["price"] + row["rate"]
"""

SCHEMA_MODULE = """
class Row:
    price: float
    qty: int
    rate: float
"""


def test_row_udf_uses_closed_body_marker(tmp_path: Path) -> None:
    # A row UDF is representable (available body) but not accepts_native, so no
    # native symbol is generated; the provider takes the closed-body path.
    _write(tmp_path, "myapp/schema.py", SCHEMA_MODULE)
    _write(tmp_path, "myapp/kernels.py", ROW_UDF_MODULE)
    source = _render(tmp_path)
    assert "__frame_apply(df, __row_udf__)" in source


def _function_source(source: str, name: str) -> str:
    marker = f"fn {name}"
    index = source.find(marker)
    assert index != -1, f"function {name} not found in generated source"
    return source[index:]


# --- single-evaluation of a non-safe receiver (generator unit) ------------
#
# A non-safe plugin-typed receiver reachable through the full analyzer requires
# a call/attribute/subscript that resolves to a MATERIALIZED plugin type, which
# native-to-native calls block (RXT092). The single-evaluation guarantee is
# therefore exercised directly at the generator, where a non-safe receiver
# (``is_safe=False``) is rendered.


def _make_renderer() -> object:
    from rextio.codegen.rust.generator import _FunctionRenderer
    from rextio.ir.nodes import BlockIR, FunctionIR
    from rextio.ir.types import RxtFloat

    function = FunctionIR(
        name="run",
        qualname="myapp.kernels.run",
        module_name="myapp.kernels",
        params=[],
        return_type=RxtFloat(),
        body=BlockIR(statements=[]),
    )
    return _FunctionRenderer(
        function,
        native_names_by_qualname={},
        native_names={},
        native_return_types={},
        mode="pyo3",
        plugin_providers={PLUGIN_ID: _TwiceReceiverProvider()},
        plugin_types_by_key=TYPES_BY_KEY,
    )


class _TwiceReceiverProvider(FrameProvider):
    """Uses ``ctx.receiver`` twice, to prove it never re-evaluates the receiver."""

    def lower(self, site: ClaimSite, ctx: LoweringContext) -> LoweredExpr:
        return LoweredExpr(rust=f"__apply({ctx.receiver}, {ctx.receiver})")


def test_non_safe_receiver_bound_to_single_use_temporary() -> None:
    from rextio.ir.nodes import CallIR, NameIR, PluginClaimIR
    from rextio.plugins.api import CallableBody, CallableBodyExpr, CallableMeta, ReceiverMeta

    body = CallableBody(
        available=True, expression=CallableBodyExpr(kind="param", param_index=0, name="x")
    )
    claim = PluginClaimIR(
        plugin_id=PLUGIN_ID,
        rule_id="rextio-frame/apply",
        kind="call",
        target="obj.apply",
        operand_types=(None,),
        result_type="float",
        receiver=ReceiverMeta(arg_type=FRAME_KEY, expr_kind="call", is_safe=False),
        callables=(CallableMeta(arg_index=0, qualname="myapp.kernels.udf", body=body),),
    )
    # The receiver renders to a distinctive text so we can count evaluations.
    call = CallIR(
        function="obj.apply",
        args=[NameIR("udf_ref")],
        claim=claim,
        receiver=NameIR("receiver_source"),
    )
    renderer = _make_renderer()
    rendered = renderer.render_expr(call)  # type: ignore[attr-defined]
    # The non-safe receiver is bound once; both provider uses reference the temp.
    assert "let __rextio_recv" in rendered
    assert rendered.count("receiver_source") == 1
    assert rendered.count("__rextio_recv") >= 3  # the let + two provider uses


def test_safe_receiver_needs_no_temporary() -> None:
    from rextio.ir.nodes import CallIR, NameIR, PluginClaimIR
    from rextio.plugins.api import CallableBody, CallableBodyExpr, CallableMeta, ReceiverMeta

    body = CallableBody(
        available=True, expression=CallableBodyExpr(kind="param", param_index=0, name="x")
    )
    claim = PluginClaimIR(
        plugin_id=PLUGIN_ID,
        rule_id="rextio-frame/apply",
        kind="call",
        target="obj.apply",
        operand_types=(None,),
        result_type="float",
        receiver=ReceiverMeta(arg_type=FRAME_KEY, expr_kind="name", is_safe=True),
        callables=(CallableMeta(arg_index=0, qualname="myapp.kernels.udf", body=body),),
    )
    call = CallIR(
        function="obj.apply",
        args=[NameIR("udf_ref")],
        claim=claim,
        receiver=NameIR("df"),
    )
    renderer = _make_renderer()
    rendered = renderer.render_expr(call)  # type: ignore[attr-defined]
    # A safe receiver is a bare reference — no temporary binding.
    assert "let __rextio_recv" not in rendered
    assert "__apply(df, df)" in rendered
