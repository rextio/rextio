"""Analyzer coverage for plugin API 1.3 method-receiver metadata (WP-4).

A method claim site (``obj.method(...)``) distinguishes the receiver value from
the ordinary positional arguments: the receiver carries its own resolved type,
declared schema (when any), expression-shape classification, and single-eval
safety flag, while the positional args stay in ``operand_types``. Receiver
metadata is offered only to providers advertising ``api_version >= 1.3``; 1.1
and 1.2 providers keep the exact pre-1.3 site shape.
"""

from __future__ import annotations

from pathlib import Path

from rextio.analyzer.models import FunctionAnalysis, ProjectAnalysis
from rextio.analyzer.plugin_claims import classify_receiver
from rextio.analyzer.project_scanner import analyze_project
from rextio.config.schema import RextioConfig
from rextio.plugins.api import (
    BoundaryConversion,
    Claimed,
    ClaimSite,
    NotCovered,
    PluginType,
    ReceiverMeta,
)
from rextio.plugins.models import (
    PluginProviderBinding,
    PluginRegistry,
    PluginTypeBinding,
    RextioPlugin,
)

FRAME = PluginType(
    key="rextio-frame/frame",
    annotations=("rextio_frame.types.Frame",),
    rust_type="FrameData",
    conversion=BoundaryConversion(
        param_rust="PyRef<'py, PyFrame>",
        param_expr="{param}.borrow().clone_data()",
        return_rust="pyo3::Bound<'py, PyFrame>",
        return_expr="PyFrame::new(py, {value})",
    ),
)


class FrameProvider:
    """A 1.3 provider claiming ``frame.total()`` method sites and recording them."""

    plugin_id = "rextio-frame"
    api_version = "1.3"

    def __init__(self) -> None:
        self.receivers: list[ReceiverMeta | None] = []

    def claim(self, site: ClaimSite, config: RextioConfig):
        # A method call is a call whose receiver value resolves to our type; the
        # method name is the last segment of the dotted target.
        if site.kind != "call":
            return NotCovered()
        method = site.target.rpartition(".")[2]
        if site.receiver is not None and site.receiver.arg_type == FRAME.key:
            self.receivers.append(site.receiver)
            if method == "total":
                return Claimed(rule_id="rextio-frame/total", result_type="int")
        return NotCovered()


class FrameProvider12(FrameProvider):
    """Same claims, but advertising plugin API 1.2 (must never see a receiver)."""

    api_version = "1.2"


def make_registry(provider: object) -> PluginRegistry:
    plugin = RextioPlugin(
        id="rextio-frame",
        name="rextio-frame",
        packages=("rextio_frame",),
        rules_provided=True,
        api_version=str(getattr(provider, "api_version")),
        lowering_provided=True,
    )
    return PluginRegistry(
        enabled=("rextio-frame",),
        discovered=(plugin,),
        active=(plugin,),
        types=(PluginTypeBinding(plugin_id="rextio-frame", plugin_type=FRAME),),
        providers=(PluginProviderBinding(plugin_id="rextio-frame", provider=provider),),
    )


def write_module(root: Path, contents: str) -> None:
    path = root / "src" / "myapp" / "kernels.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")


def analyze(root: Path, provider: object) -> ProjectAnalysis:
    return analyze_project(
        root, plugin_registry=make_registry(provider), plugin_config=RextioConfig()
    )


def function_named(analysis: ProjectAnalysis, qualname: str) -> FunctionAnalysis:
    for module in analysis.modules:
        for function in module.functions:
            if function.qualname == qualname:
                return function
    raise AssertionError(f"function not found: {qualname}")


METHOD_MODULE = """
from rextio_frame.types import Frame


def kernel(df: Frame) -> int:
    return df.total()
"""


def test_method_call_records_receiver_metadata(tmp_path: Path) -> None:
    write_module(tmp_path, METHOD_MODULE)
    provider = FrameProvider()
    analysis = analyze(tmp_path, provider)

    kernel = function_named(analysis, "myapp.kernels.kernel")
    assert kernel.accepted is True
    assert kernel.route == "native-plugin:rextio-frame"
    assert len(kernel.plugin_claims) == 1
    claim = kernel.plugin_claims[0]
    # The receiver is distinguished from the (empty) positional args.
    assert claim.operand_types == ()
    assert claim.receiver is not None
    assert claim.receiver.arg_type == FRAME.key
    assert claim.receiver.expr_kind == "name"
    assert claim.receiver.is_safe is True
    # The declared-schema surface is separate; a schemaless receiver is None.
    assert claim.receiver.schema is None


def test_receiver_metadata_survives_to_dict(tmp_path: Path) -> None:
    write_module(tmp_path, METHOD_MODULE)
    analysis = analyze(tmp_path, FrameProvider())
    claim = function_named(analysis, "myapp.kernels.kernel").plugin_claims[0]
    data = claim.to_dict()
    assert data["receiver"] == {
        "arg_type": FRAME.key,
        "expr_kind": "name",
        "is_safe": True,
        "schema": None,
    }


def test_receiver_offered_to_provider(tmp_path: Path) -> None:
    write_module(tmp_path, METHOD_MODULE)
    provider = FrameProvider()
    analyze(tmp_path, provider)
    # The provider actually observed a receiver-bearing site (not a stripped one).
    assert provider.receivers
    assert all(r is not None and r.arg_type == FRAME.key for r in provider.receivers)


def test_api_12_provider_never_sees_receiver(tmp_path: Path) -> None:
    write_module(tmp_path, METHOD_MODULE)
    provider = FrameProvider12()
    analysis = analyze(tmp_path, provider)
    # A 1.2 provider is offered the site (its receiver type matches its package),
    # but the 1.3 receiver metadata is stripped: it always sees receiver=None.
    assert provider.receivers == [] or all(r is None for r in provider.receivers)
    kernel = function_named(analysis, "myapp.kernels.kernel")
    # With no receiver visible the 1.2 provider cannot claim total(); the method
    # call is unclaimed and the function stays off the native-plugin route.
    assert all(claim.receiver is None for claim in kernel.plugin_claims)


PLAIN_CALL_MODULE = """
import rextio_frame as rextio_frame


def kernel(n: int) -> int:
    return rextio_frame.total(n)
"""


def test_module_qualified_call_has_no_receiver(tmp_path: Path) -> None:
    # ``rextio_frame.total(n)`` is a module-qualified function call: its base
    # (``rextio_frame``) has no value type, so there is no receiver.
    write_module(tmp_path, PLAIN_CALL_MODULE)

    class ModuleProvider:
        plugin_id = "rextio-frame"
        api_version = "1.3"

        def claim(self, site: ClaimSite, config: RextioConfig):
            if site.kind == "call" and site.target == "rextio_frame.total":
                assert site.receiver is None
                return Claimed(rule_id="rextio-frame/total", result_type="int")
            return NotCovered()

    analysis = analyze(tmp_path, ModuleProvider())
    kernel = function_named(analysis, "myapp.kernels.kernel")
    assert kernel.plugin_claims[0].receiver is None


def test_classify_receiver_shapes() -> None:
    import ast

    def classify(expr: str) -> tuple[str, bool]:
        return classify_receiver(ast.parse(expr, mode="eval").body)

    # Only a plain local name is intrinsically safe: reading a Rust local is
    # pure and repeatable.
    assert classify("df") == ("name", True)
    # Attribute access can fire a descriptor / __getattr__ — never intrinsically
    # safe, even rooted in a plain name.
    assert classify("self.df") == ("attribute", False)
    # Subscript invokes __getitem__ (and evaluates the key) — unsafe.
    assert classify("frames[0]") == ("subscript", False)
    # A call anywhere in the receiver chain is unsafe (must be bound once).
    assert classify("get_df()") == ("call", False)
    assert classify("get_df().view") == ("attribute", False)
    assert classify("frames[key()].df") == ("attribute", False)
