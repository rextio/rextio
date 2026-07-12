from __future__ import annotations

import ast
from pathlib import Path

import pytest

from rextio.analyzer.diagnostics import Diagnostic
from rextio.analyzer.models import FunctionAnalysis, ProjectAnalysis
from rextio.analyzer.project_scanner import analyze_project
from rextio.config.schema import RextioConfig
from rextio.plugins.api import (
    BoundaryConversion,
    Claimed,
    ClaimSite,
    NotCovered,
    PluginType,
    Rejected,
)
from rextio.plugins.loader import PluginError
from rextio.plugins.models import (
    PluginProviderBinding,
    PluginRegistry,
    PluginTypeBinding,
    RextioPlugin,
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


class NumpyProvider:
    plugin_id = "rextio-numpy"
    api_version = "1.1"

    def claim(self, site: ClaimSite, config: RextioConfig):
        if site.kind == "call" and site.target == "numpy.dot":
            if all(operand == F64_ARR1.key for operand in site.operand_types):
                return Claimed(rule_id="rextio-numpy/dot-float64", result_type="float")
            return Rejected(
                diagnostic=Diagnostic(
                    code="RXTP-NUMPY-010",
                    severity="error",
                    message="numpy.dot requires float64 1-D array operands",
                    file_path="",
                    line=0,
                    column=0,
                )
            )
        if site.kind == "binop" and site.target == "+":
            return Claimed(
                rule_id="rextio-numpy/elementwise-float64",
                result_type=site.operand_types[0],
            )
        if site.kind == "call" and site.target == "numpy.mean":
            return Rejected(
                diagnostic=Diagnostic(
                    code="RXTP-NUMPY-010",
                    severity="error",
                    message="axis reductions are not covered by the initial surface",
                    file_path="",
                    line=0,
                    column=0,
                )
            )
        return NotCovered()


def make_registry(*providers: object) -> PluginRegistry:
    plugins = []
    provider_bindings = []
    type_bindings = []
    for index, provider in enumerate(providers):
        plugin_id = getattr(provider, "plugin_id", f"rextio-p{index}")
        plugins.append(
            RextioPlugin(
                id=plugin_id,
                name=plugin_id,
                packages=("numpy",),
                rules_provided=True,
                api_version="1.1",
                lowering_provided=True,
            )
        )
        provider_bindings.append(PluginProviderBinding(plugin_id=plugin_id, provider=provider))
        if plugin_id == "rextio-numpy":
            type_bindings.append(PluginTypeBinding(plugin_id=plugin_id, plugin_type=F64_ARR1))
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


def function_named(analysis: ProjectAnalysis, qualname: str) -> FunctionAnalysis:
    for module in analysis.modules:
        for function in module.functions:
            if function.qualname == qualname:
                return function
    raise AssertionError(f"function not found: {qualname}")


DOT_MODULE = """
from rextio_numpy.types import F64Arr1
import numpy as np

def dot(a: F64Arr1, b: F64Arr1) -> float:
    return np.dot(a, b)
"""


def test_claimed_call_is_accepted_with_plugin_route(tmp_path: Path) -> None:
    write_module(tmp_path, DOT_MODULE)
    analysis = analyze_project(
        tmp_path, plugin_registry=make_registry(NumpyProvider()), plugin_config=RextioConfig()
    )

    function = function_named(analysis, "myapp.kernels.dot")
    assert function.accepted is True
    assert function.native_status == "accepted"
    assert function.route == "native-plugin:rextio-numpy"
    assert [claim.rule_id for claim in function.plugin_claims] == ["rextio-numpy/dot-float64"]
    assert function.plugin_claims[0].result_type == "float"
    assert not function.error_diagnostics

    data = function.to_dict()
    assert data["route"] == "native-plugin:rextio-numpy"
    assert data["plugin_claims"][0]["target"] == "numpy.dot"


def test_claimed_binop_on_plugin_types(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        """
from rextio_numpy.types import F64Arr1

def add(a: F64Arr1, b: F64Arr1) -> F64Arr1:
    return a + b
""",
    )
    analysis = analyze_project(
        tmp_path, plugin_registry=make_registry(NumpyProvider()), plugin_config=RextioConfig()
    )

    function = function_named(analysis, "myapp.kernels.add")
    assert function.accepted is True
    assert function.route == "native-plugin:rextio-numpy"
    claim = function.plugin_claims[0]
    assert claim.kind == "binop"
    assert claim.target == "+"
    assert claim.result_type == F64_ARR1.key


def test_rejected_claim_carries_plugin_diagnostic(tmp_path: Path) -> None:
    # Auto-discovered candidate: the claim rejection surfaces at the boundary
    # pass (like RXT030), so the candidate stays visible and rejected with the
    # plugin's own diagnostic instead of silently dropping out.
    write_module(
        tmp_path,
        """
import numpy as np
from rextio_numpy.types import F64Arr1

def mean(a: F64Arr1) -> float:
    return np.mean(a)
""",
    )
    analysis = analyze_project(
        tmp_path,
        plugin_registry=make_registry(NumpyProvider()),
        plugin_config=RextioConfig(),
    )

    function = function_named(analysis, "myapp.kernels.mean")
    assert function.native_status == "rejected"
    assert function.route == "fallback-python"
    assert "RXTP-NUMPY-010" in function.rejection_codes
    rejection = next(d for d in function.diagnostics if d.code == "RXTP-NUMPY-010")
    assert rejection.function_name == "myapp.kernels.mean"
    assert rejection.line > 0
    assert not any(d.code == "RXT030" for d in function.diagnostics)


def test_not_covered_call_still_rejects_with_rxt030(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        """
import rextio
import numpy as np
from rextio_numpy.types import F64Arr1

@rextio.native
def cross(a: F64Arr1, b: F64Arr1) -> float:
    return np.cross(a, b)
""",
    )
    analysis = analyze_project(
        tmp_path,
        native_marker="decorator",
        plugin_registry=make_registry(NumpyProvider()),
        plugin_config=RextioConfig(),
    )

    function = function_named(analysis, "myapp.kernels.cross")
    assert function.native_status == "rejected"
    assert "RXT030" in function.rejection_codes
    assert function.plugin_claims == []


def test_plugin_annotation_without_registry_stays_unsupported(tmp_path: Path) -> None:
    # Without an active lowering plugin the annotation stays unresolved. An
    # auto candidate silently stays off; an explicitly marked function rides
    # the existing RXT080 shim (its body reads np.* attributes), exactly as
    # any other marked function with unsupported types does today.
    write_module(
        tmp_path,
        """
import rextio
import numpy as np
from rextio_numpy.types import F64Arr1

@rextio.native
def dot(a: F64Arr1, b: F64Arr1) -> float:
    return np.dot(a, b)

def auto_dot(a: F64Arr1, b: F64Arr1) -> float:
    return np.dot(a, b)
""",
    )
    analysis = analyze_project(tmp_path, native_marker="auto")

    marked = function_named(analysis, "myapp.kernels.dot")
    assert marked.route == "native-shim"
    assert marked.plugin_claims == []

    auto = function_named(analysis, "myapp.kernels.auto_dot")
    assert auto.native_status == "not-candidate"
    assert auto.plugin_claims == []


def test_overlapping_claims_fail_loudly(tmp_path: Path) -> None:
    class OtherProvider(NumpyProvider):
        plugin_id = "rextio-other"

    write_module(tmp_path, DOT_MODULE)
    with pytest.raises(PluginError, match="claimed by multiple plugins"):
        analyze_project(
            tmp_path,
            plugin_registry=make_registry(NumpyProvider(), OtherProvider()),
            plugin_config=RextioConfig(),
        )


def test_claim_engine_absent_means_no_claims(tmp_path: Path) -> None:
    write_module(tmp_path, DOT_MODULE)
    analysis = analyze_project(tmp_path)
    function = function_named(analysis, "myapp.kernels.dot")
    assert function.plugin_claims == []
    assert function.native_status == "not-candidate"


def test_plugin_typed_signature_without_claims_routes_as_plugin(tmp_path: Path) -> None:
    # Council M18: a function with a plugin-typed parameter needs the
    # plugin's boundary conversions and crates even though no body site is
    # claimed, so it must not report native-direct.
    write_module(
        tmp_path,
        """
from rextio_numpy.types import F64Arr1

def peek(a: F64Arr1) -> float:
    return 0.0
""",
    )
    analysis = analyze_project(
        tmp_path, plugin_registry=make_registry(NumpyProvider()), plugin_config=RextioConfig()
    )

    function = function_named(analysis, "myapp.kernels.peek")
    assert function.accepted is True
    assert function.plugin_claims == []
    assert function.plugin_type_keys == [F64_ARR1.key]
    assert function.route == "native-plugin:rextio-numpy"


def test_returning_plugin_typed_parameter_alias_is_rejected(tmp_path: Path) -> None:
    # Council T1 (round 3): the fallback of `return a` returns the caller's
    # own object while the native leg returns a fresh copy — an aliasing
    # divergence the kit's value comparison cannot see. Reject to fallback.
    write_module(
        tmp_path,
        """
import rextio
from rextio_numpy.types import F64Arr1

@rextio.native
def identity(a: F64Arr1) -> F64Arr1:
    return a

@rextio.native
def renamed(a: F64Arr1) -> F64Arr1:
    b = a
    return b

@rextio.native
def fresh(a: F64Arr1, b: F64Arr1) -> F64Arr1:
    return a + b
""",
    )
    analysis = analyze_project(
        tmp_path,
        native_marker="decorator",
        plugin_registry=make_registry(NumpyProvider()),
        plugin_config=RextioConfig(),
    )

    for name in ("identity", "renamed"):
        function = function_named(analysis, f"myapp.kernels.{name}")
        assert function.accepted is False, name
        assert any(
            "alias" in diagnostic.message for diagnostic in function.error_diagnostics
        ), (name, function.diagnostics)
    fresh = function_named(analysis, "myapp.kernels.fresh")
    assert fresh.accepted is True


def test_alias_escape_is_flow_ordered_and_conditional_aware(tmp_path: Path) -> None:
    # Council round 4 (claude/antigravity/minimax): the original single-pass
    # ast.walk visited top-level returns before nested assignments, so a
    # re-alias inside a branch or loop escaped; and rebinding a param to a
    # computed value was falsely rejected. The rewritten walker processes
    # statements in source order, clears alias status on straight-line
    # rebinding, and treats bindings inside branches/loops additively.
    write_module(
        tmp_path,
        """
import rextio
from rextio_numpy.types import F64Arr1

@rextio.native
def if_realias(a: F64Arr1, flag: bool) -> F64Arr1:
    b = a + a
    if flag:
        b = a
    return b

@rextio.native
def for_realias(a: F64Arr1, n: int) -> F64Arr1:
    b = a + a
    for i in range(n):
        b = a
    return b

@rextio.native
def loop_chain(a: F64Arr1, n: int) -> F64Arr1:
    b = a + a
    c = a + a
    for i in range(n):
        c = b
        b = a
    return c

@rextio.native
def branch_then_chain(a: F64Arr1, flag: bool) -> F64Arr1:
    b = a + a
    if flag:
        b = a
    c = b
    return c

@rextio.native
def rebound_param(a: F64Arr1, b: F64Arr1) -> F64Arr1:
    a = a + b
    return a

@rextio.native
def rebound_alias(a: F64Arr1, b: F64Arr1) -> F64Arr1:
    c = a
    c = a + b
    return c

@rextio.native
def cond_rebind_still_alias(a: F64Arr1, b: F64Arr1, flag: bool) -> F64Arr1:
    c = a
    if flag:
        c = a + b
    return c
""",
    )
    analysis = analyze_project(
        tmp_path,
        native_marker="decorator",
        plugin_registry=make_registry(NumpyProvider()),
        plugin_config=RextioConfig(),
    )

    rejected = ("if_realias", "for_realias", "loop_chain", "branch_then_chain")
    for name in rejected:
        function = function_named(analysis, f"myapp.kernels.{name}")
        assert function.accepted is False, name
        assert any(
            "alias" in diagnostic.message for diagnostic in function.error_diagnostics
        ), (name, function.diagnostics)
    # Straight-line rebinding to a computed value clears alias status: both
    # legs bind a fresh object, so returning the name is legal.
    for name in ("rebound_param", "rebound_alias"):
        function = function_named(analysis, f"myapp.kernels.{name}")
        assert function.accepted is True, (name, function.diagnostics)
    # A rebinding on only ONE branch cannot clear: the other path still
    # returns the caller's object (conservative rejection).
    function = function_named(analysis, "myapp.kernels.cond_rebind_still_alias")
    assert function.accepted is False


def test_augmented_assignment_on_plugin_typed_value_is_rejected(tmp_path: Path) -> None:
    # Council T8 (round 3): NumPy's `a += b` mutates in place through the
    # caller's reference; the native lowering rebinds instead. Reject.
    write_module(
        tmp_path,
        """
import rextio
from rextio_numpy.types import F64Arr1

@rextio.native
def accumulate(a: F64Arr1, b: F64Arr1) -> float:
    a += b
    return 0.0
""",
    )
    analysis = analyze_project(
        tmp_path,
        native_marker="decorator",
        plugin_registry=make_registry(NumpyProvider()),
        plugin_config=RextioConfig(),
    )

    function = function_named(analysis, "myapp.kernels.accumulate")
    assert function.accepted is False
    assert any(
        "aliasing semantics" in diagnostic.message
        for diagnostic in function.error_diagnostics
    ), function.diagnostics


def test_parameter_named_py_on_plugin_typed_function_is_rejected(tmp_path: Path) -> None:
    # Council T9 (round 3): plugin-typed PyO3 functions receive an injected
    # `py: pyo3::Python<'py>` token; a user parameter named `py` would emit a
    # duplicate parameter and fail to compile.
    write_module(
        tmp_path,
        """
import rextio
from rextio_numpy.types import F64Arr1

@rextio.native
def scaled(py: float, a: F64Arr1) -> float:
    return py
""",
    )
    analysis = analyze_project(
        tmp_path,
        native_marker="decorator",
        plugin_registry=make_registry(NumpyProvider()),
        plugin_config=RextioConfig(),
    )

    function = function_named(analysis, "myapp.kernels.scaled")
    assert function.accepted is False
    assert "RXT011" in function.rejection_codes


class RejectingBinopProvider(NumpyProvider):
    def claim(self, site: ClaimSite, config: RextioConfig):
        if site.kind == "binop":
            return Rejected(
                diagnostic=Diagnostic(
                    code="RXTP-NUMPY-010",
                    severity="error",
                    message="elementwise op outside the covered surface",
                    file_path="",
                    line=0,
                    column=0,
                )
            )
        return super().claim(site, config)


def test_claim_cache_distinguishes_unresolved_operand_types(tmp_path: Path) -> None:
    # Council T20 (round 3): the claim cache keys on operand_types, so a site
    # first offered with an unresolved (None) operand must not serve its
    # cached verdict to the same target with fully resolved operands.
    from rextio.analyzer.plugin_claims import ClaimEngine

    calls: list[tuple[str | None, ...]] = []

    class CountingProvider(NumpyProvider):
        def claim(self, site: ClaimSite, config: RextioConfig):
            calls.append(site.operand_types)
            if any(operand is None for operand in site.operand_types):
                return NotCovered()
            return Claimed(rule_id="rextio-numpy/dot-float64", result_type="float")

    engine = ClaimEngine(make_registry(CountingProvider()), RextioConfig())
    function = FunctionAnalysis(
        name="f",
        qualname="myapp.kernels.f",
        module_name="myapp.kernels",
        file_path="src/myapp/kernels.py",
        line=1,
        column=0,
    )
    node = ast.parse("numpy.dot(a, b)").body[0].value

    unresolved = engine.claim_call(function, node, "numpy.dot", (None, F64_ARR1.key))
    resolved = engine.claim_call(
        function, node, "numpy.dot", (F64_ARR1.key, F64_ARR1.key)
    )
    cached = engine.claim_call(
        function, node, "numpy.dot", (F64_ARR1.key, F64_ARR1.key)
    )

    assert unresolved == (False, None)
    assert resolved == (True, "float")
    assert cached == (True, "float")
    # Two distinct cache entries; the repeat came from the cache.
    assert calls == [(None, F64_ARR1.key), (F64_ARR1.key, F64_ARR1.key)]


def test_two_plugins_types_in_one_signature_join_the_route(tmp_path: Path) -> None:
    # Council round 5 (glm): the +-joined route form is reachable WITHOUT any
    # multi-claim error - two plugins' types on one signature suffice - so
    # the contract documents the join grammar and this pins it.
    other_type = PluginType(
        key="rextio-other/i64-1d",
        annotations=("otherlib.types.I64Arr1",),
        rust_type="ndarray::Array1<i64>",
        conversion=F64_ARR1.conversion,
    )

    class OtherProvider(NumpyProvider):
        plugin_id = "rextio-other"

        def claim(self, site: ClaimSite, config: RextioConfig):
            return NotCovered()

    registry = make_registry(NumpyProvider(), OtherProvider())
    registry = PluginRegistry(
        enabled=registry.enabled,
        discovered=registry.discovered,
        active=registry.active,
        types=(*registry.types, PluginTypeBinding(plugin_id="rextio-other", plugin_type=other_type)),
        providers=registry.providers,
    )
    write_module(
        tmp_path,
        """
from rextio_numpy.types import F64Arr1
from otherlib.types import I64Arr1

def mixed(a: F64Arr1, b: I64Arr1) -> float:
    return 0.0
""",
    )
    analysis = analyze_project(tmp_path, plugin_registry=registry, plugin_config=RextioConfig())

    function = function_named(analysis, "myapp.kernels.mixed")
    assert function.accepted is True
    assert function.route == "native-plugin:rextio-numpy+rextio-other"


def test_comparisons_on_plugin_typed_values_are_rejected(tmp_path: Path) -> None:
    # Council round 6 (7/8 reviewers): same-plugin-type comparison pairs
    # passed _types_comparable and lowered to raw Rust - ndarray's PartialEq
    # returns a scalar bool where NumPy returns an elementwise bool array, a
    # silent divergence that COMPILED. Plugins have no comparison claim
    # vocabulary this release, so every form rejects.
    write_module(
        tmp_path,
        """
import rextio
from rextio_numpy.types import F64Arr1

@rextio.native
def eq(a: F64Arr1, b: F64Arr1) -> bool:
    return a == b

@rextio.native
def lt(a: F64Arr1, b: F64Arr1) -> bool:
    return a < b

@rextio.native
def chained(a: F64Arr1, b: F64Arr1, c: F64Arr1) -> bool:
    return a == b == c
""",
    )
    analysis = analyze_project(
        tmp_path,
        native_marker="decorator",
        plugin_registry=make_registry(NumpyProvider()),
        plugin_config=RextioConfig(),
    )

    for name in ("eq", "lt", "chained"):
        function = function_named(analysis, f"myapp.kernels.{name}")
        assert function.accepted is False, name
        assert any(
            "comparing plugin-typed values" in diagnostic.message
            for diagnostic in function.error_diagnostics
        ), (name, function.diagnostics)


def test_matmul_on_plugin_typed_values_is_offered_to_plugins(tmp_path: Path) -> None:
    # Council round 6 (glm): the operator allow-set (and the blanket syntax
    # blocklist) rejected `@` BEFORE the claim offer, so _BINOP_SYMBOLS'
    # MatMult entry was dead code. Plugin-typed `@` is now offered first;
    # non-plugin `@` still rejects with the same message.
    class MatmulProvider(NumpyProvider):
        def claim(self, site: ClaimSite, config: RextioConfig):
            if site.kind == "binop" and site.target == "@":
                return Claimed(rule_id="rextio-numpy/dot-float64", result_type="float")
            return super().claim(site, config)

    write_module(
        tmp_path,
        """
import rextio
from rextio_numpy.types import F64Arr1

@rextio.native
def matmul(a: F64Arr1, b: F64Arr1) -> float:
    return a @ b

@rextio.native
def core_matmul(x: float, y: float) -> float:
    return x @ y
""",
    )
    analysis = analyze_project(
        tmp_path,
        native_marker="decorator",
        plugin_registry=make_registry(MatmulProvider()),
        plugin_config=RextioConfig(),
    )

    claimed = function_named(analysis, "myapp.kernels.matmul")
    assert claimed.accepted is True
    assert claimed.route == "native-plugin:rextio-numpy"
    assert len(claimed.plugin_claims) == 1
    core = function_named(analysis, "myapp.kernels.core_matmul")
    assert core.accepted is False


def test_binop_claim_vocabulary_covers_core_arithmetic() -> None:
    # Council round 7 (hy3): the claim vocabulary and core's arithmetic
    # allow-set are defined independently; this pins that every core
    # arithmetic operator stays claimable so the two sets cannot silently
    # drift apart.
    import ast

    from rextio.analyzer.plugin_claims import _BINOP_SYMBOLS

    for op in (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod):
        assert op in _BINOP_SYMBOLS, op.__name__


def test_claim_under_wrong_scope_kind_fails_analysis(tmp_path: Path) -> None:
    # Council round 7 (kimi): a claim must cite a rule whose scope kind
    # matches the site kind, or manifest remediation lookups dangle.
    from rextio.plugins.api import RuleRecord, RuleScope

    class WrongKindProvider(NumpyProvider):
        def claim(self, site: ClaimSite, config: RextioConfig):
            if site.kind == "call" and site.target == "numpy.dot":
                return Claimed(rule_id="rextio-numpy/binop-rule", result_type="float")
            return NotCovered()

    registry = make_registry(WrongKindProvider())
    registry = PluginRegistry(
        enabled=registry.enabled,
        discovered=registry.discovered,
        active=registry.active,
        rule_records=(
            RuleRecord(
                id="rextio-numpy/binop-rule",
                provider="rextio-numpy",
                scope=RuleScope(kind="binop", pattern="x"),
                constraint="c",
                outcome="native",
                diagnostic_code="RXTP-NUMPY-001",
                guidance="g",
            ),
        ),
        types=registry.types,
        providers=registry.providers,
    )
    write_module(tmp_path, DOT_MODULE)
    with pytest.raises(PluginError, match="scope kind"):
        analyze_project(tmp_path, plugin_registry=registry, plugin_config=RextioConfig())


def test_claim_with_unknown_result_type_fails_analysis(tmp_path: Path) -> None:
    # Council round 7 (kimi): a bogus result type previously leaked to
    # codegen; the analyzer is the user-visible gate.
    class BadTypeProvider(NumpyProvider):
        def claim(self, site: ClaimSite, config: RextioConfig):
            if site.kind == "call" and site.target == "numpy.dot":
                return Claimed(rule_id="rextio-numpy/dot-float64", result_type="bad_type")
            return NotCovered()

    write_module(tmp_path, DOT_MODULE)
    with pytest.raises(PluginError, match="neither a core type"):
        analyze_project(
            tmp_path,
            plugin_registry=make_registry(BadTypeProvider()),
            plugin_config=RextioConfig(),
        )


def test_claim_with_unsupported_container_element_type_fails_analysis(tmp_path: Path) -> None:
    # Council round 8 (codex): _is_known_core_type accepted any list[...]/dict[...]
    # shape, so list[object] passed claim validation and only failed in codegen.
    class ContainerTypeProvider(NumpyProvider):
        def claim(self, site: ClaimSite, config: RextioConfig):
            if site.kind == "call" and site.target == "numpy.dot":
                return Claimed(rule_id="rextio-numpy/dot-float64", result_type="list[object]")
            return NotCovered()

    write_module(tmp_path, DOT_MODULE)
    with pytest.raises(PluginError, match="neither a core type"):
        analyze_project(
            tmp_path,
            plugin_registry=make_registry(ContainerTypeProvider()),
            plugin_config=RextioConfig(),
        )


def test_rejection_outside_plugin_namespace_fails_analysis(tmp_path: Path) -> None:
    # Council round 7 (antigravity): a plugin could previously reject with a
    # core-shaped diagnostic code, defeating manifest remediation lookups.
    class ForeignCodeProvider(NumpyProvider):
        def claim(self, site: ClaimSite, config: RextioConfig):
            if site.kind == "call" and site.target == "numpy.dot":
                return Rejected(
                    diagnostic=Diagnostic(
                        code="RXT002",
                        severity="error",
                        message="masquerading as core",
                        file_path="",
                        line=0,
                        column=0,
                    )
                )
            return NotCovered()

    write_module(tmp_path, DOT_MODULE)
    with pytest.raises(PluginError, match="namespace"):
        analyze_project(
            tmp_path,
            plugin_registry=make_registry(ForeignCodeProvider()),
            plugin_config=RextioConfig(),
        )


def test_claim_without_result_type_fails_analysis(tmp_path: Path) -> None:
    # Council round 6 (codex): a Claimed(result_type=None) left the enclosing
    # expression untyped, return validation was skipped, and check reported
    # accepted/native-plugin for a function the analyzer never finished
    # typing.
    class NoneTypeProvider(NumpyProvider):
        def claim(self, site: ClaimSite, config: RextioConfig):
            if site.kind == "call" and site.target == "numpy.dot":
                return Claimed(rule_id="rextio-numpy/dot-float64", result_type=None)
            return super().claim(site, config)

    write_module(tmp_path, DOT_MODULE)
    with pytest.raises(PluginError, match="without a result_type"):
        analyze_project(
            tmp_path,
            plugin_registry=make_registry(NoneTypeProvider()),
            plugin_config=RextioConfig(),
        )


def test_local_name_py_on_plugin_typed_function_is_rejected(tmp_path: Path) -> None:
    # Council round 5 (kimi): a LOCAL named `py` shadows the injected
    # interpreter token in the generated Rust body, so the return conversion
    # receives the local's value and cargo fails - the analyzer must reject
    # it like the parameter case (round-3 T9).
    write_module(
        tmp_path,
        """
import rextio
from rextio_numpy.types import F64Arr1

@rextio.native
def scaled(a: F64Arr1) -> F64Arr1:
    py = 2.0
    return a + a
""",
    )
    analysis = analyze_project(
        tmp_path,
        native_marker="decorator",
        plugin_registry=make_registry(NumpyProvider()),
        plugin_config=RextioConfig(),
    )

    function = function_named(analysis, "myapp.kernels.scaled")
    assert function.accepted is False
    assert "RXT011" in function.rejection_codes


def test_subscript_on_plugin_typed_value_is_rejected(tmp_path: Path) -> None:
    # Council round 5 (codex): a plugin-typed subscript previously fell
    # through to codegen's generic sequence indexing - an unclaimed,
    # uncertified native surface with core's IndexError semantics instead of
    # the library's.
    write_module(
        tmp_path,
        """
import rextio
from rextio_numpy.types import F64Arr1

@rextio.native
def first(a: F64Arr1) -> float:
    return a[0]
""",
    )
    analysis = analyze_project(
        tmp_path,
        native_marker="decorator",
        plugin_registry=make_registry(NumpyProvider()),
        plugin_config=RextioConfig(),
    )

    function = function_named(analysis, "myapp.kernels.first")
    assert function.accepted is False
    assert any(
        "indexing a plugin-typed value" in diagnostic.message
        for diagnostic in function.error_diagnostics
    ), function.diagnostics


def test_rejection_on_internal_allowlist_call_is_still_delivered(tmp_path: Path) -> None:
    # Council round 4 (antigravity): the boundary loop's internal-call
    # allowlist (`len`, `.append`, ...) `continue`d before the rejection
    # lookup, so a plugin's Rejected verdict on e.g. `numpy.append` was
    # recorded but never delivered - the function stayed accepted with an
    # un-lowerable call.
    class AppendRejectingProvider(NumpyProvider):
        def claim(self, site: ClaimSite, config: RextioConfig):
            if site.kind == "call" and site.target == "numpy.append":
                return Rejected(
                    diagnostic=Diagnostic(
                        code="RXTP-NUMPY-010",
                        severity="error",
                        message="numpy.append is not covered by the initial surface",
                        file_path="",
                        line=0,
                        column=0,
                    )
                )
            return super().claim(site, config)

    write_module(
        tmp_path,
        """
import numpy as np
from rextio_numpy.types import F64Arr1

def appender(a: F64Arr1, b: F64Arr1) -> F64Arr1:
    return np.append(a, b)
""",
    )
    analysis = analyze_project(
        tmp_path,
        plugin_registry=make_registry(AppendRejectingProvider()),
        plugin_config=RextioConfig(),
    )

    function = function_named(analysis, "myapp.kernels.appender")
    assert function.native_status == "rejected"
    assert "RXTP-NUMPY-010" in function.rejection_codes
    assert function.route == "fallback-python"


def test_rejected_binop_sharing_position_with_claimed_call_is_delivered(
    tmp_path: Path,
) -> None:
    # Council T2 (round 3): a BinOp's start position equals its leftmost
    # operand's, so `np.dot(a, b) + c` places a rejected binop at the same
    # (line, column) as a CLAIMED call. Position-based matching alone dropped
    # the rejection on both boundary paths; delivery must be kind-aware.
    write_module(
        tmp_path,
        """
import numpy as np
from rextio_numpy.types import F64Arr1

def mixed(a: F64Arr1, b: F64Arr1, c: F64Arr1) -> F64Arr1:
    return np.dot(a, b) + c
""",
    )
    analysis = analyze_project(
        tmp_path,
        plugin_registry=make_registry(RejectingBinopProvider()),
        plugin_config=RextioConfig(),
    )

    function = function_named(analysis, "myapp.kernels.mixed")
    assert function.native_status == "rejected"
    assert "RXTP-NUMPY-010" in function.rejection_codes
    assert function.route == "fallback-python"


def test_rejected_binop_claim_rejects_the_function(tmp_path: Path) -> None:
    # Council round-2 R3: binop rejections have no CallSite, so the boundary
    # pass must still deliver them - previously they were silently dropped
    # and the function stayed accepted with un-lowerable plugin-typed math.
    write_module(
        tmp_path,
        """
from rextio_numpy.types import F64Arr1

def add(a: F64Arr1, b: F64Arr1) -> F64Arr1:
    return a + b
""",
    )
    analysis = analyze_project(
        tmp_path,
        plugin_registry=make_registry(RejectingBinopProvider()),
        plugin_config=RextioConfig(),
    )

    function = function_named(analysis, "myapp.kernels.add")
    assert function.native_status == "rejected"
    assert "RXTP-NUMPY-010" in function.rejection_codes
    assert function.route == "fallback-python"


def test_native_caller_of_plugin_typed_function_is_rejected(tmp_path: Path) -> None:
    # Council round-2 R8: plugin-typed functions compile as PyO3 boundary
    # entry points; a native call into one would emit wrong-arity Rust.
    write_module(
        tmp_path,
        """
import numpy as np
from rextio_numpy.types import F64Arr1

def dot(a: F64Arr1, b: F64Arr1) -> float:
    return np.dot(a, b)

def use(a: F64Arr1, b: F64Arr1) -> float:
    return dot(a, b)
""",
    )
    analysis = analyze_project(
        tmp_path,
        plugin_registry=make_registry(NumpyProvider()),
        plugin_config=RextioConfig(),
    )

    callee = function_named(analysis, "myapp.kernels.dot")
    assert callee.native_status == "accepted"
    caller = function_named(analysis, "myapp.kernels.use")
    assert caller.native_status == "rejected"
    assert "RXT092" in caller.rejection_codes


def test_used_plugin_ids_excludes_unused_active_plugins(tmp_path: Path) -> None:
    # Council round 8 (codex): only plugins whose lowering an accepted function
    # actually uses may contribute crates; an enabled-but-unused plugin must
    # not be injected.
    from rextio.build.orchestrator import _used_plugin_ids

    write_module(
        tmp_path,
        """
import numpy as np
from rextio_numpy.types import F64Arr1

def dot(a: F64Arr1, b: F64Arr1) -> float:
    return np.dot(a, b)
""",
    )
    analysis = analyze_project(
        tmp_path, plugin_registry=make_registry(NumpyProvider()), plugin_config=RextioConfig()
    )
    assert _used_plugin_ids(analysis) == {"rextio-numpy"}
    # A function that never touches the plugin surface contributes no plugin id.
    write_module(
        tmp_path,
        """
def scalar(a: int, b: int) -> int:
    return a + b
""",
    )
    plain = analyze_project(
        tmp_path, plugin_registry=make_registry(NumpyProvider()), plugin_config=RextioConfig()
    )
    assert _used_plugin_ids(plain) == set()
