from __future__ import annotations

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
    # Council M18: an identity function needs the plugin's boundary
    # conversions and crates even though no body site is claimed, so it must
    # not report native-direct.
    write_module(
        tmp_path,
        """
from rextio_numpy.types import F64Arr1

def identity(a: F64Arr1) -> F64Arr1:
    return a
""",
    )
    analysis = analyze_project(
        tmp_path, plugin_registry=make_registry(NumpyProvider()), plugin_config=RextioConfig()
    )

    function = function_named(analysis, "myapp.kernels.identity")
    assert function.accepted is True
    assert function.plugin_claims == []
    assert function.plugin_type_keys == [F64_ARR1.key]
    assert function.route == "native-plugin:rextio-numpy"


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
