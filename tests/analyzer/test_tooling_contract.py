from __future__ import annotations

from pathlib import Path

from rextio.analyzer.diagnostics import Diagnostic
from rextio.analyzer.models import FunctionAnalysis
from rextio.analyzer.project_scanner import analyze_project
from rextio.contract import TOOLING_CONTRACT_VERSION


def write_module(root: Path, name: str, contents: str) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")
    return path


def make_function(**overrides: object) -> FunctionAnalysis:
    defaults: dict[str, object] = {
        "name": "f",
        "qualname": "myapp.mod.f",
        "module_name": "myapp.mod",
        "file_path": "src/myapp/mod.py",
        "line": 1,
        "column": 0,
    }
    defaults.update(overrides)
    return FunctionAnalysis(**defaults)  # type: ignore[arg-type]


def test_route_native_direct() -> None:
    function = make_function(is_native_candidate=True, accepted=True)
    assert function.route == "native-direct"
    assert function.native_status == "accepted"
    assert function.rejection_codes == []


def test_route_native_shim() -> None:
    function = make_function(
        is_native_candidate=True, accepted=True, native_runtime_semantics=True
    )
    assert function.route == "native-shim"
    assert function.native_status == "accepted"


def test_route_rejected_candidate_runs_on_fallback() -> None:
    function = make_function(is_native_candidate=True, accepted=False)
    function.add_diagnostic(
        Diagnostic(
            code="RXT002",
            severity="error",
            message="unsupported argument type",
            file_path="src/myapp/mod.py",
            line=1,
            column=0,
            function_name="f",
        )
    )
    assert function.route == "fallback-python"
    assert function.native_status == "rejected"
    assert function.rejection_codes == ["RXT002"]


def test_rejection_codes_deduplicate_and_ignore_warnings() -> None:
    function = make_function(is_native_candidate=True, accepted=False)
    for line in (1, 2):
        function.add_diagnostic(
            Diagnostic(
                code="RXT010",
                severity="error",
                message="unsupported syntax",
                file_path="src/myapp/mod.py",
                line=line,
                column=0,
                function_name="f",
            )
        )
    function.add_diagnostic(
        Diagnostic(
            code="RXT073",
            severity="warning",
            message="boundary warning",
            file_path="src/myapp/mod.py",
            line=3,
            column=0,
            function_name="f",
        )
    )
    assert function.rejection_codes == ["RXT010"]


def test_route_external_accelerator() -> None:
    function = make_function(external_accelerator="numba")
    assert function.route == "fallback-accelerated:numba"
    assert function.native_status == "not-candidate"
    assert function.rejection_codes == []


def test_route_plain_fallback() -> None:
    function = make_function()
    assert function.route == "fallback-python"
    assert function.native_status == "not-candidate"


def test_function_to_dict_carries_contract_fields() -> None:
    function = make_function(is_native_candidate=True, accepted=True)
    data = function.to_dict()
    assert data["route"] == "native-direct"
    assert data["native_status"] == "accepted"
    assert data["rejection_codes"] == []


def test_project_analysis_json_carries_contract_version_and_routes(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "src/myapp/mod.py",
        """
import rextio
import numba

@rextio.native
def square(x: float) -> float:
    return x * x

@rextio.native
def rejected(handler: object) -> float:
    return handler

@numba.njit
def kernel(x: float) -> float:
    return x * 2.0
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")
    data = analysis.to_dict()

    assert data["contract_version"] == TOOLING_CONTRACT_VERSION

    functions = {
        function["qualname"]: function
        for module in data["modules"]  # type: ignore[union-attr]
        for function in module["functions"]
    }
    accepted = functions["myapp.mod.square"]
    assert accepted["route"] == "native-direct"
    assert accepted["native_status"] == "accepted"

    rejected = functions["myapp.mod.rejected"]
    assert rejected["route"] == "fallback-python"
    assert rejected["native_status"] == "rejected"
    assert rejected["rejection_codes"], "a rejected candidate must carry its codes"
    assert all(code.startswith("RXT") for code in rejected["rejection_codes"])

    accelerated = functions["myapp.mod.kernel"]
    assert accelerated["route"] == "fallback-accelerated:numba"
    assert accelerated["native_status"] == "not-candidate"
