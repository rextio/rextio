from __future__ import annotations

from pathlib import Path

import pytest

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
    function = make_function(is_native_candidate=True, accepted=True, native_runtime_semantics=True)
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
    # Contract 2.14.0 adds C6.9 bounded graph observation while retaining prior shapes.
    assert data["contract_version"] == "2.14.0"
    assert TOOLING_CONTRACT_VERSION.split(".", 1)[0] == "2"

    # Contract 2.1.0 always serializes logger_group_targets on each module.
    for module in data["modules"]:  # type: ignore[union-attr]
        assert "logger_group_targets" in module
        assert isinstance(module["logger_group_targets"], dict)

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


def test_auto_probe_failure_isolated_as_promotion_evidence(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "src/myapp/mod.py",
        "def missing_types(value):\n    return value\n",
    )

    analysis = analyze_project(tmp_path, native_marker="auto")
    function = analysis.modules[0].functions[0]
    data = function.to_dict()

    assert data["route"] == "fallback-python"
    assert data["native_status"] == "not-candidate"
    assert data["rejection_codes"] == []
    assert data["diagnostics"] == []
    assert analysis.has_error_diagnostics is False
    assessment = data["promotion_assessment"]
    assert assessment["status"] == "ineligible"
    assert assessment["provenance"] == "auto"
    assert "RXT001" in assessment["diagnostic_codes"]
    assert {item["kind"] for item in assessment["diagnostics"]} == {"blocker"}
    assert all(item["suggestion"] for item in assessment["diagnostics"])
    assert assessment["skip_reason"] is None


def test_promotion_contract_reports_markers_skips_and_methods(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "src/myapp/mod.py",
        """import rextio
import numba

def eligible(value: int) -> int:
    return value + 1

@rextio.native
def rejected(value: object) -> object:
    return value

@rextio.exempt
def exempt(value):
    return value

@numba.njit
def accelerated(value: float) -> float:
    return value * 2.0

async def coroutine(value: int) -> int:
    return value

class Worker:
    def method(self, value: int) -> int:
        return value

    async def async_method(self, value: int) -> int:
        return value

    @rextio.native
    def explicit_method(self, value: int) -> int:
        return value

    class Nested:
        @rextio.native
        def legacy_rejection(self, value: int) -> int:
            return value

def outer(value: int) -> int:
    def deliberately_not_reported(inner: int) -> int:
        return inner
    return value
""",
    )

    analysis = analyze_project(tmp_path, native_marker="auto")
    records = [function.to_dict() for function in analysis.modules[0].functions]
    by_name = {record["name"]: record for record in records}

    assert by_name["eligible"]["promotion_assessment"]["status"] == "eligible"
    assert by_name["eligible"]["promotion_assessment"]["provenance"] == "auto"
    assert by_name["rejected"]["marker_kind"] == "native"
    assert by_name["rejected"]["promotion_assessment"]["status"] == "ineligible"
    assert by_name["rejected"]["promotion_assessment"]["provenance"] == "explicit-native"
    assert by_name["exempt"]["marker_kind"] == "exempt"
    assert by_name["exempt"]["promotion_assessment"] == {
        "status": "skipped",
        "provenance": "explicit-exempt",
        "diagnostic_codes": [],
        "diagnostics": [],
        "skip_reason": "explicit-exemption",
    }
    assert by_name["accelerated"]["marker_kind"] == "none"
    assert by_name["accelerated"]["promotion_assessment"]["provenance"] == (
        "external-accelerator"
    )
    assert by_name["accelerated"]["promotion_assessment"]["skip_reason"] == (
        "external-accelerator"
    )
    assert by_name["coroutine"]["promotion_assessment"]["skip_reason"] == (
        "async-auto-promotion-not-supported"
    )
    assert by_name["method"]["promotion_assessment"]["skip_reason"] == (
        "method-auto-promotion-not-supported"
    )
    assert by_name["async_method"]["promotion_assessment"]["skip_reason"] == (
        "method-auto-promotion-not-supported"
    )
    assert by_name["explicit_method"]["promotion_assessment"]["status"] == "eligible"
    assert by_name["legacy_rejection"]["native_status"] == "rejected"
    assert by_name["legacy_rejection"]["marker_kind"] == "native"
    assert "deliberately_not_reported" not in by_name

    positions = [
        (record["source_range"]["start"]["line"], record["source_range"]["start"]["column"])
        for record in records
    ]
    assert positions == sorted(positions)
    for record in records:
        assert set(record) >= {
            "marker_kind",
            "promotion_assessment",
            "source_range",
            "name_range",
        }
        assert record["line"] == record["source_range"]["start"]["line"]
        assert record["column"] == record["source_range"]["start"]["column"]


def test_decorator_policy_serializes_unmarked_function_as_policy_skip(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "src/myapp/mod.py",
        "def typed(value: int) -> int:\n    return value\n",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")
    data = analysis.modules[0].functions[0].to_dict()

    assert data["route"] == "fallback-python"
    assert data["native_status"] == "not-candidate"
    assert data["promotion_assessment"] == {
        "status": "skipped",
        "provenance": "policy-skip",
        "diagnostic_codes": [],
        "diagnostics": [],
        "skip_reason": "automatic-promotion-disabled",
    }


def test_auto_mode_arbitrary_decorator_is_ineligible_not_policy_skipped(
    tmp_path: Path,
) -> None:
    write_module(
        tmp_path,
        "src/myapp/mod.py",
        """def decorate(function):
    return function

@decorate
def typed(value: int) -> int:
    return value
""",
    )

    analysis = analyze_project(tmp_path, native_marker="auto")
    function = next(
        function for function in analysis.modules[0].functions if function.name == "typed"
    )
    data = function.to_dict()

    assert data["native_status"] == "not-candidate"
    assert data["diagnostics"] == []
    assert analysis.has_error_diagnostics is False
    assert data["promotion_assessment"]["status"] == "ineligible"
    assert data["promotion_assessment"]["provenance"] == "auto"
    assert "RXT010" in data["promotion_assessment"]["diagnostic_codes"]
    assert data["promotion_assessment"]["skip_reason"] is None


@pytest.mark.parametrize("definition", ["def", "async def"])
def test_decorator_policy_unproven_marker_is_policy_skip_for_sync_and_async(
    tmp_path: Path,
    definition: str,
) -> None:
    write_module(
        tmp_path,
        "src/myapp/mod.py",
        (
            "def native(function):\n    return function\n\n"
            f"@native\n{definition} target(value: int) -> int:\n    return value\n"
        ),
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")
    function = next(
        function for function in analysis.modules[0].functions if function.name == "target"
    )
    data = function.to_dict()

    assert data["marker_kind"] == "none"
    assert data["native_status"] == "not-candidate"
    assert any(diagnostic["code"] == "RXT010" for diagnostic in data["diagnostics"])
    assert data["promotion_assessment"] == {
        "status": "skipped",
        "provenance": "policy-skip",
        "diagnostic_codes": [],
        "diagnostics": [],
        "skip_reason": "automatic-promotion-disabled",
    }


def test_auto_mode_unproven_async_and_direct_methods_are_structural_skips(
    tmp_path: Path,
) -> None:
    write_module(
        tmp_path,
        "src/myapp/mod.py",
        """def native(function):
    return function

@native
async def coroutine(value: int) -> int:
    return value

class Worker:
    @native
    def method(self, value: int) -> int:
        return value

    @native
    async def async_method(self, value: int) -> int:
        return value
""",
    )

    analysis = analyze_project(tmp_path, native_marker="auto")
    by_name = {
        function.name: function.to_dict()
        for function in analysis.modules[0].functions
        if function.name in {"coroutine", "method", "async_method"}
    }

    for name, reason in {
        "coroutine": "async-auto-promotion-not-supported",
        "method": "method-auto-promotion-not-supported",
        "async_method": "method-auto-promotion-not-supported",
    }.items():
        data = by_name[name]
        assert data["marker_kind"] == "none"
        assert data["native_status"] == "not-candidate"
        assert any(diagnostic["code"] == "RXT010" for diagnostic in data["diagnostics"])
        assert data["promotion_assessment"] == {
            "status": "skipped",
            "provenance": "structural-skip",
            "diagnostic_codes": [],
            "diagnostics": [],
            "skip_reason": reason,
        }


def test_decorator_policy_unproven_direct_methods_are_policy_skips(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "src/myapp/mod.py",
        """def native(function):
    return function

class Worker:
    @native
    def method(self, value: int) -> int:
        return value

    @native
    async def async_method(self, value: int) -> int:
        return value
""",
    )

    analysis = analyze_project(tmp_path, native_marker="decorator")
    methods = [
        function.to_dict()
        for function in analysis.modules[0].functions
        if function.name in {"method", "async_method"}
    ]
    assert len(methods) == 2
    for data in methods:
        assert data["marker_kind"] == "none"
        assert any(diagnostic["code"] == "RXT010" for diagnostic in data["diagnostics"])
        assert data["promotion_assessment"] == {
            "status": "skipped",
            "provenance": "policy-skip",
            "diagnostic_codes": [],
            "diagnostics": [],
            "skip_reason": "automatic-promotion-disabled",
        }


def test_utf8_half_open_function_ranges_are_token_based(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "src/myapp/mod.py",
        "class 이름:\n    async def 계산값(self, 값: int) -> int:\n        return 값\n",
    )

    analysis = analyze_project(tmp_path, native_marker="auto")
    data = analysis.modules[0].functions[0].to_dict()

    # AST/token columns are UTF-8 byte offsets: four indentation bytes, then
    # ``async def `` (10 bytes), followed by the three-code-point identifier.
    assert data["source_range"]["start"] == {"line": 2, "column": 4}
    assert data["source_range"]["end"] == {"line": 3, "column": 18}
    assert data["name_range"] == {
        "start": {"line": 2, "column": 14},
        "end": {"line": 2, "column": 23},
    }
    assert data["name_range"]["end"]["column"] - data["name_range"]["start"][
        "column"
    ] == len("계산값".encode("utf-8"))
