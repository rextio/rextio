from __future__ import annotations

import ast
from pathlib import Path

import pytest

from rextio.analyzer.final_bindings import build_module_bindings
from rextio.analyzer.models import (
    CallSite,
    FunctionAnalysis,
    ModuleAnalysis,
    PluginClaim,
    ProjectAnalysis,
)
from rextio.analyzer.project_scanner import analyze_project
from rextio.artifacts.closure import (
    ClosureBlocker,
    ClosureNode,
    ClosureStatus,
    FallbackClosureEdge,
    NativeClosureEdge,
    calculate_native_closure,
    closure_requires_prebuild_failure,
    resolve_executable_fallback,
)
from rextio.artifacts.models import FallbackStrategy
from rextio.artifacts.entry_graph import executable_entry_graph
from rextio.artifacts.profiles import host_executable_profile


def test_native_closure_is_transitive_complete_and_deterministic() -> None:
    profile = host_executable_profile(
        "x86_64-unknown-linux-gnu", fallback=FallbackStrategy.PYTHON_SUBPROCESS
    )
    report = calculate_native_closure(
        "app.main",
        [
            ClosureNode("unused.fn"),
            ClosureNode("app.worker"),
            ClosureNode("app.main"),
            ClosureNode("app.helper", "embedded-helper"),
        ],
        [
            NativeClosureEdge("unused.fn", "app.helper"),
            NativeClosureEdge("app.worker", "app.helper"),
            NativeClosureEdge("app.main", "app.worker"),
        ],
        [
            FallbackClosureEdge("app.worker", "app.zeta", "rejected", "int"),
            FallbackClosureEdge("unused.fn", "unused.fallback", "unreachable", "int"),
            FallbackClosureEdge("app.main", "app.alpha", "exempt", "str"),
        ],
        strategy=FallbackStrategy.PYTHON_SUBPROCESS,
        profile=profile,
    )

    assert report.status is ClosureStatus.OPEN
    assert report.reachable_native_functions == (
        "app.helper",
        "app.main",
        "app.worker",
    )
    assert [edge.callee for edge in report.fallback_edges] == [
        "app.alpha",
        "app.zeta",
    ]
    assert report.delegated_return_types == {"app.alpha": "str", "app.zeta": "int"}
    assert report.to_dict() == report.to_dict()
    assert report.to_dict()["strategy"] == "python-subprocess"


@pytest.mark.parametrize(
    ("legacy", "expected"),
    [
        ("source", FallbackStrategy.PYTHON_SUBPROCESS),
        ("nuitka", FallbackStrategy.NUITKA_SIDECAR),
    ],
)
def test_legacy_fallback_mapping(legacy: str, expected: FallbackStrategy) -> None:
    assert resolve_executable_fallback(hybrid_runtime=legacy) is expected


def test_conflicting_fallback_spellings_are_rejected() -> None:
    with pytest.raises(ValueError, match="conflicting executable fallback settings"):
        resolve_executable_fallback(FallbackStrategy.ERROR, "source")


def test_reachable_blocker_and_dangling_native_edge_make_closure_unavailable() -> None:
    profile = host_executable_profile(
        "x86_64-unknown-linux-gnu",
        fallback=FallbackStrategy.PYTHON_SUBPROCESS,
    )
    report = calculate_native_closure(
        "app.main",
        [ClosureNode("app.main")],
        [NativeClosureEdge("app.main", "app.plugin_helper")],
        [],
        blockers=[
            ClosureBlocker(
                "unused.fn",
                "unused.plugin",
                "unreachable plugin capability",
            )
        ],
        strategy=FallbackStrategy.PYTHON_SUBPROCESS,
        profile=profile,
    )

    assert report.status is ClosureStatus.UNAVAILABLE
    assert closure_requires_prebuild_failure(report)
    assert report.blockers == (
        ClosureBlocker(
            "app.main",
            "app.plugin_helper",
            "native call target has no standalone Rust closure node",
        ),
    )


def test_missing_entrypoint_fails_prebuild_for_every_strategy() -> None:
    for strategy in FallbackStrategy:
        report = calculate_native_closure(
            "missing.main",
            [],
            [],
            [],
            strategy=strategy,
            profile=host_executable_profile("x86_64-unknown-linux-gnu", fallback=strategy),
        )
        assert report.status is ClosureStatus.UNAVAILABLE
        assert closure_requires_prebuild_failure(report)


def test_plugin_lowering_without_standalone_capability_is_a_reachable_blocker() -> None:
    bindings = build_module_bindings(
        ast.parse("def main():\n    return helper()\ndef helper():\n    return 1\n"),
        "app",
    )
    direct = FunctionAnalysis(
        name="main",
        qualname="app.main",
        module_name="app",
        file_path="app.py",
        line=1,
        column=0,
        is_native_candidate=True,
        accepted=True,
        calls=[CallSite("app.helper", 2, 4)],
        module_bindings=bindings,
    )
    plugin = FunctionAnalysis(
        name="helper",
        qualname="app.helper",
        module_name="app",
        file_path="app.py",
        line=3,
        column=0,
        is_native_candidate=True,
        accepted=True,
        plugin_claims=[PluginClaim("demo", "rule", "call", "vendor.op", 5, 4, "int")],
        module_bindings=bindings,
    )
    analysis = ProjectAnalysis(
        project_root=Path("."),
        modules=[ModuleAnalysis("app", "app.py", functions=[direct, plugin])],
    )
    profile = host_executable_profile(
        "x86_64-unknown-linux-gnu",
        fallback=FallbackStrategy.PYTHON_SUBPROCESS,
    )

    blocked = executable_entry_graph(
        analysis,
        "app.main",
        profile=profile,
    )
    plugin_entry = executable_entry_graph(
        analysis,
        "app.helper",
        profile=profile,
    )

    assert blocked.status is ClosureStatus.UNAVAILABLE
    assert blocked.blockers[0].callee == "app.helper"
    assert "standalone Rust" in blocked.blockers[0].reason
    assert plugin_entry.status is ClosureStatus.UNAVAILABLE
    assert "plugin-lowered" in (plugin_entry.entrypoint_reason or "")


def test_unreachable_plugin_function_does_not_block_direct_entrypoint() -> None:
    direct = FunctionAnalysis(
        name="main",
        qualname="app.main",
        module_name="app",
        file_path="app.py",
        line=1,
        column=0,
        is_native_candidate=True,
        accepted=True,
    )
    plugin = FunctionAnalysis(
        name="unused",
        qualname="app.unused",
        module_name="app",
        file_path="app.py",
        line=4,
        column=0,
        is_native_candidate=True,
        accepted=True,
        plugin_claims=[PluginClaim("demo", "rule", "call", "vendor.op", 5, 4, "int")],
    )
    analysis = ProjectAnalysis(
        project_root=Path("."),
        modules=[ModuleAnalysis("app", "app.py", functions=[direct, plugin])],
    )

    report = executable_entry_graph(
        analysis,
        "app.main",
        profile=host_executable_profile(
            "x86_64-unknown-linux-gnu",
            fallback=FallbackStrategy.ERROR,
        ),
        strategy=FallbackStrategy.ERROR,
    )

    assert report.status is ClosureStatus.CLOSED


def test_executable_entry_graph_records_authorized_module_initializer(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "seed = 1\n\ndef main(argv: list[str]) -> int:\n    return len(argv)\n",
        encoding="utf-8",
    )
    analysis = analyze_project(tmp_path, native_top_level=True, delegate_fallback=True)

    report = executable_entry_graph(analysis, "app.main")

    assert report.status is ClosureStatus.CLOSED
    assert report.module_initializers == ("app.__rextio_top_level__",)
    assert report.to_dict()["module_initializers"] == ["app.__rextio_top_level__"]


@pytest.mark.parametrize("strategy", list(FallbackStrategy))
def test_initializer_blocker_makes_closure_unavailable_for_every_strategy(
    tmp_path: Path,
    strategy: FallbackStrategy,
) -> None:
    (tmp_path / "app.py").write_text(
        "seed: int = 1\n\ndef main(argv: list[str]) -> int:\n    return len(argv)\n",
        encoding="utf-8",
    )
    analysis = analyze_project(tmp_path, native_top_level=True, delegate_fallback=True)

    report = executable_entry_graph(analysis, "app.main", strategy)

    assert report.status is ClosureStatus.UNAVAILABLE
    assert closure_requires_prebuild_failure(report)
    assert report.module_initializers == ()
    assert "module initializer is unavailable" in report.blockers[0].reason


def test_initializer_value_is_not_treated_as_a_rust_global(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "seed = 1\n\ndef main(argv: list[str]) -> int:\n    return seed\n",
        encoding="utf-8",
    )
    analysis = analyze_project(tmp_path, native_top_level=True, delegate_fallback=True)

    report = executable_entry_graph(analysis, "app.main")

    assert report.status is ClosureStatus.UNAVAILABLE
    assert report.entrypoint_reason is not None
    assert "rejected from native lowering" in report.entrypoint_reason
