"""Focused C6.6 transformation model, collector, and privacy regressions."""

from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

import rextio.artifacts.evidence as evidence_mod
from rextio.analyzer.models import (
    FunctionAnalysis,
    ModuleAnalysis,
    PluginClaim,
    ProjectAnalysis,
    SourcePosition,
    SourceRange,
)
from rextio.artifacts.evidence import (
    MAX_EVIDENCE_STRING_CHARS,
    MAX_SOURCE_TRANSFORMATION_PLUGIN_IDS,
    MAX_SOURCE_TRANSFORMATION_PLUGIN_REFERENCES,
    MAX_SOURCE_TRANSFORMATIONS,
    EvidenceFileRef,
    SourceTransformationInventory,
    SourceTransformationRange,
)
from rextio.artifacts.profiles import host_extension_profile
from rextio.build.supply_chain import EvidenceInputSnapshot
from rextio.build.transformation_inventory import (
    collect_source_transformation_inventory,
)
from rextio.partition.build_plan import BuildPlan
from rextio.partition.fallback_plan import FallbackPlan
from rextio.partition.native_plan import NativePlan
from rextio.source.models import SourceModule, SourceModuleGraph, SourceOrigin
from rextio.source.planning import HostSourcePlan


def _fixture(
    tmp_path: Path,
) -> tuple[BuildPlan, EvidenceInputSnapshot, FunctionAnalysis, str]:
    source = (
        "def transform(value: int) -> int:\n"
        "    private_marker = '/Users/private/token-value'\n"
        "    return value + 1\n"
    )
    source_path = tmp_path / "pkg" / "worker.py"
    source_path.parent.mkdir()
    source_path.write_text(source, encoding="utf-8")
    source_sha256 = hashlib.sha256(source.encode("utf-8")).hexdigest()
    node = ast.parse(source).body[0]
    assert isinstance(node, ast.FunctionDef)
    function = FunctionAnalysis(
        name="transform",
        qualname="pkg.worker.transform",
        module_name="pkg.worker",
        file_path=str(source_path),
        line=1,
        column=0,
        source_range=SourceRange(
            start=SourcePosition(line=1, column=0),
            end=SourcePosition(line=3, column=20),
        ),
        is_native_candidate=True,
        accepted=True,
        source_ast_fingerprint=ast.dump(
            node,
            annotate_fields=True,
            include_attributes=False,
        ),
        plugin_claims=[
            PluginClaim(
                plugin_id="z-plugin",
                rule_id="rule",
                kind="call",
                target="pkg.op",
                line=3,
                column=11,
                result_type="int",
            )
        ],
        plugin_type_keys=["a-plugin/value", "z-plugin/value"],
    )
    analysis = ProjectAnalysis(
        project_root=tmp_path,
        modules=[
            ModuleAnalysis(
                module_name="pkg.worker",
                file_path=str(source_path),
                functions=[function],
            )
        ],
    )
    module = SourceModule(
        module_name="pkg.worker",
        path="pkg/worker.py",
        is_package_init=False,
        source_origin=SourceOrigin.PROJECT,
        sha256=source_sha256,
        dependency_depth=0,
    )
    plan = BuildPlan(
        analysis=analysis,
        native=NativePlan(accepted_functions=(function,), rejected_functions=()),
        fallback=FallbackPlan(backend="cpython", modules=()),
        host_source_plan=HostSourcePlan(
            graph=SourceModuleGraph(modules=(module,)),
            module_initializers=(),
            unavailable_reason=None,
        ),
        artifact_profiles=(
            host_extension_profile("x86_64-unknown-linux-gnu"),
        ),
    )
    source_ref = EvidenceFileRef(
        logical_path="pkg/worker.py",
        sha256=source_sha256,
        size=len(source.encode("utf-8")),
        role="project-python-source",
    )
    generated_ref = EvidenceFileRef(
        logical_path=".rextio/generated/rust/src/lib.rs",
        sha256="b" * 64,
        size=123,
        role="generated-rust-input",
    )
    snapshot = EvidenceInputSnapshot(
        project_inputs=(source_ref,),
        generated_python=(),
        generated_rust=(generated_ref,),
    )
    return plan, snapshot, function, source


def test_collector_binds_exact_models_deterministically_without_source_disclosure(
    tmp_path: Path,
) -> None:
    plan, snapshot, _function, source = _fixture(tmp_path)
    first = collect_source_transformation_inventory(
        project_root=tmp_path,
        plan=plan,
        input_snapshot=snapshot,
    )
    second = collect_source_transformation_inventory(
        project_root=tmp_path,
        plan=plan,
        input_snapshot=snapshot,
    )

    assert first is not None and first == second
    report = first.to_dict()
    record = report["records"][0]
    assert record["source_path"] == "pkg/worker.py"
    assert record["source_sha256"] == snapshot.project_inputs[0].sha256
    assert record["generated_rust"] == snapshot.generated_rust[0].to_dict()
    assert record["generator_backend"] == "rextio-core-rust-pyo3-v1"
    assert record["plugin_ids"] == ["a-plugin", "z-plugin"]
    assert len(record["semantic_ast_sha256"]) == 64
    serialized = json.dumps(report, sort_keys=True)
    assert source not in serialized
    assert "token-value" not in serialized
    assert str(tmp_path) not in serialized
    assert "ast.FunctionDef" not in serialized


def test_collector_accepts_value_equal_detached_codegen_authority(
    tmp_path: Path,
) -> None:
    plan, snapshot, function, _source = _fixture(tmp_path)
    detached = replace(function)
    detached_plan = replace(
        plan,
        native=NativePlan(accepted_functions=(detached,), rejected_functions=()),
    )

    inventory = collect_source_transformation_inventory(
        project_root=tmp_path,
        plan=detached_plan,
        input_snapshot=snapshot,
    )

    assert inventory is not None
    assert inventory.records[0].function_qualname == function.qualname


def test_collector_degrades_orphan_ambiguous_and_external_bindings_to_none(
    tmp_path: Path,
) -> None:
    plan, snapshot, function, _source = _fixture(tmp_path)

    function.file_path = str(tmp_path.parent / "outside.py")
    assert (
        collect_source_transformation_inventory(
            project_root=tmp_path, plan=plan, input_snapshot=snapshot
        )
        is None
    )
    function.file_path = str(tmp_path / "pkg" / "worker.py")
    ambiguous_snapshot = replace(
        snapshot,
        project_inputs=(snapshot.project_inputs[0], snapshot.project_inputs[0]),
    )
    assert (
        collect_source_transformation_inventory(
            project_root=tmp_path,
            plan=plan,
            input_snapshot=ambiguous_snapshot,
        )
        is None
    )
    object.__setattr__(
        plan.host_source_plan.graph.modules[0],
        "source_origin",
        SourceOrigin.DISTRIBUTION,
    )
    assert (
        collect_source_transformation_inventory(
            project_root=tmp_path, plan=plan, input_snapshot=snapshot
        )
        is None
    )


def test_collector_distinguishes_a_closed_empty_scope_from_unavailability(
    tmp_path: Path,
) -> None:
    plan, snapshot, _function, _source = _fixture(tmp_path)
    empty_plan = replace(
        plan,
        analysis=replace(
            plan.analysis,
            modules=[replace(plan.analysis.modules[0], functions=[])],
        ),
        native=NativePlan(accepted_functions=(), rejected_functions=()),
    )

    inventory = collect_source_transformation_inventory(
        project_root=tmp_path,
        plan=empty_plan,
        input_snapshot=snapshot,
    )

    assert inventory is not None
    assert inventory.records == ()
    assert inventory.to_dict()["record_count"] == 0


def test_collector_rejects_function_omitted_from_native_plan(tmp_path: Path) -> None:
    plan, snapshot, _function, _source = _fixture(tmp_path)
    omitted = replace(
        plan,
        native=NativePlan(accepted_functions=(), rejected_functions=()),
    )

    assert (
        collect_source_transformation_inventory(
            project_root=tmp_path,
            plan=omitted,
            input_snapshot=snapshot,
        )
        is None
    )


def test_collector_rejects_function_extra_to_codegen_analysis(tmp_path: Path) -> None:
    plan, snapshot, _function, _source = _fixture(tmp_path)
    extra = replace(
        plan,
        analysis=replace(
            plan.analysis,
            modules=[replace(plan.analysis.modules[0], functions=[])],
        ),
    )

    assert (
        collect_source_transformation_inventory(
            project_root=tmp_path,
            plan=extra,
            input_snapshot=snapshot,
        )
        is None
    )


def test_collector_rejects_stale_function_fingerprint(tmp_path: Path) -> None:
    plan, snapshot, function, _source = _fixture(tmp_path)
    stale = replace(
        plan,
        native=NativePlan(
            accepted_functions=(
                replace(
                    function,
                    source_ast_fingerprint=f"{function.source_ast_fingerprint}-stale",
                ),
            ),
            rejected_functions=(),
        ),
    )

    assert (
        collect_source_transformation_inventory(
            project_root=tmp_path,
            plan=stale,
            input_snapshot=snapshot,
        )
        is None
    )


def test_collector_rejects_mismatched_function_path_and_duplicates(
    tmp_path: Path,
) -> None:
    plan, snapshot, function, _source = _fixture(tmp_path)
    mismatched = replace(
        plan,
        native=NativePlan(
            accepted_functions=(
                replace(function, file_path=str(tmp_path / "pkg" / "other.py")),
            ),
            rejected_functions=(),
        ),
    )
    duplicated = replace(
        plan,
        native=NativePlan(
            accepted_functions=(function, replace(function)),
            rejected_functions=(),
        ),
    )

    assert (
        collect_source_transformation_inventory(
            project_root=tmp_path,
            plan=mismatched,
            input_snapshot=snapshot,
        )
        is None
    )
    assert (
        collect_source_transformation_inventory(
            project_root=tmp_path,
            plan=duplicated,
            input_snapshot=snapshot,
        )
        is None
    )


def test_collector_rejects_too_many_accepted_functions_before_record_building(
    tmp_path: Path,
) -> None:
    plan, snapshot, function, _source = _fixture(tmp_path)
    functions = tuple(
        replace(
            function,
            name=f"transform_{index:04d}",
            qualname=f"pkg.worker.transform_{index:04d}",
            source_range=SourceRange(
                start=SourcePosition(line=index + 1, column=0),
                end=SourcePosition(line=index + 1, column=1),
            ),
            source_ast_fingerprint=f"fingerprint-{index:04d}",
        )
        for index in range(MAX_SOURCE_TRANSFORMATIONS + 1)
    )
    oversized = replace(
        plan,
        analysis=replace(
            plan.analysis,
            modules=[replace(plan.analysis.modules[0], functions=list(functions))],
        ),
        native=NativePlan(accepted_functions=functions, rejected_functions=()),
    )

    assert (
        collect_source_transformation_inventory(
            project_root=tmp_path,
            plan=oversized,
            input_snapshot=snapshot,
        )
        is None
    )


def test_collector_rejects_too_many_unique_plugin_ids(tmp_path: Path) -> None:
    plan, snapshot, function, _source = _fixture(tmp_path)
    function.plugin_claims = []
    function.plugin_type_keys = [
        f"plugin-{index:02d}/value"
        for index in range(MAX_SOURCE_TRANSFORMATION_PLUGIN_IDS + 1)
    ]

    assert (
        collect_source_transformation_inventory(
            project_root=tmp_path,
            plan=plan,
            input_snapshot=snapshot,
        )
        is None
    )


@pytest.mark.parametrize(
    "type_keys",
    [
        ["same-plugin/value"] * (MAX_SOURCE_TRANSFORMATION_PLUGIN_REFERENCES + 1),
        ["p" * (MAX_EVIDENCE_STRING_CHARS + 1)],
    ],
)
def test_collector_rejects_duplicate_heavy_or_oversized_plugin_references(
    tmp_path: Path,
    type_keys: list[str],
) -> None:
    plan, snapshot, function, _source = _fixture(tmp_path)
    function.plugin_claims = []
    function.plugin_type_keys = type_keys

    assert (
        collect_source_transformation_inventory(
            project_root=tmp_path,
            plan=plan,
            input_snapshot=snapshot,
        )
        is None
    )


def test_inventory_models_reject_noncanonical_and_path_shaped_identifiers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, snapshot, _function, _source = _fixture(tmp_path)
    inventory = collect_source_transformation_inventory(
        project_root=tmp_path, plan=plan, input_snapshot=snapshot
    )
    assert inventory is not None
    record = inventory.records[0]

    with pytest.raises(FrozenInstanceError):
        inventory.records = ()  # type: ignore[misc]
    with pytest.raises(ValueError, match="plugin ids"):
        replace(record, plugin_ids=("z-plugin", "a-plugin"))
    with pytest.raises(ValueError, match="count"):
        replace(
            record,
            plugin_ids=tuple(
                f"plugin-{index:02d}"
                for index in range(MAX_SOURCE_TRANSFORMATION_PLUGIN_IDS + 1)
            ),
        )
    with pytest.raises(ValueError, match="function module"):
        replace(record, function_module="/Users/private/module")
    with pytest.raises(ValueError, match="generator/backend"):
        replace(record, generator_backend="future-backend")
    with pytest.raises(ValueError, match="range"):
        SourceTransformationRange(
            start_line=3,
            start_column=0,
            end_line=2,
            end_column=0,
        )
    with pytest.raises(ValueError, match="unique"):
        SourceTransformationInventory(records=(record, record))
    with pytest.raises(ValueError, match="incomplete"):
        replace(inventory, complete=True)
    with pytest.raises(ValueError, match="authority"):
        replace(inventory, authority="distribution-authority")
    monkeypatch.setattr(
        evidence_mod,
        "MAX_SOURCE_TRANSFORMATION_INVENTORY_CHARS",
        1,
    )
    with pytest.raises(ValueError, match="character bound"):
        replace(inventory)
