"""Focused RED tests for C6.10 scoped source-transformation replay."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from rextio.analyzer.project_scanner import analyze_project
from rextio.artifacts.profiles import host_extension_profile
from rextio.artifacts.evidence import (
    SourceTransformationRange,
    SourceTransformationVerification,
)
from rextio.build.artifact_layout import ArtifactLayout
from rextio.build.supply_chain import (
    EvidenceInputSnapshot,
    capture_generated_rust_inputs,
    capture_project_source_snapshot,
)
from rextio.build.transformation_inventory import (
    collect_source_transformation_inventory,
)
from rextio.build.transformation_verification import (
    collect_scoped_source_transformation_verification,
)
import rextio.build.transformation_verification as transformation_verification_module
from rextio.codegen.rust.generator import generate_rust_module
from rextio.ir.lowering import lower_project
from rextio.partition.build_plan import BuildPlan, create_build_plan


def _real_plugin_free_native_closure(
    project_root: Path,
) -> tuple[BuildPlan, EvidenceInputSnapshot, object]:
    source = project_root / "worker.py"
    source.write_text(
        "def helper(value: int) -> int:\n"
        "    return value + 1\n"
        "\n"
        "def score(value: int) -> int:\n"
        "    return helper(value) * 2\n",
        encoding="utf-8",
        newline="\n",
    )
    analysis = analyze_project(project_root, native_marker="auto")
    accepted = tuple(analysis.accepted_native_functions)
    assert tuple(function.qualname for function in accepted) == (
        "worker.helper",
        "worker.score",
    )
    assert all(
        not function.plugin_claims
        and not function.plugin_type_keys
        and not function.native_runtime_semantics
        and not function.boundary_call_targets
        and not function.delegated_call_targets
        for function in accepted
    )

    module_ir = lower_project(
        analysis,
        include_embedding=False,
        plugin_types=None,
    )
    assert tuple(function.qualname for function in module_ir.functions) == (
        "worker.helper",
        "worker.score",
    )
    generated = generate_rust_module(
        module_ir,
        boundary_call_return_types={},
        plugin_providers={},
        plugin_types_by_key={},
    )

    layout = ArtifactLayout(project_root)
    layout.rust_src_dir.mkdir(parents=True)
    (layout.rust_src_dir / "lib.rs").write_text(
        generated,
        encoding="utf-8",
        newline="\n",
    )
    (layout.rust_dir / "Cargo.toml").write_text(
        "[package]\n"
        'name = "rextio_generated_native"\n'
        'version = "0.1.0"\n'
        'edition = "2021"\n',
        encoding="utf-8",
        newline="\n",
    )

    plan = create_build_plan(
        analysis,
        "cpython",
        artifact_profiles=(
            host_extension_profile("x86_64-unknown-linux-gnu"),
        ),
    )
    snapshot = capture_project_source_snapshot(
        project_root=project_root,
        plan=plan,
    )
    snapshot = capture_generated_rust_inputs(
        snapshot,
        project_root=project_root,
        layout=layout,
    )
    assert snapshot.unavailable_reason is None
    inventory = collect_source_transformation_inventory(
        project_root=project_root,
        plan=plan,
        input_snapshot=snapshot,
    )
    assert inventory is not None
    assert tuple(record.function_qualname for record in inventory.records) == (
        "worker.helper",
        "worker.score",
    )
    assert len({record.generated_rust for record in inventory.records}) == 1
    assert inventory.records[0].generated_rust in snapshot.generated_rust
    return plan, snapshot, inventory


def test_scoped_replay_verifies_full_plugin_free_native_closure(
    tmp_path: Path,
) -> None:
    plan, snapshot, inventory = _real_plugin_free_native_closure(tmp_path)

    verification = collect_scoped_source_transformation_verification(
        project_root=tmp_path,
        plan=plan,
        input_snapshot=snapshot,
        transformation_inventory=inventory,
        embedding_enabled=False,
    )

    assert isinstance(verification, SourceTransformationVerification)
    assert verification.function_qualnames == ("worker.helper", "worker.score")
    assert verification.source_inputs == snapshot.project_inputs
    assert verification.generated_rust == next(
        item
        for item in snapshot.generated_rust
        if item.logical_path.endswith("/src/lib.rs")
    )
    assert verification.regenerated_rust_sha256 == verification.generated_rust.sha256
    assert verification.regenerated_rust_size == verification.generated_rust.size
    assert len(verification.source_transformation_inventory_sha256) == 64
    assert len(verification.source_input_set_sha256) == 64
    assert len(verification.module_ir_sha256) == 64
    assert verification.complete_for_scope is True
    assert verification.global_provenance_complete is False
    assert verification.complete is False
    assert verification.authority == "observation-only"


@pytest.mark.parametrize("tamper", ["qualname", "range", "semantic"])
def test_scoped_replay_rejects_rederived_identity_tampering(
    tmp_path: Path,
    tamper: str,
) -> None:
    plan, snapshot, inventory = _real_plugin_free_native_closure(tmp_path)
    record = inventory.records[1]
    if tamper == "qualname":
        changed = replace(record, function_qualname="worker.score_alt")
    elif tamper == "range":
        source_range = record.source_range
        changed = replace(
            record,
            source_range=SourceTransformationRange(
                start_line=source_range.start_line,
                start_column=source_range.start_column,
                end_line=source_range.end_line,
                end_column=source_range.end_column + 1,
            ),
        )
    else:
        changed = replace(record, semantic_ast_sha256="f" * 64)
    tampered = replace(inventory, records=(inventory.records[0], changed))

    assert (
        collect_scoped_source_transformation_verification(
            project_root=tmp_path,
            plan=plan,
            input_snapshot=snapshot,
            transformation_inventory=tampered,
            embedding_enabled=False,
        )
        is None
    )


@pytest.mark.parametrize("target", ["source", "generated-rust"])
def test_scoped_replay_rejects_changed_captured_bytes(
    tmp_path: Path,
    target: str,
) -> None:
    plan, snapshot, inventory = _real_plugin_free_native_closure(tmp_path)
    if target == "source":
        path = tmp_path / "worker.py"
    else:
        generated = next(
            item
            for item in snapshot.generated_rust
            if item.logical_path.endswith("/src/lib.rs")
        )
        path = tmp_path / generated.logical_path
    path.write_bytes(path.read_bytes() + b"\n// changed\n")

    assert (
        collect_scoped_source_transformation_verification(
            project_root=tmp_path,
            plan=plan,
            input_snapshot=snapshot,
            transformation_inventory=inventory,
            embedding_enabled=False,
        )
        is None
    )


def test_scoped_replay_rejects_incomplete_inventory_and_embedding(
    tmp_path: Path,
) -> None:
    plan, snapshot, inventory = _real_plugin_free_native_closure(tmp_path)

    assert (
        collect_scoped_source_transformation_verification(
            project_root=tmp_path,
            plan=plan,
            input_snapshot=snapshot,
            transformation_inventory=replace(
                inventory,
                records=(inventory.records[0],),
            ),
            embedding_enabled=False,
        )
        is None
    )
    assert (
        collect_scoped_source_transformation_verification(
            project_root=tmp_path,
            plan=plan,
            input_snapshot=snapshot,
            transformation_inventory=inventory,
            embedding_enabled=True,
        )
        is None
    )


def test_scoped_replay_rejects_symlinked_source(tmp_path: Path) -> None:
    plan, snapshot, inventory = _real_plugin_free_native_closure(tmp_path)
    source = tmp_path / "worker.py"
    target = tmp_path / "worker-real.py"
    source.rename(target)
    source.symlink_to(target.name)

    assert (
        collect_scoped_source_transformation_verification(
            project_root=tmp_path,
            plan=plan,
            input_snapshot=snapshot,
            transformation_inventory=inventory,
            embedding_enabled=False,
        )
        is None
    )


def test_scoped_replay_rejects_sibling_stub_changed_only_during_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, snapshot, inventory = _real_plugin_free_native_closure(tmp_path)
    stub = tmp_path / "worker.pyi"
    assert not stub.exists()
    real_analyze = transformation_verification_module.analyze_project

    def analyze_with_temporary_stub_change(*args: object, **kwargs: object) -> object:
        stub.write_bytes(b"# replay-only mutation\n")
        try:
            return real_analyze(*args, **kwargs)
        finally:
            stub.unlink()

    monkeypatch.setattr(
        transformation_verification_module,
        "analyze_project",
        analyze_with_temporary_stub_change,
    )
    assert (
        collect_scoped_source_transformation_verification(
            project_root=tmp_path,
            plan=plan,
            input_snapshot=snapshot,
            transformation_inventory=inventory,
            embedding_enabled=False,
        )
        is None
    )
    assert not stub.exists()
