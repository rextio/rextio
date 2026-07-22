"""Focused RED tests for C6.10 scoped source-transformation replay."""

from __future__ import annotations

from dataclasses import replace
import copy
import hashlib
import json
import pickle
from pathlib import Path

import pytest

from rextio.analyzer.project_scanner import analyze_project
from rextio.artifacts.profiles import host_extension_profile
from rextio.artifacts.evidence import (
    SourceTransformationRange,
    SourceTransformationVerification,
)
from rextio.build.artifact_layout import ArtifactLayout
from rextio.build.full_c6_cargo_workspace import (
    compute_full_c6_cargo_vendor_tree_sha256,
)
from rextio.build.full_c6_host_inputs import (
    FullC6AnalysisScope,
    collect_full_c6_analysis_scope,
)
from rextio.build.supply_chain import (
    EvidenceInputSnapshot,
    capture_generated_python_inputs,
    capture_generated_rust_inputs,
    capture_project_source_snapshot,
)
from rextio.build.transformation_inventory import (
    collect_source_transformation_inventory,
)
from rextio.build.transformation_verification import (
    SourceTransformationReplayAuthority,
    collect_scoped_source_transformation_replay_authority,
    collect_scoped_source_transformation_verification,
    validate_source_transformation_replay_authority,
)
import rextio.build.transformation_verification as transformation_verification_module
from rextio.build.orchestrator import (
    _write_python_fallback_tree,
    _write_runtime_support,
)
from rextio.codegen.rust.cargo import render_cargo_toml
from rextio.codegen.rust.generator import generate_rust_module
from rextio.config.schema import BuildConfig, RextioConfig
from rextio.ir.lowering import lower_project
from rextio.partition.build_plan import BuildPlan, create_build_plan


def _real_plugin_free_native_closure(
    project_root: Path,
    *,
    config: RextioConfig | None = None,
    analysis_scope: FullC6AnalysisScope | None = None,
) -> tuple[BuildPlan, EvidenceInputSnapshot, object]:
    source = project_root / "worker.py"
    source_text = (
        "def helper(value: int) -> int:\n"
        "    return value + 1\n"
        "\n"
        "def score(value: int) -> int:\n"
        "    return helper(value) * 2\n"
    )
    if source.exists():
        assert source.read_text(encoding="utf-8") == source_text
    else:
        source.write_text(source_text, encoding="utf-8", newline="\n")
    analysis = analyze_project(
        project_root,
        native_marker="auto",
        plugin_config=config,
        full_c6_analysis_scope=analysis_scope,
    )
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

    plan = create_build_plan(
        analysis,
        "cpython",
        artifact_profiles=(
            host_extension_profile("x86_64-unknown-linux-gnu"),
        ),
    )
    layout = ArtifactLayout(project_root)
    layout.python_dir.mkdir(parents=True)
    _write_python_fallback_tree(plan.fallback, layout.python_dir, 1000)
    _write_runtime_support(layout.python_dir)
    layout.rust_src_dir.mkdir(parents=True)
    (layout.rust_src_dir / "lib.rs").write_text(
        generated,
        encoding="utf-8",
        newline="\n",
    )
    (layout.rust_dir / "Cargo.toml").write_text(
        render_cargo_toml(extra_dependencies=()),
        encoding="utf-8",
        newline="\n",
    )

    snapshot = capture_project_source_snapshot(
        project_root=project_root,
        plan=plan,
    )
    snapshot = capture_generated_python_inputs(
        snapshot,
        project_root=project_root,
        layout=layout,
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


def _strict_plugin_free_native_closure(
    tmp_path: Path,
) -> tuple[
    Path,
    BuildPlan,
    EvidenceInputSnapshot,
    object,
    RextioConfig,
    FullC6AnalysisScope,
    Path,
]:
    project = (tmp_path / "project").resolve()
    project.mkdir()
    worker = project / "worker.py"
    worker.write_text(
        "def helper(value: int) -> int:\n"
        "    return value + 1\n"
        "\n"
        "def score(value: int) -> int:\n"
        "    return helper(value) * 2\n",
        encoding="utf-8",
        newline="\n",
    )
    lock = project / "Cargo.lock"
    lock.write_text(
        """\
version = 4

[[package]]
name = "rextio_generated_native"
version = "0.1.0"

[[package]]
name = "demo-dep"
version = "1.2.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
""",
        encoding="utf-8",
    )
    vendor = project / "vendor"
    package = vendor / "demo-dep-1.2.3"
    vendor_files = {
        "Cargo.toml": (
            b'[package]\nname = "demo-dep"\nversion = "1.2.3"\n'
            b'license = "MIT"\nlicense-file = "LICENSE"\n'
        ),
        "LICENSE": b"MIT license evidence\n",
        "src/lib.rs": b"pub fn answer() -> u32 { 42 }\n",
        "python/shadow.py": (
            b"def vendor_shadow(value: int) -> int:\n    return value - 100\n"
        ),
        "python/shadow.pyi": b"def vendor_shadow(value: int) -> int: ...\n",
    }
    for relative, payload in vendor_files.items():
        path = package.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        path.chmod(0o644)
    (package / ".cargo-checksum.json").write_text(
        json.dumps(
            {
                "files": {
                    name: hashlib.sha256(payload).hexdigest()
                    for name, payload in sorted(vendor_files.items())
                },
                "package": "a" * 64,
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    config = RextioConfig(
        build=BuildConfig(
            artifact_distribution_policy="full-c6-required",
            artifact_cargo_lock=lock.relative_to(project).as_posix(),
            artifact_cargo_lock_sha256=hashlib.sha256(lock.read_bytes()).hexdigest(),
            artifact_cargo_vendor=vendor.relative_to(project).as_posix(),
            artifact_cargo_vendor_sha256=(
                compute_full_c6_cargo_vendor_tree_sha256(vendor)
            ),
            artifact_signing_request_output=(
                "state/rextio.full-c6-final-authorization-request.json"
            ),
        )
    )
    scope = collect_full_c6_analysis_scope(project, config=config)
    plan, snapshot, inventory = _real_plugin_free_native_closure(
        project,
        config=config,
        analysis_scope=scope,
    )
    return project, plan, snapshot, inventory, config, scope, vendor


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


def test_scoped_replay_mints_only_process_local_nonserializable_authority(
    tmp_path: Path,
) -> None:
    plan, snapshot, inventory = _real_plugin_free_native_closure(tmp_path)

    authority = collect_scoped_source_transformation_replay_authority(
        project_root=tmp_path,
        plan=plan,
        input_snapshot=snapshot,
        transformation_inventory=inventory,
        embedding_enabled=False,
    )

    assert isinstance(authority, SourceTransformationReplayAuthority)
    assert validate_source_transformation_replay_authority(authority) is authority
    assert authority.generated_python == snapshot.generated_python
    assert authority.generated_cargo_toml == next(
        item
        for item in snapshot.generated_rust
        if item.logical_path.endswith("/Cargo.toml")
    )
    assert len(authority.generated_python_tree_sha256) == 64
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.copy(authority)
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.deepcopy(authority)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(authority)


def test_strict_scoped_replay_excludes_verified_vendor_python_and_stub(
    tmp_path: Path,
) -> None:
    project, plan, snapshot, inventory, config, scope, _vendor = (
        _strict_plugin_free_native_closure(tmp_path)
    )
    stub_inputs = plan.analysis._stub_inputs
    assert stub_inputs is not None
    assert tuple(item.source_path for item in stub_inputs.records) == ("worker.py",)

    authority = collect_scoped_source_transformation_replay_authority(
        project_root=project,
        plan=plan,
        input_snapshot=snapshot,
        transformation_inventory=inventory,
        embedding_enabled=False,
        full_c6_analysis_scope=scope,
        full_c6_config=config,
    )

    assert isinstance(authority, SourceTransformationReplayAuthority)
    assert authority.verification.function_qualnames == (
        "worker.helper",
        "worker.score",
    )


@pytest.mark.parametrize(
    "mutation",
    ("missing-scope", "missing-config", "foreign-config", "stale-vendor"),
)
def test_strict_scoped_replay_requires_exact_live_scope_and_config(
    tmp_path: Path,
    mutation: str,
) -> None:
    project, plan, snapshot, inventory, config, scope, vendor = (
        _strict_plugin_free_native_closure(tmp_path)
    )
    supplied_scope: FullC6AnalysisScope | None = scope
    supplied_config: RextioConfig | None = config
    if mutation == "missing-scope":
        supplied_scope = None
    elif mutation == "missing-config":
        supplied_config = None
    elif mutation == "foreign-config":
        supplied_config = RextioConfig(build=config.build)
    else:
        (vendor / "demo-dep-1.2.3" / "src" / "lib.rs").write_text(
            "pub fn answer() -> u32 { 7 }\n",
            encoding="utf-8",
        )

    assert (
        collect_scoped_source_transformation_replay_authority(
            project_root=project,
            plan=plan,
            input_snapshot=snapshot,
            transformation_inventory=inventory,
            embedding_enabled=False,
            full_c6_analysis_scope=supplied_scope,
            full_c6_config=supplied_config,
        )
        is None
    )


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


@pytest.mark.parametrize("target", ["wrapper", "cargo-toml"])
def test_scoped_replay_rejects_changed_regenerated_output(
    tmp_path: Path,
    target: str,
) -> None:
    plan, snapshot, inventory = _real_plugin_free_native_closure(tmp_path)
    if target == "wrapper":
        path = tmp_path / next(
            item.logical_path
            for item in snapshot.generated_python
            if item.logical_path.endswith("/worker.py")
        )
    else:
        path = tmp_path / next(
            item.logical_path
            for item in snapshot.generated_rust
            if item.logical_path.endswith("/Cargo.toml")
        )
    path.write_bytes(path.read_bytes() + b"\n# changed\n")

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


@pytest.mark.parametrize(
    "mutation",
    ["additional", "unexpected-non-python", "missing"],
)
def test_scoped_replay_rejects_generated_python_tree_shape_change(
    tmp_path: Path,
    mutation: str,
) -> None:
    plan, snapshot, inventory = _real_plugin_free_native_closure(tmp_path)
    python_root = ArtifactLayout(tmp_path).python_dir
    if mutation == "additional":
        (python_root / "unexpected.py").write_text("value = 1\n", encoding="utf-8")
    elif mutation == "unexpected-non-python":
        (python_root / "unexpected.txt").write_text("untracked data\n", encoding="utf-8")
    else:
        (python_root / "worker.py").unlink()

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
