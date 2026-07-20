"""Focused C6.3 tests for the opt-in required artifact-evidence gate."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import rextio.artifacts.evidence as evidence_mod
import rextio.build.orchestrator as orchestrator
import rextio.build.supply_chain as supply_chain
import rextio.cli.build_cmd as build_cmd
from rextio.analyzer.models import ProjectAnalysis
from rextio.artifacts.evidence import (
    REASON_RUNTIME_BINARY_MISMATCH,
    REASON_RUNTIME_INSPECTOR_MISSING,
    ArtifactEvidence,
    ArtifactEvidenceError,
    NativeRuntimeInventory,
    NativeRuntimePathResolutionInventory,
    WheelEntryRef,
    hash_regular_file,
)
from rextio.build.orchestrator import ArtifactEvidenceRequiredError
from rextio.build.orchestrator import required_artifact_evidence_scope_is_valid
from rextio.build.artifact_layout import ArtifactLayout
from rextio.build.runtime_resolution import NativeRuntimePathResolutionObservation
from rextio.cli.main import main


def _write_native_project(project: Path) -> None:
    (project / "app.py").write_text(
        "def add(a: int, b: int) -> int:\n    return a + b\n",
        encoding="utf-8",
    )


def _report(project: Path) -> dict[str, object]:
    return json.loads((project / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8"))


def _required_output_transaction(project: Path, *, preexisting_wheel: bytes | None = None):
    layout = ArtifactLayout(project)
    layout.build_dir.mkdir(parents=True)
    layout.dist_dir.mkdir()
    wheel = layout.dist_dir / "demo-0.1.0-py3-none-any.whl"
    if preexisting_wheel is not None:
        wheel.write_bytes(preexisting_wheel)
    transaction = orchestrator._RequiredEvidenceOutputs.prepare(layout, wheel)
    return layout, wheel, transaction


def test_required_rollback_preserves_unclaimed_concurrent_output(tmp_path: Path) -> None:
    _layout, wheel, transaction = _required_output_transaction(tmp_path)
    wheel.write_bytes(b"third-party-wheel")

    rollback = transaction.rollback()

    assert rollback.complete is False
    assert wheel.read_bytes() == b"third-party-wheel"


def test_required_claim_without_publication_receipt_never_claims_concurrent_wheel(
    tmp_path: Path,
) -> None:
    _layout, wheel, transaction = _required_output_transaction(tmp_path)
    wheel.write_bytes(b"concurrent-owner-wheel")

    with pytest.raises(OSError, match="publication receipt"):
        transaction.claim(wheel)
    rollback = transaction.rollback()

    assert rollback.complete is False
    assert wheel.read_bytes() == b"concurrent-owner-wheel"


def test_required_private_wheel_publication_never_replaces_concurrent_final(
    tmp_path: Path,
) -> None:
    _layout, wheel, transaction = _required_output_transaction(tmp_path)
    staged = transaction.backup_dir / wheel.name
    staged.write_bytes(b"transaction-wheel")
    wheel.write_bytes(b"concurrent-owner-wheel")

    with pytest.raises(OSError, match="not exclusive"):
        transaction.publish_wheel(staged)
    rollback = transaction.rollback()

    assert rollback.complete is False
    assert wheel.read_bytes() == b"concurrent-owner-wheel"
    assert not staged.exists()


def test_required_oversized_private_wheel_uses_fixed_rxt060_gate(
    tmp_path: Path,
    fake_cargo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_native_project(tmp_path)
    build_wheel = orchestrator._build_wheel_artifact

    def build_oversized_wheel(*args, **kwargs):
        result = build_wheel(*args, **kwargs)
        assert result.status == "built" and result.path is not None
        with Path(result.path).open("r+b") as handle:
            handle.truncate(evidence_mod.MAX_EVIDENCE_FILE_BYTES + 1)
        return result

    monkeypatch.setattr(orchestrator, "_build_wheel_artifact", build_oversized_wheel)

    assert main(["build", str(tmp_path), "--artifact-evidence-policy=required"]) == 1
    report = _report(tmp_path)
    evidence = report["artifact_evidence"]
    gate = report["artifact_evidence_gate"]
    failed_wheel = report["wheel_build"]
    assert isinstance(evidence, dict)
    assert evidence["reason"] == "wheel-bytes-mutated"
    assert isinstance(gate, dict)
    assert gate["reason"] == "evidence-unavailable"
    assert gate["evidence_reason"] == "wheel-bytes-mutated"
    authorization = report["artifact_distribution_authorization"]
    assert isinstance(authorization, dict)
    assert authorization["status"] == "blocked"
    assert authorization["evidence_status"] == "unavailable"
    assert authorization["evidence_reason"] == "wheel-bytes-mutated"
    assert authorization["blockers"] == ["evidence-unavailable"]
    assert authorization["distribution_authorized"] is False
    assert isinstance(failed_wheel, dict)
    assert failed_wheel["status"] == "failed"
    assert failed_wheel["message"].startswith("RXT060")


def test_required_post_claim_oversize_is_fixed_reason_and_nonthrowing_rollback(
    tmp_path: Path,
) -> None:
    _layout, wheel, transaction = _required_output_transaction(tmp_path)
    staged = transaction.backup_dir / wheel.name
    staged.write_bytes(b"transaction-wheel")
    transaction.publish_wheel(staged)
    with wheel.open("r+b") as handle:
        handle.truncate(evidence_mod.MAX_EVIDENCE_FILE_BYTES + 1)

    assert transaction.claim_mismatch_reason() == "wheel-bytes-mutated"
    rollback = transaction.rollback()

    assert rollback.complete is False
    assert wheel.stat().st_size == evidence_mod.MAX_EVIDENCE_FILE_BYTES + 1
    quarantine = transaction.backup_dir / "0.current-quarantine"
    assert quarantine.stat().st_size == evidence_mod.MAX_EVIDENCE_FILE_BYTES + 1


def test_required_rollback_quarantines_before_receipt_and_preserves_racing_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _layout, wheel, transaction = _required_output_transaction(tmp_path)
    staged = transaction.backup_dir / wheel.name
    staged.write_bytes(b"transaction-wheel")
    transaction.publish_wheel(staged)
    real_matches = evidence_mod._receipt_matches_at
    raced = False

    def race_after_quarantine(dir_fd: int, name: str, receipt) -> bool:
        nonlocal raced
        matches = real_matches(dir_fd, name, receipt)
        if matches and not raced:
            raced = True
            replacement = wheel.with_name(f".{wheel.name}.concurrent")
            replacement.write_bytes(b"concurrent-owner-wheel")
            os.replace(replacement, wheel)
        return matches

    monkeypatch.setattr(evidence_mod, "_receipt_matches_at", race_after_quarantine)
    rollback = transaction.rollback()

    assert raced is True
    assert rollback.complete is False
    assert wheel.read_bytes() == b"concurrent-owner-wheel"


def test_required_rollback_retains_quarantine_for_replaced_publication(
    tmp_path: Path,
) -> None:
    _layout, wheel, transaction = _required_output_transaction(tmp_path)
    staged = transaction.backup_dir / wheel.name
    staged.write_bytes(b"transaction-wheel")
    transaction.publish_wheel(staged)
    wheel.write_bytes(b"concurrent-owner-wheel")

    rollback = transaction.rollback()

    assert rollback.complete is False
    assert wheel.read_bytes() == b"concurrent-owner-wheel"
    quarantine = transaction.backup_dir / "0.current-quarantine"
    assert quarantine.read_bytes() == b"concurrent-owner-wheel"


def test_required_rollback_preserves_concurrent_replacement_and_backup(
    tmp_path: Path,
) -> None:
    _layout, wheel, transaction = _required_output_transaction(
        tmp_path, preexisting_wheel=b"owner-wheel"
    )
    wheel.write_bytes(b"third-party-wheel")

    rollback = transaction.rollback()

    assert rollback.complete is False
    assert wheel.read_bytes() == b"third-party-wheel"
    backup = transaction.backups[0]
    assert backup is not None
    assert backup.read_bytes() == b"owner-wheel"


def test_required_prepare_wal_survives_post_rename_and_recovery_receipt_faults(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = ArtifactLayout(tmp_path)
    layout.build_dir.mkdir(parents=True)
    layout.dist_dir.mkdir()
    wheel = layout.dist_dir / "demo-0.1.0-py3-none-any.whl"
    wheel.write_bytes(b"owner-wheel")
    real_receipt_at = orchestrator._receipt_at
    real_matches_at = orchestrator._receipt_matches_at
    receipt_calls = 0
    match_calls = 0

    def fail_old_recovery_receipt(*args, **kwargs):
        nonlocal receipt_calls
        receipt_calls += 1
        if receipt_calls == 2:
            raise ArtifactEvidenceError(
                "synthetic recovery receipt failure",
                reason="sidecar-write-failed",
            )
        return real_receipt_at(*args, **kwargs)

    def fail_first_post_rename_match(*args, **kwargs):
        nonlocal match_calls
        match_calls += 1
        if match_calls == 1:
            raise ArtifactEvidenceError(
                "synthetic post-rename inspection failure",
                reason="sidecar-write-failed",
            )
        return real_matches_at(*args, **kwargs)

    monkeypatch.setattr(orchestrator, "_receipt_at", fail_old_recovery_receipt)
    monkeypatch.setattr(orchestrator, "_receipt_matches_at", fail_first_post_rename_match)

    with pytest.raises(ArtifactEvidenceError, match="post-rename"):
        orchestrator._RequiredEvidenceOutputs.prepare(layout, wheel)

    assert wheel.read_bytes() == b"owner-wheel"
    assert receipt_calls == 1
    assert not (layout.build_dir / "required-evidence-output-backup").exists()


def test_required_prepare_receipt_disappearance_uses_fixed_rxt060_gate(
    tmp_path: Path,
    fake_cargo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_native_project(tmp_path)
    assert main(["build", str(tmp_path)]) == 0
    first_wheel = _report(tmp_path)["wheel_build"]
    assert isinstance(first_wheel, dict) and isinstance(first_wheel["path"], str)
    wheel = Path(first_wheel["path"])
    real_receipt_at = orchestrator._receipt_at
    raced = False

    def disappear_during_receipt(dir_fd: int, name: str, *, max_bytes: int):
        nonlocal raced
        if name == wheel.name and not raced:
            raced = True
            wheel.unlink()
            raise ArtifactEvidenceError(
                "synthetic disappearing owner output",
                reason="sidecar-write-failed",
            )
        return real_receipt_at(dir_fd, name, max_bytes=max_bytes)

    monkeypatch.setattr(orchestrator, "_receipt_at", disappear_during_receipt)

    assert main(["build", str(tmp_path), "--artifact-evidence-policy=required"]) == 1
    report = _report(tmp_path)
    error = report["error"]
    gate = report["artifact_evidence_gate"]
    assert raced is True
    assert report["status"] == "artifact-evidence-required-failed"
    assert isinstance(error, dict) and error["code"] == "RXT060"
    assert isinstance(gate, dict)
    assert gate["reason"] == "evidence-unavailable"
    assert gate["evidence_reason"] == "sidecar-write-failed"


@pytest.mark.skipif(__import__("os").name == "nt", reason="ancestor swap is POSIX-focused")
def test_required_rollback_pins_original_dist_across_ancestor_swap(
    tmp_path: Path,
) -> None:
    layout, wheel, transaction = _required_output_transaction(
        tmp_path, preexisting_wheel=b"owner-wheel"
    )
    original_dist = tmp_path / "dist-original"
    layout.dist_dir.rename(original_dist)
    layout.dist_dir.mkdir()
    replacement = layout.dist_dir / wheel.name
    replacement.write_bytes(b"third-party-wheel")

    rollback = transaction.rollback()

    assert rollback.complete is False
    assert replacement.read_bytes() == b"third-party-wheel"
    assert (original_dist / wheel.name).read_bytes() == b"owner-wheel"


@pytest.mark.skipif(__import__("os").name == "nt", reason="dirfd cleanup is POSIX-focused")
def test_required_prepare_cleans_own_backup_dir_when_open_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = ArtifactLayout(tmp_path)
    layout.build_dir.mkdir(parents=True)
    layout.dist_dir.mkdir()
    wheel = layout.dist_dir / "demo-0.1.0-py3-none-any.whl"
    real_open = orchestrator.os.open

    def fail_backup_open(
        path,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ):
        if path == "required-evidence-output-backup":
            raise OSError("synthetic backup directory open failure")
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(orchestrator.os, "open", fail_backup_open)

    with pytest.raises(OSError, match="synthetic backup directory open failure"):
        orchestrator._RequiredEvidenceOutputs.prepare(layout, wheel)

    assert not (layout.build_dir / "required-evidence-output-backup").exists()


def _synthetic_runtime_inventory(
    *,
    installed_path: Path | None,
    expected_python_root: Path,
    wheel_entries: tuple[WheelEntryRef, ...],
    target_triple: str,
    timeout: float,
) -> NativeRuntimeInventory:
    """Bind the real test binary to its wheel member without an inspector."""
    del expected_python_root, timeout
    assert installed_path is not None
    digest, size = hash_regular_file(installed_path)
    matches = tuple(entry for entry in wheel_entries if entry.name == installed_path.name)
    assert len(matches) == 1
    member = matches[0]
    assert member.sha256 == digest
    assert member.uncompressed_size == size
    triple_arch = target_triple.split("-", 1)[0]
    architecture = {"i386": "x86", "i686": "x86"}.get(
        triple_arch,
        triple_arch,
    )
    is_macos = target_triple.endswith("-apple-darwin")
    return NativeRuntimeInventory(
        format="mach-o" if is_macos else "elf",
        architecture=architecture,
        inspector="otool" if is_macos else "readelf",
        subject_basename=installed_path.name,
        subject_sha256=digest,
        subject_size=size,
        wheel_member=member.name,
        wheel_member_sha256=member.sha256,
        wheel_member_size=member.uncompressed_size,
        dependencies=(),
    )


@pytest.fixture(autouse=True)
def _use_synthetic_runtime_inventory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep required-gate transaction tests independent of host inspectors."""
    monkeypatch.setattr(
        supply_chain,
        "inspect_native_runtime_inventory",
        _synthetic_runtime_inventory,
    )
    monkeypatch.setattr(
        supply_chain,
        "collect_native_runtime_path_resolution",
        lambda *, runtime_inventory, **_kwargs: NativeRuntimePathResolutionObservation(
            inventory=NativeRuntimePathResolutionInventory(
                subject_wheel_member=runtime_inventory.wheel_member,
                subject_sha256=runtime_inventory.subject_sha256,
                records=(),
            ),
            receipts=(),
        ),
    )


def test_required_policy_succeeds_only_with_preview_ready_evidence(
    tmp_path: Path,
    fake_cargo: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write_native_project(tmp_path)

    assert main(["build", str(tmp_path), "--artifact-evidence-policy=required"]) == 0

    report = _report(tmp_path)
    assert report["status"] == "built"
    evidence = report["artifact_evidence"]
    assert isinstance(evidence, dict) and evidence["status"] == "preview-ready"
    assert report["artifact_evidence_gate"] == {
        "mode": "required",
        "status": "satisfied",
        "scope": "host-extension-wheel-cpython-v1",
        "required_status": "preview-ready",
        "observed_status": "preview-ready",
        "reason": None,
        "evidence_reason": None,
        "distribution_authorized": False,
        "complete": False,
        "signed": False,
    }
    authorization = report["artifact_distribution_authorization"]
    assert isinstance(authorization, dict)
    assert authorization["status"] == "blocked"
    assert authorization["authority"] == "readiness-assessment-only"
    assert authorization["evidence_status"] == "preview-ready"
    statuses = {item["id"]: item["status"] for item in authorization["checks"]}
    assert statuses["component-license-inventory-bound"] == "satisfied"
    assert statuses["scoped-component-license-policy-verified"] == "unavailable"
    assert (
        statuses["scoped-project-source-license-policy-verified"]
        == "unavailable"
    )
    assert statuses["component-license-policy-complete"] == "blocked"
    assert authorization["blockers"] == [
        "component-license-policy-incomplete",
        "native-runtime-resolution-incomplete",
        "native-runtime-transitive-closure-incomplete",
        "runtime-dynamic-loading-unverified",
        "build-input-closure-incomplete",
        "source-transformation-provenance-incomplete",
        "builder-toolchain-identity-unbound",
        "reproducibility-unverified",
        "attestation-unsigned",
        "sbom-composition-incomplete",
        "scoped-component-license-policy-verification-unavailable",
        "scoped-project-source-license-policy-verification-unavailable",
    ]
    assert authorization["distribution_authorized"] is False
    output = capsys.readouterr().out
    assert "artifact evidence gate: satisfied" in output
    assert "artifact distribution authorization: blocked" in output
    assert "preview evidence gate satisfaction is not distribution authorization" in output


@pytest.mark.parametrize("policy", ["best-effort", "required"])
def test_sparse_preview_readiness_never_changes_build_or_required_gate(
    tmp_path: Path,
    fake_cargo: Path,
    monkeypatch: pytest.MonkeyPatch,
    policy: str,
) -> None:
    _write_native_project(tmp_path)
    emit = orchestrator.emit_host_extension_wheel_evidence

    def emit_sparse(**kwargs):
        evidence = emit(**kwargs)
        assert evidence is not None and evidence.status == "preview-ready"
        object.__setattr__(evidence, "inputs", ())
        return evidence

    monkeypatch.setattr(orchestrator, "emit_host_extension_wheel_evidence", emit_sparse)

    assert main(["build", str(tmp_path), f"--artifact-evidence-policy={policy}"]) == 0
    report = _report(tmp_path)
    assert report["status"] == "built"
    authorization = report["artifact_distribution_authorization"]
    assert isinstance(authorization, dict)
    assert authorization["evidence_status"] == "preview-ready"
    assert authorization["blockers"] == ["readiness-assessment-unavailable"]
    assert {item["status"] for item in authorization["checks"]} == {
        "not-evaluated"
    }
    if policy == "required":
        gate = report["artifact_evidence_gate"]
        assert isinstance(gate, dict) and gate["status"] == "satisfied"
    else:
        assert "artifact_evidence_gate" not in report


def test_nested_preview_mutation_is_sanitized_without_changing_best_effort_success(
    tmp_path: Path,
    fake_cargo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_native_project(tmp_path)
    emit = orchestrator.emit_host_extension_wheel_evidence

    def emit_mutated(**kwargs):
        evidence = emit(**kwargs)
        assert evidence is not None and evidence.native_runtime_inventory is not None
        mutated_architecture = (
            "x86_64"
            if evidence.native_runtime_inventory.architecture == "aarch64"
            else "aarch64"
        )
        object.__setattr__(
            evidence.native_runtime_inventory,
            "architecture",
            mutated_architecture,
        )
        return evidence

    monkeypatch.setattr(orchestrator, "emit_host_extension_wheel_evidence", emit_mutated)

    assert main(["build", str(tmp_path), "--artifact-evidence-policy=best-effort"]) == 0
    report = _report(tmp_path)
    assert report["status"] == "built"
    authorization = report["artifact_distribution_authorization"]
    assert isinstance(authorization, dict)
    assert authorization["blockers"] == ["readiness-assessment-unavailable"]
    assert authorization["evidence_reason"] is None
    assert "private" not in json.dumps(authorization, sort_keys=True)


def test_required_policy_rejects_scope_before_toolchain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "app.py").write_text(
        "import rextio\n\n@rextio.exempt\ndef value() -> int:\n    return 1\n",
        encoding="utf-8",
    )

    def unexpected(*_args, **_kwargs):
        pytest.fail("out-of-scope required policy must not probe the toolchain")

    monkeypatch.setattr(build_cmd, "_prepare_build_toolchain", unexpected)

    assert main(["build", str(tmp_path), "--artifact-evidence-policy=required"]) == 1
    report = _report(tmp_path)
    assert report["status"] == "artifact-evidence-required-failed"
    error = report["error"]
    gate = report["artifact_evidence_gate"]
    assert isinstance(error, dict) and error["code"] == "RXT060"
    assert isinstance(gate, dict) and gate["reason"] == "artifact-set-out-of-scope"
    assert gate["observed_status"] is None
    assert "artifact_distribution_authorization" not in report
    assert "artifact-set-out-of-scope" in capsys.readouterr().err


def test_programmatic_required_policy_cannot_bypass_scope() -> None:
    with pytest.raises(ArtifactEvidenceRequiredError) as raised:
        orchestrator.build_hybrid_artifact(
            Path("unused"),
            ProjectAnalysis(project_root=Path("unused"), modules=[]),
            "cpython",
            artifact_evidence_policy="required",
        )
    assert raised.value.gate.reason == "artifact-set-out-of-scope"
    assert raised.value.result is None


@pytest.mark.parametrize(
    ("native_extension", "fallback", "entrypoint", "rust_importable"),
    [
        (False, "cpython", None, False),
        (True, "nuitka", None, False),
        (True, "cpython", "app:main", False),
        (True, "cpython", None, True),
    ],
)
def test_required_scope_rejects_each_extra_or_missing_artifact_dimension(
    native_extension: bool,
    fallback: str,
    entrypoint: str | None,
    rust_importable: bool,
) -> None:
    assert not required_artifact_evidence_scope_is_valid(
        native_extension=native_extension,
        fallback=fallback,
        executable_entrypoint=entrypoint,
        rust_importable=rust_importable,
    )


def test_required_unavailable_restores_exact_preexisting_outputs(
    tmp_path: Path,
    fake_cargo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_native_project(tmp_path)
    assert main(["build", str(tmp_path)]) == 0
    first = _report(tmp_path)
    wheel_build = first["wheel_build"]
    assert isinstance(wheel_build, dict) and isinstance(wheel_build["path"], str)
    wheel = Path(wheel_build["path"])
    sbom = wheel.with_suffix(wheel.suffix + ".cdx.json")
    provenance = wheel.with_suffix(wheel.suffix + ".intoto.json")
    unrelated = tmp_path / "dist" / "owner.txt"
    wheel.write_bytes(b"owner-wheel")
    sbom.write_bytes(b"owner-sbom")
    provenance.write_bytes(b"owner-provenance")
    unrelated.write_bytes(b"owner-unrelated")

    monkeypatch.setattr(
        orchestrator,
        "emit_host_extension_wheel_evidence",
        lambda **_kwargs: ArtifactEvidence.unavailable(reason="cargo-metadata-failed"),
    )

    assert main(["build", str(tmp_path), "--artifact-evidence-policy=required"]) == 1
    report = _report(tmp_path)
    assert report["status"] == "artifact-evidence-required-failed"
    failed_wheel = report["wheel_build"]
    gate = report["artifact_evidence_gate"]
    assert isinstance(failed_wheel, dict) and failed_wheel["status"] == "failed"
    assert isinstance(gate, dict) and gate["reason"] == "evidence-unavailable"
    assert gate["evidence_reason"] == "cargo-metadata-failed"
    assert wheel.read_bytes() == b"owner-wheel"
    assert sbom.read_bytes() == b"owner-sbom"
    assert provenance.read_bytes() == b"owner-provenance"
    assert unrelated.read_bytes() == b"owner-unrelated"
    assert (tmp_path / ".rextio" / "generated" / "rust" / "src" / "lib.rs").is_file()


def test_required_runtime_inspector_unavailable_uses_fixed_reason_and_rolls_back(
    tmp_path: Path,
    fake_cargo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_native_project(tmp_path)

    def unavailable(**_kwargs):
        raise ArtifactEvidenceError(
            "synthetic inspector unavailable",
            reason=REASON_RUNTIME_INSPECTOR_MISSING,
        )

    monkeypatch.setattr(
        supply_chain,
        "inspect_native_runtime_inventory",
        unavailable,
    )

    assert main(["build", str(tmp_path), "--artifact-evidence-policy=required"]) == 1
    report = _report(tmp_path)
    evidence = report["artifact_evidence"]
    gate = report["artifact_evidence_gate"]
    assert isinstance(evidence, dict)
    assert evidence["status"] == "unavailable"
    assert evidence["reason"] == REASON_RUNTIME_INSPECTOR_MISSING
    assert isinstance(gate, dict)
    assert gate["reason"] == "evidence-unavailable"
    assert gate["evidence_reason"] == REASON_RUNTIME_INSPECTOR_MISSING
    assert not any((tmp_path / "dist").glob("*.whl*"))


def test_required_late_native_mutation_restores_preexisting_exact_outputs(
    tmp_path: Path,
    fake_cargo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_native_project(tmp_path)
    monkeypatch.setattr(
        supply_chain,
        "inspect_native_runtime_inventory",
        _synthetic_runtime_inventory,
    )

    # Establish the exact output names, then replace them with owner content so
    # required mode must prove its transactional rollback after a late native
    # binary mutation.
    assert main(["build", str(tmp_path)]) == 0
    first = _report(tmp_path)
    wheel_build = first["wheel_build"]
    assert isinstance(wheel_build, dict) and isinstance(wheel_build["path"], str)
    wheel = Path(wheel_build["path"])
    sbom = wheel.with_suffix(wheel.suffix + ".cdx.json")
    provenance = wheel.with_suffix(wheel.suffix + ".intoto.json")
    unrelated = tmp_path / "dist" / "owner-unrelated.txt"
    wheel.write_bytes(b"owner-wheel")
    sbom.write_bytes(b"owner-sbom")
    provenance.write_bytes(b"owner-provenance")
    unrelated.write_bytes(b"owner-unrelated")

    emit = orchestrator.emit_host_extension_wheel_evidence

    def emit_then_mutate(**kwargs):
        evidence = emit(**kwargs)
        assert evidence is not None and evidence.status == "preview-ready"
        installed_path = kwargs["native_build"].installed_path
        assert installed_path is not None
        Path(installed_path).write_bytes(b"mutated-after-evidence")
        return evidence

    monkeypatch.setattr(
        orchestrator,
        "emit_host_extension_wheel_evidence",
        emit_then_mutate,
    )

    assert main(["build", str(tmp_path), "--artifact-evidence-policy=required"]) == 1
    report = _report(tmp_path)
    evidence = report["artifact_evidence"]
    gate = report["artifact_evidence_gate"]
    assert isinstance(evidence, dict)
    assert evidence["reason"] == REASON_RUNTIME_BINARY_MISMATCH
    assert isinstance(gate, dict)
    assert gate["reason"] == "evidence-unavailable"
    assert gate["evidence_reason"] == REASON_RUNTIME_BINARY_MISMATCH
    assert wheel.read_bytes() == b"owner-wheel"
    assert sbom.read_bytes() == b"owner-sbom"
    assert provenance.read_bytes() == b"owner-provenance"
    assert unrelated.read_bytes() == b"owner-unrelated"
    assert not (tmp_path / ".rextio" / "build" / "required-evidence-output-backup").exists()


def test_required_wheel_builder_exception_restores_preexisting_outputs(
    tmp_path: Path,
    fake_cargo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_native_project(tmp_path)
    assert main(["build", str(tmp_path)]) == 0
    wheel_build = _report(tmp_path)["wheel_build"]
    assert isinstance(wheel_build, dict) and isinstance(wheel_build["path"], str)
    wheel = Path(wheel_build["path"])
    sbom = wheel.with_suffix(wheel.suffix + ".cdx.json")
    provenance = wheel.with_suffix(wheel.suffix + ".intoto.json")
    wheel.write_bytes(b"owner-wheel")
    sbom.write_bytes(b"owner-sbom")
    provenance.write_bytes(b"owner-provenance")

    def fail_wheel(*_args, **_kwargs):
        raise RuntimeError("forced wheel builder failure")

    monkeypatch.setattr(orchestrator, "_build_wheel_artifact", fail_wheel)
    with pytest.raises(RuntimeError, match="forced wheel builder failure"):
        main(["build", str(tmp_path), "--artifact-evidence-policy=required"])

    assert wheel.read_bytes() == b"owner-wheel"
    assert sbom.read_bytes() == b"owner-sbom"
    assert provenance.read_bytes() == b"owner-provenance"
    assert not (tmp_path / ".rextio" / "build" / "required-evidence-output-backup").exists()


@pytest.mark.parametrize(
    ("mutated", "reason"),
    [("wheel", "wheel-bytes-mutated"), ("sbom", "sidecar-write-failed")],
)
def test_required_gate_preserves_concurrently_mutated_final_output(
    tmp_path: Path,
    fake_cargo: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutated: str,
    reason: str,
) -> None:
    _write_native_project(tmp_path)
    emit = orchestrator.emit_host_extension_wheel_evidence

    def emit_then_mutate(**kwargs):
        evidence = emit(**kwargs)
        assert evidence is not None and evidence.status == "preview-ready"
        wheel_build = kwargs["wheel_build"]
        wheel = Path(wheel_build.path)
        path = wheel if mutated == "wheel" else wheel.with_suffix(wheel.suffix + ".cdx.json")
        path.write_bytes(b"mutated-after-evidence")
        return evidence

    monkeypatch.setattr(orchestrator, "emit_host_extension_wheel_evidence", emit_then_mutate)
    assert main(["build", str(tmp_path), "--artifact-evidence-policy=required"]) == 1
    report = _report(tmp_path)
    evidence = report["artifact_evidence"]
    assert isinstance(evidence, dict) and evidence["reason"] == reason
    failed_wheel = report["wheel_build"]
    assert isinstance(failed_wheel, dict)
    assert "rollback was incomplete" in failed_wheel["message"]
    wheel = next((tmp_path / "dist").glob("*.whl")) if mutated == "wheel" else None
    if wheel is None:
        mutated_path = next((tmp_path / "dist").glob("*.whl.cdx.json"))
    else:
        mutated_path = wheel
    assert mutated_path.read_bytes() == b"mutated-after-evidence"
    assert list((tmp_path / "dist").glob("*.whl*")) == [mutated_path]


def test_required_commit_race_is_fixed_reason_and_preserves_replacement(
    tmp_path: Path,
    fake_cargo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_native_project(tmp_path)
    commit = orchestrator._RequiredEvidenceOutputs.commit

    def mutate_then_commit(outputs: orchestrator._RequiredEvidenceOutputs) -> None:
        outputs.paths[1].write_bytes(b"concurrent-sbom-at-commit")
        commit(outputs)

    monkeypatch.setattr(
        orchestrator._RequiredEvidenceOutputs,
        "commit",
        mutate_then_commit,
    )

    assert main(["build", str(tmp_path), "--artifact-evidence-policy=required"]) == 1
    report = _report(tmp_path)
    evidence = report["artifact_evidence"]
    gate = report["artifact_evidence_gate"]
    failed_wheel = report["wheel_build"]
    assert isinstance(evidence, dict)
    assert evidence["reason"] == "sidecar-write-failed"
    assert isinstance(gate, dict)
    assert gate["reason"] == "evidence-unavailable"
    assert gate["evidence_reason"] == "sidecar-write-failed"
    assert isinstance(failed_wheel, dict)
    assert "rollback was incomplete" in failed_wheel["message"]
    sbom = next((tmp_path / "dist").glob("*.whl.cdx.json"))
    assert sbom.read_bytes() == b"concurrent-sbom-at-commit"
    assert list((tmp_path / "dist").glob("*.whl*")) == [sbom]


def test_required_prebuild_failure_clears_stale_reports(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "app.py").write_text(
        "import rextio\n\n@rextio.exempt\ndef value() -> int:\n    return 1\n",
        encoding="utf-8",
    )
    reports = tmp_path / ".rextio" / "reports"
    reports.mkdir(parents=True)
    for name in ("build.json", "generate.json", "check.json"):
        (reports / name).write_text('{"stale": true}\n', encoding="utf-8")

    assert main(["build", str(tmp_path), "--artifact-evidence-policy=required"]) == 1
    assert not (reports / "generate.json").exists()
    assert _report(tmp_path)["status"] == "artifact-evidence-required-failed"
    assert "stale" not in json.loads((reports / "check.json").read_text(encoding="utf-8"))
    assert "artifact-set-out-of-scope" in capsys.readouterr().err


def test_cli_evidence_policy_overrides_environment(
    tmp_path: Path,
    fake_cargo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_native_project(tmp_path)
    monkeypatch.setenv("REXTIO_ARTIFACT_EVIDENCE_POLICY", "required")
    monkeypatch.setattr(
        orchestrator,
        "emit_host_extension_wheel_evidence",
        lambda **_kwargs: ArtifactEvidence.unavailable(reason="cargo-metadata-failed"),
    )

    assert main(["build", str(tmp_path), "--artifact-evidence-policy=best-effort"]) == 0
    report = _report(tmp_path)
    assert "artifact_evidence_gate" not in report
    authorization = report["artifact_distribution_authorization"]
    assert isinstance(authorization, dict)
    assert authorization["evidence_status"] == "unavailable"
    assert authorization["blockers"] == ["evidence-unavailable"]
    assert authorization["status"] == "blocked"
    assert report["status"] == "built"


def test_required_policy_refuses_symlinked_dist_parent(
    tmp_path: Path,
    fake_cargo: Path,
) -> None:
    _write_native_project(tmp_path)
    owner_dir = tmp_path / "owner-output"
    owner_dir.mkdir()
    marker = owner_dir / "marker.txt"
    marker.write_text("owner", encoding="utf-8")
    (tmp_path / "dist").symlink_to(owner_dir, target_is_directory=True)

    assert main(["build", str(tmp_path), "--artifact-evidence-policy=required"]) == 1

    report = _report(tmp_path)
    evidence = report["artifact_evidence"]
    gate = report["artifact_evidence_gate"]
    assert isinstance(evidence, dict) and evidence["reason"] == "sidecar-write-failed"
    assert isinstance(gate, dict) and gate["reason"] == "evidence-unavailable"
    authorization = report["artifact_distribution_authorization"]
    assert isinstance(authorization, dict)
    assert authorization["evidence_reason"] == "sidecar-write-failed"
    assert authorization["blockers"] == ["evidence-unavailable"]
    assert marker.read_text(encoding="utf-8") == "owner"
    assert list(owner_dir.iterdir()) == [marker]
