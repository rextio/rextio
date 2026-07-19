"""Focused C6.3 tests for the opt-in required artifact-evidence gate."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import rextio.build.orchestrator as orchestrator
import rextio.cli.build_cmd as build_cmd
from rextio.analyzer.models import ProjectAnalysis
from rextio.artifacts.evidence import ArtifactEvidence
from rextio.build.orchestrator import ArtifactEvidenceRequiredError
from rextio.build.orchestrator import required_artifact_evidence_scope_is_valid
from rextio.cli.main import main


def _write_native_project(project: Path) -> None:
    (project / "app.py").write_text(
        "def add(a: int, b: int) -> int:\n    return a + b\n",
        encoding="utf-8",
    )


def _report(project: Path) -> dict[str, object]:
    return json.loads(
        (project / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )


def test_required_policy_succeeds_only_with_preview_ready_evidence(
    tmp_path: Path, fake_cargo: Path
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
    assert not (
        tmp_path / ".rextio" / "build" / "required-evidence-output-backup"
    ).exists()


@pytest.mark.parametrize(
    ("mutated", "reason"),
    [("wheel", "wheel-bytes-mutated"), ("sbom", "sidecar-write-failed")],
)
def test_required_gate_revalidates_exact_final_outputs(
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

    monkeypatch.setattr(
        orchestrator, "emit_host_extension_wheel_evidence", emit_then_mutate
    )
    assert main(["build", str(tmp_path), "--artifact-evidence-policy=required"]) == 1
    report = _report(tmp_path)
    evidence = report["artifact_evidence"]
    assert isinstance(evidence, dict) and evidence["reason"] == reason
    assert not any((tmp_path / "dist").glob("*.whl*"))


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

    assert (
        main(["build", str(tmp_path), "--artifact-evidence-policy=best-effort"])
        == 0
    )
    assert "artifact_evidence_gate" not in _report(tmp_path)


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
    assert marker.read_text(encoding="utf-8") == "owner"
    assert list(owner_dir.iterdir()) == [marker]
