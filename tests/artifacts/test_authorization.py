"""Focused tests for the C6.5 hard-authorization readiness contract."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError, replace

import pytest

from rextio.artifacts.authorization import (
    ARTIFACT_AUTHORIZATION_CHECK_IDS,
    ARTIFACT_AUTHORIZATION_PREVIEW_BLOCKERS,
    ARTIFACT_AUTHORIZATION_READINESS_UNAVAILABLE,
    ArtifactAuthorizationCheck,
    ArtifactDistributionAuthorizationAssessment,
    evaluate_artifact_distribution_authorization,
)
from rextio.artifacts.evidence import (
    ArtifactEvidence,
    CargoDepEdge,
    CargoPackageRef,
    EvidenceFileRef,
    NativeRuntimeDependency,
    NativeRuntimeInventory,
    SidecarArtifact,
    WheelEntryRef,
)


def _preview_evidence() -> ArtifactEvidence:
    native_entry = WheelEntryRef(
        name="_rextio_native.so",
        sha256="9" * 64,
        compressed_size=1,
        uncompressed_size=1,
    )
    root_package = CargoPackageRef(
        name="rextio-generated-native",
        version="0.1.0",
        source=None,
        checksum=None,
        kind="path-root",
    )
    registry_package = CargoPackageRef(
        name="pyo3",
        version="0.23.5",
        source="registry+https://github.com/rust-lang/crates.io-index",
        checksum="7" * 64,
        kind="registry",
    )
    return ArtifactEvidence(
        kind="host-extension-wheel",
        status="preview-ready",
        target_triple="x86_64-unknown-linux-gnu",
        subject=EvidenceFileRef(
            logical_path="dist/demo.whl",
            sha256="0" * 64,
            size=1,
            role="host-extension-wheel",
        ),
        sbom=SidecarArtifact(
            format="CycloneDX",
            logical_path="dist/demo.whl.cdx.json",
            sha256="1" * 64,
            size=1,
            extra={"spec_version": "1.6", "aggregate": "incomplete", "signed": False},
        ),
        provenance=SidecarArtifact(
            format="in-toto-Statement",
            logical_path="dist/demo.whl.intoto.json",
            sha256="2" * 64,
            size=1,
            extra={
                "predicate_type": "https://slsa.dev/provenance/v1",
                "statement_type": "https://in-toto.io/Statement/v1",
                "signed": False,
            },
        ),
        inputs=(
            EvidenceFileRef(
                logical_path="app.py",
                sha256="3" * 64,
                size=1,
                role="project-python-source",
            ),
            EvidenceFileRef(
                logical_path=".rextio/generated/python/app.py",
                sha256="4" * 64,
                size=1,
                role="generated-python-input",
            ),
            EvidenceFileRef(
                logical_path=".rextio/generated/rust/src/lib.rs",
                sha256="5" * 64,
                size=1,
                role="generated-rust-input",
            ),
            EvidenceFileRef(
                logical_path=".rextio/generated/rust/Cargo.lock",
                sha256="6" * 64,
                size=1,
                role="generated-cargo-lock",
            ),
        ),
        cargo_packages=(root_package, registry_package),
        cargo_dependencies=(
            CargoDepEdge(
                dependent_ref=root_package.bom_ref(),
                dependency_ref=registry_package.bom_ref(),
            ),
        ),
        wheel_entries=(native_entry,),
        native_runtime_inventory=NativeRuntimeInventory(
            format="elf",
            architecture="x86_64",
            inspector="readelf",
            subject_basename=native_entry.name,
            subject_sha256=native_entry.sha256,
            subject_size=native_entry.uncompressed_size,
            wheel_member=native_entry.name,
            wheel_member_sha256=native_entry.sha256,
            wheel_member_size=native_entry.uncompressed_size,
            dependencies=(NativeRuntimeDependency(name="libc.so.6"),),
        ),
    )


def test_preview_ready_assessment_is_canonical_and_always_blocked() -> None:
    assessment = ArtifactDistributionAuthorizationAssessment.from_evidence(
        _preview_evidence()
    )
    report = assessment.to_dict()

    assert report["kind"] == "artifact-distribution-authorization"
    assert report["policy"] == "host-extension-wheel-cpython-v1"
    assert report["policy_version"] == 1
    assert report["scope"] == "host-extension-wheel-cpython-v1"
    assert report["status"] == "blocked"
    assert report["authority"] == "readiness-assessment-only"
    assert report["evidence_status"] == "preview-ready"
    assert report["evidence_reason"] is None
    assert [item["id"] for item in report["checks"]] == list(
        ARTIFACT_AUTHORIZATION_CHECK_IDS
    )
    assert [item["status"] for item in report["checks"][:4]] == [
        "satisfied",
        "satisfied",
        "satisfied",
        "satisfied",
    ]
    assert {item["status"] for item in report["checks"][4:]} == {"blocked"}
    assert report["blockers"] == list(ARTIFACT_AUTHORIZATION_PREVIEW_BLOCKERS)
    assert report["complete"] is False
    assert report["signed"] is False
    assert report["distribution_authorized"] is False


def test_unavailable_assessment_does_not_speculate_or_leak_free_text() -> None:
    assessment = ArtifactDistributionAuthorizationAssessment.from_evidence(
        ArtifactEvidence.unavailable(reason="cargo-metadata-failed")
    )
    report = assessment.to_dict()

    assert report["evidence_status"] == "unavailable"
    assert report["evidence_reason"] == "cargo-metadata-failed"
    assert [item["status"] for item in report["checks"][:4]] == [
        "unavailable",
        "unavailable",
        "unavailable",
        "unavailable",
    ]
    assert {item["status"] for item in report["checks"][4:]} == {"not-evaluated"}
    assert report["blockers"] == ["evidence-unavailable"]
    assert "/" not in json.dumps(report, sort_keys=True)


def test_assessment_is_immutable_and_truthy_authority_fields_are_forced_false() -> None:
    assessment = ArtifactDistributionAuthorizationAssessment.from_evidence(
        _preview_evidence()
    )

    with pytest.raises(FrozenInstanceError):
        assessment.status = "authorized"  # type: ignore[misc]

    rewritten = replace(
        assessment,
        complete=True,
        signed=True,
        distribution_authorized=True,
    )
    assert rewritten.complete is False
    assert rewritten.signed is False
    assert rewritten.distribution_authorized is False


def test_assessment_rejects_unknown_duplicate_reordered_and_free_text_values() -> None:
    assessment = ArtifactDistributionAuthorizationAssessment.from_evidence(
        _preview_evidence()
    )

    with pytest.raises(ValueError, match="allowlist"):
        ArtifactAuthorizationCheck(id="future-check", status="blocked")
    with pytest.raises(ValueError, match="unique"):
        replace(
            assessment,
            checks=(assessment.checks[0], *assessment.checks[:-1]),
        )
    with pytest.raises(ValueError, match="canonical order"):
        replace(
            assessment,
            checks=(assessment.checks[1], assessment.checks[0], *assessment.checks[2:]),
        )
    with pytest.raises(ValueError, match="allowlist"):
        replace(assessment, blockers=("/tmp/untrusted failure detail",))


def test_assessment_revalidates_tampered_evidence_and_serializes_deterministically() -> None:
    evidence = _preview_evidence()
    first = ArtifactDistributionAuthorizationAssessment.from_evidence(evidence)
    second = ArtifactDistributionAuthorizationAssessment.from_evidence(evidence)
    assert json.dumps(first.to_dict(), sort_keys=True) == json.dumps(
        second.to_dict(), sort_keys=True
    )

    object.__setattr__(evidence, "reason", "/tmp/private/error")
    report = evaluate_artifact_distribution_authorization(evidence).to_dict()
    assert report["evidence_status"] == "preview-ready"
    assert report["evidence_reason"] is None
    assert report["blockers"] == [ARTIFACT_AUTHORIZATION_READINESS_UNAVAILABLE]
    assert {item["status"] for item in report["checks"]} == {"not-evaluated"}
    assert "/tmp/private/error" not in json.dumps(report, sort_keys=True)


@pytest.mark.parametrize("missing_field", ["inputs", "cargo_packages"])
def test_assessment_never_claims_sparse_preview_observations(
    missing_field: str,
) -> None:
    evidence = _preview_evidence()
    replacements = {missing_field: ()}
    if missing_field == "cargo_packages":
        replacements["cargo_dependencies"] = ()
    sparse = replace(evidence, **replacements)

    report = ArtifactDistributionAuthorizationAssessment.from_evidence(sparse).to_dict()
    assert report["evidence_status"] == "preview-ready"
    assert report["blockers"] == [ARTIFACT_AUTHORIZATION_READINESS_UNAVAILABLE]
    assert {item["status"] for item in report["checks"]} == {"not-evaluated"}


@pytest.mark.parametrize(
    "nested_model",
    [
        "subject",
        "sbom",
        "provenance",
        "input",
        "wheel_entry",
        "cargo_package",
        "cargo_edge",
        "runtime_inventory",
        "runtime_architecture",
        "runtime_dependency",
    ],
)
def test_nested_low_level_mutation_never_yields_satisfied_observations(
    nested_model: str,
) -> None:
    evidence = _preview_evidence()
    injected = "/private/review-secret"
    if nested_model == "subject":
        assert evidence.subject is not None
        object.__setattr__(evidence.subject, "logical_path", injected)
    elif nested_model == "sbom":
        assert evidence.sbom is not None
        object.__setattr__(evidence.sbom, "logical_path", injected)
    elif nested_model == "provenance":
        assert evidence.provenance is not None
        object.__setattr__(evidence.provenance, "logical_path", injected)
    elif nested_model == "input":
        object.__setattr__(evidence.inputs[0], "logical_path", injected)
    elif nested_model == "wheel_entry":
        object.__setattr__(evidence.wheel_entries[0], "name", injected)
    elif nested_model == "cargo_package":
        object.__setattr__(evidence.cargo_packages[1], "source", injected)
    elif nested_model == "cargo_edge":
        object.__setattr__(evidence.cargo_dependencies[0], "dependent_ref", injected)
    elif nested_model == "runtime_inventory":
        assert evidence.native_runtime_inventory is not None
        object.__setattr__(
            evidence.native_runtime_inventory,
            "wheel_member",
            injected,
        )
    elif nested_model == "runtime_architecture":
        assert evidence.native_runtime_inventory is not None
        object.__setattr__(evidence.native_runtime_inventory, "architecture", "aarch64")
    else:
        assert evidence.native_runtime_inventory is not None
        object.__setattr__(
            evidence.native_runtime_inventory.dependencies[0],
            "name",
            injected,
        )

    report = evaluate_artifact_distribution_authorization(evidence).to_dict()
    assert report["evidence_status"] == "preview-ready"
    assert report["blockers"] == [ARTIFACT_AUTHORIZATION_READINESS_UNAVAILABLE]
    assert {item["status"] for item in report["checks"]} == {"not-evaluated"}
    assert injected not in json.dumps(report, sort_keys=True)


@pytest.mark.parametrize(
    ("target_triple", "architecture"),
    [
        ("thumbv7neon-unknown-linux-gnueabihf", "arm"),
        ("powerpc64le-unknown-linux-gnu", "powerpc64"),
        ("ppc64le-unknown-linux-gnu", "powerpc64"),
        ("riscv64gc-unknown-linux-gnu", "riscv64"),
    ],
)
def test_target_architecture_vocabulary_matches_c6_4_runtime_inventory(
    target_triple: str,
    architecture: str,
) -> None:
    evidence = _preview_evidence()
    assert evidence.native_runtime_inventory is not None
    runtime = replace(evidence.native_runtime_inventory, architecture=architecture)
    adjusted = replace(
        evidence,
        target_triple=target_triple,
        native_runtime_inventory=runtime,
    )

    report = evaluate_artifact_distribution_authorization(adjusted).to_dict()
    assert [item["status"] for item in report["checks"][:4]] == ["satisfied"] * 4


def test_evaluator_is_total_for_low_level_invalid_top_level_status() -> None:
    evidence = _preview_evidence()
    object.__setattr__(evidence, "status", [])

    report = evaluate_artifact_distribution_authorization(evidence).to_dict()
    assert report["evidence_status"] == "unavailable"
    assert report["evidence_reason"] == "evidence-internal-error"
    assert report["blockers"] == ["evidence-unavailable"]
    assert report["distribution_authorized"] is False
