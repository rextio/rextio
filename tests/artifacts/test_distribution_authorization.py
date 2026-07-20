"""Focused tests for the C6.5 hard-authorization readiness contract."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError, replace

import pytest

from rextio.artifacts.authorization import (
    ARTIFACT_AUTHORIZATION_CHECK_IDS,
    ARTIFACT_AUTHORIZATION_PREVIEW_BLOCKERS,
    ARTIFACT_AUTHORIZATION_READINESS_UNAVAILABLE,
    ARTIFACT_AUTHORIZATION_LICENSE_UNAVAILABLE,
    ARTIFACT_AUTHORIZATION_TRANSFORMATION_UNAVAILABLE,
    ArtifactAuthorizationCheck,
    ArtifactDistributionAuthorizationAssessment,
    evaluate_artifact_distribution_authorization,
)
from rextio.artifacts.evidence import (
    MAX_SOURCE_TRANSFORMATION_PLUGIN_IDS,
    MAX_SOURCE_TRANSFORMATIONS,
    MAX_COMPONENT_LICENSE_RECORDS,
    ArtifactEvidence,
    CargoDepEdge,
    CargoPackageRef,
    ComponentLicenseInventory,
    ComponentLicenseRecord,
    EvidenceFileRef,
    NativeRuntimeDependency,
    NativeRuntimeInventory,
    SidecarArtifact,
    SourceTransformationInventory,
    SourceTransformationRange,
    SourceTransformationRecord,
    ArtifactEvidenceGate,
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
        license="MIT OR Apache-2.0",
    )
    source_ref = EvidenceFileRef(
        logical_path="app.py",
        sha256="3" * 64,
        size=1,
        role="project-python-source",
    )
    generated_rust_ref = EvidenceFileRef(
        logical_path=".rextio/generated/rust/src/lib.rs",
        sha256="5" * 64,
        size=1,
        role="generated-rust-input",
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
            source_ref,
            EvidenceFileRef(
                logical_path=".rextio/generated/python/app.py",
                sha256="4" * 64,
                size=1,
                role="generated-python-input",
            ),
            generated_rust_ref,
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
        source_transformation_inventory=SourceTransformationInventory(
            records=(
                SourceTransformationRecord(
                    source_path=source_ref.logical_path,
                    source_sha256=source_ref.sha256,
                    function_module="app",
                    function_qualname="app.add",
                    source_range=SourceTransformationRange(
                        start_line=1,
                        start_column=0,
                        end_line=2,
                        end_column=16,
                    ),
                    semantic_ast_sha256="8" * 64,
                    generated_rust=generated_rust_ref,
                    generator_backend="rextio-core-rust-pyo3-v1",
                ),
            )
        ),
        component_license_inventory=ComponentLicenseInventory(
            records=tuple(
                ComponentLicenseRecord(
                    bom_ref=package.bom_ref(),
                    name=package.name,
                    version=package.version,
                    kind=package.kind,
                    license_observed=package.license,
                    license_observation=(
                        "declared-unvalidated" if package.license is not None else "missing"
                    ),
                )
                for package in sorted(
                    (root_package, registry_package),
                    key=lambda package: package.bom_ref(),
                )
            )
        ),
    )


def test_preview_ready_assessment_is_canonical_and_always_blocked() -> None:
    assessment = ArtifactDistributionAuthorizationAssessment.from_evidence(
        _preview_evidence()
    )
    report = assessment.to_dict()

    assert report["kind"] == "artifact-distribution-authorization"
    assert report["policy"] == "host-extension-wheel-cpython-v1"
    assert report["policy_version"] == 3
    assert report["scope"] == "host-extension-wheel-cpython-v1"
    assert report["status"] == "blocked"
    assert report["authority"] == "readiness-assessment-only"
    assert report["evidence_status"] == "preview-ready"
    assert report["evidence_reason"] is None
    assert [item["id"] for item in report["checks"]] == list(
        ARTIFACT_AUTHORIZATION_CHECK_IDS
    )
    assert [item["status"] for item in report["checks"][:6]] == [
        "satisfied",
        "satisfied",
        "satisfied",
        "satisfied",
        "satisfied",
        "satisfied",
    ]
    assert {item["status"] for item in report["checks"][6:]} == {"blocked"}
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
    assert [item["status"] for item in report["checks"][:6]] == [
        "unavailable",
        "unavailable",
        "unavailable",
        "unavailable",
        "unavailable",
        "unavailable",
    ]
    assert {item["status"] for item in report["checks"][6:]} == {"not-evaluated"}
    assert report["blockers"] == ["evidence-unavailable"]
    assert "/" not in json.dumps(report, sort_keys=True)


def test_missing_transformation_inventory_is_a_dedicated_closed_observation() -> None:
    evidence = replace(_preview_evidence(), source_transformation_inventory=None)
    report = evaluate_artifact_distribution_authorization(evidence).to_dict()
    statuses = {item["id"]: item["status"] for item in report["checks"]}

    assert statuses["artifact-subject-bound"] == "satisfied"
    assert statuses["direct-native-linkage-observed"] == "satisfied"
    assert statuses["source-transformation-inventory-bound"] == "unavailable"
    assert statuses["source-transformation-provenance-complete"] == "blocked"
    assert report["blockers"] == [
        *ARTIFACT_AUTHORIZATION_PREVIEW_BLOCKERS,
        ARTIFACT_AUTHORIZATION_TRANSFORMATION_UNAVAILABLE,
    ]
    assert ARTIFACT_AUTHORIZATION_READINESS_UNAVAILABLE not in report["blockers"]
    # C6.3 evaluates the existing preview evidence independently.
    assert ArtifactEvidenceGate.from_evidence(evidence).status == "satisfied"


def test_missing_license_inventory_is_a_dedicated_closed_observation() -> None:
    evidence = replace(_preview_evidence(), component_license_inventory=None)
    report = evaluate_artifact_distribution_authorization(evidence).to_dict()
    statuses = {item["id"]: item["status"] for item in report["checks"]}

    assert statuses["source-transformation-inventory-bound"] == "satisfied"
    assert statuses["component-license-inventory-bound"] == "unavailable"
    assert statuses["component-license-policy-complete"] == "blocked"
    assert report["blockers"] == [
        *ARTIFACT_AUTHORIZATION_PREVIEW_BLOCKERS,
        ARTIFACT_AUTHORIZATION_LICENSE_UNAVAILABLE,
    ]
    assert ArtifactEvidenceGate.from_evidence(evidence).status == "satisfied"


def test_structurally_valid_semantic_hash_change_remains_unsigned_observation() -> None:
    evidence = _preview_evidence()
    inventory = evidence.source_transformation_inventory
    assert inventory is not None
    changed_record = replace(
        inventory.records[0],
        semantic_ast_sha256="9" * 64,
    )
    adjusted = replace(
        evidence,
        source_transformation_inventory=replace(
            inventory,
            records=(changed_record,),
        ),
    )

    report = evaluate_artifact_distribution_authorization(adjusted).to_dict()
    statuses = {item["id"]: item["status"] for item in report["checks"]}
    assert statuses["source-transformation-inventory-bound"] == "satisfied"
    assert statuses["source-transformation-provenance-complete"] == "blocked"
    assert report["status"] == "blocked"
    assert report["signed"] is False
    assert report["distribution_authorized"] is False


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


@pytest.mark.parametrize("mutation", ["missing", "extra", "reordered", "stale"])
def test_non_exact_component_license_binding_fails_closed(mutation: str) -> None:
    evidence = _preview_evidence()
    inventory = evidence.component_license_inventory
    assert inventory is not None
    records = inventory.records
    if mutation == "missing":
        mutated = records[:-1]
    elif mutation == "extra":
        mutated = (*records, records[-1])
    elif mutation == "reordered":
        mutated = tuple(reversed(records))
    elif mutation == "stale":
        mutated = (replace(records[0], version="9.9.9"), *records[1:])
    else:  # pragma: no cover - closed parametrization guard
        raise AssertionError(mutation)
    # Bypass constructors to model a stale/deserialized or low-level-mutated
    # record. The evaluator must reconstruct and fail closed.
    object.__setattr__(inventory, "records", mutated)

    report = evaluate_artifact_distribution_authorization(evidence).to_dict()
    assert report["blockers"] == [ARTIFACT_AUTHORIZATION_READINESS_UNAVAILABLE]
    assert {item["status"] for item in report["checks"]} == {"not-evaluated"}


@pytest.mark.parametrize("missing_field", ["inputs", "cargo_packages"])
def test_assessment_never_claims_sparse_preview_observations(
    missing_field: str,
) -> None:
    evidence = _preview_evidence()
    if missing_field == "inputs":
        # Low-level mutation simulates a deserialized/tampered sparse model;
        # normal construction correctly rejects the orphan transformation.
        object.__setattr__(evidence, "inputs", ())
        sparse = evidence
    else:
        # The exact C6.7 binding also rejects sparse Cargo construction, so
        # model the same low-level/deserialized corruption path explicitly.
        object.__setattr__(evidence, "cargo_packages", ())
        object.__setattr__(evidence, "cargo_dependencies", ())
        sparse = evidence

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
        "transformation_inventory",
        "transformation_record_count",
        "transformation_plugin_count",
        "transformation_authority",
        "transformation_complete",
        "transformation_range",
        "transformation_output",
        "license_inventory",
        "license_record",
        "license_record_count",
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
    elif nested_model == "runtime_dependency":
        assert evidence.native_runtime_inventory is not None
        object.__setattr__(
            evidence.native_runtime_inventory.dependencies[0],
            "name",
            injected,
        )
    elif nested_model == "transformation_inventory":
        assert evidence.source_transformation_inventory is not None
        object.__setattr__(evidence.source_transformation_inventory, "scope", injected)
    elif nested_model == "transformation_record_count":
        assert evidence.source_transformation_inventory is not None
        record = evidence.source_transformation_inventory.records[0]
        object.__setattr__(
            evidence.source_transformation_inventory,
            "records",
            (record,) * (MAX_SOURCE_TRANSFORMATIONS + 1),
        )
    elif nested_model == "transformation_plugin_count":
        assert evidence.source_transformation_inventory is not None
        object.__setattr__(
            evidence.source_transformation_inventory.records[0],
            "plugin_ids",
            ("plugin",) * (MAX_SOURCE_TRANSFORMATION_PLUGIN_IDS + 1),
        )
    elif nested_model == "transformation_authority":
        assert evidence.source_transformation_inventory is not None
        object.__setattr__(evidence.source_transformation_inventory, "authority", injected)
    elif nested_model == "transformation_complete":
        assert evidence.source_transformation_inventory is not None
        object.__setattr__(evidence.source_transformation_inventory, "complete", True)
    elif nested_model == "transformation_range":
        assert evidence.source_transformation_inventory is not None
        object.__setattr__(
            evidence.source_transformation_inventory.records[0].source_range,
            "start_line",
            -1,
        )
    elif nested_model == "transformation_output":
        assert evidence.source_transformation_inventory is not None
        object.__setattr__(
            evidence.source_transformation_inventory.records[0].generated_rust,
            "logical_path",
            injected,
        )
    elif nested_model == "license_inventory":
        assert evidence.component_license_inventory is not None
        object.__setattr__(evidence.component_license_inventory, "scope", injected)
    elif nested_model == "license_record":
        assert evidence.component_license_inventory is not None
        object.__setattr__(
            evidence.component_license_inventory.records[0],
            "name",
            injected,
        )
    elif nested_model == "license_record_count":
        assert evidence.component_license_inventory is not None
        record = evidence.component_license_inventory.records[0]
        object.__setattr__(
            evidence.component_license_inventory,
            "records",
            (record,) * (MAX_COMPONENT_LICENSE_RECORDS + 1),
        )
    else:  # pragma: no cover - closed parametrization guard
        raise AssertionError(f"unexpected nested model: {nested_model}")

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
    assert [item["status"] for item in report["checks"][:6]] == ["satisfied"] * 6


def test_evaluator_is_total_for_low_level_invalid_top_level_status() -> None:
    evidence = _preview_evidence()
    object.__setattr__(evidence, "status", [])

    report = evaluate_artifact_distribution_authorization(evidence).to_dict()
    assert report["evidence_status"] == "unavailable"
    assert report["evidence_reason"] == "evidence-internal-error"
    assert report["blockers"] == ["evidence-unavailable"]
    assert report["distribution_authorized"] is False
