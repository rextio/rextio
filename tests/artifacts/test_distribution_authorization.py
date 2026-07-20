"""Focused tests for the C6.5 hard-authorization readiness contract."""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import FrozenInstanceError, replace

import pytest

from rextio.artifacts.authorization import (
    ARTIFACT_AUTHORIZATION_CHECK_IDS,
    ARTIFACT_AUTHORIZATION_PREVIEW_BLOCKERS,
    ARTIFACT_AUTHORIZATION_READINESS_UNAVAILABLE,
    ARTIFACT_AUTHORIZATION_LICENSE_UNAVAILABLE,
    ARTIFACT_AUTHORIZATION_LICENSE_POLICY_VERIFICATION_UNAVAILABLE,
    ARTIFACT_AUTHORIZATION_PROJECT_SOURCE_LICENSE_POLICY_VERIFICATION_UNAVAILABLE,
    ARTIFACT_AUTHORIZATION_ANALYSIS_INPUTS_VERIFICATION_UNAVAILABLE,
    ARTIFACT_AUTHORIZATION_POLICY_COVERAGE_UNAVAILABLE,
    ARTIFACT_AUTHORIZATION_RUNTIME_CLOSURE_UNAVAILABLE,
    ARTIFACT_AUTHORIZATION_RUNTIME_PATH_RESOLUTION_UNAVAILABLE,
    ARTIFACT_AUTHORIZATION_TRANSFORMATION_UNAVAILABLE,
    ArtifactAuthorizationCheck,
    ArtifactDistributionAuthorizationAssessment,
    evaluate_artifact_distribution_authorization,
)
from rextio.artifacts.evidence import (
    CARGO_LICENSE_POLICY,
    CARGO_LICENSE_POLICY_ACKNOWLEDGEMENT,
    CARGO_LICENSE_POLICY_ACTION_SCOPES,
    CARGO_LICENSE_POLICY_LOCK_KIND,
    CARGO_LICENSE_POLICY_LOCK_SCHEMA_VERSION,
    COMPONENT_LICENSE_POLICY_VERIFICATION_SCOPE,
    PROJECT_SOURCE_LICENSE_POLICY,
    PROJECT_SOURCE_LICENSE_POLICY_ACKNOWLEDGEMENT,
    PROJECT_SOURCE_LICENSE_POLICY_ACTION_SCOPES,
    PROJECT_SOURCE_LICENSE_POLICY_LOCK_KIND,
    PROJECT_SOURCE_LICENSE_POLICY_LOCK_SCHEMA_VERSION,
    PROJECT_SOURCE_LICENSE_POLICY_VERIFICATION_SCOPE,
    MAX_EVIDENCE_COMPONENTS,
    MAX_INPUT_FILES,
    MAX_SOURCE_TRANSFORMATION_PLUGIN_IDS,
    MAX_SOURCE_TRANSFORMATIONS,
    MAX_COMPONENT_LICENSE_RECORDS,
    ArtifactEvidence,
    ARTIFACT_POLICY_COVERAGE_CLASS_IDS,
    AnalysisInputRecord,
    AnalysisInputVerification,
    CargoDepEdge,
    CargoPackageRef,
    ComponentLicenseInventory,
    ComponentLicensePolicyVerification,
    ComponentLicenseRecord,
    EvidenceFileRef,
    NativeRuntimeDependency,
    NativeRuntimeInventory,
    NativeRuntimePathResolutionInventory,
    NativeRuntimePathResolutionRecord,
    NativeRuntimeTransitiveClosureEdge,
    NativeRuntimeTransitiveClosureInventory,
    NativeRuntimeTransitiveClosureNode,
    ProjectSourceLicensePolicyVerification,
    SidecarArtifact,
    SourceTransformationInventory,
    SourceTransformationRange,
    SourceTransformationRecord,
    SourceTransformationVerification,
    ArtifactEvidenceGate,
    SOURCE_TRANSFORMATION_VERIFICATION_KIND,
    WheelEntryRef,
    canonical_json_bytes,
    analysis_input_records_digest,
    analysis_input_projections_digest,
    derive_artifact_policy_coverage_inventory,
)
from rextio.build.policy_coverage import (
    collect_artifact_policy_coverage_inventory,
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
    runtime_dependency = NativeRuntimeDependency(name="libc.so.6")
    runtime_inventory = NativeRuntimeInventory(
        format="elf",
        architecture="x86_64",
        inspector="readelf",
        subject_basename=native_entry.name,
        subject_sha256=native_entry.sha256,
        subject_size=native_entry.uncompressed_size,
        wheel_member=native_entry.name,
        wheel_member_sha256=native_entry.sha256,
        wheel_member_size=native_entry.uncompressed_size,
        dependencies=(runtime_dependency,),
    )
    path_resolution = NativeRuntimePathResolutionInventory(
        subject_wheel_member=native_entry.name,
        subject_sha256=native_entry.sha256,
        records=(
            NativeRuntimePathResolutionRecord(
                dependency_bom_ref=runtime_dependency.bom_ref(),
                dependency_name="libc.so.6",
                dependency_origin="unresolved",
                resolution="system-logical",
                mechanism="elf-system-name",
            ),
        ),
    )
    root_node = NativeRuntimeTransitiveClosureNode(
        kind="wheel-member",
        format="elf",
        name=native_entry.name,
        wheel_member=native_entry.name,
        sha256=native_entry.sha256,
        size=native_entry.uncompressed_size,
    )
    system_node = NativeRuntimeTransitiveClosureNode(
        kind="system-logical",
        format="elf",
        name="libc.so.6",
    )
    runtime_closure = NativeRuntimeTransitiveClosureInventory(
        format="elf",
        architecture="x86_64",
        subject_wheel_member=native_entry.name,
        subject_sha256=native_entry.sha256,
        subject_size=native_entry.uncompressed_size,
        root_node_ref=root_node.node_ref,
        nodes=tuple(sorted((root_node, system_node), key=lambda node: node.node_ref)),
        edges=(
            NativeRuntimeTransitiveClosureEdge(
                source_ref=root_node.node_ref,
                target_ref=system_node.node_ref,
                dependency_name=system_node.name,
                mechanism="elf-system-name",
            ),
        ),
    )
    transformation_inventory = SourceTransformationInventory(
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
    )
    transformation_verification = SourceTransformationVerification(
        source_transformation_inventory_sha256=hashlib.sha256(
            canonical_json_bytes(transformation_inventory.to_dict())
        ).hexdigest(),
        source_input_set_sha256=hashlib.sha256(
            canonical_json_bytes([source_ref.to_dict()])
        ).hexdigest(),
        module_ir_sha256="a" * 64,
        function_qualnames=("app.add",),
        source_inputs=(source_ref,),
        generated_rust=generated_rust_ref,
        regenerated_rust_sha256=generated_rust_ref.sha256,
        regenerated_rust_size=generated_rust_ref.size,
        generator_backend="rextio-core-rust-pyo3-v1",
    )
    component_license_inventory = ComponentLicenseInventory(
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
    )
    license_policy_document = {
        "schema_version": CARGO_LICENSE_POLICY_LOCK_SCHEMA_VERSION,
        "kind": CARGO_LICENSE_POLICY_LOCK_KIND,
        "scope": COMPONENT_LICENSE_POLICY_VERIFICATION_SCOPE,
        "policy": CARGO_LICENSE_POLICY,
        "component_license_inventory_sha256": hashlib.sha256(
            canonical_json_bytes(component_license_inventory.to_dict())
        ).hexdigest(),
        "registry_components": [
            record.to_dict()
            for record in component_license_inventory.records
            if record.kind == "registry"
        ],
        "attestation": {
            "attestor": "Acme Engineering",
            "attestor_kind": "organization",
            "attestor_relationship": "organization-owner",
            "decision": "allow",
            "action_scopes": list(CARGO_LICENSE_POLICY_ACTION_SCOPES),
            "acknowledgement": CARGO_LICENSE_POLICY_ACKNOWLEDGEMENT,
        },
    }
    component_license_policy_verification = ComponentLicensePolicyVerification(
        component_license_inventory_sha256=hashlib.sha256(
            canonical_json_bytes(component_license_inventory.to_dict())
        ).hexdigest(),
        lock_file=EvidenceFileRef(
            logical_path="rextio.cargo-license.lock.json",
            sha256="b" * 64,
            size=1,
            role="cargo-license-policy-lock",
        ),
        policy_snapshot_sha256=hashlib.sha256(
            canonical_json_bytes(license_policy_document)
        ).hexdigest(),
        registry_component_bom_refs=(registry_package.bom_ref(),),
        attestor="Acme Engineering",
        attestor_kind="organization",
        attestor_relationship="organization-owner",
    )
    transformation_verification_digest = hashlib.sha256(
        canonical_json_bytes(transformation_verification.to_dict())
    ).hexdigest()
    project_source_license_policy_document = {
        "schema_version": PROJECT_SOURCE_LICENSE_POLICY_LOCK_SCHEMA_VERSION,
        "kind": PROJECT_SOURCE_LICENSE_POLICY_LOCK_KIND,
        "scope": PROJECT_SOURCE_LICENSE_POLICY_VERIFICATION_SCOPE,
        "policy": PROJECT_SOURCE_LICENSE_POLICY,
        "source_transformation_verification_sha256": (transformation_verification_digest),
        "source_input_set_sha256": transformation_verification.source_input_set_sha256,
        "project_sources": [source_ref.to_dict()],
        "generated_rust": generated_rust_ref.to_dict(),
        "license_declarations": {
            "project_sources": "MIT",
            "generated_rust": "MIT",
        },
        "attestation": {
            "attestor": "Acme Engineering",
            "attestor_kind": "organization",
            "attestor_relationship": "organization-owner",
            "decision": "allow",
            "action_scopes": list(PROJECT_SOURCE_LICENSE_POLICY_ACTION_SCOPES),
            "acknowledgement": PROJECT_SOURCE_LICENSE_POLICY_ACKNOWLEDGEMENT,
        },
    }
    project_source_license_policy_verification = ProjectSourceLicensePolicyVerification(
        source_transformation_verification_sha256=(transformation_verification_digest),
        source_input_set_sha256=(transformation_verification.source_input_set_sha256),
        source_inputs=(source_ref,),
        generated_rust=generated_rust_ref,
        lock_file=EvidenceFileRef(
            logical_path="rextio.source-license.lock.json",
            sha256="c" * 64,
            size=1,
            role="project-source-license-policy-lock",
        ),
        policy_snapshot_sha256=hashlib.sha256(
            canonical_json_bytes(project_source_license_policy_document)
        ).hexdigest(),
        project_source_license_declared="MIT",
        generated_rust_license_declared="MIT",
        attestor="Acme Engineering",
        attestor_kind="organization",
        attestor_relationship="organization-owner",
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
        native_runtime_inventory=runtime_inventory,
        native_runtime_path_resolution=path_resolution,
        native_runtime_transitive_closure=runtime_closure,
        source_transformation_inventory=transformation_inventory,
        source_transformation_verification=transformation_verification,
        component_license_inventory=component_license_inventory,
        component_license_policy_verification=(component_license_policy_verification),
        project_source_license_policy_verification=(project_source_license_policy_verification),
    )


def _preview_evidence_with_c613(*, stub_present: bool = False) -> ArtifactEvidence:
    evidence = _preview_evidence()
    verification = evidence.source_transformation_verification
    assert verification is not None
    records = (
        AnalysisInputRecord(
            "app.py",
            "app.pyi",
            "present" if stub_present else "absent",
            stub=(
                EvidenceFileRef("app.pyi", "d" * 64, 1, "project-python-stub")
                if stub_present
                else None
            ),
            supported_signature_projection_version=1 if stub_present else None,
            supported_signature_projection_sha256=("e" * 64 if stub_present else None),
        ),
    )
    analysis_inputs = AnalysisInputVerification(
        source_transformation_verification_sha256=hashlib.sha256(
            canonical_json_bytes(verification.to_dict())
        ).hexdigest(),
        source_input_set_sha256=verification.source_input_set_sha256,
        source_paths=("app.py",),
        records=records,
        analysis_input_set_sha256=analysis_input_records_digest(records, 1),
        supported_signature_projection_set_sha256=(analysis_input_projections_digest(records, 1)),
    )
    return replace(evidence, analysis_input_verification=analysis_inputs)


def _preview_evidence_with_c614(*, stub_present: bool = False) -> ArtifactEvidence:
    evidence = _preview_evidence_with_c613(stub_present=stub_present)
    assert evidence.subject is not None
    assert evidence.native_runtime_inventory is not None
    assert evidence.native_runtime_path_resolution is not None
    assert evidence.native_runtime_transitive_closure is not None
    assert evidence.source_transformation_inventory is not None
    assert evidence.source_transformation_verification is not None
    assert evidence.analysis_input_verification is not None
    assert evidence.component_license_inventory is not None
    assert evidence.component_license_policy_verification is not None
    assert evidence.project_source_license_policy_verification is not None
    coverage = derive_artifact_policy_coverage_inventory(
        target_triple=evidence.target_triple or "",
        subject=evidence.subject,
        inputs=evidence.inputs,
        wheel_entries=evidence.wheel_entries,
        cargo_packages=evidence.cargo_packages,
        native_runtime_inventory=evidence.native_runtime_inventory,
        native_runtime_path_resolution=evidence.native_runtime_path_resolution,
        native_runtime_transitive_closure=(evidence.native_runtime_transitive_closure),
        source_transformation_inventory=evidence.source_transformation_inventory,
        source_transformation_verification=(evidence.source_transformation_verification),
        analysis_input_verification=evidence.analysis_input_verification,
        component_license_inventory=evidence.component_license_inventory,
        component_license_policy_verification=(evidence.component_license_policy_verification),
        project_source_license_policy_verification=(
            evidence.project_source_license_policy_verification
        ),
    )
    return replace(evidence, artifact_policy_coverage_inventory=coverage)


def _collect_c614(evidence: ArtifactEvidence):
    return collect_artifact_policy_coverage_inventory(
        target_triple=evidence.target_triple or "",
        subject=evidence.subject,  # type: ignore[arg-type]
        inputs=evidence.inputs,
        wheel_entries=evidence.wheel_entries,
        cargo_packages=evidence.cargo_packages,
        native_runtime_inventory=evidence.native_runtime_inventory,
        native_runtime_path_resolution=evidence.native_runtime_path_resolution,
        native_runtime_transitive_closure=(evidence.native_runtime_transitive_closure),
        source_transformation_inventory=evidence.source_transformation_inventory,
        source_transformation_verification=(evidence.source_transformation_verification),
        analysis_input_verification=evidence.analysis_input_verification,
        component_license_inventory=evidence.component_license_inventory,
        component_license_policy_verification=(evidence.component_license_policy_verification),
        project_source_license_policy_verification=(
            evidence.project_source_license_policy_verification
        ),
    )


def test_preview_ready_assessment_is_canonical_and_always_blocked() -> None:
    assessment = ArtifactDistributionAuthorizationAssessment.from_evidence(_preview_evidence())
    report = assessment.to_dict()

    assert report["kind"] == "artifact-distribution-authorization"
    assert report["policy"] == "host-extension-wheel-cpython-v1"
    assert report["policy_version"] == 10
    assert report["scope"] == "host-extension-wheel-cpython-v1"
    assert report["status"] == "blocked"
    assert report["authority"] == "readiness-assessment-only"
    assert report["evidence_status"] == "preview-ready"
    assert report["evidence_reason"] is None
    assert [item["id"] for item in report["checks"]] == list(ARTIFACT_AUTHORIZATION_CHECK_IDS)
    assert [item["status"] for item in report["checks"][:13]] == [
        "satisfied",
        "satisfied",
        "satisfied",
        "satisfied",
        "satisfied",
        "satisfied",
        "satisfied",
        "satisfied",
        "satisfied",
        "satisfied",
        "satisfied",
        "unavailable",
        "unavailable",
    ]
    assert {item["status"] for item in report["checks"][13:]} == {"blocked"}
    assert report["blockers"] == [
        *ARTIFACT_AUTHORIZATION_PREVIEW_BLOCKERS,
        ARTIFACT_AUTHORIZATION_ANALYSIS_INPUTS_VERIFICATION_UNAVAILABLE,
        ARTIFACT_AUTHORIZATION_POLICY_COVERAGE_UNAVAILABLE,
    ]
    assert report["complete"] is False
    assert report["signed"] is False
    assert report["distribution_authorized"] is False


def test_valid_c613_is_the_twelfth_observation_only() -> None:
    report = evaluate_artifact_distribution_authorization(_preview_evidence_with_c613()).to_dict()
    statuses = {item["id"]: item["status"] for item in report["checks"]}

    assert len(report["checks"]) == 23
    assert statuses["scoped-analysis-inputs-verified"] == "satisfied"
    assert all(
        statuses[check_id] == "blocked"
        for check_id in (
            "build-input-closure-complete",
            "reproducibility-verified",
            "attestation-signed",
            "component-license-policy-complete",
            "sbom-composition-complete",
        )
    )
    assert report["blockers"] == [
        *ARTIFACT_AUTHORIZATION_PREVIEW_BLOCKERS,
        ARTIFACT_AUTHORIZATION_POLICY_COVERAGE_UNAVAILABLE,
    ]
    assert report["complete"] is False
    assert report["signed"] is False
    assert report["distribution_authorized"] is False


def test_valid_c614_is_deterministic_disjoint_and_non_authorizing() -> None:
    evidence = _preview_evidence_with_c614()
    coverage = evidence.artifact_policy_coverage_inventory
    assert coverage is not None
    assert tuple(item.class_id for item in coverage.classes) == (ARTIFACT_POLICY_COVERAGE_CLASS_IDS)
    rows = {item.class_id: item for item in coverage.classes}
    assert rows["file-input:project-python-source"].license_policy_state == (
        "scoped-owner-declaration-bound"
    )
    assert (
        rows["file-input:project-python-source"].transformation_provenance_state
        == "scoped-replay-input-bound"
    )
    assert rows["file-input:generated-rust-lib"].transformation_provenance_state == (
        "scoped-replay-output-verified"
    )
    assert rows["cargo-component:registry-package"].identity_state == ("declared-checksum-bound")
    assert rows["native-runtime:logical-system-leaf"].identity_state == ("logical-only")
    assert rows["wheel-entry:packaged-native-runtime-member"].observed_count == 1
    assert rows["wheel-entry:other"].observed_count == 0
    assert rows["file-input:present-project-python-stub"].observed_count == 0
    assert coverage.scope_complete is False
    assert coverage.global_license_policy_complete is False
    assert coverage.global_transformation_provenance_complete is False
    assert coverage.complete is False
    assert coverage.signed is False
    assert coverage.distribution_authorized is False
    assert _preview_evidence_with_c614().artifact_policy_coverage_inventory == coverage
    present = _preview_evidence_with_c614(stub_present=True)
    present_coverage = present.artifact_policy_coverage_inventory
    assert present_coverage is not None
    present_rows = {item.class_id: item for item in present_coverage.classes}
    assert present_rows["file-input:present-project-python-stub"].observed_count == 1
    assert present_coverage.canonical_partition_sha256 != (coverage.canonical_partition_sha256)

    report = evaluate_artifact_distribution_authorization(evidence).to_dict()
    statuses = {item["id"]: item["status"] for item in report["checks"]}
    assert report["policy_version"] == 10
    assert statuses["artifact-policy-coverage-bound"] == "satisfied"
    assert all(
        statuses[check_id] == "blocked"
        for check_id in (
            "component-license-policy-complete",
            "build-input-closure-complete",
            "source-transformation-provenance-complete",
            "attestation-signed",
            "sbom-composition-complete",
        )
    )
    assert report["complete"] is False
    assert report["signed"] is False
    assert report["distribution_authorized"] is False


def test_c614_missing_or_forged_prerequisite_fails_closed() -> None:
    evidence = _preview_evidence_with_c614()
    coverage = copy.deepcopy(evidence.artifact_policy_coverage_inventory)
    assert coverage is not None
    object.__setattr__(coverage.classes[0], "observed_count", 999)
    object.__setattr__(evidence, "artifact_policy_coverage_inventory", coverage)
    report = evaluate_artifact_distribution_authorization(evidence).to_dict()
    assert {item["status"] for item in report["checks"]} == {"not-evaluated"}
    assert report["blockers"] == [ARTIFACT_AUTHORIZATION_READINESS_UNAVAILABLE]

    missing = _preview_evidence_with_c613()
    missing_report = evaluate_artifact_distribution_authorization(missing).to_dict()
    missing_statuses = {item["id"]: item["status"] for item in missing_report["checks"]}
    assert missing_statuses["artifact-policy-coverage-bound"] == "unavailable"
    assert ARTIFACT_AUTHORIZATION_POLICY_COVERAGE_UNAVAILABLE in missing_report["blockers"]


def test_c614_domain_digests_and_dimension_receipts_are_unambiguous() -> None:
    coverage = _preview_evidence_with_c614().artifact_policy_coverage_inventory
    assert coverage is not None
    empty_rows = [item for item in coverage.classes if item.observed_count == 0]
    assert len(empty_rows) >= 2
    assert len({item.canonical_identity_set_sha256 for item in empty_rows}) == len(empty_rows)
    source_row = next(
        item for item in coverage.classes if item.class_id == "file-input:project-python-source"
    )
    with pytest.raises(ValueError, match="license policy receipt kind"):
        replace(
            source_row,
            license_policy_receipt_kind=SOURCE_TRANSFORMATION_VERIFICATION_KIND,
        )
    with pytest.raises(ValueError, match="class semantics"):
        replace(source_row, transformation_provenance_state="not-applicable")


@pytest.mark.parametrize("forgery", ["c610", "c611", "c69", "oversized"])
def test_c614_collector_omits_forged_nested_prerequisites(forgery: str) -> None:
    evidence = _preview_evidence_with_c614()
    if forgery == "c610":
        inventory = copy.deepcopy(evidence.source_transformation_inventory)
        assert inventory is not None
        object.__setattr__(inventory.records[0], "semantic_ast_sha256", "bad")
        object.__setattr__(evidence, "source_transformation_inventory", inventory)
    elif forgery == "c611":
        receipt = copy.deepcopy(evidence.component_license_policy_verification)
        assert receipt is not None
        object.__setattr__(receipt.lock_file, "sha256", "bad")
        object.__setattr__(evidence, "component_license_policy_verification", receipt)
    elif forgery == "c69":
        closure = copy.deepcopy(evidence.native_runtime_transitive_closure)
        assert closure is not None
        node = next(item for item in closure.nodes if item.kind == "wheel-member")
        object.__setattr__(node, "size", True)
        object.__setattr__(evidence, "native_runtime_transitive_closure", closure)
    else:
        inventory = copy.deepcopy(evidence.source_transformation_inventory)
        assert inventory is not None
        object.__setattr__(
            inventory,
            "records",
            inventory.records * (MAX_SOURCE_TRANSFORMATIONS + 1),
        )
        object.__setattr__(evidence, "source_transformation_inventory", inventory)
    assert _collect_c614(evidence) is None


def test_c614_collector_rejects_cross_role_and_wheel_aliases() -> None:
    evidence = _preview_evidence_with_c613()
    aliased_input = EvidenceFileRef("APP.py", "f" * 64, 1, "generated-python-input")
    object.__setattr__(evidence, "inputs", (*evidence.inputs, aliased_input))
    assert _collect_c614(evidence) is None

    wheel_alias = _preview_evidence_with_c613()
    object.__setattr__(
        wheel_alias,
        "wheel_entries",
        (
            *wheel_alias.wheel_entries,
            WheelEntryRef("_REXTIO_NATIVE.SO", "f" * 64, 1, 1),
        ),
    )
    assert _collect_c614(wheel_alias) is None


@pytest.mark.parametrize(
    "mutation",
    [
        lambda receipt: object.__setattr__(receipt, "analysis_input_set_sha256", "0" * 64),
        lambda receipt: object.__setattr__(receipt, "source_paths", ("app.py", "other.py")),
        lambda receipt: object.__setattr__(receipt, "records", [receipt.records[0]]),
    ],
)
def test_forged_c613_receipts_are_not_evaluated(mutation) -> None:
    evidence = _preview_evidence_with_c613()
    receipt = copy.deepcopy(evidence.analysis_input_verification)
    assert receipt is not None
    mutation(receipt)
    object.__setattr__(evidence, "analysis_input_verification", receipt)

    report = evaluate_artifact_distribution_authorization(evidence).to_dict()
    assert len(report["checks"]) == 23
    assert {item["status"] for item in report["checks"]} == {"not-evaluated"}
    assert report["blockers"] == [ARTIFACT_AUTHORIZATION_READINESS_UNAVAILABLE]


def test_unavailable_assessment_does_not_speculate_or_leak_free_text() -> None:
    assessment = ArtifactDistributionAuthorizationAssessment.from_evidence(
        ArtifactEvidence.unavailable(reason="cargo-metadata-failed")
    )
    report = assessment.to_dict()

    assert report["evidence_status"] == "unavailable"
    assert report["evidence_reason"] == "cargo-metadata-failed"
    assert [item["status"] for item in report["checks"][:13]] == [
        "unavailable",
        "unavailable",
        "unavailable",
        "unavailable",
        "unavailable",
        "unavailable",
        "unavailable",
        "unavailable",
        "unavailable",
        "unavailable",
        "unavailable",
        "unavailable",
        "unavailable",
    ]
    assert {item["status"] for item in report["checks"][13:]} == {"not-evaluated"}
    assert report["blockers"] == ["evidence-unavailable"]
    assert "/" not in json.dumps(report, sort_keys=True)


def test_missing_transformation_inventory_is_a_dedicated_closed_observation() -> None:
    evidence = replace(
        _preview_evidence(),
        source_transformation_inventory=None,
        source_transformation_verification=None,
        project_source_license_policy_verification=None,
    )
    report = evaluate_artifact_distribution_authorization(evidence).to_dict()
    statuses = {item["id"]: item["status"] for item in report["checks"]}

    assert statuses["artifact-subject-bound"] == "satisfied"
    assert statuses["direct-native-linkage-observed"] == "satisfied"
    assert statuses["source-transformation-inventory-bound"] == "unavailable"
    assert statuses["source-transformation-provenance-complete"] == "blocked"
    assert report["blockers"] == [
        *ARTIFACT_AUTHORIZATION_PREVIEW_BLOCKERS,
        ARTIFACT_AUTHORIZATION_TRANSFORMATION_UNAVAILABLE,
        "scoped-source-transformation-verification-unavailable",
        ARTIFACT_AUTHORIZATION_PROJECT_SOURCE_LICENSE_POLICY_VERIFICATION_UNAVAILABLE,
        ARTIFACT_AUTHORIZATION_ANALYSIS_INPUTS_VERIFICATION_UNAVAILABLE,
        ARTIFACT_AUTHORIZATION_POLICY_COVERAGE_UNAVAILABLE,
    ]
    assert ARTIFACT_AUTHORIZATION_READINESS_UNAVAILABLE not in report["blockers"]
    # C6.3 evaluates the existing preview evidence independently.
    assert ArtifactEvidenceGate.from_evidence(evidence).status == "satisfied"


def test_missing_scoped_verification_is_a_dedicated_unavailable_observation() -> None:
    evidence = replace(
        _preview_evidence(),
        source_transformation_verification=None,
        project_source_license_policy_verification=None,
    )
    report = evaluate_artifact_distribution_authorization(evidence).to_dict()
    statuses = {item["id"]: item["status"] for item in report["checks"]}

    assert report["policy_version"] == 10
    assert statuses["source-transformation-inventory-bound"] == "satisfied"
    assert statuses["scoped-source-transformation-verified"] == "unavailable"
    assert statuses["source-transformation-provenance-complete"] == "blocked"
    assert "scoped-source-transformation-verification-unavailable" in report["blockers"]
    assert (
        ARTIFACT_AUTHORIZATION_PROJECT_SOURCE_LICENSE_POLICY_VERIFICATION_UNAVAILABLE
        in report["blockers"]
    )
    assert ArtifactEvidenceGate.from_evidence(evidence).status == "satisfied"


def test_missing_runtime_path_resolution_is_a_dedicated_closed_observation() -> None:
    evidence = replace(
        _preview_evidence(),
        native_runtime_path_resolution=None,
        native_runtime_transitive_closure=None,
    )
    report = evaluate_artifact_distribution_authorization(evidence).to_dict()
    statuses = {item["id"]: item["status"] for item in report["checks"]}

    assert statuses["direct-native-linkage-observed"] == "satisfied"
    assert statuses["direct-native-path-resolution-bound"] == "unavailable"
    assert statuses["bounded-static-native-runtime-graph-bound"] == "unavailable"
    assert statuses["native-runtime-resolution-complete"] == "blocked"
    assert report["blockers"] == [
        *ARTIFACT_AUTHORIZATION_PREVIEW_BLOCKERS,
        ARTIFACT_AUTHORIZATION_RUNTIME_PATH_RESOLUTION_UNAVAILABLE,
        ARTIFACT_AUTHORIZATION_RUNTIME_CLOSURE_UNAVAILABLE,
        ARTIFACT_AUTHORIZATION_ANALYSIS_INPUTS_VERIFICATION_UNAVAILABLE,
        ARTIFACT_AUTHORIZATION_POLICY_COVERAGE_UNAVAILABLE,
    ]
    assert ArtifactEvidenceGate.from_evidence(evidence).status == "satisfied"


def test_missing_bounded_runtime_graph_retains_direct_path_observation() -> None:
    evidence = replace(_preview_evidence(), native_runtime_transitive_closure=None)
    report = evaluate_artifact_distribution_authorization(evidence).to_dict()
    statuses = {item["id"]: item["status"] for item in report["checks"]}

    assert statuses["direct-native-path-resolution-bound"] == "satisfied"
    assert statuses["bounded-static-native-runtime-graph-bound"] == "unavailable"
    assert statuses["native-runtime-transitive-closure-complete"] == "blocked"
    assert report["blockers"] == [
        *ARTIFACT_AUTHORIZATION_PREVIEW_BLOCKERS,
        ARTIFACT_AUTHORIZATION_RUNTIME_CLOSURE_UNAVAILABLE,
        ARTIFACT_AUTHORIZATION_ANALYSIS_INPUTS_VERIFICATION_UNAVAILABLE,
        ARTIFACT_AUTHORIZATION_POLICY_COVERAGE_UNAVAILABLE,
    ]


def test_missing_license_inventory_is_a_dedicated_closed_observation() -> None:
    evidence = replace(
        _preview_evidence(),
        component_license_inventory=None,
        component_license_policy_verification=None,
    )
    report = evaluate_artifact_distribution_authorization(evidence).to_dict()
    statuses = {item["id"]: item["status"] for item in report["checks"]}

    assert statuses["source-transformation-inventory-bound"] == "satisfied"
    assert statuses["component-license-inventory-bound"] == "unavailable"
    assert statuses["scoped-component-license-policy-verified"] == "unavailable"
    assert statuses["component-license-policy-complete"] == "blocked"
    assert report["blockers"] == [
        *ARTIFACT_AUTHORIZATION_PREVIEW_BLOCKERS,
        ARTIFACT_AUTHORIZATION_LICENSE_UNAVAILABLE,
        ARTIFACT_AUTHORIZATION_LICENSE_POLICY_VERIFICATION_UNAVAILABLE,
        ARTIFACT_AUTHORIZATION_ANALYSIS_INPUTS_VERIFICATION_UNAVAILABLE,
        ARTIFACT_AUTHORIZATION_POLICY_COVERAGE_UNAVAILABLE,
    ]
    assert ArtifactEvidenceGate.from_evidence(evidence).status == "satisfied"


def test_missing_scoped_license_policy_receipt_is_dedicated_and_non_authorizing() -> None:
    evidence = replace(
        _preview_evidence(),
        component_license_policy_verification=None,
    )
    report = evaluate_artifact_distribution_authorization(evidence).to_dict()
    statuses = {item["id"]: item["status"] for item in report["checks"]}

    assert statuses["component-license-inventory-bound"] == "satisfied"
    assert statuses["scoped-component-license-policy-verified"] == "unavailable"
    assert statuses["component-license-policy-complete"] == "blocked"
    assert report["blockers"] == [
        *ARTIFACT_AUTHORIZATION_PREVIEW_BLOCKERS,
        ARTIFACT_AUTHORIZATION_LICENSE_POLICY_VERIFICATION_UNAVAILABLE,
        ARTIFACT_AUTHORIZATION_ANALYSIS_INPUTS_VERIFICATION_UNAVAILABLE,
        ARTIFACT_AUTHORIZATION_POLICY_COVERAGE_UNAVAILABLE,
    ]
    assert report["complete"] is False
    assert report["signed"] is False
    assert report["distribution_authorized"] is False
    assert ArtifactEvidenceGate.from_evidence(evidence).status == "satisfied"


def test_missing_project_source_license_policy_receipt_is_scoped_only() -> None:
    evidence = replace(
        _preview_evidence(),
        project_source_license_policy_verification=None,
    )
    report = evaluate_artifact_distribution_authorization(evidence).to_dict()
    statuses = {item["id"]: item["status"] for item in report["checks"]}

    assert statuses["scoped-source-transformation-verified"] == "satisfied"
    assert statuses["scoped-project-source-license-policy-verified"] == "unavailable"
    assert statuses["component-license-policy-complete"] == "blocked"
    assert statuses["source-transformation-provenance-complete"] == "blocked"
    assert report["blockers"] == [
        *ARTIFACT_AUTHORIZATION_PREVIEW_BLOCKERS,
        ARTIFACT_AUTHORIZATION_PROJECT_SOURCE_LICENSE_POLICY_VERIFICATION_UNAVAILABLE,
        ARTIFACT_AUTHORIZATION_ANALYSIS_INPUTS_VERIFICATION_UNAVAILABLE,
        ARTIFACT_AUTHORIZATION_POLICY_COVERAGE_UNAVAILABLE,
    ]
    assert report["complete"] is False
    assert report["signed"] is False
    assert report["distribution_authorized"] is False


def test_artifact_evidence_rejects_low_level_mutated_c6_12_receipt() -> None:
    evidence = _preview_evidence()
    receipt = copy.deepcopy(evidence.project_source_license_policy_verification)
    assert receipt is not None
    object.__setattr__(
        receipt,
        "project_source_license_declared",
        "Apache-2.0",
    )

    with pytest.raises(ValueError, match="snapshot digest differs"):
        replace(
            evidence,
            project_source_license_policy_verification=receipt,
        )


def test_source_transformation_schema_versions_reject_boolean_type_confusion() -> None:
    evidence = _preview_evidence()
    assert evidence.source_transformation_inventory is not None
    assert evidence.source_transformation_verification is not None

    with pytest.raises(TypeError, match="inventory schema must be an integer"):
        replace(evidence.source_transformation_inventory, schema_version=True)
    with pytest.raises(TypeError, match="verification schema must be an integer"):
        replace(evidence.source_transformation_verification, schema_version=True)


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
        source_transformation_verification=None,
        project_source_license_policy_verification=None,
    )

    report = evaluate_artifact_distribution_authorization(adjusted).to_dict()
    statuses = {item["id"]: item["status"] for item in report["checks"]}
    assert statuses["source-transformation-inventory-bound"] == "satisfied"
    assert statuses["scoped-source-transformation-verified"] == "unavailable"
    assert statuses["source-transformation-provenance-complete"] == "blocked"
    assert report["status"] == "blocked"
    assert report["signed"] is False
    assert report["distribution_authorized"] is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_transformation_inventory_sha256", "0" * 64),
        ("source_input_set_sha256", "0" * 64),
        ("function_qualnames", ("app.other",)),
        ("regenerated_rust_sha256", "0" * 64),
        ("complete_for_scope", False),
    ],
)
def test_tampered_scoped_verification_never_yields_satisfied_observation(
    field: str,
    value: object,
) -> None:
    evidence = _preview_evidence()
    verification = evidence.source_transformation_verification
    assert verification is not None
    object.__setattr__(verification, field, value)

    report = evaluate_artifact_distribution_authorization(evidence).to_dict()

    assert report["blockers"] == [ARTIFACT_AUTHORIZATION_READINESS_UNAVAILABLE]
    assert {item["status"] for item in report["checks"]} == {"not-evaluated"}
    assert report["distribution_authorized"] is False


def test_assessment_is_immutable_and_truthy_authority_fields_are_forced_false() -> None:
    assessment = ArtifactDistributionAuthorizationAssessment.from_evidence(_preview_evidence())

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
    assessment = ArtifactDistributionAuthorizationAssessment.from_evidence(_preview_evidence())

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
        "cargo_feature_count",
        "cargo_edge",
        "runtime_inventory",
        "runtime_architecture",
        "runtime_dependency",
        "runtime_path_inventory",
        "runtime_path_subject",
        "runtime_path_record",
        "runtime_path_mechanism",
        "transformation_inventory",
        "transformation_inventory_schema",
        "transformation_record_count",
        "transformation_plugin_count",
        "transformation_authority",
        "transformation_complete",
        "transformation_range",
        "transformation_output",
        "transformation_verification_schema",
        "license_inventory",
        "license_record",
        "license_record_count",
        "license_policy_verification",
        "license_policy_lock",
        "license_policy_refs",
        "license_policy_collections",
        "license_policy_authority",
        "project_source_license_policy_verification",
        "project_source_license_policy_lock",
        "project_source_license_policy_inputs",
        "project_source_license_policy_input_count",
        "project_source_license_policy_scopes",
        "project_source_license_policy_authority",
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
    elif nested_model == "cargo_feature_count":
        object.__setattr__(
            evidence.cargo_packages[1],
            "features",
            ("feature",) * (MAX_EVIDENCE_COMPONENTS + 1),
        )
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
    elif nested_model == "runtime_path_inventory":
        assert evidence.native_runtime_path_resolution is not None
        object.__setattr__(evidence.native_runtime_path_resolution, "scope", injected)
    elif nested_model == "runtime_path_subject":
        assert evidence.native_runtime_path_resolution is not None
        object.__setattr__(
            evidence.native_runtime_path_resolution,
            "subject_wheel_member",
            injected,
        )
    elif nested_model == "runtime_path_record":
        assert evidence.native_runtime_path_resolution is not None
        object.__setattr__(
            evidence.native_runtime_path_resolution.records[0],
            "dependency_name",
            injected,
        )
    elif nested_model == "runtime_path_mechanism":
        assert evidence.native_runtime_path_resolution is not None
        object.__setattr__(
            evidence.native_runtime_path_resolution.records[0],
            "mechanism",
            "macho-system",
        )
    elif nested_model == "transformation_inventory":
        assert evidence.source_transformation_inventory is not None
        object.__setattr__(evidence.source_transformation_inventory, "scope", injected)
    elif nested_model == "transformation_inventory_schema":
        assert evidence.source_transformation_inventory is not None
        object.__setattr__(evidence.source_transformation_inventory, "schema_version", True)
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
    elif nested_model == "transformation_verification_schema":
        assert evidence.source_transformation_verification is not None
        object.__setattr__(
            evidence.source_transformation_verification,
            "schema_version",
            True,
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
    elif nested_model == "license_policy_verification":
        assert evidence.component_license_policy_verification is not None
        object.__setattr__(
            evidence.component_license_policy_verification,
            "policy_snapshot_sha256",
            "not-a-digest",
        )
    elif nested_model == "license_policy_lock":
        assert evidence.component_license_policy_verification is not None
        object.__setattr__(
            evidence.component_license_policy_verification.lock_file,
            "logical_path",
            injected,
        )
    elif nested_model == "license_policy_refs":
        assert evidence.component_license_policy_verification is not None
        object.__setattr__(
            evidence.component_license_policy_verification,
            "registry_component_bom_refs",
            ("urn:rextio:cargo:00000000000000000000000000000000",),
        )
    elif nested_model == "license_policy_collections":
        assert evidence.component_license_policy_verification is not None
        object.__setattr__(
            evidence.component_license_policy_verification,
            "registry_component_bom_refs",
            list(evidence.component_license_policy_verification.registry_component_bom_refs),
        )
    elif nested_model == "license_policy_authority":
        assert evidence.component_license_policy_verification is not None
        object.__setattr__(
            evidence.component_license_policy_verification,
            "authority",
            injected,
        )
    elif nested_model == "project_source_license_policy_verification":
        assert evidence.project_source_license_policy_verification is not None
        object.__setattr__(
            evidence.project_source_license_policy_verification,
            "policy_snapshot_sha256",
            "not-a-digest",
        )
    elif nested_model == "project_source_license_policy_lock":
        assert evidence.project_source_license_policy_verification is not None
        object.__setattr__(
            evidence.project_source_license_policy_verification.lock_file,
            "logical_path",
            injected,
        )
    elif nested_model == "project_source_license_policy_inputs":
        assert evidence.project_source_license_policy_verification is not None
        object.__setattr__(
            evidence.project_source_license_policy_verification,
            "source_inputs",
            list(evidence.project_source_license_policy_verification.source_inputs),
        )
    elif nested_model == "project_source_license_policy_input_count":
        assert evidence.project_source_license_policy_verification is not None
        source_input = evidence.project_source_license_policy_verification.source_inputs[0]
        object.__setattr__(
            evidence.project_source_license_policy_verification,
            "source_inputs",
            (source_input,) * (MAX_INPUT_FILES + 1),
        )
    elif nested_model == "project_source_license_policy_scopes":
        assert evidence.project_source_license_policy_verification is not None
        object.__setattr__(
            evidence.project_source_license_policy_verification,
            "action_scopes",
            list(evidence.project_source_license_policy_verification.action_scopes),
        )
    elif nested_model == "project_source_license_policy_authority":
        assert evidence.project_source_license_policy_verification is not None
        object.__setattr__(
            evidence.project_source_license_policy_verification,
            "authority",
            injected,
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
        native_runtime_transitive_closure=replace(
            evidence.native_runtime_transitive_closure,
            architecture=architecture,
        ),
    )

    report = evaluate_artifact_distribution_authorization(adjusted).to_dict()
    assert [item["status"] for item in report["checks"][:8]] == ["satisfied"] * 8


def test_evaluator_is_total_for_low_level_invalid_top_level_status() -> None:
    evidence = _preview_evidence()
    object.__setattr__(evidence, "status", [])

    report = evaluate_artifact_distribution_authorization(evidence).to_dict()
    assert report["evidence_status"] == "unavailable"
    assert report["evidence_reason"] == "evidence-internal-error"
    assert report["blockers"] == ["evidence-unavailable"]
    assert report["distribution_authorized"] is False
