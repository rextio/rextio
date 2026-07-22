"""Focused adversarial tests for the strict final Full C6 policy receipt."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import json

import pytest

import rextio.build.full_c6_policy as policy_module
from rextio.artifacts.evidence import (
    ANALYSIS_INPUT_VERIFICATION_KIND,
    ARTIFACT_POLICY_COVERAGE_CLASS_IDS,
    COMPONENT_LICENSE_POLICY_VERIFICATION_KIND,
    PROJECT_SOURCE_LICENSE_POLICY_VERIFICATION_KIND,
    SOURCE_TRANSFORMATION_VERIFICATION_KIND,
    ArtifactPolicyCoverageClass,
    ArtifactPolicyCoverageInventory,
    artifact_policy_identity_set_digest,
    artifact_policy_partition_digest,
)
from rextio.artifacts.full_authorization import FULL_C6_SCOPE
from rextio.build.full_c6_policy import (
    FULL_C6_ANALYSIS_RECEIPT_KIND,
    FULL_C6_EXTERNAL_POLICY_CLASS_IDS,
    FULL_C6_LOWERED_IR_RECEIPT_KIND,
    FULL_C6_OWNER_ACKNOWLEDGEMENT,
    FULL_C6_OWNER_ACTION_SCOPES,
    FULL_C6_OWNER_AUTHENTICATION,
    FULL_C6_POLICY_CLASS_IDS,
    FullC6ExternalAuthorityClass,
    FullC6ExternalAuthorityPartition,
    FullC6LicenseEvidence,
    FullC6OwnerDeclaration,
    FullC6PolicyError,
    FullC6PolicyFileIdentity,
    FullC6PolicyInputRow,
    FullC6PolicyReceipt,
    FullC6TransformationRecord,
    full_c6_analysis_receipt_digest,
    full_c6_authority_partition_digest,
    full_c6_external_authority_identity,
    full_c6_external_authority_identity_set_digest,
    full_c6_external_authority_partition_digest,
    full_c6_lowered_ir_receipt_digest,
    full_c6_policy_digest,
    full_c6_transformation_source_set_digest,
)


_NA_LICENSE = {
    "file-input:generated-cargo-lock": "not-applicable-build-input",
    "native-runtime:logical-system-leaf": "not-applicable-system-leaf",
    "file-input:policy-lock": "not-applicable-build-input",
}
_SOURCES = {
    "file-input:project-python-source",
    "file-input:present-project-python-stub",
    "external-source:python-source",
}
_OUTPUTS = {
    "file-input:generated-python-input",
    "file-input:generated-rust-lib",
    "file-input:generated-rust-build-input",
}
_CONTENT = set(FULL_C6_POLICY_CLASS_IDS) - {
    "cargo-component:registry-package",
    "cargo-component:path-root-package",
    "native-runtime:logical-system-leaf",
}
_IDENTITIES = {
    "file-input:project-python-source": "project/src/app.py",
    "file-input:present-project-python-stub": "project/src/app.pyi",
    "file-input:generated-python-input": "generated/python/wrapper.py",
    "file-input:generated-rust-lib": "generated/rust/src/lib.rs",
    "file-input:generated-rust-build-input": "generated/rust/build.rs",
    "file-input:generated-cargo-lock": "generated/rust/Cargo.lock",
    "cargo-component:registry-package": "cargo:serde@1.0.0#registry",
    "cargo-component:path-root-package": "cargo:rextio-generated@0.1.4#path-root",
    "wheel-entry:packaged-native-runtime-member": "wheel/rextio/libnative.so",
    "native-runtime:logical-system-leaf": "system:libc.so.6",
    "file-input:policy-lock": "policy/rextio.policy.lock.json",
    "wheel-output:subject": "dist/pkg-0.1.0-cp311-cp311-manylinux.whl",
    "wheel-entry:other": "wheel/pkg/__init__.py",
    "external-source:wheel-archive": "external/pkg-1.0-py3-none-any.whl",
    "external-source:python-source": "external/pkg/__init__.py",
    "external-source:distribution-metadata": "external/pkg-1.0.dist-info/METADATA",
    "external-source:license-file": "external/pkg-1.0.dist-info/licenses/LICENSE",
}
_COVERAGE_SEMANTICS = (
    (
        "byte-bound",
        "scoped-owner-declaration-bound",
        PROJECT_SOURCE_LICENSE_POLICY_VERIFICATION_KIND,
        "scoped-replay-input-bound",
        SOURCE_TRANSFORMATION_VERIFICATION_KIND,
    ),
    (
        "byte-bound",
        "unassessed",
        None,
        "scoped-analysis-input-projection-bound",
        ANALYSIS_INPUT_VERIFICATION_KIND,
    ),
    ("byte-bound", "unassessed", None, "unassessed", None),
    (
        "byte-bound",
        "scoped-owner-declaration-bound",
        PROJECT_SOURCE_LICENSE_POLICY_VERIFICATION_KIND,
        "scoped-replay-output-verified",
        SOURCE_TRANSFORMATION_VERIFICATION_KIND,
    ),
    ("byte-bound", "unassessed", None, "unassessed", None),
    ("byte-bound", "unassessed", None, "unassessed", None),
    (
        "declared-checksum-bound",
        "scoped-cargo-owner-receipt-bound",
        COMPONENT_LICENSE_POLICY_VERIFICATION_KIND,
        "not-applicable",
        None,
    ),
    ("logical-only", "unassessed", None, "not-applicable", None),
    ("byte-bound", "unassessed", None, "not-applicable", None),
    ("logical-only", "unassessed", None, "not-applicable", None),
    ("byte-bound", "unassessed", None, "unassessed", None),
    ("byte-bound", "unassessed", None, "unassessed", None),
    ("byte-bound", "unassessed", None, "unassessed", None),
)


def _artifact_identity(class_id: str, index: int = 1) -> str:
    return f"urn:rextio:artifact-component:{class_id}:{index:064x}"


def _authority_sets(
    *,
    zero_artifact: frozenset[str] = frozenset(),
    zero_external: frozenset[str] = frozenset(),
) -> tuple[dict[str, tuple[str, ...]], dict[str, tuple[str, ...]]]:
    artifact: dict[str, tuple[str, ...]] = {
        class_id: (() if class_id in zero_artifact else (_artifact_identity(class_id),))
        for class_id in ARTIFACT_POLICY_COVERAGE_CLASS_IDS
    }
    external: dict[str, tuple[str, ...]] = {
        class_id: (
            ()
            if class_id in zero_external
            else (full_c6_external_authority_identity(class_id, {"index": 1}),)
        )
        for class_id in FULL_C6_EXTERNAL_POLICY_CLASS_IDS
    }
    return artifact, external


def _coverage(identities: dict[str, tuple[str, ...]]) -> ArtifactPolicyCoverageInventory:
    classes = tuple(
        ArtifactPolicyCoverageClass(
            class_id=class_id,
            observed_count=len(identities[class_id]),
            canonical_identity_set_sha256=artifact_policy_identity_set_digest(
                class_id,
                identities[class_id],
            ),
            identity_state=identity_state,
            license_policy_state=license_state,
            license_policy_receipt_kind=license_kind,
            license_policy_receipt_sha256=("a" * 64 if license_kind else None),
            transformation_provenance_state=transformation_state,
            transformation_provenance_receipt_kind=transformation_kind,
            transformation_provenance_receipt_sha256=("b" * 64 if transformation_kind else None),
        )
        for class_id, (
            identity_state,
            license_state,
            license_kind,
            transformation_state,
            transformation_kind,
        ) in zip(
            ARTIFACT_POLICY_COVERAGE_CLASS_IDS,
            _COVERAGE_SEMANTICS,
            strict=True,
        )
    )
    return ArtifactPolicyCoverageInventory(
        classes=classes,
        observed_component_count=sum(item.observed_count for item in classes),
        canonical_partition_sha256=artifact_policy_partition_digest(classes),
    )


def _external_partition(
    identities: dict[str, tuple[str, ...]],
) -> FullC6ExternalAuthorityPartition:
    classes = tuple(
        FullC6ExternalAuthorityClass(
            class_id=class_id,
            observed_count=len(identities[class_id]),
            canonical_identity_set_sha256=full_c6_external_authority_identity_set_digest(
                class_id,
                identities[class_id],
            ),
        )
        for class_id in FULL_C6_EXTERNAL_POLICY_CLASS_IDS
    )
    return FullC6ExternalAuthorityPartition(
        classes=classes,
        observed_component_count=sum(item.observed_count for item in classes),
        canonical_partition_sha256=full_c6_external_authority_partition_digest(classes),
    )


def _file(
    path: str,
    *,
    role: str = "license-file",
    digest: str = "a" * 64,
) -> FullC6PolicyFileIdentity:
    return FullC6PolicyFileIdentity(path, digest, 101, role)


def _license(
    *,
    authority_identity: str,
    authority_partition_sha256: str,
    declared: str = "MIT",
    detected: str = "MIT",
    files: tuple[FullC6PolicyFileIdentity, ...] | None = None,
    source_detector_receipt_sha256: str = "c" * 64,
    detector_payload_sha256: str = "b" * 64,
) -> FullC6LicenseEvidence:
    return FullC6LicenseEvidence(
        declared_spdx=declared,
        detected_spdx=detected,
        subject_authority_identity=authority_identity,
        subject_identity_sha256=authority_identity.rsplit(":", 1)[-1],
        authority_partition_sha256=authority_partition_sha256,
        source_detector_receipt_sha256=source_detector_receipt_sha256,
        detector_payload_sha256=detector_payload_sha256,
        license_files=files or (_file("licenses/PROJECT-LICENSE"),),
    )


def _disposition(class_id: str) -> str:
    if class_id in _SOURCES:
        return "exact-source-input"
    if class_id in _OUTPUTS:
        return "exact-generated-output"
    if class_id in {"file-input:generated-cargo-lock", "file-input:policy-lock"}:
        return "not-applicable-build-input"
    if class_id == "native-runtime:logical-system-leaf":
        return "not-applicable-system-leaf"
    return "not-applicable-nontransformable"


def _rows(
    artifact_identities: dict[str, tuple[str, ...]],
    external_identities: dict[str, tuple[str, ...]],
    authority_partition_sha256: str,
) -> tuple[FullC6PolicyInputRow, ...]:
    result: list[FullC6PolicyInputRow] = []
    for class_index, class_id in enumerate(FULL_C6_POLICY_CLASS_IDS, start=1):
        identities = (
            artifact_identities[class_id]
            if class_id in artifact_identities
            else external_identities[class_id]
        )
        for member_index, authority_identity in enumerate(identities, start=1):
            if class_id in _CONTENT:
                mode = "content-sha256"
                digest: str | None = authority_identity.rsplit(":", 1)[-1]
                size: int | None = 100 + class_index + member_index
            elif class_id == "cargo-component:registry-package":
                mode = "cargo-registry-checksum"
                digest = authority_identity.rsplit(":", 1)[-1]
                size = None
            elif class_id == "cargo-component:path-root-package":
                mode = "source-tree-sha256"
                digest = authority_identity.rsplit(":", 1)[-1]
                size = None
            else:
                mode = "logical-system-leaf"
                digest = None
                size = None
            identity = _IDENTITIES[class_id]
            if member_index > 1:
                identity = f"{identity}.member-{member_index}"
            license_disposition = _NA_LICENSE.get(class_id, "owner-approved-allow")
            result.append(
                FullC6PolicyInputRow(
                    class_id=class_id,
                    canonical_identity=identity,
                    authority_identity=authority_identity,
                    identity_mode=mode,
                    sha256=digest,
                    size=size,
                    license_disposition=license_disposition,
                    transformation_disposition=_disposition(class_id),
                    license_evidence=(
                        _license(
                            authority_identity=authority_identity,
                            authority_partition_sha256=authority_partition_sha256,
                        )
                        if license_disposition == "owner-approved-allow"
                        else None
                    ),
                )
            )
    return tuple(result)


def _record(
    *,
    record_id: str,
    kind: str,
    source_identities: tuple[str, ...],
    source_identity_sha256s: tuple[str, ...],
    output_identity: str,
    output_identity_sha256: str,
    authority_partition_sha256: str,
    analysis_sha256: str,
    lowered_ir_sha256: str,
    generator_sha256: str = "c" * 64,
    analysis_receipt_kind: str = FULL_C6_ANALYSIS_RECEIPT_KIND,
    lowered_ir_receipt_kind: str = FULL_C6_LOWERED_IR_RECEIPT_KIND,
) -> FullC6TransformationRecord:
    source_set = full_c6_transformation_source_set_digest(
        source_identities,
        source_identity_sha256s,
    )
    analysis_receipt = full_c6_analysis_receipt_digest(
        authority_partition_sha256=authority_partition_sha256,
        source_identity_set_sha256=source_set,
        output_identity_sha256=output_identity_sha256,
        analysis_sha256=analysis_sha256,
    )
    ir_receipt = full_c6_lowered_ir_receipt_digest(
        authority_partition_sha256=authority_partition_sha256,
        transformation_kind=kind,
        source_identity_set_sha256=source_set,
        output_identity_sha256=output_identity_sha256,
        generator_sha256=generator_sha256,
        analysis_receipt_sha256=analysis_receipt,
        lowered_ir_sha256=lowered_ir_sha256,
    )
    return FullC6TransformationRecord(
        record_id=record_id,
        kind=kind,
        source_identities=source_identities,
        source_identity_sha256s=source_identity_sha256s,
        output_identity=output_identity,
        output_identity_sha256=output_identity_sha256,
        authority_partition_sha256=authority_partition_sha256,
        source_identity_set_sha256=source_set,
        generator_sha256=generator_sha256,
        analysis_sha256=analysis_sha256,
        analysis_receipt_sha256=analysis_receipt,
        lowered_ir_sha256=lowered_ir_sha256,
        lowered_ir_receipt_sha256=ir_receipt,
        analysis_receipt_kind=analysis_receipt_kind,
        lowered_ir_receipt_kind=lowered_ir_receipt_kind,
    )


def _transformations(
    rows: tuple[FullC6PolicyInputRow, ...],
    authority_partition_sha256: str,
) -> tuple[FullC6TransformationRecord, ...]:
    sources = tuple(
        sorted(
            (row for row in rows if row.class_id in _SOURCES),
            key=lambda item: item.authority_identity,
        )
    )
    source_identities = tuple(item.authority_identity for item in sources)
    source_sha256s = tuple(item.canonical_identity_sha256 for item in sources)
    outputs = tuple(row for row in rows if row.class_id in _OUTPUTS)
    return tuple(
        _record(
            record_id=f"transform:{index:03d}",
            kind=(
                "python-wrapper-generation-v1"
                if output.class_id == "file-input:generated-python-input"
                else "python-to-rust-lowering-v1"
            ),
            source_identities=source_identities,
            source_identity_sha256s=source_sha256s,
            output_identity=output.authority_identity,
            output_identity_sha256=output.canonical_identity_sha256,
            authority_partition_sha256=authority_partition_sha256,
            analysis_sha256=f"{index + 100:064x}",
            lowered_ir_sha256=f"{index + 200:064x}",
        )
        for index, output in enumerate(outputs, start=1)
    )


def _owner(**changes: object) -> FullC6OwnerDeclaration:
    values: dict[str, object] = {
        "owner_identity": "Acme Engineering",
        "owner_role": "organization-owner",
        "trusted_public_key_sha256": "f" * 64,
    }
    values.update(changes)
    return FullC6OwnerDeclaration(**values)  # type: ignore[arg-type]


def _fixture(
    *,
    zero_artifact: frozenset[str] = frozenset(),
    zero_external: frozenset[str] = frozenset(),
) -> tuple[
    tuple[FullC6PolicyInputRow, ...],
    tuple[FullC6TransformationRecord, ...],
    ArtifactPolicyCoverageInventory,
    FullC6ExternalAuthorityPartition,
]:
    artifact_ids, external_ids = _authority_sets(
        zero_artifact=zero_artifact,
        zero_external=zero_external,
    )
    coverage = _coverage(artifact_ids)
    external = _external_partition(external_ids)
    partition = full_c6_authority_partition_digest(coverage, external)
    rows = _rows(artifact_ids, external_ids, partition)
    return rows, _transformations(rows, partition), coverage, external


def _receipt() -> FullC6PolicyReceipt:
    rows, transformations, coverage, external = _fixture()
    return FullC6PolicyReceipt(
        rows=rows,
        transformations=transformations,
        owner_declaration=_owner(),
        artifact_coverage=coverage,
        external_authority=external,
        bootstrap_request_sha256="d" * 64,
    )


def _digest(
    rows: tuple[FullC6PolicyInputRow, ...],
    transformations: tuple[FullC6TransformationRecord, ...],
    coverage: ArtifactPolicyCoverageInventory,
    external: FullC6ExternalAuthorityPartition,
    owner: FullC6OwnerDeclaration | None = None,
) -> str:
    return full_c6_policy_digest(
        rows,
        transformations,
        owner or _owner(),
        coverage,
        external,
    )


def test_frozen_vocabulary_is_exact_c614_classes_plus_c52_authority_inputs() -> None:
    assert FULL_C6_POLICY_CLASS_IDS == (
        *ARTIFACT_POLICY_COVERAGE_CLASS_IDS,
        *FULL_C6_EXTERNAL_POLICY_CLASS_IDS,
    )
    assert FULL_C6_EXTERNAL_POLICY_CLASS_IDS == (
        "external-source:wheel-archive",
        "external-source:python-source",
        "external-source:distribution-metadata",
        "external-source:license-file",
    )


def test_complete_receipt_is_deterministic_deeply_rebuilt_and_exposes_gate_inputs() -> None:
    rows, transformations, coverage, external = _fixture()
    declaration = _owner()
    receipt = FullC6PolicyReceipt(rows, transformations, declaration, coverage, external)
    original = json.loads(json.dumps(receipt.to_dict(), sort_keys=True))

    assert receipt.scope == FULL_C6_SCOPE
    assert receipt.to_dict() == original
    assert len(receipt.policy_sha256) == 64
    assert receipt.trusted_owner_public_key_sha256 == "f" * 64
    assert receipt.authority_partition_sha256 == full_c6_authority_partition_digest(
        coverage,
        external,
    )
    assert original["complete_for_scope"] is True
    assert original["owner_allow_declaration_authenticated"] is False
    assert original["distribution_authorized"] is False
    with pytest.raises(FrozenInstanceError):
        receipt.rows = ()  # type: ignore[misc]

    object.__setattr__(rows[0], "canonical_identity", "attacker/replaced.py")
    object.__setattr__(declaration, "trusted_public_key_sha256", "0" * 64)
    object.__setattr__(coverage.classes[0], "observed_count", 999)
    assert receipt.to_dict() == original


def test_zero_member_c614_and_c52_classes_are_exactly_supported() -> None:
    rows, transformations, coverage, external = _fixture(
        zero_artifact=frozenset({"wheel-entry:other"}),
        zero_external=frozenset({"external-source:license-file"}),
    )
    assert _digest(rows, transformations, coverage, external)
    assert coverage.classes[-1].observed_count == 0
    assert external.classes[-1].observed_count == 0
    assert all(row.class_id != "wheel-entry:other" for row in rows)
    assert all(row.class_id != "external-source:license-file" for row in rows)


@pytest.mark.parametrize("mutation", ["missing", "extra", "forged-coverage", "forged-external"])
def test_rows_must_equal_actual_c614_and_c52_count_set_partitions(mutation: str) -> None:
    rows, transformations, coverage, external = _fixture()
    candidate_rows = rows
    candidate_coverage = coverage
    candidate_external = external
    if mutation == "missing":
        candidate_rows = rows[:-1]
    elif mutation == "extra":
        original = rows[0]
        extra_authority = _artifact_identity(original.class_id, 2)
        candidate_rows = (
            original,
            replace(
                original,
                canonical_identity="project/src/extra.py",
                authority_identity=extra_authority,
                sha256=extra_authority.rsplit(":", 1)[-1],
                license_evidence=_license(
                    authority_identity=extra_authority,
                    authority_partition_sha256=original.license_evidence.authority_partition_sha256,  # type: ignore[union-attr]
                ),
            ),
            *rows[1:],
        )
    elif mutation == "forged-coverage":
        artifact_ids, _ = _authority_sets()
        artifact_ids[ARTIFACT_POLICY_COVERAGE_CLASS_IDS[0]] = (
            _artifact_identity(ARTIFACT_POLICY_COVERAGE_CLASS_IDS[0], 9),
        )
        candidate_coverage = _coverage(artifact_ids)
    else:
        _, external_ids = _authority_sets()
        external_ids[FULL_C6_EXTERNAL_POLICY_CLASS_IDS[0]] = (
            full_c6_external_authority_identity(
                FULL_C6_EXTERNAL_POLICY_CLASS_IDS[0],
                {"forged": True},
            ),
        )
        candidate_external = _external_partition(external_ids)

    with pytest.raises(FullC6PolicyError, match="exact C6.14|exact C5.2"):
        _digest(
            candidate_rows,
            transformations,
            candidate_coverage,
            candidate_external,
        )


def test_noncanonical_or_aliased_rows_fail_closed() -> None:
    rows, transformations, coverage, external = _fixture()
    reordered = list(rows)
    reordered[0], reordered[1] = reordered[1], reordered[0]
    with pytest.raises(FullC6PolicyError, match="canonically ordered"):
        _digest(tuple(reordered), transformations, coverage, external)
    aliased = list(rows)
    aliased[1] = replace(aliased[1], canonical_identity=rows[0].canonical_identity.upper())
    with pytest.raises(FullC6PolicyError, match="alias or duplicate"):
        _digest(tuple(aliased), transformations, coverage, external)


def test_spdx_v1_parser_accepts_only_canonical_bounded_allowlisted_expressions() -> None:
    rows, _, _, _ = _fixture()
    authority_identity = rows[0].authority_identity
    partition = rows[0].license_evidence.authority_partition_sha256  # type: ignore[union-attr]
    evidence = _license(
        authority_identity=authority_identity,
        authority_partition_sha256=partition,
        declared="(MIT OR Apache-2.0) AND BSD-3-Clause",
        detected="(MIT OR Apache-2.0) AND BSD-3-Clause",
    )
    assert evidence.declared_spdx == "(MIT OR Apache-2.0) AND BSD-3-Clause"

    for invalid in (
        "Custom-Proprietary-1.0",
        "MIT or Apache-2.0",
        "MIT AND",
        "((MIT))",
        "MIT WITH Unknown-exception",
        "(MIT OR Apache-2.0) WITH LLVM-exception",
    ):
        with pytest.raises(FullC6PolicyError):
            _license(
                authority_identity=authority_identity,
                authority_partition_sha256=partition,
                declared=invalid,
                detected=invalid,
            )


def test_detector_and_license_file_set_are_bound_to_each_exact_row() -> None:
    rows, transformations, coverage, external = _fixture()
    first = rows[0]
    second = rows[1]
    assert first.license_evidence is not None
    assert second.license_evidence is not None
    assert (
        first.license_evidence.detector_receipt_sha256
        != second.license_evidence.detector_receipt_sha256
    )
    with pytest.raises(FullC6PolicyError, match="does not bind the row"):
        replace(second, license_evidence=first.license_evidence)

    different_files = _license(
        authority_identity=first.authority_identity,
        authority_partition_sha256=first.license_evidence.authority_partition_sha256,
        files=(_file("licenses/OTHER", digest="9" * 64),),
    )
    assert (
        different_files.license_file_identity_set_sha256
        != first.license_evidence.license_file_identity_set_sha256
    )
    assert different_files.detector_receipt_sha256 != first.license_evidence.detector_receipt_sha256

    different_source_detector = replace(
        first.license_evidence,
        source_detector_receipt_sha256="9" * 64,
    )
    assert (
        different_source_detector.detector_receipt_sha256
        != first.license_evidence.detector_receipt_sha256
    )

    stale = replace(
        first.license_evidence,
        authority_partition_sha256="0" * 64,
    )
    candidate = (replace(first, license_evidence=stale), *rows[1:])
    with pytest.raises(FullC6PolicyError, match="stale authority partition"):
        _digest(candidate, transformations, coverage, external)


def test_detector_kind_and_conflicting_license_file_identity_fail_closed() -> None:
    rows, transformations, coverage, external = _fixture()
    first = rows[0]
    assert first.license_evidence is not None
    with pytest.raises(FullC6PolicyError, match="detector receipt kind"):
        replace(first.license_evidence, detector_receipt_kind="generic-report")

    candidate = list(rows)
    assert candidate[1].license_evidence is not None
    candidate[0] = replace(
        candidate[0],
        license_evidence=_license(
            authority_identity=candidate[0].authority_identity,
            authority_partition_sha256=(
                candidate[0].license_evidence.authority_partition_sha256  # type: ignore[union-attr]
            ),
            files=(_file("licenses/LICENSE", digest="1" * 64),),
        ),
    )
    candidate[1] = replace(
        candidate[1],
        license_evidence=_license(
            authority_identity=candidate[1].authority_identity,
            authority_partition_sha256=(candidate[1].license_evidence.authority_partition_sha256),
            files=(_file("licenses/LICENSE", digest="2" * 64),),
        ),
    )
    with pytest.raises(FullC6PolicyError, match="conflicts"):
        _digest(tuple(candidate), transformations, coverage, external)


def _rebuild_record_with_sources(
    record: FullC6TransformationRecord,
    source_identities: tuple[str, ...],
    source_sha256s: tuple[str, ...],
) -> FullC6TransformationRecord:
    return _record(
        record_id=record.record_id,
        kind=record.kind,
        source_identities=source_identities,
        source_identity_sha256s=source_sha256s,
        output_identity=record.output_identity,
        output_identity_sha256=record.output_identity_sha256,
        authority_partition_sha256=record.authority_partition_sha256,
        analysis_sha256=record.analysis_sha256,
        lowered_ir_sha256=record.lowered_ir_sha256,
    )


def test_union_only_source_coverage_cannot_hide_per_output_omissions() -> None:
    rows, transformations, coverage, external = _fixture()
    records = list(transformations)
    records[0] = _rebuild_record_with_sources(
        records[0],
        records[0].source_identities[1:],
        records[0].source_identity_sha256s[1:],
    )
    records[1] = _rebuild_record_with_sources(
        records[1],
        records[1].source_identities[:-1],
        records[1].source_identity_sha256s[:-1],
    )
    with pytest.raises(FullC6PolicyError, match="per-output exact source set"):
        _digest(rows, tuple(records), coverage, external)


def test_output_class_kind_and_receipt_identities_are_exactly_cross_bound() -> None:
    rows, transformations, coverage, external = _fixture()
    wrapper = transformations[0]
    wrong_kind = _record(
        record_id=wrapper.record_id,
        kind="python-to-rust-lowering-v1",
        source_identities=wrapper.source_identities,
        source_identity_sha256s=wrapper.source_identity_sha256s,
        output_identity=wrapper.output_identity,
        output_identity_sha256=wrapper.output_identity_sha256,
        authority_partition_sha256=wrapper.authority_partition_sha256,
        analysis_sha256=wrapper.analysis_sha256,
        lowered_ir_sha256=wrapper.lowered_ir_sha256,
    )
    with pytest.raises(FullC6PolicyError, match="kind does not match"):
        _digest(rows, (wrong_kind, *transformations[1:]), coverage, external)

    with pytest.raises(FullC6PolicyError, match="analysis receipt identity"):
        replace(wrapper, analysis_receipt_sha256="0" * 64)
    with pytest.raises(FullC6PolicyError, match="lowered IR receipt identity"):
        replace(wrapper, lowered_ir_receipt_sha256="0" * 64)
    with pytest.raises(FullC6PolicyError, match="analysis receipt kind"):
        replace(wrapper, analysis_receipt_kind="analysis")
    with pytest.raises(FullC6PolicyError, match="lowered IR receipt kind"):
        replace(wrapper, lowered_ir_receipt_kind="ir")


def test_analysis_or_ir_receipt_replay_to_another_output_is_rejected() -> None:
    _, transformations, _, _ = _fixture()
    first, second = transformations[:2]
    with pytest.raises(FullC6PolicyError, match="analysis receipt identity"):
        replace(second, analysis_receipt_sha256=first.analysis_receipt_sha256)
    with pytest.raises(FullC6PolicyError, match="lowered IR receipt identity"):
        replace(second, lowered_ir_receipt_sha256=first.lowered_ir_receipt_sha256)


@pytest.mark.parametrize("mutation", ["stale-output", "missing-output", "duplicate-output"])
def test_output_transformation_coverage_fails_closed(mutation: str) -> None:
    rows, transformations, coverage, external = _fixture()
    records = list(transformations)
    if mutation == "stale-output":
        with pytest.raises(FullC6PolicyError, match="analysis receipt identity"):
            replace(records[0], output_identity_sha256="0" * 64)
        return
    if mutation == "missing-output":
        records.pop()
    else:
        records[1] = _record(
            record_id=records[1].record_id,
            kind=records[0].kind,
            source_identities=records[0].source_identities,
            source_identity_sha256s=records[0].source_identity_sha256s,
            output_identity=records[0].output_identity,
            output_identity_sha256=records[0].output_identity_sha256,
            authority_partition_sha256=records[0].authority_partition_sha256,
            analysis_sha256=records[1].analysis_sha256,
            lowered_ir_sha256=records[1].lowered_ir_sha256,
        )
    with pytest.raises(FullC6PolicyError):
        _digest(rows, tuple(records), coverage, external)


def test_owner_policy_digest_and_late_key_hash_binding_are_explicit() -> None:
    rows, transformations, coverage, external = _fixture()
    digest = _digest(rows, transformations, coverage, external)
    changed_owner = _digest(
        rows,
        transformations,
        coverage,
        external,
        _owner(owner_identity="Acme Release Engineering"),
    )
    changed_key = _digest(
        rows,
        transformations,
        coverage,
        external,
        _owner(trusted_public_key_sha256="0" * 64),
    )
    assert len({digest, changed_owner, changed_key}) == 3
    receipt = _receipt()
    assert receipt.trusted_owner_public_key_sha256 == "f" * 64
    serialized = json.dumps(receipt.to_dict(), sort_keys=True)
    assert "owner-policy-signature" not in serialized
    assert "signature_verification_receipt" not in serialized


def test_owner_declaration_is_exact_allow_pending_final_authentication() -> None:
    with pytest.raises(FullC6PolicyError, match="explicit allow"):
        _owner(decision="deny")
    with pytest.raises(FullC6PolicyError, match="action scopes"):
        _owner(action_scopes=("redistribution",))
    with pytest.raises(FullC6PolicyError, match="acknowledgement"):
        _owner(acknowledgement="I guess this is fine")
    with pytest.raises(FullC6PolicyError, match="authentication state"):
        _owner(authentication="self-asserted-authenticated")
    assert _owner().acknowledgement == FULL_C6_OWNER_ACKNOWLEDGEMENT
    assert _owner().action_scopes == FULL_C6_OWNER_ACTION_SCOPES
    assert _owner().authentication == FULL_C6_OWNER_AUTHENTICATION


def test_boolean_size_count_and_serialized_bounds_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rows, transformations, coverage, external = _fixture()
    with pytest.raises(TypeError, match="integer"):
        replace(rows[0], size=True)
    with pytest.raises(FullC6PolicyError, match="count"):
        FullC6ExternalAuthorityClass(
            FULL_C6_EXTERNAL_POLICY_CLASS_IDS[0],
            True,
            "0" * 64,
        )

    monkeypatch.setattr(policy_module, "MAX_FULL_C6_POLICY_ROWS", len(rows) - 1)
    with pytest.raises(FullC6PolicyError, match="row count"):
        _digest(rows, transformations, coverage, external)
    monkeypatch.setattr(policy_module, "MAX_FULL_C6_POLICY_ROWS", 1024)
    monkeypatch.setattr(policy_module, "MAX_FULL_C6_POLICY_SERIALIZED_BYTES", 100)
    with pytest.raises(FullC6PolicyError, match="serialized byte bound"):
        _digest(rows, transformations, coverage, external)


def test_receipt_rejects_nonexact_container_and_nested_object_types() -> None:
    rows, transformations, coverage, external = _fixture()
    with pytest.raises(TypeError, match="exact tuple"):
        FullC6PolicyReceipt(
            list(rows),  # type: ignore[arg-type]
            transformations,
            _owner(),
            coverage,
            external,
        )
    with pytest.raises(TypeError, match="invalid type"):
        FullC6PolicyReceipt(
            rows,
            transformations,
            object(),  # type: ignore[arg-type]
            coverage,
            external,
        )
