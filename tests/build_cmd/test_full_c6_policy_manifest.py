"""Focused tests for the canonical artifact-policy owner manifest boundary."""

from __future__ import annotations

import json
import os
from pathlib import Path
import runpy

import pytest

from rextio.artifacts.contract_dialects import (
    CURRENT,
    LEGACY_0_1_7,
    POLICY_MANIFEST,
    ArtifactContractDialect,
)
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
    canonical_json_bytes,
    sha256_hex,
)
from rextio.build.full_c6_policy import (
    FULL_C6_EXTERNAL_POLICY_CLASS_IDS,
    MAX_FULL_C6_POLICY_ROWS,
    FullC6ExternalAuthorityClass,
    FullC6ExternalAuthorityPartition,
    FullC6LicenseEvidence,
    FullC6OwnerDeclaration,
    FullC6PolicyFileIdentity,
    FullC6PolicyInputRow,
    FullC6PolicyReceipt,
    FullC6TransformationRecord,
    full_c6_analysis_receipt_digest,
    full_c6_authority_partition_digest,
    full_c6_external_authority_identity_set_digest,
    full_c6_external_authority_partition_digest,
    full_c6_lowered_ir_receipt_digest,
    full_c6_transformation_source_set_digest,
)
from rextio.build.full_c6_policy_manifest import (
    FULL_C6_POLICY_MANIFEST_DOMAIN,
    FULL_C6_POLICY_MANIFEST_KIND,
    FULL_C6_POLICY_MANIFEST_SCHEMA_VERSION,
    FullC6PolicyManifestError,
    MAX_FULL_C6_POLICY_MANIFEST_BYTES,
    full_c6_policy_manifest_bytes,
    full_c6_policy_manifest_document,
    load_full_c6_policy_manifest,
    parse_full_c6_policy_manifest,
)
import rextio.build.owner_policy_lock as owner_policy_lock


_POLICY = runpy.run_path(str(Path(__file__).with_name("test_full_c6_policy.py")))


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
_SOURCE_CLASS = "file-input:project-python-source"
_OUTPUT_CLASS = "file-input:generated-rust-lib"


def _artifact_identity(class_id: str, digest: str) -> str:
    return f"urn:rextio:artifact-evidence:component:{class_id}:{digest}"


def _coverage(identities: dict[str, tuple[str, ...]]) -> ArtifactPolicyCoverageInventory:
    classes = tuple(
        ArtifactPolicyCoverageClass(
            class_id=class_id,
            observed_count=len(identities[class_id]),
            canonical_identity_set_sha256=artifact_policy_identity_set_digest(
                class_id, identities[class_id]
            ),
            identity_state=identity_state,
            license_policy_state=license_state,
            license_policy_receipt_kind=license_kind,
            license_policy_receipt_sha256=("a" * 64 if license_kind is not None else None),
            transformation_provenance_state=transformation_state,
            transformation_provenance_receipt_kind=transformation_kind,
            transformation_provenance_receipt_sha256=(
                "b" * 64 if transformation_kind is not None else None
            ),
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


def _external_authority() -> FullC6ExternalAuthorityPartition:
    classes = tuple(
        FullC6ExternalAuthorityClass(
            class_id=class_id,
            observed_count=0,
            canonical_identity_set_sha256=full_c6_external_authority_identity_set_digest(
                class_id, ()
            ),
        )
        for class_id in FULL_C6_EXTERNAL_POLICY_CLASS_IDS
    )
    return FullC6ExternalAuthorityPartition(
        classes=classes,
        observed_component_count=0,
        canonical_partition_sha256=full_c6_external_authority_partition_digest(classes),
    )


def _license(authority_identity: str, partition_sha256: str) -> FullC6LicenseEvidence:
    return FullC6LicenseEvidence(
        declared_spdx="MIT",
        detected_spdx="MIT",
        subject_authority_identity=authority_identity,
        subject_identity_sha256=authority_identity.rsplit(":", 1)[-1],
        authority_partition_sha256=partition_sha256,
        source_detector_receipt_sha256="c" * 64,
        detector_payload_sha256="d" * 64,
        license_files=(
            FullC6PolicyFileIdentity(
                logical_path="licenses/LICENSE",
                sha256="e" * 64,
                size=101,
                role="license-file",
            ),
        ),
    )


def _receipt() -> FullC6PolicyReceipt:
    source_digest = "1" * 64
    output_digest = "2" * 64
    source_authority = _artifact_identity(_SOURCE_CLASS, source_digest)
    output_authority = _artifact_identity(_OUTPUT_CLASS, output_digest)
    identities = {class_id: () for class_id in ARTIFACT_POLICY_COVERAGE_CLASS_IDS}
    identities[_SOURCE_CLASS] = (source_authority,)
    identities[_OUTPUT_CLASS] = (output_authority,)
    coverage = _coverage(identities)
    external = _external_authority()
    authority_partition = full_c6_authority_partition_digest(coverage, external)
    rows = (
        FullC6PolicyInputRow(
            class_id=_SOURCE_CLASS,
            canonical_identity="project/src/app.py",
            authority_identity=source_authority,
            identity_mode="content-sha256",
            sha256=source_digest,
            size=110,
            license_disposition="owner-approved-allow",
            transformation_disposition="exact-source-input",
            license_evidence=_license(source_authority, authority_partition),
        ),
        FullC6PolicyInputRow(
            class_id=_OUTPUT_CLASS,
            canonical_identity="generated/rust/src/lib.rs",
            authority_identity=output_authority,
            identity_mode="content-sha256",
            sha256=output_digest,
            size=120,
            license_disposition="owner-approved-allow",
            transformation_disposition="exact-generated-output",
            license_evidence=_license(output_authority, authority_partition),
        ),
    )
    source_set = full_c6_transformation_source_set_digest((source_authority,), (source_digest,))
    analysis_digest = "3" * 64
    analysis_receipt = full_c6_analysis_receipt_digest(
        authority_partition_sha256=authority_partition,
        source_identity_set_sha256=source_set,
        output_identity_sha256=output_digest,
        analysis_sha256=analysis_digest,
    )
    lowered_ir_digest = "4" * 64
    generator_digest = "5" * 64
    lowered_ir_receipt = full_c6_lowered_ir_receipt_digest(
        authority_partition_sha256=authority_partition,
        transformation_kind="python-to-rust-lowering-v1",
        source_identity_set_sha256=source_set,
        output_identity_sha256=output_digest,
        generator_sha256=generator_digest,
        analysis_receipt_sha256=analysis_receipt,
        lowered_ir_sha256=lowered_ir_digest,
    )
    transformation = FullC6TransformationRecord(
        record_id="transform:001",
        kind="python-to-rust-lowering-v1",
        source_identities=(source_authority,),
        source_identity_sha256s=(source_digest,),
        output_identity=output_authority,
        output_identity_sha256=output_digest,
        authority_partition_sha256=authority_partition,
        source_identity_set_sha256=source_set,
        generator_sha256=generator_digest,
        analysis_sha256=analysis_digest,
        analysis_receipt_sha256=analysis_receipt,
        lowered_ir_sha256=lowered_ir_digest,
        lowered_ir_receipt_sha256=lowered_ir_receipt,
    )
    return FullC6PolicyReceipt(
        rows=rows,
        transformations=(transformation,),
        owner_declaration=FullC6OwnerDeclaration(
            owner_identity="Acme Engineering",
            owner_role="organization-owner",
            trusted_public_key_sha256="f" * 64,
        ),
        artifact_coverage=coverage,
        external_authority=external,
        bootstrap_request_sha256="6" * 64,
    )


def _canonical(document: object) -> bytes:
    return canonical_json_bytes(document)


def _parse_document(document: dict[str, object]) -> FullC6PolicyReceipt:
    raw = _canonical(document)
    return parse_full_c6_policy_manifest(raw, expected_sha256=sha256_hex(raw))


def test_round_trip_reconstructs_all_nested_models_without_authorizing() -> None:
    original = _receipt()
    raw = full_c6_policy_manifest_bytes(original)

    rebuilt = parse_full_c6_policy_manifest(raw, expected_sha256=sha256_hex(raw))

    assert rebuilt is not original
    assert type(rebuilt) is FullC6PolicyReceipt
    assert type(rebuilt.artifact_coverage) is ArtifactPolicyCoverageInventory
    assert type(rebuilt.external_authority) is FullC6ExternalAuthorityPartition
    assert type(rebuilt.rows[0].license_evidence) is FullC6LicenseEvidence
    assert type(rebuilt.rows[0].license_evidence.license_files[0]) is FullC6PolicyFileIdentity
    assert type(rebuilt.transformations[0]) is FullC6TransformationRecord
    assert type(rebuilt.owner_declaration) is FullC6OwnerDeclaration
    assert rebuilt.to_dict() == original.to_dict()
    assert rebuilt.distribution_authorized is False
    assert full_c6_policy_manifest_document(rebuilt) == json.loads(raw)
    assert set(json.loads(raw)) == {
        "kind",
        "schema_version",
        "domain",
        "artifact_coverage",
        "external_authority",
        "rows",
        "transformations",
        "owner_declaration",
        "bootstrap_request_sha256",
        "policy_sha256",
        "receipt_digest",
    }
    assert b"private_key" not in raw
    assert b'"signature":' not in raw


def test_manifest_identity_and_exact_complete_partitions_are_serialized() -> None:
    receipt = _receipt()
    document = full_c6_policy_manifest_document(receipt)

    assert document["kind"] == FULL_C6_POLICY_MANIFEST_KIND
    assert document["domain"] == FULL_C6_POLICY_MANIFEST_DOMAIN
    assert document["schema_version"] == FULL_C6_POLICY_MANIFEST_SCHEMA_VERSION
    assert document["artifact_coverage"] == receipt.artifact_coverage.to_dict()
    assert document["external_authority"] == receipt.external_authority.to_dict()
    assert document["bootstrap_request_sha256"] == receipt.bootstrap_request_sha256
    assert document["policy_sha256"] == receipt.policy_sha256
    assert document["receipt_digest"] == receipt.digest


@pytest.mark.parametrize(
    ("schema_version", "domain"),
    [
        (1, "rextio.full-c6-owner-policy-manifest.v1"),
        (1, FULL_C6_POLICY_MANIFEST_DOMAIN),
        (FULL_C6_POLICY_MANIFEST_SCHEMA_VERSION, "rextio.full-c6-owner-policy-manifest.v1"),
    ],
)
def test_mixed_manifest_wire_identity_is_rejected(
    schema_version: int,
    domain: str,
) -> None:
    document = full_c6_policy_manifest_document(_receipt())
    document["schema_version"] = schema_version
    document["domain"] = domain

    with pytest.raises(FullC6PolicyManifestError, match="identity is invalid"):
        _parse_document(document)


def test_exact_legacy_manifest_round_trip_preserves_bytes_and_digests() -> None:
    legacy = _POLICY["_receipt"](dialect=LEGACY_0_1_7)
    raw = full_c6_policy_manifest_bytes(legacy)

    rebuilt = parse_full_c6_policy_manifest(
        raw,
        expected_sha256=sha256_hex(raw),
    )

    assert rebuilt._artifact_contract_dialect == LEGACY_0_1_7.name
    assert full_c6_policy_manifest_bytes(rebuilt) == raw
    assert rebuilt.policy_sha256 == legacy.policy_sha256
    assert rebuilt.digest == legacy.digest


@pytest.mark.parametrize(
    ("root_dialect", "nested_dialect"),
    [
        (CURRENT, LEGACY_0_1_7),
        (LEGACY_0_1_7, CURRENT),
    ],
)
def test_manifest_rejects_root_and_nested_dialect_hybrids(
    root_dialect: ArtifactContractDialect,
    nested_dialect: ArtifactContractDialect,
) -> None:
    nested = _POLICY["_receipt"](dialect=nested_dialect)
    document = full_c6_policy_manifest_document(nested)
    identity = root_dialect.identity(POLICY_MANIFEST)
    document.update(
        {
            "kind": identity.kind,
            "schema_version": identity.schema_version,
            "domain": identity.domain,
        }
    )

    with pytest.raises(
        FullC6PolicyManifestError,
        match="mixed nested dialect|values are invalid",
    ):
        _parse_document(document)


def test_manifest_requires_exact_bootstrap_lineage() -> None:
    receipt = _receipt()
    without_lineage = FullC6PolicyReceipt(
        rows=receipt.rows,
        transformations=receipt.transformations,
        owner_declaration=receipt.owner_declaration,
        artifact_coverage=receipt.artifact_coverage,
        external_authority=receipt.external_authority,
    )
    with pytest.raises(FullC6PolicyManifestError, match="requires bootstrap"):
        full_c6_policy_manifest_bytes(without_lineage)

    document = full_c6_policy_manifest_document(receipt)
    document["bootstrap_request_sha256"] = None
    with pytest.raises(FullC6PolicyManifestError, match="must be a string"):
        _parse_document(document)


@pytest.mark.parametrize(
    "mutator",
    [
        lambda value: value.update({"unexpected": False}),
        lambda value: value["owner_declaration"].update({"private_key": "secret"}),
        lambda value: value["artifact_coverage"]["classes"][0].update({"unexpected": False}),
        lambda value: value["rows"][0]["license_evidence"]["license_files"][0].update(
            {"unexpected": False}
        ),
        lambda value: value["transformations"][0]["output"].update({"unexpected": False}),
    ],
)
def test_unknown_key_at_every_schema_layer_is_rejected(mutator: object) -> None:
    document = full_c6_policy_manifest_document(_receipt())
    assert callable(mutator)
    mutator(document)

    with pytest.raises(FullC6PolicyManifestError, match="schema is invalid"):
        _parse_document(document)


def test_duplicate_key_noncanonical_json_and_wrong_pin_are_rejected() -> None:
    raw = full_c6_policy_manifest_bytes(_receipt())
    duplicate = raw.replace(
        b'{"artifact_coverage"',
        b'{"kind":"full-c6-owner-policy-manifest","artifact_coverage"',
        1,
    )
    noncanonical = raw + b"\n"

    with pytest.raises(FullC6PolicyManifestError, match="duplicate"):
        parse_full_c6_policy_manifest(duplicate, expected_sha256=sha256_hex(duplicate))
    with pytest.raises(FullC6PolicyManifestError, match="not canonical"):
        parse_full_c6_policy_manifest(noncanonical, expected_sha256=sha256_hex(noncanonical))
    with pytest.raises(FullC6PolicyManifestError, match="does not match"):
        parse_full_c6_policy_manifest(raw, expected_sha256="0" * 64)


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("rows", 0, "canonical_identity_sha256"), "9" * 64),
        (("rows", 0, "license_evidence", "detector_receipt_sha256"), "9" * 64),
        (("transformations", 0, "analysis_receipt_sha256"), "9" * 64),
        (("policy_sha256",), "9" * 64),
        (("receipt_digest",), "9" * 64),
    ],
)
def test_stale_derived_content_or_digest_is_rejected(
    path: tuple[str | int, ...], replacement: str
) -> None:
    document: object = full_c6_policy_manifest_document(_receipt())
    target = document
    for key in path[:-1]:
        target = target[key]  # type: ignore[index]
    target[path[-1]] = replacement  # type: ignore[index]

    with pytest.raises(FullC6PolicyManifestError):
        _parse_document(document)  # type: ignore[arg-type]


def test_secure_loader_accepts_regular_file_and_rejects_links(tmp_path: Path) -> None:
    raw = full_c6_policy_manifest_bytes(_receipt())
    digest = sha256_hex(raw)
    manifest = tmp_path / "policy.json"
    manifest.write_bytes(raw)

    assert (
        load_full_c6_policy_manifest(manifest, expected_sha256=digest).digest == _receipt().digest
    )

    symlink = tmp_path / "symlink.json"
    symlink.symlink_to(manifest)
    with pytest.raises(FullC6PolicyManifestError, match="file is unsafe"):
        load_full_c6_policy_manifest(symlink, expected_sha256=digest)

    hardlink = tmp_path / "hardlink.json"
    os.link(manifest, hardlink)
    with pytest.raises(FullC6PolicyManifestError, match="file is unsafe"):
        load_full_c6_policy_manifest(hardlink, expected_sha256=digest)


def test_secure_loader_detects_a_same_inode_read_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = full_c6_policy_manifest_bytes(_receipt())
    digest = sha256_hex(raw)
    manifest = tmp_path / "policy.json"
    manifest.write_bytes(raw)
    real_read = os.read
    raced = False

    def racing_read(file_descriptor: int, count: int) -> bytes:
        nonlocal raced
        chunk = real_read(file_descriptor, count)
        if chunk and not raced:
            raced = True
            manifest.write_bytes(raw + b" ")
        return chunk

    monkeypatch.setattr(owner_policy_lock.os, "read", racing_read)
    with pytest.raises(FullC6PolicyManifestError, match="file is unsafe"):
        load_full_c6_policy_manifest(manifest, expected_sha256=digest)


def test_manifest_byte_and_expected_digest_bounds_are_strict() -> None:
    with pytest.raises(FullC6PolicyManifestError, match="byte bound"):
        parse_full_c6_policy_manifest(
            b"x" * (MAX_FULL_C6_POLICY_MANIFEST_BYTES + 1),
            expected_sha256="0" * 64,
        )
    with pytest.raises(FullC6PolicyManifestError, match="lowercase SHA-256"):
        parse_full_c6_policy_manifest(b"{}", expected_sha256="F" * 64)

    document = full_c6_policy_manifest_document(_receipt())
    document["rows"] = [document["rows"][0]] * (MAX_FULL_C6_POLICY_ROWS + 1)
    with pytest.raises(FullC6PolicyManifestError, match="row count exceeds"):
        _parse_document(document)
