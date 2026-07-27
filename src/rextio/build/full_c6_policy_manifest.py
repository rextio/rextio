"""Canonical owner-authored input boundary for the final Full C6 policy.

The policy model itself deliberately accepts only fully constructed typed
objects.  This module adds the corresponding untrusted-file boundary: an owner
can serialize the complete policy universe, pin the exact file SHA-256 in build
configuration, and recover a deeply validated :class:`FullC6PolicyReceipt`.

The manifest is data, not an authorization or a signature.  It contains a
trusted *public-key digest* for the later signing gate, but never accepts key
material, infers a license, or grants distribution authority.
"""

from __future__ import annotations

import hmac
import json
from pathlib import Path
import re
from typing import cast

from rextio.artifacts.contract_dialects import (
    ARTIFACT_CONTRACT_DIALECTS,
    CURRENT,
    POLICY_MANIFEST,
    POLICY_MANIFEST_FILENAME,
    ArtifactContractDialect,
    resolve_artifact_contract_dialect,
)
from rextio.artifacts.evidence import (
    ARTIFACT_POLICY_COVERAGE_CLASS_IDS,
    ArtifactPolicyCoverageClass,
    ArtifactPolicyCoverageInventory,
    canonical_json_bytes,
    sha256_hex,
)
from rextio.build.full_c6_policy import (
    FULL_C6_EXTERNAL_POLICY_CLASS_IDS,
    MAX_FULL_C6_LICENSE_FILES_PER_ROW,
    MAX_FULL_C6_POLICY_ROWS,
    MAX_FULL_C6_POLICY_SERIALIZED_BYTES,
    MAX_FULL_C6_POLICY_SOURCES_PER_TRANSFORMATION,
    MAX_FULL_C6_POLICY_TRANSFORMATIONS,
    FullC6ExternalAuthorityClass,
    FullC6ExternalAuthorityPartition,
    FullC6LicenseEvidence,
    FullC6OwnerDeclaration,
    FullC6PolicyFileIdentity,
    FullC6PolicyInputRow,
    FullC6PolicyReceipt,
    FullC6TransformationRecord,
)
from rextio.build.owner_policy_lock import read_strict_owner_policy_lock


_CURRENT_MANIFEST_IDENTITY = CURRENT.identity(POLICY_MANIFEST)
FULL_C6_POLICY_MANIFEST_KIND = _CURRENT_MANIFEST_IDENTITY.kind
FULL_C6_POLICY_MANIFEST_DOMAIN = _CURRENT_MANIFEST_IDENTITY.domain
FULL_C6_POLICY_MANIFEST_SCHEMA_VERSION = _CURRENT_MANIFEST_IDENTITY.schema_version
FULL_C6_POLICY_MANIFEST_FILENAME = CURRENT.filename(POLICY_MANIFEST_FILENAME)

# A valid policy receipt is already bounded to four MiB.  The manifest repeats
# the small exact coverage partitions so they can be reconstructed rather than
# trusted as ambient objects.
MAX_FULL_C6_POLICY_MANIFEST_BYTES = MAX_FULL_C6_POLICY_SERIALIZED_BYTES + 64 * 1024
MAX_FULL_C6_POLICY_MANIFEST_JSON_DEPTH = 32

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TOP_LEVEL_FIELDS = {
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
_ARTIFACT_COVERAGE_FIELDS = {
    "kind",
    "schema_version",
    "scope",
    "identity_scheme",
    "authority",
    "scope_complete",
    "global_license_policy_complete",
    "global_transformation_provenance_complete",
    "complete",
    "signed",
    "distribution_authorized",
    "class_count",
    "observed_component_count",
    "canonical_partition_sha256",
    "classes",
}
_ARTIFACT_COVERAGE_CLASS_FIELDS = {
    "class_id",
    "observed_count",
    "canonical_identity_set_sha256",
    "identity_state",
    "license_policy_state",
    "license_policy_receipt_kind",
    "license_policy_receipt_sha256",
    "transformation_provenance_state",
    "transformation_provenance_receipt_kind",
    "transformation_provenance_receipt_sha256",
}
_EXTERNAL_AUTHORITY_FIELDS = {
    "domain",
    "identity_scheme",
    "class_count",
    "observed_component_count",
    "canonical_partition_sha256",
    "classes",
}
_EXTERNAL_AUTHORITY_CLASS_FIELDS = {
    "class_id",
    "observed_count",
    "canonical_identity_set_sha256",
}
_ROW_FIELDS = {
    "class_id",
    "canonical_identity",
    "authority_identity",
    "identity_mode",
    "sha256",
    "size",
    "canonical_identity_sha256",
    "license_disposition",
    "transformation_disposition",
    "license_evidence",
}
_LICENSE_EVIDENCE_FIELDS = {
    "declared_spdx",
    "detected_spdx",
    "subject_authority_identity",
    "subject_identity_sha256",
    "authority_partition_sha256",
    "detector_receipt_kind",
    "source_detector_receipt_sha256",
    "detector_payload_sha256",
    "detector_receipt_sha256",
    "license_file_identity_set_sha256",
    "license_files",
}
_POLICY_FILE_FIELDS = {"logical_path", "sha256", "size", "role"}
_TRANSFORMATION_FIELDS = {
    "record_id",
    "kind",
    "sources",
    "output",
    "authority_partition_sha256",
    "source_identity_set_sha256",
    "generator_sha256",
    "analysis_sha256",
    "analysis_receipt_kind",
    "analysis_receipt_sha256",
    "lowered_ir_sha256",
    "lowered_ir_receipt_kind",
    "lowered_ir_receipt_sha256",
}
_TRANSFORMATION_IDENTITY_FIELDS = {
    "canonical_identity",
    "canonical_identity_sha256",
}
_OWNER_FIELDS = {
    "owner_identity",
    "owner_role",
    "trusted_public_key_sha256",
    "decision",
    "action_scopes",
    "acknowledgement",
    "authentication",
}


class FullC6PolicyManifestError(ValueError):
    """The Full C6 owner policy manifest is unsafe or noncanonical."""


def full_c6_policy_manifest_document(
    receipt: FullC6PolicyReceipt,
) -> dict[str, object]:
    """Return the closed, non-authorizing manifest document for ``receipt``."""
    trusted = _reconstruct_receipt(receipt)
    if trusted.bootstrap_request_sha256 is None:
        raise FullC6PolicyManifestError(
            "Full C6 policy manifest requires bootstrap request lineage"
        )
    dialect = full_c6_policy_manifest_dialect(trusted)
    identity = dialect.identity(POLICY_MANIFEST)
    return {
        "kind": identity.kind,
        "schema_version": identity.schema_version,
        "domain": identity.domain,
        "artifact_coverage": trusted.artifact_coverage.to_dict(),
        "external_authority": trusted.external_authority.to_dict(),
        "rows": [item.to_dict() for item in trusted.rows],
        "transformations": [item.to_dict() for item in trusted.transformations],
        "owner_declaration": trusted.owner_declaration.to_dict(),
        "bootstrap_request_sha256": trusted.bootstrap_request_sha256,
        "policy_sha256": trusted.policy_sha256,
        "receipt_digest": trusted.digest,
    }


def full_c6_policy_manifest_bytes(receipt: FullC6PolicyReceipt) -> bytes:
    """Serialize one policy receipt as bounded canonical UTF-8 JSON."""
    try:
        value = canonical_json_bytes(full_c6_policy_manifest_document(receipt))
    except FullC6PolicyManifestError:
        raise
    except (TypeError, ValueError, RecursionError) as exc:
        raise FullC6PolicyManifestError("Full C6 policy manifest cannot be serialized") from exc
    if not value or len(value) > MAX_FULL_C6_POLICY_MANIFEST_BYTES:
        raise FullC6PolicyManifestError("Full C6 policy manifest exceeds the byte bound")
    return value


def parse_full_c6_policy_manifest(
    value: bytes,
    *,
    expected_sha256: str,
) -> FullC6PolicyReceipt:
    """Parse exact canonical bytes pinned by ``expected_sha256`` into a receipt."""
    raw = _bounded_bytes(value)
    expected_digest = _sha256(expected_sha256, "expected manifest SHA-256")
    observed_digest = sha256_hex(raw)
    if not hmac.compare_digest(observed_digest, expected_digest):
        raise FullC6PolicyManifestError("Full C6 policy manifest SHA-256 does not match the pin")
    document = _parse_json(raw)
    try:
        canonical = canonical_json_bytes(document)
    except (TypeError, ValueError, RecursionError) as exc:
        raise FullC6PolicyManifestError("Full C6 policy manifest JSON is invalid") from exc
    if not hmac.compare_digest(raw, canonical):
        raise FullC6PolicyManifestError("Full C6 policy manifest is not canonical JSON")

    root = _exact_dict(document, _TOP_LEVEL_FIELDS, "manifest")
    try:
        dialect = resolve_artifact_contract_dialect(
            POLICY_MANIFEST,
            kind=root["kind"],
            schema_version=_integer(root["schema_version"], "manifest schema version"),
            domain=root["domain"],
        )
    except ValueError as exc:
        raise FullC6PolicyManifestError(
            "Full C6 policy manifest identity is invalid"
        ) from exc
    declared_policy_digest = _sha256(root["policy_sha256"], "policy SHA-256")
    declared_receipt_digest = _sha256(root["receipt_digest"], "receipt digest")

    try:
        receipt = FullC6PolicyReceipt(
            rows=_rows(root["rows"]),
            transformations=_transformations(root["transformations"]),
            owner_declaration=_owner(root["owner_declaration"]),
            artifact_coverage=_artifact_coverage(root["artifact_coverage"]),
            external_authority=_external_authority(root["external_authority"]),
            bootstrap_request_sha256=_sha256(
                root["bootstrap_request_sha256"],
                "bootstrap request SHA-256",
            ),
        )
    except FullC6PolicyManifestError:
        raise
    except (TypeError, ValueError) as exc:
        raise FullC6PolicyManifestError("Full C6 policy manifest values are invalid") from exc
    object.__setattr__(receipt, "_artifact_contract_dialect", dialect.name)

    if not hmac.compare_digest(receipt.policy_sha256, declared_policy_digest):
        raise FullC6PolicyManifestError("Full C6 policy manifest policy digest is stale")
    if not hmac.compare_digest(receipt.digest, declared_receipt_digest):
        raise FullC6PolicyManifestError("Full C6 policy manifest receipt digest is stale")
    if receipt.distribution_authorized:
        raise FullC6PolicyManifestError("Full C6 policy manifest cannot authorize distribution")
    if full_c6_policy_manifest_document(receipt) != root:
        raise FullC6PolicyManifestError("Full C6 policy manifest content is not canonical")
    return receipt


def full_c6_policy_manifest_dialect(
    receipt: FullC6PolicyReceipt,
) -> ArtifactContractDialect:
    """Return the exact manifest dialect retained by a parsed receipt."""
    if type(receipt) is not FullC6PolicyReceipt:
        raise TypeError("Full C6 policy receipt has an invalid type")
    try:
        dialect = ARTIFACT_CONTRACT_DIALECTS[receipt._artifact_contract_dialect]
    except KeyError as exc:
        raise FullC6PolicyManifestError(
            "Full C6 policy receipt dialect is invalid"
        ) from exc
    return dialect


def load_full_c6_policy_manifest(
    path: Path,
    *,
    expected_sha256: str,
) -> FullC6PolicyReceipt:
    """Securely read and parse one pinned owner-authored policy manifest.

    Every path ancestor and the final regular file are descriptor-pinned and
    opened without following links.  The final file must have exactly one hard
    link and remain byte-identical for the duration of the read.
    """
    if not isinstance(path, Path):
        raise TypeError("Full C6 policy manifest path must be a pathlib.Path")
    try:
        locked = read_strict_owner_policy_lock(
            project_root=path.parent,
            filename=path.name,
            max_bytes=MAX_FULL_C6_POLICY_MANIFEST_BYTES,
        )
    except (OSError, TypeError, ValueError) as exc:
        raise FullC6PolicyManifestError("Full C6 policy manifest file is unsafe") from exc
    return parse_full_c6_policy_manifest(locked.data, expected_sha256=expected_sha256)


def _bounded_bytes(value: object) -> bytes:
    if type(value) is not bytes or not value or len(value) > MAX_FULL_C6_POLICY_MANIFEST_BYTES:
        raise FullC6PolicyManifestError("Full C6 policy manifest exceeds the byte bound")
    return value


def _parse_json(value: bytes) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise FullC6PolicyManifestError(
                    "Full C6 policy manifest contains a duplicate object key"
                )
            result[key] = item
        return result

    def reject_constant(_value: str) -> object:
        raise FullC6PolicyManifestError("Full C6 policy manifest contains non-finite JSON")

    try:
        parsed = json.loads(
            value.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except FullC6PolicyManifestError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise FullC6PolicyManifestError("Full C6 policy manifest is not valid JSON") from exc
    if type(parsed) is not dict:
        raise FullC6PolicyManifestError("Full C6 policy manifest root must be an object")
    _assert_json_depth(parsed, depth=0)
    return cast(dict[str, object], parsed)


def _assert_json_depth(value: object, *, depth: int) -> None:
    if depth > MAX_FULL_C6_POLICY_MANIFEST_JSON_DEPTH:
        raise FullC6PolicyManifestError("Full C6 policy manifest nesting is too deep")
    if type(value) is dict:
        for child in cast(dict[str, object], value).values():
            _assert_json_depth(child, depth=depth + 1)
    elif type(value) is list:
        for child in cast(list[object], value):
            _assert_json_depth(child, depth=depth + 1)


def _exact_dict(value: object, fields: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != fields:
        raise FullC6PolicyManifestError(f"Full C6 policy {label} schema is invalid")
    return cast(dict[str, object], value)


def _exact_list(value: object, label: str) -> list[object]:
    if type(value) is not list:
        raise FullC6PolicyManifestError(f"Full C6 policy {label} must be a JSON array")
    return cast(list[object], value)


def _string(value: object, label: str) -> str:
    if type(value) is not str:
        raise FullC6PolicyManifestError(f"Full C6 policy {label} must be a string")
    return value


def _optional_string(value: object, label: str) -> str | None:
    if value is None:
        return None
    return _string(value, label)


def _integer(value: object, label: str) -> int:
    if type(value) is not int:
        raise FullC6PolicyManifestError(f"Full C6 policy {label} must be an integer")
    return value


def _optional_integer(value: object, label: str) -> int | None:
    if value is None:
        return None
    return _integer(value, label)


def _boolean(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise FullC6PolicyManifestError(f"Full C6 policy {label} must be a boolean")
    return value


def _sha256(value: object, label: str) -> str:
    result = _string(value, label)
    if _SHA256.fullmatch(result) is None:
        raise FullC6PolicyManifestError(
            f"Full C6 policy {label} must be a lowercase SHA-256 digest"
        )
    return result


def _optional_digest(value: object, label: str) -> str | None:
    if value is None:
        return None
    return _sha256(value, label)


def _artifact_coverage(value: object) -> ArtifactPolicyCoverageInventory:
    data = _exact_dict(value, _ARTIFACT_COVERAGE_FIELDS, "artifact coverage")
    raw_classes = _exact_list(data["classes"], "artifact coverage classes")
    if len(raw_classes) != len(ARTIFACT_POLICY_COVERAGE_CLASS_IDS):
        raise FullC6PolicyManifestError("Full C6 artifact coverage class count is invalid")
    classes = tuple(_artifact_coverage_class(item) for item in raw_classes)
    if _integer(data["class_count"], "artifact coverage class count") != len(classes):
        raise FullC6PolicyManifestError("Full C6 artifact coverage class count is stale")
    return ArtifactPolicyCoverageInventory(
        classes=classes,
        observed_component_count=_integer(
            data["observed_component_count"], "artifact coverage observed count"
        ),
        canonical_partition_sha256=_sha256(
            data["canonical_partition_sha256"], "artifact coverage partition SHA-256"
        ),
        kind=_string(data["kind"], "artifact coverage kind"),
        schema_version=_integer(data["schema_version"], "artifact coverage schema version"),
        scope=_string(data["scope"], "artifact coverage scope"),
        identity_scheme=_string(data["identity_scheme"], "artifact coverage identity scheme"),
        authority=_string(data["authority"], "artifact coverage authority"),
        scope_complete=_boolean(data["scope_complete"], "artifact coverage scope-complete claim"),
        global_license_policy_complete=_boolean(
            data["global_license_policy_complete"], "artifact coverage license-complete claim"
        ),
        global_transformation_provenance_complete=_boolean(
            data["global_transformation_provenance_complete"],
            "artifact coverage transformation-complete claim",
        ),
        complete=_boolean(data["complete"], "artifact coverage complete claim"),
        signed=_boolean(data["signed"], "artifact coverage signed claim"),
        distribution_authorized=_boolean(
            data["distribution_authorized"], "artifact coverage distribution claim"
        ),
    )


def _artifact_coverage_class(value: object) -> ArtifactPolicyCoverageClass:
    data = _exact_dict(value, _ARTIFACT_COVERAGE_CLASS_FIELDS, "artifact coverage class")
    return ArtifactPolicyCoverageClass(
        class_id=_string(data["class_id"], "artifact coverage class id"),
        observed_count=_integer(data["observed_count"], "artifact coverage class count"),
        canonical_identity_set_sha256=_sha256(
            data["canonical_identity_set_sha256"], "artifact coverage identity-set SHA-256"
        ),
        identity_state=_string(data["identity_state"], "artifact coverage identity state"),
        license_policy_state=_string(
            data["license_policy_state"], "artifact coverage license state"
        ),
        license_policy_receipt_kind=_optional_string(
            data["license_policy_receipt_kind"], "artifact coverage license receipt kind"
        ),
        license_policy_receipt_sha256=_optional_digest(
            data["license_policy_receipt_sha256"], "artifact coverage license receipt SHA-256"
        ),
        transformation_provenance_state=_string(
            data["transformation_provenance_state"], "artifact coverage transformation state"
        ),
        transformation_provenance_receipt_kind=_optional_string(
            data["transformation_provenance_receipt_kind"],
            "artifact coverage transformation receipt kind",
        ),
        transformation_provenance_receipt_sha256=_optional_digest(
            data["transformation_provenance_receipt_sha256"],
            "artifact coverage transformation receipt SHA-256",
        ),
    )


def _external_authority(value: object) -> FullC6ExternalAuthorityPartition:
    data = _exact_dict(value, _EXTERNAL_AUTHORITY_FIELDS, "external authority")
    raw_classes = _exact_list(data["classes"], "external authority classes")
    if len(raw_classes) != len(FULL_C6_EXTERNAL_POLICY_CLASS_IDS):
        raise FullC6PolicyManifestError("Full C6 external authority class count is invalid")
    classes = tuple(_external_authority_class(item) for item in raw_classes)
    if _integer(data["class_count"], "external authority class count") != len(classes):
        raise FullC6PolicyManifestError("Full C6 external authority class count is stale")
    # Domain and scheme are derived fields on the typed partition.  Parse them
    # now; the final exact document comparison rejects any alternate values.
    _string(data["domain"], "external authority domain")
    _string(data["identity_scheme"], "external authority identity scheme")
    return FullC6ExternalAuthorityPartition(
        classes=classes,
        observed_component_count=_integer(
            data["observed_component_count"], "external authority observed count"
        ),
        canonical_partition_sha256=_sha256(
            data["canonical_partition_sha256"], "external authority partition SHA-256"
        ),
    )


def _external_authority_class(value: object) -> FullC6ExternalAuthorityClass:
    data = _exact_dict(value, _EXTERNAL_AUTHORITY_CLASS_FIELDS, "external authority class")
    return FullC6ExternalAuthorityClass(
        class_id=_string(data["class_id"], "external authority class id"),
        observed_count=_integer(data["observed_count"], "external authority class count"),
        canonical_identity_set_sha256=_sha256(
            data["canonical_identity_set_sha256"], "external authority identity-set SHA-256"
        ),
    )


def _rows(value: object) -> tuple[FullC6PolicyInputRow, ...]:
    values = _exact_list(value, "rows")
    if len(values) > MAX_FULL_C6_POLICY_ROWS:
        raise FullC6PolicyManifestError("Full C6 policy row count exceeds the bound")
    return tuple(_row(item) for item in values)


def _row(value: object) -> FullC6PolicyInputRow:
    data = _exact_dict(value, _ROW_FIELDS, "row")
    _sha256(data["canonical_identity_sha256"], "row canonical identity SHA-256")
    evidence_value = data["license_evidence"]
    return FullC6PolicyInputRow(
        class_id=_string(data["class_id"], "row class id"),
        canonical_identity=_string(data["canonical_identity"], "row canonical identity"),
        authority_identity=_string(data["authority_identity"], "row authority identity"),
        identity_mode=_string(data["identity_mode"], "row identity mode"),
        sha256=_optional_digest(data["sha256"], "row SHA-256"),
        size=_optional_integer(data["size"], "row size"),
        license_disposition=_string(data["license_disposition"], "row license disposition"),
        transformation_disposition=_string(
            data["transformation_disposition"], "row transformation disposition"
        ),
        license_evidence=(None if evidence_value is None else _license_evidence(evidence_value)),
    )


def _license_evidence(value: object) -> FullC6LicenseEvidence:
    data = _exact_dict(value, _LICENSE_EVIDENCE_FIELDS, "license evidence")
    _sha256(data["detector_receipt_sha256"], "license detector receipt SHA-256")
    _sha256(data["license_file_identity_set_sha256"], "license file-set SHA-256")
    raw_files = _exact_list(data["license_files"], "license evidence files")
    if not raw_files or len(raw_files) > MAX_FULL_C6_LICENSE_FILES_PER_ROW:
        raise FullC6PolicyManifestError("Full C6 policy license file count exceeds the bound")
    return FullC6LicenseEvidence(
        declared_spdx=_string(data["declared_spdx"], "declared SPDX"),
        detected_spdx=_string(data["detected_spdx"], "detected SPDX"),
        subject_authority_identity=_string(
            data["subject_authority_identity"], "license subject authority identity"
        ),
        subject_identity_sha256=_sha256(
            data["subject_identity_sha256"], "license subject identity SHA-256"
        ),
        authority_partition_sha256=_sha256(
            data["authority_partition_sha256"], "license authority partition SHA-256"
        ),
        source_detector_receipt_sha256=_sha256(
            data["source_detector_receipt_sha256"],
            "source license detector receipt SHA-256",
        ),
        detector_payload_sha256=_sha256(
            data["detector_payload_sha256"], "license detector payload SHA-256"
        ),
        license_files=tuple(_policy_file(item) for item in raw_files),
        detector_receipt_kind=_string(
            data["detector_receipt_kind"], "license detector receipt kind"
        ),
    )


def _policy_file(value: object) -> FullC6PolicyFileIdentity:
    data = _exact_dict(value, _POLICY_FILE_FIELDS, "license file")
    return FullC6PolicyFileIdentity(
        logical_path=_string(data["logical_path"], "license file path"),
        sha256=_sha256(data["sha256"], "license file SHA-256"),
        size=_integer(data["size"], "license file size"),
        role=_string(data["role"], "license file role"),
    )


def _transformations(value: object) -> tuple[FullC6TransformationRecord, ...]:
    values = _exact_list(value, "transformations")
    if len(values) > MAX_FULL_C6_POLICY_TRANSFORMATIONS:
        raise FullC6PolicyManifestError("Full C6 policy transformation count exceeds the bound")
    return tuple(_transformation(item) for item in values)


def _transformation(value: object) -> FullC6TransformationRecord:
    data = _exact_dict(value, _TRANSFORMATION_FIELDS, "transformation")
    raw_sources = _exact_list(data["sources"], "transformation sources")
    if not raw_sources or len(raw_sources) > MAX_FULL_C6_POLICY_SOURCES_PER_TRANSFORMATION:
        raise FullC6PolicyManifestError("Full C6 transformation source count exceeds the bound")
    source_values = tuple(
        _transformation_identity(item, label="transformation source")
        for item in raw_sources
    )
    output_identity, output_sha256 = _transformation_identity(
        data["output"], label="transformation output"
    )
    return FullC6TransformationRecord(
        record_id=_string(data["record_id"], "transformation record id"),
        kind=_string(data["kind"], "transformation kind"),
        source_identities=tuple(item[0] for item in source_values),
        source_identity_sha256s=tuple(item[1] for item in source_values),
        output_identity=output_identity,
        output_identity_sha256=output_sha256,
        authority_partition_sha256=_sha256(
            data["authority_partition_sha256"], "transformation authority partition SHA-256"
        ),
        source_identity_set_sha256=_sha256(
            data["source_identity_set_sha256"], "transformation source-set SHA-256"
        ),
        generator_sha256=_sha256(data["generator_sha256"], "transformation generator SHA-256"),
        analysis_sha256=_sha256(data["analysis_sha256"], "transformation analysis SHA-256"),
        analysis_receipt_sha256=_sha256(
            data["analysis_receipt_sha256"], "transformation analysis receipt SHA-256"
        ),
        lowered_ir_sha256=_sha256(
            data["lowered_ir_sha256"], "transformation lowered IR SHA-256"
        ),
        lowered_ir_receipt_sha256=_sha256(
            data["lowered_ir_receipt_sha256"], "transformation lowered IR receipt SHA-256"
        ),
        analysis_receipt_kind=_string(
            data["analysis_receipt_kind"], "transformation analysis receipt kind"
        ),
        lowered_ir_receipt_kind=_string(
            data["lowered_ir_receipt_kind"], "transformation lowered IR receipt kind"
        ),
    )


def _transformation_identity(value: object, *, label: str) -> tuple[str, str]:
    data = _exact_dict(value, _TRANSFORMATION_IDENTITY_FIELDS, label)
    return (
        _string(data["canonical_identity"], f"{label} identity"),
        _sha256(data["canonical_identity_sha256"], f"{label} identity SHA-256"),
    )


def _owner(value: object) -> FullC6OwnerDeclaration:
    data = _exact_dict(value, _OWNER_FIELDS, "owner declaration")
    return FullC6OwnerDeclaration(
        owner_identity=_string(data["owner_identity"], "owner identity"),
        owner_role=_string(data["owner_role"], "owner role"),
        trusted_public_key_sha256=_sha256(
            data["trusted_public_key_sha256"], "trusted public-key SHA-256"
        ),
        decision=_string(data["decision"], "owner decision"),
        action_scopes=tuple(
            _string(item, "owner action scope")
            for item in _exact_list(data["action_scopes"], "owner action scopes")
        ),
        acknowledgement=_string(data["acknowledgement"], "owner acknowledgement"),
        authentication=_string(data["authentication"], "owner authentication"),
    )


def parse_full_c6_artifact_coverage_document(
    value: object,
) -> ArtifactPolicyCoverageInventory:
    """Parse one exact public C6.14 coverage document."""
    return _artifact_coverage(value)


def parse_full_c6_external_authority_document(
    value: object,
) -> FullC6ExternalAuthorityPartition:
    """Parse one exact public C5.2 authority-partition document."""
    return _external_authority(value)


def parse_full_c6_transformation_document(
    value: object,
) -> FullC6TransformationRecord:
    """Parse one exact public technical transformation record."""
    return _transformation(value)


def parse_full_c6_owner_declaration_document(
    value: object,
) -> FullC6OwnerDeclaration:
    """Parse one exact explicit owner declaration document."""
    return _owner(value)


def _reconstruct_receipt(receipt: FullC6PolicyReceipt) -> FullC6PolicyReceipt:
    if type(receipt) is not FullC6PolicyReceipt:
        raise TypeError("Full C6 policy receipt has an invalid type")
    try:
        rebuilt = FullC6PolicyReceipt(
            rows=tuple(receipt.rows),
            transformations=tuple(receipt.transformations),
            owner_declaration=receipt.owner_declaration,
            artifact_coverage=receipt.artifact_coverage,
            external_authority=receipt.external_authority,
            bootstrap_request_sha256=receipt.bootstrap_request_sha256,
        )
        object.__setattr__(
            rebuilt,
            "_artifact_contract_dialect",
            receipt._artifact_contract_dialect,
        )
        return rebuilt
    except (TypeError, ValueError) as exc:
        raise FullC6PolicyManifestError("Full C6 policy receipt cannot be reconstructed") from exc


__all__ = [
    "FULL_C6_POLICY_MANIFEST_DOMAIN",
    "FULL_C6_POLICY_MANIFEST_FILENAME",
    "FULL_C6_POLICY_MANIFEST_KIND",
    "FULL_C6_POLICY_MANIFEST_SCHEMA_VERSION",
    "FullC6PolicyManifestError",
    "MAX_FULL_C6_POLICY_MANIFEST_BYTES",
    "full_c6_policy_manifest_bytes",
    "full_c6_policy_manifest_dialect",
    "full_c6_policy_manifest_document",
    "load_full_c6_policy_manifest",
    "parse_full_c6_policy_manifest",
    "parse_full_c6_artifact_coverage_document",
    "parse_full_c6_external_authority_document",
    "parse_full_c6_owner_declaration_document",
    "parse_full_c6_transformation_document",
]
