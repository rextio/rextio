"""Bounded C6.15 verification of one exact artifact-class policy lock."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
import unicodedata

from rextio.artifacts.evidence import (
    ARTIFACT_CLASS_POLICY,
    ARTIFACT_CLASS_POLICY_ACKNOWLEDGEMENT,
    ARTIFACT_CLASS_POLICY_ACTION_SCOPES,
    ARTIFACT_CLASS_POLICY_LOCK_FILENAME,
    ARTIFACT_CLASS_POLICY_LOCK_KIND,
    ARTIFACT_CLASS_POLICY_LOCK_ROLE,
    ARTIFACT_CLASS_POLICY_LOCK_SCHEMA_VERSION,
    ARTIFACT_EVIDENCE_SCOPE,
    ARTIFACT_POLICY_COVERAGE_CLASS_IDS,
    MAX_ARTIFACT_CLASS_POLICY_LOCK_BYTES,
    MAX_EVIDENCE_COMPONENTS,
    MAX_EVIDENCE_STRING_CHARS,
    ArtifactClassPolicyDeclaration,
    ArtifactClassPolicyVerification,
    ArtifactPolicyCoverageClass,
    ArtifactPolicyCoverageInventory,
    EvidenceFileRef,
    artifact_policy_coverage_inventory_digest,
    canonical_json_bytes,
    sha256_hex,
)
from rextio.build.owner_policy_lock import read_strict_owner_policy_lock


_COVERAGE_KEYS = {
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


def collect_artifact_class_policy_verification(
    *,
    project_root: Path,
    artifact_policy_coverage_inventory: ArtifactPolicyCoverageInventory,
    occupied_logical_paths: Sequence[str] = (),
) -> ArtifactClassPolicyVerification | None:
    """Return an exact C6.15 receipt, or omit it on any unsafe mismatch."""
    try:
        coverage_digest = artifact_policy_coverage_inventory_digest(
            artifact_policy_coverage_inventory
        )
        _reject_lock_path_aliases(occupied_logical_paths)
        lock = read_strict_owner_policy_lock(
            project_root=project_root,
            filename=ARTIFACT_CLASS_POLICY_LOCK_FILENAME,
            max_bytes=MAX_ARTIFACT_CLASS_POLICY_LOCK_BYTES,
        )
        classes, attestation = _verify_lock_document(
            document=lock.document,
            inventory=artifact_policy_coverage_inventory,
            coverage_digest=coverage_digest,
        )
        policy_snapshot_sha256 = sha256_hex(canonical_json_bytes(lock.document))
        return ArtifactClassPolicyVerification(
            artifact_policy_coverage_inventory_sha256=coverage_digest,
            canonical_partition_sha256=(
                artifact_policy_coverage_inventory.canonical_partition_sha256
            ),
            classes=classes,
            lock_file=EvidenceFileRef(
                logical_path=ARTIFACT_CLASS_POLICY_LOCK_FILENAME,
                sha256=lock.sha256,
                size=len(lock.data),
                role=ARTIFACT_CLASS_POLICY_LOCK_ROLE,
            ),
            policy_snapshot_sha256=policy_snapshot_sha256,
            attestor=attestation["attestor"],
            attestor_kind=attestation["attestor_kind"],
            attestor_relationship=attestation["attestor_relationship"],
        )
    except Exception:
        return None


def _reject_lock_path_aliases(paths: Sequence[str]) -> None:
    if type(paths) not in {tuple, list} or len(paths) > MAX_EVIDENCE_COMPONENTS:
        raise ValueError("artifact class policy occupied paths exceed the bound")
    lock_key = unicodedata.normalize("NFC", ARTIFACT_CLASS_POLICY_LOCK_FILENAME).casefold()
    seen: set[str] = set()
    for path in paths:
        if (
            type(path) is not str
            or not path
            or len(path) > MAX_EVIDENCE_STRING_CHARS
            or any(ord(character) < 32 for character in path)
        ):
            raise ValueError("artifact class policy occupied path is invalid")
        key = unicodedata.normalize("NFC", path).casefold()
        if key in seen:
            raise ValueError("artifact class policy occupied paths contain aliases")
        seen.add(key)
    if lock_key in seen:
        raise ValueError("artifact class policy lock aliases an existing material")


def _verify_lock_document(
    *,
    document: object,
    inventory: ArtifactPolicyCoverageInventory,
    coverage_digest: str,
) -> tuple[tuple[ArtifactClassPolicyDeclaration, ...], dict[str, str]]:
    if type(document) is not dict:
        raise ValueError("artifact class policy lock root is invalid")
    _require_exact_keys(
        document,
        {
            "schema_version",
            "kind",
            "scope",
            "policy",
            "artifact_policy_coverage_inventory_sha256",
            "canonical_partition_sha256",
            "classes",
            "attestation",
        },
    )
    fixed_strings = {
        "schema_version": ARTIFACT_CLASS_POLICY_LOCK_SCHEMA_VERSION,
        "kind": ARTIFACT_CLASS_POLICY_LOCK_KIND,
        "scope": ARTIFACT_EVIDENCE_SCOPE,
        "policy": ARTIFACT_CLASS_POLICY,
        "artifact_policy_coverage_inventory_sha256": coverage_digest,
        "canonical_partition_sha256": inventory.canonical_partition_sha256,
    }
    for field, expected in fixed_strings.items():
        value = document[field]
        if type(value) is not str or value != expected:
            raise ValueError("artifact class policy lock identity is stale")

    raw_classes = document["classes"]
    if type(raw_classes) is not list or len(raw_classes) != len(
        ARTIFACT_POLICY_COVERAGE_CLASS_IDS
    ):
        raise ValueError("artifact class policy rows are incomplete")
    declarations: list[ArtifactClassPolicyDeclaration] = []
    for index, raw in enumerate(raw_classes):
        if type(raw) is not dict:
            raise TypeError("artifact class policy row is invalid")
        _require_exact_keys(
            raw,
            {
                "coverage",
                "license_policy_disposition",
                "transformation_provenance_disposition",
            },
        )
        coverage = _parse_coverage_row(raw["coverage"])
        if coverage != inventory.classes[index]:
            raise ValueError("artifact class policy coverage row is stale or reordered")
        license_disposition = raw["license_policy_disposition"]
        transformation_disposition = raw["transformation_provenance_disposition"]
        if type(license_disposition) is not str or type(transformation_disposition) is not str:
            raise TypeError("artifact class policy disposition must be a string")
        declarations.append(
            ArtifactClassPolicyDeclaration(
                coverage=coverage,
                license_policy_disposition=license_disposition,
                transformation_provenance_disposition=transformation_disposition,
            )
        )
    classes = tuple(declarations)
    if tuple(item.coverage.class_id for item in classes) != ARTIFACT_POLICY_COVERAGE_CLASS_IDS:
        raise ValueError("artifact class policy rows are not canonically ordered")

    raw_attestation = document["attestation"]
    if type(raw_attestation) is not dict:
        raise ValueError("artifact class policy attestation is invalid")
    _require_exact_keys(
        raw_attestation,
        {
            "attestor",
            "attestor_kind",
            "attestor_relationship",
            "decision",
            "action_scopes",
            "acknowledgement",
        },
    )
    for field in ("attestor", "attestor_kind", "attestor_relationship"):
        if type(raw_attestation[field]) is not str:
            raise TypeError("artifact class policy attestation is invalid")
    if (
        type(raw_attestation["decision"]) is not str
        or raw_attestation["decision"] != "allow"
        or type(raw_attestation["action_scopes"]) is not list
        or raw_attestation["action_scopes"]
        != list(ARTIFACT_CLASS_POLICY_ACTION_SCOPES)
        or type(raw_attestation["acknowledgement"]) is not str
        or raw_attestation["acknowledgement"]
        != ARTIFACT_CLASS_POLICY_ACKNOWLEDGEMENT
    ):
        raise ValueError("artifact class policy attestation is invalid")
    return (
        classes,
        {
            "attestor": raw_attestation["attestor"],
            "attestor_kind": raw_attestation["attestor_kind"],
            "attestor_relationship": raw_attestation["attestor_relationship"],
        },
    )


def _parse_coverage_row(value: object) -> ArtifactPolicyCoverageClass:
    if type(value) is not dict:
        raise TypeError("artifact class policy coverage row is invalid")
    _require_exact_keys(value, _COVERAGE_KEYS)
    for field in (
        "class_id",
        "canonical_identity_set_sha256",
        "identity_state",
        "license_policy_state",
        "transformation_provenance_state",
    ):
        if type(value[field]) is not str:
            raise TypeError("artifact class policy coverage string is invalid")
    if type(value["observed_count"]) is not int or isinstance(
        value["observed_count"], bool
    ):
        raise TypeError("artifact class policy coverage count is invalid")
    for field in (
        "license_policy_receipt_kind",
        "license_policy_receipt_sha256",
        "transformation_provenance_receipt_kind",
        "transformation_provenance_receipt_sha256",
    ):
        if value[field] is not None and type(value[field]) is not str:
            raise TypeError("artifact class policy receipt binding is invalid")
    return ArtifactPolicyCoverageClass(
        class_id=value["class_id"],
        observed_count=value["observed_count"],
        canonical_identity_set_sha256=value["canonical_identity_set_sha256"],
        identity_state=value["identity_state"],
        license_policy_state=value["license_policy_state"],
        license_policy_receipt_kind=value["license_policy_receipt_kind"],
        license_policy_receipt_sha256=value["license_policy_receipt_sha256"],
        transformation_provenance_state=value["transformation_provenance_state"],
        transformation_provenance_receipt_kind=(
            value["transformation_provenance_receipt_kind"]
        ),
        transformation_provenance_receipt_sha256=(
            value["transformation_provenance_receipt_sha256"]
        ),
    )


def _require_exact_keys(value: dict[str, object], expected: set[str]) -> None:
    if set(value) != expected:
        raise ValueError("artifact class policy lock keys are invalid")


__all__ = ["collect_artifact_class_policy_verification"]
