"""Bounded C6.11 verification of one project-owned Cargo license lock."""

from __future__ import annotations

import os
from pathlib import Path

from rextio.artifacts.evidence import (
    CARGO_LICENSE_POLICY,
    CARGO_LICENSE_POLICY_ACKNOWLEDGEMENT,
    CARGO_LICENSE_POLICY_ACTION_SCOPES,
    CARGO_LICENSE_POLICY_LOCK_FILENAME,
    CARGO_LICENSE_POLICY_LOCK_KIND,
    CARGO_LICENSE_POLICY_LOCK_ROLE,
    CARGO_LICENSE_POLICY_LOCK_SCHEMA_VERSION,
    COMPONENT_LICENSE_POLICY_VERIFICATION_SCOPE,
    MAX_CARGO_LICENSE_LOCK_BYTES,
    ComponentLicenseInventory,
    ComponentLicensePolicyVerification,
    ComponentLicenseRecord,
    EvidenceFileRef,
    cargo_license_metadata_is_unknown,
    canonical_json_bytes,
    sha256_hex,
)
from rextio.build.owner_policy_lock import read_strict_owner_policy_lock


def collect_component_license_policy_verification(
    *,
    project_root: Path,
    component_license_inventory: ComponentLicenseInventory,
) -> ComponentLicensePolicyVerification | None:
    """Verify the exact scoped owner lock, returning ``None`` on any failure."""
    try:
        return _collect_component_license_policy_verification(
            project_root=project_root,
            component_license_inventory=component_license_inventory,
        )
    except Exception:
        # C6.11 is an additive observation. Lock failures never perturb an
        # ordinary build or the independently configured C6.3 evidence gate.
        return None


def _collect_component_license_policy_verification(
    *,
    project_root: Path,
    component_license_inventory: ComponentLicenseInventory,
) -> ComponentLicensePolicyVerification:
    if type(component_license_inventory) is not ComponentLicenseInventory:
        raise TypeError("Cargo license policy inventory is invalid")
    registry_records = tuple(
        record for record in component_license_inventory.records if record.kind == "registry"
    )
    if not registry_records:
        raise ValueError("Cargo license policy requires registry components")
    if not all(type(record) is ComponentLicenseRecord for record in registry_records):
        raise TypeError("Cargo license policy record is invalid")
    if any(
        record.license_observed is None
        or record.license_observation != "declared-unvalidated"
        or cargo_license_metadata_is_unknown(record.license_observed)
        for record in registry_records
    ):
        raise ValueError("Cargo license policy contains an unknown license")

    inventory_digest = sha256_hex(canonical_json_bytes(component_license_inventory.to_dict()))
    root = Path(os.path.abspath(project_root))
    lock_receipt = read_strict_owner_policy_lock(
        project_root=root,
        filename=CARGO_LICENSE_POLICY_LOCK_FILENAME,
        max_bytes=MAX_CARGO_LICENSE_LOCK_BYTES,
    )
    document = lock_receipt.document
    attestation = _verify_lock_document(
        document=document,
        inventory_digest=inventory_digest,
        registry_records=registry_records,
    )
    lock_ref = EvidenceFileRef(
        logical_path=CARGO_LICENSE_POLICY_LOCK_FILENAME,
        sha256=lock_receipt.sha256,
        size=len(lock_receipt.data),
        role=CARGO_LICENSE_POLICY_LOCK_ROLE,
    )
    return ComponentLicensePolicyVerification(
        component_license_inventory_sha256=inventory_digest,
        lock_file=lock_ref,
        policy_snapshot_sha256=sha256_hex(canonical_json_bytes(document)),
        registry_component_bom_refs=tuple(record.bom_ref for record in registry_records),
        attestor=attestation["attestor"],
        attestor_kind=attestation["attestor_kind"],
        attestor_relationship=attestation["attestor_relationship"],
    )


def _verify_lock_document(
    *,
    document: object,
    inventory_digest: str,
    registry_records: tuple[ComponentLicenseRecord, ...],
) -> dict[str, str]:
    if not isinstance(document, dict):
        raise ValueError("Cargo license policy lock root is invalid")
    _require_exact_keys(
        document,
        {
            "schema_version",
            "kind",
            "scope",
            "policy",
            "component_license_inventory_sha256",
            "registry_components",
            "attestation",
        },
    )
    if (
        document["schema_version"] != CARGO_LICENSE_POLICY_LOCK_SCHEMA_VERSION
        or document["kind"] != CARGO_LICENSE_POLICY_LOCK_KIND
        or document["scope"] != COMPONENT_LICENSE_POLICY_VERIFICATION_SCOPE
        or document["policy"] != CARGO_LICENSE_POLICY
        or document["component_license_inventory_sha256"] != inventory_digest
    ):
        raise ValueError("Cargo license policy lock identity is stale")
    expected_records = [record.to_dict() for record in registry_records]
    if document["registry_components"] != expected_records:
        raise ValueError("Cargo license policy registry records are stale")

    raw_attestation = document["attestation"]
    if not isinstance(raw_attestation, dict):
        raise ValueError("Cargo license policy attestation is invalid")
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
            raise TypeError("Cargo license policy attestation string is invalid")
    if raw_attestation["decision"] != "allow":
        raise ValueError("Cargo license policy decision is not allow")
    if raw_attestation["action_scopes"] != list(CARGO_LICENSE_POLICY_ACTION_SCOPES):
        raise ValueError("Cargo license policy scopes are invalid")
    if raw_attestation["acknowledgement"] != CARGO_LICENSE_POLICY_ACKNOWLEDGEMENT:
        raise ValueError("Cargo license policy acknowledgement is invalid")
    return {
        "attestor": raw_attestation["attestor"],
        "attestor_kind": raw_attestation["attestor_kind"],
        "attestor_relationship": raw_attestation["attestor_relationship"],
    }


def _require_exact_keys(value: dict[str, object], expected: set[str]) -> None:
    if set(value) != expected:
        raise ValueError("Cargo license policy lock keys are invalid")


__all__ = ["collect_component_license_policy_verification"]
