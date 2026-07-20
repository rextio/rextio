"""Bounded C6.12 owner policy for one exact C6.10 source/output scope."""

from __future__ import annotations

from pathlib import Path

from rextio.artifacts.evidence import (
    MAX_PROJECT_SOURCE_LICENSE_LOCK_BYTES,
    PROJECT_SOURCE_LICENSE_POLICY,
    PROJECT_SOURCE_LICENSE_POLICY_ACKNOWLEDGEMENT,
    PROJECT_SOURCE_LICENSE_POLICY_ACTION_SCOPES,
    PROJECT_SOURCE_LICENSE_POLICY_LOCK_FILENAME,
    PROJECT_SOURCE_LICENSE_POLICY_LOCK_KIND,
    PROJECT_SOURCE_LICENSE_POLICY_LOCK_ROLE,
    PROJECT_SOURCE_LICENSE_POLICY_LOCK_SCHEMA_VERSION,
    PROJECT_SOURCE_LICENSE_POLICY_VERIFICATION_SCOPE,
    EvidenceFileRef,
    ProjectSourceLicensePolicyVerification,
    SourceTransformationVerification,
    canonical_json_bytes,
    sha256_hex,
)
from rextio.build.owner_policy_lock import read_strict_owner_policy_lock


def collect_project_source_license_policy_verification(
    *,
    project_root: Path,
    source_transformation_verification: SourceTransformationVerification,
) -> ProjectSourceLicensePolicyVerification | None:
    """Verify one exact owner lock, returning ``None`` on every failure."""
    try:
        return _collect_project_source_license_policy_verification(
            project_root=project_root,
            source_transformation_verification=source_transformation_verification,
        )
    except Exception:
        # This is an optional scoped observation. It must not perturb the
        # ordinary build or any independently configured evidence gate.
        return None


def _collect_project_source_license_policy_verification(
    *,
    project_root: Path,
    source_transformation_verification: SourceTransformationVerification,
) -> ProjectSourceLicensePolicyVerification:
    verification = _reconstruct_transformation_verification(source_transformation_verification)
    verification_digest = sha256_hex(canonical_json_bytes(verification.to_dict()))
    lock_receipt = read_strict_owner_policy_lock(
        project_root=project_root,
        filename=PROJECT_SOURCE_LICENSE_POLICY_LOCK_FILENAME,
        max_bytes=MAX_PROJECT_SOURCE_LICENSE_LOCK_BYTES,
    )
    document = lock_receipt.document
    declarations, attestation = _verify_lock_document(
        document=document,
        verification=verification,
        verification_digest=verification_digest,
    )
    receipt = ProjectSourceLicensePolicyVerification(
        source_transformation_verification_sha256=verification_digest,
        source_input_set_sha256=verification.source_input_set_sha256,
        source_inputs=verification.source_inputs,
        generated_rust=verification.generated_rust,
        lock_file=EvidenceFileRef(
            logical_path=PROJECT_SOURCE_LICENSE_POLICY_LOCK_FILENAME,
            sha256=lock_receipt.sha256,
            size=len(lock_receipt.data),
            role=PROJECT_SOURCE_LICENSE_POLICY_LOCK_ROLE,
        ),
        policy_snapshot_sha256=sha256_hex(canonical_json_bytes(document)),
        project_source_license_declared=declarations["project_sources"],
        generated_rust_license_declared=declarations["generated_rust"],
        attestor=attestation["attestor"],
        attestor_kind=attestation["attestor_kind"],
        attestor_relationship=attestation["attestor_relationship"],
    )
    if receipt.policy_document() != document:
        raise ValueError("project source license policy document is noncanonical")
    return receipt


def _reconstruct_transformation_verification(
    value: SourceTransformationVerification,
) -> SourceTransformationVerification:
    """Re-run the closed C6.10 model invariants before trusting its digest."""
    if type(value) is not SourceTransformationVerification:
        raise TypeError("project source license policy requires a C6.10 receipt")
    if type(value.function_qualnames) is not tuple or type(value.source_inputs) is not tuple:
        raise TypeError("project source license policy C6.10 collections are invalid")
    rebuilt = SourceTransformationVerification(
        source_transformation_inventory_sha256=(value.source_transformation_inventory_sha256),
        source_input_set_sha256=value.source_input_set_sha256,
        module_ir_sha256=value.module_ir_sha256,
        function_qualnames=tuple(value.function_qualnames),
        source_inputs=tuple(_copy_file_ref(item) for item in value.source_inputs),
        generated_rust=_copy_file_ref(value.generated_rust),
        regenerated_rust_sha256=value.regenerated_rust_sha256,
        regenerated_rust_size=value.regenerated_rust_size,
        generator_backend=value.generator_backend,
        kind=value.kind,
        schema_version=value.schema_version,
        scope=value.scope,
        complete_for_scope=value.complete_for_scope,
        global_provenance_complete=value.global_provenance_complete,
        complete=value.complete,
        authority=value.authority,
    )
    if rebuilt != value:
        raise ValueError("project source license policy C6.10 receipt is noncanonical")
    return rebuilt


def _copy_file_ref(value: EvidenceFileRef) -> EvidenceFileRef:
    if type(value) is not EvidenceFileRef:
        raise TypeError("project source license policy file binding is invalid")
    return EvidenceFileRef(
        logical_path=value.logical_path,
        sha256=value.sha256,
        size=value.size,
        role=value.role,
    )


def _verify_lock_document(
    *,
    document: object,
    verification: SourceTransformationVerification,
    verification_digest: str,
) -> tuple[dict[str, str], dict[str, str]]:
    if not isinstance(document, dict):
        raise ValueError("project source license policy lock root is invalid")
    _require_exact_keys(
        document,
        {
            "schema_version",
            "kind",
            "scope",
            "policy",
            "source_transformation_verification_sha256",
            "source_input_set_sha256",
            "project_sources",
            "generated_rust",
            "license_declarations",
            "attestation",
        },
    )
    if (
        document["schema_version"] != PROJECT_SOURCE_LICENSE_POLICY_LOCK_SCHEMA_VERSION
        or document["kind"] != PROJECT_SOURCE_LICENSE_POLICY_LOCK_KIND
        or document["scope"] != PROJECT_SOURCE_LICENSE_POLICY_VERIFICATION_SCOPE
        or document["policy"] != PROJECT_SOURCE_LICENSE_POLICY
        or document["source_transformation_verification_sha256"] != verification_digest
        or document["source_input_set_sha256"] != verification.source_input_set_sha256
    ):
        raise ValueError("project source license policy lock identity is stale")
    if document["project_sources"] != [item.to_dict() for item in verification.source_inputs]:
        raise ValueError("project source license policy source records are stale")
    if document["generated_rust"] != verification.generated_rust.to_dict():
        raise ValueError("project source license policy Rust record is stale")

    raw_declarations = document["license_declarations"]
    if not isinstance(raw_declarations, dict):
        raise ValueError("project source license declarations are invalid")
    _require_exact_keys(raw_declarations, {"project_sources", "generated_rust"})
    if any(type(raw_declarations[field]) is not str for field in raw_declarations):
        raise TypeError("project source license declaration must be a string")

    raw_attestation = document["attestation"]
    if not isinstance(raw_attestation, dict):
        raise ValueError("project source license policy attestation is invalid")
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
            raise TypeError("project source license policy attestation is invalid")
    if raw_attestation["decision"] != "allow":
        raise ValueError("project source license policy decision is invalid")
    if raw_attestation["action_scopes"] != list(PROJECT_SOURCE_LICENSE_POLICY_ACTION_SCOPES):
        raise ValueError("project source license policy scopes are invalid")
    if raw_attestation["acknowledgement"] != PROJECT_SOURCE_LICENSE_POLICY_ACKNOWLEDGEMENT:
        raise ValueError("project source license policy acknowledgement is invalid")
    return (
        {
            "project_sources": raw_declarations["project_sources"],
            "generated_rust": raw_declarations["generated_rust"],
        },
        {
            "attestor": raw_attestation["attestor"],
            "attestor_kind": raw_attestation["attestor_kind"],
            "attestor_relationship": raw_attestation["attestor_relationship"],
        },
    )


def _require_exact_keys(value: dict[str, object], expected: set[str]) -> None:
    if set(value) != expected:
        raise ValueError("project source license policy lock keys are invalid")


__all__ = ["collect_project_source_license_policy_verification"]
