"""Final non-circular Full C6 distribution-authorization hard gate.

This is the only module which mints a positive
``FullC6DistributionAuthorization``.  It rebuilds the complete frozen receipt
graph, requires a same-transaction SourceLock v2 verified context, validates
the exact subject bytes, checks the detached owner signature over the unsigned
evidence digest, revalidates the subject after that check, and only then emits
final evidence and authorization.

The gate supports exactly macOS AArch64 and Linux x86-64 host-extension wheels
with one depth-1 pure-Python external source wheel and no plugins.  It does not
promote any C6 preview evidence or broaden that scope.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import os
from pathlib import Path
import stat

from rextio.artifacts.evidence import EvidenceFileRef, WheelEntryRef, canonical_json_bytes
from rextio.artifacts.full_authorization import (
    FULL_C6_AUTHORIZATION_CHECK_IDS,
    FULL_C6_PREAUTHORIZATION_RECEIPT_IDS,
    FULL_C6_SCOPE,
    FullC6ArtifactEvidence,
    FullC6DistributionAuthorization,
    FullC6EvidenceReceipt,
    FullC6PreauthorizationEvidence,
    FullC6AuthorizationCheck,
    _reconstruct_full_c6_evidence,
    full_c6_evidence_digest,
    full_c6_preauthorization_evidence_digest,
)
from rextio.build.full_c6_policy import FullC6PolicyReceipt
from rextio.build.full_c6_supply_chain import (
    FullC6CargoPathSource,
    FullC6SupplyChainReceipt,
    build_full_c6_supply_chain_receipt,
    verify_full_c6_supply_chain_receipt,
)
from rextio.build.input_closure import (
    BuildInputClosure,
    BuildInputIdentityError,
    capture_exact_file,
    capture_exact_file_bytes,
)
from rextio.build.reproducibility import ReproducibilityReceipt
from rextio.build.runtime_authorization import RuntimeAuthorizationReceipt
from rextio.build.signing import (
    MAX_SIGNATURE_ENVELOPE_BYTES,
    DetachedSignatureEnvelope,
    FinalAuthorizationRequest,
    SignatureVerificationError,
    SignatureVerificationReceipt,
    parse_detached_signature_envelope,
    verify_detached_authorization_signature,
)
from rextio.build.toolchain_identity import BuildToolchainIdentity
from rextio.source.source_lock_v2 import (
    SourceLockV2Admission,
    SourceLockV2Manifest,
    SourceLockV2Verification,
    SourceLockV2VerifiedContext,
)


FULL_C6_EXTERNAL_ARCHIVE_RECEIPT_DOMAIN = (
    "rextio.full-c6-external-source-archive-bound.v1"
)
FULL_C6_SOURCE_LOCK_RECEIPT_DOMAIN = "rextio.full-c6-source-lock-verified.v1"
FULL_C6_FINAL_OUTPUT_RECEIPT_DOMAIN = "rextio.full-c6-final-output-revalidated.v1"
MAX_FULL_C6_PUBLIC_KEY_BYTES = 32


class FullC6GateError(RuntimeError):
    """The final Full C6 authorization graph failed closed."""


@dataclass(frozen=True, slots=True)
class FullC6GateResult:
    """The exact records emitted by one successful hard-gate transaction."""

    preauthorization_evidence: FullC6PreauthorizationEvidence
    signature_receipt: SignatureVerificationReceipt
    evidence: FullC6ArtifactEvidence
    authorization: FullC6DistributionAuthorization

    def __post_init__(self) -> None:
        if type(self.preauthorization_evidence) is not FullC6PreauthorizationEvidence:
            raise TypeError("Full C6 gate result preauthorization evidence is invalid")
        if type(self.signature_receipt) is not SignatureVerificationReceipt:
            raise TypeError("Full C6 gate result signature receipt is invalid")
        if type(self.evidence) is not FullC6ArtifactEvidence:
            raise TypeError("Full C6 gate result evidence is invalid")
        if type(self.authorization) is not FullC6DistributionAuthorization:
            raise TypeError("Full C6 gate result authorization is invalid")
        preauthorization_sha256 = full_c6_preauthorization_evidence_digest(
            self.preauthorization_evidence
        )
        if (
            self.evidence.preauthorization_evidence_sha256 != preauthorization_sha256
            or self.authorization.preauthorization_evidence_sha256
            != preauthorization_sha256
            or self.authorization.evidence_sha256 != full_c6_evidence_digest(self.evidence)
            or self.signature_receipt.public_key_sha256
            != self.evidence.trusted_public_key_sha256
        ):
            raise ValueError("Full C6 gate result bindings are inconsistent")


def prepare_full_c6_preauthorization_evidence(
    *,
    target_triple: str,
    subject_path: Path | str,
    subject: EvidenceFileRef,
    build_inputs: BuildInputClosure,
    wheel_entries: tuple[WheelEntryRef, ...],
    policy: FullC6PolicyReceipt,
    source_verification: SourceLockV2Verification,
    toolchain: BuildToolchainIdentity,
    cargo_path_source: FullC6CargoPathSource,
    runtime_authorization: RuntimeAuthorizationReceipt,
    reproducibility: ReproducibilityReceipt,
    supply_chain: FullC6SupplyChainReceipt,
    expected_public_key_sha256: str,
) -> FullC6PreauthorizationEvidence:
    """Rebuild the exact pre-signing graph and return its safe-to-sign record."""
    try:
        trusted_context = _rebuild_source_verification(source_verification)
        source_lock = trusted_context.manifest
        source_admission = trusted_context.admission
        _require_owner_key_bindings(
            policy=policy,
            source_context=trusted_context,
            expected_public_key_sha256=expected_public_key_sha256,
        )
        _revalidate_subject(subject_path, subject)
        fresh_supply_chain = build_full_c6_supply_chain_receipt(
            target_triple=target_triple,
            subject=subject,
            build_inputs=build_inputs,
            wheel_entries=wheel_entries,
            policy=policy,
            source_lock=source_lock,
            source_admission=source_admission,
            toolchain=toolchain,
            cargo_path_source=cargo_path_source,
            runtime_authorization=runtime_authorization,
            reproducibility=reproducibility,
        )
        trusted_supply_chain = verify_full_c6_supply_chain_receipt(supply_chain)
        if fresh_supply_chain != trusted_supply_chain:
            raise FullC6GateError("Full C6 supply-chain receipt is stale or replayed")
        if (
            target_triple != trusted_supply_chain.target_triple
            or subject != trusted_supply_chain.subject
            or source_lock.package != trusted_context.plan.package
            or source_lock.distribution != trusted_context.plan.distribution
            or source_lock.version != trusted_context.plan.requested_version
        ):
            raise FullC6GateError("Full C6 target, subject, or external project is stale")

        archive = EvidenceFileRef(
            logical_path=f"external/{source_lock.archive.filename}",
            sha256=source_lock.archive.sha256,
            size=source_lock.archive.size,
            role="external-source-wheel-archive",
        )
        receipts = _preauthorization_receipts(
            source_lock=source_lock,
            source_admission=source_admission,
            policy=policy,
            build_inputs=build_inputs,
            toolchain=toolchain,
            runtime_authorization=runtime_authorization,
            reproducibility=reproducibility,
            supply_chain=trusted_supply_chain,
        )
        return FullC6PreauthorizationEvidence(
            target_triple=target_triple,
            subject=subject,
            external_package=source_lock.package,
            external_distribution=source_lock.distribution,
            external_version=source_lock.version,
            external_source_archive=archive,
            trusted_public_key_sha256=expected_public_key_sha256,
            receipts=receipts,
        )
    except FullC6GateError:
        raise
    except Exception as exc:
        raise FullC6GateError("Full C6 preauthorization evidence failed closed") from exc


def authorize_full_c6_distribution(
    *,
    target_triple: str,
    subject_path: Path | str,
    subject: EvidenceFileRef,
    build_inputs: BuildInputClosure,
    wheel_entries: tuple[WheelEntryRef, ...],
    policy: FullC6PolicyReceipt,
    source_verification: SourceLockV2Verification,
    toolchain: BuildToolchainIdentity,
    cargo_path_source: FullC6CargoPathSource,
    runtime_authorization: RuntimeAuthorizationReceipt,
    reproducibility: ReproducibilityReceipt,
    supply_chain: FullC6SupplyChainReceipt,
    request: FinalAuthorizationRequest,
    signature_envelope_path: Path | str,
    public_key_path: Path | str,
    expected_public_key_sha256: str,
) -> FullC6GateResult:
    """Verify and mint one final Full C6 authorization, or fail closed."""
    preauthorization = prepare_full_c6_preauthorization_evidence(
        target_triple=target_triple,
        subject_path=subject_path,
        subject=subject,
        build_inputs=build_inputs,
        wheel_entries=wheel_entries,
        policy=policy,
        source_verification=source_verification,
        toolchain=toolchain,
        cargo_path_source=cargo_path_source,
        runtime_authorization=runtime_authorization,
        reproducibility=reproducibility,
        supply_chain=supply_chain,
        expected_public_key_sha256=expected_public_key_sha256,
    )
    try:
        trusted_request = _rebuild_request(request)
        preauthorization_sha256 = full_c6_preauthorization_evidence_digest(
            preauthorization
        )
        _validate_request_bindings(
            request=trusted_request,
            preauthorization_sha256=preauthorization_sha256,
            target_triple=target_triple,
            subject=subject,
            build_inputs=build_inputs,
            policy=policy,
            reproducibility=reproducibility,
        )
        envelope = _read_signature_envelope(signature_envelope_path)
        public_key = _read_public_key(public_key_path)
        signature_receipt = verify_detached_authorization_signature(
            request=trusted_request,
            envelope=envelope,
            public_key=public_key,
            expected_public_key_sha256=expected_public_key_sha256,
        )
        if (
            signature_receipt.public_key_sha256
            != preauthorization.trusted_public_key_sha256
            or signature_receipt.manifest_sha256 != trusted_request.manifest_sha256
            or signature_receipt.target_triple != target_triple
            or signature_receipt.scope != FULL_C6_SCOPE
        ):
            raise FullC6GateError("Full C6 signature receipt is stale or replayed")

        # This capture happens after signature verification by design.  It is
        # the final trust-boundary read before the positive model is minted.
        final_subject = _revalidate_subject(subject_path, subject)
        final_output_sha256 = _semantic_digest(
            {
                "domain": FULL_C6_FINAL_OUTPUT_RECEIPT_DOMAIN,
                "scope": FULL_C6_SCOPE,
                "subject": final_subject.to_dict(),
            }
        )
        final_receipts = (
            *preauthorization.receipts,
            FullC6EvidenceReceipt(
                id="attestation-signature-verified",
                sha256=signature_receipt.digest,
            ),
            FullC6EvidenceReceipt(
                id="final-output-revalidated",
                sha256=final_output_sha256,
            ),
        )
        evidence = FullC6ArtifactEvidence(
            target_triple=preauthorization.target_triple,
            subject=final_subject,
            external_package=preauthorization.external_package,
            external_distribution=preauthorization.external_distribution,
            external_version=preauthorization.external_version,
            external_source_archive=preauthorization.external_source_archive,
            trusted_public_key_sha256=preauthorization.trusted_public_key_sha256,
            preauthorization_evidence_sha256=preauthorization_sha256,
            authorization_request_sha256=trusted_request.manifest_sha256,
            receipts=final_receipts,
        )
        authorization = _mint_distribution_authorization(evidence)
        result = FullC6GateResult(
            preauthorization_evidence=preauthorization,
            signature_receipt=signature_receipt,
            evidence=evidence,
            authorization=authorization,
        )
        if tuple(item.id for item in authorization.checks) != (
            FULL_C6_AUTHORIZATION_CHECK_IDS
        ):
            raise FullC6GateError("Full C6 hard-gate check coverage is incomplete")
        return result
    except FullC6GateError:
        raise
    except (BuildInputIdentityError, SignatureVerificationError) as exc:
        raise FullC6GateError("Full C6 final signature or output verification failed") from exc
    except Exception as exc:
        raise FullC6GateError("Full C6 authorization failed closed") from exc


def _rebuild_source_verification(
    value: SourceLockV2Verification,
) -> SourceLockV2VerifiedContext:
    if (
        type(value) is not SourceLockV2Verification
        or value.admission.status != "admitted"
        or type(value.context) is not SourceLockV2VerifiedContext
    ):
        raise FullC6GateError("Full C6 requires an admitted SourceLock v2 context")
    context = value.context
    rebuilt = SourceLockV2VerifiedContext(
        admission=SourceLockV2Admission(
            status=context.admission.status,
            reason=context.admission.reason,
            manifest_sha256=context.admission.manifest_sha256,
            public_key_sha256=context.admission.public_key_sha256,
            signature_sha256=context.admission.signature_sha256,
            domain=context.admission.domain,
            prebuild_admitted=context.admission.prebuild_admitted,
            authorizes_build=context.admission.authorizes_build,
            authorizes_distribution=context.admission.authorizes_distribution,
        ),
        plan=context.plan,
        wheel=context.wheel,
        analyses=tuple(context.analyses),
        manifest=context.manifest,
    )
    rebuilt_verification = SourceLockV2Verification(
        admission=rebuilt.admission,
        context=rebuilt,
    )
    if rebuilt_verification != value:
        raise FullC6GateError("Full C6 SourceLock v2 context is not canonical")
    return rebuilt


def _require_owner_key_bindings(
    *,
    policy: FullC6PolicyReceipt,
    source_context: SourceLockV2VerifiedContext,
    expected_public_key_sha256: str,
) -> None:
    admission_key = source_context.admission.public_key_sha256
    if admission_key is None:
        raise FullC6GateError("Full C6 SourceLock admission key is missing")
    bindings = (
        policy.trusted_owner_public_key_sha256,
        source_context.manifest.trusted_public_key_sha256,
        admission_key,
        expected_public_key_sha256,
    )
    if type(expected_public_key_sha256) is not str or len(expected_public_key_sha256) != 64:
        raise FullC6GateError("Full C6 pinned public-key digest is invalid")
    try:
        bytes.fromhex(expected_public_key_sha256)
    except ValueError as exc:
        raise FullC6GateError("Full C6 pinned public-key digest is invalid") from exc
    if any(type(value) is not str for value in bindings) or not all(
        hmac.compare_digest(bindings[0], value) for value in bindings[1:]
    ):
        raise FullC6GateError("Full C6 owner public-key bindings disagree")
    if policy.owner_declaration.owner_identity != source_context.manifest.owner:
        raise FullC6GateError("Full C6 owner identity bindings disagree")


def _preauthorization_receipts(
    *,
    source_lock: SourceLockV2Manifest,
    source_admission: SourceLockV2Admission,
    policy: FullC6PolicyReceipt,
    build_inputs: BuildInputClosure,
    toolchain: BuildToolchainIdentity,
    runtime_authorization: RuntimeAuthorizationReceipt,
    reproducibility: ReproducibilityReceipt,
    supply_chain: FullC6SupplyChainReceipt,
) -> tuple[FullC6EvidenceReceipt, ...]:
    archive_receipt = _semantic_digest(
        {
            "domain": FULL_C6_EXTERNAL_ARCHIVE_RECEIPT_DOMAIN,
            "scope": FULL_C6_SCOPE,
            "archive": source_lock.archive.to_dict(),
            "wheel_authority_sha256": source_lock.wheel_authority_sha256,
        }
    )
    source_lock_receipt = _semantic_digest(
        {
            "domain": FULL_C6_SOURCE_LOCK_RECEIPT_DOMAIN,
            "scope": FULL_C6_SCOPE,
            "admission": source_admission.to_dict(),
        }
    )
    values = (
        archive_receipt,
        source_lock_receipt,
        policy.artifact_policy_coverage_inventory_sha256,
        policy.license_policy_sha256,
        policy.transformation_policy_sha256,
        runtime_authorization.transitive_closure_sha256,
        runtime_authorization.digest,
        build_inputs.digest,
        toolchain.digest,
        reproducibility.digest,
        supply_chain.sbom_sha256,
        supply_chain.provenance_sha256,
    )
    return tuple(
        FullC6EvidenceReceipt(id=receipt_id, sha256=digest)
        for receipt_id, digest in zip(
            FULL_C6_PREAUTHORIZATION_RECEIPT_IDS,
            values,
            strict=True,
        )
    )


def _rebuild_request(value: FinalAuthorizationRequest) -> FinalAuthorizationRequest:
    if type(value) is not FinalAuthorizationRequest:
        raise FullC6GateError("Full C6 final authorization request has an invalid type")
    rebuilt = FinalAuthorizationRequest(
        target_triple=value.target_triple,
        project_sha256=value.project_sha256,
        artifact_sha256=value.artifact_sha256,
        evidence_sha256=value.evidence_sha256,
        reproducibility_sha256=value.reproducibility_sha256,
        policy_sha256=value.policy_sha256,
        scope=value.scope,
    )
    if rebuilt != value:
        raise FullC6GateError("Full C6 final authorization request is not canonical")
    return rebuilt


def _validate_request_bindings(
    *,
    request: FinalAuthorizationRequest,
    preauthorization_sha256: str,
    target_triple: str,
    subject: EvidenceFileRef,
    build_inputs: BuildInputClosure,
    policy: FullC6PolicyReceipt,
    reproducibility: ReproducibilityReceipt,
) -> None:
    # In this frozen v1 request schema, project_sha256 is the semantic digest
    # of the complete exact build-input closure, not a caller-selected subset.
    expected = (
        (request.target_triple, target_triple),
        (request.scope, FULL_C6_SCOPE),
        (request.project_sha256, build_inputs.digest),
        (request.artifact_sha256, subject.sha256),
        (request.evidence_sha256, preauthorization_sha256),
        (request.reproducibility_sha256, reproducibility.digest),
        (request.policy_sha256, policy.digest),
    )
    if any(
        type(actual) is not str
        or type(wanted) is not str
        or not hmac.compare_digest(actual, wanted)
        for actual, wanted in expected
    ):
        raise FullC6GateError("Full C6 final authorization request is stale or replayed")


def _revalidate_subject(path: Path | str, expected: EvidenceFileRef) -> EvidenceFileRef:
    if type(expected) is not EvidenceFileRef:
        raise FullC6GateError("Full C6 subject identity has an invalid type")
    candidate = Path(path)
    _reject_symlink_components(candidate)
    try:
        captured = capture_exact_file(
            candidate,
            logical_name=expected.logical_path,
            role=expected.role,
        )
    except (BuildInputIdentityError, TypeError, ValueError) as exc:
        raise FullC6GateError("Full C6 subject cannot be read through a no-follow file") from exc
    if captured.sha256 != expected.sha256 or captured.size != expected.size:
        raise FullC6GateError("Full C6 subject bytes changed after evidence capture")
    return EvidenceFileRef(
        logical_path=captured.logical_name,
        sha256=captured.sha256,
        size=captured.size,
        role=captured.role,
    )


def _read_signature_envelope(path: Path | str) -> DetachedSignatureEnvelope:
    data = _read_pinned_file(
        path,
        logical_name="authorization/final-signature.json",
        role="authorization-signature-envelope",
        max_bytes=MAX_SIGNATURE_ENVELOPE_BYTES,
    )
    return parse_detached_signature_envelope(data)


def _read_public_key(path: Path | str) -> bytes:
    data = _read_pinned_file(
        path,
        logical_name="authorization/owner.ed25519.pub",
        role="authorization-public-key",
        max_bytes=MAX_FULL_C6_PUBLIC_KEY_BYTES,
    )
    if len(data) != MAX_FULL_C6_PUBLIC_KEY_BYTES:
        raise FullC6GateError("Full C6 public key must be exactly 32 raw bytes")
    return data


def _read_pinned_file(
    path: Path | str,
    *,
    logical_name: str,
    role: str,
    max_bytes: int,
) -> bytes:
    candidate = Path(path)
    _reject_symlink_components(candidate)
    try:
        _identity, data = capture_exact_file_bytes(
            candidate,
            logical_name=logical_name,
            role=role,
            max_bytes=max_bytes,
        )
    except (BuildInputIdentityError, TypeError, ValueError) as exc:
        raise FullC6GateError("Full C6 signature material cannot be read safely") from exc
    return data


def _reject_symlink_components(path: Path) -> None:
    absolute = path.absolute()
    for component in reversed((absolute, *absolute.parents)):
        try:
            observed = os.lstat(component)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise FullC6GateError("Full C6 input path cannot be inspected") from exc
        if stat.S_ISLNK(observed.st_mode):
            raise FullC6GateError("Full C6 input path contains a symlink")


def _semantic_digest(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _mint_distribution_authorization(
    evidence: FullC6ArtifactEvidence,
) -> FullC6DistributionAuthorization:
    """Mint the sole positive model after every hard-gate check has succeeded."""
    trusted = _reconstruct_full_c6_evidence(evidence)
    authorization = object.__new__(FullC6DistributionAuthorization)
    object.__setattr__(authorization, "evidence_sha256", full_c6_evidence_digest(trusted))
    object.__setattr__(
        authorization,
        "preauthorization_evidence_sha256",
        trusted.preauthorization_evidence_sha256,
    )
    object.__setattr__(
        authorization,
        "authorization_request_sha256",
        trusted.authorization_request_sha256,
    )
    object.__setattr__(
        authorization,
        "trusted_public_key_sha256",
        trusted.trusted_public_key_sha256,
    )
    object.__setattr__(
        authorization,
        "checks",
        tuple(
            FullC6AuthorizationCheck(id=check_id)
            for check_id in FULL_C6_AUTHORIZATION_CHECK_IDS
        ),
    )
    return authorization


__all__ = [
    "FULL_C6_EXTERNAL_ARCHIVE_RECEIPT_DOMAIN",
    "FULL_C6_FINAL_OUTPUT_RECEIPT_DOMAIN",
    "FULL_C6_SOURCE_LOCK_RECEIPT_DOMAIN",
    "FullC6GateError",
    "FullC6GateResult",
    "authorize_full_c6_distribution",
    "prepare_full_c6_preauthorization_evidence",
]
