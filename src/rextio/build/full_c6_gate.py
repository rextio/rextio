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
from pathlib import Path, PurePosixPath
import stat
from typing import TYPE_CHECKING

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
from rextio.build.full_c6_analysis_transaction import (
    FullC6AnalysisIRTransaction,
    FullC6AnalysisTransactionError,
    validate_full_c6_analysis_ir_transaction,
)
from rextio.build import full_c6_executor as _executor
from rextio.build.full_c6_cargo_workspace import (
    FullC6CargoDependencyWorkspaceReceipt,
)
from rextio.build.full_c6_policy import (
    FullC6PolicyFileIdentity,
    FullC6PolicyReceipt,
    full_c6_license_detector_payload_digest,
)
from rextio.build.full_c6_executor import (
    FULL_C6_CALLBACK_LOCK_DRIVER,
    FULL_C6_NATIVE_DRIVER_MANIFEST,
    FULL_C6_NATIVE_EXECUTION_DRIVER,
    FULL_C6_NATIVE_POSTPROCESSOR,
    FullC6EnvironmentBinding,
    FullC6ExecutorReceipt,
    FullC6FrozenTreeManifest,
    FullC6InvocationReceipt,
    FullC6TreeEntry,
)
from rextio.build.full_c6_native_output import (
    full_c6_native_output_subject,
    full_c6_native_output_wheel_entries,
    full_c6_native_output_wheel_path,
)
from rextio.build.full_c6_output_license import (
    validate_full_c6_output_license_contract,
)
from rextio.build.full_c6_supply_chain import (
    FullC6AuthorityAggregateBinding,
    FullC6CargoPathSource,
    FullC6SupplyChainReceipt,
    build_full_c6_supply_chain_receipt,
    verify_full_c6_supply_chain_receipt,
)
from rextio.build.input_closure import (
    BuildInputClosure,
    BuildInputIdentityError,
    ExactFileIdentity,
    capture_exact_file,
    capture_exact_file_bytes,
)
from rextio.build.runtime_authorization import (
    RUNTIME_VERIFICATION_NATIVE_FRESH,
    RuntimeAuthorizationReceipt,
    verify_native_runtime_authorization,
)
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
    validate_source_lock_v2_verified_context,
)
from rextio.source.wheel_authority import verify_source_wheel_license_detection

if TYPE_CHECKING:
    from rextio.build.full_c6_production import FullC6ProductionAuthority


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


@dataclass(frozen=True, slots=True)
class _FullC6GateInputs:
    target_triple: str
    subject_path: Path
    subject: EvidenceFileRef
    build_inputs: BuildInputClosure
    wheel_entries: tuple[WheelEntryRef, ...]
    policy: FullC6PolicyReceipt
    source_verification: SourceLockV2Verification
    analysis_ir_transaction: FullC6AnalysisIRTransaction
    toolchain: BuildToolchainIdentity
    cargo_path_source: FullC6CargoPathSource
    runtime_authorization: RuntimeAuthorizationReceipt
    executor: FullC6ExecutorReceipt
    supply_chain: FullC6SupplyChainReceipt
    cargo_dependency_workspace: FullC6CargoDependencyWorkspaceReceipt
    authority_aggregate: FullC6AuthorityAggregateBinding
    expected_public_key_sha256: str


def _validated_production_gate_inputs(
    authority: FullC6ProductionAuthority,
) -> _FullC6GateInputs:
    """Extract only the complete, process-validated production graph."""
    try:
        from rextio.build.full_c6_production import (
            FullC6ProductionAuthority,
            _validated_full_c6_production_material,
        )

        if type(authority) is not FullC6ProductionAuthority:
            raise FullC6GateError(
                "Full C6 hard gate requires exact production authority"
            )
        material = _validated_full_c6_production_material(authority)
        if material.lifecycle.status not in {
            "signing-required",
            "publication-required",
        }:
            raise FullC6GateError(
                "Full C6 hard gate requires pinned owner policy"
            )
        if (
            type(material.policy) is not FullC6PolicyReceipt
            or type(material.supply_chain) is not FullC6SupplyChainReceipt
            or type(material.cargo_workspace)
            is not FullC6CargoDependencyWorkspaceReceipt
            or type(material.build_inputs) is not BuildInputClosure
            or type(material.analysis_ir_transaction)
            is not FullC6AnalysisIRTransaction
            or type(material.runtime_authorization)
            is not RuntimeAuthorizationReceipt
            or type(material.executor_receipt) is not FullC6ExecutorReceipt
            or type(material.cargo_path_source) is not FullC6CargoPathSource
        ):
            raise FullC6GateError("Full C6 production material is incomplete")
        execution = _executor._validated_full_c6_native_output_material(
            material.native_execution_authority
        )
        if (
            type(execution.toolchain) is not BuildToolchainIdentity
            or execution.cargo_workspace is not material.cargo_workspace
            or execution.toolchain.cargo_sources
            is not material.cargo_workspace.cargo_sources
        ):
            raise FullC6GateError("Full C6 retained Cargo authority is split")
        source_verification = material.preflight.context.source_verification
        if (
            type(source_verification) is not SourceLockV2Verification
            or source_verification.context is None
        ):
            raise FullC6GateError("Full C6 retained SourceLock authority is invalid")
        subject = full_c6_native_output_subject(
            material.native_output_transaction
        )
        wheel_entries = full_c6_native_output_wheel_entries(
            material.native_output_transaction
        )
        subject_path = full_c6_native_output_wheel_path(
            material.native_output_transaction
        )
        output_license = validate_full_c6_output_license_contract(
            material.license_materials_transaction,
            material.output_license_contract,
            source_context=source_verification.context,
        )
        aggregate = FullC6AuthorityAggregateBinding(
            analysis_ir_transaction_sha256=(
                material.analysis_ir_transaction.digest
            ),
            license_materials_transaction_sha256=(
                material.license_materials_transaction.digest
            ),
            output_license_contract_sha256=(
                output_license.output_contract_sha256
            ),
            cargo_workspace_sha256=material.cargo_workspace.digest,
            native_execution_authority_sha256=(
                material.native_execution_authority.digest
            ),
            native_output_transaction_sha256=(
                material.native_output_transaction.digest
            ),
            subject_wheel_transaction_sha256=(
                material.subject_wheel_transaction.digest
            ),
            native_runtime_authority_sha256=(
                material.native_runtime_authority.digest
            ),
            runtime_authorization_sha256=material.runtime_authorization.digest,
            executor_receipt_sha256=material.executor_receipt.digest,
        )
        if (
            aggregate != material.authority_aggregate
            or material.supply_chain.authority_aggregate != aggregate
        ):
            raise FullC6GateError(
                "Full C6 production authority aggregate is stale"
            )
        return _FullC6GateInputs(
            target_triple=material.runtime_authorization.target_triple,
            subject_path=subject_path,
            subject=subject,
            build_inputs=material.build_inputs,
            wheel_entries=wheel_entries,
            policy=material.policy,
            source_verification=source_verification,
            analysis_ir_transaction=material.analysis_ir_transaction,
            toolchain=execution.toolchain,
            cargo_path_source=material.cargo_path_source,
            runtime_authorization=material.runtime_authorization,
            executor=material.executor_receipt,
            supply_chain=material.supply_chain,
            cargo_dependency_workspace=material.cargo_workspace,
            authority_aggregate=aggregate,
            expected_public_key_sha256=(
                material.policy.trusted_owner_public_key_sha256
            ),
        )
    except FullC6GateError:
        raise
    except Exception as exc:
        raise FullC6GateError(
            "Full C6 production authority failed deep validation"
        ) from exc


def prepare_full_c6_preauthorization_evidence(
    authority: FullC6ProductionAuthority,
) -> FullC6PreauthorizationEvidence:
    """Rebuild the exact pre-signing graph and return its safe-to-sign record."""
    try:
        inputs = _validated_production_gate_inputs(authority)
        target_triple = inputs.target_triple
        subject_path = inputs.subject_path
        subject = inputs.subject
        build_inputs = inputs.build_inputs
        wheel_entries = inputs.wheel_entries
        policy = inputs.policy
        source_verification = inputs.source_verification
        analysis_ir_transaction = inputs.analysis_ir_transaction
        toolchain = inputs.toolchain
        cargo_path_source = inputs.cargo_path_source
        runtime_authorization = inputs.runtime_authorization
        executor = inputs.executor
        supply_chain = inputs.supply_chain
        cargo_dependency_workspace = inputs.cargo_dependency_workspace
        expected_public_key_sha256 = inputs.expected_public_key_sha256
        trusted_context = _rebuild_source_verification(source_verification)
        source_lock = trusted_context.manifest
        source_admission = trusted_context.admission
        _require_owner_key_bindings(
            policy=policy,
            source_context=trusted_context,
            expected_public_key_sha256=expected_public_key_sha256,
        )
        validate_full_c6_analysis_ir_transaction(
            analysis_ir_transaction,
            source_verification=source_verification,
            build_inputs=build_inputs,
            policy=policy,
        )
        _require_external_license_bindings(
            policy=policy,
            source_context=trusted_context,
        )
        _revalidate_subject(subject_path, subject)
        trusted_executor = _validate_executor_bindings(
            executor,
            toolchain=toolchain,
            subject=subject,
            target_triple=target_triple,
            build_inputs=build_inputs,
            policy=policy,
        )
        if not hmac.compare_digest(
            trusted_executor.digest,
            inputs.authority_aggregate.executor_receipt_sha256,
        ):
            raise FullC6GateError(
                "Full C6 authority aggregate does not bind the executor receipt"
            )
        if (
            type(runtime_authorization) is not RuntimeAuthorizationReceipt
            or runtime_authorization.verification_mode
            != RUNTIME_VERIFICATION_NATIVE_FRESH
            or not verify_native_runtime_authorization(runtime_authorization)
        ):
            raise FullC6GateError(
                "Full C6 requires a freshly reverified native runtime receipt"
            )
        trusted_supply_chain = verify_full_c6_supply_chain_receipt(
            supply_chain,
            cargo_dependency_workspace=cargo_dependency_workspace,
        )
        authority_aggregate = trusted_supply_chain.authority_aggregate
        if authority_aggregate != inputs.authority_aggregate:
            raise FullC6GateError(
                "Full C6 authority aggregate does not bind the gate inputs"
            )
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
            reproducibility=trusted_executor.reproducibility,
            authority_aggregate=authority_aggregate,
            cargo_dependency_workspace=cargo_dependency_workspace,
        )
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
            executor=trusted_executor,
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
    authority: FullC6ProductionAuthority,
    *,
    request: FinalAuthorizationRequest,
    signature_envelope_path: Path | str,
    public_key_path: Path | str,
) -> FullC6GateResult:
    """Verify and mint one final Full C6 authorization, or fail closed."""
    preauthorization = prepare_full_c6_preauthorization_evidence(authority)
    try:
        inputs = _validated_production_gate_inputs(authority)
        target_triple = inputs.target_triple
        subject_path = inputs.subject_path
        subject = inputs.subject
        build_inputs = inputs.build_inputs
        policy = inputs.policy
        executor = inputs.executor
        expected_public_key_sha256 = inputs.expected_public_key_sha256
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
            executor=executor,
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
        # Mint inline only inside the completed cryptographic transaction.
        # There is intentionally no module-level evidence-only mint helper:
        # publication independently re-verifies this signature and chain.
        trusted_evidence = _reconstruct_full_c6_evidence(evidence)
        authorization = object.__new__(FullC6DistributionAuthorization)
        object.__setattr__(
            authorization,
            "evidence_sha256",
            full_c6_evidence_digest(trusted_evidence),
        )
        object.__setattr__(
            authorization,
            "preauthorization_evidence_sha256",
            trusted_evidence.preauthorization_evidence_sha256,
        )
        object.__setattr__(
            authorization,
            "authorization_request_sha256",
            trusted_evidence.authorization_request_sha256,
        )
        object.__setattr__(
            authorization,
            "trusted_public_key_sha256",
            trusted_evidence.trusted_public_key_sha256,
        )
        object.__setattr__(
            authorization,
            "checks",
            tuple(
                FullC6AuthorizationCheck(id=check_id)
                for check_id in FULL_C6_AUTHORIZATION_CHECK_IDS
            ),
        )
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
    except (
        BuildInputIdentityError,
        FullC6AnalysisTransactionError,
        SignatureVerificationError,
    ) as exc:
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
    if not validate_source_lock_v2_verified_context(context):
        raise FullC6GateError(
            "Full C6 SourceLock v2 context is not from a valid verification transaction"
        )
    rebuilt_verification = SourceLockV2Verification(
        admission=value.admission,
        context=context,
    )
    if rebuilt_verification != value:
        raise FullC6GateError("Full C6 SourceLock v2 context is not canonical")
    return context


def _require_external_license_bindings(
    *,
    policy: FullC6PolicyReceipt,
    source_context: SourceLockV2VerifiedContext,
) -> None:
    """Re-derive external license evidence from the admitted wheel bytes."""
    wheel = source_context.wheel
    detection = wheel.license_detection
    if (
        not verify_source_wheel_license_detection(
            detection,
            wheel.license_entry_paths,
            wheel.license_payloads,
        )
        or detection.status != "detected"
        or detection.detected_spdx is None
        or detection.detected_spdx != source_context.manifest.observed_license
    ):
        raise FullC6GateError(
            "Full C6 requires independent exact-byte license detection"
        )
    source_detector_receipt_sha256 = detection.semantic_sha256
    entries = {item.path: item for item in wheel.entries}
    files: list[FullC6PolicyFileIdentity] = []
    if len(wheel.license_payloads) != len(wheel.license_entry_paths):
        raise FullC6GateError("Full C6 external license payload coverage is incomplete")
    for path, payload in zip(
        wheel.license_entry_paths,
        wheel.license_payloads,
        strict=True,
    ):
        entry = entries.get(path)
        digest = hashlib.sha256(payload).hexdigest()
        if (
            type(payload) is not bytes
            or entry is None
            or entry.sha256 != digest
            or entry.size != len(payload)
        ):
            raise FullC6GateError("Full C6 external license payload bytes are stale")
        files.append(
            FullC6PolicyFileIdentity(
                logical_path=f"external/{path}",
                sha256=digest,
                size=len(payload),
                role="license-file",
            )
        )
    actual_files = tuple(sorted(files, key=lambda item: item.logical_path.casefold()))
    try:
        detector_payload_sha256 = full_c6_license_detector_payload_digest(
            detection.detected_spdx,
            actual_files,
            source_detector_receipt_sha256=source_detector_receipt_sha256,
        )
    except (TypeError, ValueError) as exc:
        raise FullC6GateError("Full C6 external license observation is invalid") from exc
    external_rows = tuple(
        row for row in policy.rows if row.class_id.startswith("external-source:")
    )
    if not external_rows:
        raise FullC6GateError("Full C6 external license policy coverage is empty")
    for row in external_rows:
        evidence = row.license_evidence
        if (
            evidence is None
            or evidence.detected_spdx != detection.detected_spdx
            or evidence.source_detector_receipt_sha256
            != source_detector_receipt_sha256
            or evidence.license_files != actual_files
            or not hmac.compare_digest(
                evidence.detector_payload_sha256,
                detector_payload_sha256,
            )
        ):
            raise FullC6GateError(
                "Full C6 external license policy is not derived from exact wheel bytes"
            )


def _validate_executor_bindings(
    value: FullC6ExecutorReceipt,
    *,
    toolchain: BuildToolchainIdentity,
    subject: EvidenceFileRef,
    target_triple: str,
    build_inputs: BuildInputClosure,
    policy: FullC6PolicyReceipt,
) -> FullC6ExecutorReceipt:
    """Rebuild and cross-bind the only executor posture accepted by Full C6."""
    if type(value) is not FullC6ExecutorReceipt:
        raise FullC6GateError("Full C6 requires an exact executor receipt")
    try:
        tree = FullC6FrozenTreeManifest(
            entries=tuple(
                FullC6TreeEntry(
                    logical_name=item.logical_name,
                    kind=item.kind,
                    sha256=item.sha256,
                    size=item.size,
                    mode=item.mode,
                )
                for item in value.frozen_tree.entries
                if type(item) is FullC6TreeEntry
            ),
            cargo_lock_generated=value.frozen_tree.cargo_lock_generated,
            complete_for_scope=value.frozen_tree.complete_for_scope,
        )
        invocations = tuple(
            FullC6InvocationReceipt(
                ordinal=item.ordinal,
                argv_sha256=item.argv_sha256,
                argv_count=item.argv_count,
                environment=tuple(
                    FullC6EnvironmentBinding(
                        name=binding.name,
                        value_sha256=binding.value_sha256,
                        value_size=binding.value_size,
                    )
                    for binding in item.environment
                    if type(binding) is FullC6EnvironmentBinding
                ),
                timeout_seconds=item.timeout_seconds,
                max_output_bytes=item.max_output_bytes,
                inherit_env=item.inherit_env,
                sandbox_engine=item.sandbox_engine,
                sandbox_plan_sha256=item.sandbox_plan_sha256,
                sandbox_profile_sha256=item.sandbox_profile_sha256,
                sandbox_seccomp_sha256=item.sandbox_seccomp_sha256,
            )
            for item in value.invocations
            if type(item) is FullC6InvocationReceipt
        )
        if len(invocations) != 2:
            raise ValueError("executor invocation coverage is incomplete")
        rebuilt = FullC6ExecutorReceipt(
            frozen_tree=tree,
            invocations=(invocations[0], invocations[1]),
            reproducibility=value.reproducibility,
            execution_driver=value.execution_driver,
            lock_driver=value.lock_driver,
            toolchain_sha256=value.toolchain_sha256,
            cargo_executable_sha256=value.cargo_executable_sha256,
            postprocessor=value.postprocessor,
            postprocessor_manifest_sha256=value.postprocessor_manifest_sha256,
            target_triple=value.target_triple,
            pyo3_config_sha256=value.pyo3_config_sha256,
            pyo3_config_size=value.pyo3_config_size,
            pyo3_config_profile_sha256=value.pyo3_config_profile_sha256,
            domain=value.domain,
            scope=value.scope,
            complete_for_scope=value.complete_for_scope,
            authorizes_distribution=value.authorizes_distribution,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise FullC6GateError("Full C6 executor receipt is not canonical") from exc
    if rebuilt != value:
        raise FullC6GateError("Full C6 executor receipt is not canonical")
    if (
        rebuilt.execution_driver != FULL_C6_NATIVE_EXECUTION_DRIVER
        or rebuilt.lock_driver == FULL_C6_CALLBACK_LOCK_DRIVER
    ):
        raise FullC6GateError(
            "Full C6 rejects callback and test-only executor authority"
        )
    invocation = rebuilt.invocations[0]
    payload_argv = toolchain.argv.values
    if target_triple == "x86_64-unknown-linux-gnu":
        payload_argv = _executor._linux_native_payload_argv(payload_argv)
    payload_argv_sha256 = hashlib.sha256(
        canonical_json_bytes(list(payload_argv))
    ).hexdigest()
    cargo_lock = tuple(
        item
        for item in rebuilt.frozen_tree.entries
        if item.kind == "file" and item.logical_name == "Cargo.lock"
    )
    driver_manifests = tuple(
        item
        for item in rebuilt.frozen_tree.entries
        if item.kind == "file" and item.logical_name == FULL_C6_NATIVE_DRIVER_MANIFEST
    )
    expected_lock = toolchain.cargo_sources.lock_file
    expected = (
        (rebuilt.toolchain_sha256, toolchain.digest),
        (rebuilt.cargo_executable_sha256, toolchain.cargo.executable.sha256),
        (invocation.argv_sha256, payload_argv_sha256),
        (rebuilt.invocations[1].argv_sha256, payload_argv_sha256),
        (rebuilt.reproducibility.wheel_sha256, subject.sha256),
    )
    if (
        invocation.argv_count != len(payload_argv)
        or rebuilt.invocations[1].argv_count != len(payload_argv)
        or len(cargo_lock) != 1
        or len(driver_manifests) != 1
        or cargo_lock[0].sha256 != expected_lock.sha256
        or cargo_lock[0].size != expected_lock.size
        or rebuilt.postprocessor != FULL_C6_NATIVE_POSTPROCESSOR
        or rebuilt.target_triple != target_triple
        or driver_manifests[0].sha256 != rebuilt.postprocessor_manifest_sha256
        or any(
            type(actual) is not str
            or type(wanted) is not str
            or not hmac.compare_digest(actual, wanted)
            for actual, wanted in expected
        )
    ):
        raise FullC6GateError(
            "Full C6 executor tree, invocations, or toolchain binding is stale"
        )
    _require_executor_build_input_projection(
        executor=rebuilt,
        build_inputs=build_inputs,
        policy=policy,
    )
    return rebuilt


def _require_executor_build_input_projection(
    *,
    executor: FullC6ExecutorReceipt,
    build_inputs: BuildInputClosure,
    policy: FullC6PolicyReceipt,
) -> None:
    """Bind every frozen Cargo-project file to the exact closure projection.

    Project sources, stubs, and the policy lock remain outside the executor
    project, but their complete closure digest is signed in the same
    preauthorization graph.  Generated Rust is projected at the executor root
    and generated Python is projected below ``python-staging``.  The native
    driver manifest is the sole executor-owned file and is separately bound to
    its receipt digest below.
    """
    if type(build_inputs) is not BuildInputClosure or type(policy) is not FullC6PolicyReceipt:
        raise FullC6GateError("Full C6 executor build-input projection is invalid")
    closure = {item.logical_name: item for item in build_inputs.files}
    generated_classes = {
        "file-input:generated-python-input": "python",
        "file-input:generated-rust-lib": "rust",
        "file-input:generated-rust-build-input": "rust",
        "file-input:generated-cargo-lock": "rust",
    }
    generated_rows = tuple(
        row for row in policy.rows if row.class_id in generated_classes
    )
    if {row.class_id for row in generated_rows} != set(generated_classes):
        raise FullC6GateError("Full C6 generated input classes are incomplete")
    projected: dict[str, ExactFileIdentity] = {}
    for row in generated_rows:
        generated_kind = generated_classes[row.class_id]
        relative = (
            "Cargo.lock"
            if row.class_id == "file-input:generated-cargo-lock"
            else _full_c6_generated_executor_path(
                row.canonical_identity,
                generated_kind=generated_kind,
            )
        )
        if row.class_id == "file-input:generated-rust-lib" and relative != "src/lib.rs":
            raise FullC6GateError("Full C6 generated Rust lib path is invalid")
        item = closure.get(row.canonical_identity)
        if (
            item is None
            or row.sha256 != item.sha256
            or row.size != item.size
            or relative in projected
        ):
            raise FullC6GateError("Full C6 generated closure projection is stale")
        projected[relative] = item
    tree_files = {
        item.logical_name: item
        for item in executor.frozen_tree.entries
        if item.kind == "file"
    }
    executor_owned = {FULL_C6_NATIVE_DRIVER_MANIFEST}
    if set(projected) | executor_owned != set(tree_files):
        raise FullC6GateError(
            "Full C6 executor frozen tree differs from the generated closure"
        )
    driver_manifest = tree_files[FULL_C6_NATIVE_DRIVER_MANIFEST]
    if (
        driver_manifest.sha256 is None
        or executor.postprocessor_manifest_sha256 is None
        or not hmac.compare_digest(
            driver_manifest.sha256,
            executor.postprocessor_manifest_sha256,
        )
        or driver_manifest.mode != 0o644
    ):
        raise FullC6GateError("Full C6 native driver manifest binding is stale")
    for logical_name, exact_file in projected.items():
        tree_file = tree_files[logical_name]
        executable = tree_file.mode == 0o755
        if (
            tree_file.sha256 != exact_file.sha256
            or tree_file.size != exact_file.size
            or executable != exact_file.executable
        ):
            raise FullC6GateError(
                "Full C6 executor frozen tree bytes differ from the build-input closure"
            )


def _full_c6_generated_executor_path(
    canonical_identity: str,
    *,
    generated_kind: str,
) -> str:
    """Project one explicit generated identity into the executor tree.

    Production identities are rooted below ``.rextio/generated``.  The
    path-free policy fixtures use the shorter ``generated`` root.  No basename
    or suffix-only guessing is accepted for either form.
    """
    if generated_kind not in {"python", "rust"}:
        raise FullC6GateError("Full C6 generated projection kind is invalid")
    parts = PurePosixPath(canonical_identity).parts
    production_marker = (".rextio", "generated", generated_kind)
    production_matches = tuple(
        index
        for index in range(len(parts) - len(production_marker) + 1)
        if parts[index : index + len(production_marker)] == production_marker
    )
    if len(production_matches) == 1:
        relative_parts = parts[production_matches[0] + len(production_marker) :]
    elif len(production_matches) > 1:
        raise FullC6GateError("Full C6 generated input root is ambiguous")
    elif parts[:2] == ("generated", generated_kind):
        relative_parts = parts[2:]
    else:
        raise FullC6GateError("Full C6 generated input root is invalid")
    if not relative_parts:
        raise FullC6GateError("Full C6 generated input path is invalid")
    relative = PurePosixPath(*relative_parts)
    if generated_kind == "python":
        relative = PurePosixPath("python-staging") / relative
    return relative.as_posix()


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
    executor: FullC6ExecutorReceipt,
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
        executor.digest,
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
    executor: FullC6ExecutorReceipt,
) -> None:
    # In this frozen v1 request schema, project_sha256 is the semantic digest
    # of the complete exact build-input closure, not a caller-selected subset.
    expected = (
        (request.target_triple, target_triple),
        (request.scope, FULL_C6_SCOPE),
        (request.project_sha256, build_inputs.digest),
        (request.artifact_sha256, subject.sha256),
        (request.evidence_sha256, preauthorization_sha256),
        (request.reproducibility_sha256, executor.digest),
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


__all__ = [
    "FULL_C6_EXTERNAL_ARCHIVE_RECEIPT_DOMAIN",
    "FULL_C6_FINAL_OUTPUT_RECEIPT_DOMAIN",
    "FULL_C6_SOURCE_LOCK_RECEIPT_DOMAIN",
    "FullC6GateError",
    "FullC6GateResult",
    "authorize_full_c6_distribution",
    "prepare_full_c6_preauthorization_evidence",
]
