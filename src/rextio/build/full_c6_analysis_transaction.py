"""Sealed analysis/IR evidence for the bounded Full C6 authorization gate.

The owner policy contains analysis, generator, and lowered-IR digests.  Those
values are declarations until this module re-derives them from the existing
C6.10 project replay receipt, the same-transaction SourceLock v2 context, and
the exact build-input closure.  Raw source bytes and host paths never enter the
serializable transaction projection.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import SupportsIndex

from rextio.artifacts.evidence import (
    EvidenceFileRef,
    SourceTransformationVerification,
    canonical_json_bytes,
)
from rextio.build.full_c6_policy import FullC6PolicyReceipt
from rextio.build.full_c6_input_identity import (
    canonical_full_c6_build_input_name,
)
from rextio.build.input_closure import BuildInputClosure, ExactFileIdentity
from rextio.build.transformation_verification import (
    SourceTransformationReplayAuthority,
    validate_source_transformation_replay_authority,
)
from rextio.source.source_lock_v2 import (
    SourceLockV2Verification,
    SourceLockV2VerifiedContext,
    validate_source_lock_v2_verified_context,
)


FULL_C6_ANALYSIS_IR_TRANSACTION_DOMAIN = "rextio.full-c6-analysis-ir-transaction.v1"
FULL_C6_ANALYSIS_PROJECTION_DOMAIN = "rextio.full-c6-analysis-projection.v1"
FULL_C6_GENERATOR_PROJECTION_DOMAIN = "rextio.full-c6-generator-projection.v1"
FULL_C6_LOWERED_IR_PROJECTION_DOMAIN = "rextio.full-c6-lowered-ir-projection.v1"
_TRANSACTION_KEY = secrets.token_bytes(32)


class FullC6AnalysisTransactionError(RuntimeError):
    """Actual analysis/IR material did not match the declared Full C6 policy."""


class FullC6AnalysisIRTransaction:
    """Process-local, non-copyable binding of actual analysis and IR evidence."""

    __slots__ = (
        "project_transformation",
        "project_replay_authority_sha256",
        "generated_python_tree_sha256",
        "generated_cargo_toml_sha256",
        "build_input_closure_sha256",
        "project_transformation_sha256",
        "external_analysis_sha256",
        "external_lowered_ir_sha256",
        "analysis_sha256",
        "generator_sha256",
        "_project_replay_authority",
        "_transaction_seal",
        "_frozen",
    )

    project_transformation: SourceTransformationVerification
    project_replay_authority_sha256: str
    generated_python_tree_sha256: str
    generated_cargo_toml_sha256: str
    build_input_closure_sha256: str
    project_transformation_sha256: str
    external_analysis_sha256: str
    external_lowered_ir_sha256: str
    analysis_sha256: str
    generator_sha256: str
    _project_replay_authority: SourceTransformationReplayAuthority
    _transaction_seal: bytes
    _frozen: bool

    def __init__(
        self,
        *,
        project_replay_authority: SourceTransformationReplayAuthority,
        project_transformation: SourceTransformationVerification,
        project_replay_authority_sha256: str,
        generated_python_tree_sha256: str,
        generated_cargo_toml_sha256: str,
        build_input_closure_sha256: str,
        project_transformation_sha256: str,
        external_analysis_sha256: str,
        external_lowered_ir_sha256: str,
        analysis_sha256: str,
        generator_sha256: str,
        _transaction_seal: bytes | None = None,
    ) -> None:
        if type(_transaction_seal) is not bytes:
            raise TypeError("Full C6 analysis/IR transaction requires a sealed factory")
        values = (
            project_replay_authority_sha256,
            generated_python_tree_sha256,
            generated_cargo_toml_sha256,
            build_input_closure_sha256,
            project_transformation_sha256,
            external_analysis_sha256,
            external_lowered_ir_sha256,
            analysis_sha256,
            generator_sha256,
        )
        if (
            type(project_replay_authority) is not SourceTransformationReplayAuthority
            or type(project_transformation) is not SourceTransformationVerification
            or any(not _is_sha256(value) for value in values)
        ):
            raise FullC6AnalysisTransactionError("Full C6 analysis/IR transaction is invalid")
        try:
            validate_source_transformation_replay_authority(project_replay_authority)
        except (TypeError, ValueError) as exc:
            raise FullC6AnalysisTransactionError(
                "Full C6 source-transformation replay authority is invalid"
            ) from exc
        if (
            project_transformation != project_replay_authority.verification
            or project_replay_authority_sha256 != project_replay_authority.digest
            or generated_python_tree_sha256
            != project_replay_authority.generated_python_tree_sha256
            or generated_cargo_toml_sha256
            != project_replay_authority.generated_cargo_toml.sha256
        ):
            raise FullC6AnalysisTransactionError(
                "Full C6 source-transformation replay authority binding is stale"
            )
        object.__setattr__(self, "_project_replay_authority", project_replay_authority)
        object.__setattr__(self, "project_transformation", project_transformation)
        object.__setattr__(
            self,
            "project_replay_authority_sha256",
            project_replay_authority_sha256,
        )
        object.__setattr__(
            self,
            "generated_python_tree_sha256",
            generated_python_tree_sha256,
        )
        object.__setattr__(
            self,
            "generated_cargo_toml_sha256",
            generated_cargo_toml_sha256,
        )
        object.__setattr__(self, "build_input_closure_sha256", build_input_closure_sha256)
        object.__setattr__(
            self,
            "project_transformation_sha256",
            project_transformation_sha256,
        )
        object.__setattr__(self, "external_analysis_sha256", external_analysis_sha256)
        object.__setattr__(
            self,
            "external_lowered_ir_sha256",
            external_lowered_ir_sha256,
        )
        object.__setattr__(self, "analysis_sha256", analysis_sha256)
        object.__setattr__(self, "generator_sha256", generator_sha256)
        object.__setattr__(self, "_transaction_seal", _transaction_seal)
        object.__setattr__(self, "_frozen", True)
        if not hmac.compare_digest(_transaction_seal, _seal(self._payload())):
            raise FullC6AnalysisTransactionError("Full C6 analysis/IR transaction seal is stale")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise TypeError("Full C6 analysis/IR transaction is immutable")

    def __copy__(self) -> object:
        raise TypeError("Full C6 analysis/IR transaction cannot be copied")

    def __deepcopy__(self, _memo: object) -> object:
        raise TypeError("Full C6 analysis/IR transaction cannot be copied")

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("Full C6 analysis/IR transaction cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        raise TypeError("Full C6 analysis/IR transaction cannot be serialized")

    def __getstate__(self) -> object:
        raise TypeError("Full C6 analysis/IR transaction cannot be serialized")

    def __repr__(self) -> str:
        return (
            "FullC6AnalysisIRTransaction("
            f"analysis_sha256={self.analysis_sha256!r}, source_material=<sealed>)"
        )

    def lowered_ir_sha256(
        self,
        *,
        transformation_kind: str,
        output_identity: str,
        output_identity_sha256: str,
    ) -> str:
        """Derive the owner-policy IR value for one exact generated output."""
        if transformation_kind not in {
            "python-to-rust-lowering-v1",
            "python-wrapper-generation-v1",
        }:
            raise FullC6AnalysisTransactionError("Full C6 transformation kind is invalid")
        if not output_identity or not _is_sha256(output_identity_sha256):
            raise FullC6AnalysisTransactionError("Full C6 transformation output is invalid")
        return _digest(
            {
                "domain": FULL_C6_LOWERED_IR_PROJECTION_DOMAIN,
                "analysis_sha256": self.analysis_sha256,
                "project_module_ir_sha256": self.project_transformation.module_ir_sha256,
                "external_lowered_ir_sha256": self.external_lowered_ir_sha256,
                "generator_sha256": self.generator_sha256,
                "transformation_kind": transformation_kind,
                "output_identity": output_identity,
                "output_identity_sha256": output_identity_sha256,
            }
        )

    @property
    def digest(self) -> str:
        """Return the safe semantic identity bound by the transaction seal."""
        return _digest(self._payload())

    def _payload(self) -> dict[str, object]:
        return {
            "domain": FULL_C6_ANALYSIS_IR_TRANSACTION_DOMAIN,
            "project_replay_authority_sha256": self.project_replay_authority_sha256,
            "generated_python_tree_sha256": self.generated_python_tree_sha256,
            "generated_cargo_toml_sha256": self.generated_cargo_toml_sha256,
            "build_input_closure_sha256": self.build_input_closure_sha256,
            "project_transformation_sha256": self.project_transformation_sha256,
            "external_analysis_sha256": self.external_analysis_sha256,
            "external_lowered_ir_sha256": self.external_lowered_ir_sha256,
            "analysis_sha256": self.analysis_sha256,
            "generator_sha256": self.generator_sha256,
        }

    def to_dict(self) -> dict[str, object]:
        """Return only path-free digests, never source bytes or local paths."""
        return {**self._payload(), "digest": self.digest}


def create_full_c6_analysis_ir_transaction(
    *,
    project_replay_authority: SourceTransformationReplayAuthority,
    source_verification: SourceLockV2Verification,
    build_inputs: BuildInputClosure,
) -> FullC6AnalysisIRTransaction:
    """Seal actual project replay plus same-transaction external analysis/IR."""
    try:
        replay_authority = validate_source_transformation_replay_authority(
            project_replay_authority
        )
    except (TypeError, ValueError) as exc:
        raise FullC6AnalysisTransactionError(
            "Full C6 requires a collector-issued source-transformation replay authority"
        ) from exc
    context = _verified_context(source_verification)
    project = _rebuild_project_transformation(replay_authority.verification)
    _require_project_closure_binding(replay_authority, build_inputs)
    project_sha256 = _digest(project.to_dict())
    external_analysis_sha256 = _digest(
        [item.to_dict() for item in context.analyses]
    )
    external_lowered_ir_sha256 = _digest(
        [
            {
                "qualname": function.qualname,
                "lowered_ir_sha256": function.lowered_ir_sha256,
            }
            for analysis in context.analyses
            for function in analysis.functions
        ]
    )
    analysis_sha256 = _digest(
        {
            "domain": FULL_C6_ANALYSIS_PROJECTION_DOMAIN,
            "build_input_closure_sha256": build_inputs.digest,
            "project_replay_authority_sha256": replay_authority.digest,
            "project_transformation_sha256": project_sha256,
            "external_analysis_sha256": external_analysis_sha256,
        }
    )
    generator_sha256 = _digest(
        {
            "domain": FULL_C6_GENERATOR_PROJECTION_DOMAIN,
            "project_generator_backend": project.generator_backend,
            "project_module_ir_sha256": project.module_ir_sha256,
            "generated_python_tree_sha256": (
                replay_authority.generated_python_tree_sha256
            ),
            "generated_cargo_toml_sha256": (
                replay_authority.generated_cargo_toml.sha256
            ),
            "external_lowered_ir_sha256": external_lowered_ir_sha256,
        }
    )
    payload = {
        "domain": FULL_C6_ANALYSIS_IR_TRANSACTION_DOMAIN,
        "project_replay_authority_sha256": replay_authority.digest,
        "generated_python_tree_sha256": replay_authority.generated_python_tree_sha256,
        "generated_cargo_toml_sha256": replay_authority.generated_cargo_toml.sha256,
        "build_input_closure_sha256": build_inputs.digest,
        "project_transformation_sha256": project_sha256,
        "external_analysis_sha256": external_analysis_sha256,
        "external_lowered_ir_sha256": external_lowered_ir_sha256,
        "analysis_sha256": analysis_sha256,
        "generator_sha256": generator_sha256,
    }
    return FullC6AnalysisIRTransaction(
        project_replay_authority=replay_authority,
        project_transformation=project,
        project_replay_authority_sha256=replay_authority.digest,
        generated_python_tree_sha256=replay_authority.generated_python_tree_sha256,
        generated_cargo_toml_sha256=replay_authority.generated_cargo_toml.sha256,
        build_input_closure_sha256=build_inputs.digest,
        project_transformation_sha256=project_sha256,
        external_analysis_sha256=external_analysis_sha256,
        external_lowered_ir_sha256=external_lowered_ir_sha256,
        analysis_sha256=analysis_sha256,
        generator_sha256=generator_sha256,
        _transaction_seal=_seal(payload),
    )


def validate_full_c6_analysis_ir_transaction(
    value: FullC6AnalysisIRTransaction,
    *,
    source_verification: SourceLockV2Verification,
    build_inputs: BuildInputClosure,
    policy: FullC6PolicyReceipt,
) -> FullC6AnalysisIRTransaction:
    """Re-derive the transaction and require every owner transformation value."""
    if type(value) is not FullC6AnalysisIRTransaction:
        raise FullC6AnalysisTransactionError("Full C6 analysis/IR transaction is missing")
    rebuilt = create_full_c6_analysis_ir_transaction(
        project_replay_authority=value._project_replay_authority,
        source_verification=source_verification,
        build_inputs=build_inputs,
    )
    if rebuilt.to_dict() != value.to_dict() or not hmac.compare_digest(
        value._transaction_seal,
        _seal(value._payload()),
    ):
        raise FullC6AnalysisTransactionError("Full C6 analysis/IR transaction is stale")
    if type(policy) is not FullC6PolicyReceipt or not policy.transformations:
        raise FullC6AnalysisTransactionError("Full C6 policy transformation coverage is empty")
    for record in policy.transformations:
        expected_ir = value.lowered_ir_sha256(
            transformation_kind=record.kind,
            output_identity=record.output_identity,
            output_identity_sha256=record.output_identity_sha256,
        )
        if (
            not hmac.compare_digest(record.analysis_sha256, value.analysis_sha256)
            or not hmac.compare_digest(record.generator_sha256, value.generator_sha256)
            or not hmac.compare_digest(record.lowered_ir_sha256, expected_ir)
        ):
            raise FullC6AnalysisTransactionError(
                "Full C6 owner transformation policy is not derived from actual analysis/IR"
            )
    return value


def _verified_context(value: SourceLockV2Verification) -> SourceLockV2VerifiedContext:
    if (
        type(value) is not SourceLockV2Verification
        or type(value.context) is not SourceLockV2VerifiedContext
        or value.admission.status != "admitted"
        or not validate_source_lock_v2_verified_context(value.context)
    ):
        raise FullC6AnalysisTransactionError("Full C6 SourceLock context is invalid")
    return value.context


def _rebuild_ref(value: EvidenceFileRef) -> EvidenceFileRef:
    if type(value) is not EvidenceFileRef:
        raise FullC6AnalysisTransactionError("Full C6 transformation file is invalid")
    return EvidenceFileRef(
        logical_path=value.logical_path,
        sha256=value.sha256,
        size=value.size,
        role=value.role,
    )


def _rebuild_project_transformation(
    value: SourceTransformationVerification,
) -> SourceTransformationVerification:
    if type(value) is not SourceTransformationVerification:
        raise FullC6AnalysisTransactionError("Full C6 project replay receipt is invalid")
    try:
        rebuilt = SourceTransformationVerification(
            source_transformation_inventory_sha256=(
                value.source_transformation_inventory_sha256
            ),
            source_input_set_sha256=value.source_input_set_sha256,
            module_ir_sha256=value.module_ir_sha256,
            function_qualnames=tuple(value.function_qualnames),
            source_inputs=tuple(_rebuild_ref(item) for item in value.source_inputs),
            generated_rust=_rebuild_ref(value.generated_rust),
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
    except (TypeError, ValueError) as exc:
        raise FullC6AnalysisTransactionError(
            "Full C6 project replay receipt is noncanonical"
        ) from exc
    if rebuilt != value:
        raise FullC6AnalysisTransactionError("Full C6 project replay receipt is forged")
    return rebuilt


def _require_project_closure_binding(
    value: SourceTransformationReplayAuthority,
    build_inputs: BuildInputClosure,
) -> None:
    if type(build_inputs) is not BuildInputClosure:
        raise FullC6AnalysisTransactionError("Full C6 build-input closure is invalid")
    closure: dict[str, ExactFileIdentity] = {
        item.logical_name: item for item in build_inputs.files
    }
    verification = value.verification
    references = (
        *verification.source_inputs,
        verification.generated_rust,
        *value.generated_python,
        value.generated_cargo_toml,
    )
    for reference in references:
        logical_name = canonical_full_c6_build_input_name(
            reference.logical_path,
            reference.role,
        )
        exact = closure.get(logical_name)
        if (
            exact is None
            or exact.sha256 != reference.sha256
            or exact.size != reference.size
        ):
            raise FullC6AnalysisTransactionError(
                "Full C6 project analysis/IR does not bind the exact build-input closure"
            )


def _seal(payload: object) -> bytes:
    return hmac.new(_TRANSACTION_KEY, canonical_json_bytes(payload), hashlib.sha256).digest()


def _digest(payload: object) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _is_sha256(value: object) -> bool:
    if type(value) is not str or len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


__all__ = [
    "FULL_C6_ANALYSIS_IR_TRANSACTION_DOMAIN",
    "FullC6AnalysisIRTransaction",
    "FullC6AnalysisTransactionError",
    "create_full_c6_analysis_ir_transaction",
    "validate_full_c6_analysis_ir_transaction",
]
