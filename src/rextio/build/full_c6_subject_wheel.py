"""Exact subject-wheel capture for the bounded Full C6 profile.

This module deliberately does not grant gate or distribution authority.  It
turns one real, no-follow wheel read into a process-local transaction that can
later be consumed by the Full C6 gate once that integration is reviewed.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from pathlib import Path, PurePosixPath
from typing import SupportsIndex

from rextio.artifacts.evidence import (
    ArtifactEvidenceError,
    EvidenceFileRef,
    WheelEntryRef,
    canonical_json_bytes,
    inventory_wheel_zip_bytes,
)
from rextio.build import wheel_builder
from rextio.build.wheel_builder import (
    ExternalWheelContract,
    ExternalWheelMemberIdentity,
    ExternalWheelNativeMemberIdentity,
    ExternalWheelVerification,
    WheelContractError,
)


FULL_C6_SUBJECT_WHEEL_TRANSACTION_DOMAIN = "rextio.full-c6-subject-wheel.v1"
_SEAL_KEY = secrets.token_bytes(32)


class FullC6SubjectWheelError(RuntimeError):
    """The actual subject wheel did not satisfy its exact frozen contract."""


class FullC6SubjectWheelTransaction:
    """Process-local, immutable authority grounded in one actual wheel read."""

    __slots__ = (
        "subject",
        "wheel_entries",
        "external_verification",
        "native_member",
        "record_member",
        "_wheel_path",
        "_external_contract",
        "_transaction_seal",
    )

    subject: EvidenceFileRef
    wheel_entries: tuple[WheelEntryRef, ...]
    external_verification: ExternalWheelVerification
    native_member: ExternalWheelNativeMemberIdentity
    record_member: WheelEntryRef
    _wheel_path: Path
    _external_contract: ExternalWheelContract
    _transaction_seal: bytes

    def __init__(self) -> None:
        raise TypeError("Full C6 subject-wheel transaction requires the capture factory")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise TypeError("Full C6 subject-wheel transaction is immutable")

    def __delattr__(self, _name: str) -> None:
        raise TypeError("Full C6 subject-wheel transaction is immutable")

    def __copy__(self) -> object:
        raise TypeError("Full C6 subject-wheel transaction cannot be copied")

    def __deepcopy__(self, _memo: object) -> object:
        raise TypeError("Full C6 subject-wheel transaction cannot be copied")

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("Full C6 subject-wheel transaction cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        raise TypeError("Full C6 subject-wheel transaction cannot be serialized")

    def __getstate__(self) -> object:
        raise TypeError("Full C6 subject-wheel transaction cannot be serialized")

    def __repr__(self) -> str:
        return (
            "FullC6SubjectWheelTransaction("
            f"subject_sha256={self.subject.sha256!r}, wheel_material=<sealed>)"
        )

    @property
    def digest(self) -> str:
        """Return the path-free semantic digest of the captured identities."""
        return _digest(_semantic_payload(self))

    def to_dict(self) -> dict[str, str]:
        """Return digest-only evidence; never emit bytes or filesystem/member paths."""
        return {**_semantic_payload(self), "digest": self.digest}


def capture_full_c6_subject_wheel(
    wheel_path: Path | str,
    *,
    expected_subject: EvidenceFileRef,
    expected_wheel_entries: tuple[WheelEntryRef, ...],
    external_contract: ExternalWheelContract,
    native_member_path: str,
    expected_native_member_sha256: str,
    expected_native_member_size: int,
) -> FullC6SubjectWheelTransaction:
    """Capture and seal one real ZIP wheel after deriving every identity again."""
    path = _lexical_absolute_path(wheel_path)
    subject = _rebuild_subject(expected_subject)
    entries = _rebuild_entries(expected_wheel_entries)
    contract = _rebuild_contract(external_contract)
    native = _rebuild_native_member(
        path=native_member_path,
        sha256=expected_native_member_sha256,
        size=expected_native_member_size,
    )
    snapshot = _capture_snapshot(
        path,
        expected_subject=subject,
        expected_entries=entries,
        contract=contract,
        expected_native=native,
    )
    transaction = object.__new__(FullC6SubjectWheelTransaction)
    object.__setattr__(transaction, "subject", snapshot.subject)
    object.__setattr__(transaction, "wheel_entries", snapshot.entries)
    object.__setattr__(transaction, "external_verification", snapshot.verification)
    object.__setattr__(transaction, "native_member", snapshot.native_member)
    object.__setattr__(transaction, "record_member", snapshot.record_member)
    object.__setattr__(transaction, "_wheel_path", path)
    object.__setattr__(transaction, "_external_contract", contract)
    object.__setattr__(transaction, "_transaction_seal", _seal(transaction))
    if not validate_full_c6_subject_wheel_transaction(transaction):
        raise FullC6SubjectWheelError("subject wheel changed before capture completed")
    return transaction


def validate_full_c6_subject_wheel_transaction(
    transaction: FullC6SubjectWheelTransaction,
) -> bool:
    """Reopen the same path no-follow and revalidate the sealed wheel transaction."""
    if type(transaction) is not FullC6SubjectWheelTransaction:
        return False
    try:
        if not hmac.compare_digest(transaction._transaction_seal, _seal(transaction)):
            return False
        snapshot = _capture_snapshot(
            transaction._wheel_path,
            expected_subject=transaction.subject,
            expected_entries=transaction.wheel_entries,
            contract=transaction._external_contract,
            expected_native=transaction.native_member,
        )
    except (FullC6SubjectWheelError, TypeError, ValueError, AttributeError):
        return False
    return (
        snapshot.subject == transaction.subject
        and snapshot.entries == transaction.wheel_entries
        and snapshot.verification == transaction.external_verification
        and snapshot.native_member == transaction.native_member
        and snapshot.record_member == transaction.record_member
        and hmac.compare_digest(transaction._transaction_seal, _seal(transaction))
    )


class _Snapshot:
    __slots__ = ("subject", "entries", "verification", "native_member", "record_member")

    def __init__(
        self,
        *,
        subject: EvidenceFileRef,
        entries: tuple[WheelEntryRef, ...],
        verification: ExternalWheelVerification,
        native_member: ExternalWheelNativeMemberIdentity,
        record_member: WheelEntryRef,
    ) -> None:
        self.subject = subject
        self.entries = entries
        self.verification = verification
        self.native_member = native_member
        self.record_member = record_member


def _capture_snapshot(
    path: Path,
    *,
    expected_subject: EvidenceFileRef,
    expected_entries: tuple[WheelEntryRef, ...],
    contract: ExternalWheelContract,
    expected_native: ExternalWheelNativeMemberIdentity,
) -> _Snapshot:
    if expected_subject.role != "host-extension-wheel":
        raise FullC6SubjectWheelError("subject wheel role is invalid")
    if PurePosixPath(expected_subject.logical_path).name != path.name:
        raise FullC6SubjectWheelError("subject wheel logical identity does not match its path")
    try:
        verified = wheel_builder._verify_external_wheel_contract_pinned(path, contract)
        actual_entries = inventory_wheel_zip_bytes(verified.wheel_bytes)
    except (WheelContractError, ArtifactEvidenceError, OSError) as error:
        raise FullC6SubjectWheelError("subject wheel could not be captured exactly") from error
    actual_subject = EvidenceFileRef(
        logical_path=expected_subject.logical_path,
        sha256=hashlib.sha256(verified.wheel_bytes).hexdigest(),
        size=len(verified.wheel_bytes),
        role=expected_subject.role,
    )
    if actual_subject != expected_subject:
        raise FullC6SubjectWheelError("subject wheel file identity is stale")
    if actual_entries != expected_entries:
        raise FullC6SubjectWheelError("caller-provided subject wheel inventory is stale")
    verification = _rebuild_verification(verified.verification)
    if not hmac.compare_digest(verification.wheel_sha256, actual_subject.sha256):
        raise FullC6SubjectWheelError("subject wheel verification identity is inconsistent")
    native_candidates = tuple(
        sorted(
            name
            for name in verified.payloads
            if PurePosixPath(name).name.startswith("_rextio_native.")
            and name.endswith((".so", ".pyd"))
        )
    )
    if native_candidates != (expected_native.path,):
        raise FullC6SubjectWheelError("subject wheel native member coverage is invalid")
    payload = verified.payloads[expected_native.path]
    if len(payload) != expected_native.size or not hmac.compare_digest(
        hashlib.sha256(payload).hexdigest(), expected_native.sha256
    ):
        raise FullC6SubjectWheelError("subject wheel native member identity is stale")
    record_matches = tuple(
        entry for entry in actual_entries if entry.name == verification.record_member
    )
    if len(record_matches) != 1:
        raise FullC6SubjectWheelError("subject wheel RECORD identity is missing")
    return _Snapshot(
        subject=actual_subject,
        entries=actual_entries,
        verification=verification,
        native_member=expected_native,
        record_member=record_matches[0],
    )


def _lexical_absolute_path(value: Path | str) -> Path:
    if not (type(value) is str or isinstance(value, Path)):
        raise TypeError("subject wheel path must be a string or Path")
    raw = os.fspath(value)
    if not raw:
        raise FullC6SubjectWheelError("subject wheel path is empty")
    return Path(os.path.abspath(raw))


def _rebuild_subject(value: EvidenceFileRef) -> EvidenceFileRef:
    if type(value) is not EvidenceFileRef:
        raise TypeError("expected subject must be an exact EvidenceFileRef")
    try:
        return EvidenceFileRef(
            logical_path=value.logical_path,
            sha256=value.sha256,
            size=value.size,
            role=value.role,
        )
    except (TypeError, ValueError) as error:
        raise FullC6SubjectWheelError("expected subject identity is invalid") from error


def _rebuild_entries(value: tuple[WheelEntryRef, ...]) -> tuple[WheelEntryRef, ...]:
    if type(value) is not tuple or any(type(item) is not WheelEntryRef for item in value):
        raise TypeError("expected wheel entries must be an exact tuple of WheelEntryRef")
    rebuilt: list[WheelEntryRef] = []
    try:
        for item in value:
            if type(item.compressed_size) is not int or type(item.uncompressed_size) is not int:
                raise TypeError("wheel entry sizes must be exact integers")
            rebuilt.append(
                WheelEntryRef(
                    name=item.name,
                    sha256=item.sha256,
                    compressed_size=item.compressed_size,
                    uncompressed_size=item.uncompressed_size,
                )
            )
    except (TypeError, ValueError) as error:
        raise FullC6SubjectWheelError("expected wheel inventory is invalid") from error
    return tuple(rebuilt)


def _rebuild_contract(value: ExternalWheelContract) -> ExternalWheelContract:
    if type(value) is not ExternalWheelContract:
        raise TypeError("external wheel contract has an invalid type")
    try:
        members = tuple(
            ExternalWheelMemberIdentity(path=item.path, sha256=item.sha256, size=item.size)
            for item in value.external_members
            if type(item) is ExternalWheelMemberIdentity
        )
        if len(members) != len(value.external_members):
            raise TypeError("external wheel member has an invalid type")
        return ExternalWheelContract(
            package=value.package,
            distribution=value.distribution,
            version=value.version,
            source_members=tuple(value.source_members),
            external_members=members,
        )
    except (TypeError, ValueError) as error:
        raise FullC6SubjectWheelError("external wheel contract is invalid") from error


def _rebuild_native_member(
    *, path: str, sha256: str, size: int
) -> ExternalWheelNativeMemberIdentity:
    try:
        return ExternalWheelNativeMemberIdentity(path=path, sha256=sha256, size=size)
    except (TypeError, ValueError) as error:
        raise FullC6SubjectWheelError("expected native member identity is invalid") from error


def _rebuild_verification(value: ExternalWheelVerification) -> ExternalWheelVerification:
    if type(value) is not ExternalWheelVerification:
        raise TypeError("external wheel verification has an invalid type")
    return ExternalWheelVerification(
        requirement=value.requirement,
        metadata_member=value.metadata_member,
        record_member=value.record_member,
        wheel_sha256=value.wheel_sha256,
    )


def _semantic_payload(transaction: FullC6SubjectWheelTransaction) -> dict[str, str]:
    return {
        "domain": FULL_C6_SUBJECT_WHEEL_TRANSACTION_DOMAIN,
        "subject_sha256": transaction.subject.sha256,
        "subject_identity_sha256": _digest(transaction.subject.to_dict()),
        "wheel_inventory_sha256": _digest(
            [item.to_dict() for item in transaction.wheel_entries]
        ),
        "external_contract_sha256": _digest(_contract_projection(transaction._external_contract)),
        "external_verification_sha256": _digest(
            {
                "requirement": transaction.external_verification.requirement,
                "metadata_member": transaction.external_verification.metadata_member,
                "record_member": transaction.external_verification.record_member,
                "wheel_sha256": transaction.external_verification.wheel_sha256,
            }
        ),
        "native_member_sha256": transaction.native_member.sha256,
        "native_member_identity_sha256": _digest(
            {
                "path": transaction.native_member.path,
                "sha256": transaction.native_member.sha256,
                "size": transaction.native_member.size,
            }
        ),
        "record_member_sha256": transaction.record_member.sha256,
        "record_member_identity_sha256": _digest(transaction.record_member.to_dict()),
    }


def _contract_projection(value: ExternalWheelContract) -> dict[str, object]:
    return {
        "package": value.package,
        "distribution": value.distribution,
        "version": value.version,
        "source_members": list(value.source_members),
        "external_members": [
            {"path": item.path, "sha256": item.sha256, "size": item.size}
            for item in value.external_members
        ],
    }


def _seal(transaction: FullC6SubjectWheelTransaction) -> bytes:
    payload = {
        "semantic": _semantic_payload(transaction),
        "path_binding_sha256": hashlib.sha256(os.fsencode(transaction._wheel_path)).hexdigest(),
    }
    return hmac.new(_SEAL_KEY, canonical_json_bytes(payload), hashlib.sha256).digest()


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


__all__ = [
    "FULL_C6_SUBJECT_WHEEL_TRANSACTION_DOMAIN",
    "FullC6SubjectWheelError",
    "FullC6SubjectWheelTransaction",
    "capture_full_c6_subject_wheel",
    "validate_full_c6_subject_wheel_transaction",
]
