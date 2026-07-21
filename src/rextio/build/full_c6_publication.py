"""Atomic, fail-closed publication primitives for the frozen Full C6 scope.

The signing request and the final distribution bundle deliberately form two
separate phases.  This module never handles a private key and never mints
distribution authority; it will only publish bytes already covered by the
sealed result returned by :mod:`rextio.build.full_c6_gate`.
"""

from __future__ import annotations

from collections.abc import Mapping
import ctypes
from dataclasses import dataclass
import errno
import hashlib
import hmac
import os
from pathlib import Path, PurePosixPath
import secrets
import shutil
import stat
import sys
import unicodedata
from typing import Final

from rextio.artifacts.evidence import canonical_json_bytes
from rextio.artifacts.full_authorization import (
    FULL_C6_AUTHORIZATION_CHECK_IDS,
    FULL_C6_RECEIPT_IDS,
    FULL_C6_SCOPE,
    FullC6ArtifactEvidence,
    FullC6AuthorizationCheck,
    FullC6DistributionAuthorization,
    FullC6EvidenceReceipt,
    FullC6PreauthorizationEvidence,
    full_c6_evidence_digest,
    full_c6_preauthorization_evidence_digest,
)
from rextio.build.full_c6_gate import (
    FULL_C6_FINAL_OUTPUT_RECEIPT_DOMAIN,
    FullC6GateResult,
)
from rextio.build.full_c6_supply_chain import validate_full_c6_supply_chain_document
from rextio.build.signing import (
    MAX_SIGNATURE_ENVELOPE_BYTES,
    FinalAuthorizationRequest,
    SignatureVerificationReceipt,
    parse_detached_signature_envelope,
    verify_detached_authorization_signature,
)


FULL_C6_PUBLICATION_DOMAIN: Final = "rextio.full-c6-atomic-publication.v1"
FULL_C6_PUBLICATION_MANIFEST_KIND: Final = "full-c6-publication-manifest"
FULL_C6_PUBLICATION_SCHEMA_VERSION: Final = 1
FULL_C6_SIGNING_REQUEST_FILENAME: Final = "rextio.full-c6-final-authorization-request.json"
FULL_C6_PUBLICATION_MANIFEST_FILENAME: Final = "rextio.full-c6-manifest.json"

ROLE_WHEEL: Final = "wheel"
ROLE_CYCLONEDX: Final = "cyclonedx"
ROLE_SLSA_PROVENANCE: Final = "slsa-provenance"
ROLE_FINAL_EVIDENCE: Final = "final-evidence"
ROLE_DETACHED_SIGNATURE: Final = "detached-signature"
ROLE_DISTRIBUTION_AUTHORIZATION: Final = "distribution-authorization"
FULL_C6_PUBLICATION_ROLES: Final = (
    ROLE_WHEEL,
    ROLE_CYCLONEDX,
    ROLE_SLSA_PROVENANCE,
    ROLE_FINAL_EVIDENCE,
    ROLE_DETACHED_SIGNATURE,
    ROLE_DISTRIBUTION_AUTHORIZATION,
)

_FIXED_ROLE_FILENAMES: Final = {
    ROLE_CYCLONEDX: "rextio.cyclonedx.json",
    ROLE_SLSA_PROVENANCE: "rextio.slsa-provenance.json",
    ROLE_FINAL_EVIDENCE: "rextio.full-c6-evidence.json",
    ROLE_DETACHED_SIGNATURE: "rextio.full-c6-signature.json",
    ROLE_DISTRIBUTION_AUTHORIZATION: "rextio.full-c6-authorization.json",
}
_ROLE_MAX_BYTES: Final = {
    ROLE_WHEEL: 16 * 1024 * 1024,
    ROLE_CYCLONEDX: 16 * 1024 * 1024,
    ROLE_SLSA_PROVENANCE: 16 * 1024 * 1024,
    ROLE_FINAL_EVIDENCE: 2 * 1024 * 1024,
    ROLE_DETACHED_SIGNATURE: MAX_SIGNATURE_ENVELOPE_BYTES,
    ROLE_DISTRIBUTION_AUTHORIZATION: 2 * 1024 * 1024,
}
_MAX_REQUEST_BYTES: Final = 64 * 1024
_MAX_BUNDLE_NAME_CHARS: Final = 160
_RAW_ED25519_PUBLIC_KEY_BYTES: Final = 32


class FullC6PublicationError(RuntimeError):
    """Raised when a publication boundary cannot be proven safe."""


class _FullC6TargetExists(FullC6PublicationError):
    pass


@dataclass(frozen=True, slots=True)
class FullC6SigningRequestReceipt:
    """Path-free record that the canonical signing request was materialized."""

    request_sha256: str
    request_size: int
    already_present: bool
    domain: str = FULL_C6_PUBLICATION_DOMAIN

    def __post_init__(self) -> None:
        _require_sha256(self.request_sha256, "signing request")
        if type(self.request_size) is not int or not (1 <= self.request_size <= _MAX_REQUEST_BYTES):
            raise ValueError("Full C6 signing-request size outside bound")
        if type(self.already_present) is not bool:
            raise TypeError("Full C6 signing-request idempotence flag must be bool")
        if self.domain != FULL_C6_PUBLICATION_DOMAIN:
            raise ValueError("Full C6 signing-request receipt domain mismatch")

    @property
    def authorizes_distribution(self) -> bool:
        """A materialized request never grants distribution authority."""
        return False

    def to_dict(self) -> dict[str, object]:
        """Return the immutable path-free receipt shape."""
        return {
            "domain": self.domain,
            "request_sha256": self.request_sha256,
            "request_size": self.request_size,
            "already_present": self.already_present,
            "authorizes_distribution": False,
        }


@dataclass(frozen=True, slots=True)
class FullC6PublishedFile:
    """One logical, path-free member of the published six-file payload."""

    role: str
    logical_name: str
    sha256: str
    size: int

    def __post_init__(self) -> None:
        if type(self.role) is not str or self.role not in FULL_C6_PUBLICATION_ROLES:
            raise ValueError("Full C6 publication role outside closed vocabulary")
        _require_logical_filename(self.logical_name)
        _require_sha256(self.sha256, f"publication role {self.role}")
        maximum = _ROLE_MAX_BYTES[self.role]
        if type(self.size) is not int or not (1 <= self.size <= maximum):
            raise ValueError("Full C6 publication member size outside bound")

    def to_dict(self) -> dict[str, object]:
        """Return the canonical logical member identity."""
        return {
            "role": self.role,
            "logical_name": self.logical_name,
            "sha256": self.sha256,
            "size": self.size,
        }


@dataclass(frozen=True, slots=True)
class FullC6PublicationReceipt:
    """Path-free observation of an atomic publication already authorized elsewhere."""

    target_triple: str
    subject_sha256: str
    evidence_sha256: str
    authorization_sha256: str
    manifest_sha256: str
    bundle_sha256: str
    files: tuple[FullC6PublishedFile, ...]
    domain: str = FULL_C6_PUBLICATION_DOMAIN

    def __post_init__(self) -> None:
        if type(self.target_triple) is not str or not self.target_triple:
            raise ValueError("Full C6 publication target triple invalid")
        for label, value in (
            ("subject", self.subject_sha256),
            ("evidence", self.evidence_sha256),
            ("authorization", self.authorization_sha256),
            ("manifest", self.manifest_sha256),
            ("bundle", self.bundle_sha256),
        ):
            _require_sha256(value, label)
        if (
            type(self.files) is not tuple
            or any(type(item) is not FullC6PublishedFile for item in self.files)
            or tuple(item.role for item in self.files) != FULL_C6_PUBLICATION_ROLES
        ):
            raise ValueError("Full C6 publication receipt file set is not exact")
        if self.domain != FULL_C6_PUBLICATION_DOMAIN:
            raise ValueError("Full C6 publication receipt domain mismatch")

    @property
    def publication_completed(self) -> bool:
        """Report that the atomic rename completed."""
        return True

    @property
    def sealed_authorization_observed(self) -> bool:
        """Report that a sealed authorization was required and observed."""
        return True

    @property
    def authorizes_distribution(self) -> bool:
        """This receipt reflects, but cannot independently grant, authority."""
        return False

    def to_dict(self) -> dict[str, object]:
        """Return the immutable path-free publication receipt."""
        return {
            "domain": self.domain,
            "target_triple": self.target_triple,
            "subject_sha256": self.subject_sha256,
            "evidence_sha256": self.evidence_sha256,
            "authorization_sha256": self.authorization_sha256,
            "manifest_sha256": self.manifest_sha256,
            "bundle_sha256": self.bundle_sha256,
            "files": [item.to_dict() for item in self.files],
            "publication_completed": True,
            "sealed_authorization_observed": True,
            "authorizes_distribution": False,
        }


@dataclass(frozen=True, slots=True)
class _CapturedFile:
    data: bytes
    identity: tuple[int, int, int, int, int, int]

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()


def materialize_full_c6_signing_request(
    *,
    state_directory: Path | str,
    request: FinalAuthorizationRequest,
) -> FullC6SigningRequestReceipt:
    """Safely persist only the canonical request in an owner-private directory.

    Existing byte-identical requests are idempotent.  An existing object with
    different bytes, a non-regular file, or any unsafe path fails closed.
    """
    trusted_request = _rebuild_request(request)
    data = trusted_request.canonical_manifest_bytes
    if not (1 <= len(data) <= _MAX_REQUEST_BYTES):
        raise FullC6PublicationError("Full C6 signing request exceeds byte bound")
    state_path = Path(state_directory)
    directory_fd, directory_stat = _open_safe_directory(
        state_path,
        label="state",
        require_mode_0700=True,
    )
    temporary_name: str | None = None
    try:
        existing = _capture_directory_member(
            directory_fd,
            FULL_C6_SIGNING_REQUEST_FILENAME,
            max_bytes=_MAX_REQUEST_BYTES,
            missing_ok=True,
        )
        if existing is not None:
            if not hmac.compare_digest(existing.data, data):
                raise FullC6PublicationError(
                    "Full C6 signing request already exists with different bytes"
                )
            _revalidate_directory(state_path, directory_stat, label="state")
            return _signing_receipt(data, already_present=True)

        temporary_name = f".rextio-signing-request-{secrets.token_hex(16)}.tmp"
        _write_exclusive_file(directory_fd, temporary_name, data, mode=0o600)

        # The private owner-only directory serializes cooperative callers.  A
        # final check avoids replacing any object that appeared meanwhile.
        raced = _capture_directory_member(
            directory_fd,
            FULL_C6_SIGNING_REQUEST_FILENAME,
            max_bytes=_MAX_REQUEST_BYTES,
            missing_ok=True,
        )
        if raced is not None:
            if not hmac.compare_digest(raced.data, data):
                raise FullC6PublicationError("Full C6 signing request concurrently changed")
            _unlink_owned_member(directory_fd, temporary_name)
            temporary_name = None
            return _signing_receipt(data, already_present=True)

        try:
            _atomic_rename_noreplace(
                directory_fd,
                source_name=temporary_name,
                destination_name=FULL_C6_SIGNING_REQUEST_FILENAME,
            )
        except _FullC6TargetExists:
            raced = _capture_directory_member(
                directory_fd,
                FULL_C6_SIGNING_REQUEST_FILENAME,
                max_bytes=_MAX_REQUEST_BYTES,
                missing_ok=False,
            )
            if raced is None or not hmac.compare_digest(raced.data, data):
                raise FullC6PublicationError(
                    "Full C6 signing request concurrently changed"
                ) from None
            _unlink_owned_member(directory_fd, temporary_name)
            temporary_name = None
            return _signing_receipt(data, already_present=True)
        temporary_name = None
        os.fsync(directory_fd)
        final = _capture_directory_member(
            directory_fd,
            FULL_C6_SIGNING_REQUEST_FILENAME,
            max_bytes=_MAX_REQUEST_BYTES,
            missing_ok=False,
        )
        if final is None or not hmac.compare_digest(final.data, data):
            raise FullC6PublicationError("Full C6 signing request final bytes changed")
        _revalidate_directory(state_path, directory_stat, label="state")
        return _signing_receipt(data, already_present=False)
    except FullC6PublicationError:
        raise
    except OSError as exc:
        raise FullC6PublicationError("Full C6 signing request could not be persisted") from exc
    finally:
        if temporary_name is not None:
            _unlink_owned_member(directory_fd, temporary_name, missing_ok=True)
        os.close(directory_fd)


def _publish_full_c6_bundle(
    *,
    publication_root: Path | str,
    bundle_name: str,
    bundle_files: Mapping[str, Path | str],
    request: FinalAuthorizationRequest,
    gate_result: FullC6GateResult,
    public_key_path: Path | str,
) -> FullC6PublicationReceipt:
    """Publish one exact six-file Full C6 payload with an atomic directory rename.

    The inputs must already contain a detached final signature and the sealed
    hard-gate authorization.  Calling the signing-request primitive alone is
    the supported unsigned state and creates no distribution output.
    """
    trusted_request = _rebuild_request(request)
    trusted_gate = _rebuild_gate_result(gate_result)
    trusted_evidence = trusted_gate.evidence
    trusted_authorization = trusted_gate.authorization
    sources = _normalize_bundle_sources(bundle_files)
    _require_bundle_name(bundle_name)

    captured = _capture_sources(sources)
    public_key_source = Path(public_key_path)
    public_key = _capture_path(
        public_key_source,
        max_bytes=_RAW_ED25519_PUBLIC_KEY_BYTES,
    )
    if len(public_key.data) != _RAW_ED25519_PUBLIC_KEY_BYTES:
        raise FullC6PublicationError("Full C6 public key must be exactly 32 raw bytes")
    published_files = _verify_bundle_semantics(
        captured=captured,
        request=trusted_request,
        gate_result=trusted_gate,
        public_key=public_key.data,
    )
    manifest = _publication_manifest(
        target_triple=trusted_evidence.target_triple,
        subject_sha256=trusted_evidence.subject.sha256,
        evidence_sha256=trusted_authorization.evidence_sha256,
        authorization_request_sha256=trusted_request.manifest_sha256,
        files=published_files,
    )
    manifest_bytes = canonical_json_bytes(manifest)
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    bundle_sha256 = hashlib.sha256(
        canonical_json_bytes(
            {
                "domain": FULL_C6_PUBLICATION_DOMAIN,
                "manifest_sha256": manifest_sha256,
                "files": [item.to_dict() for item in published_files],
            }
        )
    ).hexdigest()
    authorization_bytes = captured[ROLE_DISTRIBUTION_AUTHORIZATION].data
    # Construct and validate the exact path-free receipt before the commit
    # operation.  Once the no-replace rename succeeds there must be no later
    # validation capable of turning a committed authorized bundle into a
    # reported failure.
    receipt = FullC6PublicationReceipt(
        target_triple=trusted_evidence.target_triple,
        subject_sha256=trusted_evidence.subject.sha256,
        evidence_sha256=trusted_authorization.evidence_sha256,
        authorization_sha256=hashlib.sha256(authorization_bytes).hexdigest(),
        manifest_sha256=manifest_sha256,
        bundle_sha256=bundle_sha256,
        files=published_files,
    )

    root_path = Path(publication_root)
    root_fd, root_stat = _open_safe_directory(
        root_path,
        label="publication root",
        require_mode_0700=False,
    )
    staging_name = f".rextio-full-c6-stage-{secrets.token_hex(16)}"
    staging_identity: tuple[int, int] | None = None
    staging_fd: int | None = None
    renamed = False
    try:
        _require_missing_directory_member(root_fd, bundle_name)
        os.mkdir(staging_name, mode=0o700, dir_fd=root_fd)
        staging_fd = os.open(
            staging_name,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=root_fd,
        )
        observed_stage = os.fstat(staging_fd)
        if not stat.S_ISDIR(observed_stage.st_mode):
            raise FullC6PublicationError("Full C6 staging object is not a directory")
        staging_identity = (observed_stage.st_dev, observed_stage.st_ino)
        if observed_stage.st_dev != root_stat.st_dev:
            raise FullC6PublicationError("Full C6 staging crosses filesystem boundary")
        os.fchmod(staging_fd, 0o700)
        for item in published_files:
            _write_exclusive_file(
                staging_fd,
                item.logical_name,
                captured[item.role].data,
                mode=0o600,
            )
        _write_exclusive_file(
            staging_fd,
            FULL_C6_PUBLICATION_MANIFEST_FILENAME,
            manifest_bytes,
            mode=0o600,
        )
        os.fsync(staging_fd)
        staged_members = _verify_staging_directory(
            staging_fd,
            captured=captured,
            files=published_files,
            manifest_bytes=manifest_bytes,
        )

        # Re-read every original immediately before publication.  Identity,
        # metadata, and bytes must all be unchanged since initial capture.
        second_capture = _capture_sources(sources)
        if second_capture != captured:
            raise FullC6PublicationError("Full C6 publication input changed during staging")
        second_public_key = _capture_path(
            public_key_source,
            max_bytes=_RAW_ED25519_PUBLIC_KEY_BYTES,
        )
        if second_public_key != public_key:
            raise FullC6PublicationError("Full C6 public key changed during staging")
        _revalidate_directory(root_path, root_stat, label="publication root")
        _require_directory_member_identity(
            root_fd,
            staging_name,
            expected_identity=staging_identity,
            label="staging",
        )
        # Same-UID processes can always race owner-writable files.  Keep the
        # directory descriptor open and revalidate name->inode plus all bytes
        # at the last possible point; no receipt is returned on any later
        # mismatch.
        _verify_staging_directory(
            staging_fd,
            captured=captured,
            files=published_files,
            manifest_bytes=manifest_bytes,
            expected_members=staged_members,
        )
        # Persist the complete staged tree and its parent entry before the
        # final rename.  Cross-crash durability of the rename itself remains
        # best effort because a post-rename fsync failure cannot safely revoke
        # a bundle that is already visible at its committed name.
        os.fsync(root_fd)
        _revalidate_directory(root_path, root_stat, label="publication root")
        _verify_staging_directory(
            staging_fd,
            captured=captured,
            files=published_files,
            manifest_bytes=manifest_bytes,
            expected_members=staged_members,
        )
        _require_directory_member_identity(
            root_fd,
            staging_name,
            expected_identity=staging_identity,
            label="staging",
        )
        _require_missing_directory_member(root_fd, bundle_name)
        _atomic_rename_noreplace(
            root_fd,
            source_name=staging_name,
            destination_name=bundle_name,
        )
        renamed = True
        _best_effort_postcommit_fsync(root_fd)
    except FullC6PublicationError:
        raise
    except OSError as exc:
        raise FullC6PublicationError("Full C6 bundle publication failed closed") from exc
    finally:
        if staging_fd is not None:
            if renamed:
                _best_effort_close(staging_fd)
            else:
                os.close(staging_fd)
        if not renamed and staging_identity is not None:
            _remove_owned_staging(root_path, staging_name, staging_identity)
        if renamed:
            _best_effort_close(root_fd)
        else:
            os.close(root_fd)

    return receipt


def _rebuild_request(value: FinalAuthorizationRequest) -> FinalAuthorizationRequest:
    if type(value) is not FinalAuthorizationRequest:
        raise FullC6PublicationError("Full C6 signing request type invalid")
    try:
        rebuilt = FinalAuthorizationRequest(
            target_triple=value.target_triple,
            project_sha256=value.project_sha256,
            artifact_sha256=value.artifact_sha256,
            evidence_sha256=value.evidence_sha256,
            reproducibility_sha256=value.reproducibility_sha256,
            policy_sha256=value.policy_sha256,
            scope=value.scope,
        )
    except (TypeError, ValueError) as exc:
        raise FullC6PublicationError("Full C6 signing request invalid") from exc
    if rebuilt != value:
        raise FullC6PublicationError("Full C6 signing request is not canonical")
    return rebuilt


def _rebuild_gate_result(value: FullC6GateResult) -> FullC6GateResult:
    if type(value) is not FullC6GateResult:
        raise FullC6PublicationError(
            "Full C6 publication requires a canonical hard-gate result"
        )
    try:
        raw_pre = value.preauthorization_evidence
        if type(raw_pre) is not FullC6PreauthorizationEvidence:
            raise TypeError("preauthorization evidence type invalid")
        preauthorization = FullC6PreauthorizationEvidence(
            target_triple=raw_pre.target_triple,
            subject=raw_pre.subject,
            external_package=raw_pre.external_package,
            external_distribution=raw_pre.external_distribution,
            external_version=raw_pre.external_version,
            external_source_archive=raw_pre.external_source_archive,
            trusted_public_key_sha256=raw_pre.trusted_public_key_sha256,
            receipts=tuple(
                FullC6EvidenceReceipt(id=item.id, sha256=item.sha256)
                for item in raw_pre.receipts
                if type(item) is FullC6EvidenceReceipt
            ),
        )
        raw_signature = value.signature_receipt
        if type(raw_signature) is not SignatureVerificationReceipt:
            raise TypeError("signature receipt type invalid")
        signature = SignatureVerificationReceipt(
            target_triple=raw_signature.target_triple,
            scope=raw_signature.scope,
            manifest_sha256=raw_signature.manifest_sha256,
            public_key_sha256=raw_signature.public_key_sha256,
            signature_sha256=raw_signature.signature_sha256,
            domain=raw_signature.domain,
            signature_verified=raw_signature.signature_verified,
            authorizes_distribution=raw_signature.authorizes_distribution,
        )
        evidence = _rebuild_evidence(value.evidence)
        authorization = _rebuild_authorization(value.authorization)
        rebuilt = FullC6GateResult(
            preauthorization_evidence=preauthorization,
            signature_receipt=signature,
            evidence=evidence,
            authorization=authorization,
        )
    except FullC6PublicationError:
        raise
    except (AttributeError, TypeError, ValueError) as exc:
        raise FullC6PublicationError("Full C6 hard-gate result is not canonical") from exc
    if rebuilt != value:
        raise FullC6PublicationError("Full C6 hard-gate result is not canonical")
    preauthorization_sha256 = full_c6_preauthorization_evidence_digest(
        preauthorization
    )
    if not (
        evidence.target_triple == preauthorization.target_triple
        and evidence.subject == preauthorization.subject
        and evidence.external_package == preauthorization.external_package
        and evidence.external_distribution == preauthorization.external_distribution
        and evidence.external_version == preauthorization.external_version
        and evidence.external_source_archive == preauthorization.external_source_archive
        and evidence.trusted_public_key_sha256
        == preauthorization.trusted_public_key_sha256
        and evidence.preauthorization_evidence_sha256 == preauthorization_sha256
        and evidence.receipts[: len(preauthorization.receipts)]
        == preauthorization.receipts
        and signature.public_key_sha256 == preauthorization.trusted_public_key_sha256
        and authorization.evidence_sha256 == full_c6_evidence_digest(evidence)
    ):
        raise FullC6PublicationError("Full C6 hard-gate evidence chain is inconsistent")
    return rebuilt


def _rebuild_evidence(value: FullC6ArtifactEvidence) -> FullC6ArtifactEvidence:
    if type(value) is not FullC6ArtifactEvidence:
        raise FullC6PublicationError("Full C6 final evidence type invalid")
    try:
        rebuilt = FullC6ArtifactEvidence(
            target_triple=value.target_triple,
            subject=value.subject,
            external_package=value.external_package,
            external_distribution=value.external_distribution,
            external_version=value.external_version,
            external_source_archive=value.external_source_archive,
            trusted_public_key_sha256=value.trusted_public_key_sha256,
            preauthorization_evidence_sha256=value.preauthorization_evidence_sha256,
            authorization_request_sha256=value.authorization_request_sha256,
            receipts=tuple(
                FullC6EvidenceReceipt(id=item.id, sha256=item.sha256)
                for item in value.receipts
                if type(item) is FullC6EvidenceReceipt
            ),
        )
    except (TypeError, ValueError) as exc:
        raise FullC6PublicationError("Full C6 final evidence invalid") from exc
    if rebuilt != value or tuple(item.id for item in rebuilt.receipts) != FULL_C6_RECEIPT_IDS:
        raise FullC6PublicationError("Full C6 final evidence is not canonical")
    return rebuilt


def _rebuild_authorization(
    value: FullC6DistributionAuthorization,
) -> FullC6DistributionAuthorization:
    if type(value) is not FullC6DistributionAuthorization:
        raise FullC6PublicationError("Full C6 publication requires sealed hard-gate authorization")
    try:
        checks = value.checks
        if (
            type(checks) is not tuple
            or any(type(item) is not FullC6AuthorizationCheck for item in checks)
            or tuple(item.id for item in checks) != FULL_C6_AUTHORIZATION_CHECK_IDS
            or not value.complete
            or not value.signed
            or not value.distribution_authorized
        ):
            raise ValueError("authorization check coverage invalid")
        for label, digest in (
            ("evidence", value.evidence_sha256),
            ("preauthorization evidence", value.preauthorization_evidence_sha256),
            ("authorization request", value.authorization_request_sha256),
            ("trusted public key", value.trusted_public_key_sha256),
        ):
            _require_sha256(digest, label)
    except (AttributeError, TypeError, ValueError) as exc:
        raise FullC6PublicationError("Full C6 sealed authorization invalid") from exc
    return value


def _normalize_bundle_sources(
    value: Mapping[str, Path | str],
) -> dict[str, Path]:
    if type(value) is not dict or set(value) != set(FULL_C6_PUBLICATION_ROLES):
        raise FullC6PublicationError("Full C6 bundle roles must be one exact closed six-file set")
    result: dict[str, Path] = {}
    for role in FULL_C6_PUBLICATION_ROLES:
        item = value[role]
        if type(item) is not str and not isinstance(item, Path):
            raise FullC6PublicationError("Full C6 bundle source path type invalid")
        result[role] = Path(item)
    return result


def _capture_sources(sources: dict[str, Path]) -> dict[str, _CapturedFile]:
    result: dict[str, _CapturedFile] = {}
    inode_keys: set[tuple[int, int]] = set()
    for role in FULL_C6_PUBLICATION_ROLES:
        captured = _capture_path(sources[role], max_bytes=_ROLE_MAX_BYTES[role])
        key = captured.identity[:2]
        if key in inode_keys:
            raise FullC6PublicationError("Full C6 bundle roles alias the same file")
        inode_keys.add(key)
        result[role] = captured
    return result


def _verify_bundle_semantics(
    *,
    captured: dict[str, _CapturedFile],
    request: FinalAuthorizationRequest,
    gate_result: FullC6GateResult,
    public_key: bytes,
) -> tuple[FullC6PublishedFile, ...]:
    evidence = gate_result.evidence
    authorization = gate_result.authorization
    wheel = captured[ROLE_WHEEL]
    if (
        wheel.sha256 != evidence.subject.sha256
        or len(wheel.data) != evidence.subject.size
        or request.artifact_sha256 != evidence.subject.sha256
    ):
        raise FullC6PublicationError("Full C6 wheel does not match authorized subject")

    evidence_sha256 = full_c6_evidence_digest(evidence)
    if not (
        authorization.evidence_sha256 == evidence_sha256
        and authorization.preauthorization_evidence_sha256
        == evidence.preauthorization_evidence_sha256
        and authorization.authorization_request_sha256 == request.manifest_sha256
        and evidence.authorization_request_sha256 == request.manifest_sha256
        and request.evidence_sha256 == evidence.preauthorization_evidence_sha256
        and authorization.trusted_public_key_sha256 == evidence.trusted_public_key_sha256
    ):
        raise FullC6PublicationError("Full C6 authorization bindings are inconsistent")

    expected_evidence = canonical_json_bytes(evidence.to_dict())
    if not hmac.compare_digest(captured[ROLE_FINAL_EVIDENCE].data, expected_evidence):
        raise FullC6PublicationError("Full C6 final evidence JSON is not exact canonical bytes")
    expected_authorization = canonical_json_bytes(authorization.to_dict())
    if not hmac.compare_digest(
        captured[ROLE_DISTRIBUTION_AUTHORIZATION].data,
        expected_authorization,
    ):
        raise FullC6PublicationError("Full C6 authorization JSON is not exact canonical bytes")

    try:
        envelope = parse_detached_signature_envelope(captured[ROLE_DETACHED_SIGNATURE].data)
        signature_receipt = verify_detached_authorization_signature(
            request=request,
            envelope=envelope,
            public_key=public_key,
            expected_public_key_sha256=evidence.trusted_public_key_sha256,
        )
    except Exception as exc:
        raise FullC6PublicationError(
            "Full C6 detached Ed25519 signature verification failed"
        ) from exc
    if signature_receipt != gate_result.signature_receipt:
        raise FullC6PublicationError("Full C6 hard-gate signature receipt is stale")
    receipts = {item.id: item.sha256 for item in evidence.receipts}
    if receipts.get("attestation-signature-verified") != signature_receipt.digest:
        raise FullC6PublicationError("Full C6 signature receipt does not match envelope")

    expected_final_output = hashlib.sha256(
        canonical_json_bytes(
            {
                "domain": FULL_C6_FINAL_OUTPUT_RECEIPT_DOMAIN,
                "scope": FULL_C6_SCOPE,
                "subject": evidence.subject.to_dict(),
            }
        )
    ).hexdigest()
    if receipts.get("final-output-revalidated") != expected_final_output:
        raise FullC6PublicationError("Full C6 final output receipt does not match wheel")

    sbom = captured[ROLE_CYCLONEDX]
    provenance = captured[ROLE_SLSA_PROVENANCE]
    try:
        validate_full_c6_supply_chain_document(
            sbom.data,
            document_kind="sbom",
        )
        validate_full_c6_supply_chain_document(
            provenance.data,
            document_kind="provenance",
        )
    except Exception as exc:
        raise FullC6PublicationError("Full C6 supply-chain document invalid") from exc
    if (
        receipts.get("sbom-composition-complete") != sbom.sha256
        or receipts.get("provenance-complete") != provenance.sha256
    ):
        raise FullC6PublicationError("Full C6 supply-chain document digest mismatch")

    wheel_name = PurePosixPath(evidence.subject.logical_path).name
    _require_logical_filename(wheel_name)
    names = {ROLE_WHEEL: wheel_name, **_FIXED_ROLE_FILENAMES}
    return tuple(
        FullC6PublishedFile(
            role=role,
            logical_name=names[role],
            sha256=captured[role].sha256,
            size=len(captured[role].data),
        )
        for role in FULL_C6_PUBLICATION_ROLES
    )


def _publication_manifest(
    *,
    target_triple: str,
    subject_sha256: str,
    evidence_sha256: str,
    authorization_request_sha256: str,
    files: tuple[FullC6PublishedFile, ...],
) -> dict[str, object]:
    return {
        "kind": FULL_C6_PUBLICATION_MANIFEST_KIND,
        "schema_version": FULL_C6_PUBLICATION_SCHEMA_VERSION,
        "domain": FULL_C6_PUBLICATION_DOMAIN,
        "scope": FULL_C6_SCOPE,
        "target_triple": target_triple,
        "subject_sha256": subject_sha256,
        "evidence_sha256": evidence_sha256,
        "authorization_request_sha256": authorization_request_sha256,
        "payload_file_count": len(FULL_C6_PUBLICATION_ROLES),
        "files": [item.to_dict() for item in files],
    }


def _capture_path(path: Path, *, max_bytes: int) -> _CapturedFile:
    _reject_symlink_components(path)
    try:
        before = os.lstat(path)
        _require_regular_single_link(before)
        if before.st_size <= 0 or before.st_size > max_bytes:
            raise FullC6PublicationError("Full C6 bundle member exceeds byte bound")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        if sys.platform == "win32":
            flags |= getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            _require_same_regular(before, opened)
            data = _read_bounded(descriptor, max_bytes=max_bytes)
            after = os.fstat(descriptor)
            _require_same_regular(opened, after)
            if len(data) != after.st_size:
                raise FullC6PublicationError("Full C6 bundle member changed while reading")
        finally:
            os.close(descriptor)
        final = os.lstat(path)
        _require_same_regular(opened, final)
        return _CapturedFile(data=data, identity=_stat_identity(final))
    except FullC6PublicationError:
        raise
    except (OSError, ValueError) as exc:
        raise FullC6PublicationError("Full C6 bundle member could not be captured safely") from exc


def _capture_directory_member(
    directory_fd: int,
    name: str,
    *,
    max_bytes: int,
    missing_ok: bool,
) -> _CapturedFile | None:
    try:
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        if missing_ok:
            return None
        raise FullC6PublicationError("Full C6 required file is missing") from None
    _require_regular_single_link(before)
    if before.st_size <= 0 or before.st_size > max_bytes:
        raise FullC6PublicationError("Full C6 file exceeds byte bound")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(name, flags, dir_fd=directory_fd)
    try:
        opened = os.fstat(descriptor)
        _require_same_regular(before, opened)
        data = _read_bounded(descriptor, max_bytes=max_bytes)
        final = os.fstat(descriptor)
        _require_same_regular(opened, final)
    finally:
        os.close(descriptor)
    if len(data) != final.st_size:
        raise FullC6PublicationError("Full C6 file changed while reading")
    try:
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as exc:
        raise FullC6PublicationError("Full C6 file name changed during capture") from exc
    _require_same_regular(final, named)
    return _CapturedFile(data=data, identity=_stat_identity(named))


def _open_safe_directory(
    path: Path,
    *,
    label: str,
    require_mode_0700: bool,
) -> tuple[int, os.stat_result]:
    _reject_symlink_components(path)
    try:
        before = os.lstat(path)
        if not stat.S_ISDIR(before.st_mode):
            raise FullC6PublicationError(f"Full C6 {label} must be a directory")
        mode = stat.S_IMODE(before.st_mode)
        if require_mode_0700 and mode != 0o700:
            raise FullC6PublicationError(f"Full C6 {label} must have mode 0700")
        if not require_mode_0700 and mode & 0o022:
            raise FullC6PublicationError(f"Full C6 {label} must not be group/world writable")
        if hasattr(os, "geteuid") and before.st_uid != os.geteuid():
            raise FullC6PublicationError(f"Full C6 {label} must be owned by current user")
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if not stat.S_ISDIR(opened.st_mode) or (
            before.st_dev,
            before.st_ino,
        ) != (opened.st_dev, opened.st_ino):
            os.close(descriptor)
            raise FullC6PublicationError(f"Full C6 {label} changed during open")
        return descriptor, opened
    except FullC6PublicationError:
        raise
    except OSError as exc:
        raise FullC6PublicationError(f"Full C6 {label} could not be opened safely") from exc


def _require_directory_member_identity(
    directory_fd: int,
    name: str,
    *,
    expected_identity: tuple[int, int],
    label: str,
) -> None:
    try:
        observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as exc:
        raise FullC6PublicationError(f"Full C6 {label} name changed") from exc
    if (
        not stat.S_ISDIR(observed.st_mode)
        or stat.S_ISLNK(observed.st_mode)
        or (observed.st_dev, observed.st_ino) != expected_identity
    ):
        raise FullC6PublicationError(f"Full C6 {label} name-to-inode binding changed")


def _revalidate_directory(path: Path, expected: os.stat_result, *, label: str) -> None:
    try:
        observed = os.lstat(path)
    except OSError as exc:
        raise FullC6PublicationError(f"Full C6 {label} changed during operation") from exc
    if not stat.S_ISDIR(observed.st_mode) or (
        observed.st_dev,
        observed.st_ino,
    ) != (expected.st_dev, expected.st_ino):
        raise FullC6PublicationError(f"Full C6 {label} changed during operation")


def _write_exclusive_file(directory_fd: int, name: str, data: bytes, *, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, mode, dir_fd=directory_fd)
    try:
        os.fchmod(descriptor, mode)
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise FullC6PublicationError("Full C6 file write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        observed = os.fstat(descriptor)
        _require_regular_single_link(observed)
        if observed.st_size != len(data):
            raise FullC6PublicationError("Full C6 written file size mismatch")
    finally:
        os.close(descriptor)


def _best_effort_postcommit_fsync(directory_fd: int) -> None:
    """Request directory durability without revoking an already committed rename."""
    try:
        os.fsync(directory_fd)
    except OSError:
        # The atomic no-replace rename is the publication commit point.  Once
        # it succeeds, an fsync error can describe uncertain crash durability
        # but cannot truthfully turn the visible signed bundle into a failed or
        # unauthorized publication.
        return


def _best_effort_close(descriptor: int) -> None:
    """Close a post-commit descriptor without manufacturing a false failure."""
    try:
        os.close(descriptor)
    except OSError:
        return


def _verify_staging_directory(
    directory_fd: int,
    *,
    captured: dict[str, _CapturedFile],
    files: tuple[FullC6PublishedFile, ...],
    manifest_bytes: bytes,
    expected_members: dict[str, _CapturedFile] | None = None,
) -> dict[str, _CapturedFile]:
    expected = {item.logical_name for item in files}
    expected.add(FULL_C6_PUBLICATION_MANIFEST_FILENAME)
    try:
        actual = set(os.listdir(directory_fd))
    except OSError as exc:
        raise FullC6PublicationError("Full C6 staging directory cannot be enumerated") from exc
    if actual != expected:
        raise FullC6PublicationError("Full C6 staging directory contains missing or extra files")
    observed_members: dict[str, _CapturedFile] = {}
    for item in files:
        staged = _capture_directory_member(
            directory_fd,
            item.logical_name,
            max_bytes=_ROLE_MAX_BYTES[item.role],
            missing_ok=False,
        )
        if staged is None or not hmac.compare_digest(staged.data, captured[item.role].data):
            raise FullC6PublicationError("Full C6 staged payload changed")
        observed_members[item.logical_name] = staged
    staged_manifest = _capture_directory_member(
        directory_fd,
        FULL_C6_PUBLICATION_MANIFEST_FILENAME,
        max_bytes=2 * 1024 * 1024,
        missing_ok=False,
    )
    if staged_manifest is None or not hmac.compare_digest(staged_manifest.data, manifest_bytes):
        raise FullC6PublicationError("Full C6 staged manifest changed")
    observed_members[FULL_C6_PUBLICATION_MANIFEST_FILENAME] = staged_manifest
    if expected_members is not None and observed_members != expected_members:
        raise FullC6PublicationError("Full C6 staged member identity changed")
    return observed_members


def _remove_owned_staging(
    root: Path,
    name: str,
    expected_identity: tuple[int, int],
) -> None:
    candidate = root / name
    try:
        observed = os.lstat(candidate)
        if (
            stat.S_ISDIR(observed.st_mode)
            and not stat.S_ISLNK(observed.st_mode)
            and (observed.st_dev, observed.st_ino) == expected_identity
        ):
            shutil.rmtree(candidate)
    except FileNotFoundError:
        return
    except OSError:
        # Never broaden cleanup after a boundary change.  Leaving private
        # owned staging is safer than deleting an object we cannot identify.
        return


def _require_missing_directory_member(directory_fd: int, name: str) -> None:
    try:
        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise FullC6PublicationError("Full C6 publication target cannot be inspected") from exc
    raise _FullC6TargetExists("Full C6 publication target already exists")


def _atomic_rename_noreplace(
    directory_fd: int,
    *,
    source_name: str,
    destination_name: str,
) -> None:
    """Atomically rename within one directory without replacing any target."""
    source = os.fsencode(source_name)
    destination = os.fsencode(destination_name)
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        if sys.platform == "darwin":
            rename = libc.renameatx_np
            rename.argtypes = (
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            )
            rename.restype = ctypes.c_int
            result = rename(
                directory_fd,
                source,
                directory_fd,
                destination,
                0x00000004,  # RENAME_EXCL from <sys/stdio.h>.
            )
        elif sys.platform.startswith("linux"):
            rename = libc.renameat2
            rename.argtypes = (
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            )
            rename.restype = ctypes.c_int
            result = rename(
                directory_fd,
                source,
                directory_fd,
                destination,
                0x00000001,  # RENAME_NOREPLACE from <linux/fs.h>.
            )
        else:
            raise FullC6PublicationError(
                "Full C6 atomic no-replace rename is unavailable on this platform"
            )
    except AttributeError as exc:
        raise FullC6PublicationError("Full C6 atomic no-replace rename API is unavailable") from exc
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise _FullC6TargetExists("Full C6 publication target already exists")
    if error_number == errno.EXDEV:
        raise FullC6PublicationError("Full C6 publication crosses filesystem boundary")
    raise FullC6PublicationError(
        f"Full C6 atomic no-replace rename failed with errno {error_number}"
    )


def _reject_symlink_components(path: Path) -> None:
    absolute = path.absolute()
    for component in reversed((absolute, *absolute.parents)):
        try:
            observed = os.lstat(component)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise FullC6PublicationError("Full C6 path component cannot be inspected") from exc
        if stat.S_ISLNK(observed.st_mode):
            raise FullC6PublicationError("Full C6 path contains symlink component")


def _read_bounded(descriptor: int, *, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    remaining = max_bytes + 1
    while remaining > 0:
        try:
            chunk = os.read(descriptor, min(65536, remaining))
        except BlockingIOError as exc:
            raise FullC6PublicationError("Full C6 file cannot be read safely") from exc
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    if len(data) > max_bytes:
        raise FullC6PublicationError("Full C6 file exceeds byte bound")
    return data


def _require_regular_single_link(value: os.stat_result) -> None:
    if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
        raise FullC6PublicationError("Full C6 file must be regular and single-linked")


def _require_same_regular(first: os.stat_result, second: os.stat_result) -> None:
    _require_regular_single_link(second)
    if _stat_identity(first) != _stat_identity(second):
        raise FullC6PublicationError("Full C6 file changed during capture")


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mode,
        getattr(value, "st_mtime_ns", int(value.st_mtime * 1_000_000_000)),
        getattr(value, "st_ctime_ns", int(value.st_ctime * 1_000_000_000)),
    )


def _signing_receipt(data: bytes, *, already_present: bool) -> FullC6SigningRequestReceipt:
    return FullC6SigningRequestReceipt(
        request_sha256=hashlib.sha256(data).hexdigest(),
        request_size=len(data),
        already_present=already_present,
    )


def _unlink_owned_member(directory_fd: int, name: str, *, missing_ok: bool = False) -> None:
    try:
        observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1:
            return
        os.unlink(name, dir_fd=directory_fd)
    except FileNotFoundError:
        if not missing_ok:
            raise
    except OSError:
        return


def _require_bundle_name(value: str) -> None:
    if (
        type(value) is not str
        or not value
        or len(value) > _MAX_BUNDLE_NAME_CHARS
        or value != unicodedata.normalize("NFC", value)
        or PurePosixPath(value).name != value
        or value in {".", ".."}
        or any(ord(character) < 32 for character in value)
    ):
        raise FullC6PublicationError("Full C6 publication bundle name invalid")


def _require_logical_filename(value: str) -> None:
    if (
        type(value) is not str
        or not value
        or len(value) > 255
        or value != unicodedata.normalize("NFC", value)
        or PurePosixPath(value).name != value
        or value in {".", ".."}
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError("Full C6 logical filename invalid")


def _require_sha256(value: object, label: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"Full C6 {label} SHA-256 invalid")


__all__ = [
    "FULL_C6_PUBLICATION_DOMAIN",
    "FULL_C6_PUBLICATION_MANIFEST_FILENAME",
    "FULL_C6_PUBLICATION_MANIFEST_KIND",
    "FULL_C6_PUBLICATION_ROLES",
    "FULL_C6_PUBLICATION_SCHEMA_VERSION",
    "FULL_C6_SIGNING_REQUEST_FILENAME",
    "ROLE_CYCLONEDX",
    "ROLE_DETACHED_SIGNATURE",
    "ROLE_DISTRIBUTION_AUTHORIZATION",
    "ROLE_FINAL_EVIDENCE",
    "ROLE_SLSA_PROVENANCE",
    "ROLE_WHEEL",
    "FullC6PublicationError",
    "FullC6PublicationReceipt",
    "FullC6PublishedFile",
    "FullC6SigningRequestReceipt",
    "materialize_full_c6_signing_request",
]
