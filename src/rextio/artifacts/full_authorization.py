"""Strict final Full C6 evidence and distribution-authorization contracts.

The C6.2-C6.15 models are deliberately preview-only and must remain unable to
authorize distribution.  This module defines a separate, closed contract for
the first final Full C6 scope.  It is a data boundary, not a cryptographic
verifier: the future hard gate is the only supported producer of these models.

Safety claims are not constructor inputs.  A caller cannot promote a preview
or toggle ``complete``, ``signed``, or ``distribution_authorized`` with boolean
arguments.  Final authorization can only be derived from one deeply rebuilt
``FullC6ArtifactEvidence`` carrying the complete, canonically ordered receipt
set for the frozen scope.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
import unicodedata

from rextio.artifacts.evidence import (
    EvidenceFileRef,
    canonical_json_bytes,
    sha256_hex,
)

FULL_C6_SCOPE = "host-extension-wheel-cpython-external-source-depth1-plugin-free-v1"
FULL_C6_POLICY = "rextio-full-c6-distribution-v1"
FULL_C6_POLICY_VERSION = 1
FULL_C6_EVIDENCE_KIND = "full-c6-artifact-evidence"
FULL_C6_EVIDENCE_SCHEMA_VERSION = 1
FULL_C6_EVIDENCE_STATUS = "complete"
FULL_C6_EVIDENCE_AUTHORITY = "full-c6-verified-evidence"
FULL_C6_AUTHORIZATION_KIND = "artifact-distribution-authorization"
FULL_C6_AUTHORIZATION_STATUS = "authorized"
FULL_C6_AUTHORIZATION_AUTHORITY = "full-c6-hard-gate"
FULL_C6_REPEAT_BUILD_COUNT = 2

FULL_C6_RECEIPT_IDS: tuple[str, ...] = (
    "external-source-archive-bound",
    "external-source-lock-verified",
    "artifact-class-policy-complete",
    "component-license-policy-complete",
    "source-transformation-provenance-complete",
    "native-runtime-closure-complete",
    "runtime-dynamic-loading-verified",
    "build-input-closure-complete",
    "builder-toolchain-identity-bound",
    "repeat-builds-byte-identical",
    "sbom-composition-complete",
    "provenance-complete",
    "attestation-signature-verified",
    "final-output-revalidated",
)
FULL_C6_AUTHORIZATION_CHECK_IDS: tuple[str, ...] = FULL_C6_RECEIPT_IDS

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TARGET_TRIPLE = re.compile(
    r"^(?:aarch64-apple-darwin|x86_64-unknown-linux-gnu)$"
)
_PACKAGE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
_DISTRIBUTION = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
_VERSION = re.compile(r"^[A-Za-z0-9]+(?:[._+-][A-Za-z0-9]+)*$")
_MAX_IDENTITY_CHARS = 256


def _require_sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{label} must be 64 lowercase hexadecimal characters")
    return value


def _require_identity(
    value: object,
    *,
    label: str,
    pattern: re.Pattern[str],
) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > _MAX_IDENTITY_CHARS
        or pattern.fullmatch(value) is None
    ):
        raise ValueError(f"{label} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class FullC6EvidenceReceipt:
    """One exact, closed-vocabulary receipt consumed by the Full C6 gate."""

    id: str
    sha256: str

    def __post_init__(self) -> None:
        if type(self.id) is not str or self.id not in FULL_C6_RECEIPT_IDS:
            raise ValueError("Full C6 receipt id is not in the closed allowlist")
        _require_sha256(self.sha256, "Full C6 receipt sha256")

    def to_dict(self) -> dict[str, str]:
        """Return the deterministic receipt representation."""
        return {"id": self.id, "sha256": self.sha256}


@dataclass(frozen=True, slots=True)
class FullC6ArtifactEvidence:
    """Complete signed evidence for one exact, narrow Full C6 artifact scope.

    ``complete`` and ``signed`` are derived read-only properties.  The evidence
    itself is not distribution authority; a separately derived
    :class:`FullC6DistributionAuthorization` records the final hard-gate result.
    """

    target_triple: str
    subject: EvidenceFileRef
    external_package: str
    external_distribution: str
    external_version: str
    external_source_archive: EvidenceFileRef
    trusted_public_key_sha256: str
    receipts: tuple[FullC6EvidenceReceipt, ...]
    kind: str = field(default=FULL_C6_EVIDENCE_KIND, init=False)
    schema_version: int = field(default=FULL_C6_EVIDENCE_SCHEMA_VERSION, init=False)
    scope: str = field(default=FULL_C6_SCOPE, init=False)
    policy: str = field(default=FULL_C6_POLICY, init=False)
    policy_version: int = field(default=FULL_C6_POLICY_VERSION, init=False)
    status: str = field(default=FULL_C6_EVIDENCE_STATUS, init=False)
    authority: str = field(default=FULL_C6_EVIDENCE_AUTHORITY, init=False)

    def __post_init__(self) -> None:
        if type(self.target_triple) is not str or _TARGET_TRIPLE.fullmatch(
            self.target_triple
        ) is None:
            raise ValueError("Full C6 target triple is outside the frozen scope")
        if type(self.subject) is not EvidenceFileRef:
            raise TypeError("Full C6 subject must be an EvidenceFileRef")
        if (
            self.subject.role != "host-extension-wheel"
            or self.subject.size <= 0
            or not self.subject.logical_path.endswith(".whl")
        ):
            raise ValueError("Full C6 subject must be one non-empty host-extension wheel")
        if type(self.external_source_archive) is not EvidenceFileRef:
            raise TypeError("Full C6 external source archive must be an EvidenceFileRef")
        if (
            self.external_source_archive.role != "external-source-wheel-archive"
            or self.external_source_archive.size <= 0
            or not self.external_source_archive.logical_path.endswith(".whl")
        ):
            raise ValueError("Full C6 external source must be one non-empty wheel archive")
        subject_key = unicodedata.normalize("NFC", self.subject.logical_path).casefold()
        source_key = unicodedata.normalize(
            "NFC", self.external_source_archive.logical_path
        ).casefold()
        if subject_key == source_key:
            raise ValueError("Full C6 subject and source archive paths must not alias")

        _require_identity(
            self.external_package,
            label="Full C6 external package",
            pattern=_PACKAGE,
        )
        _require_identity(
            self.external_distribution,
            label="Full C6 external distribution",
            pattern=_DISTRIBUTION,
        )
        _require_identity(
            self.external_version,
            label="Full C6 external version",
            pattern=_VERSION,
        )
        _require_sha256(
            self.trusted_public_key_sha256,
            "Full C6 trusted public key sha256",
        )
        if type(self.receipts) is not tuple or any(
            type(item) is not FullC6EvidenceReceipt for item in self.receipts
        ):
            raise TypeError("Full C6 receipts must be an exact tuple")
        if tuple(item.id for item in self.receipts) != FULL_C6_RECEIPT_IDS:
            raise ValueError("Full C6 receipts must have exact canonical coverage and order")

    @property
    def complete(self) -> bool:
        """Return the immutable final-evidence completeness claim."""
        return True

    @property
    def signed(self) -> bool:
        """Return the immutable final-evidence signature claim."""
        return True

    @property
    def distribution_authorized(self) -> bool:
        """Keep evidence distinct from the final authorization decision."""
        return False

    @property
    def repeat_build_count(self) -> int:
        """Return the exact repeat-build count frozen by this scope."""
        return FULL_C6_REPEAT_BUILD_COUNT

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic final-evidence contract shape."""
        return {
            "kind": FULL_C6_EVIDENCE_KIND,
            "schema_version": FULL_C6_EVIDENCE_SCHEMA_VERSION,
            "scope": FULL_C6_SCOPE,
            "policy": FULL_C6_POLICY,
            "policy_version": FULL_C6_POLICY_VERSION,
            "status": FULL_C6_EVIDENCE_STATUS,
            "authority": FULL_C6_EVIDENCE_AUTHORITY,
            "artifact_profile": {
                "artifact_kind": "host-extension",
                "packaging_backend": "wheel",
                "python_fallback_backend": "cpython",
                "plugin_ids": [],
            },
            "target_triple": self.target_triple,
            "subject": self.subject.to_dict(),
            "external_source": {
                "package": self.external_package,
                "distribution": self.external_distribution,
                "version": self.external_version,
                "max_depth": 1,
                "archive": self.external_source_archive.to_dict(),
            },
            "trusted_public_key_sha256": self.trusted_public_key_sha256,
            "repeat_build_count": FULL_C6_REPEAT_BUILD_COUNT,
            "receipts": [item.to_dict() for item in self.receipts],
            "complete": True,
            "signed": True,
            "distribution_authorized": False,
        }


def _reconstruct_full_c6_evidence(value: FullC6ArtifactEvidence) -> FullC6ArtifactEvidence:
    """Deeply reconstruct one final record before deriving authorization."""
    if type(value) is not FullC6ArtifactEvidence:
        raise TypeError("Full C6 authorization requires exact final evidence")
    rebuilt = FullC6ArtifactEvidence(
        target_triple=value.target_triple,
        subject=EvidenceFileRef(
            logical_path=value.subject.logical_path,
            sha256=value.subject.sha256,
            size=value.subject.size,
            role=value.subject.role,
        ),
        external_package=value.external_package,
        external_distribution=value.external_distribution,
        external_version=value.external_version,
        external_source_archive=EvidenceFileRef(
            logical_path=value.external_source_archive.logical_path,
            sha256=value.external_source_archive.sha256,
            size=value.external_source_archive.size,
            role=value.external_source_archive.role,
        ),
        trusted_public_key_sha256=value.trusted_public_key_sha256,
        receipts=tuple(
            FullC6EvidenceReceipt(id=item.id, sha256=item.sha256)
            for item in value.receipts
            if type(item) is FullC6EvidenceReceipt
        ),
    )
    if rebuilt != value:
        raise ValueError("Full C6 evidence is not in canonical model form")
    return rebuilt


def full_c6_evidence_digest(value: FullC6ArtifactEvidence) -> str:
    """Return the canonical semantic digest of one reconstructed final record."""
    trusted = _reconstruct_full_c6_evidence(value)
    return sha256_hex(canonical_json_bytes(trusted.to_dict()))


@dataclass(frozen=True, slots=True)
class FullC6AuthorizationCheck:
    """One immutable satisfied check in the final hard-gate result."""

    id: str
    status: str = field(default="satisfied", init=False)

    def __post_init__(self) -> None:
        if type(self.id) is not str or self.id not in FULL_C6_AUTHORIZATION_CHECK_IDS:
            raise ValueError("Full C6 authorization check id is not in the closed allowlist")

    def to_dict(self) -> dict[str, str]:
        """Return the deterministic final check shape."""
        return {"id": self.id, "status": "satisfied"}


@dataclass(frozen=True, slots=True, init=False)
class FullC6DistributionAuthorization:
    """Final positive authorization derived from exact complete signed evidence.

    The constructor accepts only final evidence.  Status, checks, blockers and
    all positive safety claims are derived constants, so caller-supplied flags
    cannot promote an incomplete record.
    """

    evidence_sha256: str
    trusted_public_key_sha256: str
    checks: tuple[FullC6AuthorizationCheck, ...]

    def __init__(self, evidence: FullC6ArtifactEvidence) -> None:
        trusted = _reconstruct_full_c6_evidence(evidence)
        object.__setattr__(self, "evidence_sha256", full_c6_evidence_digest(trusted))
        object.__setattr__(
            self,
            "trusted_public_key_sha256",
            trusted.trusted_public_key_sha256,
        )
        object.__setattr__(
            self,
            "checks",
            tuple(FullC6AuthorizationCheck(id=check_id) for check_id in FULL_C6_RECEIPT_IDS),
        )

    @property
    def complete(self) -> bool:
        """Return the immutable final authorization completeness claim."""
        return True

    @property
    def signed(self) -> bool:
        """Return the immutable verified-signature claim."""
        return True

    @property
    def distribution_authorized(self) -> bool:
        """Return the immutable positive distribution decision."""
        return True

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic final authorization contract shape."""
        return {
            "kind": FULL_C6_AUTHORIZATION_KIND,
            "policy": FULL_C6_POLICY,
            "policy_version": FULL_C6_POLICY_VERSION,
            "scope": FULL_C6_SCOPE,
            "status": FULL_C6_AUTHORIZATION_STATUS,
            "authority": FULL_C6_AUTHORIZATION_AUTHORITY,
            "evidence_sha256": self.evidence_sha256,
            "trusted_public_key_sha256": self.trusted_public_key_sha256,
            "checks": [item.to_dict() for item in self.checks],
            "blockers": [],
            "complete": True,
            "signed": True,
            "distribution_authorized": True,
        }


__all__ = [
    "FULL_C6_AUTHORIZATION_AUTHORITY",
    "FULL_C6_AUTHORIZATION_CHECK_IDS",
    "FULL_C6_AUTHORIZATION_KIND",
    "FULL_C6_AUTHORIZATION_STATUS",
    "FULL_C6_EVIDENCE_AUTHORITY",
    "FULL_C6_EVIDENCE_KIND",
    "FULL_C6_EVIDENCE_SCHEMA_VERSION",
    "FULL_C6_EVIDENCE_STATUS",
    "FULL_C6_POLICY",
    "FULL_C6_POLICY_VERSION",
    "FULL_C6_RECEIPT_IDS",
    "FULL_C6_REPEAT_BUILD_COUNT",
    "FULL_C6_SCOPE",
    "FullC6ArtifactEvidence",
    "FullC6AuthorizationCheck",
    "FullC6DistributionAuthorization",
    "FullC6EvidenceReceipt",
    "full_c6_evidence_digest",
]
