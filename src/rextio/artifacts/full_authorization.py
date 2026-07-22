"""Closed evidence models for the first strict Full C6 authorization gate.

The final detached signature cannot sign a digest which already contains its
own verification receipt.  Full C6 therefore has two deliberately different
evidence records:

* :class:`FullC6PreauthorizationEvidence` contains the exact twelve receipts
  available before signing.  Its digest is the value carried by
  ``FinalAuthorizationRequest.evidence_sha256``.
* :class:`FullC6ArtifactEvidence` adds the verified-signature and final-output
  revalidation receipts only after the signature has been checked.

Neither record is distribution authority.  The positive authorization model
has a sealed constructor and is minted only by ``rextio.build.full_c6_gate``.
The older C6.2--C6.15 preview models remain separate and non-authorizing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
import unicodedata

from rextio.artifacts.evidence import EvidenceFileRef, canonical_json_bytes, sha256_hex


FULL_C6_SCOPE = "host-extension-wheel-cpython-external-source-depth1-plugin-free-v1"
FULL_C6_POLICY = "rextio-full-c6-distribution-v1"
FULL_C6_POLICY_VERSION = 1
FULL_C6_PREAUTHORIZATION_EVIDENCE_KIND = "full-c6-preauthorization-evidence"
FULL_C6_PREAUTHORIZATION_EVIDENCE_STATUS = "unsigned-complete"
FULL_C6_PREAUTHORIZATION_EVIDENCE_AUTHORITY = "full-c6-preauthorization-only"
FULL_C6_EVIDENCE_KIND = "full-c6-artifact-evidence"
FULL_C6_EVIDENCE_SCHEMA_VERSION = 1
FULL_C6_EVIDENCE_STATUS = "complete"
FULL_C6_EVIDENCE_AUTHORITY = "full-c6-verified-evidence"
FULL_C6_AUTHORIZATION_KIND = "artifact-distribution-authorization"
FULL_C6_AUTHORIZATION_STATUS = "authorized"
FULL_C6_AUTHORIZATION_AUTHORITY = "full-c6-hard-gate"
FULL_C6_REPEAT_BUILD_COUNT = 2

# This exact set exists before the final authorization request is signed.  It
# intentionally excludes both the signature-verification receipt and the
# subject revalidation which occurs after signature verification.
FULL_C6_PREAUTHORIZATION_RECEIPT_IDS: tuple[str, ...] = (
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
)
FULL_C6_POSTAUTHORIZATION_RECEIPT_IDS: tuple[str, ...] = (
    "attestation-signature-verified",
    "final-output-revalidated",
)
FULL_C6_RECEIPT_IDS: tuple[str, ...] = (
    *FULL_C6_PREAUTHORIZATION_RECEIPT_IDS,
    *FULL_C6_POSTAUTHORIZATION_RECEIPT_IDS,
)
FULL_C6_AUTHORIZATION_CHECK_IDS: tuple[str, ...] = FULL_C6_RECEIPT_IDS

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TARGET_TRIPLE = re.compile(r"^(?:aarch64-apple-darwin|x86_64-unknown-linux-gnu)$")
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


def _rebuild_file_ref(value: EvidenceFileRef, *, label: str) -> EvidenceFileRef:
    if type(value) is not EvidenceFileRef:
        raise TypeError(f"{label} must be an EvidenceFileRef")
    return EvidenceFileRef(
        logical_path=value.logical_path,
        sha256=value.sha256,
        size=value.size,
        role=value.role,
    )


def _validate_evidence_identity(
    *,
    target_triple: str,
    subject: EvidenceFileRef,
    external_package: str,
    external_distribution: str,
    external_version: str,
    external_source_archive: EvidenceFileRef,
    trusted_public_key_sha256: str,
) -> tuple[EvidenceFileRef, EvidenceFileRef]:
    if type(target_triple) is not str or _TARGET_TRIPLE.fullmatch(target_triple) is None:
        raise ValueError("Full C6 target triple is outside the frozen scope")
    trusted_subject = _rebuild_file_ref(subject, label="Full C6 subject")
    if (
        trusted_subject.role != "host-extension-wheel"
        or trusted_subject.size <= 0
        or not trusted_subject.logical_path.endswith(".whl")
    ):
        raise ValueError("Full C6 subject must be one non-empty host-extension wheel")
    trusted_source = _rebuild_file_ref(
        external_source_archive,
        label="Full C6 external source archive",
    )
    if (
        trusted_source.role != "external-source-wheel-archive"
        or trusted_source.size <= 0
        or not trusted_source.logical_path.endswith(".whl")
    ):
        raise ValueError("Full C6 external source must be one non-empty wheel archive")
    subject_key = unicodedata.normalize("NFC", trusted_subject.logical_path).casefold()
    source_key = unicodedata.normalize("NFC", trusted_source.logical_path).casefold()
    if subject_key == source_key:
        raise ValueError("Full C6 subject and source archive paths must not alias")
    _require_identity(external_package, label="Full C6 external package", pattern=_PACKAGE)
    _require_identity(
        external_distribution,
        label="Full C6 external distribution",
        pattern=_DISTRIBUTION,
    )
    _require_identity(external_version, label="Full C6 external version", pattern=_VERSION)
    _require_sha256(trusted_public_key_sha256, "Full C6 trusted public key sha256")
    return trusted_subject, trusted_source


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
class FullC6PreauthorizationEvidence:
    """Complete unsigned evidence whose digest is safe to sign exactly once."""

    target_triple: str
    subject: EvidenceFileRef
    external_package: str
    external_distribution: str
    external_version: str
    external_source_archive: EvidenceFileRef
    trusted_public_key_sha256: str
    receipts: tuple[FullC6EvidenceReceipt, ...]
    kind: str = field(default=FULL_C6_PREAUTHORIZATION_EVIDENCE_KIND, init=False)
    schema_version: int = field(default=FULL_C6_EVIDENCE_SCHEMA_VERSION, init=False)
    scope: str = field(default=FULL_C6_SCOPE, init=False)
    policy: str = field(default=FULL_C6_POLICY, init=False)
    policy_version: int = field(default=FULL_C6_POLICY_VERSION, init=False)
    status: str = field(default=FULL_C6_PREAUTHORIZATION_EVIDENCE_STATUS, init=False)
    authority: str = field(default=FULL_C6_PREAUTHORIZATION_EVIDENCE_AUTHORITY, init=False)

    def __post_init__(self) -> None:
        subject, source = _validate_evidence_identity(
            target_triple=self.target_triple,
            subject=self.subject,
            external_package=self.external_package,
            external_distribution=self.external_distribution,
            external_version=self.external_version,
            external_source_archive=self.external_source_archive,
            trusted_public_key_sha256=self.trusted_public_key_sha256,
        )
        object.__setattr__(self, "subject", subject)
        object.__setattr__(self, "external_source_archive", source)
        if type(self.receipts) is not tuple or any(
            type(item) is not FullC6EvidenceReceipt for item in self.receipts
        ):
            raise TypeError("Full C6 preauthorization receipts must be an exact tuple")
        if tuple(item.id for item in self.receipts) != FULL_C6_PREAUTHORIZATION_RECEIPT_IDS:
            raise ValueError(
                "Full C6 preauthorization receipts must have exact canonical coverage and order"
            )

    @property
    def complete(self) -> bool:
        """The exact pre-signing receipt set is complete for the frozen scope."""
        return True

    @property
    def signed(self) -> bool:
        """Preauthorization evidence is intentionally unsigned."""
        return False

    @property
    def distribution_authorized(self) -> bool:
        """Preauthorization evidence never grants distribution authority."""
        return False

    @property
    def repeat_build_count(self) -> int:
        """Return the exact repeat-build count frozen by this scope."""
        return FULL_C6_REPEAT_BUILD_COUNT

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic preauthorization evidence shape."""
        return _evidence_payload(
            kind=FULL_C6_PREAUTHORIZATION_EVIDENCE_KIND,
            status=FULL_C6_PREAUTHORIZATION_EVIDENCE_STATUS,
            authority=FULL_C6_PREAUTHORIZATION_EVIDENCE_AUTHORITY,
            target_triple=self.target_triple,
            subject=self.subject,
            external_package=self.external_package,
            external_distribution=self.external_distribution,
            external_version=self.external_version,
            external_source_archive=self.external_source_archive,
            trusted_public_key_sha256=self.trusted_public_key_sha256,
            receipts=self.receipts,
            signed=False,
        )


@dataclass(frozen=True, slots=True)
class FullC6ArtifactEvidence:
    """Final evidence assembled only after signature and output revalidation."""

    target_triple: str
    subject: EvidenceFileRef
    external_package: str
    external_distribution: str
    external_version: str
    external_source_archive: EvidenceFileRef
    trusted_public_key_sha256: str
    preauthorization_evidence_sha256: str
    authorization_request_sha256: str
    receipts: tuple[FullC6EvidenceReceipt, ...]
    kind: str = field(default=FULL_C6_EVIDENCE_KIND, init=False)
    schema_version: int = field(default=FULL_C6_EVIDENCE_SCHEMA_VERSION, init=False)
    scope: str = field(default=FULL_C6_SCOPE, init=False)
    policy: str = field(default=FULL_C6_POLICY, init=False)
    policy_version: int = field(default=FULL_C6_POLICY_VERSION, init=False)
    status: str = field(default=FULL_C6_EVIDENCE_STATUS, init=False)
    authority: str = field(default=FULL_C6_EVIDENCE_AUTHORITY, init=False)

    def __post_init__(self) -> None:
        subject, source = _validate_evidence_identity(
            target_triple=self.target_triple,
            subject=self.subject,
            external_package=self.external_package,
            external_distribution=self.external_distribution,
            external_version=self.external_version,
            external_source_archive=self.external_source_archive,
            trusted_public_key_sha256=self.trusted_public_key_sha256,
        )
        object.__setattr__(self, "subject", subject)
        object.__setattr__(self, "external_source_archive", source)
        _require_sha256(
            self.preauthorization_evidence_sha256,
            "Full C6 preauthorization evidence sha256",
        )
        _require_sha256(
            self.authorization_request_sha256,
            "Full C6 authorization request sha256",
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
            **_evidence_payload(
                kind=FULL_C6_EVIDENCE_KIND,
                status=FULL_C6_EVIDENCE_STATUS,
                authority=FULL_C6_EVIDENCE_AUTHORITY,
                target_triple=self.target_triple,
                subject=self.subject,
                external_package=self.external_package,
                external_distribution=self.external_distribution,
                external_version=self.external_version,
                external_source_archive=self.external_source_archive,
                trusted_public_key_sha256=self.trusted_public_key_sha256,
                receipts=self.receipts,
                signed=True,
            ),
            "preauthorization_evidence_sha256": self.preauthorization_evidence_sha256,
            "authorization_request_sha256": self.authorization_request_sha256,
        }


def _evidence_payload(
    *,
    kind: str,
    status: str,
    authority: str,
    target_triple: str,
    subject: EvidenceFileRef,
    external_package: str,
    external_distribution: str,
    external_version: str,
    external_source_archive: EvidenceFileRef,
    trusted_public_key_sha256: str,
    receipts: tuple[FullC6EvidenceReceipt, ...],
    signed: bool,
) -> dict[str, object]:
    return {
        "kind": kind,
        "schema_version": FULL_C6_EVIDENCE_SCHEMA_VERSION,
        "scope": FULL_C6_SCOPE,
        "policy": FULL_C6_POLICY,
        "policy_version": FULL_C6_POLICY_VERSION,
        "status": status,
        "authority": authority,
        "artifact_profile": {
            "artifact_kind": "host-extension",
            "packaging_backend": "wheel",
            "python_fallback_backend": "cpython",
            "plugin_ids": [],
        },
        "target_triple": target_triple,
        "subject": subject.to_dict(),
        "external_source": {
            "package": external_package,
            "distribution": external_distribution,
            "version": external_version,
            "max_depth": 1,
            "archive": external_source_archive.to_dict(),
        },
        "trusted_public_key_sha256": trusted_public_key_sha256,
        "repeat_build_count": FULL_C6_REPEAT_BUILD_COUNT,
        "receipts": [item.to_dict() for item in receipts],
        "complete": True,
        "signed": signed,
        "distribution_authorized": False,
    }


def _reconstruct_full_c6_preauthorization_evidence(
    value: FullC6PreauthorizationEvidence,
) -> FullC6PreauthorizationEvidence:
    if type(value) is not FullC6PreauthorizationEvidence:
        raise TypeError("Full C6 gate requires exact preauthorization evidence")
    rebuilt = FullC6PreauthorizationEvidence(
        target_triple=value.target_triple,
        subject=_rebuild_file_ref(value.subject, label="Full C6 subject"),
        external_package=value.external_package,
        external_distribution=value.external_distribution,
        external_version=value.external_version,
        external_source_archive=_rebuild_file_ref(
            value.external_source_archive,
            label="Full C6 external source archive",
        ),
        trusted_public_key_sha256=value.trusted_public_key_sha256,
        receipts=tuple(
            FullC6EvidenceReceipt(id=item.id, sha256=item.sha256)
            for item in value.receipts
            if type(item) is FullC6EvidenceReceipt
        ),
    )
    if rebuilt != value:
        raise ValueError("Full C6 preauthorization evidence is not canonical")
    return rebuilt


def _reconstruct_full_c6_evidence(value: FullC6ArtifactEvidence) -> FullC6ArtifactEvidence:
    if type(value) is not FullC6ArtifactEvidence:
        raise TypeError("Full C6 authorization requires exact final evidence")
    rebuilt = FullC6ArtifactEvidence(
        target_triple=value.target_triple,
        subject=_rebuild_file_ref(value.subject, label="Full C6 subject"),
        external_package=value.external_package,
        external_distribution=value.external_distribution,
        external_version=value.external_version,
        external_source_archive=_rebuild_file_ref(
            value.external_source_archive,
            label="Full C6 external source archive",
        ),
        trusted_public_key_sha256=value.trusted_public_key_sha256,
        preauthorization_evidence_sha256=value.preauthorization_evidence_sha256,
        authorization_request_sha256=value.authorization_request_sha256,
        receipts=tuple(
            FullC6EvidenceReceipt(id=item.id, sha256=item.sha256)
            for item in value.receipts
            if type(item) is FullC6EvidenceReceipt
        ),
    )
    if rebuilt != value:
        raise ValueError("Full C6 evidence is not in canonical model form")
    return rebuilt


def full_c6_preauthorization_evidence_digest(
    value: FullC6PreauthorizationEvidence,
) -> str:
    """Return the non-circular digest signed by the final owner request."""
    trusted = _reconstruct_full_c6_preauthorization_evidence(value)
    return sha256_hex(canonical_json_bytes(trusted.to_dict()))


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
    """Sealed positive result minted exclusively by the final hard gate."""

    evidence_sha256: str
    preauthorization_evidence_sha256: str
    authorization_request_sha256: str
    trusted_public_key_sha256: str
    checks: tuple[FullC6AuthorizationCheck, ...]

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError(
            "Full C6 distribution authorization can only be created by the hard gate"
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
            "preauthorization_evidence_sha256": self.preauthorization_evidence_sha256,
            "authorization_request_sha256": self.authorization_request_sha256,
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
    "FULL_C6_POSTAUTHORIZATION_RECEIPT_IDS",
    "FULL_C6_PREAUTHORIZATION_EVIDENCE_AUTHORITY",
    "FULL_C6_PREAUTHORIZATION_EVIDENCE_KIND",
    "FULL_C6_PREAUTHORIZATION_EVIDENCE_STATUS",
    "FULL_C6_PREAUTHORIZATION_RECEIPT_IDS",
    "FULL_C6_RECEIPT_IDS",
    "FULL_C6_REPEAT_BUILD_COUNT",
    "FULL_C6_SCOPE",
    "FullC6ArtifactEvidence",
    "FullC6AuthorizationCheck",
    "FullC6DistributionAuthorization",
    "FullC6EvidenceReceipt",
    "FullC6PreauthorizationEvidence",
    "full_c6_evidence_digest",
    "full_c6_preauthorization_evidence_digest",
]
