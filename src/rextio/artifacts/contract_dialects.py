"""Immutable semantic dialects for persisted artifact contracts.

The public product terminology changed after 0.1.7.  Persisted policy,
authorization, and SourceLock documents cannot be migrated by partially
matching their metadata, however: their exact root identity and signing domain
are part of the bytes that were reviewed or signed.

New objects always use :data:`CURRENT`.  :data:`LEGACY_0_1_7` exists only so
strict parsers and verifiers can consume exact historical documents.  It must
never be selected for a newly emitted, authorizing, or published artifact.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping


POLICY_BOOTSTRAP = "policy-bootstrap"
POLICY_TEMPLATE = "policy-template"
POLICY_COMPLETION = "policy-completion"
POLICY_MANIFEST = "policy-manifest"
AUTHORIZATION_REQUEST = "authorization-request"
AUTHORIZATION_SIGNATURE = "authorization-signature"
SOURCE_LOCK_MANIFEST = "source-lock-manifest"
SOURCE_LOCK_SIGNATURE = "source-lock-signature"

POLICY_BOOTSTRAP_FILENAME = "policy-bootstrap"
POLICY_MANIFEST_FILENAME = "policy-manifest"
AUTHORIZATION_REQUEST_FILENAME = "authorization-request"

AUTHORIZATION_SIGNED_MESSAGE = "authorization-signed-message"
AUTHORIZATION_VERIFICATION_RECEIPT = "authorization-verification-receipt"
SOURCE_LOCK_SIGNED_MESSAGE = "source-lock-signed-message"
SOURCE_LOCK_VERIFICATION_RECEIPT = "source-lock-verification-receipt"
SOURCE_LOCK_INDEPENDENT_DETECTION = "source-lock-independent-detection"


@dataclass(frozen=True, slots=True)
class ArtifactContractIdentity:
    """The exact root identity of one closed JSON contract."""

    kind: str
    schema_version: int
    domain: str

    @property
    def triple(self) -> tuple[str, int, str]:
        """Return the exact registry key portion encoded by this identity."""
        return (self.kind, self.schema_version, self.domain)


@dataclass(frozen=True, slots=True)
class ArtifactContractDialect:
    """One immutable, internally consistent persisted-contract dialect."""

    name: str
    semantic_version: str
    production_capable: bool
    identities: Mapping[str, ArtifactContractIdentity]
    filenames: Mapping[str, str]
    byte_values: Mapping[str, bytes]
    string_values: Mapping[str, str]

    def identity(self, artifact: str) -> ArtifactContractIdentity:
        """Return the exact root identity for ``artifact``."""
        try:
            return self.identities[artifact]
        except KeyError as exc:
            raise ValueError(f"unknown artifact contract: {artifact}") from exc

    def filename(self, artifact: str) -> str:
        """Return the canonical filename assigned to ``artifact``."""
        try:
            return self.filenames[artifact]
        except KeyError as exc:
            raise ValueError(f"artifact contract has no filename: {artifact}") from exc

    def byte_value(self, name: str) -> bytes:
        """Return one dialect-specific domain-separation byte string."""
        try:
            return self.byte_values[name]
        except KeyError as exc:
            raise ValueError(f"artifact contract has no byte value: {name}") from exc

    def string_value(self, name: str) -> str:
        """Return one dialect-specific semantic string value."""
        try:
            return self.string_values[name]
        except KeyError as exc:
            raise ValueError(f"artifact contract has no string value: {name}") from exc


def _identity(kind: str, schema_version: int, domain: str) -> ArtifactContractIdentity:
    return ArtifactContractIdentity(
        kind=kind,
        schema_version=schema_version,
        domain=domain,
    )


CURRENT = ArtifactContractDialect(
    name="current",
    semantic_version="0.1.8",
    production_capable=True,
    identities=MappingProxyType(
        {
            POLICY_BOOTSTRAP: _identity(
                "artifact-policy-completion-request",
                3,
                "rextio.artifact-policy-bootstrap.v3",
            ),
            POLICY_TEMPLATE: _identity(
                "artifact-policy-technical-template",
                2,
                "rextio.artifact-policy-template.v2",
            ),
            POLICY_COMPLETION: _identity(
                "artifact-policy-owner-completion",
                2,
                "rextio.artifact-policy-owner-completion.v2",
            ),
            POLICY_MANIFEST: _identity(
                "artifact-policy-manifest",
                3,
                "rextio.artifact-policy-manifest.v3",
            ),
            AUTHORIZATION_REQUEST: _identity(
                "artifact-authorization-request",
                2,
                "rextio.artifact-authorization-request.v2",
            ),
            AUTHORIZATION_SIGNATURE: _identity(
                "artifact-authorization-detached-signature",
                2,
                "rextio.artifact-authorization-detached-signature.v2",
            ),
            SOURCE_LOCK_MANIFEST: _identity(
                "rextio.external-source-lock",
                3,
                "rextio.external-source-lock.v3",
            ),
            SOURCE_LOCK_SIGNATURE: _identity(
                "rextio.external-source-lock-detached-signature",
                2,
                "rextio.external-source-lock-signature.v3",
            ),
        }
    ),
    filenames=MappingProxyType(
        {
            POLICY_BOOTSTRAP_FILENAME: "rextio.artifact-policy.bootstrap.json",
            POLICY_MANIFEST_FILENAME: "rextio.artifact-policy.json",
            AUTHORIZATION_REQUEST_FILENAME: "rextio.artifact-authorization-request.json",
        }
    ),
    byte_values=MappingProxyType(
        {
            AUTHORIZATION_SIGNED_MESSAGE: (
                b"REXTIO-ARTIFACT-AUTHORIZATION-ED25519-V2\0"
            ),
            SOURCE_LOCK_SIGNED_MESSAGE: (
                b"REXTIO-EXTERNAL-SOURCE-LOCK-ED25519-V3\0"
            ),
        }
    ),
    string_values=MappingProxyType(
        {
            AUTHORIZATION_VERIFICATION_RECEIPT: (
                "rextio.artifact-authorization-verification.v2"
            ),
            SOURCE_LOCK_VERIFICATION_RECEIPT: (
                "rextio.external-source-lock-verification.v3"
            ),
            SOURCE_LOCK_INDEPENDENT_DETECTION: (
                "pending-independent-license-detection"
            ),
        }
    ),
)


LEGACY_0_1_7 = ArtifactContractDialect(
    name="legacy-0.1.7",
    semantic_version="0.1.7",
    production_capable=False,
    identities=MappingProxyType(
        {
            POLICY_BOOTSTRAP: _identity(
                "full-c6-owner-policy-completion-request",
                2,
                "rextio.full-c6-owner-policy-bootstrap.v2",
            ),
            POLICY_TEMPLATE: _identity(
                "full-c6-owner-policy-technical-template",
                1,
                "rextio.full-c6-owner-policy-template.v1",
            ),
            POLICY_COMPLETION: _identity(
                "full-c6-owner-policy-completion",
                1,
                "rextio.full-c6-owner-policy-completion.v1",
            ),
            POLICY_MANIFEST: _identity(
                "full-c6-owner-policy-manifest",
                2,
                "rextio.full-c6-owner-policy-manifest.v2",
            ),
            AUTHORIZATION_REQUEST: _identity(
                "full-c6-final-authorization-request",
                1,
                "rextio.full-c6-final-authorization-request.v1",
            ),
            AUTHORIZATION_SIGNATURE: _identity(
                "full-c6-detached-signature",
                1,
                "rextio.full-c6-detached-signature.v1",
            ),
            SOURCE_LOCK_MANIFEST: _identity(
                "rextio.external-source-lock",
                2,
                "rextio.external-source-lock.v2",
            ),
            SOURCE_LOCK_SIGNATURE: _identity(
                "rextio.external-source-lock-detached-signature",
                1,
                "rextio.external-source-lock-signature.v2",
            ),
        }
    ),
    filenames=MappingProxyType(
        {
            POLICY_BOOTSTRAP_FILENAME: "rextio.full-c6-policy.bootstrap.json",
            POLICY_MANIFEST_FILENAME: "rextio.full-c6-policy.json",
            AUTHORIZATION_REQUEST_FILENAME: (
                "rextio.full-c6-final-authorization-request.json"
            ),
        }
    ),
    byte_values=MappingProxyType(
        {
            AUTHORIZATION_SIGNED_MESSAGE: b"REXTIO-FULL-C6-ED25519-V1\0",
            SOURCE_LOCK_SIGNED_MESSAGE: (
                b"REXTIO-EXTERNAL-SOURCE-LOCK-ED25519-V2\0"
            ),
        }
    ),
    string_values=MappingProxyType(
        {
            AUTHORIZATION_VERIFICATION_RECEIPT: (
                "rextio.full-c6-signature-verification.v1"
            ),
            SOURCE_LOCK_VERIFICATION_RECEIPT: (
                "rextio.external-source-lock-verification.v2"
            ),
            SOURCE_LOCK_INDEPENDENT_DETECTION: (
                "pending-final-full-c6-detector"
            ),
        }
    ),
)


ARTIFACT_CONTRACT_DIALECTS: Mapping[str, ArtifactContractDialect] = MappingProxyType(
    {
        CURRENT.name: CURRENT,
        LEGACY_0_1_7.name: LEGACY_0_1_7,
    }
)

_EXACT_ROOT_REGISTRY: Mapping[
    tuple[str, str, int, str],
    ArtifactContractDialect,
] = MappingProxyType(
    {
        (artifact, identity.kind, identity.schema_version, identity.domain): dialect
        for dialect in ARTIFACT_CONTRACT_DIALECTS.values()
        for artifact, identity in dialect.identities.items()
    }
)


def resolve_artifact_contract_dialect(
    artifact: str,
    *,
    kind: object,
    schema_version: object,
    domain: object,
) -> ArtifactContractDialect:
    """Resolve only one exact ``(kind, schema_version, domain)`` root triple."""
    if (
        type(kind) is not str
        or type(schema_version) is not int
        or type(domain) is not str
    ):
        raise ValueError("artifact contract root identity has invalid types")
    dialect = _EXACT_ROOT_REGISTRY.get((artifact, kind, schema_version, domain))
    if dialect is None:
        raise ValueError("artifact contract root identity is unknown or hybrid")
    return dialect


def require_current_dialect(dialect: ArtifactContractDialect) -> None:
    """Reject read-only dialects at production authorization/publication gates."""
    if dialect is not CURRENT or not dialect.production_capable:
        raise ValueError("legacy artifact contracts are read/verify-only")


__all__ = [
    "ARTIFACT_CONTRACT_DIALECTS",
    "AUTHORIZATION_REQUEST",
    "AUTHORIZATION_REQUEST_FILENAME",
    "AUTHORIZATION_SIGNATURE",
    "AUTHORIZATION_SIGNED_MESSAGE",
    "AUTHORIZATION_VERIFICATION_RECEIPT",
    "ArtifactContractDialect",
    "ArtifactContractIdentity",
    "CURRENT",
    "LEGACY_0_1_7",
    "POLICY_BOOTSTRAP",
    "POLICY_BOOTSTRAP_FILENAME",
    "POLICY_COMPLETION",
    "POLICY_MANIFEST",
    "POLICY_MANIFEST_FILENAME",
    "POLICY_TEMPLATE",
    "SOURCE_LOCK_INDEPENDENT_DETECTION",
    "SOURCE_LOCK_MANIFEST",
    "SOURCE_LOCK_SIGNATURE",
    "SOURCE_LOCK_SIGNED_MESSAGE",
    "SOURCE_LOCK_VERIFICATION_RECEIPT",
    "require_current_dialect",
    "resolve_artifact_contract_dialect",
]
