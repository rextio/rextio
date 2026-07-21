"""Signed, non-authorizing SourceLock v2 admission for bounded C5.2.

This lock is intentionally domain-separated from Full C6 artifact signing.  A
valid signature admits exact external source bytes to prebuild analysis/codegen
work only; it cannot authorize a build, package, redistribution, or release.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import SupportsIndex

from rextio.artifacts import ArtifactProvenance
from rextio.build.signing import verify_ed25519_signature
from rextio.source.external import (
    MAX_SOURCE_LOCK_BYTES,
    AuthorityFile,
    ExternalSourcePlan,
)
from rextio.source.external_analysis import (
    ExternalSourceNativePlan,
    analyze_external_source_snapshot,
)
from rextio.source.models import SourceModule, SourceOrigin
from rextio.source.authorization import (
    SOURCE_LOCK_FILENAME,
    ExternalSourceAuthorization,
)
from rextio.source.wheel_authority import (
    SourceWheelArchiveIdentity,
    SourceWheelEntryIdentity,
    VerifiedSourceWheel,
    verify_source_wheel,
)


SOURCE_LOCK_V2_KIND = "rextio.external-source-lock"
SOURCE_LOCK_V2_SCHEMA_VERSION = 2
SOURCE_LOCK_V2_DOMAIN = "rextio.external-source-lock.v2"
SOURCE_LOCK_V2_SIGNATURE_KIND = "rextio.external-source-lock-detached-signature"
SOURCE_LOCK_V2_SIGNATURE_DOMAIN = "rextio.external-source-lock-signature.v2"
SOURCE_LOCK_V2_RECEIPT_DOMAIN = "rextio.external-source-lock-verification.v2"
SOURCE_LOCK_V2_SIGNED_MESSAGE_PREFIX = b"REXTIO-EXTERNAL-SOURCE-LOCK-ED25519-V2\0"
MAX_SOURCE_LOCK_V2_SIGNATURE_BYTES = 16 * 1024
MAX_SOURCE_LOCK_V2_KEY_BYTES = 32
SOURCE_LOCK_V2_LICENSE_DETECTION = "pending-final-full-c6-detector"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_OWNER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._@+:/-]{0,254}$")
_VERIFIED_CONTEXT_KEY = os.urandom(32)


class SourceLockV2Error(ValueError):
    """Stable internal rejection used by the total public verifier."""


@dataclass(frozen=True, slots=True)
class SourceLockV2FunctionIdentity:
    """Exact analyzed scalar-function identity."""

    qualname: str
    semantic_ast_sha256: str
    lowered_ir_sha256: str

    def __post_init__(self) -> None:
        if type(self.qualname) is not str or not self.qualname or len(self.qualname) > 512:
            raise ValueError("SourceLock v2 function identity is invalid")
        _require_sha256(self.semantic_ast_sha256, "function AST")
        _require_sha256(self.lowered_ir_sha256, "function IR")

    def to_dict(self) -> dict[str, str]:
        """Return the canonical function identity."""
        return {
            "qualname": self.qualname,
            "semantic_ast_sha256": self.semantic_ast_sha256,
            "lowered_ir_sha256": self.lowered_ir_sha256,
        }


@dataclass(frozen=True, slots=True)
class SourceLockV2AnalysisIdentity:
    """Exact analysis result for one wheel source snapshot."""

    module_name: str
    source_sha256: str
    semantic_sha256: str
    functions: tuple[SourceLockV2FunctionIdentity, ...]

    def __post_init__(self) -> None:
        if type(self.module_name) is not str or not self.module_name:
            raise ValueError("SourceLock v2 analysis module is invalid")
        _require_sha256(self.source_sha256, "analysis source")
        _require_sha256(self.semantic_sha256, "analysis semantic")
        if (
            type(self.functions) is not tuple
            or not self.functions
            or not all(type(item) is SourceLockV2FunctionIdentity for item in self.functions)
            or tuple(item.qualname for item in self.functions)
            != tuple(sorted(item.qualname for item in self.functions))
            or len({item.qualname for item in self.functions}) != len(self.functions)
        ):
            raise ValueError("SourceLock v2 analysis functions are invalid")

    def to_dict(self) -> dict[str, object]:
        """Return the canonical module-analysis identity."""
        return {
            "module_name": self.module_name,
            "source_sha256": self.source_sha256,
            "semantic_sha256": self.semantic_sha256,
            "functions": [item.to_dict() for item in self.functions],
        }


@dataclass(frozen=True, slots=True)
class SourceLockV2Manifest:
    """Closed canonical manifest signed by the external-source owner.

    ``observed_license`` is the exact source-wheel METADATA observation.  It is
    deliberately not represented as independent license detection; that final
    Full C6 evidence remains pending under ``SOURCE_LOCK_V2_LICENSE_DETECTION``.
    """

    package: str
    distribution: str
    version: str
    plan_snapshot_sha256: str
    wheel_authority_sha256: str
    archive: SourceWheelArchiveIdentity
    entries: tuple[SourceWheelEntryIdentity, ...]
    analyses: tuple[SourceLockV2AnalysisIdentity, ...]
    declared_license: str
    observed_license: str
    license_material_sha256: str
    license_evidence_sha256: str
    owner: str
    allow: bool
    redistribute: bool
    transform: bool
    trusted_public_key_sha256: str
    kind: str = field(default=SOURCE_LOCK_V2_KIND, init=False)
    schema_version: int = field(default=SOURCE_LOCK_V2_SCHEMA_VERSION, init=False)
    domain: str = field(default=SOURCE_LOCK_V2_DOMAIN, init=False)
    max_depth: int = field(default=1, init=False)
    authority: str = field(default="prebuild-admission-only", init=False)

    def __post_init__(self) -> None:
        if not all(
            type(value) is str and value
            for value in (self.package, self.distribution, self.version)
        ):
            raise ValueError("SourceLock v2 package identity is invalid")
        for value, label in (
            (self.plan_snapshot_sha256, "plan snapshot"),
            (self.wheel_authority_sha256, "wheel authority"),
            (self.license_material_sha256, "license material"),
            (self.license_evidence_sha256, "license evidence"),
            (self.trusted_public_key_sha256, "trusted public key"),
        ):
            _require_sha256(value, label)
        if type(self.archive) is not SourceWheelArchiveIdentity:
            raise TypeError("SourceLock v2 archive identity is invalid")
        if (
            type(self.entries) is not tuple
            or not self.entries
            or not all(type(item) is SourceWheelEntryIdentity for item in self.entries)
            or tuple(item.path for item in self.entries)
            != tuple(sorted(item.path for item in self.entries))
            or len({item.path for item in self.entries}) != len(self.entries)
        ):
            raise ValueError("SourceLock v2 entries are invalid")
        if (
            type(self.analyses) is not tuple
            or not self.analyses
            or not all(type(item) is SourceLockV2AnalysisIdentity for item in self.analyses)
            or tuple(item.module_name for item in self.analyses)
            != tuple(sorted(item.module_name for item in self.analyses))
            or len({item.module_name for item in self.analyses}) != len(self.analyses)
        ):
            raise ValueError("SourceLock v2 analyses are invalid")
        if (
            type(self.declared_license) is not str
            or not self.declared_license
            or type(self.observed_license) is not str
            or not self.observed_license
            or self.declared_license != self.observed_license
        ):
            raise ValueError("SourceLock v2 license evidence disagrees")
        if type(self.owner) is not str or _OWNER.fullmatch(self.owner) is None:
            raise ValueError("SourceLock v2 owner identity is invalid")
        if self.allow is not True or self.redistribute is not True or self.transform is not True:
            raise ValueError("SourceLock v2 owner decision must allow every required scope")

    @property
    def canonical_json_bytes(self) -> bytes:
        """Return the only byte representation accepted for signing."""
        return _canonical_json(self.to_dict())

    @property
    def manifest_sha256(self) -> str:
        """Return the canonical manifest digest."""
        return hashlib.sha256(self.canonical_json_bytes).hexdigest()

    def to_dict(self) -> dict[str, object]:
        """Return the closed SourceLock v2 document."""
        return {
            "kind": SOURCE_LOCK_V2_KIND,
            "schema_version": SOURCE_LOCK_V2_SCHEMA_VERSION,
            "domain": SOURCE_LOCK_V2_DOMAIN,
            "authority": "prebuild-admission-only",
            "package": self.package,
            "distribution": self.distribution,
            "version": self.version,
            "max_depth": 1,
            "plan_snapshot_sha256": self.plan_snapshot_sha256,
            "wheel_authority_sha256": self.wheel_authority_sha256,
            "archive": self.archive.to_dict(),
            "entries": [item.to_dict() for item in self.entries],
            "analyses": [item.to_dict() for item in self.analyses],
            "license": {
                "declared": self.declared_license,
                "observed": self.observed_license,
                "independent_detection": SOURCE_LOCK_V2_LICENSE_DETECTION,
                "material_sha256": self.license_material_sha256,
                "evidence_sha256": self.license_evidence_sha256,
            },
            "owner_decision": {
                "owner": self.owner,
                "allow": True,
                "redistribute": True,
                "transform": True,
            },
            "trusted_public_key_sha256": self.trusted_public_key_sha256,
            "authorizes_build": False,
            "authorizes_distribution": False,
        }


@dataclass(frozen=True, slots=True)
class SourceLockV2Signature:
    """Detached SourceLock v2 Ed25519 signature envelope."""

    public_key_sha256: str
    manifest_sha256: str
    signature: str

    def __post_init__(self) -> None:
        _require_sha256(self.public_key_sha256, "signature public key")
        _require_sha256(self.manifest_sha256, "signature manifest")
        _decode_signature(self.signature)

    @classmethod
    def from_signature(
        cls,
        *,
        public_key_sha256: str,
        manifest_sha256: str,
        signature: bytes,
    ) -> SourceLockV2Signature:
        """Construct an envelope from one exact raw signature."""
        if type(signature) is not bytes or len(signature) != 64:
            raise ValueError("SourceLock v2 signature must be 64 bytes")
        return cls(
            public_key_sha256=public_key_sha256,
            manifest_sha256=manifest_sha256,
            signature=base64.b64encode(signature).decode("ascii"),
        )

    @property
    def signature_bytes(self) -> bytes:
        """Return the exact decoded Ed25519 signature."""
        return _decode_signature(self.signature)

    @property
    def canonical_json_bytes(self) -> bytes:
        """Return the canonical detached-envelope bytes."""
        return _canonical_json(self.to_dict())

    def to_dict(self) -> dict[str, object]:
        """Return the closed detached-envelope document."""
        return {
            "kind": SOURCE_LOCK_V2_SIGNATURE_KIND,
            "schema_version": 1,
            "algorithm": "ed25519",
            "domain": SOURCE_LOCK_V2_SIGNATURE_DOMAIN,
            "public_key_sha256": self.public_key_sha256,
            "manifest_sha256": self.manifest_sha256,
            "signature": self.signature,
        }


@dataclass(frozen=True, slots=True)
class SourceLockV2Admission:
    """Total, non-authorizing result of SourceLock v2 verification."""

    status: str
    reason: str
    manifest_sha256: str | None = None
    public_key_sha256: str | None = None
    signature_sha256: str | None = None
    domain: str = SOURCE_LOCK_V2_RECEIPT_DOMAIN
    prebuild_admitted: bool = False
    authorizes_build: bool = False
    authorizes_distribution: bool = False

    def __post_init__(self) -> None:
        if self.domain != SOURCE_LOCK_V2_RECEIPT_DOMAIN:
            raise ValueError("SourceLock v2 admission domain is invalid")
        if self.status not in {"admitted", "rejected"}:
            raise ValueError("SourceLock v2 admission status is invalid")
        admitted = self.status == "admitted"
        if admitted != self.prebuild_admitted:
            raise ValueError("SourceLock v2 admission status is inconsistent")
        if self.authorizes_build or self.authorizes_distribution:
            raise ValueError("SourceLock v2 admission cannot authorize an artifact")
        hashes = (self.manifest_sha256, self.public_key_sha256, self.signature_sha256)
        if admitted:
            for value, label in zip(hashes, ("manifest", "public key", "signature"), strict=True):
                _require_sha256(value, label)
        elif any(value is not None for value in hashes):
            raise ValueError("rejected SourceLock v2 admission must not carry identities")

    def to_dict(self) -> dict[str, object]:
        """Return the sanitized total admission result."""
        return {
            "domain": SOURCE_LOCK_V2_RECEIPT_DOMAIN,
            "status": self.status,
            "reason": self.reason,
            "manifest_sha256": self.manifest_sha256,
            "public_key_sha256": self.public_key_sha256,
            "signature_sha256": self.signature_sha256,
            "prebuild_admitted": self.prebuild_admitted,
            "authorizes_build": False,
            "authorizes_distribution": False,
        }


class SourceLockV2VerifiedContext:
    """Sealed, non-copyable objects admitted by one verification transaction.

    This is deliberately not a dataclass: ``dataclasses.asdict`` must never
    traverse the source bytes and local paths held for immediate codegen.  The
    transaction seal is process-local and bound to the safe semantic digests;
    consumers must call :func:`validate_source_lock_v2_verified_context` at an
    authority boundary instead of reconstructing a context.
    """

    admission: SourceLockV2Admission
    plan: ExternalSourcePlan
    wheel: VerifiedSourceWheel
    analyses: tuple[ExternalSourceNativePlan, ...]
    manifest: SourceLockV2Manifest
    _transaction_seal: bytes
    _frozen: bool

    __slots__ = (
        "admission",
        "plan",
        "wheel",
        "analyses",
        "manifest",
        "_transaction_seal",
        "_frozen",
    )

    def __init__(
        self,
        *,
        admission: SourceLockV2Admission,
        plan: ExternalSourcePlan,
        wheel: VerifiedSourceWheel,
        analyses: tuple[ExternalSourceNativePlan, ...],
        manifest: SourceLockV2Manifest,
        _transaction_seal: bytes | None = None,
    ) -> None:
        if type(_transaction_seal) is not bytes:
            raise TypeError("SourceLock v2 context requires a verification transaction")
        object.__setattr__(self, "admission", admission)
        object.__setattr__(self, "plan", plan)
        object.__setattr__(self, "wheel", wheel)
        object.__setattr__(self, "analyses", analyses)
        object.__setattr__(self, "manifest", manifest)
        object.__setattr__(self, "_transaction_seal", _transaction_seal)
        object.__setattr__(self, "_frozen", True)
        self._validate_bindings()
        expected_seal = _source_lock_context_seal(
            admission=admission,
            plan=plan,
            wheel=wheel,
            analyses=analyses,
            manifest=manifest,
        )
        if not hmac.compare_digest(_transaction_seal, expected_seal):
            raise ValueError("SourceLock v2 verified context seal is invalid")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise TypeError("SourceLock v2 verified context is immutable")

    def _validate_bindings(self) -> None:
        if (
            type(self.admission) is not SourceLockV2Admission
            or self.admission.status != "admitted"
            or type(self.plan) is not ExternalSourcePlan
            or self.plan.authorization is not None
            or type(self.wheel) is not VerifiedSourceWheel
            or type(self.analyses) is not tuple
            or not self.analyses
            or any(type(item) is not ExternalSourceNativePlan for item in self.analyses)
            or type(self.manifest) is not SourceLockV2Manifest
        ):
            raise ValueError("SourceLock v2 verified context is invalid")
        expected = build_source_lock_v2_manifest(
            plan=self.plan,
            wheel=self.wheel,
            analyses=self.analyses,
            owner=self.manifest.owner,
            trusted_public_key_sha256=self.manifest.trusted_public_key_sha256,
            allow=self.manifest.allow,
            redistribute=self.manifest.redistribute,
            transform=self.manifest.transform,
        )
        if (
            expected != self.manifest
            or self.admission.manifest_sha256 != self.manifest.manifest_sha256
            or self.admission.public_key_sha256 != self.manifest.trusted_public_key_sha256
        ):
            raise ValueError("SourceLock v2 verified context bindings disagree")

    def __repr__(self) -> str:
        return (
            "SourceLockV2VerifiedContext("
            f"manifest_sha256={self.manifest.manifest_sha256!r}, "
            "source_material=<sealed>)"
        )

    def __copy__(self) -> object:
        raise TypeError("SourceLock v2 verified context cannot be copied")

    def __deepcopy__(self, _memo: object) -> object:
        raise TypeError("SourceLock v2 verified context cannot be copied")

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("SourceLock v2 verified context cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        raise TypeError("SourceLock v2 verified context cannot be serialized")

    def __getstate__(self) -> object:
        raise TypeError("SourceLock v2 verified context cannot be serialized")

    def to_dict(self) -> dict[str, object]:
        """Return only sanitized digests; never serialize source or local paths."""
        return {
            "admission": self.admission.to_dict(),
            "plan_snapshot_sha256": self.manifest.plan_snapshot_sha256,
            "wheel_authority_sha256": self.manifest.wheel_authority_sha256,
            "analysis_semantic_sha256": [item.semantic_sha256 for item in self.analyses],
            "manifest_sha256": self.manifest.manifest_sha256,
            "context_available": True,
            "authorizes_build": False,
            "authorizes_distribution": False,
        }


def _source_lock_context_seal(
    *,
    admission: SourceLockV2Admission,
    plan: ExternalSourcePlan,
    wheel: VerifiedSourceWheel,
    analyses: tuple[ExternalSourceNativePlan, ...],
    manifest: SourceLockV2Manifest,
) -> bytes:
    """Bind a context to safe semantic identities with a process-local MAC."""
    payload = {
        "admission": admission.to_dict(),
        "plan_snapshot_sha256": plan.plan_snapshot_sha256(),
        "wheel_authority_sha256": wheel.semantic_sha256,
        "analysis_semantic_sha256": [item.semantic_sha256 for item in analyses],
        "manifest_sha256": manifest.manifest_sha256,
    }
    return hmac.new(_VERIFIED_CONTEXT_KEY, _canonical_json(payload), hashlib.sha256).digest()


def _create_source_lock_v2_verified_context(
    *,
    admission: SourceLockV2Admission,
    plan: ExternalSourcePlan,
    wheel: VerifiedSourceWheel,
    analyses: tuple[ExternalSourceNativePlan, ...],
    manifest: SourceLockV2Manifest,
) -> SourceLockV2VerifiedContext:
    seal = _source_lock_context_seal(
        admission=admission,
        plan=plan,
        wheel=wheel,
        analyses=analyses,
        manifest=manifest,
    )
    return SourceLockV2VerifiedContext(
        admission=admission,
        plan=plan,
        wheel=wheel,
        analyses=analyses,
        manifest=manifest,
        _transaction_seal=seal,
    )


def validate_source_lock_v2_verified_context(
    value: SourceLockV2VerifiedContext,
) -> bool:
    """Return whether a context retains its exact same-transaction bindings."""
    try:
        if type(value) is not SourceLockV2VerifiedContext:
            return False
        value._validate_bindings()
        expected = _source_lock_context_seal(
            admission=value.admission,
            plan=value.plan,
            wheel=value.wheel,
            analyses=value.analyses,
            manifest=value.manifest,
        )
        return hmac.compare_digest(value._transaction_seal, expected)
    except Exception:
        return False


@dataclass(frozen=True, slots=True)
class SourceLockV2Verification:
    """Total result with an in-memory context only after exact admission."""

    admission: SourceLockV2Admission
    context: SourceLockV2VerifiedContext | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if type(self.admission) is not SourceLockV2Admission:
            raise TypeError("SourceLock v2 verification admission is invalid")
        if self.admission.status == "admitted":
            if (
                type(self.context) is not SourceLockV2VerifiedContext
                or self.context.admission != self.admission
                or not validate_source_lock_v2_verified_context(self.context)
            ):
                raise ValueError("admitted SourceLock v2 verification requires context")
        elif self.context is not None:
            raise ValueError("rejected SourceLock v2 verification cannot expose context")

    def to_dict(self) -> dict[str, object]:
        """Return the total sanitized result without the in-memory context."""
        return {
            **self.admission.to_dict(),
            "verified_context_available": self.context is not None,
        }


def build_source_lock_v2_manifest(
    *,
    plan: ExternalSourcePlan,
    wheel: VerifiedSourceWheel,
    analyses: tuple[ExternalSourceNativePlan, ...],
    owner: str,
    trusted_public_key_sha256: str,
    allow: bool = True,
    redistribute: bool = True,
    transform: bool = True,
) -> SourceLockV2Manifest:
    """Build the sole canonical manifest for exact verified inputs."""
    if type(plan) is not ExternalSourcePlan or type(wheel) is not VerifiedSourceWheel:
        raise SourceLockV2Error("SourceLock v2 inputs are invalid")
    snapshot_digest = plan.plan_snapshot_sha256()
    license_digest = plan.license_material_sha256()
    if (
        snapshot_digest is None
        or license_digest is None
        or plan.max_depth != 1
        or plan.status != "preview-ready"
        or plan.license is None
        or wheel.package != plan.package
        or wheel.distribution != plan.distribution
        or wheel.version != plan.requested_version
        or wheel.license_observed != plan.license
        or not wheel.license_entry_paths
        or not any(item.role == "license-file" for item in plan.metadata_files)
    ):
        raise SourceLockV2Error("SourceLock v2 inputs do not match the C5.1 plan")
    if (
        type(analyses) is not tuple
        or not analyses
        or not all(type(item) is ExternalSourceNativePlan for item in analyses)
    ):
        raise SourceLockV2Error("SourceLock v2 analyses are invalid")
    snapshots = {item.module.module_name: item for item in wheel.snapshots}
    if len(snapshots) != len(wheel.snapshots):
        raise SourceLockV2Error("SourceLock v2 snapshots are duplicated")
    identities: list[SourceLockV2AnalysisIdentity] = []
    for analysis in analyses:
        module_name = analysis.snapshot.module.module_name
        snapshot = snapshots.get(module_name)
        if snapshot is None or snapshot != analysis.snapshot:
            raise SourceLockV2Error("SourceLock v2 analysis snapshot is stale")
        identities.append(
            SourceLockV2AnalysisIdentity(
                module_name=module_name,
                source_sha256=analysis.snapshot.module.sha256,
                semantic_sha256=analysis.semantic_sha256,
                functions=tuple(
                    SourceLockV2FunctionIdentity(
                        qualname=item.qualname,
                        semantic_ast_sha256=item.semantic_ast_sha256,
                        lowered_ir_sha256=item.lowered_ir_sha256,
                    )
                    for item in analysis.functions
                ),
            )
        )
    identities_tuple = tuple(sorted(identities, key=lambda item: item.module_name))
    if tuple(item.module_name for item in identities_tuple) != tuple(sorted(snapshots)):
        raise SourceLockV2Error("SourceLock v2 analysis coverage is incomplete")
    analyzed_functions = tuple(
        function.qualname for identity in identities_tuple for function in identity.functions
    )
    if tuple(sorted(analyzed_functions)) != tuple(sorted(plan.candidate_functions)):
        raise SourceLockV2Error("SourceLock v2 function coverage disagrees with the plan")
    entry_by_path = {item.path: item for item in wheel.entries}
    license_entries = tuple(entry_by_path[path].to_dict() for path in wheel.license_entry_paths)
    license_evidence_sha256 = hashlib.sha256(_canonical_json(license_entries)).hexdigest()
    return SourceLockV2Manifest(
        package=plan.package,
        distribution=plan.distribution,
        version=plan.requested_version,
        plan_snapshot_sha256=snapshot_digest,
        wheel_authority_sha256=wheel.semantic_sha256,
        archive=wheel.archive,
        entries=wheel.entries,
        analyses=identities_tuple,
        declared_license=plan.license,
        observed_license=wheel.license_observed,
        license_material_sha256=license_digest,
        license_evidence_sha256=license_evidence_sha256,
        owner=owner,
        allow=allow,
        redistribute=redistribute,
        transform=transform,
        trusted_public_key_sha256=trusted_public_key_sha256,
    )


def _deep_rebuild_plan(plan: ExternalSourcePlan) -> ExternalSourcePlan:
    """Rebuild the strict C5.2 plan without trusting frozen Python objects."""
    if type(plan) is not ExternalSourcePlan:
        raise SourceLockV2Error("SourceLock v2 plan is invalid")
    if (
        type(plan.package) is not str
        or type(plan.distribution) is not str
        or type(plan.requested_version) is not str
        or type(plan.installed_version) is not str
        or type(plan.max_depth) is not int
        or type(plan.status) is not str
        or type(plan.license) is not str
        or type(plan.modules) is not tuple
        or type(plan.candidate_functions) is not tuple
        or type(plan.source_files) is not tuple
        or type(plan.metadata_files) is not tuple
        or type(plan.inventory_schema) is not str
        or (plan.reason is not None and type(plan.reason) is not str)
    ):
        raise SourceLockV2Error("SourceLock v2 plan shape is invalid")
    if not plan.candidate_functions or any(
        type(item) is not str for item in plan.candidate_functions
    ):
        raise SourceLockV2Error("SourceLock v2 candidate functions are invalid")
    if plan.authorization is not None:
        _deep_rebuild_legacy_authorization(plan.authorization, plan=plan)
    modules = tuple(_deep_rebuild_module(item) for item in plan.modules)
    source_files = tuple(_deep_rebuild_authority_file(item) for item in plan.source_files)
    metadata_files = tuple(_deep_rebuild_authority_file(item) for item in plan.metadata_files)
    rebuilt = ExternalSourcePlan(
        package=plan.package,
        distribution=plan.distribution,
        requested_version=plan.requested_version,
        installed_version=plan.installed_version,
        max_depth=plan.max_depth,
        status=plan.status,
        license=plan.license,
        modules=modules,
        candidate_functions=tuple(plan.candidate_functions),
        reason=plan.reason,
        source_files=source_files,
        metadata_files=metadata_files,
        inventory_schema=plan.inventory_schema,
        authorization=None,
    )
    if any(
        getattr(rebuilt, field_name) != getattr(plan, field_name)
        for field_name in ExternalSourcePlan.__dataclass_fields__
        if field_name != "authorization"
    ):
        raise SourceLockV2Error("SourceLock v2 plan is noncanonical")
    return rebuilt


def _deep_rebuild_legacy_authorization(
    value: ExternalSourceAuthorization,
    *,
    plan: ExternalSourcePlan,
) -> ExternalSourceAuthorization:
    """Validate legacy C6.1 evidence as inert input, never as v2 authority."""
    if type(value) is not ExternalSourceAuthorization:
        raise SourceLockV2Error("legacy source authorization is invalid")
    optional_strings = (
        value.reason,
        value.snapshot_sha256,
        value.attestor,
        value.attestor_kind,
        value.license_observed,
    )
    if (
        type(value.status) is not str
        or value.status
        not in {"verified", "missing", "invalid", "incomplete", "stale", "plan-unavailable"}
        or type(value.path) is not str
        or value.path != SOURCE_LOCK_FILENAME
        or any(item is not None and type(item) is not str for item in optional_strings)
        or any(
            type(item) is not bool
            for item in (
                value.license_attestation_verified,
                value.source_inventory_verified,
                value.provenance_verified,
            )
        )
        or any(
            item is not None and len(item) > 512
            for item in (
                value.reason,
                value.attestor,
                value.attestor_kind,
                value.license_observed,
            )
        )
    ):
        raise SourceLockV2Error("legacy source authorization shape is invalid")
    if value.snapshot_sha256 is not None:
        _require_sha256(value.snapshot_sha256, "legacy authorization snapshot")
    if value.status == "verified" and (
        value.reason is not None
        or value.snapshot_sha256 != plan.plan_snapshot_sha256()
        or value.license_observed != plan.license
        or not value.attestor
        or not value.attestor_kind
        or value.license_attestation_verified is not True
        or value.source_inventory_verified is not True
        or value.provenance_verified is not True
    ):
        raise SourceLockV2Error("legacy verified source authorization is inconsistent")
    rebuilt = ExternalSourceAuthorization(
        status=value.status,
        path=value.path,
        reason=value.reason,
        snapshot_sha256=value.snapshot_sha256,
        attestor=value.attestor,
        attestor_kind=value.attestor_kind,
        license_observed=value.license_observed,
        license_attestation_verified=value.license_attestation_verified,
        source_inventory_verified=value.source_inventory_verified,
        provenance_verified=value.provenance_verified,
    )
    if rebuilt != value:
        raise SourceLockV2Error("legacy source authorization is noncanonical")
    return rebuilt


def _deep_rebuild_authority_file(value: AuthorityFile) -> AuthorityFile:
    if type(value) is not AuthorityFile:
        raise SourceLockV2Error("SourceLock v2 authority file is invalid")
    if (
        type(value.path) is not str
        or type(value.sha256) is not str
        or type(value.size) is not int
        or type(value.role) is not str
        or (value.module_name is not None and type(value.module_name) is not str)
    ):
        raise SourceLockV2Error("SourceLock v2 authority file shape is invalid")
    return AuthorityFile(
        path=value.path,
        sha256=value.sha256,
        size=value.size,
        role=value.role,
        module_name=value.module_name,
    )


def _deep_rebuild_module(value: SourceModule) -> SourceModule:
    if type(value) is not SourceModule or type(value.provenance) is not ArtifactProvenance:
        raise SourceLockV2Error("SourceLock v2 source module is invalid")
    if (
        type(value.module_name) is not str
        or type(value.path) is not str
        or type(value.is_package_init) is not bool
        or value.source_origin is not SourceOrigin.DISTRIBUTION
        or type(value.sha256) is not str
        or type(value.dependency_depth) is not int
        or type(value.imports) is not tuple
        or value.imports
        or type(value.distribution) is not str
        or type(value.version) is not str
        or type(value.license) is not str
        or type(value.provenance.producer) is not str
        or type(value.provenance.source_references) is not tuple
        or type(value.provenance.evidence) is not tuple
        or any(
            type(item) is not str
            for item in (
                *value.provenance.source_references,
                *value.provenance.evidence,
            )
        )
    ):
        raise SourceLockV2Error("SourceLock v2 source module shape is invalid")
    provenance = ArtifactProvenance(
        producer=value.provenance.producer,
        source_references=tuple(value.provenance.source_references),
        evidence=tuple(value.provenance.evidence),
    )
    rebuilt = SourceModule(
        module_name=value.module_name,
        path=value.path,
        is_package_init=value.is_package_init,
        source_origin=value.source_origin,
        sha256=value.sha256,
        dependency_depth=value.dependency_depth,
        imports=(),
        distribution=value.distribution,
        version=value.version,
        license=value.license,
        provenance=provenance,
    )
    if rebuilt != value:
        raise SourceLockV2Error("SourceLock v2 source module is noncanonical")
    return rebuilt


def verify_source_lock_v2_with_context(
    *,
    lock_path: str | Path,
    signature_path: str | Path,
    public_key_path: str | Path,
    wheel_path: str | Path,
    expected_wheel_sha256: str,
    expected_public_key_sha256: str,
    plan: ExternalSourcePlan,
) -> SourceLockV2Verification:
    """Verify once and return the exact admitted in-memory context."""
    try:
        trusted_plan = _deep_rebuild_plan(plan)
        wheel = verify_source_wheel(
            wheel_path,
            expected_sha256=expected_wheel_sha256,
            plan=trusted_plan,
        )
        analyses = tuple(analyze_external_source_snapshot(snapshot) for snapshot in wheel.snapshots)
        lock_bytes = _read_pinned_regular(Path(lock_path), MAX_SOURCE_LOCK_BYTES)
        signature_bytes = _read_pinned_regular(
            Path(signature_path), MAX_SOURCE_LOCK_V2_SIGNATURE_BYTES
        )
        public_key = _read_pinned_regular(Path(public_key_path), MAX_SOURCE_LOCK_V2_KEY_BYTES)
        if len(public_key) != 32:
            raise SourceLockV2Error("public key size is invalid")
        _require_sha256(expected_public_key_sha256, "expected public key")
        public_key_sha256 = hashlib.sha256(public_key).hexdigest()
        if not hmac.compare_digest(public_key_sha256, expected_public_key_sha256):
            raise SourceLockV2Error("public key hash mismatch")
        manifest = parse_source_lock_v2_manifest(lock_bytes)
        envelope = parse_source_lock_v2_signature(signature_bytes)
        expected = build_source_lock_v2_manifest(
            plan=trusted_plan,
            wheel=wheel,
            analyses=analyses,
            owner=manifest.owner,
            trusted_public_key_sha256=expected_public_key_sha256,
            allow=manifest.allow,
            redistribute=manifest.redistribute,
            transform=manifest.transform,
        )
        if manifest != expected:
            raise SourceLockV2Error("SourceLock v2 is stale")
        if (
            envelope.public_key_sha256 != expected_public_key_sha256
            or envelope.manifest_sha256 != manifest.manifest_sha256
        ):
            raise SourceLockV2Error("SourceLock v2 signature binding is stale")
        raw_signature = envelope.signature_bytes
        message = SOURCE_LOCK_V2_SIGNED_MESSAGE_PREFIX + manifest.canonical_json_bytes
        if not verify_ed25519_signature(public_key, message, raw_signature):
            raise SourceLockV2Error("SourceLock v2 signature verification failed")
        final_wheel = verify_source_wheel(
            wheel_path,
            expected_sha256=expected_wheel_sha256,
            plan=trusted_plan,
        )
        if final_wheel != wheel:
            raise SourceLockV2Error("source wheel authority changed during verification")
        admission = SourceLockV2Admission(
            status="admitted",
            reason="source-lock-v2-signature-verified",
            manifest_sha256=manifest.manifest_sha256,
            public_key_sha256=public_key_sha256,
            signature_sha256=hashlib.sha256(raw_signature).hexdigest(),
            prebuild_admitted=True,
        )
        context = _create_source_lock_v2_verified_context(
            admission=admission,
            plan=trusted_plan,
            wheel=wheel,
            analyses=analyses,
            manifest=manifest,
        )
        return SourceLockV2Verification(admission=admission, context=context)
    except Exception:
        return SourceLockV2Verification(
            admission=SourceLockV2Admission(
                status="rejected",
                reason="source-lock-v2-verification-failed",
            )
        )


def verify_source_lock_v2(
    *,
    lock_path: str | Path,
    signature_path: str | Path,
    public_key_path: str | Path,
    wheel_path: str | Path,
    expected_wheel_sha256: str,
    expected_public_key_sha256: str,
    plan: ExternalSourcePlan,
) -> SourceLockV2Admission:
    """Compatibility wrapper returning only the total admission receipt."""
    return verify_source_lock_v2_with_context(
        lock_path=lock_path,
        signature_path=signature_path,
        public_key_path=public_key_path,
        wheel_path=wheel_path,
        expected_wheel_sha256=expected_wheel_sha256,
        expected_public_key_sha256=expected_public_key_sha256,
        plan=plan,
    ).admission


def parse_source_lock_v2_manifest(value: bytes) -> SourceLockV2Manifest:
    """Parse only the closed canonical SourceLock v2 JSON representation."""
    document = _parse_canonical_document(value, MAX_SOURCE_LOCK_BYTES)
    expected_fields = {
        "kind",
        "schema_version",
        "domain",
        "authority",
        "package",
        "distribution",
        "version",
        "max_depth",
        "plan_snapshot_sha256",
        "wheel_authority_sha256",
        "archive",
        "entries",
        "analyses",
        "license",
        "owner_decision",
        "trusted_public_key_sha256",
        "authorizes_build",
        "authorizes_distribution",
    }
    if set(document) != expected_fields or (
        document.get("kind") != SOURCE_LOCK_V2_KIND
        or document.get("schema_version") != SOURCE_LOCK_V2_SCHEMA_VERSION
        or document.get("domain") != SOURCE_LOCK_V2_DOMAIN
        or document.get("authority") != "prebuild-admission-only"
        or document.get("max_depth") != 1
        or document.get("authorizes_build") is not False
        or document.get("authorizes_distribution") is not False
    ):
        raise SourceLockV2Error("SourceLock v2 schema is invalid")
    archive_doc = _exact_dict(document["archive"], {"filename", "sha256", "size"})
    entry_docs = _exact_list(document["entries"])
    analysis_docs = _exact_list(document["analyses"])
    license_doc = _exact_dict(
        document["license"],
        {
            "declared",
            "observed",
            "independent_detection",
            "material_sha256",
            "evidence_sha256",
        },
    )
    if license_doc["independent_detection"] != SOURCE_LOCK_V2_LICENSE_DETECTION:
        raise SourceLockV2Error("SourceLock v2 license detection state is invalid")
    decision_doc = _exact_dict(
        document["owner_decision"], {"owner", "allow", "redistribute", "transform"}
    )
    entries_list: list[SourceWheelEntryIdentity] = []
    for item in entry_docs:
        entry = _exact_dict(
            item, {"path", "sha256", "size", "compressed_size", "crc32", "unix_mode"}
        )
        entries_list.append(
            SourceWheelEntryIdentity(
                path=_string(entry["path"]),
                sha256=_string(entry["sha256"]),
                size=_integer(entry["size"]),
                compressed_size=_integer(entry["compressed_size"]),
                crc32=_string(entry["crc32"]),
                unix_mode=_integer(entry["unix_mode"]),
            )
        )
    entries = tuple(entries_list)
    analyses: list[SourceLockV2AnalysisIdentity] = []
    for raw_analysis in analysis_docs:
        analysis = _exact_dict(
            raw_analysis, {"module_name", "source_sha256", "semantic_sha256", "functions"}
        )
        functions_list: list[SourceLockV2FunctionIdentity] = []
        for item in _exact_list(analysis["functions"]):
            function = _exact_dict(item, {"qualname", "semantic_ast_sha256", "lowered_ir_sha256"})
            functions_list.append(
                SourceLockV2FunctionIdentity(
                    qualname=_string(function["qualname"]),
                    semantic_ast_sha256=_string(function["semantic_ast_sha256"]),
                    lowered_ir_sha256=_string(function["lowered_ir_sha256"]),
                )
            )
        functions = tuple(functions_list)
        analyses.append(
            SourceLockV2AnalysisIdentity(
                module_name=_string(analysis["module_name"]),
                source_sha256=_string(analysis["source_sha256"]),
                semantic_sha256=_string(analysis["semantic_sha256"]),
                functions=functions,
            )
        )
    try:
        manifest = SourceLockV2Manifest(
            package=_string(document["package"]),
            distribution=_string(document["distribution"]),
            version=_string(document["version"]),
            plan_snapshot_sha256=_string(document["plan_snapshot_sha256"]),
            wheel_authority_sha256=_string(document["wheel_authority_sha256"]),
            archive=SourceWheelArchiveIdentity(
                filename=_string(archive_doc["filename"]),
                sha256=_string(archive_doc["sha256"]),
                size=_integer(archive_doc["size"]),
            ),
            entries=entries,
            analyses=tuple(analyses),
            declared_license=_string(license_doc["declared"]),
            observed_license=_string(license_doc["observed"]),
            license_material_sha256=_string(license_doc["material_sha256"]),
            license_evidence_sha256=_string(license_doc["evidence_sha256"]),
            owner=_string(decision_doc["owner"]),
            allow=_boolean(decision_doc["allow"]),
            redistribute=_boolean(decision_doc["redistribute"]),
            transform=_boolean(decision_doc["transform"]),
            trusted_public_key_sha256=_string(document["trusted_public_key_sha256"]),
        )
    except (TypeError, ValueError) as exc:
        raise SourceLockV2Error("SourceLock v2 values are invalid") from exc
    if not hmac.compare_digest(value, manifest.canonical_json_bytes):
        raise SourceLockV2Error("SourceLock v2 JSON is not canonical")
    return manifest


def parse_source_lock_v2_signature(value: bytes) -> SourceLockV2Signature:
    """Parse only the closed canonical detached signature envelope."""
    document = _parse_canonical_document(value, MAX_SOURCE_LOCK_V2_SIGNATURE_BYTES)
    fields = {
        "kind",
        "schema_version",
        "algorithm",
        "domain",
        "public_key_sha256",
        "manifest_sha256",
        "signature",
    }
    if set(document) != fields or (
        document.get("kind") != SOURCE_LOCK_V2_SIGNATURE_KIND
        or document.get("schema_version") != 1
        or document.get("algorithm") != "ed25519"
        or document.get("domain") != SOURCE_LOCK_V2_SIGNATURE_DOMAIN
    ):
        raise SourceLockV2Error("SourceLock v2 signature schema is invalid")
    try:
        envelope = SourceLockV2Signature(
            public_key_sha256=_string(document["public_key_sha256"]),
            manifest_sha256=_string(document["manifest_sha256"]),
            signature=_string(document["signature"]),
        )
    except (TypeError, ValueError) as exc:
        raise SourceLockV2Error("SourceLock v2 signature values are invalid") from exc
    if not hmac.compare_digest(value, envelope.canonical_json_bytes):
        raise SourceLockV2Error("SourceLock v2 signature JSON is not canonical")
    return envelope


def _read_pinned_regular(path: Path, limit: int) -> bytes:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise SourceLockV2Error("no-follow reads are unavailable")
    try:
        linked = path.lstat()
        if stat.S_ISLNK(linked.st_mode) or not stat.S_ISREG(linked.st_mode):
            raise SourceLockV2Error("SourceLock v2 input is not a regular file")
        fd = os.open(path, os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0))
    except SourceLockV2Error:
        raise
    except OSError as exc:
        raise SourceLockV2Error("SourceLock v2 input cannot be opened") from exc
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or (before.st_dev, before.st_ino) != (linked.st_dev, linked.st_ino)
            or before.st_size <= 0
            or before.st_size > limit
        ):
            raise SourceLockV2Error("SourceLock v2 input identity is invalid")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(64 * 1024, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise SourceLockV2Error("SourceLock v2 input exceeds the bound")
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, item) != getattr(after, item) for item in fields):
            raise SourceLockV2Error("SourceLock v2 input changed during read")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _parse_canonical_document(value: bytes, limit: int) -> dict[str, object]:
    if type(value) is not bytes or not value or len(value) > limit:
        raise SourceLockV2Error("SourceLock v2 JSON exceeds the bound")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise SourceLockV2Error("SourceLock v2 JSON has duplicate fields")
            result[key] = item
        return result

    try:
        parsed = json.loads(
            value.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda _item: (_ for _ in ()).throw(
                SourceLockV2Error("SourceLock v2 JSON has an invalid constant")
            ),
        )
    except SourceLockV2Error:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise SourceLockV2Error("SourceLock v2 JSON is invalid") from exc
    if type(parsed) is not dict:
        raise SourceLockV2Error("SourceLock v2 JSON root is invalid")
    return parsed


def _exact_dict(value: object, fields: set[str]) -> dict[str, object]:
    if type(value) is not dict or set(value) != fields:
        raise SourceLockV2Error("SourceLock v2 nested schema is invalid")
    return value


def _exact_list(value: object) -> list[object]:
    if type(value) is not list:
        raise SourceLockV2Error("SourceLock v2 list schema is invalid")
    return value


def _string(value: object) -> str:
    if type(value) is not str:
        raise SourceLockV2Error("SourceLock v2 string value is invalid")
    return value


def _integer(value: object) -> int:
    if type(value) is not int:
        raise SourceLockV2Error("SourceLock v2 integer value is invalid")
    return value


def _boolean(value: object) -> bool:
    if type(value) is not bool:
        raise SourceLockV2Error("SourceLock v2 boolean value is invalid")
    return value


def _decode_signature(value: object) -> bytes:
    if type(value) is not str or not value:
        raise ValueError("SourceLock v2 signature is invalid")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("SourceLock v2 signature is invalid") from exc
    if len(raw) != 64 or base64.b64encode(raw).decode("ascii") != value:
        raise ValueError("SourceLock v2 signature is not canonical")
    return raw


def _require_sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ValueError(f"SourceLock v2 {label} SHA-256 is invalid")
    return value


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")


__all__ = [
    "SOURCE_LOCK_V2_DOMAIN",
    "SOURCE_LOCK_V2_LICENSE_DETECTION",
    "SOURCE_LOCK_V2_SIGNATURE_DOMAIN",
    "SOURCE_LOCK_V2_SIGNED_MESSAGE_PREFIX",
    "SourceLockV2Admission",
    "SourceLockV2AnalysisIdentity",
    "SourceLockV2FunctionIdentity",
    "SourceLockV2Manifest",
    "SourceLockV2Signature",
    "SourceLockV2Verification",
    "SourceLockV2VerifiedContext",
    "build_source_lock_v2_manifest",
    "parse_source_lock_v2_manifest",
    "parse_source_lock_v2_signature",
    "validate_source_lock_v2_verified_context",
    "verify_source_lock_v2",
    "verify_source_lock_v2_with_context",
]
