"""Bounded C6.2/C6.4 artifact-evidence models and sidecar helpers.

This module is intentionally separate from :class:`ArtifactProvenance`, which
remains planning metadata only. C6.2 emits preview-only, incomplete, unsigned
supply-chain sidecars for ordinary successful host-extension+cpython wheels.
C6.4 adds a sanitized direct native runtime linkage inventory (macOS Mach-O /
Linux ELF only) under the same evidence-only authority. Evidence unavailability
never changes ordinary build success.
"""

from __future__ import annotations

import hashlib
import inspect
import io
import json
import os
import re
import secrets
import stat
import sys
import uuid
import zipfile
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Callable, Mapping, Sequence
from urllib.parse import urlparse

from rextio.__about__ import __version__ as REXTIO_VERSION

# Fixed bounds for the C6.2 preview path.
MAX_EVIDENCE_COMPONENTS = 512
MAX_EVIDENCE_STRING_CHARS = 512
MAX_EVIDENCE_FILE_BYTES = 16 * 1024 * 1024
MAX_SIDECAR_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_INPUT_FILES = 256
MAX_CARGO_PACKAGES = 512
MAX_CARGO_EDGES = 2048
MAX_CARGO_METADATA_BYTES = 8 * 1024 * 1024
MAX_LIMITATION_COUNT = 32
MAX_WHEEL_ENTRIES = 4096
MAX_WHEEL_ENTRY_PATH_CHARS = 512
MAX_WHEEL_ENTRY_UNCOMPRESSED = 8 * 1024 * 1024
MAX_WHEEL_TOTAL_UNCOMPRESSED = 64 * 1024 * 1024
MAX_RUNTIME_DEPS = 64
MAX_RUNTIME_DEP_NAME_CHARS = 256
MAX_RUNTIME_INSPECTOR_OUTPUT_BYTES = 256 * 1024

_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_LOGICAL_SEGMENT = re.compile(r"^[A-Za-z0-9._@+%-]+$")
_WHEEL_VERSION_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._]*)-(?P<version>[A-Za-z0-9][A-Za-z0-9._+]*)-"
)

# Honest, non-overclaiming limitation markers.
DEFAULT_LIMITATIONS: tuple[str, ...] = (
    "preview-only",
    "composition-incomplete",
    "unsigned",
    "not-reproducible-claim",
    "not-hermetic-claim",
    "not-completeness-claim",
    "not-external-source-authorization",
    "direct-native-linkage-only",
    "no-transitive-dylib-closure",
    "no-runtime-dlopen-inventory",
    "no-recursive-package-inventory",
    "evidence-only-authority",
)

# Fixed sanitized unavailability reasons (never echo attacker-controlled text).
REASON_NATIVE_NOT_BUILT = "native-extension-not-built"
REASON_SOURCE_SNAPSHOT_MISMATCH = "source-snapshot-mismatch"
REASON_SOURCE_UNREADABLE = "source-input-unreadable"
REASON_INPUT_COUNT_EXCEEDED = "input-count-exceeded"
REASON_CARGO_LOCK_MISSING = "cargo-lock-missing"
REASON_CARGO_METADATA_FAILED = "cargo-metadata-failed"
REASON_CARGO_OUTPUT_EXCEEDED = "cargo-metadata-output-exceeded"
REASON_CARGO_GRAPH_INVALID = "cargo-resolve-graph-invalid"
REASON_WHEEL_INVENTORY_INVALID = "wheel-inventory-invalid"
REASON_SIDECAR_WRITE_FAILED = "sidecar-write-failed"
REASON_EVIDENCE_INTERNAL = "evidence-internal-error"
REASON_SNAPSHOT_MISSING = "input-snapshot-missing"
REASON_WHEEL_MUTATED = "wheel-bytes-mutated"
REASON_RUNTIME_PLATFORM_UNSUPPORTED = "native-runtime-platform-unsupported"
REASON_RUNTIME_INSPECTOR_MISSING = "native-runtime-inspector-missing"
REASON_RUNTIME_INSPECTOR_FAILED = "native-runtime-inspector-failed"
REASON_RUNTIME_INSPECTOR_TIMEOUT = "native-runtime-inspector-timeout"
REASON_RUNTIME_OUTPUT_EXCEEDED = "native-runtime-output-exceeded"
REASON_RUNTIME_MALFORMED = "native-runtime-inventory-malformed"
REASON_RUNTIME_UNSAFE_PATH = "native-runtime-unsafe-dependency-path"
REASON_RUNTIME_DEP_COUNT_EXCEEDED = "native-runtime-dependency-count-exceeded"
REASON_RUNTIME_BINARY_MISSING = "native-extension-binary-missing"
REASON_RUNTIME_BINARY_MISMATCH = "native-extension-binary-mismatch"
REASON_RUNTIME_WHEEL_MEMBER_MISMATCH = "native-wheel-member-mismatch"
REASON_RUNTIME_ARCHITECTURE_MISMATCH = "native-runtime-architecture-mismatch"
REASON_RUNTIME_UNEXPECTED_DEPENDENCY = "native-runtime-unexpected-dependency"

# Closed allowlist for ``ArtifactEvidence.reason`` when status is unavailable.
UNAVAILABLE_REASONS: frozenset[str] = frozenset(
    {
        REASON_NATIVE_NOT_BUILT,
        REASON_SOURCE_SNAPSHOT_MISMATCH,
        REASON_SOURCE_UNREADABLE,
        REASON_INPUT_COUNT_EXCEEDED,
        REASON_CARGO_LOCK_MISSING,
        REASON_CARGO_METADATA_FAILED,
        REASON_CARGO_OUTPUT_EXCEEDED,
        REASON_CARGO_GRAPH_INVALID,
        REASON_WHEEL_INVENTORY_INVALID,
        REASON_SIDECAR_WRITE_FAILED,
        REASON_EVIDENCE_INTERNAL,
        REASON_SNAPSHOT_MISSING,
        REASON_WHEEL_MUTATED,
        REASON_RUNTIME_PLATFORM_UNSUPPORTED,
        REASON_RUNTIME_INSPECTOR_MISSING,
        REASON_RUNTIME_INSPECTOR_FAILED,
        REASON_RUNTIME_INSPECTOR_TIMEOUT,
        REASON_RUNTIME_OUTPUT_EXCEEDED,
        REASON_RUNTIME_MALFORMED,
        REASON_RUNTIME_UNSAFE_PATH,
        REASON_RUNTIME_DEP_COUNT_EXCEEDED,
        REASON_RUNTIME_BINARY_MISSING,
        REASON_RUNTIME_BINARY_MISMATCH,
        REASON_RUNTIME_WHEEL_MEMBER_MISMATCH,
        REASON_RUNTIME_ARCHITECTURE_MISMATCH,
        REASON_RUNTIME_UNEXPECTED_DEPENDENCY,
    }
)

ARTIFACT_EVIDENCE_POLICY_BEST_EFFORT = "best-effort"
ARTIFACT_EVIDENCE_POLICY_REQUIRED = "required"
ARTIFACT_EVIDENCE_SCOPE = "host-extension-wheel-cpython-v1"
ARTIFACT_EVIDENCE_REQUIRED_STATUS = "preview-ready"
ARTIFACT_EVIDENCE_GATE_OUT_OF_SCOPE = "artifact-set-out-of-scope"
ARTIFACT_EVIDENCE_GATE_UNAVAILABLE = "evidence-unavailable"

# Deterministic UUID namespace for CycloneDX serialNumber (RFC 4122 UUIDv5).
_CDX_UUID_NAMESPACE = uuid.UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")


class ArtifactEvidenceError(RuntimeError):
    """A bounded, sanitized failure while producing artifact evidence."""

    def __init__(self, message: str, *, reason: str = REASON_EVIDENCE_INTERNAL) -> None:
        self.reason = reason
        super().__init__(_sanitize_error_message(message))


@dataclass(frozen=True)
class ArtifactEvidenceGate:
    """Immutable report for the opt-in C6.3 required evidence policy."""

    mode: str
    status: str
    scope: str = ARTIFACT_EVIDENCE_SCOPE
    required_status: str = ARTIFACT_EVIDENCE_REQUIRED_STATUS
    observed_status: str | None = None
    reason: str | None = None
    evidence_reason: str | None = None
    distribution_authorized: bool = False
    complete: bool = False
    signed: bool = False

    def __post_init__(self) -> None:
        if self.mode != ARTIFACT_EVIDENCE_POLICY_REQUIRED:
            raise ValueError("artifact evidence gate mode must be required")
        if self.status not in {"satisfied", "blocked"}:
            raise ValueError("artifact evidence gate status must be satisfied or blocked")
        if self.scope != ARTIFACT_EVIDENCE_SCOPE:
            raise ValueError("artifact evidence gate scope is invalid")
        if self.required_status != ARTIFACT_EVIDENCE_REQUIRED_STATUS:
            raise ValueError("artifact evidence gate required_status is invalid")
        if self.reason not in {
            None,
            ARTIFACT_EVIDENCE_GATE_OUT_OF_SCOPE,
            ARTIFACT_EVIDENCE_GATE_UNAVAILABLE,
        }:
            raise ValueError("artifact evidence gate reason is invalid")
        if self.status == "satisfied":
            if self.observed_status != ARTIFACT_EVIDENCE_REQUIRED_STATUS:
                raise ValueError("satisfied gate requires preview-ready evidence")
            if self.reason is not None or self.evidence_reason is not None:
                raise ValueError("satisfied gate must not carry failure reasons")
        elif self.reason is None:
            raise ValueError("blocked gate requires a reason")
        if self.reason == ARTIFACT_EVIDENCE_GATE_OUT_OF_SCOPE:
            if self.observed_status is not None or self.evidence_reason is not None:
                raise ValueError("out-of-scope gate must not claim observed evidence")
        if self.reason == ARTIFACT_EVIDENCE_GATE_UNAVAILABLE:
            if (
                self.observed_status != "unavailable"
                or self.evidence_reason not in UNAVAILABLE_REASONS
            ):
                raise ValueError("unavailable gate requires a fixed evidence reason")
        object.__setattr__(self, "distribution_authorized", False)
        object.__setattr__(self, "complete", False)
        object.__setattr__(self, "signed", False)

    @classmethod
    def out_of_scope(cls) -> ArtifactEvidenceGate:
        """Return the stable pre-build scope rejection report."""
        return cls(
            mode=ARTIFACT_EVIDENCE_POLICY_REQUIRED,
            status="blocked",
            reason=ARTIFACT_EVIDENCE_GATE_OUT_OF_SCOPE,
        )

    @classmethod
    def from_evidence(cls, evidence: ArtifactEvidence) -> ArtifactEvidenceGate:
        """Evaluate one C6.2 evidence record without widening its authority."""
        if evidence.status == ARTIFACT_EVIDENCE_REQUIRED_STATUS:
            return cls(
                mode=ARTIFACT_EVIDENCE_POLICY_REQUIRED,
                status="satisfied",
                observed_status=evidence.status,
            )
        return cls(
            mode=ARTIFACT_EVIDENCE_POLICY_REQUIRED,
            status="blocked",
            observed_status=evidence.status,
            reason=ARTIFACT_EVIDENCE_GATE_UNAVAILABLE,
            evidence_reason=evidence.reason,
        )

    def to_dict(self) -> dict[str, object]:
        """Return the fixed, deterministic tooling-contract shape."""
        return {
            "mode": self.mode,
            "status": self.status,
            "scope": self.scope,
            "required_status": self.required_status,
            "observed_status": self.observed_status,
            "reason": self.reason,
            "evidence_reason": self.evidence_reason,
            "distribution_authorized": False,
            "complete": False,
            "signed": False,
        }


@dataclass(frozen=True)
class EvidenceFileRef:
    """One hashed file referenced by logical (project-relative) path only."""

    logical_path: str
    sha256: str
    size: int
    role: str

    def __post_init__(self) -> None:
        validate_logical_reference(self.logical_path)
        if not _HEX_SHA256.fullmatch(self.sha256):
            raise ValueError("evidence file sha256 must be 64 lowercase hex characters")
        if self.size < 0 or self.size > MAX_EVIDENCE_FILE_BYTES:
            raise ValueError("evidence file size is outside the allowed range")
        if not self.role.strip() or len(self.role) > MAX_EVIDENCE_STRING_CHARS:
            raise ValueError("evidence file role is invalid")
        object.__setattr__(self, "role", self.role.strip())

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable representation."""
        return {
            "logical_path": self.logical_path,
            "sha256": self.sha256,
            "size": self.size,
            "role": self.role,
        }


@dataclass(frozen=True)
class WheelEntryRef:
    """One deterministic wheel ZIP member (no extraction of payload bytes)."""

    name: str
    sha256: str
    compressed_size: int
    uncompressed_size: int

    def __post_init__(self) -> None:
        # Enforce the same canonical ZIP name rules used at inventory time.
        try:
            canonical = canonicalize_zip_entry_name(self.name)
        except ArtifactEvidenceError as exc:
            raise ValueError(str(exc)) from exc
        if canonical != self.name:
            raise ValueError("wheel entry name is noncanonical")
        if not _HEX_SHA256.fullmatch(self.sha256):
            raise ValueError("wheel entry sha256 must be 64 lowercase hex characters")
        if self.compressed_size < 0 or self.uncompressed_size < 0:
            raise ValueError("wheel entry size is invalid")
        if self.uncompressed_size > MAX_WHEEL_ENTRY_UNCOMPRESSED:
            raise ValueError("wheel entry uncompressed size exceeds the bound")
        if self.name.endswith("/") and self.uncompressed_size != 0:
            raise ValueError("directory ZIP entries must have zero uncompressed size")

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable representation."""
        return {
            "name": self.name,
            "sha256": self.sha256,
            "compressed_size": self.compressed_size,
            "uncompressed_size": self.uncompressed_size,
        }


@dataclass(frozen=True)
class CargoPackageRef:
    """One sanitized reachable Cargo package from metadata + Cargo.lock.

    Registry sources are retained only for exact lock checksum binding and are
    never serialized as raw URIs. Reports expose SHA-256 fingerprints only.
    """

    name: str
    version: str
    source: str | None
    checksum: str | None
    kind: str
    features: tuple[str, ...] = ()
    license: str | None = None
    package_id: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _bounded_identifier(self.name, "package name"))
        object.__setattr__(self, "version", _bounded_identifier(self.version, "package version"))
        if self.source is not None:
            # Internal canonical registry URI only — never serialized raw.
            object.__setattr__(self, "source", _bounded_string(self.source, "package source"))
        if self.checksum is not None and not _HEX_SHA256.fullmatch(self.checksum):
            raise ValueError("cargo package checksum must be 64 lowercase hex characters")
        object.__setattr__(self, "kind", _bounded_identifier(self.kind, "package kind"))
        features = tuple(_bounded_identifier(item, "feature") for item in self.features)
        object.__setattr__(self, "features", tuple(sorted(set(features))))
        if self.license is not None:
            object.__setattr__(self, "license", _bounded_string(self.license, "license"))
        if self.package_id:
            object.__setattr__(self, "package_id", _bounded_string(self.package_id, "package id"))

    def source_fingerprint(self) -> str | None:
        """Return SHA-256 of the canonical registry source, or None for path-root."""
        if self.source is None:
            return None
        return sha256_hex(self.source.encode("utf-8"))

    def purl(self) -> str:
        """Return a bounded package URL (never a raw registry URI with secrets)."""
        if self.kind == "registry":
            return f"pkg:cargo/{self.name}@{self.version}"
        return f"pkg:cargo/{self.name}@{self.version}?kind={self.kind}"

    def bom_ref(self) -> str:
        """Collision-resistant CycloneDX bom-ref for this package."""
        fingerprint = self.source_fingerprint() or ""
        digest = sha256_hex(
            f"{self.kind}|{self.name}|{self.version}|{fingerprint}|{self.checksum or ''}".encode(
                "utf-8"
            )
        )
        return f"urn:rextio:cargo:{digest[:32]}"

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable representation.

        Never includes raw registry URIs — only a SHA-256 source fingerprint.
        """
        return {
            "name": self.name,
            "version": self.version,
            "source_fingerprint": self.source_fingerprint(),
            "checksum": self.checksum,
            "kind": self.kind,
            "features": list(self.features),
            "license": self.license,
            "purl": self.purl(),
            "bom_ref": self.bom_ref(),
        }

    def __repr__(self) -> str:
        # Hide internal registry source URI from repr (never log credentials/paths).
        return (
            f"CargoPackageRef(name={self.name!r}, version={self.version!r}, "
            f"kind={self.kind!r}, source_fingerprint={self.source_fingerprint()!r}, "
            f"checksum={self.checksum!r})"
        )


@dataclass(frozen=True)
class CargoDepEdge:
    """One directed dependency edge keyed by unique package bom-refs."""

    dependent_ref: str
    dependency_ref: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "dependent_ref", _bounded_identifier(self.dependent_ref, "dependent_ref")
        )
        object.__setattr__(
            self, "dependency_ref", _bounded_identifier(self.dependency_ref, "dependency_ref")
        )
        if self.dependent_ref == self.dependency_ref:
            raise ValueError("cargo dependency edges must not be self-referential")

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable representation."""
        return {
            "dependent_ref": self.dependent_ref,
            "dependency_ref": self.dependency_ref,
        }


@dataclass(frozen=True)
class NativeRuntimeDependency:
    """One sanitized direct dynamic dependency name (basename or install-name)."""

    name: str
    origin: str = "unresolved"  # system | unresolved

    def __post_init__(self) -> None:
        text = self.name.strip()
        if not text or len(text) > MAX_RUNTIME_DEP_NAME_CHARS:
            raise ValueError("native runtime dependency name is invalid")
        if any(ord(ch) < 32 for ch in text):
            raise ValueError("native runtime dependency name contains control characters")
        if "/" in text or "\\" in text or "\0" in text:
            raise ValueError("native runtime dependency name is unsafe")
        # Absolute private paths are never admitted.
        if text.startswith("/") or (len(text) >= 2 and text[1] == ":"):
            raise ValueError("native runtime dependency name must not be absolute")
        if ".." in PurePosixPath(text).parts:
            raise ValueError("native runtime dependency name must not escape")
        object.__setattr__(self, "name", text)
        object.__setattr__(
            self, "origin", _bounded_identifier(self.origin, "runtime dependency origin")
        )
        if self.origin not in {"system", "unresolved"}:
            raise ValueError("native runtime dependency origin is invalid")

    def bom_ref(self) -> str:
        """Return a stable sanitized identity for this observed dependency."""
        identity = hashlib.sha256(f"{self.origin}|{self.name}".encode("utf-8")).hexdigest()
        return f"urn:rextio:native-dep:{identity[:32]}"

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable representation."""
        return {"name": self.name, "origin": self.origin, "bom_ref": self.bom_ref()}


@dataclass(frozen=True)
class NativeRuntimeInventory:
    """Bounded direct native linkage inventory for one host-extension binary."""

    format: str  # mach-o | elf
    architecture: str
    inspector: str  # otool | readelf (tool name only)
    subject_basename: str
    subject_sha256: str
    subject_size: int
    wheel_member: str
    wheel_member_sha256: str
    wheel_member_size: int
    dependencies: tuple[NativeRuntimeDependency, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "format", _bounded_identifier(self.format, "runtime format"))
        if self.format not in {"mach-o", "elf"}:
            raise ValueError("native runtime format must be mach-o or elf")
        object.__setattr__(
            self,
            "architecture",
            _bounded_identifier(self.architecture, "runtime architecture"),
        )
        if self.architecture not in {
            "aarch64",
            "arm",
            "powerpc",
            "powerpc64",
            "riscv64",
            "s390x",
            "x86",
            "x86_64",
        }:
            raise ValueError("native runtime architecture is unsupported")
        object.__setattr__(
            self, "inspector", _bounded_identifier(self.inspector, "runtime inspector")
        )
        if self.inspector not in {"otool", "readelf"}:
            raise ValueError("native runtime inspector must be otool or readelf")
        if (self.format, self.inspector) not in {
            ("mach-o", "otool"),
            ("elf", "readelf"),
        }:
            raise ValueError("native runtime format and inspector must match")
        object.__setattr__(
            self,
            "subject_basename",
            _bounded_identifier(self.subject_basename, "subject basename"),
        )
        if not _HEX_SHA256.fullmatch(self.subject_sha256):
            raise ValueError("subject sha256 must be 64 lowercase hex characters")
        if self.subject_size < 0 or self.subject_size > MAX_EVIDENCE_FILE_BYTES:
            raise ValueError("subject size is outside the allowed range")
        try:
            canonical = canonicalize_zip_entry_name(self.wheel_member)
        except ArtifactEvidenceError as exc:
            raise ValueError(str(exc)) from exc
        if canonical != self.wheel_member:
            raise ValueError("wheel member name is noncanonical")
        if PurePosixPath(self.wheel_member).name != self.subject_basename:
            raise ValueError("subject basename must match the wheel member basename")
        if not _HEX_SHA256.fullmatch(self.wheel_member_sha256):
            raise ValueError("wheel member sha256 must be 64 lowercase hex characters")
        if self.wheel_member_size < 0 or self.wheel_member_size > MAX_EVIDENCE_FILE_BYTES:
            raise ValueError("wheel member size is outside the allowed range")
        if self.subject_sha256 != self.wheel_member_sha256:
            raise ValueError("subject and wheel member digests must match")
        if self.subject_size != self.wheel_member_size:
            raise ValueError("subject and wheel member sizes must match")
        if len(self.dependencies) > MAX_RUNTIME_DEPS:
            raise ValueError("too many native runtime dependencies")
        names = [dep.name for dep in self.dependencies]
        if len(names) != len(set(names)):
            raise ValueError("native runtime dependency names must be unique")

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable representation."""
        return {
            "format": self.format,
            "architecture": self.architecture,
            "inspector": self.inspector,
            "subject_basename": self.subject_basename,
            "subject_sha256": self.subject_sha256,
            "subject_size": self.subject_size,
            "wheel_member": self.wheel_member,
            "wheel_member_sha256": self.wheel_member_sha256,
            "wheel_member_size": self.wheel_member_size,
            "dependency_count": len(self.dependencies),
            "dependencies": [dep.to_dict() for dep in self.dependencies],
            "scope": "direct-only",
            "transitive_closure": False,
            "runtime_dlopen": False,
        }


@dataclass(frozen=True)
class SidecarArtifact:
    """One finalized sidecar written next to the wheel."""

    format: str
    logical_path: str
    sha256: str
    size: int
    extra: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "format", _bounded_identifier(self.format, "sidecar format"))
        validate_logical_reference(self.logical_path)
        if not _HEX_SHA256.fullmatch(self.sha256):
            raise ValueError("sidecar sha256 must be 64 lowercase hex characters")
        if self.size < 0 or self.size > MAX_SIDECAR_BYTES:
            raise ValueError("sidecar size is outside the allowed range")
        object.__setattr__(self, "extra", dict(self.extra))

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable representation."""
        data: dict[str, object] = {
            "format": self.format,
            "logical_path": self.logical_path,
            "sha256": self.sha256,
            "size": self.size,
        }
        for key in sorted(self.extra):
            data[key] = self.extra[key]
        return data


@dataclass(frozen=True)
class ArtifactEvidence:
    """Additive ``build.json.artifact_evidence`` record for C6.2/C6.4 preview."""

    kind: str
    status: str  # preview-ready | unavailable
    authority: str = "evidence-only"
    signature_status: str = "unsigned"
    composition: str = "incomplete"
    reason: str | None = None
    target_triple: str | None = None
    subject: EvidenceFileRef | None = None
    sbom: SidecarArtifact | None = None
    provenance: SidecarArtifact | None = None
    inputs: tuple[EvidenceFileRef, ...] = ()
    wheel_entries: tuple[WheelEntryRef, ...] = ()
    cargo_packages: tuple[CargoPackageRef, ...] = ()
    cargo_dependencies: tuple[CargoDepEdge, ...] = ()
    native_runtime_inventory: NativeRuntimeInventory | None = None
    limitations: tuple[str, ...] = DEFAULT_LIMITATIONS
    preview: bool = True
    complete: bool = False
    signed: bool = False
    distribution_authorized: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _bounded_identifier(self.kind, "evidence kind"))
        if self.status not in {"preview-ready", "unavailable"}:
            raise ValueError("evidence status must be preview-ready or unavailable")
        object.__setattr__(self, "authority", "evidence-only")
        object.__setattr__(self, "signature_status", "unsigned")
        object.__setattr__(self, "composition", "incomplete")
        object.__setattr__(self, "preview", True)
        object.__setattr__(self, "complete", False)
        object.__setattr__(self, "signed", False)
        object.__setattr__(self, "distribution_authorized", False)
        if self.status == "unavailable":
            if not self.reason:
                raise ValueError("unavailable evidence requires a fixed reason")
            reason = _bounded_identifier(self.reason, "reason")
            if reason not in UNAVAILABLE_REASONS:
                raise ValueError("unavailable evidence reason is not in the allowlist")
            object.__setattr__(self, "reason", reason)
            # Unavailable records must not claim sidecars or input inventories.
            if self.subject is not None or self.sbom is not None or self.provenance is not None:
                raise ValueError("unavailable evidence must not carry subject or sidecars")
            if (
                self.inputs
                or self.wheel_entries
                or self.cargo_packages
                or self.cargo_dependencies
                or self.native_runtime_inventory is not None
            ):
                raise ValueError("unavailable evidence must not carry inventory fields")
        else:
            if self.reason is not None:
                raise ValueError("preview-ready evidence must not carry a reason")
            if self.subject is None or self.sbom is None or self.provenance is None:
                raise ValueError("preview-ready evidence requires subject and sidecars")
            if self.target_triple is None:
                raise ValueError("preview-ready evidence requires target_triple")
            if self.native_runtime_inventory is None:
                raise ValueError("preview-ready evidence requires native_runtime_inventory")
            runtime_matches = [
                entry
                for entry in self.wheel_entries
                if entry.name == self.native_runtime_inventory.wheel_member
            ]
            if len(runtime_matches) != 1:
                raise ValueError("preview-ready runtime wheel member must occur exactly once")
            runtime_entry = runtime_matches[0]
            if (
                runtime_entry.sha256 != self.native_runtime_inventory.wheel_member_sha256
                or runtime_entry.uncompressed_size
                != self.native_runtime_inventory.wheel_member_size
            ):
                raise ValueError("preview-ready runtime wheel member hash/size must match")
        if self.target_triple is not None:
            object.__setattr__(
                self,
                "target_triple",
                _bounded_identifier(self.target_triple, "target triple"),
            )
        if len(self.inputs) > MAX_INPUT_FILES:
            raise ValueError("too many evidence inputs")
        if len(self.cargo_packages) > MAX_CARGO_PACKAGES:
            raise ValueError("too many cargo packages")
        if len(self.cargo_dependencies) > MAX_CARGO_EDGES:
            raise ValueError("too many cargo dependency edges")
        if len(self.wheel_entries) > MAX_WHEEL_ENTRIES:
            raise ValueError("too many wheel entries")
        # Reject duplicate normalized cargo bom-refs (collision / graph corruption).
        bom_refs = [package.bom_ref() for package in self.cargo_packages]
        if len(bom_refs) != len(set(bom_refs)):
            raise ValueError("cargo package bom-refs must be unique")
        _validate_cargo_dependency_graph(self.cargo_packages, self.cargo_dependencies)
        limitations = tuple(_bounded_identifier(item, "limitation") for item in self.limitations)
        if len(limitations) > MAX_LIMITATION_COUNT:
            raise ValueError("too many limitations")
        object.__setattr__(self, "limitations", limitations)

    @classmethod
    def unavailable(
        cls,
        *,
        reason: str,
        target_triple: str | None = None,
    ) -> ArtifactEvidence:
        """Return a sanitized unavailable evidence record."""
        return cls(
            kind="host-extension-wheel",
            status="unavailable",
            reason=reason,
            target_triple=target_triple,
        )

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable representation."""
        data: dict[str, object] = {
            "kind": self.kind,
            "status": self.status,
            "authority": "evidence-only",
            "signature_status": "unsigned",
            "composition": "incomplete",
            "preview": True,
            "complete": False,
            "signed": False,
            "distribution_authorized": False,
            "limitations": list(self.limitations),
        }
        if self.reason is not None:
            data["reason"] = self.reason
        if self.target_triple is not None:
            data["target_triple"] = self.target_triple
        if self.status == "preview-ready":
            # Invariants enforced in __post_init__; serialize without asserts.
            if self.subject is not None and self.sbom is not None and self.provenance is not None:
                data["subject"] = self.subject.to_dict()
                data["sbom"] = self.sbom.to_dict()
                data["provenance"] = self.provenance.to_dict()
                data["inputs"] = [item.to_dict() for item in self.inputs]
                data["wheel_entries"] = [item.to_dict() for item in self.wheel_entries]
                data["cargo_packages"] = [item.to_dict() for item in self.cargo_packages]
                data["cargo_dependencies"] = [item.to_dict() for item in self.cargo_dependencies]
                if self.native_runtime_inventory is not None:
                    data["native_runtime_inventory"] = self.native_runtime_inventory.to_dict()
        return data


def validate_logical_reference(reference: str) -> None:
    """Reject absolute, parent-escaping, or machine-private path references."""
    if not reference or not reference.strip():
        raise ValueError("logical reference must not be empty")
    text = reference.strip()
    if len(text) > MAX_EVIDENCE_STRING_CHARS:
        raise ValueError("logical reference exceeds the allowed length")
    if "\\" in text or "\0" in text or any(ord(ch) < 32 for ch in text):
        raise ValueError("logical reference contains unsafe characters")
    posix = PurePosixPath(text)
    windows = PureWindowsPath(text)
    if posix.is_absolute() or windows.is_absolute() or ".." in posix.parts or ".." in windows.parts:
        raise ValueError("logical reference must be project-relative")
    if text.startswith("/") or (len(text) >= 2 and text[1] == ":"):
        raise ValueError("logical reference must be project-relative")
    for part in posix.parts:
        if part in ("", ".", ".."):
            raise ValueError("logical reference is invalid")
        if not _SAFE_LOGICAL_SEGMENT.fullmatch(part):
            raise ValueError("logical reference segment is invalid")


def project_relative_logical_path(project_root: Path, path: Path) -> str:
    """Return a sanitized project-relative logical path for ``path``."""
    try:
        root = project_root.resolve(strict=False)
        resolved = path.resolve(strict=False)
        relative = resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise ArtifactEvidenceError(
            "path escapes the project root", reason=REASON_SOURCE_UNREADABLE
        ) from exc
    logical = relative.as_posix()
    validate_logical_reference(logical)
    return logical


def sha256_hex(data: bytes) -> str:
    """Return the lowercase SHA-256 hex digest of ``data``."""
    return hashlib.sha256(data).hexdigest()


def read_regular_file_bytes(path: Path, *, max_bytes: int = MAX_EVIDENCE_FILE_BYTES) -> bytes:
    """Read a regular non-symlink file with fixed size bounds and post-read fstat."""
    if max_bytes <= 0 or max_bytes > MAX_EVIDENCE_FILE_BYTES:
        raise ArtifactEvidenceError("file size bound is invalid", reason=REASON_SOURCE_UNREADABLE)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if sys.platform == "win32" and hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY

    try:
        link_stat = os.lstat(path)
    except FileNotFoundError as exc:
        raise ArtifactEvidenceError(
            "evidence input file is missing", reason=REASON_SOURCE_UNREADABLE
        ) from exc
    except OSError as exc:
        raise ArtifactEvidenceError(
            "evidence input file could not be inspected", reason=REASON_SOURCE_UNREADABLE
        ) from exc
    if stat.S_ISLNK(link_stat.st_mode) or not stat.S_ISREG(link_stat.st_mode):
        raise ArtifactEvidenceError(
            "evidence input must be a regular non-symlink file",
            reason=REASON_SOURCE_UNREADABLE,
        )
    if link_stat.st_size < 0 or link_stat.st_size > max_bytes:
        raise ArtifactEvidenceError(
            "evidence input size is outside the allowed range",
            reason=REASON_SOURCE_UNREADABLE,
        )

    try:
        fd = os.open(str(path), flags)
    except OSError as exc:
        raise ArtifactEvidenceError(
            "evidence input could not be opened", reason=REASON_SOURCE_UNREADABLE
        ) from exc
    try:
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode):
            raise ArtifactEvidenceError(
                "evidence input must be a regular non-symlink file",
                reason=REASON_SOURCE_UNREADABLE,
            )
        if hasattr(link_stat, "st_ino") and hasattr(file_stat, "st_ino"):
            if link_stat.st_ino != file_stat.st_ino or link_stat.st_dev != file_stat.st_dev:
                raise ArtifactEvidenceError(
                    "evidence input changed during open",
                    reason=REASON_SOURCE_SNAPSHOT_MISMATCH,
                )
        if file_stat.st_size > max_bytes:
            raise ArtifactEvidenceError(
                "evidence input size is outside the allowed range",
                reason=REASON_SOURCE_UNREADABLE,
            )
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            try:
                chunk = os.read(fd, min(65536, remaining))
            except BlockingIOError as exc:
                raise ArtifactEvidenceError(
                    "evidence input could not be read", reason=REASON_SOURCE_UNREADABLE
                ) from exc
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > max_bytes:
            raise ArtifactEvidenceError(
                "evidence input size is outside the allowed range",
                reason=REASON_SOURCE_UNREADABLE,
            )
        # Post-read coherence: the descriptor must still name the same regular file.
        post_stat = os.fstat(fd)
        if not stat.S_ISREG(post_stat.st_mode):
            raise ArtifactEvidenceError(
                "evidence input changed after read",
                reason=REASON_SOURCE_SNAPSHOT_MISMATCH,
            )
        if hasattr(file_stat, "st_ino") and hasattr(post_stat, "st_ino"):
            if file_stat.st_ino != post_stat.st_ino or file_stat.st_dev != post_stat.st_dev:
                raise ArtifactEvidenceError(
                    "evidence input changed after read",
                    reason=REASON_SOURCE_SNAPSHOT_MISMATCH,
                )
        if post_stat.st_size != len(data):
            raise ArtifactEvidenceError(
                "evidence input size changed during read",
                reason=REASON_SOURCE_SNAPSHOT_MISMATCH,
            )
        return data
    finally:
        os.close(fd)


def hash_regular_file(path: Path, *, max_bytes: int = MAX_EVIDENCE_FILE_BYTES) -> tuple[str, int]:
    """Return ``(sha256, size)`` for a bounded regular file."""
    data = read_regular_file_bytes(path, max_bytes=max_bytes)
    return sha256_hex(data), len(data)


def ensure_sidecar_path_contained(path: Path, *, project_root: Path, expected_parent: Path) -> Path:
    """Validate sidecar path containment and return the resolved final path.

    Rejects symlink parents and paths that escape ``project_root`` or are not
    direct children of ``expected_parent`` (typically ``dist/``).
    """
    try:
        root = project_root.resolve(strict=False)
        parent = expected_parent.resolve(strict=False)
    except OSError as exc:
        raise ArtifactEvidenceError(
            "sidecar parent could not be resolved", reason=REASON_SIDECAR_WRITE_FAILED
        ) from exc
    try:
        parent.relative_to(root)
    except ValueError as exc:
        raise ArtifactEvidenceError(
            "sidecar parent escapes the project root",
            reason=REASON_SIDECAR_WRITE_FAILED,
        ) from exc
    if expected_parent.is_symlink():
        raise ArtifactEvidenceError(
            "sidecar parent must not be a symlink",
            reason=REASON_SIDECAR_WRITE_FAILED,
        )
    if path.parent.resolve(strict=False) != parent:
        raise ArtifactEvidenceError(
            "sidecar path is not contained in the expected parent",
            reason=REASON_SIDECAR_WRITE_FAILED,
        )
    if path.name != path.name.strip() or "/" in path.name or "\\" in path.name:
        raise ArtifactEvidenceError(
            "sidecar basename is invalid", reason=REASON_SIDECAR_WRITE_FAILED
        )
    return parent / path.name


def _dirfd_ops_available() -> bool:
    """Return whether Python dir_fd keyword ops are usable on this platform.

    Uses the real Python APIs (``os.open(..., dir_fd=)``, ``os.replace`` /
    ``os.rename`` with ``src_dir_fd``/``dst_dir_fd``, ``os.unlink(..., dir_fd=)``).
    The dead ``os.openat`` / ``os.renameat`` / ``os.unlinkat`` names are never
    required — they are absent on common CPython builds (including macOS).
    """
    if os.name == "nt":  # pragma: no cover - Windows uses path fallback
        return False
    try:
        open_params = inspect.signature(os.open).parameters
        unlink_params = inspect.signature(os.unlink).parameters
        replace_params = inspect.signature(os.replace).parameters
    except (TypeError, ValueError):  # pragma: no cover - exotic interpreters
        return False
    return (
        "dir_fd" in open_params
        and "dir_fd" in unlink_params
        and "src_dir_fd" in replace_params
        and "dst_dir_fd" in replace_params
    )


def _open_pinned_parent_dirfd(parent: Path) -> tuple[int, os.stat_result]:
    """Open ``parent`` with O_DIRECTORY|O_NOFOLLOW and verify inode against lstat.

    Returns ``(dir_fd, link_stat)``. Caller owns the dirfd and must close it.
    """
    try:
        link_stat = os.lstat(parent)
    except OSError as exc:
        raise ArtifactEvidenceError(
            "sidecar parent could not be inspected",
            reason=REASON_SIDECAR_WRITE_FAILED,
        ) from exc
    if stat.S_ISLNK(link_stat.st_mode):
        raise ArtifactEvidenceError(
            "sidecar parent must not be a symlink",
            reason=REASON_SIDECAR_WRITE_FAILED,
        )
    if not stat.S_ISDIR(link_stat.st_mode):
        raise ArtifactEvidenceError(
            "sidecar parent is not a directory",
            reason=REASON_SIDECAR_WRITE_FAILED,
        )
    dir_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        dir_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        dir_flags |= os.O_NOFOLLOW
    try:
        dir_fd = os.open(str(parent), dir_flags)
    except OSError as exc:
        raise ArtifactEvidenceError(
            "sidecar parent directory could not be opened",
            reason=REASON_SIDECAR_WRITE_FAILED,
        ) from exc
    try:
        dir_stat = os.fstat(dir_fd)
        if not stat.S_ISDIR(dir_stat.st_mode):
            raise ArtifactEvidenceError(
                "sidecar parent is not a directory",
                reason=REASON_SIDECAR_WRITE_FAILED,
            )
        if (
            getattr(link_stat, "st_ino", None) is not None
            and getattr(dir_stat, "st_ino", None) is not None
            and (link_stat.st_ino != dir_stat.st_ino or link_stat.st_dev != dir_stat.st_dev)
        ):
            raise ArtifactEvidenceError(
                "sidecar parent changed during open",
                reason=REASON_SIDECAR_WRITE_FAILED,
            )
        return dir_fd, link_stat
    except ArtifactEvidenceError:
        try:
            os.close(dir_fd)
        except OSError:
            pass
        raise
    except OSError as exc:
        try:
            os.close(dir_fd)
        except OSError:
            pass
        raise ArtifactEvidenceError(
            "sidecar parent directory could not be verified",
            reason=REASON_SIDECAR_WRITE_FAILED,
        ) from exc


def _validate_sidecar_basename(name: str) -> str:
    if (
        not name
        or name != name.strip()
        or "/" in name
        or "\\" in name
        or name in {".", ".."}
        or "\0" in name
    ):
        raise ArtifactEvidenceError(
            "sidecar basename is invalid", reason=REASON_SIDECAR_WRITE_FAILED
        )
    return name


@dataclass(frozen=True)
class _EntryIdentity:
    """No-follow filesystem identity used to prove transaction ownership."""

    device: int
    inode: int
    mode: int

    @classmethod
    def from_stat(cls, entry: os.stat_result) -> _EntryIdentity:
        return cls(entry.st_dev, entry.st_ino, entry.st_mode)


@dataclass(frozen=True)
class _FileReceipt:
    """Identity plus bounded exact bytes for an owned regular output."""

    identity: _EntryIdentity
    sha256: str
    size: int

    @classmethod
    def from_bytes(cls, identity: _EntryIdentity, data: bytes) -> _FileReceipt:
        return cls(identity=identity, sha256=sha256_hex(data), size=len(data))


def _lstat_at(dir_fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _lstat_path(path: Path) -> os.stat_result | None:
    try:
        return path.lstat()
    except FileNotFoundError:
        return None


def _write_exclusive_at(dir_fd: int, name: str, data: bytes) -> _EntryIdentity:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd: int | None = None
    created = False
    succeeded = False
    identity: _EntryIdentity | None = None
    offset = 0
    try:
        fd = os.open(name, flags, 0o644, dir_fd=dir_fd)
        created = True
        entry = os.fstat(fd)
        identity = _EntryIdentity.from_stat(entry)
        if not stat.S_ISREG(entry.st_mode) or getattr(entry, "st_nlink", 1) != 1:
            raise ArtifactEvidenceError(
                "sidecar stage is not an exclusive regular file",
                reason=REASON_SIDECAR_WRITE_FAILED,
            )
        view = memoryview(data)
        while offset < len(data):
            written = os.write(fd, view[offset:])
            if written <= 0:
                raise OSError("short sidecar stage write")
            offset += written
        os.fsync(fd)
        succeeded = True
        assert identity is not None
        return identity
    except ArtifactEvidenceError:
        raise
    except OSError as exc:
        raise ArtifactEvidenceError(
            "sidecar stage could not be written",
            reason=REASON_SIDECAR_WRITE_FAILED,
        ) from exc
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if created and not succeeded and identity is not None:
            expected = _FileReceipt.from_bytes(identity, data[:offset])
            current = _lstat_at(dir_fd, name)
            if (
                current is not None
                and getattr(current, "st_nlink", 1) == 1
                and _receipt_matches_at(dir_fd, name, expected)
            ):
                try:
                    os.unlink(name, dir_fd=dir_fd)
                except OSError:
                    pass


def _read_exact_at(dir_fd: int, name: str, expected: _EntryIdentity, *, max_bytes: int) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd: int | None = None
    try:
        fd = os.open(name, flags, dir_fd=dir_fd)
        before = os.fstat(fd)
        if _EntryIdentity.from_stat(before) != expected or not stat.S_ISREG(before.st_mode):
            raise ArtifactEvidenceError(
                "sidecar ownership changed during verification",
                reason=REASON_SIDECAR_WRITE_FAILED,
            )
        if before.st_size < 0 or before.st_size > max_bytes:
            raise ArtifactEvidenceError(
                "sidecar size changed during verification",
                reason=REASON_SIDECAR_WRITE_FAILED,
            )
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(fd)
        if (
            len(data) > max_bytes
            or _EntryIdentity.from_stat(after) != expected
            or after.st_size != len(data)
        ):
            raise ArtifactEvidenceError(
                "sidecar changed during verification",
                reason=REASON_SIDECAR_WRITE_FAILED,
            )
        return data
    except ArtifactEvidenceError:
        raise
    except OSError as exc:
        raise ArtifactEvidenceError(
            "sidecar could not be verified",
            reason=REASON_SIDECAR_WRITE_FAILED,
        ) from exc
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def _receipt_at(dir_fd: int, name: str, *, max_bytes: int) -> _FileReceipt:
    entry = _lstat_at(dir_fd, name)
    if entry is None or not stat.S_ISREG(entry.st_mode):
        raise ArtifactEvidenceError(
            "owned sidecar is not a regular file",
            reason=REASON_SIDECAR_WRITE_FAILED,
        )
    identity = _EntryIdentity.from_stat(entry)
    data = _read_exact_at(dir_fd, name, identity, max_bytes=max_bytes)
    return _FileReceipt.from_bytes(identity, data)


def _receipt_path(path: Path, *, max_bytes: int) -> _FileReceipt:
    before = _lstat_path(path)
    if before is None or not stat.S_ISREG(before.st_mode):
        raise ArtifactEvidenceError(
            "owned sidecar is not a regular file",
            reason=REASON_SIDECAR_WRITE_FAILED,
        )
    if before.st_size < 0 or before.st_size > max_bytes:
        raise ArtifactEvidenceError(
            "owned sidecar size is outside the bound",
            reason=REASON_SIDECAR_WRITE_FAILED,
        )
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ArtifactEvidenceError(
            "owned sidecar could not be read",
            reason=REASON_SIDECAR_WRITE_FAILED,
        ) from exc
    after = _lstat_path(path)
    identity = _EntryIdentity.from_stat(before)
    if (
        after is None
        or _EntryIdentity.from_stat(after) != identity
        or len(data) != after.st_size
        or len(data) > max_bytes
    ):
        raise ArtifactEvidenceError(
            "owned sidecar changed during read",
            reason=REASON_SIDECAR_WRITE_FAILED,
        )
    return _FileReceipt.from_bytes(identity, data)


def _receipt_matches_at(dir_fd: int, name: str, receipt: _FileReceipt) -> bool:
    try:
        current = _receipt_at(dir_fd, name, max_bytes=receipt.size)
    except ArtifactEvidenceError:
        return False
    return current == receipt


def _receipt_matches_path(path: Path, receipt: _FileReceipt) -> bool:
    try:
        current = _receipt_path(path, max_bytes=receipt.size)
    except ArtifactEvidenceError:
        return False
    return current == receipt


def _restore_quarantined_at(
    quarantine_fd: int,
    quarantine_name: str,
    public_fd: int,
    public_name: str,
) -> bool:
    """Restore one quarantined regular entry without replacing a public name."""
    try:
        quarantined = _lstat_at(quarantine_fd, quarantine_name)
        if quarantined is None or not stat.S_ISREG(quarantined.st_mode):
            return False
        identity = _EntryIdentity.from_stat(quarantined)
        os.link(
            quarantine_name,
            public_name,
            src_dir_fd=quarantine_fd,
            dst_dir_fd=public_fd,
            follow_symlinks=False,
        )
        restored = _lstat_at(public_fd, public_name)
        if restored is None or _EntryIdentity.from_stat(restored) != identity:
            return False
        # Keep the recovery link even after a create-if-absent public restore.
        # A concurrent public replacement after the identity check must not
        # turn a later quarantine unlink into deletion of the last known copy.
        return True
    except OSError:
        # EEXIST deliberately preserves both the concurrent public entry and
        # this transaction's quarantined recovery copy.
        return False


def _restore_quarantined_path(quarantine: Path, public: Path) -> bool:
    """Path fallback for create-if-absent quarantine restoration."""
    try:
        quarantined = _lstat_path(quarantine)
        if quarantined is None or not stat.S_ISREG(quarantined.st_mode):
            return False
        identity = _EntryIdentity.from_stat(quarantined)
        os.link(quarantine, public, follow_symlinks=False)
        restored = _lstat_path(public)
        if restored is None or _EntryIdentity.from_stat(restored) != identity:
            return False
        # Deliberately retain the transaction-private recovery link; mismatch
        # already makes rollback incomplete and requires manual disposition.
        return True
    except OSError:
        return False


def _quarantine_and_dispose_owned_at(
    public_fd: int,
    public_name: str,
    quarantine_fd: int,
    quarantine_name: str,
    receipt: _FileReceipt,
) -> bool:
    """Atomically isolate a public entry before proving and deleting ownership."""
    try:
        os.replace(
            public_name,
            quarantine_name,
            src_dir_fd=public_fd,
            dst_dir_fd=quarantine_fd,
        )
    except OSError:
        return False
    if _receipt_matches_at(quarantine_fd, quarantine_name, receipt):
        try:
            os.unlink(quarantine_name, dir_fd=quarantine_fd)
            return _lstat_at(public_fd, public_name) is None
        except OSError:
            return False
    # The moved entry was not ours. Put it back only with create-if-absent
    # semantics; otherwise retain the private recovery copy for manual action.
    _restore_quarantined_at(
        quarantine_fd,
        quarantine_name,
        public_fd,
        public_name,
    )
    return False


def _quarantine_and_dispose_owned_path(
    public: Path,
    quarantine: Path,
    receipt: _FileReceipt,
) -> bool:
    """Path fallback for quarantine-first ownership cleanup."""
    try:
        os.replace(public, quarantine)
    except OSError:
        return False
    if _receipt_matches_path(quarantine, receipt):
        try:
            quarantine.unlink()
            return _lstat_path(public) is None
        except OSError:
            return False
    _restore_quarantined_path(quarantine, public)
    return False


class SidecarWriteTransaction:
    """Publish a bounded sidecar set without losing pre-existing entries.

    Existing exact output entries are renamed into a private same-filesystem
    backup directory. New regular files are installed with hard-link
    create-if-absent semantics, and rollback removes only the exact inode/dev
    identities emitted by this transaction before restoring prior entries.
    """

    def __init__(
        self,
        paths: Sequence[Path],
        *,
        project_root: Path,
        expected_parent: Path,
    ) -> None:
        if not paths:
            raise ArtifactEvidenceError(
                "sidecar transaction is empty", reason=REASON_SIDECAR_WRITE_FAILED
            )
        contained = tuple(
            ensure_sidecar_path_contained(
                path, project_root=project_root, expected_parent=expected_parent
            )
            for path in paths
        )
        basenames = tuple(_validate_sidecar_basename(path.name) for path in contained)
        if len(set(basenames)) != len(basenames):
            raise ArtifactEvidenceError(
                "sidecar transaction contains duplicate outputs",
                reason=REASON_SIDECAR_WRITE_FAILED,
            )

        expected_parent.mkdir(parents=True, exist_ok=True)
        self.paths = contained
        self.basenames = basenames
        self.project_root = project_root
        self.expected_parent = expected_parent
        self._token = secrets.token_hex(16)
        self._backup_dir_name = _validate_sidecar_basename(
            f".rextio-sidecar-{self._token}.rollback"
        )
        self._originals: list[_FileReceipt | None] = [None] * len(paths)
        self._processed: set[int] = set()
        self._emitted: dict[int, _FileReceipt] = {}
        self._staged: dict[int, tuple[str, _FileReceipt, bytes]] = {}
        self._active = True
        self._parent_fd: int | None = None
        self._backup_fd: int | None = None
        self._parent_identity: _EntryIdentity | None = None
        self._backup_path = expected_parent / self._backup_dir_name

        try:
            if _dirfd_ops_available():
                self._prepare_dirfd()
            else:
                self._prepare_path()
        except BaseException:
            self.rollback()
            raise

    @classmethod
    def prepare(
        cls,
        paths: Sequence[Path],
        *,
        project_root: Path,
        expected_parent: Path,
    ) -> SidecarWriteTransaction:
        return cls(
            paths,
            project_root=project_root,
            expected_parent=expected_parent,
        )

    def _prepare_dirfd(self) -> None:
        parent_fd, parent_stat = _open_pinned_parent_dirfd(self.expected_parent)
        self._parent_fd = parent_fd
        self._parent_identity = _EntryIdentity.from_stat(parent_stat)
        try:
            os.mkdir(self._backup_dir_name, 0o700, dir_fd=parent_fd)
            flags = os.O_RDONLY
            if hasattr(os, "O_DIRECTORY"):
                flags |= os.O_DIRECTORY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            self._backup_fd = os.open(self._backup_dir_name, flags, dir_fd=parent_fd)
        except OSError as exc:
            raise ArtifactEvidenceError(
                "sidecar transaction could not preserve prior outputs",
                reason=REASON_SIDECAR_WRITE_FAILED,
            ) from exc

    def _prepare_path(self) -> None:
        parent = self.expected_parent
        parent_entry = parent.lstat()
        if stat.S_ISLNK(parent_entry.st_mode) or not stat.S_ISDIR(parent_entry.st_mode):
            raise ArtifactEvidenceError(
                "sidecar parent is not a real directory",
                reason=REASON_SIDECAR_WRITE_FAILED,
            )
        self._parent_identity = _EntryIdentity.from_stat(parent_entry)
        try:
            self._backup_path.mkdir(mode=0o700)
        except ArtifactEvidenceError:
            raise
        except OSError as exc:
            raise ArtifactEvidenceError(
                "sidecar transaction could not preserve prior outputs",
                reason=REASON_SIDECAR_WRITE_FAILED,
            ) from exc

    def _index_for(self, path: Path) -> int:
        try:
            return self.paths.index(path)
        except ValueError as exc:
            raise ArtifactEvidenceError(
                "sidecar output is outside the transaction",
                reason=REASON_SIDECAR_WRITE_FAILED,
            ) from exc

    def write(self, path: Path, data: bytes) -> None:
        if not self._active or len(data) > MAX_SIDECAR_BYTES:
            raise ArtifactEvidenceError(
                "sidecar transaction write is invalid",
                reason=REASON_SIDECAR_WRITE_FAILED,
            )
        index = self._index_for(path)
        if index in self._staged:
            raise ArtifactEvidenceError(
                "sidecar output was staged twice", reason=REASON_SIDECAR_WRITE_FAILED
            )
        if self._parent_fd is not None:
            self._write_dirfd(index, data)
        else:
            self._write_path(index, data)

    def _write_dirfd(self, index: int, data: bytes) -> None:
        assert self._parent_fd is not None
        name = self.basenames[index]
        temp_name = _validate_sidecar_basename(f".{name}.{self._token}.{index}.stage")
        identity = _write_exclusive_at(self._parent_fd, temp_name, data)
        if _read_exact_at(self._parent_fd, temp_name, identity, max_bytes=len(data)) != data:
            raise ArtifactEvidenceError(
                "sidecar stage bytes changed",
                reason=REASON_SIDECAR_WRITE_FAILED,
            )
        self._staged[index] = (
            temp_name,
            _FileReceipt.from_bytes(identity, data),
            data,
        )

    def _write_path(self, index: int, data: bytes) -> None:
        path = self.paths[index]
        temp = self.expected_parent / f".{path.name}.{self._token}.{index}.stage"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if sys.platform == "win32" and hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        fd: int | None = None
        identity: _EntryIdentity | None = None
        offset = 0
        staged = False
        try:
            fd = os.open(str(temp), flags, 0o644)
            entry = os.fstat(fd)
            identity = _EntryIdentity.from_stat(entry)
            if not stat.S_ISREG(entry.st_mode) or getattr(entry, "st_nlink", 1) != 1:
                raise ArtifactEvidenceError(
                    "sidecar stage is not an exclusive regular file",
                    reason=REASON_SIDECAR_WRITE_FAILED,
                )
            view = memoryview(data)
            while offset < len(data):
                written = os.write(fd, view[offset:])
                if written <= 0:
                    raise OSError("short sidecar stage write")
                offset += written
            os.fsync(fd)
            if _EntryIdentity.from_stat(os.fstat(fd)) != identity:
                raise ArtifactEvidenceError(
                    "sidecar stage ownership changed",
                    reason=REASON_SIDECAR_WRITE_FAILED,
                )
            os.close(fd)
            fd = None
            if temp.read_bytes() != data:
                raise ArtifactEvidenceError(
                    "sidecar stage bytes changed",
                    reason=REASON_SIDECAR_WRITE_FAILED,
                )
            self._staged[index] = (
                temp.name,
                _FileReceipt.from_bytes(identity, data),
                data,
            )
            staged = True
        except ArtifactEvidenceError:
            raise
        except OSError as exc:
            raise ArtifactEvidenceError(
                "sidecar stage could not be written",
                reason=REASON_SIDECAR_WRITE_FAILED,
            ) from exc
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
            if not staged and identity is not None:
                expected = _FileReceipt.from_bytes(identity, data[:offset])
                current = _lstat_path(temp)
                if (
                    current is not None
                    and getattr(current, "st_nlink", 1) == 1
                    and _receipt_matches_path(temp, expected)
                ):
                    try:
                        temp.unlink()
                    except OSError:
                        pass

    def _parent_matches(self) -> bool:
        try:
            current = self.expected_parent.lstat()
        except OSError:
            return False
        return (
            self._parent_identity is not None
            and _EntryIdentity.from_stat(current) == self._parent_identity
        )

    def commit(
        self,
        claim_sink: Callable[[tuple[tuple[Path, _FileReceipt], ...]], None] | None = None,
    ) -> None:
        if not self._active or len(self._staged) != len(self.paths):
            raise ArtifactEvidenceError(
                "sidecar transaction is incomplete",
                reason=REASON_SIDECAR_WRITE_FAILED,
            )
        if not self._parent_matches():
            raise ArtifactEvidenceError(
                "sidecar parent changed before commit",
                reason=REASON_SIDECAR_WRITE_FAILED,
            )
        self._preserve_outputs()
        self._publish_staged_outputs()
        for index, receipt in self._emitted.items():
            current = (
                _lstat_at(self._parent_fd, self.basenames[index])
                if self._parent_fd is not None
                else _lstat_path(self.paths[index])
            )
            identity_matches = (
                current is not None and _EntryIdentity.from_stat(current) == receipt.identity
            )
            content_matches = (
                _receipt_matches_at(self._parent_fd, self.basenames[index], receipt)
                if self._parent_fd is not None
                else _receipt_matches_path(self.paths[index], receipt)
            )
            if not identity_matches or not content_matches:
                raise ArtifactEvidenceError(
                    "sidecar ownership changed before commit",
                    reason=REASON_SIDECAR_WRITE_FAILED,
                )
        if claim_sink is not None:
            claim_sink(
                tuple(
                    (self.paths[index], receipt) for index, receipt in sorted(self._emitted.items())
                )
            )
        if not self._cleanup_stages():
            raise ArtifactEvidenceError(
                "sidecar stage cleanup lost ownership",
                reason=REASON_SIDECAR_WRITE_FAILED,
            )
        self._active = False
        self._discard_backups()
        self._close()

    def _preserve_outputs(self) -> None:
        try:
            for index, name in enumerate(self.basenames):
                entry = (
                    _lstat_at(self._parent_fd, name)
                    if self._parent_fd is not None
                    else _lstat_path(self.paths[index])
                )
                if entry is None:
                    self._processed.add(index)
                    continue
                if stat.S_ISDIR(entry.st_mode):
                    raise ArtifactEvidenceError(
                        "sidecar output is a directory",
                        reason=REASON_SIDECAR_WRITE_FAILED,
                    )
                if not stat.S_ISREG(entry.st_mode):
                    raise ArtifactEvidenceError(
                        "sidecar output is not a regular file",
                        reason=REASON_SIDECAR_WRITE_FAILED,
                    )
                receipt = (
                    _receipt_at(self._parent_fd, name, max_bytes=MAX_SIDECAR_BYTES)
                    if self._parent_fd is not None
                    else _receipt_path(self.paths[index], max_bytes=MAX_SIDECAR_BYTES)
                )
                # Write-ahead recovery state: once the following rename can
                # succeed, rollback must already know exactly which prior file
                # belongs in this slot. Post-rename inspection must never be the
                # first point at which ownership becomes durable in memory.
                self._originals[index] = receipt
                self._processed.add(index)
                if self._parent_fd is not None:
                    assert self._backup_fd is not None
                    os.replace(
                        name,
                        str(index),
                        src_dir_fd=self._parent_fd,
                        dst_dir_fd=self._backup_fd,
                    )
                    moved = _lstat_at(self._backup_fd, str(index))
                else:
                    backup = self._backup_path / str(index)
                    os.replace(self.paths[index], backup)
                    moved = _lstat_path(backup)
                moved_matches = (
                    moved is not None
                    and _EntryIdentity.from_stat(moved) == receipt.identity
                    and (
                        _receipt_matches_at(self._backup_fd, str(index), receipt)
                        if self._backup_fd is not None
                        else _receipt_matches_path(self._backup_path / str(index), receipt)
                    )
                )
                if not moved_matches:
                    raise ArtifactEvidenceError(
                        "sidecar backup identity changed",
                        reason=REASON_SIDECAR_WRITE_FAILED,
                    )
        except ArtifactEvidenceError:
            raise
        except OSError as exc:
            raise ArtifactEvidenceError(
                "sidecar transaction could not preserve prior outputs",
                reason=REASON_SIDECAR_WRITE_FAILED,
            ) from exc

    def _publish_staged_outputs(self) -> None:
        try:
            for index in range(len(self.paths)):
                temp_name, receipt, data = self._staged[index]
                current = (
                    _lstat_at(self._parent_fd, self.basenames[index])
                    if self._parent_fd is not None
                    else _lstat_path(self.paths[index])
                )
                if current is not None:
                    raise ArtifactEvidenceError(
                        "sidecar output was concurrently created",
                        reason=REASON_SIDECAR_WRITE_FAILED,
                    )
                if self._parent_fd is not None:
                    os.link(
                        temp_name,
                        self.basenames[index],
                        src_dir_fd=self._parent_fd,
                        dst_dir_fd=self._parent_fd,
                        follow_symlinks=False,
                    )
                    installed = _lstat_at(self._parent_fd, self.basenames[index])
                else:
                    os.link(
                        self.expected_parent / temp_name,
                        self.paths[index],
                        follow_symlinks=False,
                    )
                    installed = _lstat_path(self.paths[index])
                if installed is None or _EntryIdentity.from_stat(installed) != receipt.identity:
                    raise ArtifactEvidenceError(
                        "sidecar install identity changed",
                        reason=REASON_SIDECAR_WRITE_FAILED,
                    )
                self._emitted[index] = receipt
                installed_bytes = (
                    _read_exact_at(
                        self._parent_fd,
                        self.basenames[index],
                        receipt.identity,
                        max_bytes=len(data),
                    )
                    if self._parent_fd is not None
                    else self.paths[index].read_bytes()
                )
                if installed_bytes != data:
                    raise ArtifactEvidenceError(
                        "sidecar bytes changed after install",
                        reason=REASON_SIDECAR_WRITE_FAILED,
                    )
            if self._parent_fd is not None:
                try:
                    os.fsync(self._parent_fd)
                except OSError:
                    pass
        except ArtifactEvidenceError:
            raise
        except OSError as exc:
            raise ArtifactEvidenceError(
                "sidecar could not be installed without replacement",
                reason=REASON_SIDECAR_WRITE_FAILED,
            ) from exc

    def rollback(self) -> bool:
        if not self._active:
            return True
        self._active = False
        complete = self._parent_matches()
        try:
            for index in sorted(self._processed, reverse=True):
                if not self._rollback_index(index):
                    complete = False
            if not self._cleanup_stages():
                complete = False
            if not self._remove_backup_directory():
                complete = False
        except Exception:
            complete = False
        self._close()
        return complete

    def _cleanup_stages(self) -> bool:
        complete = True
        for index, (name, receipt, _data) in tuple(self._staged.items()):
            quarantine_name = _validate_sidecar_basename(f"stage-{self._token}-{index}.quarantine")
            if self._parent_fd is not None:
                assert self._backup_fd is not None
                cleaned = _quarantine_and_dispose_owned_at(
                    self._parent_fd,
                    name,
                    self._backup_fd,
                    quarantine_name,
                    receipt,
                )
            else:
                cleaned = _quarantine_and_dispose_owned_path(
                    self.expected_parent / name,
                    self._backup_path / quarantine_name,
                    receipt,
                )
            if cleaned:
                del self._staged[index]
            else:
                complete = False
        return complete

    def _rollback_index(self, index: int) -> bool:
        emitted = self._emitted.get(index)
        complete = True
        if emitted is not None:
            quarantine_name = _validate_sidecar_basename(f"output-{self._token}-{index}.quarantine")
            if self._parent_fd is not None:
                assert self._backup_fd is not None
                complete = _quarantine_and_dispose_owned_at(
                    self._parent_fd,
                    self.basenames[index],
                    self._backup_fd,
                    quarantine_name,
                    emitted,
                )
            else:
                complete = _quarantine_and_dispose_owned_path(
                    self.paths[index],
                    self._backup_path / quarantine_name,
                    emitted,
                )
        elif (
            _lstat_at(self._parent_fd, self.basenames[index])
            if self._parent_fd is not None
            else _lstat_path(self.paths[index])
        ) is not None:
            # Never delete an output that this transaction did not emit.
            complete = False

        original = self._originals[index]
        if original is None:
            return complete
        current = (
            _lstat_at(self._parent_fd, self.basenames[index])
            if self._parent_fd is not None
            else _lstat_path(self.paths[index])
        )
        if current is not None:
            return False
        try:
            if self._parent_fd is not None:
                assert self._backup_fd is not None
                backup = _lstat_at(self._backup_fd, str(index))
                if (
                    backup is None
                    or _EntryIdentity.from_stat(backup) != original.identity
                    or not _receipt_matches_at(self._backup_fd, str(index), original)
                ):
                    return False
                os.link(
                    str(index),
                    self.basenames[index],
                    src_dir_fd=self._backup_fd,
                    dst_dir_fd=self._parent_fd,
                    follow_symlinks=False,
                )
                restored = _lstat_at(self._parent_fd, self.basenames[index])
                if (
                    restored is None
                    or _EntryIdentity.from_stat(restored) != original.identity
                    or not _receipt_matches_at(self._parent_fd, self.basenames[index], original)
                ):
                    return False
                os.unlink(str(index), dir_fd=self._backup_fd)
            else:
                backup_path = self._backup_path / str(index)
                backup = _lstat_path(backup_path)
                if (
                    backup is None
                    or _EntryIdentity.from_stat(backup) != original.identity
                    or not _receipt_matches_path(backup_path, original)
                ):
                    return False
                os.link(backup_path, self.paths[index], follow_symlinks=False)
                restored = _lstat_path(self.paths[index])
                if (
                    restored is None
                    or _EntryIdentity.from_stat(restored) != original.identity
                    or not _receipt_matches_path(self.paths[index], original)
                ):
                    return False
                backup_path.unlink()
        except OSError:
            return False
        return complete

    def _discard_backups(self) -> None:
        for index, original in enumerate(self._originals):
            if original is None:
                continue
            try:
                if self._backup_fd is not None:
                    backup = _lstat_at(self._backup_fd, str(index))
                    if (
                        backup is not None
                        and _EntryIdentity.from_stat(backup) == original.identity
                        and _receipt_matches_at(self._backup_fd, str(index), original)
                    ):
                        os.unlink(str(index), dir_fd=self._backup_fd)
                else:
                    backup_path = self._backup_path / str(index)
                    backup = _lstat_path(backup_path)
                    if (
                        backup is not None
                        and _EntryIdentity.from_stat(backup) == original.identity
                        and _receipt_matches_path(backup_path, original)
                    ):
                        backup_path.unlink()
            except OSError:
                continue
        self._remove_backup_directory()

    def _remove_backup_directory(self) -> bool:
        try:
            if self._backup_fd is not None:
                assert self._parent_fd is not None
                os.rmdir(self._backup_dir_name, dir_fd=self._parent_fd)
            elif self._backup_path.exists():
                self._backup_path.rmdir()
        except OSError:
            return False
        return True

    def _close(self) -> None:
        for fd_name in ("_backup_fd", "_parent_fd"):
            fd = getattr(self, fd_name)
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
                setattr(self, fd_name, None)


def write_atomic_bytes(
    path: Path,
    data: bytes,
    *,
    project_root: Path | None = None,
    expected_parent: Path | None = None,
) -> Path:
    """Write ``data`` atomically with containment checks and exclusive create.

    On supported POSIX platforms the parent directory is pinned with a dirfd
    for exclusive temp create, replace, and fsync via real Python ``dir_fd``
    APIs. Elsewhere a conservative contained path-based fallback is used.
    Returns the final path.
    """
    if len(data) > MAX_SIDECAR_BYTES:
        raise ArtifactEvidenceError(
            "sidecar payload exceeds the allowed size", reason=REASON_SIDECAR_WRITE_FAILED
        )
    if project_root is not None and expected_parent is not None:
        path = ensure_sidecar_path_contained(
            path, project_root=project_root, expected_parent=expected_parent
        )
        parent = expected_parent
    else:
        parent = path.parent
        if parent.is_symlink():
            raise ArtifactEvidenceError(
                "sidecar parent must not be a symlink",
                reason=REASON_SIDECAR_WRITE_FAILED,
            )
    parent.mkdir(parents=True, exist_ok=True)
    if parent.is_symlink():
        raise ArtifactEvidenceError(
            "sidecar parent must not be a symlink",
            reason=REASON_SIDECAR_WRITE_FAILED,
        )

    token = secrets.token_hex(8)
    basename = _validate_sidecar_basename(path.name)
    tmp_name = f".{basename}.{token}.tmp"
    _validate_sidecar_basename(tmp_name)

    # Prefer real Python dir_fd ops on POSIX (not the absent os.openat symbols).
    if _dirfd_ops_available():
        return _write_atomic_bytes_dirfd(
            path, data, parent=parent, tmp_name=tmp_name, basename=basename
        )

    return _write_atomic_bytes_path(path, data, tmp_path=parent / tmp_name)


def _write_atomic_bytes_dirfd(
    path: Path,
    data: bytes,
    *,
    parent: Path,
    tmp_name: str,
    basename: str,
) -> Path:
    """POSIX dirfd-pinned exclusive write/replace/fsync for sidecar mutation.

    Uses ``os.open(name, flags, mode, dir_fd=...)``, ``os.replace`` with
    ``src_dir_fd``/``dst_dir_fd``, and ``os.unlink(name, dir_fd=...)``.
    """
    dir_fd, _link_stat = _open_pinned_parent_dirfd(parent)
    tmp_created = False
    operation_error: ArtifactEvidenceError | None = None
    try:
        file_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            file_flags |= os.O_NOFOLLOW

        fd: int | None = None
        file_error: ArtifactEvidenceError | None = None
        try:
            fd = os.open(tmp_name, file_flags, 0o644, dir_fd=dir_fd)
            tmp_created = True
            file_stat = os.fstat(fd)
            if not stat.S_ISREG(file_stat.st_mode):
                raise ArtifactEvidenceError(
                    "sidecar temp path is not a regular file",
                    reason=REASON_SIDECAR_WRITE_FAILED,
                )
            if getattr(file_stat, "st_nlink", 1) != 1:
                raise ArtifactEvidenceError(
                    "sidecar temp path has unexpected hard links",
                    reason=REASON_SIDECAR_WRITE_FAILED,
                )
            view = memoryview(data)
            offset = 0
            while offset < len(data):
                written = os.write(fd, view[offset:])
                if written <= 0:
                    raise ArtifactEvidenceError(
                        "sidecar write failed", reason=REASON_SIDECAR_WRITE_FAILED
                    )
                offset += written
            os.fsync(fd)
        except ArtifactEvidenceError as exc:
            file_error = exc
        except OSError:
            file_error = ArtifactEvidenceError(
                "sidecar temp could not be written",
                reason=REASON_SIDECAR_WRITE_FAILED,
            )
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    # Preserve an earlier, more precise error instead of
                    # allowing close() to mask it. A close-only failure is
                    # still surfaced through the sanitized evidence error.
                    if file_error is None:
                        file_error = ArtifactEvidenceError(
                            "sidecar temp could not be closed",
                            reason=REASON_SIDECAR_WRITE_FAILED,
                        )
                fd = None
        if file_error is not None:
            raise file_error

        try:
            os.replace(tmp_name, basename, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        except OSError as exc:
            raise ArtifactEvidenceError(
                "sidecar could not be replaced atomically",
                reason=REASON_SIDECAR_WRITE_FAILED,
            ) from exc
        tmp_created = False
        try:
            os.fsync(dir_fd)
        except OSError:
            # Directory fsync is a best-effort durability strengthening after
            # the atomic replacement; it cannot make the replacement partial.
            pass
    except ArtifactEvidenceError as exc:
        operation_error = exc
    except OSError:
        # No raw OS failure may escape the bounded evidence path.
        operation_error = ArtifactEvidenceError(
            "sidecar could not be written",
            reason=REASON_SIDECAR_WRITE_FAILED,
        )
    finally:
        if tmp_created:
            # Remove only the exact random temp name created by this call.
            try:
                os.unlink(tmp_name, dir_fd=dir_fd)
            except OSError:
                pass
        try:
            os.close(dir_fd)
        except OSError:
            # Closing the pinned directory is best-effort. In particular, once
            # replace() succeeded, a close failure must not prevent the caller
            # from hashing the sidecar and recording that this emission owns it.
            # On pre-replace failures, ``operation_error`` already carries the
            # sanitized cause and must not be masked by cleanup.
            pass

    if operation_error is not None:
        raise operation_error
    return path


def _write_atomic_bytes_path(path: Path, data: bytes, *, tmp_path: Path) -> Path:
    """Conservative contained path-based atomic write fallback."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if sys.platform == "win32" and hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        fd = os.open(str(tmp_path), flags, 0o644)
        try:
            file_stat = os.fstat(fd)
            if not stat.S_ISREG(file_stat.st_mode):
                raise ArtifactEvidenceError(
                    "sidecar temp path is not a regular file",
                    reason=REASON_SIDECAR_WRITE_FAILED,
                )
            if getattr(file_stat, "st_nlink", 1) != 1:
                raise ArtifactEvidenceError(
                    "sidecar temp path has unexpected hard links",
                    reason=REASON_SIDECAR_WRITE_FAILED,
                )
            view = memoryview(data)
            offset = 0
            while offset < len(data):
                written = os.write(fd, view[offset:])
                if written <= 0:
                    raise ArtifactEvidenceError(
                        "sidecar write failed", reason=REASON_SIDECAR_WRITE_FAILED
                    )
                offset += written
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp_path, path)
        _fsync_directory(path.parent)
        return path
    except ArtifactEvidenceError:
        _unlink_quiet(tmp_path)
        raise
    except OSError as exc:
        _unlink_quiet(tmp_path)
        raise ArtifactEvidenceError(
            "sidecar could not be written", reason=REASON_SIDECAR_WRITE_FAILED
        ) from exc


def _cleanup_created_sidecars_impl(
    basenames: Sequence[str],
    *,
    project_root: Path,
    expected_parent: Path,
) -> None:
    """Implement exact created-sidecar cleanup under a pinned parent.

    Never path-unlinks through a symlink or swapped parent and never sweeps a
    directory. Uses the same dirfd mechanism as write when available; on path
    fallback still refuses symlink parents.
    """
    if not basenames:
        return
    try:
        root = project_root.resolve(strict=False)
        parent = expected_parent.resolve(strict=False)
        parent.relative_to(root)
    except (OSError, ValueError):
        return
    try:
        if expected_parent.is_symlink():
            return
    except OSError:
        return

    names: list[str] = []
    for name in basenames:
        try:
            names.append(_validate_sidecar_basename(name))
        except ArtifactEvidenceError:
            continue
    if not names:
        return

    if _dirfd_ops_available():
        try:
            dir_fd, _ = _open_pinned_parent_dirfd(expected_parent)
        except ArtifactEvidenceError:
            return
        try:
            for name in names:
                try:
                    os.unlink(name, dir_fd=dir_fd)
                except OSError:
                    continue
            try:
                os.fsync(dir_fd)
            except OSError:
                pass
        finally:
            try:
                os.close(dir_fd)
            except OSError:
                pass
        return

    # Contained path fallback: still refuse symlink parents; unlink only exact
    # children of expected_parent by basename (no recursive sweep).
    for name in names:
        candidate = expected_parent / name
        try:
            if candidate.is_symlink():
                continue
            if candidate.parent.resolve(strict=False) != parent:
                continue
        except OSError:
            continue
        _unlink_quiet(candidate)


def cleanup_created_sidecars(
    basenames: Sequence[str],
    *,
    project_root: Path,
    expected_parent: Path,
) -> None:
    """Best-effort no-throw removal of exact sidecars created by one emission."""
    try:
        _cleanup_created_sidecars_impl(
            basenames,
            project_root=project_root,
            expected_parent=expected_parent,
        )
    except Exception:
        # Evidence cleanup must never turn an otherwise successful wheel build
        # into a failure, including on unusual filesystem/interpreter errors.
        return


def cleanup_paths(paths: Sequence[Path]) -> None:
    """Remove specific paths without a directory sweep (test-only helper).

    Prefer :func:`cleanup_created_sidecars` for emission cleanup. Does not
    follow symlinks.
    """
    for path in paths:
        try:
            if path.is_symlink():
                continue
        except OSError:
            continue
        _unlink_quiet(path)


def canonical_json_bytes(value: object) -> bytes:
    """Serialize ``value`` as deterministic UTF-8 JSON (sorted, compact)."""
    _assert_json_depth(value, depth=0)
    text = json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return text.encode("utf-8")


def pretty_json_bytes(value: object) -> bytes:
    """Serialize ``value`` as deterministic pretty UTF-8 JSON with trailing NL."""
    _assert_json_depth(value, depth=0)
    text = json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        indent=2,
        allow_nan=False,
    )
    return (text + "\n").encode("utf-8")


def content_uuid_urn(digest_hex: str) -> str:
    """Derive a deterministic RFC 4122 UUIDv5 ``urn:uuid:`` from a SHA-256 digest."""
    if not _HEX_SHA256.fullmatch(digest_hex):
        raise ValueError("digest must be 64 lowercase hex characters")
    value = uuid.uuid5(_CDX_UUID_NAMESPACE, f"rextio:cdx:sha256:{digest_hex}")
    return f"urn:uuid:{value}"


def canonicalize_registry_source(source: str) -> str:
    """Canonicalize a Cargo registry source; reject credentials and local paths."""
    if not isinstance(source, str) or not source.startswith("registry+"):
        raise ArtifactEvidenceError(
            "cargo package source is not a registry URI",
            reason=REASON_CARGO_GRAPH_INVALID,
        )
    rest = source[len("registry+") :]
    if any(ord(ch) < 32 for ch in rest) or len(rest) > MAX_EVIDENCE_STRING_CHARS:
        raise ArtifactEvidenceError(
            "cargo package source is invalid", reason=REASON_CARGO_GRAPH_INVALID
        )
    parsed = urlparse(rest)
    if parsed.username or parsed.password:
        raise ArtifactEvidenceError(
            "cargo package source must not carry credentials",
            reason=REASON_CARGO_GRAPH_INVALID,
        )
    if parsed.query or parsed.fragment:
        raise ArtifactEvidenceError(
            "cargo package source must not carry query or fragment",
            reason=REASON_CARGO_GRAPH_INVALID,
        )
    if parsed.scheme not in {"https", "http"}:
        raise ArtifactEvidenceError(
            "cargo package source scheme is not allowed",
            reason=REASON_CARGO_GRAPH_INVALID,
        )
    if not parsed.hostname:
        raise ArtifactEvidenceError(
            "cargo package source host is missing", reason=REASON_CARGO_GRAPH_INVALID
        )
    host = parsed.hostname.lower()
    path = parsed.path or ""
    if ".." in PurePosixPath(path).parts:
        raise ArtifactEvidenceError(
            "cargo package source path is invalid", reason=REASON_CARGO_GRAPH_INVALID
        )
    netloc = host if parsed.port is None else f"{host}:{parsed.port}"
    return f"registry+{parsed.scheme}://{netloc}{path}".rstrip("/")


def canonicalize_zip_entry_name(name: str) -> str:
    """Return a strict canonical ZIP entry name or raise on unsafe/noncanonical forms."""
    if not isinstance(name, str) or not name:
        raise ArtifactEvidenceError(
            "wheel entry name is invalid", reason=REASON_WHEEL_INVENTORY_INVALID
        )
    if len(name) > MAX_WHEEL_ENTRY_PATH_CHARS:
        raise ArtifactEvidenceError(
            "wheel entry path is too long", reason=REASON_WHEEL_INVENTORY_INVALID
        )
    if "\0" in name or any(ord(ch) < 32 for ch in name):
        raise ArtifactEvidenceError(
            "wheel entry name contains control characters",
            reason=REASON_WHEEL_INVENTORY_INVALID,
        )
    if "\\" in name:
        raise ArtifactEvidenceError(
            "wheel entry path uses backslashes",
            reason=REASON_WHEEL_INVENTORY_INVALID,
        )
    if name.startswith("/") or name.startswith("\\"):
        raise ArtifactEvidenceError(
            "wheel entry path is absolute",
            reason=REASON_WHEEL_INVENTORY_INVALID,
        )
    # Reject Windows drive paths such as "C:foo" or "C:/foo".
    if len(name) >= 2 and name[1] == ":":
        raise ArtifactEvidenceError(
            "wheel entry path contains a drive prefix",
            reason=REASON_WHEEL_INVENTORY_INVALID,
        )
    is_dir = name.endswith("/")
    body = name[:-1] if is_dir else name
    if not body:
        raise ArtifactEvidenceError(
            "wheel entry name is invalid", reason=REASON_WHEEL_INVENTORY_INVALID
        )
    parts = body.split("/")
    if any(part == "" for part in parts):
        raise ArtifactEvidenceError(
            "wheel entry path is noncanonical",
            reason=REASON_WHEEL_INVENTORY_INVALID,
        )
    if any(part in {".", ".."} for part in parts):
        raise ArtifactEvidenceError(
            "wheel entry path contains a dot segment",
            reason=REASON_WHEEL_INVENTORY_INVALID,
        )
    canonical = "/".join(parts) + ("/" if is_dir else "")
    if canonical != name:
        raise ArtifactEvidenceError(
            "wheel entry path is noncanonical",
            reason=REASON_WHEEL_INVENTORY_INVALID,
        )
    return canonical


def _preflight_zip_eocd_entry_count(data: bytes) -> int:
    r"""Parse a structurally valid classic EOCD; fail closed on ZIP64/malformed.

    Locates the classic EOCD by requiring ``comment_length`` to reach EOF (so a
    forged EOCD signature inside the archive comment cannot win). Validates
    disk/count fields and central-directory bounds. Inspects a ZIP64 end-of-
    central-directory locator **only** at its legal 20-byte position
    immediately before EOCD — never by scanning payload bytes for ``PK\x06\x07``.
    """
    if len(data) < 22:
        raise ArtifactEvidenceError(
            "wheel is not a valid ZIP archive", reason=REASON_WHEEL_INVENTORY_INVALID
        )
    max_comment = 65535
    search_start = max(0, len(data) - (22 + max_comment))
    eocd_sig = b"PK\x05\x06"
    candidates: list[int] = []
    # Walk every candidate in the bounded EOCD window. More than one terminal
    # candidate is ambiguous: a forged record inside the real archive comment
    # can otherwise cause a non-empty wheel to be interpreted as empty.
    cursor = len(data) - 22
    while cursor >= search_start:
        if data[cursor : cursor + 4] == eocd_sig:
            comment_len = int.from_bytes(data[cursor + 20 : cursor + 22], "little")
            if cursor + 22 + comment_len == len(data):
                candidates.append(cursor)
        cursor -= 1
    if not candidates:
        raise ArtifactEvidenceError(
            "wheel EOCD is missing or truncated",
            reason=REASON_WHEEL_INVENTORY_INVALID,
        )
    if len(candidates) != 1:
        raise ArtifactEvidenceError(
            "wheel EOCD is ambiguous",
            reason=REASON_WHEEL_INVENTORY_INVALID,
        )
    pos = candidates[0]

    disk_no = int.from_bytes(data[pos + 4 : pos + 6], "little")
    cd_disk = int.from_bytes(data[pos + 6 : pos + 8], "little")
    entries_on_disk = int.from_bytes(data[pos + 8 : pos + 10], "little")
    total_entries = int.from_bytes(data[pos + 10 : pos + 12], "little")
    cd_size = int.from_bytes(data[pos + 12 : pos + 16], "little")
    cd_offset = int.from_bytes(data[pos + 16 : pos + 20], "little")

    # Classic ZIP64 sentinels in EOCD fields mean the real sizes live in ZIP64.
    if (
        total_entries == 0xFFFF
        or entries_on_disk == 0xFFFF
        or cd_size == 0xFFFFFFFF
        or cd_offset == 0xFFFFFFFF
    ):
        raise ArtifactEvidenceError(
            "ZIP64 wheels are not supported in this evidence slice",
            reason=REASON_WHEEL_INVENTORY_INVALID,
        )
    # Single-disk classic archives only.
    if disk_no != 0 or cd_disk != 0:
        raise ArtifactEvidenceError(
            "multi-disk ZIP archives are not supported",
            reason=REASON_WHEEL_INVENTORY_INVALID,
        )
    if entries_on_disk != total_entries:
        raise ArtifactEvidenceError(
            "wheel EOCD entry counts are inconsistent",
            reason=REASON_WHEEL_INVENTORY_INVALID,
        )
    if total_entries > MAX_WHEEL_ENTRIES:
        raise ArtifactEvidenceError(
            "wheel entry count exceeds the bound",
            reason=REASON_WHEEL_INVENTORY_INVALID,
        )
    # Central directory must sit entirely before EOCD and within the archive.
    if cd_offset > pos or cd_size > pos:
        raise ArtifactEvidenceError(
            "wheel central directory bounds are invalid",
            reason=REASON_WHEEL_INVENTORY_INVALID,
        )
    if cd_offset + cd_size > pos:
        raise ArtifactEvidenceError(
            "wheel central directory bounds are invalid",
            reason=REASON_WHEEL_INVENTORY_INVALID,
        )
    if cd_offset + cd_size > len(data):
        raise ArtifactEvidenceError(
            "wheel central directory bounds are invalid",
            reason=REASON_WHEEL_INVENTORY_INVALID,
        )

    # ZIP64 EOCD locator is exactly 20 bytes immediately before the classic EOCD.
    locator_sig = b"PK\x06\x07"
    if pos >= 20 and data[pos - 20 : pos - 16] == locator_sig:
        raise ArtifactEvidenceError(
            "ZIP64 wheels are not supported in this evidence slice",
            reason=REASON_WHEEL_INVENTORY_INVALID,
        )
    return total_entries


def inventory_wheel_zip_bytes(data: bytes) -> tuple[WheelEntryRef, ...]:
    """Bounded ZIP inventory from exact wheel bytes (no filesystem re-read)."""
    if not data or len(data) > MAX_EVIDENCE_FILE_BYTES:
        raise ArtifactEvidenceError(
            "wheel size is outside the allowed range",
            reason=REASON_WHEEL_INVENTORY_INVALID,
        )
    # Preflight EOCD entry count before constructing ZipFile.
    expected_entry_count = _preflight_zip_eocd_entry_count(data)
    try:
        archive = zipfile.ZipFile(io.BytesIO(data), mode="r")
    except zipfile.BadZipFile as exc:
        raise ArtifactEvidenceError(
            "wheel is not a valid ZIP archive", reason=REASON_WHEEL_INVENTORY_INVALID
        ) from exc

    entries: list[WheelEntryRef] = []
    seen_names: set[str] = set()
    total_uncompressed = 0
    try:
        infos = archive.infolist()
        if len(infos) != expected_entry_count:
            raise ArtifactEvidenceError(
                "wheel EOCD entry count does not match the central directory",
                reason=REASON_WHEEL_INVENTORY_INVALID,
            )
        if len(infos) > MAX_WHEEL_ENTRIES:
            raise ArtifactEvidenceError(
                "wheel entry count exceeds the bound",
                reason=REASON_WHEEL_INVENTORY_INVALID,
            )
        for info in infos:
            # Validate original (possibly NUL-truncated) names so parser
            # truncation cannot bypass canonicalization rules.
            orig = getattr(info, "orig_filename", None)
            if isinstance(orig, (bytes, bytearray)) and b"\x00" in bytes(orig):
                raise ArtifactEvidenceError(
                    "wheel entry original name contains NUL",
                    reason=REASON_WHEEL_INVENTORY_INVALID,
                )
            if isinstance(orig, str) and "\0" in orig:
                raise ArtifactEvidenceError(
                    "wheel entry original name contains NUL",
                    reason=REASON_WHEEL_INVENTORY_INVALID,
                )
            if isinstance(orig, (bytes, bytearray)):
                try:
                    orig_text = bytes(orig).decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise ArtifactEvidenceError(
                        "wheel entry original name is not UTF-8",
                        reason=REASON_WHEEL_INVENTORY_INVALID,
                    ) from exc
                if orig_text != info.filename and "\0" not in orig_text:
                    # ZipFile may normalize; still require the reported filename
                    # to be canonical and the original to not smuggle controls.
                    canonicalize_zip_entry_name(orig_text.split("\0", 1)[0] or orig_text)
            name = canonicalize_zip_entry_name(info.filename)
            if name in seen_names:
                raise ArtifactEvidenceError(
                    "wheel contains duplicate entry names",
                    reason=REASON_WHEEL_INVENTORY_INVALID,
                )
            seen_names.add(name)
            if info.flag_bits & 0x1:
                raise ArtifactEvidenceError(
                    "wheel contains an encrypted entry",
                    reason=REASON_WHEEL_INVENTORY_INVALID,
                )
            # Unix symlink: high 16 bits of external_attr hold the mode.
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                raise ArtifactEvidenceError(
                    "wheel contains a symlink entry",
                    reason=REASON_WHEEL_INVENTORY_INVALID,
                )
            if info.file_size > MAX_WHEEL_ENTRY_UNCOMPRESSED:
                raise ArtifactEvidenceError(
                    "wheel entry uncompressed size exceeds the bound",
                    reason=REASON_WHEEL_INVENTORY_INVALID,
                )
            total_uncompressed += info.file_size
            if total_uncompressed > MAX_WHEEL_TOTAL_UNCOMPRESSED:
                raise ArtifactEvidenceError(
                    "wheel total uncompressed size exceeds the bound",
                    reason=REASON_WHEEL_INVENTORY_INVALID,
                )
            if name.endswith("/"):
                # Directory entries must be empty (no payload).
                if info.file_size != 0:
                    raise ArtifactEvidenceError(
                        "wheel directory entry must be empty",
                        reason=REASON_WHEEL_INVENTORY_INVALID,
                    )
                digest = sha256_hex(b"")
                entries.append(
                    WheelEntryRef(
                        name=name,
                        sha256=digest,
                        compressed_size=info.compress_size,
                        uncompressed_size=0,
                    )
                )
                continue
            hasher = hashlib.sha256()
            remaining = info.file_size
            try:
                with archive.open(info, "r") as handle:
                    while remaining > 0:
                        chunk = handle.read(min(65536, remaining))
                        if not chunk:
                            break
                        if len(chunk) > remaining:
                            raise ArtifactEvidenceError(
                                "wheel entry expanded beyond declared size",
                                reason=REASON_WHEEL_INVENTORY_INVALID,
                            )
                        hasher.update(chunk)
                        remaining -= len(chunk)
            except (RuntimeError, zipfile.BadZipFile, OSError) as exc:
                raise ArtifactEvidenceError(
                    "wheel entry could not be streamed",
                    reason=REASON_WHEEL_INVENTORY_INVALID,
                ) from exc
            if remaining != 0:
                raise ArtifactEvidenceError(
                    "wheel entry size mismatch during stream",
                    reason=REASON_WHEEL_INVENTORY_INVALID,
                )
            entries.append(
                WheelEntryRef(
                    name=name,
                    sha256=hasher.hexdigest(),
                    compressed_size=info.compress_size,
                    uncompressed_size=info.file_size,
                )
            )
    finally:
        archive.close()

    return tuple(sorted(entries, key=lambda item: item.name))


def inventory_wheel_zip(path: Path) -> tuple[WheelEntryRef, ...]:
    """Bounded final-wheel ZIP inventory by reading the path once as bytes."""
    data = read_regular_file_bytes(path)
    return inventory_wheel_zip_bytes(data)


def load_wheel_snapshot(
    path: Path, *, project_root: Path
) -> tuple[EvidenceFileRef, tuple[WheelEntryRef, ...]]:
    """Load one immutable wheel byte snapshot for both SHA-256 and ZIP inventory."""
    data = read_regular_file_bytes(path)
    digest = sha256_hex(data)
    entries = inventory_wheel_zip_bytes(data)
    logical = project_relative_logical_path(project_root, path)
    subject = EvidenceFileRef(
        logical_path=logical,
        sha256=digest,
        size=len(data),
        role="host-extension-wheel",
    )
    return subject, entries


def parse_wheel_version(logical_path: str) -> str:
    """Extract the distribution version from a wheel filename, or ``unknown``."""
    name = PurePosixPath(logical_path).name
    match = _WHEEL_VERSION_RE.match(name)
    if match is None:
        return "unknown"
    return match.group("version")


def _cargo_package_sort_key(
    package: CargoPackageRef,
) -> tuple[str, str, str, str, str, str]:
    """Return a total order across every serialized Cargo package identity."""
    return (
        package.name,
        package.version,
        package.kind,
        package.source_fingerprint() or "",
        package.checksum or "",
        package.bom_ref(),
    )


def _validate_cargo_dependency_graph(
    cargo_packages: Sequence[CargoPackageRef],
    cargo_dependencies: Sequence[CargoDepEdge],
) -> None:
    """Reject duplicate package identities and dangling/self dependency edges."""
    package_refs = [package.bom_ref() for package in cargo_packages]
    known_refs = set(package_refs)
    if len(package_refs) != len(known_refs):
        raise ValueError("cargo package bom-refs must be unique")
    for edge in cargo_dependencies:
        if edge.dependent_ref == edge.dependency_ref:
            raise ValueError("cargo dependency edges must not be self-referential")
        if edge.dependent_ref not in known_refs or edge.dependency_ref not in known_refs:
            raise ValueError("cargo dependency edge endpoint is not a known package")


def _wheel_entry_bom_ref(entry: WheelEntryRef) -> str:
    """Return the single canonical CycloneDX identity for a wheel member."""
    return f"urn:rextio:wheel-entry:{entry.sha256}:{sha256_hex(entry.name.encode('utf-8'))[:16]}"


def build_cyclonedx_document(
    *,
    subject: EvidenceFileRef,
    inputs: Sequence[EvidenceFileRef],
    wheel_entries: Sequence[WheelEntryRef],
    cargo_packages: Sequence[CargoPackageRef],
    cargo_dependencies: Sequence[CargoDepEdge],
    target_triple: str,
    native_runtime_inventory: NativeRuntimeInventory | None = None,
) -> dict[str, object]:
    """Build a CycloneDX 1.6 JSON document with honest incomplete composition.

    The primary component lives only in ``metadata.component`` (not duplicated
    in ``components``). Top-level ``dependencies`` describe the incomplete graph.
    Direct native runtime linkage (C6.4) is optional additive inventory only and
    is never claimed as a transitive closure.
    """
    runtime_dep_count = (
        len(native_runtime_inventory.dependencies) if native_runtime_inventory is not None else 0
    )
    if (
        len(inputs) + len(wheel_entries) + len(cargo_packages) + runtime_dep_count + 1
        > MAX_EVIDENCE_COMPONENTS
    ):
        raise ArtifactEvidenceError(
            "evidence component count exceeds the bound",
            reason=REASON_EVIDENCE_INTERNAL,
        )
    try:
        _validate_cargo_dependency_graph(cargo_packages, cargo_dependencies)
    except ValueError as exc:
        raise ArtifactEvidenceError(
            "cargo dependency graph is invalid",
            reason=REASON_CARGO_GRAPH_INVALID,
        ) from exc

    subject_ref = f"urn:rextio:wheel:{subject.sha256}"
    wheel_version = parse_wheel_version(subject.logical_path)
    components: list[dict[str, object]] = []
    depends_on: list[str] = []
    native_wheel_ref: str | None = None
    if native_runtime_inventory is not None:
        inv = native_runtime_inventory
        matching_entries = [entry for entry in wheel_entries if entry.name == inv.wheel_member]
        if len(matching_entries) != 1:
            raise ArtifactEvidenceError(
                "native runtime wheel member is not unique",
                reason=REASON_RUNTIME_WHEEL_MEMBER_MISMATCH,
            )
        native_entry = matching_entries[0]
        if (
            native_entry.sha256 != inv.wheel_member_sha256
            or native_entry.uncompressed_size != inv.wheel_member_size
        ):
            raise ArtifactEvidenceError(
                "native runtime wheel member binding is inconsistent",
                reason=REASON_RUNTIME_WHEEL_MEMBER_MISMATCH,
            )
        native_wheel_ref = _wheel_entry_bom_ref(native_entry)

    for item in sorted(inputs, key=lambda value: (value.role, value.logical_path, value.sha256)):
        # Include path and role in bom-ref identity so equal digests do not collide.
        identity = sha256_hex(f"{item.role}|{item.logical_path}|{item.sha256}".encode("utf-8"))
        bom_ref = f"urn:rextio:input:{identity}"
        components.append(
            {
                "type": "file",
                "bom-ref": bom_ref,
                "name": PurePosixPath(item.logical_path).name,
                "hashes": [{"alg": "SHA-256", "content": item.sha256}],
                "properties": [
                    {"name": "rextio:role", "value": item.role},
                    {"name": "rextio:logical_path", "value": item.logical_path},
                ],
            }
        )
        depends_on.append(bom_ref)

    for wheel_entry in sorted(wheel_entries, key=lambda value: value.name):
        bom_ref = _wheel_entry_bom_ref(wheel_entry)
        wheel_properties = [
            {"name": "rextio:role", "value": "wheel-zip-entry"},
            {
                "name": "rextio:compressed_size",
                "value": str(wheel_entry.compressed_size),
            },
            {
                "name": "rextio:uncompressed_size",
                "value": str(wheel_entry.uncompressed_size),
            },
        ]
        if native_runtime_inventory is not None and bom_ref == native_wheel_ref:
            wheel_properties.extend(
                [
                    {"name": "rextio:native_runtime_subject", "value": "true"},
                    {"name": "rextio:format", "value": native_runtime_inventory.format},
                    {
                        "name": "rextio:architecture",
                        "value": native_runtime_inventory.architecture,
                    },
                    {
                        "name": "rextio:inspector",
                        "value": native_runtime_inventory.inspector,
                    },
                    {"name": "rextio:linkage_scope", "value": "direct-only"},
                    {"name": "rextio:transitive_closure", "value": "false"},
                ]
            )
        components.append(
            {
                "type": "file",
                "bom-ref": bom_ref,
                "name": wheel_entry.name,
                "hashes": [{"alg": "SHA-256", "content": wheel_entry.sha256}],
                "properties": wheel_properties,
            }
        )
        depends_on.append(bom_ref)

    for package in sorted(cargo_packages, key=_cargo_package_sort_key):
        bom_ref = package.bom_ref()
        properties: list[dict[str, str]] = [
            {"name": "rextio:role", "value": "cargo-package"},
            {"name": "rextio:kind", "value": package.kind},
        ]
        fingerprint = package.source_fingerprint()
        if fingerprint is not None:
            properties.append({"name": "rextio:source_fingerprint", "value": fingerprint})
        if package.features:
            properties.append({"name": "rextio:features", "value": ",".join(package.features)})
        component_entry: dict[str, object] = {
            "type": "library",
            "bom-ref": bom_ref,
            "name": package.name,
            "version": package.version,
            "purl": package.purl(),
            "properties": properties,
        }
        if package.license is not None:
            # Cargo metadata may contain legacy/arbitrary license text. Do not
            # claim it is a valid SPDX expression without a real validator.
            component_entry["licenses"] = [{"license": {"name": package.license}}]
        if package.checksum is not None:
            component_entry["hashes"] = [{"alg": "SHA-256", "content": package.checksum}]
        components.append(component_entry)
        depends_on.append(bom_ref)

    runtime_dependency_refs: list[str] = []
    if native_runtime_inventory is not None:
        for dep in sorted(native_runtime_inventory.dependencies, key=lambda item: item.name):
            dep_ref = dep.bom_ref()
            components.append(
                {
                    "type": "library",
                    "bom-ref": dep_ref,
                    "name": dep.name,
                    "properties": [
                        {"name": "rextio:role", "value": "native-direct-dependency"},
                        {"name": "rextio:origin", "value": dep.origin},
                        {
                            "name": "rextio:format",
                            "value": native_runtime_inventory.format,
                        },
                        {"name": "rextio:linkage_scope", "value": "direct-only"},
                    ],
                }
            )
            runtime_dependency_refs.append(dep_ref)

    # Aggregate and deduplicate dependency refs by package bom-ref identity.
    deps_map: dict[str, set[str]] = defaultdict(set)
    for component_ref in (subject_ref, *depends_on, *runtime_dependency_refs):
        deps_map[component_ref]
    deps_map[subject_ref].update(depends_on)
    for edge in cargo_dependencies:
        deps_map[edge.dependent_ref].add(edge.dependency_ref)
    if native_wheel_ref is not None:
        deps_map[native_wheel_ref].update(runtime_dependency_refs)
    dependency_graph: list[dict[str, object]] = [
        {"ref": ref, "dependsOn": sorted(children)}
        for ref, children in sorted(deps_map.items(), key=lambda item: item[0])
    ]

    metadata_properties: list[dict[str, str]] = [
        {"name": "rextio:preview", "value": "true"},
        {"name": "rextio:evidence_kind", "value": "host-extension-wheel"},
        {"name": "rextio:target_triple", "value": target_triple},
        {"name": "rextio:composition", "value": "incomplete"},
        {"name": "rextio:signed", "value": "false"},
        {"name": "rextio:authority", "value": "evidence-only"},
        {"name": "rextio:distribution_authorized", "value": "false"},
    ]
    if native_runtime_inventory is not None:
        metadata_properties.extend(
            [
                {
                    "name": "rextio:native_runtime_format",
                    "value": native_runtime_inventory.format,
                },
                {
                    "name": "rextio:native_runtime_architecture",
                    "value": native_runtime_inventory.architecture,
                },
                {
                    "name": "rextio:native_runtime_scope",
                    "value": "direct-only",
                },
                {
                    "name": "rextio:native_runtime_transitive_closure",
                    "value": "false",
                },
            ]
        )

    document: dict[str, object] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "serialNumber": content_uuid_urn(subject.sha256),
        "metadata": {
            "component": {
                "type": "library",
                "bom-ref": subject_ref,
                "name": PurePosixPath(subject.logical_path).name,
                "version": wheel_version,
                "hashes": [{"alg": "SHA-256", "content": subject.sha256}],
                "properties": [
                    {"name": "rextio:role", "value": subject.role},
                    {"name": "rextio:logical_path", "value": subject.logical_path},
                ],
            },
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "rextio",
                        "version": REXTIO_VERSION,
                    }
                ]
            },
            "properties": metadata_properties,
        },
        "components": components,
        "dependencies": dependency_graph,
        "compositions": [
            {
                "aggregate": "incomplete",
                "assemblies": [subject_ref],
            }
        ],
    }
    return document


def build_intoto_provenance_document(
    *,
    subject: EvidenceFileRef,
    sbom: EvidenceFileRef,
    inputs: Sequence[EvidenceFileRef],
    cargo_packages: Sequence[CargoPackageRef],
    target_triple: str,
    native_runtime_inventory: NativeRuntimeInventory | None = None,
) -> dict[str, object]:
    """Build an unsigned in-toto Statement v1 with SLSA Provenance v1 predicate.

    The SBOM is a second statement subject (an output), not a resolved input.
    ``invocationId`` is omitted so deterministic sidecars do not invent a unique
    invocation identity from the wheel hash alone. C6.4 native linkage is an
    observation of the produced binary, so it is metadata rather than a resolved
    build input/material.
    """
    materials: list[dict[str, object]] = []
    for item in sorted(inputs, key=lambda value: (value.role, value.logical_path, value.sha256)):
        materials.append(
            {
                "uri": f"file:{item.logical_path}",
                "digest": {"sha256": item.sha256},
                "annotations": {
                    "rextio:role": item.role,
                    "rextio:size": str(item.size),
                },
            }
        )
    for package in sorted(cargo_packages, key=_cargo_package_sort_key):
        annotations: dict[str, str] = {
            "rextio:role": "cargo-package",
            "rextio:kind": package.kind,
        }
        fingerprint = package.source_fingerprint()
        if fingerprint is not None:
            annotations["rextio:source_fingerprint"] = fingerprint
        entry: dict[str, object] = {
            "uri": package.purl(),
            "annotations": annotations,
        }
        if package.checksum is not None:
            entry["digest"] = {"sha256": package.checksum}
        materials.append(entry)

    if len(materials) > MAX_EVIDENCE_COMPONENTS:
        raise ArtifactEvidenceError(
            "provenance material count exceeds the bound",
            reason=REASON_EVIDENCE_INTERNAL,
        )

    internal_parameters: dict[str, object] = {
        "signed": False,
        "reproducible_claim": False,
        "hermetic_claim": False,
        "complete_claim": False,
        "external_source_authorization": False,
        "authority": "evidence-only",
        "distribution_authorized": False,
        "native_runtime_transitive_closure": False,
        "native_runtime_dlopen": False,
    }
    if native_runtime_inventory is not None:
        internal_parameters["native_runtime_format"] = native_runtime_inventory.format
        internal_parameters["native_runtime_scope"] = "direct-only"

    run_metadata: dict[str, object] = {}
    if native_runtime_inventory is not None:
        run_metadata["rextio:observed_native_runtime"] = native_runtime_inventory.to_dict()

    document: dict[str, object] = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": subject.logical_path,
                "digest": {"sha256": subject.sha256},
            },
            {
                "name": sbom.logical_path,
                "digest": {"sha256": sbom.sha256},
            },
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://rextio.dev/buildtypes/host-extension-wheel/v1-preview",
                "externalParameters": {
                    "artifact_kind": "host-extension",
                    "packaging_backend": "wheel",
                    "target_triple": target_triple,
                    "preview": True,
                },
                "internalParameters": internal_parameters,
                "resolvedDependencies": materials,
            },
            "runDetails": {
                "builder": {
                    "id": "https://rextio.dev/builder/host-extension-wheel/v1-preview",
                    "version": {"rextio": REXTIO_VERSION},
                },
                "metadata": run_metadata,
            },
        },
    }
    return document


def _bounded_identifier(value: str, label: str) -> str:
    text = value.strip()
    if not text or len(text) > MAX_EVIDENCE_STRING_CHARS:
        raise ValueError(f"{label} is invalid")
    if any(ord(ch) < 32 for ch in text):
        raise ValueError(f"{label} contains control characters")
    return text


def _bounded_string(value: str, label: str) -> str:
    text = value.strip()
    if not text or len(text) > MAX_EVIDENCE_STRING_CHARS:
        raise ValueError(f"{label} is invalid")
    if any(ord(ch) < 32 for ch in text):
        raise ValueError(f"{label} contains control characters")
    return text


def _assert_json_depth(value: object, *, depth: int) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ArtifactEvidenceError(
            "JSON nesting exceeds the allowed depth", reason=REASON_EVIDENCE_INTERNAL
        )
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ArtifactEvidenceError(
                    "JSON object keys must be strings", reason=REASON_EVIDENCE_INTERNAL
                )
            _assert_json_depth(child, depth=depth + 1)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _assert_json_depth(child, depth=depth + 1)


def _sanitize_error_message(message: str) -> str:
    """Strip absolute paths and truncate attacker-influenced text."""
    text = " ".join(message.split())
    text = re.sub(r"(/[^ \t\n]+)+", "<redacted-path>", text)
    text = re.sub(r"[A-Za-z]:\\[^ \t\n]+", "<redacted-path>", text)
    # Never echo credential-looking userinfo fragments.
    text = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+", "<redacted-identity>", text)
    if len(text) > 240:
        text = text[:237] + "..."
    return text or "artifact evidence generation failed"


def _unlink_quiet(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        return


def _fsync_directory(directory: Path) -> None:
    """Best-effort directory fsync so the rename is durable where supported."""
    if os.name == "nt":  # pragma: no cover - Windows directory fsync is limited
        return
    try:
        fd = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        return
    finally:
        os.close(fd)


__all__ = [
    "ArtifactEvidence",
    "ArtifactEvidenceError",
    "ArtifactEvidenceGate",
    "CargoDepEdge",
    "CargoPackageRef",
    "DEFAULT_LIMITATIONS",
    "EvidenceFileRef",
    "MAX_CARGO_EDGES",
    "MAX_CARGO_METADATA_BYTES",
    "MAX_CARGO_PACKAGES",
    "MAX_EVIDENCE_COMPONENTS",
    "MAX_EVIDENCE_FILE_BYTES",
    "MAX_EVIDENCE_STRING_CHARS",
    "MAX_INPUT_FILES",
    "MAX_JSON_DEPTH",
    "MAX_RUNTIME_DEPS",
    "MAX_RUNTIME_DEP_NAME_CHARS",
    "MAX_RUNTIME_INSPECTOR_OUTPUT_BYTES",
    "MAX_SIDECAR_BYTES",
    "MAX_WHEEL_ENTRIES",
    "MAX_WHEEL_ENTRY_PATH_CHARS",
    "MAX_WHEEL_ENTRY_UNCOMPRESSED",
    "MAX_WHEEL_TOTAL_UNCOMPRESSED",
    "NativeRuntimeDependency",
    "NativeRuntimeInventory",
    "REASON_CARGO_GRAPH_INVALID",
    "REASON_CARGO_LOCK_MISSING",
    "REASON_CARGO_METADATA_FAILED",
    "REASON_CARGO_OUTPUT_EXCEEDED",
    "REASON_EVIDENCE_INTERNAL",
    "REASON_INPUT_COUNT_EXCEEDED",
    "REASON_NATIVE_NOT_BUILT",
    "REASON_RUNTIME_ARCHITECTURE_MISMATCH",
    "REASON_RUNTIME_BINARY_MISMATCH",
    "REASON_RUNTIME_BINARY_MISSING",
    "REASON_RUNTIME_DEP_COUNT_EXCEEDED",
    "REASON_RUNTIME_INSPECTOR_FAILED",
    "REASON_RUNTIME_INSPECTOR_MISSING",
    "REASON_RUNTIME_INSPECTOR_TIMEOUT",
    "REASON_RUNTIME_MALFORMED",
    "REASON_RUNTIME_OUTPUT_EXCEEDED",
    "REASON_RUNTIME_PLATFORM_UNSUPPORTED",
    "REASON_RUNTIME_UNSAFE_PATH",
    "REASON_RUNTIME_UNEXPECTED_DEPENDENCY",
    "REASON_RUNTIME_WHEEL_MEMBER_MISMATCH",
    "REASON_SIDECAR_WRITE_FAILED",
    "REASON_SNAPSHOT_MISSING",
    "REASON_SOURCE_SNAPSHOT_MISMATCH",
    "REASON_SOURCE_UNREADABLE",
    "REASON_WHEEL_INVENTORY_INVALID",
    "REASON_WHEEL_MUTATED",
    "SidecarArtifact",
    "UNAVAILABLE_REASONS",
    "WheelEntryRef",
    "build_cyclonedx_document",
    "build_intoto_provenance_document",
    "canonicalize_registry_source",
    "canonicalize_zip_entry_name",
    "canonical_json_bytes",
    "cleanup_created_sidecars",
    "cleanup_paths",
    "content_uuid_urn",
    "ensure_sidecar_path_contained",
    "hash_regular_file",
    "inventory_wheel_zip",
    "inventory_wheel_zip_bytes",
    "load_wheel_snapshot",
    "parse_wheel_version",
    "pretty_json_bytes",
    "project_relative_logical_path",
    "read_regular_file_bytes",
    "sha256_hex",
    "validate_logical_reference",
    "write_atomic_bytes",
]
