"""Immutable contracts used to describe planned build artifacts."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any, Callable, TypeVar


class ArtifactKind(str, Enum):
    """Artifact classes implemented by the initial host planning layer."""

    HOST_EXTENSION = "host-extension"
    HOST_EXECUTABLE = "host-executable"
    RUST_CRATE = "rust-crate"


class FallbackStrategy(str, Enum):
    """Canonical fallback strategies for a native host executable."""

    ERROR = "error"
    PYTHON_SUBPROCESS = "python-subprocess"
    NUITKA_SIDECAR = "nuitka-sidecar"


class CertificationTier(str, Enum):
    """Evidence level attached to a declared target capability."""

    CERTIFIED = "certified"
    EXPERIMENTAL = "experimental"
    BUILD_ONLY = "build-only"
    UNSUPPORTED = "unsupported"


_T = TypeVar("_T")


def _sorted_unique(values: tuple[_T, ...], *, key: Callable[[_T], Any]) -> tuple[_T, ...]:
    """Return hashable values de-duplicated and sorted by a stable key."""
    return tuple(sorted(set(values), key=key))


def _sorted_strings(values: tuple[str, ...]) -> tuple[str, ...]:
    """Return strings de-duplicated in lexical order."""
    normalized = tuple(value.strip() for value in values)
    if any(not value for value in normalized):
        raise ValueError("canonical string collections must not contain empty values")
    return tuple(sorted(set(normalized)))


def _validate_project_relative_reference(reference: str) -> None:
    """Reject provenance references that disclose a machine-private path."""
    posix = PurePosixPath(reference)
    windows = PureWindowsPath(reference)
    if posix.is_absolute() or windows.is_absolute() or ".." in posix.parts or ".." in windows.parts:
        raise ValueError("artifact provenance source references must be project-relative")


def _reject_conflicting_named_requirements(
    values: tuple[ABIRequirement, ...] | tuple[RuntimeRequirement, ...],
    *,
    label: str,
) -> None:
    """Reject two non-identical requirements with the same logical name."""
    by_name: dict[str, ABIRequirement | RuntimeRequirement] = {}
    for value in values:
        previous = by_name.get(value.name)
        if previous is not None and previous != value:
            raise ValueError(f"conflicting {label} requirements for {value.name!r}")
        by_name[value.name] = value


@dataclass(frozen=True)
class ABIRequirement:
    """One ABI required by a generated artifact."""

    name: str
    version: str | None = None
    features: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Validate and canonicalize the requirement."""
        if not self.name.strip():
            raise ValueError("ABI requirement name must not be empty")
        object.__setattr__(self, "name", self.name.strip())
        if self.version is not None:
            if not self.version.strip():
                raise ValueError("ABI requirement version must not be empty")
            object.__setattr__(self, "version", self.version.strip())
        object.__setattr__(self, "features", _sorted_strings(self.features))

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable representation."""
        return {
            "name": self.name,
            "version": self.version,
            "features": list(self.features),
        }


@dataclass(frozen=True)
class RuntimeRequirement:
    """One runtime required to execute a generated artifact."""

    name: str
    version: str | None = None
    features: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Validate and canonicalize the requirement."""
        if not self.name.strip():
            raise ValueError("runtime requirement name must not be empty")
        object.__setattr__(self, "name", self.name.strip())
        if self.version is not None:
            if not self.version.strip():
                raise ValueError("runtime requirement version must not be empty")
            object.__setattr__(self, "version", self.version.strip())
        object.__setattr__(self, "features", _sorted_strings(self.features))

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable representation."""
        return {
            "name": self.name,
            "version": self.version,
            "features": list(self.features),
        }


@dataclass(frozen=True)
class ArtifactProvenance:
    """Stable references describing how an artifact plan was derived."""

    producer: str = "rextio"
    source_references: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Validate and canonicalize provenance references."""
        if not self.producer.strip():
            raise ValueError("artifact provenance producer must not be empty")
        object.__setattr__(self, "producer", self.producer.strip())
        source_references = _sorted_strings(self.source_references)
        for reference in source_references:
            _validate_project_relative_reference(reference)
        object.__setattr__(self, "source_references", source_references)
        object.__setattr__(self, "evidence", _sorted_strings(self.evidence))

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable representation."""
        return {
            "producer": self.producer,
            "source_references": list(self.source_references),
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class DeviceRequirement:
    """Passive hardware/runtime requirements declared by a domain lowering."""

    logical_device: str
    backend: str | None = None
    runtime: str | None = None
    features: tuple[str, ...] = ()
    layouts: tuple[str, ...] = ()
    memory_spaces: tuple[str, ...] = ()
    architectures: tuple[str, ...] = ()
    reuse_domain_runtime: bool = False

    def __post_init__(self) -> None:
        """Validate and canonicalize the passive requirement."""
        if not self.logical_device.strip():
            raise ValueError("logical device must not be empty")
        object.__setattr__(self, "logical_device", self.logical_device.strip())
        for field_name in ("backend", "runtime"):
            value = getattr(self, field_name)
            if value is not None:
                if not value.strip():
                    raise ValueError(f"device requirement {field_name} must not be empty")
                object.__setattr__(self, field_name, value.strip())
        for field_name in ("features", "layouts", "memory_spaces", "architectures"):
            object.__setattr__(self, field_name, _sorted_strings(getattr(self, field_name)))

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable representation."""
        return {
            "logical_device": self.logical_device,
            "backend": self.backend,
            "runtime": self.runtime,
            "features": list(self.features),
            "layouts": list(self.layouts),
            "memory_spaces": list(self.memory_spaces),
            "architectures": list(self.architectures),
            "reuse_domain_runtime": self.reuse_domain_runtime,
        }


@dataclass(frozen=True)
class TargetCapability:
    """A declared target capability; this record never probes local hardware."""

    id: str
    target_triples: tuple[str, ...] = ()
    artifact_kinds: tuple[ArtifactKind, ...] = ()
    cpu_feature_level: str | None = None
    cpu_features: tuple[str, ...] = ()
    accelerator_backends: tuple[str, ...] = ()
    minimum_runtime_version: str | None = None
    minimum_driver_version: str | None = None
    architectures: tuple[str, ...] = ()
    device_requirements: tuple[DeviceRequirement, ...] = ()
    certification_tier: CertificationTier = CertificationTier.UNSUPPORTED
    evidence_references: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Validate and canonicalize the declaration."""
        if not self.id.strip():
            raise ValueError("target capability id must not be empty")
        object.__setattr__(self, "id", self.id.strip())
        object.__setattr__(
            self,
            "artifact_kinds",
            tuple(ArtifactKind(kind) for kind in self.artifact_kinds),
        )
        object.__setattr__(
            self,
            "certification_tier",
            CertificationTier(self.certification_tier),
        )
        for field_name in (
            "cpu_feature_level",
            "minimum_runtime_version",
            "minimum_driver_version",
        ):
            value = getattr(self, field_name)
            if value is not None:
                if not value.strip():
                    raise ValueError(f"target capability {field_name} must not be empty")
                object.__setattr__(self, field_name, value.strip())
        object.__setattr__(self, "target_triples", _sorted_strings(self.target_triples))
        object.__setattr__(
            self,
            "artifact_kinds",
            _sorted_unique(self.artifact_kinds, key=lambda kind: kind.value),
        )
        object.__setattr__(self, "cpu_features", _sorted_strings(self.cpu_features))
        object.__setattr__(self, "accelerator_backends", _sorted_strings(self.accelerator_backends))
        object.__setattr__(self, "architectures", _sorted_strings(self.architectures))
        object.__setattr__(
            self,
            "device_requirements",
            _sorted_unique(
                self.device_requirements,
                key=lambda requirement: (
                    requirement.logical_device,
                    requirement.backend or "",
                    requirement.runtime or "",
                    requirement.features,
                    requirement.layouts,
                    requirement.memory_spaces,
                    requirement.architectures,
                    requirement.reuse_domain_runtime,
                ),
            ),
        )
        object.__setattr__(self, "evidence_references", _sorted_strings(self.evidence_references))
        if self.certification_tier is not CertificationTier.UNSUPPORTED:
            if not self.target_triples or not self.artifact_kinds:
                raise ValueError(
                    "supported target capability requires target triples and artifact kinds"
                )
            if not self.evidence_references:
                raise ValueError("supported target capability requires evidence references")

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable representation."""
        return {
            "id": self.id,
            "target_triples": list(self.target_triples),
            "artifact_kinds": [kind.value for kind in self.artifact_kinds],
            "cpu_feature_level": self.cpu_feature_level,
            "cpu_features": list(self.cpu_features),
            "accelerator_backends": list(self.accelerator_backends),
            "minimum_runtime_version": self.minimum_runtime_version,
            "minimum_driver_version": self.minimum_driver_version,
            "architectures": list(self.architectures),
            "device_requirements": [item.to_dict() for item in self.device_requirements],
            "certification_tier": self.certification_tier.value,
            "evidence_references": list(self.evidence_references),
        }


@dataclass(frozen=True)
class ArtifactProfile:
    """The resolved requirements and packaging policy for one output artifact."""

    kind: ArtifactKind
    target_triple: str
    packaging_backend: str
    fallback: FallbackStrategy | None = None
    python_fallback_backend: str | None = None
    abi_requirements: tuple[ABIRequirement, ...] = ()
    runtime_requirements: tuple[RuntimeRequirement, ...] = ()
    device_requirements: tuple[DeviceRequirement, ...] = ()
    provenance: ArtifactProvenance = field(default_factory=ArtifactProvenance)

    def __post_init__(self) -> None:
        """Validate cross-field invariants and canonicalize requirement ordering."""
        object.__setattr__(self, "kind", ArtifactKind(self.kind))
        if self.fallback is not None:
            object.__setattr__(self, "fallback", FallbackStrategy(self.fallback))
        if not self.target_triple.strip():
            raise ValueError("artifact target triple must not be empty")
        if not self.packaging_backend.strip():
            raise ValueError("artifact packaging backend must not be empty")
        object.__setattr__(self, "target_triple", self.target_triple.strip())
        object.__setattr__(self, "packaging_backend", self.packaging_backend.strip())
        if self.kind is ArtifactKind.HOST_EXECUTABLE and self.fallback is None:
            raise ValueError("host executable artifact requires an explicit fallback strategy")
        if self.kind is not ArtifactKind.HOST_EXECUTABLE and self.fallback is not None:
            raise ValueError("fallback strategy is only valid for a host executable artifact")
        if self.kind is ArtifactKind.HOST_EXTENSION:
            if self.python_fallback_backend not in {"cpython", "nuitka"}:
                raise ValueError(
                    "host extension artifact requires python fallback backend cpython or nuitka"
                )
        elif self.python_fallback_backend is not None:
            raise ValueError("python fallback backend is only valid for a host extension artifact")
        _reject_conflicting_named_requirements(self.abi_requirements, label="ABI")
        _reject_conflicting_named_requirements(self.runtime_requirements, label="runtime")
        object.__setattr__(
            self,
            "abi_requirements",
            _sorted_unique(
                self.abi_requirements,
                key=lambda requirement: (
                    requirement.name,
                    requirement.version or "",
                    requirement.features,
                ),
            ),
        )
        object.__setattr__(
            self,
            "runtime_requirements",
            _sorted_unique(
                self.runtime_requirements,
                key=lambda requirement: (
                    requirement.name,
                    requirement.version or "",
                    requirement.features,
                ),
            ),
        )
        object.__setattr__(
            self,
            "device_requirements",
            _sorted_unique(
                self.device_requirements,
                key=lambda requirement: (
                    requirement.logical_device,
                    requirement.backend or "",
                    requirement.runtime or "",
                    requirement.features,
                    requirement.layouts,
                    requirement.memory_spaces,
                    requirement.architectures,
                    requirement.reuse_domain_runtime,
                ),
            ),
        )

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable representation."""
        return {
            "kind": self.kind.value,
            "target_triple": self.target_triple,
            "packaging_backend": self.packaging_backend,
            "fallback": self.fallback.value if self.fallback is not None else None,
            "python_fallback_backend": self.python_fallback_backend,
            "abi_requirements": [item.to_dict() for item in self.abi_requirements],
            "runtime_requirements": [item.to_dict() for item in self.runtime_requirements],
            "device_requirements": [item.to_dict() for item in self.device_requirements],
            "provenance": self.provenance.to_dict(),
        }
