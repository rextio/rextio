"""Behavior-neutral draft contracts for future device providers.

Device providers are not ordinary Rextio lowering plugins.  A domain plugin
owns Python semantics and claim/lower decisions; a future device provider will
own hardware and runtime compatibility.  This module intentionally contains no
discovery, resolution, entry-point, build, or link integration.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath, PureWindowsPath
from typing import Protocol, runtime_checkable

from rextio.artifacts.models import ArtifactProfile, RuntimeRequirement, TargetCapability


# This is a design draft, not a stable provider API 1.0 compatibility promise.
DEVICE_PROVIDER_API_VERSION = "0.1-draft"

_PROVIDER_ID_PATTERN = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
_OBSERVATION_KEY_PATTERN = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
_MAX_OBSERVATION_KEY_LENGTH = 64
_MAX_OBSERVATION_VALUE_LENGTH = 256


def _canonical_strings(values: tuple[str, ...], *, label: str) -> tuple[str, ...]:
    """Validate an immutable string tuple and return stable lexical order."""
    if not isinstance(values, tuple):
        raise ValueError(f"{label} must be a tuple of strings")
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{label} must contain only non-empty strings")
        normalized.append(value.strip())
    return tuple(sorted(set(normalized)))


def _canonical_observations(
    values: tuple[tuple[str, str], ...],
) -> tuple[tuple[str, str], ...]:
    """Validate bounded report-safe facts and canonicalize them by key.

    This generic draft gate rejects control characters and obvious absolute
    paths.  Providers still own semantic redaction: arbitrary strings cannot be
    proven secret-free without a future typed observation vocabulary.
    """
    if not isinstance(values, tuple):
        raise ValueError("observations must be a tuple of string pairs")
    by_key: dict[str, str] = {}
    for value in values:
        if not isinstance(value, tuple) or len(value) != 2:
            raise ValueError("observations must be a tuple of string pairs")
        key, item = value
        if not isinstance(key, str) or not key.strip():
            raise ValueError("observation keys must be non-empty strings")
        if not isinstance(item, str) or not item.strip():
            raise ValueError("observation values must be non-empty strings")
        normalized_key = key.strip()
        normalized_item = item.strip()
        if (
            len(normalized_key) > _MAX_OBSERVATION_KEY_LENGTH
            or _OBSERVATION_KEY_PATTERN.fullmatch(normalized_key) is None
        ):
            raise ValueError("observation keys must be bounded lowercase identifiers")
        if len(normalized_item) > _MAX_OBSERVATION_VALUE_LENGTH or any(
            not character.isprintable() for character in normalized_item
        ):
            raise ValueError("observation values must be bounded and contain no control characters")
        if PurePosixPath(normalized_item).is_absolute() or PureWindowsPath(
            normalized_item
        ).is_absolute():
            raise ValueError("observation values must not contain absolute paths")
        previous = by_key.get(normalized_key)
        if previous is not None and previous != normalized_item:
            raise ValueError(f"conflicting observations for {normalized_key!r}")
        by_key[normalized_key] = normalized_item
    return tuple(sorted(by_key.items()))


def _validate_provider_id(provider_id: str) -> str:
    """Return a normalized provider id or reject an unstable identifier."""
    if not isinstance(provider_id, str):
        raise ValueError("provider_id must be a string")
    normalized = provider_id.strip()
    if _PROVIDER_ID_PATTERN.fullmatch(normalized) is None:
        raise ValueError(
            "provider_id must use lowercase ASCII letters, digits, dots, hyphens, or underscores"
        )
    return normalized


@dataclass(frozen=True)
class DeviceProviderManifest:
    """Passive identity and declared capability data for one draft provider."""

    provider_id: str
    display_name: str
    api_version: str = DEVICE_PROVIDER_API_VERSION
    capabilities: tuple[TargetCapability, ...] = ()
    runtime_requirements: tuple[RuntimeRequirement, ...] = ()

    def __post_init__(self) -> None:
        """Validate and canonicalize the immutable manifest."""
        object.__setattr__(self, "provider_id", _validate_provider_id(self.provider_id))
        if not isinstance(self.display_name, str) or not self.display_name.strip():
            raise ValueError("display_name must be a non-empty string")
        object.__setattr__(self, "display_name", self.display_name.strip())
        if self.api_version != DEVICE_PROVIDER_API_VERSION:
            raise ValueError(
                "device provider manifests must use the current draft API version "
                f"{DEVICE_PROVIDER_API_VERSION!r}"
            )
        if not isinstance(self.capabilities, tuple) or not all(
            isinstance(item, TargetCapability) for item in self.capabilities
        ):
            raise ValueError("capabilities must be a tuple of TargetCapability records")
        if not isinstance(self.runtime_requirements, tuple) or not all(
            isinstance(item, RuntimeRequirement) for item in self.runtime_requirements
        ):
            raise ValueError("runtime_requirements must be a tuple of RuntimeRequirement records")

        capabilities_by_id: dict[str, TargetCapability] = {}
        for capability in self.capabilities:
            previous = capabilities_by_id.get(capability.id)
            if previous is not None and previous != capability:
                raise ValueError(f"conflicting provider capabilities for {capability.id!r}")
            capabilities_by_id[capability.id] = capability
        object.__setattr__(
            self,
            "capabilities",
            tuple(capabilities_by_id[key] for key in sorted(capabilities_by_id)),
        )

        requirements_by_name: dict[str, RuntimeRequirement] = {}
        for requirement in self.runtime_requirements:
            previous_requirement = requirements_by_name.get(requirement.name)
            if previous_requirement is not None and previous_requirement != requirement:
                raise ValueError(
                    f"conflicting provider runtime requirements for {requirement.name!r}"
                )
            requirements_by_name[requirement.name] = requirement
        object.__setattr__(
            self,
            "runtime_requirements",
            tuple(requirements_by_name[key] for key in sorted(requirements_by_name)),
        )

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable representation."""
        return {
            "provider_id": self.provider_id,
            "display_name": self.display_name,
            "api_version": self.api_version,
            "stability": "draft-experimental",
            "capabilities": [item.to_dict() for item in self.capabilities],
            "runtime_requirements": [item.to_dict() for item in self.runtime_requirements],
        }


@dataclass(frozen=True)
class DevicePreflightRequest:
    """One side-effect-free compatibility request for an artifact profile."""

    artifact_profile: ArtifactProfile

    def __post_init__(self) -> None:
        """Reject malformed requests before a provider can inspect them."""
        if not isinstance(self.artifact_profile, ArtifactProfile):
            raise ValueError("artifact_profile must be an ArtifactProfile")

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable representation."""
        return {"artifact_profile": self.artifact_profile.to_dict()}


class DevicePreflightStatus(str, Enum):
    """Closed outcomes for the behavior-neutral draft preflight."""

    READY = "ready"
    UNAVAILABLE = "unavailable"
    INCOMPATIBLE = "incompatible"
    ERROR = "error"


@dataclass(frozen=True)
class DevicePreflightResult:
    """Bounded provider observations; never certification or a support claim."""

    provider_id: str
    status: DevicePreflightStatus
    reason_codes: tuple[str, ...] = ()
    observations: tuple[tuple[str, str], ...] = ()
    support_claim: bool = False

    def __post_init__(self) -> None:
        """Validate and canonicalize the immutable preflight result."""
        object.__setattr__(self, "provider_id", _validate_provider_id(self.provider_id))
        object.__setattr__(self, "status", DevicePreflightStatus(self.status))
        object.__setattr__(
            self,
            "reason_codes",
            _canonical_strings(self.reason_codes, label="reason_codes"),
        )
        object.__setattr__(self, "observations", _canonical_observations(self.observations))
        if type(self.support_claim) is not bool or self.support_claim:
            raise ValueError("draft device preflight results must have support_claim=False")
        if self.status is not DevicePreflightStatus.READY and not self.reason_codes:
            raise ValueError("a non-ready preflight result requires at least one reason code")

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable representation."""
        return {
            "provider_id": self.provider_id,
            "status": self.status.value,
            "reason_codes": list(self.reason_codes),
            "observations": [{"key": key, "value": value} for key, value in self.observations],
            "support_claim": False,
        }


@runtime_checkable
class DeviceProvider(Protocol):
    """Structural draft provider surface with no build integration hooks."""

    def manifest(self) -> DeviceProviderManifest:
        """Return passive provider identity and declared capability data."""
        ...

    def preflight(self, request: DevicePreflightRequest) -> DevicePreflightResult:
        """Inspect compatibility without claiming Python syntax or mutating a build."""
        ...
