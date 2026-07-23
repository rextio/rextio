"""Vendor-neutral Device Provider API 1 contracts.

Device providers are not ordinary Rextio lowering plugins. A domain plugin
owns Python semantics and claim/lower decisions; a device provider owns
hardware/runtime compatibility and declarative native-build contributions.
Provider selection is always explicit and preflight must complete before any
provider contribution can be admitted to a build plan.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath, PureWindowsPath
from typing import Mapping, Protocol, runtime_checkable

from rextio.artifacts.models import (
    ArtifactProfile,
    CertificationTier,
    RuntimeRequirement,
    TargetCapability,
)


# Device-provider compatibility evolves independently from the lowering-plugin
# API. Domain plugins must never infer compatibility from this version alone.
DEVICE_PROVIDER_API_VERSION = "1.0"
DEVICE_PROVIDER_ENTRY_POINT = "rextio.device_providers"

_PROVIDER_ID_PATTERN = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
_OBSERVATION_KEY_PATTERN = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
_MAX_OBSERVATION_KEY_LENGTH = 64
_MAX_OBSERVATION_VALUE_LENGTH = 256
_MAX_DEVICE_PROVIDER_OPTIONS = 64
_MAX_PROVIDER_OPTION_VALUE_LENGTH = 4096
_MAX_SOURCE_IDENTITY_VALUE_LENGTH = 256
_DEVICE_ID_PATTERN = re.compile(
    r"^(?:(?:/)?device:)?(cpu|gpu|tpu|npu|cuda|rocm|mps)(?::([0-9]+))?$",
    re.IGNORECASE,
)
_BUILD_INPUT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}$")
_ENTRY_POINT_VALUE_PATTERN = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_.]*(?::[A-Za-z_][A-Za-z0-9_.]*)?$"
)
_SOURCE_IDENTITY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+!-]{0,255}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


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


def _validate_optional_string(value: str | None, *, label: str) -> str | None:
    """Return one normalized optional string."""
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string when present")
    return value.strip()


def _validate_source_identity_string(value: str, *, label: str) -> str:
    """Return one bounded public identity component, never a file locator."""
    normalized = _validate_optional_string(value, label=label)
    if normalized is None:
        raise ValueError(f"{label} must be a non-empty string")
    if (
        len(normalized) > _MAX_SOURCE_IDENTITY_VALUE_LENGTH
        or _SOURCE_IDENTITY_PATTERN.fullmatch(normalized) is None
        or ".." in normalized
    ):
        raise ValueError(
            f"{label} must be a bounded package/version identity, not a filesystem locator"
        )
    return normalized


def _validate_project_relative_references(
    values: tuple[str, ...], *, label: str
) -> tuple[str, ...]:
    """Canonicalize project-relative, report-safe references."""
    normalized = _canonical_strings(values, label=label)
    for value in normalized:
        if (
            PurePosixPath(value).is_absolute()
            or PureWindowsPath(value).is_absolute()
            or ".." in PurePosixPath(value).parts
            or ".." in PureWindowsPath(value).parts
        ):
            raise ValueError(f"{label} must contain only project-relative references")
    return normalized


def _validate_build_input_ids(values: tuple[str, ...], *, label: str) -> tuple[str, ...]:
    """Canonicalize bounded identifiers safe for generated Cargo/Rust text."""
    normalized = _canonical_strings(values, label=label)
    if any(_BUILD_INPUT_ID_PATTERN.fullmatch(value) is None for value in normalized):
        raise ValueError(f"{label} must contain only bounded build identifiers")
    return normalized


def _canonical_json_sha256(value: object) -> str:
    """Hash one deterministic JSON value."""
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class CanonicalDeviceId:
    """One normalized logical device identity, separate from its backend."""

    kind: str
    index: int = 0
    backend: str | None = None

    def __post_init__(self) -> None:
        """Validate the closed logical-kind vocabulary."""
        kind = self.kind.strip().lower()
        if kind not in {"cpu", "gpu", "tpu", "npu"}:
            raise ValueError(f"unsupported logical device kind: {self.kind!r}")
        if type(self.index) is not int or self.index < 0:
            raise ValueError("device index must be a non-negative integer")
        backend = _validate_optional_string(self.backend, label="device backend")
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "backend", backend.lower() if backend is not None else None)

    @property
    def logical_device(self) -> str:
        """Return the canonical backend-neutral device id."""
        return f"{self.kind}:{self.index}"

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable representation."""
        return {
            "logical_device": self.logical_device,
            "kind": self.kind,
            "index": self.index,
            "backend": self.backend,
        }


def normalize_device_id(value: str, *, backend: str | None = None) -> CanonicalDeviceId:
    """Normalize common framework spellings without guessing a backend.

    ``cuda:N``, ``rocm:N``, and ``mps:N`` identify a GPU backend explicitly.
    Generic ``GPU:N`` and TensorFlow ``/device:GPU:N`` spellings remain
    backend-neutral unless the caller supplies ``backend=``.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError("logical device must be a non-empty string")
    match = _DEVICE_ID_PATTERN.fullmatch(value.strip())
    if match is None:
        raise ValueError(f"unsupported logical device id: {value!r}")
    raw_kind = match.group(1).lower()
    index = int(match.group(2) or "0")
    explicit_backend: str | None = None
    kind = raw_kind
    if raw_kind in {"cuda", "rocm", "mps"}:
        explicit_backend = raw_kind
        kind = "gpu"
    normalized_backend = _validate_optional_string(backend, label="device backend")
    if normalized_backend is not None:
        normalized_backend = normalized_backend.lower()
    if (
        explicit_backend is not None
        and normalized_backend is not None
        and explicit_backend != normalized_backend
    ):
        raise ValueError(
            f"logical device {value!r} conflicts with backend {normalized_backend!r}"
        )
    return CanonicalDeviceId(
        kind=kind,
        index=index,
        backend=explicit_backend or normalized_backend,
    )


@dataclass(frozen=True)
class DeviceValueMetadata:
    """Structured static facts for a domain-plugin value."""

    logical_device: str
    backend: str | None = None
    dtype: str | None = None
    rank: int | None = None
    layout: str | None = None
    runtime_version: str | None = None
    static_shape: tuple[int | None, ...] = ()

    def __post_init__(self) -> None:
        """Canonicalize device identity and validate shape/rank facts."""
        device = normalize_device_id(self.logical_device, backend=self.backend)
        object.__setattr__(self, "logical_device", device.logical_device)
        object.__setattr__(self, "backend", device.backend)
        for field_name in ("dtype", "layout", "runtime_version"):
            object.__setattr__(
                self,
                field_name,
                _validate_optional_string(getattr(self, field_name), label=field_name),
            )
        if self.rank is not None and (type(self.rank) is not int or self.rank < 0):
            raise ValueError("rank must be a non-negative integer when present")
        if not isinstance(self.static_shape, tuple):
            raise ValueError("static_shape must be a tuple")
        if any(
            dimension is not None
            and (type(dimension) is not int or dimension < 0)
            for dimension in self.static_shape
        ):
            raise ValueError("static_shape dimensions must be non-negative integers or None")
        if self.static_shape and self.rank is None:
            raise ValueError("static_shape requires a statically known rank")
        if self.rank is not None and self.static_shape and len(self.static_shape) != self.rank:
            raise ValueError("static_shape length must equal rank")

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable representation."""
        return {
            "logical_device": self.logical_device,
            "backend": self.backend,
            "dtype": self.dtype,
            "rank": self.rank,
            "layout": self.layout,
            "runtime_version": self.runtime_version,
            "static_shape": list(self.static_shape),
        }


class DeviceResourceOwner(str, Enum):
    """Ownership domains recognized by Device Provider API 1."""

    PROVIDER = "provider"
    FRAMEWORK = "framework"


class DeviceResourceAccess(str, Enum):
    """Closed resource access modes."""

    OWNED = "owned"
    BORROW_VALIDATE = "borrow-validate"


@dataclass(frozen=True)
class DeviceResourceContract:
    """One provider-owned resource or fail-closed framework borrow."""

    resource_kind: str
    owner: DeviceResourceOwner
    access: DeviceResourceAccess
    may_allocate: bool = False
    may_replace: bool = False
    may_synchronize: bool = False

    def __post_init__(self) -> None:
        """Enforce the framework/provider ownership boundary."""
        resource_kind = _validate_optional_string(
            self.resource_kind, label="resource_kind"
        )
        if resource_kind is None:  # defensive: helper contract permits None
            raise ValueError("resource_kind must be a non-empty string")
        object.__setattr__(self, "resource_kind", resource_kind)
        object.__setattr__(self, "owner", DeviceResourceOwner(self.owner))
        object.__setattr__(self, "access", DeviceResourceAccess(self.access))
        for field_name in ("may_allocate", "may_replace", "may_synchronize"):
            if type(getattr(self, field_name)) is not bool:
                raise ValueError(f"{field_name} must be a bool")
        if self.owner is DeviceResourceOwner.FRAMEWORK:
            if self.access is not DeviceResourceAccess.BORROW_VALIDATE:
                raise ValueError("framework resources may only be borrowed and validated")
            if self.may_allocate or self.may_replace or self.may_synchronize:
                raise ValueError(
                    "a provider may not allocate, replace, or synchronize a "
                    "framework-owned resource"
                )
        elif self.access is not DeviceResourceAccess.OWNED:
            raise ValueError("provider-owned resources require access='owned'")

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable representation."""
        return {
            "resource_kind": self.resource_kind,
            "owner": self.owner.value,
            "access": self.access.value,
            "may_allocate": self.may_allocate,
            "may_replace": self.may_replace,
            "may_synchronize": self.may_synchronize,
        }


@dataclass(frozen=True)
class DeviceBuildContribution:
    """Declarative E0 build inputs selected after a successful preflight."""

    cargo_features: tuple[str, ...] = ()
    native_libraries: tuple[str, ...] = ()
    package_references: tuple[str, ...] = ()
    generated_helper_ids: tuple[str, ...] = ()
    runtime_check_ids: tuple[str, ...] = ()
    resource_contracts: tuple[DeviceResourceContract, ...] = ()

    def __post_init__(self) -> None:
        """Canonicalize reportable inputs and reject private paths."""
        for field_name in (
            "cargo_features",
            "native_libraries",
            "generated_helper_ids",
            "runtime_check_ids",
        ):
            object.__setattr__(
                self,
                field_name,
                _validate_build_input_ids(getattr(self, field_name), label=field_name),
            )
        object.__setattr__(
            self,
            "package_references",
            _validate_project_relative_references(
                self.package_references, label="package_references"
            ),
        )
        if not isinstance(self.resource_contracts, tuple) or not all(
            isinstance(item, DeviceResourceContract) for item in self.resource_contracts
        ):
            raise ValueError(
                "resource_contracts must be a tuple of DeviceResourceContract records"
            )
        object.__setattr__(
            self,
            "resource_contracts",
            tuple(
                sorted(
                    set(self.resource_contracts),
                    key=lambda item: (
                        item.resource_kind,
                        item.owner.value,
                        item.access.value,
                        item.may_allocate,
                        item.may_replace,
                        item.may_synchronize,
                    ),
                )
            ),
        )

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable representation."""
        return {
            "cargo_features": list(self.cargo_features),
            "native_libraries": list(self.native_libraries),
            "package_references": list(self.package_references),
            "generated_helper_ids": list(self.generated_helper_ids),
            "runtime_check_ids": list(self.runtime_check_ids),
            "resource_contracts": [item.to_dict() for item in self.resource_contracts],
        }


@dataclass(frozen=True)
class DeviceProviderManifest:
    """Passive identity and declared capability data for one API-1 provider."""

    provider_id: str
    display_name: str
    provider_version: str = "0"
    backend: str | None = None
    api_version: str = DEVICE_PROVIDER_API_VERSION
    capabilities: tuple[TargetCapability, ...] = ()
    runtime_requirements: tuple[RuntimeRequirement, ...] = ()

    def __post_init__(self) -> None:
        """Validate and canonicalize the immutable manifest."""
        object.__setattr__(self, "provider_id", _validate_provider_id(self.provider_id))
        if not isinstance(self.display_name, str) or not self.display_name.strip():
            raise ValueError("display_name must be a non-empty string")
        object.__setattr__(self, "display_name", self.display_name.strip())
        provider_version = _validate_optional_string(
            self.provider_version, label="provider_version"
        )
        if provider_version is None:  # defensive: helper contract permits None
            raise ValueError("provider_version must be a non-empty string")
        object.__setattr__(self, "provider_version", provider_version)
        backend = _validate_optional_string(self.backend, label="provider backend")
        object.__setattr__(self, "backend", backend.lower() if backend is not None else None)
        if self.api_version != DEVICE_PROVIDER_API_VERSION:
            raise ValueError(
                "device provider manifests must use the current API version "
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
            "provider_version": self.provider_version,
            "backend": self.backend,
            "api_version": self.api_version,
            "stability": "alpha",
            "capabilities": [item.to_dict() for item in self.capabilities],
            "runtime_requirements": [item.to_dict() for item in self.runtime_requirements],
        }


@dataclass(frozen=True)
class DeviceProviderSelection:
    """Explicit provider/capability selection for one artifact profile."""

    provider_id: str
    capability_id: str

    def __post_init__(self) -> None:
        """Validate stable selection identifiers."""
        object.__setattr__(self, "provider_id", _validate_provider_id(self.provider_id))
        capability_id = _validate_optional_string(
            self.capability_id, label="capability_id"
        )
        if capability_id is None:  # defensive: helper contract permits None
            raise ValueError("capability_id must be a non-empty string")
        object.__setattr__(self, "capability_id", capability_id)

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable representation."""
        return {
            "provider_id": self.provider_id,
            "capability_id": self.capability_id,
        }


@dataclass(frozen=True)
class DeviceProviderOptions:
    """Private explicit provider inputs with a public redacted projection."""

    values: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        """Canonicalize keys while retaining raw values only in memory."""
        if not isinstance(self.values, tuple):
            raise ValueError("device provider options must be a tuple of string pairs")
        if len(self.values) > _MAX_DEVICE_PROVIDER_OPTIONS:
            raise ValueError(
                f"device provider options must contain at most "
                f"{_MAX_DEVICE_PROVIDER_OPTIONS} entries"
            )
        by_key: dict[str, str] = {}
        for pair in self.values:
            if not isinstance(pair, tuple) or len(pair) != 2:
                raise ValueError("device provider options must be a tuple of string pairs")
            key, value = pair
            if (
                not isinstance(key, str)
                or len(key.strip()) > _MAX_OBSERVATION_KEY_LENGTH
                or _OBSERVATION_KEY_PATTERN.fullmatch(key.strip()) is None
            ):
                raise ValueError(
                    "device provider option keys must be bounded lowercase identifiers"
                )
            if (
                not isinstance(value, str)
                or not value
                or len(value) > _MAX_PROVIDER_OPTION_VALUE_LENGTH
                or any(not character.isprintable() for character in value)
            ):
                raise ValueError(
                    "device provider option values must be bounded printable strings"
                )
            normalized_key = key.strip()
            previous = by_key.get(normalized_key)
            if previous is not None and previous != value:
                raise ValueError(
                    f"conflicting device provider option {normalized_key!r}"
                )
            by_key[normalized_key] = value
        object.__setattr__(self, "values", tuple(sorted(by_key.items())))

    @property
    def keys(self) -> tuple[str, ...]:
        """Return option names safe for public reports."""
        return tuple(key for key, _value in self.values)

    @property
    def sha256(self) -> str:
        """Bind exact key/value bytes without exposing values."""
        return _canonical_json_sha256(
            [{"key": key, "value": value} for key, value in self.values]
        )

    def get(self, key: str, default: str | None = None) -> str | None:
        """Return one raw option value to the explicitly selected provider."""
        return dict(self.values).get(key, default)

    def public_dict(self) -> dict[str, object]:
        """Return a redacted deterministic projection."""
        return {
            "option_keys": list(self.keys),
            "options_sha256": self.sha256,
        }


@dataclass(frozen=True)
class DevicePreflightRequest:
    """One side-effect-free compatibility request for an artifact profile."""

    artifact_profile: ArtifactProfile
    selection: DeviceProviderSelection
    options: DeviceProviderOptions = DeviceProviderOptions()

    def __post_init__(self) -> None:
        """Reject malformed requests before a provider can inspect them."""
        if not isinstance(self.artifact_profile, ArtifactProfile):
            raise ValueError("artifact_profile must be an ArtifactProfile")
        if not isinstance(self.selection, DeviceProviderSelection):
            raise ValueError("selection must be a DeviceProviderSelection")
        if not isinstance(self.options, DeviceProviderOptions):
            raise ValueError("options must be DeviceProviderOptions")

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable representation."""
        return {
            "artifact_profile": self.artifact_profile.to_dict(),
            "selection": self.selection.to_dict(),
            "options": self.options.public_dict(),
        }


class DevicePreflightStatus(str, Enum):
    """Closed outcomes for the fail-closed API-1 preflight."""

    READY = "ready"
    UNAVAILABLE = "unavailable"
    INCOMPATIBLE = "incompatible"
    ERROR = "error"


@dataclass(frozen=True)
class DevicePreflightResult:
    """Bounded provider observations; never certification by themselves."""

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
            raise ValueError("device preflight results must have support_claim=False")
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
    """Structural Device Provider API 1 surface."""

    def manifest(self) -> DeviceProviderManifest:
        """Return passive provider identity and declared capability data."""
        ...

    def preflight(self, request: DevicePreflightRequest) -> DevicePreflightResult:
        """Inspect compatibility before native side effects or build mutation."""
        ...

    def build_contribution(
        self, request: DevicePreflightRequest
    ) -> DeviceBuildContribution:
        """Return declarative build inputs after a successful preflight."""
        ...


@dataclass(frozen=True)
class DeviceProviderSource:
    """Installed entry-point distribution identity used by one resolution."""

    entry_point_group: str
    entry_point_name: str
    entry_point_value: str
    distribution_name: str
    distribution_version: str

    def __post_init__(self) -> None:
        """Validate stable public package metadata, never filesystem locators."""
        if self.entry_point_group != DEVICE_PROVIDER_ENTRY_POINT:
            raise ValueError(
                f"device provider entry-point group must be {DEVICE_PROVIDER_ENTRY_POINT!r}"
            )
        object.__setattr__(
            self,
            "entry_point_name",
            _validate_provider_id(self.entry_point_name),
        )
        entry_point_value = _validate_optional_string(
            self.entry_point_value,
            label="entry_point_value",
        )
        if (
            entry_point_value is None
            or len(entry_point_value) > _MAX_SOURCE_IDENTITY_VALUE_LENGTH
            or _ENTRY_POINT_VALUE_PATTERN.fullmatch(entry_point_value) is None
        ):
            raise ValueError(
                "entry_point_value must be a module or module:attribute import target"
            )
        object.__setattr__(self, "entry_point_value", entry_point_value)
        for field_name in ("distribution_name", "distribution_version"):
            value = _validate_source_identity_string(
                getattr(self, field_name),
                label=field_name,
            )
            object.__setattr__(
                self,
                field_name,
                value,
            )

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable representation."""
        return {
            "entry_point_group": self.entry_point_group,
            "entry_point_name": self.entry_point_name,
            "entry_point_value": self.entry_point_value,
            "distribution_name": self.distribution_name,
            "distribution_version": self.distribution_version,
        }


@dataclass(frozen=True)
class DeviceProviderLock:
    """Exact provider decision suitable for a source/build lock."""

    provider_id: str
    provider_version: str
    api_version: str
    backend: str | None
    capability_id: str
    target_triple: str
    manifest_sha256: str
    artifact_profile_sha256: str
    contribution_sha256: str
    source_identity_sha256: str | None = None
    option_keys: tuple[str, ...] = ()
    options_sha256: str = _canonical_json_sha256([])

    def __post_init__(self) -> None:
        """Validate every lock digest and stable identity field."""
        object.__setattr__(self, "provider_id", _validate_provider_id(self.provider_id))
        for field_name in (
            "provider_version",
            "api_version",
            "capability_id",
            "target_triple",
        ):
            value = _validate_optional_string(getattr(self, field_name), label=field_name)
            if value is None:
                raise ValueError(f"{field_name} must be a non-empty string")
            object.__setattr__(self, field_name, value)
        object.__setattr__(
            self,
            "backend",
            _validate_optional_string(self.backend, label="backend"),
        )
        for field_name in (
            "manifest_sha256",
            "artifact_profile_sha256",
            "contribution_sha256",
        ):
            digest = getattr(self, field_name)
            if not isinstance(digest, str) or _SHA256_PATTERN.fullmatch(digest) is None:
                raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")
        if self.source_identity_sha256 is not None and (
            not isinstance(self.source_identity_sha256, str)
            or _SHA256_PATTERN.fullmatch(self.source_identity_sha256) is None
        ):
            raise ValueError("source_identity_sha256 must be a lowercase SHA-256 digest")
        object.__setattr__(
            self,
            "option_keys",
            _canonical_strings(self.option_keys, label="option_keys"),
        )
        if _SHA256_PATTERN.fullmatch(self.options_sha256) is None:
            raise ValueError("options_sha256 must be a lowercase SHA-256 digest")

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable representation."""
        return {
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "api_version": self.api_version,
            "backend": self.backend,
            "capability_id": self.capability_id,
            "target_triple": self.target_triple,
            "manifest_sha256": self.manifest_sha256,
            "artifact_profile_sha256": self.artifact_profile_sha256,
            "contribution_sha256": self.contribution_sha256,
            "source_identity_sha256": self.source_identity_sha256,
            "option_keys": list(self.option_keys),
            "options_sha256": self.options_sha256,
        }


@dataclass(frozen=True)
class DeviceProviderReport:
    """Public report projection for one resolved provider plan."""

    lock: DeviceProviderLock
    certification_tier: CertificationTier
    status: DevicePreflightStatus
    reason_codes: tuple[str, ...]
    observations: tuple[tuple[str, str], ...]
    evidence_references: tuple[str, ...]
    support_claim: bool = False

    def __post_init__(self) -> None:
        """Keep preflight/report evidence distinct from a support claim."""
        object.__setattr__(
            self, "certification_tier", CertificationTier(self.certification_tier)
        )
        object.__setattr__(self, "status", DevicePreflightStatus(self.status))
        object.__setattr__(
            self,
            "reason_codes",
            _canonical_strings(self.reason_codes, label="reason_codes"),
        )
        object.__setattr__(self, "observations", _canonical_observations(self.observations))
        object.__setattr__(
            self,
            "evidence_references",
            _validate_project_relative_references(
                self.evidence_references, label="evidence_references"
            ),
        )
        if type(self.support_claim) is not bool or self.support_claim:
            raise ValueError("an E0 device provider report must have support_claim=False")

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable representation."""
        return {
            "lock": self.lock.to_dict(),
            "certification_tier": self.certification_tier.value,
            "status": self.status.value,
            "reason_codes": list(self.reason_codes),
            "observations": [
                {"key": key, "value": value} for key, value in self.observations
            ],
            "evidence_references": list(self.evidence_references),
            "support_claim": False,
        }


@dataclass(frozen=True)
class ResolvedDevicePlan:
    """One deterministic provider decision for an artifact profile."""

    selection: DeviceProviderSelection
    artifact_profile: ArtifactProfile
    manifest: DeviceProviderManifest
    capability: TargetCapability
    preflight: DevicePreflightResult
    contribution: DeviceBuildContribution
    source: DeviceProviderSource | None = None
    options: DeviceProviderOptions = DeviceProviderOptions()

    def lock_record(self) -> DeviceProviderLock:
        """Project the exact provider/capability decision into a lock."""
        return DeviceProviderLock(
            provider_id=self.manifest.provider_id,
            provider_version=self.manifest.provider_version,
            api_version=self.manifest.api_version,
            backend=self.manifest.backend,
            capability_id=self.capability.id,
            target_triple=self.artifact_profile.target_triple,
            manifest_sha256=_canonical_json_sha256(self.manifest.to_dict()),
            artifact_profile_sha256=_canonical_json_sha256(
                self.artifact_profile.to_dict()
            ),
            contribution_sha256=_canonical_json_sha256(
                self.contribution.to_dict()
            ),
            source_identity_sha256=(
                _canonical_json_sha256(self.source.to_dict())
                if self.source is not None
                else None
            ),
            option_keys=self.options.keys,
            options_sha256=self.options.sha256,
        )

    def report_record(self) -> DeviceProviderReport:
        """Project bounded preflight/certification evidence into a report."""
        return DeviceProviderReport(
            lock=self.lock_record(),
            certification_tier=self.capability.certification_tier,
            status=self.preflight.status,
            reason_codes=self.preflight.reason_codes,
            observations=self.preflight.observations,
            evidence_references=self.capability.evidence_references,
        )

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable representation."""
        return {
            "selection": self.selection.to_dict(),
            "artifact_profile": self.artifact_profile.to_dict(),
            "manifest": self.manifest.to_dict(),
            "capability": self.capability.to_dict(),
            "preflight": self.preflight.to_dict(),
            "contribution": self.contribution.to_dict(),
            "source": self.source.to_dict() if self.source is not None else None,
            "options": self.options.public_dict(),
            "lock": self.lock_record().to_dict(),
            "report": self.report_record().to_dict(),
        }


class DeviceProviderError(RuntimeError):
    """Raised when an explicit device-provider resolution fails closed."""


def _profile_requires_provider(profile: ArtifactProfile) -> bool:
    """Whether an artifact profile requests a non-CPU device/backend."""
    for requirement in profile.device_requirements:
        if requirement.backend is not None and requirement.backend.lower() != "cpu":
            return True
        try:
            if (
                normalize_device_id(
                    requirement.logical_device,
                    backend=requirement.backend,
                ).kind
                != "cpu"
            ):
                return True
        except ValueError:
            # Unknown device spellings cannot be treated as implicit CPU.
            return True
    return False


def _capability_matches_profile(
    capability: TargetCapability, profile: ArtifactProfile
) -> bool:
    """Check the bounded E0 target/backend/architecture compatibility surface."""
    if (
        capability.target_triples
        and profile.target_triple not in capability.target_triples
    ):
        return False
    if capability.artifact_kinds and profile.kind not in capability.artifact_kinds:
        return False
    for requirement in profile.device_requirements:
        try:
            device = normalize_device_id(
                requirement.logical_device,
                backend=requirement.backend,
            )
        except ValueError:
            return False
        backend = device.backend
        if device.kind != "cpu" and (
            backend is None or backend not in capability.accelerator_backends
        ):
            return False
        if (
            requirement.architectures
            and not set(requirement.architectures).issubset(capability.architectures)
        ):
            return False
    return True


def resolve_device_plan(
    *,
    artifact_profile: ArtifactProfile,
    selection: DeviceProviderSelection | None,
    providers: Mapping[str, DeviceProvider],
    provider_sources: Mapping[str, DeviceProviderSource] | None = None,
    options: DeviceProviderOptions | None = None,
) -> ResolvedDevicePlan | None:
    """Resolve exactly one explicitly selected provider and preflight it.

    Installed-but-unselected providers are never inspected. No selection keeps
    legacy CPU-only profiles unchanged, while an accelerator requirement with
    no selection fails closed.
    """
    if not isinstance(artifact_profile, ArtifactProfile):
        raise DeviceProviderError("artifact_profile must be an ArtifactProfile")
    if selection is None:
        if options is not None and options.values:
            raise DeviceProviderError(
                "device provider options require an explicit provider selection"
            )
        if _profile_requires_provider(artifact_profile):
            raise DeviceProviderError(
                "artifact profile requires an explicit device provider selection"
            )
        return None
    provider = providers.get(selection.provider_id)
    if provider is None:
        raise DeviceProviderError(
            f"selected device provider {selection.provider_id!r} is not available"
        )
    if not isinstance(provider, DeviceProvider):
        raise DeviceProviderError(
            f"selected object {selection.provider_id!r} does not implement "
            "Device Provider API 1"
        )
    try:
        manifest = provider.manifest()
    except Exception as exc:
        raise DeviceProviderError(
            f"selected device provider {selection.provider_id!r} manifest stage failed"
        ) from exc
    if not isinstance(manifest, DeviceProviderManifest):
        raise DeviceProviderError("device provider manifest() returned an invalid record")
    if manifest.provider_id != selection.provider_id:
        raise DeviceProviderError(
            "selected device provider id does not match its manifest identity"
        )
    matches = tuple(
        capability
        for capability in manifest.capabilities
        if capability.id == selection.capability_id
    )
    if len(matches) != 1:
        raise DeviceProviderError(
            f"device provider {selection.provider_id!r} does not declare capability "
            f"{selection.capability_id!r}"
        )
    capability = matches[0]
    if capability.certification_tier is CertificationTier.UNSUPPORTED:
        raise DeviceProviderError(
            f"device capability {selection.capability_id!r} is explicitly unsupported"
        )
    requested_backends: set[str] = set()
    try:
        for requirement in artifact_profile.device_requirements:
            device = normalize_device_id(
                requirement.logical_device,
                backend=requirement.backend,
            )
            if device.kind != "cpu" and device.backend is not None:
                requested_backends.add(device.backend)
    except ValueError as exc:
        raise DeviceProviderError(f"invalid artifact device requirement: {exc}") from exc
    if manifest.backend is not None and not requested_backends:
        raise DeviceProviderError(
            f"accelerator device provider {selection.provider_id!r} requires a "
            "matching typed non-CPU artifact device requirement"
        )
    if (
        manifest.backend is not None
        and requested_backends
        and requested_backends != {manifest.backend}
    ):
        raise DeviceProviderError(
            f"device provider {selection.provider_id!r} backend "
            f"{manifest.backend!r} does not match artifact requirements"
        )
    if (
        manifest.backend is not None
        and capability.accelerator_backends
        and set(capability.accelerator_backends) != {manifest.backend}
    ):
        raise DeviceProviderError(
            f"device capability {selection.capability_id!r} backend declaration "
            "does not match its provider manifest"
        )
    if requested_backends and manifest.backend is None:
        raise DeviceProviderError(
            f"device provider {selection.provider_id!r} must declare the required backend"
        )
    if not _capability_matches_profile(capability, artifact_profile):
        raise DeviceProviderError(
            f"device capability {selection.capability_id!r} is incompatible with "
            f"{artifact_profile.kind.value} for {artifact_profile.target_triple}"
        )
    resolved_options = options or DeviceProviderOptions()
    request = DevicePreflightRequest(
        artifact_profile=artifact_profile,
        selection=selection,
        options=resolved_options,
    )
    try:
        preflight = provider.preflight(request)
    except Exception as exc:
        raise DeviceProviderError(
            f"selected device provider {selection.provider_id!r} preflight stage failed"
        ) from exc
    if not isinstance(preflight, DevicePreflightResult):
        raise DeviceProviderError("device provider preflight() returned an invalid record")
    if preflight.provider_id != selection.provider_id:
        raise DeviceProviderError(
            "device provider preflight result does not match the selected provider"
        )
    if preflight.status is not DevicePreflightStatus.READY:
        raise DeviceProviderError(
            f"selected device provider {selection.provider_id!r} failed preflight "
            f"with status {preflight.status.value!r}"
        )
    try:
        contribution = provider.build_contribution(request)
    except Exception as exc:
        raise DeviceProviderError(
            f"selected device provider {selection.provider_id!r} "
            "build-contribution stage failed"
        ) from exc
    if not isinstance(contribution, DeviceBuildContribution):
        raise DeviceProviderError(
            "device provider build_contribution() returned an invalid record"
        )
    return ResolvedDevicePlan(
        selection=selection,
        artifact_profile=artifact_profile,
        manifest=manifest,
        capability=capability,
        preflight=preflight,
        contribution=contribution,
        source=(provider_sources or {}).get(selection.provider_id),
        options=resolved_options,
    )
