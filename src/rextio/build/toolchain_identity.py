"""Canonical, non-authorizing build-toolchain identities for bounded Full C6.

The models in this module bind exact executable/component bytes, reported
versions, a fixed allowlist of environment variables, and registry package
checksums from one securely-read Cargo.lock.  They are foundation receipts;
they do not execute tools, prove the truth of a version string, or authorize
distribution on their own.
"""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping
from urllib.parse import urlsplit

from rextio.build.input_closure import (
    BuildInputIdentityError,
    ExactFileIdentity,
    InputFileSpec,
    capture_build_input_closure,
    capture_exact_file,
    capture_exact_file_bytes,
)
from rextio.build.strict_cargo import STRICT_CARGO_FLAGS


MAX_TOOLCHAIN_STRING_CHARS = 512
MAX_TOOLCHAIN_ENV_VALUE_BYTES = 64 * 1024
MAX_CARGO_SOURCE_PACKAGES = 1024
MAX_TOOLCHAIN_ARGV_ITEMS = 256
BUILD_TOOLCHAIN_IDENTITY_DOMAIN = "rextio.build-toolchain-identity.v1"
BUILD_TOOLCHAIN_IDENTITY_SCOPE = (
    "host-extension-wheel-cpython-external-source-depth1-plugin-free-v1"
)
_TOOL_NAMES = frozenset({"python", "cargo", "rustc", "linker", "otool", "readelf"})
_INSPECTOR_NAMES = frozenset({"otool", "readelf"})
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:-]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

# Only these values may influence a future strict subprocess environment.  The
# receipt stores hashes rather than raw values so paths and credentials cannot
# leak through reports.  Integration must also run with inherit_env=False;
# filtering a receipt without filtering execution would not be a closure.
STRICT_BUILD_ENV_ALLOWLIST = frozenset(
    {
        "AR",
        "CARGO_BUILD_TARGET",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_HOME",
        "CARGO_NET_OFFLINE",
        "CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER",
        "CARGO_TARGET_DIR",
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER",
        "CC",
        "CFLAGS",
        "COMPILER_PATH",
        "CXX",
        "CXXFLAGS",
        "DEVELOPER_DIR",
        "LANG",
        "LC_ALL",
        "LD",
        "LD_LIBRARY_PATH",
        "LDFLAGS",
        "LIBRARY_PATH",
        "MACOSX_DEPLOYMENT_TARGET",
        "PATH",
        "PKG_CONFIG_PATH",
        "PYO3_PYTHON",
        "PYTHONHASHSEED",
        "RANLIB",
        "RUSTC",
        "RUSTFLAGS",
        "RUSTUP_HOME",
        "RUSTUP_TOOLCHAIN",
        "SDKROOT",
        "SOURCE_DATE_EPOCH",
        "TZ",
    }
)


class ToolchainIdentityError(RuntimeError):
    """A strict toolchain identity is malformed, incomplete, or stale."""


@dataclass(frozen=True, slots=True)
class ToolIdentity:
    """Exact executable bytes plus one bounded caller-observed version string."""

    name: str
    executable: ExactFileIdentity
    reported_version: str

    def __post_init__(self) -> None:
        if self.name not in _TOOL_NAMES:
            raise ValueError("toolchain tool name is not supported")
        if type(self.executable) is not ExactFileIdentity:
            raise TypeError("toolchain executable identity has an invalid type")
        if not self.executable.executable or self.executable.role != "toolchain-executable":
            raise ValueError("toolchain executable identity is not executable")
        _validate_bounded_text(self.reported_version, "toolchain reported version")

    def to_dict(self) -> dict[str, object]:
        """Return the canonical tool identity without a machine-local path."""
        return {
            "name": self.name,
            "reported_version": self.reported_version,
            "executable": self.executable.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class EnvironmentVariableIdentity:
    """Digest-only identity for one allowlisted environment value."""

    name: str
    value_sha256: str
    value_size: int

    def __post_init__(self) -> None:
        if self.name not in STRICT_BUILD_ENV_ALLOWLIST:
            raise ValueError("environment variable is not in the strict allowlist")
        if _SHA256_RE.fullmatch(self.value_sha256) is None:
            raise ValueError("environment value SHA-256 is invalid")
        if type(self.value_size) is not int or isinstance(self.value_size, bool):
            raise TypeError("environment value size must be an integer")
        if self.value_size < 0 or self.value_size > MAX_TOOLCHAIN_ENV_VALUE_BYTES:
            raise ValueError("environment value exceeds the byte bound")

    def to_dict(self) -> dict[str, object]:
        """Return the digest-only environment binding."""
        return {
            "name": self.name,
            "value_sha256": self.value_sha256,
            "value_size": self.value_size,
        }


@dataclass(frozen=True, slots=True)
class CargoSourceIdentity:
    """One exact registry package selected by Cargo.lock."""

    name: str
    version: str
    source: str
    checksum: str

    def __post_init__(self) -> None:
        if _NAME_RE.fullmatch(self.name) is None or _VERSION_RE.fullmatch(self.version) is None:
            raise ValueError("Cargo source package identity is invalid")
        _validate_registry_source(self.source)
        if _SHA256_RE.fullmatch(self.checksum) is None:
            raise ValueError("Cargo source checksum is invalid")

    def to_dict(self) -> dict[str, str]:
        """Return the exact registry source selection."""
        return {
            "name": self.name,
            "version": self.version,
            "source": self.source,
            "checksum": self.checksum,
        }


@dataclass(frozen=True, slots=True)
class CargoSourcesIdentity:
    """Complete registry-source selection for one exact Cargo.lock."""

    root_package: str
    lock_file: ExactFileIdentity
    packages: tuple[CargoSourceIdentity, ...]
    complete_for_scope: bool = True

    def __post_init__(self) -> None:
        if _NAME_RE.fullmatch(self.root_package) is None:
            raise ValueError("Cargo root package identity is invalid")
        if type(self.lock_file) is not ExactFileIdentity or self.lock_file.role != "cargo-lockfile":
            raise TypeError("Cargo lockfile identity is invalid")
        packages = tuple(self.packages)
        if len(packages) > MAX_CARGO_SOURCE_PACKAGES:
            raise ValueError("Cargo source package count exceeds the bound")
        if not all(type(item) is CargoSourceIdentity for item in packages):
            raise TypeError("Cargo source package identity has an invalid type")
        canonical = tuple(
            sorted(packages, key=lambda item: (item.name, item.version, item.source, item.checksum))
        )
        if packages != canonical or len(set(packages)) != len(packages):
            raise ValueError("Cargo source identities are not unique canonical records")
        if self.complete_for_scope is not True:
            raise ValueError("Cargo source identity must be complete for its scope")
        object.__setattr__(self, "packages", packages)

    @property
    def digest(self) -> str:
        """Return the semantic digest of the complete Cargo source receipt."""
        return hashlib.sha256(_canonical_json(self._payload())).hexdigest()

    def _payload(self) -> dict[str, object]:
        return {
            "root_package": self.root_package,
            "lock_file": self.lock_file.to_dict(),
            "packages": [item.to_dict() for item in self.packages],
            "complete_for_scope": True,
        }

    def to_dict(self) -> dict[str, object]:
        """Return the Cargo source receipt with its semantic digest."""
        return {**self._payload(), "digest": self.digest}


@dataclass(frozen=True, slots=True)
class RextioIdentity:
    """Exact Rextio Python-source component used by the build process."""

    version: str
    files: tuple[ExactFileIdentity, ...]
    content_digest: str
    name: str = "rextio"

    def __post_init__(self) -> None:
        if self.name != "rextio" or _VERSION_RE.fullmatch(self.version) is None:
            raise ValueError("Rextio component identity is invalid")
        files = tuple(self.files)
        if not files or not all(type(item) is ExactFileIdentity for item in files):
            raise TypeError("Rextio component files are invalid")
        canonical = tuple(sorted(files, key=lambda item: (item.role, item.logical_name)))
        if files != canonical or any(item.role != "rextio-python-source" for item in files):
            raise ValueError("Rextio component files are not canonical source identities")
        if _SHA256_RE.fullmatch(self.content_digest) is None:
            raise ValueError("Rextio content digest is invalid")
        object.__setattr__(self, "files", files)

    def to_dict(self) -> dict[str, object]:
        """Return the exact Rextio component identity."""
        return {
            "name": "rextio",
            "version": self.version,
            "content_digest": self.content_digest,
            "files": [item.to_dict() for item in self.files],
        }


@dataclass(frozen=True, slots=True)
class ArgvIdentity:
    """Exact canonical argument vector used for the strict Cargo invocation."""

    values: tuple[str, ...]

    def __post_init__(self) -> None:
        values = tuple(self.values)
        if len(values) < 2 or len(values) > MAX_TOOLCHAIN_ARGV_ITEMS:
            raise ValueError("toolchain argv count is outside the allowed range")
        if not all(type(item) is str for item in values):
            raise TypeError("toolchain argv values must be strings")
        if any(
            not item
            or len(item) > MAX_TOOLCHAIN_STRING_CHARS
            or "\0" in item
            or any(ord(character) < 32 for character in item)
            for item in values
        ):
            raise ValueError("toolchain argv value is invalid")
        separator = values.index("--") if "--" in values else len(values)
        leading = values[:separator]
        if any(leading.count(flag) != 1 for flag in STRICT_CARGO_FLAGS):
            raise ValueError("toolchain argv is missing canonical strict Cargo flags")
        object.__setattr__(self, "values", values)

    @property
    def digest(self) -> str:
        """Return the canonical argument-vector digest."""
        return hashlib.sha256(_canonical_json(list(self.values))).hexdigest()

    def to_dict(self) -> dict[str, object]:
        """Return the exact argument vector and its digest."""
        return {"values": list(self.values), "digest": self.digest}


@dataclass(frozen=True, slots=True)
class BuildToolchainIdentity:
    """Closed receipt for every toolchain input in the bounded strict scope."""

    python: ToolIdentity
    rextio: RextioIdentity
    cargo: ToolIdentity
    rustc: ToolIdentity
    linker: ToolIdentity
    inspectors: tuple[ToolIdentity, ...]
    argv: ArgvIdentity
    environment: tuple[EnvironmentVariableIdentity, ...]
    cargo_sources: CargoSourcesIdentity
    support_plan_sha256: str
    support_lock_raw_sha256: str
    support_lock_merkle_sha256: str
    domain: str = BUILD_TOOLCHAIN_IDENTITY_DOMAIN
    scope: str = BUILD_TOOLCHAIN_IDENTITY_SCOPE
    complete_for_scope: bool = True

    def __post_init__(self) -> None:
        if self.domain != BUILD_TOOLCHAIN_IDENTITY_DOMAIN:
            raise ValueError("build-toolchain identity domain is invalid")
        if self.scope != BUILD_TOOLCHAIN_IDENTITY_SCOPE:
            raise ValueError("build-toolchain identity scope is invalid")
        for value, expected_name in (
            (self.python, "python"),
            (self.cargo, "cargo"),
            (self.rustc, "rustc"),
            (self.linker, "linker"),
        ):
            if type(value) is not ToolIdentity or value.name != expected_name:
                raise TypeError(f"required {expected_name} identity is invalid")
        if type(self.rextio) is not RextioIdentity:
            raise TypeError("required Rextio identity is invalid")
        inspectors = tuple(self.inspectors)
        if not inspectors or not all(
            type(item) is ToolIdentity and item.name in _INSPECTOR_NAMES for item in inspectors
        ):
            raise TypeError("native inspector identities are invalid")
        canonical_inspectors = tuple(
            sorted(inspectors, key=lambda item: (item.name, item.executable.sha256))
        )
        if inspectors != canonical_inspectors or len({item.name for item in inspectors}) != len(
            inspectors
        ):
            raise ValueError("native inspector identities are not canonical and unique")
        environment = tuple(self.environment)
        if not all(type(item) is EnvironmentVariableIdentity for item in environment):
            raise TypeError("toolchain environment identities are invalid")
        if environment != tuple(sorted(environment, key=lambda item: item.name)) or len(
            {item.name for item in environment}
        ) != len(environment):
            raise ValueError("toolchain environment identities are not canonical and unique")
        if type(self.argv) is not ArgvIdentity:
            raise TypeError("toolchain argv identity is invalid")
        if type(self.cargo_sources) is not CargoSourcesIdentity:
            raise TypeError("Cargo source identity is invalid")
        for digest_value, label in (
            (self.support_plan_sha256, "support plan SHA-256"),
            (self.support_lock_raw_sha256, "support lock raw SHA-256"),
            (self.support_lock_merkle_sha256, "support lock Merkle SHA-256"),
        ):
            if (
                type(digest_value) is not str
                or _SHA256_RE.fullmatch(digest_value) is None
            ):
                raise ValueError(f"build-toolchain {label} is invalid")
        if self.complete_for_scope is not True:
            raise ValueError("build-toolchain identity must be complete for its scope")
        object.__setattr__(self, "inspectors", inspectors)
        object.__setattr__(self, "environment", environment)

    @property
    def digest(self) -> str:
        """Return the semantic digest of the closed toolchain receipt."""
        return hashlib.sha256(_canonical_json(self._payload())).hexdigest()

    def _payload(self) -> dict[str, object]:
        return {
            "domain": self.domain,
            "scope": self.scope,
            "complete_for_scope": True,
            "python": self.python.to_dict(),
            "rextio": self.rextio.to_dict(),
            "cargo": self.cargo.to_dict(),
            "rustc": self.rustc.to_dict(),
            "linker": self.linker.to_dict(),
            "inspectors": [item.to_dict() for item in self.inspectors],
            "argv": self.argv.to_dict(),
            "environment": [item.to_dict() for item in self.environment],
            "cargo_sources": self.cargo_sources.to_dict(),
            "support_plan_sha256": self.support_plan_sha256,
            "support_lock_raw_sha256": self.support_lock_raw_sha256,
            "support_lock_merkle_sha256": self.support_lock_merkle_sha256,
        }

    def to_dict(self) -> dict[str, object]:
        """Return the closed toolchain receipt with its semantic digest."""
        return {**self._payload(), "digest": self.digest}


def capture_tool_identity(
    name: str,
    path: Path | str,
    *,
    reported_version: str,
) -> ToolIdentity:
    """Bind one executable's exact bytes without serializing its local path."""
    if name not in _TOOL_NAMES:
        raise ToolchainIdentityError("toolchain tool name is not supported")
    try:
        executable = capture_exact_file(
            path,
            logical_name=f"toolchain/{name}",
            role="toolchain-executable",
            require_executable=True,
        )
        return ToolIdentity(
            name=name,
            executable=executable,
            reported_version=reported_version,
        )
    except (BuildInputIdentityError, TypeError, ValueError) as exc:
        raise ToolchainIdentityError(str(exc)) from exc


def verify_tool_identity(path: Path | str, expected: ToolIdentity) -> None:
    """Fail unless fresh executable bytes still match ``expected`` exactly."""
    if type(expected) is not ToolIdentity:
        raise ToolchainIdentityError("expected tool identity has an invalid type")
    try:
        observed = capture_tool_identity(
            expected.name,
            path,
            reported_version=expected.reported_version,
        )
    except ToolchainIdentityError as exc:
        raise ToolchainIdentityError("toolchain executable changed or became unavailable") from exc
    if observed != expected:
        raise ToolchainIdentityError("toolchain executable changed after capture")


def capture_environment_identity(
    environment: Mapping[str, str],
) -> tuple[EnvironmentVariableIdentity, ...]:
    """Filter to the fixed strict allowlist and hash each exact UTF-8 value."""
    if not isinstance(environment, Mapping):
        raise ToolchainIdentityError("toolchain environment must be a mapping")
    result: list[EnvironmentVariableIdentity] = []
    for name in sorted(STRICT_BUILD_ENV_ALLOWLIST.intersection(environment)):
        value = environment[name]
        if type(value) is not str or "\0" in value:
            raise ToolchainIdentityError("allowlisted environment value is invalid")
        data = value.encode("utf-8")
        if len(data) > MAX_TOOLCHAIN_ENV_VALUE_BYTES:
            raise ToolchainIdentityError("allowlisted environment value exceeds the byte bound")
        result.append(
            EnvironmentVariableIdentity(
                name=name,
                value_sha256=hashlib.sha256(data).hexdigest(),
                value_size=len(data),
            )
        )
    return tuple(result)


def capture_rextio_identity(
    files: Mapping[str, Path | str],
    *,
    version: str,
) -> RextioIdentity:
    """Capture an explicitly enumerated Rextio source set without directory walks."""
    if not isinstance(files, Mapping) or not files:
        raise ToolchainIdentityError("Rextio source identity requires explicit files")
    try:
        closure = capture_build_input_closure(
            tuple(
                InputFileSpec(
                    path=Path(path),
                    logical_name=logical_name,
                    role="rextio-python-source",
                )
                for logical_name, path in files.items()
            )
        )
        return RextioIdentity(
            version=version,
            files=closure.files,
            content_digest=closure.digest,
        )
    except (BuildInputIdentityError, TypeError, ValueError) as exc:
        raise ToolchainIdentityError(str(exc)) from exc


def capture_argv_identity(values: tuple[str, ...] | list[str]) -> ArgvIdentity:
    """Validate and bind one already-strict, semantic Cargo argument vector."""
    try:
        return ArgvIdentity(values=tuple(values))
    except (TypeError, ValueError) as exc:
        raise ToolchainIdentityError(str(exc)) from exc


def assemble_build_toolchain_identity(
    *,
    python: ToolIdentity,
    rextio: RextioIdentity,
    cargo: ToolIdentity,
    rustc: ToolIdentity,
    linker: ToolIdentity,
    inspectors: tuple[ToolIdentity, ...] | list[ToolIdentity],
    argv: ArgvIdentity,
    environment: tuple[EnvironmentVariableIdentity, ...] | list[EnvironmentVariableIdentity],
    cargo_sources: CargoSourcesIdentity,
    support_plan_sha256: str,
    support_lock_raw_sha256: str,
    support_lock_merkle_sha256: str,
) -> BuildToolchainIdentity:
    """Assemble the closed receipt while canonicalizing unordered inputs."""
    try:
        return BuildToolchainIdentity(
            python=python,
            rextio=rextio,
            cargo=cargo,
            rustc=rustc,
            linker=linker,
            inspectors=tuple(
                sorted(inspectors, key=lambda item: (item.name, item.executable.sha256))
            ),
            argv=argv,
            environment=tuple(sorted(environment, key=lambda item: item.name)),
            cargo_sources=cargo_sources,
            support_plan_sha256=support_plan_sha256,
            support_lock_raw_sha256=support_lock_raw_sha256,
            support_lock_merkle_sha256=support_lock_merkle_sha256,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise ToolchainIdentityError(str(exc)) from exc


def capture_cargo_sources(
    cargo_lock: Path | str,
    *,
    root_package: str,
    logical_name: str = "cargo/Cargo.lock",
) -> CargoSourcesIdentity:
    """Parse one securely-read lockfile into a complete registry source receipt."""
    if _NAME_RE.fullmatch(root_package) is None:
        raise ToolchainIdentityError("Cargo root package identity is invalid")
    try:
        lock_identity, data = capture_exact_file_bytes(
            cargo_lock,
            logical_name=logical_name,
            role="cargo-lockfile",
            max_bytes=8 * 1024 * 1024,
        )
    except (BuildInputIdentityError, TypeError, ValueError) as exc:
        raise ToolchainIdentityError(str(exc)) from exc
    try:
        document = tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ToolchainIdentityError("Cargo.lock is not valid UTF-8 TOML") from exc
    raw_packages = document.get("package")
    if not isinstance(raw_packages, list) or len(raw_packages) > MAX_CARGO_SOURCE_PACKAGES + 1:
        raise ToolchainIdentityError("Cargo.lock package inventory is missing or exceeds the bound")

    root_matches = 0
    packages: list[CargoSourceIdentity] = []
    seen: set[tuple[str, str, str]] = set()
    for raw in raw_packages:
        if not isinstance(raw, dict) or set(raw) - {
            "name",
            "version",
            "source",
            "checksum",
            "dependencies",
            "replace",
        }:
            raise ToolchainIdentityError("Cargo.lock package entry is invalid")
        name = raw.get("name")
        version = raw.get("version")
        source = raw.get("source")
        checksum = raw.get("checksum")
        if type(name) is not str or type(version) is not str:
            raise ToolchainIdentityError("Cargo.lock package identity is invalid")
        if source is None:
            if name != root_package or checksum is not None:
                raise ToolchainIdentityError("Cargo.lock contains an undeclared path source")
            root_matches += 1
            continue
        if type(source) is not str:
            raise ToolchainIdentityError("Cargo.lock source identity is invalid")
        if type(checksum) is not str:
            raise ToolchainIdentityError("Cargo registry source is missing a checksum")
        key = (name, version, source)
        if key in seen:
            raise ToolchainIdentityError("Cargo.lock source identity is duplicated")
        seen.add(key)
        try:
            packages.append(
                CargoSourceIdentity(
                    name=name,
                    version=version,
                    source=source,
                    checksum=checksum,
                )
            )
        except ValueError as exc:
            message = str(exc)
            if "checksum" in message:
                raise ToolchainIdentityError(message) from exc
            raise ToolchainIdentityError("Cargo registry source identity is invalid") from exc
    if root_matches != 1:
        raise ToolchainIdentityError("Cargo.lock must contain exactly one generated root package")
    try:
        return CargoSourcesIdentity(
            root_package=root_package,
            lock_file=lock_identity,
            packages=tuple(
                sorted(
                    packages,
                    key=lambda item: (item.name, item.version, item.source, item.checksum),
                )
            ),
        )
    except (TypeError, ValueError) as exc:
        raise ToolchainIdentityError(str(exc)) from exc


def _validate_registry_source(value: str) -> None:
    if type(value) is not str or len(value) > MAX_TOOLCHAIN_STRING_CHARS:
        raise ValueError("Cargo registry source is invalid")
    if any(ord(character) < 32 for character in value):
        raise ValueError("Cargo registry source is invalid")
    prefix = next((item for item in ("registry+", "sparse+") if value.startswith(item)), None)
    if prefix is None:
        raise ValueError("Cargo source is not an allowed registry source")
    parsed = urlsplit(value.removeprefix(prefix))
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Cargo registry source URL is invalid")
    if parsed.fragment:
        raise ValueError("Cargo registry source URL is invalid")


def _validate_bounded_text(value: str, label: str) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise ValueError(f"{label} is invalid")
    if len(value) > MAX_TOOLCHAIN_STRING_CHARS or any(ord(item) < 32 for item in value):
        raise ValueError(f"{label} is invalid")


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


__all__ = [
    "ArgvIdentity",
    "BUILD_TOOLCHAIN_IDENTITY_DOMAIN",
    "BUILD_TOOLCHAIN_IDENTITY_SCOPE",
    "BuildToolchainIdentity",
    "CargoSourceIdentity",
    "CargoSourcesIdentity",
    "EnvironmentVariableIdentity",
    "RextioIdentity",
    "STRICT_BUILD_ENV_ALLOWLIST",
    "ToolIdentity",
    "ToolchainIdentityError",
    "assemble_build_toolchain_identity",
    "capture_argv_identity",
    "capture_cargo_sources",
    "capture_environment_identity",
    "capture_rextio_identity",
    "capture_tool_identity",
    "verify_tool_identity",
]
