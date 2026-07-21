"""Strict, bounded two-build executor for the narrow Full C6 profile.

This module owns the filesystem and subprocess boundary that the lower-level
reproducibility verifier intentionally leaves to its caller.  It freezes one
generated Cargo project, materializes two independent private copies, and
requires the existing two-build verifier to compare the resulting wheel and
canonical JSON evidence.

The returned receipt is deliberately non-authorizing.  In-process callbacks
are a test/integration seam and cannot prove process or network isolation;
production callers should use the command-factory path and feed this receipt
into the separate final Full C6 authorization gate.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
import hashlib
import hmac
import json
import math
import os
import re
import shutil
import stat
import sys
import sysconfig
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import TypeAlias

from rextio.artifacts.profiles import detect_host_target_triple
from rextio.build.reproducibility import (
    ReproducibilityBuildOutputs,
    ReproducibilityError,
    ReproducibilityReceipt,
    verify_two_build_reproducibility,
)
from rextio.build.strict_cargo import StrictCargoCommandError, enforce_strict_cargo_command
from rextio.build.subprocess_utils import run_build_tool
from rextio.build.toolchain_identity import (
    STRICT_BUILD_ENV_ALLOWLIST,
    BuildToolchainIdentity,
    ToolchainIdentityError,
    verify_tool_identity,
)
from rextio.build.wheel_builder import (
    ExternalWheelContract,
    ExternalWheelMemberIdentity,
    WheelContractError,
    build_artifact_wheel,
    verify_external_wheel_contract,
)
from rextio.limits import DEFAULT_BUILD_TIMEOUT_SECONDS, MAX_BUILD_TIMEOUT_SECONDS


FULL_C6_EXECUTOR_DOMAIN = "rextio.full-c6-two-build-executor.v1"
FULL_C6_EXECUTOR_SCOPE = (
    "host-extension-wheel-cpython-external-source-depth1-plugin-free-v1"
)
FULL_C6_NATIVE_EXECUTION_DRIVER = "rextio-native-orchestrator-v1"
FULL_C6_CALLBACK_EXECUTION_DRIVER = "callback-test-seam"
FULL_C6_UNBOUND_EXECUTION_DRIVER = "native-subprocess-unbound"
FULL_C6_NATIVE_DRIVER_MANIFEST = "rextio.full-c6-native-driver.json"
FULL_C6_NATIVE_POSTPROCESSOR = "rextio-external-wheel-postprocessor-v1"
FULL_C6_NATIVE_DRIVER_DOMAIN = "rextio.full-c6-native-driver.v1"
FULL_C6_PREEXISTING_LOCK_DRIVER = "preexisting-lock"
FULL_C6_NATIVE_LOCK_DRIVER = "native-subprocess"
FULL_C6_CALLBACK_LOCK_DRIVER = "callback-test-seam"
MAX_FULL_C6_TREE_ENTRIES = 2048
MAX_FULL_C6_TREE_FILES = 1024
MAX_FULL_C6_TREE_BYTES = 256 * 1024 * 1024
MAX_FULL_C6_FILE_BYTES = 64 * 1024 * 1024
MAX_FULL_C6_PATH_DEPTH = 32
MAX_FULL_C6_PATH_CHARS = 4096
MAX_FULL_C6_OUTPUT_BYTES = 16 * 1024 * 1024
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_RESERVED_ENV = frozenset(
    {
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_HOME",
        "CARGO_NET_OFFLINE",
        "CARGO_TARGET_DIR",
        "HOME",
        "LANG",
        "LC_ALL",
        "PYTHONHASHSEED",
        "RUSTFLAGS",
        "SOURCE_DATE_EPOCH",
        "TZ",
    }
)
_EXECUTOR_ENV_ALLOWLIST = STRICT_BUILD_ENV_ALLOWLIST | frozenset({"HOME"})
_FORBIDDEN_ENV = frozenset(
    {
        "ALL_PROXY",
        "CARGO_HTTP_PROXY",
        "CARGO_HTTP_CHECK_REVOKE",
        "CARGO_NET_GIT_FETCH_WITH_CLI",
        "GIT_PROXY_COMMAND",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "NO_PROXY",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
    }
)
_BUILD_ROOT_TOKEN = "/rextio/build"
_PROJECT_ROOT_TOKEN = "/rextio/project"
_CANONICAL_DIRECTORY_MODE = 0o700
_CANONICAL_FILE_MODE = 0o644
_CANONICAL_EXECUTABLE_MODE = 0o755


class FullC6ExecutorError(ReproducibilityError):
    """The strict Full C6 executor could not establish its bounded receipt."""


@dataclass(frozen=True, slots=True)
class FullC6NativeDriverManifest:
    """Canonical frozen input for the executor-owned native wheel driver.

    The manifest lives inside the project tree captured by
    :class:`FullC6FrozenTreeManifest`.  It binds the exact Cargo invocation,
    host target, output distribution name, and the complete C5.2 source-wheel
    exclusion contract.  It is configuration, never distribution authority.
    """

    target_triple: str
    distribution_name: str
    cargo_argv: tuple[str, ...]
    external_contract: ExternalWheelContract
    domain: str = FULL_C6_NATIVE_DRIVER_DOMAIN
    execution_driver: str = FULL_C6_NATIVE_EXECUTION_DRIVER
    postprocessor: str = FULL_C6_NATIVE_POSTPROCESSOR
    authority: str = "non-authorizing"
    distribution_authorized: bool = False

    def __post_init__(self) -> None:
        argv = tuple(self.cargo_argv)
        if self.domain != FULL_C6_NATIVE_DRIVER_DOMAIN:
            raise ValueError("Full C6 native driver domain is invalid")
        if self.execution_driver != FULL_C6_NATIVE_EXECUTION_DRIVER:
            raise ValueError("Full C6 native execution driver is invalid")
        if self.postprocessor != FULL_C6_NATIVE_POSTPROCESSOR:
            raise ValueError("Full C6 native postprocessor is invalid")
        if self.authority != "non-authorizing" or self.distribution_authorized is not False:
            raise ValueError("Full C6 native driver has an invalid authority posture")
        if self.target_triple not in {
            "aarch64-apple-darwin",
            "x86_64-unknown-linux-gnu",
        }:
            raise ValueError("Full C6 native driver target is unsupported")
        if (
            type(self.distribution_name) is not str
            or re.fullmatch(r"[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?", self.distribution_name)
            is None
        ):
            raise ValueError("Full C6 native distribution name is invalid")
        if type(self.external_contract) is not ExternalWheelContract:
            raise TypeError("Full C6 native external wheel contract is invalid")
        _require_exact_native_cargo_command(argv)
        object.__setattr__(self, "cargo_argv", argv)

    @property
    def digest(self) -> str:
        """Return the SHA-256 of the exact canonical manifest bytes."""
        return hashlib.sha256(self.to_bytes()).hexdigest()

    def to_dict(self) -> dict[str, object]:
        """Return the complete canonical manifest document."""
        contract = self.external_contract
        return {
            "authority": "non-authorizing",
            "cargo_argv": list(self.cargo_argv),
            "distribution_authorized": False,
            "distribution_name": self.distribution_name,
            "domain": self.domain,
            "execution_driver": self.execution_driver,
            "external_wheel_contract": {
                "distribution": contract.distribution,
                "external_members": [
                    {"path": item.path, "sha256": item.sha256, "size": item.size}
                    for item in contract.external_members
                ],
                "package": contract.package,
                "source_members": list(contract.source_members),
                "version": contract.version,
            },
            "postprocessor": self.postprocessor,
            "target_triple": self.target_triple,
        }

    def to_bytes(self) -> bytes:
        """Return the only accepted on-disk encoding."""
        return _canonical_json(self.to_dict())


def full_c6_native_driver_manifest_bytes(
    *,
    target_triple: str,
    distribution_name: str,
    cargo_argv: Sequence[str],
    external_contract: ExternalWheelContract,
) -> bytes:
    """Create canonical bytes for the frozen executor-owned driver manifest."""
    try:
        return FullC6NativeDriverManifest(
            target_triple=target_triple,
            distribution_name=distribution_name,
            cargo_argv=tuple(cargo_argv),
            external_contract=external_contract,
        ).to_bytes()
    except (TypeError, ValueError) as exc:
        raise FullC6ExecutorError(str(exc)) from exc


def _parse_full_c6_native_driver_manifest(data: bytes) -> FullC6NativeDriverManifest:
    if type(data) is not bytes or not data or len(data) > 8 * 1024 * 1024:
        raise FullC6ExecutorError("Full C6 native driver manifest exceeds its byte bound")

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise FullC6ExecutorError(
                    "Full C6 native driver manifest contains a duplicate key"
                )
            result[key] = value
        return result

    try:
        document = json.loads(data.decode("utf-8"), object_pairs_hook=unique_object)
    except FullC6ExecutorError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise FullC6ExecutorError("Full C6 native driver manifest is invalid JSON") from exc
    if type(document) is not dict or data != _canonical_json(document):
        raise FullC6ExecutorError("Full C6 native driver manifest is not canonical JSON")
    required = {
        "authority",
        "cargo_argv",
        "distribution_authorized",
        "distribution_name",
        "domain",
        "execution_driver",
        "external_wheel_contract",
        "postprocessor",
        "target_triple",
    }
    if set(document) != required:
        raise FullC6ExecutorError("Full C6 native driver manifest fields are invalid")
    raw_contract = document["external_wheel_contract"]
    if type(raw_contract) is not dict or set(raw_contract) != {
        "distribution",
        "external_members",
        "package",
        "source_members",
        "version",
    }:
        raise FullC6ExecutorError("Full C6 native external wheel contract is invalid")
    raw_members = raw_contract["external_members"]
    raw_sources = raw_contract["source_members"]
    raw_argv = document["cargo_argv"]
    if (
        type(raw_members) is not list
        or type(raw_sources) is not list
        or type(raw_argv) is not list
        or not all(type(item) is str for item in raw_sources)
        or not all(type(item) is str for item in raw_argv)
    ):
        raise FullC6ExecutorError("Full C6 native driver manifest collections are invalid")
    members: list[ExternalWheelMemberIdentity] = []
    try:
        for raw in raw_members:
            if type(raw) is not dict or set(raw) != {"path", "sha256", "size"}:
                raise ValueError("external member fields are invalid")
            if (
                type(raw["path"]) is not str
                or type(raw["sha256"]) is not str
                or type(raw["size"]) is not int
                or isinstance(raw["size"], bool)
            ):
                raise TypeError("external member values are invalid")
            members.append(
                ExternalWheelMemberIdentity(
                    path=raw["path"],
                    sha256=raw["sha256"],
                    size=raw["size"],
                )
            )
        for name in ("package", "distribution", "version"):
            if type(raw_contract[name]) is not str:
                raise TypeError("external wheel identity is invalid")
        contract = ExternalWheelContract(
            package=raw_contract["package"],
            distribution=raw_contract["distribution"],
            version=raw_contract["version"],
            source_members=tuple(raw_sources),
            external_members=tuple(members),
        )
        for name in (
            "target_triple",
            "distribution_name",
            "domain",
            "execution_driver",
            "postprocessor",
            "authority",
        ):
            if type(document[name]) is not str:
                raise TypeError("native driver identity is invalid")
        if type(document["distribution_authorized"]) is not bool:
            raise TypeError("native driver authority flag is invalid")
        manifest = FullC6NativeDriverManifest(
            target_triple=document["target_triple"],
            distribution_name=document["distribution_name"],
            cargo_argv=tuple(raw_argv),
            external_contract=contract,
            domain=document["domain"],
            execution_driver=document["execution_driver"],
            postprocessor=document["postprocessor"],
            authority=document["authority"],
            distribution_authorized=document["distribution_authorized"],
        )
    except (TypeError, ValueError) as exc:
        raise FullC6ExecutorError("Full C6 native driver manifest is invalid") from exc
    if manifest.to_bytes() != data:
        raise FullC6ExecutorError("Full C6 native driver manifest is not canonical")
    return manifest


@dataclass(frozen=True, slots=True)
class FullC6TreeEntry:
    """One path-only, content-bound member of the frozen project tree."""

    logical_name: str
    kind: str
    sha256: str | None
    size: int
    mode: int

    def __post_init__(self) -> None:
        _validate_relative_name(self.logical_name)
        if self.kind not in {"directory", "file"}:
            raise ValueError("Full C6 tree entry kind is invalid")
        if self.kind == "directory":
            if (
                self.sha256 is not None
                or type(self.size) is not int
                or isinstance(self.size, bool)
                or self.size != 0
                or type(self.mode) is not int
                or isinstance(self.mode, bool)
                or self.mode != _CANONICAL_DIRECTORY_MODE
            ):
                raise ValueError("Full C6 directory entry is not canonical")
        elif (
            type(self.sha256) is not str
            or _SHA256_RE.fullmatch(self.sha256) is None
            or type(self.size) is not int
            or isinstance(self.size, bool)
            or not (0 <= self.size <= MAX_FULL_C6_FILE_BYTES)
            or type(self.mode) is not int
            or isinstance(self.mode, bool)
            or self.mode not in {_CANONICAL_FILE_MODE, _CANONICAL_EXECUTABLE_MODE}
        ):
            raise ValueError("Full C6 file entry is not canonical")

    def to_dict(self) -> dict[str, object]:
        """Return the path-sanitized canonical entry."""
        return {
            "logical_name": self.logical_name,
            "kind": self.kind,
            "sha256": self.sha256,
            "size": self.size,
            "mode": self.mode,
        }


@dataclass(frozen=True, slots=True)
class FullC6FrozenTreeManifest:
    """Complete immutable identity for the generated project copied twice."""

    entries: tuple[FullC6TreeEntry, ...]
    cargo_lock_generated: bool
    complete_for_scope: bool = True

    def __post_init__(self) -> None:
        entries = tuple(self.entries)
        if not entries or len(entries) > MAX_FULL_C6_TREE_ENTRIES:
            raise ValueError("Full C6 tree entry count is outside the bound")
        if not all(type(item) is FullC6TreeEntry for item in entries):
            raise TypeError("Full C6 tree entries have an invalid type")
        canonical = tuple(sorted(entries, key=lambda item: (item.logical_name, item.kind)))
        if entries != canonical or len({item.logical_name for item in entries}) != len(entries):
            raise ValueError("Full C6 tree entries are not canonical and unique")
        if sum(item.kind == "file" for item in entries) > MAX_FULL_C6_TREE_FILES:
            raise ValueError("Full C6 tree file count exceeds the bound")
        if sum(item.size for item in entries) > MAX_FULL_C6_TREE_BYTES:
            raise ValueError("Full C6 tree byte count exceeds the bound")
        if type(self.cargo_lock_generated) is not bool:
            raise TypeError("Cargo.lock generation marker must be boolean")
        if self.complete_for_scope is not True:
            raise ValueError("Full C6 tree manifest must be complete for its scope")
        names = {item.logical_name for item in entries if item.kind == "file"}
        if "Cargo.toml" not in names or "Cargo.lock" not in names:
            raise ValueError("Full C6 tree must contain exact Cargo.toml and Cargo.lock files")
        cargo_inputs = {
            item.logical_name: item
            for item in entries
            if item.logical_name in {"Cargo.toml", "Cargo.lock"}
        }
        if any(
            item.kind != "file" or item.mode != _CANONICAL_FILE_MODE or item.size == 0
            for item in cargo_inputs.values()
        ):
            raise ValueError("Full C6 Cargo.toml and Cargo.lock must be nonempty data files")
        object.__setattr__(self, "entries", entries)

    @property
    def digest(self) -> str:
        """Return the semantic digest of the complete frozen tree."""
        return hashlib.sha256(_canonical_json(self._payload())).hexdigest()

    def _payload(self) -> dict[str, object]:
        return {
            "entries": [item.to_dict() for item in self.entries],
            "cargo_lock_generated": self.cargo_lock_generated,
            "complete_for_scope": True,
        }

    def to_dict(self) -> dict[str, object]:
        """Return the canonical path-free manifest and digest."""
        return {**self._payload(), "digest": self.digest}


@dataclass(frozen=True, slots=True)
class FullC6EnvironmentBinding:
    """Digest-only binding for one exact subprocess environment value."""

    name: str
    value_sha256: str
    value_size: int

    def __post_init__(self) -> None:
        if self.name not in _EXECUTOR_ENV_ALLOWLIST:
            raise ValueError("Full C6 environment name is outside the allowlist")
        if _SHA256_RE.fullmatch(self.value_sha256) is None:
            raise ValueError("Full C6 environment value digest is invalid")
        if (
            type(self.value_size) is not int
            or isinstance(self.value_size, bool)
            or not (0 <= self.value_size <= 64 * 1024)
        ):
            raise ValueError("Full C6 environment value size is invalid")

    def to_dict(self) -> dict[str, object]:
        """Return the digest-only environment binding."""
        return {
            "name": self.name,
            "value_sha256": self.value_sha256,
            "value_size": self.value_size,
        }


@dataclass(frozen=True, slots=True)
class FullC6InvocationReceipt:
    """Path-free command and closed-environment identity for one build."""

    ordinal: int
    argv_sha256: str
    argv_count: int
    environment: tuple[FullC6EnvironmentBinding, ...]
    timeout_seconds: float
    max_output_bytes: int
    inherit_env: bool = False

    def __post_init__(self) -> None:
        if self.ordinal not in (1, 2):
            raise ValueError("Full C6 invocation ordinal is invalid")
        if _SHA256_RE.fullmatch(self.argv_sha256) is None:
            raise ValueError("Full C6 invocation argv digest is invalid")
        if type(self.argv_count) is not int or not (5 <= self.argv_count <= 256):
            raise ValueError("Full C6 invocation argv count is invalid")
        environment = tuple(self.environment)
        if not all(type(item) is FullC6EnvironmentBinding for item in environment):
            raise TypeError("Full C6 invocation environment is invalid")
        if environment != tuple(sorted(environment, key=lambda item: item.name)) or len(
            {item.name for item in environment}
        ) != len(environment):
            raise ValueError("Full C6 invocation environment is not canonical and unique")
        _validate_timeout(self.timeout_seconds)
        _validate_output_bound(self.max_output_bytes)
        if self.inherit_env is not False:
            raise ValueError("Full C6 invocation must not inherit the host environment")
        object.__setattr__(self, "environment", environment)

    def to_dict(self) -> dict[str, object]:
        """Return the path-free exact invocation binding."""
        return {
            "ordinal": self.ordinal,
            "argv_sha256": self.argv_sha256,
            "argv_count": self.argv_count,
            "environment": [item.to_dict() for item in self.environment],
            "timeout_seconds": self.timeout_seconds,
            "max_output_bytes": self.max_output_bytes,
            "inherit_env": False,
        }


@dataclass(frozen=True, slots=True)
class FullC6ExecutorReceipt:
    """Non-authorizing receipt for one strict, reproducible two-build run."""

    frozen_tree: FullC6FrozenTreeManifest
    invocations: tuple[FullC6InvocationReceipt, FullC6InvocationReceipt]
    reproducibility: ReproducibilityReceipt
    execution_driver: str = FULL_C6_CALLBACK_EXECUTION_DRIVER
    lock_driver: str = FULL_C6_PREEXISTING_LOCK_DRIVER
    toolchain_sha256: str | None = None
    cargo_executable_sha256: str | None = None
    postprocessor: str | None = None
    postprocessor_manifest_sha256: str | None = None
    target_triple: str | None = None
    domain: str = FULL_C6_EXECUTOR_DOMAIN
    scope: str = FULL_C6_EXECUTOR_SCOPE
    complete_for_scope: bool = True
    authorizes_distribution: bool = False

    def __post_init__(self) -> None:
        if type(self.frozen_tree) is not FullC6FrozenTreeManifest:
            raise TypeError("Full C6 executor tree manifest is invalid")
        invocations = tuple(self.invocations)
        if len(invocations) != 2 or tuple(item.ordinal for item in invocations) != (1, 2):
            raise ValueError("Full C6 executor requires exactly two ordered invocations")
        if not all(type(item) is FullC6InvocationReceipt for item in invocations):
            raise TypeError("Full C6 executor invocation receipt is invalid")
        if not hmac.compare_digest(invocations[0].argv_sha256, invocations[1].argv_sha256):
            raise ValueError("Full C6 executor commands differ between builds")
        if type(self.reproducibility) is not ReproducibilityReceipt:
            raise TypeError("Full C6 executor reproducibility receipt is invalid")
        if self.execution_driver not in {
            FULL_C6_NATIVE_EXECUTION_DRIVER,
            FULL_C6_CALLBACK_EXECUTION_DRIVER,
            FULL_C6_UNBOUND_EXECUTION_DRIVER,
        }:
            raise ValueError("Full C6 executor execution driver is invalid")
        if self.lock_driver not in {
            FULL_C6_PREEXISTING_LOCK_DRIVER,
            FULL_C6_NATIVE_LOCK_DRIVER,
            FULL_C6_CALLBACK_LOCK_DRIVER,
        }:
            raise ValueError("Full C6 executor lock driver is invalid")
        if self.execution_driver == FULL_C6_NATIVE_EXECUTION_DRIVER:
            _require_sha256(self.toolchain_sha256, "executor toolchain")
            _require_sha256(self.cargo_executable_sha256, "executor Cargo executable")
            if self.postprocessor != FULL_C6_NATIVE_POSTPROCESSOR:
                raise ValueError("Full C6 executor postprocessor is invalid")
            _require_sha256(
                self.postprocessor_manifest_sha256,
                "executor postprocessor manifest",
            )
            if self.target_triple not in {
                "aarch64-apple-darwin",
                "x86_64-unknown-linux-gnu",
            }:
                raise ValueError("Full C6 executor target is unsupported")
        elif any(
            item is not None
            for item in (
                self.toolchain_sha256,
                self.cargo_executable_sha256,
                self.postprocessor,
                self.postprocessor_manifest_sha256,
                self.target_triple,
            )
        ):
            raise ValueError("non-authoritative executor cannot claim toolchain bindings")
        if self.domain != FULL_C6_EXECUTOR_DOMAIN or self.scope != FULL_C6_EXECUTOR_SCOPE:
            raise ValueError("Full C6 executor domain or scope is invalid")
        if self.complete_for_scope is not True or self.authorizes_distribution is not False:
            raise ValueError("Full C6 executor receipt has an invalid authority posture")
        object.__setattr__(self, "invocations", invocations)

    @property
    def digest(self) -> str:
        """Return the semantic digest of the non-authorizing executor receipt."""
        return hashlib.sha256(_canonical_json(self._payload())).hexdigest()

    def _payload(self) -> dict[str, object]:
        return {
            "domain": self.domain,
            "scope": self.scope,
            "complete_for_scope": True,
            "authorizes_distribution": False,
            "frozen_tree": self.frozen_tree.to_dict(),
            "invocations": [item.to_dict() for item in self.invocations],
            "reproducibility_sha256": self.reproducibility.digest,
            "execution_driver": self.execution_driver,
            "lock_driver": self.lock_driver,
            "toolchain_sha256": self.toolchain_sha256,
            "cargo_executable_sha256": self.cargo_executable_sha256,
            "postprocessor": self.postprocessor,
            "postprocessor_manifest_sha256": self.postprocessor_manifest_sha256,
            "target_triple": self.target_triple,
        }

    def to_dict(self) -> dict[str, object]:
        """Return the complete path-free executor binding and digest."""
        return {**self._payload(), "digest": self.digest}


@dataclass(frozen=True, slots=True)
class FullC6BuildContext:
    """Private, non-serializable context supplied to a command factory."""

    ordinal: int
    build_root: Path
    project_root: Path
    environment: tuple[tuple[str, str], ...]
    timeout_seconds: float
    max_output_bytes: int
    inherit_env: bool = False

    def environment_dict(self) -> dict[str, str]:
        """Return a fresh exact environment mapping for a subprocess."""
        return dict(self.environment)


@dataclass(frozen=True, slots=True)
class FullC6BuildRequest:
    """Private callback request with the already-validated strict Cargo argv."""

    context: FullC6BuildContext
    cargo_argv: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FullC6BuildCommand:
    """One command-factory result and its three build-root-relative outputs."""

    argv: tuple[str, ...]
    unsigned_wheel: str
    sbom_json: str
    provenance_input_json: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "argv", tuple(self.argv))
        for name in (self.unsigned_wheel, self.sbom_json, self.provenance_input_json):
            _validate_relative_name(name)
        if len({self.unsigned_wheel, self.sbom_json, self.provenance_input_json}) != 3:
            raise ValueError("Full C6 build outputs must be distinct")


@dataclass(frozen=True, slots=True)
class FullC6LockGenerationRequest:
    """Private request for exactly one offline Cargo.lock generation step."""

    quarantine_root: Path
    project_root: Path
    cargo_argv: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    timeout_seconds: float
    max_output_bytes: int
    inherit_env: bool = False

    def environment_dict(self) -> dict[str, str]:
        """Return a fresh exact lock-generation environment."""
        return dict(self.environment)


@dataclass(frozen=True, slots=True)
class FullC6LockCommand:
    """One lock command-factory result."""

    argv: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "argv", tuple(self.argv))


FullC6BuildCallback: TypeAlias = Callable[[FullC6BuildRequest], ReproducibilityBuildOutputs]
FullC6BuildCommandFactory: TypeAlias = Callable[[FullC6BuildContext], FullC6BuildCommand]
FullC6LockCallback: TypeAlias = Callable[[FullC6LockGenerationRequest], None]
FullC6LockCommandFactory: TypeAlias = Callable[[FullC6LockGenerationRequest], FullC6LockCommand]


@dataclass(frozen=True, slots=True)
class _FrozenEntry:
    public: FullC6TreeEntry
    data: bytes | None


@dataclass(frozen=True, slots=True)
class _FrozenTree:
    manifest: FullC6FrozenTreeManifest | None
    entries: tuple[_FrozenEntry, ...]
    cargo_lock_generated: bool
    root_key: tuple[int, int]
    filesystem_keys: tuple[tuple[str, int, int], ...]


def execute_full_c6_two_build(
    source_root: Path | str,
    first_quarantine_root: Path | str,
    second_quarantine_root: Path | str,
    *,
    build: FullC6BuildCallback | None = None,
    cargo_command: Sequence[str] | None = None,
    command_factory: FullC6BuildCommandFactory | None = None,
    lock_generator: FullC6LockCallback | None = None,
    lock_command_factory: FullC6LockCommandFactory | None = None,
    base_environment: Mapping[str, str] | None = None,
    source_date_epoch: int,
    timeout_seconds: float = DEFAULT_BUILD_TIMEOUT_SECONDS,
    max_output_bytes: int = MAX_FULL_C6_OUTPUT_BYTES,
    toolchain: BuildToolchainIdentity | None = None,
    native_orchestrator: bool = False,
) -> FullC6ExecutorReceipt:
    """Freeze one project and execute exactly two strict isolated builds.

    Exactly one of ``build`` and ``command_factory`` is required.  The callback
    seam receives a closed request and is checked after returning; the command
    factory is safer for production because this module launches its command
    with a bounded process tree, output cap, and ``inherit_env=False``.

    If the source has no ``Cargo.lock``, exactly one explicit lock callback or
    command factory is required.  Lock generation occurs in a temporary copy,
    must be offline, and may add only ``Cargo.lock`` to the project tree.
    """
    _validate_executor_arguments(
        build=build,
        cargo_command=cargo_command,
        command_factory=command_factory,
        lock_generator=lock_generator,
        lock_command_factory=lock_command_factory,
        source_date_epoch=source_date_epoch,
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
        toolchain=toolchain,
        native_orchestrator=native_orchestrator,
    )
    source, _source_stat = _validate_source_root(source_root)
    first = _validate_quarantine_root(first_quarantine_root)
    second = _validate_quarantine_root(second_quarantine_root)
    _require_disjoint_roots((source, first[0], second[0]))
    environment_seed = _validate_base_environment(base_environment)
    if native_orchestrator and "CARGO_BUILD_TARGET" in environment_seed:
        raise FullC6ExecutorError(
            "Full C6 native driver owns host target selection"
        )

    without_generated_lock = _capture_stable_tree(source, cargo_lock_generated=False)
    has_lock = any(
        item.public.kind == "file" and item.public.logical_name == "Cargo.lock"
        for item in without_generated_lock.entries
    )
    if has_lock:
        if lock_generator is not None or lock_command_factory is not None:
            raise FullC6ExecutorError("Cargo.lock already exists; lock generation is ambiguous")
        frozen = without_generated_lock
        lock_driver = FULL_C6_PREEXISTING_LOCK_DRIVER
    else:
        if (lock_generator is None) == (lock_command_factory is None):
            raise FullC6ExecutorError(
                "missing Cargo.lock requires exactly one explicit offline lock generator"
            )
        lock_data = _generate_lock(
            without_generated_lock,
            first[0],
            root_stat=first[1],
            environment_seed=environment_seed,
            source_date_epoch=source_date_epoch,
            timeout_seconds=float(timeout_seconds),
            max_output_bytes=max_output_bytes,
            callback=lock_generator,
            command_factory=lock_command_factory,
        )
        frozen = _with_generated_lock(without_generated_lock, lock_data)
        lock_driver = (
            FULL_C6_CALLBACK_LOCK_DRIVER
            if lock_generator is not None
            else FULL_C6_NATIVE_LOCK_DRIVER
        )

    fixed_argv: tuple[str, ...] | None = None
    if build is not None:
        assert cargo_command is not None
        fixed_argv = _require_prestrict_build_command(cargo_command)
        _reject_private_argv(fixed_argv, source=source, roots=(first[0], second[0]))
    native_manifest: FullC6NativeDriverManifest | None = None
    if native_orchestrator:
        assert toolchain is not None
        if frozen.manifest is None:
            raise FullC6ExecutorError("Full C6 native driver requires a frozen Cargo.lock")
        try:
            manifest_data = _entry_data(frozen, FULL_C6_NATIVE_DRIVER_MANIFEST)
        except FullC6ExecutorError as exc:
            raise FullC6ExecutorError(
                f"Full C6 frozen tree is missing exact {FULL_C6_NATIVE_DRIVER_MANIFEST}"
            ) from exc
        native_manifest = _parse_full_c6_native_driver_manifest(manifest_data)
        fixed_argv = _require_exact_native_cargo_command(native_manifest.cargo_argv)
        if fixed_argv != toolchain.argv.values:
            raise FullC6ExecutorError(
                "Full C6 native driver argv differs from toolchain identity"
            )
        try:
            host_target = detect_host_target_triple()
        except ValueError as exc:
            raise FullC6ExecutorError("Full C6 native host target is unsupported") from exc
        if native_manifest.target_triple != host_target:
            raise FullC6ExecutorError(
                "Full C6 native driver target differs from the current host"
            )
        _reject_private_argv(fixed_argv, source=source, roots=(first[0], second[0]))

    invocation_receipts: list[FullC6InvocationReceipt] = []
    copied_inodes: list[frozenset[tuple[int, int]]] = []
    project_copies: list[Path] = []
    project_identities: list[os.stat_result] = []
    command_values: list[tuple[str, ...]] = []

    def isolated_build(build_root: Path) -> ReproducibilityBuildOutputs:
        ordinal = len(invocation_receipts) + 1
        expected_root = first if ordinal == 1 else second
        _verify_private_root(build_root, expected_root[1])
        _assert_source_unchanged(source, without_generated_lock)
        project_root, inode_keys = _materialize_build_root(build_root, frozen)
        copied_inodes.append(inode_keys)
        project_copies.append(project_root)
        project_identity = os.lstat(project_root)
        project_identities.append(project_identity)
        _assert_source_unchanged(source, without_generated_lock)
        environment = _build_environment(
            build_root,
            project_root,
            environment_seed,
            source_date_epoch=source_date_epoch,
        )
        context = FullC6BuildContext(
            ordinal=ordinal,
            build_root=build_root,
            project_root=project_root,
            environment=tuple(sorted(environment.items())),
            timeout_seconds=float(timeout_seconds),
            max_output_bytes=max_output_bytes,
        )
        started = time.monotonic()
        if build is not None:
            assert fixed_argv is not None
            argv = fixed_argv
            try:
                outputs = build(FullC6BuildRequest(context=context, cargo_argv=argv))
            except FullC6ExecutorError:
                raise
            except Exception as exc:
                raise FullC6ExecutorError("Full C6 build callback failed") from exc
        elif native_orchestrator:
            assert fixed_argv is not None
            assert native_manifest is not None
            assert toolchain is not None
            argv = fixed_argv
            _verify_native_toolchain_invocation(
                argv,
                environment=environment,
                toolchain=toolchain,
            )
            completed = run_build_tool(
                list(argv),
                cwd=project_root,
                timeout=float(timeout_seconds),
                env=environment,
                inherit_env=False,
                max_output_bytes=max_output_bytes,
            )
            if completed.returncode != 0:
                raise FullC6ExecutorError(
                    f"strict Cargo build failed with exit status {completed.returncode}"
                )
            _verify_native_toolchain_invocation(
                argv,
                environment=environment,
                toolchain=toolchain,
            )
            outputs = _postprocess_native_build(
                context=context,
                frozen=frozen,
                manifest=native_manifest,
                toolchain=toolchain,
            )
        else:
            assert command_factory is not None
            try:
                spec = command_factory(context)
            except Exception as exc:
                raise FullC6ExecutorError("Full C6 command factory failed") from exc
            if type(spec) is not FullC6BuildCommand:
                raise FullC6ExecutorError("Full C6 command factory returned an invalid command")
            argv = _require_prestrict_build_command(spec.argv)
            _reject_private_argv(argv, source=source, roots=(first[0], second[0]))
            if toolchain is not None:
                _verify_native_toolchain_invocation(
                    argv,
                    environment=environment,
                    toolchain=toolchain,
                )
            completed = run_build_tool(
                list(argv),
                cwd=project_root,
                timeout=float(timeout_seconds),
                env=environment,
                inherit_env=False,
                max_output_bytes=max_output_bytes,
            )
            if completed.returncode != 0:
                raise FullC6ExecutorError(
                    f"strict Cargo build failed with exit status {completed.returncode}"
                )
            if toolchain is not None:
                _verify_native_toolchain_invocation(
                    argv,
                    environment=environment,
                    toolchain=toolchain,
                )
            outputs = ReproducibilityBuildOutputs(
                unsigned_wheel=build_root / spec.unsigned_wheel,
                sbom_json=build_root / spec.sbom_json,
                provenance_input_json=build_root / spec.provenance_input_json,
            )
        if time.monotonic() - started > float(timeout_seconds):
            raise FullC6ExecutorError("Full C6 build callback exceeded its timeout bound")
        if type(outputs) is not ReproducibilityBuildOutputs:
            raise FullC6ExecutorError("Full C6 build returned invalid output paths")
        _verify_private_root(build_root, expected_root[1])
        _verify_project_root(project_root, project_identity)
        _verify_outputs_are_independent(build_root, project_root, outputs)
        _verify_materialized_tree(project_root, frozen)
        _verify_project_root(project_root, project_identity)
        _verify_private_root(build_root, expected_root[1])
        _assert_source_unchanged(source, without_generated_lock)
        command_values.append(argv)
        invocation_receipts.append(
            _invocation_receipt(
                ordinal,
                argv,
                environment,
                timeout_seconds=float(timeout_seconds),
                max_output_bytes=max_output_bytes,
            )
        )
        return outputs

    try:
        reproducibility = verify_two_build_reproducibility(
            first[0],
            second[0],
            build=isolated_build,
        )
    except (ReproducibilityError, FullC6ExecutorError) as exc:
        if isinstance(exc, FullC6ExecutorError):
            raise
        raise FullC6ExecutorError(str(exc)) from exc
    if (
        len(invocation_receipts) != 2
        or len(command_values) != 2
        or len(copied_inodes) != 2
        or len(project_copies) != 2
        or len(project_identities) != 2
    ):
        raise FullC6ExecutorError("Full C6 executor did not perform exactly two builds")
    if command_values[0] != command_values[1]:
        raise FullC6ExecutorError("strict Cargo commands differ between isolated builds")
    if copied_inodes[0].intersection(copied_inodes[1]):
        raise FullC6ExecutorError("isolated project copies share hardlinked files")
    for root, root_identity, project, project_identity in (
        (first[0], first[1], project_copies[0], project_identities[0]),
        (second[0], second[1], project_copies[1], project_identities[1]),
    ):
        _verify_private_root(root, root_identity)
        _verify_project_root(project, project_identity)
        _verify_materialized_tree(project, frozen)
    _assert_source_unchanged(source, without_generated_lock)
    if frozen.manifest is None:
        raise FullC6ExecutorError("Full C6 frozen tree is missing its complete manifest")
    try:
        return FullC6ExecutorReceipt(
            frozen_tree=frozen.manifest,
            invocations=(invocation_receipts[0], invocation_receipts[1]),
            reproducibility=reproducibility,
            execution_driver=(
                FULL_C6_NATIVE_EXECUTION_DRIVER
                if native_orchestrator
                else (
                    FULL_C6_CALLBACK_EXECUTION_DRIVER
                    if build is not None
                    else FULL_C6_UNBOUND_EXECUTION_DRIVER
                )
            ),
            lock_driver=lock_driver,
            toolchain_sha256=(
                toolchain.digest if native_orchestrator and toolchain is not None else None
            ),
            cargo_executable_sha256=(
                toolchain.cargo.executable.sha256
                if native_orchestrator and toolchain is not None
                else None
            ),
            postprocessor=(
                native_manifest.postprocessor if native_manifest is not None else None
            ),
            postprocessor_manifest_sha256=(
                native_manifest.digest if native_manifest is not None else None
            ),
            target_triple=(
                native_manifest.target_triple if native_manifest is not None else None
            ),
        )
    except (TypeError, ValueError) as exc:
        raise FullC6ExecutorError(str(exc)) from exc


def execute_full_c6_native_two_build(
    source_root: Path | str,
    first_quarantine_root: Path | str,
    second_quarantine_root: Path | str,
    *,
    base_environment: Mapping[str, str] | None = None,
    source_date_epoch: int,
    toolchain: BuildToolchainIdentity,
    timeout_seconds: float = DEFAULT_BUILD_TIMEOUT_SECONDS,
    max_output_bytes: int = MAX_FULL_C6_OUTPUT_BYTES,
) -> FullC6ExecutorReceipt:
    """Run the sole production Full C6 native build and wheel postprocessor.

    Unlike :func:`execute_full_c6_two_build`'s callback and command-factory
    seams, this entrypoint owns every output-producing step.  Its canonical
    manifest and Python staging bytes must already be part of ``source_root``.
    """
    return execute_full_c6_two_build(
        source_root,
        first_quarantine_root,
        second_quarantine_root,
        base_environment=base_environment,
        source_date_epoch=source_date_epoch,
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
        toolchain=toolchain,
        native_orchestrator=True,
    )


def _postprocess_native_build(
    *,
    context: FullC6BuildContext,
    frozen: _FrozenTree,
    manifest: FullC6NativeDriverManifest,
    toolchain: BuildToolchainIdentity,
) -> ReproducibilityBuildOutputs:
    """Create one wheel and two preliminary non-authorizing documents."""
    if frozen.manifest is None:
        raise FullC6ExecutorError("Full C6 native postprocessor lacks a frozen tree")
    extension_suffix = _full_c6_extension_suffix()
    artifact = (
        context.build_root
        / "target"
        / "release"
        / _native_cargo_artifact_name(manifest.target_triple)
    )
    try:
        before = os.lstat(artifact)
        artifact_data, artifact_stat = _secure_read_regular(artifact, before)
    except FullC6ExecutorError:
        raise
    except OSError as exc:
        raise FullC6ExecutorError("Full C6 native Cargo artifact is missing") from exc
    if (before.st_dev, before.st_ino) != (artifact_stat.st_dev, artifact_stat.st_ino):
        raise FullC6ExecutorError("Full C6 native Cargo artifact changed")

    staging = context.build_root / "wheel-staging"
    output = context.build_root / "output"
    try:
        staging.mkdir(mode=_CANONICAL_DIRECTORY_MODE)
        output.mkdir(mode=_CANONICAL_DIRECTORY_MODE)
        os.chmod(staging, _CANONICAL_DIRECTORY_MODE)
        os.chmod(output, _CANONICAL_DIRECTORY_MODE)
    except OSError as exc:
        raise FullC6ExecutorError("Full C6 native output staging could not be created") from exc
    _materialize_frozen_python_staging(frozen, staging)
    installed = staging / f"_rextio_native{extension_suffix}"
    _write_exclusive_bytes(installed, artifact_data, mode=_CANONICAL_FILE_MODE)

    try:
        wheel_result = build_artifact_wheel(
            Path(manifest.distribution_name),
            staging,
            output,
            external_contract=manifest.external_contract,
        )
        if wheel_result.status != "built" or type(wheel_result.path) is not str:
            raise FullC6ExecutorError("Full C6 native wheel postprocessor failed")
        wheel = Path(wheel_result.path)
        verification = verify_external_wheel_contract(
            wheel,
            manifest.external_contract,
        )
    except FullC6ExecutorError:
        raise
    except (OSError, TypeError, ValueError, WheelContractError) as exc:
        raise FullC6ExecutorError(
            "Full C6 native wheel contract verification failed"
        ) from exc
    try:
        wheel_stat = os.lstat(wheel)
    except OSError as exc:
        raise FullC6ExecutorError("Full C6 native wheel disappeared") from exc
    if not stat.S_ISREG(wheel_stat.st_mode) or wheel_stat.st_nlink != 1:
        raise FullC6ExecutorError("Full C6 native wheel is not an independent file")

    common = {
        "authority": "non-authorizing",
        "cargo_argv_sha256": toolchain.argv.digest,
        "cargo_artifact_sha256": hashlib.sha256(artifact_data).hexdigest(),
        "distribution_authorized": False,
        "driver_manifest_sha256": manifest.digest,
        "execution_driver": FULL_C6_NATIVE_EXECUTION_DRIVER,
        "frozen_tree_sha256": frozen.manifest.digest,
        "postprocessor": FULL_C6_NATIVE_POSTPROCESSOR,
        "target_triple": manifest.target_triple,
        "toolchain_sha256": toolchain.digest,
        "wheel_sha256": verification.wheel_sha256,
        "wheel_size": wheel_stat.st_size,
    }
    sbom_document = {
        "bomFormat": "CycloneDX",
        "components": [],
        "metadata": {"properties": _preliminary_properties(common)},
        "rextio": common,
        "serialNumber": f"urn:uuid:{verification.wheel_sha256[:32]}",
        "specVersion": "1.5",
        "version": 1,
    }
    provenance_document = {
        "_type": "https://in-toto.io/Statement/v1",
        "authority": "non-authorizing",
        "distribution_authorized": False,
        "predicate": {
            "buildDefinition": {
                "buildType": "https://rextio.dev/build/full-c6-native-orchestrator/v1",
                "externalParameters": common,
                "internalParameters": {
                    "authority": "non-authorizing",
                    "distribution_authorized": False,
                },
                "resolvedDependencies": [],
            },
            "runDetails": {
                "builder": {"id": FULL_C6_NATIVE_EXECUTION_DRIVER},
                "metadata": {"invocationId": manifest.digest},
            },
        },
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [
            {
                "digest": {"sha256": verification.wheel_sha256},
                "name": wheel.name,
            }
        ],
    }
    sbom = output / "rextio.preliminary-sbom.json"
    provenance = output / "rextio.preliminary-provenance-input.json"
    _write_exclusive_bytes(sbom, _canonical_json(sbom_document), mode=_CANONICAL_FILE_MODE)
    _write_exclusive_bytes(
        provenance,
        _canonical_json(provenance_document),
        mode=_CANONICAL_FILE_MODE,
    )
    return ReproducibilityBuildOutputs(
        unsigned_wheel=wheel,
        sbom_json=sbom,
        provenance_input_json=provenance,
    )


def _full_c6_extension_suffix() -> str:
    """Return the exact pinned CPython 3.11 extension suffix."""
    if sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 11):
        raise FullC6ExecutorError(
            "Full C6 native Alpha postprocessor requires exact CPython 3.11"
        )
    extension_suffix = sysconfig.get_config_var("EXT_SUFFIX")
    if (
        type(extension_suffix) is not str
        or not extension_suffix
        or PurePosixPath(extension_suffix).name != extension_suffix
        or not extension_suffix.endswith(".so")
    ):
        raise FullC6ExecutorError("Full C6 CPython extension suffix is unavailable")
    return extension_suffix


def _native_cargo_artifact_name(target_triple: str) -> str:
    if target_triple == "aarch64-apple-darwin":
        return "lib_rextio_native.dylib"
    if target_triple == "x86_64-unknown-linux-gnu":
        return "lib_rextio_native.so"
    raise FullC6ExecutorError("Full C6 native Cargo artifact target is unsupported")


def _materialize_frozen_python_staging(tree: _FrozenTree, destination: Path) -> None:
    prefix = PurePosixPath("python-staging")
    root = tuple(
        item
        for item in tree.entries
        if item.public.logical_name == prefix.as_posix()
    )
    if len(root) != 1 or root[0].public.kind != "directory":
        raise FullC6ExecutorError(
            "Full C6 frozen tree is missing exact python-staging directory"
        )
    selected = tuple(
        item
        for item in tree.entries
        if PurePosixPath(item.public.logical_name).is_relative_to(prefix)
        and item.public.logical_name != prefix.as_posix()
    )
    files = tuple(item for item in selected if item.public.kind == "file")
    if not files:
        raise FullC6ExecutorError("Full C6 frozen Python staging is empty")
    if any(
        PurePosixPath(item.public.logical_name).name.startswith("_rextio_native")
        and PurePosixPath(item.public.logical_name).name.endswith((".so", ".dylib", ".dll", ".pyd"))
        for item in files
    ):
        raise FullC6ExecutorError(
            "Full C6 frozen Python staging contains a caller-supplied native extension"
        )
    directories = sorted(
        (item for item in selected if item.public.kind == "directory"),
        key=lambda item: len(PurePosixPath(item.public.logical_name).parts),
    )
    try:
        for item in directories:
            relative = PurePosixPath(item.public.logical_name).relative_to(prefix)
            path = destination.joinpath(*relative.parts)
            path.mkdir(mode=_CANONICAL_DIRECTORY_MODE)
            os.chmod(path, _CANONICAL_DIRECTORY_MODE)
    except OSError as exc:
        raise FullC6ExecutorError("Full C6 Python staging directory could not be copied") from exc
    for item in files:
        relative = PurePosixPath(item.public.logical_name).relative_to(prefix)
        assert item.data is not None
        _write_exclusive_bytes(
            destination.joinpath(*relative.parts),
            item.data,
            mode=item.public.mode,
        )


def _write_exclusive_bytes(path: Path, data: bytes, *, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, mode)
    except OSError as exc:
        raise FullC6ExecutorError("Full C6 output file could not be created safely") from exc
    try:
        os.fchmod(descriptor, mode)
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise FullC6ExecutorError("Full C6 output file write failed")
            view = view[written:]
        os.fsync(descriptor)
        observed = os.fstat(descriptor)
        if (
            not stat.S_ISREG(observed.st_mode)
            or observed.st_nlink != 1
            or observed.st_size != len(data)
        ):
            raise FullC6ExecutorError("Full C6 output file identity is invalid")
    finally:
        os.close(descriptor)


def _preliminary_properties(values: Mapping[str, object]) -> list[dict[str, str]]:
    return [
        {"name": f"rextio:{name}", "value": str(value).lower() if type(value) is bool else str(value)}
        for name, value in sorted(values.items())
    ]


def _validate_executor_arguments(
    *,
    build: FullC6BuildCallback | None,
    cargo_command: Sequence[str] | None,
    command_factory: FullC6BuildCommandFactory | None,
    lock_generator: FullC6LockCallback | None,
    lock_command_factory: FullC6LockCommandFactory | None,
    source_date_epoch: int,
    timeout_seconds: float,
    max_output_bytes: int,
    toolchain: BuildToolchainIdentity | None,
    native_orchestrator: bool,
) -> None:
    if type(native_orchestrator) is not bool:
        raise FullC6ExecutorError("Full C6 native orchestrator flag must be boolean")
    if sum((build is not None, command_factory is not None, native_orchestrator)) != 1:
        raise FullC6ExecutorError(
            "choose exactly one build callback, command factory, or native orchestrator"
        )
    if build is not None:
        if not callable(build) or cargo_command is None:
            raise FullC6ExecutorError("build callback requires one strict Cargo command")
    elif cargo_command is not None:
        raise FullC6ExecutorError("command-factory mode must supply its own Cargo command")
    if toolchain is not None and type(toolchain) is not BuildToolchainIdentity:
        raise FullC6ExecutorError("Full C6 executor toolchain identity is invalid")
    if build is not None and toolchain is not None:
        raise FullC6ExecutorError("callback executor cannot claim a production toolchain")
    if native_orchestrator:
        if type(toolchain) is not BuildToolchainIdentity:
            raise FullC6ExecutorError(
                "Full C6 native orchestrator requires an exact toolchain identity"
            )
        if lock_generator is not None or lock_command_factory is not None:
            raise FullC6ExecutorError(
                "Full C6 native orchestrator requires a pre-generated frozen Cargo.lock"
            )
    for value, label in (
        (lock_generator, "lock generator"),
        (lock_command_factory, "lock command factory"),
    ):
        if value is not None and not callable(value):
            raise FullC6ExecutorError(f"Full C6 {label} is not callable")
    if (
        type(source_date_epoch) is not int
        or isinstance(source_date_epoch, bool)
        or not (0 <= source_date_epoch <= 2_147_483_647)
    ):
        raise FullC6ExecutorError("SOURCE_DATE_EPOCH is outside the allowed bound")
    try:
        _validate_timeout(timeout_seconds)
        _validate_output_bound(max_output_bytes)
    except ValueError as exc:
        raise FullC6ExecutorError(str(exc)) from exc


def _validate_timeout(value: float) -> None:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(value)
        or value <= 0
        or value > MAX_BUILD_TIMEOUT_SECONDS
    ):
        raise ValueError("Full C6 timeout is outside the allowed bound")


def _validate_output_bound(value: int) -> None:
    if (
        type(value) is not int
        or isinstance(value, bool)
        or not (1 <= value <= MAX_FULL_C6_OUTPUT_BYTES)
    ):
        raise ValueError("Full C6 subprocess output bound is invalid")


def _validate_source_root(value: Path | str) -> tuple[Path, os.stat_result]:
    root, observed = _validate_real_directory(value, label="source")
    try:
        if next(root.iterdir(), None) is None:
            raise FullC6ExecutorError("Full C6 source root must not be empty")
    except OSError as exc:
        raise FullC6ExecutorError("Full C6 source root could not be inspected") from exc
    return root, observed


def _validate_quarantine_root(value: Path | str) -> tuple[Path, os.stat_result]:
    root, observed = _validate_real_directory(value, label="quarantine")
    if stat.S_IMODE(observed.st_mode) != _CANONICAL_DIRECTORY_MODE:
        raise FullC6ExecutorError("Full C6 quarantine root must have mode 0700")
    if hasattr(os, "geteuid") and observed.st_uid != os.geteuid():
        raise FullC6ExecutorError("Full C6 quarantine root must be owned by the current user")
    try:
        if next(root.iterdir(), None) is not None:
            raise FullC6ExecutorError("Full C6 quarantine root must be empty")
    except OSError as exc:
        raise FullC6ExecutorError("Full C6 quarantine root could not be inspected") from exc
    return root, observed


def _validate_real_directory(value: Path | str, *, label: str) -> tuple[Path, os.stat_result]:
    candidate = Path(value)
    try:
        _reject_symlink_components(candidate)
        observed = os.lstat(candidate)
    except FileNotFoundError as exc:
        raise FullC6ExecutorError(f"Full C6 {label} root is missing") from exc
    except OSError as exc:
        raise FullC6ExecutorError(f"Full C6 {label} root could not be inspected") from exc
    if stat.S_ISLNK(observed.st_mode) or not stat.S_ISDIR(observed.st_mode):
        raise FullC6ExecutorError(f"Full C6 {label} root must be a real directory")
    try:
        return candidate.resolve(strict=True), observed
    except OSError as exc:
        raise FullC6ExecutorError(f"Full C6 {label} root could not be resolved") from exc


def _require_disjoint_roots(roots: tuple[Path, Path, Path]) -> None:
    if len(set(roots)) != len(roots):
        raise FullC6ExecutorError("Full C6 source and quarantine roots must be distinct")
    for index, root in enumerate(roots):
        for other in roots[index + 1 :]:
            if root in other.parents or other in root.parents:
                raise FullC6ExecutorError("Full C6 source and quarantine roots must not be nested")


def _verify_private_root(root: Path, expected: os.stat_result) -> None:
    try:
        _reject_symlink_components(root)
        observed = os.lstat(root)
    except OSError as exc:
        raise FullC6ExecutorError("Full C6 quarantine root changed") from exc
    if (
        not stat.S_ISDIR(observed.st_mode)
        or stat.S_IMODE(observed.st_mode) != _CANONICAL_DIRECTORY_MODE
        or (observed.st_dev, observed.st_ino) != (expected.st_dev, expected.st_ino)
    ):
        raise FullC6ExecutorError("Full C6 quarantine root changed")


def _verify_project_root(root: Path, expected: os.stat_result) -> None:
    try:
        _reject_symlink_components(root)
        observed = os.lstat(root)
    except OSError as exc:
        raise FullC6ExecutorError("Full C6 materialized project root changed") from exc
    if (
        not stat.S_ISDIR(observed.st_mode)
        or stat.S_IMODE(observed.st_mode) != _CANONICAL_DIRECTORY_MODE
        or (observed.st_dev, observed.st_ino) != (expected.st_dev, expected.st_ino)
    ):
        raise FullC6ExecutorError("Full C6 materialized project root changed")


def _capture_stable_tree(root: Path, *, cargo_lock_generated: bool) -> _FrozenTree:
    first = _capture_tree_once(root, cargo_lock_generated=cargo_lock_generated)
    second = _capture_tree_once(root, cargo_lock_generated=cargo_lock_generated)
    if (
        first.manifest != second.manifest
        or first.entries != second.entries
        or first.root_key != second.root_key
        or first.filesystem_keys != second.filesystem_keys
    ):
        raise FullC6ExecutorError("Full C6 source tree changed during capture")
    return first


def _capture_tree_once(root: Path, *, cargo_lock_generated: bool) -> _FrozenTree:
    try:
        _reject_symlink_components(root)
        root_observed = os.lstat(root)
    except OSError as exc:
        raise FullC6ExecutorError("Full C6 source root changed during capture") from exc
    if not stat.S_ISDIR(root_observed.st_mode):
        raise FullC6ExecutorError("Full C6 source root changed during capture")
    entries: list[_FrozenEntry] = []
    aliases: set[str] = set()
    inode_keys: set[tuple[int, int]] = set()
    filesystem_keys: list[tuple[str, int, int]] = []
    file_count = 0
    total_bytes = 0
    pending: list[tuple[Path, PurePosixPath, os.stat_result]] = [
        (root, PurePosixPath("."), root_observed)
    ]
    while pending:
        directory, relative_directory, expected_directory = pending.pop()
        try:
            before_directory = os.lstat(directory)
            _require_same_directory(expected_directory, before_directory)
            with os.scandir(directory) as iterator:
                children = sorted(iterator, key=lambda item: item.name)
        except OSError as exc:
            raise FullC6ExecutorError("Full C6 source tree could not be enumerated") from exc
        for child in children:
            relative = (
                PurePosixPath(child.name)
                if relative_directory == PurePosixPath(".")
                else relative_directory / child.name
            )
            logical_name = relative.as_posix()
            _validate_relative_name(logical_name)
            alias = unicodedata.normalize("NFC", logical_name).casefold()
            if alias in aliases:
                raise FullC6ExecutorError("Full C6 source tree contains a path alias")
            aliases.add(alias)
            try:
                observed = child.stat(follow_symlinks=False)
            except OSError as exc:
                raise FullC6ExecutorError("Full C6 source member could not be inspected") from exc
            if stat.S_ISLNK(observed.st_mode):
                raise FullC6ExecutorError("Full C6 source tree must not contain symlinks")
            if stat.S_ISDIR(observed.st_mode):
                filesystem_keys.append((logical_name, observed.st_dev, observed.st_ino))
                public = FullC6TreeEntry(
                    logical_name=logical_name,
                    kind="directory",
                    sha256=None,
                    size=0,
                    mode=_CANONICAL_DIRECTORY_MODE,
                )
                entries.append(_FrozenEntry(public=public, data=None))
                pending.append((Path(child.path), relative, observed))
            elif stat.S_ISREG(observed.st_mode):
                if observed.st_nlink != 1:
                    raise FullC6ExecutorError(
                        "Full C6 source tree must not contain shared hardlinks"
                    )
                data, opened = _secure_read_regular(Path(child.path), observed)
                inode_key = (opened.st_dev, opened.st_ino)
                if inode_key in inode_keys:
                    raise FullC6ExecutorError(
                        "Full C6 source tree must not contain shared hardlinks"
                    )
                inode_keys.add(inode_key)
                filesystem_keys.append((logical_name, opened.st_dev, opened.st_ino))
                file_count += 1
                total_bytes += len(data)
                executable = bool(
                    observed.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                )
                public = FullC6TreeEntry(
                    logical_name=logical_name,
                    kind="file",
                    sha256=hashlib.sha256(data).hexdigest(),
                    size=len(data),
                    mode=(
                        _CANONICAL_EXECUTABLE_MODE if executable else _CANONICAL_FILE_MODE
                    ),
                )
                entries.append(_FrozenEntry(public=public, data=data))
            else:
                raise FullC6ExecutorError(
                    "Full C6 source tree contains a non-regular filesystem member"
                )
            if (
                len(entries) > MAX_FULL_C6_TREE_ENTRIES
                or file_count > MAX_FULL_C6_TREE_FILES
                or total_bytes > MAX_FULL_C6_TREE_BYTES
            ):
                raise FullC6ExecutorError("Full C6 source tree exceeds a configured bound")
        try:
            after_directory = os.lstat(directory)
        except OSError as exc:
            raise FullC6ExecutorError("Full C6 source directory changed during capture") from exc
        _require_same_directory(before_directory, after_directory)
    canonical_entries = tuple(sorted(entries, key=lambda item: item.public.logical_name))
    has_lock = any(
        item.public.kind == "file" and item.public.logical_name == "Cargo.lock"
        for item in canonical_entries
    )
    manifest: FullC6FrozenTreeManifest | None = None
    if has_lock:
        try:
            manifest = FullC6FrozenTreeManifest(
                entries=tuple(item.public for item in canonical_entries),
                cargo_lock_generated=cargo_lock_generated,
            )
        except (TypeError, ValueError) as exc:
            raise FullC6ExecutorError(str(exc)) from exc
    elif not any(
        item.public.kind == "file" and item.public.logical_name == "Cargo.toml"
        for item in canonical_entries
    ):
        raise FullC6ExecutorError("Full C6 tree must contain exact Cargo.toml")
    return _FrozenTree(
        manifest=manifest,
        entries=canonical_entries,
        cargo_lock_generated=cargo_lock_generated,
        root_key=(root_observed.st_dev, root_observed.st_ino),
        filesystem_keys=tuple(sorted(filesystem_keys)),
    )


def _secure_read_regular(path: Path, before: os.stat_result) -> tuple[bytes, os.stat_result]:
    if before.st_size < 0 or before.st_size > MAX_FULL_C6_FILE_BYTES:
        raise FullC6ExecutorError("Full C6 source file exceeds the byte bound")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if sys.platform == "win32" and hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise FullC6ExecutorError("Full C6 source file could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        _require_same_regular(before, opened)
        chunks: list[bytes] = []
        remaining = MAX_FULL_C6_FILE_BYTES + 1
        while remaining > 0:
            try:
                chunk = os.read(descriptor, min(65536, remaining))
            except BlockingIOError as exc:
                raise FullC6ExecutorError("Full C6 source file could not be read safely") from exc
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        _require_same_regular(opened, after)
        if len(data) != after.st_size or len(data) > MAX_FULL_C6_FILE_BYTES:
            raise FullC6ExecutorError("Full C6 source file changed during capture")
    finally:
        os.close(descriptor)
    try:
        final = os.lstat(path)
    except OSError as exc:
        raise FullC6ExecutorError("Full C6 source file changed during capture") from exc
    _require_same_regular(opened, final)
    return data, opened


def _require_same_regular(earlier: os.stat_result, later: os.stat_result) -> None:
    if not stat.S_ISREG(later.st_mode) or later.st_nlink != 1:
        raise FullC6ExecutorError("Full C6 source file changed or is hardlinked")
    if (earlier.st_dev, earlier.st_ino, earlier.st_size) != (
        later.st_dev,
        later.st_ino,
        later.st_size,
    ):
        raise FullC6ExecutorError("Full C6 source file changed during capture")
    for field in ("st_mtime_ns", "st_ctime_ns"):
        if hasattr(earlier, field) and getattr(earlier, field) != getattr(later, field):
            raise FullC6ExecutorError("Full C6 source file changed during capture")


def _require_same_directory(earlier: os.stat_result, later: os.stat_result) -> None:
    if not stat.S_ISDIR(later.st_mode) or (earlier.st_dev, earlier.st_ino) != (
        later.st_dev,
        later.st_ino,
    ):
        raise FullC6ExecutorError("Full C6 source directory changed during capture")
    for field in ("st_mtime_ns", "st_ctime_ns"):
        if hasattr(earlier, field) and getattr(earlier, field) != getattr(later, field):
            raise FullC6ExecutorError("Full C6 source directory changed during capture")


def _assert_source_unchanged(source: Path, expected: _FrozenTree) -> None:
    observed = _capture_stable_tree(
        source,
        cargo_lock_generated=expected.cargo_lock_generated,
    )
    if (
        observed.manifest != expected.manifest
        or observed.entries != expected.entries
        or observed.root_key != expected.root_key
        or observed.filesystem_keys != expected.filesystem_keys
    ):
        raise FullC6ExecutorError("Full C6 source tree changed after it was frozen")


def _with_generated_lock(tree: _FrozenTree, lock_data: bytes) -> _FrozenTree:
    if not lock_data or len(lock_data) > MAX_FULL_C6_FILE_BYTES:
        raise FullC6ExecutorError("generated Cargo.lock is empty or exceeds the byte bound")
    lock = _FrozenEntry(
        public=FullC6TreeEntry(
            logical_name="Cargo.lock",
            kind="file",
            sha256=hashlib.sha256(lock_data).hexdigest(),
            size=len(lock_data),
            mode=_CANONICAL_FILE_MODE,
        ),
        data=lock_data,
    )
    entries = tuple(sorted((*tree.entries, lock), key=lambda item: item.public.logical_name))
    try:
        return _FrozenTree(
            manifest=FullC6FrozenTreeManifest(
                entries=tuple(item.public for item in entries),
                cargo_lock_generated=True,
            ),
            entries=entries,
            cargo_lock_generated=True,
            root_key=tree.root_key,
            filesystem_keys=tree.filesystem_keys,
        )
    except (TypeError, ValueError) as exc:
        raise FullC6ExecutorError(str(exc)) from exc


def _generate_lock(
    tree: _FrozenTree,
    quarantine_root: Path,
    *,
    root_stat: os.stat_result,
    environment_seed: dict[str, str],
    source_date_epoch: int,
    timeout_seconds: float,
    max_output_bytes: int,
    callback: FullC6LockCallback | None,
    command_factory: FullC6LockCommandFactory | None,
) -> bytes:
    staging = quarantine_root / ".rextio-lock-generation"
    try:
        staging.mkdir(mode=_CANONICAL_DIRECTORY_MODE)
        os.chmod(staging, _CANONICAL_DIRECTORY_MODE)
        project_root, _inode_keys = _materialize_project(staging, tree)
        staging_identity = os.lstat(staging)
        project_identity = os.lstat(project_root)
        environment = _build_environment(
            staging,
            project_root,
            environment_seed,
            source_date_epoch=source_date_epoch,
        )
        fixed = ("cargo", "generate-lockfile", "--offline")
        request = FullC6LockGenerationRequest(
            quarantine_root=staging,
            project_root=project_root,
            cargo_argv=fixed,
            environment=tuple(sorted(environment.items())),
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
        started = time.monotonic()
        if callback is not None:
            callback(request)
        else:
            assert command_factory is not None
            spec = command_factory(request)
            if type(spec) is not FullC6LockCommand:
                raise FullC6ExecutorError("lock command factory returned an invalid command")
            argv = _require_offline_lock_command(spec.argv)
            completed = run_build_tool(
                list(argv),
                cwd=project_root,
                timeout=timeout_seconds,
                env=environment,
                inherit_env=False,
                max_output_bytes=max_output_bytes,
            )
            if completed.returncode != 0:
                raise FullC6ExecutorError(
                    f"offline Cargo.lock generation failed with exit status {completed.returncode}"
                )
        if time.monotonic() - started > timeout_seconds:
            raise FullC6ExecutorError("Cargo.lock generator exceeded its timeout bound")
        _verify_private_root(staging, staging_identity)
        _verify_project_root(project_root, project_identity)
        generated = _capture_stable_tree(project_root, cargo_lock_generated=True)
        _verify_project_root(project_root, project_identity)
        expected = _with_generated_lock(tree, _entry_data(generated, "Cargo.lock"))
        if generated.manifest != expected.manifest or generated.entries != expected.entries:
            raise FullC6ExecutorError("Cargo.lock generation changed files outside Cargo.lock")
        return _entry_data(generated, "Cargo.lock")
    except FullC6ExecutorError:
        raise
    except Exception as exc:
        raise FullC6ExecutorError("Cargo.lock generation callback failed") from exc
    finally:
        try:
            if staging.exists() or staging.is_symlink():
                shutil.rmtree(staging)
        except OSError as exc:
            raise FullC6ExecutorError("Cargo.lock staging could not be removed safely") from exc
        _verify_private_root(quarantine_root, root_stat)
        try:
            if next(quarantine_root.iterdir(), None) is not None:
                raise FullC6ExecutorError("Cargo.lock generation escaped its private staging root")
        except OSError as exc:
            raise FullC6ExecutorError("Cargo.lock quarantine root could not be verified") from exc


def _entry_data(tree: _FrozenTree, logical_name: str) -> bytes:
    for entry in tree.entries:
        if entry.public.logical_name == logical_name and entry.public.kind == "file":
            assert entry.data is not None
            return entry.data
    raise FullC6ExecutorError(f"generated tree is missing exact {logical_name}")


def _materialize_build_root(root: Path, tree: _FrozenTree) -> tuple[Path, frozenset[tuple[int, int]]]:
    return _materialize_project(root, tree)


def _materialize_project(root: Path, tree: _FrozenTree) -> tuple[Path, frozenset[tuple[int, int]]]:
    project = root / "project"
    try:
        project.mkdir(mode=_CANONICAL_DIRECTORY_MODE)
        os.chmod(project, _CANONICAL_DIRECTORY_MODE)
        directories = sorted(
            (item for item in tree.entries if item.public.kind == "directory"),
            key=lambda item: len(PurePosixPath(item.public.logical_name).parts),
        )
        for entry in directories:
            path = project.joinpath(*PurePosixPath(entry.public.logical_name).parts)
            path.mkdir(mode=_CANONICAL_DIRECTORY_MODE)
            os.chmod(path, _CANONICAL_DIRECTORY_MODE)
        inode_keys: set[tuple[int, int]] = set()
        for entry in (item for item in tree.entries if item.public.kind == "file"):
            path = project.joinpath(*PurePosixPath(entry.public.logical_name).parts)
            assert entry.data is not None
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(path, flags, entry.public.mode)
            try:
                os.fchmod(descriptor, entry.public.mode)
                view = memoryview(entry.data)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise FullC6ExecutorError("Full C6 project copy could not be written")
                    view = view[written:]
                os.fsync(descriptor)
                observed = os.fstat(descriptor)
                if not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1:
                    raise FullC6ExecutorError("Full C6 project copy is not an independent file")
                inode_keys.add((observed.st_dev, observed.st_ino))
            finally:
                os.close(descriptor)
        _verify_materialized_tree(project, tree)
        return project, frozenset(inode_keys)
    except FullC6ExecutorError:
        raise
    except OSError as exc:
        raise FullC6ExecutorError("Full C6 project tree could not be materialized safely") from exc


def _verify_materialized_tree(project: Path, expected: _FrozenTree) -> None:
    observed = _capture_stable_tree(
        project,
        cargo_lock_generated=expected.cargo_lock_generated,
    )
    if observed.manifest != expected.manifest or observed.entries != expected.entries:
        raise FullC6ExecutorError("Full C6 materialized project tree changed")


def _verify_outputs_are_independent(
    build_root: Path,
    project_root: Path,
    outputs: ReproducibilityBuildOutputs,
) -> None:
    inodes: set[tuple[int, int]] = set()
    for output in (
        outputs.unsigned_wheel,
        outputs.sbom_json,
        outputs.provenance_input_json,
    ):
        candidate = Path(output)
        try:
            _reject_symlink_components(candidate)
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(build_root)
            if resolved == project_root or project_root in resolved.parents:
                raise FullC6ExecutorError("Full C6 outputs must be outside the frozen project")
            observed = os.lstat(candidate)
        except ValueError as exc:
            raise FullC6ExecutorError("Full C6 output escaped its private build root") from exc
        except OSError as exc:
            raise FullC6ExecutorError("Full C6 output could not be inspected") from exc
        if not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1:
            raise FullC6ExecutorError("Full C6 output must be an independent regular file")
        key = (observed.st_dev, observed.st_ino)
        if key in inodes:
            raise FullC6ExecutorError("Full C6 outputs must not share hardlinks")
        inodes.add(key)


def _build_environment(
    root: Path,
    project: Path,
    seed: dict[str, str],
    *,
    source_date_epoch: int,
) -> dict[str, str]:
    directories = {
        "HOME": root / "home",
        "CARGO_HOME": root / "cargo-home",
        "CARGO_TARGET_DIR": root / "target",
    }
    for path in directories.values():
        path.mkdir(mode=_CANONICAL_DIRECTORY_MODE)
        os.chmod(path, _CANONICAL_DIRECTORY_MODE)
    remaps = (
        f"--remap-path-prefix={project}={_PROJECT_ROOT_TOKEN}",
        f"--remap-path-prefix={root}={_BUILD_ROOT_TOKEN}",
    )
    environment = dict(seed)
    environment.update(
        {
            "CARGO_ENCODED_RUSTFLAGS": "\x1f".join(remaps),
            "CARGO_HOME": str(directories["CARGO_HOME"]),
            "CARGO_NET_OFFLINE": "true",
            "CARGO_TARGET_DIR": str(directories["CARGO_TARGET_DIR"]),
            "HOME": str(directories["HOME"]),
            "LANG": "C",
            "LC_ALL": "C",
            "PYTHONHASHSEED": "0",
            "SOURCE_DATE_EPOCH": str(source_date_epoch),
            "TZ": "UTC",
        }
    )
    return environment


def _validate_base_environment(value: Mapping[str, str] | None) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise FullC6ExecutorError("Full C6 base environment must be a mapping")
    result: dict[str, str] = {}
    for name, item in value.items():
        if type(name) is not str or type(item) is not str:
            raise FullC6ExecutorError("Full C6 environment names and values must be strings")
        upper = name.upper()
        if name != upper or upper not in _EXECUTOR_ENV_ALLOWLIST:
            raise FullC6ExecutorError("Full C6 environment name is outside the allowlist")
        if upper in _RESERVED_ENV:
            raise FullC6ExecutorError("Full C6 caller cannot override an executor-owned variable")
        if upper in _FORBIDDEN_ENV or upper.endswith("_PROXY") or "WRAPPER" in upper:
            raise FullC6ExecutorError("Full C6 proxy or compiler-wrapper environment is forbidden")
        encoded = item.encode("utf-8")
        if not item or "\0" in item or len(encoded) > 64 * 1024:
            raise FullC6ExecutorError("Full C6 environment value is invalid")
        result[name] = item
    return result


def _require_prestrict_build_command(value: Sequence[str]) -> tuple[str, ...]:
    argv = tuple(value)
    try:
        canonical = enforce_strict_cargo_command(argv, strict=True)
    except (StrictCargoCommandError, TypeError, ValueError) as exc:
        raise FullC6ExecutorError(str(exc)) from exc
    if canonical != argv:
        raise FullC6ExecutorError(
            "strict Cargo command must already contain one canonical --locked/--offline/--frozen set"
        )
    if Path(argv[0]).name not in {"cargo", "cargo.exe"} or argv[1] != "build":
        raise FullC6ExecutorError("Full C6 executor supports only the Cargo build subcommand")
    if "--" in argv or any(any(ord(character) < 32 for character in item) for item in argv):
        raise FullC6ExecutorError("strict Cargo command contains an unsafe argument")
    forbidden = {
        "--artifact-dir",
        "--config",
        "--lockfile-path",
        "--manifest-path",
        "--out-dir",
        "--target-dir",
        "-Z",
    }
    if any(item in forbidden or any(item.startswith(f"{flag}=") for flag in forbidden) for item in argv):
        raise FullC6ExecutorError("strict Cargo command contains a boundary-changing argument")
    return argv


def _require_exact_native_cargo_command(value: Sequence[str]) -> tuple[str, ...]:
    """Require the frozen Alpha driver's sole Cargo command shape."""
    argv = _require_prestrict_build_command(value)
    if argv[1:] != (
        "build",
        "--release",
        "--locked",
        "--offline",
        "--frozen",
    ):
        raise FullC6ExecutorError(
            "Full C6 native driver command must be exactly "
            "cargo build --release --locked --offline --frozen"
        )
    return argv


def _require_offline_lock_command(value: Sequence[str]) -> tuple[str, ...]:
    argv = tuple(value)
    if (
        len(argv) != 3
        or not all(type(item) is str for item in argv)
        or Path(argv[0]).name not in {"cargo", "cargo.exe"}
        or argv[1:] != ("generate-lockfile", "--offline")
    ):
        raise FullC6ExecutorError(
            "lock command must be exactly cargo generate-lockfile --offline"
        )
    return argv


def _reject_private_argv(argv: tuple[str, ...], *, source: Path, roots: tuple[Path, Path]) -> None:
    private = tuple(str(item) for item in (source, *roots))
    if any(any(path and path in argument for path in private) for argument in argv):
        raise FullC6ExecutorError("strict Cargo argv must not embed private workspace paths")


def _invocation_receipt(
    ordinal: int,
    argv: tuple[str, ...],
    environment: dict[str, str],
    *,
    timeout_seconds: float,
    max_output_bytes: int,
) -> FullC6InvocationReceipt:
    bindings = tuple(
        FullC6EnvironmentBinding(
            name=name,
            value_sha256=hashlib.sha256(value.encode("utf-8")).hexdigest(),
            value_size=len(value.encode("utf-8")),
        )
        for name, value in sorted(environment.items())
    )
    try:
        return FullC6InvocationReceipt(
            ordinal=ordinal,
            argv_sha256=hashlib.sha256(_canonical_json(list(argv))).hexdigest(),
            argv_count=len(argv),
            environment=bindings,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
    except (TypeError, ValueError) as exc:
        raise FullC6ExecutorError(str(exc)) from exc


def _verify_native_toolchain_invocation(
    argv: tuple[str, ...],
    *,
    environment: Mapping[str, str],
    toolchain: BuildToolchainIdentity,
) -> None:
    """Bind the internally launched argv to the captured Cargo executable."""
    if argv != toolchain.argv.values:
        raise FullC6ExecutorError("Full C6 executor argv differs from toolchain identity")
    executable_text = argv[0]
    if "/" in executable_text or (os.altsep is not None and os.altsep in executable_text):
        executable = Path(executable_text)
    else:
        resolved = shutil.which(executable_text, path=environment.get("PATH"))
        if resolved is None:
            raise FullC6ExecutorError("Full C6 Cargo executable cannot be resolved")
        executable = Path(resolved)
    try:
        executable = executable.resolve(strict=True)
        verify_tool_identity(executable, toolchain.cargo)
    except (OSError, ToolchainIdentityError) as exc:
        raise FullC6ExecutorError(
            "Full C6 Cargo executable differs from toolchain identity"
        ) from exc


def _require_sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"Full C6 {label} digest is invalid")
    return value


def _validate_relative_name(value: str) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise ValueError("Full C6 relative path is invalid")
    if len(value) > MAX_FULL_C6_PATH_CHARS or "\\" in value or "\0" in value:
        raise ValueError("Full C6 relative path is invalid")
    if value != unicodedata.normalize("NFC", value):
        raise ValueError("Full C6 relative path must be NFC-normalized")
    if any(ord(character) < 32 for character in value):
        raise ValueError("Full C6 relative path is invalid")
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if (
        posix.is_absolute()
        or windows.is_absolute()
        or not posix.parts
        or len(posix.parts) > MAX_FULL_C6_PATH_DEPTH
        or any(part in {"", ".", ".."} or len(part) > 255 for part in posix.parts)
        or ".." in windows.parts
    ):
        raise ValueError("Full C6 relative path is outside the allowed bounds")


def _reject_symlink_components(value: Path) -> None:
    absolute = value.absolute()
    for component in reversed((absolute, *absolute.parents)):
        try:
            observed = os.lstat(component)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(observed.st_mode):
            raise FullC6ExecutorError("Full C6 path contains a symlink component")


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


__all__ = [
    "FULL_C6_CALLBACK_EXECUTION_DRIVER",
    "FULL_C6_CALLBACK_LOCK_DRIVER",
    "FULL_C6_EXECUTOR_DOMAIN",
    "FULL_C6_EXECUTOR_SCOPE",
    "FULL_C6_NATIVE_DRIVER_DOMAIN",
    "FULL_C6_NATIVE_DRIVER_MANIFEST",
    "FULL_C6_NATIVE_EXECUTION_DRIVER",
    "FULL_C6_NATIVE_LOCK_DRIVER",
    "FULL_C6_NATIVE_POSTPROCESSOR",
    "FULL_C6_PREEXISTING_LOCK_DRIVER",
    "FULL_C6_UNBOUND_EXECUTION_DRIVER",
    "FullC6BuildCommand",
    "FullC6BuildContext",
    "FullC6BuildRequest",
    "FullC6EnvironmentBinding",
    "FullC6ExecutorError",
    "FullC6ExecutorReceipt",
    "FullC6FrozenTreeManifest",
    "FullC6InvocationReceipt",
    "FullC6LockCommand",
    "FullC6LockGenerationRequest",
    "FullC6TreeEntry",
    "FullC6NativeDriverManifest",
    "MAX_FULL_C6_FILE_BYTES",
    "MAX_FULL_C6_OUTPUT_BYTES",
    "MAX_FULL_C6_PATH_DEPTH",
    "MAX_FULL_C6_TREE_BYTES",
    "MAX_FULL_C6_TREE_ENTRIES",
    "execute_full_c6_two_build",
    "execute_full_c6_native_two_build",
    "full_c6_native_driver_manifest_bytes",
]
