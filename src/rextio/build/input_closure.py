"""Fail-closed, immutable build-input identities for bounded artifact build work.

This module is deliberately independent from artifact evidence and build
orchestration.  It captures exact regular-file bytes through one no-follow
descriptor and exposes only canonical logical identities; callers retain the
local path separately and must reverify immediately before each trust-boundary
transition.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import TYPE_CHECKING, Mapping, Sequence

from rextio.artifacts.contract_dialects import (
    CARGO_METADATA_SET_DOMAIN,
    CARGO_PACKAGE_RECEIPTS_DOMAIN,
    CARGO_PACKAGE_SET_DOMAIN,
    CURRENT,
)

if TYPE_CHECKING:
    from rextio.build.full_c6_cargo_workspace import (
        FullC6CargoDependencyWorkspaceReceipt,
    )


MAX_BUILD_INPUT_BYTES = 64 * 1024 * 1024
MAX_TOOLCHAIN_EXECUTABLE_BYTES = 512 * 1024 * 1024
MAX_BUILD_INPUT_NAME_CHARS = 512
MAX_BUILD_INPUT_FILES = 1024
MAX_BUILD_INPUT_TOTAL_BYTES = 256 * 1024 * 1024
MAX_BUILD_INPUT_AGGREGATES = 64
MAX_BUILD_INPUT_AGGREGATE_MEMBERS = 1_000_000
MAX_BUILD_INPUT_AGGREGATE_ID_CHARS = 256
BUILD_INPUT_CLOSURE_DOMAIN = "rextio.build-input-closure.v1"
BUILD_INPUT_CLOSURE_SCOPE = (
    "host-extension-wheel-cpython-external-source-depth1-plugin-free-v1"
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_LOGICAL_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._+@=-]*$")
_ROLE_RE = re.compile(r"^[a-z][a-z0-9-]{0,127}$")
_AGGREGATE_ID_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._+@=-]*$")

FULL_C6_CARGO_PACKAGE_SET_DOMAIN = CURRENT.string_value(CARGO_PACKAGE_SET_DOMAIN)
FULL_C6_CARGO_PACKAGE_RECEIPTS_DOMAIN = (
    CURRENT.string_value(CARGO_PACKAGE_RECEIPTS_DOMAIN)
)
FULL_C6_CARGO_METADATA_SET_DOMAIN = CURRENT.string_value(CARGO_METADATA_SET_DOMAIN)
FULL_C6_CARGO_INPUT_AGGREGATE_IDS = frozenset(
    {
        "artifact-evidence-cargo-workspace",
        "artifact-evidence-cargo-sources",
        "artifact-evidence-cargo-vendor-tree",
        "artifact-evidence-cargo-executor-config",
        "artifact-evidence-cargo-package-set",
        "artifact-evidence-cargo-package-receipts",
        "artifact-evidence-cargo-metadata-set",
    }
)


class BuildInputIdentityError(RuntimeError):
    """A build input could not be captured or no longer matches its receipt."""


@dataclass(frozen=True, slots=True)
class BuildInputAggregateIdentity:
    """One exact digest-only identity for a bounded non-file input aggregate.

    The row is intentionally not represented as a synthetic file.  ``digest``
    binds the aggregate's documented producer-domain preimage, while the
    optional ``metadata_digest`` can bind a related canonical metadata set.
    """

    aggregate_id: str
    kind: str
    digest: str
    member_count: int
    metadata_digest: str | None = None

    def __post_init__(self) -> None:
        if (
            type(self.aggregate_id) is not str
            or not self.aggregate_id
            or self.aggregate_id != self.aggregate_id.strip()
            or len(self.aggregate_id) > MAX_BUILD_INPUT_AGGREGATE_ID_CHARS
            or _AGGREGATE_ID_RE.fullmatch(self.aggregate_id) is None
        ):
            raise ValueError("build-input aggregate id is invalid")
        if type(self.kind) is not str or _ROLE_RE.fullmatch(self.kind) is None:
            raise ValueError("build-input aggregate kind is invalid")
        if type(self.digest) is not str or _SHA256_RE.fullmatch(self.digest) is None:
            raise ValueError("build-input aggregate digest is invalid")
        if (
            type(self.member_count) is not int
            or isinstance(self.member_count, bool)
            or not 0 <= self.member_count <= MAX_BUILD_INPUT_AGGREGATE_MEMBERS
        ):
            raise ValueError("build-input aggregate member count is outside the bound")
        if self.metadata_digest is not None and (
            type(self.metadata_digest) is not str
            or _SHA256_RE.fullmatch(self.metadata_digest) is None
        ):
            raise ValueError("build-input aggregate metadata digest is invalid")

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic digest-only aggregate identity."""
        payload: dict[str, object] = {
            "aggregate_id": self.aggregate_id,
            "kind": self.kind,
            "digest": self.digest,
            "member_count": self.member_count,
        }
        if self.metadata_digest is not None:
            payload["metadata_digest"] = self.metadata_digest
        return payload


@dataclass(frozen=True, slots=True)
class ExactFileIdentity:
    """Canonical content identity for one local regular file.

    Absolute paths, inode numbers, timestamps, and other machine-private
    details are intentionally excluded from the serializable receipt.
    """

    logical_name: str
    role: str
    sha256: str
    size: int
    executable: bool

    def __post_init__(self) -> None:
        _validate_logical_name(self.logical_name)
        if type(self.role) is not str or _ROLE_RE.fullmatch(self.role) is None:
            raise ValueError("build-input role is invalid")
        if type(self.sha256) is not str or _SHA256_RE.fullmatch(self.sha256) is None:
            raise ValueError("build-input SHA-256 is invalid")
        if type(self.size) is not int or isinstance(self.size, bool):
            raise TypeError("build-input size must be an integer")
        maximum_size = (
            MAX_TOOLCHAIN_EXECUTABLE_BYTES
            if self.role == "toolchain-executable"
            else MAX_BUILD_INPUT_BYTES
        )
        if self.size < 0 or self.size > maximum_size:
            raise ValueError("build-input size is outside the allowed range")
        if type(self.executable) is not bool:
            raise TypeError("build-input executable flag must be boolean")

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic, path-sanitized receipt shape."""
        return {
            "logical_name": self.logical_name,
            "role": self.role,
            "sha256": self.sha256,
            "size": self.size,
            "executable": self.executable,
        }


@dataclass(frozen=True, slots=True)
class InputFileSpec:
    """Private path plus the public identity labels used to capture one input."""

    path: Path
    logical_name: str
    role: str
    require_executable: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", Path(self.path))
        _validate_logical_name(self.logical_name)
        if type(self.role) is not str or _ROLE_RE.fullmatch(self.role) is None:
            raise ValueError("build-input role is invalid")
        if type(self.require_executable) is not bool:
            raise TypeError("build-input executable requirement must be boolean")


@dataclass(frozen=True, slots=True)
class BuildInputClosure:
    """Canonical exact-file closure for one deliberately bounded build scope."""

    files: tuple[ExactFileIdentity, ...]
    domain: str = BUILD_INPUT_CLOSURE_DOMAIN
    scope: str = BUILD_INPUT_CLOSURE_SCOPE
    complete_for_scope: bool = True
    aggregates: tuple[BuildInputAggregateIdentity, ...] = ()

    def __post_init__(self) -> None:
        if self.domain != BUILD_INPUT_CLOSURE_DOMAIN:
            raise ValueError("build-input closure domain is invalid")
        if self.scope != BUILD_INPUT_CLOSURE_SCOPE:
            raise ValueError("build-input closure scope is invalid")
        if self.complete_for_scope is not True:
            raise ValueError("build-input closure must be complete for its bounded scope")
        files = tuple(self.files)
        if not files or len(files) > MAX_BUILD_INPUT_FILES:
            raise ValueError("build-input closure file count is outside the allowed range")
        if not all(type(item) is ExactFileIdentity for item in files):
            raise TypeError("build-input closure files have an invalid type")
        canonical = tuple(sorted(files, key=lambda item: (item.role, item.logical_name)))
        if files != canonical:
            raise ValueError("build-input closure files are not in canonical order")
        aliases = [_logical_alias(item.logical_name) for item in files]
        if len(aliases) != len(set(aliases)):
            raise ValueError("build-input closure contains a logical path alias")
        if sum(item.size for item in files) > MAX_BUILD_INPUT_TOTAL_BYTES:
            raise ValueError("build-input closure exceeds the aggregate byte bound")
        aggregates = tuple(self.aggregates)
        if len(aggregates) > MAX_BUILD_INPUT_AGGREGATES:
            raise ValueError("build-input aggregate count exceeds the bound")
        if not all(type(item) is BuildInputAggregateIdentity for item in aggregates):
            raise TypeError("build-input closure aggregates have an invalid type")
        canonical_aggregates = tuple(
            sorted(aggregates, key=lambda item: (item.kind, item.aggregate_id))
        )
        if aggregates != canonical_aggregates:
            raise ValueError("build-input closure aggregates are not in canonical order")
        aggregate_aliases = [
            unicodedata.normalize("NFC", item.aggregate_id).casefold()
            for item in aggregates
        ]
        if len(aggregate_aliases) != len(set(aggregate_aliases)):
            raise ValueError("build-input closure contains an aggregate id alias")
        object.__setattr__(self, "files", files)
        object.__setattr__(self, "aggregates", aggregates)

    @property
    def digest(self) -> str:
        """SHA-256 of the canonical receipt payload (excluding the digest itself)."""
        return hashlib.sha256(_canonical_json(self._payload())).hexdigest()

    def _payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "domain": self.domain,
            "scope": self.scope,
            "complete_for_scope": True,
            "files": [item.to_dict() for item in self.files],
        }
        # Preserve the byte-for-byte v1 receipt and digest for legacy closures.
        # Aggregate-aware closures bind their non-file identities explicitly.
        if self.aggregates:
            payload["aggregates"] = [item.to_dict() for item in self.aggregates]
        return payload

    def to_dict(self) -> dict[str, object]:
        """Return the canonical receipt plus its semantic digest."""
        return {**self._payload(), "digest": self.digest}


def capture_exact_file(
    path: Path | str,
    *,
    logical_name: str,
    role: str,
    require_executable: bool = False,
    max_bytes: int = MAX_BUILD_INPUT_BYTES,
) -> ExactFileIdentity:
    """Capture one exact non-symlink regular file through a pinned descriptor."""
    identity, _data = capture_exact_file_bytes(
        path,
        logical_name=logical_name,
        role=role,
        require_executable=require_executable,
        max_bytes=max_bytes,
    )
    return identity


def capture_exact_file_bytes(
    path: Path | str,
    *,
    logical_name: str,
    role: str,
    require_executable: bool = False,
    max_bytes: int = MAX_BUILD_INPUT_BYTES,
) -> tuple[ExactFileIdentity, bytes]:
    """Return one exact identity and the same securely-read immutable bytes."""
    _validate_logical_name(logical_name)
    if _ROLE_RE.fullmatch(role) is None:
        raise BuildInputIdentityError("build-input role is invalid")
    if type(max_bytes) is not int or isinstance(max_bytes, bool) or not (1 <= max_bytes <= MAX_BUILD_INPUT_BYTES):
        raise BuildInputIdentityError("build-input byte bound is invalid")

    candidate = Path(path)
    try:
        before = os.lstat(candidate)
    except FileNotFoundError as exc:
        raise BuildInputIdentityError("build input is missing") from exc
    except OSError as exc:
        raise BuildInputIdentityError("build input could not be inspected") from exc
    if stat.S_ISLNK(before.st_mode):
        raise BuildInputIdentityError("build input must not be a symlink")
    if not stat.S_ISREG(before.st_mode):
        raise BuildInputIdentityError("build input must be a regular file")
    if before.st_size < 0 or before.st_size > max_bytes:
        raise BuildInputIdentityError("build input exceeds the byte bound")
    executable = bool(before.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
    if require_executable and not executable:
        raise BuildInputIdentityError("toolchain input is not executable")

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if sys.platform == "win32" and hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        fd = os.open(candidate, flags)
    except OSError as exc:
        raise BuildInputIdentityError("build input could not be opened safely") from exc
    try:
        opened = os.fstat(fd)
        _require_same_regular_file(before, opened, "changed during open")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            try:
                chunk = os.read(fd, min(65536, remaining))
            except BlockingIOError as exc:
                raise BuildInputIdentityError("build input could not be read safely") from exc
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > max_bytes:
            raise BuildInputIdentityError("build input exceeds the byte bound")
        after = os.fstat(fd)
        _require_same_regular_file(opened, after, "changed during read")
        if after.st_size != len(data):
            raise BuildInputIdentityError("build input changed during read")
    finally:
        os.close(fd)

    return (
        ExactFileIdentity(
            logical_name=logical_name,
            role=role,
            sha256=hashlib.sha256(data).hexdigest(),
            size=len(data),
            executable=executable,
        ),
        data,
    )


def _capture_streamed_toolchain_executable(
    path: Path | str,
    *,
    logical_name: str,
) -> ExactFileIdentity:
    """Capture one bounded executable identity without retaining its bytes."""
    _validate_logical_name(logical_name)
    candidate = Path(path)
    try:
        before = os.lstat(candidate)
    except FileNotFoundError as exc:
        raise BuildInputIdentityError("build input is missing") from exc
    except OSError as exc:
        raise BuildInputIdentityError("build input could not be inspected") from exc
    if stat.S_ISLNK(before.st_mode):
        raise BuildInputIdentityError("build input must not be a symlink")
    if not stat.S_ISREG(before.st_mode):
        raise BuildInputIdentityError("build input must be a regular file")
    if before.st_size < 0 or before.st_size > MAX_TOOLCHAIN_EXECUTABLE_BYTES:
        raise BuildInputIdentityError("build input exceeds the byte bound")
    executable = bool(before.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
    if not executable:
        raise BuildInputIdentityError("toolchain input is not executable")

    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if type(nofollow) is not int or nofollow == 0:
        raise BuildInputIdentityError(
            "toolchain input no-follow capture is unavailable"
        )
    flags = os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if sys.platform == "win32" and hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        fd = os.open(candidate, flags)
    except OSError as exc:
        raise BuildInputIdentityError("build input could not be opened safely") from exc
    try:
        opened = os.fstat(fd)
        _require_same_regular_file(before, opened, "changed during open")
        digest = hashlib.sha256()
        remaining = opened.st_size
        size = 0
        while remaining:
            try:
                chunk = os.read(fd, min(1024 * 1024, remaining))
            except OSError as exc:
                raise BuildInputIdentityError(
                    "build input could not be read safely"
                ) from exc
            if not chunk:
                raise BuildInputIdentityError("build input changed during read")
            digest.update(chunk)
            size += len(chunk)
            remaining -= len(chunk)
        try:
            grew = os.read(fd, 1)
        except OSError as exc:
            raise BuildInputIdentityError(
                "build input could not be read safely"
            ) from exc
        if grew:
            raise BuildInputIdentityError("build input changed during read")
        after = os.fstat(fd)
        _require_same_regular_file(opened, after, "changed during read")
        if size != after.st_size:
            raise BuildInputIdentityError("build input changed during read")
        try:
            linked = os.lstat(candidate)
        except OSError as exc:
            raise BuildInputIdentityError("build input changed during read") from exc
        _require_same_regular_file(after, linked, "path changed during read")
    finally:
        os.close(fd)

    return ExactFileIdentity(
        logical_name=logical_name,
        role="toolchain-executable",
        sha256=digest.hexdigest(),
        size=size,
        executable=True,
    )


def verify_exact_file(
    path: Path | str,
    expected: ExactFileIdentity,
    *,
    max_bytes: int = MAX_BUILD_INPUT_BYTES,
) -> None:
    """Fail unless a fresh secure capture exactly matches ``expected``."""
    if type(expected) is not ExactFileIdentity:
        raise BuildInputIdentityError("expected build-input receipt has an invalid type")
    observed = capture_exact_file(
        path,
        logical_name=expected.logical_name,
        role=expected.role,
        require_executable=expected.executable,
        max_bytes=max_bytes,
    )
    if observed != expected:
        raise BuildInputIdentityError("build input changed after capture")


def capture_build_input_closure(
    specs: tuple[InputFileSpec, ...] | list[InputFileSpec],
) -> BuildInputClosure:
    """Securely capture and canonically order one exact bounded input set."""
    items = tuple(specs)
    if not items or len(items) > MAX_BUILD_INPUT_FILES:
        raise BuildInputIdentityError("build-input closure file count is outside the bound")
    if not all(type(item) is InputFileSpec for item in items):
        raise BuildInputIdentityError("build-input closure specifications are invalid")
    aliases = [_logical_alias(item.logical_name) for item in items]
    if len(aliases) != len(set(aliases)):
        raise BuildInputIdentityError("build-input closure contains a logical path alias")
    captured = tuple(
        sorted(
            (
                capture_exact_file(
                    item.path,
                    logical_name=item.logical_name,
                    role=item.role,
                    require_executable=item.require_executable,
                )
                for item in items
            ),
            key=lambda item: (item.role, item.logical_name),
        )
    )
    try:
        return BuildInputClosure(files=captured)
    except (TypeError, ValueError) as exc:
        raise BuildInputIdentityError(str(exc)) from exc


def verify_build_input_closure(
    specs: tuple[InputFileSpec, ...] | list[InputFileSpec],
    expected: BuildInputClosure,
) -> None:
    """Fail unless a complete fresh capture equals the immutable receipt."""
    if type(expected) is not BuildInputClosure:
        raise BuildInputIdentityError("expected build-input closure has an invalid type")
    observed_files = capture_build_input_closure(specs)
    observed = BuildInputClosure(
        files=observed_files.files,
        aggregates=expected.aggregates,
    )
    if observed != expected or observed.digest != expected.digest:
        raise BuildInputIdentityError("build-input closure changed after capture")


def bind_full_c6_cargo_workspace_aggregates(
    closure: BuildInputClosure,
    workspace: FullC6CargoDependencyWorkspaceReceipt,
) -> BuildInputClosure:
    """Bind the seven exact sealed-Cargo identities to an existing closure.

    External receipt digests keep their producer domains.  The three derived
    rows use the domain-separated preimages below:

    * package set: the ordered ``CargoSourceIdentity.to_dict()`` list;
    * package receipts: the ordered ``FullC6CargoPackageReceipt.to_dict()`` list;
    * metadata set: exact ordered workspace-entry identities for every declared
      package metadata path.

    No vendor, manifest, or license bytes are retained by the closure.
    """
    from rextio.build.full_c6_cargo_workspace import (
        FullC6CargoDependencyWorkspaceReceipt,
        validate_full_c6_cargo_dependency_workspace_receipt,
    )

    if type(closure) is not BuildInputClosure:
        raise BuildInputIdentityError("build-input closure has an invalid type")
    existing_aliases = {
        unicodedata.normalize("NFC", item.aggregate_id).casefold()
        for item in closure.aggregates
    }
    cargo_aliases = {
        unicodedata.normalize("NFC", item).casefold()
        for item in FULL_C6_CARGO_INPUT_AGGREGATE_IDS
    }
    if existing_aliases.intersection(cargo_aliases):
        raise BuildInputIdentityError(
            "build-input closure already contains a Cargo aggregate"
        )
    if (
        type(workspace) is not FullC6CargoDependencyWorkspaceReceipt
        or not validate_full_c6_cargo_dependency_workspace_receipt(workspace)
    ):
        raise BuildInputIdentityError("artifact build Cargo workspace receipt is not sealed")

    package_members = [item.package.to_dict() for item in workspace.packages]
    package_receipt_members = [item.to_dict() for item in workspace.packages]
    metadata_names = set(workspace.metadata_files)
    metadata_members = [
        item.to_dict()
        for item in workspace.vendor_entries
        if item.kind == "file" and item.logical_name in metadata_names
    ]
    if {str(item["logical_name"]) for item in metadata_members} != metadata_names:
        raise BuildInputIdentityError("Cargo workspace metadata set is incomplete")

    package_set_digest = _aggregate_members_digest(
        FULL_C6_CARGO_PACKAGE_SET_DOMAIN,
        package_members,
    )
    package_receipts_digest = _aggregate_members_digest(
        FULL_C6_CARGO_PACKAGE_RECEIPTS_DOMAIN,
        package_receipt_members,
    )
    metadata_set_digest = _aggregate_members_digest(
        FULL_C6_CARGO_METADATA_SET_DOMAIN,
        metadata_members,
    )
    package_count = len(workspace.packages)
    cargo_aggregates = tuple(
        sorted(
            (
                BuildInputAggregateIdentity(
                    aggregate_id="artifact-evidence-cargo-workspace",
                    kind="cargo-workspace",
                    digest=workspace.digest,
                    member_count=package_count,
                    metadata_digest=metadata_set_digest,
                ),
                BuildInputAggregateIdentity(
                    aggregate_id="artifact-evidence-cargo-sources",
                    kind="cargo-sources",
                    digest=workspace.cargo_sources.digest,
                    member_count=len(workspace.cargo_sources.packages),
                ),
                BuildInputAggregateIdentity(
                    aggregate_id="artifact-evidence-cargo-vendor-tree",
                    kind="cargo-vendor-tree",
                    digest=workspace.vendor_tree_sha256,
                    member_count=len(workspace.vendor_entries),
                ),
                BuildInputAggregateIdentity(
                    aggregate_id="artifact-evidence-cargo-executor-config",
                    kind="cargo-executor-config",
                    digest=workspace.executor_config.sha256 or "",
                    member_count=1,
                ),
                BuildInputAggregateIdentity(
                    aggregate_id="artifact-evidence-cargo-package-set",
                    kind="cargo-package-set",
                    digest=package_set_digest,
                    member_count=package_count,
                ),
                BuildInputAggregateIdentity(
                    aggregate_id="artifact-evidence-cargo-package-receipts",
                    kind="cargo-package-receipts",
                    digest=package_receipts_digest,
                    member_count=package_count,
                    metadata_digest=metadata_set_digest,
                ),
                BuildInputAggregateIdentity(
                    aggregate_id="artifact-evidence-cargo-metadata-set",
                    kind="cargo-metadata-set",
                    digest=metadata_set_digest,
                    member_count=len(metadata_members),
                ),
            ),
            key=lambda item: (item.kind, item.aggregate_id),
        )
    )
    if {
        item.aggregate_id for item in cargo_aggregates
    } != FULL_C6_CARGO_INPUT_AGGREGATE_IDS:
        raise BuildInputIdentityError("Cargo aggregate identity set is incomplete")
    aggregates = tuple(
        sorted(
            (*closure.aggregates, *cargo_aggregates),
            key=lambda item: (item.kind, item.aggregate_id),
        )
    )
    return BuildInputClosure(
        files=closure.files,
        domain=closure.domain,
        scope=closure.scope,
        complete_for_scope=closure.complete_for_scope,
        aggregates=aggregates,
    )


def bind_build_input_aggregate(
    closure: BuildInputClosure,
    aggregate: BuildInputAggregateIdentity,
) -> BuildInputClosure:
    """Add one canonical generic aggregate without replacing existing rows."""
    if type(closure) is not BuildInputClosure:
        raise BuildInputIdentityError("build-input closure has an invalid type")
    if type(aggregate) is not BuildInputAggregateIdentity:
        raise BuildInputIdentityError("build-input aggregate has an invalid type")
    alias = unicodedata.normalize("NFC", aggregate.aggregate_id).casefold()
    if any(
        unicodedata.normalize("NFC", item.aggregate_id).casefold() == alias
        for item in closure.aggregates
    ):
        raise BuildInputIdentityError(
            "build-input aggregate id is duplicated or aliased"
        )
    try:
        return BuildInputClosure(
            files=closure.files,
            domain=closure.domain,
            scope=closure.scope,
            complete_for_scope=closure.complete_for_scope,
            aggregates=tuple(
                sorted(
                    (*closure.aggregates, aggregate),
                    key=lambda item: (item.kind, item.aggregate_id),
                )
            ),
        )
    except (TypeError, ValueError) as exc:
        raise BuildInputIdentityError(str(exc)) from exc


def _require_same_regular_file(
    earlier: os.stat_result,
    later: os.stat_result,
    reason: str,
) -> None:
    if not stat.S_ISREG(later.st_mode):
        raise BuildInputIdentityError(f"build input {reason}")
    if (earlier.st_dev, earlier.st_ino) != (later.st_dev, later.st_ino):
        raise BuildInputIdentityError(f"build input {reason}")
    if earlier.st_size != later.st_size:
        raise BuildInputIdentityError(f"build input {reason}")
    for attribute in ("st_mtime_ns", "st_ctime_ns"):
        if hasattr(earlier, attribute) and getattr(earlier, attribute) != getattr(later, attribute):
            raise BuildInputIdentityError(f"build input {reason}")


def _validate_logical_name(value: str) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise ValueError("build-input logical name is invalid")
    if len(value) > MAX_BUILD_INPUT_NAME_CHARS or "\\" in value or "\0" in value:
        raise ValueError("build-input logical name is invalid")
    if any(ord(character) < 32 for character in value):
        raise ValueError("build-input logical name is invalid")
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if posix.is_absolute() or windows.is_absolute() or ".." in posix.parts or ".." in windows.parts:
        raise ValueError("build-input logical name must be relative")
    if not posix.parts or any(_LOGICAL_SEGMENT_RE.fullmatch(part) is None for part in posix.parts):
        raise ValueError("build-input logical name is invalid")


def _logical_alias(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def _aggregate_members_digest(
    domain: str,
    members: Sequence[Mapping[str, object]],
) -> str:
    return hashlib.sha256(
        _canonical_json({"domain": domain, "members": members})
    ).hexdigest()


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


__all__ = [
    "BuildInputIdentityError",
    "BuildInputAggregateIdentity",
    "BuildInputClosure",
    "BUILD_INPUT_CLOSURE_DOMAIN",
    "BUILD_INPUT_CLOSURE_SCOPE",
    "ExactFileIdentity",
    "FULL_C6_CARGO_INPUT_AGGREGATE_IDS",
    "FULL_C6_CARGO_METADATA_SET_DOMAIN",
    "FULL_C6_CARGO_PACKAGE_RECEIPTS_DOMAIN",
    "FULL_C6_CARGO_PACKAGE_SET_DOMAIN",
    "InputFileSpec",
    "MAX_BUILD_INPUT_BYTES",
    "bind_build_input_aggregate",
    "bind_full_c6_cargo_workspace_aggregates",
    "capture_build_input_closure",
    "capture_exact_file",
    "capture_exact_file_bytes",
    "verify_build_input_closure",
    "verify_exact_file",
]
