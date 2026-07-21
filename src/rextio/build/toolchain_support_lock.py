"""Bounded exact support-file locks for the Full C6 host toolchain.

This module is deliberately independent from tool discovery and execution.  A
caller supplies explicit, path-bearing locators; capture turns them into a
canonical lock containing only opaque locator-path digests.  The lock describes
only the narrow CPython 3.11 / PyO3 host-cdylib profile and does not authorize a
build or distribution.

Regular files are streamed through descriptor-pinned, no-follow opens.  Trees
are inventoried without following links.  A relative symlink is accepted only
when its component-wise resolution terminates at another captured member in
the same tree; absolute, escaping, broken, and cyclic links fail closed.
Content Merkle nodes also bind stable observable stat metadata and exact
bounded xattr name/value receipts (including macOS resource forks).  Volatile
access times are deliberately excluded.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
import ctypes
from dataclasses import dataclass
import errno
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import stat
import sys
from typing import Any, Protocol, SupportsIndex, TypeVar, cast
import unicodedata


TOOLCHAIN_SUPPORT_LOCK_KIND = "full-c6-toolchain-support-lock"
TOOLCHAIN_SUPPORT_LOCK_DOMAIN = "rextio.full-c6-toolchain-support-lock.v1"
TOOLCHAIN_SUPPORT_LOCK_SCHEMA_VERSION = 1
TOOLCHAIN_SUPPORT_SCOPE = "cpython-3.11-pyo3-host-cdylib-v1"
TOOLCHAIN_SUPPORT_TARGETS = (
    "aarch64-apple-darwin",
    "x86_64-unknown-linux-gnu",
)

MAX_TOOLCHAIN_SUPPORT_LOCK_BYTES = 32 * 1024 * 1024
MAX_TOOLCHAIN_SUPPORT_JSON_DEPTH = 16
MAX_TOOLCHAIN_SUPPORT_LOCATORS = 64
MAX_TOOLCHAIN_SUPPORT_TREE_MEMBERS = 65_536
MAX_TOOLCHAIN_SUPPORT_TREE_DEPTH = 64
MAX_TOOLCHAIN_SUPPORT_PATH_CHARS = 2_048
MAX_TOOLCHAIN_SUPPORT_PATH_BYTES = 8_192
MAX_TOOLCHAIN_SUPPORT_FILE_BYTES = 512 * 1024 * 1024
MAX_TOOLCHAIN_SUPPORT_TREE_BYTES = 8 * 1024 * 1024 * 1024
MAX_TOOLCHAIN_SUPPORT_SYMLINK_BYTES = 8_192
MAX_TOOLCHAIN_SUPPORT_DIRECTORY_ENTRIES = 65_536
MAX_TOOLCHAIN_SUPPORT_XATTRS_PER_MEMBER = 64
MAX_TOOLCHAIN_SUPPORT_XATTR_NAME_BYTES = 1_024
MAX_TOOLCHAIN_SUPPORT_XATTR_VALUE_BYTES = 16 * 1024 * 1024
MAX_TOOLCHAIN_SUPPORT_XATTR_LIST_BYTES = 64 * 1024
MAX_TOOLCHAIN_SUPPORT_TREE_XATTRS = 131_072
MAX_TOOLCHAIN_SUPPORT_TREE_XATTR_BYTES = 1024 * 1024 * 1024
MAX_TOOLCHAIN_SUPPORT_LOCK_XATTRS = 131_072
MAX_TOOLCHAIN_SUPPORT_LOCK_XATTR_BYTES = 1024 * 1024 * 1024

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ROLE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_LOCK_FIELDS = {
    "kind",
    "schema_version",
    "domain",
    "scope",
    "manifests",
    "roots",
    "manifest_count",
    "root_count",
    "member_count",
    "total_bytes",
    "xattr_count",
    "xattr_bytes",
    "merkle_sha256",
    "authorizes_build",
    "authorizes_distribution",
}
_SCOPE_FIELDS = {
    "profile",
    "python_implementation",
    "python_version",
    "rust_binding",
    "artifact_kind",
    "target_triple",
}
_FILE_FIELDS = {
    "logical_role",
    "locator_path_sha256",
    "metadata_sha256",
    "raw_sha256",
    "size",
    "mode",
    "member_count",
    "total_bytes",
    "xattr_count",
    "xattr_bytes",
    "xattrs_sha256",
    "merkle_sha256",
}
_TREE_FIELDS = {
    "logical_role",
    "locator_path_sha256",
    "root_metadata_sha256",
    "root_mode",
    "member_count",
    "file_count",
    "directory_count",
    "symlink_count",
    "total_bytes",
    "xattr_count",
    "xattr_bytes",
    "merkle_sha256",
}
class _RoleReceipt(Protocol):
    @property
    def logical_role(self) -> str: ...


_RoleReceiptT = TypeVar("_RoleReceiptT", bound=_RoleReceipt)


class ToolchainSupportLockError(ValueError):
    """A toolchain support locator, tree, or lock is unsafe or noncanonical."""


class ToolchainSupportLocator:
    """Validated path-bearing locator whose machine path remains private.

    Locators intentionally have no public path property and cannot be pickled.
    Their only safe public fields are the logical role and expected node kind.
    """

    __slots__ = ("_absolute_path", "_kind", "_logical_role")

    _absolute_path: Path
    _kind: str
    _logical_role: str

    def __init__(self, *, logical_role: str, path: Path | str, kind: str) -> None:
        _validate_role(logical_role)
        if kind not in {"file", "tree"}:
            raise ToolchainSupportLockError(
                "toolchain support locator kind must be file or tree"
            )
        absolute = _validate_absolute_locator(path)
        object.__setattr__(self, "_logical_role", logical_role)
        object.__setattr__(self, "_absolute_path", absolute)
        object.__setattr__(self, "_kind", kind)

    @property
    def logical_role(self) -> str:
        """Return the path-free role written to the lock."""
        return self._logical_role

    @property
    def kind(self) -> str:
        """Return whether this locator addresses one file or one tree."""
        return self._kind

    def __repr__(self) -> str:
        return (
            "ToolchainSupportLocator("
            f"logical_role={self.logical_role!r}, kind={self.kind!r}, path=<private>)"
        )

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("toolchain support locators cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        raise TypeError("toolchain support locators cannot be serialized")

    def __getstate__(self) -> object:
        raise TypeError("toolchain support locators cannot be serialized")


@dataclass(frozen=True, slots=True)
class ToolchainSupportScope:
    """The one fixed Full C6 host-extension profile and selected host target."""

    target_triple: str
    profile: str = TOOLCHAIN_SUPPORT_SCOPE
    python_implementation: str = "cpython"
    python_version: str = "3.11"
    rust_binding: str = "pyo3"
    artifact_kind: str = "host-cdylib"

    def __post_init__(self) -> None:
        if (
            self.profile != TOOLCHAIN_SUPPORT_SCOPE
            or self.python_implementation != "cpython"
            or self.python_version != "3.11"
            or self.rust_binding != "pyo3"
            or self.artifact_kind != "host-cdylib"
            or self.target_triple not in TOOLCHAIN_SUPPORT_TARGETS
        ):
            raise ToolchainSupportLockError(
                "toolchain support scope is outside the fixed host profile"
            )

    def to_dict(self) -> dict[str, object]:
        """Return the closed canonical scope document."""
        return {
            "profile": self.profile,
            "python_implementation": self.python_implementation,
            "python_version": self.python_version,
            "rust_binding": self.rust_binding,
            "artifact_kind": self.artifact_kind,
            "target_triple": self.target_triple,
        }


@dataclass(frozen=True, slots=True)
class ToolchainSupportFileReceipt:
    """Exact raw-byte receipt for one explicitly named support manifest."""

    logical_role: str
    locator_path_sha256: str
    metadata_sha256: str
    raw_sha256: str
    size: int
    mode: int
    xattr_count: int
    xattr_bytes: int
    xattrs_sha256: str
    merkle_sha256: str
    member_count: int = 1
    total_bytes: int = 0

    def __post_init__(self) -> None:
        _validate_role(self.logical_role)
        _require_sha256(self.locator_path_sha256, "support locator path SHA-256")
        _require_sha256(self.metadata_sha256, "support manifest metadata SHA-256")
        _require_sha256(self.xattrs_sha256, "support manifest xattr SHA-256")
        _require_sha256(self.raw_sha256, "support manifest raw SHA-256")
        _require_sha256(self.merkle_sha256, "support manifest Merkle SHA-256")
        _validate_size(self.size, maximum=MAX_TOOLCHAIN_SUPPORT_FILE_BYTES)
        _validate_mode(self.mode)
        _validate_xattr_summary(self.xattr_count, self.xattr_bytes)
        if self.member_count != 1 or self.total_bytes != self.size:
            raise ToolchainSupportLockError(
                "toolchain support manifest summary is noncanonical"
            )
        if not hmac.compare_digest(self.merkle_sha256, _file_merkle(self)):
            raise ToolchainSupportLockError(
                "toolchain support manifest Merkle receipt is stale"
            )

    def to_dict(self) -> dict[str, object]:
        """Return the complete path-free file receipt."""
        return {
            "logical_role": self.logical_role,
            "locator_path_sha256": self.locator_path_sha256,
            "metadata_sha256": self.metadata_sha256,
            "raw_sha256": self.raw_sha256,
            "size": self.size,
            "mode": self.mode,
            "member_count": self.member_count,
            "total_bytes": self.total_bytes,
            "xattr_count": self.xattr_count,
            "xattr_bytes": self.xattr_bytes,
            "xattrs_sha256": self.xattrs_sha256,
            "merkle_sha256": self.merkle_sha256,
        }


@dataclass(frozen=True, slots=True)
class _ToolchainSupportTreeEntry:
    """Ephemeral exact tree member used only while deriving a Merkle root."""

    relative_path: str
    kind: str
    mode: int
    metadata_sha256: str
    xattr_count: int
    xattr_bytes: int
    xattrs_sha256: str
    size: int
    raw_sha256: str | None
    link_target: str | None
    merkle_sha256: str

    def __post_init__(self) -> None:
        _validate_relative_path(self.relative_path)
        _validate_mode(self.mode)
        _require_sha256(self.metadata_sha256, "support member metadata SHA-256")
        _require_sha256(self.xattrs_sha256, "support member xattr SHA-256")
        _validate_xattr_summary(self.xattr_count, self.xattr_bytes)
        _require_sha256(self.merkle_sha256, "support tree member Merkle SHA-256")
        if self.kind == "directory":
            if self.size != 0 or self.raw_sha256 is not None or self.link_target is not None:
                raise ToolchainSupportLockError(
                    "toolchain support directory receipt is noncanonical"
                )
            return
        if self.kind == "file":
            _validate_size(self.size, maximum=MAX_TOOLCHAIN_SUPPORT_FILE_BYTES)
            _require_sha256(self.raw_sha256, "support tree file raw SHA-256")
            if self.link_target is not None:
                raise ToolchainSupportLockError(
                    "toolchain support regular file has a link target"
                )
            return
        if self.kind == "symlink":
            if (
                type(self.link_target) is not str
                or self.raw_sha256 is None
                or self.size != len(self.link_target.encode("utf-8"))
                or not 0 < self.size <= MAX_TOOLCHAIN_SUPPORT_SYMLINK_BYTES
            ):
                raise ToolchainSupportLockError(
                    "toolchain support symlink receipt is noncanonical"
                )
            _require_sha256(self.raw_sha256, "support symlink raw SHA-256")
            if not hmac.compare_digest(
                self.raw_sha256,
                hashlib.sha256(self.link_target.encode("utf-8")).hexdigest(),
            ):
                raise ToolchainSupportLockError(
                    "toolchain support symlink raw receipt is stale"
                )
            _validate_link_target(self.link_target)
            return
        raise ToolchainSupportLockError("toolchain support tree member kind is invalid")

    def to_dict(self) -> dict[str, object]:
        """Return the exact member identity used by the tree Merkle receipt."""
        return {
            "relative_path": self.relative_path,
            "kind": self.kind,
            "mode": self.mode,
            "metadata_sha256": self.metadata_sha256,
            "xattr_count": self.xattr_count,
            "xattr_bytes": self.xattr_bytes,
            "xattrs_sha256": self.xattrs_sha256,
            "size": self.size,
            "raw_sha256": self.raw_sha256,
            "link_target": self.link_target,
            "merkle_sha256": self.merkle_sha256,
        }


@dataclass(frozen=True, slots=True)
class ToolchainSupportTreeReceipt:
    """Exact bounded Merkle receipt for one explicit support root."""

    logical_role: str
    locator_path_sha256: str
    root_metadata_sha256: str
    root_mode: int
    member_count: int
    file_count: int
    directory_count: int
    symlink_count: int
    total_bytes: int
    xattr_count: int
    xattr_bytes: int
    merkle_sha256: str

    def __post_init__(self) -> None:
        _validate_role(self.logical_role)
        _require_sha256(self.locator_path_sha256, "support locator path SHA-256")
        _require_sha256(self.root_metadata_sha256, "support root metadata SHA-256")
        _validate_mode(self.root_mode)
        if (
            type(self.member_count) is not int
            or isinstance(self.member_count, bool)
            or not 1 <= self.member_count <= MAX_TOOLCHAIN_SUPPORT_TREE_MEMBERS
        ):
            raise ToolchainSupportLockError(
                "toolchain support tree member count is outside the bound"
            )
        if (
            type(self.file_count) is not int
            or isinstance(self.file_count, bool)
            or self.file_count < 0
            or type(self.directory_count) is not int
            or isinstance(self.directory_count, bool)
            or self.directory_count < 0
            or type(self.symlink_count) is not int
            or isinstance(self.symlink_count, bool)
            or self.symlink_count < 0
            or self.file_count + self.directory_count + self.symlink_count
            != self.member_count
            or type(self.total_bytes) is not int
            or isinstance(self.total_bytes, bool)
            or self.total_bytes < 0
            or self.total_bytes > MAX_TOOLCHAIN_SUPPORT_TREE_BYTES
            or type(self.xattr_count) is not int
            or isinstance(self.xattr_count, bool)
            or not 0 <= self.xattr_count <= MAX_TOOLCHAIN_SUPPORT_TREE_XATTRS
            or type(self.xattr_bytes) is not int
            or isinstance(self.xattr_bytes, bool)
            or not 0 <= self.xattr_bytes <= MAX_TOOLCHAIN_SUPPORT_TREE_XATTR_BYTES
        ):
            raise ToolchainSupportLockError(
                "toolchain support tree summary is noncanonical"
            )
        _require_sha256(self.merkle_sha256, "support tree Merkle SHA-256")

    def to_dict(self) -> dict[str, object]:
        """Return the complete path-free exact tree receipt."""
        return {
            "logical_role": self.logical_role,
            "locator_path_sha256": self.locator_path_sha256,
            "root_metadata_sha256": self.root_metadata_sha256,
            "root_mode": self.root_mode,
            "member_count": self.member_count,
            "file_count": self.file_count,
            "directory_count": self.directory_count,
            "symlink_count": self.symlink_count,
            "total_bytes": self.total_bytes,
            "xattr_count": self.xattr_count,
            "xattr_bytes": self.xattr_bytes,
            "merkle_sha256": self.merkle_sha256,
        }


@dataclass(frozen=True, slots=True)
class ToolchainSupportLock:
    """Canonical, non-authorizing support closure for one fixed host profile."""

    scope: ToolchainSupportScope
    manifests: tuple[ToolchainSupportFileReceipt, ...]
    roots: tuple[ToolchainSupportTreeReceipt, ...]
    manifest_count: int
    root_count: int
    member_count: int
    total_bytes: int
    xattr_count: int
    xattr_bytes: int
    merkle_sha256: str
    kind: str = TOOLCHAIN_SUPPORT_LOCK_KIND
    schema_version: int = TOOLCHAIN_SUPPORT_LOCK_SCHEMA_VERSION
    domain: str = TOOLCHAIN_SUPPORT_LOCK_DOMAIN
    authorizes_build: bool = False
    authorizes_distribution: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.scope) is not ToolchainSupportScope
            or self.kind != TOOLCHAIN_SUPPORT_LOCK_KIND
            or self.schema_version != TOOLCHAIN_SUPPORT_LOCK_SCHEMA_VERSION
            or self.domain != TOOLCHAIN_SUPPORT_LOCK_DOMAIN
            or self.authorizes_build is not False
            or self.authorizes_distribution is not False
        ):
            raise ToolchainSupportLockError("toolchain support lock identity is invalid")
        if (
            type(self.manifests) is not tuple
            or type(self.roots) is not tuple
            or not self.manifests
            or not self.roots
            or len(self.manifests) > MAX_TOOLCHAIN_SUPPORT_LOCATORS
            or len(self.roots) > MAX_TOOLCHAIN_SUPPORT_LOCATORS
            or any(type(item) is not ToolchainSupportFileReceipt for item in self.manifests)
            or any(type(item) is not ToolchainSupportTreeReceipt for item in self.roots)
            or self.manifests != _canonical_receipts(self.manifests)
            or self.roots != _canonical_receipts(self.roots)
        ):
            raise ToolchainSupportLockError(
                "toolchain support lock receipts are missing, unbounded, or unordered"
            )
        roles = [item.logical_role for item in self.manifests] + [
            item.logical_role for item in self.roots
        ]
        if len({_alias(item) for item in roles}) != len(roles):
            raise ToolchainSupportLockError(
                "toolchain support lock contains an NFC/casefold role alias"
            )
        expected_members = sum(item.member_count for item in self.manifests) + sum(
            item.member_count for item in self.roots
        )
        expected_bytes = sum(item.total_bytes for item in self.manifests) + sum(
            item.total_bytes for item in self.roots
        )
        expected_xattr_count = sum(item.xattr_count for item in self.manifests) + sum(
            item.xattr_count for item in self.roots
        )
        expected_xattr_bytes = sum(item.xattr_bytes for item in self.manifests) + sum(
            item.xattr_bytes for item in self.roots
        )
        if (
            self.manifest_count != len(self.manifests)
            or self.root_count != len(self.roots)
            or self.member_count != expected_members
            or self.total_bytes != expected_bytes
            or type(self.xattr_count) is not int
            or isinstance(self.xattr_count, bool)
            or type(self.xattr_bytes) is not int
            or isinstance(self.xattr_bytes, bool)
            or self.xattr_count != expected_xattr_count
            or self.xattr_bytes != expected_xattr_bytes
            or expected_xattr_count > MAX_TOOLCHAIN_SUPPORT_LOCK_XATTRS
            or expected_xattr_bytes > MAX_TOOLCHAIN_SUPPORT_LOCK_XATTR_BYTES
            or self.total_bytes
            > MAX_TOOLCHAIN_SUPPORT_TREE_BYTES * MAX_TOOLCHAIN_SUPPORT_LOCATORS
        ):
            raise ToolchainSupportLockError(
                "toolchain support lock summary is noncanonical"
            )
        _require_sha256(self.merkle_sha256, "toolchain support lock Merkle SHA-256")
        if not hmac.compare_digest(self.merkle_sha256, _lock_merkle(self)):
            raise ToolchainSupportLockError("toolchain support lock Merkle receipt is stale")

    @property
    def canonical_bytes(self) -> bytes:
        """Return the bounded canonical UTF-8 JSON lock bytes."""
        payload = _canonical_json(self.to_dict())
        if not payload or len(payload) > MAX_TOOLCHAIN_SUPPORT_LOCK_BYTES:
            raise ToolchainSupportLockError(
                "toolchain support lock exceeds its serialized byte bound"
            )
        return payload

    @property
    def raw_sha256(self) -> str:
        """Return the SHA-256 of the exact canonical lock bytes."""
        return hashlib.sha256(self.canonical_bytes).hexdigest()

    def to_dict(self) -> dict[str, object]:
        """Return the closed canonical lock document."""
        return {
            "kind": self.kind,
            "schema_version": self.schema_version,
            "domain": self.domain,
            "scope": self.scope.to_dict(),
            "manifests": [item.to_dict() for item in self.manifests],
            "roots": [item.to_dict() for item in self.roots],
            "manifest_count": self.manifest_count,
            "root_count": self.root_count,
            "member_count": self.member_count,
            "total_bytes": self.total_bytes,
            "xattr_count": self.xattr_count,
            "xattr_bytes": self.xattr_bytes,
            "merkle_sha256": self.merkle_sha256,
            "authorizes_build": False,
            "authorizes_distribution": False,
        }


@dataclass(frozen=True, slots=True)
class _FilesystemStamp:
    device: int
    inode: int
    mode: int
    uid: int
    gid: int
    links: int
    size: int
    ctime_ns: int
    mtime_ns: int
    flags: int | None
    birthtime_ns: int | None
    blocks: int | None
    block_size: int | None


@dataclass(frozen=True, slots=True)
class _RawTreeEntry:
    relative_path: str
    kind: str
    mode: int
    metadata_sha256: str
    xattr_count: int
    xattr_bytes: int
    xattrs_sha256: str
    size: int
    raw_sha256: str | None
    link_target: str | None


@dataclass(frozen=True, slots=True)
class _XattrReceipt:
    count: int
    total_bytes: int
    merkle_sha256: str


@dataclass(slots=True)
class _XattrBudget:
    remaining_count: int
    remaining_bytes: int

    def __post_init__(self) -> None:
        if (
            type(self.remaining_count) is not int
            or isinstance(self.remaining_count, bool)
            or self.remaining_count < 0
            or type(self.remaining_bytes) is not int
            or isinstance(self.remaining_bytes, bool)
            or self.remaining_bytes < 0
        ):
            raise ToolchainSupportLockError(
                "toolchain support xattr remaining budget is invalid"
            )

    def clone(self) -> _XattrBudget:
        return _XattrBudget(
            remaining_count=self.remaining_count,
            remaining_bytes=self.remaining_bytes,
        )

    def consume(self, *, count: int, total_bytes: int) -> None:
        if count > self.remaining_count or total_bytes > self.remaining_bytes:
            raise ToolchainSupportLockError(
                "toolchain support xattr aggregate exceeds the remaining budget"
            )
        self.remaining_count -= count
        self.remaining_bytes -= total_bytes


def create_toolchain_support_locator(
    *,
    logical_role: str,
    path: Path | str,
    kind: str,
) -> ToolchainSupportLocator:
    """Create one private validated locator for an explicit file or tree root."""
    return ToolchainSupportLocator(logical_role=logical_role, path=path, kind=kind)


def capture_toolchain_support_file(
    locator: ToolchainSupportLocator,
) -> ToolchainSupportFileReceipt:
    """Stream and stably receipt one single-link regular support manifest."""
    _require_locator(locator, kind="file")
    return _capture_stable_file(
        locator,
        budget=_XattrBudget(
            remaining_count=MAX_TOOLCHAIN_SUPPORT_XATTRS_PER_MEMBER,
            remaining_bytes=MAX_TOOLCHAIN_SUPPORT_TREE_XATTR_BYTES,
        ),
    )


def _capture_stable_file(
    locator: ToolchainSupportLocator,
    *,
    budget: _XattrBudget,
) -> ToolchainSupportFileReceipt:
    capture_budget = _XattrBudget(
        remaining_count=min(
            budget.remaining_count,
            MAX_TOOLCHAIN_SUPPORT_XATTRS_PER_MEMBER,
        ),
        remaining_bytes=min(
            budget.remaining_bytes,
            MAX_TOOLCHAIN_SUPPORT_TREE_XATTR_BYTES,
        ),
    )
    starting_count = capture_budget.remaining_count
    starting_bytes = capture_budget.remaining_bytes
    replay_budget = capture_budget.clone()
    first = _capture_file_once(locator, xattr_budget=capture_budget)
    second = _capture_file_once(locator, xattr_budget=replay_budget)
    if first != second or capture_budget != replay_budget:
        raise ToolchainSupportLockError(
            "toolchain support manifest changed across stable capture"
        )
    consumed_count = starting_count - capture_budget.remaining_count
    consumed_bytes = starting_bytes - capture_budget.remaining_bytes
    if first.xattr_count != consumed_count or first.xattr_bytes != consumed_bytes:
        raise ToolchainSupportLockError(
            "toolchain support manifest xattr accounting is inconsistent"
        )
    budget.consume(count=consumed_count, total_bytes=consumed_bytes)
    return first


def _capture_file_once(
    locator: ToolchainSupportLocator,
    *,
    xattr_budget: _XattrBudget,
) -> ToolchainSupportFileReceipt:
    starting_xattr_count = xattr_budget.remaining_count
    starting_xattr_bytes = xattr_budget.remaining_bytes
    chain = _open_directory_chain(locator._absolute_path.parent)
    file_fd = -1
    try:
        parent_fd = chain[-1][0]
        name = locator._absolute_path.name
        expected = _stamp(os.stat(name, dir_fd=parent_fd, follow_symlinks=False))
        file_fd = _open_regular_file(parent_fd, name)
        opened = _stamp(os.fstat(file_fd))
        if opened != expected:
            raise ToolchainSupportLockError(
                "toolchain support manifest changed before capture"
            )
        xattrs = _capture_fd_xattrs(file_fd, budget=xattr_budget)
        if (
            xattrs.count != starting_xattr_count - xattr_budget.remaining_count
            or xattrs.total_bytes
            != starting_xattr_bytes - xattr_budget.remaining_bytes
        ):
            raise ToolchainSupportLockError(
                "toolchain support manifest xattr accounting is inconsistent"
            )
        digest, size, final_stamp = _stream_file_digest(
            file_fd,
            expected=opened,
            maximum=MAX_TOOLCHAIN_SUPPORT_FILE_BYTES,
        )
        linked = _stamp(os.stat(name, dir_fd=parent_fd, follow_symlinks=False))
        if linked != final_stamp:
            raise ToolchainSupportLockError(
                "toolchain support manifest link changed during capture"
            )
        _verify_directory_chain(chain)
        provisional = ToolchainSupportFileReceipt.__new__(ToolchainSupportFileReceipt)
        object.__setattr__(provisional, "logical_role", locator.logical_role)
        object.__setattr__(
            provisional,
            "locator_path_sha256",
            _locator_path_digest(locator._absolute_path),
        )
        object.__setattr__(
            provisional,
            "metadata_sha256",
            _metadata_digest(final_stamp, kind="file"),
        )
        object.__setattr__(provisional, "raw_sha256", digest)
        object.__setattr__(provisional, "size", size)
        object.__setattr__(provisional, "mode", stat.S_IMODE(final_stamp.mode))
        object.__setattr__(provisional, "xattr_count", xattrs.count)
        object.__setattr__(provisional, "xattr_bytes", xattrs.total_bytes)
        object.__setattr__(provisional, "xattrs_sha256", xattrs.merkle_sha256)
        object.__setattr__(provisional, "member_count", 1)
        object.__setattr__(provisional, "total_bytes", size)
        object.__setattr__(provisional, "merkle_sha256", "")
        merkle = _file_merkle(provisional)
        return ToolchainSupportFileReceipt(
            logical_role=locator.logical_role,
            locator_path_sha256=_locator_path_digest(locator._absolute_path),
            metadata_sha256=_metadata_digest(final_stamp, kind="file"),
            raw_sha256=digest,
            size=size,
            mode=stat.S_IMODE(final_stamp.mode),
            xattr_count=xattrs.count,
            xattr_bytes=xattrs.total_bytes,
            xattrs_sha256=xattrs.merkle_sha256,
            member_count=1,
            total_bytes=size,
            merkle_sha256=merkle,
        )
    except ToolchainSupportLockError:
        raise
    except OSError as exc:
        raise ToolchainSupportLockError(
            "toolchain support manifest could not be captured safely"
        ) from exc
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        _close_directory_chain(chain)


def capture_toolchain_support_tree(
    locator: ToolchainSupportLocator,
) -> ToolchainSupportTreeReceipt:
    """Capture one deterministic, exact, bounded support-root Merkle tree."""
    _require_locator(locator, kind="tree")
    return _capture_stable_tree(
        locator,
        budget=_XattrBudget(
            remaining_count=MAX_TOOLCHAIN_SUPPORT_TREE_XATTRS,
            remaining_bytes=MAX_TOOLCHAIN_SUPPORT_TREE_XATTR_BYTES,
        ),
    )


def _capture_stable_tree(
    locator: ToolchainSupportLocator,
    *,
    budget: _XattrBudget,
) -> ToolchainSupportTreeReceipt:
    capture_budget = _XattrBudget(
        remaining_count=min(
            budget.remaining_count,
            MAX_TOOLCHAIN_SUPPORT_TREE_XATTRS,
        ),
        remaining_bytes=min(
            budget.remaining_bytes,
            MAX_TOOLCHAIN_SUPPORT_TREE_XATTR_BYTES,
        ),
    )
    starting_count = capture_budget.remaining_count
    starting_bytes = capture_budget.remaining_bytes
    replay_budget = capture_budget.clone()
    first = _capture_tree_once(locator, xattr_budget=capture_budget)
    second = _capture_tree_once(locator, xattr_budget=replay_budget)
    if first != second or capture_budget != replay_budget:
        raise ToolchainSupportLockError(
            "toolchain support tree changed across stable capture"
        )
    consumed_count = starting_count - capture_budget.remaining_count
    consumed_bytes = starting_bytes - capture_budget.remaining_bytes
    if first.xattr_count != consumed_count or first.xattr_bytes != consumed_bytes:
        raise ToolchainSupportLockError(
            "toolchain support tree xattr accounting is inconsistent"
        )
    budget.consume(count=consumed_count, total_bytes=consumed_bytes)
    return first


def _capture_lock_receipts(
    *,
    manifests: tuple[ToolchainSupportLocator, ...],
    roots: tuple[ToolchainSupportLocator, ...],
) -> tuple[
    tuple[ToolchainSupportFileReceipt, ...],
    tuple[ToolchainSupportTreeReceipt, ...],
]:
    budget = _XattrBudget(
        remaining_count=MAX_TOOLCHAIN_SUPPORT_LOCK_XATTRS,
        remaining_bytes=MAX_TOOLCHAIN_SUPPORT_LOCK_XATTR_BYTES,
    )
    ordered_manifests = tuple(
        sorted(
            manifests,
            key=lambda item: (_alias(item.logical_role), item.logical_role),
        )
    )
    ordered_roots = tuple(
        sorted(
            roots,
            key=lambda item: (_alias(item.logical_role), item.logical_role),
        )
    )
    manifest_receipts = tuple(
        _capture_stable_file(item, budget=budget) for item in ordered_manifests
    )
    root_receipts = tuple(
        _capture_stable_tree(item, budget=budget) for item in ordered_roots
    )
    captured_count = sum(item.xattr_count for item in manifest_receipts) + sum(
        item.xattr_count for item in root_receipts
    )
    captured_bytes = sum(item.xattr_bytes for item in manifest_receipts) + sum(
        item.xattr_bytes for item in root_receipts
    )
    if (
        captured_count
        != MAX_TOOLCHAIN_SUPPORT_LOCK_XATTRS - budget.remaining_count
        or captured_bytes
        != MAX_TOOLCHAIN_SUPPORT_LOCK_XATTR_BYTES - budget.remaining_bytes
    ):
        raise ToolchainSupportLockError(
            "toolchain support lock xattr accounting is inconsistent"
        )
    return manifest_receipts, root_receipts


def generate_toolchain_support_lock(
    *,
    target_triple: str,
    manifests: Sequence[ToolchainSupportLocator],
    roots: Sequence[ToolchainSupportLocator],
) -> ToolchainSupportLock:
    """Generate a canonical lock from explicit manifest and root locators."""
    scope = ToolchainSupportScope(target_triple=target_triple)
    if (
        isinstance(manifests, (str, bytes))
        or isinstance(roots, (str, bytes))
        or not isinstance(manifests, Sequence)
        or not isinstance(roots, Sequence)
        or not 1 <= len(manifests) <= MAX_TOOLCHAIN_SUPPORT_LOCATORS
        or not 1 <= len(roots) <= MAX_TOOLCHAIN_SUPPORT_LOCATORS
    ):
        raise ToolchainSupportLockError(
            "toolchain support generation requires bounded explicit locators"
        )
    manifest_locators = tuple(manifests)
    root_locators = tuple(roots)
    for locator in manifest_locators:
        _require_locator(locator, kind="file")
    for locator in root_locators:
        _require_locator(locator, kind="tree")
    roles = [item.logical_role for item in (*manifest_locators, *root_locators)]
    if len({_alias(item) for item in roles}) != len(roles):
        raise ToolchainSupportLockError(
            "toolchain support locators contain an NFC/casefold role alias"
        )
    manifest_receipts, root_receipts = _capture_lock_receipts(
        manifests=manifest_locators,
        roots=root_locators,
    )
    return _new_lock(
        scope=scope,
        manifests=manifest_receipts,
        roots=root_receipts,
    )


def parse_toolchain_support_lock(
    value: bytes,
    *,
    expected_raw_sha256: str,
) -> ToolchainSupportLock:
    """Parse exact canonical lock bytes after validating their external pin."""
    if type(value) is not bytes or not value or len(value) > MAX_TOOLCHAIN_SUPPORT_LOCK_BYTES:
        raise ToolchainSupportLockError(
            "toolchain support lock bytes are empty or exceed the bound"
        )
    expected = _require_sha256(expected_raw_sha256, "expected lock raw SHA-256")
    observed = hashlib.sha256(value).hexdigest()
    if not hmac.compare_digest(observed, expected):
        raise ToolchainSupportLockError(
            "toolchain support lock raw SHA-256 does not match the pin"
        )
    document = _parse_json(value)
    if not hmac.compare_digest(value, _canonical_json(document)):
        raise ToolchainSupportLockError(
            "toolchain support lock is not canonical JSON"
        )
    root = _exact_dict(document, _LOCK_FIELDS, "lock")
    if (
        root["kind"] != TOOLCHAIN_SUPPORT_LOCK_KIND
        or _integer(root["schema_version"], "schema version")
        != TOOLCHAIN_SUPPORT_LOCK_SCHEMA_VERSION
        or root["domain"] != TOOLCHAIN_SUPPORT_LOCK_DOMAIN
        or root["authorizes_build"] is not False
        or root["authorizes_distribution"] is not False
    ):
        raise ToolchainSupportLockError("toolchain support lock identity is invalid")
    manifest_documents = _bounded_list(
        root["manifests"],
        "manifests",
        maximum=MAX_TOOLCHAIN_SUPPORT_LOCATORS,
    )
    root_documents = _bounded_list(
        root["roots"],
        "roots",
        maximum=MAX_TOOLCHAIN_SUPPORT_LOCATORS,
    )
    lock = ToolchainSupportLock(
        scope=_parse_scope(root["scope"]),
        manifests=tuple(_parse_file(item) for item in manifest_documents),
        roots=tuple(_parse_tree(item) for item in root_documents),
        manifest_count=_integer(root["manifest_count"], "manifest count"),
        root_count=_integer(root["root_count"], "root count"),
        member_count=_integer(root["member_count"], "member count"),
        total_bytes=_integer(root["total_bytes"], "total bytes"),
        xattr_count=_integer(root["xattr_count"], "xattr count"),
        xattr_bytes=_integer(root["xattr_bytes"], "xattr bytes"),
        merkle_sha256=_string(root["merkle_sha256"], "lock Merkle SHA-256"),
    )
    if lock.to_dict() != root or not hmac.compare_digest(lock.raw_sha256, observed):
        raise ToolchainSupportLockError(
            "toolchain support lock content is stale or noncanonical"
        )
    return lock


def load_toolchain_support_lock(
    locator: ToolchainSupportLocator,
    *,
    expected_raw_sha256: str,
) -> ToolchainSupportLock:
    """Securely stream, pin, and parse a lock addressed by a private locator."""
    _require_locator(locator, kind="file")
    data = _read_locator_bytes(locator, maximum=MAX_TOOLCHAIN_SUPPORT_LOCK_BYTES)
    return parse_toolchain_support_lock(data, expected_raw_sha256=expected_raw_sha256)


def verify_toolchain_support_lock(
    lock: ToolchainSupportLock,
    *,
    manifests: Sequence[ToolchainSupportLocator],
    roots: Sequence[ToolchainSupportLocator],
) -> bool:
    """Rewalk exact private locators and compare them with a parsed lock.

    Roles form the join key and must match exactly once across both locator
    kinds.  Missing, extra, reclassified, or renamed roles fail before capture;
    changed bytes, modes, namespace members, or symlink targets fail when the
    fresh aggregate receipts are compared.
    """
    if type(lock) is not ToolchainSupportLock:
        raise ToolchainSupportLockError(
            "toolchain support verification requires an exact typed lock"
        )
    try:
        trusted_lock = parse_toolchain_support_lock(
            lock.canonical_bytes,
            expected_raw_sha256=lock.raw_sha256,
        )
    except ToolchainSupportLockError as exc:
        raise ToolchainSupportLockError(
            "toolchain support verification received a stale typed lock"
        ) from exc
    if trusted_lock != lock:
        raise ToolchainSupportLockError(
            "toolchain support verification received a stale typed lock"
        )
    lock = trusted_lock
    manifest_locators, root_locators = _validated_locator_sets(
        manifests=manifests,
        roots=roots,
    )
    expected_manifest_roles = tuple(item.logical_role for item in lock.manifests)
    expected_root_roles = tuple(item.logical_role for item in lock.roots)
    actual_manifest_roles = tuple(
        item.logical_role
        for item in sorted(
            manifest_locators,
            key=lambda item: (_alias(item.logical_role), item.logical_role),
        )
    )
    actual_root_roles = tuple(
        item.logical_role
        for item in sorted(
            root_locators,
            key=lambda item: (_alias(item.logical_role), item.logical_role),
        )
    )
    if (
        actual_manifest_roles != expected_manifest_roles
        or actual_root_roles != expected_root_roles
    ):
        raise ToolchainSupportLockError(
            "toolchain support locator roles or kinds differ from the lock"
        )
    observed_manifests, observed_roots = _capture_lock_receipts(
        manifests=manifest_locators,
        roots=root_locators,
    )
    if observed_manifests != lock.manifests or observed_roots != lock.roots:
        raise ToolchainSupportLockError(
            "toolchain support files or trees differ from the exact lock"
        )
    return True


def _capture_tree_once(
    locator: ToolchainSupportLocator,
    *,
    xattr_budget: _XattrBudget,
) -> ToolchainSupportTreeReceipt:
    starting_xattr_count = xattr_budget.remaining_count
    starting_xattr_bytes = xattr_budget.remaining_bytes
    chain = _open_directory_chain(locator._absolute_path)
    try:
        root_fd = chain[-1][0]
        opened_root = _stamp(os.fstat(root_fd))
        if not stat.S_ISDIR(opened_root.mode):
            raise ToolchainSupportLockError(
                "toolchain support root is not a directory"
            )
        _validate_mode(stat.S_IMODE(opened_root.mode))
        raw_entries: list[_RawTreeEntry] = []
        aliases: set[str] = set()
        inode_keys: set[tuple[int, int]] = set()
        total_bytes = [0]
        root_stamp, root_xattrs = _walk_tree(
            root_fd,
            root_path=locator._absolute_path,
            relative=PurePosixPath(),
            entries=raw_entries,
            aliases=aliases,
            inode_keys=inode_keys,
            total_bytes=total_bytes,
            xattr_budget=xattr_budget,
        )
        if not raw_entries:
            raise ToolchainSupportLockError("toolchain support root is empty")
        if not _same_stable_stamp(opened_root, root_stamp):
            raise ToolchainSupportLockError(
                "toolchain support root changed during capture"
            )
        _verify_directory_chain(chain)
    except ToolchainSupportLockError:
        raise
    except OSError as exc:
        raise ToolchainSupportLockError(
            "toolchain support tree could not be captured safely"
        ) from exc
    finally:
        _close_directory_chain(chain)
    entries_without_merkle = tuple(
        _ToolchainSupportTreeEntry(
            relative_path=item.relative_path,
            kind=item.kind,
            mode=item.mode,
            metadata_sha256=item.metadata_sha256,
            xattr_count=item.xattr_count,
            xattr_bytes=item.xattr_bytes,
            xattrs_sha256=item.xattrs_sha256,
            size=item.size,
            raw_sha256=item.raw_sha256,
            link_target=item.link_target,
            merkle_sha256="0" * 64,
        )
        for item in sorted(raw_entries, key=lambda item: (_alias(item.relative_path), item.relative_path))
    )
    _validate_tree_namespace(entries_without_merkle, validate_merkle=False)
    entries, merkle = _build_tree_merkle(
        logical_role=locator.logical_role,
        locator_path_sha256=_locator_path_digest(locator._absolute_path),
        root_mode=stat.S_IMODE(root_stamp.mode),
        root_metadata_sha256=_metadata_digest(root_stamp, kind="directory"),
        root_xattrs=root_xattrs,
        entries=entries_without_merkle,
    )
    xattr_count = root_xattrs.count + sum(item.xattr_count for item in entries)
    xattr_bytes = root_xattrs.total_bytes + sum(item.xattr_bytes for item in entries)
    if (
        xattr_count > MAX_TOOLCHAIN_SUPPORT_TREE_XATTRS
        or xattr_bytes > MAX_TOOLCHAIN_SUPPORT_TREE_XATTR_BYTES
    ):
        raise ToolchainSupportLockError(
            "toolchain support tree xattr aggregate exceeds the bound"
        )
    if (
        xattr_count != starting_xattr_count - xattr_budget.remaining_count
        or xattr_bytes != starting_xattr_bytes - xattr_budget.remaining_bytes
    ):
        raise ToolchainSupportLockError(
            "toolchain support tree xattr accounting is inconsistent"
        )
    return ToolchainSupportTreeReceipt(
        logical_role=locator.logical_role,
        locator_path_sha256=_locator_path_digest(locator._absolute_path),
        root_metadata_sha256=_metadata_digest(root_stamp, kind="directory"),
        root_mode=stat.S_IMODE(root_stamp.mode),
        member_count=len(entries),
        file_count=sum(item.kind == "file" for item in entries),
        directory_count=sum(item.kind == "directory" for item in entries),
        symlink_count=sum(item.kind == "symlink" for item in entries),
        total_bytes=sum(item.size for item in entries if item.kind == "file"),
        xattr_count=xattr_count,
        xattr_bytes=xattr_bytes,
        merkle_sha256=merkle,
    )


def _walk_tree(
    directory_fd: int,
    *,
    root_path: Path,
    relative: PurePosixPath,
    entries: list[_RawTreeEntry],
    aliases: set[str],
    inode_keys: set[tuple[int, int]],
    total_bytes: list[int],
    xattr_budget: _XattrBudget,
) -> tuple[_FilesystemStamp, _XattrReceipt]:
    directory_before = _stamp(os.fstat(directory_fd))
    if not stat.S_ISDIR(directory_before.mode):
        raise ToolchainSupportLockError("toolchain support directory identity is invalid")
    directory_xattrs = _capture_fd_xattrs(directory_fd, budget=xattr_budget)
    names = _bounded_directory_names(directory_fd)
    local_aliases: set[str] = set()
    for name in names:
        _validate_segment(name)
        alias = _alias(name)
        if alias in local_aliases:
            raise ToolchainSupportLockError(
                "toolchain support directory contains an NFC/casefold alias"
            )
        local_aliases.add(alias)
    ordered = sorted(names, key=lambda item: (_alias(item), item))
    for name in ordered:
        child_relative = relative / name
        logical = child_relative.as_posix()
        _validate_relative_path(logical)
        if len(child_relative.parts) > MAX_TOOLCHAIN_SUPPORT_TREE_DEPTH:
            raise ToolchainSupportLockError(
                "toolchain support tree exceeds the depth bound"
            )
        logical_alias = _alias(logical)
        if logical_alias in aliases:
            raise ToolchainSupportLockError(
                "toolchain support tree contains an NFC/casefold path alias"
            )
        aliases.add(logical_alias)
        if len(entries) >= MAX_TOOLCHAIN_SUPPORT_TREE_MEMBERS:
            raise ToolchainSupportLockError(
                "toolchain support tree member count exceeds the bound"
            )
        observed = _stamp(os.stat(name, dir_fd=directory_fd, follow_symlinks=False))
        mode = stat.S_IMODE(observed.mode)
        _validate_mode(mode)
        if stat.S_ISDIR(observed.mode):
            child_fd = _open_child_directory(directory_fd, name)
            try:
                opened = _stamp(os.fstat(child_fd))
                if opened != observed:
                    raise ToolchainSupportLockError(
                        "toolchain support directory changed before capture"
                    )
                child_final, child_xattrs = _walk_tree(
                    child_fd,
                    root_path=root_path,
                    relative=child_relative,
                    entries=entries,
                    aliases=aliases,
                    inode_keys=inode_keys,
                    total_bytes=total_bytes,
                    xattr_budget=xattr_budget,
                )
                linked = _stamp(
                    os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                )
                if (
                    not _same_stable_stamp(opened, child_final)
                    or linked != child_final
                ):
                    raise ToolchainSupportLockError(
                        "toolchain support directory changed during capture"
                    )
                entries.append(
                    _RawTreeEntry(
                        relative_path=logical,
                        kind="directory",
                        mode=stat.S_IMODE(child_final.mode),
                        metadata_sha256=_metadata_digest(
                            child_final, kind="directory"
                        ),
                        xattr_count=child_xattrs.count,
                        xattr_bytes=child_xattrs.total_bytes,
                        xattrs_sha256=child_xattrs.merkle_sha256,
                        size=0,
                        raw_sha256=None,
                        link_target=None,
                    )
                )
            finally:
                os.close(child_fd)
            continue
        if stat.S_ISREG(observed.mode):
            _require_unaliased_inode(observed, inode_keys, label="regular file")
            if observed.size > MAX_TOOLCHAIN_SUPPORT_FILE_BYTES:
                raise ToolchainSupportLockError(
                    "toolchain support file exceeds the byte bound"
                )
            if total_bytes[0] + observed.size > MAX_TOOLCHAIN_SUPPORT_TREE_BYTES:
                raise ToolchainSupportLockError(
                    "toolchain support tree byte count exceeds the bound"
                )
            file_fd = _open_regular_file(directory_fd, name)
            try:
                opened = _stamp(os.fstat(file_fd))
                if opened != observed:
                    raise ToolchainSupportLockError(
                        "toolchain support file changed before capture"
                    )
                xattrs = _capture_fd_xattrs(file_fd, budget=xattr_budget)
                digest, size, final_stamp = _stream_file_digest(
                    file_fd,
                    expected=opened,
                    maximum=MAX_TOOLCHAIN_SUPPORT_FILE_BYTES,
                )
                linked = _stamp(
                    os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                )
                if linked != final_stamp:
                    raise ToolchainSupportLockError(
                        "toolchain support file link changed during capture"
                    )
            finally:
                os.close(file_fd)
            total_bytes[0] += size
            entries.append(
                _RawTreeEntry(
                    relative_path=logical,
                    kind="file",
                    mode=stat.S_IMODE(final_stamp.mode),
                    metadata_sha256=_metadata_digest(final_stamp, kind="file"),
                    xattr_count=xattrs.count,
                    xattr_bytes=xattrs.total_bytes,
                    xattrs_sha256=xattrs.merkle_sha256,
                    size=size,
                    raw_sha256=digest,
                    link_target=None,
                )
            )
            continue
        if stat.S_ISLNK(observed.mode):
            _require_unaliased_inode(observed, inode_keys, label="symlink")
            try:
                target = os.readlink(name, dir_fd=directory_fd)
            except OSError as exc:
                raise ToolchainSupportLockError(
                    "toolchain support symlink could not be read safely"
                ) from exc
            _validate_link_target(target)
            target_bytes = target.encode("utf-8")
            if len(target_bytes) > MAX_TOOLCHAIN_SUPPORT_SYMLINK_BYTES:
                raise ToolchainSupportLockError(
                    "toolchain support symlink target exceeds the byte bound"
                )
            xattrs = _capture_symlink_xattrs(
                root_path / child_relative,
                budget=xattr_budget,
            )
            final_stamp = _stamp(
                os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            )
            if not _same_stable_stamp(observed, final_stamp):
                raise ToolchainSupportLockError(
                    "toolchain support symlink changed during capture"
                )
            entries.append(
                _RawTreeEntry(
                    relative_path=logical,
                    kind="symlink",
                    mode=stat.S_IMODE(final_stamp.mode),
                    metadata_sha256=_metadata_digest(final_stamp, kind="symlink"),
                    xattr_count=xattrs.count,
                    xattr_bytes=xattrs.total_bytes,
                    xattrs_sha256=xattrs.merkle_sha256,
                    size=len(target_bytes),
                    raw_sha256=hashlib.sha256(target_bytes).hexdigest(),
                    link_target=target,
                )
            )
            continue
        raise ToolchainSupportLockError(
            "toolchain support tree contains a special file"
        )
    after_names = _bounded_directory_names(directory_fd)
    if sorted(after_names, key=lambda item: (_alias(item), item)) != ordered:
        raise ToolchainSupportLockError(
            "toolchain support directory inventory changed during capture"
        )
    directory_after = _stamp(os.fstat(directory_fd))
    if not _same_stable_stamp(directory_after, directory_before):
        raise ToolchainSupportLockError(
            "toolchain support directory changed during capture"
        )
    return directory_after, directory_xattrs


def _bounded_directory_names(directory_fd: int) -> list[str]:
    names: list[str] = []
    try:
        with os.scandir(directory_fd) as iterator:
            for entry in iterator:
                if len(names) >= MAX_TOOLCHAIN_SUPPORT_DIRECTORY_ENTRIES:
                    raise ToolchainSupportLockError(
                        "toolchain support directory entry count exceeds the bound"
                    )
                name = entry.name
                _validate_segment(name)
                names.append(name)
    except ToolchainSupportLockError:
        raise
    except OSError as exc:
        raise ToolchainSupportLockError(
            "toolchain support directory could not be inventoried"
        ) from exc
    return names


def _capture_fd_xattrs(
    descriptor: int,
    *,
    budget: _XattrBudget,
) -> _XattrReceipt:
    return _capture_xattrs(
        list_names=lambda: _list_fd_xattr_names(descriptor),
        read_value=lambda name, maximum: _read_fd_xattr(
            descriptor,
            name,
            maximum_value_bytes=maximum,
        ),
        budget=budget,
    )


def _capture_symlink_xattrs(
    path: Path,
    *,
    budget: _XattrBudget,
) -> _XattrReceipt:
    path_bytes = os.fsencode(path)
    return _capture_xattrs(
        list_names=lambda: _list_symlink_xattr_names(path_bytes),
        read_value=lambda name, maximum: _read_symlink_xattr(
            path_bytes,
            name,
            maximum_value_bytes=maximum,
        ),
        budget=budget,
    )


def _capture_xattrs(
    *,
    list_names: Callable[[], tuple[bytes, ...]],
    read_value: Callable[[bytes, int], bytes],
    budget: _XattrBudget,
) -> _XattrReceipt:
    try:
        names = tuple(sorted(list_names()))
    except ToolchainSupportLockError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise ToolchainSupportLockError(
            "toolchain support xattr names could not be captured"
        ) from exc
    if (
        len(names) > MAX_TOOLCHAIN_SUPPORT_XATTRS_PER_MEMBER
        or len(set(names)) != len(names)
        or any(
            type(name) is not bytes
            or not name
            or len(name) > MAX_TOOLCHAIN_SUPPORT_XATTR_NAME_BYTES
            or b"\0" in name
            for name in names
        )
    ):
        raise ToolchainSupportLockError(
            "toolchain support xattr name set is invalid or exceeds the bound"
        )
    items: list[dict[str, object]] = []
    total_bytes = 0
    for name in names:
        member_remaining = MAX_TOOLCHAIN_SUPPORT_TREE_XATTR_BYTES - total_bytes
        if (
            budget.remaining_count <= 0
            or len(name) > budget.remaining_bytes
            or len(name) > member_remaining
        ):
            raise ToolchainSupportLockError(
                "toolchain support xattr aggregate exceeds the remaining budget"
            )
        maximum_value_bytes = min(
            budget.remaining_bytes - len(name),
            member_remaining - len(name),
        )
        try:
            value = read_value(name, maximum_value_bytes)
        except ToolchainSupportLockError:
            raise
        except (OSError, TypeError, ValueError) as exc:
            raise ToolchainSupportLockError(
                "toolchain support xattr value could not be captured"
            ) from exc
        if (
            type(value) is not bytes
            or len(value) > MAX_TOOLCHAIN_SUPPORT_XATTR_VALUE_BYTES
            or len(value) > maximum_value_bytes
        ):
            raise ToolchainSupportLockError(
                "toolchain support xattr value exceeds the bound or remaining budget"
            )
        item_bytes = len(name) + len(value)
        budget.consume(count=1, total_bytes=item_bytes)
        total_bytes += item_bytes
        items.append(
            {
                "name_hex": name.hex(),
                "size": len(value),
                "raw_sha256": hashlib.sha256(value).hexdigest(),
            }
        )
    if tuple(sorted(list_names())) != names:
        raise ToolchainSupportLockError(
            "toolchain support xattr name set changed during capture"
        )
    return _XattrReceipt(
        count=len(items),
        total_bytes=total_bytes,
        merkle_sha256=_sha256(
            {
                "domain": "rextio.full-c6-toolchain-support-xattrs.v1",
                "items": items,
            }
        ),
    )


def _libc_xattr_function(name: str) -> Any:
    if sys.platform not in {"darwin", "linux"}:
        raise ToolchainSupportLockError(
            "toolchain support xattr capture is unavailable on this platform"
        )
    try:
        function = getattr(ctypes.CDLL(None, use_errno=True), name)
    except (AttributeError, OSError) as exc:
        raise ToolchainSupportLockError(
            "toolchain support xattr capture is unavailable"
        ) from exc
    function.restype = ctypes.c_ssize_t
    return function


def _xattr_result(result: int, *, label: str, allow_unsupported: bool) -> int:
    if result >= 0:
        return result
    error = ctypes.get_errno()
    unsupported = {
        errno.ENOSYS,
        getattr(errno, "ENOTSUP", errno.EOPNOTSUPP),
        errno.EOPNOTSUPP,
    }
    if allow_unsupported and error in unsupported:
        return 0
    raise ToolchainSupportLockError(
        f"toolchain support {label} failed with errno {error}"
    )


def _split_xattr_names(value: bytes) -> tuple[bytes, ...]:
    if not value:
        return ()
    if len(value) > MAX_TOOLCHAIN_SUPPORT_XATTR_LIST_BYTES or not value.endswith(b"\0"):
        raise ToolchainSupportLockError(
            "toolchain support xattr name list is invalid or exceeds the bound"
        )
    names = tuple(value[:-1].split(b"\0"))
    if any(not name for name in names):
        raise ToolchainSupportLockError("toolchain support xattr name list is invalid")
    return names


def _validate_xattr_read_budget(value: int) -> int:
    if type(value) is not int or isinstance(value, bool) or value < 0:
        raise ToolchainSupportLockError(
            "toolchain support xattr read budget is invalid"
        )
    return value


def _list_fd_xattr_names(descriptor: int) -> tuple[bytes, ...]:
    function = _libc_xattr_function("flistxattr")
    ctypes.set_errno(0)
    if sys.platform == "darwin":
        size = _xattr_result(
            function(descriptor, None, 0, 0),
            label="fd xattr inventory",
            allow_unsupported=True,
        )
    else:
        size = _xattr_result(
            function(descriptor, None, 0),
            label="fd xattr inventory",
            allow_unsupported=True,
        )
    if size == 0:
        return ()
    if size > MAX_TOOLCHAIN_SUPPORT_XATTR_LIST_BYTES:
        raise ToolchainSupportLockError(
            "toolchain support xattr name list exceeds the bound"
        )
    buffer = ctypes.create_string_buffer(size)
    ctypes.set_errno(0)
    if sys.platform == "darwin":
        observed = _xattr_result(
            function(descriptor, buffer, size, 0),
            label="fd xattr inventory",
            allow_unsupported=False,
        )
    else:
        observed = _xattr_result(
            function(descriptor, buffer, size),
            label="fd xattr inventory",
            allow_unsupported=False,
        )
    if observed != size:
        raise ToolchainSupportLockError(
            "toolchain support xattr name list changed during capture"
        )
    return _split_xattr_names(buffer.raw[:observed])


def _read_fd_xattr(
    descriptor: int,
    name: bytes,
    *,
    maximum_value_bytes: int,
) -> bytes:
    _validate_xattr_read_budget(maximum_value_bytes)
    function = _libc_xattr_function("fgetxattr")
    name_pointer = ctypes.c_char_p(name)
    ctypes.set_errno(0)
    if sys.platform == "darwin":
        size = _xattr_result(
            function(descriptor, name_pointer, None, 0, 0, 0),
            label="fd xattr read",
            allow_unsupported=False,
        )
    else:
        size = _xattr_result(
            function(descriptor, name_pointer, None, 0),
            label="fd xattr read",
            allow_unsupported=False,
        )
    if (
        size > MAX_TOOLCHAIN_SUPPORT_XATTR_VALUE_BYTES
        or size > maximum_value_bytes
    ):
        raise ToolchainSupportLockError(
            "toolchain support xattr value exceeds the bound or remaining budget"
        )
    if size == 0:
        return b""
    buffer = ctypes.create_string_buffer(size)
    ctypes.set_errno(0)
    if sys.platform == "darwin":
        observed = _xattr_result(
            function(descriptor, name_pointer, buffer, size, 0, 0),
            label="fd xattr read",
            allow_unsupported=False,
        )
    else:
        observed = _xattr_result(
            function(descriptor, name_pointer, buffer, size),
            label="fd xattr read",
            allow_unsupported=False,
        )
    if observed != size:
        raise ToolchainSupportLockError(
            "toolchain support xattr value changed during capture"
        )
    return buffer.raw[:observed]


def _list_symlink_xattr_names(path: bytes) -> tuple[bytes, ...]:
    if sys.platform == "darwin":
        function = _libc_xattr_function("listxattr")

        def query(buffer: object, size: int) -> int:
            return function(path, buffer, size, 0x0001)
    else:
        function = _libc_xattr_function("llistxattr")

        def query(buffer: object, size: int) -> int:
            return function(path, buffer, size)
    ctypes.set_errno(0)
    size = _xattr_result(
        query(None, 0),
        label="symlink xattr inventory",
        allow_unsupported=True,
    )
    if size == 0:
        return ()
    if size > MAX_TOOLCHAIN_SUPPORT_XATTR_LIST_BYTES:
        raise ToolchainSupportLockError(
            "toolchain support xattr name list exceeds the bound"
        )
    buffer = ctypes.create_string_buffer(size)
    ctypes.set_errno(0)
    observed = _xattr_result(
        query(buffer, size),
        label="symlink xattr inventory",
        allow_unsupported=False,
    )
    if observed != size:
        raise ToolchainSupportLockError(
            "toolchain support symlink xattrs changed during capture"
        )
    return _split_xattr_names(buffer.raw[:observed])


def _read_symlink_xattr(
    path: bytes,
    name: bytes,
    *,
    maximum_value_bytes: int,
) -> bytes:
    _validate_xattr_read_budget(maximum_value_bytes)
    name_pointer = ctypes.c_char_p(name)
    if sys.platform == "darwin":
        function = _libc_xattr_function("getxattr")

        def query(buffer: object, size: int) -> int:
            return function(path, name_pointer, buffer, size, 0, 0x0001)
    else:
        function = _libc_xattr_function("lgetxattr")

        def query(buffer: object, size: int) -> int:
            return function(path, name_pointer, buffer, size)
    ctypes.set_errno(0)
    size = _xattr_result(
        query(None, 0),
        label="symlink xattr read",
        allow_unsupported=False,
    )
    if (
        size > MAX_TOOLCHAIN_SUPPORT_XATTR_VALUE_BYTES
        or size > maximum_value_bytes
    ):
        raise ToolchainSupportLockError(
            "toolchain support xattr value exceeds the bound or remaining budget"
        )
    if size == 0:
        return b""
    buffer = ctypes.create_string_buffer(size)
    ctypes.set_errno(0)
    observed = _xattr_result(
        query(buffer, size),
        label="symlink xattr read",
        allow_unsupported=False,
    )
    if observed != size:
        raise ToolchainSupportLockError(
            "toolchain support symlink xattr changed during capture"
        )
    return buffer.raw[:observed]


def _build_tree_merkle(
    *,
    logical_role: str,
    locator_path_sha256: str,
    root_mode: int,
    root_metadata_sha256: str,
    root_xattrs: _XattrReceipt,
    entries: tuple[_ToolchainSupportTreeEntry, ...],
) -> tuple[tuple[_ToolchainSupportTreeEntry, ...], str]:
    by_path = {item.relative_path: item for item in entries}
    children_by_parent: dict[str, list[str]] = {}
    for path in by_path:
        parent = PurePosixPath(path).parent
        parent_name = "" if parent == PurePosixPath(".") else parent.as_posix()
        children_by_parent.setdefault(parent_name, []).append(path)
    for children in children_by_parent.values():
        children.sort(key=lambda value: (_alias(value), value))
    digests: dict[str, str] = {}
    rebuilt: dict[str, _ToolchainSupportTreeEntry] = {}
    paths = sorted(
        by_path,
        key=lambda item: (-len(PurePosixPath(item).parts), _alias(item), item),
    )
    for path in paths:
        item = by_path[path]
        payload: dict[str, object] = {
            "domain": "rextio.full-c6-toolchain-support-node.v1",
            "relative_path": path,
            "kind": item.kind,
            "mode": item.mode,
            "metadata_sha256": item.metadata_sha256,
            "xattr_count": item.xattr_count,
            "xattr_bytes": item.xattr_bytes,
            "xattrs_sha256": item.xattrs_sha256,
        }
        if item.kind == "directory":
            payload["children"] = [
                {
                    "name": PurePosixPath(child).name,
                    "merkle_sha256": digests[child],
                }
                for child in children_by_parent.get(path, ())
            ]
        elif item.kind == "file":
            payload["size"] = item.size
            payload["raw_sha256"] = item.raw_sha256
        else:
            payload["size"] = item.size
            payload["raw_sha256"] = item.raw_sha256
            payload["link_target"] = item.link_target
        digest = _sha256(payload)
        digests[path] = digest
        rebuilt[path] = _ToolchainSupportTreeEntry(
            relative_path=item.relative_path,
            kind=item.kind,
            mode=item.mode,
            metadata_sha256=item.metadata_sha256,
            xattr_count=item.xattr_count,
            xattr_bytes=item.xattr_bytes,
            xattrs_sha256=item.xattrs_sha256,
            size=item.size,
            raw_sha256=item.raw_sha256,
            link_target=item.link_target,
            merkle_sha256=digest,
        )
    root_merkle = _sha256(
        {
            "domain": "rextio.full-c6-toolchain-support-tree.v1",
            "logical_role": logical_role,
            "locator_path_sha256": locator_path_sha256,
            "root_mode": root_mode,
            "root_metadata_sha256": root_metadata_sha256,
            "root_xattr_count": root_xattrs.count,
            "root_xattr_bytes": root_xattrs.total_bytes,
            "root_xattrs_sha256": root_xattrs.merkle_sha256,
            "member_count": len(entries),
            "file_count": sum(item.kind == "file" for item in entries),
            "directory_count": sum(item.kind == "directory" for item in entries),
            "symlink_count": sum(item.kind == "symlink" for item in entries),
            "total_bytes": sum(
                item.size for item in entries if item.kind == "file"
            ),
            "xattr_count": root_xattrs.count
            + sum(item.xattr_count for item in entries),
            "xattr_bytes": root_xattrs.total_bytes
            + sum(item.xattr_bytes for item in entries),
            "children": [
                {
                    "name": path,
                    "merkle_sha256": digests[path],
                }
                for path in children_by_parent.get("", ())
            ],
        }
    )
    return _canonical_entries(tuple(rebuilt.values())), root_merkle


def _validate_tree_namespace(
    entries: tuple[_ToolchainSupportTreeEntry, ...],
    *,
    validate_merkle: bool = True,
) -> None:
    by_path = {item.relative_path: item for item in entries}
    if len(by_path) != len(entries):
        raise ToolchainSupportLockError("toolchain support tree repeats a path")
    for item in entries:
        parts = PurePosixPath(item.relative_path).parts
        if len(parts) > MAX_TOOLCHAIN_SUPPORT_TREE_DEPTH:
            raise ToolchainSupportLockError(
                "toolchain support tree exceeds the depth bound"
            )
        for depth in range(1, len(parts)):
            parent = PurePosixPath(*parts[:depth]).as_posix()
            parent_entry = by_path.get(parent)
            if parent_entry is None or parent_entry.kind != "directory":
                raise ToolchainSupportLockError(
                    "toolchain support tree has a missing or nondirectory parent"
                )
        if item.kind == "symlink":
            assert item.link_target is not None
            _resolve_captured_link(item.relative_path, item.link_target, by_path)
        if validate_merkle:
            _require_sha256(item.merkle_sha256, "support tree member Merkle SHA-256")


def _resolve_captured_link(
    link_path: str,
    link_target: str,
    entries: dict[str, _ToolchainSupportTreeEntry],
) -> str:
    pending = list(PurePosixPath(link_path).parent.parts) + link_target.split("/")
    resolved: list[str] = []
    visited: set[str] = {link_path}
    hops = 0
    while pending:
        part = pending.pop(0)
        if part in {"", "."}:
            continue
        if part == "..":
            if not resolved:
                raise ToolchainSupportLockError(
                    "toolchain support symlink escapes its support root"
                )
            resolved.pop()
            continue
        resolved.append(part)
        candidate = PurePosixPath(*resolved).as_posix()
        node = entries.get(candidate)
        if node is not None and node.kind == "symlink":
            if candidate in visited:
                raise ToolchainSupportLockError(
                    "toolchain support symlink graph contains a cycle"
                )
            visited.add(candidate)
            hops += 1
            if hops > MAX_TOOLCHAIN_SUPPORT_TREE_DEPTH:
                raise ToolchainSupportLockError(
                    "toolchain support symlink graph exceeds the depth bound"
                )
            assert node.link_target is not None
            replacement = list(PurePosixPath(candidate).parent.parts) + node.link_target.split("/")
            pending = replacement + pending
            resolved = []
    if not resolved:
        return "."
    final = PurePosixPath(*resolved).as_posix()
    if final not in entries:
        raise ToolchainSupportLockError(
            "toolchain support symlink is broken or leaves the captured tree"
        )
    return final


def _new_lock(
    *,
    scope: ToolchainSupportScope,
    manifests: tuple[ToolchainSupportFileReceipt, ...],
    roots: tuple[ToolchainSupportTreeReceipt, ...],
) -> ToolchainSupportLock:
    provisional = ToolchainSupportLock.__new__(ToolchainSupportLock)
    object.__setattr__(provisional, "scope", scope)
    object.__setattr__(provisional, "manifests", manifests)
    object.__setattr__(provisional, "roots", roots)
    object.__setattr__(provisional, "manifest_count", len(manifests))
    object.__setattr__(provisional, "root_count", len(roots))
    object.__setattr__(
        provisional,
        "member_count",
        sum(item.member_count for item in manifests)
        + sum(item.member_count for item in roots),
    )
    object.__setattr__(
        provisional,
        "total_bytes",
        sum(item.total_bytes for item in manifests) + sum(item.total_bytes for item in roots),
    )
    object.__setattr__(
        provisional,
        "xattr_count",
        sum(item.xattr_count for item in manifests) + sum(item.xattr_count for item in roots),
    )
    object.__setattr__(
        provisional,
        "xattr_bytes",
        sum(item.xattr_bytes for item in manifests) + sum(item.xattr_bytes for item in roots),
    )
    object.__setattr__(provisional, "merkle_sha256", "")
    object.__setattr__(provisional, "kind", TOOLCHAIN_SUPPORT_LOCK_KIND)
    object.__setattr__(provisional, "schema_version", TOOLCHAIN_SUPPORT_LOCK_SCHEMA_VERSION)
    object.__setattr__(provisional, "domain", TOOLCHAIN_SUPPORT_LOCK_DOMAIN)
    object.__setattr__(provisional, "authorizes_build", False)
    object.__setattr__(provisional, "authorizes_distribution", False)
    merkle = _lock_merkle(provisional)
    return ToolchainSupportLock(
        scope=scope,
        manifests=manifests,
        roots=roots,
        manifest_count=len(manifests),
        root_count=len(roots),
        member_count=sum(item.member_count for item in manifests)
        + sum(item.member_count for item in roots),
        total_bytes=sum(item.total_bytes for item in manifests)
        + sum(item.total_bytes for item in roots),
        xattr_count=sum(item.xattr_count for item in manifests)
        + sum(item.xattr_count for item in roots),
        xattr_bytes=sum(item.xattr_bytes for item in manifests)
        + sum(item.xattr_bytes for item in roots),
        merkle_sha256=merkle,
    )


def _file_merkle(receipt: ToolchainSupportFileReceipt) -> str:
    return _sha256(
        {
            "domain": "rextio.full-c6-toolchain-support-file.v1",
            "logical_role": receipt.logical_role,
            "locator_path_sha256": receipt.locator_path_sha256,
            "metadata_sha256": receipt.metadata_sha256,
            "raw_sha256": receipt.raw_sha256,
            "size": receipt.size,
            "mode": receipt.mode,
            "xattr_count": receipt.xattr_count,
            "xattr_bytes": receipt.xattr_bytes,
            "xattrs_sha256": receipt.xattrs_sha256,
        }
    )


def _lock_merkle(lock: ToolchainSupportLock) -> str:
    return _sha256(
        {
            "domain": "rextio.full-c6-toolchain-support-aggregate.v1",
            "scope": lock.scope.to_dict(),
            "manifest_count": lock.manifest_count,
            "root_count": lock.root_count,
            "member_count": lock.member_count,
            "total_bytes": lock.total_bytes,
            "xattr_count": lock.xattr_count,
            "xattr_bytes": lock.xattr_bytes,
            "manifests": [
                {
                    "logical_role": item.logical_role,
                    "merkle_sha256": item.merkle_sha256,
                }
                for item in lock.manifests
            ],
            "roots": [
                {
                    "logical_role": item.logical_role,
                    "merkle_sha256": item.merkle_sha256,
                }
                for item in lock.roots
            ],
        }
    )


def _parse_scope(value: object) -> ToolchainSupportScope:
    document = _exact_dict(value, _SCOPE_FIELDS, "scope")
    return ToolchainSupportScope(
        target_triple=_string(document["target_triple"], "target triple"),
        profile=_string(document["profile"], "profile"),
        python_implementation=_string(
            document["python_implementation"], "Python implementation"
        ),
        python_version=_string(document["python_version"], "Python version"),
        rust_binding=_string(document["rust_binding"], "Rust binding"),
        artifact_kind=_string(document["artifact_kind"], "artifact kind"),
    )


def _parse_file(value: object) -> ToolchainSupportFileReceipt:
    document = _exact_dict(value, _FILE_FIELDS, "manifest receipt")
    return ToolchainSupportFileReceipt(
        logical_role=_string(document["logical_role"], "manifest role"),
        locator_path_sha256=_string(
            document["locator_path_sha256"], "manifest locator path SHA-256"
        ),
        metadata_sha256=_string(
            document["metadata_sha256"], "manifest metadata SHA-256"
        ),
        raw_sha256=_string(document["raw_sha256"], "manifest raw SHA-256"),
        size=_integer(document["size"], "manifest size"),
        mode=_integer(document["mode"], "manifest mode"),
        member_count=_integer(document["member_count"], "manifest member count"),
        total_bytes=_integer(document["total_bytes"], "manifest total bytes"),
        xattr_count=_integer(document["xattr_count"], "manifest xattr count"),
        xattr_bytes=_integer(document["xattr_bytes"], "manifest xattr bytes"),
        xattrs_sha256=_string(
            document["xattrs_sha256"], "manifest xattr SHA-256"
        ),
        merkle_sha256=_string(document["merkle_sha256"], "manifest Merkle SHA-256"),
    )


def _parse_tree(value: object) -> ToolchainSupportTreeReceipt:
    document = _exact_dict(value, _TREE_FIELDS, "tree receipt")
    return ToolchainSupportTreeReceipt(
        logical_role=_string(document["logical_role"], "tree role"),
        locator_path_sha256=_string(
            document["locator_path_sha256"], "tree locator path SHA-256"
        ),
        root_metadata_sha256=_string(
            document["root_metadata_sha256"], "tree root metadata SHA-256"
        ),
        root_mode=_integer(document["root_mode"], "tree root mode"),
        member_count=_integer(document["member_count"], "tree member count"),
        file_count=_integer(document["file_count"], "tree file count"),
        directory_count=_integer(document["directory_count"], "tree directory count"),
        symlink_count=_integer(document["symlink_count"], "tree symlink count"),
        total_bytes=_integer(document["total_bytes"], "tree total bytes"),
        xattr_count=_integer(document["xattr_count"], "tree xattr count"),
        xattr_bytes=_integer(document["xattr_bytes"], "tree xattr bytes"),
        merkle_sha256=_string(document["merkle_sha256"], "tree Merkle SHA-256"),
    )


def _read_locator_bytes(locator: ToolchainSupportLocator, *, maximum: int) -> bytes:
    chain = _open_directory_chain(locator._absolute_path.parent)
    file_fd = -1
    try:
        parent_fd = chain[-1][0]
        name = locator._absolute_path.name
        expected = _stamp(os.stat(name, dir_fd=parent_fd, follow_symlinks=False))
        file_fd = _open_regular_file(parent_fd, name)
        opened = _stamp(os.fstat(file_fd))
        if opened != expected or opened.size <= 0 or opened.size > maximum:
            raise ToolchainSupportLockError(
                "toolchain support lock file identity is unsafe"
            )
        chunks: list[bytes] = []
        remaining = opened.size
        while remaining:
            chunk = os.read(file_fd, min(1024 * 1024, remaining))
            if not chunk:
                raise ToolchainSupportLockError(
                    "toolchain support lock file was truncated"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(file_fd, 1):
            raise ToolchainSupportLockError("toolchain support lock file grew")
        if (
            _stamp(os.fstat(file_fd)) != opened
            or _stamp(os.stat(name, dir_fd=parent_fd, follow_symlinks=False))
            != opened
        ):
            raise ToolchainSupportLockError(
                "toolchain support lock file changed during capture"
            )
        _verify_directory_chain(chain)
        return b"".join(chunks)
    except ToolchainSupportLockError:
        raise
    except OSError as exc:
        raise ToolchainSupportLockError(
            "toolchain support lock file could not be read safely"
        ) from exc
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        _close_directory_chain(chain)


def _open_directory_chain(
    path: Path,
) -> list[tuple[int, int | None, str | None, _FilesystemStamp]]:
    nofollow = _require_flag("O_NOFOLLOW")
    directory = _require_flag("O_DIRECTORY")
    flags = os.O_RDONLY | nofollow | directory | getattr(os, "O_CLOEXEC", 0)
    absolute = _validate_absolute_locator(path)
    handles: list[tuple[int, int | None, str | None, _FilesystemStamp]] = []
    try:
        current_fd = os.open(absolute.anchor, flags)
        anchor = _stamp(os.fstat(current_fd))
        if not stat.S_ISDIR(anchor.mode):
            raise ToolchainSupportLockError(
                "toolchain support locator anchor is not a directory"
            )
        handles.append((current_fd, None, None, anchor))
        for part in absolute.parts[1:]:
            _validate_segment(part)
            child_fd = os.open(part, flags, dir_fd=current_fd)
            child = _stamp(os.fstat(child_fd))
            linked = _stamp(os.stat(part, dir_fd=current_fd, follow_symlinks=False))
            if child != linked or not stat.S_ISDIR(child.mode):
                os.close(child_fd)
                raise ToolchainSupportLockError(
                    "toolchain support locator directory changed"
                )
            handles.append((child_fd, current_fd, part, child))
            current_fd = child_fd
        return handles
    except ToolchainSupportLockError:
        _close_directory_chain(handles)
        raise
    except OSError as exc:
        _close_directory_chain(handles)
        raise ToolchainSupportLockError(
            "toolchain support locator requires a symlink-free directory walk"
        ) from exc


def _verify_directory_chain(
    chain: list[tuple[int, int | None, str | None, _FilesystemStamp]],
) -> None:
    for descriptor, parent_fd, name, expected in chain:
        actual = _stamp(os.fstat(descriptor))
        if not _same_stable_stamp(actual, expected) or not stat.S_ISDIR(actual.mode):
            raise ToolchainSupportLockError(
                "toolchain support locator directory changed during capture"
            )
        if parent_fd is not None and name is not None:
            linked = _stamp(os.stat(name, dir_fd=parent_fd, follow_symlinks=False))
            if linked != actual:
                raise ToolchainSupportLockError(
                    "toolchain support locator link changed during capture"
                )


def _close_directory_chain(
    chain: list[tuple[int, int | None, str | None, _FilesystemStamp]],
) -> None:
    for descriptor, _parent_fd, _name, _stamp_value in reversed(chain):
        try:
            os.close(descriptor)
        except OSError:
            pass


def _open_child_directory(parent_fd: int, name: str) -> int:
    return os.open(
        name,
        os.O_RDONLY
        | _require_flag("O_NOFOLLOW")
        | _require_flag("O_DIRECTORY")
        | getattr(os, "O_CLOEXEC", 0),
        dir_fd=parent_fd,
    )


def _open_regular_file(parent_fd: int, name: str) -> int:
    flags = (
        os.O_RDONLY
        | _require_flag("O_NOFOLLOW")
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(name, flags, dir_fd=parent_fd)
    opened = _stamp(os.fstat(descriptor))
    if not stat.S_ISREG(opened.mode) or opened.links != 1:
        os.close(descriptor)
        raise ToolchainSupportLockError(
            "toolchain support file must be a single-link regular file"
        )
    _validate_mode(stat.S_IMODE(opened.mode))
    return descriptor


def _stream_file_digest(
    descriptor: int,
    *,
    expected: _FilesystemStamp,
    maximum: int,
) -> tuple[str, int, _FilesystemStamp]:
    if (
        not stat.S_ISREG(expected.mode)
        or expected.links != 1
        or expected.size < 0
        or expected.size > maximum
    ):
        raise ToolchainSupportLockError(
            "toolchain support file identity is outside the bound"
        )
    digest = hashlib.sha256()
    remaining = expected.size
    total = 0
    while remaining:
        try:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
        except OSError as exc:
            raise ToolchainSupportLockError(
                "toolchain support file streaming read failed"
            ) from exc
        if not chunk:
            raise ToolchainSupportLockError(
                "toolchain support file was truncated during capture"
            )
        digest.update(chunk)
        total += len(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise ToolchainSupportLockError(
            "toolchain support file grew during capture"
        )
    final_stamp = _stamp(os.fstat(descriptor))
    if not _same_stable_stamp(final_stamp, expected) or total != expected.size:
        raise ToolchainSupportLockError(
            "toolchain support file changed during capture"
        )
    return digest.hexdigest(), total, final_stamp


def _parse_json(value: bytes) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise ToolchainSupportLockError(
                    "toolchain support lock contains a duplicate object key"
                )
            result[key] = item
        return result

    def reject_constant(_value: str) -> object:
        raise ToolchainSupportLockError(
            "toolchain support lock contains non-finite JSON"
        )

    try:
        parsed = json.loads(
            value.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except ToolchainSupportLockError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ToolchainSupportLockError(
            "toolchain support lock is not valid JSON"
        ) from exc
    if type(parsed) is not dict:
        raise ToolchainSupportLockError(
            "toolchain support lock root must be an object"
        )
    _assert_json_depth(parsed, depth=0)
    return cast(dict[str, object], parsed)


def _assert_json_depth(value: object, *, depth: int) -> None:
    if depth > MAX_TOOLCHAIN_SUPPORT_JSON_DEPTH:
        raise ToolchainSupportLockError(
            "toolchain support lock JSON nesting exceeds the bound"
        )
    if type(value) is dict:
        for child in cast(dict[str, object], value).values():
            _assert_json_depth(child, depth=depth + 1)
    elif type(value) is list:
        for child in cast(list[object], value):
            _assert_json_depth(child, depth=depth + 1)


def _validate_absolute_locator(value: Path | str) -> Path:
    if isinstance(value, Path):
        text = str(value)
    elif type(value) is str:
        text = value
    else:
        raise ToolchainSupportLockError(
            "toolchain support locator path must be a string or pathlib.Path"
        )
    if (
        not text.startswith("/")
        or text.startswith("//")
        or text.endswith("/")
        or "\\" in text
        or "\0" in text
        or text != unicodedata.normalize("NFC", text)
    ):
        raise ToolchainSupportLockError(
            "toolchain support locator path must be absolute, NFC, and canonical"
        )
    path = Path(text)
    if not path.is_absolute() or path.anchor != "/" or len(path.parts) < 2:
        raise ToolchainSupportLockError(
            "toolchain support locator path must name an item below the root"
        )
    if path.as_posix() != text or any(part in {"", ".", ".."} for part in path.parts[1:]):
        raise ToolchainSupportLockError(
            "toolchain support locator path is lexically noncanonical"
        )
    for part in path.parts[1:]:
        _validate_segment(part)
    return path


def _validate_role(value: object) -> str:
    if (
        type(value) is not str
        or _ROLE_RE.fullmatch(value) is None
        or value != unicodedata.normalize("NFC", value)
    ):
        raise ToolchainSupportLockError("toolchain support logical role is invalid")
    return value


def _validate_relative_path(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > MAX_TOOLCHAIN_SUPPORT_PATH_CHARS
        or len(value.encode("utf-8")) > MAX_TOOLCHAIN_SUPPORT_PATH_BYTES
        or value != unicodedata.normalize("NFC", value)
    ):
        raise ToolchainSupportLockError(
            "toolchain support relative path is invalid or exceeds the bound"
        )
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if (
        posix.is_absolute()
        or windows.is_absolute()
        or bool(windows.drive)
        or posix.as_posix() != value
        or "\\" in value
        or any(part in {"", ".", ".."} for part in posix.parts)
    ):
        raise ToolchainSupportLockError(
            "toolchain support relative path is noncanonical"
        )
    for part in posix.parts:
        _validate_segment(part)
    return value


def _validate_segment(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or value in {".", ".."}
        or len(value.encode("utf-8")) > 255
        or "/" in value
        or "\\" in value
        or "\0" in value
        or value != value.strip()
        or value != unicodedata.normalize("NFC", value)
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ToolchainSupportLockError(
            "toolchain support path segment is unsafe or noncanonical"
        )
    return value


def _validate_link_target(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or len(value.encode("utf-8")) > MAX_TOOLCHAIN_SUPPORT_SYMLINK_BYTES
        or value.startswith("/")
        or value.startswith("//")
        or value.endswith("/")
        or "\\" in value
        or "\0" in value
        or value != unicodedata.normalize("NFC", value)
        or "//" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ToolchainSupportLockError(
            "toolchain support symlink target is unsafe or noncanonical"
        )
    windows = PureWindowsPath(value)
    if windows.is_absolute() or bool(windows.drive):
        raise ToolchainSupportLockError(
            "toolchain support symlink target must be relative"
        )
    for part in value.split("/"):
        if part not in {".", ".."}:
            _validate_segment(part)
    return value


def _validate_size(value: object, *, maximum: int) -> int:
    if type(value) is not int or isinstance(value, bool) or not 0 <= value <= maximum:
        raise ToolchainSupportLockError("toolchain support byte size is invalid")
    return value


def _validate_xattr_summary(count: object, total_bytes: object) -> None:
    if (
        type(count) is not int
        or isinstance(count, bool)
        or not 0 <= count <= MAX_TOOLCHAIN_SUPPORT_XATTRS_PER_MEMBER
        or type(total_bytes) is not int
        or isinstance(total_bytes, bool)
        or not 0 <= total_bytes <= MAX_TOOLCHAIN_SUPPORT_TREE_XATTR_BYTES
    ):
        raise ToolchainSupportLockError(
            "toolchain support xattr summary is invalid or exceeds the bound"
        )


def _validate_mode(value: object) -> int:
    if (
        type(value) is not int
        or isinstance(value, bool)
        or value < 0
        or value > 0o777
    ):
        raise ToolchainSupportLockError("toolchain support permission mode is invalid")
    return value


def _require_unaliased_inode(
    value: _FilesystemStamp,
    inode_keys: set[tuple[int, int]],
    *,
    label: str,
) -> None:
    if value.links != 1:
        raise ToolchainSupportLockError(
            f"toolchain support {label} is a shared hardlink"
        )
    key = value.device, value.inode
    if key in inode_keys:
        raise ToolchainSupportLockError(
            f"toolchain support {label} reuses an inode"
        )
    inode_keys.add(key)


def _require_locator(locator: object, *, kind: str) -> ToolchainSupportLocator:
    if type(locator) is not ToolchainSupportLocator or locator.kind != kind:
        raise ToolchainSupportLockError(
            f"toolchain support capture requires an exact {kind} locator"
        )
    _validate_role(locator.logical_role)
    if _validate_absolute_locator(locator._absolute_path) != locator._absolute_path:
        raise ToolchainSupportLockError(
            "toolchain support locator path is stale"
        )
    return locator


def _validated_locator_sets(
    *,
    manifests: Sequence[ToolchainSupportLocator],
    roots: Sequence[ToolchainSupportLocator],
) -> tuple[tuple[ToolchainSupportLocator, ...], tuple[ToolchainSupportLocator, ...]]:
    if (
        isinstance(manifests, (str, bytes))
        or isinstance(roots, (str, bytes))
        or not isinstance(manifests, Sequence)
        or not isinstance(roots, Sequence)
        or not 1 <= len(manifests) <= MAX_TOOLCHAIN_SUPPORT_LOCATORS
        or not 1 <= len(roots) <= MAX_TOOLCHAIN_SUPPORT_LOCATORS
    ):
        raise ToolchainSupportLockError(
            "toolchain support verification requires bounded explicit locators"
        )
    manifest_locators = tuple(manifests)
    root_locators = tuple(roots)
    for item in manifest_locators:
        _require_locator(item, kind="file")
    for item in root_locators:
        _require_locator(item, kind="tree")
    roles = [item.logical_role for item in manifest_locators] + [
        item.logical_role for item in root_locators
    ]
    if len({_alias(item) for item in roles}) != len(roles):
        raise ToolchainSupportLockError(
            "toolchain support locators contain an NFC/casefold role alias"
        )
    return manifest_locators, root_locators


def _require_flag(name: str) -> int:
    value = getattr(os, name, None)
    if type(value) is not int or value == 0:
        raise ToolchainSupportLockError(
            "toolchain support secure descriptor operations are unavailable"
        )
    return value


def _stamp(value: os.stat_result) -> _FilesystemStamp:
    birthtime_ns = getattr(value, "st_birthtime_ns", None)
    if birthtime_ns is None and hasattr(value, "st_birthtime"):
        birthtime_ns = int(value.st_birthtime * 1_000_000_000)
    return _FilesystemStamp(
        device=value.st_dev,
        inode=value.st_ino,
        mode=value.st_mode,
        uid=value.st_uid,
        gid=value.st_gid,
        links=value.st_nlink,
        size=value.st_size,
        ctime_ns=getattr(value, "st_ctime_ns", int(value.st_ctime * 1_000_000_000)),
        mtime_ns=getattr(value, "st_mtime_ns", int(value.st_mtime * 1_000_000_000)),
        flags=getattr(value, "st_flags", None),
        birthtime_ns=birthtime_ns,
        blocks=getattr(value, "st_blocks", None),
        block_size=getattr(value, "st_blksize", None),
    )


def _same_stable_stamp(left: _FilesystemStamp, right: _FilesystemStamp) -> bool:
    return left == right


def _metadata_digest(value: _FilesystemStamp, *, kind: str) -> str:
    if kind not in {"file", "directory", "symlink"}:
        raise ToolchainSupportLockError("toolchain support metadata kind is invalid")
    return _sha256(
        {
            "domain": "rextio.full-c6-toolchain-support-stat.v1",
            "kind": kind,
            "device": value.device,
            "inode": value.inode,
            "mode": value.mode,
            "uid": value.uid,
            "gid": value.gid,
            "links": value.links,
            "size": value.size,
            "ctime_ns": value.ctime_ns,
            "mtime_ns": value.mtime_ns,
            "flags": value.flags,
            "birthtime_ns": value.birthtime_ns,
            "blocks": value.blocks,
            "block_size": value.block_size,
        }
    )


def _locator_path_digest(path: Path) -> str:
    return _sha256(
        {
            "domain": "rextio.full-c6-toolchain-support-locator-path.v1",
            "absolute_path": str(_validate_absolute_locator(path)),
        }
    )


def _canonical_entries(
    entries: tuple[_ToolchainSupportTreeEntry, ...],
) -> tuple[_ToolchainSupportTreeEntry, ...]:
    return tuple(
        sorted(entries, key=lambda item: (_alias(item.relative_path), item.relative_path))
    )


def _canonical_receipts(
    value: tuple[_RoleReceiptT, ...],
) -> tuple[_RoleReceiptT, ...]:
    return tuple(
        sorted(
            value,
            key=lambda item: (_alias(item.logical_role), item.logical_role),
        )
    )


def _alias(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def _exact_dict(value: object, fields: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != fields:
        raise ToolchainSupportLockError(
            f"toolchain support {label} schema is invalid"
        )
    return cast(dict[str, object], value)


def _list(value: object, label: str) -> list[object]:
    if type(value) is not list:
        raise ToolchainSupportLockError(f"toolchain support {label} must be an array")
    return cast(list[object], value)


def _bounded_list(value: object, label: str, *, maximum: int) -> list[object]:
    result = _list(value, label)
    if not 1 <= len(result) <= maximum:
        raise ToolchainSupportLockError(
            f"toolchain support {label} count is outside the bound"
        )
    return result


def _string(value: object, label: str) -> str:
    if type(value) is not str:
        raise ToolchainSupportLockError(f"toolchain support {label} must be a string")
    return value


def _integer(value: object, label: str) -> int:
    if type(value) is not int or isinstance(value, bool):
        raise ToolchainSupportLockError(f"toolchain support {label} must be an integer")
    return value


def _require_sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise ToolchainSupportLockError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise ToolchainSupportLockError(
            "toolchain support value cannot be canonicalized"
        ) from exc


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


__all__ = [
    "MAX_TOOLCHAIN_SUPPORT_DIRECTORY_ENTRIES",
    "MAX_TOOLCHAIN_SUPPORT_FILE_BYTES",
    "MAX_TOOLCHAIN_SUPPORT_JSON_DEPTH",
    "MAX_TOOLCHAIN_SUPPORT_LOCATORS",
    "MAX_TOOLCHAIN_SUPPORT_LOCK_BYTES",
    "MAX_TOOLCHAIN_SUPPORT_LOCK_XATTR_BYTES",
    "MAX_TOOLCHAIN_SUPPORT_LOCK_XATTRS",
    "MAX_TOOLCHAIN_SUPPORT_PATH_BYTES",
    "MAX_TOOLCHAIN_SUPPORT_PATH_CHARS",
    "MAX_TOOLCHAIN_SUPPORT_SYMLINK_BYTES",
    "MAX_TOOLCHAIN_SUPPORT_TREE_BYTES",
    "MAX_TOOLCHAIN_SUPPORT_TREE_DEPTH",
    "MAX_TOOLCHAIN_SUPPORT_TREE_MEMBERS",
    "MAX_TOOLCHAIN_SUPPORT_TREE_XATTR_BYTES",
    "MAX_TOOLCHAIN_SUPPORT_TREE_XATTRS",
    "MAX_TOOLCHAIN_SUPPORT_XATTR_LIST_BYTES",
    "MAX_TOOLCHAIN_SUPPORT_XATTR_NAME_BYTES",
    "MAX_TOOLCHAIN_SUPPORT_XATTR_VALUE_BYTES",
    "MAX_TOOLCHAIN_SUPPORT_XATTRS_PER_MEMBER",
    "TOOLCHAIN_SUPPORT_LOCK_DOMAIN",
    "TOOLCHAIN_SUPPORT_LOCK_KIND",
    "TOOLCHAIN_SUPPORT_LOCK_SCHEMA_VERSION",
    "TOOLCHAIN_SUPPORT_SCOPE",
    "TOOLCHAIN_SUPPORT_TARGETS",
    "ToolchainSupportFileReceipt",
    "ToolchainSupportLocator",
    "ToolchainSupportLock",
    "ToolchainSupportLockError",
    "ToolchainSupportScope",
    "ToolchainSupportTreeReceipt",
    "capture_toolchain_support_file",
    "capture_toolchain_support_tree",
    "create_toolchain_support_locator",
    "generate_toolchain_support_lock",
    "load_toolchain_support_lock",
    "parse_toolchain_support_lock",
    "verify_toolchain_support_lock",
]
