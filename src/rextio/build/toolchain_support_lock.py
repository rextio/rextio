"""Bounded exact support-file locks for the Full C6 host toolchain.

This module is deliberately independent from tool discovery and execution.  A
caller supplies explicit, path-bearing locators; capture turns them into a
canonical lock containing only opaque locator-path digests.  The lock describes
only the narrow CPython 3.11 / PyO3 host-cdylib profile and does not authorize a
build or distribution.

Regular files are streamed through descriptor-pinned, no-follow opens.  Trees
are inventoried without following links.  Relative symlinks normally must
terminate at another member in the same tree.  The Linux host profile adds one
acyclic GCC-support-to-runtime-support edge whose target tree is captured both
before and after the source; every other absolute, escaping, broken, cyclic,
or re-escaping link fails closed.
Content Merkle nodes also bind stable observable stat metadata and exact
bounded xattr name/value receipts (including macOS resource forks).  Volatile
access times are deliberately excluded.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
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
TOOLCHAIN_SUPPORT_LOCK_DOMAIN = "rextio.full-c6-toolchain-support-lock.v5"
TOOLCHAIN_SUPPORT_LOCK_SCHEMA_VERSION = 5
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
_XCODE_DEFAULT_TOOLCHAIN = Path(
    "/Applications/Xcode.app/Contents/Developer/Toolchains/"
    "XcodeDefault.xctoolchain"
)
_XCODE_APP_BOUNDARY = Path("/Applications/Xcode.app")
_XCODE_HARDLINK_ROLE = "xcode-clang-resource"
_XCODE_RESOURCE_ROOT = _XCODE_DEFAULT_TOOLCHAIN / "usr/lib/clang/17"
_XCODE_RESOURCE_ROOT_LOCATOR_PATH_SHA256 = (
    "b1651ac788182662f8cb83412e9bd39c0997fd955e675067ce577bc212f40d78"
)
_XCODE_VERSION_MANIFEST_ROLE = "xcode-version-plist"
_XCODE_VERSION_MANIFEST = _XCODE_APP_BOUNDARY / "Contents/version.plist"
_XCODE_VERSION_MANIFEST_LOCATOR_PATH_SHA256 = (
    "4bc0a3ad0c28086639932a1adb600483885d7a67afbd61310b638c7d647ac0f5"
)
_XCODE_VERSION_MANIFEST_RAW_SHA256 = (
    "b44fcf33ce9e1ac6759f5e71f682bcf734743e6ecd8ad6263116338236b25926"
)
_XCODE_HARDLINK_GROUP_COUNT = 121
_XCODE_HARDLINK_SUPPORT_MEMBER_COUNT = 121
_XCODE_HARDLINK_ALIAS_COUNT = 361
_XCODE_HARDLINK_POLICY_MERKLE_SHA256 = (
    "46dfe178bd85f3df653adbda460c674045acbc370c96e1a756564011e2a01e46"
)
_XCODE_SDK_HARDLINK_ROLE = "xcode-sdk"
_XCODE_SDK_ROOT = (
    _XCODE_APP_BOUNDARY
    / "Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"
)
_XCODE_SDK_ROOT_LOCATOR_PATH_SHA256 = (
    "06a2a3aad7cf447c6c6606bfbffc69f1de90229943e1b7d73e4b0534c73c35d0"
)
_XCODE_SDK_HARDLINK_GROUP_COUNT = 4_626
_XCODE_SDK_HARDLINK_SUPPORT_MEMBER_COUNT = 8_605
_XCODE_SDK_HARDLINK_ALIAS_COUNT = 24_430
_XCODE_SDK_HARDLINK_POLICY_MERKLE_SHA256 = (
    "6e5221cfc1d3ff7ca60fdae6b6f6bcc9b126af9dc62e57b4d0242368a018e4b8"
)
_XCODE_HARDLINK_SUPPORT_MAX_ENTRIES = 250_000
_XCODE_HARDLINK_APP_MAX_ENTRIES = 1_000_000
_XCODE_HARDLINK_MAX_GROUPS = 4_626
_XCODE_HARDLINK_MAX_MEMBERS_PER_GROUP = 128
_LINUX_CASEFOLD_ROLE = "linux-runtime-support"
_LINUX_CASEFOLD_GROUP_COUNT = 10
_LINUX_CASEFOLD_MEMBER_COUNT = 20
_LINUX_CASEFOLD_TOPOLOGY_SHA256 = (
    "54895f5f13d52076ce8637e71aa7daa1d980741478f6f0c108745907af465562"
)
_MAX_CASEFOLD_GROUPS = 16
_MAX_CASEFOLD_GROUP_MEMBERS = 16
_LINUX_MODE_DISPOSITION_RELATIVE_PATH_SHA256 = (
    "023ed662ba1d5597854b981623cc146009db9f4b1b2111c3498b420fb5f10d69"
)
_LINUX_MODE_DISPOSITION_ROOT = Path("/usr/lib/x86_64-linux-gnu")
_LINUX_MODE_DISPOSITION_ROOT_LOCATOR_PATH_SHA256 = (
    "8cb7b098c3bba9a6c8a0257da50a363ac54fbe6eb28b46be38a5231be7b5e80a"
)
_LINUX_MODE_DISPOSITION_RELATIVE_PATH = "utempter/utempter"
_LINUX_MODE_DISPOSITION_MODE = 0o2755
_LINUX_UNMAPPED_SYMLINK_ROOT = Path("/usr/lib/x86_64-linux-gnu")
_LINUX_UNMAPPED_SYMLINK_ROOT_LOCATOR_PATH_SHA256 = (
    "8cb7b098c3bba9a6c8a0257da50a363ac54fbe6eb28b46be38a5231be7b5e80a"
)
_LINUX_GCC_UNMAPPED_SYMLINK_ROOT = Path(
    "/usr/lib/gcc/x86_64-linux-gnu/13"
)
_LINUX_GCC_UNMAPPED_SYMLINK_ROOT_LOCATOR_PATH_SHA256 = (
    "fc92c0ab8a96a0a6c852f2b7289a763216bbbc99a2faae062fa8ed08a624e528"
)
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
    "symlink_disposition_count",
    "symlink_dispositions",
    "hardlink_disposition_count",
    "hardlink_dispositions",
    "mode_disposition_count",
    "mode_dispositions",
    "casefold_disposition_count",
    "casefold_dispositions",
    "merkle_sha256",
}
_SYMLINK_DISPOSITION_FIELDS = {
    "relative_path",
    "disposition",
    "raw_link_target",
    "canonical_link_target",
    "external_manifest_role",
    "external_manifest_merkle_sha256",
    "external_support_root_role",
    "external_support_root_merkle_sha256",
    "resolved_relative_path",
    "resolved_path_sha256",
    "mode",
    "metadata_sha256",
    "xattr_count",
    "xattr_bytes",
    "xattrs_sha256",
    "size",
    "raw_sha256",
    "merkle_sha256",
}
_HARDLINK_DISPOSITION_FIELDS = {
    "disposition",
    "resource_root_locator_path_sha256",
    "version_manifest_role",
    "version_manifest_raw_sha256",
    "version_manifest_merkle_sha256",
    "group_count",
    "support_member_count",
    "alias_count",
    "policy_merkle_sha256",
    "observation_merkle_sha256",
    "merkle_sha256",
}
_MODE_DISPOSITION_FIELDS = {
    "disposition",
    "support_root_locator_path_sha256",
    "relative_path_sha256",
    "kind",
    "mode",
    "full_stamp_sha256",
    "metadata_sha256",
    "raw_sha256",
    "member_receipt_sha256",
    "merkle_sha256",
}
_CASEFOLD_DISPOSITION_FIELDS = {
    "disposition",
    "group_count",
    "member_count",
    "topology_sha256",
    "merkle_sha256",
}
class _RoleReceipt(Protocol):
    @property
    def logical_role(self) -> str: ...


_RoleReceiptT = TypeVar("_RoleReceiptT", bound=_RoleReceipt)


class ToolchainSupportLockError(ValueError):
    """A toolchain support locator, tree, or lock is unsafe or noncanonical."""


class ToolchainSupportVerificationDriftError(ToolchainSupportLockError):
    """One bounded, path-free expected/observed receipt difference."""

    __slots__ = (
        "after_merkle_sha256",
        "before_merkle_sha256",
        "diagnostic",
        "first_difference_kind",
        "first_logical_role",
        "hardlink_after_observation_sha256",
        "hardlink_before_observation_sha256",
        "manifest_difference_count",
        "root_difference_count",
    )

    def __init__(
        self,
        *,
        manifest_difference_count: int,
        root_difference_count: int,
        first_difference_kind: str,
        first_logical_role: str,
        before_merkle_sha256: str,
        after_merkle_sha256: str,
        hardlink_before_observation_sha256: str | None,
        hardlink_after_observation_sha256: str | None,
    ) -> None:
        if (
            type(manifest_difference_count) is not int
            or isinstance(manifest_difference_count, bool)
            or not 0
            <= manifest_difference_count
            <= MAX_TOOLCHAIN_SUPPORT_LOCATORS
            or type(root_difference_count) is not int
            or isinstance(root_difference_count, bool)
            or not 0 <= root_difference_count <= MAX_TOOLCHAIN_SUPPORT_LOCATORS
            or manifest_difference_count + root_difference_count == 0
            or first_difference_kind not in {"manifest", "root"}
            or (
                first_difference_kind == "manifest"
                and manifest_difference_count == 0
            )
            or first_difference_kind == "root"
            and root_difference_count == 0
        ):
            raise ToolchainSupportLockError(
                "toolchain support verification drift shape is invalid"
            )
        role = _validate_role(first_logical_role)
        before = _require_sha256(
            before_merkle_sha256,
            "support verification before Merkle SHA-256",
        )
        after = _require_sha256(
            after_merkle_sha256,
            "support verification after Merkle SHA-256",
        )
        hardlink_before = _optional_verification_sha256(
            hardlink_before_observation_sha256,
            label="support verification hardlink-before observation SHA-256",
        )
        hardlink_after = _optional_verification_sha256(
            hardlink_after_observation_sha256,
            label="support verification hardlink-after observation SHA-256",
        )
        diagnostic = (
            "toolchain support verification differs "
            f"(manifests={manifest_difference_count},"
            f"roots={root_difference_count},kind={first_difference_kind},"
            f"role={role},before={before},after={after},"
            f"hbefore={hardlink_before or 'none'},"
            f"hafter={hardlink_after or 'none'})"
        )
        if not diagnostic.isascii() or len(diagnostic.encode("ascii")) > 512:
            raise ToolchainSupportLockError(
                "toolchain support verification drift diagnostic exceeds the bound"
            )
        self.manifest_difference_count = manifest_difference_count
        self.root_difference_count = root_difference_count
        self.first_difference_kind = first_difference_kind
        self.first_logical_role = role
        self.before_merkle_sha256 = before
        self.after_merkle_sha256 = after
        self.hardlink_before_observation_sha256 = hardlink_before
        self.hardlink_after_observation_sha256 = hardlink_after
        self.diagnostic = diagnostic
        super().__init__(diagnostic)


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
class ToolchainSupportSymlinkDispositionReceipt:
    """One closed fixed-policy or bounded cross-root symlink receipt."""

    relative_path: str
    disposition: str
    raw_link_target: str
    canonical_link_target: str | None
    external_manifest_role: str | None
    external_manifest_merkle_sha256: str | None
    external_support_root_role: str | None
    external_support_root_merkle_sha256: str | None
    resolved_relative_path: str | None
    resolved_path_sha256: str
    mode: int
    metadata_sha256: str
    xattr_count: int
    xattr_bytes: int
    xattrs_sha256: str
    size: int
    raw_sha256: str
    merkle_sha256: str

    def __post_init__(self) -> None:
        _validate_relative_path(self.relative_path)
        if self.disposition not in {
            "bind-external-manifest",
            "bind-external-support-root",
            "deny-unmapped-virtual-target",
            "deny-isolated-site-packages",
            "normalize-in-root-alias",
        }:
            raise ToolchainSupportLockError(
                "toolchain support symlink disposition is invalid"
            )
        if (
            type(self.raw_link_target) is not str
            or not self.raw_link_target
            or len(self.raw_link_target.encode("utf-8"))
            > MAX_TOOLCHAIN_SUPPORT_SYMLINK_BYTES
            or "\\" in self.raw_link_target
            or "\0" in self.raw_link_target
            or self.raw_link_target
            != unicodedata.normalize("NFC", self.raw_link_target)
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in self.raw_link_target
            )
        ):
            raise ToolchainSupportLockError(
                "toolchain support disposition raw link target is invalid"
            )
        if self.canonical_link_target is not None:
            _validate_link_target(self.canonical_link_target)
        if self.external_manifest_role is not None:
            _validate_role(self.external_manifest_role)
        if self.external_manifest_merkle_sha256 is not None:
            _require_sha256(
                self.external_manifest_merkle_sha256,
                "support disposition external manifest Merkle SHA-256",
            )
        if self.external_support_root_role is not None:
            _validate_role(self.external_support_root_role)
        if self.external_support_root_merkle_sha256 is not None:
            _require_sha256(
                self.external_support_root_merkle_sha256,
                "support disposition external support-root Merkle SHA-256",
            )
        if self.resolved_relative_path is not None:
            _validate_relative_path(self.resolved_relative_path)
        if self.disposition == "bind-external-manifest":
            valid_shape = (
                self.canonical_link_target is not None
                and self.external_manifest_role is not None
                and self.external_manifest_merkle_sha256 is not None
                and self.external_support_root_role is None
                and self.external_support_root_merkle_sha256 is None
                and self.resolved_relative_path is None
            )
        elif self.disposition == "bind-external-support-root":
            valid_shape = (
                self.canonical_link_target is None
                and self.external_manifest_role is None
                and self.external_manifest_merkle_sha256 is None
                and self.external_support_root_role is not None
                and self.external_support_root_merkle_sha256 is not None
                and self.resolved_relative_path is not None
            )
        elif self.disposition in {
            "deny-isolated-site-packages",
            "deny-unmapped-virtual-target",
        }:
            valid_shape = (
                self.canonical_link_target is None
                and self.external_manifest_role is None
                and self.external_manifest_merkle_sha256 is None
                and self.external_support_root_role is None
                and self.external_support_root_merkle_sha256 is None
                and self.resolved_relative_path is None
            )
        else:
            valid_shape = (
                self.canonical_link_target is not None
                and self.external_manifest_role is None
                and self.external_manifest_merkle_sha256 is None
                and self.external_support_root_role is None
                and self.external_support_root_merkle_sha256 is None
                and self.resolved_relative_path is not None
            )
        if not valid_shape:
            raise ToolchainSupportLockError(
                "toolchain support symlink disposition binding shape is invalid"
            )
        _require_sha256(
            self.resolved_path_sha256,
            "support disposition resolved path SHA-256",
        )
        _validate_mode(self.mode)
        _require_sha256(
            self.metadata_sha256,
            "support disposition metadata SHA-256",
        )
        _validate_xattr_summary(self.xattr_count, self.xattr_bytes)
        _require_sha256(
            self.xattrs_sha256,
            "support disposition xattr SHA-256",
        )
        _validate_size(self.size, maximum=MAX_TOOLCHAIN_SUPPORT_SYMLINK_BYTES)
        _require_sha256(self.raw_sha256, "support disposition raw SHA-256")
        _require_sha256(self.merkle_sha256, "support disposition Merkle SHA-256")
        if (
            self.size != len(self.raw_link_target.encode("utf-8"))
            or not hmac.compare_digest(
                self.raw_sha256,
                hashlib.sha256(self.raw_link_target.encode("utf-8")).hexdigest(),
            )
            or not hmac.compare_digest(
                self.merkle_sha256,
                _symlink_disposition_merkle(self),
            )
        ):
            raise ToolchainSupportLockError(
                "toolchain support symlink disposition receipt is stale"
            )

    def to_dict(self) -> dict[str, object]:
        """Return the complete path-free exceptional symlink receipt."""
        return {
            "relative_path": self.relative_path,
            "disposition": self.disposition,
            "raw_link_target": self.raw_link_target,
            "canonical_link_target": self.canonical_link_target,
            "external_manifest_role": self.external_manifest_role,
            "external_manifest_merkle_sha256": self.external_manifest_merkle_sha256,
            "external_support_root_role": self.external_support_root_role,
            "external_support_root_merkle_sha256": (
                self.external_support_root_merkle_sha256
            ),
            "resolved_relative_path": self.resolved_relative_path,
            "resolved_path_sha256": self.resolved_path_sha256,
            "mode": self.mode,
            "metadata_sha256": self.metadata_sha256,
            "xattr_count": self.xattr_count,
            "xattr_bytes": self.xattr_bytes,
            "xattrs_sha256": self.xattrs_sha256,
            "size": self.size,
            "raw_sha256": self.raw_sha256,
            "merkle_sha256": self.merkle_sha256,
        }


@dataclass(frozen=True, slots=True)
class ToolchainSupportHardlinkDispositionReceipt:
    """One exact root-scoped Xcode hardlink-topology disposition."""

    disposition: str
    resource_root_locator_path_sha256: str
    version_manifest_role: str
    version_manifest_raw_sha256: str
    version_manifest_merkle_sha256: str
    group_count: int
    support_member_count: int
    alias_count: int
    policy_merkle_sha256: str
    observation_merkle_sha256: str
    merkle_sha256: str

    def __post_init__(self) -> None:
        if self.disposition != "bind-xcode-resource-hardlink-topology":
            raise ToolchainSupportLockError(
                "toolchain support hardlink disposition is invalid"
            )
        _require_sha256(
            self.resource_root_locator_path_sha256,
            "support hardlink resource-root locator SHA-256",
        )
        _validate_role(self.version_manifest_role)
        _require_sha256(
            self.version_manifest_raw_sha256,
            "support hardlink version-manifest raw SHA-256",
        )
        _require_sha256(
            self.version_manifest_merkle_sha256,
            "support hardlink version-manifest Merkle SHA-256",
        )
        if (
            type(self.group_count) is not int
            or isinstance(self.group_count, bool)
            or not 1 <= self.group_count <= _XCODE_HARDLINK_MAX_GROUPS
            or type(self.support_member_count) is not int
            or isinstance(self.support_member_count, bool)
            or self.support_member_count < self.group_count
            or type(self.alias_count) is not int
            or isinstance(self.alias_count, bool)
            or not self.support_member_count <= self.alias_count
            <= self.group_count * _XCODE_HARDLINK_MAX_MEMBERS_PER_GROUP
        ):
            raise ToolchainSupportLockError(
                "toolchain support hardlink disposition counts are noncanonical"
            )
        _require_sha256(
            self.policy_merkle_sha256,
            "support hardlink policy Merkle SHA-256",
        )
        _require_sha256(
            self.observation_merkle_sha256,
            "support hardlink observation Merkle SHA-256",
        )
        _require_sha256(
            self.merkle_sha256,
            "support hardlink disposition Merkle SHA-256",
        )
        if not hmac.compare_digest(
            self.merkle_sha256,
            _hardlink_disposition_merkle(self),
        ):
            raise ToolchainSupportLockError(
                "toolchain support hardlink disposition receipt is stale"
            )

    def to_dict(self) -> dict[str, object]:
        """Return the path-opaque root-scoped topology receipt."""
        return {
            "disposition": self.disposition,
            "resource_root_locator_path_sha256": (
                self.resource_root_locator_path_sha256
            ),
            "version_manifest_role": self.version_manifest_role,
            "version_manifest_raw_sha256": self.version_manifest_raw_sha256,
            "version_manifest_merkle_sha256": (
                self.version_manifest_merkle_sha256
            ),
            "group_count": self.group_count,
            "support_member_count": self.support_member_count,
            "alias_count": self.alias_count,
            "policy_merkle_sha256": self.policy_merkle_sha256,
            "observation_merkle_sha256": self.observation_merkle_sha256,
            "merkle_sha256": self.merkle_sha256,
        }


@dataclass(frozen=True, slots=True)
class ToolchainSupportModeDispositionReceipt:
    """One exact path-opaque Linux regular-file special-mode disposition."""

    disposition: str
    support_root_locator_path_sha256: str
    relative_path_sha256: str
    kind: str
    mode: int
    full_stamp_sha256: str
    metadata_sha256: str
    raw_sha256: str
    member_receipt_sha256: str
    merkle_sha256: str

    def __post_init__(self) -> None:
        if self.disposition != "bind-linux-runtime-regular-mode":
            raise ToolchainSupportLockError(
                "toolchain support mode disposition is invalid"
            )
        _require_sha256(
            self.support_root_locator_path_sha256,
            "support mode disposition root locator SHA-256",
        )
        _require_sha256(
            self.relative_path_sha256,
            "support mode disposition relative-path SHA-256",
        )
        if self.kind != "regular" or self.mode != _LINUX_MODE_DISPOSITION_MODE:
            raise ToolchainSupportLockError(
                "toolchain support mode disposition shape is invalid"
            )
        _require_sha256(
            self.full_stamp_sha256,
            "support mode disposition full-stamp SHA-256",
        )
        _require_sha256(
            self.metadata_sha256,
            "support mode disposition metadata SHA-256",
        )
        _require_sha256(
            self.raw_sha256,
            "support mode disposition raw SHA-256",
        )
        _require_sha256(
            self.member_receipt_sha256,
            "support mode disposition member receipt SHA-256",
        )
        _require_sha256(
            self.merkle_sha256,
            "support mode disposition Merkle SHA-256",
        )
        if not hmac.compare_digest(
            self.merkle_sha256,
            _mode_disposition_merkle(self),
        ):
            raise ToolchainSupportLockError(
                "toolchain support mode disposition receipt is stale"
            )

    def to_dict(self) -> dict[str, object]:
        """Return the closed path-opaque mode disposition."""
        return {
            "disposition": self.disposition,
            "support_root_locator_path_sha256": (
                self.support_root_locator_path_sha256
            ),
            "relative_path_sha256": self.relative_path_sha256,
            "kind": self.kind,
            "mode": self.mode,
            "full_stamp_sha256": self.full_stamp_sha256,
            "metadata_sha256": self.metadata_sha256,
            "raw_sha256": self.raw_sha256,
            "member_receipt_sha256": self.member_receipt_sha256,
            "merkle_sha256": self.merkle_sha256,
        }


@dataclass(frozen=True, slots=True)
class ToolchainSupportCasefoldDispositionReceipt:
    """One exact Linux runtime casefold-collision topology receipt."""

    disposition: str
    group_count: int
    member_count: int
    topology_sha256: str
    merkle_sha256: str

    def __post_init__(self) -> None:
        if self.disposition != "bind-linux-runtime-casefold-topology":
            raise ToolchainSupportLockError(
                "toolchain support casefold disposition is invalid"
            )
        if (
            type(self.group_count) is not int
            or isinstance(self.group_count, bool)
            or not 1 <= self.group_count <= _MAX_CASEFOLD_GROUPS
            or type(self.member_count) is not int
            or isinstance(self.member_count, bool)
            or not 2 * self.group_count
            <= self.member_count
            <= self.group_count * _MAX_CASEFOLD_GROUP_MEMBERS
        ):
            raise ToolchainSupportLockError(
                "toolchain support casefold disposition counts are noncanonical"
            )
        _require_sha256(
            self.topology_sha256,
            "support casefold topology SHA-256",
        )
        _require_sha256(
            self.merkle_sha256,
            "support casefold disposition Merkle SHA-256",
        )
        if not hmac.compare_digest(
            self.merkle_sha256,
            _casefold_disposition_merkle(self),
        ):
            raise ToolchainSupportLockError(
                "toolchain support casefold disposition receipt is stale"
            )

    def to_dict(self) -> dict[str, object]:
        """Return the path- and name-opaque collision topology receipt."""
        return {
            "disposition": self.disposition,
            "group_count": self.group_count,
            "member_count": self.member_count,
            "topology_sha256": self.topology_sha256,
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
    symlink_disposition_count: int
    symlink_dispositions: tuple[ToolchainSupportSymlinkDispositionReceipt, ...]
    hardlink_disposition_count: int
    hardlink_dispositions: tuple[ToolchainSupportHardlinkDispositionReceipt, ...]
    mode_disposition_count: int
    mode_dispositions: tuple[ToolchainSupportModeDispositionReceipt, ...]
    casefold_disposition_count: int
    casefold_dispositions: tuple[ToolchainSupportCasefoldDispositionReceipt, ...]
    merkle_sha256: str

    def __post_init__(self) -> None:
        _validate_role(self.logical_role)
        _require_sha256(self.locator_path_sha256, "support locator path SHA-256")
        _require_sha256(self.root_metadata_sha256, "support root metadata SHA-256")
        _validate_mode(self.root_mode)
        if (
            type(self.symlink_dispositions) is not tuple
            or any(
                type(item) is not ToolchainSupportSymlinkDispositionReceipt
                for item in self.symlink_dispositions
            )
            or self.symlink_dispositions
            != tuple(
                sorted(
                    self.symlink_dispositions,
                    key=lambda item: (_alias(item.relative_path), item.relative_path),
                )
            )
            or len(
                {_alias(item.relative_path) for item in self.symlink_dispositions}
            )
            != len(self.symlink_dispositions)
            or type(self.symlink_disposition_count) is not int
            or isinstance(self.symlink_disposition_count, bool)
            or self.symlink_disposition_count != len(self.symlink_dispositions)
        ):
            raise ToolchainSupportLockError(
                "toolchain support symlink dispositions are noncanonical"
            )
        if (
            type(self.hardlink_dispositions) is not tuple
            or any(
                type(item) is not ToolchainSupportHardlinkDispositionReceipt
                for item in self.hardlink_dispositions
            )
            or len(self.hardlink_dispositions) > 1
            or type(self.hardlink_disposition_count) is not int
            or isinstance(self.hardlink_disposition_count, bool)
            or self.hardlink_disposition_count != len(self.hardlink_dispositions)
        ):
            raise ToolchainSupportLockError(
                "toolchain support hardlink dispositions are noncanonical"
            )
        if (
            type(self.mode_dispositions) is not tuple
            or any(
                type(item) is not ToolchainSupportModeDispositionReceipt
                for item in self.mode_dispositions
            )
            or len(self.mode_dispositions) > 1
            or type(self.mode_disposition_count) is not int
            or isinstance(self.mode_disposition_count, bool)
            or self.mode_disposition_count != len(self.mode_dispositions)
        ):
            raise ToolchainSupportLockError(
                "toolchain support mode dispositions are noncanonical"
            )
        if (
            type(self.casefold_dispositions) is not tuple
            or any(
                type(item) is not ToolchainSupportCasefoldDispositionReceipt
                for item in self.casefold_dispositions
            )
            or len(self.casefold_dispositions) > 1
            or type(self.casefold_disposition_count) is not int
            or isinstance(self.casefold_disposition_count, bool)
            or self.casefold_disposition_count != len(self.casefold_dispositions)
        ):
            raise ToolchainSupportLockError(
                "toolchain support casefold dispositions are noncanonical"
            )
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
            or self.symlink_count < self.symlink_disposition_count
            or any(
                item.support_member_count > self.file_count
                for item in self.hardlink_dispositions
            )
            or self.file_count < self.mode_disposition_count
            or any(
                item.member_count > self.member_count
                for item in self.casefold_dispositions
            )
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
            "symlink_disposition_count": self.symlink_disposition_count,
            "symlink_dispositions": [
                item.to_dict() for item in self.symlink_dispositions
            ],
            "hardlink_disposition_count": self.hardlink_disposition_count,
            "hardlink_dispositions": [
                item.to_dict() for item in self.hardlink_dispositions
            ],
            "mode_disposition_count": self.mode_disposition_count,
            "mode_dispositions": [
                item.to_dict() for item in self.mode_dispositions
            ],
            "casefold_disposition_count": self.casefold_disposition_count,
            "casefold_dispositions": [
                item.to_dict() for item in self.casefold_dispositions
            ],
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
        _validate_lock_symlink_dispositions(
            scope=self.scope,
            manifests=self.manifests,
            roots=self.roots,
        )
        _validate_lock_topology_dispositions(
            scope=self.scope,
            manifests=self.manifests,
            roots=self.roots,
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
class _XcodeHardlinkPolicy:
    logical_role: str
    support_root: Path
    support_root_locator_path_sha256: str
    group_count: int
    support_member_count: int
    alias_count: int
    policy_merkle_sha256: str

    def __post_init__(self) -> None:
        _require_sha256(
            self.support_root_locator_path_sha256,
            "Xcode hardlink support-root locator SHA-256",
        )
        if (
            type(self.group_count) is not int
            or isinstance(self.group_count, bool)
            or not 1 <= self.group_count <= _XCODE_HARDLINK_MAX_GROUPS
            or type(self.support_member_count) is not int
            or isinstance(self.support_member_count, bool)
            or self.support_member_count < self.group_count
            or type(self.alias_count) is not int
            or isinstance(self.alias_count, bool)
            or self.alias_count < self.support_member_count
        ):
            raise ToolchainSupportLockError(
                "toolchain support Xcode hardlink topology policy counts are "
                "noncanonical"
            )
        if (
            self.alias_count
            > self.group_count * _XCODE_HARDLINK_MAX_MEMBERS_PER_GROUP
        ):
            raise ToolchainSupportLockError(
                "toolchain support Xcode hardlink alias bound is noncanonical"
            )
        _require_sha256(
            self.policy_merkle_sha256,
            "Xcode hardlink policy Merkle SHA-256",
        )


def _fixed_xcode_hardlink_policies() -> tuple[_XcodeHardlinkPolicy, ...]:
    """Return only the two frozen Xcode roots admitted by this profile."""
    return (
        _XcodeHardlinkPolicy(
            logical_role=_XCODE_HARDLINK_ROLE,
            support_root=_XCODE_RESOURCE_ROOT,
            support_root_locator_path_sha256=(
                _XCODE_RESOURCE_ROOT_LOCATOR_PATH_SHA256
            ),
            group_count=_XCODE_HARDLINK_GROUP_COUNT,
            support_member_count=_XCODE_HARDLINK_SUPPORT_MEMBER_COUNT,
            alias_count=_XCODE_HARDLINK_ALIAS_COUNT,
            policy_merkle_sha256=_XCODE_HARDLINK_POLICY_MERKLE_SHA256,
        ),
        _XcodeHardlinkPolicy(
            logical_role=_XCODE_SDK_HARDLINK_ROLE,
            support_root=_XCODE_SDK_ROOT,
            support_root_locator_path_sha256=(
                _XCODE_SDK_ROOT_LOCATOR_PATH_SHA256
            ),
            group_count=_XCODE_SDK_HARDLINK_GROUP_COUNT,
            support_member_count=_XCODE_SDK_HARDLINK_SUPPORT_MEMBER_COUNT,
            alias_count=_XCODE_SDK_HARDLINK_ALIAS_COUNT,
            policy_merkle_sha256=_XCODE_SDK_HARDLINK_POLICY_MERKLE_SHA256,
        ),
    )


def _select_xcode_hardlink_policy(
    *,
    target_triple: str,
    logical_role: str,
    support_root: Path,
    locator_path_sha256: str,
) -> _XcodeHardlinkPolicy | None:
    if target_triple != "aarch64-apple-darwin":
        return None
    matches = tuple(
        policy
        for policy in _fixed_xcode_hardlink_policies()
        if policy.logical_role == logical_role
        and policy.support_root == support_root
        and policy.support_root_locator_path_sha256 == locator_path_sha256
    )
    if len(matches) > 1:
        raise ToolchainSupportLockError(
            "toolchain support Xcode hardlink policy is ambiguous"
        )
    return matches[0] if matches else None


def _select_xcode_hardlink_policy_receipt(
    *,
    target_triple: str,
    logical_role: str,
    locator_path_sha256: str,
) -> _XcodeHardlinkPolicy | None:
    if target_triple != "aarch64-apple-darwin":
        return None
    matches = tuple(
        policy
        for policy in _fixed_xcode_hardlink_policies()
        if policy.logical_role == logical_role
        and policy.support_root_locator_path_sha256 == locator_path_sha256
    )
    if len(matches) > 1:
        raise ToolchainSupportLockError(
            "toolchain support Xcode hardlink policy is ambiguous"
        )
    return matches[0] if matches else None


@dataclass(frozen=True, slots=True)
class _XcodeHardlinkTopologyGroup:
    policy_group_sha256: str
    observation_group_sha256: str
    stamp: _FilesystemStamp
    support_relative_paths: tuple[str, ...]
    app_relative_paths: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _XcodeHardlinkTopologyObservation:
    policy: _XcodeHardlinkPolicy
    groups: tuple[_XcodeHardlinkTopologyGroup, ...]
    group_count: int
    support_member_count: int
    alias_count: int
    policy_merkle_sha256: str
    observation_merkle_sha256: str


@dataclass(slots=True)
class _AllowedHardlinkPlan:
    """Exact one-shot support-member plan derived from an app-wide scan."""

    entries: dict[str, _FilesystemStamp]

    @classmethod
    def from_topology(
        cls,
        topology: _XcodeHardlinkTopologyObservation,
    ) -> _AllowedHardlinkPlan:
        entries = {
            relative_path: group.stamp
            for group in topology.groups
            for relative_path in group.support_relative_paths
        }
        if len(entries) != topology.support_member_count:
            raise ToolchainSupportLockError(
                "toolchain support Xcode hardlink plan is ambiguous"
            )
        return cls(entries=entries)

    def consume(self, *, relative_path: str, observed: _FilesystemStamp) -> bool:
        expected = self.entries.pop(relative_path, None)
        if expected is None:
            return False
        if expected != observed:
            raise ToolchainSupportLockError(
                "toolchain support Xcode hardlink plan stamp differs"
            )
        return True


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
class _FixedSymlinkDisposition:
    relative_path: str
    raw_link_target: str
    disposition: str
    canonical_link_target: str | None = None
    external_manifest_role: str | None = None
    resolved_path_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class _RawSymlinkDisposition:
    policy: _FixedSymlinkDisposition
    mode: int
    metadata_sha256: str
    xattr_count: int
    xattr_bytes: int
    xattrs_sha256: str
    size: int
    raw_sha256: str


@dataclass(frozen=True, slots=True)
class _RawCasefoldGroup:
    group_sha256: str
    member_count: int


@dataclass(frozen=True, slots=True)
class _ExternalSupportRootBinding:
    locator: ToolchainSupportLocator
    receipt: ToolchainSupportTreeReceipt


_MACOS_PYTHON_RUNTIME_DISPOSITIONS = (
    _FixedSymlinkDisposition(
        relative_path="config-3.11-darwin/libpython3.11.a",
        raw_link_target="../../../Python",
        disposition="bind-external-manifest",
        canonical_link_target="../../../Python",
        external_manifest_role="python-runtime-library",
    ),
    _FixedSymlinkDisposition(
        relative_path="config-3.11-darwin/libpython3.11.dylib",
        raw_link_target="../../../Python",
        disposition="bind-external-manifest",
        canonical_link_target="../../../Python",
        external_manifest_role="python-runtime-library",
    ),
    _FixedSymlinkDisposition(
        relative_path="site-packages",
        raw_link_target="../../../../../../../../../lib/python3.11/site-packages",
        disposition="deny-isolated-site-packages",
    ),
)
_MACOS_PYTHON_RUNTIME_HOMEBREW_DISPOSITION_PATHS = frozenset(
    {
        "config-3.11-darwin/libpython3.11.a",
        "config-3.11-darwin/libpython3.11.dylib",
        "site-packages",
    }
)
_MACOS_PYTHON_RUNTIME_ACTIONS_DISPOSITION_PATHS = frozenset(
    {
        "config-3.11-darwin/libpython3.11.a",
        "config-3.11-darwin/libpython3.11.dylib",
    }
)
_MACOS_PYTHON_RUNTIME_SITE_PACKAGES = "site-packages"
_MACOS_PYTHON_RUNTIME_HOMEBREW_VARIANT = "homebrew"
_MACOS_PYTHON_RUNTIME_ACTIONS_VARIANT = "actions-python-org"
_FIXED_SYMLINK_DISPOSITION_VARIANT = "fixed"
_MACOS_XCODE_SDK_DISPOSITIONS = (
    _FixedSymlinkDisposition(
        relative_path="System/Library/Frameworks/vecLib.framework",
        raw_link_target=(
            "Accelerate.framework//Versions/A/Frameworks/vecLib.framework"
        ),
        disposition="normalize-in-root-alias",
        canonical_link_target=(
            "Accelerate.framework/Versions/A/Frameworks/vecLib.framework"
        ),
    ),
    _FixedSymlinkDisposition(
        relative_path="usr/lib/swift/libswiftSoundAnalysis.tbd",
        raw_link_target=(
            "../../..//System/Library/Frameworks/SoundAnalysis.framework/"
            "Versions/A/SoundAnalysis.tbd"
        ),
        disposition="normalize-in-root-alias",
        canonical_link_target=(
            "../../../System/Library/Frameworks/SoundAnalysis.framework/"
            "Versions/A/SoundAnalysis.tbd"
        ),
    ),
    _FixedSymlinkDisposition(
        relative_path="usr/lib/swift/libswiftSoundAnalysis_Private.tbd",
        raw_link_target=(
            "../../..//System/Library/Frameworks/SoundAnalysis.framework/"
            "Versions/A/SoundAnalysis.tbd"
        ),
        disposition="normalize-in-root-alias",
        canonical_link_target=(
            "../../../System/Library/Frameworks/SoundAnalysis.framework/"
            "Versions/A/SoundAnalysis.tbd"
        ),
    ),
)
_MACOS_XCODE_SDK_MODERN_DISPOSITION_PATHS = frozenset(
    {
        "System/Library/Frameworks/vecLib.framework",
        "usr/lib/swift/libswiftSoundAnalysis.tbd",
        "usr/lib/swift/libswiftSoundAnalysis_Private.tbd",
    }
)
_MACOS_XCODE_SDK_16_4_DISPOSITION_PATHS = frozenset(
    {"System/Library/Frameworks/vecLib.framework"}
)
_MACOS_XCODE_SDK_16_4_REGULAR_FILES = frozenset(
    {
        "usr/lib/swift/libswiftSoundAnalysis.tbd",
        "usr/lib/swift/libswiftSoundAnalysis_Private.tbd",
    }
)
_MACOS_XCODE_SDK_MODERN_VARIANT = "modern"
_MACOS_XCODE_SDK_16_4_VARIANT = "xcode-16.4"
_LINUX_UNMAPPED_SYMLINK_DISPOSITIONS = (
    _FixedSymlinkDisposition(
        relative_path="libLLVM-18.so",
        raw_link_target="libLLVM.so.18.1",
        disposition="deny-unmapped-virtual-target",
        resolved_path_sha256=(
            "438f53d5024cec3f9b5be422a4dfc6e24c9c080cdcad0375d2c518c2f239b266"
        ),
    ),
    _FixedSymlinkDisposition(
        relative_path="libLLVM.so.18.1",
        raw_link_target="../llvm-18/lib/libLLVM.so.1",
        disposition="deny-unmapped-virtual-target",
        resolved_path_sha256=(
            "438f53d5024cec3f9b5be422a4dfc6e24c9c080cdcad0375d2c518c2f239b266"
        ),
    ),
    _FixedSymlinkDisposition(
        relative_path="libclang-cpp.so.16",
        raw_link_target="../llvm-16/lib/libclang-cpp.so.16",
        disposition="deny-unmapped-virtual-target",
        resolved_path_sha256=(
            "72e94f1b5b94780e49cd2c3379ddaba4472cb78febb35ee72e5a62aeb8bd4160"
        ),
    ),
    _FixedSymlinkDisposition(
        relative_path="libclang-cpp.so.17",
        raw_link_target="../llvm-17/lib/libclang-cpp.so.17",
        disposition="deny-unmapped-virtual-target",
        resolved_path_sha256=(
            "15e5024198ecf325a8ab1f75411f16953c196961afec6f2e1977593a5420d161"
        ),
    ),
    _FixedSymlinkDisposition(
        relative_path="libclang-cpp.so.18",
        raw_link_target="../llvm-18/lib/libclang-cpp.so.18.1",
        disposition="deny-unmapped-virtual-target",
        resolved_path_sha256=(
            "84f655ae7665283dae00379724674759314189a8391bade80d0d90abaeb1175f"
        ),
    ),
    _FixedSymlinkDisposition(
        relative_path="libclang-cpp.so.18.1",
        raw_link_target="../llvm-18/lib/libclang-cpp.so.18.1",
        disposition="deny-unmapped-virtual-target",
        resolved_path_sha256=(
            "84f655ae7665283dae00379724674759314189a8391bade80d0d90abaeb1175f"
        ),
    ),
    _FixedSymlinkDisposition(
        relative_path="libpython3.12.a",
        raw_link_target=(
            "../python3.12/config-3.12-x86_64-linux-gnu/libpython3.12.a"
        ),
        disposition="deny-unmapped-virtual-target",
        resolved_path_sha256=(
            "9757c5cb339432c22968634e3166747d7e8ce4a6e8351e89ccf3b648c7d1b7f0"
        ),
    ),
)
_LINUX_UNMAPPED_SYMLINK_DISPOSITION_PATHS = frozenset(
    item.relative_path for item in _LINUX_UNMAPPED_SYMLINK_DISPOSITIONS
)
_LINUX_UNMAPPED_SYMLINK_MINIMAL_VARIANT = "minimal-host"
_LINUX_UNMAPPED_SYMLINK_GITHUB_RUNNER_VARIANT = "github-runner"
_LINUX_GCC_UNMAPPED_SYMLINK_DISPOSITIONS = (
    _FixedSymlinkDisposition(
        relative_path="liblto_plugin.so",
        raw_link_target=(
            "../../../../libexec/gcc/x86_64-linux-gnu/13/liblto_plugin.so"
        ),
        disposition="deny-unmapped-virtual-target",
        resolved_path_sha256=(
            "b0d3612fd801488c96c48b9ee4320633da71497f0b7507d849754b017c9ebd00"
        ),
    ),
)
_LINUX_GCC_UNMAPPED_SYMLINK_DISPOSITION_PATHS = frozenset(
    item.relative_path for item in _LINUX_GCC_UNMAPPED_SYMLINK_DISPOSITIONS
)
_LINUX_GCC_UNMAPPED_SYMLINK_MINIMAL_VARIANT = "minimal-host"
_LINUX_GCC_UNMAPPED_SYMLINK_RUNNER_VARIANT = "ubuntu-24.04-gcc13"
_FIXED_SYMLINK_DISPOSITIONS: dict[
    tuple[str, str],
    tuple[_FixedSymlinkDisposition, ...],
] = {
    (
        "aarch64-apple-darwin",
        "python-runtime",
    ): _MACOS_PYTHON_RUNTIME_DISPOSITIONS,
    (
        "aarch64-apple-darwin",
        "xcode-sdk",
    ): _MACOS_XCODE_SDK_DISPOSITIONS,
    (
        "x86_64-unknown-linux-gnu",
        "linux-runtime-support",
    ): _LINUX_UNMAPPED_SYMLINK_DISPOSITIONS,
    (
        "x86_64-unknown-linux-gnu",
        "linux-gcc-support",
    ): _LINUX_GCC_UNMAPPED_SYMLINK_DISPOSITIONS,
}


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
        locator_path_sha256 = _locator_path_digest(locator._absolute_path)
        _validate_generated_mode(
            stat.S_IMODE(expected.mode),
            origin="manifest-observation",
            target_triple=None,
            logical_role=locator.logical_role,
            kind="regular",
            path_digest_label="locator_path_sha256",
            path_sha256=locator_path_sha256,
        )
        file_fd = _open_regular_file(
            parent_fd,
            name,
            mode_origin="manifest-open",
            mode_logical_role=locator.logical_role,
            mode_path_digest_label="locator_path_sha256",
            mode_path_sha256=locator_path_sha256,
        )
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
            locator_path_sha256,
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
        receipt_mode = _validate_generated_mode(
            stat.S_IMODE(final_stamp.mode),
            origin="manifest-receipt",
            target_triple=None,
            logical_role=locator.logical_role,
            kind="regular",
            path_digest_label="locator_path_sha256",
            path_sha256=locator_path_sha256,
        )
        return ToolchainSupportFileReceipt(
            logical_role=locator.logical_role,
            locator_path_sha256=locator_path_sha256,
            metadata_sha256=_metadata_digest(final_stamp, kind="file"),
            raw_sha256=digest,
            size=size,
            mode=receipt_mode,
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
        target_triple=None,
        manifest_bindings={},
        external_support_root_binding=None,
        budget=_XattrBudget(
            remaining_count=MAX_TOOLCHAIN_SUPPORT_TREE_XATTRS,
            remaining_bytes=MAX_TOOLCHAIN_SUPPORT_TREE_XATTR_BYTES,
        ),
    )


def _capture_stable_tree(
    locator: ToolchainSupportLocator,
    *,
    target_triple: str | None,
    manifest_bindings: dict[
        str,
        tuple[ToolchainSupportLocator, ToolchainSupportFileReceipt],
    ],
    external_support_root_binding: _ExternalSupportRootBinding | None,
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
    topology: _XcodeHardlinkTopologyObservation | None = None
    hardlink_receipt: ToolchainSupportHardlinkDispositionReceipt | None = None
    xcode_manifest_binding: tuple[
        ToolchainSupportLocator, ToolchainSupportFileReceipt
    ] | None = None
    xcode_policy = (
        None
        if target_triple is None
        else _select_xcode_hardlink_policy(
            target_triple=target_triple,
            logical_role=locator.logical_role,
            support_root=locator._absolute_path,
            locator_path_sha256=_locator_path_digest(locator._absolute_path),
        )
    )
    if xcode_policy is not None:
        manifest_binding = manifest_bindings.get(_XCODE_VERSION_MANIFEST_ROLE)
        if manifest_binding is None:
            raise ToolchainSupportLockError(
                "toolchain support Xcode topology version manifest is missing"
            )
        manifest_locator, manifest_receipt = manifest_binding
        if (
            manifest_locator._absolute_path != _XCODE_VERSION_MANIFEST
            or _locator_path_digest(manifest_locator._absolute_path)
            != _XCODE_VERSION_MANIFEST_LOCATOR_PATH_SHA256
            or manifest_receipt.locator_path_sha256
            != _XCODE_VERSION_MANIFEST_LOCATOR_PATH_SHA256
            or manifest_receipt.raw_sha256
            != _XCODE_VERSION_MANIFEST_RAW_SHA256
        ):
            raise ToolchainSupportLockError(
                "toolchain support Xcode topology version manifest differs"
            )
        xcode_manifest_binding = manifest_binding
        topology = _scan_xcode_hardlink_topology(
            support_root=locator._absolute_path,
            app_boundary=_XCODE_APP_BOUNDARY,
        )
        if topology.policy != xcode_policy:
            raise ToolchainSupportLockError(
                "toolchain support Xcode topology selected a different policy"
            )
        hardlink_receipt = _new_xcode_hardlink_topology_receipt(
            topology=topology,
            manifest=manifest_receipt,
        )
    first = _capture_tree_once(
        locator,
        target_triple=target_triple,
        manifest_bindings=manifest_bindings,
        external_support_root_binding=external_support_root_binding,
        hardlink_topology=topology,
        hardlink_receipt=hardlink_receipt,
        xattr_budget=capture_budget,
    )
    second = _capture_tree_once(
        locator,
        target_triple=target_triple,
        manifest_bindings=manifest_bindings,
        external_support_root_binding=external_support_root_binding,
        hardlink_topology=topology,
        hardlink_receipt=hardlink_receipt,
        xattr_budget=replay_budget,
    )
    if first != second or capture_budget != replay_budget:
        raise ToolchainSupportLockError(
            "toolchain support tree changed across stable capture"
        )
    if topology is not None:
        replayed_topology = _scan_xcode_hardlink_topology(
            support_root=locator._absolute_path,
            app_boundary=_XCODE_APP_BOUNDARY,
        )
        if replayed_topology != topology:
            raise ToolchainSupportLockError(
                "toolchain support Xcode topology changed across tree capture"
            )
        _reopen_xcode_hardlink_topology(
            replayed_topology,
            support_root=locator._absolute_path,
            app_boundary=_XCODE_APP_BOUNDARY,
        )
        assert xcode_manifest_binding is not None
        manifest_locator, manifest_receipt = xcode_manifest_binding
        replayed_manifest = _capture_stable_file(
            manifest_locator,
            budget=_XattrBudget(
                remaining_count=MAX_TOOLCHAIN_SUPPORT_XATTRS_PER_MEMBER,
                remaining_bytes=MAX_TOOLCHAIN_SUPPORT_TREE_XATTR_BYTES,
            ),
        )
        if replayed_manifest != manifest_receipt:
            raise ToolchainSupportLockError(
                "toolchain support Xcode topology version manifest changed"
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
    target_triple: str,
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
    manifest_bindings = {
        locator.logical_role: (locator, receipt)
        for locator, receipt in zip(
            ordered_manifests,
            manifest_receipts,
            strict=True,
        )
    }
    roots_by_role = {item.logical_role: item for item in ordered_roots}
    captured_roots: dict[str, ToolchainSupportTreeReceipt] = {}
    gcc_locator = roots_by_role.get("linux-gcc-support")
    runtime_locator = roots_by_role.get("linux-runtime-support")
    if (
        target_triple == "x86_64-unknown-linux-gnu"
        and gcc_locator is not None
        and runtime_locator is not None
    ):
        _validate_external_support_root_isolation(
            source=gcc_locator,
            target=runtime_locator,
        )
        runtime_receipt = _capture_stable_tree(
            runtime_locator,
            target_triple=target_triple,
            manifest_bindings=manifest_bindings,
            external_support_root_binding=None,
            budget=budget,
        )
        captured_roots[runtime_locator.logical_role] = runtime_receipt
        captured_roots[gcc_locator.logical_role] = _capture_stable_tree(
            gcc_locator,
            target_triple=target_triple,
            manifest_bindings=manifest_bindings,
            external_support_root_binding=_ExternalSupportRootBinding(
                locator=runtime_locator,
                receipt=runtime_receipt,
            ),
            budget=budget,
        )
        replayed_runtime = _capture_stable_tree(
            runtime_locator,
            target_triple=target_triple,
            manifest_bindings=manifest_bindings,
            external_support_root_binding=None,
            budget=_XattrBudget(
                remaining_count=MAX_TOOLCHAIN_SUPPORT_TREE_XATTRS,
                remaining_bytes=MAX_TOOLCHAIN_SUPPORT_TREE_XATTR_BYTES,
            ),
        )
        if replayed_runtime != runtime_receipt:
            raise ToolchainSupportLockError(
                "toolchain support external runtime root changed across source capture"
            )
    for item in ordered_roots:
        if item.logical_role in captured_roots:
            continue
        captured_roots[item.logical_role] = _capture_stable_tree(
            item,
            target_triple=target_triple,
            manifest_bindings=manifest_bindings,
            external_support_root_binding=None,
            budget=budget,
        )
    root_receipts = tuple(
        captured_roots[item.logical_role] for item in ordered_roots
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
        target_triple=target_triple,
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
        target_triple=lock.scope.target_triple,
        manifests=manifest_locators,
        roots=root_locators,
    )
    if observed_manifests != lock.manifests or observed_roots != lock.roots:
        raise _verification_drift_error(
            before_manifests=lock.manifests,
            after_manifests=observed_manifests,
            before_roots=lock.roots,
            after_roots=observed_roots,
        )
    return True


def _optional_verification_sha256(value: str | None, *, label: str) -> str | None:
    if value is None:
        return None
    return _require_sha256(value, label)


def _verification_hardlink_observation(
    receipt: ToolchainSupportTreeReceipt,
) -> str | None:
    dispositions = receipt.hardlink_dispositions
    if not dispositions:
        return None
    if len(dispositions) != 1:
        raise ToolchainSupportLockError(
            "toolchain support verification hardlink disposition count is invalid"
        )
    return dispositions[0].observation_merkle_sha256


def _verification_drift_error(
    *,
    before_manifests: tuple[ToolchainSupportFileReceipt, ...],
    after_manifests: tuple[ToolchainSupportFileReceipt, ...],
    before_roots: tuple[ToolchainSupportTreeReceipt, ...],
    after_roots: tuple[ToolchainSupportTreeReceipt, ...],
) -> ToolchainSupportVerificationDriftError:
    manifest_differences = tuple(
        (before, after)
        for before, after in zip(
            before_manifests,
            after_manifests,
            strict=True,
        )
        if before != after
    )
    root_differences = tuple(
        (before, after)
        for before, after in zip(before_roots, after_roots, strict=True)
        if before != after
    )
    if manifest_differences:
        manifest_before, manifest_after = manifest_differences[0]
        if manifest_before.logical_role != manifest_after.logical_role:
            raise ToolchainSupportLockError(
                "toolchain support verification receipt roles are inconsistent"
            )
        kind = "manifest"
        first_logical_role = manifest_before.logical_role
        before_merkle_sha256 = manifest_before.merkle_sha256
        after_merkle_sha256 = manifest_after.merkle_sha256
        hardlink_before = None
        hardlink_after = None
    elif root_differences:
        root_before, root_after = root_differences[0]
        if root_before.logical_role != root_after.logical_role:
            raise ToolchainSupportLockError(
                "toolchain support verification receipt roles are inconsistent"
            )
        kind = "root"
        first_logical_role = root_before.logical_role
        before_merkle_sha256 = root_before.merkle_sha256
        after_merkle_sha256 = root_after.merkle_sha256
        hardlink_before = _verification_hardlink_observation(root_before)
        hardlink_after = _verification_hardlink_observation(root_after)
    else:
        raise ToolchainSupportLockError(
            "toolchain support verification drift accounting is inconsistent"
        )
    return ToolchainSupportVerificationDriftError(
        manifest_difference_count=len(manifest_differences),
        root_difference_count=len(root_differences),
        first_difference_kind=kind,
        first_logical_role=first_logical_role,
        before_merkle_sha256=before_merkle_sha256,
        after_merkle_sha256=after_merkle_sha256,
        hardlink_before_observation_sha256=hardlink_before,
        hardlink_after_observation_sha256=hardlink_after,
    )


def _fixed_symlink_disposition_map(
    target_triple: str | None,
    logical_role: str,
) -> dict[str, _FixedSymlinkDisposition]:
    if target_triple is None:
        return {}
    rows = _FIXED_SYMLINK_DISPOSITIONS.get(
        (target_triple, logical_role),
        (),
    )
    result: dict[str, _FixedSymlinkDisposition] = {}
    for row in rows:
        _validate_relative_path(row.relative_path)
        if (
            row.relative_path in result
            or not row.raw_link_target
            or row.raw_link_target
            != unicodedata.normalize("NFC", row.raw_link_target)
            or "\\" in row.raw_link_target
            or "\0" in row.raw_link_target
            or len(row.raw_link_target.encode("utf-8"))
            > MAX_TOOLCHAIN_SUPPORT_SYMLINK_BYTES
        ):
            raise ToolchainSupportLockError(
                "toolchain support fixed symlink disposition is invalid"
            )
        if row.canonical_link_target is not None:
            _validate_link_target(row.canonical_link_target)
        if row.external_manifest_role is not None:
            _validate_role(row.external_manifest_role)
        if row.resolved_path_sha256 is not None:
            _require_sha256(
                row.resolved_path_sha256,
                "fixed symlink disposition resolved path SHA-256",
            )
        if row.disposition == "bind-external-manifest":
            valid_shape = (
                row.canonical_link_target is not None
                and row.external_manifest_role == "python-runtime-library"
                and row.resolved_path_sha256 is None
            )
        elif row.disposition == "deny-isolated-site-packages":
            valid_shape = (
                row.canonical_link_target is None
                and row.external_manifest_role is None
                and row.resolved_path_sha256 is None
            )
        elif row.disposition == "deny-unmapped-virtual-target":
            valid_shape = (
                row.canonical_link_target is None
                and row.external_manifest_role is None
                and row.resolved_path_sha256 is not None
                and not PurePosixPath(row.raw_link_target).is_absolute()
            )
        elif row.disposition == "normalize-in-root-alias":
            valid_shape = (
                row.canonical_link_target is not None
                and row.external_manifest_role is None
                and row.resolved_path_sha256 is None
                and "//" in row.raw_link_target
                and "//" not in row.canonical_link_target
            )
        else:
            valid_shape = False
        if not valid_shape:
            raise ToolchainSupportLockError(
                "toolchain support fixed symlink disposition shape is invalid"
            )
        result[row.relative_path] = row
    return result


def _deny_unmapped_symlink_profile(
    *,
    target_triple: str | None,
    logical_role: str,
) -> tuple[Path, str]:
    if target_triple != "x86_64-unknown-linux-gnu":
        raise ToolchainSupportLockError(
            "toolchain support unmapped virtual target is outside the exact Linux profile"
        )
    if logical_role == "linux-runtime-support":
        return (
            _LINUX_UNMAPPED_SYMLINK_ROOT,
            _LINUX_UNMAPPED_SYMLINK_ROOT_LOCATOR_PATH_SHA256,
        )
    if logical_role == "linux-gcc-support":
        return (
            _LINUX_GCC_UNMAPPED_SYMLINK_ROOT,
            _LINUX_GCC_UNMAPPED_SYMLINK_ROOT_LOCATOR_PATH_SHA256,
        )
    raise ToolchainSupportLockError(
        "toolchain support unmapped virtual target is outside the exact Linux role"
    )


def _validate_lock_symlink_dispositions(
    *,
    scope: ToolchainSupportScope,
    manifests: tuple[ToolchainSupportFileReceipt, ...],
    roots: tuple[ToolchainSupportTreeReceipt, ...],
) -> None:
    manifests_by_role = {item.logical_role: item for item in manifests}
    roots_by_role = {item.logical_role: item for item in roots}
    for root in roots:
        expected = _fixed_symlink_disposition_map(
            scope.target_triple,
            root.logical_role,
        )
        observed = {
            item.relative_path: item
            for item in root.symlink_dispositions
            if item.disposition != "bind-external-support-root"
        }
        _select_fixed_symlink_disposition_variant(
            target_triple=scope.target_triple,
            logical_role=root.logical_role,
            expected=expected,
            observed_paths=frozenset(observed),
        )
        for relative_path, receipt in observed.items():
            policy = expected[relative_path]
            if (
                receipt.disposition != policy.disposition
                or receipt.raw_link_target != policy.raw_link_target
                or receipt.canonical_link_target
                != policy.canonical_link_target
                or receipt.external_manifest_role
                != policy.external_manifest_role
            ):
                raise ToolchainSupportLockError(
                    "toolchain support lock symlink disposition policy changed"
                )
            if policy.disposition == "bind-external-manifest":
                assert policy.external_manifest_role is not None
                manifest = manifests_by_role.get(policy.external_manifest_role)
                if (
                    manifest is None
                    or receipt.external_manifest_merkle_sha256
                    != manifest.merkle_sha256
                    or receipt.resolved_relative_path is not None
                ):
                    raise ToolchainSupportLockError(
                        "toolchain support external symlink manifest binding is stale"
                    )
            elif policy.disposition == "deny-isolated-site-packages":
                if (
                    receipt.external_manifest_merkle_sha256 is not None
                    or receipt.resolved_relative_path is not None
                ):
                    raise ToolchainSupportLockError(
                        "toolchain support denied site-packages disposition is stale"
                    )
            elif policy.disposition == "deny-unmapped-virtual-target":
                _profile_root, profile_locator_path_sha256 = (
                    _deny_unmapped_symlink_profile(
                        target_triple=scope.target_triple,
                        logical_role=root.logical_role,
                    )
                )
                if (
                    root.locator_path_sha256
                    != profile_locator_path_sha256
                    or receipt.external_manifest_merkle_sha256 is not None
                    or receipt.external_support_root_role is not None
                    or receipt.external_support_root_merkle_sha256 is not None
                    or receipt.resolved_relative_path is not None
                    or receipt.resolved_path_sha256
                    != policy.resolved_path_sha256
                ):
                    raise ToolchainSupportLockError(
                        "toolchain support unmapped virtual target disposition is stale"
                    )
            elif (
                receipt.external_manifest_merkle_sha256 is not None
                or receipt.resolved_relative_path is None
            ):
                raise ToolchainSupportLockError(
                    "toolchain support normalized SDK disposition is stale"
                )
        external = tuple(
            item
            for item in root.symlink_dispositions
            if item.disposition == "bind-external-support-root"
        )
        if not external:
            continue
        runtime = roots_by_role.get("linux-runtime-support")
        if (
            scope.target_triple != "x86_64-unknown-linux-gnu"
            or root.logical_role != "linux-gcc-support"
            or runtime is None
        ):
            raise ToolchainSupportLockError(
                "toolchain support external support-root edge is outside policy"
            )
        for receipt in external:
            if (
                receipt.canonical_link_target is not None
                or receipt.external_manifest_role is not None
                or receipt.external_manifest_merkle_sha256 is not None
                or receipt.external_support_root_role
                != "linux-runtime-support"
                or receipt.external_support_root_merkle_sha256
                != runtime.merkle_sha256
                or receipt.resolved_relative_path is None
            ):
                raise ToolchainSupportLockError(
                    "toolchain support external support-root binding is stale"
                )


def _validate_lock_topology_dispositions(
    *,
    scope: ToolchainSupportScope,
    manifests: tuple[ToolchainSupportFileReceipt, ...],
    roots: tuple[ToolchainSupportTreeReceipt, ...],
) -> None:
    """Enforce singular target-, role-, root-, and manifest-bound policies."""
    manifests_by_role = {item.logical_role: item for item in manifests}
    for root in roots:
        xcode_policy = _select_xcode_hardlink_policy_receipt(
            target_triple=scope.target_triple,
            logical_role=root.logical_role,
            locator_path_sha256=root.locator_path_sha256,
        )
        if xcode_policy is not None and len(root.hardlink_dispositions) != 1:
            raise ToolchainSupportLockError(
                "toolchain support Xcode hardlink topology disposition is missing"
            )
        if root.hardlink_dispositions:
            if (
                xcode_policy is None
                or len(root.hardlink_dispositions) != 1
            ):
                raise ToolchainSupportLockError(
                    "toolchain support hardlink disposition is outside policy"
                )
            hardlink_receipt = root.hardlink_dispositions[0]
            version_manifest = manifests_by_role.get(
                _XCODE_VERSION_MANIFEST_ROLE
            )
            if (
                hardlink_receipt.resource_root_locator_path_sha256
                != root.locator_path_sha256
                or hardlink_receipt.resource_root_locator_path_sha256
                != xcode_policy.support_root_locator_path_sha256
                or hardlink_receipt.version_manifest_role
                != _XCODE_VERSION_MANIFEST_ROLE
                or hardlink_receipt.version_manifest_raw_sha256
                != _XCODE_VERSION_MANIFEST_RAW_SHA256
                or version_manifest is None
                or version_manifest.locator_path_sha256
                != _XCODE_VERSION_MANIFEST_LOCATOR_PATH_SHA256
                or version_manifest.raw_sha256
                != _XCODE_VERSION_MANIFEST_RAW_SHA256
                or hardlink_receipt.version_manifest_merkle_sha256
                != version_manifest.merkle_sha256
                or hardlink_receipt.group_count != xcode_policy.group_count
                or hardlink_receipt.support_member_count
                != xcode_policy.support_member_count
                or hardlink_receipt.alias_count != xcode_policy.alias_count
                or hardlink_receipt.policy_merkle_sha256
                != xcode_policy.policy_merkle_sha256
            ):
                raise ToolchainSupportLockError(
                    "toolchain support Xcode hardlink topology policy changed"
                )
        if root.mode_dispositions:
            if (
                scope.target_triple != "x86_64-unknown-linux-gnu"
                or root.logical_role != _LINUX_CASEFOLD_ROLE
                or len(root.mode_dispositions) != 1
            ):
                raise ToolchainSupportLockError(
                    "toolchain support mode disposition is outside policy"
                )
            mode_receipt = root.mode_dispositions[0]
            if (
                root.locator_path_sha256
                != _LINUX_MODE_DISPOSITION_ROOT_LOCATOR_PATH_SHA256
                or mode_receipt.support_root_locator_path_sha256
                != root.locator_path_sha256
                or mode_receipt.relative_path_sha256
                != _LINUX_MODE_DISPOSITION_RELATIVE_PATH_SHA256
                or mode_receipt.kind != "regular"
                or mode_receipt.mode != _LINUX_MODE_DISPOSITION_MODE
            ):
                raise ToolchainSupportLockError(
                    "toolchain support Linux mode disposition differs from policy"
                )
        exact_linux_mode_root = (
            scope.target_triple == "x86_64-unknown-linux-gnu"
            and root.logical_role == _LINUX_CASEFOLD_ROLE
            and root.locator_path_sha256
            == _LINUX_MODE_DISPOSITION_ROOT_LOCATOR_PATH_SHA256
        )
        if exact_linux_mode_root != (len(root.mode_dispositions) == 1):
            raise ToolchainSupportLockError(
                "toolchain support Linux mode disposition presence differs from policy"
            )
        if root.casefold_dispositions:
            if (
                scope.target_triple != "x86_64-unknown-linux-gnu"
                or root.logical_role != _LINUX_CASEFOLD_ROLE
                or len(root.casefold_dispositions) != 1
            ):
                raise ToolchainSupportLockError(
                    "toolchain support casefold disposition is outside policy"
                )
            casefold_receipt = root.casefold_dispositions[0]
            if (
                casefold_receipt.group_count != _LINUX_CASEFOLD_GROUP_COUNT
                or casefold_receipt.member_count != _LINUX_CASEFOLD_MEMBER_COUNT
                or casefold_receipt.topology_sha256
                != _LINUX_CASEFOLD_TOPOLOGY_SHA256
            ):
                raise ToolchainSupportLockError(
                    "toolchain support Linux casefold topology differs from policy"
                )


def _select_fixed_symlink_disposition_variant(
    *,
    target_triple: str | None,
    logical_role: str,
    expected: Mapping[str, _FixedSymlinkDisposition],
    observed_paths: frozenset[str],
) -> str:
    expected_paths = frozenset(expected)
    if (
        target_triple == "aarch64-apple-darwin"
        and logical_role == "python-runtime"
    ):
        if expected_paths != _MACOS_PYTHON_RUNTIME_HOMEBREW_DISPOSITION_PATHS:
            raise ToolchainSupportLockError(
                "toolchain support macOS Python disposition policy is incomplete"
            )
        if observed_paths == _MACOS_PYTHON_RUNTIME_HOMEBREW_DISPOSITION_PATHS:
            return _MACOS_PYTHON_RUNTIME_HOMEBREW_VARIANT
        if observed_paths == _MACOS_PYTHON_RUNTIME_ACTIONS_DISPOSITION_PATHS:
            return _MACOS_PYTHON_RUNTIME_ACTIONS_VARIANT
    elif (
        target_triple == "aarch64-apple-darwin"
        and logical_role == "xcode-sdk"
    ):
        if expected_paths != _MACOS_XCODE_SDK_MODERN_DISPOSITION_PATHS:
            raise ToolchainSupportLockError(
                "toolchain support macOS Xcode SDK disposition policy is incomplete"
            )
        if observed_paths == _MACOS_XCODE_SDK_MODERN_DISPOSITION_PATHS:
            return _MACOS_XCODE_SDK_MODERN_VARIANT
        if observed_paths == _MACOS_XCODE_SDK_16_4_DISPOSITION_PATHS:
            return _MACOS_XCODE_SDK_16_4_VARIANT
    elif (
        target_triple == "x86_64-unknown-linux-gnu"
        and logical_role == "linux-runtime-support"
    ):
        if expected_paths != _LINUX_UNMAPPED_SYMLINK_DISPOSITION_PATHS:
            raise ToolchainSupportLockError(
                "toolchain support Linux unmapped symlink policy is incomplete"
            )
        if observed_paths == _LINUX_UNMAPPED_SYMLINK_DISPOSITION_PATHS:
            return _LINUX_UNMAPPED_SYMLINK_GITHUB_RUNNER_VARIANT
        if not observed_paths:
            return _LINUX_UNMAPPED_SYMLINK_MINIMAL_VARIANT
    elif (
        target_triple == "x86_64-unknown-linux-gnu"
        and logical_role == "linux-gcc-support"
    ):
        if expected_paths != _LINUX_GCC_UNMAPPED_SYMLINK_DISPOSITION_PATHS:
            raise ToolchainSupportLockError(
                "toolchain support Linux GCC unmapped symlink policy is incomplete"
            )
        if observed_paths == _LINUX_GCC_UNMAPPED_SYMLINK_DISPOSITION_PATHS:
            return _LINUX_GCC_UNMAPPED_SYMLINK_RUNNER_VARIANT
        if not observed_paths:
            return _LINUX_GCC_UNMAPPED_SYMLINK_MINIMAL_VARIANT
    elif observed_paths == expected_paths:
        return _FIXED_SYMLINK_DISPOSITION_VARIANT
    raise ToolchainSupportLockError(
        "toolchain support fixed symlink dispositions are missing or extra"
    )


def _finalize_symlink_dispositions(
    *,
    target_triple: str | None,
    logical_role: str,
    root_path: Path,
    entries: tuple[_ToolchainSupportTreeEntry, ...],
    raw_dispositions: tuple[_RawSymlinkDisposition, ...],
    manifest_bindings: dict[
        str,
        tuple[ToolchainSupportLocator, ToolchainSupportFileReceipt],
    ],
) -> tuple[ToolchainSupportSymlinkDispositionReceipt, ...]:
    expected = _fixed_symlink_disposition_map(target_triple, logical_role)
    observed = {
        item.policy.relative_path: item for item in raw_dispositions
    }
    if len(observed) != len(raw_dispositions):
        raise ToolchainSupportLockError(
            "toolchain support fixed symlink dispositions are missing or extra"
        )
    variant = _select_fixed_symlink_disposition_variant(
        target_triple=target_triple,
        logical_role=logical_role,
        expected=expected,
        observed_paths=frozenset(observed),
    )
    by_path = {item.relative_path: item for item in entries}
    if variant == _MACOS_PYTHON_RUNTIME_ACTIONS_VARIANT:
        site_packages = by_path.get(_MACOS_PYTHON_RUNTIME_SITE_PACKAGES)
        if site_packages is None or site_packages.kind != "directory":
            raise ToolchainSupportLockError(
                "toolchain support Actions Python site-packages is not a regular directory"
            )
    elif variant == _MACOS_XCODE_SDK_16_4_VARIANT:
        if any(
            (entry := by_path.get(relative_path)) is None or entry.kind != "file"
            for relative_path in _MACOS_XCODE_SDK_16_4_REGULAR_FILES
        ):
            raise ToolchainSupportLockError(
                "toolchain support Xcode 16.4 SoundAnalysis inputs are not regular files"
            )
    receipts: list[ToolchainSupportSymlinkDispositionReceipt] = []
    for relative_path in sorted(observed, key=lambda value: (_alias(value), value)):
        raw = observed[relative_path]
        policy = expected[relative_path]
        if raw.policy != policy:
            raise ToolchainSupportLockError(
                "toolchain support fixed symlink disposition changed"
            )
        external_role: str | None = None
        external_merkle: str | None = None
        resolved_relative: str | None = None
        if policy.disposition == "deny-unmapped-virtual-target":
            profile_root, profile_locator_path_sha256 = (
                _deny_unmapped_symlink_profile(
                    target_triple=target_triple,
                    logical_role=logical_role,
                )
            )
            if (
                root_path != profile_root
                or _locator_path_digest(root_path)
                != profile_locator_path_sha256
            ):
                raise ToolchainSupportLockError(
                    "toolchain support unmapped virtual target is outside the exact Linux profile"
                )
            resolved_path_sha256 = _unmapped_virtual_target_digest(
                root_path=root_path,
                initial_policy=policy,
                expected=expected,
            )
        else:
            link_path = root_path / PurePosixPath(relative_path)
            try:
                resolved = link_path.resolve(strict=True)
            except OSError as exc:
                raise ToolchainSupportLockError(
                    "toolchain support fixed symlink disposition is unresolved"
                ) from exc
            resolved_path_sha256 = _locator_path_digest(resolved)
        if policy.disposition != "deny-unmapped-virtual-target":
            if policy.disposition == "deny-isolated-site-packages":
                try:
                    resolved.relative_to(root_path)
                except ValueError:
                    pass
                else:
                    raise ToolchainSupportLockError(
                        "toolchain support denied Python site-packages alias entered the runtime root"
                    )
            elif policy.disposition == "bind-external-manifest":
                assert policy.external_manifest_role is not None
                binding = manifest_bindings.get(policy.external_manifest_role)
                if binding is None:
                    raise ToolchainSupportLockError(
                        "toolchain support external symlink manifest is missing"
                    )
                manifest_locator, manifest_receipt = binding
                if resolved != manifest_locator._absolute_path:
                    raise ToolchainSupportLockError(
                        "toolchain support external symlink resolution differs from its manifest"
                    )
                if not hmac.compare_digest(
                    resolved_path_sha256,
                    manifest_receipt.locator_path_sha256,
                ):
                    raise ToolchainSupportLockError(
                        "toolchain support external symlink path binding is stale"
                    )
                external_role = policy.external_manifest_role
                external_merkle = manifest_receipt.merkle_sha256
            else:
                assert policy.canonical_link_target is not None
                try:
                    physical_relative = resolved.relative_to(root_path).as_posix()
                except ValueError as exc:
                    raise ToolchainSupportLockError(
                        "toolchain support normalized SDK alias escaped its root"
                    ) from exc
                resolved_relative = _resolve_captured_link(
                    relative_path,
                    policy.canonical_link_target,
                    by_path,
                )
                if physical_relative != resolved_relative:
                    raise ToolchainSupportLockError(
                        "toolchain support normalized SDK alias resolution changed"
                    )
        receipts.append(
            _new_symlink_disposition_receipt(
                raw=raw,
                target_triple=target_triple,
                logical_role=logical_role,
                resolved_path_sha256=resolved_path_sha256,
                external_manifest_role=external_role,
                external_manifest_merkle_sha256=external_merkle,
                resolved_relative_path=resolved_relative,
            )
        )
    return tuple(receipts)


def _unmapped_virtual_target_digest(
    *,
    root_path: Path,
    initial_policy: _FixedSymlinkDisposition,
    expected: Mapping[str, _FixedSymlinkDisposition],
) -> str:
    """Bind an exact escaping target without following or opening host bytes."""
    current = initial_policy
    visited: set[str] = set()
    traversed: list[_FixedSymlinkDisposition] = []
    for _hop in range(len(expected) + 1):
        if (
            current.relative_path in visited
            or current.disposition != "deny-unmapped-virtual-target"
            or current.resolved_path_sha256 is None
        ):
            raise ToolchainSupportLockError(
                "toolchain support unmapped virtual target policy is cyclic or malformed"
            )
        visited.add(current.relative_path)
        traversed.append(current)
        candidate = _lexical_absolute_link_target(
            root_path=root_path,
            relative_path=current.relative_path,
            link_target=current.raw_link_target,
        )
        try:
            candidate_relative = candidate.relative_to(root_path).as_posix()
        except ValueError:
            digest = _locator_path_digest(candidate)
            if any(
                policy.resolved_path_sha256 != digest for policy in traversed
            ):
                raise ToolchainSupportLockError(
                    "toolchain support unmapped virtual target resolution differs from policy"
                )
            return digest
        next_policy = expected.get(candidate_relative)
        if next_policy is None:
            raise ToolchainSupportLockError(
                "toolchain support unmapped virtual target entered an unbound in-root path"
            )
        current = next_policy
    raise ToolchainSupportLockError(
        "toolchain support unmapped virtual target exceeds the policy hop bound"
    )


def _new_symlink_disposition_receipt(
    *,
    raw: _RawSymlinkDisposition,
    target_triple: str | None,
    logical_role: str,
    resolved_path_sha256: str,
    external_manifest_role: str | None,
    external_manifest_merkle_sha256: str | None,
    resolved_relative_path: str | None,
    external_support_root_role: str | None = None,
    external_support_root_merkle_sha256: str | None = None,
) -> ToolchainSupportSymlinkDispositionReceipt:
    receipt_mode = _validate_generated_mode(
        raw.mode,
        origin="symlink-disposition-receipt",
        target_triple=target_triple,
        logical_role=logical_role,
        kind="symlink",
        path_digest_label="relative_path_sha256",
        path_sha256=_relative_mode_path_digest(raw.policy.relative_path),
    )
    provisional = ToolchainSupportSymlinkDispositionReceipt.__new__(
        ToolchainSupportSymlinkDispositionReceipt
    )
    values: dict[str, object] = {
        "relative_path": raw.policy.relative_path,
        "disposition": raw.policy.disposition,
        "raw_link_target": raw.policy.raw_link_target,
        "canonical_link_target": raw.policy.canonical_link_target,
        "external_manifest_role": external_manifest_role,
        "external_manifest_merkle_sha256": external_manifest_merkle_sha256,
        "external_support_root_role": external_support_root_role,
        "external_support_root_merkle_sha256": (
            external_support_root_merkle_sha256
        ),
        "resolved_relative_path": resolved_relative_path,
        "resolved_path_sha256": resolved_path_sha256,
        "mode": receipt_mode,
        "metadata_sha256": raw.metadata_sha256,
        "xattr_count": raw.xattr_count,
        "xattr_bytes": raw.xattr_bytes,
        "xattrs_sha256": raw.xattrs_sha256,
        "size": raw.size,
        "raw_sha256": raw.raw_sha256,
    }
    for name, value in values.items():
        object.__setattr__(provisional, name, value)
    object.__setattr__(provisional, "merkle_sha256", "")
    return ToolchainSupportSymlinkDispositionReceipt(
        relative_path=raw.policy.relative_path,
        disposition=raw.policy.disposition,
        raw_link_target=raw.policy.raw_link_target,
        canonical_link_target=raw.policy.canonical_link_target,
        external_manifest_role=external_manifest_role,
        external_manifest_merkle_sha256=external_manifest_merkle_sha256,
        external_support_root_role=external_support_root_role,
        external_support_root_merkle_sha256=(
            external_support_root_merkle_sha256
        ),
        resolved_relative_path=resolved_relative_path,
        resolved_path_sha256=resolved_path_sha256,
        mode=receipt_mode,
        metadata_sha256=raw.metadata_sha256,
        xattr_count=raw.xattr_count,
        xattr_bytes=raw.xattr_bytes,
        xattrs_sha256=raw.xattrs_sha256,
        size=raw.size,
        raw_sha256=raw.raw_sha256,
        merkle_sha256=_symlink_disposition_merkle(provisional),
    )


def _linux_casefold_topology_sha256(
    groups: tuple[_RawCasefoldGroup, ...],
) -> str:
    return _sha256(
        {
            "domain": "rextio.full-c6-linux-folded-name-topology.v1",
            "groups": [
                {
                    "group_sha256": item.group_sha256,
                    "member_count": item.member_count,
                }
                for item in groups
            ],
        }
    )


def _finalize_casefold_dispositions(
    *,
    target_triple: str | None,
    logical_role: str,
    groups: tuple[_RawCasefoldGroup, ...],
) -> tuple[ToolchainSupportCasefoldDispositionReceipt, ...]:
    if not groups:
        return ()
    if (
        target_triple != "x86_64-unknown-linux-gnu"
        or logical_role != _LINUX_CASEFOLD_ROLE
    ):
        raise ToolchainSupportLockError(
            "toolchain support casefold collision is outside policy"
        )
    ordered = tuple(sorted(groups, key=lambda item: item.group_sha256))
    if len({item.group_sha256 for item in ordered}) != len(ordered):
        raise ToolchainSupportLockError(
            "toolchain support casefold collision groups are noncanonical"
        )
    topology_sha256 = _linux_casefold_topology_sha256(ordered)
    member_count = sum(item.member_count for item in ordered)
    if (
        len(ordered) != _LINUX_CASEFOLD_GROUP_COUNT
        or member_count != _LINUX_CASEFOLD_MEMBER_COUNT
        or topology_sha256 != _LINUX_CASEFOLD_TOPOLOGY_SHA256
    ):
        raise ToolchainSupportLockError(
            "toolchain support Linux casefold topology differs from policy"
        )
    provisional = ToolchainSupportCasefoldDispositionReceipt.__new__(
        ToolchainSupportCasefoldDispositionReceipt
    )
    object.__setattr__(
        provisional,
        "disposition",
        "bind-linux-runtime-casefold-topology",
    )
    object.__setattr__(provisional, "group_count", len(ordered))
    object.__setattr__(provisional, "member_count", member_count)
    object.__setattr__(provisional, "topology_sha256", topology_sha256)
    object.__setattr__(provisional, "merkle_sha256", "")
    return (
        ToolchainSupportCasefoldDispositionReceipt(
            disposition="bind-linux-runtime-casefold-topology",
            group_count=len(ordered),
            member_count=member_count,
            topology_sha256=topology_sha256,
            merkle_sha256=_casefold_disposition_merkle(provisional),
        ),
    )


def _extract_external_support_root_dispositions(
    *,
    target_triple: str | None,
    logical_role: str,
    root_path: Path,
    entries: tuple[_ToolchainSupportTreeEntry, ...],
    binding: _ExternalSupportRootBinding | None,
) -> tuple[
    tuple[_ToolchainSupportTreeEntry, ...],
    tuple[ToolchainSupportSymlinkDispositionReceipt, ...],
]:
    retained: list[_ToolchainSupportTreeEntry] = []
    dispositions: list[ToolchainSupportSymlinkDispositionReceipt] = []
    for entry in entries:
        if entry.kind != "symlink":
            retained.append(entry)
            continue
        assert entry.link_target is not None
        candidate = _lexical_absolute_link_target(
            root_path=root_path,
            relative_path=entry.relative_path,
            link_target=entry.link_target,
        )
        try:
            candidate.relative_to(root_path)
        except ValueError:
            pass
        else:
            retained.append(entry)
            continue
        if binding is None:
            retained.append(entry)
            continue
        try:
            candidate_relative = candidate.relative_to(binding.locator._absolute_path)
        except ValueError as exc:
            raise ToolchainSupportLockError(
                "toolchain support external symlink did not enter the exact runtime root"
            ) from exc
        if not candidate_relative.parts:
            raise ToolchainSupportLockError(
                "toolchain support external symlink did not resolve to a regular runtime member"
            )
        resolved_relative = _resolve_external_support_member(
            root_path=binding.locator._absolute_path,
            initial_relative=PurePosixPath(candidate_relative.as_posix()),
        )
        raw = _RawSymlinkDisposition(
            policy=_FixedSymlinkDisposition(
                relative_path=entry.relative_path,
                raw_link_target=entry.link_target,
                disposition="bind-external-support-root",
            ),
            mode=entry.mode,
            metadata_sha256=entry.metadata_sha256,
            xattr_count=entry.xattr_count,
            xattr_bytes=entry.xattr_bytes,
            xattrs_sha256=entry.xattrs_sha256,
            size=entry.size,
            raw_sha256=cast(str, entry.raw_sha256),
        )
        resolved_path = binding.locator._absolute_path / PurePosixPath(
            resolved_relative
        )
        dispositions.append(
            _new_symlink_disposition_receipt(
                raw=raw,
                target_triple=target_triple,
                logical_role=logical_role,
                resolved_path_sha256=_locator_path_digest(resolved_path),
                external_manifest_role=None,
                external_manifest_merkle_sha256=None,
                external_support_root_role=binding.locator.logical_role,
                external_support_root_merkle_sha256=binding.receipt.merkle_sha256,
                resolved_relative_path=resolved_relative,
            )
        )
    return tuple(retained), tuple(dispositions)


def _lexical_absolute_link_target(
    *,
    root_path: Path,
    relative_path: str,
    link_target: str,
) -> Path:
    parts = list(root_path.parts[1:])
    parts.extend(PurePosixPath(relative_path).parent.parts)
    for part in link_target.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                raise ToolchainSupportLockError(
                    "toolchain support symlink escapes the filesystem root"
                )
            parts.pop()
            continue
        parts.append(part)
    return Path("/", *parts)


def _resolve_external_support_member(
    *,
    root_path: Path,
    initial_relative: PurePosixPath,
) -> str:
    pending = list(initial_relative.parts)
    resolved: list[str] = []
    visited: set[str] = set()
    hops = 0
    while pending:
        part = pending.pop(0)
        if part in {"", "."}:
            continue
        if part == "..":
            if not resolved:
                raise ToolchainSupportLockError(
                    "toolchain support external symlink re-escapes its runtime root"
                )
            resolved.pop()
            continue
        resolved.append(part)
        relative = PurePosixPath(*resolved).as_posix()
        path = root_path / PurePosixPath(relative)
        try:
            observed = os.lstat(path)
        except OSError as exc:
            raise ToolchainSupportLockError(
                "toolchain support external symlink is broken"
            ) from exc
        if stat.S_ISLNK(observed.st_mode):
            if relative in visited:
                raise ToolchainSupportLockError(
                    "toolchain support external symlink graph contains a cycle"
                )
            visited.add(relative)
            hops += 1
            if hops > MAX_TOOLCHAIN_SUPPORT_TREE_DEPTH:
                raise ToolchainSupportLockError(
                    "toolchain support external symlink graph exceeds the depth bound"
                )
            try:
                target = os.readlink(path)
            except OSError as exc:
                raise ToolchainSupportLockError(
                    "toolchain support external symlink could not be read"
                ) from exc
            _validate_link_target(target)
            pending = (
                list(PurePosixPath(relative).parent.parts)
                + target.split("/")
                + pending
            )
            resolved = []
            continue
        if pending and not stat.S_ISDIR(observed.st_mode):
            raise ToolchainSupportLockError(
                "toolchain support external symlink crosses a nondirectory member"
            )
        if not pending and not stat.S_ISREG(observed.st_mode):
            raise ToolchainSupportLockError(
                "toolchain support external symlink did not resolve to a regular runtime member"
            )
    if not resolved:
        raise ToolchainSupportLockError(
            "toolchain support external symlink did not resolve to a regular runtime member"
        )
    return PurePosixPath(*resolved).as_posix()


def _capture_tree_once(
    locator: ToolchainSupportLocator,
    *,
    target_triple: str | None,
    manifest_bindings: dict[
        str,
        tuple[ToolchainSupportLocator, ToolchainSupportFileReceipt],
    ],
    external_support_root_binding: _ExternalSupportRootBinding | None,
    hardlink_topology: _XcodeHardlinkTopologyObservation | None,
    hardlink_receipt: ToolchainSupportHardlinkDispositionReceipt | None,
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
        _validate_tree_root_mode(
            target_triple=target_triple,
            logical_role=locator.logical_role,
            locator_path=locator._absolute_path,
            full_mode=opened_root.mode,
        )
        raw_entries: list[_RawTreeEntry] = []
        raw_dispositions: list[_RawSymlinkDisposition] = []
        hardlink_dispositions = (
            [] if hardlink_receipt is None else [hardlink_receipt]
        )
        hardlink_plan = (
            None
            if hardlink_topology is None
            else _AllowedHardlinkPlan.from_topology(hardlink_topology)
        )
        mode_dispositions: list[ToolchainSupportModeDispositionReceipt] = []
        raw_casefold_groups: list[_RawCasefoldGroup] = []
        aliases: set[str] = set()
        inode_keys: set[tuple[int, int]] = set()
        total_bytes = [0]
        root_stamp, root_xattrs = _walk_tree(
            root_fd,
            target_triple=target_triple,
            root_path=locator._absolute_path,
            logical_role=locator.logical_role,
            relative=PurePosixPath(),
            entries=raw_entries,
            dispositions=raw_dispositions,
            hardlink_plan=hardlink_plan,
            mode_dispositions=mode_dispositions,
            casefold_groups=raw_casefold_groups,
            disposition_policies=_fixed_symlink_disposition_map(
                target_triple,
                locator.logical_role,
            ),
            aliases=aliases,
            inode_keys=inode_keys,
            total_bytes=total_bytes,
            xattr_budget=xattr_budget,
        )
        if not raw_entries and not raw_dispositions:
            raise ToolchainSupportLockError("toolchain support root is empty")
        if hardlink_plan is not None and hardlink_plan.entries:
            raise ToolchainSupportLockError(
                "toolchain support Xcode hardlink plan was not fully consumed"
            )
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
            mode=_validate_tree_receipt_mode(
                mode=item.mode,
                target_triple=target_triple,
                logical_role=locator.logical_role,
                kind=item.kind,
                relative_path=item.relative_path,
                mode_dispositions=tuple(mode_dispositions),
            ),
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
    entries_without_merkle, external_dispositions = (
        _extract_external_support_root_dispositions(
            target_triple=target_triple,
            logical_role=locator.logical_role,
            root_path=locator._absolute_path,
            entries=entries_without_merkle,
            binding=external_support_root_binding,
        )
    )
    _validate_tree_namespace(entries_without_merkle, validate_merkle=False)
    fixed_dispositions = _finalize_symlink_dispositions(
        target_triple=target_triple,
        logical_role=locator.logical_role,
        root_path=locator._absolute_path,
        entries=entries_without_merkle,
        raw_dispositions=tuple(raw_dispositions),
        manifest_bindings=manifest_bindings,
    )
    dispositions = tuple(
        sorted(
            (*fixed_dispositions, *external_dispositions),
            key=lambda item: (_alias(item.relative_path), item.relative_path),
        )
    )
    hardlink_receipts = tuple(
        hardlink_dispositions
    )
    mode_receipts = tuple(mode_dispositions)
    casefold_receipts = _finalize_casefold_dispositions(
        target_triple=target_triple,
        logical_role=locator.logical_role,
        groups=tuple(raw_casefold_groups),
    )
    entries, merkle = _build_tree_merkle(
        logical_role=locator.logical_role,
        locator_path_sha256=_locator_path_digest(locator._absolute_path),
        root_mode=stat.S_IMODE(root_stamp.mode),
        root_metadata_sha256=_metadata_digest(root_stamp, kind="directory"),
        root_xattrs=root_xattrs,
        entries=entries_without_merkle,
        symlink_dispositions=dispositions,
        hardlink_dispositions=hardlink_receipts,
        mode_dispositions=mode_receipts,
        casefold_dispositions=casefold_receipts,
    )
    xattr_count = (
        root_xattrs.count
        + sum(item.xattr_count for item in entries)
        + sum(item.xattr_count for item in dispositions)
    )
    xattr_bytes = (
        root_xattrs.total_bytes
        + sum(item.xattr_bytes for item in entries)
        + sum(item.xattr_bytes for item in dispositions)
    )
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
    receipt_root_mode = _validate_generated_mode(
        stat.S_IMODE(root_stamp.mode),
        origin="tree-root-receipt",
        target_triple=target_triple,
        logical_role=locator.logical_role,
        kind="root",
        path_digest_label="locator_path_sha256",
        path_sha256=_locator_path_digest(locator._absolute_path),
    )
    return ToolchainSupportTreeReceipt(
        logical_role=locator.logical_role,
        locator_path_sha256=_locator_path_digest(locator._absolute_path),
        root_metadata_sha256=_metadata_digest(root_stamp, kind="directory"),
        root_mode=receipt_root_mode,
        member_count=len(entries) + len(dispositions),
        file_count=sum(item.kind == "file" for item in entries),
        directory_count=sum(item.kind == "directory" for item in entries),
        symlink_count=sum(item.kind == "symlink" for item in entries)
        + len(dispositions),
        total_bytes=sum(item.size for item in entries if item.kind == "file"),
        xattr_count=xattr_count,
        xattr_bytes=xattr_bytes,
        symlink_disposition_count=len(dispositions),
        symlink_dispositions=dispositions,
        hardlink_disposition_count=len(hardlink_receipts),
        hardlink_dispositions=hardlink_receipts,
        mode_disposition_count=len(mode_receipts),
        mode_dispositions=mode_receipts,
        casefold_disposition_count=len(casefold_receipts),
        casefold_dispositions=casefold_receipts,
        merkle_sha256=merkle,
    )


def _walk_tree(
    directory_fd: int,
    *,
    target_triple: str | None,
    root_path: Path,
    logical_role: str,
    relative: PurePosixPath,
    entries: list[_RawTreeEntry],
    dispositions: list[_RawSymlinkDisposition],
    hardlink_plan: _AllowedHardlinkPlan | None,
    mode_dispositions: list[ToolchainSupportModeDispositionReceipt],
    casefold_groups: list[_RawCasefoldGroup],
    disposition_policies: dict[str, _FixedSymlinkDisposition],
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
    local_groups: dict[str, list[str]] = {}
    for name in names:
        _validate_segment(name)
        local_groups.setdefault(_alias(name), []).append(name)
    collisions = {
        alias: tuple(sorted(members))
        for alias, members in local_groups.items()
        if len(members) > 1
    }
    if collisions and not (
        target_triple == "x86_64-unknown-linux-gnu"
        and logical_role == _LINUX_CASEFOLD_ROLE
    ):
        raise ToolchainSupportLockError(
            "toolchain support directory contains an NFC/casefold alias"
        )
    directory_relative = relative.as_posix() if relative.parts else ""
    for folded_key, members in sorted(collisions.items()):
        if (
            len(members) > _MAX_CASEFOLD_GROUP_MEMBERS
            or len(casefold_groups) >= _MAX_CASEFOLD_GROUPS
        ):
            raise ToolchainSupportLockError(
                "toolchain support casefold collision exceeds the bound"
            )
        casefold_groups.append(
            _RawCasefoldGroup(
                group_sha256=_sha256(
                    {
                        "domain": "rextio.full-c6-linux-folded-name-group.v1",
                        "directory_relative_path": directory_relative,
                        "folded_key": folded_key,
                        "member_names": list(members),
                    }
                ),
                member_count=len(members),
            )
        )
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
        if logical_alias in aliases and _alias(name) not in collisions:
            raise ToolchainSupportLockError(
                "toolchain support tree contains an NFC/casefold path alias"
            )
        aliases.add(logical_alias)
        if (
            len(entries) + len(dispositions)
            >= MAX_TOOLCHAIN_SUPPORT_TREE_MEMBERS
        ):
            raise ToolchainSupportLockError(
                "toolchain support tree member count exceeds the bound"
            )
        observed = _stamp(os.stat(name, dir_fd=directory_fd, follow_symlinks=False))
        _validate_tree_member_mode(
            target_triple=target_triple,
            logical_role=logical_role,
            relative_path=logical,
            full_mode=observed.mode,
            root_path=root_path,
        )
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
                    target_triple=target_triple,
                    root_path=root_path,
                    logical_role=logical_role,
                    relative=child_relative,
                    entries=entries,
                    dispositions=dispositions,
                    hardlink_plan=hardlink_plan,
                    mode_dispositions=mode_dispositions,
                    casefold_groups=casefold_groups,
                    disposition_policies=disposition_policies,
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
            _require_unaliased_regular_tree_inode(
                observed,
                inode_keys,
                logical_role=logical_role,
                relative_path=logical,
                hardlink_plan=hardlink_plan,
            )
            if observed.size > MAX_TOOLCHAIN_SUPPORT_FILE_BYTES:
                raise ToolchainSupportLockError(
                    "toolchain support file exceeds the byte bound"
                )
            if total_bytes[0] + observed.size > MAX_TOOLCHAIN_SUPPORT_TREE_BYTES:
                raise ToolchainSupportLockError(
                    "toolchain support tree byte count exceeds the bound"
                )
            file_fd = _open_regular_file(
                directory_fd,
                name,
                expected_links=observed.links,
                mode_origin="tree-member-open",
                mode_target_triple=target_triple,
                mode_logical_role=logical_role,
                mode_path_digest_label="relative_path_sha256",
                mode_path_sha256=_relative_mode_path_digest(logical),
                allowed_special_mode=(
                    _LINUX_MODE_DISPOSITION_MODE
                    if stat.S_IMODE(observed.mode)
                    == _LINUX_MODE_DISPOSITION_MODE
                    else None
                ),
            )
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
                    expected_links=observed.links,
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
            metadata_sha256 = _metadata_digest(final_stamp, kind="file")
            if stat.S_IMODE(final_stamp.mode) > 0o777:
                if mode_dispositions:
                    raise ToolchainSupportLockError(
                        "toolchain support Linux mode disposition is repeated"
                    )
                mode_dispositions.append(
                    _new_mode_disposition_receipt(
                        stamp=final_stamp,
                        metadata_sha256=metadata_sha256,
                        raw_sha256=digest,
                        size=size,
                        xattrs=xattrs,
                    )
                )
            entries.append(
                _RawTreeEntry(
                    relative_path=logical,
                    kind="file",
                    mode=stat.S_IMODE(final_stamp.mode),
                    metadata_sha256=metadata_sha256,
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
            policy = disposition_policies.get(logical)
            if policy is not None:
                if target != policy.raw_link_target:
                    raise ToolchainSupportLockError(
                        "toolchain support fixed symlink disposition target changed"
                    )
                dispositions.append(
                    _RawSymlinkDisposition(
                        policy=policy,
                        mode=stat.S_IMODE(final_stamp.mode),
                        metadata_sha256=_metadata_digest(
                            final_stamp,
                            kind="symlink",
                        ),
                        xattr_count=xattrs.count,
                        xattr_bytes=xattrs.total_bytes,
                        xattrs_sha256=xattrs.merkle_sha256,
                        size=len(target_bytes),
                        raw_sha256=hashlib.sha256(target_bytes).hexdigest(),
                    )
                )
                continue
            _validate_link_target(target)
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
    symlink_dispositions: tuple[
        ToolchainSupportSymlinkDispositionReceipt, ...
    ] = (),
    hardlink_dispositions: tuple[
        ToolchainSupportHardlinkDispositionReceipt, ...
    ] = (),
    mode_dispositions: tuple[ToolchainSupportModeDispositionReceipt, ...] = (),
    casefold_dispositions: tuple[
        ToolchainSupportCasefoldDispositionReceipt, ...
    ] = (),
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
            "domain": "rextio.full-c6-toolchain-support-tree.v4",
            "logical_role": logical_role,
            "locator_path_sha256": locator_path_sha256,
            "root_mode": root_mode,
            "root_metadata_sha256": root_metadata_sha256,
            "root_xattr_count": root_xattrs.count,
            "root_xattr_bytes": root_xattrs.total_bytes,
            "root_xattrs_sha256": root_xattrs.merkle_sha256,
            "member_count": len(entries) + len(symlink_dispositions),
            "file_count": sum(item.kind == "file" for item in entries),
            "directory_count": sum(item.kind == "directory" for item in entries),
            "symlink_count": sum(item.kind == "symlink" for item in entries)
            + len(symlink_dispositions),
            "symlink_disposition_count": len(symlink_dispositions),
            "hardlink_disposition_count": len(hardlink_dispositions),
            "mode_disposition_count": len(mode_dispositions),
            "casefold_disposition_count": len(casefold_dispositions),
            "total_bytes": sum(
                item.size for item in entries if item.kind == "file"
            ),
            "xattr_count": root_xattrs.count
            + sum(item.xattr_count for item in entries)
            + sum(item.xattr_count for item in symlink_dispositions),
            "xattr_bytes": root_xattrs.total_bytes
            + sum(item.xattr_bytes for item in entries)
            + sum(item.xattr_bytes for item in symlink_dispositions),
            "symlink_dispositions": [
                {
                    "relative_path": item.relative_path,
                    "merkle_sha256": item.merkle_sha256,
                }
                for item in symlink_dispositions
            ],
            "hardlink_dispositions": [
                {"merkle_sha256": item.merkle_sha256}
                for item in hardlink_dispositions
            ],
            "mode_dispositions": [
                {"merkle_sha256": item.merkle_sha256}
                for item in mode_dispositions
            ],
            "casefold_dispositions": [
                {"merkle_sha256": item.merkle_sha256}
                for item in casefold_dispositions
            ],
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


def _symlink_disposition_merkle(
    receipt: ToolchainSupportSymlinkDispositionReceipt,
) -> str:
    return _sha256(
        {
            "domain": "rextio.full-c6-toolchain-support-symlink-disposition.v2",
            "relative_path": receipt.relative_path,
            "disposition": receipt.disposition,
            "raw_link_target": receipt.raw_link_target,
            "canonical_link_target": receipt.canonical_link_target,
            "external_manifest_role": receipt.external_manifest_role,
            "external_manifest_merkle_sha256": (
                receipt.external_manifest_merkle_sha256
            ),
            "external_support_root_role": receipt.external_support_root_role,
            "external_support_root_merkle_sha256": (
                receipt.external_support_root_merkle_sha256
            ),
            "resolved_relative_path": receipt.resolved_relative_path,
            "resolved_path_sha256": receipt.resolved_path_sha256,
            "mode": receipt.mode,
            "metadata_sha256": receipt.metadata_sha256,
            "xattr_count": receipt.xattr_count,
            "xattr_bytes": receipt.xattr_bytes,
            "xattrs_sha256": receipt.xattrs_sha256,
            "size": receipt.size,
            "raw_sha256": receipt.raw_sha256,
        }
    )


def _hardlink_disposition_merkle(
    receipt: ToolchainSupportHardlinkDispositionReceipt,
) -> str:
    return _sha256(
        {
            "domain": "rextio.full-c6-toolchain-support-hardlink-disposition.v2",
            "disposition": receipt.disposition,
            "resource_root_locator_path_sha256": (
                receipt.resource_root_locator_path_sha256
            ),
            "version_manifest_role": receipt.version_manifest_role,
            "version_manifest_raw_sha256": receipt.version_manifest_raw_sha256,
            "version_manifest_merkle_sha256": (
                receipt.version_manifest_merkle_sha256
            ),
            "group_count": receipt.group_count,
            "support_member_count": receipt.support_member_count,
            "alias_count": receipt.alias_count,
            "policy_merkle_sha256": receipt.policy_merkle_sha256,
            "observation_merkle_sha256": receipt.observation_merkle_sha256,
        }
    )


def _mode_disposition_merkle(
    receipt: ToolchainSupportModeDispositionReceipt,
) -> str:
    return _sha256(
        {
            "domain": "rextio.full-c6-toolchain-support-mode-disposition.v1",
            "disposition": receipt.disposition,
            "support_root_locator_path_sha256": (
                receipt.support_root_locator_path_sha256
            ),
            "relative_path_sha256": receipt.relative_path_sha256,
            "kind": receipt.kind,
            "mode": receipt.mode,
            "full_stamp_sha256": receipt.full_stamp_sha256,
            "metadata_sha256": receipt.metadata_sha256,
            "raw_sha256": receipt.raw_sha256,
            "member_receipt_sha256": receipt.member_receipt_sha256,
        }
    )


def _casefold_disposition_merkle(
    receipt: ToolchainSupportCasefoldDispositionReceipt,
) -> str:
    return _sha256(
        {
            "domain": "rextio.full-c6-toolchain-support-casefold-disposition.v1",
            "disposition": receipt.disposition,
            "group_count": receipt.group_count,
            "member_count": receipt.member_count,
            "topology_sha256": receipt.topology_sha256,
        }
    )


def _lock_merkle(lock: ToolchainSupportLock) -> str:
    return _sha256(
        {
            "domain": "rextio.full-c6-toolchain-support-aggregate.v2",
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
    symlink_documents = _list(
        document["symlink_dispositions"],
        "symlink dispositions",
    )
    hardlink_documents = _list(
        document["hardlink_dispositions"],
        "hardlink dispositions",
    )
    mode_documents = _list(
        document["mode_dispositions"],
        "mode dispositions",
    )
    casefold_documents = _list(
        document["casefold_dispositions"],
        "casefold dispositions",
    )
    if (
        len(symlink_documents) > MAX_TOOLCHAIN_SUPPORT_TREE_MEMBERS
        or len(hardlink_documents) > 1
        or len(mode_documents) > 1
        or len(casefold_documents) > 1
    ):
        raise ToolchainSupportLockError(
            "toolchain support disposition count exceeds the bound"
        )
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
        symlink_disposition_count=_integer(
            document["symlink_disposition_count"],
            "tree symlink disposition count",
        ),
        symlink_dispositions=tuple(
            _parse_symlink_disposition(item)
            for item in symlink_documents
        ),
        hardlink_disposition_count=_integer(
            document["hardlink_disposition_count"],
            "tree hardlink disposition count",
        ),
        hardlink_dispositions=tuple(
            _parse_hardlink_disposition(item)
            for item in hardlink_documents
        ),
        mode_disposition_count=_integer(
            document["mode_disposition_count"],
            "tree mode disposition count",
        ),
        mode_dispositions=tuple(
            _parse_mode_disposition(item) for item in mode_documents
        ),
        casefold_disposition_count=_integer(
            document["casefold_disposition_count"],
            "tree casefold disposition count",
        ),
        casefold_dispositions=tuple(
            _parse_casefold_disposition(item)
            for item in casefold_documents
        ),
        merkle_sha256=_string(document["merkle_sha256"], "tree Merkle SHA-256"),
    )


def _parse_hardlink_disposition(
    value: object,
) -> ToolchainSupportHardlinkDispositionReceipt:
    document = _exact_dict(
        value,
        _HARDLINK_DISPOSITION_FIELDS,
        "hardlink disposition receipt",
    )
    return ToolchainSupportHardlinkDispositionReceipt(
        disposition=_string(document["disposition"], "hardlink disposition"),
        resource_root_locator_path_sha256=_string(
            document["resource_root_locator_path_sha256"],
            "hardlink resource-root locator path SHA-256",
        ),
        version_manifest_role=_string(
            document["version_manifest_role"],
            "hardlink version-manifest role",
        ),
        version_manifest_raw_sha256=_string(
            document["version_manifest_raw_sha256"],
            "hardlink version-manifest raw SHA-256",
        ),
        version_manifest_merkle_sha256=_string(
            document["version_manifest_merkle_sha256"],
            "hardlink version-manifest Merkle SHA-256",
        ),
        group_count=_integer(document["group_count"], "hardlink group count"),
        support_member_count=_integer(
            document["support_member_count"],
            "hardlink support-member count",
        ),
        alias_count=_integer(document["alias_count"], "hardlink alias count"),
        policy_merkle_sha256=_string(
            document["policy_merkle_sha256"],
            "hardlink policy Merkle SHA-256",
        ),
        observation_merkle_sha256=_string(
            document["observation_merkle_sha256"],
            "hardlink observation Merkle SHA-256",
        ),
        merkle_sha256=_string(
            document["merkle_sha256"],
            "hardlink disposition Merkle SHA-256",
        ),
    )


def _parse_mode_disposition(
    value: object,
) -> ToolchainSupportModeDispositionReceipt:
    document = _exact_dict(
        value,
        _MODE_DISPOSITION_FIELDS,
        "mode disposition receipt",
    )
    return ToolchainSupportModeDispositionReceipt(
        disposition=_string(document["disposition"], "mode disposition"),
        support_root_locator_path_sha256=_string(
            document["support_root_locator_path_sha256"],
            "mode disposition root locator SHA-256",
        ),
        relative_path_sha256=_string(
            document["relative_path_sha256"],
            "mode disposition relative-path SHA-256",
        ),
        kind=_string(document["kind"], "mode disposition kind"),
        mode=_integer(document["mode"], "mode disposition mode"),
        full_stamp_sha256=_string(
            document["full_stamp_sha256"],
            "mode disposition full-stamp SHA-256",
        ),
        metadata_sha256=_string(
            document["metadata_sha256"],
            "mode disposition metadata SHA-256",
        ),
        raw_sha256=_string(
            document["raw_sha256"],
            "mode disposition raw SHA-256",
        ),
        member_receipt_sha256=_string(
            document["member_receipt_sha256"],
            "mode disposition member receipt SHA-256",
        ),
        merkle_sha256=_string(
            document["merkle_sha256"],
            "mode disposition Merkle SHA-256",
        ),
    )


def _parse_casefold_disposition(
    value: object,
) -> ToolchainSupportCasefoldDispositionReceipt:
    document = _exact_dict(
        value,
        _CASEFOLD_DISPOSITION_FIELDS,
        "casefold disposition receipt",
    )
    return ToolchainSupportCasefoldDispositionReceipt(
        disposition=_string(document["disposition"], "casefold disposition"),
        group_count=_integer(document["group_count"], "casefold group count"),
        member_count=_integer(document["member_count"], "casefold member count"),
        topology_sha256=_string(
            document["topology_sha256"],
            "casefold topology SHA-256",
        ),
        merkle_sha256=_string(
            document["merkle_sha256"],
            "casefold disposition Merkle SHA-256",
        ),
    )


def _parse_symlink_disposition(
    value: object,
) -> ToolchainSupportSymlinkDispositionReceipt:
    document = _exact_dict(
        value,
        _SYMLINK_DISPOSITION_FIELDS,
        "symlink disposition receipt",
    )

    def optional_string(name: str) -> str | None:
        item = document[name]
        return None if item is None else _string(item, name.replace("_", " "))

    return ToolchainSupportSymlinkDispositionReceipt(
        relative_path=_string(document["relative_path"], "disposition path"),
        disposition=_string(document["disposition"], "disposition kind"),
        raw_link_target=_string(
            document["raw_link_target"],
            "disposition raw link target",
        ),
        canonical_link_target=optional_string("canonical_link_target"),
        external_manifest_role=optional_string("external_manifest_role"),
        external_manifest_merkle_sha256=optional_string(
            "external_manifest_merkle_sha256"
        ),
        external_support_root_role=optional_string(
            "external_support_root_role"
        ),
        external_support_root_merkle_sha256=optional_string(
            "external_support_root_merkle_sha256"
        ),
        resolved_relative_path=optional_string("resolved_relative_path"),
        resolved_path_sha256=_string(
            document["resolved_path_sha256"],
            "disposition resolved path SHA-256",
        ),
        mode=_integer(document["mode"], "disposition mode"),
        metadata_sha256=_string(
            document["metadata_sha256"],
            "disposition metadata SHA-256",
        ),
        xattr_count=_integer(
            document["xattr_count"],
            "disposition xattr count",
        ),
        xattr_bytes=_integer(
            document["xattr_bytes"],
            "disposition xattr bytes",
        ),
        xattrs_sha256=_string(
            document["xattrs_sha256"],
            "disposition xattr SHA-256",
        ),
        size=_integer(document["size"], "disposition size"),
        raw_sha256=_string(
            document["raw_sha256"],
            "disposition raw SHA-256",
        ),
        merkle_sha256=_string(
            document["merkle_sha256"],
            "disposition Merkle SHA-256",
        ),
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


def _open_regular_file(
    parent_fd: int,
    name: str,
    *,
    expected_links: int = 1,
    mode_origin: str | None = None,
    mode_target_triple: str | None = None,
    mode_logical_role: str | None = None,
    mode_path_digest_label: str | None = None,
    mode_path_sha256: str | None = None,
    allowed_special_mode: int | None = None,
) -> int:
    flags = (
        os.O_RDONLY
        | _require_flag("O_NOFOLLOW")
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(name, flags, dir_fd=parent_fd)
    opened = _stamp(os.fstat(descriptor))
    if (
        type(expected_links) is not int
        or isinstance(expected_links, bool)
        or expected_links < 1
        or not stat.S_ISREG(opened.mode)
        or opened.links != expected_links
    ):
        os.close(descriptor)
        raise ToolchainSupportLockError(
            "toolchain support file must be a single-link regular file"
        )
    mode = stat.S_IMODE(opened.mode)
    try:
        if allowed_special_mode is not None and mode == allowed_special_mode:
            if allowed_special_mode != _LINUX_MODE_DISPOSITION_MODE:
                raise ToolchainSupportLockError(
                    "toolchain support special mode allowance is invalid"
                )
        elif mode_origin is None:
            _validate_mode(mode)
        else:
            if (
                mode_logical_role is None
                or mode_path_digest_label is None
                or mode_path_sha256 is None
            ):
                raise ToolchainSupportLockError(
                    "toolchain support mode diagnostic context is incomplete"
                )
            _validate_generated_mode(
                mode,
                origin=mode_origin,
                target_triple=mode_target_triple,
                logical_role=mode_logical_role,
                kind="regular",
                path_digest_label=mode_path_digest_label,
                path_sha256=mode_path_sha256,
            )
    except ToolchainSupportLockError:
        os.close(descriptor)
        raise
    return descriptor


def _stream_file_digest(
    descriptor: int,
    *,
    expected: _FilesystemStamp,
    maximum: int,
    expected_links: int = 1,
) -> tuple[str, int, _FilesystemStamp]:
    if (
        not stat.S_ISREG(expected.mode)
        or type(expected_links) is not int
        or isinstance(expected_links, bool)
        or expected_links < 1
        or expected.links != expected_links
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


def _validate_generated_mode(
    value: object,
    *,
    origin: str,
    target_triple: str | None,
    logical_role: str,
    kind: str,
    path_digest_label: str,
    path_sha256: str,
) -> int:
    """Add bounded, path-opaque context only to generated receipt failures."""
    try:
        return _validate_mode(value)
    except ToolchainSupportLockError:
        if origin not in {
            "manifest-observation",
            "manifest-open",
            "manifest-receipt",
            "tree-member-observation",
            "tree-member-open",
            "tree-member-receipt",
            "tree-merkle-receipt",
            "tree-root-observation",
            "tree-root-receipt",
            "symlink-disposition-receipt",
        }:
            raise ToolchainSupportLockError(
                "toolchain support mode diagnostic origin is invalid"
            ) from None
        if kind not in {"directory", "file", "regular", "root", "special", "symlink"}:
            raise ToolchainSupportLockError(
                "toolchain support mode diagnostic kind is invalid"
            ) from None
        if path_digest_label not in {
            "locator_path_sha256",
            "relative_path_sha256",
        }:
            raise ToolchainSupportLockError(
                "toolchain support mode diagnostic path label is invalid"
            ) from None
        validated_target = (
            "unscoped"
            if target_triple is None
            else ToolchainSupportScope(target_triple=target_triple).target_triple
        )
        _require_sha256(path_sha256, "support mode diagnostic path SHA-256")
        mode_text = (
            f"{value:04o}"
            if type(value) is int
            and not isinstance(value, bool)
            and 0 <= value <= 0o7777
            else "non-posix"
        )
        raise ToolchainSupportLockError(
            "toolchain support permission mode is invalid "
            f"(origin={origin}, target_triple={validated_target}, "
            f"logical_role={_validate_role(logical_role)}, kind={kind}, "
            f"{path_digest_label}={path_sha256}, mode={mode_text})"
        ) from None


def _relative_mode_path_digest(relative_path: str) -> str:
    return _sha256(
        {
            "domain": "rextio.full-c6-toolchain-support-mode-diagnostic-path.v1",
            "relative_path": _validate_relative_path(relative_path),
        }
    )


def _validate_tree_member_mode(
    *,
    target_triple: str | None,
    logical_role: str,
    relative_path: str,
    full_mode: int,
    root_path: Path | None = None,
) -> int:
    mode = stat.S_IMODE(full_mode)
    try:
        return _validate_mode(mode)
    except ToolchainSupportLockError:
        relative_path_sha256 = _relative_mode_path_digest(relative_path)
        if (
            target_triple == "x86_64-unknown-linux-gnu"
            and logical_role == _LINUX_CASEFOLD_ROLE
            and root_path == _LINUX_MODE_DISPOSITION_ROOT
            and _locator_path_digest(root_path)
            == _LINUX_MODE_DISPOSITION_ROOT_LOCATOR_PATH_SHA256
            and relative_path == _LINUX_MODE_DISPOSITION_RELATIVE_PATH
            and stat.S_ISREG(full_mode)
            and relative_path_sha256
            == _LINUX_MODE_DISPOSITION_RELATIVE_PATH_SHA256
            and mode == _LINUX_MODE_DISPOSITION_MODE
        ):
            return mode
        if stat.S_ISREG(full_mode):
            kind = "regular"
        elif stat.S_ISDIR(full_mode):
            kind = "directory"
        elif stat.S_ISLNK(full_mode):
            kind = "symlink"
        else:
            kind = "special"
        validated_target = (
            "unscoped"
            if target_triple is None
            else ToolchainSupportScope(target_triple=target_triple).target_triple
        )
        raise ToolchainSupportLockError(
            "toolchain support permission mode is invalid "
            f"(target_triple={validated_target}, "
            f"logical_role={_validate_role(logical_role)}, "
            f"kind={kind}, "
            "relative_path_sha256="
            f"{relative_path_sha256}, "
            f"mode={mode:04o})"
        ) from None


def _linux_mode_full_stamp_sha256(value: _FilesystemStamp) -> str:
    return _sha256(
        {
            "domain": "rextio.full-c6-linux-mode-full-stamp.v1",
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


def _linux_mode_member_receipt_sha256(
    *,
    relative_path_sha256: str,
    stamp: _FilesystemStamp,
    metadata_sha256: str,
    raw_sha256: str,
    size: int,
    xattrs: _XattrReceipt,
) -> str:
    return _sha256(
        {
            "domain": "rextio.full-c6-linux-mode-member-receipt.v1",
            "relative_path_sha256": relative_path_sha256,
            "mode": stat.S_IMODE(stamp.mode),
            "full_stamp_sha256": _linux_mode_full_stamp_sha256(stamp),
            "metadata_sha256": metadata_sha256,
            "raw_sha256": raw_sha256,
            "size": size,
            "xattr_count": xattrs.count,
            "xattr_bytes": xattrs.total_bytes,
            "xattrs_sha256": xattrs.merkle_sha256,
        }
    )


def _new_mode_disposition_receipt(
    *,
    stamp: _FilesystemStamp,
    metadata_sha256: str,
    raw_sha256: str,
    size: int,
    xattrs: _XattrReceipt,
) -> ToolchainSupportModeDispositionReceipt:
    member_receipt_sha256 = _linux_mode_member_receipt_sha256(
        relative_path_sha256=_LINUX_MODE_DISPOSITION_RELATIVE_PATH_SHA256,
        stamp=stamp,
        metadata_sha256=metadata_sha256,
        raw_sha256=raw_sha256,
        size=size,
        xattrs=xattrs,
    )
    provisional = ToolchainSupportModeDispositionReceipt.__new__(
        ToolchainSupportModeDispositionReceipt
    )
    values: dict[str, object] = {
        "disposition": "bind-linux-runtime-regular-mode",
        "support_root_locator_path_sha256": (
            _LINUX_MODE_DISPOSITION_ROOT_LOCATOR_PATH_SHA256
        ),
        "relative_path_sha256": _LINUX_MODE_DISPOSITION_RELATIVE_PATH_SHA256,
        "kind": "regular",
        "mode": _LINUX_MODE_DISPOSITION_MODE,
        "full_stamp_sha256": _linux_mode_full_stamp_sha256(stamp),
        "metadata_sha256": metadata_sha256,
        "raw_sha256": raw_sha256,
        "member_receipt_sha256": member_receipt_sha256,
    }
    for name, value in values.items():
        object.__setattr__(provisional, name, value)
    object.__setattr__(provisional, "merkle_sha256", "")
    return ToolchainSupportModeDispositionReceipt(
        disposition="bind-linux-runtime-regular-mode",
        support_root_locator_path_sha256=(
            _LINUX_MODE_DISPOSITION_ROOT_LOCATOR_PATH_SHA256
        ),
        relative_path_sha256=_LINUX_MODE_DISPOSITION_RELATIVE_PATH_SHA256,
        kind="regular",
        mode=_LINUX_MODE_DISPOSITION_MODE,
        full_stamp_sha256=_linux_mode_full_stamp_sha256(stamp),
        metadata_sha256=metadata_sha256,
        raw_sha256=raw_sha256,
        member_receipt_sha256=member_receipt_sha256,
        merkle_sha256=_mode_disposition_merkle(provisional),
    )


def _validate_tree_receipt_mode(
    *,
    mode: int,
    target_triple: str | None,
    logical_role: str,
    kind: str,
    relative_path: str,
    mode_dispositions: tuple[ToolchainSupportModeDispositionReceipt, ...],
) -> int:
    """Replay the one exact special-mode allowance at receipt construction."""
    path_sha256 = _relative_mode_path_digest(relative_path)
    if mode > 0o777:
        if (
            target_triple == "x86_64-unknown-linux-gnu"
            and logical_role == _LINUX_CASEFOLD_ROLE
            and kind == "file"
            and mode == _LINUX_MODE_DISPOSITION_MODE
            and len(mode_dispositions) == 1
            and mode_dispositions[0].relative_path_sha256 == path_sha256
        ):
            return _validate_mode(mode & 0o777)
    return _validate_generated_mode(
        mode,
        origin="tree-member-receipt",
        target_triple=target_triple,
        logical_role=logical_role,
        kind=kind,
        path_digest_label="relative_path_sha256",
        path_sha256=path_sha256,
    )


def _validate_tree_root_mode(
    *,
    target_triple: str | None,
    logical_role: str,
    locator_path: Path,
    full_mode: int,
) -> int:
    mode = stat.S_IMODE(full_mode)
    try:
        return _validate_mode(mode)
    except ToolchainSupportLockError:
        validated_target = (
            "unscoped"
            if target_triple is None
            else ToolchainSupportScope(target_triple=target_triple).target_triple
        )
        raise ToolchainSupportLockError(
            "toolchain support permission mode is invalid "
            f"(target_triple={validated_target}, "
            f"logical_role={_validate_role(logical_role)}, "
            "kind=root, "
            f"locator_path_sha256={_locator_path_digest(locator_path)}, "
            f"mode={mode:04o})"
        ) from None


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


def _xcode_hardlink_full_stamp_sha256(value: _FilesystemStamp) -> str:
    if type(value) is not _FilesystemStamp:
        raise ToolchainSupportLockError(
            "toolchain support xcode hardlink stamp is invalid"
        )
    return _sha256(
        {
            "domain": "rextio.full-c6-xcode-hardlink-full-stamp.v1",
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


def _xcode_topology_sha256(domain: str, value: Mapping[str, object]) -> str:
    return _sha256({"domain": domain, **value})


def _open_xcode_topology_regular(
    *,
    boundary: Path,
    relative_path: str,
    expected: _FilesystemStamp,
) -> None:
    """Reopen one path through no-follow descriptors and compare its full stamp."""
    relative = PurePosixPath(_validate_relative_path(relative_path))
    if (
        not boundary.is_absolute()
        or len(relative.parts) > MAX_TOOLCHAIN_SUPPORT_TREE_DEPTH
        or len(relative_path.encode("utf-8")) > MAX_TOOLCHAIN_SUPPORT_PATH_BYTES
    ):
        raise ToolchainSupportLockError(
            "toolchain support Xcode topology final path is invalid"
        )
    chain = _open_directory_chain(boundary.joinpath(*relative.parts).parent)
    descriptor = -1
    try:
        parent_fd = chain[-1][0]
        descriptor = os.open(
            relative.name,
            os.O_RDONLY
            | _require_flag("O_NOFOLLOW")
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=parent_fd,
        )
        opened = _stamp(os.fstat(descriptor))
        linked = _stamp(
            os.stat(relative.name, dir_fd=parent_fd, follow_symlinks=False)
        )
        if opened != expected or linked != opened or not stat.S_ISREG(opened.mode):
            raise ToolchainSupportLockError(
                "toolchain support Xcode topology final stamp changed"
            )
        _verify_directory_chain(chain)
    except ToolchainSupportLockError:
        raise
    except OSError as exc:
        raise ToolchainSupportLockError(
            "toolchain support Xcode topology final entry is unavailable"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        _close_directory_chain(chain)


def _scan_xcode_hardlink_topology(
    *,
    support_root: Path,
    app_boundary: Path,
) -> _XcodeHardlinkTopologyObservation:
    """Capture every shared support inode and every in-app alias exactly once."""
    try:
        support_root.relative_to(app_boundary)
    except ValueError:
        raise ToolchainSupportLockError(
            "toolchain support Xcode topology scope is invalid"
        ) from None
    if not support_root.is_absolute() or not app_boundary.is_absolute():
        raise ToolchainSupportLockError(
            "toolchain support Xcode topology scope is invalid"
        )
    matching_policies = tuple(
        policy
        for policy in _fixed_xcode_hardlink_policies()
        if policy.support_root == support_root
        and policy.support_root_locator_path_sha256
        == _locator_path_digest(support_root)
    )
    if app_boundary != _XCODE_APP_BOUNDARY or len(matching_policies) != 1:
        raise ToolchainSupportLockError(
            "toolchain support Xcode topology is outside the exact profile"
        )
    policy = matching_policies[0]

    def scan_tree(
        *,
        boundary: Path,
        max_entries: int,
        visit: Callable[
            [int, str, PurePosixPath, _FilesystemStamp, tuple[dict[str, str], ...]],
            None,
        ],
    ) -> None:
        chain = _open_directory_chain(boundary)
        entry_count = 0

        def walk(
            directory_fd: int,
            *,
            relative: PurePosixPath,
            parent_chain: tuple[dict[str, str], ...],
        ) -> _FilesystemStamp:
            nonlocal entry_count
            directory_before = _stamp(os.fstat(directory_fd))
            if not stat.S_ISDIR(directory_before.mode):
                raise ToolchainSupportLockError(
                    "toolchain support Xcode topology directory is invalid"
                )
            current_relative = relative.as_posix() if relative.parts else ""
            current_chain = (
                *parent_chain,
                {
                    "relative_path_sha256": _xcode_topology_sha256(
                        "rextio.full-c6-xcode-hardlink-topology-parent-path.v1",
                        {"relative_path": current_relative},
                    ),
                    "full_stamp_sha256": _xcode_hardlink_full_stamp_sha256(
                        directory_before
                    ),
                },
            )
            names = _bounded_directory_names(directory_fd)
            ordered = sorted(names, key=lambda item: (_alias(item), item))
            for name in ordered:
                entry_count += 1
                if entry_count > max_entries:
                    raise ToolchainSupportLockError(
                        "toolchain support Xcode topology entry bound exceeded"
                    )
                child_relative = relative / name
                logical = child_relative.as_posix()
                if (
                    len(child_relative.parts) > MAX_TOOLCHAIN_SUPPORT_TREE_DEPTH
                    or len(logical.encode("utf-8"))
                    > MAX_TOOLCHAIN_SUPPORT_PATH_BYTES
                ):
                    raise ToolchainSupportLockError(
                        "toolchain support Xcode topology path bound exceeded"
                    )
                observed = _stamp(
                    os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                )
                if stat.S_ISDIR(observed.mode):
                    child_fd = _open_child_directory(directory_fd, name)
                    try:
                        if _stamp(os.fstat(child_fd)) != observed:
                            raise ToolchainSupportLockError(
                                "toolchain support Xcode topology directory changed"
                            )
                        child_final = walk(
                            child_fd,
                            relative=child_relative,
                            parent_chain=current_chain,
                        )
                        linked = _stamp(
                            os.stat(
                                name,
                                dir_fd=directory_fd,
                                follow_symlinks=False,
                            )
                        )
                        if child_final != observed or linked != child_final:
                            raise ToolchainSupportLockError(
                                "toolchain support Xcode topology directory changed"
                            )
                    finally:
                        os.close(child_fd)
                elif stat.S_ISREG(observed.mode):
                    visit(
                        directory_fd,
                        name,
                        child_relative,
                        observed,
                        current_chain,
                    )
            after_names = _bounded_directory_names(directory_fd)
            if sorted(after_names, key=lambda item: (_alias(item), item)) != ordered:
                raise ToolchainSupportLockError(
                    "toolchain support Xcode topology inventory changed"
                )
            directory_after = _stamp(os.fstat(directory_fd))
            if not _same_stable_stamp(directory_after, directory_before):
                raise ToolchainSupportLockError(
                    "toolchain support Xcode topology directory changed"
                )
            return directory_after

        try:
            walk(chain[-1][0], relative=PurePosixPath(), parent_chain=())
            _verify_directory_chain(chain)
        except ToolchainSupportLockError:
            raise
        except OSError as exc:
            raise ToolchainSupportLockError(
                "toolchain support Xcode topology scan failed closed"
            ) from exc
        finally:
            _close_directory_chain(chain)

    def open_observed_regular(
        directory_fd: int,
        name: str,
        observed: _FilesystemStamp,
    ) -> _FilesystemStamp:
        descriptor = -1
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY
                | _require_flag("O_NOFOLLOW")
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NONBLOCK", 0),
                dir_fd=directory_fd,
            )
            opened = _stamp(os.fstat(descriptor))
            linked = _stamp(
                os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            )
            if opened != observed or linked != opened:
                raise ToolchainSupportLockError(
                    "toolchain support Xcode topology regular entry changed"
                )
            return opened
        except ToolchainSupportLockError:
            raise
        except OSError as exc:
            raise ToolchainSupportLockError(
                "toolchain support Xcode topology regular entry is unavailable"
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    support_groups: dict[tuple[int, int], dict[str, object]] = {}

    def visit_support(
        directory_fd: int,
        name: str,
        relative_path: PurePosixPath,
        observed: _FilesystemStamp,
        parent_chain: tuple[dict[str, str], ...],
    ) -> None:
        del parent_chain
        if observed.links <= 1:
            return
        opened = open_observed_regular(directory_fd, name, observed)
        key = opened.device, opened.inode
        group = support_groups.get(key)
        if group is None:
            if len(support_groups) >= _XCODE_HARDLINK_MAX_GROUPS:
                raise ToolchainSupportLockError(
                    "toolchain support Xcode topology group bound exceeded"
                )
            group = {"stamp": opened, "paths": []}
            support_groups[key] = group
        elif group["stamp"] != opened:
            raise ToolchainSupportLockError(
                "toolchain support Xcode topology inode stamp changed"
            )
        paths = cast(list[str], group["paths"])
        if len(paths) >= _XCODE_HARDLINK_MAX_MEMBERS_PER_GROUP:
            raise ToolchainSupportLockError(
                "toolchain support Xcode topology support-member bound exceeded"
            )
        paths.append(relative_path.as_posix())

    scan_tree(
        boundary=support_root,
        max_entries=_XCODE_HARDLINK_SUPPORT_MAX_ENTRIES,
        visit=visit_support,
    )
    if not support_groups:
        raise ToolchainSupportLockError(
            "toolchain support Xcode topology contains no shared files"
        )
    aliases: dict[tuple[int, int], list[tuple[str, str, str]]] = {
        key: [] for key in support_groups
    }

    def visit_app(
        directory_fd: int,
        name: str,
        relative_path: PurePosixPath,
        observed: _FilesystemStamp,
        parent_chain: tuple[dict[str, str], ...],
    ) -> None:
        key = observed.device, observed.inode
        group = support_groups.get(key)
        if group is None:
            return
        opened = open_observed_regular(directory_fd, name, observed)
        if group["stamp"] != opened:
            raise ToolchainSupportLockError(
                "toolchain support Xcode topology alias stamp differs"
            )
        members = aliases[key]
        if len(members) >= _XCODE_HARDLINK_MAX_MEMBERS_PER_GROUP:
            raise ToolchainSupportLockError(
                "toolchain support Xcode topology alias bound exceeded"
            )
        logical = relative_path.as_posix()
        members.append(
            (
                logical,
                _xcode_topology_sha256(
                    "rextio.full-c6-xcode-hardlink-topology-alias-path.v1",
                    {"app_relative_path": logical},
                ),
                _xcode_topology_sha256(
                    "rextio.full-c6-xcode-hardlink-topology-parent-chain.v1",
                    {"directories": list(parent_chain)},
                ),
            )
        )

    scan_tree(
        boundary=app_boundary,
        max_entries=_XCODE_HARDLINK_APP_MAX_ENTRIES,
        visit=visit_app,
    )
    records: list[_XcodeHardlinkTopologyGroup] = []
    alias_count = 0
    for key, group in support_groups.items():
        stamp = cast(_FilesystemStamp, group["stamp"])
        support_paths = tuple(sorted(cast(list[str], group["paths"])))
        if not support_paths:
            raise ToolchainSupportLockError(
                "toolchain support Xcode topology support-member count differs"
            )
        ordered_aliases = tuple(
            sorted(aliases[key], key=lambda item: (item[1], item[0]))
        )
        if (
            len(ordered_aliases) != stamp.links
            or len({item[1] for item in ordered_aliases}) != len(ordered_aliases)
        ):
            raise ToolchainSupportLockError(
                "toolchain support Xcode topology alias count differs"
            )
        support_path_sha256s = tuple(
            sorted(
                _xcode_topology_sha256(
                    "rextio.full-c6-xcode-hardlink-topology-support-path.v1",
                    {"support_relative_path": relative_path},
                )
                for relative_path in support_paths
            )
        )
        if len(set(support_path_sha256s)) != len(support_path_sha256s):
            raise ToolchainSupportLockError(
                "toolchain support Xcode topology support paths are ambiguous"
            )
        alias_parent_chain_merkle = _xcode_topology_sha256(
            "rextio.full-c6-xcode-hardlink-topology-alias-parents.v1",
            {
                "aliases": [
                    {
                        "alias_path_sha256": path_sha256,
                        "parent_chain_sha256": parent_sha256,
                    }
                    for _path, path_sha256, parent_sha256 in ordered_aliases
                ]
            },
        )
        policy_group_sha256 = _xcode_topology_sha256(
            "rextio.full-c6-xcode-hardlink-topology-policy-group.v1",
            {
                "support_relative_path_sha256s": list(support_path_sha256s),
                "link_count": stamp.links,
                "alias_count": len(ordered_aliases),
                "alias_path_sha256s": [item[1] for item in ordered_aliases],
            },
        )
        observation_group_sha256 = _xcode_topology_sha256(
            "rextio.full-c6-xcode-hardlink-topology-observation-group.v1",
            {
                "policy_group_sha256": policy_group_sha256,
                "full_stamp_sha256": _xcode_hardlink_full_stamp_sha256(stamp),
                "alias_parent_chain_merkle_sha256": alias_parent_chain_merkle,
            },
        )
        records.append(
            _XcodeHardlinkTopologyGroup(
                policy_group_sha256=policy_group_sha256,
                observation_group_sha256=observation_group_sha256,
                stamp=stamp,
                support_relative_paths=support_paths,
                app_relative_paths=tuple(item[0] for item in ordered_aliases),
            )
        )
        alias_count += len(ordered_aliases)
    ordered_records = tuple(sorted(records, key=lambda item: item.policy_group_sha256))
    if len({item.policy_group_sha256 for item in ordered_records}) != len(
        ordered_records
    ):
        raise ToolchainSupportLockError(
            "toolchain support Xcode topology groups are ambiguous"
        )
    policy_merkle = _xcode_topology_sha256(
        "rextio.full-c6-xcode-hardlink-topology-policy.v1",
        {"policy_group_sha256s": [item.policy_group_sha256 for item in ordered_records]},
    )
    observation_merkle = _xcode_topology_sha256(
        "rextio.full-c6-xcode-hardlink-topology-observation.v1",
        {
            "groups": [
                {
                    "policy_group_sha256": item.policy_group_sha256,
                    "observation_group_sha256": item.observation_group_sha256,
                }
                for item in ordered_records
            ]
        },
    )
    result = _XcodeHardlinkTopologyObservation(
        policy=policy,
        groups=ordered_records,
        group_count=len(ordered_records),
        support_member_count=sum(
            len(item.support_relative_paths) for item in ordered_records
        ),
        alias_count=alias_count,
        policy_merkle_sha256=policy_merkle,
        observation_merkle_sha256=observation_merkle,
    )
    if (
        result.group_count != policy.group_count
        or result.support_member_count != policy.support_member_count
        or result.alias_count != policy.alias_count
        or result.policy_merkle_sha256 != policy.policy_merkle_sha256
    ):
        raise ToolchainSupportLockError(
            "toolchain support Xcode hardlink topology differs from policy "
            f"(logical_role={_validate_role(policy.logical_role)}, "
            f"observed_group_count={result.group_count}, "
            f"expected_group_count={policy.group_count}, "
            "observed_support_member_count="
            f"{result.support_member_count}, "
            "expected_support_member_count="
            f"{policy.support_member_count}, "
            f"observed_alias_count={result.alias_count}, "
            f"expected_alias_count={policy.alias_count}, "
            "observed_policy_merkle_sha256="
            f"{result.policy_merkle_sha256}, "
            "expected_policy_merkle_sha256="
            f"{policy.policy_merkle_sha256})"
        )
    return result


def _reopen_xcode_hardlink_topology(
    topology: _XcodeHardlinkTopologyObservation,
    *,
    support_root: Path,
    app_boundary: Path,
) -> None:
    """Final-reopen every support and app alias after the bracketed scans."""
    if (
        support_root != topology.policy.support_root
        or app_boundary != _XCODE_APP_BOUNDARY
    ):
        raise ToolchainSupportLockError(
            "toolchain support Xcode topology final reopen is outside the exact profile"
        )
    for group in topology.groups:
        for relative_path in group.support_relative_paths:
            _open_xcode_topology_regular(
                boundary=support_root,
                relative_path=relative_path,
                expected=group.stamp,
            )
        for relative_path in group.app_relative_paths:
            _open_xcode_topology_regular(
                boundary=app_boundary,
                relative_path=relative_path,
                expected=group.stamp,
            )


def _new_xcode_hardlink_topology_receipt(
    *,
    topology: _XcodeHardlinkTopologyObservation,
    manifest: ToolchainSupportFileReceipt,
) -> ToolchainSupportHardlinkDispositionReceipt:
    values: dict[str, object] = {
        "disposition": "bind-xcode-resource-hardlink-topology",
        "resource_root_locator_path_sha256": (
            topology.policy.support_root_locator_path_sha256
        ),
        "version_manifest_role": _XCODE_VERSION_MANIFEST_ROLE,
        "version_manifest_raw_sha256": _XCODE_VERSION_MANIFEST_RAW_SHA256,
        "version_manifest_merkle_sha256": manifest.merkle_sha256,
        "group_count": topology.group_count,
        "support_member_count": topology.support_member_count,
        "alias_count": topology.alias_count,
        "policy_merkle_sha256": topology.policy_merkle_sha256,
        "observation_merkle_sha256": topology.observation_merkle_sha256,
    }
    provisional = ToolchainSupportHardlinkDispositionReceipt.__new__(
        ToolchainSupportHardlinkDispositionReceipt
    )
    for name, value in values.items():
        object.__setattr__(provisional, name, value)
    object.__setattr__(provisional, "merkle_sha256", "")
    return ToolchainSupportHardlinkDispositionReceipt(
        disposition="bind-xcode-resource-hardlink-topology",
        resource_root_locator_path_sha256=(
            topology.policy.support_root_locator_path_sha256
        ),
        version_manifest_role=_XCODE_VERSION_MANIFEST_ROLE,
        version_manifest_raw_sha256=_XCODE_VERSION_MANIFEST_RAW_SHA256,
        version_manifest_merkle_sha256=manifest.merkle_sha256,
        group_count=topology.group_count,
        support_member_count=topology.support_member_count,
        alias_count=topology.alias_count,
        policy_merkle_sha256=topology.policy_merkle_sha256,
        observation_merkle_sha256=topology.observation_merkle_sha256,
        merkle_sha256=_hardlink_disposition_merkle(provisional),
    )


def _require_unaliased_regular_tree_inode(
    value: _FilesystemStamp,
    inode_keys: set[tuple[int, int]],
    *,
    logical_role: str,
    relative_path: str,
    hardlink_plan: _AllowedHardlinkPlan | None,
) -> None:
    key = value.device, value.inode
    if value.links != 1:
        observation_count = 1 + int(key in inode_keys)
        path_sha256 = _sha256(
            {
                "domain": (
                    "rextio.full-c6-toolchain-support-"
                    "hardlink-diagnostic-path.v1"
                ),
                "relative_path": _validate_relative_path(relative_path),
            }
        )
        if (
            hardlink_plan is not None
            and hardlink_plan.consume(
                relative_path=relative_path,
                observed=value,
            )
        ):
            inode_keys.add(key)
            return
        raise ToolchainSupportLockError(
            "toolchain support regular tree member is a shared hardlink "
            f"(logical_role={_validate_role(logical_role)}, "
            f"relative_path_sha256={path_sha256}, "
            f"st_uid={value.uid}, "
            f"st_gid={value.gid}, "
            f"st_mode={value.mode}, "
            f"st_nlink={value.links}, "
            "in_root_inode_observation_count="
            f"{observation_count})"
        )
    _require_unaliased_inode(value, inode_keys, label="regular file")


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


def _validate_external_support_root_isolation(
    *,
    source: ToolchainSupportLocator,
    target: ToolchainSupportLocator,
) -> None:
    source_path = source._absolute_path
    target_path = target._absolute_path
    if (
        source_path == target_path
        or source_path in target_path.parents
        or target_path in source_path.parents
    ):
        raise ToolchainSupportLockError(
            "toolchain support external root locators overlap or alias"
        )
    inode_keys: set[tuple[int, int]] = set()
    for locator in (source, target):
        chain = _open_directory_chain(locator._absolute_path)
        try:
            observed = _stamp(os.fstat(chain[-1][0]))
            if not stat.S_ISDIR(observed.mode):
                raise ToolchainSupportLockError(
                    "toolchain support external root locator is not a directory"
                )
            key = observed.device, observed.inode
            if key in inode_keys:
                raise ToolchainSupportLockError(
                    "toolchain support external root locators overlap or alias"
                )
            inode_keys.add(key)
            _verify_directory_chain(chain)
        finally:
            _close_directory_chain(chain)


def _require_flag(name: str) -> int:
    value = getattr(os, name, None)
    if type(value) is not int or value == 0:
        raise ToolchainSupportLockError(
            "toolchain support secure descriptor operations are unavailable"
        )
    return value


def _stamp(value: os.stat_result) -> _FilesystemStamp:
    birthtime_ns = getattr(value, "st_birthtime_ns", None)
    if birthtime_ns is None:
        birthtime = getattr(value, "st_birthtime", None)
        if birthtime is not None:
            birthtime_ns = int(birthtime * 1_000_000_000)
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
    "ToolchainSupportHardlinkDispositionReceipt",
    "ToolchainSupportLocator",
    "ToolchainSupportLock",
    "ToolchainSupportLockError",
    "ToolchainSupportVerificationDriftError",
    "ToolchainSupportModeDispositionReceipt",
    "ToolchainSupportScope",
    "ToolchainSupportCasefoldDispositionReceipt",
    "ToolchainSupportSymlinkDispositionReceipt",
    "ToolchainSupportTreeReceipt",
    "capture_toolchain_support_file",
    "capture_toolchain_support_tree",
    "create_toolchain_support_locator",
    "generate_toolchain_support_lock",
    "load_toolchain_support_lock",
    "parse_toolchain_support_lock",
    "verify_toolchain_support_lock",
]
