"""Strict bounded reads for project-owner policy lock files.

The C6 owner-policy receipts are optional observations, but a present receipt
must never be built from a path that can be redirected while it is read.  This
module centralizes the descriptor-pinned, no-follow traversal first introduced
for C6.11 so later scoped policies use the same filesystem and JSON boundary.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePath
from typing import Any

from rextio.artifacts.evidence import sha256_hex

MAX_OWNER_POLICY_JSON_DEPTH = 32


@dataclass(frozen=True, slots=True)
class _FilesystemStamp:
    device: int
    inode: int
    size: int
    ctime_ns: int
    mtime_ns: int
    mode: int
    links: int


@dataclass(frozen=True, slots=True)
class StrictOwnerPolicyLock:
    """Exact bytes plus the strictly decoded JSON value for one lock."""

    data: bytes
    document: object

    @property
    def sha256(self) -> str:
        """Return the digest of the exact bytes read from the lock file."""
        return sha256_hex(self.data)


def read_strict_owner_policy_lock(
    *,
    project_root: Path,
    filename: str,
    max_bytes: int,
) -> StrictOwnerPolicyLock:
    """Read one root lock through pinned ancestors and strict bounded JSON."""
    if (
        type(filename) is not str
        or not filename
        or PurePath(filename).name != filename
        or "/" in filename
        or "\\" in filename
        or "\0" in filename
    ):
        raise ValueError("owner policy lock filename is invalid")
    if type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError("owner policy lock byte bound is invalid")

    root = Path(os.path.abspath(project_root))
    data = _read_lock_bytes(root=root, filename=filename, max_bytes=max_bytes)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("owner policy lock is not UTF-8") from exc
    return StrictOwnerPolicyLock(data=data, document=_load_strict_json(text))


def _load_strict_json(text: str) -> object:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("owner policy lock contains a duplicate key")
            result[key] = value
        return result

    def parse_constant(_value: str) -> object:
        raise ValueError("owner policy lock contains a non-finite value")

    try:
        document = json.loads(
            text,
            object_pairs_hook=object_pairs,
            parse_constant=parse_constant,
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("owner policy lock JSON is invalid") from exc
    _assert_json_depth(document, depth=0)
    return document


def _assert_json_depth(value: object, *, depth: int) -> None:
    if depth > MAX_OWNER_POLICY_JSON_DEPTH:
        raise ValueError("owner policy lock nesting is too deep")
    if isinstance(value, dict):
        for child in value.values():
            _assert_json_depth(child, depth=depth + 1)
    elif isinstance(value, list):
        for child in value:
            _assert_json_depth(child, depth=depth + 1)


def _stamp(value: os.stat_result) -> _FilesystemStamp:
    return _FilesystemStamp(
        device=value.st_dev,
        inode=value.st_ino,
        size=value.st_size,
        ctime_ns=value.st_ctime_ns,
        mtime_ns=value.st_mtime_ns,
        mode=value.st_mode,
        links=value.st_nlink,
    )


def _directory_open_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None:
        raise OSError("secure owner policy lock traversal is unavailable")
    return os.O_RDONLY | nofollow | directory | getattr(os, "O_CLOEXEC", 0)


def _open_absolute_directory_chain(
    root: Path,
) -> list[tuple[int, int | None, str | None, _FilesystemStamp]]:
    """Pin every project-root ancestor through no-follow directory handles."""
    absolute = Path(os.path.abspath(root))
    if not absolute.is_absolute() or not absolute.anchor:
        raise OSError("owner policy root is not absolute")
    handles: list[tuple[int, int | None, str | None, _FilesystemStamp]] = []
    try:
        current_fd = os.open(absolute.anchor, _directory_open_flags())
        anchor_stamp = _stamp(os.fstat(current_fd))
        handles.append((current_fd, None, None, anchor_stamp))
        if not stat.S_ISDIR(anchor_stamp.mode):
            raise OSError("owner policy root anchor is unsafe")
        for part in absolute.parts[1:]:
            if not part or part in {".", ".."} or "/" in part or "\\" in part:
                raise OSError("owner policy root component is unsafe")
            next_fd = os.open(part, _directory_open_flags(), dir_fd=current_fd)
            next_stamp = _stamp(os.fstat(next_fd))
            handles.append((next_fd, current_fd, part, next_stamp))
            linked_stamp = _stamp(os.stat(part, dir_fd=current_fd, follow_symlinks=False))
            if next_stamp != linked_stamp or not stat.S_ISDIR(next_stamp.mode):
                raise OSError("owner policy root component changed")
            current_fd = next_fd
        return handles
    except Exception:
        for handle, _parent, _name, _expected in reversed(handles):
            try:
                os.close(handle)
            except OSError:
                pass
        raise


def _verify_directory_chain(
    handles: list[tuple[int, int | None, str | None, _FilesystemStamp]],
) -> None:
    for handle, parent, name, expected in handles:
        actual = _stamp(os.fstat(handle))
        if actual != expected or not stat.S_ISDIR(actual.mode):
            raise OSError("owner policy root directory changed")
        if parent is None or name is None:
            continue
        linked = _stamp(os.stat(name, dir_fd=parent, follow_symlinks=False))
        if linked != expected or not stat.S_ISDIR(linked.mode):
            raise OSError("owner policy root path changed")


def _read_lock_bytes(*, root: Path, filename: str, max_bytes: int) -> bytes:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise OSError("secure owner policy lock traversal is unavailable")
    file_flags = os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NONBLOCK"):
        file_flags |= os.O_NONBLOCK

    directory_chain: list[tuple[int, int | None, str | None, _FilesystemStamp]] = []
    file_fd = -1
    try:
        directory_chain = _open_absolute_directory_chain(root)
        root_fd = directory_chain[-1][0]
        file_fd = os.open(filename, file_flags, dir_fd=root_fd)
        file_stamp = _stamp(os.fstat(file_fd))
        linked_file = _stamp(os.stat(filename, dir_fd=root_fd, follow_symlinks=False))
        if (
            file_stamp != linked_file
            or not stat.S_ISREG(file_stamp.mode)
            or file_stamp.links != 1
            or file_stamp.size <= 0
            or file_stamp.size > max_bytes
        ):
            raise OSError("owner policy lock identity is unsafe")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(file_fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) != file_stamp.size or len(data) > max_bytes:
            raise OSError("owner policy lock size changed")
        if _stamp(os.fstat(file_fd)) != file_stamp:
            raise OSError("owner policy lock changed during read")
        if _stamp(os.stat(filename, dir_fd=root_fd, follow_symlinks=False)) != file_stamp:
            raise OSError("owner policy lock link changed during read")
        _verify_directory_chain(directory_chain)
        return data
    finally:
        if file_fd >= 0:
            try:
                os.close(file_fd)
            except OSError:
                pass
        for handle, _parent, _name, _expected in reversed(directory_chain):
            try:
                os.close(handle)
            except OSError:
                pass


__all__ = ["StrictOwnerPolicyLock", "read_strict_owner_policy_lock"]
