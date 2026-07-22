"""Bounded fixed-root diagnostics for failed Full C6 CI lifecycle jobs.

This script is evidence collection only.  It never changes product admission
policy and deliberately avoids project, home, environment, and arbitrary
user-selected paths.
"""

from __future__ import annotations

import json
import os
import posixpath
import stat
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

MACOS_XCODE_APP = Path("/Applications/Xcode.app")
MACOS_SUPPORT_ROOTS = (
    (
        "xcode-sdk",
        MACOS_XCODE_APP / "Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk",
    ),
    (
        "xcode-clang-17",
        MACOS_XCODE_APP
        / ("Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/17"),
    ),
)
LINUX_RUNTIME_ROOT = Path("/usr/lib/x86_64-linux-gnu")

MAX_ROOT_SCAN_ENTRIES = 250_000
MAX_XCODE_APP_SCAN_ENTRIES = 1_000_000
MAX_REPORT_ENTRIES = 512
MAX_RELEVANT_INODES = 1_024
MAX_ALIAS_PATHS = 16
MAX_SCAN_DEPTH = 128
MAX_PATH_BYTES = 8_192
MAX_LINE_BYTES = 8_192
MAX_OUTPUT_BYTES = 256 * 1_024


class _ScanBoundExceeded(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class _CapturedEntry:
    relative_path: str
    stat_result: os.stat_result
    link_target: str | None


class _Reporter:
    def __init__(self) -> None:
        self._bytes_written = 0
        self._closed = False

    def emit(self, event: str, **fields: object) -> None:
        if self._closed:
            return
        line = json.dumps(
            {"event": event, **fields},
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        encoded = (line + "\n").encode("utf-8")
        if len(encoded) > MAX_LINE_BYTES:
            encoded = ('{"event":"diagnostic-record-omitted","reason":"line-bound"}\n').encode(
                "ascii"
            )
        reserve = 96
        if self._bytes_written + len(encoded) > MAX_OUTPUT_BYTES - reserve:
            marker = ('{"event":"diagnostic-output-truncated","reason":"byte-bound"}\n').encode(
                "ascii"
            )
            if self._bytes_written + len(marker) <= MAX_OUTPUT_BYTES:
                sys.stdout.buffer.write(marker)
                sys.stdout.buffer.flush()
                self._bytes_written += len(marker)
            self._closed = True
            return
        sys.stdout.buffer.write(encoded)
        sys.stdout.buffer.flush()
        self._bytes_written += len(encoded)


def _bounded_text(value: str) -> str:
    encoded = os.fsencode(value)
    if len(encoded) > MAX_PATH_BYTES or "\0" in value:
        raise _ScanBoundExceeded("path-bound")
    return value


def _is_within(path: Path, root: Path) -> bool:
    try:
        return os.path.commonpath((os.fspath(path), os.fspath(root))) == os.fspath(root)
    except ValueError:
        return False


def _stable_stamp(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
        int(getattr(value, "st_flags", 0)),
        int(getattr(value, "st_birthtime_ns", 0)),
    )


def _directory_open_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if nofollow == 0 or directory == 0:
        raise RuntimeError("descriptor-no-follow-unavailable")
    return os.O_RDONLY | nofollow | directory | getattr(os, "O_CLOEXEC", 0)


def _open_directory_chain(
    path: Path,
) -> list[tuple[int, tuple[int, ...], str | None]]:
    if not path.is_absolute() or path != Path(os.path.normpath(os.fspath(path))):
        raise RuntimeError("fixed-root-path")
    flags = _directory_open_flags()
    handles: list[tuple[int, tuple[int, ...], str | None]] = []
    try:
        root_fd = os.open(os.sep, flags)
        handles.append((root_fd, _stable_stamp(os.fstat(root_fd)), None))
        for component in path.parts[1:]:
            if component in {"", ".", ".."} or os.sep in component or "\0" in component:
                raise RuntimeError("fixed-root-component")
            parent_fd = handles[-1][0]
            linked = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
            if not stat.S_ISDIR(linked.st_mode):
                raise RuntimeError("fixed-root-kind")
            child_fd = os.open(component, flags, dir_fd=parent_fd)
            opened_stamp = _stable_stamp(os.fstat(child_fd))
            if opened_stamp != _stable_stamp(linked):
                os.close(child_fd)
                raise RuntimeError("fixed-root-changed")
            handles.append((child_fd, opened_stamp, component))
        return handles
    except BaseException:
        for descriptor, _stamp, _component in reversed(handles):
            os.close(descriptor)
        raise


def _verify_directory_chain(
    handles: list[tuple[int, tuple[int, ...], str | None]],
) -> None:
    for index, (descriptor, expected, component) in enumerate(handles):
        if _stable_stamp(os.fstat(descriptor)) != expected:
            raise RuntimeError("fixed-root-changed")
        if index == 0:
            continue
        assert component is not None
        linked = os.stat(
            component,
            dir_fd=handles[index - 1][0],
            follow_symlinks=False,
        )
        if _stable_stamp(linked) != expected:
            raise RuntimeError("fixed-root-changed")


def _walk_nofollow(root: Path, *, entry_limit: int) -> Iterator[_CapturedEntry]:
    handles = _open_directory_chain(root)
    observed_count = 0

    def walk(directory_fd: int, *, relative: PurePosixPath) -> Iterator[_CapturedEntry]:
        nonlocal observed_count
        directory_before = _stable_stamp(os.fstat(directory_fd))
        names = os.listdir(directory_fd)
        for name in names:
            _bounded_text(name)
            if name in {"", ".", ".."} or os.sep in name:
                raise RuntimeError("entry-name")
        ordered = sorted(names, key=os.fsencode)
        for name in ordered:
            observed_count += 1
            if observed_count > entry_limit:
                raise _ScanBoundExceeded("entry-bound")
            child_relative = relative / name
            logical = child_relative.as_posix()
            if len(child_relative.parts) > MAX_SCAN_DEPTH:
                raise _ScanBoundExceeded("depth-bound")
            _bounded_text(logical)
            linked = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            linked_stamp = _stable_stamp(linked)
            link_target: str | None = None
            if stat.S_ISLNK(linked.st_mode):
                link_target = _bounded_text(os.readlink(name, dir_fd=directory_fd))
            if stat.S_ISDIR(linked.st_mode):
                child_fd = os.open(
                    name,
                    _directory_open_flags(),
                    dir_fd=directory_fd,
                )
                try:
                    if _stable_stamp(os.fstat(child_fd)) != linked_stamp:
                        raise RuntimeError("directory-entry-changed")
                    yield _CapturedEntry(logical, linked, None)
                    if (
                        _stable_stamp(os.stat(name, dir_fd=directory_fd, follow_symlinks=False))
                        != linked_stamp
                    ):
                        raise RuntimeError("directory-entry-changed")
                    yield from walk(child_fd, relative=child_relative)
                    if (
                        _stable_stamp(os.fstat(child_fd)) != linked_stamp
                        or _stable_stamp(
                            os.stat(
                                name,
                                dir_fd=directory_fd,
                                follow_symlinks=False,
                            )
                        )
                        != linked_stamp
                    ):
                        raise RuntimeError("directory-entry-changed")
                finally:
                    os.close(child_fd)
            else:
                yield _CapturedEntry(logical, linked, link_target)
                if (
                    _stable_stamp(os.stat(name, dir_fd=directory_fd, follow_symlinks=False))
                    != linked_stamp
                ):
                    raise RuntimeError("entry-changed")
        after_names = os.listdir(directory_fd)
        if sorted(after_names, key=os.fsencode) != ordered:
            raise RuntimeError("directory-inventory-changed")
        if _stable_stamp(os.fstat(directory_fd)) != directory_before:
            raise RuntimeError("directory-changed")

    try:
        yield from walk(handles[-1][0], relative=PurePosixPath())
        _verify_directory_chain(handles)
    finally:
        for descriptor, _stamp, _component in reversed(handles):
            os.close(descriptor)


def _diagnose_macos(
    reporter: _Reporter,
    *,
    app: Path = MACOS_XCODE_APP,
    support_roots: tuple[tuple[str, Path], ...] = MACOS_SUPPORT_ROOTS,
) -> None:
    if not app.is_absolute():
        raise RuntimeError("fixed-app-path")
    for _label, root in support_roots:
        try:
            root.relative_to(app)
        except ValueError:
            raise RuntimeError("fixed-support-root-scope") from None

    records: list[tuple[str, str, str, tuple[int, int], int]] = []
    relevant_inodes: dict[tuple[int, int], int] = {}
    shared_member_count = 0
    topology_truncated = False
    for label, root in support_roots:
        app_prefix = root.relative_to(app).as_posix()
        for entry in _walk_nofollow(root, entry_limit=MAX_ROOT_SCAN_ENTRIES):
            observed = entry.stat_result
            if not stat.S_ISREG(observed.st_mode) or observed.st_nlink <= 1:
                continue
            shared_member_count += 1
            inode = (observed.st_dev, observed.st_ino)
            expected_links = relevant_inodes.get(inode)
            if expected_links is None:
                if len(relevant_inodes) >= MAX_RELEVANT_INODES:
                    topology_truncated = True
                    continue
                relevant_inodes[inode] = observed.st_nlink
            elif expected_links != observed.st_nlink:
                raise RuntimeError("shared-inode-link-count-changed")
            if len(records) >= MAX_REPORT_ENTRIES:
                continue
            relative = entry.relative_path
            app_relative = _bounded_text(posixpath.join(app_prefix, entry.relative_path))
            records.append((label, relative, app_relative, inode, observed.st_nlink))

    alias_counts = {inode: 0 for inode in relevant_inodes}
    alias_paths: dict[tuple[int, int], list[str]] = {inode: [] for inode in relevant_inodes}
    app_scan_entries = 0
    for entry in _walk_nofollow(app, entry_limit=MAX_XCODE_APP_SCAN_ENTRIES):
        app_scan_entries += 1
        observed = entry.stat_result
        if not stat.S_ISREG(observed.st_mode):
            continue
        inode = (observed.st_dev, observed.st_ino)
        if inode not in relevant_inodes:
            continue
        alias_counts[inode] += 1
        paths = alias_paths[inode]
        if len(paths) < MAX_ALIAS_PATHS + 1:
            paths.append(entry.relative_path)

    for label, relative, app_relative, inode, link_count in records:
        aliases = sorted(path for path in alias_paths[inode] if path != app_relative)[
            :MAX_ALIAS_PATHS
        ]
        alias_count = max(0, alias_counts[inode] - 1)
        reporter.emit(
            "macos-shared-regular-file",
            root=label,
            relative_path=relative,
            nlink=link_count,
            alias_count=alias_count,
            alias_paths=aliases,
            alias_paths_truncated=alias_count > len(aliases),
        )
    complete_alias_group_count = sum(
        alias_counts[inode] == link_count for inode, link_count in relevant_inodes.items()
    )
    alias_count_mismatch_group_count = len(relevant_inodes) - complete_alias_group_count
    reporter.emit(
        "macos-diagnostic-summary",
        shared_member_count=shared_member_count,
        tracked_group_count=len(relevant_inodes),
        complete_alias_group_count=complete_alias_group_count,
        alias_count_mismatch_group_count=alias_count_mismatch_group_count,
        topology_truncated=topology_truncated,
        reported_count=len(records),
        reports_truncated=shared_member_count > len(records),
        xcode_app_scan_entries=app_scan_entries,
    )


def _diagnose_linux(
    reporter: _Reporter,
    *,
    root: Path = LINUX_RUNTIME_ROOT,
) -> None:
    offender_count = 0
    reported_count = 0
    scan_entries = 0
    for entry in _walk_nofollow(root, entry_limit=MAX_ROOT_SCAN_ENTRIES):
        scan_entries += 1
        observed = entry.stat_result
        if not stat.S_ISLNK(observed.st_mode):
            continue
        if entry.link_target is None:
            raise RuntimeError("captured-symlink-target-missing")
        raw_target = entry.link_target
        link_path = root.joinpath(*PurePosixPath(entry.relative_path).parts)
        if os.path.isabs(raw_target):
            lexical_target = Path(os.path.normpath(raw_target))
        else:
            lexical_target = Path(
                os.path.normpath(os.path.join(os.fspath(link_path.parent), raw_target))
            )
        resolved_target = Path(os.path.realpath(lexical_target))
        lexical_leaves_root = not _is_within(lexical_target, root)
        resolved_leaves_root = not _is_within(resolved_target, root)
        if not lexical_leaves_root and not resolved_leaves_root:
            continue
        offender_count += 1
        if reported_count >= MAX_REPORT_ENTRIES:
            continue
        reporter.emit(
            "linux-escaping-symlink",
            relative_path=entry.relative_path,
            raw_target=raw_target,
            resolved_target=_bounded_text(os.fspath(resolved_target)),
            lstat_mode=oct(observed.st_mode),
            lexical_leaves_root=lexical_leaves_root,
            resolved_leaves_root=resolved_leaves_root,
        )
        reported_count += 1
    reporter.emit(
        "linux-diagnostic-summary",
        scan_entries=scan_entries,
        offender_count=offender_count,
        reported_count=reported_count,
        reports_truncated=offender_count > reported_count,
    )


def main() -> int:
    reporter = _Reporter()
    reporter.emit(
        "full-c6-failure-diagnostic-start",
        platform=("macos" if sys.platform == "darwin" else "linux"),
        root_scan_entry_bound=MAX_ROOT_SCAN_ENTRIES,
        relevant_inode_bound=MAX_RELEVANT_INODES,
        report_entry_bound=MAX_REPORT_ENTRIES,
        output_byte_bound=MAX_OUTPUT_BYTES,
    )
    try:
        if sys.platform == "darwin":
            _diagnose_macos(reporter)
        elif sys.platform.startswith("linux"):
            _diagnose_linux(reporter)
        else:
            reporter.emit("diagnostic-skipped", reason="unsupported-platform")
    except Exception as error:  # Diagnostic failure must not replace test failure.
        reporter.emit(
            "diagnostic-failed-closed",
            error_type=type(error).__name__,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
