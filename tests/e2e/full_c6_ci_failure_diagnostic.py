"""Bounded fixed-root diagnostics for failed Full C6 CI lifecycle jobs.

This script is evidence collection only.  It never changes product admission
policy and deliberately avoids project, home, environment, and arbitrary
user-selected paths.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from collections.abc import Iterator
from pathlib import Path

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
MAX_ALIAS_PATHS = 16
MAX_PATH_BYTES = 8_192
MAX_LINE_BYTES = 8_192
MAX_OUTPUT_BYTES = 256 * 1_024


class _ScanBoundExceeded(RuntimeError):
    pass


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


def _require_exact_directory(path: Path, *, boundary: Path) -> None:
    observed = os.lstat(path)
    if stat.S_ISLNK(observed.st_mode) or not stat.S_ISDIR(observed.st_mode):
        raise RuntimeError("fixed-root-kind")
    if Path(os.path.realpath(path)) != path or not _is_within(path, boundary):
        raise RuntimeError("fixed-root-resolution")


def _walk_nofollow(root: Path, *, entry_limit: int) -> Iterator[os.DirEntry[str]]:
    pending = [root]
    observed = 0
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as stream:
            for entry in stream:
                observed += 1
                if observed > entry_limit:
                    raise _ScanBoundExceeded("entry-bound")
                yield entry
                if entry.is_dir(follow_symlinks=False):
                    pending.append(Path(entry.path))


def _relative_path(path: str | Path, root: Path) -> str:
    relative = os.path.relpath(os.fspath(path), os.fspath(root))
    if relative == ".." or relative.startswith(f"..{os.sep}"):
        raise RuntimeError("relative-path-escape")
    return _bounded_text(relative)


def _diagnose_macos(
    reporter: _Reporter,
    *,
    app: Path = MACOS_XCODE_APP,
    support_roots: tuple[tuple[str, Path], ...] = MACOS_SUPPORT_ROOTS,
) -> None:
    _require_exact_directory(app, boundary=app)
    for _label, root in support_roots:
        _require_exact_directory(root, boundary=app)

    records: list[tuple[str, str, str, tuple[int, int], int]] = []
    relevant_inodes: set[tuple[int, int]] = set()
    shared_member_count = 0
    for label, root in support_roots:
        for entry in _walk_nofollow(root, entry_limit=MAX_ROOT_SCAN_ENTRIES):
            observed = entry.stat(follow_symlinks=False)
            if not stat.S_ISREG(observed.st_mode) or observed.st_nlink <= 1:
                continue
            shared_member_count += 1
            if len(records) >= MAX_REPORT_ENTRIES:
                continue
            relative = _relative_path(entry.path, root)
            app_relative = _relative_path(entry.path, app)
            inode = (observed.st_dev, observed.st_ino)
            records.append((label, relative, app_relative, inode, observed.st_nlink))
            relevant_inodes.add(inode)

    alias_counts = {inode: 0 for inode in relevant_inodes}
    alias_paths: dict[tuple[int, int], list[str]] = {inode: [] for inode in relevant_inodes}
    app_scan_entries = 0
    for entry in _walk_nofollow(app, entry_limit=MAX_XCODE_APP_SCAN_ENTRIES):
        app_scan_entries += 1
        observed = entry.stat(follow_symlinks=False)
        if not stat.S_ISREG(observed.st_mode):
            continue
        inode = (observed.st_dev, observed.st_ino)
        if inode not in relevant_inodes:
            continue
        alias_counts[inode] += 1
        paths = alias_paths[inode]
        if len(paths) < MAX_ALIAS_PATHS + 1:
            paths.append(_relative_path(entry.path, app))

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
    reporter.emit(
        "macos-diagnostic-summary",
        shared_member_count=shared_member_count,
        reported_count=len(records),
        reports_truncated=shared_member_count > len(records),
        xcode_app_scan_entries=app_scan_entries,
    )


def _diagnose_linux(
    reporter: _Reporter,
    *,
    root: Path = LINUX_RUNTIME_ROOT,
) -> None:
    _require_exact_directory(root, boundary=root)
    offender_count = 0
    reported_count = 0
    scan_entries = 0
    for entry in _walk_nofollow(root, entry_limit=MAX_ROOT_SCAN_ENTRIES):
        scan_entries += 1
        observed = entry.stat(follow_symlinks=False)
        if not stat.S_ISLNK(observed.st_mode):
            continue
        raw_target = _bounded_text(os.readlink(entry.path))
        if os.path.isabs(raw_target):
            lexical_target = Path(os.path.normpath(raw_target))
        else:
            lexical_target = Path(
                os.path.normpath(os.path.join(os.path.dirname(entry.path), raw_target))
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
            relative_path=_relative_path(entry.path, root),
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
