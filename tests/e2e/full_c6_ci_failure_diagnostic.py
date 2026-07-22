"""Bounded fixed-root diagnostics for failed Full C6 CI lifecycle jobs.

This script is evidence collection only.  It never changes product admission
policy and deliberately avoids project, home, environment, and arbitrary
user-selected paths.
"""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
import stat
import subprocess
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field
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
MAX_RELEVANT_INODES = 16_384
MAX_ALIAS_PATHS = 16
MAX_TOPOLOGY_MEMBERS_PER_GROUP = 128
MAX_TOPOLOGY_PATH_HASHES = 250_000
MAX_SCAN_DEPTH = 128
MAX_DIRECTORY_ENTRIES = 65_536
MAX_PATH_BYTES = 8_192
MAX_LINE_BYTES = 8_192
MAX_OUTPUT_BYTES = 256 * 1_024
MAX_MACOS_SANDBOX_LOG_BYTES = 512 * 1_024
MAX_MACOS_SANDBOX_LOG_RECORDS = 4_096
MAX_MACOS_SANDBOX_MESSAGE_BYTES = 8_192
MACOS_SANDBOX_LOG_TIMEOUT_SECONDS = 20.0

MACOS_SANDBOX_OPERATION_FAMILIES = (
    "file-read",
    "file-write",
    "file-map-exec",
    "process-exec",
    "sysctl-read",
    "mach-lookup",
    "ipc",
    "network",
    "other",
)
MACOS_SANDBOX_ROOT_FAMILIES = (
    "/dev",
    "private-var",
    "private-etc",
    "Library",
    "Preboot",
    "host-temp",
    "Xcode",
    "other-absolute",
    "non-path",
)
_MACOS_SANDBOX_PROCESSES = (
    "cargo",
    "rustc",
    "clang",
    "ld",
    "cc",
    "ar",
    "ranlib",
    "build-script-build",
)
_MACOS_SANDBOX_LOG_PREDICATE = (
    'subsystem == "com.apple.sandbox.reporting" AND '
    'eventMessage BEGINSWITH "Sandbox:"'
)
_MACOS_SANDBOX_DENIAL = re.compile(
    r"^Sandbox: (?P<process>"
    + "|".join(re.escape(item) for item in _MACOS_SANDBOX_PROCESSES)
    + r")\([0-9]{1,20}\) deny\([0-9]{1,20}\) "
    + r"(?P<operation>[a-z][a-z0-9-]{0,63}) "
    + r"(?P<resource>[^\r\n]+)$"
)

XCODE_SUPPORT_PATH_POLICY_DOMAIN = "rextio.full-c6-xcode-hardlink-topology-support-path.v1"
XCODE_ALIAS_PATH_POLICY_DOMAIN = "rextio.full-c6-xcode-hardlink-topology-alias-path.v1"
XCODE_POLICY_GROUP_DOMAIN = "rextio.full-c6-xcode-hardlink-topology-policy-group.v1"
XCODE_POLICY_DOMAIN = "rextio.full-c6-xcode-hardlink-topology-policy.v1"


class _ScanBoundExceeded(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class _CapturedEntry:
    relative_path: str
    stat_result: os.stat_result
    link_target: str | None


@dataclass(slots=True)
class _SharedInodeGroup:
    link_count: int
    support_member_count: int = 0
    support_path_sha256s: set[str] = field(default_factory=set)


@dataclass(slots=True)
class _RootTopology:
    groups: dict[tuple[int, int], _SharedInodeGroup] = field(default_factory=dict)
    support_member_count: int = 0
    topology_truncated: bool = False


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


def _policy_sha256(domain: str, fields: dict[str, object]) -> str:
    payload = {"domain": domain, **fields}
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _path_policy_sha256(*, domain: str, field_name: str, path: str) -> str:
    return _policy_sha256(domain, {field_name: _bounded_text(path)})


def _empty_macos_sandbox_log_summary(*, status: str) -> dict[str, object]:
    return {
        "status": status,
        "accepted_count": 0,
        "operation_counts": {
            name: 0 for name in MACOS_SANDBOX_OPERATION_FAMILIES
        },
        "root_counts": {name: 0 for name in MACOS_SANDBOX_ROOT_FAMILIES},
    }


def _macos_sandbox_operation_family(operation: str) -> str:
    if operation.startswith("file-read"):
        return "file-read"
    if operation.startswith("file-write"):
        return "file-write"
    if operation == "file-map-executable":
        return "file-map-exec"
    if operation == "process-exec":
        return "process-exec"
    if operation == "sysctl-read":
        return "sysctl-read"
    if operation == "mach-lookup":
        return "mach-lookup"
    if operation.startswith("ipc-"):
        return "ipc"
    if operation == "network" or operation.startswith("network-"):
        return "network"
    return "other"


def _resource_is_within(resource: str, root: str) -> bool:
    return resource == root or resource.startswith(root + "/")


def _macos_sandbox_root_family(resource: str) -> str:
    for root in (
        "/private/var/folders",
        "/var/folders",
        "/private/tmp",
        "/tmp",
        "/Users/runner/work/_temp",
    ):
        if _resource_is_within(resource, root):
            return "host-temp"
    for root, family in (
        ("/dev", "/dev"),
        ("/private/var", "private-var"),
        ("/var", "private-var"),
        ("/private/etc", "private-etc"),
        ("/etc", "private-etc"),
        ("/Library", "Library"),
        ("/System/Volumes/Preboot", "Preboot"),
        ("/Applications/Xcode.app", "Xcode"),
    ):
        if _resource_is_within(resource, root):
            return family
    return "other-absolute" if resource.startswith("/") else "non-path"


def _parse_macos_sandbox_log_json(payload: bytes) -> dict[str, object]:
    if len(payload) > MAX_MACOS_SANDBOX_LOG_BYTES:
        raise _ScanBoundExceeded("macos-sandbox-log-byte-bound")
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("macos-sandbox-log-json") from exc
    if type(document) is not list or len(document) > MAX_MACOS_SANDBOX_LOG_RECORDS:
        raise RuntimeError("macos-sandbox-log-document")
    summary = _empty_macos_sandbox_log_summary(status="ok")
    operation_counts = summary["operation_counts"]
    root_counts = summary["root_counts"]
    assert isinstance(operation_counts, dict)
    assert isinstance(root_counts, dict)
    accepted_count = 0
    for record in document:
        if type(record) is not dict:
            raise RuntimeError("macos-sandbox-log-record")
        subsystem = record.get("subsystem")
        message = record.get("eventMessage")
        if subsystem != "com.apple.sandbox.reporting" or type(message) is not str:
            continue
        if (
            len(message.encode("utf-8")) > MAX_MACOS_SANDBOX_MESSAGE_BYTES
            or any(ord(character) < 32 for character in message)
        ):
            raise RuntimeError("macos-sandbox-log-message")
        matched = _MACOS_SANDBOX_DENIAL.fullmatch(message)
        if matched is None:
            continue
        operation = _macos_sandbox_operation_family(matched.group("operation"))
        root = _macos_sandbox_root_family(matched.group("resource"))
        operation_counts[operation] += 1
        root_counts[root] += 1
        accepted_count += 1
    summary["accepted_count"] = accepted_count
    return summary


def _query_macos_sandbox_log() -> dict[str, object]:
    try:
        completed = subprocess.run(
            [
                "/usr/bin/log",
                "show",
                "--last",
                "15m",
                "--style",
                "json",
                "--predicate",
                _MACOS_SANDBOX_LOG_PREDICATE,
            ],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=MACOS_SANDBOX_LOG_TIMEOUT_SECONDS,
            env={"LANG": "C", "LC_ALL": "C"},
        )
        if completed.returncode != 0 or type(completed.stdout) is not bytes:
            raise RuntimeError("macos-sandbox-log-command")
        return _parse_macos_sandbox_log_json(completed.stdout)
    except (
        OSError,
        RuntimeError,
        subprocess.SubprocessError,
        _ScanBoundExceeded,
    ):
        return _empty_macos_sandbox_log_summary(status="failed-closed")


def _emit_macos_sandbox_log_summary(reporter: _Reporter) -> None:
    try:
        summary = _query_macos_sandbox_log()
    except Exception:  # CI diagnostics must not hide the original failure.
        summary = _empty_macos_sandbox_log_summary(status="failed-closed")
    reporter.emit("macos-sandbox-denial-summary", **summary)


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
            try:
                opened_stamp = _stable_stamp(os.fstat(child_fd))
            except BaseException:
                os.close(child_fd)
                raise
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


def _bounded_directory_names(descriptor: int, *, maximum: int) -> list[str]:
    names: list[str] = []
    with os.scandir(descriptor) as entries:
        for entry in entries:
            names.append(entry.name)
            if len(names) > maximum:
                raise _ScanBoundExceeded("directory-entry-bound")
    return names


def _walk_nofollow(root: Path, *, entry_limit: int) -> Iterator[_CapturedEntry]:
    handles = _open_directory_chain(root)
    observed_count = 0

    def walk(directory_fd: int, *, relative: PurePosixPath) -> Iterator[_CapturedEntry]:
        nonlocal observed_count
        directory_before = _stable_stamp(os.fstat(directory_fd))
        remaining = entry_limit - observed_count
        if remaining < 0:
            raise _ScanBoundExceeded("entry-bound")
        names = _bounded_directory_names(
            directory_fd,
            maximum=min(MAX_DIRECTORY_ENTRIES, remaining),
        )
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
        after_names = _bounded_directory_names(
            directory_fd,
            maximum=min(MAX_DIRECTORY_ENTRIES, len(ordered) + 1),
        )
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


def _root_topology_evidence(
    *,
    label: str,
    topology: _RootTopology,
    alias_counts: dict[tuple[int, int], int],
    alias_path_sha256s: dict[tuple[int, int], set[str]],
) -> dict[str, object]:
    complete_alias_group_count = 0
    alias_count_mismatch_group_count = 0
    policy_group_sha256s: list[str] = []
    alias_count = 0
    max_support_members_per_group = 0
    max_alias_members_per_group = 0
    policy_complete = not topology.topology_truncated
    for inode, group in topology.groups.items():
        observed_alias_count = alias_counts[inode]
        observed_alias_hashes = alias_path_sha256s[inode]
        alias_count += observed_alias_count
        max_support_members_per_group = max(
            max_support_members_per_group,
            group.support_member_count,
        )
        max_alias_members_per_group = max(
            max_alias_members_per_group,
            observed_alias_count,
        )
        if observed_alias_count == group.link_count:
            complete_alias_group_count += 1
        else:
            alias_count_mismatch_group_count += 1
            policy_complete = False
        if (
            len(group.support_path_sha256s) != group.support_member_count
            or len(observed_alias_hashes) != observed_alias_count
        ):
            policy_complete = False
        policy_group_sha256s.append(
            _policy_sha256(
                XCODE_POLICY_GROUP_DOMAIN,
                {
                    "support_relative_path_sha256s": sorted(group.support_path_sha256s),
                    "link_count": group.link_count,
                    "alias_count": observed_alias_count,
                    "alias_path_sha256s": sorted(observed_alias_hashes),
                },
            )
        )
    policy_merkle_sha256 = None
    if policy_complete:
        policy_merkle_sha256 = _policy_sha256(
            XCODE_POLICY_DOMAIN,
            {"policy_group_sha256s": sorted(policy_group_sha256s)},
        )
    return {
        "root": label,
        "group_count": len(topology.groups),
        "support_member_count": topology.support_member_count,
        "tracked_support_member_count": sum(
            group.support_member_count for group in topology.groups.values()
        ),
        "alias_count": alias_count,
        "complete_alias_group_count": complete_alias_group_count,
        "alias_count_mismatch_group_count": alias_count_mismatch_group_count,
        "max_support_members_per_group": max_support_members_per_group,
        "max_alias_members_per_group": max_alias_members_per_group,
        "max_members_per_group": max(
            max_support_members_per_group,
            max_alias_members_per_group,
        ),
        "policy_merkle_domain": XCODE_POLICY_DOMAIN,
        "policy_merkle_sha256": policy_merkle_sha256,
        "policy_complete": policy_complete,
        "topology_truncated": topology.topology_truncated,
    }


def _diagnose_macos(
    reporter: _Reporter,
    *,
    app: Path = MACOS_XCODE_APP,
    support_roots: tuple[tuple[str, Path], ...] = MACOS_SUPPORT_ROOTS,
) -> None:
    if not app.is_absolute():
        raise RuntimeError("fixed-app-path")
    labels = tuple(label for label, _root in support_roots)
    if len(set(labels)) != len(labels):
        raise RuntimeError("fixed-support-root-label")
    root_topologies = {label: _RootTopology() for label in labels}
    for _label, root in support_roots:
        try:
            root.relative_to(app)
        except ValueError:
            raise RuntimeError("fixed-support-root-scope") from None

    records: list[tuple[str, str, str, tuple[int, int], int]] = []
    relevant_inodes: dict[tuple[int, int], int] = {}
    inode_roots: dict[tuple[int, int], set[str]] = {}
    topology_path_hash_count = 0
    for label, root in support_roots:
        topology = root_topologies[label]
        app_prefix = root.relative_to(app).as_posix()
        for entry in _walk_nofollow(root, entry_limit=MAX_ROOT_SCAN_ENTRIES):
            observed = entry.stat_result
            if not stat.S_ISREG(observed.st_mode) or observed.st_nlink <= 1:
                continue
            topology.support_member_count += 1
            inode = (observed.st_dev, observed.st_ino)
            expected_links = relevant_inodes.get(inode)
            if expected_links is None:
                if len(relevant_inodes) >= MAX_RELEVANT_INODES:
                    topology.topology_truncated = True
                    continue
                relevant_inodes[inode] = observed.st_nlink
                inode_roots[inode] = set()
            elif expected_links != observed.st_nlink:
                raise RuntimeError("shared-inode-link-count-changed")
            inode_roots[inode].add(label)
            group = topology.groups.get(inode)
            if group is None:
                group = _SharedInodeGroup(link_count=observed.st_nlink)
                topology.groups[inode] = group
            elif group.link_count != observed.st_nlink:
                raise RuntimeError("shared-root-inode-link-count-changed")
            group.support_member_count += 1
            if (
                group.support_member_count > MAX_TOPOLOGY_MEMBERS_PER_GROUP
                or topology_path_hash_count >= MAX_TOPOLOGY_PATH_HASHES
            ):
                topology.topology_truncated = True
            else:
                support_path_sha256 = _path_policy_sha256(
                    domain=XCODE_SUPPORT_PATH_POLICY_DOMAIN,
                    field_name="support_relative_path",
                    path=entry.relative_path,
                )
                if support_path_sha256 in group.support_path_sha256s:
                    raise RuntimeError("support-path-hash-collision")
                group.support_path_sha256s.add(support_path_sha256)
                topology_path_hash_count += 1
            if len(records) >= MAX_REPORT_ENTRIES:
                continue
            relative = entry.relative_path
            app_relative = _bounded_text(posixpath.join(app_prefix, entry.relative_path))
            records.append((label, relative, app_relative, inode, observed.st_nlink))

    alias_counts = {inode: 0 for inode in relevant_inodes}
    alias_paths: dict[tuple[int, int], list[str]] = {inode: [] for inode in relevant_inodes}
    alias_path_sha256s: dict[tuple[int, int], set[str]] = {
        inode: set() for inode in relevant_inodes
    }
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
        if (
            alias_counts[inode] > MAX_TOPOLOGY_MEMBERS_PER_GROUP
            or topology_path_hash_count >= MAX_TOPOLOGY_PATH_HASHES
        ):
            for label in inode_roots[inode]:
                root_topologies[label].topology_truncated = True
        else:
            alias_path_sha256 = _path_policy_sha256(
                domain=XCODE_ALIAS_PATH_POLICY_DOMAIN,
                field_name="app_relative_path",
                path=entry.relative_path,
            )
            if alias_path_sha256 in alias_path_sha256s[inode]:
                raise RuntimeError("alias-path-hash-collision")
            alias_path_sha256s[inode].add(alias_path_sha256)
            topology_path_hash_count += 1
        paths = alias_paths[inode]
        if len(paths) < MAX_ALIAS_PATHS + 1:
            paths.append(entry.relative_path)

    complete_alias_group_count = sum(
        alias_counts[inode] == link_count for inode, link_count in relevant_inodes.items()
    )
    alias_count_mismatch_group_count = len(relevant_inodes) - complete_alias_group_count
    shared_member_count = sum(
        topology.support_member_count for topology in root_topologies.values()
    )
    topology_truncated = any(topology.topology_truncated for topology in root_topologies.values())
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
    for label in labels:
        reporter.emit(
            "macos-support-hardlink-topology",
            **_root_topology_evidence(
                label=label,
                topology=root_topologies[label],
                alias_counts=alias_counts,
                alias_path_sha256s=alias_path_sha256s,
            ),
        )
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


def _diagnose_linux(
    reporter: _Reporter,
    *,
    root: Path = LINUX_RUNTIME_ROOT,
) -> None:
    offender_count = 0
    records: list[dict[str, object]] = []
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
        if len(records) >= MAX_REPORT_ENTRIES:
            continue
        records.append(
            {
                "relative_path": entry.relative_path,
                "raw_target": raw_target,
                "resolved_target": _bounded_text(os.fspath(resolved_target)),
                "lstat_mode": oct(observed.st_mode),
                "lexical_leaves_root": lexical_leaves_root,
                "resolved_leaves_root": resolved_leaves_root,
            }
        )
    reporter.emit(
        "linux-diagnostic-summary",
        scan_entries=scan_entries,
        offender_count=offender_count,
        reported_count=len(records),
        reports_truncated=offender_count > len(records),
    )
    for record in records:
        reporter.emit("linux-escaping-symlink", **record)


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
            _emit_macos_sandbox_log_summary(reporter)
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
