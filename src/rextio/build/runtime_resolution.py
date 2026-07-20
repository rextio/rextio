"""Bounded one-hop native runtime path-resolution observations for C6.8.

This module resolves only direct dependencies already admitted by the C6.4
inventory.  It never loads an artifact and never consults the ambient loader
environment, linker cache, ``ldd``, or ``dlopen``.  System dependencies remain
logical leaves; packaged candidates must bind exact regular, non-symlink files
under the generated Python root to exact wheel entries.
"""

from __future__ import annotations

import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from rextio.artifacts.evidence import (
    MAX_RUNTIME_DEP_NAME_CHARS,
    MAX_RUNTIME_DEPS,
    REASON_RUNTIME_MALFORMED,
    REASON_RUNTIME_UNSAFE_PATH,
    ArtifactEvidenceError,
    NativeRuntimeDependency,
    NativeRuntimeInventory,
    NativeRuntimePathResolutionInventory,
    NativeRuntimePathResolutionRecord,
    WheelEntryRef,
)
from rextio.build.runtime_inventory import (
    _FilesystemStamp,
    _allowed_elf_dependencies,
    _clamp_inspector_timeout,
    _hash_open_regular_file,
    _open_absolute_directory_chain,
    _open_relative_regular_file,
    _path_contains_symlink,
    _private_binary_snapshot,
    _record_directory_stamps,
    _require_regular_stamp,
    _run_runtime_inspector,
    _same_stamp,
    _verify_directory_stamps,
    resolve_installed_native_binary,
)
from rextio.build.subprocess_utils import DEFAULT_BUILD_TIMEOUT_SECONDS

_MACHO_BLOCK = re.compile(r"^Load command [0-9]+$")
_MACHO_COMMAND = re.compile(r"^\s*cmd (?P<command>LC_[A-Z0-9_]+)\s*$")
_MACHO_NAME = re.compile(r"^\s*name (?P<value>.+?) \(offset [0-9]+\)\s*$")
_MACHO_PATH = re.compile(r"^\s*path (?P<value>.+?) \(offset [0-9]+\)\s*$")
_READELF_NEEDED = re.compile(
    r"^\s*0x[0-9a-fA-F]+\s+\(NEEDED\)\s+Shared library:\s+\[(?P<name>[^\]]+)\]\s*$"
)
_READELF_PATH = re.compile(
    r"^\s*0x[0-9a-fA-F]+\s+\((?P<tag>RPATH|RUNPATH)\)\s+"
    r"Library (?:rpath|runpath):\s+\[(?P<value>[^\]]*)\]\s*$"
)
_READELF_TAG = re.compile(r"^\s*0x[0-9a-fA-F]+\s+\((?P<tag>[A-Z0-9_]+)\).*$")
_SAFE_BASENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$")
_UNSUPPORTED_MACHO_LOAD_COMMANDS = frozenset(
    {
        "LC_LAZY_LOAD_DYLIB",
        "LC_LOAD_UPWARD_DYLIB",
        "LC_LOAD_WEAK_DYLIB",
        "LC_REEXPORT_DYLIB",
    }
)
_ALTERNATE_ELF_LOADER_TAGS = frozenset({"AUDIT", "DEPAUDIT", "FILTER", "AUXILIARY"})
_MAX_CANDIDATE_ATTEMPTS = 256


@dataclass(frozen=True, slots=True)
class MachoLoadPlan:
    """Sanitized direct dependency forms and self-contained run paths."""

    dependencies: tuple[str, ...]
    run_paths: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ElfLoadPlan:
    """Sanitized direct SONAMEs and one explicit ORIGIN search-path tag."""

    dependencies: tuple[str, ...]
    path_tag: str | None
    search_paths: tuple[tuple[str, ...], ...]


@dataclass(frozen=True, slots=True)
class _CandidateReceipt:
    parts: tuple[str, ...]
    directory_stamps: tuple[_FilesystemStamp, ...]
    file_stamp: _FilesystemStamp
    sha256: str
    size: int


@dataclass(frozen=True, slots=True)
class NativeRuntimePathResolutionObservation:
    """Internal inventory plus non-serialized filesystem verification receipts."""

    inventory: NativeRuntimePathResolutionInventory
    receipts: tuple[_CandidateReceipt, ...]


def _validated_lexical_root(expected_python_root: Path) -> Path:
    """Return one absolute non-symlink root without erasing lexical policy."""
    try:
        lexical = Path(os.path.abspath(expected_python_root))
        if _path_contains_symlink(lexical):
            raise ArtifactEvidenceError(
                "native runtime generated root contains a symlink",
                reason=REASON_RUNTIME_UNSAFE_PATH,
            )
        linked = lexical.lstat()
        if not stat.S_ISDIR(linked.st_mode):
            raise ArtifactEvidenceError(
                "native runtime generated root is not a directory",
                reason=REASON_RUNTIME_UNSAFE_PATH,
            )
        if lexical.resolve(strict=True) != lexical:
            raise ArtifactEvidenceError(
                "native runtime generated root is noncanonical",
                reason=REASON_RUNTIME_UNSAFE_PATH,
            )
        return lexical
    except ArtifactEvidenceError:
        raise
    except (OSError, ValueError) as exc:
        raise ArtifactEvidenceError(
            "native runtime generated root is unavailable",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        ) from exc


def _refresh_directory_stamps_match(
    *,
    previous: tuple[_FilesystemStamp, ...],
    current: tuple[_FilesystemStamp, ...],
    root: Path,
) -> bool:
    """Allow only the generated root metadata delta caused by C6.9 snapshots."""
    if len(previous) != len(current):
        return False
    root_index = len(root.parts) - 1
    if root_index < 0 or root_index >= len(previous):
        return False
    for index, (old_stamp, new_stamp) in enumerate(zip(previous, current, strict=True)):
        if index == root_index:
            if (
                old_stamp.device != new_stamp.device
                or old_stamp.inode != new_stamp.inode
                or old_stamp.mode != new_stamp.mode
            ):
                return False
        elif old_stamp != new_stamp:
            return False
    return True


def collect_native_runtime_path_resolution(
    *,
    installed_path: Path | None,
    expected_python_root: Path,
    wheel_entries: tuple[WheelEntryRef, ...],
    runtime_inventory: NativeRuntimeInventory,
    target_triple: str,
    timeout: float = DEFAULT_BUILD_TIMEOUT_SECONDS,
) -> NativeRuntimePathResolutionObservation | None:
    """Return the optional C6.8 observation, omitting it on every unsafe gap."""
    try:
        return _collect_native_runtime_path_resolution(
            installed_path=installed_path,
            expected_python_root=expected_python_root,
            wheel_entries=wheel_entries,
            runtime_inventory=runtime_inventory,
            target_triple=target_triple,
            timeout=timeout,
        )
    except Exception:
        # C6.8 is additive observation metadata. Fixed low-level errors are not
        # serialized, and absence must not change earlier evidence/build gates.
        return None


def _collect_native_runtime_path_resolution(
    *,
    installed_path: Path | None,
    expected_python_root: Path,
    wheel_entries: tuple[WheelEntryRef, ...],
    runtime_inventory: NativeRuntimeInventory,
    target_triple: str,
    timeout: float,
) -> NativeRuntimePathResolutionObservation:
    if type(runtime_inventory) is not NativeRuntimeInventory:
        raise TypeError("native runtime inventory model is invalid")
    root = _validated_lexical_root(expected_python_root)
    reported = None if installed_path is None else str(installed_path)
    binary = resolve_installed_native_binary(
        installed_path=reported,
        expected_python_root=root,
    )
    if binary is None:
        raise ArtifactEvidenceError(
            "native runtime path-resolution subject is unavailable",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )
    subject_member = binary.relative_to(root).as_posix()
    if (
        subject_member != runtime_inventory.wheel_member
        or binary.name != runtime_inventory.subject_basename
    ):
        raise ArtifactEvidenceError(
            "native runtime path-resolution subject path binding is invalid",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )
    subject_entries = tuple(entry for entry in wheel_entries if entry.name == subject_member)
    if len(subject_entries) != 1 or (
        subject_entries[0].sha256 != runtime_inventory.subject_sha256
        or subject_entries[0].uncompressed_size != runtime_inventory.subject_size
    ):
        raise ArtifactEvidenceError(
            "native runtime path-resolution subject binding is invalid",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )

    triple = target_triple.strip().lower()
    inspector_timeout = _clamp_inspector_timeout(timeout)
    macho_plan: MachoLoadPlan | None = None
    elf_plan: ElfLoadPlan | None = None
    with _private_binary_snapshot(binary, expected_root=root) as snapshot:
        if (
            snapshot.sha256 != runtime_inventory.subject_sha256
            or snapshot.size != runtime_inventory.subject_size
            or snapshot.sha256 != subject_entries[0].sha256
            or snapshot.size != subject_entries[0].uncompressed_size
        ):
            raise ArtifactEvidenceError(
                "native runtime path-resolution snapshot binding is invalid",
                reason=REASON_RUNTIME_UNSAFE_PATH,
            )
        if "apple-darwin" in triple:
            stdout = _run_resolution_inspector(
                ["/usr/bin/otool", "-l", str(snapshot.path)],
                cwd=snapshot.path.parent,
                timeout=inspector_timeout,
            )
            macho_plan = parse_macho_load_commands(stdout)
        elif "linux" in triple:
            stdout = _run_resolution_inspector(
                ["/usr/bin/readelf", "-W", "-d", str(snapshot.path)],
                cwd=snapshot.path.parent,
                timeout=inspector_timeout,
            )
            elf_plan = parse_elf_load_plan(stdout)
        else:
            raise ArtifactEvidenceError(
                "native runtime path-resolution platform is unsupported",
                reason=REASON_RUNTIME_UNSAFE_PATH,
            )
    # Resolve packaged files only after the private inspector snapshot has been
    # removed, so its lifecycle cannot invalidate candidate-directory receipts.
    if "apple-darwin" in triple:
        if macho_plan is None:  # closed branch/type guard
            raise TypeError("Mach-O resolution plan is invalid")
        records, receipts = _resolve_macho_records(
            plan=macho_plan,
            runtime_inventory=runtime_inventory,
            root=root,
            subject_member=subject_member,
            wheel_entries=wheel_entries,
        )
    else:
        if elf_plan is None:  # closed branch/type guard
            raise TypeError("ELF resolution plan is invalid")
        records, receipts = _resolve_elf_records(
            plan=elf_plan,
            runtime_inventory=runtime_inventory,
            target_triple=target_triple,
            root=root,
            subject_member=subject_member,
            wheel_entries=wheel_entries,
        )
    inventory = NativeRuntimePathResolutionInventory(
        subject_wheel_member=subject_member,
        subject_sha256=runtime_inventory.subject_sha256,
        records=tuple(sorted(records, key=lambda record: record.dependency_bom_ref)),
    )
    return NativeRuntimePathResolutionObservation(
        inventory=inventory,
        receipts=tuple(sorted(receipts, key=lambda receipt: receipt.parts)),
    )


def verify_native_runtime_path_resolution(
    observation: NativeRuntimePathResolutionObservation,
    *,
    expected_python_root: Path,
) -> bool:
    """Reopen every packaged candidate securely and verify its exact receipt."""
    try:
        if type(observation) is not NativeRuntimePathResolutionObservation:
            return False
        root = _validated_lexical_root(expected_python_root)
        for receipt in observation.receipts:
            current = _read_candidate_secure(root=root, parts=receipt.parts)
            if (
                current.directory_stamps != receipt.directory_stamps
                or not _same_stamp(current.file_stamp, receipt.file_stamp)
                or current.sha256 != receipt.sha256
                or current.size != receipt.size
            ):
                return False
        return True
    except Exception:
        return False


def refresh_native_runtime_path_resolution_observation(
    observation: NativeRuntimePathResolutionObservation,
    *,
    expected_python_root: Path,
) -> NativeRuntimePathResolutionObservation | None:
    """Refresh C6.8 receipts only across C6.9's bounded root-stamp delta.

    C6.9 private snapshot directories intentionally live below the generated
    Python root. Their create/remove lifecycle changes directory metadata that
    an earlier C6.8 receipt observed. Require exact prior receipt coverage and
    preserve every file and ancestor/descendant stamp, allowing only the root
    directory's size/ctime/mtime to differ while its identity and mode remain.
    """
    try:
        if type(observation) is not NativeRuntimePathResolutionObservation:
            return None
        root = _validated_lexical_root(expected_python_root)
        source = observation.inventory
        if type(source) is not NativeRuntimePathResolutionInventory:
            return None
        records = tuple(
            NativeRuntimePathResolutionRecord(
                dependency_bom_ref=record.dependency_bom_ref,
                dependency_name=record.dependency_name,
                dependency_origin=record.dependency_origin,
                resolution=record.resolution,
                mechanism=record.mechanism,
                wheel_member=record.wheel_member,
                sha256=record.sha256,
                size=record.size,
            )
            for record in source.records
        )
        inventory = NativeRuntimePathResolutionInventory(
            subject_wheel_member=source.subject_wheel_member,
            subject_sha256=source.subject_sha256,
            records=records,
            kind=source.kind,
            schema_version=source.schema_version,
            scope=source.scope,
            complete=source.complete,
            authority=source.authority,
        )
        packaged_records = tuple(
            record for record in inventory.records if record.resolution == "wheel-member"
        )
        expected_parts: list[tuple[str, ...]] = []
        for record in packaged_records:
            if (
                record.wheel_member is None
                or record.sha256 is None
                or record.size is None
            ):
                return None
            parts = PurePosixPath(record.wheel_member).parts
            _validate_parts(parts)
            expected_parts.append(parts)
        if len(expected_parts) != len(set(expected_parts)):
            return None

        prior_by_parts: dict[tuple[str, ...], _CandidateReceipt] = {}
        for receipt in observation.receipts:
            if type(receipt) is not _CandidateReceipt or receipt.parts in prior_by_parts:
                return None
            prior_by_parts[receipt.parts] = receipt
        if set(prior_by_parts) != set(expected_parts):
            return None

        if not packaged_records:
            return NativeRuntimePathResolutionObservation(
                inventory=inventory,
                receipts=(),
            )

        receipts: list[_CandidateReceipt] = []
        for record, parts in zip(packaged_records, expected_parts, strict=True):
            if record.sha256 is None or record.size is None:  # closed model/type guard
                return None
            previous = prior_by_parts[parts]
            if previous.sha256 != record.sha256 or previous.size != record.size:
                return None
            receipt = _read_candidate_secure(
                root=root,
                parts=parts,
            )
            if (
                receipt.parts != previous.parts
                or receipt.sha256 != previous.sha256
                or receipt.size != previous.size
                or receipt.file_stamp != previous.file_stamp
                or not _refresh_directory_stamps_match(
                    previous=previous.directory_stamps,
                    current=receipt.directory_stamps,
                    root=root,
                )
            ):
                return None
            receipts.append(receipt)
        ordered = tuple(sorted(receipts, key=lambda receipt: receipt.parts))
        if len({receipt.parts for receipt in ordered}) != len(ordered):
            return None
        return NativeRuntimePathResolutionObservation(
            inventory=inventory,
            receipts=ordered,
        )
    except Exception:
        return None


def parse_macho_load_commands(stdout: str) -> MachoLoadPlan:
    """Parse only strong load dependencies and self loader-anchored run paths."""
    if type(stdout) is not str or not stdout.strip():
        raise ArtifactEvidenceError(
            "Mach-O load-command output is malformed", reason=REASON_RUNTIME_MALFORMED
        )
    blocks: list[list[str]] = []
    current: list[str] | None = None
    for raw_line in stdout.splitlines():
        line = raw_line.rstrip("\r")
        if _MACHO_BLOCK.fullmatch(line):
            current = []
            blocks.append(current)
        elif current is not None:
            current.append(line)
        elif line.strip() and not line.endswith(":"):
            raise ArtifactEvidenceError(
                "Mach-O load-command preamble is malformed",
                reason=REASON_RUNTIME_MALFORMED,
            )
    if not blocks or len(blocks) > 512:
        raise ArtifactEvidenceError(
            "Mach-O load-command count is invalid", reason=REASON_RUNTIME_MALFORMED
        )
    dependencies: list[str] = []
    run_paths: list[str] = []
    for block in blocks:
        commands = [match.group("command") for line in block if (match := _MACHO_COMMAND.fullmatch(line))]
        if len(commands) != 1:
            raise ArtifactEvidenceError(
                "Mach-O load command lacks one command kind",
                reason=REASON_RUNTIME_MALFORMED,
            )
        command = commands[0]
        if command in _UNSUPPORTED_MACHO_LOAD_COMMANDS:
            raise ArtifactEvidenceError(
                "Mach-O alternate load command is unsupported",
                reason=REASON_RUNTIME_UNSAFE_PATH,
            )
        if command == "LC_LOAD_DYLIB":
            values = [match.group("value") for line in block if (match := _MACHO_NAME.fullmatch(line))]
            if len(values) != 1:
                raise ArtifactEvidenceError(
                    "Mach-O dependency load command is malformed",
                    reason=REASON_RUNTIME_MALFORMED,
                )
            dependencies.append(_validate_macho_dependency_form(values[0]))
        elif command == "LC_RPATH":
            values = [match.group("value") for line in block if (match := _MACHO_PATH.fullmatch(line))]
            if len(values) != 1:
                raise ArtifactEvidenceError(
                    "Mach-O run-path command is malformed",
                    reason=REASON_RUNTIME_MALFORMED,
                )
            run_paths.append(_validate_loader_anchored_path(values[0]))
    if len(dependencies) > MAX_RUNTIME_DEPS or len(run_paths) > MAX_RUNTIME_DEPS:
        raise ArtifactEvidenceError(
            "Mach-O path-resolution observation exceeds the bound",
            reason=REASON_RUNTIME_MALFORMED,
        )
    return MachoLoadPlan(
        dependencies=tuple(dependencies),
        run_paths=tuple(sorted(set(run_paths))),
    )


def parse_elf_load_plan(stdout: str) -> ElfLoadPlan:
    """Parse direct NEEDED names and at most one ORIGIN RPATH/RUNPATH tag."""
    if type(stdout) is not str or not stdout.strip():
        raise ArtifactEvidenceError(
            "ELF dynamic output is malformed", reason=REASON_RUNTIME_MALFORMED
        )
    dependencies: list[str] = []
    paths: list[tuple[str, str]] = []
    for raw_line in stdout.splitlines():
        line = raw_line.rstrip("\r")
        needed = _READELF_NEEDED.fullmatch(line)
        if needed is not None:
            dependencies.append(_validate_basename(needed.group("name")))
            continue
        path = _READELF_PATH.fullmatch(line)
        if path is not None:
            paths.append((path.group("tag"), path.group("value")))
            continue
        tag = _READELF_TAG.fullmatch(line)
        if tag is not None and tag.group("tag") in _ALTERNATE_ELF_LOADER_TAGS:
            raise ArtifactEvidenceError(
                "ELF alternate loader tag is unsupported",
                reason=REASON_RUNTIME_UNSAFE_PATH,
            )
    if len(dependencies) > MAX_RUNTIME_DEPS or len(paths) > 1:
        raise ArtifactEvidenceError(
            "ELF path-resolution observation is ambiguous",
            reason=REASON_RUNTIME_MALFORMED,
        )
    path_tag: str | None = None
    search_paths: tuple[tuple[str, ...], ...] = ()
    if paths:
        path_tag, value = paths[0]
        search_paths = tuple(_parse_origin_search_paths(value))
    return ElfLoadPlan(
        dependencies=tuple(dependencies),
        path_tag=path_tag,
        search_paths=search_paths,
    )


def _resolve_macho_records(
    *,
    plan: MachoLoadPlan,
    runtime_inventory: NativeRuntimeInventory,
    root: Path,
    subject_member: str,
    wheel_entries: tuple[WheelEntryRef, ...],
) -> tuple[tuple[NativeRuntimePathResolutionRecord, ...], tuple[_CandidateReceipt, ...]]:
    raw_by_name: dict[str, list[str]] = {}
    for raw_dependency_path in plan.dependencies:
        raw_by_name.setdefault(PurePosixPath(raw_dependency_path).name, []).append(
            raw_dependency_path
        )
    records: list[NativeRuntimePathResolutionRecord] = []
    receipts: list[_CandidateReceipt] = []
    candidate_attempts = sum(
        1
        if raw.startswith("@loader_path/")
        else len(plan.run_paths)
        if raw.startswith("@rpath/")
        else 0
        for raw in plan.dependencies
    )
    if candidate_attempts > _MAX_CANDIDATE_ATTEMPTS:
        raise ArtifactEvidenceError(
            "Mach-O candidate attempt count exceeds the bound",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )
    for runtime_dependency in runtime_inventory.dependencies:
        raw_matches = raw_by_name.get(runtime_dependency.name, [])
        if len(raw_matches) != 1:
            raise ArtifactEvidenceError(
                "Mach-O dependency path binding is ambiguous",
                reason=REASON_RUNTIME_UNSAFE_PATH,
            )
        raw = raw_matches[0]
        if runtime_dependency.origin == "system":
            if not raw.startswith(("/usr/lib/", "/System/Library/")):
                raise ArtifactEvidenceError(
                    "Mach-O system dependency binding disagrees",
                    reason=REASON_RUNTIME_UNSAFE_PATH,
                )
            records.append(_logical_record(runtime_dependency, mechanism="macho-system"))
            continue
        if runtime_dependency.origin != "wheel-candidate":
            raise ArtifactEvidenceError(
                "Mach-O dependency origin cannot be resolved",
                reason=REASON_RUNTIME_UNSAFE_PATH,
            )
        if raw.startswith("@loader_path/"):
            candidate_parts = _member_parent(subject_member) + _relative_parts(
                raw.removeprefix("@loader_path/")
            )
            records.append(
                _wheel_record(
                    runtime_dependency,
                    mechanism="macho-loader-path",
                    candidate_parts=(candidate_parts,),
                    root=root,
                    subject_member=subject_member,
                    wheel_entries=wheel_entries,
                    receipts=receipts,
                )
            )
        elif raw.startswith("@rpath/"):
            suffix = _relative_parts(raw.removeprefix("@rpath/"))
            candidates = tuple(
                _member_parent(subject_member)
                + _loader_path_suffix(run_path)
                + suffix
                for run_path in plan.run_paths
            )
            records.append(
                _wheel_record(
                    runtime_dependency,
                    mechanism="macho-rpath",
                    candidate_parts=candidates,
                    root=root,
                    subject_member=subject_member,
                    wheel_entries=wheel_entries,
                    receipts=receipts,
                )
            )
        else:
            raise ArtifactEvidenceError(
                "Mach-O packaged dependency form is unsupported",
                reason=REASON_RUNTIME_UNSAFE_PATH,
            )
    if len(plan.dependencies) != len(runtime_inventory.dependencies):
        raise ArtifactEvidenceError(
            "Mach-O direct dependency coverage is incomplete",
            reason=REASON_RUNTIME_MALFORMED,
        )
    return tuple(records), tuple(receipts)


def _resolve_elf_records(
    *,
    plan: ElfLoadPlan,
    runtime_inventory: NativeRuntimeInventory,
    target_triple: str,
    root: Path,
    subject_member: str,
    wheel_entries: tuple[WheelEntryRef, ...],
) -> tuple[tuple[NativeRuntimePathResolutionRecord, ...], tuple[_CandidateReceipt, ...]]:
    if len(plan.dependencies) != len(set(plan.dependencies)):
        raise ArtifactEvidenceError(
            "ELF direct dependency names are ambiguous",
            reason=REASON_RUNTIME_MALFORMED,
        )
    raw_names = set(plan.dependencies)
    inventory_names = {dependency.name for dependency in runtime_inventory.dependencies}
    if raw_names != inventory_names:
        raise ArtifactEvidenceError(
            "ELF direct dependency coverage is incomplete",
            reason=REASON_RUNTIME_MALFORMED,
        )
    system_names = _allowed_elf_dependencies(target_triple)
    records: list[NativeRuntimePathResolutionRecord] = []
    receipts: list[_CandidateReceipt] = []
    wheel_dependency_count = sum(
        dependency.name not in system_names
        for dependency in runtime_inventory.dependencies
    )
    if wheel_dependency_count * len(plan.search_paths) > _MAX_CANDIDATE_ATTEMPTS:
        raise ArtifactEvidenceError(
            "ELF candidate attempt count exceeds the bound",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )
    for dependency in runtime_inventory.dependencies:
        if dependency.name in system_names:
            # C6.4 intentionally retains the historic ``unresolved`` origin for
            # allowlisted ELF names; C6.8 adds only the logical-leaf observation.
            if dependency.origin != "unresolved":
                raise ArtifactEvidenceError(
                    "ELF system dependency origin disagrees",
                    reason=REASON_RUNTIME_UNSAFE_PATH,
                )
            records.append(_logical_record(dependency, mechanism="elf-system-name"))
            continue
        if dependency.origin != "wheel-candidate" or not plan.search_paths:
            raise ArtifactEvidenceError(
                "ELF packaged dependency cannot be resolved",
                reason=REASON_RUNTIME_UNSAFE_PATH,
            )
        candidates = tuple(
            _member_parent(subject_member) + search_path + (dependency.name,)
            for search_path in plan.search_paths
        )
        records.append(
            _wheel_record(
                dependency,
                mechanism="elf-origin-rpath",
                candidate_parts=candidates,
                root=root,
                subject_member=subject_member,
                wheel_entries=wheel_entries,
                receipts=receipts,
            )
        )
    return tuple(records), tuple(receipts)


def _logical_record(
    dependency: NativeRuntimeDependency,
    *,
    mechanism: str,
) -> NativeRuntimePathResolutionRecord:
    return NativeRuntimePathResolutionRecord(
        dependency_bom_ref=dependency.bom_ref(),
        dependency_name=dependency.name,
        dependency_origin=dependency.origin,
        resolution="system-logical",
        mechanism=mechanism,
    )


def _wheel_record(
    dependency: NativeRuntimeDependency,
    *,
    mechanism: str,
    candidate_parts: tuple[tuple[str, ...], ...],
    root: Path,
    subject_member: str,
    wheel_entries: tuple[WheelEntryRef, ...],
    receipts: list[_CandidateReceipt],
) -> NativeRuntimePathResolutionRecord:
    unique_parts = tuple(sorted(set(candidate_parts)))
    if len(unique_parts) > MAX_RUNTIME_DEPS:
        raise ArtifactEvidenceError(
            "native runtime candidate attempt count exceeds the bound",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )
    matches: list[tuple[str, str, int]] = []
    matched_receipts: list[_CandidateReceipt] = []
    for parts in unique_parts:
        candidate = _bind_candidate(
            parts=parts,
            root=root,
            subject_member=subject_member,
            wheel_entries=wheel_entries,
        )
        if candidate is not None:
            member, digest, size, receipt = candidate
            matches.append((member, digest, size))
            matched_receipts.append(receipt)
    if len(matches) != 1:
        raise ArtifactEvidenceError(
            "native runtime wheel candidate is missing or ambiguous",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )
    member, digest, size = matches[0]
    receipts.append(matched_receipts[0])
    return NativeRuntimePathResolutionRecord(
        dependency_bom_ref=dependency.bom_ref(),
        dependency_name=dependency.name,
        dependency_origin=dependency.origin,
        resolution="wheel-member",
        mechanism=mechanism,
        wheel_member=member,
        sha256=digest,
        size=size,
    )


def _bind_candidate(
    *,
    parts: tuple[str, ...],
    root: Path,
    subject_member: str,
    wheel_entries: tuple[WheelEntryRef, ...],
) -> tuple[str, str, int, _CandidateReceipt] | None:
    _validate_parts(parts)
    member = PurePosixPath(*parts).as_posix()
    if member == subject_member:
        raise ArtifactEvidenceError(
            "native runtime dependency resolves to its subject",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )
    candidate_path = root.joinpath(*parts)
    try:
        candidate_path.lstat()
    except FileNotFoundError:
        return None
    try:
        receipt = _read_candidate_secure(root=root, parts=parts)
    except ArtifactEvidenceError:
        raise
    except (FileNotFoundError, NotADirectoryError) as exc:
        raise ArtifactEvidenceError(
            "native runtime candidate changed during exact binding",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        ) from exc
    wheel_matches = tuple(entry for entry in wheel_entries if entry.name == member)
    if len(wheel_matches) != 1:
        raise ArtifactEvidenceError(
            "native runtime candidate lacks one exact wheel inventory binding",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )
    digest, size = receipt.sha256, receipt.size
    wheel_entry = wheel_matches[0]
    if wheel_entry.sha256 != digest or wheel_entry.uncompressed_size != size:
        raise ArtifactEvidenceError(
            "native runtime candidate bytes do not match the wheel",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )
    return member, digest, size, receipt


def _read_candidate_secure(
    *,
    root: Path,
    parts: tuple[str, ...],
) -> _CandidateReceipt:
    """Pin every ancestor and hash one O_NOFOLLOW-opened regular file."""
    absolute_chain: list[tuple[int, int | None, str | None]] = []
    relative_directories: list[tuple[int, int, str]] = []
    file_fd = -1
    try:
        absolute_chain = _open_absolute_directory_chain(root)
        root_fd = absolute_chain[-1][0]
        file_fd, relative_directories = _open_relative_regular_file(
            root_fd,
            parts,
            retain_directories=True,
        )
        directories: list[tuple[int, int | None, str | None]] = [
            *absolute_chain,
            *relative_directories,
        ]
        records = _record_directory_stamps(directories)
        file_stamp = _require_regular_stamp(os.fstat(file_fd))
        digest, size = _hash_open_regular_file(file_fd, expected=file_stamp)
        # There is no private snapshot directory in this path, so use -1 and
        # compare every ordinary directory without special permission rules.
        _verify_directory_stamps(records, private_directory_fd=-1)
        return _CandidateReceipt(
            parts=parts,
            directory_stamps=tuple(record[3] for record in records),
            file_stamp=file_stamp,
            sha256=digest,
            size=size,
        )
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        for relative_handle, _relative_parent, _relative_name in reversed(
            relative_directories
        ):
            try:
                os.close(relative_handle)
            except OSError:
                pass
        for absolute_handle, _absolute_parent, _absolute_name in reversed(
            absolute_chain
        ):
            try:
                os.close(absolute_handle)
            except OSError:
                pass


def _run_resolution_inspector(command: list[str], *, cwd: Path, timeout: float) -> str:
    tool = Path(command[0])
    if not tool.is_file() or not os.access(tool, os.X_OK):
        raise ArtifactEvidenceError(
            "native runtime path-resolution inspector is unavailable",
            reason=REASON_RUNTIME_MALFORMED,
        )
    if (sys.platform == "darwin" and command[:2] != ["/usr/bin/otool", "-l"]) or (
        sys.platform.startswith("linux")
        and command[:3] != ["/usr/bin/readelf", "-W", "-d"]
    ):
        raise ArtifactEvidenceError(
            "native runtime path-resolution inspector does not match the host",
            reason=REASON_RUNTIME_MALFORMED,
        )
    return _run_runtime_inspector(command, cwd=cwd, timeout=timeout)


def _validate_macho_dependency_form(value: str) -> str:
    _validate_path_text(value)
    if value.startswith(("/usr/lib/", "/System/Library/")):
        return _validate_macho_system_dependency_path(value)
    for prefix in ("@loader_path/", "@rpath/"):
        if value.startswith(prefix):
            _relative_parts(value.removeprefix(prefix))
            return value
    raise ArtifactEvidenceError(
        "Mach-O dependency path form is unsupported",
        reason=REASON_RUNTIME_UNSAFE_PATH,
    )


def _validate_macho_system_dependency_path(value: str) -> str:
    """Require one canonical absolute Apple system-library path."""
    _validate_path_text(value)
    if not value.startswith(("/usr/lib/", "/System/Library/")):
        raise ArtifactEvidenceError(
            "Mach-O system dependency path is unsupported",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )
    raw_parts = value.split("/")
    if not raw_parts or raw_parts[0] != "":
        raise ArtifactEvidenceError(
            "Mach-O system dependency path is noncanonical",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )
    parts = tuple(raw_parts[1:])
    _validate_parts(parts)
    if PurePosixPath(value).as_posix() != value:
        raise ArtifactEvidenceError(
            "Mach-O system dependency path is noncanonical",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )
    _validate_basename(parts[-1])
    return value


def _validate_loader_anchored_path(value: str) -> str:
    _validate_path_text(value)
    if value == "@loader_path":
        return value
    if value.startswith("@loader_path/"):
        _relative_parts(value.removeprefix("@loader_path/"))
        return value
    raise ArtifactEvidenceError(
        "Mach-O run path is not loader-path anchored",
        reason=REASON_RUNTIME_UNSAFE_PATH,
    )


def _parse_origin_search_paths(value: str) -> list[tuple[str, ...]]:
    if not value or len(value) > MAX_RUNTIME_DEP_NAME_CHARS * 4:
        raise ArtifactEvidenceError(
            "ELF runtime search path is invalid", reason=REASON_RUNTIME_UNSAFE_PATH
        )
    result: list[tuple[str, ...]] = []
    for segment in value.split(":"):
        if not segment:
            raise ArtifactEvidenceError(
                "ELF runtime search path has an empty segment",
                reason=REASON_RUNTIME_UNSAFE_PATH,
            )
        if segment.startswith("${ORIGIN}"):
            suffix = segment[len("${ORIGIN}") :]
        elif segment.startswith("$ORIGIN"):
            suffix = segment[len("$ORIGIN") :]
        else:
            raise ArtifactEvidenceError(
                "ELF runtime search path is not ORIGIN-anchored",
                reason=REASON_RUNTIME_UNSAFE_PATH,
            )
        if suffix and not suffix.startswith("/"):
            raise ArtifactEvidenceError(
                "ELF ORIGIN search suffix is malformed",
                reason=REASON_RUNTIME_UNSAFE_PATH,
            )
        relative = suffix.removeprefix("/")
        if "$" in relative:
            raise ArtifactEvidenceError(
                "ELF runtime search path has an unsupported variable",
                reason=REASON_RUNTIME_UNSAFE_PATH,
            )
        if not relative:
            result.append(())
        else:
            result.append(_relative_parts(relative))
    return result


def _loader_path_suffix(value: str) -> tuple[str, ...]:
    if value == "@loader_path":
        return ()
    return _relative_parts(value.removeprefix("@loader_path/"))


def _member_parent(member: str) -> tuple[str, ...]:
    return PurePosixPath(member).parent.parts


def _relative_parts(value: str) -> tuple[str, ...]:
    _validate_path_text(value)
    if value.startswith("/") or "//" in value:
        raise ArtifactEvidenceError(
            "native runtime relative path is unsafe",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )
    parts = PurePosixPath(value).parts
    _validate_parts(parts)
    return parts


def _validate_parts(parts: tuple[str, ...]) -> None:
    if not parts or any(
        not part
        or part in {".", ".."}
        or "/" in part
        or "\\" in part
        or len(part) > MAX_RUNTIME_DEP_NAME_CHARS
        or any(ord(character) < 32 for character in part)
        for part in parts
    ):
        raise ArtifactEvidenceError(
            "native runtime path components are unsafe",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )


def _validate_path_text(value: str) -> None:
    if (
        type(value) is not str
        or not value
        or len(value) > MAX_RUNTIME_DEP_NAME_CHARS * 4
        or "\\" in value
        or "\0" in value
        or any(ord(character) < 32 for character in value)
    ):
        raise ArtifactEvidenceError(
            "native runtime path text is unsafe",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )


def _validate_basename(value: str) -> str:
    text = value.strip()
    if (
        not text
        or len(text) > MAX_RUNTIME_DEP_NAME_CHARS
        or not _SAFE_BASENAME.fullmatch(text)
        or "/" in text
        or "\\" in text
    ):
        raise ArtifactEvidenceError(
            "native runtime dependency basename is unsafe",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )
    return text


__all__ = [
    "ElfLoadPlan",
    "MachoLoadPlan",
    "NativeRuntimePathResolutionObservation",
    "collect_native_runtime_path_resolution",
    "parse_elf_load_plan",
    "parse_macho_load_commands",
    "verify_native_runtime_path_resolution",
]
