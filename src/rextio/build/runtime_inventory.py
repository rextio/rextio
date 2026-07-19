"""Bounded direct native runtime linkage inventory for C6.4 host-extension evidence.

Inspects the installed host-extension native binary after a successful ordinary
host-extension+CPython wheel build:

* macOS Mach-O: ``otool -L`` (direct load commands only)
* Linux ELF: ``/usr/bin/readelf -W -d`` (``NEEDED`` entries only)

The inventory is deliberately incomplete: no transitive dylib/so closure, no
runtime ``dlopen`` graph, no Windows PE, no WASM. Inspector paths, raw
stdout/stderr, absolute private paths, and environment secrets are never
serialized. Failures raise :class:`ArtifactEvidenceError` with a fixed reason
so callers can map best-effort builds to ``unavailable`` evidence.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import secrets
import stat
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterator, Literal

from rextio.artifacts.evidence import (
    MAX_RUNTIME_DEPS,
    MAX_RUNTIME_DEP_NAME_CHARS,
    MAX_RUNTIME_INSPECTOR_OUTPUT_BYTES,
    MAX_EVIDENCE_FILE_BYTES,
    REASON_RUNTIME_ARCHITECTURE_MISMATCH,
    REASON_RUNTIME_BINARY_MISMATCH,
    REASON_RUNTIME_BINARY_MISSING,
    REASON_RUNTIME_DEP_COUNT_EXCEEDED,
    REASON_RUNTIME_INSPECTOR_FAILED,
    REASON_RUNTIME_INSPECTOR_MISSING,
    REASON_RUNTIME_INSPECTOR_TIMEOUT,
    REASON_RUNTIME_MALFORMED,
    REASON_RUNTIME_OUTPUT_EXCEEDED,
    REASON_RUNTIME_PLATFORM_UNSUPPORTED,
    REASON_RUNTIME_UNSAFE_PATH,
    REASON_RUNTIME_UNEXPECTED_DEPENDENCY,
    REASON_RUNTIME_WHEEL_MEMBER_MISMATCH,
    ArtifactEvidenceError,
    NativeRuntimeDependency,
    NativeRuntimeInventory,
    WheelEntryRef,
)
from rextio.build.subprocess_utils import (
    DEFAULT_BUILD_TIMEOUT_SECONDS,
    OUTPUT_OVERFLOW_EXIT_CODE,
    TIMEOUT_EXIT_CODE,
    run_build_tool,
)

_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_OTOOL_COMPAT = re.compile(
    r"^\t(?P<path>.+?) \(compatibility version (?P<compat>[^,]+), "
    r"current version (?P<current>[^)]+)\)$"
)
_READELF_NEEDED = re.compile(
    r"^\s*0x[0-9a-fA-F]+\s+\(NEEDED\)\s+Shared library:\s+\[(?P<name>[^\]]+)\]\s*$"
)
_READELF_RPATH = re.compile(
    r"^\s*0x[0-9a-fA-F]+\s+\((?P<tag>RPATH|RUNPATH)\)\s+"
    r"Library (?:rpath|runpath):\s+\[(?P<value>[^\]]*)\]\s*$"
)
_READELF_TAG = re.compile(r"^\s*0x[0-9a-fA-F]+\s+\((?P<tag>[A-Z0-9_]+)\)(?:\s+(?P<value>.+?))?\s*$")
_READELF_SONAME = re.compile(r"^Library soname:\s+\[(?P<name>[^\]]+)\]$")
_SAFE_BINARY_BASENAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._+-]{0,254}$")
_SAFE_BASENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$")
_ARCH_HEADER = re.compile(r"\(architecture\s+(?P<arch>[A-Za-z0-9_]+)\)\s*:?\s*$")
_MAX_INSPECTOR_TIMEOUT_SECONDS = 10.0
_ET_DYN = 3
_MH_DYLIB = 6
_MH_BUNDLE = 8
_SNAPSHOT_PREFIX = ".rextio-runtime-snapshot-"
_FAT_MACHO_MAGICS = {
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
}
_SAFE_ELF_DYNAMIC_TAGS = frozenset(
    {
        "BIND_NOW",
        "DEBUG",
        "FINI",
        "FINI_ARRAY",
        "FINI_ARRAYSZ",
        "FLAGS",
        "FLAGS_1",
        "GNU_HASH",
        "HASH",
        "INIT",
        "INIT_ARRAY",
        "INIT_ARRAYSZ",
        "JMPREL",
        "NULL",
        "PLTGOT",
        "PLTREL",
        "PLTRELSZ",
        "RELA",
        "RELACOUNT",
        "RELAENT",
        "RELASZ",
        "REL",
        "RELCOUNT",
        "RELENT",
        "RELSZ",
        "SONAME",
        "STRSZ",
        "STRTAB",
        "SYMENT",
        "SYMTAB",
        "TEXTREL",
        "VERDEF",
        "VERDEFNUM",
        "VERNEED",
        "VERNEEDNUM",
        "VERSYM",
    }
)
_ALTERNATE_LOADER_DEP_TAGS = frozenset({"AUDIT", "DEPAUDIT", "FILTER", "AUXILIARY"})
_VALUELESS_ELF_DYNAMIC_TAGS = frozenset({"BIND_NOW", "TEXTREL"})


@dataclass(frozen=True)
class _ParsedLinkage:
    """Internal parse result for one inspector format."""

    format: str
    dependencies: tuple[NativeRuntimeDependency, ...]
    architectures: tuple[str, ...]


@dataclass(frozen=True)
class _BinaryHeader:
    format: str
    architecture: str
    macho_filetype: int | None = None


@dataclass(frozen=True)
class _FilesystemStamp:
    device: int
    inode: int
    size: int
    ctime_ns: int
    mtime_ns: int
    mode: int


@dataclass(frozen=True)
class _PrivateBinarySnapshot:
    path: Path
    sha256: str
    size: int


def inspect_native_runtime_inventory(
    *,
    installed_path: Path | None,
    expected_python_root: Path,
    wheel_entries: tuple[WheelEntryRef, ...],
    target_triple: str,
    timeout: float = DEFAULT_BUILD_TIMEOUT_SECONDS,
) -> NativeRuntimeInventory:
    """Inspect an immutable private snapshot and bind it to a wheel member."""
    reported_path = None if installed_path is None else str(installed_path)
    binary = resolve_installed_native_binary(
        installed_path=reported_path,
        expected_python_root=expected_python_root,
    )
    if binary is None:
        raise ArtifactEvidenceError(
            "native extension binary is missing or not a regular file",
            reason=REASON_RUNTIME_BINARY_MISSING,
        )

    basename = binary.name
    if not basename or len(basename) > MAX_RUNTIME_DEP_NAME_CHARS:
        raise ArtifactEvidenceError(
            "native extension basename is invalid",
            reason=REASON_RUNTIME_BINARY_MISSING,
        )
    if not _SAFE_BINARY_BASENAME.fullmatch(basename):
        raise ArtifactEvidenceError(
            "native extension basename is unsafe",
            reason=REASON_RUNTIME_BINARY_MISSING,
        )

    _expected_target_format(target_triple)
    root = expected_python_root.resolve(strict=True)
    wheel_member_path = binary.relative_to(root).as_posix()
    with _private_binary_snapshot(binary, expected_root=root) as snapshot:
        wheel_member, wheel_member_sha256, wheel_member_size = _match_wheel_member(
            expected_member=wheel_member_path,
            subject_sha256=snapshot.sha256,
            subject_size=snapshot.size,
            wheel_entries=wheel_entries,
        )
        header = _inspect_binary_header(snapshot.path, target_triple=target_triple)
        inspector_name, command = _inspector_command(snapshot.path)
        inspector_timeout = _clamp_inspector_timeout(timeout)
        stdout = _run_runtime_inspector(
            command,
            cwd=snapshot.path.parent,
            timeout=inspector_timeout,
        )
        if inspector_name == "otool":
            expected_self = _expected_cargo_macho_self_install_basename(basename)
            verified_self_names: frozenset[str] = frozenset()
            if header.macho_filetype == _MH_DYLIB:
                identity_stdout = _run_runtime_inspector(
                    ["/usr/bin/otool", "-D", str(snapshot.path)],
                    cwd=snapshot.path.parent,
                    timeout=inspector_timeout,
                )
                verified_self_names = parse_otool_d_output(
                    identity_stdout,
                    expected_self_install_basename=expected_self,
                )
            parsed = parse_otool_l_output(
                stdout,
                expected_self_install_basename=expected_self,
                verified_self_install_names=verified_self_names,
            )
        else:
            parsed = parse_readelf_d_output(stdout, target_triple=target_triple)

        if parsed.format != header.format:
            raise ArtifactEvidenceError(
                "native runtime inspector format disagrees with the binary header",
                reason=REASON_RUNTIME_ARCHITECTURE_MISMATCH,
            )
        return NativeRuntimeInventory(
            format=parsed.format,
            architecture=header.architecture,
            inspector=inspector_name,
            subject_basename=basename,
            subject_sha256=snapshot.sha256,
            subject_size=snapshot.size,
            wheel_member=wheel_member,
            wheel_member_sha256=wheel_member_sha256,
            wheel_member_size=wheel_member_size,
            dependencies=parsed.dependencies,
        )


def parse_otool_l_output(
    stdout: str,
    *,
    expected_self_install_basename: str | None = None,
    verified_self_install_names: frozenset[str] = frozenset(),
) -> _ParsedLinkage:
    """Parse sanitized direct load dependencies from ``otool -L`` stdout.

    Only absolute install names under ``/usr/lib`` or ``/System/Library`` are
    accepted and serialized as basenames. The sole exception is the first row
    of each section when it is a private absolute Cargo ``LC_ID_DYLIB`` whose
    basename exactly matches ``expected_self_install_basename`` *and* the full
    install name was independently verified by bounded ``otool -D`` output;
    that self row is dropped. Bare names, every ``@``-relative name, all other
    private paths, and a matching self name in any later row fail closed.
    """
    if not isinstance(stdout, str):
        raise ArtifactEvidenceError("otool output is malformed", reason=REASON_RUNTIME_MALFORMED)
    if not stdout.strip():
        raise ArtifactEvidenceError("otool output is empty", reason=REASON_RUNTIME_MALFORMED)
    if expected_self_install_basename is not None and (
        not _SAFE_BASENAME.fullmatch(expected_self_install_basename)
        or not expected_self_install_basename.startswith("lib_")
        or not expected_self_install_basename.endswith(".dylib")
    ):
        raise ArtifactEvidenceError(
            "expected Mach-O self install name is invalid",
            reason=REASON_RUNTIME_MALFORMED,
        )
    if verified_self_install_names and expected_self_install_basename is None:
        raise ArtifactEvidenceError(
            "verified Mach-O self identities lack an expected basename",
            reason=REASON_RUNTIME_MALFORMED,
        )
    for identity in verified_self_install_names:
        if not _is_safe_private_macho_self_install_name(
            identity,
            expected_self_install_basename=expected_self_install_basename,
        ):
            raise ArtifactEvidenceError(
                "verified Mach-O self identity is unsafe",
                reason=REASON_RUNTIME_UNSAFE_PATH,
            )

    sections: dict[str, list[str]] = {}
    section_row_counts: dict[str, int] = {}
    current_arch = "_default"
    sections[current_arch] = []
    section_row_counts[current_arch] = 0
    consumed_self_names: set[str] = set()
    saw_header = False
    for raw_line in stdout.splitlines():
        line = raw_line.rstrip("\r")
        if not line.strip():
            continue
        # Header lines end with ':' and are never dependency rows.
        if line.endswith(":") and not line.startswith("\t"):
            saw_header = True
            arch_match = _ARCH_HEADER.search(line)
            if arch_match is not None:
                current_arch = arch_match.group("arch")
            else:
                current_arch = "_default"
            sections.setdefault(current_arch, [])
            section_row_counts.setdefault(current_arch, 0)
            continue
        if not line.startswith("\t"):
            raise ArtifactEvidenceError(
                "otool output contains an unexpected line",
                reason=REASON_RUNTIME_MALFORMED,
            )
        match = _OTOOL_COMPAT.fullmatch(line)
        if match is None:
            raise ArtifactEvidenceError(
                "otool dependency line is malformed",
                reason=REASON_RUNTIME_MALFORMED,
            )
        install_path = match.group("path").strip()
        row_index = section_row_counts.setdefault(current_arch, 0)
        section_row_counts[current_arch] = row_index + 1
        if row_index == 0 and _is_expected_private_macho_self_install_name(
            install_path,
            expected_self_install_basename=expected_self_install_basename,
            verified_self_install_names=verified_self_install_names,
        ):
            consumed_self_names.add(install_path)
            continue
        name = _sanitize_macho_install_name(install_path)
        sections.setdefault(current_arch, []).append(name)

    if not saw_header:
        raise ArtifactEvidenceError(
            "otool output is missing a header", reason=REASON_RUNTIME_MALFORMED
        )
    if consumed_self_names != set(verified_self_install_names):
        raise ArtifactEvidenceError(
            "verified Mach-O self identity does not match otool linkage",
            reason=REASON_RUNTIME_MALFORMED,
        )

    # Drop empty default when only architecture-specific sections exist.
    non_empty = {arch: deps for arch, deps in sections.items() if deps or arch != "_default"}
    if not non_empty:
        # Binary with zero load dependencies is rare but accept empty set when
        # a header was present (still direct-only inventory).
        return _ParsedLinkage(format="mach-o", dependencies=(), architectures=())

    arch_keys = sorted(non_empty)
    # Normalize each section: drop self-reference if first entry equals subject
    # is not possible here (we only have basenames). Deduplicate while preserving
    # first-seen order within a section.
    normalized: dict[str, tuple[str, ...]] = {}
    for arch, deps in non_empty.items():
        ordered: list[str] = []
        seen: set[str] = set()
        for dep in deps:
            if dep in seen:
                continue
            seen.add(dep)
            ordered.append(dep)
        if len(ordered) > MAX_RUNTIME_DEPS:
            raise ArtifactEvidenceError(
                "native runtime dependency count exceeds the bound",
                reason=REASON_RUNTIME_DEP_COUNT_EXCEEDED,
            )
        normalized[arch] = tuple(ordered)

    unique_sets = {normalized[arch] for arch in normalized}
    if len(unique_sets) > 1:
        raise ArtifactEvidenceError(
            "native runtime multi-arch dependency sets disagree",
            reason=REASON_RUNTIME_ARCHITECTURE_MISMATCH,
        )
    dependencies = next(iter(unique_sets))
    architectures = tuple(arch for arch in arch_keys if arch != "_default")
    return _ParsedLinkage(
        format="mach-o",
        dependencies=tuple(
            NativeRuntimeDependency(name=name, origin="system") for name in dependencies
        ),
        architectures=architectures,
    )


def parse_otool_d_output(
    stdout: str,
    *,
    expected_self_install_basename: str,
) -> frozenset[str]:
    """Parse bounded ``otool -D`` output into verified private LC_ID names."""
    if not isinstance(stdout, str) or not stdout.strip():
        raise ArtifactEvidenceError(
            "otool identity output is malformed",
            reason=REASON_RUNTIME_MALFORMED,
        )
    if (
        not _SAFE_BASENAME.fullmatch(expected_self_install_basename)
        or not expected_self_install_basename.startswith("lib_")
        or not expected_self_install_basename.endswith(".dylib")
    ):
        raise ArtifactEvidenceError(
            "expected Mach-O self install name is invalid",
            reason=REASON_RUNTIME_MALFORMED,
        )

    identities: set[str] = set()
    saw_header = False
    section_has_identity = False
    for raw_line in stdout.splitlines():
        line = raw_line.rstrip("\r")
        if not line.strip():
            continue
        if line.endswith(":") and not line.startswith((" ", "\t")):
            if saw_header and not section_has_identity:
                raise ArtifactEvidenceError(
                    "otool identity section is empty",
                    reason=REASON_RUNTIME_MALFORMED,
                )
            saw_header = True
            section_has_identity = False
            continue
        if not saw_header or section_has_identity:
            raise ArtifactEvidenceError(
                "otool identity output contains an unexpected row",
                reason=REASON_RUNTIME_MALFORMED,
            )
        identity = line.strip()
        if not _is_safe_private_macho_self_install_name(
            identity,
            expected_self_install_basename=expected_self_install_basename,
        ):
            raise ArtifactEvidenceError(
                "otool identity is not the expected private Cargo self ID",
                reason=REASON_RUNTIME_UNSAFE_PATH,
            )
        identities.add(identity)
        section_has_identity = True

    if not saw_header or not section_has_identity or not identities:
        raise ArtifactEvidenceError(
            "otool identity output is incomplete",
            reason=REASON_RUNTIME_MALFORMED,
        )
    return frozenset(identities)


def parse_readelf_d_output(stdout: str, *, target_triple: str) -> _ParsedLinkage:
    """Parse sanitized direct ``NEEDED`` entries from ``readelf -d`` stdout.

    Any absolute or parent-escaping ``RPATH`` / ``RUNPATH`` fails closed.
    """
    if not isinstance(stdout, str):
        raise ArtifactEvidenceError("readelf output is malformed", reason=REASON_RUNTIME_MALFORMED)
    if not stdout.strip():
        raise ArtifactEvidenceError("readelf output is empty", reason=REASON_RUNTIME_MALFORMED)

    needed: list[str] = []
    saw_dynamic = False
    for raw_line in stdout.splitlines():
        line = raw_line.rstrip("\r")
        stripped = line.strip()
        if not stripped:
            continue
        if "Dynamic section" in stripped or stripped.startswith("Tag "):
            saw_dynamic = True
            continue
        rpath_match = _READELF_RPATH.fullmatch(line)
        if rpath_match is not None:
            _validate_elf_search_path(rpath_match.group("value"))
            continue
        needed_match = _READELF_NEEDED.fullmatch(line)
        if needed_match is not None:
            name = _sanitize_elf_needed(needed_match.group("name"), target_triple=target_triple)
            needed.append(name)
            continue
        tag_match = _READELF_TAG.fullmatch(line)
        if tag_match is not None:
            tag = tag_match.group("tag")
            value = tag_match.group("value")
            if tag in _ALTERNATE_LOADER_DEP_TAGS:
                raise ArtifactEvidenceError(
                    "ELF alternate loader dependency tags are unsupported",
                    reason=REASON_RUNTIME_UNEXPECTED_DEPENDENCY,
                )
            if tag not in _SAFE_ELF_DYNAMIC_TAGS:
                raise ArtifactEvidenceError(
                    "ELF dynamic tag is outside the closed allowlist",
                    reason=REASON_RUNTIME_MALFORMED,
                )
            if value is None:
                if tag not in _VALUELESS_ELF_DYNAMIC_TAGS:
                    raise ArtifactEvidenceError(
                        "ELF dynamic tag value is missing",
                        reason=REASON_RUNTIME_MALFORMED,
                    )
                continue
            if tag == "SONAME":
                soname_match = _READELF_SONAME.fullmatch(value)
                if soname_match is None:
                    raise ArtifactEvidenceError(
                        "ELF SONAME is malformed", reason=REASON_RUNTIME_MALFORMED
                    )
                _sanitize_elf_basename(soname_match.group("name"))
            continue
        if stripped.startswith("There is no dynamic section"):
            raise ArtifactEvidenceError(
                "ELF binary has no dynamic section",
                reason=REASON_RUNTIME_MALFORMED,
            )
        # Allow the common "File: <name>" preamble some toolchains emit only
        # when it is a bare basename (never an absolute private path).
        if stripped.startswith("File:"):
            file_value = stripped[len("File:") :].strip()
            if file_value.startswith("/") or "\\" in file_value or ".." in file_value:
                raise ArtifactEvidenceError(
                    "readelf output embeds an unsafe path",
                    reason=REASON_RUNTIME_UNSAFE_PATH,
                )
            continue
        raise ArtifactEvidenceError(
            "readelf output contains an unexpected line",
            reason=REASON_RUNTIME_MALFORMED,
        )

    if not saw_dynamic and not needed:
        raise ArtifactEvidenceError(
            "readelf output is missing a dynamic section",
            reason=REASON_RUNTIME_MALFORMED,
        )

    ordered: list[str] = []
    seen: set[str] = set()
    for name in needed:
        if name in seen:
            continue
        seen.add(name)
        ordered.append(name)
    if len(ordered) > MAX_RUNTIME_DEPS:
        raise ArtifactEvidenceError(
            "native runtime dependency count exceeds the bound",
            reason=REASON_RUNTIME_DEP_COUNT_EXCEEDED,
        )
    return _ParsedLinkage(
        format="elf",
        dependencies=tuple(
            NativeRuntimeDependency(name=name, origin="unresolved") for name in ordered
        ),
        architectures=(),
    )


def resolve_installed_native_binary(
    *,
    installed_path: str | None,
    expected_python_root: Path,
) -> Path | None:
    """Resolve only the builder-reported binary inside one generated root."""
    if not installed_path:
        return None
    path = Path(installed_path)
    try:
        lexical_root = Path(os.path.abspath(expected_python_root))
        lexical_path = Path(os.path.abspath(path))
        lexical_path.relative_to(lexical_root)
        if _path_contains_symlink(lexical_root):
            return None
        relative = lexical_path.relative_to(lexical_root)
        current = lexical_root
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                return None
        if not lexical_root.is_dir():
            return None
        root = lexical_root.resolve(strict=True)
        resolved = lexical_path.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError):
        return None
    if not lexical_path.is_file():
        return None
    if not lexical_path.name.startswith("_rextio_native"):
        return None
    return resolved


def _match_wheel_member(
    *,
    expected_member: str,
    subject_sha256: str,
    subject_size: int,
    wheel_entries: tuple[WheelEntryRef, ...],
) -> tuple[str, str, int]:
    matches = [
        entry
        for entry in wheel_entries
        if entry.name == expected_member and not entry.name.endswith("/")
    ]
    if len(matches) != 1:
        raise ArtifactEvidenceError(
            "native extension wheel member match failed",
            reason=REASON_RUNTIME_WHEEL_MEMBER_MISMATCH,
        )
    member = matches[0]
    if member.sha256 != subject_sha256 or not _HEX_SHA256.fullmatch(member.sha256):
        raise ArtifactEvidenceError(
            "installed native binary does not match the wheel member digest",
            reason=REASON_RUNTIME_BINARY_MISMATCH,
        )
    if member.uncompressed_size != subject_size:
        raise ArtifactEvidenceError(
            "installed native binary does not match the wheel member size",
            reason=REASON_RUNTIME_WHEEL_MEMBER_MISMATCH,
        )
    return member.name, member.sha256, member.uncompressed_size


def _inspector_command(binary: Path) -> tuple[str, list[str]]:
    if sys.platform == "darwin":
        name = "otool"
        tool = Path("/usr/bin/otool")
    elif sys.platform.startswith("linux"):
        name = "readelf"
        tool = Path("/usr/bin/readelf")
    else:
        raise ArtifactEvidenceError(
            "native runtime inventory is unsupported on this platform",
            reason=REASON_RUNTIME_PLATFORM_UNSUPPORTED,
        )
    if not tool.is_file() or not os.access(tool, os.X_OK):
        raise ArtifactEvidenceError(
            "native runtime inspector is not available",
            reason=REASON_RUNTIME_INSPECTOR_MISSING,
        )
    if name == "otool":
        return name, [str(tool), "-L", str(binary)]
    return name, [str(tool), "-W", "-d", str(binary)]


def _expected_cargo_macho_self_install_basename(subject_basename: str) -> str:
    """Derive Cargo's exact dylib self ID from an installed extension name."""
    crate_basename = subject_basename.split(".", 1)[0]
    if crate_basename != "_rextio_native":
        raise ArtifactEvidenceError(
            "native extension basename cannot identify the Cargo dylib",
            reason=REASON_RUNTIME_BINARY_MISSING,
        )
    return f"lib{crate_basename}.dylib"


def _is_expected_private_macho_self_install_name(
    install_path: str,
    *,
    expected_self_install_basename: str | None,
    verified_self_install_names: frozenset[str],
) -> bool:
    """Recognize only an independently verified first-row Cargo LC_ID_DYLIB."""
    return install_path in verified_self_install_names and (
        _is_safe_private_macho_self_install_name(
            install_path,
            expected_self_install_basename=expected_self_install_basename,
        )
    )


def _is_safe_private_macho_self_install_name(
    install_path: str,
    *,
    expected_self_install_basename: str | None,
) -> bool:
    if expected_self_install_basename is None or not install_path.startswith("/"):
        return False
    if install_path.startswith("/usr/lib/") or install_path.startswith("/System/Library/"):
        return False
    if (
        len(install_path) > MAX_RUNTIME_DEP_NAME_CHARS * 4
        or "\0" in install_path
        or any(ord(ch) < 32 for ch in install_path)
        or "\\" in install_path
        or ".." in PurePosixPath(install_path).parts
    ):
        return False
    return PurePosixPath(install_path).name == expected_self_install_basename


def _sanitize_macho_install_name(install_path: str) -> str:
    if not install_path or len(install_path) > MAX_RUNTIME_DEP_NAME_CHARS * 4:
        raise ArtifactEvidenceError(
            "mach-o install name is invalid", reason=REASON_RUNTIME_UNSAFE_PATH
        )
    if "\0" in install_path or any(ord(ch) < 32 for ch in install_path):
        raise ArtifactEvidenceError(
            "mach-o install name contains control characters",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )
    if "\\" in install_path or ".." in PurePosixPath(install_path).parts:
        raise ArtifactEvidenceError(
            "mach-o install name is unsafe", reason=REASON_RUNTIME_UNSAFE_PATH
        )

    if not (install_path.startswith("/usr/lib/") or install_path.startswith("/System/Library/")):
        raise ArtifactEvidenceError(
            "mach-o dependency is outside the trusted system roots",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )

    # Trusted system absolute paths are reduced to basenames before serialization.
    basename = PurePosixPath(install_path).name
    if len(basename) > MAX_RUNTIME_DEP_NAME_CHARS:
        raise ArtifactEvidenceError(
            "mach-o dependency name exceeds the bound",
            reason=REASON_RUNTIME_DEP_COUNT_EXCEEDED,
        )
    if not basename or not _SAFE_BASENAME.fullmatch(basename):
        raise ArtifactEvidenceError(
            "mach-o dependency basename is unsafe",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )
    return basename


def _sanitize_elf_basename(name: str) -> str:
    text = name.strip()
    if not text:
        raise ArtifactEvidenceError(
            "ELF dependency name is invalid", reason=REASON_RUNTIME_UNSAFE_PATH
        )
    if len(text) > MAX_RUNTIME_DEP_NAME_CHARS:
        raise ArtifactEvidenceError(
            "ELF dependency name exceeds the bound",
            reason=REASON_RUNTIME_DEP_COUNT_EXCEEDED,
        )
    if "/" in text or "\\" in text or ".." in text:
        raise ArtifactEvidenceError(
            "ELF NEEDED name must be a basename", reason=REASON_RUNTIME_UNSAFE_PATH
        )
    if not _SAFE_BASENAME.fullmatch(text):
        raise ArtifactEvidenceError("ELF NEEDED name is unsafe", reason=REASON_RUNTIME_UNSAFE_PATH)
    if any(ord(ch) < 32 for ch in text):
        raise ArtifactEvidenceError(
            "ELF NEEDED name contains control characters",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )
    return text


def _sanitize_elf_needed(name: str, *, target_triple: str) -> str:
    text = _sanitize_elf_basename(name)
    if text not in _allowed_elf_dependencies(target_triple):
        raise ArtifactEvidenceError(
            "ELF NEEDED dependency is outside the closed allowlist",
            reason=REASON_RUNTIME_UNEXPECTED_DEPENDENCY,
        )
    return text


def _allowed_elf_dependencies(target_triple: str) -> frozenset[str]:
    """Return the narrow system/Python ABI SONAME allowlist for one target."""
    triple = target_triple.strip().lower()
    arch = _expected_target_architecture(triple)
    python_stem = f"libpython{sys.version_info.major}.{sys.version_info.minor}"
    allowed = {
        f"{python_stem}.so",
        f"{python_stem}.so.1.0",
    }
    if "linux-gnu" in triple:
        allowed.update(
            {
                "libc.so.6",
                "libdl.so.2",
                "libgcc_s.so.1",
                "libm.so.6",
                "libpthread.so.0",
                "libresolv.so.2",
                "librt.so.1",
                "libutil.so.1",
            }
        )
        loaders = {
            "aarch64": "ld-linux-aarch64.so.1",
            "arm": "ld-linux-armhf.so.3",
            "powerpc64": "ld64.so.2",
            "riscv64": "ld-linux-riscv64-lp64d.so.1",
            "s390x": "ld64.so.1",
            "x86": "ld-linux.so.2",
            "x86_64": "ld-linux-x86-64.so.2",
        }
        loader = loaders.get(arch)
        if loader is not None:
            allowed.add(loader)
    elif "linux-musl" in triple:
        musl_arches = {
            "aarch64": "aarch64",
            "arm": "arm",
            "powerpc64": "powerpc64",
            "riscv64": "riscv64",
            "s390x": "s390x",
            "x86": "i386",
            "x86_64": "x86_64",
        }
        musl_arch = musl_arches.get(arch)
        if musl_arch is not None:
            allowed.add(f"libc.musl-{musl_arch}.so.1")
    return frozenset(allowed)


def _validate_elf_search_path(value: str) -> None:
    """Fail closed on every RPATH/RUNPATH, including ``$ORIGIN``."""
    del value
    raise ArtifactEvidenceError(
        "ELF RPATH/RUNPATH is unsupported",
        reason=REASON_RUNTIME_UNSAFE_PATH,
    )


def _path_contains_symlink(path: Path) -> bool:
    """Return whether any existing lexical component is a symlink."""
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if current.is_symlink():
            return True
    return False


def _inspector_environment() -> dict[str, str]:
    """Return the complete, minimal environment for a native inspector."""
    return {"LC_ALL": "C", "LANG": "C", "PATH": "/usr/bin:/bin"}


def _run_runtime_inspector(command: list[str], *, cwd: Path, timeout: float) -> str:
    """Run one fixed inspector without inheriting the build environment."""
    try:
        completed = run_build_tool(
            command,
            cwd=cwd,
            timeout=timeout,
            env=_inspector_environment(),
            inherit_env=False,
            max_output_bytes=MAX_RUNTIME_INSPECTOR_OUTPUT_BYTES,
        )
    except FileNotFoundError as exc:
        raise ArtifactEvidenceError(
            "native runtime inspector is not available",
            reason=REASON_RUNTIME_INSPECTOR_MISSING,
        ) from exc
    except (OSError, ValueError) as exc:
        raise ArtifactEvidenceError(
            "native runtime inspector could not be started",
            reason=REASON_RUNTIME_INSPECTOR_FAILED,
        ) from exc

    if completed.returncode == TIMEOUT_EXIT_CODE:
        reason = REASON_RUNTIME_INSPECTOR_TIMEOUT
    elif completed.returncode == OUTPUT_OVERFLOW_EXIT_CODE:
        reason = REASON_RUNTIME_OUTPUT_EXCEEDED
    elif completed.returncode != 0:
        reason = REASON_RUNTIME_INSPECTOR_FAILED
    else:
        reason = None
    if reason is not None:
        raise ArtifactEvidenceError(
            "native runtime inspector failed",
            reason=reason,
        )
    if not isinstance(completed.stdout, str):
        raise ArtifactEvidenceError(
            "native runtime inspector output is malformed",
            reason=REASON_RUNTIME_MALFORMED,
        )
    return completed.stdout


def _stamp(stat_result: os.stat_result) -> _FilesystemStamp:
    return _FilesystemStamp(
        device=stat_result.st_dev,
        inode=stat_result.st_ino,
        size=stat_result.st_size,
        ctime_ns=stat_result.st_ctime_ns,
        mtime_ns=stat_result.st_mtime_ns,
        mode=stat_result.st_mode,
    )


def _same_stamp(left: _FilesystemStamp, right: _FilesystemStamp) -> bool:
    return (
        left.device == right.device
        and left.inode == right.inode
        and left.size == right.size
        and left.ctime_ns == right.ctime_ns
        and left.mtime_ns == right.mtime_ns
        and left.mode == right.mode
    )


def _require_regular_stamp(
    stat_result: os.stat_result, *, exact_permissions: int | None = None
) -> _FilesystemStamp:
    value = _stamp(stat_result)
    if not stat.S_ISREG(value.mode) or (
        exact_permissions is not None and stat.S_IMODE(value.mode) != exact_permissions
    ):
        raise ArtifactEvidenceError(
            "native runtime file identity is unsafe",
            reason=REASON_RUNTIME_BINARY_MISMATCH,
        )
    return value


def _require_directory_stamp(
    stat_result: os.stat_result, *, exact_permissions: int | None = None
) -> _FilesystemStamp:
    value = _stamp(stat_result)
    if not stat.S_ISDIR(value.mode) or (
        exact_permissions is not None and stat.S_IMODE(value.mode) != exact_permissions
    ):
        raise ArtifactEvidenceError(
            "native runtime directory identity is unsafe",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )
    return value


def _directory_open_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None:
        raise ArtifactEvidenceError(
            "secure native runtime path traversal is unavailable",
            reason=REASON_RUNTIME_PLATFORM_UNSUPPORTED,
        )
    return os.O_RDONLY | nofollow | directory | getattr(os, "O_CLOEXEC", 0)


def _file_open_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise ArtifactEvidenceError(
            "secure native runtime path traversal is unavailable",
            reason=REASON_RUNTIME_PLATFORM_UNSUPPORTED,
        )
    return os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)


def _open_absolute_directory_chain(
    path: Path,
) -> list[tuple[int, int | None, str | None]]:
    """Pin every absolute ancestor so swap-and-restore changes are observable."""
    absolute = Path(os.path.abspath(path))
    if not absolute.is_absolute():  # pragma: no cover - abspath guarantees this.
        raise ArtifactEvidenceError(
            "native runtime root is not absolute",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )
    handles: list[tuple[int, int | None, str | None]] = []
    try:
        current_fd = os.open(absolute.anchor, _directory_open_flags())
        handles.append((current_fd, None, None))
        for part in absolute.parts[1:]:
            next_fd = os.open(part, _directory_open_flags(), dir_fd=current_fd)
            handles.append((next_fd, current_fd, part))
            current_fd = next_fd
        return handles
    except (ArtifactEvidenceError, OSError) as exc:
        for handle, _parent, _name in reversed(handles):
            try:
                os.close(handle)
            except OSError:
                pass
        if isinstance(exc, ArtifactEvidenceError):
            raise
        raise ArtifactEvidenceError(
            "native runtime root could not be pinned",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        ) from exc


def _validate_relative_parts(parts: tuple[str, ...]) -> None:
    if not parts or any(
        not part or part in {".", ".."} or "/" in part or "\\" in part for part in parts
    ):
        raise ArtifactEvidenceError(
            "native runtime relative path is unsafe",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        )


def _open_relative_regular_file(
    root_fd: int,
    parts: tuple[str, ...],
    *,
    retain_directories: bool = False,
) -> tuple[int, list[tuple[int, int, str]]]:
    """Open one contained regular file with openat/O_NOFOLLOW traversal."""
    _validate_relative_parts(parts)
    current_fd = root_fd
    retained: list[tuple[int, int, str]] = []
    opened: list[int] = []
    file_fd = -1
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, _directory_open_flags(), dir_fd=current_fd)
            opened.append(next_fd)
            if retain_directories:
                retained.append((next_fd, current_fd, part))
            current_fd = next_fd
        file_fd = os.open(parts[-1], _file_open_flags(), dir_fd=current_fd)
        _require_regular_stamp(os.fstat(file_fd))
    except (ArtifactEvidenceError, OSError) as exc:
        if file_fd >= 0:
            try:
                os.close(file_fd)
            except OSError:
                pass
        for handle in reversed(opened):
            try:
                os.close(handle)
            except OSError:
                pass
        if isinstance(exc, ArtifactEvidenceError):
            raise
        raise ArtifactEvidenceError(
            "native runtime file could not be opened safely",
            reason=REASON_RUNTIME_BINARY_MISMATCH,
        ) from exc
    if not retain_directories:
        for handle in reversed(opened):
            os.close(handle)
        retained = []
    return file_fd, retained


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short native snapshot write")
        view = view[written:]


def _copy_and_hash_regular_file(
    source_fd: int, destination_fd: int
) -> tuple[str, int, _FilesystemStamp]:
    before = _require_regular_stamp(os.fstat(source_fd))
    if before.size < 0 or before.size > MAX_EVIDENCE_FILE_BYTES:
        raise ArtifactEvidenceError(
            "native runtime binary exceeds the evidence bound",
            reason=REASON_RUNTIME_BINARY_MISMATCH,
        )
    digest = hashlib.sha256()
    total = 0
    os.lseek(source_fd, 0, os.SEEK_SET)
    while True:
        chunk = os.read(source_fd, min(1024 * 1024, MAX_EVIDENCE_FILE_BYTES + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_EVIDENCE_FILE_BYTES:
            raise ArtifactEvidenceError(
                "native runtime binary exceeds the evidence bound",
                reason=REASON_RUNTIME_BINARY_MISMATCH,
            )
        digest.update(chunk)
        _write_all(destination_fd, chunk)
    after = _require_regular_stamp(os.fstat(source_fd))
    if not _same_stamp(before, after) or total != before.size:
        raise ArtifactEvidenceError(
            "native runtime source changed while snapshotting",
            reason=REASON_RUNTIME_BINARY_MISMATCH,
        )
    return digest.hexdigest(), total, after


def _hash_open_regular_file(
    fd: int, *, expected: _FilesystemStamp, exact_permissions: int | None = None
) -> tuple[str, int]:
    before = _require_regular_stamp(os.fstat(fd), exact_permissions=exact_permissions)
    if not _same_stamp(before, expected) or before.size > MAX_EVIDENCE_FILE_BYTES:
        raise ArtifactEvidenceError(
            "native runtime file identity changed",
            reason=REASON_RUNTIME_BINARY_MISMATCH,
        )
    digest = hashlib.sha256()
    total = 0
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        chunk = os.read(fd, min(1024 * 1024, MAX_EVIDENCE_FILE_BYTES + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_EVIDENCE_FILE_BYTES:
            raise ArtifactEvidenceError(
                "native runtime file exceeds the evidence bound",
                reason=REASON_RUNTIME_BINARY_MISMATCH,
            )
        digest.update(chunk)
    after = _require_regular_stamp(os.fstat(fd), exact_permissions=exact_permissions)
    if not _same_stamp(after, expected) or total != expected.size:
        raise ArtifactEvidenceError(
            "native runtime file changed while hashing",
            reason=REASON_RUNTIME_BINARY_MISMATCH,
        )
    return digest.hexdigest(), total


def _record_directory_stamps(
    handles: list[tuple[int, int | None, str | None]],
) -> list[tuple[int, int | None, str | None, _FilesystemStamp]]:
    return [
        (handle, parent, name, _require_directory_stamp(os.fstat(handle)))
        for handle, parent, name in handles
    ]


def _verify_directory_stamps(
    records: list[tuple[int, int | None, str | None, _FilesystemStamp]],
    *,
    private_directory_fd: int,
) -> None:
    for handle, parent, name, expected in records:
        exact_permissions = 0o700 if handle == private_directory_fd else None
        actual = _require_directory_stamp(os.fstat(handle), exact_permissions=exact_permissions)
        if not _same_stamp(actual, expected):
            raise ArtifactEvidenceError(
                "native runtime directory changed during inspection",
                reason=REASON_RUNTIME_BINARY_MISMATCH,
            )
        if parent is not None and name is not None:
            try:
                linked = _require_directory_stamp(
                    os.stat(name, dir_fd=parent, follow_symlinks=False),
                    exact_permissions=exact_permissions,
                )
            except (ArtifactEvidenceError, OSError) as exc:
                raise ArtifactEvidenceError(
                    "native runtime directory path changed during inspection",
                    reason=REASON_RUNTIME_BINARY_MISMATCH,
                ) from exc
            if not _same_stamp(linked, expected):
                raise ArtifactEvidenceError(
                    "native runtime directory path changed during inspection",
                    reason=REASON_RUNTIME_BINARY_MISMATCH,
                )


def _verify_private_snapshot(
    *,
    directory_records: list[tuple[int, int | None, str | None, _FilesystemStamp]],
    root_fd: int,
    source_parts: tuple[str, ...],
    source_fd: int,
    source_stamp: _FilesystemStamp,
    snapshot_directory_fd: int,
    snapshot_name: str,
    snapshot_fd: int,
    snapshot_stamp: _FilesystemStamp,
    expected_digest: str,
) -> None:
    _verify_directory_stamps(directory_records, private_directory_fd=snapshot_directory_fd)
    source_digest, source_size = _hash_open_regular_file(source_fd, expected=source_stamp)
    reopened_source, temporary_directories = _open_relative_regular_file(root_fd, source_parts)
    try:
        reopened_source_digest, reopened_source_size = _hash_open_regular_file(
            reopened_source, expected=source_stamp
        )
    finally:
        os.close(reopened_source)
        for handle, _parent, _name in reversed(temporary_directories):
            os.close(handle)

    snapshot_digest, snapshot_size = _hash_open_regular_file(
        snapshot_fd, expected=snapshot_stamp, exact_permissions=0o400
    )
    try:
        reopened_snapshot = os.open(
            snapshot_name,
            _file_open_flags(),
            dir_fd=snapshot_directory_fd,
        )
    except OSError as exc:
        raise ArtifactEvidenceError(
            "private native snapshot path changed during inspection",
            reason=REASON_RUNTIME_BINARY_MISMATCH,
        ) from exc
    try:
        reopened_snapshot_digest, reopened_snapshot_size = _hash_open_regular_file(
            reopened_snapshot,
            expected=snapshot_stamp,
            exact_permissions=0o400,
        )
    finally:
        os.close(reopened_snapshot)

    if (
        source_digest != expected_digest
        or reopened_source_digest != expected_digest
        or snapshot_digest != expected_digest
        or reopened_snapshot_digest != expected_digest
        or source_size != source_stamp.size
        or reopened_source_size != source_stamp.size
        or snapshot_size != snapshot_stamp.size
        or reopened_snapshot_size != snapshot_stamp.size
    ):
        raise ArtifactEvidenceError(
            "native runtime bytes changed during inspection",
            reason=REASON_RUNTIME_BINARY_MISMATCH,
        )


@contextmanager
def _private_binary_snapshot(
    binary: Path, *, expected_root: Path
) -> Iterator[_PrivateBinarySnapshot]:
    """Yield a read-only private copy while pinning every relevant inode."""
    absolute_root = Path(os.path.abspath(expected_root))
    absolute_binary = Path(os.path.abspath(binary))
    try:
        source_parts = absolute_binary.relative_to(absolute_root).parts
    except ValueError as exc:
        raise ArtifactEvidenceError(
            "native runtime source is outside the generated root",
            reason=REASON_RUNTIME_UNSAFE_PATH,
        ) from exc
    _validate_relative_parts(source_parts)

    absolute_chain: list[tuple[int, int | None, str | None]] = []
    source_directories: list[tuple[int, int, str]] = []
    source_fd = -1
    snapshot_directory_fd = -1
    snapshot_write_fd = -1
    snapshot_fd = -1
    snapshot_directory_name: str | None = None
    snapshot_name = absolute_binary.name
    try:
        absolute_chain = _open_absolute_directory_chain(absolute_root)
        root_fd = absolute_chain[-1][0]
        source_fd, source_directories = _open_relative_regular_file(
            root_fd, source_parts, retain_directories=True
        )

        for _attempt in range(16):
            candidate = f"{_SNAPSHOT_PREFIX}{secrets.token_hex(16)}"
            try:
                os.mkdir(candidate, 0o700, dir_fd=root_fd)
            except FileExistsError:
                continue
            snapshot_directory_name = candidate
            break
        if snapshot_directory_name is None:
            raise ArtifactEvidenceError(
                "private native snapshot directory could not be allocated",
                reason=REASON_RUNTIME_BINARY_MISMATCH,
            )
        snapshot_directory_fd = os.open(
            snapshot_directory_name,
            _directory_open_flags(),
            dir_fd=root_fd,
        )
        os.fchmod(snapshot_directory_fd, 0o700)
        snapshot_write_fd = os.open(
            snapshot_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=snapshot_directory_fd,
        )
        digest, size, source_stamp = _copy_and_hash_regular_file(source_fd, snapshot_write_fd)
        os.fsync(snapshot_write_fd)
        os.fchmod(snapshot_write_fd, 0o400)
        os.close(snapshot_write_fd)
        snapshot_write_fd = -1
        snapshot_fd = os.open(
            snapshot_name,
            _file_open_flags(),
            dir_fd=snapshot_directory_fd,
        )
        snapshot_stamp = _require_regular_stamp(os.fstat(snapshot_fd), exact_permissions=0o400)
        snapshot_digest, snapshot_size = _hash_open_regular_file(
            snapshot_fd,
            expected=snapshot_stamp,
            exact_permissions=0o400,
        )
        if snapshot_digest != digest or snapshot_size != size:
            raise ArtifactEvidenceError(
                "private native snapshot does not match its source",
                reason=REASON_RUNTIME_BINARY_MISMATCH,
            )

        all_directories: list[tuple[int, int | None, str | None]] = [
            *absolute_chain,
            *source_directories,
            (snapshot_directory_fd, root_fd, snapshot_directory_name),
        ]
        directory_records = _record_directory_stamps(all_directories)
        snapshot_path = absolute_root / snapshot_directory_name / snapshot_name
        snapshot = _PrivateBinarySnapshot(
            path=snapshot_path,
            sha256=digest,
            size=size,
        )
        try:
            yield snapshot
        except BaseException:
            raise
        else:
            _verify_private_snapshot(
                directory_records=directory_records,
                root_fd=root_fd,
                source_parts=source_parts,
                source_fd=source_fd,
                source_stamp=source_stamp,
                snapshot_directory_fd=snapshot_directory_fd,
                snapshot_name=snapshot_name,
                snapshot_fd=snapshot_fd,
                snapshot_stamp=snapshot_stamp,
                expected_digest=digest,
            )
    except ArtifactEvidenceError:
        raise
    except OSError as exc:
        raise ArtifactEvidenceError(
            "private native snapshot operation failed",
            reason=REASON_RUNTIME_BINARY_MISMATCH,
        ) from exc
    finally:
        if snapshot_write_fd >= 0:
            try:
                os.close(snapshot_write_fd)
            except OSError:
                pass
        if snapshot_fd >= 0:
            try:
                os.close(snapshot_fd)
            except OSError:
                pass
        root_fd = absolute_chain[-1][0] if absolute_chain else -1
        if snapshot_directory_fd >= 0:
            try:
                os.unlink(snapshot_name, dir_fd=snapshot_directory_fd)
            except OSError:
                pass
            if root_fd >= 0 and snapshot_directory_name is not None:
                try:
                    held = os.fstat(snapshot_directory_fd)
                    linked = os.stat(
                        snapshot_directory_name,
                        dir_fd=root_fd,
                        follow_symlinks=False,
                    )
                    if held.st_dev == linked.st_dev and held.st_ino == linked.st_ino:
                        os.rmdir(snapshot_directory_name, dir_fd=root_fd)
                except OSError:
                    pass
            try:
                os.close(snapshot_directory_fd)
            except OSError:
                pass
        if source_fd >= 0:
            try:
                os.close(source_fd)
            except OSError:
                pass
        for handle, _parent, _name in reversed(source_directories):
            try:
                os.close(handle)
            except OSError:
                pass
        for handle, _absolute_parent, _absolute_name in reversed(absolute_chain):
            try:
                os.close(handle)
            except OSError:
                pass


def _clamp_inspector_timeout(timeout: float) -> float:
    if (
        not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ArtifactEvidenceError(
            "native runtime inspector timeout is invalid",
            reason=REASON_RUNTIME_INSPECTOR_TIMEOUT,
        )
    return min(float(timeout), _MAX_INSPECTOR_TIMEOUT_SECONDS)


def _inspect_binary_header(binary: Path, *, target_triple: str) -> _BinaryHeader:
    """Read object format/architecture from the binary header, not tool output."""
    try:
        with binary.open("rb") as handle:
            header = handle.read(64)
    except OSError as exc:
        raise ArtifactEvidenceError(
            "native extension header could not be read",
            reason=REASON_RUNTIME_BINARY_MISMATCH,
        ) from exc

    if header[:4] in _FAT_MACHO_MAGICS:
        raise ArtifactEvidenceError(
            "native runtime universal Mach-O binaries are unsupported",
            reason=REASON_RUNTIME_ARCHITECTURE_MISMATCH,
        )

    binary_format: str
    architecture: str | None
    macho_filetype: int | None = None
    byteorder: Literal["little", "big"]
    if header.startswith(b"\x7fELF"):
        if len(header) < 20 or header[4] not in {1, 2} or header[5] not in {1, 2}:
            raise ArtifactEvidenceError(
                "ELF header is malformed",
                reason=REASON_RUNTIME_ARCHITECTURE_MISMATCH,
            )
        byteorder = "little" if header[5] == 1 else "big"
        object_type = int.from_bytes(header[16:18], byteorder)
        if object_type != _ET_DYN:
            raise ArtifactEvidenceError(
                "native runtime ELF object type is unsupported",
                reason=REASON_RUNTIME_ARCHITECTURE_MISMATCH,
            )
        machine = int.from_bytes(header[18:20], byteorder)
        architecture = {
            3: "x86",
            20: "powerpc",
            21: "powerpc64",
            22: "s390x",
            40: "arm",
            62: "x86_64",
            183: "aarch64",
            243: "riscv64",
        }.get(machine)
        is_64_bit = header[4] == 2
        binary_format = "elf"
    else:
        macho_magics: dict[bytes, tuple[Literal["little", "big"], bool]] = {
            b"\xce\xfa\xed\xfe": ("little", False),
            b"\xcf\xfa\xed\xfe": ("little", True),
            b"\xfe\xed\xfa\xce": ("big", False),
            b"\xfe\xed\xfa\xcf": ("big", True),
        }
        macho_header = macho_magics.get(header[:4])
        if macho_header is None or len(header) < 16:
            raise ArtifactEvidenceError(
                "native extension object header is unsupported",
                reason=REASON_RUNTIME_ARCHITECTURE_MISMATCH,
            )
        byteorder, is_64_bit = macho_header
        cpu_type = int.from_bytes(header[4:8], byteorder)
        architecture = {
            7: "x86",
            12: "arm",
            0x01000007: "x86_64",
            0x0100000C: "aarch64",
        }.get(cpu_type)
        binary_format = "mach-o"
        macho_filetype = int.from_bytes(header[12:16], byteorder)
        if macho_filetype not in {_MH_DYLIB, _MH_BUNDLE}:
            raise ArtifactEvidenceError(
                "native runtime Mach-O file type is unsupported",
                reason=REASON_RUNTIME_ARCHITECTURE_MISMATCH,
            )

    expected_width_64 = architecture in {
        "aarch64",
        "powerpc64",
        "riscv64",
        "s390x",
        "x86_64",
    }
    if architecture is None or is_64_bit != expected_width_64:
        raise ArtifactEvidenceError(
            "native runtime object width disagrees with its architecture",
            reason=REASON_RUNTIME_ARCHITECTURE_MISMATCH,
        )

    expected_format = _expected_target_format(target_triple)
    expected_architecture = _expected_target_architecture(target_triple)
    if binary_format != expected_format or architecture != expected_architecture:
        raise ArtifactEvidenceError(
            "native runtime object header does not match the target triple",
            reason=REASON_RUNTIME_ARCHITECTURE_MISMATCH,
        )
    return _BinaryHeader(
        format=binary_format,
        architecture=expected_architecture,
        macho_filetype=macho_filetype,
    )


def _expected_target_format(target_triple: str) -> str:
    triple = target_triple.strip().lower()
    if "apple-darwin" in triple:
        return "mach-o"
    if "linux" in triple:
        return "elf"
    raise ArtifactEvidenceError(
        "native runtime target platform is unsupported",
        reason=REASON_RUNTIME_PLATFORM_UNSUPPORTED,
    )


def _expected_target_architecture(target_triple: str) -> str:
    arch = target_triple.strip().lower().split("-", 1)[0]
    if arch in {"aarch64", "arm64"}:
        return "aarch64"
    if arch.startswith("arm") or arch.startswith("thumb"):
        return "arm"
    if arch in {"i386", "i486", "i586", "i686", "x86"}:
        return "x86"
    if arch == "x86_64":
        return "x86_64"
    if arch in {"powerpc", "ppc"}:
        return "powerpc"
    if arch in {"powerpc64", "powerpc64le", "ppc64", "ppc64le"}:
        return "powerpc64"
    if arch == "s390x":
        return "s390x"
    if arch == "riscv64gc" or arch == "riscv64":
        return "riscv64"
    raise ArtifactEvidenceError(
        "native runtime target architecture is unsupported",
        reason=REASON_RUNTIME_ARCHITECTURE_MISMATCH,
    )


__all__ = [
    "inspect_native_runtime_inventory",
    "parse_otool_d_output",
    "parse_otool_l_output",
    "parse_readelf_d_output",
    "resolve_installed_native_binary",
]
