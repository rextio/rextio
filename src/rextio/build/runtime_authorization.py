"""Fail-closed runtime authorization for the first narrow Full C6 profile.

This module turns the C6.4, C6.8, and C6.9 *observations* into one bounded
runtime receipt.  It deliberately supports only the two profiles for which
the loader can be inspected without guessing:

* ``aarch64-apple-darwin`` / Mach-O
* ``x86_64-unknown-linux-gnu`` / ELF

The production entry point always uses fresh native loader and binary
inspection.  Dependency injection exists only behind an explicitly test-only
entry point whose receipts are marked ineligible for Full C6 authorization.
The native implementation uses dyld APIs on macOS and ``/proc/self/maps`` on
Linux.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
import ctypes
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import subprocess
import sys

from rextio.artifacts.evidence import (
    NativeRuntimeInventory,
    NativeRuntimePathResolutionInventory,
    NativeRuntimeTransitiveClosureInventory,
    canonical_json_bytes,
    sha256_hex,
)
from rextio.artifacts.full_authorization import FULL_C6_SCOPE
from rextio.build.runtime_closure import (
    NativeRuntimeTransitiveClosureObservation,
    verify_native_runtime_transitive_closure,
)
from rextio.build.runtime_resolution import (
    NativeRuntimePathResolutionObservation,
    parse_elf_load_plan,
    parse_macho_load_commands,
    verify_native_runtime_path_resolution,
)


RUNTIME_AUTHORIZATION_KIND = "native-runtime-authorization"
RUNTIME_AUTHORIZATION_SCOPE = FULL_C6_SCOPE
RUNTIME_AUTHORIZATION_AUTHORITY = "verification-receipt-only"
RUNTIME_AUTHORIZATION_SCHEMA_VERSION = 2

RUNTIME_VERIFICATION_NATIVE_FRESH = "native-fresh"
RUNTIME_VERIFICATION_INJECTED_TEST_ONLY = "injected-test-only"

RUNTIME_AUTHORIZED = "authorized"
RUNTIME_DENIED = "denied"
RUNTIME_OUT_OF_SCOPE = "out-of-scope"

REASON_AUTHORIZED = "runtime-authorization-complete"
REASON_OUT_OF_SCOPE = "runtime-authorization-profile-out-of-scope"
REASON_STATIC_INVALID = "runtime-static-observation-invalid"
REASON_LOAD_CONSTRUCT = "runtime-load-construct-forbidden"
REASON_IMPORTED_SYMBOL = "runtime-imported-symbol-forbidden"
REASON_PLATFORM_BASE = "runtime-platform-base-mismatch"
REASON_PROBE_FAILED = "runtime-load-probe-failed"
REASON_LOAD_SET = "runtime-loaded-image-set-mismatch"

MAX_RUNTIME_IMAGE_BYTES = 1024 * 1024 * 1024
MAX_RUNTIME_IMAGES = 2048
MAX_RUNTIME_PATH_CHARS = 4096
MAX_INSPECTOR_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_INSPECTOR_TOKENS = 4096

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SUPPORTED_PROFILES: dict[str, tuple[str, str, str]] = {
    "aarch64-apple-darwin": ("darwin", "mach-o", "aarch64"),
    "x86_64-unknown-linux-gnu": ("linux", "elf", "x86_64"),
}
_FORBIDDEN_MACHO_COMMANDS = frozenset(
    {
        "LC_LAZY_LOAD_DYLIB",
        "LC_LOAD_UPWARD_DYLIB",
        "LC_LOAD_WEAK_DYLIB",
        "LC_REEXPORT_DYLIB",
        "LC_RPATH",
    }
)
_FORBIDDEN_ELF_TAGS = frozenset(
    {"AUDIT", "DEPAUDIT", "FILTER", "AUXILIARY", "RPATH", "RUNPATH"}
)
_FORBIDDEN_DYNAMIC_SYMBOL_PARTS = ("dlopen", "dlmopen", "dlsym", "dlvsym")
_SAFE_DEPENDENCY_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$")
_SAFE_ELF_IMPORTED_SYMBOL = re.compile(
    r"^[^@()\s]{1,512}(?:@[A-Za-z0-9_][A-Za-z0-9_.+-]{0,254})?$"
)
_SAFE_MACHO_IMPORTED_SYMBOL = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]{0,511}$")
_MACHO_MAGIC_64_LE = 0xFEEDFACF
_MACHO_CPU_TYPE_ARM64 = 0x0100000C
_MACHO_FILETYPE_DYLIB = 0x6
_MACHO_FILETYPE_BUNDLE = 0x8
_MACHO_LC_SYMTAB = 0x2
_MACHO_LC_DYSYMTAB = 0xB
_MACHO_LC_LOAD_DYLIB = 0xC
_MACHO_LC_LOAD_WEAK_DYLIB = 0x80000018
_MACHO_LC_REEXPORT_DYLIB = 0x8000001F
_MACHO_LC_LOAD_UPWARD_DYLIB = 0x80000023
_MACHO_DYNAMIC_LOOKUP_ORDINAL = 0xFE
_MACHO_EXECUTABLE_ORDINAL = 0xFF
_MACHO_N_EXT = 0x01
_MACHO_N_PEXT = 0x10
_MACHO_N_STAB = 0xE0
_MACHO_N_TYPE = 0x0E
_MACHO_N_UNDF = 0x00
_MACHO_N_WEAK_REF = 0x0040
_MACHO_MAX_BINARY_BYTES = 512 * 1024 * 1024
_LINUX_LOADER_ENVIRONMENT = frozenset(
    {
        "GLIBC_TUNABLES",
        "LD_ASSUME_KERNEL",
        "LD_AUDIT",
        "LD_BIND_NOW",
        "LD_CONFIG_FILE",
        "LD_DEBUG",
        "LD_DEBUG_OUTPUT",
        "LD_DYNAMIC_WEAK",
        "LD_HWCAP_MASK",
        "LD_LIBRARY_PATH",
        "LD_LIBRARY_PATH_32",
        "LD_LIBRARY_PATH_64",
        "LD_ORIGIN_PATH",
        "LD_PRELOAD",
        "LD_PROFILE",
        "LD_SHOW_AUXV",
        "LD_USE_LOAD_BIAS",
    }
)
_LINUX_TRUSTED_SYSTEM_ROOTS = (
    "/lib",
    "/lib32",
    "/lib64",
    "/usr/lib",
    "/usr/lib32",
    "/usr/lib64",
)
_DARWIN_TRUSTED_SYSTEM_ROOTS = ("/usr/lib", "/System/Library")

SnapshotCollector = Callable[[], "RuntimeImageSnapshot"]
LoadCommandInspector = Callable[[Path, str], "RuntimeLoadCommandInspection"]
SymbolInspector = Callable[[Path, str], Sequence[str]]
ImportAction = Callable[[], object]


class RuntimeAuthorizationError(RuntimeError):
    """A low-level runtime identity or inspection operation failed closed."""


@dataclass(frozen=True, slots=True)
class _ElfImportedSymbol:
    """One exact GNU ``readelf --dyn-syms`` undefined-symbol record."""

    symbol: str
    version_index: int | None
    symbol_type: str
    binding: str
    visibility: str

    def __post_init__(self) -> None:
        if (
            type(self.symbol) is not str
            or _SAFE_ELF_IMPORTED_SYMBOL.fullmatch(self.symbol) is None
            or self.symbol_type not in {"FUNC", "OBJECT", "NOTYPE"}
            or self.binding not in {"GLOBAL", "WEAK"}
            or self.visibility != "DEFAULT"
            or (
                self.version_index is not None
                and (
                    type(self.version_index) is not int
                    or isinstance(self.version_index, bool)
                    or not 1 <= self.version_index <= 0xFFFF
                )
            )
            or (("@" in self.symbol) != (self.version_index is not None))
        ):
            raise ValueError("ELF imported-symbol record is invalid")

    @property
    def canonical_token(self) -> str:
        """Preserve the symbol version and GNU version-table index."""
        name = (
            self.symbol
            if self.version_index is None
            else f"{self.symbol} ({self.version_index})"
        )
        return (
            f"{name} [type={self.symbol_type};binding={self.binding};"
            f"visibility={self.visibility}]"
        )


@dataclass(frozen=True, slots=True)
class _MachoImportedSymbol:
    """One exact undefined nlist_64 record from a thin arm64 dylib."""

    symbol: str
    library_ordinal: int
    library_name: str | None
    weak_reference: bool

    def __post_init__(self) -> None:
        if (
            type(self.symbol) is not str
            or _SAFE_MACHO_IMPORTED_SYMBOL.fullmatch(self.symbol) is None
            or type(self.library_ordinal) is not int
            or isinstance(self.library_ordinal, bool)
            or not 1 <= self.library_ordinal <= 0xFF
            or (
                self.library_ordinal == _MACHO_DYNAMIC_LOOKUP_ORDINAL
                and self.library_name is not None
            )
            or (
                self.library_ordinal != _MACHO_DYNAMIC_LOOKUP_ORDINAL
                and (
                    type(self.library_name) is not str
                    or not self.library_name
                    or len(self.library_name) > 4096
                )
            )
            or self.weak_reference is not False
        ):
            raise ValueError("Mach-O imported-symbol record is invalid")


@dataclass(frozen=True, slots=True)
class RuntimeLoadCommandInspection:
    """Fresh direct dependency and loader-construct view of one exact binary."""

    format: str
    dependencies: tuple[str, ...]
    commands: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.format not in {"mach-o", "elf"}:
            raise ValueError("runtime load-command inspection format is invalid")
        if type(self.dependencies) is not tuple or not all(
            type(name) is str and _SAFE_DEPENDENCY_NAME.fullmatch(name)
            for name in self.dependencies
        ):
            raise TypeError("runtime load-command dependencies are invalid")
        if self.dependencies != tuple(sorted(set(self.dependencies))):
            raise ValueError("runtime load-command dependencies are noncanonical")
        canonical_commands = _canonical_inspector_tokens(self.commands)
        if self.commands != canonical_commands:
            raise ValueError("runtime load commands are noncanonical")

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic fresh-inspection representation."""
        return {
            "format": self.format,
            "dependencies": list(self.dependencies),
            "commands": list(self.commands),
        }


@dataclass(frozen=True, slots=True)
class RuntimeLoadedImage:
    """One exact regular native file reported by the process loader."""

    path: str
    device: int
    inode: int
    sha256: str
    size: int

    def __post_init__(self) -> None:
        if type(self.path) is not str or not _is_canonical_absolute_path(self.path):
            raise ValueError("runtime image path is not canonical and absolute")
        if type(self.device) is not int or isinstance(self.device, bool) or self.device < 0:
            raise ValueError("runtime image device is invalid")
        if type(self.inode) is not int or isinstance(self.inode, bool) or self.inode <= 0:
            raise ValueError("runtime image inode is invalid")
        if type(self.sha256) is not str or _SHA256.fullmatch(self.sha256) is None:
            raise ValueError("runtime image sha256 is invalid")
        if (
            type(self.size) is not int
            or isinstance(self.size, bool)
            or self.size < 0
            or self.size > MAX_RUNTIME_IMAGE_BYTES
        ):
            raise ValueError("runtime image size is outside the allowed bound")

    @property
    def inode_key(self) -> tuple[int, int]:
        """Return the loader-wide filesystem identity."""
        return (self.device, self.inode)

    def to_dict(self) -> dict[str, object]:
        """Return the exact deterministic image identity."""
        return {
            "path": self.path,
            "device": self.device,
            "inode": self.inode,
            "sha256": self.sha256,
            "size": self.size,
        }


@dataclass(frozen=True, slots=True)
class RuntimeImageSnapshot:
    """Canonical set of regular native files visible to the process loader."""

    images: tuple[RuntimeLoadedImage, ...]
    platform_images: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if type(self.images) is not tuple or not all(
            type(image) is RuntimeLoadedImage for image in self.images
        ):
            raise TypeError("runtime image snapshot must use the closed image model")
        if len(self.images) > MAX_RUNTIME_IMAGES:
            raise ValueError("runtime image snapshot exceeds the image bound")
        canonical = tuple(sorted(self.images, key=lambda image: image.path))
        if self.images != canonical:
            raise ValueError("runtime image snapshot is not in canonical order")
        paths = tuple(image.path for image in self.images)
        inodes = tuple(image.inode_key for image in self.images)
        if len(paths) != len(set(paths)):
            raise ValueError("runtime image snapshot contains duplicate paths")
        if len(inodes) != len(set(inodes)):
            raise ValueError("runtime image snapshot contains inode aliases")
        if type(self.platform_images) is not tuple or not all(
            type(path) is str and _is_canonical_absolute_path(path)
            for path in self.platform_images
        ):
            raise TypeError("runtime platform image snapshot is invalid")
        if self.platform_images != tuple(sorted(set(self.platform_images))):
            raise ValueError("runtime platform images must be canonical and unique")
        if len(self.images) + len(self.platform_images) > MAX_RUNTIME_IMAGES:
            raise ValueError("runtime image snapshot exceeds the aggregate bound")
        if set(paths) & set(self.platform_images):
            raise ValueError("regular and platform runtime image paths overlap")

    @property
    def digest(self) -> str:
        """Return the canonical exact platform-image identity."""
        return sha256_hex(canonical_json_bytes(self.to_dict()))

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic snapshot representation."""
        return {
            "images": [image.to_dict() for image in self.images],
            "platform_images": list(self.platform_images),
        }


@dataclass(frozen=True, slots=True)
class RuntimeAuthorizationReceipt:
    """Positive receipt for one exact static graph and import-time load set."""

    target_triple: str
    extension: RuntimeLoadedImage
    platform_base_sha256: str
    declared_system_images: tuple[RuntimeLoadedImage, ...]
    declared_system_platform_images: tuple[str, ...]
    newly_loaded_images: tuple[RuntimeLoadedImage, ...]
    newly_loaded_platform_images: tuple[str, ...]
    path_resolution_sha256: str
    transitive_closure_sha256: str
    load_commands_sha256: str
    imported_symbols_sha256: str
    final_snapshot_sha256: str
    verification_mode: str

    def __post_init__(self) -> None:
        if self.target_triple not in _SUPPORTED_PROFILES:
            raise ValueError("runtime authorization receipt target is unsupported")
        if self.verification_mode not in {
            RUNTIME_VERIFICATION_NATIVE_FRESH,
            RUNTIME_VERIFICATION_INJECTED_TEST_ONLY,
        }:
            raise ValueError("runtime authorization verification mode is invalid")
        if type(self.extension) is not RuntimeLoadedImage:
            raise TypeError("runtime authorization extension identity is invalid")
        for value in (
            self.platform_base_sha256,
            self.path_resolution_sha256,
            self.transitive_closure_sha256,
            self.load_commands_sha256,
            self.imported_symbols_sha256,
            self.final_snapshot_sha256,
        ):
            if type(value) is not str or _SHA256.fullmatch(value) is None:
                raise ValueError("runtime authorization receipt digest is invalid")
        for values, label in (
            (self.declared_system_images, "declared system images"),
            (self.newly_loaded_images, "newly loaded images"),
        ):
            if type(values) is not tuple or not all(
                type(image) is RuntimeLoadedImage for image in values
            ):
                raise TypeError(f"runtime authorization {label} are invalid")
            if values != tuple(sorted(values, key=lambda image: image.path)):
                raise ValueError(f"runtime authorization {label} are noncanonical")
        for paths, label in (
            (self.declared_system_platform_images, "declared platform images"),
            (self.newly_loaded_platform_images, "new platform images"),
        ):
            if type(paths) is not tuple or not all(
                type(path) is str and _is_darwin_platform_image_path(path)
                for path in paths
            ):
                raise TypeError(f"runtime authorization {label} are invalid")
            if paths != tuple(sorted(set(paths))):
                raise ValueError(f"runtime authorization {label} are noncanonical")
        if self.target_triple != "aarch64-apple-darwin" and (
            self.declared_system_platform_images or self.newly_loaded_platform_images
        ):
            raise ValueError("non-macOS receipt must not contain platform-cache images")
        declared_image_keys = {
            image.inode_key for image in self.declared_system_images
        } | {self.extension.inode_key}
        if any(
            image.inode_key not in declared_image_keys
            for image in self.newly_loaded_images
        ):
            raise ValueError("runtime receipt contains an undeclared regular image")
        if not set(self.newly_loaded_platform_images).issubset(
            self.declared_system_platform_images
        ):
            raise ValueError("runtime receipt contains an undeclared platform image")

    @property
    def digest(self) -> str:
        """Return the semantic receipt digest consumed by Full C6."""
        return sha256_hex(canonical_json_bytes(self.to_dict()))

    def to_dict(self) -> dict[str, object]:
        """Return the complete positive receipt without caller-set safety flags."""
        return {
            "kind": RUNTIME_AUTHORIZATION_KIND,
            "schema_version": RUNTIME_AUTHORIZATION_SCHEMA_VERSION,
            "scope": RUNTIME_AUTHORIZATION_SCOPE,
            "authority": RUNTIME_AUTHORIZATION_AUTHORITY,
            "target_triple": self.target_triple,
            "extension": self.extension.to_dict(),
            "platform_base_sha256": self.platform_base_sha256,
            "declared_system_images": [
                image.to_dict() for image in self.declared_system_images
            ],
            "declared_system_platform_images": list(
                self.declared_system_platform_images
            ),
            "newly_loaded_images": [image.to_dict() for image in self.newly_loaded_images],
            "newly_loaded_platform_images": list(self.newly_loaded_platform_images),
            "path_resolution_sha256": self.path_resolution_sha256,
            "transitive_closure_sha256": self.transitive_closure_sha256,
            "load_commands_sha256": self.load_commands_sha256,
            "imported_symbols_sha256": self.imported_symbols_sha256,
            "final_snapshot_sha256": self.final_snapshot_sha256,
            "verification_mode": self.verification_mode,
            "complete_for_scope": True,
            "distribution_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class RuntimeAuthorizationResult:
    """Closed, fixed-reason outcome; only an authorized result has a receipt."""

    status: str
    reason: str
    receipt: RuntimeAuthorizationReceipt | None = None

    def __post_init__(self) -> None:
        allowed = {
            RUNTIME_AUTHORIZED: {REASON_AUTHORIZED},
            RUNTIME_OUT_OF_SCOPE: {REASON_OUT_OF_SCOPE},
            RUNTIME_DENIED: {
                REASON_STATIC_INVALID,
                REASON_LOAD_CONSTRUCT,
                REASON_IMPORTED_SYMBOL,
                REASON_PLATFORM_BASE,
                REASON_PROBE_FAILED,
                REASON_LOAD_SET,
            },
        }
        if self.status not in allowed or self.reason not in allowed[self.status]:
            raise ValueError("runtime authorization result is outside the closed vocabulary")
        if self.status == RUNTIME_AUTHORIZED:
            if type(self.receipt) is not RuntimeAuthorizationReceipt:
                raise TypeError("authorized runtime result requires an exact receipt")
        elif self.receipt is not None:
            raise ValueError("non-authorized runtime result must not carry a receipt")

    @property
    def authorized(self) -> bool:
        """Return whether the narrow runtime hard gate succeeded."""
        return self.status == RUNTIME_AUTHORIZED

    @property
    def distribution_authorized(self) -> bool:
        """A component runtime receipt never grants distribution authority."""
        return False

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic closed result."""
        return {
            "kind": RUNTIME_AUTHORIZATION_KIND,
            "schema_version": RUNTIME_AUTHORIZATION_SCHEMA_VERSION,
            "scope": RUNTIME_AUTHORIZATION_SCOPE,
            "authority": RUNTIME_AUTHORIZATION_AUTHORITY,
            "status": self.status,
            "reason": self.reason,
            "authorized": self.authorized,
            "distribution_authorized": False,
            "receipt": None if self.receipt is None else self.receipt.to_dict(),
        }


def capture_runtime_loaded_image(path: Path | str) -> RuntimeLoadedImage:
    """Securely capture one lexical, non-symlink regular file through one fd."""
    text = os.fspath(path)
    if type(text) is not str or not _is_canonical_absolute_path(text):
        raise RuntimeAuthorizationError("runtime image path is unsafe")
    candidate = Path(text)
    _require_no_symlink_components(candidate)
    try:
        linked = candidate.lstat()
    except OSError as exc:
        raise RuntimeAuthorizationError("runtime image is unavailable") from exc
    if not stat.S_ISREG(linked.st_mode) or linked.st_nlink != 1:
        raise RuntimeAuthorizationError("runtime image is not an unaliased regular file")
    if linked.st_size < 0 or linked.st_size > MAX_RUNTIME_IMAGE_BYTES:
        raise RuntimeAuthorizationError("runtime image size is outside the bound")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(candidate, flags)
    except OSError as exc:
        raise RuntimeAuthorizationError("runtime image cannot be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if not _same_file_stamp(linked, opened) or not stat.S_ISREG(opened.st_mode):
            raise RuntimeAuthorizationError("runtime image changed before capture")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        final_opened = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        final_linked = candidate.lstat()
    except OSError as exc:
        raise RuntimeAuthorizationError("runtime image changed after capture") from exc
    if not _same_file_stamp(opened, final_opened) or not _same_file_stamp(
        final_opened, final_linked
    ):
        raise RuntimeAuthorizationError("runtime image changed during capture")
    return RuntimeLoadedImage(
        path=text,
        device=final_opened.st_dev,
        inode=final_opened.st_ino,
        sha256=digest.hexdigest(),
        size=final_opened.st_size,
    )


def capture_runtime_image_snapshot(
    paths: Iterable[Path | str],
) -> RuntimeImageSnapshot:
    """Capture and canonicalize loader-reported paths, rejecting inode aliases."""
    unique_paths: set[str] = set()
    for value in paths:
        text = os.fspath(value)
        if type(text) is not str:
            raise RuntimeAuthorizationError("runtime loader path is not text")
        unique_paths.add(text)
        if len(unique_paths) > MAX_RUNTIME_IMAGES:
            raise RuntimeAuthorizationError("runtime loader image count exceeds the bound")
    images = tuple(
        sorted(
            (capture_runtime_loaded_image(path) for path in unique_paths),
            key=lambda image: image.path,
        )
    )
    try:
        return RuntimeImageSnapshot(images=images)
    except (TypeError, ValueError) as exc:
        raise RuntimeAuthorizationError("runtime loader image set is ambiguous") from exc


def _capture_native_runtime_snapshot(
    paths: Iterable[Path | str],
    *,
    allow_darwin_platform_images: bool,
) -> RuntimeImageSnapshot:
    """Capture regular images and bind macOS shared-cache names separately."""
    unique_paths: set[str] = set()
    for value in paths:
        text = os.fspath(value)
        if type(text) is not str or not _is_canonical_absolute_path(text):
            raise RuntimeAuthorizationError("native loader image path is unsafe")
        unique_paths.add(text)
        if len(unique_paths) > MAX_RUNTIME_IMAGES:
            raise RuntimeAuthorizationError("native loader image count exceeds the bound")

    regular: list[RuntimeLoadedImage] = []
    platform_images: list[str] = []
    for path in sorted(unique_paths):
        try:
            Path(path).lstat()
        except FileNotFoundError:
            if allow_darwin_platform_images and _is_darwin_platform_image_path(path):
                platform_images.append(path)
                continue
            raise RuntimeAuthorizationError("native loader image is unavailable") from None
        except OSError as exc:
            raise RuntimeAuthorizationError("native loader image is unavailable") from exc
        regular.append(capture_runtime_loaded_image(path))
    try:
        return RuntimeImageSnapshot(
            images=tuple(regular),
            platform_images=tuple(platform_images),
        )
    except (TypeError, ValueError) as exc:
        raise RuntimeAuthorizationError("native loader image set is ambiguous") from exc


def collect_loaded_runtime_images(target_triple: str) -> RuntimeImageSnapshot:
    """Capture regular loader images using the native supported platform API."""
    profile = _SUPPORTED_PROFILES.get(target_triple)
    if profile is None:
        raise RuntimeAuthorizationError("runtime platform is unsupported")
    platform, _, _ = profile
    if platform == "darwin":
        if sys.platform != "darwin":
            raise RuntimeAuthorizationError("dyld image APIs are unavailable")
        paths = _darwin_loaded_image_paths()
    else:
        if not sys.platform.startswith("linux"):
            raise RuntimeAuthorizationError("Linux process maps are unavailable")
        paths = _linux_loaded_image_paths()
    return _capture_native_runtime_snapshot(
        paths,
        allow_darwin_platform_images=platform == "darwin",
    )


def authorize_native_runtime(
    *,
    target_triple: str,
    expected_python_root: Path,
    extension_path: Path,
    runtime_inventory: NativeRuntimeInventory,
    path_resolution: NativeRuntimePathResolutionObservation,
    transitive_closure: NativeRuntimeTransitiveClosureObservation,
    platform_base: RuntimeImageSnapshot,
    declared_system_images: tuple[RuntimeLoadedImage, ...],
    import_action: ImportAction,
    declared_system_platform_images: tuple[str, ...] = (),
) -> RuntimeAuthorizationResult:
    """Authorize one exact extension import using only fresh native evidence.

    Production callers cannot inject loader snapshots or binary inspectors.
    That separation is part of the Full C6 authority boundary, not merely an
    API convenience.
    """
    return _authorize_native_runtime(
        target_triple=target_triple,
        expected_python_root=expected_python_root,
        extension_path=extension_path,
        runtime_inventory=runtime_inventory,
        path_resolution=path_resolution,
        transitive_closure=transitive_closure,
        platform_base=platform_base,
        declared_system_images=declared_system_images,
        import_action=import_action,
        declared_system_platform_images=declared_system_platform_images,
        snapshot_collector=lambda: collect_loaded_runtime_images(target_triple),
        load_command_inspector=_inspect_load_commands,
        symbol_inspector=_inspect_imported_symbols,
        verification_mode=RUNTIME_VERIFICATION_NATIVE_FRESH,
    )


def authorize_native_runtime_for_testing(
    *,
    target_triple: str,
    expected_python_root: Path,
    extension_path: Path,
    runtime_inventory: NativeRuntimeInventory,
    path_resolution: NativeRuntimePathResolutionObservation,
    transitive_closure: NativeRuntimeTransitiveClosureObservation,
    platform_base: RuntimeImageSnapshot,
    declared_system_images: tuple[RuntimeLoadedImage, ...],
    import_action: ImportAction,
    snapshot_collector: SnapshotCollector,
    load_command_inspector: LoadCommandInspector,
    symbol_inspector: SymbolInspector,
    declared_system_platform_images: tuple[str, ...] = (),
) -> RuntimeAuthorizationResult:
    """Exercise the authorization algorithm with explicitly non-native hooks.

    A successful result is stamped ``injected-test-only`` and therefore must
    never satisfy Full C6.  The function is exported only so deterministic unit
    tests can cover denial branches without importing arbitrary binaries.
    """
    if not all(
        callable(value)
        for value in (snapshot_collector, load_command_inspector, symbol_inspector)
    ):
        return _result(RUNTIME_DENIED, REASON_STATIC_INVALID)
    return _authorize_native_runtime(
        target_triple=target_triple,
        expected_python_root=expected_python_root,
        extension_path=extension_path,
        runtime_inventory=runtime_inventory,
        path_resolution=path_resolution,
        transitive_closure=transitive_closure,
        platform_base=platform_base,
        declared_system_images=declared_system_images,
        import_action=import_action,
        declared_system_platform_images=declared_system_platform_images,
        snapshot_collector=snapshot_collector,
        load_command_inspector=load_command_inspector,
        symbol_inspector=symbol_inspector,
        verification_mode=RUNTIME_VERIFICATION_INJECTED_TEST_ONLY,
    )


def _authorize_native_runtime(
    *,
    target_triple: str,
    expected_python_root: Path,
    extension_path: Path,
    runtime_inventory: NativeRuntimeInventory,
    path_resolution: NativeRuntimePathResolutionObservation,
    transitive_closure: NativeRuntimeTransitiveClosureObservation,
    platform_base: RuntimeImageSnapshot,
    declared_system_images: tuple[RuntimeLoadedImage, ...],
    import_action: ImportAction,
    declared_system_platform_images: tuple[str, ...],
    snapshot_collector: SnapshotCollector,
    load_command_inspector: LoadCommandInspector,
    symbol_inspector: SymbolInspector,
    verification_mode: str,
) -> RuntimeAuthorizationResult:
    """Shared closed algorithm for native and visibly test-only evidence.

    Unsupported targets return before touching paths, observations, callbacks,
    or the process loader.  Every supported-target exception is collapsed into
    a fixed denial reason; low-level text and private paths never escape.
    """
    if type(target_triple) is not str or target_triple not in _SUPPORTED_PROFILES:
        return _result(RUNTIME_OUT_OF_SCOPE, REASON_OUT_OF_SCOPE)
    try:
        native_evidence = verification_mode == RUNTIME_VERIFICATION_NATIVE_FRESH
        if verification_mode not in {
            RUNTIME_VERIFICATION_NATIVE_FRESH,
            RUNTIME_VERIFICATION_INJECTED_TEST_ONLY,
        }:
            raise RuntimeAuthorizationError("runtime verification mode is invalid")
        if native_evidence:
            _require_native_host_and_loader_environment(target_triple)
        profile = _SUPPORTED_PROFILES[target_triple]
        path_inventory, closure_inventory = _validate_static_observations(
            target_triple=target_triple,
            profile=profile,
            expected_python_root=expected_python_root,
            runtime_inventory=runtime_inventory,
            path_resolution=path_resolution,
            transitive_closure=transitive_closure,
        )
        extension = _capture_and_bind_extension(
            extension_path=extension_path,
            expected_python_root=expected_python_root,
            runtime_inventory=runtime_inventory,
        )
        base, system_images, system_platform_images = _validate_declared_runtime_set(
            platform_base=platform_base,
            declared_system_images=declared_system_images,
            declared_system_platform_images=declared_system_platform_images,
            extension=extension,
            closure=closure_inventory,
            target_triple=target_triple,
            native_evidence=native_evidence,
        )
    except Exception:
        return _result(RUNTIME_DENIED, REASON_STATIC_INVALID)

    try:
        load_inspection = load_command_inspector(Path(extension.path), target_triple)
        if type(load_inspection) is not RuntimeLoadCommandInspection:
            raise RuntimeAuthorizationError("runtime load inspection model is invalid")
        commands = load_inspection.commands
        expected_dependencies = tuple(
            sorted(dependency.name for dependency in runtime_inventory.dependencies)
        )
        if (
            load_inspection.format != profile[1]
            or load_inspection.dependencies != expected_dependencies
        ):
            return _result(RUNTIME_DENIED, REASON_LOAD_CONSTRUCT)
        if _has_forbidden_load_construct(commands, profile[1]):
            return _result(RUNTIME_DENIED, REASON_LOAD_CONSTRUCT)
        _require_image_unchanged(extension)
    except Exception:
        return _result(RUNTIME_DENIED, REASON_LOAD_CONSTRUCT)

    try:
        symbols = _canonical_inspector_tokens(
            symbol_inspector(Path(extension.path), target_triple)
        )
        if any(_is_forbidden_dynamic_symbol(symbol) for symbol in symbols):
            return _result(RUNTIME_DENIED, REASON_IMPORTED_SYMBOL)
        _require_image_unchanged(extension)
    except Exception:
        return _result(RUNTIME_DENIED, REASON_IMPORTED_SYMBOL)

    try:
        before = snapshot_collector()
        if type(before) is not RuntimeImageSnapshot or before != base:
            return _result(RUNTIME_DENIED, REASON_PLATFORM_BASE)
        import_action()
        after = snapshot_collector()
        if type(after) is not RuntimeImageSnapshot:
            return _result(RUNTIME_DENIED, REASON_PROBE_FAILED)
    except Exception:
        return _result(RUNTIME_DENIED, REASON_PROBE_FAILED)

    try:
        expected_after = _merge_exact_images(base.images, (extension, *system_images))
        expected_platform_after = tuple(
            sorted(set(base.platform_images) | set(system_platform_images))
        )
        if (
            after.images != expected_after
            or after.platform_images != expected_platform_after
        ):
            return _result(RUNTIME_DENIED, REASON_LOAD_SET)
        before_inodes = {image.inode_key for image in before.images}
        newly_loaded = tuple(
            image for image in after.images if image.inode_key not in before_inodes
        )
        newly_loaded_platform = tuple(
            path for path in after.platform_images if path not in set(before.platform_images)
        )
        _require_image_unchanged(extension)
        for image in system_images:
            _require_image_unchanged(image)
    except Exception:
        return _result(RUNTIME_DENIED, REASON_LOAD_SET)

    receipt = RuntimeAuthorizationReceipt(
        target_triple=target_triple,
        extension=extension,
        platform_base_sha256=base.digest,
        declared_system_images=system_images,
        declared_system_platform_images=system_platform_images,
        newly_loaded_images=newly_loaded,
        newly_loaded_platform_images=newly_loaded_platform,
        path_resolution_sha256=sha256_hex(
            canonical_json_bytes(path_inventory.to_dict())
        ),
        transitive_closure_sha256=sha256_hex(
            canonical_json_bytes(closure_inventory.to_dict())
        ),
        load_commands_sha256=sha256_hex(
            canonical_json_bytes(load_inspection.to_dict())
        ),
        imported_symbols_sha256=_token_digest(symbols),
        final_snapshot_sha256=after.digest,
        verification_mode=verification_mode,
    )
    return RuntimeAuthorizationResult(
        status=RUNTIME_AUTHORIZED,
        reason=REASON_AUTHORIZED,
        receipt=receipt,
    )


def _validate_static_observations(
    *,
    target_triple: str,
    profile: tuple[str, str, str],
    expected_python_root: Path,
    runtime_inventory: NativeRuntimeInventory,
    path_resolution: NativeRuntimePathResolutionObservation,
    transitive_closure: NativeRuntimeTransitiveClosureObservation,
) -> tuple[NativeRuntimePathResolutionInventory, NativeRuntimeTransitiveClosureInventory]:
    if type(runtime_inventory) is not NativeRuntimeInventory:
        raise RuntimeAuthorizationError("runtime inventory model is invalid")
    if type(path_resolution) is not NativeRuntimePathResolutionObservation:
        raise RuntimeAuthorizationError("path-resolution observation model is invalid")
    if type(transitive_closure) is not NativeRuntimeTransitiveClosureObservation:
        raise RuntimeAuthorizationError("closure observation model is invalid")
    path_inventory = path_resolution.inventory
    closure = transitive_closure.inventory
    if type(path_inventory) is not NativeRuntimePathResolutionInventory or type(
        closure
    ) is not NativeRuntimeTransitiveClosureInventory:
        raise RuntimeAuthorizationError("runtime serialized model is invalid")
    if not verify_native_runtime_path_resolution(
        path_resolution, expected_python_root=expected_python_root
    ) or not verify_native_runtime_transitive_closure(
        transitive_closure, expected_python_root=expected_python_root
    ):
        raise RuntimeAuthorizationError("runtime observation receipt changed")

    _, expected_format, expected_architecture = profile
    subject = (
        runtime_inventory.wheel_member,
        runtime_inventory.subject_sha256,
        runtime_inventory.subject_size,
    )
    if (
        runtime_inventory.format != expected_format
        or runtime_inventory.architecture != expected_architecture
        or closure.format != expected_format
        or closure.architecture != expected_architecture
        or path_inventory.subject_wheel_member != subject[0]
        or path_inventory.subject_sha256 != subject[1]
        or closure.subject_wheel_member != subject[0]
        or closure.subject_sha256 != subject[1]
        or closure.subject_size != subject[2]
    ):
        raise RuntimeAuthorizationError("runtime subject observations disagree")

    nodes = {node.node_ref: node for node in closure.nodes}
    root = nodes.get(closure.root_node_ref)
    packaged = tuple(node for node in closure.nodes if node.kind == "wheel-member")
    system_nodes = tuple(node for node in closure.nodes if node.kind == "system-logical")
    if root is None or packaged != (root,):
        raise RuntimeAuthorizationError("packaged third-party runtime is forbidden")
    if (
        root.wheel_member != subject[0]
        or root.sha256 != subject[1]
        or root.size != subject[2]
        or root.format != expected_format
    ):
        raise RuntimeAuthorizationError("runtime root binding is invalid")

    records = path_inventory.records
    dependencies = runtime_inventory.dependencies
    if len(records) != len(dependencies) or len(closure.edges) != len(records):
        raise RuntimeAuthorizationError("runtime direct dependency coverage is incomplete")
    records_by_name = {record.dependency_name: record for record in records}
    if len(records_by_name) != len(records):
        raise RuntimeAuthorizationError("runtime direct dependency is ambiguous")
    safe_mechanism = "macho-system" if expected_format == "mach-o" else "elf-system-name"
    for dependency in dependencies:
        record = records_by_name.get(dependency.name)
        if (
            dependency.origin != "system"
            or record is None
            or record.dependency_bom_ref != dependency.bom_ref()
            or record.dependency_origin != "system"
            or record.resolution != "system-logical"
            or record.mechanism != safe_mechanism
        ):
            raise RuntimeAuthorizationError("runtime resolution is search-path-sensitive")

    edge_names: set[str] = set()
    for edge in closure.edges:
        target = nodes.get(edge.target_ref)
        record = records_by_name.get(edge.dependency_name)
        if (
            edge.source_ref != closure.root_node_ref
            or target is None
            or target.kind != "system-logical"
            or target.format != expected_format
            or target.name != edge.dependency_name
            or record is None
            or edge.mechanism != safe_mechanism
            or record.mechanism != edge.mechanism
        ):
            raise RuntimeAuthorizationError("runtime closure edge is unsafe")
        edge_names.add(edge.dependency_name)
    if edge_names != {node.name for node in system_nodes} or edge_names != set(
        records_by_name
    ):
        raise RuntimeAuthorizationError("runtime closure contains orphan nodes")
    return path_inventory, closure


def _capture_and_bind_extension(
    *,
    extension_path: Path,
    expected_python_root: Path,
    runtime_inventory: NativeRuntimeInventory,
) -> RuntimeLoadedImage:
    root = Path(os.path.abspath(expected_python_root))
    expected = root.joinpath(*PurePosixPath(runtime_inventory.wheel_member).parts)
    lexical = Path(os.path.abspath(extension_path))
    if lexical != expected or lexical.name != runtime_inventory.subject_basename:
        raise RuntimeAuthorizationError("extension path is not the observed wheel member")
    image = capture_runtime_loaded_image(lexical)
    if (
        image.sha256 != runtime_inventory.subject_sha256
        or image.size != runtime_inventory.subject_size
    ):
        raise RuntimeAuthorizationError("extension bytes disagree with observations")
    return image


def _validate_declared_runtime_set(
    *,
    platform_base: RuntimeImageSnapshot,
    declared_system_images: tuple[RuntimeLoadedImage, ...],
    declared_system_platform_images: tuple[str, ...],
    extension: RuntimeLoadedImage,
    closure: NativeRuntimeTransitiveClosureInventory,
    target_triple: str,
    native_evidence: bool,
) -> tuple[RuntimeImageSnapshot, tuple[RuntimeLoadedImage, ...], tuple[str, ...]]:
    if type(platform_base) is not RuntimeImageSnapshot:
        raise TypeError("platform base identity is invalid")
    if type(declared_system_images) is not tuple or not all(
        type(image) is RuntimeLoadedImage for image in declared_system_images
    ):
        raise TypeError("declared system image identity is invalid")
    canonical = tuple(sorted(declared_system_images, key=lambda image: image.path))
    if declared_system_images != canonical:
        raise ValueError("declared system images are noncanonical")
    for image in platform_base.images:
        _require_image_unchanged(image)
    for image in canonical:
        _require_image_unchanged(image)
    if type(declared_system_platform_images) is not tuple or not all(
        type(path) is str for path in declared_system_platform_images
    ):
        raise TypeError("declared system platform image identity is invalid")
    platform_canonical = tuple(sorted(set(declared_system_platform_images)))
    if declared_system_platform_images != platform_canonical:
        raise ValueError("declared system platform images are noncanonical")
    if target_triple != "aarch64-apple-darwin" and platform_canonical:
        raise ValueError("platform-cache images are only supported on macOS")
    if not all(_is_darwin_platform_image_path(path) for path in platform_canonical):
        raise ValueError("declared system platform image path is unsafe")
    if target_triple != "aarch64-apple-darwin" and platform_base.platform_images:
        raise ValueError("Linux platform base must contain only regular images")
    if not all(
        _is_darwin_platform_image_path(path) for path in platform_base.platform_images
    ):
        raise ValueError("platform base contains an unsafe logical image")
    system_names = tuple(
        sorted(node.name for node in closure.nodes if node.kind == "system-logical")
    )
    if native_evidence:
        for image in canonical:
            if not _is_trusted_system_image_path(image.path, target_triple):
                raise ValueError("declared system image is outside trusted OS roots")
        declared_regular_names = tuple(
            _native_system_image_name(image, target_triple) for image in canonical
        )
    else:
        declared_regular_names = tuple(Path(image.path).name for image in canonical)
    declared_names = tuple(
        sorted((*declared_regular_names, *(Path(path).name for path in platform_canonical)))
    )
    if declared_names != system_names:
        raise ValueError("declared system images do not bind every logical leaf")
    _merge_exact_images(platform_base.images, (extension, *canonical))
    if extension.inode_key in {image.inode_key for image in platform_base.images}:
        raise ValueError("extension was already part of the platform base")
    if extension.path in set(platform_base.platform_images) | set(platform_canonical):
        raise ValueError("extension aliases a platform image")
    if {image.path for image in canonical} & set(platform_canonical):
        raise ValueError("regular and platform system declarations overlap")
    return platform_base, canonical, platform_canonical


def verify_native_runtime_authorization(
    receipt: RuntimeAuthorizationReceipt,
) -> bool:
    """Freshly revalidate a native receipt at the Full C6 consumption point.

    This verifier intentionally requires the current loader set to equal the
    exact post-import snapshot.  Loading any additional image between runtime
    authorization and the final gate makes the transaction stale and forces a
    new authorization pass.
    """
    try:
        if (
            type(receipt) is not RuntimeAuthorizationReceipt
            or receipt.verification_mode != RUNTIME_VERIFICATION_NATIVE_FRESH
        ):
            return False
        _require_native_host_and_loader_environment(receipt.target_triple)
        if capture_runtime_loaded_image(receipt.extension.path) != receipt.extension:
            return False
        for image in receipt.declared_system_images:
            if (
                not _is_trusted_system_image_path(image.path, receipt.target_triple)
                or capture_runtime_loaded_image(image.path) != image
            ):
                return False
        inspection = _inspect_load_commands(
            Path(receipt.extension.path), receipt.target_triple
        )
        if sha256_hex(canonical_json_bytes(inspection.to_dict())) != (
            receipt.load_commands_sha256
        ):
            return False
        symbols = _canonical_inspector_tokens(
            _inspect_imported_symbols(
                Path(receipt.extension.path), receipt.target_triple
            )
        )
        if _token_digest(symbols) != receipt.imported_symbols_sha256:
            return False
        current = collect_loaded_runtime_images(receipt.target_triple)
        if current.digest != receipt.final_snapshot_sha256:
            return False
        current_by_inode = {image.inode_key: image for image in current.images}
        for image in (receipt.extension, *receipt.declared_system_images):
            if current_by_inode.get(image.inode_key) != image:
                return False
        if not set(receipt.declared_system_platform_images).issubset(
            current.platform_images
        ):
            return False
        return True
    except Exception:
        return False


def _merge_exact_images(
    base: tuple[RuntimeLoadedImage, ...],
    additions: tuple[RuntimeLoadedImage, ...],
) -> tuple[RuntimeLoadedImage, ...]:
    by_inode = {image.inode_key: image for image in base}
    by_path = {image.path: image for image in base}
    for image in additions:
        prior_inode = by_inode.get(image.inode_key)
        prior_path = by_path.get(image.path)
        if prior_inode is not None and prior_inode != image:
            raise RuntimeAuthorizationError("runtime image inode identity changed")
        if prior_path is not None and prior_path != image:
            raise RuntimeAuthorizationError("runtime image path identity changed")
        by_inode[image.inode_key] = image
        by_path[image.path] = image
    if len(by_inode) != len(by_path):
        raise RuntimeAuthorizationError("runtime image set contains an alias")
    return tuple(sorted(by_path.values(), key=lambda image: image.path))


def _require_image_unchanged(expected: RuntimeLoadedImage) -> None:
    if capture_runtime_loaded_image(expected.path) != expected:
        raise RuntimeAuthorizationError("runtime image changed")


def _canonical_inspector_tokens(values: Sequence[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise RuntimeAuthorizationError("runtime inspector result is invalid")
    if len(values) > MAX_INSPECTOR_TOKENS:
        raise RuntimeAuthorizationError("runtime inspector token count exceeds the bound")
    tokens: list[str] = []
    for value in values:
        if (
            type(value) is not str
            or not value
            or len(value) > 1024
            or "\0" in value
            or any(ord(character) < 32 for character in value)
        ):
            raise RuntimeAuthorizationError("runtime inspector token is unsafe")
        tokens.append(value)
    return tuple(sorted(set(tokens)))


def _has_forbidden_load_construct(commands: tuple[str, ...], format_name: str) -> bool:
    forbidden = (
        _FORBIDDEN_MACHO_COMMANDS if format_name == "mach-o" else _FORBIDDEN_ELF_TAGS
    )
    return bool(set(commands) & forbidden)


def _is_forbidden_dynamic_symbol(symbol: str) -> bool:
    # GNU readelf appends a separate version-table index, for example
    # ``dlsym@GLIBC_2.34 (2)``.  Inspect the lookup name rather than the
    # suffix so a version or index cannot hide a forbidden loader primitive.
    raw_symbol = symbol.split(" ", 1)[0]
    normalized = raw_symbol.split("@", 1)[0].lstrip("_").casefold()
    return any(part in normalized for part in _FORBIDDEN_DYNAMIC_SYMBOL_PARTS)


def _inspect_load_commands(
    path: Path, target_triple: str
) -> RuntimeLoadCommandInspection:
    if target_triple == "aarch64-apple-darwin":
        output = _run_inspector(("/usr/bin/otool", "-l", str(path)))
        plan = parse_macho_load_commands(output)
        dependencies: list[str] = []
        for dependency in plan.dependencies:
            if not dependency.startswith(("/usr/lib/", "/System/Library/")):
                raise RuntimeAuthorizationError(
                    "Mach-O direct dependency is not a system ABI leaf"
                )
            dependencies.append(PurePosixPath(dependency).name)
        commands = tuple(
            match.group(1)
            for line in output.splitlines()
            if (match := re.fullmatch(r"\s*cmd (LC_[A-Z0-9_]+)\s*", line))
        )
        return RuntimeLoadCommandInspection(
            format="mach-o",
            dependencies=tuple(sorted(set(dependencies))),
            commands=_canonical_inspector_tokens(commands),
        )
    output = _run_inspector(("/usr/bin/readelf", "-W", "-d", str(path)))
    elf_plan = parse_elf_load_plan(output)
    commands = tuple(
        match.group(1)
        for line in output.splitlines()
        if (match := re.match(r"^\s*0x[0-9a-fA-F]+\s+\(([A-Z0-9_]+)\)", line))
    )
    return RuntimeLoadCommandInspection(
        format="elf",
        dependencies=tuple(sorted(set(elf_plan.dependencies))),
        commands=_canonical_inspector_tokens(commands),
    )


def _inspect_imported_symbols(path: Path, target_triple: str) -> tuple[str, ...]:
    if target_triple == "aarch64-apple-darwin":
        return tuple(
            record.symbol for record in _inspect_macho_imported_symbol_records(path)
        )
    output = _run_inspector(("/usr/bin/readelf", "-W", "--dyn-syms", str(path)))
    return tuple(
        record.canonical_token for record in _parse_elf_imported_symbols(output)
    )


def _parse_elf_imported_symbols(output: str) -> tuple[_ElfImportedSymbol, ...]:
    """Parse one GNU ``.dynsym`` table without losing binding metadata."""
    if type(output) is not str:
        raise RuntimeAuthorizationError("ELF imported-symbol output is invalid")
    table_names = tuple(
        match.group(1)
        for line in output.splitlines()
        if (
            match := re.fullmatch(
                r"\s*Symbol table '([^']+)' contains [0-9]+ entr(?:y|ies):\s*",
                line,
            )
        )
    )
    if table_names and table_names != (".dynsym",):
        raise RuntimeAuthorizationError(
            "ELF imported-symbol output is not one dynamic symbol table"
        )
    symbols: list[_ElfImportedSymbol] = []
    for line in output.splitlines():
        stripped = line.strip()
        if re.match(r"^\d+:\s", stripped) is None:
            continue
        fields = stripped.split(maxsplit=7)
        if fields == [
            "0:",
            "0000000000000000",
            "0",
            "NOTYPE",
            "LOCAL",
            "DEFAULT",
            "UND",
        ]:
            # GNU readelf renders the mandatory ELF null symbol as a blank
            # undefined row.  It is structural metadata, not an import.
            continue
        if len(fields) != 8:
            raise RuntimeAuthorizationError("ELF imported-symbol row is invalid")
        if fields[6] != "UND":
            continue
        ordinal, value, size, symbol_type, binding, visibility, _index, raw_name = (
            fields
        )
        if (
            re.fullmatch(r"[1-9][0-9]*:", ordinal) is None
            or re.fullmatch(r"0+", value) is None
            or size != "0"
        ):
            raise RuntimeAuthorizationError("ELF imported-symbol row is invalid")
        match = re.fullmatch(
            r"(?P<symbol>\S+?)(?:\s+\((?P<version_index>[1-9][0-9]{0,4})\))?",
            raw_name,
        )
        if match is None:
            raise RuntimeAuthorizationError("ELF imported-symbol name is invalid")
        version_index_text = match.group("version_index")
        try:
            symbols.append(
                _ElfImportedSymbol(
                    symbol=match.group("symbol"),
                    version_index=(
                        None
                        if version_index_text is None
                        else int(version_index_text, 10)
                    ),
                    symbol_type=symbol_type,
                    binding=binding,
                    visibility=visibility,
                )
            )
        except ValueError as exc:
            raise RuntimeAuthorizationError(
                "ELF imported-symbol name is invalid"
            ) from exc
    return tuple(symbols)


def _inspect_macho_imported_symbol_records(
    path: Path,
) -> tuple[_MachoImportedSymbol, ...]:
    return _parse_macho_imported_symbols(_read_exact_macho_bytes(path))


def _read_exact_macho_bytes(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_size > _MACHO_MAX_BINARY_BYTES
            or before.st_nlink != 1
        ):
            raise RuntimeAuthorizationError("Mach-O subject is not an exact file")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise RuntimeAuthorizationError("Mach-O subject was truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise RuntimeAuthorizationError("Mach-O subject grew during capture")
        after = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino, before.st_mode, before.st_size)
            != (after.st_dev, after.st_ino, after.st_mode, after.st_size)
        ):
            raise RuntimeAuthorizationError("Mach-O subject changed during capture")
        return b"".join(chunks)
    except RuntimeAuthorizationError:
        raise
    except (OSError, ValueError) as exc:
        raise RuntimeAuthorizationError("Mach-O subject could not be captured") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _parse_macho_imported_symbols(data: bytes) -> tuple[_MachoImportedSymbol, ...]:
    if type(data) is not bytes or len(data) < 32:
        raise RuntimeAuthorizationError("Mach-O header is unavailable")
    try:
        magic, cpu_type, _cpu_subtype, file_type, command_count, command_size, _flags, _reserved = struct.unpack_from(
            "<IiiIIIII", data, 0
        )
    except struct.error as exc:
        raise RuntimeAuthorizationError("Mach-O header is malformed") from exc
    if (
        magic != _MACHO_MAGIC_64_LE
        or cpu_type != _MACHO_CPU_TYPE_ARM64
        or file_type != _MACHO_FILETYPE_DYLIB
        or not 1 <= command_count <= 4096
        or command_size < command_count * 8
        or 32 + command_size > len(data)
    ):
        raise RuntimeAuthorizationError(
            "Mach-O subject is not a thin arm64 64-bit dylib"
        )

    symtab: tuple[int, int, int, int] | None = None
    dysymtab: tuple[int, int] | None = None
    dylibraries: list[tuple[int, str]] = []
    offset = 32
    commands_end = 32 + command_size
    dylib_commands = {
        _MACHO_LC_LOAD_DYLIB,
        _MACHO_LC_LOAD_WEAK_DYLIB,
        _MACHO_LC_REEXPORT_DYLIB,
        _MACHO_LC_LOAD_UPWARD_DYLIB,
    }
    for _index in range(command_count):
        if offset + 8 > commands_end:
            raise RuntimeAuthorizationError("Mach-O load-command table is truncated")
        command, size = struct.unpack_from("<II", data, offset)
        if size < 8 or size % 8 or offset + size > commands_end:
            raise RuntimeAuthorizationError("Mach-O load command is malformed")
        if command == _MACHO_LC_SYMTAB:
            if symtab is not None or size != 24:
                raise RuntimeAuthorizationError("Mach-O symbol table is ambiguous")
            _cmd, _size, symbol_offset, symbol_count, string_offset, string_size = (
                struct.unpack_from("<IIIIII", data, offset)
            )
            symtab = (symbol_offset, symbol_count, string_offset, string_size)
        elif command == _MACHO_LC_DYSYMTAB:
            if dysymtab is not None or size != 80:
                raise RuntimeAuthorizationError(
                    "Mach-O dynamic symbol table is ambiguous"
                )
            fields = struct.unpack_from("<20I", data, offset)
            dysymtab = (fields[6], fields[7])
        elif command in dylib_commands:
            if size < 24:
                raise RuntimeAuthorizationError("Mach-O dylib command is malformed")
            name_offset = struct.unpack_from("<I", data, offset + 8)[0]
            if name_offset < 24 or name_offset >= size:
                raise RuntimeAuthorizationError("Mach-O dylib name offset is invalid")
            name = _macho_c_string(data, offset + name_offset, offset + size)
            dylibraries.append((command, name))
        offset += size
    if offset != commands_end or symtab is None or dysymtab is None:
        raise RuntimeAuthorizationError("Mach-O symbol metadata is incomplete")

    symbol_offset, symbol_count, string_offset, string_size = symtab
    undefined_index, undefined_count = dysymtab
    if (
        not 1 <= symbol_count <= 1_000_000
        or not 1 <= undefined_count <= MAX_INSPECTOR_TOKENS
        or undefined_index > symbol_count
        or undefined_count > symbol_count - undefined_index
        or symbol_offset < commands_end
        or symbol_offset + symbol_count * 16 > len(data)
        or string_offset < commands_end
        or not 1 <= string_size <= len(data)
        or string_offset + string_size > len(data)
        or not (
            symbol_offset + symbol_count * 16 <= string_offset
            or string_offset + string_size <= symbol_offset
        )
    ):
        raise RuntimeAuthorizationError("Mach-O symbol-table bounds are invalid")

    imports: list[_MachoImportedSymbol] = []
    for symbol_index in range(undefined_index, undefined_index + undefined_count):
        entry_offset = symbol_offset + symbol_index * 16
        string_index, symbol_type, section, description, value = struct.unpack_from(
            "<IBBHQ", data, entry_offset
        )
        if (
            symbol_type & _MACHO_N_EXT == 0
            or symbol_type & _MACHO_N_PEXT
            or symbol_type & _MACHO_N_STAB
            or symbol_type & _MACHO_N_TYPE != _MACHO_N_UNDF
            or section != 0
            or value != 0
            or description & 0x7 not in {0, 1}
            or description & _MACHO_N_WEAK_REF
            or string_index == 0
            or string_index >= string_size
        ):
            raise RuntimeAuthorizationError("Mach-O undefined symbol is malformed")
        symbol = _macho_c_string(
            data,
            string_offset + string_index,
            string_offset + string_size,
        )
        ordinal = (description >> 8) & 0xFF
        if ordinal == _MACHO_DYNAMIC_LOOKUP_ORDINAL:
            library_name = None
        elif ordinal in {0, 0xFD, _MACHO_EXECUTABLE_ORDINAL}:
            raise RuntimeAuthorizationError(
                "Mach-O undefined symbol has an unsupported library ordinal"
            )
        elif ordinal <= len(dylibraries):
            command, library_name = dylibraries[ordinal - 1]
            if command != _MACHO_LC_LOAD_DYLIB:
                raise RuntimeAuthorizationError(
                    "Mach-O undefined symbol uses a non-strong dependency"
                )
        else:
            raise RuntimeAuthorizationError(
                "Mach-O undefined symbol library ordinal is out of bounds"
            )
        try:
            imports.append(
                _MachoImportedSymbol(
                    symbol=symbol,
                    library_ordinal=ordinal,
                    library_name=library_name,
                    weak_reference=bool(description & _MACHO_N_WEAK_REF),
                )
            )
        except ValueError as exc:
            raise RuntimeAuthorizationError(
                "Mach-O undefined symbol identity is invalid"
            ) from exc
    canonical = tuple(
        sorted(
            imports,
            key=lambda item: (
                item.symbol,
                item.library_ordinal,
                item.library_name or "",
            ),
        )
    )
    if len(canonical) != len(
        {(item.symbol, item.library_ordinal, item.library_name) for item in canonical}
    ):
        raise RuntimeAuthorizationError("Mach-O undefined symbols are ambiguous")
    return canonical


def _macho_c_string(data: bytes, start: int, limit: int) -> str:
    if start < 0 or start >= limit or limit > len(data):
        raise RuntimeAuthorizationError("Mach-O string offset is invalid")
    end = data.find(b"\0", start, limit)
    if end < 0 or end == start:
        raise RuntimeAuthorizationError("Mach-O string is unterminated")
    try:
        value = data[start:end].decode("ascii")
    except UnicodeError as exc:
        raise RuntimeAuthorizationError("Mach-O string is not ASCII") from exc
    if len(value) > 4096 or any(ord(character) < 32 for character in value):
        raise RuntimeAuthorizationError("Mach-O string is invalid")
    return value


def _native_system_image_name(
    image: RuntimeLoadedImage, target_triple: str
) -> str:
    """Return the loader identity exported by one trusted system image."""
    if target_triple == "aarch64-apple-darwin":
        return Path(image.path).name
    output = _run_inspector(("/usr/bin/readelf", "-W", "-d", image.path))
    sonames = tuple(
        match.group(1)
        for line in output.splitlines()
        if (match := re.search(r"\(SONAME\).*\[([^\]]+)\]", line))
    )
    if (
        len(sonames) != 1
        or _SAFE_DEPENDENCY_NAME.fullmatch(sonames[0]) is None
    ):
        raise RuntimeAuthorizationError("system ELF SONAME is unavailable")
    return sonames[0]


def _run_inspector(command: tuple[str, ...]) -> str:
    try:
        completed = subprocess.run(
            command,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10.0,
            env={"LC_ALL": "C", "LANG": "C", "PATH": "/usr/bin:/bin"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeAuthorizationError("runtime inspector failed") from exc
    if (
        completed.returncode != 0
        or len(completed.stdout) > MAX_INSPECTOR_OUTPUT_BYTES
        or len(completed.stderr) > MAX_INSPECTOR_OUTPUT_BYTES
    ):
        raise RuntimeAuthorizationError("runtime inspector failed")
    try:
        return completed.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeAuthorizationError("runtime inspector output is not UTF-8") from exc


def _darwin_loaded_image_paths() -> tuple[str, ...]:
    process = ctypes.CDLL(None)
    try:
        image_count = process._dyld_image_count
        image_name = process._dyld_get_image_name
    except AttributeError as exc:
        raise RuntimeAuthorizationError("dyld image APIs are unavailable") from exc
    image_count.argtypes = []
    image_count.restype = ctypes.c_uint32
    image_name.argtypes = [ctypes.c_uint32]
    image_name.restype = ctypes.c_char_p
    count = int(image_count())
    if count < 0 or count > MAX_RUNTIME_IMAGES:
        raise RuntimeAuthorizationError("dyld image count exceeds the bound")
    result: list[str] = []
    for index in range(count):
        raw = image_name(index)
        if raw is None:
            raise RuntimeAuthorizationError("dyld returned an empty image path")
        try:
            value = os.fsdecode(raw)
        except UnicodeError as exc:
            raise RuntimeAuthorizationError("dyld image path cannot be decoded") from exc
        if value.startswith("/"):
            result.append(value)
    return tuple(result)


def _linux_loaded_image_paths() -> tuple[str, ...]:
    try:
        data = Path("/proc/self/maps").read_bytes()
    except OSError as exc:
        raise RuntimeAuthorizationError("Linux process maps are unavailable") from exc
    if len(data) > MAX_INSPECTOR_OUTPUT_BYTES:
        raise RuntimeAuthorizationError("Linux process maps exceed the bound")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeAuthorizationError("Linux process maps are not UTF-8") from exc
    paths: list[str] = []
    for line in text.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) != 6 or "x" not in fields[1]:
            continue
        path = fields[5]
        if "memfd:" in path or path.endswith(" (deleted)"):
            raise RuntimeAuthorizationError(
                "Linux loader contains a deleted or memory-backed image"
            )
        if path.startswith("/"):
            try:
                resolved = str(Path(path).resolve(strict=True))
            except (OSError, RuntimeError) as exc:
                raise RuntimeAuthorizationError(
                    "Linux loader image cannot be resolved"
                ) from exc
            if not _is_canonical_absolute_path(resolved):
                raise RuntimeAuthorizationError("Linux loader image path is unsafe")
            paths.append(resolved)
    return tuple(paths)


def _require_native_host_and_loader_environment(target_triple: str) -> None:
    platform_name, _, architecture = _SUPPORTED_PROFILES[target_triple]
    if platform_name == "darwin":
        if sys.platform != "darwin" or os.uname().machine not in {"arm64", "aarch64"}:
            raise RuntimeAuthorizationError("runtime target does not match the native host")
        if any(name.startswith("DYLD_") for name in os.environ) or any(
            name in os.environ for name in _LINUX_LOADER_ENVIRONMENT
        ):
            raise RuntimeAuthorizationError("loader-affecting environment is present")
    else:
        if not sys.platform.startswith("linux") or os.uname().machine not in {
            "x86_64",
            "amd64",
        }:
            raise RuntimeAuthorizationError("runtime target does not match the native host")
        if architecture != "x86_64" or any(
            name in os.environ for name in _LINUX_LOADER_ENVIRONMENT
        ):
            raise RuntimeAuthorizationError("loader-affecting environment is present")


def _is_trusted_system_image_path(path: str, target_triple: str) -> bool:
    if not _is_canonical_absolute_path(path):
        return False
    roots = (
        _DARWIN_TRUSTED_SYSTEM_ROOTS
        if target_triple == "aarch64-apple-darwin"
        else _LINUX_TRUSTED_SYSTEM_ROOTS
    )
    candidate = PurePosixPath(path)
    return any(candidate.is_relative_to(PurePosixPath(root)) for root in roots)


def _token_digest(tokens: tuple[str, ...]) -> str:
    return hashlib.sha256(
        json.dumps(tokens, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _is_canonical_absolute_path(value: str) -> bool:
    return bool(
        value
        and len(value) <= MAX_RUNTIME_PATH_CHARS
        and value == value.strip()
        and "\0" not in value
        and not any(ord(character) < 32 for character in value)
        and os.path.isabs(value)
        and os.path.abspath(value) == value
    )


def _is_darwin_platform_image_path(value: str) -> bool:
    """Return whether dyld's logical shared-cache path is OS-owned and bounded."""
    return _is_canonical_absolute_path(value) and value.startswith(
        ("/usr/lib/", "/System/Library/")
    )


def _require_no_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    try:
        for part in path.parts[1:]:
            current = current / part
            if stat.S_ISLNK(current.lstat().st_mode):
                raise RuntimeAuthorizationError("runtime image path contains a symlink")
    except OSError as exc:
        raise RuntimeAuthorizationError("runtime image path cannot be inspected") from exc


def _same_file_stamp(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and left.st_mode == right.st_mode
        and left.st_nlink == right.st_nlink
        and left.st_size == right.st_size
        and left.st_ctime_ns == right.st_ctime_ns
        and left.st_mtime_ns == right.st_mtime_ns
    )


def _result(status: str, reason: str) -> RuntimeAuthorizationResult:
    return RuntimeAuthorizationResult(status=status, reason=reason)


__all__ = [
    "REASON_AUTHORIZED",
    "REASON_IMPORTED_SYMBOL",
    "REASON_LOAD_CONSTRUCT",
    "REASON_LOAD_SET",
    "REASON_OUT_OF_SCOPE",
    "REASON_PLATFORM_BASE",
    "REASON_PROBE_FAILED",
    "REASON_STATIC_INVALID",
    "RUNTIME_AUTHORIZATION_KIND",
    "RUNTIME_AUTHORIZATION_AUTHORITY",
    "RUNTIME_AUTHORIZATION_SCHEMA_VERSION",
    "RUNTIME_AUTHORIZATION_SCOPE",
    "RUNTIME_AUTHORIZED",
    "RUNTIME_DENIED",
    "RUNTIME_OUT_OF_SCOPE",
    "RUNTIME_VERIFICATION_INJECTED_TEST_ONLY",
    "RUNTIME_VERIFICATION_NATIVE_FRESH",
    "RuntimeAuthorizationError",
    "RuntimeAuthorizationReceipt",
    "RuntimeAuthorizationResult",
    "RuntimeImageSnapshot",
    "RuntimeLoadedImage",
    "RuntimeLoadCommandInspection",
    "authorize_native_runtime",
    "authorize_native_runtime_for_testing",
    "capture_runtime_image_snapshot",
    "capture_runtime_loaded_image",
    "collect_loaded_runtime_images",
    "verify_native_runtime_authorization",
]
