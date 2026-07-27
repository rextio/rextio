"""Process-sealed native runtime authority for the bounded artifact build profile.

The public factory accepts only an exact, already validated native-output
transaction.  Paths, wheel members, static observations, loader snapshots,
the import operation, and the runtime receipt are all derived internally.
The resulting object is process-local verification authority for this one
runtime slice; it never grants distribution authority.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
import hashlib
import hmac
import importlib.util
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import sys
import sysconfig
import threading
from types import ModuleType
from typing import SupportsIndex

from rextio.artifacts.contract_dialects import (
    CURRENT,
    NATIVE_RUNTIME_AUTHORITY_DOMAIN,
)
from rextio.artifacts.evidence import (
    NativeRuntimeInventory,
    NativeRuntimeTransitiveClosureInventory,
    WheelEntryRef,
    canonical_json_bytes,
)
from rextio.build import runtime_authorization as _runtime
from rextio.build.full_c6_native_output import (
    FullC6NativeOutputTransaction,
    _full_c6_native_output_toolchain_identity,
    full_c6_native_output_executor_receipt,
    full_c6_native_output_extension_path,
    full_c6_native_output_python_root,
    full_c6_native_output_wheel_entries,
    validate_full_c6_native_output_transaction,
)
from rextio.build.runtime_authorization import (
    REASON_IMPORTED_SYMBOL,
    REASON_LOAD_CONSTRUCT,
    REASON_STATIC_INVALID,
    RUNTIME_AUTHORIZED,
    RUNTIME_DENIED,
    RUNTIME_VERIFICATION_NATIVE_FRESH,
    RuntimeAuthorizationReceipt,
    RuntimeImageSnapshot,
    RuntimeLoadedImage,
    authorize_native_runtime,
    capture_runtime_loaded_image,
    collect_loaded_runtime_images,
    verify_native_runtime_authorization,
)
from rextio.build.runtime_closure import (
    NativeRuntimeTransitiveClosureObservation,
    collect_native_runtime_transitive_closure,
    verify_native_runtime_transitive_closure,
)
from rextio.build.runtime_inventory import inspect_native_runtime_inventory
from rextio.build.runtime_resolution import (
    NativeRuntimePathResolutionObservation,
    collect_native_runtime_path_resolution,
    parse_elf_load_plan,
    refresh_native_runtime_path_resolution_observation,
    verify_native_runtime_path_resolution,
)
from rextio.build.toolchain_identity import (
    BuildToolchainIdentity,
    ToolchainIdentityError,
    verify_tool_identity,
)


FULL_C6_NATIVE_RUNTIME_AUTHORITY_DOMAIN = CURRENT.string_value(
    NATIVE_RUNTIME_AUTHORITY_DOMAIN
)
FULL_C6_NATIVE_RUNTIME_MODULE_NAME = "_rextio_native"
_SUPPORTED_TARGETS = frozenset(
    {"aarch64-apple-darwin", "x86_64-unknown-linux-gnu"}
)
_MAX_IMPORTED_SYMBOLS = 4096
_SAFE_IMPORTED_SYMBOL = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,511}$")
_SAFE_ELF_VERSION = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.+-]{0,254}$")
_SAFE_MACHO_INSTALL_NAME = re.compile(
    r"^/(?:usr/lib|System/Library)/[A-Za-z0-9_./+@-]{1,4060}$"
)
_DARWIN_SHARED_CACHE_LIBSYSTEM_PROVIDER = re.compile(
    r"^/usr/lib/system/libsystem_[a-z0-9_]{1,128}\.dylib$"
)
_DARWIN_SHARED_CACHE_LIBSYSTEM_SINGLETONS = frozenset(
    {
        "/usr/lib/system/libcommonCrypto.dylib",
        "/usr/lib/system/libdispatch.dylib",
        "/usr/lib/system/libdyld.dylib",
        "/usr/lib/system/libunwind.dylib",
    }
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMPORT_MODES = frozenset(
    {
        "macho-flat-python",
        "macho-two-level",
        "macho-stub-binder",
        "elf-unversioned",
        "elf-versioned",
    }
)
_PROVIDER_KINDS = frozenset(
    {
        "toolchain-python-executable",
        "toolchain-python-runtime",
        "declared-system-regular",
        "declared-system-platform",
        "unresolved-weak",
    }
)
_SEAL_KEY = secrets.token_bytes(32)


class FullC6NativeRuntimeError(RuntimeError):
    """The exact native runtime authority could not be established."""


class FullC6NativeRuntimeAuthority:
    """Immutable process-local authority over one exact native import."""

    __slots__ = (
        "_output_transaction",
        "_output_digest",
        "_runtime_inventory",
        "_path_resolution",
        "_transitive_closure",
        "_platform_base",
        "_final_snapshot",
        "_declared_system_images",
        "_declared_system_platform_images",
        "_runtime_receipt",
        "_toolchain",
        "_toolchain_sha256",
        "_symbol_providers",
        "_target_triple",
        "_module",
        "_transaction_seal",
    )

    _output_transaction: FullC6NativeOutputTransaction
    _output_digest: str
    _runtime_inventory: NativeRuntimeInventory
    _path_resolution: NativeRuntimePathResolutionObservation
    _transitive_closure: NativeRuntimeTransitiveClosureObservation
    _platform_base: RuntimeImageSnapshot
    _final_snapshot: RuntimeImageSnapshot
    _declared_system_images: tuple[RuntimeLoadedImage, ...]
    _declared_system_platform_images: tuple[str, ...]
    _runtime_receipt: RuntimeAuthorizationReceipt
    _toolchain: BuildToolchainIdentity
    _toolchain_sha256: str
    _symbol_providers: _SymbolProviderObservation
    _target_triple: str
    _module: ModuleType
    _transaction_seal: bytes

    def __init__(self) -> None:
        raise TypeError("artifact build native runtime authority requires the sealed factory")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise TypeError("artifact build native runtime authority is immutable")

    def __delattr__(self, _name: str) -> None:
        raise TypeError("artifact build native runtime authority is immutable")

    def __copy__(self) -> object:
        raise TypeError("artifact build native runtime authority cannot be copied")

    def __deepcopy__(self, _memo: object) -> object:
        raise TypeError("artifact build native runtime authority cannot be copied")

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("artifact build native runtime authority cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        raise TypeError("artifact build native runtime authority cannot be serialized")

    def __getstate__(self) -> object:
        raise TypeError("artifact build native runtime authority cannot be serialized")

    def __repr__(self) -> str:
        return "FullC6NativeRuntimeAuthority(material=<sealed>)"

    @property
    def digest(self) -> str:
        """Return the path-free authority digest after fresh revalidation."""
        _require_valid_authority(self)
        return _digest(_semantic_payload(self))

    def to_dict(self) -> dict[str, object]:
        """Return a path/bytes-free, explicitly non-distribution projection."""
        _require_valid_authority(self)
        payload = _semantic_payload(self)
        return {**payload, "digest": _digest(payload)}


_PROCESS_STATE_CLEAN = "clean"
_PROCESS_STATE_IN_FLIGHT = "in-flight"
_PROCESS_STATE_AUTHORIZED = "authorized"
_PROCESS_STATE_TAINTED = "tainted"
_PURE_PREIMPORT_DENIAL_REASONS = frozenset(
    {REASON_STATIC_INVALID, REASON_LOAD_CONSTRUCT, REASON_IMPORTED_SYMBOL}
)
_PROCESS_LOCK = threading.RLock()
_PROCESS_PID = os.getpid()
_PROCESS_STATE = _PROCESS_STATE_CLEAN
_PROCESS_AUTHORITY: FullC6NativeRuntimeAuthority | None = None


@dataclass(frozen=True, slots=True)
class _UndefinedImport:
    raw_name: str
    lookup_name: str
    mode: str
    version: str | None = None
    version_index: int | None = None
    qualifier: str | None = None
    macho_library_ordinal: int | None = None
    macho_install_name: str | None = None
    elf_symbol_type: str | None = None
    elf_binding: str | None = None
    elf_visibility: str | None = None

    def __post_init__(self) -> None:
        if (
            type(self.raw_name) is not str
            or not self.raw_name
            or len(self.raw_name) > 1024
            or type(self.lookup_name) is not str
            or _SAFE_IMPORTED_SYMBOL.fullmatch(self.lookup_name) is None
            or self.mode not in _IMPORT_MODES
            or (
                self.version is not None
                and (
                    type(self.version) is not str
                    or _SAFE_ELF_VERSION.fullmatch(self.version) is None
                    or self.mode != "elf-versioned"
                )
            )
            or (
                self.version_index is not None
                and (
                    type(self.version_index) is not int
                    or isinstance(self.version_index, bool)
                    or not 1 <= self.version_index <= 0xFFFF
                    or self.version is None
                )
            )
            or ((self.version is None) != (self.version_index is None))
            or (
                self.qualifier is not None
                and (
                    type(self.qualifier) is not str
                    or not self.qualifier
                    or len(self.qualifier) > 512
                )
            )
            or (
                self.mode.startswith("macho-")
                and (
                    self.elf_symbol_type is not None
                    or self.elf_binding is not None
                    or self.elf_visibility is not None
                    or type(self.macho_library_ordinal) is not int
                    or isinstance(self.macho_library_ordinal, bool)
                    or not 1 <= self.macho_library_ordinal <= 0xFF
                    or (
                        self.mode == "macho-flat-python"
                        and (
                            self.macho_library_ordinal
                            != _runtime._MACHO_DYNAMIC_LOOKUP_ORDINAL
                            or self.macho_install_name is not None
                        )
                    )
                    or (
                        self.mode != "macho-flat-python"
                        and (
                            type(self.macho_install_name) is not str
                            or _SAFE_MACHO_INSTALL_NAME.fullmatch(
                                self.macho_install_name
                            )
                            is None
                        )
                    )
                )
            )
            or (
                self.mode.startswith("elf-")
                and (
                    self.macho_library_ordinal is not None
                    or self.macho_install_name is not None
                    or self.elf_symbol_type not in {"FUNC", "OBJECT", "NOTYPE"}
                    or self.elf_binding not in {"GLOBAL", "WEAK"}
                    or self.elf_visibility != "DEFAULT"
                )
            )
        ):
            raise ValueError("artifact build imported symbol is invalid")


@dataclass(frozen=True, slots=True)
class _SymbolProviderBinding:
    symbol: str
    resolution_mode: str
    resolved_address: int | None
    provider_kind: str
    provider_path: str | None
    provider_identity_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.symbol) is not str
            or not self.symbol
            or len(self.symbol) > 1024
            or "\0" in self.symbol
            or any(ord(character) < 32 for character in self.symbol)
            or self.resolution_mode not in _IMPORT_MODES
            or self.provider_kind not in _PROVIDER_KINDS
            or _SHA256.fullmatch(self.provider_identity_sha256) is None
            or (
                self.provider_kind == "unresolved-weak"
                and (
                    self.resolution_mode not in {"elf-unversioned", "elf-versioned"}
                    or self.resolved_address is not None
                    or self.provider_path is not None
                )
            )
            or (
                self.provider_kind != "unresolved-weak"
                and (
                    type(self.provider_path) is not str
                    or not self.provider_path
                    or (
                        self.resolution_mode == "macho-stub-binder"
                        and self.resolved_address is not None
                    )
                    or (
                        self.resolution_mode != "macho-stub-binder"
                        and (
                            type(self.resolved_address) is not int
                            or isinstance(self.resolved_address, bool)
                            or self.resolved_address <= 0
                        )
                    )
                )
            )
        ):
            raise ValueError("artifact build symbol-provider binding is invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "symbol_sha256": _digest_text(self.symbol),
            "resolution_mode": self.resolution_mode,
            "provider_kind": self.provider_kind,
            "provider_path_sha256": (
                None
                if self.provider_path is None
                else _digest_text(self.provider_path)
            ),
            "provider_identity_sha256": self.provider_identity_sha256,
        }


@dataclass(frozen=True, slots=True)
class _PythonAbiIdentity:
    ext_suffix: str
    soabi: str
    ld_library: str | None
    inst_soname: str | None
    framework: str | None
    framework_prefix: str | None
    framework_install_dir: str | None

    def __post_init__(self) -> None:
        required = (self.ext_suffix, self.soabi)
        optional = (
            self.ld_library,
            self.inst_soname,
            self.framework,
            self.framework_prefix,
            self.framework_install_dir,
        )
        if (
            not all(
                type(value) is str
                and value
                and len(value) <= 4096
                and "\0" not in value
                and not any(ord(character) < 32 for character in value)
                for value in required
            )
            or not all(
                value is None
                or (
                    type(value) is str
                    and value
                    and len(value) <= 4096
                    and "\0" not in value
                    and not any(ord(character) < 32 for character in value)
                )
                for value in optional
            )
            or not self.soabi.startswith("cpython-311-")
        ):
            raise ValueError("artifact build Python ABI identity is invalid")

    @property
    def digest(self) -> str:
        return _digest(
            {
                "ext_suffix": self.ext_suffix,
                "soabi": self.soabi,
                "ld_library": self.ld_library,
                "inst_soname": self.inst_soname,
                "framework": self.framework,
                "framework_prefix": self.framework_prefix,
                "framework_install_dir": self.framework_install_dir,
            }
        )


@dataclass(frozen=True, slots=True)
class _SymbolProviderObservation:
    toolchain_sha256: str
    python_abi: _PythonAbiIdentity
    python_images: tuple[RuntimeLoadedImage, ...]
    bindings: tuple[_SymbolProviderBinding, ...]

    def __post_init__(self) -> None:
        if _SHA256.fullmatch(self.toolchain_sha256) is None:
            raise ValueError("artifact build symbol-provider toolchain identity is invalid")
        if (
            type(self.python_abi) is not _PythonAbiIdentity
            or type(self.python_images) is not tuple
            or not self.python_images
            or not all(type(image) is RuntimeLoadedImage for image in self.python_images)
            or self.python_images
            != tuple(sorted(self.python_images, key=lambda image: image.path))
        ):
            raise ValueError("artifact build Python runtime image set is invalid")
        if (
            type(self.bindings) is not tuple
            or not self.bindings
            or len(self.bindings) > _MAX_IMPORTED_SYMBOLS
            or not all(type(binding) is _SymbolProviderBinding for binding in self.bindings)
            or self.bindings
            != tuple(sorted(self.bindings, key=lambda binding: binding.symbol))
            or len({binding.symbol for binding in self.bindings}) != len(self.bindings)
        ):
            raise ValueError("artifact build symbol-provider bindings are invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "toolchain_sha256": self.toolchain_sha256,
            "python_abi_sha256": self.python_abi.digest,
            "python_images_sha256": _digest(
                [image.to_dict() for image in self.python_images]
            ),
            "symbol_count": len(self.bindings),
            "bindings": [binding.to_dict() for binding in self.bindings],
        }


class _DlInfo(ctypes.Structure):
    _fields_ = (
        ("filename", ctypes.c_char_p),
        ("image_base", ctypes.c_void_p),
        ("symbol_name", ctypes.c_char_p),
        ("symbol_address", ctypes.c_void_p),
    )


@dataclass(frozen=True, slots=True)
class _NativeOutputContext:
    output_digest: str
    target_triple: str
    python_root: Path
    extension_path: Path
    wheel_entries: tuple[WheelEntryRef, ...]
    toolchain: BuildToolchainIdentity
    toolchain_sha256: str


@dataclass(frozen=True, slots=True)
class _StaticRuntimeObservations:
    runtime_inventory: NativeRuntimeInventory
    path_resolution: NativeRuntimePathResolutionObservation
    transitive_closure: NativeRuntimeTransitiveClosureObservation


@dataclass(frozen=True, slots=True)
class _FullC6NativeRuntimeMaterial:
    """Validated private material for a later aggregate artifact build gate."""

    output_transaction: FullC6NativeOutputTransaction
    runtime_inventory: NativeRuntimeInventory
    path_resolution: NativeRuntimePathResolutionObservation
    transitive_closure: NativeRuntimeTransitiveClosureObservation
    runtime_receipt: RuntimeAuthorizationReceipt
    final_snapshot: RuntimeImageSnapshot
    toolchain: BuildToolchainIdentity
    symbol_providers: _SymbolProviderObservation


def create_full_c6_native_runtime_authority(
    output_transaction: FullC6NativeOutputTransaction,
) -> FullC6NativeRuntimeAuthority:
    """Collect, import, authorize, and seal one exact native runtime.

    No caller-selected target, path, wheel inventory, observation, loader
    snapshot, receipt, module name, or callback crosses this authority boundary.
    Every failure is collapsed to one bounded public error without private
    path or loader detail.
    """
    try:
        if os.getpid() != _PROCESS_PID:
            raise FullC6NativeRuntimeError
        with _PROCESS_LOCK:
            if (
                _PROCESS_STATE != _PROCESS_STATE_CLEAN
                or _PROCESS_AUTHORITY is not None
            ):
                raise FullC6NativeRuntimeError
            return _create_full_c6_native_runtime_authority_locked(
                output_transaction
            )
    except Exception:
        raise FullC6NativeRuntimeError(
            "artifact build native runtime authority could not be established"
        ) from None


def _create_full_c6_native_runtime_authority_locked(
    output_transaction: FullC6NativeOutputTransaction,
) -> FullC6NativeRuntimeAuthority:
    global _PROCESS_AUTHORITY, _PROCESS_STATE

    _PROCESS_STATE = _PROCESS_STATE_IN_FLIGHT
    context: _NativeOutputContext | None = None
    platform_base: RuntimeImageSnapshot | None = None
    authorizer_started = False
    import_started = False
    pure_preimport_denial = False
    try:
        if (
            type(output_transaction) is not FullC6NativeOutputTransaction
            or not validate_full_c6_native_output_transaction(output_transaction)
        ):
            raise FullC6NativeRuntimeError
        context = _derive_output_context(output_transaction)
        observations = _collect_static_observations(context)
        if not _validate_static_bindings(context, observations):
            raise FullC6NativeRuntimeError

        platform_base = collect_loaded_runtime_images(context.target_triple)
        declared_images, declared_platform_images = _resolve_system_images(
            target_triple=context.target_triple,
            platform_base=platform_base,
            closure=observations.transitive_closure.inventory,
        )
        imported: dict[str, ModuleType] = {}

        def import_action() -> None:
            nonlocal import_started
            if import_started or imported:
                raise FullC6NativeRuntimeError
            import_started = True
            imported["module"] = _import_extension_module(context.extension_path)

        authorizer_started = True
        result = authorize_native_runtime(
            target_triple=context.target_triple,
            expected_python_root=context.python_root,
            extension_path=context.extension_path,
            runtime_inventory=observations.runtime_inventory,
            path_resolution=observations.path_resolution,
            transitive_closure=observations.transitive_closure,
            platform_base=platform_base,
            declared_system_images=declared_images,
            import_action=import_action,
            declared_system_platform_images=declared_platform_images,
        )
        pure_preimport_denial = bool(
            import_started is False
            and result.status == RUNTIME_DENIED
            and result.reason in _PURE_PREIMPORT_DENIAL_REASONS
        )
        receipt = result.receipt
        module = imported.get("module")
        if (
            result.status != RUNTIME_AUTHORIZED
            or result.authorized is not True
            or type(receipt) is not RuntimeAuthorizationReceipt
            or receipt.verification_mode != RUNTIME_VERIFICATION_NATIVE_FRESH
            or type(module) is not ModuleType
        ):
            raise FullC6NativeRuntimeError
        final_snapshot = collect_loaded_runtime_images(context.target_triple)
        if final_snapshot.digest != receipt.final_snapshot_sha256:
            raise FullC6NativeRuntimeError
        symbol_providers = _collect_symbol_provider_observation(
            context=context,
            runtime_receipt=receipt,
            final_snapshot=final_snapshot,
            declared_system_images=declared_images,
            declared_system_platform_images=declared_platform_images,
        )
        authority = _mint_authority(
            output_transaction=output_transaction,
            context=context,
            observations=observations,
            platform_base=platform_base,
            final_snapshot=final_snapshot,
            declared_system_images=declared_images,
            declared_system_platform_images=declared_platform_images,
            runtime_receipt=receipt,
            symbol_providers=symbol_providers,
            module=module,
        )
        if not _validate_authority_bindings(authority):
            raise FullC6NativeRuntimeError
        _PROCESS_AUTHORITY = authority
        _PROCESS_STATE = _PROCESS_STATE_AUTHORIZED
        return authority
    except BaseException:
        _PROCESS_AUTHORITY = None
        if _failed_attempt_can_restore_clean(
            context=context,
            platform_base=platform_base,
            authorizer_started=authorizer_started,
            import_started=import_started,
            pure_preimport_denial=pure_preimport_denial,
        ):
            _PROCESS_STATE = _PROCESS_STATE_CLEAN
        else:
            _PROCESS_STATE = _PROCESS_STATE_TAINTED
        raise


def _failed_attempt_can_restore_clean(
    *,
    context: _NativeOutputContext | None,
    platform_base: RuntimeImageSnapshot | None,
    authorizer_started: bool,
    import_started: bool,
    pure_preimport_denial: bool,
) -> bool:
    if import_started or (authorizer_started and not pure_preimport_denial):
        return False
    if platform_base is None:
        return True
    if context is None:
        return False
    try:
        return collect_loaded_runtime_images(context.target_triple) == platform_base
    except Exception:
        return False


def validate_full_c6_native_runtime_authority(
    authority: FullC6NativeRuntimeAuthority,
) -> bool:
    """Freshly revalidate every sealed static and actual-loader binding."""
    global _PROCESS_AUTHORITY, _PROCESS_STATE

    if (
        type(authority) is not FullC6NativeRuntimeAuthority
        or os.getpid() != _PROCESS_PID
    ):
        return False
    with _PROCESS_LOCK:
        if (
            _PROCESS_STATE != _PROCESS_STATE_AUTHORIZED
            or _PROCESS_AUTHORITY is not authority
        ):
            return False
        valid = _validate_authority_bindings(authority)
        if not valid:
            _PROCESS_AUTHORITY = None
            _PROCESS_STATE = _PROCESS_STATE_TAINTED
        return valid


def _validate_authority_bindings(
    authority: FullC6NativeRuntimeAuthority,
) -> bool:
    try:
        if (
            type(authority._output_transaction) is not FullC6NativeOutputTransaction
            or type(authority._output_digest) is not str
            or type(authority._runtime_inventory) is not NativeRuntimeInventory
            or type(authority._path_resolution)
            is not NativeRuntimePathResolutionObservation
            or type(authority._transitive_closure)
            is not NativeRuntimeTransitiveClosureObservation
            or type(authority._platform_base) is not RuntimeImageSnapshot
            or type(authority._final_snapshot) is not RuntimeImageSnapshot
            or type(authority._declared_system_images) is not tuple
            or not all(
                type(image) is RuntimeLoadedImage
                for image in authority._declared_system_images
            )
            or type(authority._declared_system_platform_images) is not tuple
            or not all(
                type(path) is str
                for path in authority._declared_system_platform_images
            )
            or type(authority._runtime_receipt) is not RuntimeAuthorizationReceipt
            or type(authority._toolchain) is not BuildToolchainIdentity
            or type(authority._toolchain_sha256) is not str
            or type(authority._symbol_providers) is not _SymbolProviderObservation
            or type(authority._target_triple) is not str
            or type(authority._module) is not ModuleType
            or type(authority._transaction_seal) is not bytes
            or not hmac.compare_digest(authority._transaction_seal, _seal(authority))
            or not validate_full_c6_native_output_transaction(
                authority._output_transaction
            )
        ):
            return False
        context = _derive_output_context(authority._output_transaction)
        observations = _StaticRuntimeObservations(
            runtime_inventory=authority._runtime_inventory,
            path_resolution=authority._path_resolution,
            transitive_closure=authority._transitive_closure,
        )
        if (
            context.output_digest != authority._output_digest
            or context.target_triple != authority._target_triple
            or context.toolchain is not authority._toolchain
            or context.toolchain_sha256 != authority._toolchain_sha256
            or _validated_toolchain_digest(authority._toolchain)
            != authority._toolchain_sha256
            or not _validate_static_bindings(context, observations)
        ):
            return False
        receipt = authority._runtime_receipt
        if (
            receipt.target_triple != context.target_triple
            or receipt.verification_mode != RUNTIME_VERIFICATION_NATIVE_FRESH
            or receipt.platform_base_sha256 != authority._platform_base.digest
            or receipt.final_snapshot_sha256 != authority._final_snapshot.digest
            or receipt.declared_system_images != authority._declared_system_images
            or receipt.declared_system_platform_images
            != authority._declared_system_platform_images
            or receipt.extension
            != capture_runtime_loaded_image(context.extension_path)
            or receipt.path_resolution_sha256
            != _digest(authority._path_resolution.inventory.to_dict())
            or receipt.transitive_closure_sha256
            != _digest(authority._transitive_closure.inventory.to_dict())
        ):
            return False
        for image in authority._platform_base.images:
            if capture_runtime_loaded_image(image.path) != image:
                return False
        expected_images, expected_platform = _resolve_system_images(
            target_triple=context.target_triple,
            platform_base=authority._platform_base,
            closure=authority._transitive_closure.inventory,
        )
        if (
            expected_images != authority._declared_system_images
            or expected_platform != authority._declared_system_platform_images
            or sys.modules.get(FULL_C6_NATIVE_RUNTIME_MODULE_NAME)
            is not authority._module
            or getattr(authority._module, "__file__", None)
            != os.fspath(context.extension_path)
            or collect_loaded_runtime_images(context.target_triple)
            != authority._final_snapshot
            or not verify_native_runtime_authorization(receipt)
        ):
            return False
        symbol_providers = _collect_symbol_provider_observation(
            context=context,
            runtime_receipt=receipt,
            final_snapshot=authority._final_snapshot,
            declared_system_images=authority._declared_system_images,
            declared_system_platform_images=authority._declared_system_platform_images,
        )
        if symbol_providers != authority._symbol_providers:
            return False
        if not hmac.compare_digest(authority._transaction_seal, _seal(authority)):
            return False
        return (
            collect_loaded_runtime_images(context.target_triple)
            == authority._final_snapshot
        )
    except Exception:
        return False


def _validated_full_c6_native_runtime_material(
    authority: FullC6NativeRuntimeAuthority,
) -> _FullC6NativeRuntimeMaterial:
    if not validate_full_c6_native_runtime_authority(authority):
        raise FullC6NativeRuntimeError("artifact build native runtime authority is stale")
    return _FullC6NativeRuntimeMaterial(
        output_transaction=authority._output_transaction,
        runtime_inventory=authority._runtime_inventory,
        path_resolution=authority._path_resolution,
        transitive_closure=authority._transitive_closure,
        runtime_receipt=authority._runtime_receipt,
        final_snapshot=authority._final_snapshot,
        toolchain=authority._toolchain,
        symbol_providers=authority._symbol_providers,
    )


def _derive_output_context(
    transaction: FullC6NativeOutputTransaction,
) -> _NativeOutputContext:
    receipt = full_c6_native_output_executor_receipt(transaction)
    toolchain = _full_c6_native_output_toolchain_identity(transaction)
    toolchain_sha256 = _validated_toolchain_digest(toolchain)
    target = receipt.target_triple
    if (
        type(target) is not str
        or target not in _SUPPORTED_TARGETS
        or toolchain_sha256 != receipt.toolchain_sha256
    ):
        raise FullC6NativeRuntimeError("artifact build native runtime target is unsupported")
    root = full_c6_native_output_python_root(transaction)
    extension = full_c6_native_output_extension_path(transaction)
    if extension.parent != root or extension.name.split(".", 1)[0] != (
        FULL_C6_NATIVE_RUNTIME_MODULE_NAME
    ):
        raise FullC6NativeRuntimeError("artifact build native extension identity is invalid")
    return _NativeOutputContext(
        output_digest=transaction.digest,
        target_triple=target,
        python_root=root,
        extension_path=extension,
        wheel_entries=full_c6_native_output_wheel_entries(transaction),
        toolchain=toolchain,
        toolchain_sha256=toolchain_sha256,
    )


def _collect_static_observations(
    context: _NativeOutputContext,
) -> _StaticRuntimeObservations:
    runtime_inventory = inspect_native_runtime_inventory(
        installed_path=context.extension_path,
        expected_python_root=context.python_root,
        wheel_entries=context.wheel_entries,
        target_triple=context.target_triple,
    )
    path_resolution = collect_native_runtime_path_resolution(
        installed_path=context.extension_path,
        expected_python_root=context.python_root,
        wheel_entries=context.wheel_entries,
        runtime_inventory=runtime_inventory,
        target_triple=context.target_triple,
    )
    if path_resolution is None:
        raise FullC6NativeRuntimeError("artifact build native path resolution is unavailable")
    transitive_closure = collect_native_runtime_transitive_closure(
        installed_path=context.extension_path,
        expected_python_root=context.python_root,
        wheel_entries=context.wheel_entries,
        runtime_inventory=runtime_inventory,
        path_resolution=path_resolution.inventory,
        target_triple=context.target_triple,
    )
    refreshed = refresh_native_runtime_path_resolution_observation(
        path_resolution,
        expected_python_root=context.python_root,
    )
    if transitive_closure is None or refreshed is None:
        raise FullC6NativeRuntimeError("artifact build native closure is unavailable")
    observations = _StaticRuntimeObservations(
        runtime_inventory=runtime_inventory,
        path_resolution=refreshed,
        transitive_closure=transitive_closure,
    )
    if not _validate_static_bindings(context, observations):
        raise FullC6NativeRuntimeError("artifact build native observations are stale")
    return observations


def _validate_static_bindings(
    context: _NativeOutputContext,
    observations: _StaticRuntimeObservations,
) -> bool:
    try:
        inventory = observations.runtime_inventory
        resolution = observations.path_resolution
        closure = observations.transitive_closure
        if (
            type(inventory) is not NativeRuntimeInventory
            or type(resolution) is not NativeRuntimePathResolutionObservation
            or type(closure) is not NativeRuntimeTransitiveClosureObservation
            or not verify_native_runtime_path_resolution(
                resolution, expected_python_root=context.python_root
            )
            or not verify_native_runtime_transitive_closure(
                closure, expected_python_root=context.python_root
            )
        ):
            return False
        profile = _runtime._SUPPORTED_PROFILES.get(context.target_triple)
        if profile is None:
            return False
        path_inventory, closure_inventory = _runtime._validate_static_observations(
            target_triple=context.target_triple,
            profile=profile,
            expected_python_root=context.python_root,
            runtime_inventory=inventory,
            path_resolution=resolution,
            transitive_closure=closure,
        )
        matches = tuple(
            entry
            for entry in context.wheel_entries
            if entry.name == inventory.wheel_member
        )
        extension = capture_runtime_loaded_image(context.extension_path)
        return (
            path_inventory == resolution.inventory
            and closure_inventory == closure.inventory
            and len(matches) == 1
            and matches[0].sha256 == inventory.subject_sha256
            and matches[0].uncompressed_size == inventory.subject_size
            and extension.sha256 == inventory.subject_sha256
            and extension.size == inventory.subject_size
            and PurePosixPath(inventory.wheel_member).name
            == context.extension_path.name
        )
    except Exception:
        return False


def _validated_toolchain_digest(toolchain: BuildToolchainIdentity) -> str:
    try:
        if type(toolchain) is not BuildToolchainIdentity:
            raise FullC6NativeRuntimeError("artifact build toolchain identity is invalid")
        digest = toolchain.digest
        if type(digest) is not str or _SHA256.fullmatch(digest) is None:
            raise FullC6NativeRuntimeError("artifact build toolchain digest is invalid")
        return digest
    except (AttributeError, TypeError, ValueError):
        raise FullC6NativeRuntimeError(
            "artifact build toolchain identity is invalid"
        ) from None


def _verify_runtime_inspector_identity(context: _NativeOutputContext) -> None:
    expected_name = (
        "otool"
        if context.target_triple == "aarch64-apple-darwin"
        else "readelf"
        if context.target_triple == "x86_64-unknown-linux-gnu"
        else None
    )
    matches = tuple(
        inspector
        for inspector in context.toolchain.inspectors
        if inspector.name == expected_name
    )
    if expected_name is None or len(matches) != 1:
        raise FullC6NativeRuntimeError(
            "artifact build runtime inspector identity is unavailable"
        )
    path = Path(f"/usr/bin/{expected_name}")
    try:
        verify_tool_identity(path, matches[0])
    except (OSError, ToolchainIdentityError) as exc:
        raise FullC6NativeRuntimeError(
            "artifact build runtime inspector differs from the sealed toolchain"
        ) from exc


def _collect_symbol_provider_observation(
    *,
    context: _NativeOutputContext,
    runtime_receipt: RuntimeAuthorizationReceipt,
    final_snapshot: RuntimeImageSnapshot,
    declared_system_images: tuple[RuntimeLoadedImage, ...],
    declared_system_platform_images: tuple[str, ...],
) -> _SymbolProviderObservation:
    if (
        type(context) is not _NativeOutputContext
        or type(runtime_receipt) is not RuntimeAuthorizationReceipt
        or type(final_snapshot) is not RuntimeImageSnapshot
        or type(declared_system_images) is not tuple
        or type(declared_system_platform_images) is not tuple
    ):
        raise FullC6NativeRuntimeError("artifact build symbol-provider inputs are invalid")
    toolchain_sha256 = _validated_toolchain_digest(context.toolchain)
    if (
        toolchain_sha256 != context.toolchain_sha256
        or runtime_receipt.final_snapshot_sha256 != final_snapshot.digest
    ):
        raise FullC6NativeRuntimeError("artifact build symbol-provider inputs are stale")
    _verify_runtime_inspector_identity(context)
    python_executable, python_abi, python_images = _collect_toolchain_python_images(
        context=context,
        final_snapshot=final_snapshot,
    )
    imports = _inspect_undefined_imports(
        context.extension_path,
        context.target_triple,
    )
    fresh_names = _runtime._canonical_inspector_tokens(
        _runtime._inspect_imported_symbols(
            context.extension_path,
            context.target_triple,
        )
    )
    raw_names = tuple(sorted(item.raw_name for item in imports))
    if (
        fresh_names != raw_names
        or _runtime._token_digest(fresh_names)
        != runtime_receipt.imported_symbols_sha256
    ):
        raise FullC6NativeRuntimeError(
            "artifact build imported-symbol observations disagree"
        )
    bindings = _bind_symbol_providers(
        imports=imports,
        extension_path=context.extension_path,
        target_triple=context.target_triple,
        final_snapshot=final_snapshot,
        python_executable=python_executable,
        python_images=python_images,
        declared_system_images=declared_system_images,
        declared_system_platform_images=declared_system_platform_images,
    )
    _verify_runtime_inspector_identity(context)
    _launcher, fresh_main, fresh_abi = _verify_toolchain_python_process_identity(
        context
    )
    if (fresh_main, fresh_abi) != (python_executable, python_abi):
        raise FullC6NativeRuntimeError("artifact build Python ABI identity changed")
    try:
        observation = _SymbolProviderObservation(
            toolchain_sha256=toolchain_sha256,
            python_abi=python_abi,
            python_images=python_images,
            bindings=bindings,
        )
    except (TypeError, ValueError) as exc:
        raise FullC6NativeRuntimeError(
            "artifact build symbol-provider observation is invalid"
        ) from exc
    if collect_loaded_runtime_images(context.target_triple) != final_snapshot:
        raise FullC6NativeRuntimeError(
            "artifact build loader changed during provider collection"
        )
    return observation


def _verify_toolchain_python_identity(
    context: _NativeOutputContext,
) -> tuple[Path, _PythonAbiIdentity]:
    if (
        sys.implementation.name != "cpython"
        or tuple(sys.version_info[:2]) != (3, 11)
        or type(sys.executable) is not str
        or not sys.executable
    ):
        raise FullC6NativeRuntimeError("artifact build requires the frozen CPython 3.11 ABI")
    try:
        python = Path(sys.executable).resolve(strict=True)
        verify_tool_identity(python, context.toolchain.python)
    except (OSError, AttributeError, ToolchainIdentityError) as exc:
        raise FullC6NativeRuntimeError(
            "artifact build current Python differs from the sealed toolchain"
        ) from exc
    abi = _collect_python_abi_identity()
    if context.extension_path.name != (
        f"{FULL_C6_NATIVE_RUNTIME_MODULE_NAME}{abi.ext_suffix}"
    ):
        raise FullC6NativeRuntimeError(
            "artifact build extension ABI differs from the sealed Python toolchain"
        )
    return python, abi


def _collect_python_abi_identity() -> _PythonAbiIdentity:
    def required(name: str) -> str:
        value = sysconfig.get_config_var(name)
        if type(value) is not str or not value:
            raise FullC6NativeRuntimeError(
                "artifact build required Python ABI configuration is unavailable"
            )
        return value

    def optional(name: str) -> str | None:
        value = sysconfig.get_config_var(name)
        if value is None or value == "":
            return None
        if type(value) is not str:
            raise FullC6NativeRuntimeError(
                "artifact build Python ABI configuration is invalid"
            )
        return value

    try:
        return _PythonAbiIdentity(
            ext_suffix=required("EXT_SUFFIX"),
            soabi=required("SOABI"),
            ld_library=optional("LDLIBRARY"),
            inst_soname=optional("INSTSONAME"),
            framework=optional("PYTHONFRAMEWORK"),
            framework_prefix=optional("PYTHONFRAMEWORKPREFIX"),
            framework_install_dir=optional("PYTHONFRAMEWORKINSTALLDIR"),
        )
    except ValueError as exc:
        raise FullC6NativeRuntimeError(
            "artifact build Python ABI configuration is invalid"
        ) from exc


def _darwin_main_executable_path() -> Path:
    """Return dyld's actual process main, not CPython's launcher path."""
    if sys.platform != "darwin":
        raise FullC6NativeRuntimeError("artifact build dyld main executable is unavailable")
    process = ctypes.CDLL(None)
    try:
        get_executable = process._NSGetExecutablePath
    except AttributeError as exc:
        raise FullC6NativeRuntimeError(
            "artifact build dyld main executable API is unavailable"
        ) from exc
    get_executable.argtypes = (
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_uint32),
    )
    get_executable.restype = ctypes.c_int
    size = ctypes.c_uint32(0)
    if get_executable(None, ctypes.byref(size)) != -1 or not 2 <= size.value <= 4096:
        raise FullC6NativeRuntimeError(
            "artifact build dyld main executable size is invalid"
        )
    buffer = ctypes.create_string_buffer(size.value)
    if get_executable(buffer, ctypes.byref(size)) != 0 or not buffer.value:
        raise FullC6NativeRuntimeError(
            "artifact build dyld main executable is unavailable"
        )
    try:
        return Path(os.fsdecode(buffer.value)).resolve(strict=True)
    except (OSError, RuntimeError, UnicodeError) as exc:
        raise FullC6NativeRuntimeError(
            "artifact build dyld main executable identity is invalid"
        ) from exc


def _verify_toolchain_python_process_identity(
    context: _NativeOutputContext,
) -> tuple[Path, Path, _PythonAbiIdentity]:
    launcher, abi = _verify_toolchain_python_identity(context)
    if context.target_triple != "aarch64-apple-darwin":
        return launcher, launcher, abi
    main = _darwin_main_executable_path()
    framework_fields = (
        abi.framework,
        abi.framework_prefix,
        abi.framework_install_dir,
    )
    if abi.framework is None:
        if any(value is not None for value in framework_fields[1:]) or main != launcher:
            raise FullC6NativeRuntimeError(
                "artifact build non-framework Python launcher differs from dyld main"
            )
        return launcher, main, abi
    if any(value is None for value in framework_fields):
        raise FullC6NativeRuntimeError(
            "artifact build framework Python ABI identity is incomplete"
        )
    assert abi.framework is not None
    assert abi.framework_prefix is not None
    assert abi.framework_install_dir is not None
    try:
        prefix = Path(abi.framework_prefix).resolve(strict=True)
        install = Path(abi.framework_install_dir).resolve(strict=True)
        version = "3.11"
        version_root = install / "Versions" / version
        expected_launcher = (version_root / "bin" / f"python{version}").resolve(
            strict=True
        )
        expected_main = (
            version_root
            / "Resources"
            / f"{abi.framework}.app"
            / "Contents"
            / "MacOS"
            / abi.framework
        ).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise FullC6NativeRuntimeError(
            "artifact build framework Python path identity is unavailable"
        ) from exc
    if (
        install.name != f"{abi.framework}.framework"
        or install.parent != prefix
        or launcher != expected_launcher
        or main != expected_main
    ):
        raise FullC6NativeRuntimeError(
            "artifact build framework Python launcher/main relationship is invalid"
        )
    return launcher, main, abi


def _collect_toolchain_python_images(
    *,
    context: _NativeOutputContext,
    final_snapshot: RuntimeImageSnapshot,
) -> tuple[Path, _PythonAbiIdentity, tuple[RuntimeLoadedImage, ...]]:
    _launcher, python, abi = _verify_toolchain_python_process_identity(context)
    python_path = os.fspath(python)
    executable_matches = tuple(
        image for image in final_snapshot.images if image.path == python_path
    )
    if len(executable_matches) != 1:
        raise FullC6NativeRuntimeError(
            "artifact build Python executable is not exact in the final loader snapshot"
        )
    if capture_runtime_loaded_image(python) != executable_matches[0]:
        raise FullC6NativeRuntimeError("artifact build Python executable image is stale")

    dependencies = _inspect_python_dependencies(python, context.target_triple)
    dependency_names = tuple(PurePosixPath(item).name for item in dependencies)
    python_like = tuple(
        name
        for name in dependency_names
        if name.casefold().startswith(("libpython", "python"))
    )
    preferred_source = (
        abi.framework
        if context.target_triple == "aarch64-apple-darwin"
        and abi.framework is not None
        else abi.inst_soname
        if abi.inst_soname is not None
        else abi.ld_library
    )
    preferred_names = (
        ()
        if preferred_source is None
        else (PurePosixPath(preferred_source).name,)
    )
    images: list[RuntimeLoadedImage] = [executable_matches[0]]
    selected_name = next(
        (name for name in preferred_names if name in dependency_names),
        None,
    )
    if selected_name is not None:
        if dependency_names.count(selected_name) != 1 or len(python_like) != 1:
            raise FullC6NativeRuntimeError(
                "artifact build Python runtime dependency is ambiguous"
            )
        selected_dependency = next(
            item
            for item in dependencies
            if PurePosixPath(item).name == selected_name
        )
        candidates = tuple(
            image
            for image in final_snapshot.images
            if Path(image.path).name == selected_name
            and (
                context.target_triple != "aarch64-apple-darwin"
                or not os.path.isabs(selected_dependency)
                or image.path == selected_dependency
            )
            and (
                context.target_triple == "aarch64-apple-darwin"
                or _runtime._native_system_image_name(
                    image, context.target_triple
                )
                == selected_name
            )
        )
        if len(candidates) != 1:
            raise FullC6NativeRuntimeError(
                "artifact build Python runtime dependency is not exact"
            )
        images.append(candidates[0])
    elif python_like:
        raise FullC6NativeRuntimeError(
            "artifact build Python runtime dependency disagrees with the current ABI"
        )
    _fresh_launcher, fresh_main, fresh_abi = (
        _verify_toolchain_python_process_identity(context)
    )
    if (fresh_main, fresh_abi) != (python, abi):
        raise FullC6NativeRuntimeError("artifact build Python ABI identity changed")
    return python, abi, tuple(sorted(images, key=lambda image: image.path))


def _inspect_python_dependencies(
    python: Path,
    target_triple: str,
) -> tuple[str, ...]:
    if target_triple == "aarch64-apple-darwin":
        output = _runtime._run_inspector(("/usr/bin/otool", "-l", os.fspath(python)))
        dependencies = _parse_macho_direct_dependencies(output)
    elif target_triple == "x86_64-unknown-linux-gnu":
        output = _runtime._run_inspector(
            ("/usr/bin/readelf", "-W", "-d", os.fspath(python))
        )
        dependencies = parse_elf_load_plan(output).dependencies
    else:
        raise FullC6NativeRuntimeError("artifact build Python target is unsupported")
    if (
        type(dependencies) is not tuple
        or len(dependencies) > _MAX_IMPORTED_SYMBOLS
        or not all(type(item) is str and item for item in dependencies)
    ):
        raise FullC6NativeRuntimeError("artifact build Python dependencies are invalid")
    return dependencies


def _parse_macho_direct_dependencies(output: str) -> tuple[str, ...]:
    if type(output) is not str or not output.strip():
        raise FullC6NativeRuntimeError("artifact build Python Mach-O output is invalid")
    blocks: list[list[str]] = []
    current: list[str] | None = None
    for line in output.splitlines():
        if re.fullmatch(r"Load command [0-9]+", line.strip()):
            current = []
            blocks.append(current)
        elif current is not None:
            current.append(line)
    dependencies: list[str] = []
    for block in blocks:
        commands = tuple(
            match.group(1)
            for line in block
            if (match := re.fullmatch(r"\s*cmd (LC_[A-Z0-9_]+)\s*", line))
        )
        if len(commands) != 1:
            raise FullC6NativeRuntimeError(
                "artifact build Python Mach-O load command is malformed"
            )
        if commands[0] in {
            "LC_LOAD_WEAK_DYLIB",
            "LC_LAZY_LOAD_DYLIB",
            "LC_LOAD_UPWARD_DYLIB",
            "LC_REEXPORT_DYLIB",
        }:
            raise FullC6NativeRuntimeError(
                "artifact build Python Mach-O dependency is not strong and direct"
            )
        if commands[0] != "LC_LOAD_DYLIB":
            continue
        names = tuple(
            match.group(1)
            for line in block
            if (match := re.fullmatch(r"\s*name (.+?) \(offset [0-9]+\)\s*", line))
        )
        if len(names) != 1:
            raise FullC6NativeRuntimeError(
                "artifact build Python Mach-O dependency is malformed"
            )
        name = names[0]
        if (
            not name
            or len(name) > 4096
            or "\0" in name
            or not (
                os.path.isabs(name)
                or name.startswith(("@rpath/", "@executable_path/"))
            )
        ):
            raise FullC6NativeRuntimeError(
                "artifact build Python Mach-O dependency path is invalid"
            )
        dependencies.append(name)
    if not blocks or len(dependencies) > _MAX_IMPORTED_SYMBOLS:
        raise FullC6NativeRuntimeError(
            "artifact build Python Mach-O dependencies are invalid"
        )
    if len(dependencies) != len(set(dependencies)):
        raise FullC6NativeRuntimeError(
            "artifact build Python Mach-O dependencies are ambiguous"
        )
    return tuple(dependencies)


def _inspect_undefined_imports(
    extension_path: Path,
    target_triple: str,
) -> tuple[_UndefinedImport, ...]:
    if target_triple == "aarch64-apple-darwin":
        imports = _macho_imports_from_records(
            _runtime._inspect_macho_imported_symbol_records(extension_path)
        )
    elif target_triple == "x86_64-unknown-linux-gnu":
        output = _runtime._run_inspector(
            ("/usr/bin/readelf", "-W", "--dyn-syms", os.fspath(extension_path))
        )
        imports = _parse_elf_undefined_imports(output)
    else:
        raise FullC6NativeRuntimeError("artifact build imported-symbol target is unsupported")
    if (
        not imports
        or len(imports) > _MAX_IMPORTED_SYMBOLS
        or imports
        != tuple(
            sorted(
                imports,
                key=lambda item: (
                    item.lookup_name,
                    item.version or "",
                    item.mode,
                    item.raw_name,
                ),
            )
        )
        or len(
            {
                (item.lookup_name, item.version, item.mode, item.raw_name)
                for item in imports
            }
        )
        != len(imports)
    ):
        raise FullC6NativeRuntimeError("artifact build imported symbols are ambiguous")
    return imports


def _macho_imports_from_records(
    records: tuple[_runtime._MachoImportedSymbol, ...],
) -> tuple[_UndefinedImport, ...]:
    imports: list[_UndefinedImport] = []
    for record in records:
        if type(record) is not _runtime._MachoImportedSymbol or record.weak_reference:
            raise FullC6NativeRuntimeError(
                "artifact build weak or invalid Mach-O import is forbidden"
            )
        raw_name = record.symbol
        if record.library_ordinal == _runtime._MACHO_DYNAMIC_LOOKUP_ORDINAL:
            if not raw_name.startswith("_"):
                raise FullC6NativeRuntimeError(
                    "artifact build flat Mach-O import name is invalid"
                )
            lookup = raw_name[1:]
            if not lookup.startswith(("Py", "_Py")):
                raise FullC6NativeRuntimeError(
                    "artifact build flat Mach-O import is not a Python ABI symbol"
                )
            mode = "macho-flat-python"
            qualifier = "dynamically looked up"
        elif (
            raw_name == "dyld_stub_binder"
            and record.library_name is not None
            and PurePosixPath(record.library_name).name == "libSystem.B.dylib"
        ):
            lookup = raw_name
            mode = "macho-stub-binder"
            qualifier = "from libSystem.B.dylib"
        else:
            if not raw_name.startswith("_") or record.library_name is None:
                raise FullC6NativeRuntimeError(
                    "artifact build Mach-O import name is invalid"
                )
            lookup = raw_name[1:]
            mode = "macho-two-level"
            qualifier = f"from {PurePosixPath(record.library_name).name}"
        try:
            imports.append(
                _UndefinedImport(
                    raw_name=raw_name,
                    lookup_name=lookup,
                    mode=mode,
                    qualifier=qualifier,
                    macho_library_ordinal=record.library_ordinal,
                    macho_install_name=record.library_name,
                )
            )
        except ValueError as exc:
            raise FullC6NativeRuntimeError(
                "artifact build Mach-O import identity is invalid"
            ) from exc
    return tuple(
        sorted(
            imports,
            key=lambda item: (item.lookup_name, item.mode, item.raw_name),
        )
    )


def _parse_elf_undefined_imports(output: str) -> tuple[_UndefinedImport, ...]:
    try:
        records = _runtime._parse_elf_imported_symbols(output)
    except Exception as exc:
        raise FullC6NativeRuntimeError(
            "artifact build ELF import records are invalid"
        ) from exc
    imports: list[_UndefinedImport] = []
    versioned = re.compile(
        r"^(?P<name>[A-Za-z_][A-Za-z0-9_]{0,511})"
        r"@(?P<version>[A-Za-z0-9_][A-Za-z0-9_.+-]{0,254})$"
    )
    for record in records:
        match = versioned.fullmatch(record.symbol)
        if match is None:
            if "@" in record.symbol or record.version_index is not None:
                raise FullC6NativeRuntimeError(
                    "artifact build versioned ELF import is noncanonical"
                )
            lookup_name = record.symbol
            version = None
            version_index = None
            mode = "elf-unversioned"
        else:
            lookup_name = match.group("name")
            version = match.group("version")
            version_index = record.version_index
            if version_index is None:
                raise FullC6NativeRuntimeError(
                    "artifact build versioned ELF import lacks an exact index"
                )
            mode = "elf-versioned"
        try:
            imports.append(
                _UndefinedImport(
                    raw_name=record.canonical_token,
                    lookup_name=lookup_name,
                    mode=mode,
                    version=version,
                    version_index=version_index,
                    elf_symbol_type=record.symbol_type,
                    elf_binding=record.binding,
                    elf_visibility=record.visibility,
                )
            )
        except ValueError as exc:
            raise FullC6NativeRuntimeError(
                "artifact build ELF import name is invalid"
            ) from exc
    return tuple(
        sorted(
            imports,
            key=lambda item: (
                item.lookup_name,
                item.version or "",
                item.raw_name,
            ),
        )
    )


def _bind_symbol_providers(
    *,
    imports: tuple[_UndefinedImport, ...],
    extension_path: Path,
    target_triple: str,
    final_snapshot: RuntimeImageSnapshot,
    python_executable: Path,
    python_images: tuple[RuntimeLoadedImage, ...],
    declared_system_images: tuple[RuntimeLoadedImage, ...],
    declared_system_platform_images: tuple[str, ...],
) -> tuple[_SymbolProviderBinding, ...]:
    macho_reexports = (
        _collect_macho_dependency_reexports(
            declared_system_images=declared_system_images,
            declared_system_platform_images=declared_system_platform_images,
            final_snapshot=final_snapshot,
            dependency_install_names=tuple(
                sorted(
                    {
                        item.macho_install_name
                        for item in imports
                        if item.mode == "macho-two-level"
                        and item.macho_install_name is not None
                    }
                )
            ),
        )
        if target_triple == "aarch64-apple-darwin"
        and any(item.mode == "macho-two-level" for item in imports)
        else ()
    )
    process = ctypes.CDLL(None)
    handle = _open_noload_handle(process, extension_path)
    failure: BaseException | None = None
    try:
        bindings = tuple(
            _bind_one_symbol_provider(
                process=process,
                handle=handle,
                imported=imported,
                target_triple=target_triple,
                final_snapshot=final_snapshot,
                python_executable=python_executable,
                python_images=python_images,
                declared_system_images=declared_system_images,
                declared_system_platform_images=declared_system_platform_images,
                macho_reexports=macho_reexports,
            )
            for imported in imports
        )
    except BaseException as exc:
        failure = exc
        raise
    finally:
        try:
            _close_noload_handle(process, handle)
        except BaseException:
            if failure is None:
                raise
    return tuple(sorted(bindings, key=lambda binding: binding.symbol))


def _open_noload_handle(process: ctypes.CDLL, extension_path: Path) -> int:
    dlopen = process.dlopen
    dlerror = process.dlerror
    dlopen.argtypes = (ctypes.c_char_p, ctypes.c_int)
    dlopen.restype = ctypes.c_void_p
    dlerror.argtypes = ()
    dlerror.restype = ctypes.c_char_p
    dlerror()
    flags = (
        getattr(os, "RTLD_NOLOAD", 0)
        | getattr(os, "RTLD_NOW", 0)
        | getattr(os, "RTLD_LOCAL", 0)
    )
    if not (flags & getattr(os, "RTLD_NOLOAD", 0)) or not (
        flags & getattr(os, "RTLD_NOW", 0)
    ):
        raise FullC6NativeRuntimeError("artifact build RTLD_NOLOAD is unavailable")
    handle = dlopen(os.fsencode(extension_path), flags)
    error = dlerror()
    if error is not None or not handle:
        raise FullC6NativeRuntimeError(
            "artifact build extension is not present in the native loader"
        )
    return int(handle)


def _close_noload_handle(process: ctypes.CDLL, handle: int) -> None:
    dlclose = process.dlclose
    dlerror = process.dlerror
    dlclose.argtypes = (ctypes.c_void_p,)
    dlclose.restype = ctypes.c_int
    dlerror.argtypes = ()
    dlerror.restype = ctypes.c_char_p
    dlerror()
    result = dlclose(ctypes.c_void_p(handle))
    error = dlerror()
    if result != 0 or error is not None:
        raise FullC6NativeRuntimeError("artifact build native loader handle close failed")


def _bind_one_symbol_provider(
    *,
    process: ctypes.CDLL,
    handle: int,
    imported: _UndefinedImport,
    target_triple: str,
    final_snapshot: RuntimeImageSnapshot,
    python_executable: Path,
    python_images: tuple[RuntimeLoadedImage, ...],
    declared_system_images: tuple[RuntimeLoadedImage, ...],
    declared_system_platform_images: tuple[str, ...],
    macho_reexports: tuple[tuple[str, str, str, str], ...] = (),
) -> _SymbolProviderBinding:
    if imported.mode == "macho-stub-binder":
        return _bind_macho_stub_binder(
            imported=imported,
            declared_system_images=declared_system_images,
            declared_system_platform_images=declared_system_platform_images,
        )

    default_handle = -2 if target_triple == "aarch64-apple-darwin" else 0
    if imported.elf_binding == "WEAK":
        globally_visible = _resolve_weak_import_address(
            process,
            default_handle,
            imported,
        )
        scoped = _resolve_weak_import_address(process, handle, imported)
        if globally_visible is None and scoped is None:
            return _SymbolProviderBinding(
                symbol=imported.raw_name,
                resolution_mode=imported.mode,
                resolved_address=None,
                provider_kind="unresolved-weak",
                provider_path=None,
                provider_identity_sha256=_digest(
                    {
                        "provider": "unresolved-weak",
                        "symbol": imported.raw_name,
                        "mode": imported.mode,
                    }
                ),
            )
        if globally_visible is None or scoped is None:
            raise FullC6NativeRuntimeError(
                "artifact build weak imported symbol is one-sided"
            )
    else:
        globally_visible = _resolve_import_address(
            process,
            default_handle,
            imported,
        )
        if imported.mode == "macho-flat-python":
            scoped = globally_visible
        else:
            scoped = _resolve_import_address(process, handle, imported)
    if scoped != globally_visible:
        raise FullC6NativeRuntimeError(
            "artifact build imported symbol is ambiguous or interposed"
        )
    provider_path = _dladdr_provider(process, scoped)
    canonical_path, provider_image = _match_provider_to_final_snapshot(
        provider_path,
        target_triple=target_triple,
        final_snapshot=final_snapshot,
    )
    categories: list[tuple[str, str]] = []
    python_paths = {image.path for image in python_images}
    if imported.mode != "macho-two-level" and canonical_path in python_paths:
        kind = (
            "toolchain-python-executable"
            if canonical_path == os.fspath(python_executable)
            else "toolchain-python-runtime"
        )
        if provider_image is None:
            raise FullC6NativeRuntimeError(
                "artifact build Python provider lacks an exact file identity"
            )
        categories.append((kind, _digest(provider_image.to_dict())))
    declared_regular = {
        image.path: image for image in declared_system_images
    }
    if imported.mode.startswith("elf-") and canonical_path in declared_regular:
        categories.append(
            (
                "declared-system-regular",
                _digest(declared_regular[canonical_path].to_dict()),
            )
        )
    if imported.mode.startswith("elf-") and canonical_path in set(
        declared_system_platform_images
    ):
        categories.append(("declared-system-platform", _digest_text(canonical_path)))
    if imported.mode == "macho-two-level":
        reexport = _macho_dependency_provider_category(
            imported=imported,
            provider_path=canonical_path,
            provider_image=provider_image,
            python_executable=python_executable,
            python_images=python_images,
            declared_system_images=declared_system_images,
            declared_system_platform_images=declared_system_platform_images,
            reexports=macho_reexports,
        )
        if reexport is not None:
            categories.append(reexport)
    if len(categories) != 1:
        raise FullC6NativeRuntimeError(
            "artifact build symbol provider is outside or ambiguous in the allowed set"
        )
    kind, identity = categories[0]
    if imported.mode == "macho-flat-python" and not kind.startswith(
        "toolchain-python-"
    ):
        raise FullC6NativeRuntimeError(
            "artifact build flat Python import resolved outside the sealed Python ABI"
        )
    try:
        return _SymbolProviderBinding(
            symbol=imported.raw_name,
            resolution_mode=imported.mode,
            resolved_address=scoped,
            provider_kind=kind,
            provider_path=canonical_path,
            provider_identity_sha256=identity,
        )
    except ValueError as exc:
        raise FullC6NativeRuntimeError(
            "artifact build symbol-provider binding is invalid"
        ) from exc


def _macho_dependency_provider_category(
    *,
    imported: _UndefinedImport,
    provider_path: str,
    provider_image: RuntimeLoadedImage | None,
    python_executable: Path,
    python_images: tuple[RuntimeLoadedImage, ...],
    declared_system_images: tuple[RuntimeLoadedImage, ...],
    declared_system_platform_images: tuple[str, ...],
    reexports: tuple[tuple[str, str, str, str], ...],
) -> tuple[str, str]:
    install_name = imported.macho_install_name
    if (
        imported.mode != "macho-two-level"
        or type(install_name) is not str
        or _SAFE_MACHO_INSTALL_NAME.fullmatch(install_name) is None
    ):
        raise FullC6NativeRuntimeError(
            "artifact build Mach-O direct dependency identity is invalid"
        )
    roots: list[tuple[str, str, str]] = []
    for image in python_images:
        if image.path == install_name:
            roots.append(
                (
                    "toolchain-python-executable"
                    if image.path == os.fspath(python_executable)
                    else "toolchain-python-runtime",
                    image.path,
                    _digest(image.to_dict()),
                )
            )
    for image in declared_system_images:
        if image.path == install_name:
            roots.append(
                ("declared-system-regular", image.path, _digest(image.to_dict()))
            )
    for path in declared_system_platform_images:
        if path == install_name:
            roots.append(("declared-system-platform", path, _digest_text(path)))
    if len(roots) != 1:
        raise FullC6NativeRuntimeError(
            "artifact build Mach-O direct dependency is outside or ambiguous"
        )
    kind, root_path, root_identity = roots[0]
    if provider_path == root_path:
        expected_identity = (
            _digest_text(provider_path)
            if provider_image is None
            else _digest(provider_image.to_dict())
        )
        if expected_identity != root_identity:
            raise FullC6NativeRuntimeError(
                "artifact build Mach-O direct provider identity changed"
            )
        return kind, root_identity
    matches = tuple(
        (candidate_kind, candidate_root, candidate_identity)
        for candidate_kind, candidate_root, candidate_identity, reexport_path in reexports
        if candidate_root == root_path and provider_path == reexport_path
    )
    if not matches:
        raise FullC6NativeRuntimeError(
            "artifact build Mach-O provider is not the direct dependency or its reexport"
        )
    if len(matches) != 1:
        raise FullC6NativeRuntimeError(
            "artifact build libSystem reexport provider is ambiguous"
        )
    if not _runtime._is_trusted_system_image_path(
        provider_path, "aarch64-apple-darwin"
    ):
        raise FullC6NativeRuntimeError(
            "artifact build libSystem reexport provider is not system-owned"
        )
    matched_kind, matched_root, matched_identity = matches[0]
    if (matched_kind, matched_root, matched_identity) != (
        kind,
        root_path,
        root_identity,
    ):
        raise FullC6NativeRuntimeError(
            "artifact build Mach-O reexport root identity changed"
        )
    provider_identity = (
        _digest_text(provider_path)
        if provider_image is None
        else _digest(provider_image.to_dict())
    )
    return (
        kind,
        _digest(
            {
                "root_path_sha256": _digest_text(root_path),
                "root_identity_sha256": root_identity,
                "provider_path_sha256": _digest_text(provider_path),
                "provider_identity_sha256": provider_identity,
                "reexport_depth": 1,
            }
        ),
    )


def _collect_macho_dependency_reexports(
    *,
    declared_system_images: tuple[RuntimeLoadedImage, ...],
    declared_system_platform_images: tuple[str, ...],
    final_snapshot: RuntimeImageSnapshot,
    dependency_install_names: tuple[str, ...],
) -> tuple[tuple[str, str, str, str], ...]:
    if (
        type(final_snapshot) is not RuntimeImageSnapshot
        or type(dependency_install_names) is not tuple
        or dependency_install_names != tuple(sorted(set(dependency_install_names)))
        or not all(
            type(name) is str
            and _SAFE_MACHO_INSTALL_NAME.fullmatch(name) is not None
            for name in dependency_install_names
        )
    ):
        raise FullC6NativeRuntimeError(
            "artifact build Mach-O dependency reexport inputs are invalid"
        )
    roots: list[tuple[str, str, str]] = []
    for image in declared_system_images:
        if image.path in dependency_install_names:
            roots.append(
                (
                    "declared-system-regular",
                    image.path,
                    _digest(image.to_dict()),
                )
            )
    for path in declared_system_platform_images:
        if path in dependency_install_names:
            roots.append(("declared-system-platform", path, _digest_text(path)))
    records: list[tuple[str, str, str, str]] = []
    for kind, root_path, root_identity in roots:
        if kind == "declared-system-regular":
            providers = _inspect_macho_reexports(root_path)
        elif root_path == "/usr/lib/libSystem.B.dylib":
            providers = tuple(
                sorted(
                    {
                        path
                        for path in final_snapshot.platform_images
                        if _is_darwin_shared_cache_libsystem_provider(path)
                    }
                    | {
                        image.path
                        for image in final_snapshot.images
                        if _is_darwin_shared_cache_libsystem_provider(image.path)
                    }
                )
            )
            if not providers:
                raise FullC6NativeRuntimeError(
                    "artifact build shared-cache libSystem providers are unavailable"
                )
        else:
            providers = ()
        records.extend(
            (kind, root_path, root_identity, provider_path)
            for provider_path in providers
        )
    frozen = tuple(records)
    if len(frozen) > _MAX_IMPORTED_SYMBOLS or len(frozen) != len(set(frozen)):
        raise FullC6NativeRuntimeError("artifact build Mach-O reexports are ambiguous")
    return frozen


def _is_darwin_shared_cache_libsystem_provider(path: str) -> bool:
    return (
        type(path) is str
        and (
            _DARWIN_SHARED_CACHE_LIBSYSTEM_PROVIDER.fullmatch(path) is not None
            or path in _DARWIN_SHARED_CACHE_LIBSYSTEM_SINGLETONS
        )
        and _runtime._is_darwin_platform_image_path(path)
    )


def _inspect_macho_reexports(path: str) -> tuple[str, ...]:
    output = _runtime._run_inspector(("/usr/bin/otool", "-l", path))
    blocks: list[list[str]] = []
    current: list[str] | None = None
    for line in output.splitlines():
        if re.fullmatch(r"Load command [0-9]+", line.strip()):
            current = []
            blocks.append(current)
        elif current is not None:
            current.append(line)
    reexports: list[str] = []
    for block in blocks:
        commands = tuple(
            match.group(1)
            for line in block
            if (match := re.fullmatch(r"\s*cmd (LC_[A-Z0-9_]+)\s*", line))
        )
        if len(commands) != 1:
            raise FullC6NativeRuntimeError(
                "artifact build Mach-O reexport load command is malformed"
            )
        if commands != ("LC_REEXPORT_DYLIB",):
            continue
        names = tuple(
            match.group(1)
            for line in block
            if (match := re.fullmatch(r"\s*name (.+?) \(offset [0-9]+\)\s*", line))
        )
        if (
            len(names) != 1
            or not _runtime._is_trusted_system_image_path(
                names[0], "aarch64-apple-darwin"
            )
        ):
            raise FullC6NativeRuntimeError(
                "artifact build libSystem reexport record is invalid"
            )
        reexports.append(names[0])
    if not blocks or len(reexports) > _MAX_IMPORTED_SYMBOLS:
        raise FullC6NativeRuntimeError(
            "artifact build libSystem reexport set is invalid"
        )
    canonical = tuple(sorted(set(reexports)))
    if len(canonical) != len(reexports):
        raise FullC6NativeRuntimeError(
            "artifact build libSystem reexport set is ambiguous"
        )
    return canonical


def _bind_macho_stub_binder(
    *,
    imported: _UndefinedImport,
    declared_system_images: tuple[RuntimeLoadedImage, ...],
    declared_system_platform_images: tuple[str, ...],
) -> _SymbolProviderBinding:
    if (
        imported.raw_name != "dyld_stub_binder"
        or imported.lookup_name != "dyld_stub_binder"
        or imported.qualifier not in {"from libSystem", "from libSystem.B.dylib"}
        or imported.macho_install_name != "/usr/lib/libSystem.B.dylib"
        or imported.macho_library_ordinal in {
            None,
            _runtime._MACHO_DYNAMIC_LOOKUP_ORDINAL,
            _runtime._MACHO_EXECUTABLE_ORDINAL,
        }
    ):
        raise FullC6NativeRuntimeError(
            "artifact build dyld stub binder is not canonical"
        )
    regular = tuple(
        image
        for image in declared_system_images
        if image.path == imported.macho_install_name
    )
    platform = tuple(
        path
        for path in declared_system_platform_images
        if path == imported.macho_install_name
    )
    if len(regular) + len(platform) != 1:
        raise FullC6NativeRuntimeError(
            "artifact build dyld stub binder lacks one declared libSystem"
        )
    if regular:
        path = regular[0].path
        identity = _digest(regular[0].to_dict())
        kind = "declared-system-regular"
    else:
        path = platform[0]
        identity = _digest_text(path)
        kind = "declared-system-platform"
    return _SymbolProviderBinding(
        symbol=imported.raw_name,
        resolution_mode=imported.mode,
        resolved_address=None,
        provider_kind=kind,
        provider_path=path,
        provider_identity_sha256=identity,
    )


def _resolve_import_address(
    process: ctypes.CDLL,
    handle: int,
    imported: _UndefinedImport,
) -> int:
    if imported.mode == "elf-versioned":
        if imported.version is None:
            raise FullC6NativeRuntimeError(
                "artifact build versioned ELF import is incomplete"
            )
        return _dlvsym_exact(
            process,
            handle,
            imported.lookup_name,
            imported.version,
        )
    return _dlsym_exact(process, handle, imported.lookup_name)


def _resolve_weak_import_address(
    process: ctypes.CDLL,
    handle: int,
    imported: _UndefinedImport,
) -> int | None:
    if imported.elf_binding != "WEAK" or not imported.mode.startswith("elf-"):
        raise FullC6NativeRuntimeError("artifact build weak import metadata is invalid")
    if imported.mode == "elf-versioned":
        if imported.version is None:
            raise FullC6NativeRuntimeError(
                "artifact build versioned weak ELF import is incomplete"
            )
        return _dlvsym_optional(
            process,
            handle,
            imported.lookup_name,
            imported.version,
        )
    return _dlsym_optional(process, handle, imported.lookup_name)


def _dlsym_exact(
    process: ctypes.CDLL,
    handle: int,
    symbol: str,
) -> int:
    dlsym = process.dlsym
    dlerror = process.dlerror
    dlsym.argtypes = (ctypes.c_void_p, ctypes.c_char_p)
    dlsym.restype = ctypes.c_void_p
    dlerror.argtypes = ()
    dlerror.restype = ctypes.c_char_p
    dlerror()
    address = dlsym(ctypes.c_void_p(handle), symbol.encode("ascii"))
    error = dlerror()
    if error is not None or not address:
        raise FullC6NativeRuntimeError("artifact build imported symbol is unresolved")
    return int(address)


def _dlsym_optional(
    process: ctypes.CDLL,
    handle: int,
    symbol: str,
) -> int | None:
    dlsym = process.dlsym
    dlerror = process.dlerror
    dlsym.argtypes = (ctypes.c_void_p, ctypes.c_char_p)
    dlsym.restype = ctypes.c_void_p
    dlerror.argtypes = ()
    dlerror.restype = ctypes.c_char_p
    dlerror()
    try:
        address = dlsym(ctypes.c_void_p(handle), symbol.encode("ascii"))
    except Exception as exc:
        raise FullC6NativeRuntimeError(
            "artifact build weak imported-symbol lookup failed"
        ) from exc
    error = dlerror()
    if address:
        if error is not None:
            raise FullC6NativeRuntimeError(
                "artifact build weak imported-symbol lookup is inconsistent"
            )
        return int(address)
    return None


def _dlvsym_exact(
    process: ctypes.CDLL,
    handle: int,
    symbol: str,
    version: str,
) -> int:
    try:
        dlvsym = process.dlvsym
    except AttributeError as exc:
        raise FullC6NativeRuntimeError(
            "artifact build dlvsym is unavailable"
        ) from exc
    dlerror = process.dlerror
    dlvsym.argtypes = (ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p)
    dlvsym.restype = ctypes.c_void_p
    dlerror.argtypes = ()
    dlerror.restype = ctypes.c_char_p
    dlerror()
    address = dlvsym(
        ctypes.c_void_p(handle),
        symbol.encode("ascii"),
        version.encode("ascii"),
    )
    error = dlerror()
    if error is not None or not address:
        raise FullC6NativeRuntimeError(
            "artifact build versioned imported symbol is unresolved"
        )
    return int(address)


def _dlvsym_optional(
    process: ctypes.CDLL,
    handle: int,
    symbol: str,
    version: str,
) -> int | None:
    try:
        dlvsym = process.dlvsym
    except AttributeError as exc:
        raise FullC6NativeRuntimeError(
            "artifact build dlvsym is unavailable"
        ) from exc
    dlerror = process.dlerror
    dlvsym.argtypes = (ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p)
    dlvsym.restype = ctypes.c_void_p
    dlerror.argtypes = ()
    dlerror.restype = ctypes.c_char_p
    dlerror()
    try:
        address = dlvsym(
            ctypes.c_void_p(handle),
            symbol.encode("ascii"),
            version.encode("ascii"),
        )
    except Exception as exc:
        raise FullC6NativeRuntimeError(
            "artifact build weak versioned imported-symbol lookup failed"
        ) from exc
    error = dlerror()
    if address:
        if error is not None:
            raise FullC6NativeRuntimeError(
                "artifact build weak versioned lookup is inconsistent"
            )
        return int(address)
    return None


def _dladdr_provider(
    process: ctypes.CDLL,
    address: int,
) -> str:
    dladdr = process.dladdr
    dladdr.argtypes = (ctypes.c_void_p, ctypes.POINTER(_DlInfo))
    dladdr.restype = ctypes.c_int
    info = _DlInfo()
    if dladdr(ctypes.c_void_p(address), ctypes.byref(info)) != 1:
        raise FullC6NativeRuntimeError("artifact build symbol provider is unresolved")
    if (
        not info.filename
        or not info.image_base
    ):
        raise FullC6NativeRuntimeError("artifact build symbol provider is not identified")
    try:
        provider = os.fsdecode(info.filename)
    except (UnicodeError, TypeError) as exc:
        raise FullC6NativeRuntimeError(
            "artifact build symbol provider identity is invalid"
        ) from exc
    return provider


def _match_provider_to_final_snapshot(
    provider_path: str,
    *,
    target_triple: str,
    final_snapshot: RuntimeImageSnapshot,
) -> tuple[str, RuntimeLoadedImage | None]:
    if provider_path in final_snapshot.platform_images:
        if (
            target_triple != "aarch64-apple-darwin"
            or not _runtime._is_darwin_platform_image_path(provider_path)
        ):
            raise FullC6NativeRuntimeError(
                "artifact build platform provider path is invalid"
            )
        return provider_path, None
    if type(provider_path) is not str or not os.path.isabs(provider_path):
        raise FullC6NativeRuntimeError("artifact build provider path is not absolute")
    try:
        canonical = os.fspath(Path(provider_path).resolve(strict=True))
    except (OSError, RuntimeError) as exc:
        raise FullC6NativeRuntimeError(
            "artifact build provider path is unavailable"
        ) from exc
    if canonical != provider_path:
        raise FullC6NativeRuntimeError("artifact build provider path is aliased")
    matches = tuple(image for image in final_snapshot.images if image.path == canonical)
    if len(matches) != 1 or capture_runtime_loaded_image(canonical) != matches[0]:
        raise FullC6NativeRuntimeError(
            "artifact build provider is not exact in the final loader snapshot"
        )
    return canonical, matches[0]


def _resolve_system_images(
    *,
    target_triple: str,
    platform_base: RuntimeImageSnapshot,
    closure: NativeRuntimeTransitiveClosureInventory,
) -> tuple[tuple[RuntimeLoadedImage, ...], tuple[str, ...]]:
    """Bind every logical system leaf to exactly one already loaded image.

    The resolver intentionally refuses search, cache lookup, soname guessing,
    or a path whose basename differs from the logical leaf.  The subsequent
    runtime authorizer independently checks the OS-owned path and ELF SONAME.
    """
    if (
        target_triple not in _SUPPORTED_TARGETS
        or type(platform_base) is not RuntimeImageSnapshot
        or type(closure) is not NativeRuntimeTransitiveClosureInventory
    ):
        raise FullC6NativeRuntimeError("artifact build system image mapping is invalid")
    names = tuple(
        sorted(node.name for node in closure.nodes if node.kind == "system-logical")
    )
    if len(names) != len(set(names)):
        raise FullC6NativeRuntimeError("artifact build system image mapping is ambiguous")
    wanted = set(names)
    candidates: dict[str, list[tuple[str, RuntimeLoadedImage | str]]] = {
        name: [] for name in names
    }
    for image in platform_base.images:
        basename = Path(image.path).name
        if basename not in wanted or not _runtime._is_trusted_system_image_path(
            image.path, target_triple
        ):
            continue
        if _runtime._native_system_image_name(image, target_triple) == basename:
            candidates[basename].append(("regular", image))
    if target_triple != "aarch64-apple-darwin" and platform_base.platform_images:
        raise FullC6NativeRuntimeError("artifact build platform image mapping is invalid")
    for path in platform_base.platform_images:
        basename = PurePosixPath(path).name
        if basename in wanted and _runtime._is_darwin_platform_image_path(path):
            candidates[basename].append(("platform", path))
    if any(len(candidates[name]) != 1 for name in names):
        raise FullC6NativeRuntimeError("artifact build system image mapping is not exact")
    regular = tuple(
        sorted(
            (
                value
                for values in candidates.values()
                for kind, value in values
                if kind == "regular" and type(value) is RuntimeLoadedImage
            ),
            key=lambda image: image.path,
        )
    )
    platform = tuple(
        sorted(
            value
            for values in candidates.values()
            for kind, value in values
            if kind == "platform" and type(value) is str
        )
    )
    if len(regular) + len(platform) != len(names):
        raise FullC6NativeRuntimeError("artifact build system image mapping is incomplete")
    return regular, platform


def _import_extension_module(extension_path: Path) -> ModuleType:
    """Import only the fixed generated extension name from its derived path."""
    if FULL_C6_NATIVE_RUNTIME_MODULE_NAME in sys.modules:
        raise FullC6NativeRuntimeError("artifact build native module name is already bound")
    spec = importlib.util.spec_from_file_location(
        FULL_C6_NATIVE_RUNTIME_MODULE_NAME,
        extension_path,
    )
    if spec is None or spec.loader is None:
        raise FullC6NativeRuntimeError("artifact build native extension loader is unavailable")
    module = importlib.util.module_from_spec(spec)
    if type(module) is not ModuleType:
        raise FullC6NativeRuntimeError("artifact build native extension module is invalid")
    sys.modules[FULL_C6_NATIVE_RUNTIME_MODULE_NAME] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        if sys.modules.get(FULL_C6_NATIVE_RUNTIME_MODULE_NAME) is module:
            del sys.modules[FULL_C6_NATIVE_RUNTIME_MODULE_NAME]
        raise
    if (
        sys.modules.get(FULL_C6_NATIVE_RUNTIME_MODULE_NAME) is not module
        or getattr(module, "__file__", None) != os.fspath(extension_path)
    ):
        raise FullC6NativeRuntimeError("artifact build native module binding changed")
    return module


def _mint_authority(
    *,
    output_transaction: FullC6NativeOutputTransaction,
    context: _NativeOutputContext,
    observations: _StaticRuntimeObservations,
    platform_base: RuntimeImageSnapshot,
    final_snapshot: RuntimeImageSnapshot,
    declared_system_images: tuple[RuntimeLoadedImage, ...],
    declared_system_platform_images: tuple[str, ...],
    runtime_receipt: RuntimeAuthorizationReceipt,
    symbol_providers: _SymbolProviderObservation,
    module: ModuleType,
) -> FullC6NativeRuntimeAuthority:
    authority = object.__new__(FullC6NativeRuntimeAuthority)
    object.__setattr__(authority, "_output_transaction", output_transaction)
    object.__setattr__(authority, "_output_digest", context.output_digest)
    object.__setattr__(authority, "_runtime_inventory", observations.runtime_inventory)
    object.__setattr__(authority, "_path_resolution", observations.path_resolution)
    object.__setattr__(authority, "_transitive_closure", observations.transitive_closure)
    object.__setattr__(authority, "_platform_base", platform_base)
    object.__setattr__(authority, "_final_snapshot", final_snapshot)
    object.__setattr__(authority, "_declared_system_images", declared_system_images)
    object.__setattr__(
        authority,
        "_declared_system_platform_images",
        declared_system_platform_images,
    )
    object.__setattr__(authority, "_runtime_receipt", runtime_receipt)
    object.__setattr__(authority, "_toolchain", context.toolchain)
    object.__setattr__(authority, "_toolchain_sha256", context.toolchain_sha256)
    object.__setattr__(authority, "_symbol_providers", symbol_providers)
    object.__setattr__(authority, "_target_triple", context.target_triple)
    object.__setattr__(authority, "_module", module)
    object.__setattr__(authority, "_transaction_seal", b"")
    object.__setattr__(authority, "_transaction_seal", _seal(authority))
    return authority


def _semantic_payload(authority: FullC6NativeRuntimeAuthority) -> dict[str, object]:
    return {
        "domain": FULL_C6_NATIVE_RUNTIME_AUTHORITY_DOMAIN,
        "authority": "process-sealed-runtime-verification-only",
        "target_triple": authority._target_triple,
        "output_transaction_sha256": authority._output_digest,
        "runtime_inventory_sha256": _digest(
            authority._runtime_inventory.to_dict()
        ),
        "path_resolution_sha256": _digest(
            authority._path_resolution.inventory.to_dict()
        ),
        "transitive_closure_sha256": _digest(
            authority._transitive_closure.inventory.to_dict()
        ),
        "platform_base_sha256": authority._platform_base.digest,
        "final_runtime_snapshot_sha256": authority._final_snapshot.digest,
        "declared_system_images_sha256": _digest(
            [image.to_dict() for image in authority._declared_system_images]
        ),
        "declared_system_platform_images_sha256": _digest(
            list(authority._declared_system_platform_images)
        ),
        "runtime_receipt_sha256": authority._runtime_receipt.digest,
        "toolchain_sha256": authority._toolchain_sha256,
        "actual_symbol_provider_sha256": _digest(
            authority._symbol_providers.to_dict()
        ),
        "actual_symbol_provider_count": len(authority._symbol_providers.bindings),
        "runtime_authorized": True,
        "complete_for_runtime_scope": True,
        "distribution_authorized": False,
    }


def _seal(authority: FullC6NativeRuntimeAuthority) -> bytes:
    payload = {
        "semantic": _semantic_payload(authority),
        "private_symbol_provider_addresses": [
            {
                "symbol_sha256": _digest_text(binding.symbol),
                "resolution_mode": binding.resolution_mode,
                "resolved_address": binding.resolved_address,
            }
            for binding in authority._symbol_providers.bindings
        ],
        "object_ids": {
            "output": id(authority._output_transaction),
            "runtime_inventory": id(authority._runtime_inventory),
            "path_resolution": id(authority._path_resolution),
            "transitive_closure": id(authority._transitive_closure),
            "platform_base": id(authority._platform_base),
            "final_snapshot": id(authority._final_snapshot),
            "declared_system_images": id(authority._declared_system_images),
            "declared_system_platform_images": id(
                authority._declared_system_platform_images
            ),
            "runtime_receipt": id(authority._runtime_receipt),
            "toolchain": id(authority._toolchain),
            "symbol_providers": id(authority._symbol_providers),
            "module": id(authority._module),
        },
        "private_path_sha256": hashlib.sha256(
            os.fsencode(getattr(authority._module, "__file__", ""))
        ).hexdigest(),
    }
    return hmac.new(_SEAL_KEY, canonical_json_bytes(payload), hashlib.sha256).digest()


def _require_valid_authority(authority: FullC6NativeRuntimeAuthority) -> None:
    if not validate_full_c6_native_runtime_authority(authority):
        raise FullC6NativeRuntimeError("artifact build native runtime authority is stale")


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


__all__ = [
    "FULL_C6_NATIVE_RUNTIME_AUTHORITY_DOMAIN",
    "FULL_C6_NATIVE_RUNTIME_MODULE_NAME",
    "FullC6NativeRuntimeAuthority",
    "FullC6NativeRuntimeError",
    "create_full_c6_native_runtime_authority",
    "validate_full_c6_native_runtime_authority",
]
