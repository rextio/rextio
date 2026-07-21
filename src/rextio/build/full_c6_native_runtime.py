"""Process-sealed native runtime authority for the bounded Full C6 profile.

The public factory accepts only an exact, already validated native-output
transaction.  Paths, wheel members, static observations, loader snapshots,
the import operation, and the runtime receipt are all derived internally.
The resulting object is process-local verification authority for this one
runtime slice; it never grants distribution authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import importlib.util
import os
from pathlib import Path, PurePosixPath
import secrets
import sys
import threading
from types import ModuleType
from typing import SupportsIndex

from rextio.artifacts.evidence import (
    NativeRuntimeInventory,
    NativeRuntimeTransitiveClosureInventory,
    WheelEntryRef,
    canonical_json_bytes,
)
from rextio.build import runtime_authorization as _runtime
from rextio.build.full_c6_native_output import (
    FullC6NativeOutputTransaction,
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
    refresh_native_runtime_path_resolution_observation,
    verify_native_runtime_path_resolution,
)


FULL_C6_NATIVE_RUNTIME_AUTHORITY_DOMAIN = "rextio.full-c6-native-runtime.v1"
FULL_C6_NATIVE_RUNTIME_MODULE_NAME = "_rextio_native"
_SUPPORTED_TARGETS = frozenset(
    {"aarch64-apple-darwin", "x86_64-unknown-linux-gnu"}
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
    _target_triple: str
    _module: ModuleType
    _transaction_seal: bytes

    def __init__(self) -> None:
        raise TypeError("Full C6 native runtime authority requires the sealed factory")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise TypeError("Full C6 native runtime authority is immutable")

    def __delattr__(self, _name: str) -> None:
        raise TypeError("Full C6 native runtime authority is immutable")

    def __copy__(self) -> object:
        raise TypeError("Full C6 native runtime authority cannot be copied")

    def __deepcopy__(self, _memo: object) -> object:
        raise TypeError("Full C6 native runtime authority cannot be copied")

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("Full C6 native runtime authority cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        raise TypeError("Full C6 native runtime authority cannot be serialized")

    def __getstate__(self) -> object:
        raise TypeError("Full C6 native runtime authority cannot be serialized")

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
class _NativeOutputContext:
    output_digest: str
    target_triple: str
    python_root: Path
    extension_path: Path
    wheel_entries: tuple[WheelEntryRef, ...]


@dataclass(frozen=True, slots=True)
class _StaticRuntimeObservations:
    runtime_inventory: NativeRuntimeInventory
    path_resolution: NativeRuntimePathResolutionObservation
    transitive_closure: NativeRuntimeTransitiveClosureObservation


@dataclass(frozen=True, slots=True)
class _FullC6NativeRuntimeMaterial:
    """Validated private material for a later aggregate Full C6 gate."""

    output_transaction: FullC6NativeOutputTransaction
    runtime_inventory: NativeRuntimeInventory
    path_resolution: NativeRuntimePathResolutionObservation
    transitive_closure: NativeRuntimeTransitiveClosureObservation
    runtime_receipt: RuntimeAuthorizationReceipt
    final_snapshot: RuntimeImageSnapshot


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
            "Full C6 native runtime authority could not be established"
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
        authority = _mint_authority(
            output_transaction=output_transaction,
            context=context,
            observations=observations,
            platform_base=platform_base,
            final_snapshot=final_snapshot,
            declared_system_images=declared_images,
            declared_system_platform_images=declared_platform_images,
            runtime_receipt=receipt,
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
        return hmac.compare_digest(authority._transaction_seal, _seal(authority))
    except Exception:
        return False


def _validated_full_c6_native_runtime_material(
    authority: FullC6NativeRuntimeAuthority,
) -> _FullC6NativeRuntimeMaterial:
    if not validate_full_c6_native_runtime_authority(authority):
        raise FullC6NativeRuntimeError("Full C6 native runtime authority is stale")
    return _FullC6NativeRuntimeMaterial(
        output_transaction=authority._output_transaction,
        runtime_inventory=authority._runtime_inventory,
        path_resolution=authority._path_resolution,
        transitive_closure=authority._transitive_closure,
        runtime_receipt=authority._runtime_receipt,
        final_snapshot=authority._final_snapshot,
    )


def _derive_output_context(
    transaction: FullC6NativeOutputTransaction,
) -> _NativeOutputContext:
    receipt = full_c6_native_output_executor_receipt(transaction)
    target = receipt.target_triple
    if type(target) is not str or target not in _SUPPORTED_TARGETS:
        raise FullC6NativeRuntimeError("Full C6 native runtime target is unsupported")
    root = full_c6_native_output_python_root(transaction)
    extension = full_c6_native_output_extension_path(transaction)
    if extension.parent != root or extension.name.split(".", 1)[0] != (
        FULL_C6_NATIVE_RUNTIME_MODULE_NAME
    ):
        raise FullC6NativeRuntimeError("Full C6 native extension identity is invalid")
    return _NativeOutputContext(
        output_digest=transaction.digest,
        target_triple=target,
        python_root=root,
        extension_path=extension,
        wheel_entries=full_c6_native_output_wheel_entries(transaction),
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
        raise FullC6NativeRuntimeError("Full C6 native path resolution is unavailable")
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
        raise FullC6NativeRuntimeError("Full C6 native closure is unavailable")
    observations = _StaticRuntimeObservations(
        runtime_inventory=runtime_inventory,
        path_resolution=refreshed,
        transitive_closure=transitive_closure,
    )
    if not _validate_static_bindings(context, observations):
        raise FullC6NativeRuntimeError("Full C6 native observations are stale")
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
        raise FullC6NativeRuntimeError("Full C6 system image mapping is invalid")
    names = tuple(
        sorted(node.name for node in closure.nodes if node.kind == "system-logical")
    )
    if len(names) != len(set(names)):
        raise FullC6NativeRuntimeError("Full C6 system image mapping is ambiguous")
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
        raise FullC6NativeRuntimeError("Full C6 platform image mapping is invalid")
    for path in platform_base.platform_images:
        basename = PurePosixPath(path).name
        if basename in wanted and _runtime._is_darwin_platform_image_path(path):
            candidates[basename].append(("platform", path))
    if any(len(candidates[name]) != 1 for name in names):
        raise FullC6NativeRuntimeError("Full C6 system image mapping is not exact")
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
        raise FullC6NativeRuntimeError("Full C6 system image mapping is incomplete")
    return regular, platform


def _import_extension_module(extension_path: Path) -> ModuleType:
    """Import only the fixed generated extension name from its derived path."""
    if FULL_C6_NATIVE_RUNTIME_MODULE_NAME in sys.modules:
        raise FullC6NativeRuntimeError("Full C6 native module name is already bound")
    spec = importlib.util.spec_from_file_location(
        FULL_C6_NATIVE_RUNTIME_MODULE_NAME,
        extension_path,
    )
    if spec is None or spec.loader is None:
        raise FullC6NativeRuntimeError("Full C6 native extension loader is unavailable")
    module = importlib.util.module_from_spec(spec)
    if type(module) is not ModuleType:
        raise FullC6NativeRuntimeError("Full C6 native extension module is invalid")
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
        raise FullC6NativeRuntimeError("Full C6 native module binding changed")
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
        "runtime_authorized": True,
        "complete_for_runtime_scope": True,
        "distribution_authorized": False,
    }


def _seal(authority: FullC6NativeRuntimeAuthority) -> bytes:
    payload = {
        "semantic": _semantic_payload(authority),
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
            "module": id(authority._module),
        },
        "private_path_sha256": hashlib.sha256(
            os.fsencode(getattr(authority._module, "__file__", ""))
        ).hexdigest(),
    }
    return hmac.new(_SEAL_KEY, canonical_json_bytes(payload), hashlib.sha256).digest()


def _require_valid_authority(authority: FullC6NativeRuntimeAuthority) -> None:
    if not validate_full_c6_native_runtime_authority(authority):
        raise FullC6NativeRuntimeError("Full C6 native runtime authority is stale")


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


__all__ = [
    "FULL_C6_NATIVE_RUNTIME_AUTHORITY_DOMAIN",
    "FULL_C6_NATIVE_RUNTIME_MODULE_NAME",
    "FullC6NativeRuntimeAuthority",
    "FullC6NativeRuntimeError",
    "create_full_c6_native_runtime_authority",
    "validate_full_c6_native_runtime_authority",
]
