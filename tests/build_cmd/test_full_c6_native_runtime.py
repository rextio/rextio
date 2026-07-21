from __future__ import annotations

from collections.abc import Iterator
from copy import copy, deepcopy
from dataclasses import dataclass, replace
import hashlib
import inspect
import json
import os
from pathlib import Path
import pickle
import sys
import threading
from types import ModuleType
from typing import Any

import pytest

from rextio.artifacts.evidence import (
    NativeRuntimeInventory,
    NativeRuntimePathResolutionInventory,
    NativeRuntimeTransitiveClosureEdge,
    NativeRuntimeTransitiveClosureInventory,
    NativeRuntimeTransitiveClosureNode,
    WheelEntryRef,
)
from rextio.build import full_c6_native_runtime as native_runtime
from rextio.build.full_c6_native_output import FullC6NativeOutputTransaction
from rextio.build.full_c6_native_runtime import (
    FULL_C6_NATIVE_RUNTIME_MODULE_NAME,
    FullC6NativeRuntimeAuthority,
    FullC6NativeRuntimeError,
    create_full_c6_native_runtime_authority,
    validate_full_c6_native_runtime_authority,
)
from rextio.build.runtime_authorization import (
    REASON_AUTHORIZED,
    REASON_LOAD_SET,
    REASON_PROBE_FAILED,
    REASON_STATIC_INVALID,
    RUNTIME_AUTHORIZED,
    RUNTIME_DENIED,
    RUNTIME_VERIFICATION_NATIVE_FRESH,
    RuntimeAuthorizationReceipt,
    RuntimeAuthorizationResult,
    RuntimeImageSnapshot,
    RuntimeLoadedImage,
    capture_runtime_image_snapshot,
    capture_runtime_loaded_image,
)
from rextio.build.runtime_closure import NativeRuntimeTransitiveClosureObservation
from rextio.build.runtime_resolution import (
    NativeRuntimePathResolutionObservation,
    _read_candidate_secure,
)


@dataclass(frozen=True, slots=True)
class _Case:
    output: FullC6NativeOutputTransaction
    context: native_runtime._NativeOutputContext
    observations: native_runtime._StaticRuntimeObservations
    platform_base: RuntimeImageSnapshot
    final_snapshot: RuntimeImageSnapshot
    runtime_receipt: RuntimeAuthorizationReceipt


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _case(tmp_path: Path) -> _Case:
    root = tmp_path / "private-python-root"
    root.mkdir()
    extension = root / "_rextio_native.so"
    extension.write_bytes(b"sealed-native-extension")
    digest = _sha(extension)
    size = extension.stat().st_size
    wheel_entry = WheelEntryRef(
        name=extension.name,
        sha256=digest,
        compressed_size=size,
        uncompressed_size=size,
    )
    inventory = NativeRuntimeInventory(
        format="mach-o",
        architecture="aarch64",
        inspector="otool",
        subject_basename=extension.name,
        subject_sha256=digest,
        subject_size=size,
        wheel_member=extension.name,
        wheel_member_sha256=digest,
        wheel_member_size=size,
    )
    resolution_inventory = NativeRuntimePathResolutionInventory(
        subject_wheel_member=extension.name,
        subject_sha256=digest,
        records=(),
    )
    resolution = NativeRuntimePathResolutionObservation(
        inventory=resolution_inventory,
        receipts=(),
    )
    root_node = NativeRuntimeTransitiveClosureNode(
        kind="wheel-member",
        format="mach-o",
        name=extension.name,
        wheel_member=extension.name,
        sha256=digest,
        size=size,
    )
    closure_inventory = NativeRuntimeTransitiveClosureInventory(
        format="mach-o",
        architecture="aarch64",
        subject_wheel_member=extension.name,
        subject_sha256=digest,
        subject_size=size,
        root_node_ref=root_node.node_ref,
        nodes=(root_node,),
        edges=(),
    )
    platform = tmp_path / "python-runtime"
    platform.write_bytes(b"python-runtime")
    platform_base = capture_runtime_image_snapshot((platform,))
    extension_image = capture_runtime_loaded_image(extension)
    final = capture_runtime_image_snapshot((platform, extension))
    # Capture path receipts only after all fixture siblings exist, because the
    # secure receipt binds every absolute ancestor directory stamp.
    closure = NativeRuntimeTransitiveClosureObservation(
        inventory=closure_inventory,
        receipts=(_read_candidate_secure(root=root, parts=(extension.name,)),),
    )
    observations = native_runtime._StaticRuntimeObservations(
        runtime_inventory=inventory,
        path_resolution=resolution,
        transitive_closure=closure,
    )
    receipt = RuntimeAuthorizationReceipt(
        target_triple="aarch64-apple-darwin",
        extension=extension_image,
        platform_base_sha256=platform_base.digest,
        declared_system_images=(),
        declared_system_platform_images=(),
        newly_loaded_images=(extension_image,),
        newly_loaded_platform_images=(),
        path_resolution_sha256=native_runtime._digest(
            resolution_inventory.to_dict()
        ),
        transitive_closure_sha256=native_runtime._digest(
            closure_inventory.to_dict()
        ),
        load_commands_sha256="1" * 64,
        imported_symbols_sha256="2" * 64,
        final_snapshot_sha256=final.digest,
        verification_mode=RUNTIME_VERIFICATION_NATIVE_FRESH,
    )
    context = native_runtime._NativeOutputContext(
        output_digest="3" * 64,
        target_triple="aarch64-apple-darwin",
        python_root=root,
        extension_path=extension,
        wheel_entries=(wheel_entry,),
    )
    output = object.__new__(FullC6NativeOutputTransaction)
    return _Case(
        output=output,
        context=context,
        observations=observations,
        platform_base=platform_base,
        final_snapshot=final,
        runtime_receipt=receipt,
    )


@pytest.fixture(autouse=True)
def _clean_process_authority_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(native_runtime, "_PROCESS_PID", os.getpid())
    monkeypatch.setattr(
        native_runtime,
        "_PROCESS_STATE",
        native_runtime._PROCESS_STATE_CLEAN,
    )
    monkeypatch.setattr(native_runtime, "_PROCESS_AUTHORITY", None)


@pytest.fixture
def runtime_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[_Case]:
    case = _case(tmp_path)
    sys.modules.pop(FULL_C6_NATIVE_RUNTIME_MODULE_NAME, None)
    monkeypatch.setattr(
        native_runtime,
        "validate_full_c6_native_output_transaction",
        lambda value: value is case.output,
    )
    monkeypatch.setattr(
        native_runtime,
        "_derive_output_context",
        lambda value: case.context
        if value is case.output
        else (_ for _ in ()).throw(FullC6NativeRuntimeError()),
    )
    monkeypatch.setattr(
        native_runtime,
        "_collect_static_observations",
        lambda context: case.observations,
    )
    monkeypatch.setattr(
        native_runtime,
        "collect_loaded_runtime_images",
        lambda target: (
            case.final_snapshot
            if FULL_C6_NATIVE_RUNTIME_MODULE_NAME in sys.modules
            else case.platform_base
        ),
    )
    monkeypatch.setattr(
        native_runtime,
        "verify_native_runtime_authorization",
        lambda receipt: receipt is case.runtime_receipt,
    )

    def import_extension(path: Path) -> ModuleType:
        module = ModuleType(FULL_C6_NATIVE_RUNTIME_MODULE_NAME)
        module.__file__ = str(path)
        sys.modules[FULL_C6_NATIVE_RUNTIME_MODULE_NAME] = module
        return module

    monkeypatch.setattr(native_runtime, "_import_extension_module", import_extension)

    def authorize(**kwargs: Any) -> RuntimeAuthorizationResult:
        kwargs["import_action"]()
        return RuntimeAuthorizationResult(
            status=RUNTIME_AUTHORIZED,
            reason=REASON_AUTHORIZED,
            receipt=case.runtime_receipt,
        )

    monkeypatch.setattr(native_runtime, "authorize_native_runtime", authorize)
    yield case
    sys.modules.pop(FULL_C6_NATIVE_RUNTIME_MODULE_NAME, None)


def test_factory_exposes_only_the_sealed_output_transaction(
    runtime_case: _Case,
) -> None:
    signature = inspect.signature(create_full_c6_native_runtime_authority)
    assert tuple(signature.parameters) == ("output_transaction",)

    authority = create_full_c6_native_runtime_authority(runtime_case.output)

    assert validate_full_c6_native_runtime_authority(authority) is True
    projection = authority.to_dict()
    serialized = json.dumps(projection, sort_keys=True)
    assert projection["runtime_authorized"] is True
    assert projection["distribution_authorized"] is False
    assert projection["runtime_receipt_sha256"] == runtime_case.runtime_receipt.digest
    assert str(runtime_case.context.python_root) not in serialized
    assert str(runtime_case.context.extension_path) not in serialized
    assert str(runtime_case.context.python_root) not in repr(authority)
    assert authority.digest == projection["digest"]


def test_authority_is_immutable_noncopyable_and_nonserializable(
    runtime_case: _Case,
) -> None:
    authority = create_full_c6_native_runtime_authority(runtime_case.output)

    with pytest.raises(TypeError):
        authority.extra = True
    with pytest.raises(TypeError):
        del authority._module
    with pytest.raises(TypeError):
        copy(authority)
    with pytest.raises(TypeError):
        deepcopy(authority)
    with pytest.raises(TypeError):
        pickle.dumps(authority)
    with pytest.raises(TypeError):
        FullC6NativeRuntimeAuthority()


def test_exact_types_reject_input_and_authority_subclasses(
    runtime_case: _Case,
) -> None:
    class OutputSubclass(FullC6NativeOutputTransaction):
        pass

    class AuthoritySubclass(FullC6NativeRuntimeAuthority):
        pass

    output_subclass = object.__new__(OutputSubclass)
    authority_subclass = object.__new__(AuthoritySubclass)

    with pytest.raises(FullC6NativeRuntimeError):
        create_full_c6_native_runtime_authority(output_subclass)
    assert validate_full_c6_native_runtime_authority(authority_subclass) is False


def test_stale_output_invalidates_the_sealed_authority(
    runtime_case: _Case, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority = create_full_c6_native_runtime_authority(runtime_case.output)
    monkeypatch.setattr(
        native_runtime,
        "validate_full_c6_native_output_transaction",
        lambda _value: False,
    )

    assert validate_full_c6_native_runtime_authority(authority) is False
    with pytest.raises(FullC6NativeRuntimeError):
        _ = authority.digest


def test_process_seal_rejects_internal_tampering(runtime_case: _Case) -> None:
    authority = create_full_c6_native_runtime_authority(runtime_case.output)
    object.__setattr__(authority, "_target_triple", "x86_64-unknown-linux-gnu")

    assert validate_full_c6_native_runtime_authority(authority) is False


def test_current_runtime_mismatch_invalidates_authority(
    runtime_case: _Case, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority = create_full_c6_native_runtime_authority(runtime_case.output)
    monkeypatch.setattr(
        native_runtime,
        "verify_native_runtime_authorization",
        lambda _receipt: False,
    )

    assert validate_full_c6_native_runtime_authority(authority) is False


def test_stale_static_observation_invalidates_authority(
    runtime_case: _Case, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority = create_full_c6_native_runtime_authority(runtime_case.output)
    monkeypatch.setattr(
        native_runtime,
        "verify_native_runtime_path_resolution",
        lambda _observation, *, expected_python_root: False,
    )

    assert validate_full_c6_native_runtime_authority(authority) is False


def test_module_binding_mismatch_invalidates_authority(runtime_case: _Case) -> None:
    authority = create_full_c6_native_runtime_authority(runtime_case.output)
    sys.modules[FULL_C6_NATIVE_RUNTIME_MODULE_NAME] = ModuleType("replacement")

    assert validate_full_c6_native_runtime_authority(authority) is False


def test_post_import_loader_mismatch_never_mints_authority(
    runtime_case: _Case, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        native_runtime,
        "collect_loaded_runtime_images",
        lambda _target: runtime_case.platform_base,
    )

    with pytest.raises(FullC6NativeRuntimeError):
        create_full_c6_native_runtime_authority(runtime_case.output)


def test_import_failure_collapses_to_the_bounded_factory_error(
    runtime_case: _Case, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_import(_path: Path) -> ModuleType:
        raise ImportError(f"private path: {runtime_case.context.extension_path}")

    def deny_after_import(**kwargs: Any) -> RuntimeAuthorizationResult:
        try:
            kwargs["import_action"]()
        except ImportError:
            pass
        return RuntimeAuthorizationResult(
            status=RUNTIME_DENIED,
            reason=REASON_PROBE_FAILED,
        )

    monkeypatch.setattr(native_runtime, "_import_extension_module", fail_import)
    monkeypatch.setattr(native_runtime, "authorize_native_runtime", deny_after_import)

    with pytest.raises(FullC6NativeRuntimeError) as captured:
        create_full_c6_native_runtime_authority(runtime_case.output)
    assert str(runtime_case.context.extension_path) not in str(captured.value)


def test_denied_runtime_result_never_mints_authority(
    runtime_case: _Case, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        native_runtime,
        "authorize_native_runtime",
        lambda **_kwargs: RuntimeAuthorizationResult(
            status=RUNTIME_DENIED,
            reason=REASON_PROBE_FAILED,
        ),
    )

    with pytest.raises(FullC6NativeRuntimeError):
        create_full_c6_native_runtime_authority(runtime_case.output)
    assert native_runtime._PROCESS_STATE == native_runtime._PROCESS_STATE_TAINTED


def test_success_claims_one_process_authority_even_if_module_binding_is_removed(
    runtime_case: _Case,
) -> None:
    authority = create_full_c6_native_runtime_authority(runtime_case.output)
    sys.modules.pop(FULL_C6_NATIVE_RUNTIME_MODULE_NAME, None)

    with pytest.raises(FullC6NativeRuntimeError):
        create_full_c6_native_runtime_authority(runtime_case.output)

    assert native_runtime._PROCESS_STATE == native_runtime._PROCESS_STATE_AUTHORIZED
    assert native_runtime._PROCESS_AUTHORITY is authority


def test_pure_preimport_denial_restores_clean_state_for_one_retry(
    runtime_case: _Case, monkeypatch: pytest.MonkeyPatch
) -> None:
    successful_authorize = native_runtime.authorize_native_runtime
    monkeypatch.setattr(
        native_runtime,
        "authorize_native_runtime",
        lambda **_kwargs: RuntimeAuthorizationResult(
            status=RUNTIME_DENIED,
            reason=REASON_STATIC_INVALID,
        ),
    )

    with pytest.raises(FullC6NativeRuntimeError):
        create_full_c6_native_runtime_authority(runtime_case.output)
    assert native_runtime._PROCESS_STATE == native_runtime._PROCESS_STATE_CLEAN

    monkeypatch.setattr(
        native_runtime, "authorize_native_runtime", successful_authorize
    )
    authority = create_full_c6_native_runtime_authority(runtime_case.output)
    assert validate_full_c6_native_runtime_authority(authority) is True


def test_failed_import_permanently_taints_retry_after_module_cleanup(
    runtime_case: _Case, monkeypatch: pytest.MonkeyPatch
) -> None:
    successful_authorize = native_runtime.authorize_native_runtime

    def deny_after_import(**kwargs: Any) -> RuntimeAuthorizationResult:
        kwargs["import_action"]()
        return RuntimeAuthorizationResult(
            status=RUNTIME_DENIED,
            reason=REASON_LOAD_SET,
        )

    monkeypatch.setattr(
        native_runtime, "authorize_native_runtime", deny_after_import
    )
    with pytest.raises(FullC6NativeRuntimeError):
        create_full_c6_native_runtime_authority(runtime_case.output)
    assert native_runtime._PROCESS_STATE == native_runtime._PROCESS_STATE_TAINTED

    sys.modules.pop(FULL_C6_NATIVE_RUNTIME_MODULE_NAME, None)
    monkeypatch.setattr(
        native_runtime, "authorize_native_runtime", successful_authorize
    )
    with pytest.raises(FullC6NativeRuntimeError):
        create_full_c6_native_runtime_authority(runtime_case.output)


def test_undeclared_dso_cannot_be_laundered_into_retry_platform_base(
    runtime_case: _Case, monkeypatch: pytest.MonkeyPatch
) -> None:
    poison = RuntimeLoadedImage(
        path="/usr/lib/rextio-undeclared-runtime.so",
        device=max(image.device for image in runtime_case.platform_base.images) + 1,
        inode=max(image.inode for image in runtime_case.platform_base.images) + 1,
        sha256=hashlib.sha256(b"undeclared-runtime").hexdigest(),
        size=len(b"undeclared-runtime"),
    )
    poisoned_base = RuntimeImageSnapshot(
        images=tuple(
            sorted(
                (*runtime_case.platform_base.images, poison),
                key=lambda image: image.path,
            )
        )
    )
    poisoned_final = RuntimeImageSnapshot(
        images=tuple(
            sorted(
                (*runtime_case.final_snapshot.images, poison),
                key=lambda image: image.path,
            )
        )
    )
    poisoned_receipt = replace(
        runtime_case.runtime_receipt,
        platform_base_sha256=poisoned_base.digest,
        final_snapshot_sha256=poisoned_final.digest,
    )
    poisoned = False
    collector_calls = 0
    authorizer_calls = 0

    def collect(_target: str) -> RuntimeImageSnapshot:
        nonlocal collector_calls
        collector_calls += 1
        if not poisoned:
            return runtime_case.platform_base
        if FULL_C6_NATIVE_RUNTIME_MODULE_NAME in sys.modules:
            return poisoned_final
        return poisoned_base

    def authorize(**kwargs: Any) -> RuntimeAuthorizationResult:
        nonlocal authorizer_calls, poisoned
        authorizer_calls += 1
        kwargs["import_action"]()
        if authorizer_calls == 1:
            poisoned = True
            return RuntimeAuthorizationResult(
                status=RUNTIME_DENIED,
                reason=REASON_LOAD_SET,
            )
        return RuntimeAuthorizationResult(
            status=RUNTIME_AUTHORIZED,
            reason=REASON_AUTHORIZED,
            receipt=poisoned_receipt,
        )

    monkeypatch.setattr(native_runtime, "collect_loaded_runtime_images", collect)
    monkeypatch.setattr(native_runtime, "authorize_native_runtime", authorize)
    monkeypatch.setattr(
        native_runtime,
        "verify_native_runtime_authorization",
        lambda receipt: receipt is poisoned_receipt,
    )

    with pytest.raises(FullC6NativeRuntimeError):
        create_full_c6_native_runtime_authority(runtime_case.output)
    assert poisoned is True
    assert native_runtime._PROCESS_STATE == native_runtime._PROCESS_STATE_TAINTED

    sys.modules.pop(FULL_C6_NATIVE_RUNTIME_MODULE_NAME, None)
    calls_before_retry = collector_calls
    with pytest.raises(FullC6NativeRuntimeError):
        create_full_c6_native_runtime_authority(runtime_case.output)
    assert collector_calls == calls_before_retry
    assert authorizer_calls == 1


def test_concurrent_attempts_execute_only_one_import_transaction(
    runtime_case: _Case, monkeypatch: pytest.MonkeyPatch
) -> None:
    successful_authorize = native_runtime.authorize_native_runtime
    entered = threading.Event()
    release = threading.Event()
    second_started = threading.Event()
    results: list[FullC6NativeRuntimeAuthority] = []
    failures: list[BaseException] = []
    authorizer_calls = 0

    def blocked_authorize(**kwargs: Any) -> RuntimeAuthorizationResult:
        nonlocal authorizer_calls
        authorizer_calls += 1
        entered.set()
        if not release.wait(timeout=5):
            raise RuntimeError("concurrent test release timed out")
        return successful_authorize(**kwargs)

    monkeypatch.setattr(
        native_runtime, "authorize_native_runtime", blocked_authorize
    )

    def run(*, second: bool) -> None:
        if second:
            second_started.set()
        try:
            results.append(
                create_full_c6_native_runtime_authority(runtime_case.output)
            )
        except BaseException as exc:
            failures.append(exc)

    first = threading.Thread(target=run, kwargs={"second": False})
    second = threading.Thread(target=run, kwargs={"second": True})
    first.start()
    assert entered.wait(timeout=5)
    second.start()
    assert second_started.wait(timeout=5)
    release.set()
    first.join(timeout=5)
    second.join(timeout=5)

    assert first.is_alive() is False
    assert second.is_alive() is False
    assert len(results) == 1
    assert len(failures) == 1
    assert isinstance(failures[0], FullC6NativeRuntimeError)
    assert authorizer_calls == 1
    assert native_runtime._PROCESS_AUTHORITY is results[0]


def test_pid_drift_rejects_inherited_authority_and_factory(
    runtime_case: _Case, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority = create_full_c6_native_runtime_authority(runtime_case.output)
    origin_pid = native_runtime._PROCESS_PID
    monkeypatch.setattr(native_runtime.os, "getpid", lambda: origin_pid + 1)

    assert validate_full_c6_native_runtime_authority(authority) is False
    with pytest.raises(FullC6NativeRuntimeError):
        create_full_c6_native_runtime_authority(runtime_case.output)


def _system_closure(name: str) -> NativeRuntimeTransitiveClosureInventory:
    root = NativeRuntimeTransitiveClosureNode(
        kind="wheel-member",
        format="mach-o",
        name="_rextio_native.so",
        wheel_member="_rextio_native.so",
        sha256="4" * 64,
        size=1,
    )
    system = NativeRuntimeTransitiveClosureNode(
        kind="system-logical",
        format="mach-o",
        name=name,
    )
    edge = NativeRuntimeTransitiveClosureEdge(
        source_ref=root.node_ref,
        target_ref=system.node_ref,
        dependency_name=name,
        mechanism="macho-system",
    )
    return NativeRuntimeTransitiveClosureInventory(
        format="mach-o",
        architecture="aarch64",
        subject_wheel_member="_rextio_native.so",
        subject_sha256="4" * 64,
        subject_size=1,
        root_node_ref=root.node_ref,
        nodes=tuple(sorted((root, system), key=lambda node: node.node_ref)),
        edges=(edge,),
    )


def test_system_image_mapping_requires_one_exact_loaded_identity() -> None:
    name = "libSystem.B.dylib"
    closure = _system_closure(name)
    exact = RuntimeImageSnapshot(
        images=(),
        platform_images=(f"/usr/lib/{name}",),
    )

    assert native_runtime._resolve_system_images(
        target_triple="aarch64-apple-darwin",
        platform_base=exact,
        closure=closure,
    ) == ((), (f"/usr/lib/{name}",))

    with pytest.raises(FullC6NativeRuntimeError):
        native_runtime._resolve_system_images(
            target_triple="aarch64-apple-darwin",
            platform_base=RuntimeImageSnapshot(images=()),
            closure=closure,
        )

    regular = RuntimeLoadedImage(
        path=f"/System/Library/Frameworks/{name}",
        device=1,
        inode=2,
        sha256="5" * 64,
        size=1,
    )
    ambiguous = RuntimeImageSnapshot(
        images=(regular,),
        platform_images=(f"/usr/lib/{name}",),
    )
    with pytest.raises(FullC6NativeRuntimeError):
        native_runtime._resolve_system_images(
            target_triple="aarch64-apple-darwin",
            platform_base=ambiguous,
            closure=closure,
        )
