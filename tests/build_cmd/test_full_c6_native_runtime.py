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
from rextio.build.toolchain_identity import BuildToolchainIdentity


@dataclass(frozen=True, slots=True)
class _Case:
    output: FullC6NativeOutputTransaction
    context: native_runtime._NativeOutputContext
    observations: native_runtime._StaticRuntimeObservations
    platform_base: RuntimeImageSnapshot
    final_snapshot: RuntimeImageSnapshot
    runtime_receipt: RuntimeAuthorizationReceipt
    toolchain: BuildToolchainIdentity
    symbol_providers: native_runtime._SymbolProviderObservation


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
    toolchain = object.__new__(BuildToolchainIdentity)
    toolchain_sha256 = "4" * 64
    python_abi = native_runtime._PythonAbiIdentity(
        ext_suffix=".so",
        soabi="cpython-311-test",
        ld_library="libpython3.11.dylib",
        inst_soname="libpython3.11.dylib",
        framework=None,
        framework_prefix=None,
        framework_install_dir=None,
    )
    platform_image = platform_base.images[0]
    symbol_providers = native_runtime._SymbolProviderObservation(
        toolchain_sha256=toolchain_sha256,
        python_abi=python_abi,
        python_images=(platform_image,),
        bindings=(
            native_runtime._SymbolProviderBinding(
                symbol="PyLong_FromLong",
                resolution_mode="macho-flat-python",
                resolved_address=123,
                provider_kind="toolchain-python-executable",
                provider_path=platform_image.path,
                provider_identity_sha256=native_runtime._digest(
                    platform_image.to_dict()
                ),
            ),
        ),
    )
    context = native_runtime._NativeOutputContext(
        output_digest="3" * 64,
        target_triple="aarch64-apple-darwin",
        python_root=root,
        extension_path=extension,
        wheel_entries=(wheel_entry,),
        toolchain=toolchain,
        toolchain_sha256=toolchain_sha256,
    )
    output = object.__new__(FullC6NativeOutputTransaction)
    return _Case(
        output=output,
        context=context,
        observations=observations,
        platform_base=platform_base,
        final_snapshot=final,
        runtime_receipt=receipt,
        toolchain=toolchain,
        symbol_providers=symbol_providers,
    )


@pytest.fixture(autouse=True)
def _clean_process_authority_state() -> Iterator[None]:
    native_runtime._PROCESS_PID = os.getpid()
    native_runtime._PROCESS_STATE = native_runtime._PROCESS_STATE_CLEAN
    native_runtime._PROCESS_AUTHORITY = None
    yield
    # Tests deliberately taint this process-local singleton.  Reset it after
    # every case as well as before the next one so no prior authorized/tainted
    # value can leak into another case.
    native_runtime._PROCESS_PID = os.getpid()
    native_runtime._PROCESS_STATE = native_runtime._PROCESS_STATE_CLEAN
    native_runtime._PROCESS_AUTHORITY = None


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
    monkeypatch.setattr(
        native_runtime,
        "_validated_toolchain_digest",
        lambda toolchain: case.context.toolchain_sha256
        if toolchain is case.toolchain
        else (_ for _ in ()).throw(FullC6NativeRuntimeError()),
    )
    monkeypatch.setattr(
        native_runtime,
        "_collect_symbol_provider_observation",
        lambda **_kwargs: case.symbol_providers,
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


def test_provider_drift_taints_the_process_authority(
    runtime_case: _Case, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority = create_full_c6_native_runtime_authority(runtime_case.output)
    changed_abi = replace(
        runtime_case.symbol_providers.python_abi,
        soabi="cpython-311-tampered",
    )
    changed = replace(runtime_case.symbol_providers, python_abi=changed_abi)
    monkeypatch.setattr(
        native_runtime,
        "_collect_symbol_provider_observation",
        lambda **_kwargs: changed,
    )

    assert validate_full_c6_native_runtime_authority(authority) is False
    assert native_runtime._PROCESS_STATE == native_runtime._PROCESS_STATE_TAINTED


def test_symbol_provider_semantics_exclude_aslr_addresses(runtime_case: _Case) -> None:
    authority = create_full_c6_native_runtime_authority(runtime_case.output)
    original = authority._symbol_providers
    original_semantic = native_runtime._semantic_payload(authority)
    original_seal = authority._transaction_seal
    changed_binding = replace(original.bindings[0], resolved_address=987654321)
    changed = replace(original, bindings=(changed_binding,))

    assert original != changed
    assert original.to_dict() == changed.to_dict()
    assert native_runtime._digest(original.to_dict()) == native_runtime._digest(
        changed.to_dict()
    )
    assert "resolved_address" not in repr(original.to_dict())
    object.__setattr__(authority, "_symbol_providers", changed)
    assert native_runtime._semantic_payload(authority) == original_semantic
    assert native_runtime._digest(native_runtime._semantic_payload(authority)) == (
        native_runtime._digest(original_semantic)
    )
    assert native_runtime._seal(authority) != original_seal


def test_macho_import_parser_accepts_flat_python_and_structural_binder() -> None:
    records = (
        native_runtime._runtime._MachoImportedSymbol(
            symbol="_PyLong_FromLong",
            library_ordinal=native_runtime._runtime._MACHO_DYNAMIC_LOOKUP_ORDINAL,
            library_name=None,
            weak_reference=False,
        ),
        native_runtime._runtime._MachoImportedSymbol(
            symbol="___bzero",
            library_ordinal=1,
            library_name="/usr/lib/libSystem.B.dylib",
            weak_reference=False,
        ),
        native_runtime._runtime._MachoImportedSymbol(
            symbol="dyld_stub_binder",
            library_ordinal=1,
            library_name="/usr/lib/libSystem.B.dylib",
            weak_reference=False,
        ),
    )

    imports = native_runtime._macho_imports_from_records(records)

    assert tuple((item.lookup_name, item.mode) for item in imports) == (
        ("PyLong_FromLong", "macho-flat-python"),
        ("__bzero", "macho-two-level"),
        ("dyld_stub_binder", "macho-stub-binder"),
    )


@pytest.mark.parametrize("symbol", ["_memcpy", "dyld_stub_binder"])
def test_macho_import_parser_rejects_unsafe_flat_or_stub_records(
    symbol: str,
) -> None:
    record = native_runtime._runtime._MachoImportedSymbol(
        symbol=symbol,
        library_ordinal=native_runtime._runtime._MACHO_DYNAMIC_LOOKUP_ORDINAL,
        library_name=None,
        weak_reference=False,
    )
    with pytest.raises(FullC6NativeRuntimeError):
        native_runtime._macho_imports_from_records((record,))


def test_elf_import_parser_keeps_same_name_versions_distinct() -> None:
    output = """
  0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
  1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND memcpy@GLIBC_2.14 (2)
  2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND memcpy@GLIBC_2.2.5 (3)
"""

    imports = native_runtime._parse_elf_undefined_imports(output)

    assert tuple(
        (item.lookup_name, item.version, item.version_index, item.raw_name)
        for item in imports
    ) == (
        (
            "memcpy",
            "GLIBC_2.14",
            2,
            "memcpy@GLIBC_2.14 (2) "
            "[type=FUNC;binding=GLOBAL;visibility=DEFAULT]",
        ),
        (
            "memcpy",
            "GLIBC_2.2.5",
            3,
            "memcpy@GLIBC_2.2.5 (3) "
            "[type=FUNC;binding=GLOBAL;visibility=DEFAULT]",
        ),
    )


def test_elf_import_parser_rejects_default_version_definition_marker() -> None:
    output = (
        "  1: 0000000000000000 0 FUNC GLOBAL DEFAULT UND "
        "memcpy@@GLIBC_2.14 (2)\n"
    )

    with pytest.raises(FullC6NativeRuntimeError):
        native_runtime._parse_elf_undefined_imports(output)


def test_macho_python_dependency_parser_consumes_otool_l_blocks() -> None:
    output = """
/tmp/python:
Load command 0
          cmd LC_SEGMENT_64
      cmdsize 72
Load command 1
          cmd LC_LOAD_DYLIB
      cmdsize 88
         name /Library/Frameworks/Python.framework/Versions/3.11/Python (offset 24)
"""

    assert native_runtime._parse_macho_direct_dependencies(output) == (
        "/Library/Frameworks/Python.framework/Versions/3.11/Python",
    )


def test_macho_python_dependency_inspection_uses_sealed_otool_l(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    python = tmp_path / "python"
    python.write_bytes(b"python")
    output = """
Load command 0
          cmd LC_LOAD_DYLIB
      cmdsize 56
         name /usr/lib/libSystem.B.dylib (offset 24)
"""
    commands: list[tuple[str, ...]] = []

    def inspect(command: tuple[str, ...]) -> str:
        commands.append(command)
        return output

    monkeypatch.setattr(native_runtime._runtime, "_run_inspector", inspect)

    assert native_runtime._inspect_python_dependencies(
        python, "aarch64-apple-darwin"
    ) == ("/usr/lib/libSystem.B.dylib",)
    assert commands == [("/usr/bin/otool", "-l", str(python))]


def test_linux_python_identity_prefers_instsoname_over_ldlibrary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    python = tmp_path / "python"
    runtime = tmp_path / "libpython3.11.so.1.0"
    extension = tmp_path / "_rextio_native.so"
    python.write_bytes(b"python")
    runtime.write_bytes(b"runtime")
    extension.write_bytes(b"extension")
    final = capture_runtime_image_snapshot((python, runtime, extension))
    abi = native_runtime._PythonAbiIdentity(
        ext_suffix=".so",
        soabi="cpython-311-x86_64-linux-gnu",
        ld_library="libpython3.11.so",
        inst_soname="libpython3.11.so.1.0",
        framework=None,
        framework_prefix=None,
        framework_install_dir=None,
    )
    context = native_runtime._NativeOutputContext(
        output_digest="a" * 64,
        target_triple="x86_64-unknown-linux-gnu",
        python_root=tmp_path,
        extension_path=extension,
        wheel_entries=(),
        toolchain=object.__new__(BuildToolchainIdentity),
        toolchain_sha256="b" * 64,
    )
    monkeypatch.setattr(
        native_runtime,
        "_verify_toolchain_python_identity",
        lambda _context: (python.resolve(), abi),
    )
    monkeypatch.setattr(
        native_runtime,
        "_inspect_python_dependencies",
        lambda _python, _target: ("libpython3.11.so.1.0",),
    )
    monkeypatch.setattr(
        native_runtime._runtime,
        "_native_system_image_name",
        lambda image, _target: Path(image.path).name,
    )

    observed_python, observed_abi, images = (
        native_runtime._collect_toolchain_python_images(
            context=context,
            final_snapshot=final,
        )
    )

    assert observed_python == python.resolve()
    assert observed_abi is abi
    assert tuple(Path(image.path).name for image in images) == (
        "libpython3.11.so.1.0",
        "python",
    )

    monkeypatch.setattr(
        native_runtime,
        "_inspect_python_dependencies",
        lambda _python, _target: ("libpython3.11.so",),
    )
    with pytest.raises(FullC6NativeRuntimeError):
        native_runtime._collect_toolchain_python_images(
            context=context,
            final_snapshot=final,
        )


def test_macos_framework_identity_uses_exact_direct_image(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install = tmp_path / "Python.framework"
    version_root = install / "Versions" / "3.11"
    python = version_root / "bin" / "python3.11"
    main = (
        version_root
        / "Resources"
        / "Python.app"
        / "Contents"
        / "MacOS"
        / "Python"
    )
    framework = version_root / "Python"
    extension = tmp_path / "_rextio_native.so"
    python.parent.mkdir(parents=True)
    main.parent.mkdir(parents=True)
    python.write_bytes(b"python")
    main.write_bytes(b"main")
    framework.write_bytes(b"framework")
    extension.write_bytes(b"extension")
    final = capture_runtime_image_snapshot((main, framework, extension))
    abi = native_runtime._PythonAbiIdentity(
        ext_suffix=".so",
        soabi="cpython-311-darwin",
        ld_library="libpython3.11.dylib",
        inst_soname="libpython3.11.dylib",
        framework="Python",
        framework_prefix=str(tmp_path),
        framework_install_dir=str(install),
    )
    context = native_runtime._NativeOutputContext(
        output_digest="a" * 64,
        target_triple="aarch64-apple-darwin",
        python_root=tmp_path,
        extension_path=extension,
        wheel_entries=(),
        toolchain=object.__new__(BuildToolchainIdentity),
        toolchain_sha256="b" * 64,
    )
    monkeypatch.setattr(
        native_runtime,
        "_verify_toolchain_python_identity",
        lambda _context: (python.resolve(), abi),
    )
    monkeypatch.setattr(
        native_runtime,
        "_darwin_main_executable_path",
        lambda: main.resolve(),
    )
    monkeypatch.setattr(
        native_runtime,
        "_inspect_python_dependencies",
        lambda _python, _target: (str(framework),),
    )

    _python, _abi, images = native_runtime._collect_toolchain_python_images(
        context=context,
        final_snapshot=final,
    )

    assert _abi is abi
    assert _python == main.resolve()
    assert tuple(Path(image.path).name for image in images) == ("Python", "Python")


def test_macos_nonframework_launcher_must_equal_dyld_main(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    launcher = tmp_path / "python3.11"
    main = tmp_path / "Python.app" / "Contents" / "MacOS" / "Python"
    main.parent.mkdir(parents=True)
    launcher.write_bytes(b"launcher")
    main.write_bytes(b"main")
    abi = native_runtime._PythonAbiIdentity(
        ext_suffix=".so",
        soabi="cpython-311-darwin",
        ld_library=None,
        inst_soname=None,
        framework=None,
        framework_prefix=None,
        framework_install_dir=None,
    )
    context = native_runtime._NativeOutputContext(
        output_digest="a" * 64,
        target_triple="aarch64-apple-darwin",
        python_root=tmp_path,
        extension_path=tmp_path / "_rextio_native.so",
        wheel_entries=(),
        toolchain=object.__new__(BuildToolchainIdentity),
        toolchain_sha256="b" * 64,
    )
    monkeypatch.setattr(
        native_runtime,
        "_verify_toolchain_python_identity",
        lambda _context: (launcher.resolve(), abi),
    )
    monkeypatch.setattr(
        native_runtime,
        "_darwin_main_executable_path",
        lambda: main.resolve(),
    )

    with pytest.raises(FullC6NativeRuntimeError, match="launcher differs"):
        native_runtime._verify_toolchain_python_process_identity(context)


def test_flat_python_provider_uses_only_rtld_default_and_exact_python_image(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    python = tmp_path / "python"
    extension = tmp_path / "_rextio_native.so"
    python.write_bytes(b"python")
    extension.write_bytes(b"extension")
    final = capture_runtime_image_snapshot((python, extension))
    python_image = next(image for image in final.images if image.path == str(python))
    imported = native_runtime._UndefinedImport(
        raw_name="_PyLong_FromLong",
        lookup_name="PyLong_FromLong",
        mode="macho-flat-python",
        qualifier="dynamically looked up",
        macho_library_ordinal=native_runtime._runtime._MACHO_DYNAMIC_LOOKUP_ORDINAL,
    )
    handles: list[int] = []

    def resolve(_process: object, handle: int, _imported: object) -> int:
        handles.append(handle)
        return 123

    monkeypatch.setattr(native_runtime, "_resolve_import_address", resolve)
    monkeypatch.setattr(native_runtime, "_dladdr_provider", lambda *_args: str(python))

    binding = native_runtime._bind_one_symbol_provider(
        process=object(),
        handle=999,
        imported=imported,
        target_triple="aarch64-apple-darwin",
        final_snapshot=final,
        python_executable=python,
        python_images=(python_image,),
        declared_system_images=(),
        declared_system_platform_images=(),
    )

    assert handles == [-2]
    assert binding.provider_kind == "toolchain-python-executable"
    assert binding.resolution_mode == "macho-flat-python"


def test_versioned_resolution_uses_dlvsym_with_exact_version() -> None:
    calls: list[tuple[int, bytes, bytes]] = []

    def dlerror() -> None:
        return None

    def dlvsym(handle: Any, symbol: bytes, version: bytes) -> int:
        calls.append((int(handle.value or 0), symbol, version))
        return 456

    process = type("Process", (), {})()
    process.dlerror = dlerror
    process.dlvsym = dlvsym
    imported = native_runtime._UndefinedImport(
        raw_name="memcpy@GLIBC_2.14 (2)",
        lookup_name="memcpy",
        mode="elf-versioned",
        version="GLIBC_2.14",
        version_index=2,
        elf_symbol_type="FUNC",
        elf_binding="GLOBAL",
        elf_visibility="DEFAULT",
    )

    assert native_runtime._resolve_import_address(process, 17, imported) == 456
    assert calls == [(17, b"memcpy", b"GLIBC_2.14")]


def test_versioned_provider_rejects_handle_default_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    extension = tmp_path / "_rextio_native.so"
    libc = tmp_path / "libc.so.6"
    extension.write_bytes(b"extension")
    libc.write_bytes(b"libc")
    final = capture_runtime_image_snapshot((extension, libc))
    extension_image = next(
        image for image in final.images if image.path == str(extension)
    )
    libc_image = next(image for image in final.images if image.path == str(libc))
    imported = native_runtime._UndefinedImport(
        raw_name="memcpy@GLIBC_2.14 (2)",
        lookup_name="memcpy",
        mode="elf-versioned",
        version="GLIBC_2.14",
        version_index=2,
        elf_symbol_type="FUNC",
        elf_binding="GLOBAL",
        elf_visibility="DEFAULT",
    )
    monkeypatch.setattr(
        native_runtime,
        "_resolve_import_address",
        lambda _process, handle, _imported: 10 if handle == 0 else 11,
    )

    with pytest.raises(FullC6NativeRuntimeError, match="interposed"):
        native_runtime._bind_one_symbol_provider(
            process=object(),
            handle=17,
            imported=imported,
            target_triple="x86_64-unknown-linux-gnu",
            final_snapshot=final,
            python_executable=extension,
            python_images=(extension_image,),
            declared_system_images=(libc_image,),
            declared_system_platform_images=(),
        )


def test_ifunc_alias_is_allowed_only_inside_the_declared_provider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    extension = tmp_path / "_rextio_native.so"
    libc = tmp_path / "libc.so.6"
    rogue = tmp_path / "rogue.so"
    for path in (extension, libc, rogue):
        path.write_bytes(path.name.encode())
    final = capture_runtime_image_snapshot((extension, libc, rogue))
    extension_image = next(
        image for image in final.images if image.path == str(extension)
    )
    libc_image = next(image for image in final.images if image.path == str(libc))
    imported = native_runtime._UndefinedImport(
        raw_name="memcpy@GLIBC_2.14 (2)",
        lookup_name="memcpy",
        mode="elf-versioned",
        version="GLIBC_2.14",
        version_index=2,
        elf_symbol_type="FUNC",
        elf_binding="GLOBAL",
        elf_visibility="DEFAULT",
    )
    monkeypatch.setattr(
        native_runtime,
        "_resolve_import_address",
        lambda _process, _handle, _imported: 777,
    )
    monkeypatch.setattr(native_runtime, "_dladdr_provider", lambda *_args: str(libc))

    binding = native_runtime._bind_one_symbol_provider(
        process=object(),
        handle=17,
        imported=imported,
        target_triple="x86_64-unknown-linux-gnu",
        final_snapshot=final,
        python_executable=extension,
        python_images=(extension_image,),
        declared_system_images=(libc_image,),
        declared_system_platform_images=(),
    )
    assert binding.resolved_address == 777

    monkeypatch.setattr(native_runtime, "_dladdr_provider", lambda *_args: str(rogue))
    with pytest.raises(FullC6NativeRuntimeError):
        native_runtime._bind_one_symbol_provider(
            process=object(),
            handle=17,
            imported=imported,
            target_triple="x86_64-unknown-linux-gnu",
            final_snapshot=final,
            python_executable=extension,
            python_images=(extension_image,),
            declared_system_images=(libc_image,),
            declared_system_platform_images=(),
        )


@pytest.mark.parametrize(
    "symbol",
    ["__cxa_finalize", "_ITM_deregisterTMCloneTable", "__gmon_start__"],
)
def test_unresolved_weak_elf_import_is_an_explicit_non_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    symbol: str,
) -> None:
    extension = tmp_path / "_rextio_native.so"
    extension.write_bytes(b"extension")
    final = capture_runtime_image_snapshot((extension,))
    extension_image = final.images[0]
    imported = native_runtime._parse_elf_undefined_imports(
        "  1: 0000000000000000 0 NOTYPE WEAK DEFAULT UND "
        f"{symbol}\n"
    )[0]
    monkeypatch.setattr(
        native_runtime,
        "_resolve_weak_import_address",
        lambda *_args: None,
    )

    binding = native_runtime._bind_one_symbol_provider(
        process=object(),
        handle=17,
        imported=imported,
        target_triple="x86_64-unknown-linux-gnu",
        final_snapshot=final,
        python_executable=extension,
        python_images=(extension_image,),
        declared_system_images=(),
        declared_system_platform_images=(),
    )

    assert binding.provider_kind == "unresolved-weak"
    assert binding.provider_path is None
    assert binding.resolved_address is None


def test_weak_elf_import_rejects_one_sided_resolution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    extension = tmp_path / "_rextio_native.so"
    extension.write_bytes(b"extension")
    final = capture_runtime_image_snapshot((extension,))
    imported = native_runtime._parse_elf_undefined_imports(
        "  1: 0000000000000000 0 NOTYPE WEAK DEFAULT UND __gmon_start__\n"
    )[0]
    monkeypatch.setattr(
        native_runtime,
        "_resolve_weak_import_address",
        lambda _process, handle, _imported: None if handle == 0 else 7,
    )

    with pytest.raises(FullC6NativeRuntimeError, match="one-sided"):
        native_runtime._bind_one_symbol_provider(
            process=object(),
            handle=17,
            imported=imported,
            target_triple="x86_64-unknown-linux-gnu",
            final_snapshot=final,
            python_executable=extension,
            python_images=(final.images[0],),
            declared_system_images=(),
            declared_system_platform_images=(),
        )


def test_resolved_weak_elf_import_still_requires_declared_snapshot_provider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    extension = tmp_path / "_rextio_native.so"
    libc = tmp_path / "libc.so.6"
    rogue = tmp_path / "rogue.so"
    for path in (extension, libc, rogue):
        path.write_bytes(path.name.encode())
    final = capture_runtime_image_snapshot((extension, libc, rogue))
    extension_image = next(image for image in final.images if image.path == str(extension))
    libc_image = next(image for image in final.images if image.path == str(libc))
    imported = native_runtime._parse_elf_undefined_imports(
        "  1: 0000000000000000 0 NOTYPE WEAK DEFAULT UND __cxa_finalize\n"
    )[0]
    monkeypatch.setattr(
        native_runtime,
        "_resolve_weak_import_address",
        lambda *_args: 777,
    )
    monkeypatch.setattr(native_runtime, "_dladdr_provider", lambda *_args: str(libc))

    binding = native_runtime._bind_one_symbol_provider(
        process=object(),
        handle=17,
        imported=imported,
        target_triple="x86_64-unknown-linux-gnu",
        final_snapshot=final,
        python_executable=extension,
        python_images=(extension_image,),
        declared_system_images=(libc_image,),
        declared_system_platform_images=(),
    )
    assert binding.provider_kind == "declared-system-regular"

    monkeypatch.setattr(native_runtime, "_dladdr_provider", lambda *_args: str(rogue))
    with pytest.raises(FullC6NativeRuntimeError):
        native_runtime._bind_one_symbol_provider(
            process=object(),
            handle=17,
            imported=imported,
            target_triple="x86_64-unknown-linux-gnu",
            final_snapshot=final,
            python_executable=extension,
            python_images=(extension_image,),
            declared_system_images=(libc_image,),
            declared_system_platform_images=(),
        )


@pytest.mark.parametrize(
    "provider",
    [
        "/usr/lib/system/libsystem_platform.dylib",
        "/usr/lib/system/libdispatch.dylib",
        "/usr/lib/system/libdyld.dylib",
        "/usr/lib/system/libunwind.dylib",
    ],
)
def test_shared_cache_libsystem_reexport_is_one_hop_and_never_uses_otool(
    monkeypatch: pytest.MonkeyPatch,
    provider: str,
) -> None:
    root = "/usr/lib/libSystem.B.dylib"
    monkeypatch.setattr(
        native_runtime,
        "_inspect_macho_reexports",
        lambda _path: (_ for _ in ()).throw(AssertionError("otool must not run")),
    )
    final = RuntimeImageSnapshot(
        images=(),
        platform_images=tuple(sorted((provider, root))),
    )
    records = native_runtime._collect_macho_dependency_reexports(
        declared_system_images=(),
        declared_system_platform_images=(root,),
        final_snapshot=final,
        dependency_install_names=(root,),
    )
    imported = native_runtime._UndefinedImport(
        raw_name="_memcpy",
        lookup_name="memcpy",
        mode="macho-two-level",
        qualifier="from libSystem.B.dylib",
        macho_library_ordinal=1,
        macho_install_name=root,
    )

    category = native_runtime._macho_dependency_provider_category(
        imported=imported,
        provider_path=provider,
        provider_image=None,
        python_executable=Path("/private/python"),
        python_images=(),
        declared_system_images=(),
        declared_system_platform_images=(root,),
        reexports=records,
    )

    assert category[0] == "declared-system-platform"
    with pytest.raises(FullC6NativeRuntimeError):
        native_runtime._macho_dependency_provider_category(
            imported=imported,
            provider_path="/usr/lib/system/libsystem_c.dylib",
            provider_image=None,
            python_executable=Path("/private/python"),
            python_images=(),
            declared_system_images=(),
            declared_system_platform_images=(root,),
            reexports=records,
        )


@pytest.mark.parametrize(
    "path",
    [
        "/tmp/libsystem_c.dylib",
        "/usr/lib/system/evil.dylib",
        "/usr/lib/system/libcompiler_rt.dylib",
        "/usr/lib/system/libsystem_C.dylib",
        "/usr/lib/system/libsystem_c.dylib/child",
    ],
)
def test_shared_cache_libsystem_provider_rejects_arbitrary_paths(path: str) -> None:
    assert native_runtime._is_darwin_shared_cache_libsystem_provider(path) is False


def test_shared_cache_libsystem_reexport_rejects_unlisted_descendant() -> None:
    root = "/usr/lib/libSystem.B.dylib"
    provider = "/usr/lib/system/libcompiler_rt.dylib"
    final = RuntimeImageSnapshot(
        images=(),
        platform_images=tuple(sorted((provider, root))),
    )
    with pytest.raises(FullC6NativeRuntimeError, match="providers are unavailable"):
        native_runtime._collect_macho_dependency_reexports(
            declared_system_images=(),
            declared_system_platform_images=(root,),
            final_snapshot=final,
            dependency_install_names=(root,),
        )


@pytest.mark.parametrize(
    "path",
    [
        "/usr/lib/system/libdispatch.dylib",
        "/usr/lib/system/libdyld.dylib",
        "/usr/lib/system/libunwind.dylib",
    ],
)
def test_shared_cache_libsystem_provider_allows_exact_observed_singletons(
    path: str,
) -> None:
    assert native_runtime._is_darwin_shared_cache_libsystem_provider(path)


def test_macho_two_level_provider_rejects_same_basename_wrong_dso() -> None:
    imported = native_runtime._UndefinedImport(
        raw_name="_memcpy",
        lookup_name="memcpy",
        mode="macho-two-level",
        qualifier="from libSame.dylib",
        macho_library_ordinal=1,
        macho_install_name="/usr/lib/libSame.dylib",
    )

    with pytest.raises(FullC6NativeRuntimeError, match="direct dependency"):
        native_runtime._macho_dependency_provider_category(
            imported=imported,
            provider_path="/System/Library/libSame.dylib",
            provider_image=None,
            python_executable=Path("/private/python"),
            python_images=(),
            declared_system_images=(),
            declared_system_platform_images=("/System/Library/libSame.dylib",),
            reexports=(),
        )


def test_macho_reexport_parser_rejects_malformed_load_command_block(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        native_runtime._runtime,
        "_run_inspector",
        lambda _command: "Load command 0\n  cmdsize 72\n",
    )

    with pytest.raises(FullC6NativeRuntimeError, match="malformed"):
        native_runtime._inspect_macho_reexports("/usr/lib/libExample.dylib")


def test_structural_stub_binder_requires_one_declared_libsystem() -> None:
    imported = native_runtime._UndefinedImport(
        raw_name="dyld_stub_binder",
        lookup_name="dyld_stub_binder",
        mode="macho-stub-binder",
        qualifier="from libSystem",
        macho_library_ordinal=1,
        macho_install_name="/usr/lib/libSystem.B.dylib",
    )

    binding = native_runtime._bind_macho_stub_binder(
        imported=imported,
        declared_system_images=(),
        declared_system_platform_images=("/usr/lib/libSystem.B.dylib",),
    )

    assert binding.resolved_address is None
    assert binding.resolution_mode == "macho-stub-binder"
    with pytest.raises(FullC6NativeRuntimeError):
        native_runtime._bind_macho_stub_binder(
            imported=imported,
            declared_system_images=(),
            declared_system_platform_images=(),
        )


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
