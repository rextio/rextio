"""Persistent, process-sealed native output for the bounded Full C6 profile.

Only a validated native executor authority can supply bytes and contracts to
this module.  The caller selects an already-created private state directory;
the factory derives every other identity and path, writes each file exactly
once, and treats any incomplete or changed deterministic tree as stale state.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import secrets
import stat
import threading
from types import ModuleType
from typing import SupportsIndex
import unicodedata

from rextio.artifacts.evidence import (
    ArtifactEvidenceError,
    EvidenceFileRef,
    WheelEntryRef,
    canonical_json_bytes,
    inventory_wheel_zip_bytes,
)
from rextio.build import full_c6_executor as _executor
from rextio.build.full_c6_cargo_workspace import (
    FullC6CargoDependencyWorkspaceReceipt,
)
from rextio.build.full_c6_executor import (
    FullC6ExecutorReceipt,
    FullC6NativeExecutionAuthority,
    validate_full_c6_native_execution_authority,
)
from rextio.build.full_c6_subject_wheel import (
    FullC6SubjectWheelError,
    FullC6SubjectWheelTransaction,
    capture_full_c6_subject_wheel,
    validate_full_c6_subject_wheel_transaction,
)
from rextio.build.runtime_authorization import (
    RuntimeAuthorizationError,
    RuntimeLoadedImage,
    capture_runtime_loaded_image,
)
from rextio.build.toolchain_identity import BuildToolchainIdentity
from rextio.build.wheel_builder import ExternalWheelNativeMemberIdentity


FULL_C6_NATIVE_OUTPUT_TRANSACTION_DOMAIN = "rextio.full-c6-native-output.v1"
FULL_C6_NATIVE_OUTPUT_DIRECTORY = "full-c6-native-output"
_DIRECTORY_MODE = 0o700
_FILE_MODE = 0o600
_MAX_AUTHORITY_DIRECTORIES = 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_WHEEL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*\.whl$")
_SEAL_KEY = secrets.token_bytes(32)
_PROCESS_LOCK = threading.RLock()


class FullC6NativeOutputError(RuntimeError):
    """A native output could not be materialized or revalidated exactly."""


class FullC6NativeOutputTransaction:
    """Immutable process-local authority over one persistent native output."""

    __slots__ = (
        "_authority",
        "_authority_digest",
        "_subject_wheel",
        "_executor_receipt",
        "_cargo_workspace",
        "_toolchain",
        "_state_directory",
        "_output_root",
        "_authority_root",
        "_wheel_path",
        "_python_root",
        "_native_extension_path",
        "_wheel_filename",
        "_native_member",
        "_snapshot",
        "_native_image",
        "_transaction_seal",
    )

    _authority: FullC6NativeExecutionAuthority
    _authority_digest: str
    _subject_wheel: FullC6SubjectWheelTransaction
    _executor_receipt: FullC6ExecutorReceipt
    _cargo_workspace: FullC6CargoDependencyWorkspaceReceipt
    _toolchain: BuildToolchainIdentity
    _state_directory: Path
    _output_root: Path
    _authority_root: Path
    _wheel_path: Path
    _python_root: Path
    _native_extension_path: Path
    _wheel_filename: str
    _native_member: ExternalWheelNativeMemberIdentity
    _snapshot: _TreeSnapshot
    _native_image: RuntimeLoadedImage
    _transaction_seal: bytes

    def __init__(self) -> None:
        raise TypeError("Full C6 native output transaction requires the materializer")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise TypeError("Full C6 native output transaction is immutable")

    def __delattr__(self, _name: str) -> None:
        raise TypeError("Full C6 native output transaction is immutable")

    def __copy__(self) -> object:
        raise TypeError("Full C6 native output transaction cannot be copied")

    def __deepcopy__(self, _memo: object) -> object:
        raise TypeError("Full C6 native output transaction cannot be copied")

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("Full C6 native output transaction cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        raise TypeError("Full C6 native output transaction cannot be serialized")

    def __getstate__(self) -> object:
        raise TypeError("Full C6 native output transaction cannot be serialized")

    def __repr__(self) -> str:
        return (
            "FullC6NativeOutputTransaction("
            f"authority_sha256={self._authority_digest!r}, material=<sealed>)"
        )

    @property
    def digest(self) -> str:
        """Return the path-free semantic digest after complete revalidation."""
        _require_valid_transaction(self)
        return _digest(_semantic_payload(self))

    def to_dict(self) -> dict[str, str]:
        """Return digest-only identities without paths, bytes, or filenames."""
        _require_valid_transaction(self)
        payload = _semantic_payload(self)
        return {**payload, "digest": _digest(payload)}


class _DirectoryIdentity:
    __slots__ = ("device", "inode", "mode", "uid")

    def __init__(self, observed: os.stat_result) -> None:
        self.device = observed.st_dev
        self.inode = observed.st_ino
        self.mode = stat.S_IMODE(observed.st_mode)
        self.uid = observed.st_uid

    def __eq__(self, other: object) -> bool:
        return type(other) is _DirectoryIdentity and self.to_dict() == other.to_dict()

    def to_dict(self) -> dict[str, int]:
        return {
            "device": self.device,
            "inode": self.inode,
            "mode": self.mode,
            "uid": self.uid,
        }


class _FileIdentity:
    __slots__ = ("device", "inode", "mode", "uid", "links", "sha256", "size")

    def __init__(self, observed: os.stat_result, *, sha256: str) -> None:
        self.device = observed.st_dev
        self.inode = observed.st_ino
        self.mode = stat.S_IMODE(observed.st_mode)
        self.uid = observed.st_uid
        self.links = observed.st_nlink
        self.sha256 = sha256
        self.size = observed.st_size

    def __eq__(self, other: object) -> bool:
        return type(other) is _FileIdentity and self.to_dict() == other.to_dict()

    def to_dict(self) -> dict[str, int | str]:
        return {
            "device": self.device,
            "inode": self.inode,
            "mode": self.mode,
            "uid": self.uid,
            "links": self.links,
            "sha256": self.sha256,
            "size": self.size,
        }


class _TreeSnapshot:
    __slots__ = (
        "state_directory",
        "output_root",
        "authority_root",
        "wheel_directory",
        "python_root",
        "wheel_file",
        "native_file",
    )

    def __init__(
        self,
        *,
        state_directory: _DirectoryIdentity,
        output_root: _DirectoryIdentity,
        authority_root: _DirectoryIdentity,
        wheel_directory: _DirectoryIdentity,
        python_root: _DirectoryIdentity,
        wheel_file: _FileIdentity,
        native_file: _FileIdentity,
    ) -> None:
        self.state_directory = state_directory
        self.output_root = output_root
        self.authority_root = authority_root
        self.wheel_directory = wheel_directory
        self.python_root = python_root
        self.wheel_file = wheel_file
        self.native_file = native_file

    def __eq__(self, other: object) -> bool:
        return type(other) is _TreeSnapshot and self.to_dict() == other.to_dict()

    def to_dict(self) -> dict[str, object]:
        return {
            "directories": {
                "state-directory": self.state_directory.to_dict(),
                "output-root": self.output_root.to_dict(),
                "authority-root": self.authority_root.to_dict(),
                "wheel-directory": self.wheel_directory.to_dict(),
                "python-root": self.python_root.to_dict(),
            },
            "files": {
                "wheel": self.wheel_file.to_dict(),
                "native-extension": self.native_file.to_dict(),
            },
        }


class _PreparedMaterial:
    __slots__ = (
        "executor",
        "authority_digest",
        "subject",
        "wheel_entries",
    )

    def __init__(
        self,
        *,
        executor: _executor._FullC6NativeOutputMaterial,
        authority_digest: str,
        subject: EvidenceFileRef,
        wheel_entries: tuple[WheelEntryRef, ...],
    ) -> None:
        self.executor = executor
        self.authority_digest = authority_digest
        self.subject = subject
        self.wheel_entries = wheel_entries


def materialize_full_c6_native_output(
    authority: FullC6NativeExecutionAuthority,
    *,
    state_directory: Path | str,
) -> FullC6NativeOutputTransaction:
    """Persist one executor-derived wheel/native pair without repair or overwrite.

    ``state_directory`` must already exist as a symlink-free directory owned by
    the current user with mode ``0700``.  This lets the future coordinator own
    state-root creation while this factory owns only its deterministic subtree.
    """
    if (
        type(authority) is not FullC6NativeExecutionAuthority
        or not validate_full_c6_native_execution_authority(authority)
    ):
        raise FullC6NativeOutputError("Full C6 native authority is invalid")
    prepared = _prepare_material(authority)
    state_path = _lexical_absolute_state_path(state_directory)
    paths = _deterministic_paths(state_path, prepared)
    transaction: FullC6NativeOutputTransaction | None = None

    with _PROCESS_LOCK:
        state_fd, _state_identity = _open_state_directory(state_path)
        output_fd = -1
        try:
            output_fd, created_output = _create_or_open_directory(
                state_fd,
                FULL_C6_NATIVE_OUTPUT_DIRECTORY,
                label="native output root",
            )
            _require_name_binding(
                state_fd,
                FULL_C6_NATIVE_OUTPUT_DIRECTORY,
                output_fd,
                label="native output root",
            )
            _require_present_without_alias(
                state_fd,
                FULL_C6_NATIVE_OUTPUT_DIRECTORY,
                label="native output root",
            )
            _lock_directory(output_fd)
            try:
                existing_authorities = _validate_output_root_inventory(output_fd)
                if (
                    prepared.authority_digest not in existing_authorities
                    and len(existing_authorities) >= _MAX_AUTHORITY_DIRECTORIES
                ):
                    raise FullC6NativeOutputError(
                        "Full C6 native output root cannot accept another authority"
                    )
                authority_fd, created_authority = _create_or_open_directory(
                    output_fd,
                    prepared.authority_digest,
                    label="native authority directory",
                )
                try:
                    if created_authority:
                        _materialize_new_authority_tree(
                            authority_fd,
                            prepared=prepared,
                        )
                        _sync_directory(output_fd)
                    snapshot = _capture_tree(
                        state_fd=state_fd,
                        output_fd=output_fd,
                        authority_fd=authority_fd,
                        prepared=prepared,
                    )
                finally:
                    os.close(authority_fd)
                _require_name_binding(
                    output_fd,
                    prepared.authority_digest,
                    None,
                    expected=snapshot.authority_root,
                    label="native authority directory",
                )
                if created_output:
                    _sync_directory(state_fd)

                subject_wheel = capture_full_c6_subject_wheel(
                    paths["wheel"],
                    expected_subject=prepared.subject,
                    expected_wheel_entries=prepared.wheel_entries,
                    external_contract=prepared.executor.external_contract,
                    native_member_path=prepared.executor.native_member.path,
                    expected_native_member_sha256=prepared.executor.native_member.sha256,
                    expected_native_member_size=prepared.executor.native_member.size,
                    output_license_contract=prepared.executor.output_license_contract,
                )
                native_image = capture_runtime_loaded_image(paths["native"])
                _require_native_image(snapshot.native_file, native_image)

                authority_fd = _open_child_directory(
                    output_fd,
                    prepared.authority_digest,
                    label="native authority directory",
                )
                try:
                    final_snapshot = _capture_tree(
                        state_fd=state_fd,
                        output_fd=output_fd,
                        authority_fd=authority_fd,
                        prepared=prepared,
                    )
                finally:
                    os.close(authority_fd)
                if final_snapshot != snapshot:
                    raise FullC6NativeOutputError(
                        "Full C6 native output changed during materialization"
                    )
                _validate_output_root_inventory(output_fd)
                _require_present_without_alias(
                    state_fd,
                    FULL_C6_NATIVE_OUTPUT_DIRECTORY,
                    label="native output root",
                )
                transaction = _mint_transaction(
                    authority=authority,
                    prepared=prepared,
                    subject_wheel=subject_wheel,
                    state_path=state_path,
                    paths=paths,
                    snapshot=snapshot,
                    native_image=native_image,
                )
            finally:
                _unlock_directory(output_fd)
        except (OSError, ValueError, TypeError, ArtifactEvidenceError) as exc:
            raise FullC6NativeOutputError(
                "Full C6 native output could not be materialized safely"
            ) from exc
        finally:
            if output_fd >= 0:
                os.close(output_fd)
            os.close(state_fd)
    if transaction is None or not validate_full_c6_native_output_transaction(transaction):
        raise FullC6NativeOutputError(
            "Full C6 native output changed before sealing completed"
        )
    return transaction


def validate_full_c6_native_output_transaction(
    transaction: FullC6NativeOutputTransaction,
) -> bool:
    """Revalidate the process seal, authority, inventory, paths, and exact bytes."""
    if type(transaction) is not FullC6NativeOutputTransaction:
        return False
    try:
        if (
            type(transaction._transaction_seal) is not bytes
            or not hmac.compare_digest(transaction._transaction_seal, _seal(transaction))
            or type(transaction._authority) is not FullC6NativeExecutionAuthority
            or not validate_full_c6_native_execution_authority(transaction._authority)
        ):
            return False
        prepared = _prepare_material(transaction._authority)
        if (
            prepared.authority_digest != transaction._authority_digest
            or transaction._executor_receipt is not prepared.executor.executor_receipt
            or transaction._cargo_workspace is not prepared.executor.cargo_workspace
            or transaction._toolchain is not prepared.executor.toolchain
            or type(transaction._toolchain) is not BuildToolchainIdentity
            or transaction._toolchain.digest
            != transaction._executor_receipt.toolchain_sha256
            or transaction._wheel_filename != prepared.executor.wheel_filename
            or transaction._native_member != prepared.executor.native_member
            or type(transaction._subject_wheel) is not FullC6SubjectWheelTransaction
            or transaction._subject_wheel.subject != prepared.subject
            or transaction._subject_wheel.wheel_entries != prepared.wheel_entries
        ):
            return False
        expected_paths = _deterministic_paths(transaction._state_directory, prepared)
        if (
            transaction._output_root != expected_paths["output"]
            or transaction._authority_root != expected_paths["authority"]
            or transaction._wheel_path != expected_paths["wheel"]
            or transaction._python_root != expected_paths["python"]
            or transaction._native_extension_path != expected_paths["native"]
        ):
            return False

        with _PROCESS_LOCK:
            state_fd, _state_identity = _open_state_directory(
                transaction._state_directory
            )
            output_fd = -1
            authority_fd = -1
            try:
                output_fd = _open_child_directory(
                    state_fd,
                    FULL_C6_NATIVE_OUTPUT_DIRECTORY,
                    label="native output root",
                )
                _require_present_without_alias(
                    state_fd,
                    FULL_C6_NATIVE_OUTPUT_DIRECTORY,
                    label="native output root",
                )
                _lock_directory(output_fd)
                try:
                    _validate_output_root_inventory(output_fd)
                    authority_fd = _open_child_directory(
                        output_fd,
                        prepared.authority_digest,
                        label="native authority directory",
                    )
                    observed = _capture_tree(
                        state_fd=state_fd,
                        output_fd=output_fd,
                        authority_fd=authority_fd,
                        prepared=prepared,
                    )
                    if observed != transaction._snapshot:
                        return False
                    if not validate_full_c6_subject_wheel_transaction(
                        transaction._subject_wheel
                    ):
                        return False
                    image = capture_runtime_loaded_image(
                        transaction._native_extension_path
                    )
                    _require_native_image(observed.native_file, image)
                    if image != transaction._native_image:
                        return False
                    final = _capture_tree(
                        state_fd=state_fd,
                        output_fd=output_fd,
                        authority_fd=authority_fd,
                        prepared=prepared,
                    )
                    if final != observed:
                        return False
                    _validate_output_root_inventory(output_fd)
                    _require_present_without_alias(
                        state_fd,
                        FULL_C6_NATIVE_OUTPUT_DIRECTORY,
                        label="native output root",
                    )
                    _require_name_binding(
                        state_fd,
                        FULL_C6_NATIVE_OUTPUT_DIRECTORY,
                        output_fd,
                        label="native output root",
                    )
                    _require_name_binding(
                        output_fd,
                        prepared.authority_digest,
                        authority_fd,
                        label="native authority directory",
                    )
                finally:
                    _unlock_directory(output_fd)
            finally:
                if authority_fd >= 0:
                    os.close(authority_fd)
                if output_fd >= 0:
                    os.close(output_fd)
                os.close(state_fd)
        return hmac.compare_digest(transaction._transaction_seal, _seal(transaction))
    except (
        AttributeError,
        ArtifactEvidenceError,
        FullC6NativeOutputError,
        FullC6SubjectWheelError,
        OSError,
        RuntimeAuthorizationError,
        TypeError,
        ValueError,
    ):
        return False


def full_c6_native_output_subject(
    transaction: FullC6NativeOutputTransaction,
) -> EvidenceFileRef:
    """Return a fresh logical subject identity from a valid transaction."""
    _require_valid_transaction(transaction)
    subject = transaction._subject_wheel.subject
    return EvidenceFileRef(
        logical_path=subject.logical_path,
        sha256=subject.sha256,
        size=subject.size,
        role=subject.role,
    )


def full_c6_native_output_wheel_entries(
    transaction: FullC6NativeOutputTransaction,
) -> tuple[WheelEntryRef, ...]:
    """Return a fresh exact wheel inventory from a valid transaction."""
    _require_valid_transaction(transaction)
    return tuple(
        WheelEntryRef(
            name=item.name,
            sha256=item.sha256,
            compressed_size=item.compressed_size,
            uncompressed_size=item.uncompressed_size,
        )
        for item in transaction._subject_wheel.wheel_entries
    )


def full_c6_native_output_executor_receipt(
    transaction: FullC6NativeOutputTransaction,
) -> FullC6ExecutorReceipt:
    """Return the exact sealed executor receipt from a valid transaction."""
    _require_valid_transaction(transaction)
    return transaction._executor_receipt


def full_c6_native_output_cargo_workspace(
    transaction: FullC6NativeOutputTransaction,
) -> FullC6CargoDependencyWorkspaceReceipt:
    """Return the exact sealed Cargo workspace from a valid transaction."""
    _require_valid_transaction(transaction)
    return transaction._cargo_workspace


def _full_c6_native_output_toolchain_identity(
    transaction: FullC6NativeOutputTransaction,
) -> BuildToolchainIdentity:
    """Return the exact retained toolchain only to the runtime authority."""
    _require_valid_transaction(transaction)
    return transaction._toolchain


def full_c6_native_output_wheel_path(
    transaction: FullC6NativeOutputTransaction,
) -> Path:
    """Return the derived persistent wheel path after exact revalidation."""
    _require_valid_transaction(transaction)
    return Path(transaction._wheel_path)


def full_c6_native_output_python_root(
    transaction: FullC6NativeOutputTransaction,
) -> Path:
    """Return the derived persistent Python root after exact revalidation."""
    _require_valid_transaction(transaction)
    return Path(transaction._python_root)


def full_c6_native_output_extension_path(
    transaction: FullC6NativeOutputTransaction,
) -> Path:
    """Return the derived native extension path after exact revalidation."""
    _require_valid_transaction(transaction)
    return Path(transaction._native_extension_path)


def _prepare_material(authority: FullC6NativeExecutionAuthority) -> _PreparedMaterial:
    material = _executor._validated_full_c6_native_output_material(authority)
    filename = _require_wheel_filename(material.wheel_filename)
    native_name = _require_native_name(material.native_member.path)
    if native_name != material.native_member.path:
        raise FullC6NativeOutputError("Full C6 native member is not canonical")
    if (
        hashlib.sha256(material.native_artifact_bytes).hexdigest()
        != material.native_member.sha256
        or len(material.native_artifact_bytes) != material.native_member.size
    ):
        raise FullC6NativeOutputError("Full C6 native artifact bytes are stale")
    try:
        entries = inventory_wheel_zip_bytes(material.wheel_bytes)
    except ArtifactEvidenceError as exc:
        raise FullC6NativeOutputError("Full C6 wheel inventory is invalid") from exc
    matches = tuple(item for item in entries if item.name == native_name)
    if (
        len(matches) != 1
        or matches[0].sha256 != material.native_member.sha256
        or matches[0].uncompressed_size != material.native_member.size
    ):
        raise FullC6NativeOutputError(
            "Full C6 wheel member differs from the retained native artifact"
        )
    authority_digest = authority.digest
    subject = EvidenceFileRef(
        logical_path=f"dist/{filename}",
        sha256=hashlib.sha256(material.wheel_bytes).hexdigest(),
        size=len(material.wheel_bytes),
        role="host-extension-wheel",
    )
    return _PreparedMaterial(
        executor=material,
        authority_digest=authority_digest,
        subject=subject,
        wheel_entries=entries,
    )


def _deterministic_paths(
    state_path: Path,
    prepared: _PreparedMaterial,
) -> dict[str, Path]:
    output = state_path / FULL_C6_NATIVE_OUTPUT_DIRECTORY
    authority = output / prepared.authority_digest
    wheel_directory = authority / "wheel"
    python_root = authority / "python"
    return {
        "output": output,
        "authority": authority,
        "wheel": wheel_directory / prepared.executor.wheel_filename,
        "python": python_root,
        "native": python_root / prepared.executor.native_member.path,
    }


def _mint_transaction(
    *,
    authority: FullC6NativeExecutionAuthority,
    prepared: _PreparedMaterial,
    subject_wheel: FullC6SubjectWheelTransaction,
    state_path: Path,
    paths: dict[str, Path],
    snapshot: _TreeSnapshot,
    native_image: RuntimeLoadedImage,
) -> FullC6NativeOutputTransaction:
    transaction = object.__new__(FullC6NativeOutputTransaction)
    object.__setattr__(transaction, "_authority", authority)
    object.__setattr__(transaction, "_authority_digest", prepared.authority_digest)
    object.__setattr__(transaction, "_subject_wheel", subject_wheel)
    object.__setattr__(transaction, "_executor_receipt", prepared.executor.executor_receipt)
    object.__setattr__(transaction, "_cargo_workspace", prepared.executor.cargo_workspace)
    object.__setattr__(transaction, "_toolchain", prepared.executor.toolchain)
    object.__setattr__(transaction, "_state_directory", state_path)
    object.__setattr__(transaction, "_output_root", paths["output"])
    object.__setattr__(transaction, "_authority_root", paths["authority"])
    object.__setattr__(transaction, "_wheel_path", paths["wheel"])
    object.__setattr__(transaction, "_python_root", paths["python"])
    object.__setattr__(transaction, "_native_extension_path", paths["native"])
    object.__setattr__(transaction, "_wheel_filename", prepared.executor.wheel_filename)
    object.__setattr__(transaction, "_native_member", prepared.executor.native_member)
    object.__setattr__(transaction, "_snapshot", snapshot)
    object.__setattr__(transaction, "_native_image", native_image)
    object.__setattr__(transaction, "_transaction_seal", b"")
    object.__setattr__(transaction, "_transaction_seal", _seal(transaction))
    return transaction


def _materialize_new_authority_tree(
    authority_fd: int,
    *,
    prepared: _PreparedMaterial,
) -> None:
    _require_exact_inventory(authority_fd, frozenset(), label="new authority directory")
    wheel_fd, wheel_created = _create_or_open_directory(
        authority_fd,
        "wheel",
        label="wheel directory",
    )
    try:
        if not wheel_created:
            raise FullC6NativeOutputError("new Full C6 wheel directory already exists")
        _write_exclusive_file(
            wheel_fd,
            prepared.executor.wheel_filename,
            prepared.executor.wheel_bytes,
        )
        _require_exact_inventory(
            wheel_fd,
            frozenset({prepared.executor.wheel_filename}),
            label="wheel directory",
        )
        _sync_directory(wheel_fd)
    finally:
        os.close(wheel_fd)
    python_fd, python_created = _create_or_open_directory(
        authority_fd,
        "python",
        label="Python directory",
    )
    try:
        if not python_created:
            raise FullC6NativeOutputError("new Full C6 Python directory already exists")
        _write_exclusive_file(
            python_fd,
            prepared.executor.native_member.path,
            prepared.executor.native_artifact_bytes,
        )
        _require_exact_inventory(
            python_fd,
            frozenset({prepared.executor.native_member.path}),
            label="Python directory",
        )
        _sync_directory(python_fd)
    finally:
        os.close(python_fd)
    _require_exact_inventory(
        authority_fd,
        frozenset({"wheel", "python"}),
        label="native authority directory",
    )
    _sync_directory(authority_fd)


def _capture_tree(
    *,
    state_fd: int,
    output_fd: int,
    authority_fd: int,
    prepared: _PreparedMaterial,
) -> _TreeSnapshot:
    _require_secure_directory_stat(os.fstat(state_fd), label="state directory")
    _require_secure_directory_stat(os.fstat(output_fd), label="native output root")
    _require_secure_directory_stat(
        os.fstat(authority_fd), label="native authority directory"
    )
    _require_exact_inventory(
        authority_fd,
        frozenset({"wheel", "python"}),
        label="native authority directory",
    )
    wheel_fd = _open_child_directory(authority_fd, "wheel", label="wheel directory")
    python_fd = _open_child_directory(authority_fd, "python", label="Python directory")
    try:
        _require_exact_inventory(
            wheel_fd,
            frozenset({prepared.executor.wheel_filename}),
            label="wheel directory",
        )
        _require_exact_inventory(
            python_fd,
            frozenset({prepared.executor.native_member.path}),
            label="Python directory",
        )
        wheel_identity = _capture_exact_file(
            wheel_fd,
            prepared.executor.wheel_filename,
            expected=prepared.executor.wheel_bytes,
            label="wheel file",
        )
        native_identity = _capture_exact_file(
            python_fd,
            prepared.executor.native_member.path,
            expected=prepared.executor.native_artifact_bytes,
            label="native extension",
        )
        snapshot = _TreeSnapshot(
            state_directory=_DirectoryIdentity(os.fstat(state_fd)),
            output_root=_DirectoryIdentity(os.fstat(output_fd)),
            authority_root=_DirectoryIdentity(os.fstat(authority_fd)),
            wheel_directory=_DirectoryIdentity(os.fstat(wheel_fd)),
            python_root=_DirectoryIdentity(os.fstat(python_fd)),
            wheel_file=wheel_identity,
            native_file=native_identity,
        )
        _require_exact_inventory(
            wheel_fd,
            frozenset({prepared.executor.wheel_filename}),
            label="wheel directory",
        )
        _require_exact_inventory(
            python_fd,
            frozenset({prepared.executor.native_member.path}),
            label="Python directory",
        )
    finally:
        os.close(python_fd)
        os.close(wheel_fd)
    _require_name_binding(
        authority_fd,
        "wheel",
        None,
        expected=snapshot.wheel_directory,
        label="wheel directory",
    )
    _require_name_binding(
        authority_fd,
        "python",
        None,
        expected=snapshot.python_root,
        label="Python directory",
    )
    _require_exact_inventory(
        authority_fd,
        frozenset({"wheel", "python"}),
        label="native authority directory",
    )
    return snapshot


def _lexical_absolute_state_path(value: Path | str) -> Path:
    if not (type(value) is str or isinstance(value, Path)):
        raise TypeError("Full C6 state directory must be a string or Path")
    raw = os.fspath(value)
    if (
        type(raw) is not str
        or not raw
        or "\0" in raw
        or not os.path.isabs(raw)
        or os.path.abspath(raw) != raw
        or unicodedata.normalize("NFC", raw) != raw
    ):
        raise FullC6NativeOutputError(
            "Full C6 state directory must be lexical, absolute, and NFC"
        )
    return Path(raw)


def _open_state_directory(path: Path) -> tuple[int, _DirectoryIdentity]:
    flags = _directory_open_flags()
    current = os.open(os.path.sep, flags)
    try:
        for component in path.parts[1:]:
            next_fd = _open_child_directory(
                current,
                component,
                label="state path component",
                require_private=False,
            )
            os.close(current)
            current = next_fd
        observed = os.fstat(current)
        _require_secure_directory_stat(observed, label="state directory")
        return current, _DirectoryIdentity(observed)
    except FullC6NativeOutputError:
        os.close(current)
        raise
    except OSError as exc:
        os.close(current)
        raise FullC6NativeOutputError(
            "Full C6 state directory could not be opened safely"
        ) from exc


def _create_or_open_directory(
    parent_fd: int,
    name: str,
    *,
    label: str,
) -> tuple[int, bool]:
    names = _stable_names(parent_fd, label=f"{label} parent")
    _reject_alias(names, name, label=label)
    created = False
    if name not in names:
        try:
            os.mkdir(name, _DIRECTORY_MODE, dir_fd=parent_fd)
            created = True
        except FileExistsError:
            created = False
    descriptor = _open_child_directory(parent_fd, name, label=label)
    _require_name_binding(parent_fd, name, descriptor, label=label)
    return descriptor, created


def _open_child_directory(
    parent_fd: int,
    name: str,
    *,
    label: str,
    require_private: bool = True,
) -> int:
    before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise FullC6NativeOutputError(f"Full C6 {label} is not a real directory")
    descriptor = os.open(name, _directory_open_flags(), dir_fd=parent_fd)
    try:
        opened = os.fstat(descriptor)
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not _same_stat(before, opened) or not _same_stat(opened, named):
            raise FullC6NativeOutputError(f"Full C6 {label} changed during open")
        if require_private:
            _require_secure_directory_stat(opened, label=label)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _require_secure_directory_stat(observed: os.stat_result, *, label: str) -> None:
    if (
        not stat.S_ISDIR(observed.st_mode)
        or stat.S_ISLNK(observed.st_mode)
        or stat.S_IMODE(observed.st_mode) != _DIRECTORY_MODE
        or observed.st_uid != _current_uid()
    ):
        raise FullC6NativeOutputError(
            f"Full C6 {label} must be owner-owned mode 0700"
        )


def _require_name_binding(
    parent_fd: int,
    name: str,
    descriptor: int | None,
    *,
    label: str,
    expected: _DirectoryIdentity | None = None,
) -> None:
    observed = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISDIR(observed.st_mode) or stat.S_ISLNK(observed.st_mode):
        raise FullC6NativeOutputError(f"Full C6 {label} name is not a directory")
    actual = _DirectoryIdentity(os.fstat(descriptor) if descriptor is not None else observed)
    if expected is not None and actual != expected:
        raise FullC6NativeOutputError(f"Full C6 {label} identity changed")
    if (observed.st_dev, observed.st_ino) != (actual.device, actual.inode):
        raise FullC6NativeOutputError(f"Full C6 {label} name binding changed")
    _require_secure_directory_stat(observed, label=label)


def _validate_output_root_inventory(output_fd: int) -> tuple[str, ...]:
    before = os.fstat(output_fd)
    names = _stable_names(output_fd, label="native output root")
    if len(names) > _MAX_AUTHORITY_DIRECTORIES:
        raise FullC6NativeOutputError("Full C6 native output root exceeds its bound")
    for name in names:
        if _SHA256.fullmatch(name) is None:
            raise FullC6NativeOutputError(
                "Full C6 native output root contains an unexpected member"
            )
        descriptor = _open_child_directory(
            output_fd,
            name,
            label="native authority directory",
        )
        os.close(descriptor)
    if not _same_directory_stamp(before, os.fstat(output_fd)):
        raise FullC6NativeOutputError(
            "Full C6 native output root changed during validation"
        )
    return names


def _require_present_without_alias(
    directory_fd: int,
    name: str,
    *,
    label: str,
) -> None:
    names = _stable_names(directory_fd, label=f"{label} parent")
    _reject_alias(names, name, label=label)
    if name not in names:
        raise FullC6NativeOutputError(f"Full C6 {label} is missing")


def _require_exact_inventory(
    directory_fd: int,
    expected: frozenset[str],
    *,
    label: str,
) -> None:
    names = _stable_names(directory_fd, label=label)
    if frozenset(names) != expected:
        raise FullC6NativeOutputError(
            f"Full C6 {label} contains missing, extra, or aliased members"
        )


def _stable_names(directory_fd: int, *, label: str) -> tuple[str, ...]:
    before = os.fstat(directory_fd)
    names = tuple(os.listdir(directory_fd))
    after = os.fstat(directory_fd)
    if not _same_directory_stamp(before, after):
        raise FullC6NativeOutputError(f"Full C6 {label} changed during enumeration")
    aliases: set[str] = set()
    for name in names:
        if type(name) is not str or not name or unicodedata.normalize("NFC", name) != name:
            raise FullC6NativeOutputError(f"Full C6 {label} contains a noncanonical name")
        alias = unicodedata.normalize("NFC", name).casefold()
        if alias in aliases:
            raise FullC6NativeOutputError(f"Full C6 {label} contains aliased names")
        aliases.add(alias)
    return tuple(sorted(names))


def _reject_alias(names: tuple[str, ...], expected: str, *, label: str) -> None:
    alias = unicodedata.normalize("NFC", expected).casefold()
    if any(
        unicodedata.normalize("NFC", name).casefold() == alias and name != expected
        for name in names
    ):
        raise FullC6NativeOutputError(f"Full C6 {label} has a case/NFC alias")


def _write_exclusive_file(directory_fd: int, name: str, data: bytes) -> None:
    names = _stable_names(directory_fd, label="native output file parent")
    _reject_alias(names, name, label="native output file")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_BINARY", 0)
    )
    descriptor = os.open(name, flags, _FILE_MODE, dir_fd=directory_fd)
    try:
        observed = os.fstat(descriptor)
        _require_secure_file_stat(observed, expected_size=0, label="new output file")
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise FullC6NativeOutputError("Full C6 output write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        final = os.fstat(descriptor)
        _require_secure_file_stat(
            final,
            expected_size=len(data),
            label="new output file",
        )
    finally:
        os.close(descriptor)


def _capture_exact_file(
    directory_fd: int,
    name: str,
    *,
    expected: bytes,
    label: str,
) -> _FileIdentity:
    before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    _require_secure_file_stat(before, expected_size=len(expected), label=label)
    descriptor = os.open(name, _file_open_flags(), dir_fd=directory_fd)
    try:
        opened = os.fstat(descriptor)
        if not _same_stat(before, opened):
            raise FullC6NativeOutputError(f"Full C6 {label} changed during open")
        chunks: list[bytes] = []
        remaining = len(expected)
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise FullC6NativeOutputError(f"Full C6 {label} exceeds expected size")
        data = b"".join(chunks)
        final = os.fstat(descriptor)
        if not _same_stat(opened, final):
            raise FullC6NativeOutputError(f"Full C6 {label} changed while reading")
    finally:
        os.close(descriptor)
    named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    if not _same_stat(final, named) or not hmac.compare_digest(data, expected):
        raise FullC6NativeOutputError(f"Full C6 {label} bytes or identity changed")
    return _FileIdentity(final, sha256=hashlib.sha256(data).hexdigest())


def _require_secure_file_stat(
    observed: os.stat_result,
    *,
    expected_size: int,
    label: str,
) -> None:
    if (
        not stat.S_ISREG(observed.st_mode)
        or stat.S_ISLNK(observed.st_mode)
        or observed.st_nlink != 1
        or stat.S_IMODE(observed.st_mode) != _FILE_MODE
        or observed.st_uid != _current_uid()
        or observed.st_size != expected_size
    ):
        raise FullC6NativeOutputError(
            f"Full C6 {label} must be an owner-owned unaliased mode 0600 file"
        )


def _require_native_image(expected: _FileIdentity, image: RuntimeLoadedImage) -> None:
    if (
        image.device != expected.device
        or image.inode != expected.inode
        or image.sha256 != expected.sha256
        or image.size != expected.size
    ):
        raise FullC6NativeOutputError("Full C6 runtime native image identity changed")


def _semantic_payload(transaction: FullC6NativeOutputTransaction) -> dict[str, str]:
    receipt = transaction._executor_receipt
    cargo = transaction._cargo_workspace
    target = receipt.target_triple
    if type(target) is not str or not target:
        raise FullC6NativeOutputError("Full C6 native target identity is missing")
    toolchain = _require_digest(receipt.toolchain_sha256, label="toolchain")
    cargo_executable = _require_digest(
        receipt.cargo_executable_sha256,
        label="Cargo executable",
    )
    driver = _require_digest(
        receipt.postprocessor_manifest_sha256,
        label="native driver",
    )
    return {
        "domain": FULL_C6_NATIVE_OUTPUT_TRANSACTION_DOMAIN,
        "authority_sha256": transaction._authority_digest,
        "subject_transaction_sha256": transaction._subject_wheel.digest,
        "subject_sha256": transaction._subject_wheel.subject.sha256,
        "wheel_inventory_sha256": _digest(
            [item.to_dict() for item in transaction._subject_wheel.wheel_entries]
        ),
        "wheel_filename_sha256": _digest_text(transaction._wheel_filename),
        "native_member_identity_sha256": _digest(
            {
                "path": transaction._native_member.path,
                "sha256": transaction._native_member.sha256,
                "size": transaction._native_member.size,
            }
        ),
        "native_member_sha256": transaction._native_member.sha256,
        "staging_identity_sha256": _digest(transaction._snapshot.to_dict()),
        "runtime_image_identity_sha256": _digest(
            {
                "device": transaction._native_image.device,
                "inode": transaction._native_image.inode,
                "sha256": transaction._native_image.sha256,
                "size": transaction._native_image.size,
            }
        ),
        "target_triple_sha256": _digest_text(target),
        "executor_receipt_sha256": receipt.digest,
        "cargo_workspace_sha256": cargo.digest,
        "cargo_sources_sha256": cargo.cargo_sources.digest,
        "toolchain_sha256": toolchain,
        "cargo_executable_sha256": cargo_executable,
        "native_driver_sha256": driver,
    }


def _seal(transaction: FullC6NativeOutputTransaction) -> bytes:
    payload = {
        "semantic": _semantic_payload(transaction),
        "authority_object_id": id(transaction._authority),
        "subject_object_id": id(transaction._subject_wheel),
        "toolchain_object_id": id(transaction._toolchain),
        "paths": {
            name: hashlib.sha256(os.fsencode(path)).hexdigest()
            for name, path in (
                ("state", transaction._state_directory),
                ("output", transaction._output_root),
                ("authority", transaction._authority_root),
                ("wheel", transaction._wheel_path),
                ("python", transaction._python_root),
                ("native", transaction._native_extension_path),
            )
        },
    }
    return hmac.new(_SEAL_KEY, canonical_json_bytes(payload), hashlib.sha256).digest()


def _require_valid_transaction(transaction: FullC6NativeOutputTransaction) -> None:
    if (
        type(transaction) is not FullC6NativeOutputTransaction
        or not validate_full_c6_native_output_transaction(transaction)
    ):
        raise FullC6NativeOutputError("Full C6 native output transaction is stale")


def _require_wheel_filename(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > 512
        or unicodedata.normalize("NFC", value) != value
        or PurePosixPath(value).name != value
        or PureWindowsPath(value).name != value
        or _WHEEL_NAME.fullmatch(value) is None
    ):
        raise FullC6NativeOutputError("Full C6 wheel filename is not canonical")
    return value


def _require_native_name(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > 512
        or unicodedata.normalize("NFC", value) != value
        or PurePosixPath(value).name != value
        or PureWindowsPath(value).name != value
        or not value.startswith("_rextio_native.")
        or not value.endswith((".so", ".pyd"))
    ):
        raise FullC6NativeOutputError("Full C6 native member name is not canonical")
    return value


def _require_digest(value: object, *, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise FullC6NativeOutputError(f"Full C6 {label} digest is invalid")
    return value


def _directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_BINARY", 0)
    )


def _file_open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_BINARY", 0)
    )


def _same_stat(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        first.st_dev,
        first.st_ino,
        first.st_mode,
        first.st_uid,
        first.st_nlink,
        first.st_size,
        first.st_mtime_ns,
        first.st_ctime_ns,
    ) == (
        second.st_dev,
        second.st_ino,
        second.st_mode,
        second.st_uid,
        second.st_nlink,
        second.st_size,
        second.st_mtime_ns,
        second.st_ctime_ns,
    )


def _same_directory_stamp(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        first.st_dev,
        first.st_ino,
        first.st_mode,
        first.st_uid,
        first.st_nlink,
        first.st_mtime_ns,
        first.st_ctime_ns,
    ) == (
        second.st_dev,
        second.st_ino,
        second.st_mode,
        second.st_uid,
        second.st_nlink,
        second.st_mtime_ns,
        second.st_ctime_ns,
    )


def _current_uid() -> int:
    getter = getattr(os, "geteuid", None) or getattr(os, "getuid", None)
    if getter is None:
        raise FullC6NativeOutputError("Full C6 native state requires POSIX ownership")
    return int(getter())


def _fcntl_module() -> ModuleType:
    if os.name != "posix":
        raise FullC6NativeOutputError("Full C6 native state locking requires POSIX")
    try:
        return importlib.import_module("fcntl")
    except ImportError as exc:
        raise FullC6NativeOutputError("Full C6 native state locking is unavailable") from exc


def _lock_directory(descriptor: int) -> None:
    module = _fcntl_module()
    module.flock(descriptor, module.LOCK_EX)


def _unlock_directory(descriptor: int) -> None:
    if descriptor < 0:
        return
    module = _fcntl_module()
    module.flock(descriptor, module.LOCK_UN)


def _sync_directory(descriptor: int) -> None:
    os.fsync(descriptor)


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


__all__ = [
    "FULL_C6_NATIVE_OUTPUT_DIRECTORY",
    "FULL_C6_NATIVE_OUTPUT_TRANSACTION_DOMAIN",
    "FullC6NativeOutputError",
    "FullC6NativeOutputTransaction",
    "full_c6_native_output_cargo_workspace",
    "full_c6_native_output_executor_receipt",
    "full_c6_native_output_extension_path",
    "full_c6_native_output_python_root",
    "full_c6_native_output_subject",
    "full_c6_native_output_wheel_entries",
    "full_c6_native_output_wheel_path",
    "materialize_full_c6_native_output",
    "validate_full_c6_native_output_transaction",
]
