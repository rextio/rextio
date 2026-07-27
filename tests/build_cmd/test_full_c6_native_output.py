"""Adversarial tests for persistent Full C6 native output transactions."""

from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
import json
import os
import pickle
from dataclasses import replace
from pathlib import Path
import runpy
import stat

import pytest


_HELPERS = runpy.run_path(str(Path(__file__).with_name("test_full_c6_executor.py")))


def _authority(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import rextio.build.full_c6_executor as executor

    root = tmp_path / "native-authority"
    source = _HELPERS["_native_project"](root)
    native_tools, environment, toolchain, cargo_workspace = _HELPERS["_native_inputs"](
        root,
        source,
    )
    _HELPERS["_use_fixed_pyo3_profile"].__wrapped__(monkeypatch)
    _HELPERS["_install_successful_native_run"](monkeypatch, executor)
    return executor.execute_full_c6_native_two_build(
        source,
        *_HELPERS["_roots"](root),
        base_environment=environment,
        source_date_epoch=1,
        toolchain=toolchain,
        native_tools=native_tools,
        cargo_workspace=cargo_workspace,
        output_license_contract=_HELPERS["_output_license_contract"](),
    )


def _state(tmp_path: Path, name: str = "state") -> Path:
    path = tmp_path / name
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def test_native_output_is_factory_only_path_free_and_exactly_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rextio.artifacts.evidence import inventory_wheel_zip_bytes
    from rextio.build.full_c6_native_output import (
        FULL_C6_NATIVE_OUTPUT_DIRECTORY,
        FullC6NativeOutputTransaction,
        full_c6_native_output_cargo_workspace,
        full_c6_native_output_executor_receipt,
        full_c6_native_output_extension_path,
        full_c6_native_output_python_root,
        full_c6_native_output_subject,
        full_c6_native_output_wheel_entries,
        full_c6_native_output_wheel_path,
        materialize_full_c6_native_output,
        validate_full_c6_native_output_transaction,
    )

    authority = _authority(tmp_path, monkeypatch)
    state = _state(tmp_path)
    transaction = materialize_full_c6_native_output(
        authority,
        state_directory=state,
    )

    assert type(transaction) is FullC6NativeOutputTransaction
    assert validate_full_c6_native_output_transaction(transaction)
    with pytest.raises(TypeError):
        FullC6NativeOutputTransaction()
    with pytest.raises(TypeError):
        copy.copy(transaction)
    with pytest.raises(TypeError):
        copy.deepcopy(transaction)
    with pytest.raises(TypeError):
        pickle.dumps(transaction)

    projection = transaction.to_dict()
    serialized = json.dumps(projection, sort_keys=True)
    assert str(tmp_path) not in serialized
    assert authority.wheel_filename not in serialized
    assert authority._wheel_captures[0].native_member.path not in serialized
    assert all(key == "domain" or key.endswith("sha256") or key == "digest" for key in projection)
    assert "wheel_bytes" not in serialized
    assert "path" not in serialized

    wheel_path = full_c6_native_output_wheel_path(transaction)
    python_root = full_c6_native_output_python_root(transaction)
    native_path = full_c6_native_output_extension_path(transaction)
    expected_root = state / FULL_C6_NATIVE_OUTPUT_DIRECTORY / authority.digest
    assert wheel_path == expected_root / "wheel" / authority.wheel_filename
    assert python_root == expected_root / "python"
    assert native_path.parent == python_root
    assert stat.S_IMODE(wheel_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(native_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(expected_root.stat().st_mode) == 0o700
    assert stat.S_IMODE(python_root.stat().st_mode) == 0o700

    subject = full_c6_native_output_subject(transaction)
    entries = full_c6_native_output_wheel_entries(transaction)
    wheel_bytes = wheel_path.read_bytes()
    assert subject.logical_path == f"dist/{authority.wheel_filename}"
    assert subject.sha256 == authority.reproducibility.wheel_sha256
    assert subject.role == "host-extension-wheel"
    assert entries == inventory_wheel_zip_bytes(wheel_bytes)
    native = authority._wheel_captures[0].native_member
    assert tuple(item for item in entries if item.name == native.path)[0].sha256 == native.sha256
    assert full_c6_native_output_executor_receipt(transaction) is authority.executor_receipt
    assert full_c6_native_output_cargo_workspace(transaction) is authority.cargo_workspace


def test_native_output_transfers_exact_private_toolchain_and_seals_its_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rextio.build.full_c6_native_output as native_output

    authority = _authority(tmp_path, monkeypatch)
    retained_toolchain = authority._toolchain
    transaction = native_output.materialize_full_c6_native_output(
        authority,
        state_directory=_state(tmp_path),
    )

    assert transaction._toolchain is retained_toolchain
    assert (
        native_output._full_c6_native_output_toolchain_identity(transaction) is retained_toolchain
    )
    assert transaction.to_dict()["toolchain_sha256"] == retained_toolchain.digest
    assert "_full_c6_native_output_toolchain_identity" not in native_output.__all__

    equal_but_distinct = replace(retained_toolchain)
    assert equal_but_distinct == retained_toolchain
    assert equal_but_distinct is not retained_toolchain
    object.__setattr__(transaction, "_toolchain", equal_but_distinct)
    assert not native_output.validate_full_c6_native_output_transaction(transaction)
    with pytest.raises(native_output.FullC6NativeOutputError, match="stale"):
        native_output._full_c6_native_output_toolchain_identity(transaction)

    object.__setattr__(transaction, "_toolchain", retained_toolchain)
    assert native_output.validate_full_c6_native_output_transaction(transaction)
    assert (
        native_output._full_c6_native_output_toolchain_identity(transaction) is retained_toolchain
    )


def test_native_output_signed_rerun_reuses_exact_inodes_and_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rextio.build.full_c6_native_output import (
        full_c6_native_output_extension_path,
        full_c6_native_output_wheel_path,
        materialize_full_c6_native_output,
    )

    authority = _authority(tmp_path, monkeypatch)
    state = _state(tmp_path)
    first = materialize_full_c6_native_output(authority, state_directory=state)
    first_wheel = full_c6_native_output_wheel_path(first)
    first_native = full_c6_native_output_extension_path(first)
    first_identities = (
        (first_wheel.stat().st_dev, first_wheel.stat().st_ino),
        (first_native.stat().st_dev, first_native.stat().st_ino),
    )

    second = materialize_full_c6_native_output(authority, state_directory=state)
    second_identities = (
        (
            full_c6_native_output_wheel_path(second).stat().st_dev,
            full_c6_native_output_wheel_path(second).stat().st_ino,
        ),
        (
            full_c6_native_output_extension_path(second).stat().st_dev,
            full_c6_native_output_extension_path(second).stat().st_ino,
        ),
    )
    assert second_identities == first_identities
    assert second.digest == first.digest


def test_native_output_rejects_authority_and_transaction_tamper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rextio.build.full_c6_executor as executor
    from rextio.build.full_c6_native_output import (
        FullC6NativeOutputError,
        full_c6_native_output_wheel_path,
        materialize_full_c6_native_output,
        validate_full_c6_native_output_transaction,
    )

    authority = _authority(tmp_path, monkeypatch)
    state = _state(tmp_path)
    original = authority._wheel_filename
    object.__setattr__(authority, "_wheel_filename", "substituted.whl")
    assert not executor.validate_full_c6_native_execution_authority(authority)
    with pytest.raises(FullC6NativeOutputError, match="authority"):
        materialize_full_c6_native_output(authority, state_directory=state)
    object.__setattr__(authority, "_wheel_filename", original)

    transaction = materialize_full_c6_native_output(authority, state_directory=state)
    digest = transaction._authority_digest
    object.__setattr__(transaction, "_authority_digest", "0" * 64)
    assert not validate_full_c6_native_output_transaction(transaction)
    with pytest.raises(FullC6NativeOutputError, match="stale"):
        full_c6_native_output_wheel_path(transaction)
    object.__setattr__(transaction, "_authority_digest", digest)
    assert validate_full_c6_native_output_transaction(transaction)


def test_native_output_requires_existing_absolute_private_nonsymlink_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rextio.build.full_c6_native_output import (
        FULL_C6_NATIVE_OUTPUT_DIRECTORY,
        FullC6NativeOutputError,
        materialize_full_c6_native_output,
    )

    authority = _authority(tmp_path, monkeypatch)
    with pytest.raises(FullC6NativeOutputError):
        materialize_full_c6_native_output(authority, state_directory="relative-state")
    with pytest.raises(FullC6NativeOutputError):
        materialize_full_c6_native_output(
            authority,
            state_directory=tmp_path / "missing-state",
        )
    wrong_mode = _state(tmp_path, "wrong-mode")
    wrong_mode.chmod(0o755)
    with pytest.raises(FullC6NativeOutputError):
        materialize_full_c6_native_output(authority, state_directory=wrong_mode)
    real = _state(tmp_path, "real-state")
    alias = tmp_path / "state-alias"
    alias.symlink_to(real, target_is_directory=True)
    with pytest.raises(FullC6NativeOutputError):
        materialize_full_c6_native_output(authority, state_directory=alias)
    output_symlink_state = _state(tmp_path, "output-symlink-state")
    output_target = _state(tmp_path, "output-symlink-target")
    output_symlink = output_symlink_state / FULL_C6_NATIVE_OUTPUT_DIRECTORY
    output_symlink.symlink_to(
        output_target,
        target_is_directory=True,
    )
    assert output_symlink.is_symlink()
    with pytest.raises(FullC6NativeOutputError):
        materialize_full_c6_native_output(
            authority,
            state_directory=output_symlink_state,
        )


def test_native_output_never_repairs_incomplete_or_aliased_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rextio.build.full_c6_native_output import (
        FULL_C6_NATIVE_OUTPUT_DIRECTORY,
        FullC6NativeOutputError,
        materialize_full_c6_native_output,
    )

    authority = _authority(tmp_path, monkeypatch)
    state = _state(tmp_path, "incomplete")
    output = state / FULL_C6_NATIVE_OUTPUT_DIRECTORY
    output.mkdir(mode=0o700)
    incomplete = output / authority.digest
    incomplete.mkdir(mode=0o700)
    with pytest.raises(FullC6NativeOutputError):
        materialize_full_c6_native_output(authority, state_directory=state)
    assert list(incomplete.iterdir()) == []

    alias_state = _state(tmp_path, "aliased")
    alias = alias_state / FULL_C6_NATIVE_OUTPUT_DIRECTORY.upper()
    alias.mkdir(mode=0o700)
    with pytest.raises(FullC6NativeOutputError):
        materialize_full_c6_native_output(authority, state_directory=alias_state)
    assert set(os.listdir(alias_state)) == {FULL_C6_NATIVE_OUTPUT_DIRECTORY.upper()}


def test_native_output_rejects_the_1025th_authority_before_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rextio.build.full_c6_native_output import (
        FULL_C6_NATIVE_OUTPUT_DIRECTORY,
        FullC6NativeOutputError,
        materialize_full_c6_native_output,
    )

    authority = _authority(tmp_path, monkeypatch)
    state = _state(tmp_path)
    output = state / FULL_C6_NATIVE_OUTPUT_DIRECTORY
    output.mkdir(mode=0o700)
    names: list[str] = []
    ordinal = 0
    while len(names) < 1024:
        candidate = f"{ordinal:064x}"
        ordinal += 1
        if candidate == authority.digest:
            continue
        (output / candidate).mkdir(mode=0o700)
        names.append(candidate)
    with pytest.raises(FullC6NativeOutputError, match="another authority"):
        materialize_full_c6_native_output(authority, state_directory=state)
    assert len(os.listdir(output)) == 1024
    assert not (output / authority.digest).exists()


def test_native_output_rejects_extra_members_and_byte_or_mode_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rextio.build.full_c6_native_output import (
        FullC6NativeOutputError,
        full_c6_native_output_extension_path,
        full_c6_native_output_wheel_path,
        materialize_full_c6_native_output,
        validate_full_c6_native_output_transaction,
    )

    authority = _authority(tmp_path, monkeypatch)

    extra_state = _state(tmp_path, "extra")
    extra = materialize_full_c6_native_output(authority, state_directory=extra_state)
    extra_root = full_c6_native_output_wheel_path(extra).parent.parent
    (extra_root / "unexpected").write_bytes(b"extra")
    assert not validate_full_c6_native_output_transaction(extra)
    with pytest.raises(FullC6NativeOutputError):
        materialize_full_c6_native_output(authority, state_directory=extra_state)

    wheel_state = _state(tmp_path, "wheel-tamper")
    wheel_transaction = materialize_full_c6_native_output(
        authority,
        state_directory=wheel_state,
    )
    wheel = full_c6_native_output_wheel_path(wheel_transaction)
    original = wheel.read_bytes()
    wheel.write_bytes(b"X" + original[1:])
    wheel.chmod(0o600)
    assert not validate_full_c6_native_output_transaction(wheel_transaction)
    with pytest.raises(FullC6NativeOutputError):
        materialize_full_c6_native_output(authority, state_directory=wheel_state)
    assert wheel.read_bytes() != original

    mode_state = _state(tmp_path, "mode-tamper")
    mode_transaction = materialize_full_c6_native_output(
        authority,
        state_directory=mode_state,
    )
    native = full_c6_native_output_extension_path(mode_transaction)
    native.chmod(0o644)
    assert not validate_full_c6_native_output_transaction(mode_transaction)
    with pytest.raises(FullC6NativeOutputError):
        materialize_full_c6_native_output(authority, state_directory=mode_state)

    directory_mode_state = _state(tmp_path, "directory-mode-tamper")
    directory_mode_transaction = materialize_full_c6_native_output(
        authority,
        state_directory=directory_mode_state,
    )
    python_root = full_c6_native_output_extension_path(directory_mode_transaction).parent
    python_root.chmod(0o755)
    assert not validate_full_c6_native_output_transaction(directory_mode_transaction)
    with pytest.raises(FullC6NativeOutputError):
        materialize_full_c6_native_output(
            authority,
            state_directory=directory_mode_state,
        )


@pytest.mark.parametrize("attack", ["symlink", "hardlink", "fifo", "directory-symlink"])
def test_native_output_rejects_link_and_special_file_attacks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attack: str,
) -> None:
    from rextio.build.full_c6_native_output import (
        FullC6NativeOutputError,
        full_c6_native_output_extension_path,
        full_c6_native_output_wheel_path,
        materialize_full_c6_native_output,
        validate_full_c6_native_output_transaction,
    )

    authority = _authority(tmp_path, monkeypatch)
    state = _state(tmp_path)
    transaction = materialize_full_c6_native_output(authority, state_directory=state)
    wheel = full_c6_native_output_wheel_path(transaction)
    native = full_c6_native_output_extension_path(transaction)
    if attack == "symlink":
        saved = state / "saved-native"
        native.rename(saved)
        native.symlink_to(saved)
    elif attack == "hardlink":
        os.link(wheel, state / "wheel-hardlink")
    elif attack == "fifo":
        native.unlink()
        os.mkfifo(native, mode=0o600)
    else:
        wheel_directory = wheel.parent
        saved = state / "saved-wheel-directory"
        wheel_directory.rename(saved)
        wheel_directory.symlink_to(saved, target_is_directory=True)
    assert not validate_full_c6_native_output_transaction(transaction)
    with pytest.raises(FullC6NativeOutputError):
        materialize_full_c6_native_output(authority, state_directory=state)


def test_native_output_concurrent_creation_converges_without_overwrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rextio.build.full_c6_native_output import (
        full_c6_native_output_wheel_path,
        materialize_full_c6_native_output,
        validate_full_c6_native_output_transaction,
    )

    authority = _authority(tmp_path, monkeypatch)
    state = _state(tmp_path)
    with ThreadPoolExecutor(max_workers=4) as pool:
        transactions = tuple(
            pool.map(
                lambda _ordinal: materialize_full_c6_native_output(
                    authority,
                    state_directory=state,
                ),
                range(4),
            )
        )
    assert all(validate_full_c6_native_output_transaction(item) for item in transactions)
    identities = {
        (
            full_c6_native_output_wheel_path(item).stat().st_dev,
            full_c6_native_output_wheel_path(item).stat().st_ino,
        )
        for item in transactions
    }
    assert len(identities) == 1
    assert len({item.digest for item in transactions}) == 1


def test_native_output_detects_a_swap_during_initial_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rextio.build.full_c6_native_output as native_output

    authority = _authority(tmp_path, monkeypatch)
    state = _state(tmp_path)
    original_capture = native_output._capture_exact_file
    swapped = False

    def capture_and_swap(directory_fd, name, *, expected, label):
        nonlocal swapped
        identity = original_capture(
            directory_fd,
            name,
            expected=expected,
            label=label,
        )
        if label == "wheel file" and not swapped:
            swapped = True
            os.rename(
                name,
                f"{name}.old",
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            descriptor = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=directory_fd,
            )
            try:
                os.write(descriptor, expected)
            finally:
                os.close(descriptor)
        return identity

    monkeypatch.setattr(native_output, "_capture_exact_file", capture_and_swap)
    with pytest.raises(native_output.FullC6NativeOutputError):
        native_output.materialize_full_c6_native_output(
            authority,
            state_directory=state,
        )


def test_native_output_owner_check_is_fail_closed_where_uid_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rextio.build.full_c6_native_output as native_output

    authority = _authority(tmp_path, monkeypatch)
    state = _state(tmp_path)
    transaction = native_output.materialize_full_c6_native_output(
        authority,
        state_directory=state,
    )
    monkeypatch.setattr(native_output, "_current_uid", lambda: os.getuid() + 1)
    assert not native_output.validate_full_c6_native_output_transaction(transaction)
    with pytest.raises(native_output.FullC6NativeOutputError):
        native_output.materialize_full_c6_native_output(
            authority,
            state_directory=state,
        )
