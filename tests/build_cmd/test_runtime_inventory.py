"""Security-focused tests for bounded C6.4 native linkage inventory."""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

import pytest

from rextio.artifacts import evidence as evidence_mod
from rextio.artifacts.evidence import (
    ArtifactEvidenceError,
    NativeRuntimeDependency,
    WheelEntryRef,
)
from rextio.build import runtime_inventory


def _elf64_header(machine: int = 62, *, object_type: int = 3) -> bytes:
    """Return the bounded part of one little-endian ELF64 header."""
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4] = 2  # ELFCLASS64
    header[5] = 1  # ELFDATA2LSB
    header[6] = 1  # EV_CURRENT
    header[16:18] = object_type.to_bytes(2, "little")
    header[18:20] = machine.to_bytes(2, "little")
    return bytes(header)


def _macho64_header(cputype: int = 0x0100000C, *, filetype: int = 6) -> bytes:
    """Return one little-endian thin Mach-O 64 header prefix."""
    header = bytearray(32)
    header[:4] = b"\xcf\xfa\xed\xfe"
    header[4:8] = cputype.to_bytes(4, "little")
    header[12:16] = filetype.to_bytes(4, "little")
    return bytes(header)


def _wheel_entry(name: str, payload: bytes) -> WheelEntryRef:
    return WheelEntryRef(
        name=name,
        sha256=hashlib.sha256(payload).hexdigest(),
        compressed_size=len(payload),
        uncompressed_size=len(payload),
    )


def _elf_runtime_case(tmp_path: Path) -> tuple[Path, Path, bytes, tuple[WheelEntryRef, ...]]:
    generated_python = tmp_path / "generated" / "python"
    binary = generated_python / "native" / "_rextio_native.so"
    binary.parent.mkdir(parents=True)
    payload = _elf64_header()
    binary.write_bytes(payload)
    entries = (_wheel_entry("native/_rextio_native.so", payload),)
    return generated_python, binary, payload, entries


def test_installed_binary_must_be_inside_exact_generated_python_root(
    tmp_path: Path,
) -> None:
    generated_python = tmp_path / "project" / ".rextio" / "generated" / "python"
    generated_python.mkdir(parents=True)
    outside = tmp_path / "outside" / "_rextio_native.so"
    outside.parent.mkdir()
    payload = _elf64_header()
    outside.write_bytes(payload)

    with pytest.raises(ArtifactEvidenceError) as raised:
        runtime_inventory.inspect_native_runtime_inventory(
            installed_path=outside,
            expected_python_root=generated_python,
            wheel_entries=(_wheel_entry("_rextio_native.so", payload),),
            target_triple="x86_64-unknown-linux-gnu",
            timeout=10.0,
        )

    assert raised.value.reason == evidence_mod.REASON_RUNTIME_BINARY_MISSING


@pytest.mark.skipif(os.name == "nt", reason="dirfd lifetime test is POSIX-only")
def test_rejected_non_regular_leaf_file_descriptor_is_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    leaf = tmp_path / "leaf"
    leaf.mkdir()
    root_fd = os.open(tmp_path, os.O_RDONLY)
    real_open = runtime_inventory.os.open
    captured_leaf_fd: int | None = None

    def observing_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal captured_leaf_fd
        fd = real_open(path, flags, mode, dir_fd=dir_fd)
        if path == "leaf":
            captured_leaf_fd = fd
        return fd

    monkeypatch.setattr(runtime_inventory.os, "open", observing_open)
    try:
        with pytest.raises(ArtifactEvidenceError):
            runtime_inventory._open_relative_regular_file(root_fd, ("leaf",))
        assert captured_leaf_fd is not None
        with pytest.raises(OSError):
            os.fstat(captured_leaf_fd)
    finally:
        os.close(root_fd)


@pytest.mark.parametrize(
    ("wheel_name", "wheel_size_delta"),
    [
        ("other/_rextio_native.so", 0),
        ("native/_rextio_native.so", 1),
    ],
)
def test_wheel_binding_requires_exact_relative_path_hash_and_size(
    tmp_path: Path,
    wheel_name: str,
    wheel_size_delta: int,
) -> None:
    generated_python = tmp_path / "generated" / "python"
    binary = generated_python / "native" / "_rextio_native.so"
    binary.parent.mkdir(parents=True)
    payload = _elf64_header()
    binary.write_bytes(payload)
    entry = _wheel_entry(wheel_name, payload)
    if wheel_size_delta:
        entry = WheelEntryRef(
            name=entry.name,
            sha256=entry.sha256,
            compressed_size=entry.compressed_size,
            uncompressed_size=entry.uncompressed_size + wheel_size_delta,
        )

    with pytest.raises(ArtifactEvidenceError) as raised:
        runtime_inventory.inspect_native_runtime_inventory(
            installed_path=binary,
            expected_python_root=generated_python,
            wheel_entries=(entry,),
            target_triple="x86_64-unknown-linux-gnu",
            timeout=10.0,
        )

    assert raised.value.reason == evidence_mod.REASON_RUNTIME_WHEEL_MEMBER_MISMATCH


def test_otool_marks_bounded_rpath_as_wheel_candidate() -> None:
    output = (
        "/generated/_rextio_native.so:\n"
        "\t@rpath/libprivate.dylib "
        "(compatibility version 1.0.0, current version 1.0.0)\n"
    )
    parsed = runtime_inventory.parse_otool_l_output(output)
    assert parsed.dependencies == (
        NativeRuntimeDependency(name="libprivate.dylib", origin="wheel-candidate"),
    )


def test_otool_still_rejects_private_absolute_dependency_path() -> None:
    output = (
        "/generated/_rextio_native.so:\n"
        "\t/Users/example/private/libprivate.dylib "
        "(compatibility version 1.0.0, current version 1.0.0)\n"
    )
    with pytest.raises(ArtifactEvidenceError) as raised:
        runtime_inventory.parse_otool_l_output(output)
    assert raised.value.reason == evidence_mod.REASON_RUNTIME_UNSAFE_PATH


def test_otool_drops_only_first_exact_private_cargo_self_install_name() -> None:
    output = (
        "/generated/_rextio_native.cpython-311-darwin.so:\n"
        "\t/private/build/target/release/deps/lib_rextio_native.dylib "
        "(compatibility version 0.0.0, current version 0.0.0)\n"
        "\t/usr/lib/libSystem.B.dylib "
        "(compatibility version 1.0.0, current version 1336.61.1)\n"
    )

    parsed = runtime_inventory.parse_otool_l_output(
        output,
        expected_self_install_basename="lib_rextio_native.dylib",
        verified_self_install_names=frozenset(
            {"/private/build/target/release/deps/lib_rextio_native.dylib"}
        ),
    )

    assert [dependency.name for dependency in parsed.dependencies] == ["libSystem.B.dylib"]
    assert [dependency.origin for dependency in parsed.dependencies] == ["system"]


def test_otool_drops_exact_self_install_name_once_per_architecture_section() -> None:
    output = (
        "/generated/native.so (architecture arm64):\n"
        "\t/private/arm64/lib_rextio_native.dylib "
        "(compatibility version 0.0.0, current version 0.0.0)\n"
        "\t/usr/lib/libSystem.B.dylib "
        "(compatibility version 1.0.0, current version 1336.61.1)\n"
        "/generated/native.so (architecture x86_64):\n"
        "\t/private/x86_64/lib_rextio_native.dylib "
        "(compatibility version 0.0.0, current version 0.0.0)\n"
        "\t/usr/lib/libSystem.B.dylib "
        "(compatibility version 1.0.0, current version 1336.61.1)\n"
    )

    parsed = runtime_inventory.parse_otool_l_output(
        output,
        expected_self_install_basename="lib_rextio_native.dylib",
        verified_self_install_names=frozenset(
            {
                "/private/arm64/lib_rextio_native.dylib",
                "/private/x86_64/lib_rextio_native.dylib",
            }
        ),
    )

    assert parsed.architectures == ("arm64", "x86_64")
    assert [dependency.name for dependency in parsed.dependencies] == ["libSystem.B.dylib"]


@pytest.mark.parametrize(
    "rows",
    [
        (
            "\t/private/first/lib_rextio_native.dylib "
            "(compatibility version 0.0.0, current version 0.0.0)\n"
            "\t/private/later/lib_rextio_native.dylib "
            "(compatibility version 0.0.0, current version 0.0.0)\n"
        ),
        ("\t@rpath/lib_rextio_native.dylib (compatibility version 0.0.0, current version 0.0.0)\n"),
        ("\t/private/build/libother.dylib (compatibility version 0.0.0, current version 0.0.0)\n"),
    ],
)
def test_otool_self_install_exception_does_not_admit_other_unsafe_rows(
    rows: str,
) -> None:
    output = "/generated/_rextio_native.so:\n" + rows

    with pytest.raises(ArtifactEvidenceError) as raised:
        runtime_inventory.parse_otool_l_output(
            output,
            expected_self_install_basename="lib_rextio_native.dylib",
            verified_self_install_names=frozenset({"/private/first/lib_rextio_native.dylib"}),
        )

    assert raised.value.reason == evidence_mod.REASON_RUNTIME_UNSAFE_PATH


def test_otool_basename_without_verified_lc_id_does_not_authorize_drop() -> None:
    output = (
        "/generated/_rextio_native.so:\n"
        "\t/private/build/lib_rextio_native.dylib "
        "(compatibility version 0.0.0, current version 0.0.0)\n"
    )

    with pytest.raises(ArtifactEvidenceError) as raised:
        runtime_inventory.parse_otool_l_output(
            output,
            expected_self_install_basename="lib_rextio_native.dylib",
        )

    assert raised.value.reason == evidence_mod.REASON_RUNTIME_UNSAFE_PATH


@pytest.mark.parametrize(
    "identity",
    [
        "@rpath/lib_rextio_native.dylib",
        "/private/build/libother.dylib",
    ],
)
def test_otool_d_requires_exact_private_absolute_cargo_identity(identity: str) -> None:
    output = f"/snapshot/native.dylib:\n{identity}\n"

    with pytest.raises(ArtifactEvidenceError) as raised:
        runtime_inventory.parse_otool_d_output(
            output,
            expected_self_install_basename="lib_rextio_native.dylib",
        )

    assert raised.value.reason == evidence_mod.REASON_RUNTIME_UNSAFE_PATH


def test_otool_d_returns_verified_exact_private_identity() -> None:
    identity = "/private/build/target/release/deps/lib_rextio_native.dylib"
    output = f"/snapshot/native.dylib:\n{identity}\n"

    assert runtime_inventory.parse_otool_d_output(
        output,
        expected_self_install_basename="lib_rextio_native.dylib",
    ) == frozenset({identity})


def test_macho_inspection_derives_exact_cargo_self_install_basename(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated_python = tmp_path / "generated" / "python"
    binary = generated_python / "native" / "_rextio_native.cpython-311-darwin.so"
    binary.parent.mkdir(parents=True)
    payload = _macho64_header()
    binary.write_bytes(payload)
    monkeypatch.setattr(
        runtime_inventory,
        "_inspector_command",
        lambda path: ("otool", ["/usr/bin/otool", "-L", str(path)]),
    )

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if "-D" in command:
            return subprocess.CompletedProcess(
                command,
                0,
                (f"{command[-1]}:\n/private/build/target/release/deps/lib_rextio_native.dylib\n"),
                "",
            )
        return subprocess.CompletedProcess(
            command,
            0,
            (
                f"{binary}:\n"
                "\t/private/build/target/release/deps/lib_rextio_native.dylib "
                "(compatibility version 0.0.0, current version 0.0.0)\n"
                "\t/usr/lib/libSystem.B.dylib "
                "(compatibility version 1.0.0, current version 1336.61.1)\n"
            ),
            "",
        )

    monkeypatch.setattr(runtime_inventory, "run_build_tool", fake_run)
    inventory = runtime_inventory.inspect_native_runtime_inventory(
        installed_path=binary,
        expected_python_root=generated_python,
        wheel_entries=(_wheel_entry("native/_rextio_native.cpython-311-darwin.so", payload),),
        target_triple="aarch64-apple-darwin",
    )

    assert [dependency.name for dependency in inventory.dependencies] == ["libSystem.B.dylib"]


def test_macho_lc_id_must_exactly_match_first_otool_l_row(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated_python = tmp_path / "generated" / "python"
    binary = generated_python / "native" / "_rextio_native.so"
    binary.parent.mkdir(parents=True)
    payload = _macho64_header()
    binary.write_bytes(payload)
    monkeypatch.setattr(
        runtime_inventory,
        "_inspector_command",
        lambda path: ("otool", ["/usr/bin/otool", "-L", str(path)]),
    )

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if "-D" in command:
            output = f"{command[-1]}:\n/private/verified/lib_rextio_native.dylib\n"
        else:
            output = (
                f"{command[-1]}:\n"
                "\t/private/different/lib_rextio_native.dylib "
                "(compatibility version 0.0.0, current version 0.0.0)\n"
            )
        return subprocess.CompletedProcess(command, 0, output, "")

    monkeypatch.setattr(runtime_inventory, "run_build_tool", fake_run)
    with pytest.raises(ArtifactEvidenceError) as raised:
        runtime_inventory.inspect_native_runtime_inventory(
            installed_path=binary,
            expected_python_root=generated_python,
            wheel_entries=(_wheel_entry("native/_rextio_native.so", payload),),
            target_triple="aarch64-apple-darwin",
        )

    assert raised.value.reason == evidence_mod.REASON_RUNTIME_UNSAFE_PATH


def test_macho_bundle_never_uses_dylib_self_id_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated_python = tmp_path / "generated" / "python"
    binary = generated_python / "native" / "_rextio_native.so"
    binary.parent.mkdir(parents=True)
    payload = _macho64_header(filetype=8)  # MH_BUNDLE
    binary.write_bytes(payload)
    monkeypatch.setattr(
        runtime_inventory,
        "_inspector_command",
        lambda path: ("otool", ["/usr/bin/otool", "-L", str(path)]),
    )

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        assert "-D" not in command
        return subprocess.CompletedProcess(
            command,
            0,
            (
                f"{command[-1]}:\n"
                "\t/private/build/lib_rextio_native.dylib "
                "(compatibility version 0.0.0, current version 0.0.0)\n"
            ),
            "",
        )

    monkeypatch.setattr(runtime_inventory, "run_build_tool", fake_run)
    with pytest.raises(ArtifactEvidenceError) as raised:
        runtime_inventory.inspect_native_runtime_inventory(
            installed_path=binary,
            expected_python_root=generated_python,
            wheel_entries=(_wheel_entry("native/_rextio_native.so", payload),),
            target_triple="aarch64-apple-darwin",
        )

    assert raised.value.reason == evidence_mod.REASON_RUNTIME_UNSAFE_PATH


def test_readelf_accepts_only_origin_anchored_rpath_and_runpath() -> None:
    for tag, label in (("RPATH", "rpath"), ("RUNPATH", "runpath")):
        output = (
            "Dynamic section at offset 0x1000 contains 1 entry:\n"
            "  Tag        Type                         Name/Value\n"
            f" 0x000000000000001d ({tag}) Library {label}: [$ORIGIN/lib]\n"
        )
        parsed = runtime_inventory.parse_readelf_d_output(
            output, target_triple="x86_64-unknown-linux-gnu"
        )
        assert parsed.dependencies == ()

    for unsafe in ("/private/lib", "$LIB/lib", "$ORIGIN/../lib", "$ORIGIN::/lib"):
        output = (
            "Dynamic section at offset 0x1000 contains 1 entry:\n"
            "  Tag        Type                         Name/Value\n"
            f" 0x000000000000001d (RUNPATH) Library runpath: [{unsafe}]\n"
        )
        with pytest.raises(ArtifactEvidenceError) as raised:
            runtime_inventory.parse_readelf_d_output(
                output, target_triple="x86_64-unknown-linux-gnu"
            )
        assert raised.value.reason == evidence_mod.REASON_RUNTIME_UNSAFE_PATH


def test_resolver_rejects_symlinked_parent_inside_generated_root(tmp_path: Path) -> None:
    generated_python = tmp_path / "generated" / "python"
    real_parent = generated_python / "real"
    real_parent.mkdir(parents=True)
    binary = real_parent / "_rextio_native.so"
    binary.write_bytes(_elf64_header())
    linked_parent = generated_python / "native"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    assert (
        runtime_inventory.resolve_installed_native_binary(
            installed_path=str(linked_parent / binary.name),
            expected_python_root=generated_python,
        )
        is None
    )


def test_resolver_normalizes_relative_root_and_installed_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    generated_python = Path("generated/python")
    binary = generated_python / "native" / "_rextio_native.so"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(_elf64_header())

    resolved = runtime_inventory.resolve_installed_native_binary(
        installed_path=str(binary), expected_python_root=generated_python
    )

    assert resolved == (tmp_path / binary).resolve()


def test_inspector_uses_fixed_system_path_not_path_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runtime_inventory.sys, "platform", "linux")
    monkeypatch.setenv("PATH", "/tmp/project-controlled")
    original_is_file = Path.is_file
    monkeypatch.setattr(
        Path,
        "is_file",
        lambda self: True if self == Path("/usr/bin/readelf") else original_is_file(self),
    )
    monkeypatch.setattr(
        runtime_inventory.os,
        "access",
        lambda path, _mode: path == Path("/usr/bin/readelf"),
    )

    name, command = runtime_inventory._inspector_command(Path("/tmp/native.so"))

    assert name == "readelf"
    assert command == ["/usr/bin/readelf", "-W", "-d", "/tmp/native.so"]


def test_inspector_clamps_timeout_sets_c_locale_and_uses_header_architecture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated_python = tmp_path / "generated" / "python"
    binary = generated_python / "native" / "_rextio_native.so"
    binary.parent.mkdir(parents=True)
    payload = _elf64_header(machine=62)
    binary.write_bytes(payload)
    observed: dict[str, object] = {}
    for key in (
        "LD_PRELOAD",
        "LD_AUDIT",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_PRINT_LIBRARIES",
        "GCONV_PATH",
        "LOCPATH",
    ):
        monkeypatch.setenv(key, f"secret-{key}")

    monkeypatch.setattr(
        runtime_inventory,
        "_inspector_command",
        lambda path: ("readelf", ["/usr/bin/readelf", "-W", "-d", str(path)]),
    )

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        observed.update(command=command, **kwargs)
        snapshot_path = Path(command[-1])
        observed["snapshot_path"] = snapshot_path
        assert snapshot_path != binary
        assert snapshot_path.parent.parent == generated_python.resolve()
        assert snapshot_path.parent.stat().st_mode & 0o777 == 0o700
        assert snapshot_path.read_bytes() == payload
        assert snapshot_path.stat().st_mode & 0o777 == 0o400
        return subprocess.CompletedProcess(
            command,
            0,
            (
                "Dynamic section at offset 0x1000 contains 1 entry:\n"
                "  Tag        Type                         Name/Value\n"
                " 0x0000000000000001 (NEEDED) Shared library: [libc.so.6]\n"
            ),
            "",
        )

    monkeypatch.setattr(runtime_inventory, "run_build_tool", fake_run)
    inventory = runtime_inventory.inspect_native_runtime_inventory(
        installed_path=binary,
        expected_python_root=generated_python,
        wheel_entries=(_wheel_entry("native/_rextio_native.so", payload),),
        target_triple="x86_64-unknown-linux-gnu",
        timeout=120.0,
    )

    assert observed["timeout"] == 10.0
    inspector_env = observed["env"]
    assert isinstance(inspector_env, dict)
    assert inspector_env == {
        "LC_ALL": "C",
        "LANG": "C",
        "PATH": "/usr/bin:/bin",
    }
    assert observed["inherit_env"] is False
    for key in (
        "LD_PRELOAD",
        "LD_AUDIT",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_PRINT_LIBRARIES",
        "GCONV_PATH",
        "LOCPATH",
    ):
        assert key not in inspector_env
    assert "secret-" not in repr(inspector_env)
    assert observed["max_output_bytes"] == 256 * 1024
    assert inventory.architecture == "x86_64"
    snapshot_path = observed["snapshot_path"]
    assert isinstance(snapshot_path, Path)
    assert not snapshot_path.exists()
    assert not snapshot_path.parent.exists()


def test_binary_header_architecture_must_match_target_before_inspector(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated_python = tmp_path / "generated" / "python"
    binary = generated_python / "native" / "_rextio_native.so"
    binary.parent.mkdir(parents=True)
    payload = _elf64_header(machine=183)  # AArch64
    binary.write_bytes(payload)
    monkeypatch.setattr(
        runtime_inventory,
        "_inspector_command",
        lambda _path: pytest.fail("inspector must not run for a mismatched header"),
    )

    with pytest.raises(ArtifactEvidenceError) as raised:
        runtime_inventory.inspect_native_runtime_inventory(
            installed_path=binary,
            expected_python_root=generated_python,
            wheel_entries=(_wheel_entry("native/_rextio_native.so", payload),),
            target_triple="x86_64-unknown-linux-gnu",
        )

    assert raised.value.reason == evidence_mod.REASON_RUNTIME_ARCHITECTURE_MISMATCH


def test_elf_executable_is_rejected_before_inspector(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated_python = tmp_path / "generated" / "python"
    binary = generated_python / "native" / "_rextio_native.so"
    binary.parent.mkdir(parents=True)
    payload = _elf64_header(object_type=2)  # ET_EXEC
    binary.write_bytes(payload)
    monkeypatch.setattr(
        runtime_inventory,
        "_inspector_command",
        lambda _path: pytest.fail("inspector must not run for an ELF executable"),
    )

    with pytest.raises(ArtifactEvidenceError) as raised:
        runtime_inventory.inspect_native_runtime_inventory(
            installed_path=binary,
            expected_python_root=generated_python,
            wheel_entries=(_wheel_entry("native/_rextio_native.so", payload),),
            target_triple="x86_64-unknown-linux-gnu",
        )

    assert raised.value.reason == evidence_mod.REASON_RUNTIME_ARCHITECTURE_MISMATCH


def test_fat_macho_header_is_rejected_before_inspector(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated_python = tmp_path / "generated" / "python"
    binary = generated_python / "native" / "_rextio_native.so"
    binary.parent.mkdir(parents=True)
    payload = b"\xca\xfe\xba\xbe" + bytes(60)
    binary.write_bytes(payload)
    monkeypatch.setattr(
        runtime_inventory,
        "_inspector_command",
        lambda _path: pytest.fail("inspector must not run for a fat Mach-O"),
    )

    with pytest.raises(ArtifactEvidenceError) as raised:
        runtime_inventory.inspect_native_runtime_inventory(
            installed_path=binary,
            expected_python_root=generated_python,
            wheel_entries=(_wheel_entry("native/_rextio_native.so", payload),),
            target_triple="aarch64-apple-darwin",
        )

    assert raised.value.reason == evidence_mod.REASON_RUNTIME_ARCHITECTURE_MISMATCH


@pytest.mark.parametrize(
    ("payload", "target_triple"),
    [
        (
            bytes(bytearray(_elf64_header(machine=62))[:4])
            + b"\x01"
            + bytes(bytearray(_elf64_header(machine=62))[5:]),
            "x86_64-unknown-linux-gnu",
        ),
        (
            b"\xce\xfa\xed\xfe" + (0x01000007).to_bytes(4, "little") + bytes(24),
            "x86_64-apple-darwin",
        ),
    ],
)
def test_object_width_must_match_header_architecture(
    payload: bytes,
    target_triple: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated_python = tmp_path / "generated" / "python"
    binary = generated_python / "native" / "_rextio_native.so"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(payload)
    monkeypatch.setattr(
        runtime_inventory,
        "_inspector_command",
        lambda _path: pytest.fail("inspector must not run for a width mismatch"),
    )

    with pytest.raises(ArtifactEvidenceError) as raised:
        runtime_inventory.inspect_native_runtime_inventory(
            installed_path=binary,
            expected_python_root=generated_python,
            wheel_entries=(_wheel_entry("native/_rextio_native.so", payload),),
            target_triple=target_triple,
        )

    assert raised.value.reason == evidence_mod.REASON_RUNTIME_ARCHITECTURE_MISMATCH


@pytest.mark.parametrize("tag", ["AUDIT", "DEPAUDIT", "FILTER", "AUXILIARY"])
def test_readelf_rejects_alternate_loader_dependency_tags(tag: str) -> None:
    output = (
        "Dynamic section at offset 0x1000 contains 1 entry:\n"
        "  Tag        Type                         Name/Value\n"
        f" 0x0000000000000000 ({tag}) Library audit: [libprivate.so]\n"
    )

    with pytest.raises(ArtifactEvidenceError) as raised:
        runtime_inventory.parse_readelf_d_output(output, target_triple="x86_64-unknown-linux-gnu")

    assert raised.value.reason == evidence_mod.REASON_RUNTIME_UNEXPECTED_DEPENDENCY


def test_readelf_rejects_arbitrary_needed_library() -> None:
    output = (
        "Dynamic section at offset 0x1000 contains 1 entry:\n"
        "  Tag        Type                         Name/Value\n"
        " 0x0000000000000001 (NEEDED) Shared library: [libssl.so.3]\n"
    )

    with pytest.raises(ArtifactEvidenceError) as raised:
        runtime_inventory.parse_readelf_d_output(output, target_triple="x86_64-unknown-linux-gnu")

    assert raised.value.reason == evidence_mod.REASON_RUNTIME_UNEXPECTED_DEPENDENCY


@pytest.mark.parametrize("tag", ["BIND_NOW", "TEXTREL"])
def test_readelf_accepts_value_less_hardening_tags(tag: str) -> None:
    output = (
        "Dynamic section at offset 0x1000 contains 2 entries:\n"
        "  Tag        Type                         Name/Value\n"
        f" 0x000000000000001e ({tag})\n"
        " 0x0000000000000000 (NULL)               0x0\n"
    )

    parsed = runtime_inventory.parse_readelf_d_output(
        output, target_triple="x86_64-unknown-linux-gnu"
    )

    assert parsed.format == "elf"
    assert parsed.dependencies == ()


def test_readelf_rejects_other_value_less_dynamic_tags() -> None:
    output = (
        "Dynamic section at offset 0x1000 contains 1 entry:\n"
        "  Tag        Type                         Name/Value\n"
        " 0x000000000000000e (SONAME)\n"
    )

    with pytest.raises(ArtifactEvidenceError) as raised:
        runtime_inventory.parse_readelf_d_output(output, target_triple="x86_64-unknown-linux-gnu")

    assert raised.value.reason == evidence_mod.REASON_RUNTIME_MALFORMED


def test_missing_fixed_system_inspector_uses_fixed_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runtime_inventory.sys, "platform", "linux")
    monkeypatch.setattr(Path, "is_file", lambda _self: False)

    with pytest.raises(ArtifactEvidenceError) as raised:
        runtime_inventory._inspector_command(Path("/tmp/native.so"))

    assert raised.value.reason == evidence_mod.REASON_RUNTIME_INSPECTOR_MISSING


@pytest.mark.parametrize(
    ("returncode", "reason"),
    [
        (1, evidence_mod.REASON_RUNTIME_INSPECTOR_FAILED),
        (
            runtime_inventory.TIMEOUT_EXIT_CODE,
            evidence_mod.REASON_RUNTIME_INSPECTOR_TIMEOUT,
        ),
        (
            runtime_inventory.OUTPUT_OVERFLOW_EXIT_CODE,
            evidence_mod.REASON_RUNTIME_OUTPUT_EXCEEDED,
        ),
    ],
)
def test_inspector_runner_exit_codes_use_fixed_reasons(
    returncode: int,
    reason: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, binary, _payload, entries = _elf_runtime_case(tmp_path)
    monkeypatch.setattr(
        runtime_inventory,
        "_inspector_command",
        lambda path: ("readelf", ["/usr/bin/readelf", "-W", "-d", str(path)]),
    )
    monkeypatch.setattr(
        runtime_inventory,
        "run_build_tool",
        lambda command, **_kwargs: subprocess.CompletedProcess(
            command, returncode, "", "sanitized failure"
        ),
    )

    with pytest.raises(ArtifactEvidenceError) as raised:
        runtime_inventory.inspect_native_runtime_inventory(
            installed_path=binary,
            expected_python_root=root,
            wheel_entries=entries,
            target_triple="x86_64-unknown-linux-gnu",
        )

    assert raised.value.reason == reason


def test_private_snapshot_is_removed_when_inspector_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, binary, _payload, entries = _elf_runtime_case(tmp_path)
    observed: dict[str, Path] = {}
    monkeypatch.setattr(
        runtime_inventory,
        "_inspector_command",
        lambda path: ("readelf", ["/usr/bin/readelf", "-W", "-d", str(path)]),
    )

    def fail(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        observed["snapshot"] = Path(command[-1])
        return subprocess.CompletedProcess(command, 1, "", "failure")

    monkeypatch.setattr(runtime_inventory, "run_build_tool", fail)
    with pytest.raises(ArtifactEvidenceError):
        runtime_inventory.inspect_native_runtime_inventory(
            installed_path=binary,
            expected_python_root=root,
            wheel_entries=entries,
            target_triple="x86_64-unknown-linux-gnu",
        )

    assert not observed["snapshot"].exists()


@pytest.mark.parametrize("operation", ["unlink", "rmdir"])
def test_private_snapshot_cleanup_failure_is_observable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    root, binary, _payload, _entries = _elf_runtime_case(tmp_path)
    real_unlink = runtime_inventory.os.unlink
    real_rmdir = runtime_inventory.os.rmdir
    observed: dict[str, Path] = {}

    def fail_unlink(path: str, *, dir_fd: int | None = None) -> None:
        if operation == "unlink" and path == binary.name and dir_fd is not None:
            raise OSError("simulated unlink failure")
        real_unlink(path, dir_fd=dir_fd)

    def fail_rmdir(path: str, *, dir_fd: int | None = None) -> None:
        if (
            operation == "rmdir"
            and path.startswith(runtime_inventory._SNAPSHOT_PREFIX)
            and dir_fd is not None
        ):
            raise OSError("simulated rmdir failure")
        real_rmdir(path, dir_fd=dir_fd)

    monkeypatch.setattr(runtime_inventory.os, "unlink", fail_unlink)
    monkeypatch.setattr(runtime_inventory.os, "rmdir", fail_rmdir)
    with pytest.raises(ArtifactEvidenceError, match="cleanup failed") as raised:
        with runtime_inventory._private_binary_snapshot(
            binary,
            expected_root=root,
        ) as snapshot:
            observed["snapshot"] = snapshot.path

    monkeypatch.setattr(runtime_inventory.os, "unlink", real_unlink)
    monkeypatch.setattr(runtime_inventory.os, "rmdir", real_rmdir)
    snapshot_path = observed["snapshot"]
    if snapshot_path.exists():
        snapshot_path.unlink()
    if snapshot_path.parent.exists():
        snapshot_path.parent.rmdir()
    assert raised.value.reason == evidence_mod.REASON_RUNTIME_BINARY_MISMATCH


def test_private_snapshot_cleanup_preserves_active_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class PrimaryFailure(RuntimeError):
        pass

    root, binary, _payload, _entries = _elf_runtime_case(tmp_path)
    real_rmdir = runtime_inventory.os.rmdir
    observed: dict[str, Path] = {}

    def fail_rmdir(path: str, *, dir_fd: int | None = None) -> None:
        if path.startswith(runtime_inventory._SNAPSHOT_PREFIX) and dir_fd is not None:
            raise OSError("simulated rmdir failure")
        real_rmdir(path, dir_fd=dir_fd)

    monkeypatch.setattr(runtime_inventory.os, "rmdir", fail_rmdir)
    with pytest.raises(PrimaryFailure, match="primary failure") as raised:
        with runtime_inventory._private_binary_snapshot(
            binary,
            expected_root=root,
        ) as snapshot:
            observed["snapshot"] = snapshot.path
            raise PrimaryFailure("primary failure")

    monkeypatch.setattr(runtime_inventory.os, "rmdir", real_rmdir)
    snapshot_directory = observed["snapshot"].parent
    if snapshot_directory.exists():
        snapshot_directory.rmdir()
    assert any(
        "cleanup also failed" in note for note in getattr(raised.value, "__notes__", ())
    )


def test_successful_inspector_with_malformed_output_uses_fixed_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, binary, _payload, entries = _elf_runtime_case(tmp_path)
    monkeypatch.setattr(
        runtime_inventory,
        "_inspector_command",
        lambda path: ("readelf", ["/usr/bin/readelf", "-W", "-d", str(path)]),
    )
    monkeypatch.setattr(
        runtime_inventory,
        "run_build_tool",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, "garbage", ""),
    )

    with pytest.raises(ArtifactEvidenceError) as raised:
        runtime_inventory.inspect_native_runtime_inventory(
            installed_path=binary,
            expected_python_root=root,
            wheel_entries=entries,
            target_triple="x86_64-unknown-linux-gnu",
        )

    assert raised.value.reason == evidence_mod.REASON_RUNTIME_MALFORMED


def test_dependency_count_and_name_bounds_fail_closed() -> None:
    too_many = "/generated/_rextio_native.so:\n" + "".join(
        f"\t/usr/lib/libsystem{i}.dylib (compatibility version 1.0.0, current version 1.0.0)\n"
        for i in range(65)
    )
    with pytest.raises(ArtifactEvidenceError) as count_error:
        runtime_inventory.parse_otool_l_output(too_many)
    assert count_error.value.reason == evidence_mod.REASON_RUNTIME_DEP_COUNT_EXCEEDED

    too_long = (
        "/generated/_rextio_native.so:\n"
        f"\t/usr/lib/{'a' * 257}.dylib "
        "(compatibility version 1.0.0, current version 1.0.0)\n"
    )
    with pytest.raises(ArtifactEvidenceError) as name_error:
        runtime_inventory.parse_otool_l_output(too_long)
    assert name_error.value.reason == evidence_mod.REASON_RUNTIME_DEP_COUNT_EXCEEDED


def test_binary_mutation_during_inspector_fails_final_rehash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, binary, _payload, entries = _elf_runtime_case(tmp_path)
    monkeypatch.setattr(
        runtime_inventory,
        "_inspector_command",
        lambda path: ("readelf", ["/usr/bin/readelf", "-W", "-d", str(path)]),
    )

    def mutate(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        binary.write_bytes(binary.read_bytes() + b"mutated")
        return subprocess.CompletedProcess(
            command,
            0,
            (
                "Dynamic section at offset 0x1000 contains 1 entry:\n"
                "  Tag        Type                         Name/Value\n"
                " 0x0000000000000001 (NEEDED) Shared library: [libc.so.6]\n"
            ),
            "",
        )

    monkeypatch.setattr(runtime_inventory, "run_build_tool", mutate)
    with pytest.raises(ArtifactEvidenceError) as raised:
        runtime_inventory.inspect_native_runtime_inventory(
            installed_path=binary,
            expected_python_root=root,
            wheel_entries=entries,
            target_triple="x86_64-unknown-linux-gnu",
        )

    assert raised.value.reason == evidence_mod.REASON_RUNTIME_BINARY_MISMATCH


def _successful_readelf_result(
    command: list[str],
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        command,
        0,
        (
            "Dynamic section at offset 0x1000 contains 1 entry:\n"
            "  Tag        Type                         Name/Value\n"
            " 0x0000000000000001 (NEEDED) Shared library: [libc.so.6]\n"
        ),
        "",
    )


def test_snapshot_in_place_mutate_restore_and_mtime_restore_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, binary, _payload, entries = _elf_runtime_case(tmp_path)
    monkeypatch.setattr(
        runtime_inventory,
        "_inspector_command",
        lambda path: ("readelf", ["/usr/bin/readelf", "-W", "-d", str(path)]),
    )

    def mutate_restore(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        snapshot = Path(command[-1])
        original = snapshot.read_bytes()
        before = snapshot.stat()
        snapshot.chmod(0o600)
        snapshot.write_bytes(bytes([original[0] ^ 0xFF]) + original[1:])
        snapshot.write_bytes(original)
        snapshot.chmod(0o400)
        os.utime(snapshot, ns=(before.st_atime_ns, before.st_mtime_ns))
        return _successful_readelf_result(command)

    monkeypatch.setattr(runtime_inventory, "run_build_tool", mutate_restore)
    with pytest.raises(ArtifactEvidenceError) as raised:
        runtime_inventory.inspect_native_runtime_inventory(
            installed_path=binary,
            expected_python_root=root,
            wheel_entries=entries,
            target_triple="x86_64-unknown-linux-gnu",
        )

    assert raised.value.reason == evidence_mod.REASON_RUNTIME_BINARY_MISMATCH


def test_snapshot_swap_restore_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, binary, _payload, entries = _elf_runtime_case(tmp_path)
    monkeypatch.setattr(
        runtime_inventory,
        "_inspector_command",
        lambda path: ("readelf", ["/usr/bin/readelf", "-W", "-d", str(path)]),
    )

    def swap_restore(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        snapshot = Path(command[-1])
        original = snapshot.read_bytes()
        backup = snapshot.with_name(f"{snapshot.name}.held")
        snapshot.rename(backup)
        snapshot.write_bytes(original)
        snapshot.chmod(0o400)
        snapshot.unlink()
        backup.rename(snapshot)
        return _successful_readelf_result(command)

    monkeypatch.setattr(runtime_inventory, "run_build_tool", swap_restore)
    with pytest.raises(ArtifactEvidenceError) as raised:
        runtime_inventory.inspect_native_runtime_inventory(
            installed_path=binary,
            expected_python_root=root,
            wheel_entries=entries,
            target_triple="x86_64-unknown-linux-gnu",
        )

    assert raised.value.reason == evidence_mod.REASON_RUNTIME_BINARY_MISMATCH


def test_source_mutate_restore_and_mtime_restore_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, binary, _payload, entries = _elf_runtime_case(tmp_path)
    monkeypatch.setattr(
        runtime_inventory,
        "_inspector_command",
        lambda path: ("readelf", ["/usr/bin/readelf", "-W", "-d", str(path)]),
    )

    def mutate_restore(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        original = binary.read_bytes()
        before = binary.stat()
        binary.write_bytes(bytes([original[0] ^ 0xFF]) + original[1:])
        binary.write_bytes(original)
        os.utime(binary, ns=(before.st_atime_ns, before.st_mtime_ns))
        return _successful_readelf_result(command)

    monkeypatch.setattr(runtime_inventory, "run_build_tool", mutate_restore)
    with pytest.raises(ArtifactEvidenceError) as raised:
        runtime_inventory.inspect_native_runtime_inventory(
            installed_path=binary,
            expected_python_root=root,
            wheel_entries=entries,
            target_triple="x86_64-unknown-linux-gnu",
        )

    assert raised.value.reason == evidence_mod.REASON_RUNTIME_BINARY_MISMATCH


def test_generated_root_swap_restore_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, binary, _payload, entries = _elf_runtime_case(tmp_path)
    monkeypatch.setattr(
        runtime_inventory,
        "_inspector_command",
        lambda path: ("readelf", ["/usr/bin/readelf", "-W", "-d", str(path)]),
    )

    def swap_restore(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        held_root = root.with_name("python-held")
        root.rename(held_root)
        root.mkdir()
        root.rmdir()
        held_root.rename(root)
        return _successful_readelf_result(command)

    monkeypatch.setattr(runtime_inventory, "run_build_tool", swap_restore)
    with pytest.raises(ArtifactEvidenceError) as raised:
        runtime_inventory.inspect_native_runtime_inventory(
            installed_path=binary,
            expected_python_root=root,
            wheel_entries=entries,
            target_triple="x86_64-unknown-linux-gnu",
        )

    assert raised.value.reason == evidence_mod.REASON_RUNTIME_BINARY_MISMATCH
