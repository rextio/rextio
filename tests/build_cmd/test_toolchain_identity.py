"""Adversarial tests for bounded Full-C6 toolchain identities."""

from __future__ import annotations

import stat
from pathlib import Path

import pytest


def _tool(path: Path, version: str) -> Path:
    path.write_text(f"#!/bin/sh\necho {version!r}\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


def test_tool_identity_binds_binary_bytes_and_detects_mutation(tmp_path: Path) -> None:
    try:
        from rextio.build.toolchain_identity import (
            ToolchainIdentityError,
            capture_tool_identity,
            verify_tool_identity,
        )
    except ImportError:
        pytest.fail("the toolchain identity module is missing")

    cargo = _tool(tmp_path / "cargo", "cargo 1.85.1")
    identity = capture_tool_identity("cargo", cargo, reported_version="cargo 1.85.1")
    assert identity.name == "cargo"
    assert identity.executable.role == "toolchain-executable"
    assert str(tmp_path) not in repr(identity.to_dict())

    cargo.write_text("#!/bin/sh\necho 'cargo 1.85.2'\n", encoding="utf-8")
    with pytest.raises(ToolchainIdentityError, match="changed"):
        verify_tool_identity(cargo, identity)


def test_environment_identity_filters_unknown_and_hashes_values() -> None:
    from rextio.build.toolchain_identity import capture_environment_identity

    receipt = capture_environment_identity(
        {
            "SOURCE_DATE_EPOCH": "0",
            "PATH": "/usr/bin:/bin",
            "SECRET_TOKEN": "must-not-leak",
            "PYTHONHASHSEED": "0",
        }
    )
    assert tuple(item.name for item in receipt) == (
        "PATH",
        "PYTHONHASHSEED",
        "SOURCE_DATE_EPOCH",
    )
    payload = [item.to_dict() for item in receipt]
    assert "must-not-leak" not in repr(payload)
    assert all(set(item) == {"name", "value_sha256", "value_size"} for item in payload)


def test_cargo_source_receipt_requires_locked_registry_checksums(tmp_path: Path) -> None:
    from rextio.build.toolchain_identity import (
        ToolchainIdentityError,
        capture_cargo_sources,
    )

    lock = tmp_path / "Cargo.lock"
    lock.write_text(
        """
version = 4

[[package]]
name = "root"
version = "0.1.0"

[[package]]
name = "dep"
version = "1.2.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
""".lstrip(),
        encoding="utf-8",
    )
    receipt = capture_cargo_sources(lock, root_package="root")
    assert receipt.lock_file.role == "cargo-lockfile"
    assert receipt.root_package == "root"
    assert [item.name for item in receipt.packages] == ["dep"]
    assert receipt.complete_for_scope is True

    lock.write_text(
        lock.read_text(encoding="utf-8").replace(
            "checksum = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
            "",
        ),
        encoding="utf-8",
    )
    with pytest.raises(ToolchainIdentityError, match="checksum"):
        capture_cargo_sources(lock, root_package="root")


def test_strict_cargo_command_is_idempotent_and_places_flags_before_separator() -> None:
    from rextio.build.strict_cargo import enforce_strict_cargo_command

    command = ("cargo", "build", "--release", "--", "--example-argument")
    strict = enforce_strict_cargo_command(command, strict=True)
    assert strict == (
        "cargo",
        "build",
        "--release",
        "--locked",
        "--offline",
        "--frozen",
        "--",
        "--example-argument",
    )
    assert enforce_strict_cargo_command(strict, strict=True) == strict
    assert enforce_strict_cargo_command(command, strict=False) == command


def test_strict_cargo_command_rejects_empty_or_value_overrides() -> None:
    from rextio.build.strict_cargo import StrictCargoCommandError, enforce_strict_cargo_command

    with pytest.raises(StrictCargoCommandError, match="program and subcommand"):
        enforce_strict_cargo_command(("cargo",), strict=True)
    with pytest.raises(StrictCargoCommandError, match="override"):
        enforce_strict_cargo_command(
            ("cargo", "build", "--offline=false"),
            strict=True,
        )


def test_complete_toolchain_receipt_covers_required_roles_canonically(tmp_path: Path) -> None:
    from rextio.build.toolchain_identity import (
        assemble_build_toolchain_identity,
        capture_argv_identity,
        capture_cargo_sources,
        capture_environment_identity,
        capture_rextio_identity,
        capture_tool_identity,
    )

    tools = {
        name: _tool(tmp_path / name, f"{name} 1.0")
        for name in ("python", "cargo", "rustc", "linker", "readelf")
    }
    rextio_source = tmp_path / "rextio_init.py"
    rextio_source.write_text('__version__ = "0.1.4"\n', encoding="utf-8")
    lock = tmp_path / "Cargo.lock"
    lock.write_text(
        """
version = 4

[[package]]
name = "root"
version = "0.1.0"
""".lstrip(),
        encoding="utf-8",
    )

    receipt = assemble_build_toolchain_identity(
        python=capture_tool_identity("python", tools["python"], reported_version="3.11.9"),
        rextio=capture_rextio_identity(
            {"rextio/__init__.py": rextio_source},
            version="0.1.4",
        ),
        cargo=capture_tool_identity("cargo", tools["cargo"], reported_version="1.85.1"),
        rustc=capture_tool_identity("rustc", tools["rustc"], reported_version="1.85.1"),
        linker=capture_tool_identity("linker", tools["linker"], reported_version="1.0"),
        inspectors=(
            capture_tool_identity(
                "readelf", tools["readelf"], reported_version="GNU readelf 2.42"
            ),
        ),
        argv=capture_argv_identity(
            ("cargo", "build", "--release", "--locked", "--offline", "--frozen")
        ),
        environment=capture_environment_identity(
            {"SOURCE_DATE_EPOCH": "0", "SECRET": "excluded"}
        ),
        cargo_sources=capture_cargo_sources(lock, root_package="root"),
    )

    from rextio.artifacts.full_authorization import FULL_C6_SCOPE

    assert receipt.complete_for_scope is True
    assert receipt.scope == FULL_C6_SCOPE
    assert receipt.digest == receipt.to_dict()["digest"]
    assert receipt.python.name == "python"
    assert receipt.rextio.name == "rextio"
    assert receipt.cargo.name == "cargo"
    assert receipt.rustc.name == "rustc"
    assert receipt.linker.name == "linker"
    assert [item.name for item in receipt.inspectors] == ["readelf"]
    assert receipt.argv.values[-3:] == ("--locked", "--offline", "--frozen")
    assert "excluded" not in repr(receipt.to_dict())
