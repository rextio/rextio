"""Tests for [toolchain] resolution, version pins, and coherence checks."""

from __future__ import annotations

import stat
import sys
from pathlib import Path

from rextio.build.toolchain import (
    cargo_environment,
    check_version_pin,
    python_version_mismatch,
    resolve_nuitka_command,
    resolve_python,
    resolve_tool,
)
from rextio.config.schema import ToolchainConfig


def _script(path: Path, body: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


def test_resolve_tool_accepts_binary_path_and_home_dir(tmp_path: Path) -> None:
    binary = _script(tmp_path / "home" / "bin" / "cargo", "echo cargo 1.85.0")

    direct, error = resolve_tool("cargo", str(binary))
    assert error is None and direct == str(binary)

    from_home, error = resolve_tool("cargo", str(tmp_path / "home"))
    assert error is None and from_home == str(binary)


def test_resolve_tool_configured_but_missing_is_an_error_not_path_fallback(
    tmp_path: Path, monkeypatch
) -> None:
    real = _script(tmp_path / "real-bin" / "cargo", "echo cargo 1.85.0")
    monkeypatch.setenv("PATH", str(real.parent))

    path, error = resolve_tool("cargo", str(tmp_path / "nowhere"))
    assert path is None
    assert error is not None and "does not exist" in error

    empty = tmp_path / "empty"
    empty.mkdir()
    path, error = resolve_tool("cargo", str(empty))
    assert path is None
    assert error is not None and "no cargo executable" in error


def test_resolve_nuitka_prefers_explicit_then_python_module(tmp_path: Path) -> None:
    nuitka = _script(tmp_path / "tools" / "nuitka", "echo 2.4.8")
    python = _script(tmp_path / "py" / "bin" / "python3", "echo Python 3.11.9")

    explicit, error = resolve_nuitka_command(
        ToolchainConfig(nuitka=str(nuitka), python=str(python))
    )
    assert error is None and explicit == [str(nuitka)]

    via_python, error = resolve_nuitka_command(ToolchainConfig(python=str(tmp_path / "py")))
    assert error is None and via_python == [str(python), "-m", "nuitka"]


def test_cargo_environment_carries_rustup_channel_and_pyo3_python(tmp_path: Path) -> None:
    python = _script(tmp_path / "py" / "bin" / "python3", "echo Python 3.11.9")
    env = cargo_environment(ToolchainConfig(rust_toolchain="1.83", python=str(tmp_path / "py")))
    assert env["RUSTUP_TOOLCHAIN"] == "1.83"
    assert env["PYO3_PYTHON"] == str(python)
    assert cargo_environment(ToolchainConfig()) == {}


def test_version_pins_are_strict_and_support_specifiers(tmp_path: Path) -> None:
    cargo = _script(tmp_path / "cargo", "echo 'cargo 1.85.1 (abcdef 2026-01-01)'")
    assert check_version_pin("cargo", [str(cargo)], None) is None
    assert check_version_pin("cargo", [str(cargo)], "1.85") is None
    assert check_version_pin("cargo", [str(cargo)], "==1.85.1") is None
    assert check_version_pin("cargo", [str(cargo)], ">=1.83") is None

    mismatch = check_version_pin("cargo", [str(cargo)], "1.84")
    assert mismatch is not None and "does not satisfy" in mismatch

    # An explicit pin is strict: unparseable output fails instead of passing.
    silent = _script(tmp_path / "silent", "exit 0")
    strict = check_version_pin("tool", [str(silent)], "1.0")
    assert strict is not None and "could not be determined" in strict


def test_python_version_mismatch_requires_same_minor(tmp_path: Path) -> None:
    matching = _script(
        tmp_path / "match",
        f"echo Python {sys.version_info[0]}.{sys.version_info[1]}.0",
    )
    assert python_version_mismatch(str(matching)) is None

    other = _script(tmp_path / "other", "echo Python 3.2.0")
    error = python_version_mismatch(str(other))
    assert error is not None and "3.2" in error


def test_resolve_python_unset_is_silent_none() -> None:
    assert resolve_python(ToolchainConfig()) == (None, None)
