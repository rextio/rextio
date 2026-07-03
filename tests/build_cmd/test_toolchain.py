"""Tests for [toolchain] resolution, version pins, and coherence checks."""

from __future__ import annotations

import stat
import sys
from pathlib import Path

from rextio.build.toolchain import (
    cargo_environment,
    rust_environment,
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

    # Explicit == is exact, unlike the bare prefix form.
    exact_mismatch = check_version_pin("cargo", [str(cargo)], "==1.85")
    assert exact_mismatch is not None and "does not satisfy" in exact_mismatch

    # An explicit pin is strict: unparseable output fails instead of passing.
    silent = _script(tmp_path / "silent", "exit 0")
    strict = check_version_pin("tool", [str(silent)], "1.0")
    assert strict is not None and "could not be determined" in strict


def test_python_version_mismatch_requires_same_minor_cpython(tmp_path: Path) -> None:
    matching = _script(
        tmp_path / "match",
        f"echo {sys.version_info[0]}.{sys.version_info[1]}.0 cpython",
    )
    assert python_version_mismatch(str(matching)) is None

    other = _script(tmp_path / "other", "echo 3.2.0 cpython")
    error = python_version_mismatch(str(other))
    assert error is not None and "3.2" in error

    pypy = _script(
        tmp_path / "pypy",
        f"echo {sys.version_info[0]}.{sys.version_info[1]}.0 pypy",
    )
    impl_error = python_version_mismatch(str(pypy))
    assert impl_error is not None and "not CPython" in impl_error

    # An explicitly configured interpreter is strict: unprobeable output fails.
    silent = _script(tmp_path / "silent", "echo Python 3.11.9")
    assert python_version_mismatch(str(silent)) is not None


def test_resolve_python_unset_is_silent_none() -> None:
    assert resolve_python(ToolchainConfig()) == (None, None)


def test_resolve_tool_returns_absolute_paths_for_relative_config(
    tmp_path: Path, monkeypatch
) -> None:
    # Builders run tools with their own working directories, so a relative
    # configured path must come back absolute or it breaks inside the build.
    _script(tmp_path / "tools" / "cargo", "echo cargo 1.85.0")
    monkeypatch.chdir(tmp_path)

    path, error = resolve_tool("cargo", "tools")
    assert error is None
    assert path is not None and Path(path).is_absolute()


def test_resolve_tool_rejects_non_executable_files(tmp_path: Path) -> None:
    plain = tmp_path / "cargo"
    plain.write_text("not a program", encoding="utf-8")

    path, error = resolve_tool("cargo", str(plain))
    assert path is None
    assert error is not None and "not" in error and "executable" in error


def test_resolve_tool_direct_path_accepts_exe_variant(tmp_path: Path) -> None:
    exe = _script(tmp_path / "cargo.exe", "echo cargo 1.85.0")

    path, error = resolve_tool("cargo", str(tmp_path / "cargo"))
    assert error is None and path == str(exe)


def test_resolve_python_error_mentions_both_names(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    path, error = resolve_python(ToolchainConfig(python=str(empty)))
    assert path is None
    assert error is not None and "python3" in error and "python" in error


def test_rust_environment_carries_only_the_rustup_channel(tmp_path: Path) -> None:
    python = _script(tmp_path / "py" / "bin" / "python3", "echo Python 3.11.9")
    toolchain = ToolchainConfig(rust_toolchain="1.83", python=str(tmp_path / "py"))
    env = rust_environment(toolchain)
    assert env == {"RUSTUP_TOOLCHAIN": "1.83"}
    assert "PYO3_PYTHON" not in env
    assert cargo_environment(toolchain)["PYO3_PYTHON"] == str(python)


def test_unresolvable_configured_python_fails_the_rust_executable(tmp_path: Path) -> None:
    from rextio.build.orchestrator import _build_rust_executable_artifact
    from rextio.build.artifact_layout import ArtifactLayout

    layout = ArtifactLayout(tmp_path)
    result = _build_rust_executable_artifact(
        layout,
        None,  # analysis is unused before the python check fails
        "app:main",
        None,
        None,
        "source",
        build_timeout=30.0,
        toolchain=ToolchainConfig(python=str(tmp_path / "nowhere")),
    )
    assert result.status == "failed"
    assert "python" in (result.message or "")
