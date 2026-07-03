"""Resolving external toolchain binaries from [toolchain] configuration.

Every place that shells out to cargo/maturin/nuitka (and the CPython used for
delegated calls) resolves the binary through this module so the preflight and
the builders can never disagree about which tool runs. Resolution order is
decided by the config layer (CLI > REXTIO_* env > rextio.toml); here a
configured value wins over PATH, and a configured value that does not resolve
is an error - it never silently falls back to PATH.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

from rextio.config.schema import ToolchainConfig

# Where a tool may live inside a configured home directory. `bin/` covers
# POSIX layouts and rustup toolchains; `Scripts/` covers Windows virtualenvs.
_HOME_SUBDIRS = ("", "bin", "Scripts")


def resolve_tool(name: str, configured: str | None) -> tuple[str | None, str | None]:
    """Resolve a tool to an executable path.

    Returns ``(path, error)``. With no configured value, falls back to PATH
    (``path`` is None when absent - the caller's existing missing-tool
    handling applies). A configured value must resolve or ``error`` explains
    what was tried; it never falls back to PATH.
    """
    if configured is None:
        return shutil.which(name), None
    base = Path(configured).expanduser()
    if base.is_file():
        return str(base), None
    if base.is_dir():
        for subdir in _HOME_SUBDIRS:
            for candidate in (base / subdir / name, base / subdir / f"{name}.exe"):
                if candidate.is_file():
                    return str(candidate), None
        return None, (
            f"[toolchain] {name} points at {base}, but no {name} executable was "
            f"found there (searched {', '.join(repr(s or '.') for s in _HOME_SUBDIRS)})."
        )
    return None, f"[toolchain] {name} points at {base}, which does not exist."


def resolve_python(toolchain: ToolchainConfig) -> tuple[str | None, str | None]:
    """Resolve the configured CPython interpreter; (None, None) when unset."""
    if toolchain.python is None:
        return None, None
    for name in ("python3", "python"):
        path, error = resolve_tool(name, toolchain.python)
        if path is not None:
            return path, None
    return None, error


def resolve_nuitka_command(toolchain: ToolchainConfig) -> tuple[list[str] | None, str | None]:
    """Resolve how to invoke Nuitka, as an argument-list prefix.

    Preference order: an explicitly configured nuitka path; the configured
    CPython's ``python -m nuitka`` (Nuitka is bound to the interpreter it is
    installed in, so this keeps the compile target coherent); PATH.
    ``(None, None)`` means "not installed" - the caller's existing
    missing-tool message applies.
    """
    if toolchain.nuitka is not None:
        path, error = resolve_tool("nuitka", toolchain.nuitka)
        if path is None:
            return None, error
        return [path], None
    if toolchain.python is not None:
        python, error = resolve_python(toolchain)
        if python is None:
            return None, error
        return [python, "-m", "nuitka"], None
    path = shutil.which("nuitka")
    return ([path] if path is not None else None), None


def cargo_environment(toolchain: ToolchainConfig) -> dict[str, str]:
    """Extra environment for cargo/maturin runs implied by the configuration.

    RUSTUP_TOOLCHAIN selects the rustup channel (a non-rustup cargo ignores
    it). PYO3_PYTHON makes the PyO3 build target the configured interpreter
    instead of whatever `python3` is first on PATH.
    """
    env: dict[str, str] = {}
    if toolchain.rust_toolchain is not None:
        env["RUSTUP_TOOLCHAIN"] = toolchain.rust_toolchain
    python, _error = resolve_python(toolchain)
    if python is not None:
        env["PYO3_PYTHON"] = python
    return env


def probe_version(command: list[str]) -> str | None:
    """Best-effort `<tool> --version` probe; None when undeterminable."""
    try:
        completed = subprocess.run(
            [*command, "--version"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    output = (completed.stdout or "").strip() or (completed.stderr or "").strip()
    first_line = output.splitlines()[0].strip() if output else ""
    match = re.search(r"\d+(\.\d+)*", first_line)
    return match.group(0) if match is not None else None


def check_version_pin(display: str, command: list[str], pin: str | None) -> str | None:
    """Verify an explicit version pin against the resolved tool.

    Unlike the best-effort floors, an explicit pin is strict: a tool whose
    version cannot be determined fails the check. Pins verify only - they
    never install or select a tool.
    """
    if pin is None:
        return None
    reported = probe_version(command)
    if reported is None:
        return (
            f"{display} version could not be determined, but [toolchain] pins it "
            f"to {pin!r}. Fix the tool or drop the pin."
        )
    if _satisfies(_version_tuple(reported), pin):
        return None
    return (
        f"{display} reports version {reported}, which does not satisfy the "
        f"[toolchain] pin {pin!r}."
    )


def python_version_mismatch(python: str) -> str | None:
    """Reject a configured CPython whose minor version differs from the build's.

    The analyzer's semantics are defined against the interpreter running the
    build, generated wheels are tagged for its minor version, and Nuitka
    output binds to the interpreter it runs under - a different minor version
    would silently split those contracts.
    """
    reported = probe_version([python])
    if reported is None:
        return f"[toolchain] python at {python} did not report a parseable version."
    build = sys.version_info[:2]
    configured = _version_tuple(reported)[:2]
    if configured != build:
        return (
            f"[toolchain] python at {python} is CPython {reported}, but the build "
            f"is running on {build[0]}.{build[1]}. Use a {build[0]}.{build[1]} "
            "interpreter (or run rextio under the configured one)."
        )
    return None


def _version_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def _satisfies(version: tuple[int, ...], pin: str) -> bool:
    match = re.fullmatch(r"(==|>=)?(\d+(?:\.\d+)*)", pin)
    if match is None:  # config validation prevents this; stay defensive
        return False
    operator = match.group(1) or "=="
    pinned = _version_tuple(match.group(2))
    if operator == ">=":
        return version >= pinned
    # "==" and bare pins are prefix matches: "1.85" accepts every 1.85.x.
    return version[: len(pinned)] == pinned
