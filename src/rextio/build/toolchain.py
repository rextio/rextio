"""Resolving external toolchain binaries from [toolchain] configuration.

Every place that shells out to cargo/maturin/nuitka (and the CPython used for
delegated calls) resolves the binary through this module so the preflight and
the builders can never disagree about which tool runs. Resolution order is
decided by the config layer (CLI > REXTIO_* env > rextio.toml); here a
configured value wins over PATH, and a configured value that does not resolve
is an error - it never silently falls back to PATH.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from rextio.config.schema import ToolchainConfig, VERSION_PIN_PATTERN

# Where a tool may live inside a configured home directory, searched in order:
# the home itself first (a flat layout wins), then `bin/` (POSIX layouts and
# rustup toolchains), then `Scripts/` (Windows virtualenvs).
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
    # Anchor relative paths to the invocation CWD WITHOUT normalizing:
    # the builders run tools with their own working directories, so the path
    # must become absolute here - but a lexical ".." collapse would reorder
    # ".." ahead of symlink traversal and change the target, and resolving
    # symlinks would escape virtualenv layouts (.venv/bin/python3 links to a
    # base interpreter that has none of the venv's packages). Joining onto
    # the CWD keeps every component for the kernel to traverse in order.
    base = Path(configured).expanduser()
    if not base.is_absolute():
        base = Path.cwd() / base
    # Non-executable matches are recorded but the search continues, so a
    # stray text file named like the tool cannot mask its .exe (or bin/)
    # sibling; every offender is named if nothing usable exists.
    not_executable: list[str] = []
    candidates = [base, base.parent / f"{base.name}.exe"]
    if base.is_dir():
        for subdir in _HOME_SUBDIRS:
            candidates.extend((base / subdir / name, base / subdir / f"{name}.exe"))
    for candidate in candidates:
        if not candidate.is_file():
            continue
        if os.access(candidate, os.X_OK):
            return str(candidate), None
        not_executable.append(str(candidate))
    if not_executable:
        return None, (
            f"[toolchain] {name} resolved to {', '.join(not_executable)}, "
            "which is not executable."
        )
    if base.is_dir():
        return None, (
            f"[toolchain] {name} points at {base}, but no {name} executable was "
            f"found there (searched {', '.join(repr(s or '.') for s in _HOME_SUBDIRS)})."
        )
    return None, f"[toolchain] {name} points at {base}, which does not exist."


def resolve_python(toolchain: ToolchainConfig) -> tuple[str | None, str | None]:
    """Resolve the configured CPython interpreter; (None, None) when unset."""
    if toolchain.python is None:
        return None, None
    errors: list[str] = []
    for name in ("python3", "python"):
        path, error = resolve_tool(name, toolchain.python)
        if path is not None:
            return path, None
        if error is not None:
            errors.append(error)
    combined = (
        f"[toolchain] python points at {toolchain.python}, but neither python3 "
        "nor python resolved there."
    )
    if errors:
        combined = f"{combined} {' '.join(dict.fromkeys(errors))}"
    return None, combined


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


def rust_environment(toolchain: ToolchainConfig) -> dict[str, str]:
    """Environment for pure-Rust cargo runs (the bin and importable crates).

    RUSTUP_TOOLCHAIN selects the rustup channel; a non-rustup cargo ignores
    the variable, so forwarding it is always safe.
    """
    env: dict[str, str] = {}
    if toolchain.rust_toolchain is not None:
        env["RUSTUP_TOOLCHAIN"] = toolchain.rust_toolchain
    return env


def cargo_environment(toolchain: ToolchainConfig) -> dict[str, str]:
    """Environment for PyO3 extension builds (cargo or maturin).

    Extends :func:`rust_environment` with PYO3_PYTHON so the PyO3 build
    targets the configured interpreter instead of whatever `python3` is
    first on PATH, and with CARGO so maturin (which discovers cargo itself)
    runs the configured cargo rather than the first one on PATH.
    """
    env = rust_environment(toolchain)
    if toolchain.cargo is not None:
        cargo, _error = resolve_tool("cargo", toolchain.cargo)
        if cargo is not None:
            env["CARGO"] = cargo
    python, _error = resolve_python(toolchain)
    if python is not None:
        env["PYO3_PYTHON"] = python
    return env


def rust_pin_error(
    toolchain: ToolchainConfig | None,
    tool: str,
    env: dict[str, str] | None = None,
) -> str | None:
    """Strict pin check for a cargo/maturin invocation at its point of use.

    Mirrors the Nuitka rule: the CLI gate gives fail-fast UX, but every
    builder that actually runs the tool re-verifies so no build shape (or
    programmatic caller) can slip past a pin. Pinned + unresolvable is an
    error.
    """
    toolchain = toolchain or ToolchainConfig()
    pin = getattr(toolchain, f"{tool}_version")
    if pin is None:
        return None
    path, resolve_error = resolve_tool(tool, getattr(toolchain, tool))
    if path is None:
        return resolve_error or (
            f"{tool} is pinned to {pin!r} but could not be resolved; a pin is "
            "strict for a tool this build uses. Install it or drop the pin."
        )
    return check_version_pin(tool, [path], pin, env)


def probe_version(command: list[str], env: dict[str, str] | None = None) -> str | None:
    """Best-effort `<tool> --version` probe; None when undeterminable.

    ``env`` entries overlay os.environ for the probe - version checks must
    run under the same environment the real invocation will use (a rustup
    shim reports a different version depending on RUSTUP_TOOLCHAIN).
    """
    try:
        completed = subprocess.run(
            [*command, "--version"],
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ, **env} if env else None,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    output = (completed.stdout or "").strip() or (completed.stderr or "").strip()
    first_line = output.splitlines()[0].strip() if output else ""
    match = re.search(r"\d+(\.\d+)*", first_line)
    return match.group(0) if match is not None else None


def check_version_pin(
    display: str,
    command: list[str],
    pin: str | None,
    env: dict[str, str] | None = None,
    *,
    reported: str | None = None,
) -> str | None:
    """Verify an explicit version pin against the resolved tool.

    Unlike the best-effort floors, an explicit pin is strict: a tool whose
    version cannot be determined fails the check. Pins verify only - they
    never install or select a tool. ``env`` must be the environment the real
    invocation will run under so the verified version is the used version.
    """
    if pin is None:
        return None
    if reported is None:
        reported = probe_version(command, env)
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


def python_toolchain_error(python: str, pin: str | None) -> str | None:
    """Run every CPython toolchain check from one interpreter probe.

    Coherence (CPython implementation, build-interpreter minor match) and the
    explicit version pin all read the same `-c` probe, so the two can never
    disagree about what the interpreter reports.
    """
    probe = _probe_python(python)
    if probe is None:
        return (
            f"[toolchain] python at {python} did not report a parseable "
            "version and implementation."
        )
    reported, implementation = probe
    if implementation != "cpython":
        return (
            f"[toolchain] python at {python} is {implementation}, not CPython; "
            "generated extensions and wheel tags target CPython only."
        )
    build = sys.version_info[:2]
    configured = _version_tuple(reported)[:2]
    if configured != build:
        return (
            f"[toolchain] python at {python} is CPython {reported}, but the build "
            f"is running on {build[0]}.{build[1]}. Use a {build[0]}.{build[1]} "
            "interpreter (or run rextio under the configured one)."
        )
    return check_version_pin("CPython", [python], pin, reported=reported)


def python_version_mismatch(python: str) -> str | None:
    """Reject a configured interpreter that cannot stand in for the build's.

    The analyzer's semantics are defined against the interpreter running the
    build, generated wheels are tagged for its minor version, and Nuitka
    output binds to the interpreter it runs under - a different minor version
    (or a non-CPython implementation: PyO3 extensions and cp-tagged wheels
    target CPython only) would silently split those contracts. An explicitly
    configured interpreter is strict: an unprobeable one is an error.
    """
    return python_toolchain_error(python, None)


def _probe_python(python: str) -> tuple[str, str] | None:
    """Return (version, implementation) for an interpreter, or None."""
    script = "import sys;print('%d.%d.%d %s'%(*sys.version_info[:3],sys.implementation.name))"
    try:
        completed = subprocess.run(
            [python, "-c", script],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    parts = (completed.stdout or "").strip().split()
    if len(parts) != 2 or re.fullmatch(r"\d+(\.\d+)*", parts[0]) is None:
        return None
    return parts[0], parts[1]


def _version_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def _satisfies(version: tuple[int, ...], pin: str) -> bool:
    match = re.fullmatch(VERSION_PIN_PATTERN, pin)
    if match is None:  # config validation prevents this; stay defensive
        return False
    operator = match.group(1)
    pinned = _version_tuple(match.group(2))
    if operator == ">=":
        return version >= pinned
    if operator == "==":
        # Explicit == is exact: "==1.85" does not accept 1.85.1.
        return version == pinned
    # A bare pin is a prefix match: "1.85" accepts every 1.85.x.
    return version[: len(pinned)] == pinned
