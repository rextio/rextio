"""Building executable artifacts (zipapp / Nuitka / native Rust binary)."""

from __future__ import annotations

import re
import shutil
import stat
import sys
import zipapp
from rextio.build.preflight import nuitka_toolchain_error
from rextio.build.toolchain import resolve_nuitka_command, resolve_tool, rust_environment
from rextio.config.schema import ToolchainConfig
from rextio.analyzer.native_marker import (
    external_accelerator_for_source,
    project_module_names_for_tree,
)
from rextio.build.subprocess_utils import DEFAULT_BUILD_TIMEOUT_SECONDS, run_build_tool
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ExecutableBuildResult:
    """The outcome of building an executable artifact."""

    status: str
    path: str | None
    message: str
    entrypoint: str | None = None
    backend: str | None = None
    command: list[str] | None = None
    stdout: str = ""
    stderr: str = ""

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this result."""
        return {
            "status": self.status,
            "path": self.path,
            "message": self.message,
            "entrypoint": self.entrypoint,
            "backend": self.backend,
            "command": self.command,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }


def skipped_executable(message: str) -> ExecutableBuildResult:
    """Return a result marking the executable build as skipped."""
    return ExecutableBuildResult(
        status="skipped",
        path=None,
        message=message,
    )


def build_rust_executable(
    crate_dir: Path,
    dist_dir: Path,
    binary_name: str,
    entrypoint: str,
    *,
    timeout: float = DEFAULT_BUILD_TIMEOUT_SECONDS,
    toolchain: ToolchainConfig | None = None,
) -> ExecutableBuildResult:
    """Compile the generated Rust bin crate and copy the binary into ``dist``.

    The crate (``Cargo.toml`` + ``src/main.rs``) is expected to already be
    written into ``crate_dir`` by the caller. This is a standalone native binary
    with no Python dependency.
    """
    toolchain = toolchain or ToolchainConfig()
    cargo, resolve_error = resolve_tool("cargo", toolchain.cargo)
    if cargo is None:
        return ExecutableBuildResult(
            status="failed",
            path=None,
            message=(
                "RXT060 Executable build failed while compiling the Rust binary. "
                f"Cause: {resolve_error or 'cargo was not found.'} "
                "Suggestion: install Rust and Cargo, then rerun rextio build."
            ),
            entrypoint=entrypoint,
            backend="rust",
        )

    command = [cargo, "build", "--release", "--manifest-path", str(crate_dir / "Cargo.toml")]
    completed = run_build_tool(command, cwd=crate_dir, timeout=timeout, env=rust_environment(toolchain))
    if completed.returncode != 0:
        return ExecutableBuildResult(
            status="failed",
            path=None,
            message="RXT060 Executable build failed while compiling the Rust binary.",
            entrypoint=entrypoint,
            backend="rust",
            command=command,
            stdout=_tail(completed.stdout),
            stderr=_tail(completed.stderr),
        )

    binary = _find_cargo_binary(crate_dir, binary_name)
    if binary is None:
        return ExecutableBuildResult(
            status="failed",
            path=None,
            message=(
                "RXT060 Executable build failed after Cargo completed. "
                f"Cause: the compiled binary '{binary_name}' was not found in target/release."
            ),
            entrypoint=entrypoint,
            backend="rust",
            command=command,
            stdout=_tail(completed.stdout),
            stderr=_tail(completed.stderr),
        )

    dist_dir.mkdir(parents=True, exist_ok=True)
    destination = dist_dir / binary.name
    shutil.copy2(binary, destination)
    destination.chmod(destination.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    return ExecutableBuildResult(
        status="built",
        path=str(destination),
        message="Generated native Rust executable artifact.",
        entrypoint=entrypoint,
        backend="rust",
        command=command,
        stdout=_tail(completed.stdout),
        stderr=_tail(completed.stderr),
    )


def _find_cargo_binary(crate_dir: Path, binary_name: str) -> Path | None:
    """Return Cargo's release binary path, accepting the Windows ``.exe`` suffix."""
    release_dir = crate_dir / "target" / "release"
    for suffix in ("", ".exe"):
        candidate = release_dir / f"{binary_name}{suffix}"
        if candidate.exists():
            return candidate
    return None


def build_zipapp_executable(
    python_dir: Path,
    dist_dir: Path,
    entrypoint: str | None,
    executable_name: str | None = None,
) -> ExecutableBuildResult:
    """Build a zipapp executable from the entrypoint and return the result."""
    if entrypoint is None:
        return skipped_executable("No executable entrypoint was requested.")
    if not python_dir.exists():
        return ExecutableBuildResult(
            status="failed",
            path=None,
            message="RXT060 Executable build failed because the Python build artifact was missing.",
            entrypoint=entrypoint,
            backend="zipapp",
        )
    if not _valid_entrypoint(entrypoint):
        return ExecutableBuildResult(
            status="failed",
            path=None,
            message=(
                "RXT060 Executable build failed because the entrypoint was invalid. "
                "Use module:function."
            ),
            entrypoint=entrypoint,
            backend="zipapp",
        )

    name = _executable_name(executable_name, entrypoint)
    dist_dir.mkdir(parents=True, exist_ok=True)
    target = dist_dir / f"{name}.pyz"
    if target.exists():
        target.unlink()

    try:
        # Pin the interpreter to the build-time Python's minor version so a
        # zipapp generated under, e.g., 3.13 is not silently run by an older
        # python3 that lacks the native extension's ABI.
        interpreter = f"/usr/bin/env python{sys.version_info.major}.{sys.version_info.minor}"
        zipapp.create_archive(
            source=python_dir,
            target=target,
            interpreter=interpreter,
            main=entrypoint,
            compressed=True,
        )
    except Exception as exc:
        return ExecutableBuildResult(
            status="failed",
            path=None,
            message=f"RXT060 Executable build failed while creating zipapp. Cause: {exc}",
            entrypoint=entrypoint,
            backend="zipapp",
        )
    target.chmod(0o755)
    return ExecutableBuildResult(
        status="built",
        path=str(target),
        message="Generated zipapp executable artifact.",
        entrypoint=entrypoint,
        backend="zipapp",
    )


def build_nuitka_executable(
    python_dir: Path,
    dist_dir: Path,
    entrypoint: str | None,
    executable_name: str | None = None,
    mode: str = "standalone",
    *,
    timeout: float = DEFAULT_BUILD_TIMEOUT_SECONDS,
    toolchain: ToolchainConfig | None = None,
) -> ExecutableBuildResult:
    """Build a Nuitka executable from the entrypoint and return the result."""
    if entrypoint is None:
        return skipped_executable("No executable entrypoint was requested.")
    if not python_dir.exists():
        return ExecutableBuildResult(
            status="failed",
            path=None,
            message="RXT060 Executable build failed because the Python build artifact was missing.",
            entrypoint=entrypoint,
            backend="nuitka",
        )
    if not _valid_entrypoint(entrypoint):
        return ExecutableBuildResult(
            status="failed",
            path=None,
            message=(
                "RXT060 Executable build failed because the entrypoint was invalid. "
                "Use module:function."
            ),
            entrypoint=entrypoint,
            backend="nuitka",
        )
    if mode not in {"standalone", "onefile"}:
        return ExecutableBuildResult(
            status="failed",
            path=None,
            message=(
                "RXT060 Executable build failed because the Nuitka mode was invalid. "
                'Use "standalone" or "onefile".'
            ),
            entrypoint=entrypoint,
            backend="nuitka",
        )

    nuitka_command, resolve_error = resolve_nuitka_command(toolchain or ToolchainConfig())
    if nuitka_command is None:
        return ExecutableBuildResult(
            status="failed",
            path=None,
            message=(
                "RXT060 Executable build failed because Nuitka is not installed. "
                f"{resolve_error or ''}"
                "Install Nuitka or use --executable-backend=zipapp or "
                "--executable-backend=rust."
            ),
            entrypoint=entrypoint,
            backend="nuitka",
        )
    version_error = nuitka_toolchain_error(nuitka_command, toolchain)
    if version_error is not None:
        return ExecutableBuildResult(
            status="failed",
            path=None,
            message=f"RXT060 Executable build failed. {version_error}",
            entrypoint=entrypoint,
            backend="nuitka",
        )

    accelerated = _externally_accelerated_modules(python_dir)
    if accelerated:
        names = ", ".join(sorted(accelerated))
        return ExecutableBuildResult(
            status="failed",
            path=None,
            message=(
                "RXT060 Executable build failed: the project uses an external "
                f"accelerator (e.g. Numba) in {names}, and a Nuitka-compiled "
                "executable cannot serve those functions (compiled functions "
                "expose no bytecode, which the accelerator requires at runtime, "
                "and the accelerator package is not bundled). Deploy such "
                "projects as a wheel/zipapp with the accelerator installed, or "
                "remove the accelerator decorators for a Nuitka executable."
            ),
            entrypoint=entrypoint,
            backend="nuitka",
        )

    name = _executable_name(executable_name, entrypoint)
    launcher = _write_nuitka_launcher(python_dir, entrypoint)
    dist_dir.mkdir(parents=True, exist_ok=True)
    command = [
        *nuitka_command,
        f"--{mode}",
        str(launcher),
        f"--output-dir={dist_dir}",
        f"--output-filename={name}",
        "--remove-output",
    ]
    completed = run_build_tool(command, cwd=python_dir, timeout=timeout)
    if completed.returncode != 0:
        return ExecutableBuildResult(
            status="failed",
            path=None,
            message=(
                "RXT060 Executable build failed while compiling Python entrypoint "
                f"with Nuitka. Cause: Nuitka exited with status {completed.returncode}."
            ),
            entrypoint=entrypoint,
            backend="nuitka",
            command=command,
            stdout=_tail(completed.stdout),
            stderr=_tail(completed.stderr),
        )

    executable = _find_nuitka_executable(dist_dir, name, mode)
    if executable is None:
        return ExecutableBuildResult(
            status="failed",
            path=None,
            message="RXT060 Executable build failed because the Nuitka output was not found.",
            entrypoint=entrypoint,
            backend="nuitka",
            command=command,
            stdout=_tail(completed.stdout),
            stderr=_tail(completed.stderr),
        )
    return ExecutableBuildResult(
        status="built",
        path=str(executable),
        message=f"Generated Nuitka {mode} executable artifact.",
        entrypoint=entrypoint,
        backend="nuitka",
        command=command,
        stdout=_tail(completed.stdout),
        stderr=_tail(completed.stderr),
    )


def _valid_entrypoint(value: str) -> bool:
    module, separator, function = value.partition(":")
    if separator != ":" or not module or not function:
        return False
    identifier = r"[A-Za-z_][A-Za-z0-9_]*"
    dotted = rf"{identifier}(\.{identifier})*"
    return re.fullmatch(dotted, module) is not None and re.fullmatch(dotted, function) is not None


def _executable_name(executable_name: str | None, entrypoint: str) -> str:
    raw = executable_name or entrypoint.split(":", 1)[0].rsplit(".", 1)[-1]
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "-", raw).strip(".-_")
    return normalized or "rextio-app"


def _write_nuitka_launcher(python_dir: Path, entrypoint: str) -> Path:
    module, function = entrypoint.split(":", 1)
    launcher = python_dir / "__rextio_executable__.py"
    launcher.write_text(
        "\n".join(
            [
                "# Generated by Rextio. Do not edit manually.",
                f"from {module} import {function} as _rextio_entrypoint",
                "",
                "if __name__ == '__main__':",
                "    raise SystemExit(_rextio_entrypoint() or 0)",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return launcher


def _externally_accelerated_modules(python_dir: Path) -> list[str]:
    """Relative paths of fallback modules using a recognized external accelerator.

    Such modules cannot ride inside a Nuitka-compiled executable: compiled
    functions expose no bytecode (which e.g. Numba lifts at first call), and the
    accelerator package itself is not bundled - so the build fails early with
    guidance instead of producing a binary that dies at the first call.
    """
    found: list[str] = []
    project_modules = project_module_names_for_tree(python_dir)
    for path in sorted(python_dir.rglob("*.py")):
        relative = path.relative_to(python_dir)
        if relative.parts and relative.parts[0] == "rextio":
            continue
        try:
            source = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if external_accelerator_for_source(source, project_modules) is not None:
            name = relative.name
            if name.startswith("_fallback_") and name.endswith(".py"):
                original = f"{name[len('_fallback_'):-len('.py')]}.py"
                found.append((relative.parent / original).as_posix() + " (fallback copy)")
            else:
                found.append(relative.as_posix())
    return found


def _find_nuitka_executable(dist_dir: Path, name: str, mode: str) -> Path | None:
    suffixes = ("", ".exe")
    if mode == "onefile":
        for suffix in suffixes:
            candidate = dist_dir / f"{name}{suffix}"
            if candidate.is_file():
                return candidate
        return None

    standalone_dir = dist_dir / f"{name}.dist"
    for suffix in suffixes:
        candidate = standalone_dir / f"{name}{suffix}"
        if candidate.is_file():
            return candidate
    # A `.dist` directory without the launcher binary inside is a partial
    # build, not a success: returning the directory here made the caller
    # report status="built" with a path no one can execute.
    return None


def _tail(value: str, limit: int = 4000) -> str:
    if len(value) <= limit:
        return value
    return value[-limit:]
