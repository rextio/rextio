"""Building executable artifacts (zipapp / Nuitka)."""

from __future__ import annotations

import re
import shutil
import zipapp
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
        zipapp.create_archive(
            source=python_dir,
            target=target,
            interpreter="/usr/bin/env python3",
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

    nuitka = shutil.which("nuitka")
    if nuitka is None:
        return ExecutableBuildResult(
            status="failed",
            path=None,
            message=(
                "RXT060 Executable build failed because Nuitka is not installed. "
                "Install Nuitka or use --executable-backend=zipapp."
            ),
            entrypoint=entrypoint,
            backend="nuitka",
        )

    name = _executable_name(executable_name, entrypoint)
    launcher = _write_nuitka_launcher(python_dir, entrypoint)
    dist_dir.mkdir(parents=True, exist_ok=True)
    command = [
        nuitka,
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
    if standalone_dir.is_dir():
        return standalone_dir
    return None


def _tail(value: str, limit: int = 4000) -> str:
    if len(value) <= limit:
        return value
    return value[-limit:]
