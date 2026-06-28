from __future__ import annotations

import shutil
import subprocess
import sys
import sysconfig
from rextio.build.subprocess_utils import run_build_tool
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class NativeBuildResult:
    status: str
    tool: str | None
    message: str
    command: list[str] = field(default_factory=list)
    artifact_path: str | None = None
    installed_path: str | None = None
    stdout: str = ""
    stderr: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "tool": self.tool,
            "message": self.message,
            "command": list(self.command),
            "artifact_path": self.artifact_path,
            "installed_path": self.installed_path,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }


def skipped_native_build(message: str) -> NativeBuildResult:
    return NativeBuildResult(status="skipped", tool=None, message=message)


def build_native_extension_with_cargo(rust_dir: Path, python_dir: Path) -> NativeBuildResult:
    cargo = shutil.which("cargo")
    if cargo is None:
        return NativeBuildResult(
            status="failed",
            tool="cargo",
            message=(
                "RXT060 Build failed while compiling generated Rust module. "
                "Cause: cargo was not found. Suggestion: install Rust and Cargo, then rerun rextio build."
            ),
        )

    command = _cargo_build_command(cargo, rust_dir, offline=False)
    completed = _run_cargo(command, rust_dir)
    if completed.returncode != 0:
        if _should_retry_offline(completed.stderr):
            offline_command = _cargo_build_command(cargo, rust_dir, offline=True)
            offline_completed = _run_cargo(offline_command, rust_dir)
            if offline_completed.returncode == 0:
                command = offline_command
                completed = offline_completed
            else:
                return NativeBuildResult(
                    status="failed",
                    tool="cargo",
                    message="RXT060 Build failed while compiling generated Rust module.",
                    command=offline_command,
                    stdout=_tail(_retry_output(completed.stdout, offline_completed.stdout)),
                    stderr=_tail(_retry_output(completed.stderr, offline_completed.stderr)),
                )

    if completed.returncode != 0:
        return NativeBuildResult(
            status="failed",
            tool="cargo",
            message="RXT060 Build failed while compiling generated Rust module.",
            command=command,
            stdout=_tail(completed.stdout),
            stderr=_tail(completed.stderr),
        )

    artifact = _find_cargo_artifact(rust_dir)
    if artifact is None:
        return NativeBuildResult(
            status="failed",
            tool="cargo",
            message=(
                "RXT060 Build failed after Cargo completed. "
                "Cause: generated native library was not found in target/release."
            ),
            command=command,
            stdout=_tail(completed.stdout),
            stderr=_tail(completed.stderr),
        )

    python_dir.mkdir(parents=True, exist_ok=True)
    installed = python_dir / f"_rextio_native{_extension_suffix()}"
    shutil.copy2(artifact, installed)
    return NativeBuildResult(
        status="built",
        tool="cargo",
        message="Generated Rust native module built with Cargo.",
        command=command,
        artifact_path=str(artifact),
        installed_path=str(installed),
        stdout=_tail(completed.stdout),
        stderr=_tail(completed.stderr),
    )


def _cargo_build_command(cargo: str, rust_dir: Path, *, offline: bool) -> list[str]:
    command = [cargo, "build", "--release"]
    if offline:
        command.append("--offline")
    command.extend(["--manifest-path", str(rust_dir / "Cargo.toml")])
    return command


def _run_cargo(command: list[str], rust_dir: Path) -> subprocess.CompletedProcess[str]:
    return run_build_tool(command, cwd=rust_dir)


def _should_retry_offline(stderr: str) -> bool:
    normalized = stderr.lower()
    network_markers = (
        "download of config.json failed",
        "failed to download",
        "failed to get",
        "unable to update registry",
        "couldn't connect",
        "could not resolve host",
        "timeout was reached",
    )
    return any(marker in normalized for marker in network_markers)


def _retry_output(first: str, second: str) -> str:
    if not first:
        return second
    if not second:
        return first
    return f"{first}\nOffline retry:\n{second}"


def _find_cargo_artifact(rust_dir: Path) -> Path | None:
    release_dir = rust_dir / "target" / "release"
    candidates = [
        release_dir / "lib_rextio_native.dylib",
        release_dir / "lib_rextio_native.so",
        release_dir / "_rextio_native.dll",
        release_dir / "_rextio_native.pyd",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _extension_suffix() -> str:
    suffix = sysconfig.get_config_var("EXT_SUFFIX")
    if isinstance(suffix, str) and suffix:
        return suffix
    if sys.platform == "win32":
        return ".pyd"
    return ".so"


def _tail(value: str, limit: int = 4000) -> str:
    if len(value) <= limit:
        return value
    return value[-limit:]
