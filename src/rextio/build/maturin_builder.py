from __future__ import annotations

import shutil
import zipfile
from pathlib import Path

from rextio.build.cargo_builder import NativeBuildResult
from rextio.build.subprocess_utils import run_build_tool


def maturin_available() -> bool:
    return shutil.which("maturin") is not None


def build_native_extension_with_maturin(rust_dir: Path, python_dir: Path) -> NativeBuildResult:
    maturin = shutil.which("maturin")
    if maturin is None:
        return NativeBuildResult(
            status="failed",
            tool="maturin",
            message=(
                "RXT060 Build failed while compiling generated Rust module. "
                "Cause: maturin was not found."
            ),
        )

    wheels_dir = rust_dir / "target" / "wheels"
    wheels_dir.mkdir(parents=True, exist_ok=True)
    command = [
        maturin,
        "build",
        "--release",
        "--manifest-path",
        str(rust_dir / "Cargo.toml"),
        "--out",
        str(wheels_dir),
    ]
    completed = run_build_tool(command, cwd=rust_dir)
    if completed.returncode != 0:
        return NativeBuildResult(
            status="failed",
            tool="maturin",
            message="RXT060 Build failed while compiling generated Rust module with maturin.",
            command=command,
            stdout=_tail(completed.stdout),
            stderr=_tail(completed.stderr),
        )

    wheel = _latest_wheel(wheels_dir)
    if wheel is None:
        return NativeBuildResult(
            status="failed",
            tool="maturin",
            message=(
                "RXT060 Build failed after maturin completed. "
                "Cause: generated wheel was not found."
            ),
            command=command,
            stdout=_tail(completed.stdout),
            stderr=_tail(completed.stderr),
        )

    installed = _extract_native_extension(wheel, python_dir)
    if installed is None:
        return NativeBuildResult(
            status="failed",
            tool="maturin",
            message=(
                "RXT060 Build failed after maturin completed. "
                "Cause: _rextio_native extension was not found in the generated wheel."
            ),
            command=command,
            artifact_path=str(wheel),
            stdout=_tail(completed.stdout),
            stderr=_tail(completed.stderr),
        )

    return NativeBuildResult(
        status="built",
        tool="maturin",
        message="Generated Rust native module built with maturin.",
        command=command,
        artifact_path=str(wheel),
        installed_path=str(installed),
        stdout=_tail(completed.stdout),
        stderr=_tail(completed.stderr),
    )


def _latest_wheel(wheels_dir: Path) -> Path | None:
    wheels = sorted(wheels_dir.glob("*.whl"), key=lambda path: path.stat().st_mtime)
    if not wheels:
        return None
    return wheels[-1]


def _extract_native_extension(wheel: Path, python_dir: Path) -> Path | None:
    python_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(wheel) as archive:
        for name in sorted(archive.namelist()):
            filename = Path(name).name
            if not _is_native_extension(filename):
                continue
            destination = python_dir / filename
            destination.write_bytes(archive.read(name))
            return destination
    return None


def _is_native_extension(filename: str) -> bool:
    return filename.startswith("_rextio_native") and filename.endswith((".so", ".pyd", ".dll", ".dylib"))


def _tail(value: str, limit: int = 4000) -> str:
    if len(value) <= limit:
        return value
    return value[-limit:]
