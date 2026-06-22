from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class RustCrateBuildResult:
    status: str
    message: str
    command: list[str] = field(default_factory=list)
    crate_path: str | None = None
    artifact_path: str | None = None
    stdout: str = ""
    stderr: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "message": self.message,
            "command": list(self.command),
            "crate_path": self.crate_path,
            "artifact_path": self.artifact_path,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }


def skipped_rust_crate_build(message: str) -> RustCrateBuildResult:
    return RustCrateBuildResult(status="skipped", message=message)


def build_importable_rust_crate(
    crate_dir: Path,
    dist_dir: Path,
    crate_name: str,
) -> RustCrateBuildResult:
    cargo = shutil.which("cargo")
    if cargo is None:
        return RustCrateBuildResult(
            status="failed",
            message=(
                "RXT060 Build failed while compiling Rust-importable crate. "
                "Cause: cargo was not found. Suggestion: install Rust and Cargo, then rerun rextio build."
            ),
        )

    command = [cargo, "build", "--release", "--manifest-path", str(crate_dir / "Cargo.toml")]
    completed = subprocess.run(
        command,
        cwd=crate_dir,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return RustCrateBuildResult(
            status="failed",
            message="RXT060 Build failed while compiling Rust-importable crate.",
            command=command,
            stdout=_tail(completed.stdout),
            stderr=_tail(completed.stderr),
        )

    artifact = _find_rlib(crate_dir, crate_name)
    if artifact is None:
        return RustCrateBuildResult(
            status="failed",
            message=(
                "RXT060 Build failed after Cargo completed. "
                "Cause: Rust rlib artifact was not found in target/release."
            ),
            command=command,
            stdout=_tail(completed.stdout),
            stderr=_tail(completed.stderr),
        )

    dist_crate = dist_dir / f"{crate_name}-rust-crate"
    if dist_crate.exists():
        shutil.rmtree(dist_crate)
    dist_crate.mkdir(parents=True, exist_ok=True)
    shutil.copy2(crate_dir / "Cargo.toml", dist_crate / "Cargo.toml")
    shutil.copytree(crate_dir / "src", dist_crate / "src")

    return RustCrateBuildResult(
        status="built",
        message="Rust-importable crate built with Cargo.",
        command=command,
        crate_path=str(dist_crate),
        artifact_path=str(artifact),
        stdout=_tail(completed.stdout),
        stderr=_tail(completed.stderr),
    )


def _find_rlib(crate_dir: Path, crate_name: str) -> Path | None:
    release_dir = crate_dir / "target" / "release"
    normalized = crate_name.replace("-", "_")
    candidate = release_dir / f"lib{normalized}.rlib"
    if candidate.exists():
        return candidate
    matches = sorted(release_dir.glob("lib*.rlib"))
    return matches[0] if matches else None


def _tail(value: str, limit: int = 4000) -> str:
    if len(value) <= limit:
        return value
    return value[-limit:]
