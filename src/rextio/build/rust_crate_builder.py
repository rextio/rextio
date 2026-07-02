"""Building the optional Rust-importable crate artifact."""

from __future__ import annotations

import shutil
from rextio.build.subprocess_utils import DEFAULT_BUILD_TIMEOUT_SECONDS, run_build_tool
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class RustCrateBuildResult:
    """The outcome of building the Rust-importable crate."""

    status: str
    message: str
    command: list[str] = field(default_factory=list)
    crate_path: str | None = None
    artifact_path: str | None = None
    stdout: str = ""
    stderr: str = ""

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this result."""
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
    """Return a result marking the crate build as skipped."""
    return RustCrateBuildResult(status="skipped", message=message)


def build_importable_rust_crate(
    crate_dir: Path,
    dist_dir: Path,
    crate_name: str,
    *,
    timeout: float = DEFAULT_BUILD_TIMEOUT_SECONDS,
) -> RustCrateBuildResult:
    """Build the Rust-importable crate artifact and return the result."""
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
    completed = run_build_tool(command, cwd=crate_dir, timeout=timeout)
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
