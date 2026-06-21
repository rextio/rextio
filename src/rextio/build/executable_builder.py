from __future__ import annotations

import re
import zipapp
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ExecutableBuildResult:
    status: str
    path: str | None
    message: str
    entrypoint: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "path": self.path,
            "message": self.message,
            "entrypoint": self.entrypoint,
        }


def skipped_executable(message: str) -> ExecutableBuildResult:
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
    if entrypoint is None:
        return skipped_executable("No executable entrypoint was requested.")
    if not python_dir.exists():
        return ExecutableBuildResult(
            status="failed",
            path=None,
            message="RXT060 Executable build failed because the Python build artifact was missing.",
            entrypoint=entrypoint,
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
        )
    target.chmod(0o755)
    return ExecutableBuildResult(
        status="built",
        path=str(target),
        message="Generated zipapp executable artifact.",
        entrypoint=entrypoint,
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
