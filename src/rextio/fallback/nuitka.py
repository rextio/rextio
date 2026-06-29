from __future__ import annotations

import shutil
from pathlib import Path

from rextio.fallback.build_result import FallbackBuildResult
from rextio.build.subprocess_utils import DEFAULT_BUILD_TIMEOUT_SECONDS, run_build_tool


def nuitka_unavailable_message() -> str:
    return (
        "Nuitka fallback was requested, but Nuitka is not installed.\n"
        "Install Nuitka or run: rextio build --fallback=cpython"
    )


def nuitka_available() -> bool:
    return shutil.which("nuitka") is not None


def build_nuitka_fallback(
    python_dir: Path,
    *,
    timeout: float = DEFAULT_BUILD_TIMEOUT_SECONDS,
) -> FallbackBuildResult:
    nuitka = shutil.which("nuitka")
    if nuitka is None:
        return FallbackBuildResult(
            status="failed",
            backend="nuitka",
            message=f"RXT060 Build failed while preparing Nuitka fallback. {nuitka_unavailable_message()}",
        )

    targets = _nuitka_module_targets(python_dir)
    if not targets:
        return FallbackBuildResult(
            status="built",
            backend="nuitka",
            message="No Python fallback modules required Nuitka compilation.",
        )

    commands: list[list[str]] = []
    compiled_artifacts: list[str] = []
    stdout_parts: list[str] = []
    stderr_parts: list[str] = []
    for target in targets:
        command = [
            nuitka,
            "--module",
            str(target),
            f"--output-dir={target.parent}",
            "--remove-output",
        ]
        commands.append(command)
        completed = run_build_tool(command, cwd=python_dir, timeout=timeout)
        stdout_parts.append(_tail(completed.stdout))
        stderr_parts.append(_tail(completed.stderr))
        if completed.returncode != 0:
            return FallbackBuildResult(
                status="failed",
                backend="nuitka",
                message=(
                    "RXT060 Build failed while compiling Python fallback with Nuitka. "
                    f"Cause: Nuitka exited with status {completed.returncode}."
                ),
                command=commands,
                compiled_artifacts=compiled_artifacts,
                stdout="\n".join(part for part in stdout_parts if part),
                stderr="\n".join(part for part in stderr_parts if part),
            )
        compiled_artifacts.extend(str(path) for path in _compiled_outputs_for(target))

    return FallbackBuildResult(
        status="built",
        backend="nuitka",
        message="Python fallback modules compiled with Nuitka.",
        command=commands,
        compiled_artifacts=sorted(set(compiled_artifacts)),
        stdout="\n".join(part for part in stdout_parts if part),
        stderr="\n".join(part for part in stderr_parts if part),
    )


def _nuitka_module_targets(python_dir: Path) -> list[Path]:
    targets: list[Path] = []
    for path in sorted(python_dir.rglob("*.py")):
        relative = path.relative_to(python_dir)
        if relative.parts and relative.parts[0] == "rextio":
            continue
        if path.name == "__init__.py":
            continue
        targets.append(path)
    return targets


def _compiled_outputs_for(source: Path) -> list[Path]:
    suffixes = (".so", ".pyd", ".dll", ".dylib")
    return [
        path
        for path in sorted(source.parent.glob(f"{source.stem}*"))
        if path.is_file() and path.suffix in suffixes
    ]


def _tail(value: str, limit: int = 4000) -> str:
    if len(value) <= limit:
        return value
    return value[-limit:]
