"""The experimental Nuitka fallback backend."""

from __future__ import annotations

import shutil
from pathlib import Path

from rextio.analyzer.native_marker import (
    external_accelerator_for_source,
    project_module_names_for_tree,
)
from rextio.fallback.build_result import FallbackBuildResult
from rextio.build.preflight import nuitka_version_error
from rextio.build.subprocess_utils import DEFAULT_BUILD_TIMEOUT_SECONDS, run_build_tool


def nuitka_unavailable_message() -> str:
    """Return the message shown when Nuitka is required but not installed."""
    return (
        "Nuitka fallback was requested, but Nuitka is not installed.\n"
        "Install Nuitka or run: rextio build --fallback=cpython"
    )


def nuitka_available() -> bool:
    """Report whether Nuitka is available."""
    return shutil.which("nuitka") is not None


def build_nuitka_fallback(
    python_dir: Path,
    *,
    timeout: float = DEFAULT_BUILD_TIMEOUT_SECONDS,
) -> FallbackBuildResult:
    """Build the Nuitka fallback and return the result."""
    nuitka = shutil.which("nuitka")
    if nuitka is None:
        return FallbackBuildResult(
            status="failed",
            backend="nuitka",
            message=f"RXT060 Build failed while preparing Nuitka fallback. {nuitka_unavailable_message()}",
        )
    version_error = nuitka_version_error(nuitka)
    if version_error is not None:
        return FallbackBuildResult(
            status="failed",
            backend="nuitka",
            message=f"RXT060 Build failed while preparing Nuitka fallback. {version_error}",
        )

    targets, accelerated = _nuitka_module_targets(python_dir)
    skipped_note = ""
    if accelerated:
        names = ", ".join(
            sorted(_display_module_path(path.relative_to(python_dir)) for path in accelerated)
        )
        skipped_note = (
            f" Kept as plain Python for external accelerators (Nuitka-compiled "
            f"functions expose no bytecode, which tools like Numba require): {names}."
        )
    if not targets:
        return FallbackBuildResult(
            status="built",
            backend="nuitka",
            message="No Python fallback modules required Nuitka compilation." + skipped_note,
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
        message="Python fallback modules compiled with Nuitka." + skipped_note,
        command=commands,
        compiled_artifacts=sorted(set(compiled_artifacts)),
        stdout="\n".join(part for part in stdout_parts if part),
        stderr="\n".join(part for part in stderr_parts if part),
    )


def _display_module_path(relative: Path) -> str:
    """Present a generated `_fallback_<stem>.py` under its source module name.

    A mixed module (native + accelerated in one source file) generates a
    public wrapper plus a `_fallback_<stem>.py` copy carrying the accelerated
    code; the internal filename would leak generated-layout details into
    user-facing messages.
    """
    name = relative.name
    if name.startswith("_fallback_") and name.endswith(".py"):
        original = f"{name[len('_fallback_'):-len('.py')]}.py"
        return (relative.parent / original).as_posix() + " (fallback copy)"
    return relative.as_posix()


def _nuitka_module_targets(python_dir: Path) -> tuple[list[Path], list[Path]]:
    """Return (modules to compile, modules kept plain for external accelerators).

    A module whose functions carry a recognized external-accelerator
    decorator (e.g. ``@numba.njit``) must stay plain Python: Nuitka-compiled
    functions expose no real bytecode, which those tools need at runtime.
    Skipping compilation is lossless here - the ``.py`` stays in the tree and
    keeps being imported (a compiled sibling would otherwise shadow it).
    """
    targets: list[Path] = []
    accelerated: list[Path] = []
    project_modules = project_module_names_for_tree(python_dir)
    for path in sorted(python_dir.rglob("*.py")):
        relative = path.relative_to(python_dir)
        if relative.parts and relative.parts[0] == "rextio":
            continue
        try:
            source = path.read_text(encoding="utf-8")
        except OSError:
            source = ""
        if source and external_accelerator_for_source(source, project_modules) is not None:
            # Report accelerated `__init__.py` too: it was never a compile
            # target (packages stay plain), but the user should see it in the
            # kept-plain list like any other accelerated module.
            accelerated.append(path)
            continue
        if path.name == "__init__.py":
            continue
        targets.append(path)
    return targets, accelerated


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
