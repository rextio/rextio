#!/usr/bin/env python3
"""Run the bounded strict artifact lifecycle on a supported host."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile


EXPECTED_CARGO_VERSION = "1.93.1"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_CONTRACT_TEST = (
    PROJECT_ROOT / "tests" / "e2e" / "test_full_c6_cli_real_cargo.py"
)
_HEAD_COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}")


class PreflightError(RuntimeError):
    """Report that the current host cannot run the bounded validation."""


def _capture(command: list[str]) -> str:
    """Run a preflight command and return its stripped standard output."""
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            check=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise PreflightError(f"preflight command failed: {command[0]}") from exc
    return completed.stdout.strip()


def _require_executable(path: Path, *, label: str) -> None:
    """Require one fixed executable path used by the strict profile."""
    if not path.is_file() or not os.access(path, os.X_OK):
        raise PreflightError(f"{label} is unavailable at {path}")


def _preflight_macos() -> None:
    """Check the macOS sandbox and selected full-Xcode installation."""
    sandbox_exec = Path("/usr/bin/sandbox-exec")
    xcode_select = Path("/usr/bin/xcode-select")
    xcrun = Path("/usr/bin/xcrun")
    _require_executable(sandbox_exec, label="sandbox-exec")
    _require_executable(xcode_select, label="xcode-select")
    _require_executable(xcrun, label="xcrun")

    xcode_app = Path("/Applications/Xcode.app")
    expected_developer_root = xcode_app / "Contents" / "Developer"
    if xcode_app.is_symlink() or not xcode_app.is_dir():
        raise PreflightError(
            "Strict artifact validation requires a non-symlink /Applications/Xcode.app"
        )
    developer_root = Path(_capture([str(xcode_select), "-p"]))
    if (
        developer_root != expected_developer_root
        or developer_root.is_symlink()
        or not developer_root.is_dir()
    ):
        raise PreflightError(
            "Strict artifact validation requires xcode-select to use "
            "/Applications/Xcode.app/Contents/Developer"
        )

    clang = Path(_capture([str(xcrun), "--find", "clang"]))
    sdk = Path(_capture([str(xcrun), "--sdk", "macosx", "--show-sdk-path"]))
    expected_clang = (
        developer_root / "Toolchains" / "XcodeDefault.xctoolchain" / "usr" / "bin" / "clang"
    )
    sdk_root = developer_root / "Platforms" / "MacOSX.platform" / "Developer" / "SDKs"
    if clang != expected_clang or clang.is_symlink():
        raise PreflightError("xcrun clang is outside the fixed Xcode toolchain")
    _require_executable(clang, label="Xcode clang")
    try:
        resolved_sdk = sdk.resolve(strict=True)
        resolved_sdk_root = sdk_root.resolve(strict=True)
    except OSError as exc:
        raise PreflightError("xcrun did not identify an available macOS SDK") from exc
    if not resolved_sdk.is_dir() or not resolved_sdk.is_relative_to(resolved_sdk_root):
        raise PreflightError("xcrun macOS SDK is outside the fixed Xcode tree")


def _preflight_linux() -> None:
    """Check the fixed bubblewrap path and unprivileged sandbox launch."""
    bubblewrap = Path("/usr/bin/bwrap")
    _require_executable(bubblewrap, label="bubblewrap")
    probe = [
        str(bubblewrap),
        "--die-with-parent",
        "--unshare-user",
        "--unshare-pid",
        "--ro-bind",
        "/",
        "/",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "/usr/bin/true",
    ]
    try:
        subprocess.run(
            probe,
            capture_output=True,
            check=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise PreflightError(
            "bubblewrap cannot create the required unprivileged user namespace"
        ) from exc


def preflight() -> str:
    """Validate the frozen interpreter, target, toolchain, and sandbox scope."""
    if platform.python_implementation() != "CPython" or sys.version_info[:2] != (3, 11):
        raise PreflightError(
            "Strict artifact host validation requires CPython 3.11 exactly"
        )

    machine = platform.machine().lower()
    if sys.platform == "darwin" and machine in {"arm64", "aarch64"}:
        target = "aarch64-apple-darwin"
        _preflight_macos()
    elif sys.platform.startswith("linux") and machine in {"x86_64", "amd64"}:
        target = "x86_64-unknown-linux-gnu"
        _preflight_linux()
    else:
        raise PreflightError(
            f"unsupported strict artifact host: {sys.platform}/{machine}"
        )

    cargo = shutil.which("cargo")
    if cargo is None:
        raise PreflightError("cargo is unavailable on PATH")
    cargo_version = _capture([cargo, "--version"]).split()
    if len(cargo_version) < 2 or cargo_version[:2] != ["cargo", EXPECTED_CARGO_VERSION]:
        observed = " ".join(cargo_version[:2]) or "unknown"
        raise PreflightError(
            "Strict artifact validation requires cargo "
            f"{EXPECTED_CARGO_VERSION} exactly; observed {observed}"
        )
    if not ARTIFACT_CONTRACT_TEST.is_file():
        raise PreflightError(
            f"Strict artifact test harness is unavailable: {ARTIFACT_CONTRACT_TEST}"
        )
    return target


def _venv_python(venv: Path) -> Path:
    """Return the Python executable for a POSIX virtual environment."""
    return venv / "bin" / "python"


def _run_checked(command: list[str], *, cwd: Path | None = None) -> None:
    """Run one setup command and fail with its original nonzero status."""
    subprocess.run(command, cwd=cwd, check=True)


def _git_output(git: str, *arguments: str) -> str:
    """Return bounded Git output or fail the manual validation closed."""
    return _capture([git, "-C", str(PROJECT_ROOT), *arguments])


def _require_clean_git_state(git: str) -> None:
    """Reject staged, unstaged, and ordinary untracked worktree state."""
    status = _git_output(
        git,
        "status",
        "--porcelain=v1",
        "--untracked-files=normal",
    )
    if status:
        raise PreflightError(
            "Strict artifact host validation requires a clean Git worktree and index"
        )


def _stage_tracked_head(destination: Path) -> str:
    """Export the clean index/HEAD into an empty, non-repository directory."""
    git = shutil.which("git")
    if git is None:
        raise PreflightError("git is unavailable on PATH")
    if destination.is_symlink() or not destination.is_dir() or any(destination.iterdir()):
        raise PreflightError(
            "Strict artifact source staging directory must be fresh and empty"
        )

    head_commit = _git_output(git, "rev-parse", "--verify", "HEAD^{commit}")
    if _HEAD_COMMIT_PATTERN.fullmatch(head_commit) is None:
        raise PreflightError("Git HEAD did not resolve to an exact SHA-1 commit id")
    _require_clean_git_state(git)
    prefix = f"{destination.resolve()}{os.sep}"
    try:
        subprocess.run(
            [
                git,
                "-C",
                str(PROJECT_ROOT),
                "checkout-index",
                "--all",
                "--ignore-skip-worktree-bits",
                f"--prefix={prefix}",
            ],
            check=True,
            timeout=60,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise PreflightError("Git could not stage the tracked HEAD source snapshot") from exc

    if _git_output(git, "rev-parse", "--verify", "HEAD^{commit}") != head_commit:
        raise PreflightError("Git HEAD changed during source staging")
    _require_clean_git_state(git)
    return head_commit


def run_validation() -> int:
    """Build, install, and run the strict artifact lifecycle harness."""
    target = preflight()

    with tempfile.TemporaryDirectory(prefix="rextio-artifact-contract-") as temporary:
        root = Path(temporary)
        source_root = root / "source"
        build_venv = root / "build-venv"
        test_venv = root / "test-venv"
        wheel_dir = root / "wheel-dist"
        run_root = root / "run"
        source_root.mkdir()
        wheel_dir.mkdir()
        run_root.mkdir()

        head_commit = _stage_tracked_head(source_root)
        staged_artifact_contract_test = (
            source_root / "tests" / "e2e" / "test_full_c6_cli_real_cargo.py"
        )
        if not staged_artifact_contract_test.is_file():
            raise PreflightError(
                "tracked HEAD snapshot omitted the strict artifact E2E harness"
            )
        print(f"Strict artifact manual host preflight passed: {target}", flush=True)
        print(
            "Strict artifact manual source snapshot: "
            f"HEAD={head_commit} tracked-files-only",
            flush=True,
        )

        _run_checked([sys.executable, "-m", "venv", str(build_venv)])
        build_python = _venv_python(build_venv)
        _run_checked(
            [str(build_python), "-m", "pip", "install", "--disable-pip-version-check", "build"]
        )
        _run_checked(
            [
                str(build_python),
                "-m",
                "build",
                "--wheel",
                "--outdir",
                str(wheel_dir),
                str(source_root),
            ]
        )
        wheels = sorted(wheel_dir.glob("*.whl"))
        if len(wheels) != 1:
            raise PreflightError(f"expected exactly one built wheel, found {len(wheels)}")

        _run_checked([sys.executable, "-m", "venv", str(test_venv)])
        test_python = _venv_python(test_venv)
        _run_checked(
            [
                str(test_python),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-compile",
                str(wheels[0]),
                "pytest",
            ]
        )

        environment = {
            key: value
            for key, value in os.environ.items()
            if key not in {"PYTHONHOME", "PYTHONPATH", "VIRTUAL_ENV"}
        }
        environment.update(
            {
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONNOUSERSITE": "1",
                "REXTIO_ARTIFACT_CONTRACT_E2E": "1",
                "REXTIO_ARTIFACT_CONTRACT_WHEEL": str(wheels[0].resolve()),
            }
        )
        completed = subprocess.run(
            [
                str(test_python),
                "-m",
                "pytest",
                "-c",
                "/dev/null",
                str(staged_artifact_contract_test),
                "-q",
                "-s",
            ],
            cwd=run_root,
            env=environment,
            check=False,
        )
        return completed.returncode


def _parser() -> argparse.ArgumentParser:
    """Create the manual validation command-line parser."""
    parser = argparse.ArgumentParser(
        description=(
            "Validate the bounded strict artifact lifecycle using a clean "
            "installed wheel on macOS arm64 or Linux x86_64."
        )
    )
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="check the host, Cargo, Xcode/sandbox-exec or bubblewrap without building",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the requested preflight or complete manual validation."""
    arguments = _parser().parse_args(argv)
    try:
        if arguments.preflight_only:
            target = preflight()
            print(f"Strict artifact manual host preflight passed: {target}")
            return 0
        return run_validation()
    except PreflightError as exc:
        print(f"Strict artifact host validation unavailable: {exc}", file=sys.stderr)
        return 2
    except subprocess.CalledProcessError as exc:
        return exc.returncode or 1


if __name__ == "__main__":
    raise SystemExit(main())
