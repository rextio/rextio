"""Installed-wheel, real-Cargo Full C6 lifecycle test.

The expensive body intentionally runs in a second process whose working
directory is outside the checkout.  That prevents pytest's repository config
(``pythonpath = ["src"]``) from making the checkout look like an installed
Rextio distribution and defeating the Full C6 RECORD/editable-install gate.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from types import ModuleType

import pytest


full_c6_e2e_only = pytest.mark.skipif(
    os.environ.get("REXTIO_FULL_C6_E2E") != "1",
    reason="dedicated installed-wheel Full C6 CI lane only",
)


def _process_group_is_alive(process_group_id: int) -> bool:
    completed = subprocess.run(
        ["ps", "-axo", "pgid=,stat="],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"could not inspect process group {process_group_id}: {completed.stderr}"
        )
    for line in completed.stdout.splitlines():
        fields = line.strip().split(maxsplit=1)
        if len(fields) != 2:
            continue
        try:
            observed_group = int(fields[0])
        except ValueError:
            continue
        if observed_group == process_group_id and not fields[1].startswith("Z"):
            return True
    return False


def _terminate_process_group(
    process: subprocess.Popen[bytes],
    *,
    stage: str,
    grace_seconds: float = 5.0,
) -> None:
    process_group_id = process.pid
    try:
        os.killpg(process_group_id, signal.SIGTERM)
    except (PermissionError, ProcessLookupError):
        pass
    try:
        process.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        pass
    if _process_group_is_alive(process_group_id):
        try:
            os.killpg(process_group_id, signal.SIGKILL)
        except (PermissionError, ProcessLookupError):
            pass
    try:
        process.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired as exc:
        raise AssertionError(f"{stage} root process did not exit after SIGKILL") from exc
    deadline = time.monotonic() + grace_seconds
    while _process_group_is_alive(process_group_id) and time.monotonic() < deadline:
        time.sleep(0.05)
    if _process_group_is_alive(process_group_id):
        raise AssertionError(f"{stage} left process group {process_group_id} alive")


def _run_contained_process(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: float,
) -> int:
    if os.name != "posix":
        raise AssertionError("Full C6 process containment requires a POSIX host")
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        start_new_session=True,
    )
    started = time.monotonic()
    try:
        while process.poll() is None:
            if time.monotonic() >= started + timeout_seconds:
                raise TimeoutError(
                    f"Full C6 harness exceeded its {timeout_seconds}-second timeout"
                )
            time.sleep(0.05)
        process.wait(timeout=10)
        if _process_group_is_alive(process.pid):
            raise AssertionError(
                "Full C6 harness root exited while its process group remained alive"
            )
    except BaseException as exc:
        try:
            _terminate_process_group(process, stage="Full C6 harness")
        except BaseException as cleanup_exc:
            raise AssertionError(
                "Full C6 harness failed and its process group could not be contained"
            ) from cleanup_exc
        raise exc
    if process.returncode is None:
        raise AssertionError("Full C6 harness did not produce a return code")
    return process.returncode


def _assert_run_root_isolated(*, run_root: Path, harness: Path) -> None:
    roots = {"checkout": harness.parents[2].resolve()}
    github_workspace = os.environ.get("GITHUB_WORKSPACE")
    if github_workspace:
        roots["GITHUB_WORKSPACE"] = Path(github_workspace).resolve()
    for label, root in roots.items():
        if run_root == root or run_root.is_relative_to(root):
            raise AssertionError(
                f"Full C6 run root must remain outside {label}: {run_root}"
            )


def _load_harness_module() -> ModuleType:
    path = Path(__file__).with_name("full_c6_real_harness.py").resolve()
    spec = importlib.util.spec_from_file_location("rextio_full_c6_real_harness", path)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load the Full C6 harness helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@full_c6_e2e_only
def test_installed_wheel_full_c6_cli_publishes_importable_native_wheel(
    tmp_path: Path,
) -> None:
    harness = Path(__file__).with_name("full_c6_real_harness.py").resolve()
    run_root = (tmp_path / "outside-checkout").resolve()
    run_root.mkdir(mode=0o700)
    _assert_run_root_isolated(run_root=run_root, harness=harness)
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {"PYTHONHOME", "PYTHONPATH", "VIRTUAL_ENV"}
    }
    environment["REXTIO_FULL_C6_E2E_CHILD"] = "1"
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    # Inherit the harness streams so flushed stage heartbeats remain visible.
    # A separate POSIX session still lets timeout/error handling contain every
    # descendant, including either of a lifecycle stage's Cargo processes.
    returncode = _run_contained_process(
        [sys.executable, str(harness), str(run_root)],
        cwd=run_root,
        env=environment,
        # Leave ten minutes of the 90-minute job budget for checkout, wheel
        # construction, environment setup, and failure reporting.
        timeout_seconds=4_800,
    )
    assert returncode == 0, "Full C6 installed-wheel harness failed"


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group contract")
def test_contained_process_timeout_kills_the_complete_group(tmp_path: Path) -> None:
    command = [
        sys.executable,
        "-c",
        (
            "import subprocess, sys, time; "
            "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
            "time.sleep(60)"
        ),
    ]
    with pytest.raises(TimeoutError, match="Full C6 harness exceeded"):
        _run_contained_process(
            command,
            cwd=tmp_path,
            env=dict(os.environ),
            timeout_seconds=0.5,
        )


@pytest.mark.parametrize("cargo_pids", [{101}, {101, 102, 103}])
def test_exact_two_cargo_pid_policy_rejects_other_counts(
    cargo_pids: set[int],
) -> None:
    harness = _load_harness_module()
    with pytest.raises(AssertionError, match="exactly two distinct Cargo"):
        harness._assert_exact_two_cargo_pids("build/test", cargo_pids)


def test_exact_two_cargo_pid_policy_accepts_two_distinct_pids() -> None:
    harness = _load_harness_module()
    harness._assert_exact_two_cargo_pids("build/test", {101, 102})


def _sandbox_invocation(
    ordinal: int,
    *,
    plan_sha256: str = "b" * 64,
    profile_sha256: str,
) -> dict[str, object]:
    return {
        "ordinal": ordinal,
        "argv_sha256": "a" * 64,
        "argv_count": 8,
        "environment": [
            {
                "name": "PATH",
                "value_sha256": "c" * 64,
                "value_size": 32,
            }
        ],
        "timeout_seconds": 900.0,
        "max_output_bytes": 1_048_576,
        "inherit_env": False,
        "sandbox_engine": "macos-sandbox-exec-v1",
        "sandbox_plan_sha256": plan_sha256,
        "sandbox_profile_sha256": profile_sha256,
        "sandbox_seccomp_sha256": None,
    }


def test_executor_projection_accepts_stable_semantic_sandbox_profile(
    tmp_path: Path,
) -> None:
    harness = _load_harness_module()
    harness._assert_executor_invocations(
        tmp_path,
        target="aarch64-apple-darwin",
        value=[
            _sandbox_invocation(1, profile_sha256="d" * 64),
            _sandbox_invocation(2, profile_sha256="d" * 64),
        ],
    )


def test_executor_projection_rejects_different_semantic_sandbox_profiles(
    tmp_path: Path,
) -> None:
    harness = _load_harness_module()
    with pytest.raises(AssertionError, match="sandbox contracts differ"):
        harness._assert_executor_invocations(
            tmp_path,
            target="aarch64-apple-darwin",
            value=[
                _sandbox_invocation(1, profile_sha256="d" * 64),
                _sandbox_invocation(2, profile_sha256="e" * 64),
            ],
        )


def test_executor_projection_rejects_different_semantic_sandbox_plans(
    tmp_path: Path,
) -> None:
    harness = _load_harness_module()
    with pytest.raises(AssertionError, match="sandbox contracts differ"):
        harness._assert_executor_invocations(
            tmp_path,
            target="aarch64-apple-darwin",
            value=[
                _sandbox_invocation(1, profile_sha256="d" * 64),
                _sandbox_invocation(
                    2,
                    plan_sha256="f" * 64,
                    profile_sha256="d" * 64,
                ),
            ],
        )
