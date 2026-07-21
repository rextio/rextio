"""Installed-wheel, real-Cargo Full C6 lifecycle test.

The expensive body intentionally runs in a second process whose working
directory is outside the checkout.  That prevents pytest's repository config
(``pythonpath = ["src"]``) from making the checkout look like an installed
Rextio distribution and defeating the Full C6 RECORD/editable-install gate.
"""

from __future__ import annotations

import errno
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from types import ModuleType

import pytest

from rextio.build.toolchain_support_lock import ToolchainSupportLockError


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


def test_support_lock_diagnostic_exposes_only_bounded_static_causes() -> None:
    harness = _load_harness_module()
    operating_system_error = NotADirectoryError(
        errno.ENOTDIR,
        "private detail",
        "/private/secret/toolchain/member",
    )
    support_error = ToolchainSupportLockError(
        "toolchain support locator requires a symlink-free directory walk"
    )
    support_error.__cause__ = operating_system_error
    outer_error = RuntimeError("outer private detail")
    outer_error.__cause__ = support_error

    diagnostic = harness._format_support_lock_diagnostic(outer_error)

    assert diagnostic == (
        "[full-c6-e2e] support-lock diagnostic: "
        "ToolchainSupportLockError=toolchain support locator requires a "
        "symlink-free directory walk; OSError=NotADirectoryError; errno=20"
    )
    assert "/private/secret" not in diagnostic
    assert "private detail" not in diagnostic
    assert len(diagnostic.encode("utf-8")) <= 512


def test_support_lock_diagnostic_preserves_bounded_hardlink_fields() -> None:
    harness = _load_harness_module()
    path_sha256 = "a" * 64
    support_message = (
        "toolchain support regular tree member is a shared hardlink "
        "(logical_role=linux-gcc-support, "
        f"relative_path_sha256={path_sha256}, "
        "st_nlink=2, in_root_inode_observation_count=1)"
    )

    diagnostic = harness._format_support_lock_diagnostic(
        ToolchainSupportLockError(support_message)
    )

    assert diagnostic == (
        "[full-c6-e2e] support-lock diagnostic: "
        f"ToolchainSupportLockError={support_message}; "
        "OSError=<unavailable>; errno=<unavailable>"
    )


@pytest.mark.parametrize(
    "raw_path",
    [
        "/private/secret/toolchain/member",
        r"C:\private\secret\toolchain\member",
    ],
)
def test_support_lock_diagnostic_rejects_raw_path_fields(raw_path: str) -> None:
    harness = _load_harness_module()
    support_message = (
        "toolchain support regular tree member is a shared hardlink "
        "(logical_role=linux-gcc-support, "
        f"relative_path={raw_path}, "
        "st_nlink=2, in_root_inode_observation_count=1)"
    )

    diagnostic = harness._format_support_lock_diagnostic(
        ToolchainSupportLockError(support_message)
    )

    assert diagnostic == (
        "[full-c6-e2e] support-lock diagnostic: "
        "ToolchainSupportLockError=<unavailable>; "
        "OSError=<unavailable>; errno=<unavailable>"
    )
    assert raw_path not in diagnostic
    assert "private" not in diagnostic


def test_support_lock_diagnostic_rerun_is_generation_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _load_harness_module()
    from rextio.build import full_c6_toolchain_support as support

    inherited_environment = {"PATH": "/fixed/toolchain/bin"}
    config = object()
    plan = object()
    observed: dict[str, object] = {}

    def load_config(
        project_root: Path,
        *,
        output: str,
        inherited_environment: dict[str, str],
    ) -> tuple[object, None]:
        observed["load"] = (project_root, output, inherited_environment)
        return config, None

    def discover_plan(
        *,
        project_root: Path,
        config: object,
        inherited_environment: dict[str, str],
    ) -> object:
        observed["discover"] = (
            project_root,
            config,
            inherited_environment,
        )
        return plan

    def generate_lock(candidate: object) -> None:
        observed["generate"] = candidate
        os_error = NotADirectoryError(
            errno.ENOTDIR,
            "private detail",
            "/private/secret/toolchain/member",
        )
        support_error = ToolchainSupportLockError(
            "toolchain support locator requires a symlink-free directory walk"
        )
        support_error.__cause__ = os_error
        raise support_error

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("diagnostic attempted output materialization")

    monkeypatch.setattr(support, "_load_full_c6_support_bootstrap_config", load_config)
    monkeypatch.setattr(support, "_discover_full_c6_bootstrap_plan", discover_plan)
    monkeypatch.setattr(support, "generate_full_c6_toolchain_support_lock", generate_lock)
    monkeypatch.setattr(support, "materialize_full_c6_toolchain_support_lock", forbidden)
    monkeypatch.setattr(support, "bootstrap_full_c6_toolchain_support_lock", forbidden)

    diagnostic = harness._diagnose_support_lock_generation(
        tmp_path,
        inherited_environment=inherited_environment,
    )

    assert diagnostic.endswith(
        "ToolchainSupportLockError=toolchain support locator requires a "
        "symlink-free directory walk; OSError=NotADirectoryError; errno=20"
    )
    assert observed == {
        "load": (tmp_path, harness._SUPPORT_LOCK_OUTPUT, inherited_environment),
        "discover": (tmp_path, config, inherited_environment),
        "generate": plan,
    }
    assert list(tmp_path.iterdir()) == []


def test_fresh_rextio_failure_runs_requested_support_lock_diagnostic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    harness = _load_harness_module()
    observed: list[tuple[Path, dict[str, str]]] = []

    def diagnose(
        project: Path,
        *,
        inherited_environment: dict[str, str],
    ) -> str:
        observed.append((project, inherited_environment))
        return "[full-c6-e2e] support-lock diagnostic: bounded-test-cause"

    monkeypatch.setattr(harness, "_diagnose_support_lock_generation", diagnose)

    with pytest.raises(AssertionError, match="bootstrap-support-lock failed with 7"):
        harness._run_fresh_rextio(
            [sys.executable, "-c", "raise SystemExit(7)"],
            cwd=tmp_path,
            stage="policy/bootstrap-support-lock",
            timeout=10,
            expect_two_cargo_builds=False,
            support_lock_diagnostic_project=tmp_path,
        )

    assert len(observed) == 1
    assert observed[0][0] == tmp_path
    assert observed[0][1]["PYTHONNOUSERSITE"] == "1"
    captured = capsys.readouterr()
    assert captured.err == (
        "[full-c6-e2e] support-lock diagnostic: bounded-test-cause\n"
    )


def test_fresh_rextio_success_does_not_run_support_lock_diagnostic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _load_harness_module()

    def forbidden(*_args: object, **_kwargs: object) -> str:
        raise AssertionError("success path ran failure-only diagnostic")

    monkeypatch.setattr(
        harness,
        "_diagnose_support_lock_generation",
        forbidden,
    )

    stdout, stderr, cargo_pids = harness._run_fresh_rextio(
        [sys.executable, "-c", "raise SystemExit(0)"],
        cwd=tmp_path,
        stage="policy/bootstrap-support-lock",
        timeout=10,
        expect_two_cargo_builds=False,
        support_lock_diagnostic_project=tmp_path,
    )

    assert (stdout, stderr, cargo_pids) == ("", "", ())


def test_support_lock_diagnostic_failure_preserves_original_child_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    harness = _load_harness_module()

    def fail_diagnostic(*_args: object, **_kwargs: object) -> str:
        raise RuntimeError("private diagnostic failure")

    monkeypatch.setattr(
        harness,
        "_diagnose_support_lock_generation",
        fail_diagnostic,
    )

    with pytest.raises(AssertionError, match="bootstrap-support-lock failed with 9"):
        harness._run_fresh_rextio(
            [sys.executable, "-c", "raise SystemExit(9)"],
            cwd=tmp_path,
            stage="policy/bootstrap-support-lock",
            timeout=10,
            expect_two_cargo_builds=False,
            support_lock_diagnostic_project=tmp_path,
        )

    captured = capsys.readouterr()
    assert captured.err == (
        "[full-c6-e2e] support-lock diagnostic: unavailable\n"
    )
    assert "private diagnostic failure" not in captured.out + captured.err


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
