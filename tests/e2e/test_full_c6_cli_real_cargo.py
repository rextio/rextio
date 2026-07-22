"""Installed-wheel, real-Cargo Full C6 lifecycle test.

The expensive body intentionally runs in a second process whose working
directory is outside the checkout.  That prevents pytest's repository config
(``pythonpath = ["src"]``) from making the checkout look like an installed
Rextio distribution and defeating the Full C6 RECORD/editable-install gate.
"""

from __future__ import annotations

import errno
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import signal
import subprocess
import sys
import time
from types import ModuleType

import pytest

from rextio.build.full_c6_linux_launcher import (
    FULL_C6_LINUX_LAUNCHER_FAILURE_STAGES,
)
from rextio.build.full_c6_toolchain_support import FullC6ToolchainSupportError
from rextio.build.toolchain_support_lock import ToolchainSupportLockError


full_c6_e2e_only = pytest.mark.skipif(
    os.environ.get("REXTIO_FULL_C6_E2E") != "1",
    reason="manual installed-wheel Full C6 host validation only",
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


def _full_c6_failure_report(
    *,
    reason_code: str = "linux-launcher-exit-125",
    **extra: object,
) -> dict[str, object]:
    return {
        "distribution_authorized": False,
        "error": {
            "code": "RXT060",
            "domain": "FullC6ProductionError",
            "message": "RXT060 strict Full C6 production-authority failed closed.",
            "reason_code": reason_code,
        },
        "lifecycle": "failed",
        "stage": "production-authority",
        "status": "full-c6-required-failed",
        **extra,
    }


def _failure_report_path(project: Path) -> Path:
    path = project / ".rextio" / "reports" / "build.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _emit_failure_report_line(
    project: Path,
    capsys: pytest.CaptureFixture[str],
) -> str:
    harness = _load_harness_module()
    harness._emit_full_c6_build_failure_report(project)
    captured = capsys.readouterr()
    assert captured.out == ""
    return captured.err


def test_build_failure_report_diagnostic_emits_only_allowlisted_scalars(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = _failure_report_path(tmp_path)
    path.write_text(json.dumps(_full_c6_failure_report()), encoding="utf-8")

    line = _emit_failure_report_line(tmp_path, capsys)

    assert line == (
        '{"distribution_authorized":false,"error_code":"RXT060",'
        '"error_domain":"FullC6ProductionError",'
        '"event":"full-c6-build-failure-report","lifecycle":"failed",'
        '"reason_code":"linux-launcher-exit-125",'
        '"stage":"production-authority",'
        '"status":"full-c6-required-failed"}\n'
    )


@pytest.mark.parametrize(
    "reason_code",
    tuple(
        f"linux-launcher-{stage}"
        for stage in FULL_C6_LINUX_LAUNCHER_FAILURE_STAGES
    ),
)
def test_build_failure_report_diagnostic_allows_static_launcher_stage(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    reason_code: str,
) -> None:
    path = _failure_report_path(tmp_path)
    path.write_text(
        json.dumps(_full_c6_failure_report(reason_code=reason_code)),
        encoding="utf-8",
    )

    line = _emit_failure_report_line(tmp_path, capsys)

    assert f'"reason_code":"{reason_code}"' in line
    assert "unavailable" not in line


@pytest.mark.parametrize(
    "reason_code",
    (
        "native-linux-permission-dev-root",
        "native-linux-permission-diagnostic-overflow",
        "native-linux-permission-dynamic-loader",
        "native-linux-permission-gcc-lto-plugin",
        "native-linux-permission-jobserver-creation",
        "native-linux-permission-lib64-root",
        "native-linux-permission-network-connect",
        "native-linux-permission-pipe-creation",
        "native-linux-permission-proc-root",
        "native-linux-permission-process-spawn",
        "native-linux-permission-python-root",
        "native-linux-permission-rextio-root",
        "native-linux-permission-socket-creation",
        "native-linux-permission-support-root",
        "native-linux-permission-tmp-root",
        "native-linux-permission-toolchain-root",
        "native-linux-permission-unclassified-no-known-operation",
    ),
)
def test_build_failure_report_diagnostic_allows_static_linux_permission(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    reason_code: str,
) -> None:
    path = _failure_report_path(tmp_path)
    path.write_text(
        json.dumps(_full_c6_failure_report(reason_code=reason_code)),
        encoding="utf-8",
    )

    line = _emit_failure_report_line(tmp_path, capsys)

    assert f'"reason_code":"{reason_code}"' in line
    assert "unavailable" not in line


def test_build_failure_report_diagnostic_is_fixed_when_report_is_missing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert _emit_failure_report_line(tmp_path, capsys) == (
        '{"event":"full-c6-build-failure-report-unavailable"}\n'
    )


def test_build_failure_report_diagnostic_rejects_unknown_reason_code(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _failure_report_path(tmp_path).write_text(
        json.dumps(_full_c6_failure_report(reason_code="private/path/detail")),
        encoding="utf-8",
    )

    line = _emit_failure_report_line(tmp_path, capsys)

    assert line == '{"event":"full-c6-build-failure-report-unavailable"}\n'
    assert "private" not in line


def test_build_failure_report_diagnostic_rejects_symlink(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    private = tmp_path / "private-report.json"
    private.write_text(
        json.dumps(_full_c6_failure_report(private="do-not-leak")),
        encoding="utf-8",
    )
    _failure_report_path(tmp_path).symlink_to(private)

    line = _emit_failure_report_line(tmp_path, capsys)

    assert line == '{"event":"full-c6-build-failure-report-unavailable"}\n'
    assert "do-not-leak" not in line


def test_build_failure_report_diagnostic_rejects_oversized_file(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    harness = _load_harness_module()
    _failure_report_path(tmp_path).write_bytes(
        b"x" * (harness._FULL_C6_BUILD_FAILURE_REPORT_MAX_BYTES + 1)
    )

    assert _emit_failure_report_line(tmp_path, capsys) == (
        '{"event":"full-c6-build-failure-report-unavailable"}\n'
    )


@pytest.mark.parametrize("payload", (b"{malformed", b'"not-an-object"', b"\xff"))
def test_build_failure_report_diagnostic_rejects_malformed_payload(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    payload: bytes,
) -> None:
    _failure_report_path(tmp_path).write_bytes(payload)

    assert _emit_failure_report_line(tmp_path, capsys) == (
        '{"event":"full-c6-build-failure-report-unavailable"}\n'
    )


def test_build_failure_report_diagnostic_does_not_leak_untrusted_nested_data(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    report = _full_c6_failure_report(
        analysis={
            "project_root": "/private/project",
            "diagnostics": [{"message": "nested-secret"}],
        },
        config={"token": "credential-secret"},
    )
    error = report["error"]
    assert type(error) is dict
    error["message"] = "private-error-secret"
    error["details"] = {"path": "/private/project/source.py"}
    _failure_report_path(tmp_path).write_text(json.dumps(report), encoding="utf-8")

    line = _emit_failure_report_line(tmp_path, capsys)

    assert '"event":"full-c6-build-failure-report"' in line
    for secret in (
        "/private/project",
        "nested-secret",
        "credential-secret",
        "private-error-secret",
    ):
        assert secret not in line


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
        "symlink-free directory walk; OSError=NotADirectoryError; errno=20; "
        "OtherErrorType=RuntimeError; OtherErrorMessage=<unavailable>"
    )
    assert "/private/secret" not in diagnostic
    assert "private detail" not in diagnostic
    assert len(diagnostic.encode("utf-8")) <= 512


def test_support_lock_diagnostic_preserves_contextual_mode_over_generic_context() -> None:
    harness = _load_harness_module()
    generic_message = "toolchain support permission mode is invalid"
    path_sha256 = "a" * 64
    contextual_message = (
        f"{generic_message} "
        "(origin=tree-member-receipt, "
        "target_triple=x86_64-unknown-linux-gnu, "
        "logical_role=linux-runtime-support, kind=regular, "
        f"relative_path_sha256={path_sha256}, mode=4755)"
    )
    generic_error = ToolchainSupportLockError(generic_message)
    contextual_error = ToolchainSupportLockError(contextual_message)
    contextual_error.__context__ = generic_error
    contextual_error.__suppress_context__ = True

    diagnostic = harness._format_support_lock_diagnostic(contextual_error)

    assert diagnostic == (
        "[full-c6-e2e] support-lock diagnostic: "
        f"ToolchainSupportLockError={contextual_message}; "
        "OSError=<unavailable>; errno=<unavailable>; "
        "OtherErrorType=<unavailable>; OtherErrorMessage=<unavailable>"
    )
    assert len(contextual_message) <= 278
    assert len(diagnostic.encode("utf-8")) <= 512


def test_support_lock_diagnostic_preserves_standalone_generic_mode_cause() -> None:
    harness = _load_harness_module()
    generic_message = "toolchain support permission mode is invalid"

    diagnostic = harness._format_support_lock_diagnostic(
        ToolchainSupportLockError(generic_message)
    )

    assert diagnostic == (
        "[full-c6-e2e] support-lock diagnostic: "
        f"ToolchainSupportLockError={generic_message}; "
        "OSError=<unavailable>; errno=<unavailable>; "
        "OtherErrorType=<unavailable>; OtherErrorMessage=<unavailable>"
    )


def test_support_lock_diagnostic_preserves_bounded_hardlink_fields() -> None:
    harness = _load_harness_module()
    path_sha256 = "a" * 64
    support_message = (
        "toolchain support regular tree member is a shared hardlink "
        "(logical_role=linux-gcc-support, "
        f"relative_path_sha256={path_sha256}, "
        "st_uid=1001, "
        "st_gid=127, "
        "st_mode=33188, "
        "st_nlink=2, in_root_inode_observation_count=1)"
    )
    assert 240 < len(support_message) <= 278

    diagnostic = harness._format_support_lock_diagnostic(
        ToolchainSupportLockError(support_message)
    )

    assert diagnostic == (
        "[full-c6-e2e] support-lock diagnostic: "
        f"ToolchainSupportLockError={support_message}; "
        "OSError=<unavailable>; errno=<unavailable>; "
        "OtherErrorType=<unavailable>; OtherErrorMessage=<unavailable>"
    )
    assert len(diagnostic.encode("utf-8")) <= 512


def test_support_lock_diagnostic_worst_case_stays_within_wire_bound() -> None:
    harness = _load_harness_module()
    operating_system_error_type = type(
        "O" * 64,
        (OSError,),
        {"__module__": "builtins"},
    )
    other_error_type = type(
        "E" * 32,
        (Exception,),
        {"__module__": "builtins"},
    )
    operating_system_error = operating_system_error_type(-4096, "private detail")
    support_message = "toolchain support " + "a" * (278 - len("toolchain support "))
    support_error = ToolchainSupportLockError(support_message)
    support_error.__cause__ = operating_system_error
    outer_error = other_error_type("outer private detail")
    outer_error.__cause__ = support_error

    diagnostic = harness._format_support_lock_diagnostic(outer_error)

    assert len(support_message) == 278
    assert diagnostic.endswith("OtherErrorMessage=<unavailable>")
    assert f"OtherErrorType={'E' * 32}" in diagnostic
    assert len(diagnostic.encode("utf-8")) == 512
    assert len(diagnostic.encode("utf-8")) <= 512


def test_support_lock_diagnostic_classifies_non_support_error_without_message() -> None:
    harness = _load_harness_module()

    diagnostic = harness._format_support_lock_diagnostic(
        ValueError("private non-support detail")
    )

    assert diagnostic == (
        "[full-c6-e2e] support-lock diagnostic: "
        "ToolchainSupportLockError=<unavailable>; "
        "OSError=<unavailable>; errno=<unavailable>; "
        "OtherErrorType=ValueError; OtherErrorMessage=<unavailable>"
    )
    assert "private non-support detail" not in diagnostic


def test_support_lock_diagnostic_exposes_bounded_full_c6_static_message() -> None:
    harness = _load_harness_module()
    message = "Full C6 Linux runtime support mapping is invalid"

    diagnostic = harness._format_support_lock_diagnostic(
        FullC6ToolchainSupportError(message)
    )

    assert diagnostic == (
        "[full-c6-e2e] support-lock diagnostic: "
        "ToolchainSupportLockError=<unavailable>; "
        "OSError=<unavailable>; errno=<unavailable>; "
        "OtherErrorType=FullC6ToolchainSupportError; "
        f"OtherErrorMessage={message}"
    )


def test_support_lock_diagnostic_message_worst_case_stays_within_wire_bound() -> None:
    harness = _load_harness_module()
    operating_system_error_type = type(
        "O" * 64,
        (OSError,),
        {"__module__": "builtins"},
    )
    other_error_type = type(
        "E" * 32,
        (Exception,),
        {"__module__": "builtins"},
    )
    operating_system_error = operating_system_error_type(-4096, "private detail")
    message = "Full C6 " + "a" * (278 - len("Full C6 "))
    full_c6_error = FullC6ToolchainSupportError(message)
    full_c6_error.__cause__ = operating_system_error
    outer_error = other_error_type("outer private detail")
    outer_error.__cause__ = full_c6_error

    diagnostic = harness._format_support_lock_diagnostic(outer_error)

    assert len(message) == 278
    assert diagnostic.endswith(f"OtherErrorMessage={message}")
    assert f"OtherErrorType={'E' * 32}" in diagnostic
    assert len(diagnostic.encode("utf-8")) == 512


def test_support_lock_diagnostic_prefers_support_message_to_full_c6_message() -> None:
    harness = _load_harness_module()
    support_message = "toolchain support root mapping is invalid"
    support_error = ToolchainSupportLockError(support_message)
    full_c6_error = FullC6ToolchainSupportError(
        "Full C6 support lock generation failed closed"
    )
    full_c6_error.__cause__ = support_error

    diagnostic = harness._format_support_lock_diagnostic(full_c6_error)

    assert f"ToolchainSupportLockError={support_message}" in diagnostic
    assert "OtherErrorType=FullC6ToolchainSupportError" in diagnostic
    assert diagnostic.endswith("OtherErrorMessage=<unavailable>")


def _xcode_hardlink_diagnostic_fixture(
    tmp_path: Path,
) -> tuple[Path, PurePosixPath, tuple[Path, Path, Path]]:
    boundary = tmp_path / "XcodeDefault.xctoolchain"
    relative_paths = tuple(
        PurePosixPath(value)
        for value in (
            "usr/lib/clang/21/include/__clang_cuda_builtin_vars.h",
            "usr/lib/tapi/21/include/__clang_cuda_builtin_vars.h",
            "usr/lib/swift/clang/include/__clang_cuda_builtin_vars.h",
        )
    )
    paths = tuple(boundary.joinpath(*value.parts) for value in relative_paths)
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)
    paths[0].write_bytes(b"fixed xcode hardlink diagnostic fixture")
    try:
        os.link(paths[0], paths[1])
        os.link(paths[0], paths[2])
    except OSError as exc:
        pytest.skip(f"hardlink creation unavailable: {exc}")
    return boundary, relative_paths[0], paths


def _xcode_hardlink_alias_message(
    harness: ModuleType,
    *,
    boundary: Path,
    target_relative_path: PurePosixPath,
) -> str:
    from rextio.build import toolchain_support_lock as support_lock

    target = boundary.joinpath(*target_relative_path.parts)
    observed = support_lock._stamp(target.stat())
    return harness._bounded_xcode_hardlink_alias_message(
        boundary=boundary,
        target_relative_path=target_relative_path,
        expected_stamp_sha256=support_lock._xcode_hardlink_full_stamp_sha256(
            observed
        ),
    )


def test_xcode_hardlink_alias_diagnostic_is_deterministic_bounded_and_opaque(
    tmp_path: Path,
) -> None:
    harness = _load_harness_module()
    boundary, target_relative_path, paths = _xcode_hardlink_diagnostic_fixture(
        tmp_path
    )
    (boundary / "ignored-symlink").symlink_to(paths[0])

    message = _xcode_hardlink_alias_message(
        harness,
        boundary=boundary,
        target_relative_path=target_relative_path,
    )
    repeated = _xcode_hardlink_alias_message(
        harness,
        boundary=boundary,
        target_relative_path=target_relative_path,
    )

    assert repeated == message
    assert message.isascii()
    assert len(message) == 277
    assert message.startswith(
        "toolchain support xcode hardlink aliases "
        "(scope=toolchain,nlink=3,count=3,digests="
    )
    assert message.endswith(")")
    digests = message.removesuffix(")").rsplit("digests=", 1)[1].split(",")
    assert len(digests) == 3
    assert digests == sorted(digests)
    expected_digests = sorted(
        harness._xcode_hardlink_diagnostic_sha256(
            "rextio.full-c6-xcode-hardlink-path-diagnostic.v1",
            {
                "root_relative_path": path.relative_to(boundary).as_posix(),
            },
        )
        for path in paths
    )
    assert digests == expected_digests
    for value in digests:
        assert len(value) == 64
        assert value == value.lower()
        assert all(character in "0123456789abcdef" for character in value)
    for path in paths:
        assert path.as_posix() not in message
        assert path.name not in message
    diagnostic = harness._format_support_lock_diagnostic(
        ToolchainSupportLockError(message)
    )
    assert f"ToolchainSupportLockError={message}" in diagnostic
    assert len(diagnostic.encode("ascii")) <= 512


def test_xcode_hardlink_alias_diagnostic_expands_to_fixed_app_scope(
    tmp_path: Path,
) -> None:
    harness = _load_harness_module()
    from rextio.build import toolchain_support_lock as support_lock

    app_boundary = tmp_path / "Xcode.app"
    boundary = (
        app_boundary
        / "Contents/Developer/Toolchains/XcodeDefault.xctoolchain"
    )
    target_relative = PurePosixPath(
        "usr/lib/clang/21/include/__clang_cuda_builtin_vars.h"
    )
    target = boundary.joinpath(*target_relative.parts)
    second = boundary / "usr/lib/tapi/21/include/__clang_cuda_builtin_vars.h"
    third = app_boundary / "Contents/Shared/usr/include/__clang_cuda_builtin_vars.h"
    for path in (target, second, third):
        path.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"fixed app-scope xcode hardlink fixture")
    try:
        os.link(target, second)
        os.link(target, third)
    except OSError as exc:
        pytest.skip(f"hardlink creation unavailable: {exc}")
    observed = support_lock._stamp(target.stat())
    expected_stamp_sha256 = support_lock._xcode_hardlink_full_stamp_sha256(
        observed
    )
    app_target_relative = PurePosixPath(
        *target.relative_to(app_boundary).parts
    )

    message = harness._bounded_xcode_hardlink_alias_message(
        boundary=boundary,
        target_relative_path=target_relative,
        expected_stamp_sha256=expected_stamp_sha256,
        app_boundary=app_boundary,
        app_target_relative_path=app_target_relative,
    )

    assert message.startswith(
        "toolchain support xcode hardlink aliases "
        "(scope=app,nlink=3,count=3,digests="
    )
    digests = message.removesuffix(")").rsplit("digests=", 1)[1].split(",")
    expected = sorted(
        harness._xcode_hardlink_diagnostic_sha256(
            "rextio.full-c6-xcode-hardlink-path-diagnostic.v1",
            {"root_relative_path": path.relative_to(app_boundary).as_posix()},
        )
        for path in (target, second, third)
    )
    assert digests == expected
    assert len(message) == 271
    assert str(app_boundary) not in message


@pytest.mark.parametrize(
    "changed_field",
    [
        "logical_role=other-role",
        "relative_path_sha256=" + "0" * 64,
        "st_nlink=2",
        "in_root_inode_observation_count=2",
    ],
)
def test_xcode_hardlink_alias_diagnostic_trigger_is_exact(changed_field: str) -> None:
    harness = _load_harness_module()
    exact = (
        "toolchain support xcode hardlink observation "
        f"(path={harness._XCODE_HARDLINK_RELATIVE_PATH_SHA256},"
        f"stamp={'a' * 64},nlink=3,count=1)"
    )
    assert harness._XCODE_HARDLINK_ERROR_RE.fullmatch(exact) is not None
    diagnostic = harness._format_support_lock_diagnostic(
        ToolchainSupportLockError(exact)
    )
    assert f"ToolchainSupportLockError={exact}" in diagnostic
    assert len(diagnostic.encode("ascii")) <= 512
    if changed_field.startswith("logical_role="):
        changed = exact.replace(
            "toolchain support xcode hardlink observation",
            f"toolchain support xcode hardlink observation {changed_field}",
        )
    elif changed_field.startswith("relative_path_sha256="):
        changed = exact.replace(
            f"path={harness._XCODE_HARDLINK_RELATIVE_PATH_SHA256}",
            changed_field.replace("relative_path_sha256", "path"),
        )
    elif changed_field.startswith("st_nlink="):
        changed = exact.replace("nlink=3", changed_field.replace("st_nlink", "nlink"))
    else:
        changed = exact.replace(
            "count=1",
            changed_field.replace("in_root_inode_observation_count", "count"),
        )
    assert harness._XCODE_HARDLINK_ERROR_RE.fullmatch(changed) is None


@pytest.mark.parametrize("mutation", ["remove", "add"])
def test_xcode_hardlink_alias_diagnostic_rejects_nonexact_alias_count(
    tmp_path: Path,
    mutation: str,
) -> None:
    harness = _load_harness_module()
    boundary, target_relative_path, paths = _xcode_hardlink_diagnostic_fixture(
        tmp_path
    )
    if mutation == "remove":
        paths[2].unlink()
    else:
        fourth = boundary / "usr/lib/extra/include/__clang_cuda_builtin_vars.h"
        fourth.parent.mkdir(parents=True)
        os.link(paths[0], fourth)

    with pytest.raises(ToolchainSupportLockError, match="target changed"):
        _xcode_hardlink_alias_message(
            harness,
            boundary=boundary,
            target_relative_path=target_relative_path,
        )


def test_xcode_hardlink_alias_diagnostic_fails_closed_on_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _load_harness_module()
    boundary, target_relative_path, paths = _xcode_hardlink_diagnostic_fixture(
        tmp_path
    )
    from rextio.build import toolchain_support_lock as support_lock

    original = support_lock._bounded_directory_names
    raced = False

    def race_after_target_capture(directory_fd: int) -> list[str]:
        nonlocal raced
        names = original(directory_fd)
        if not raced:
            raced = True
            paths[2].unlink()
            paths[2].write_bytes(b"replacement")
        return names

    monkeypatch.setattr(
        support_lock,
        "_bounded_directory_names",
        race_after_target_capture,
    )

    with pytest.raises(ToolchainSupportLockError, match="changed"):
        _xcode_hardlink_alias_message(
            harness,
            boundary=boundary,
            target_relative_path=target_relative_path,
        )


def test_xcode_hardlink_alias_diagnostic_rejects_target_replacement_after_error(
    tmp_path: Path,
) -> None:
    harness = _load_harness_module()
    boundary, target_relative_path, paths = _xcode_hardlink_diagnostic_fixture(
        tmp_path
    )
    from rextio.build import toolchain_support_lock as support_lock

    observed = support_lock._stamp(paths[0].stat())
    expected_stamp_sha256 = support_lock._xcode_hardlink_full_stamp_sha256(
        observed
    )
    paths[0].unlink()
    paths[0].write_bytes(b"replacement after production observation")

    with pytest.raises(ToolchainSupportLockError, match="target changed"):
        harness._bounded_xcode_hardlink_alias_message(
            boundary=boundary,
            target_relative_path=target_relative_path,
            expected_stamp_sha256=expected_stamp_sha256,
        )


def test_xcode_hardlink_alias_diagnostic_rechecks_completed_second_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _load_harness_module()
    boundary, target_relative_path, paths = _xcode_hardlink_diagnostic_fixture(
        tmp_path
    )
    from rextio.build import toolchain_support_lock as support_lock

    observed = support_lock._stamp(paths[0].stat())
    expected_stamp_sha256 = support_lock._xcode_hardlink_full_stamp_sha256(
        observed
    )
    original = harness._open_xcode_hardlink_target
    target_open_count = 0

    def mutate_after_second_scan(**kwargs: object) -> object:
        nonlocal target_open_count
        target_open_count += 1
        if target_open_count == 3:
            paths[2].unlink()
            paths[2].write_bytes(b"replacement after completed second scan")
        return original(**kwargs)

    monkeypatch.setattr(
        harness,
        "_open_xcode_hardlink_target",
        mutate_after_second_scan,
    )

    with pytest.raises(ToolchainSupportLockError, match="target changed"):
        harness._bounded_xcode_hardlink_alias_message(
            boundary=boundary,
            target_relative_path=target_relative_path,
            expected_stamp_sha256=expected_stamp_sha256,
        )
    assert target_open_count == 3


@pytest.mark.parametrize(
    ("constant", "value", "match"),
    [
        ("_XCODE_HARDLINK_MAX_ENTRIES", 1, "entry bound"),
        ("_XCODE_HARDLINK_MAX_DEPTH", 2, "path bound"),
    ],
)
def test_xcode_hardlink_alias_diagnostic_enforces_scan_bounds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    constant: str,
    value: int,
    match: str,
) -> None:
    harness = _load_harness_module()
    boundary, target_relative_path, _paths = _xcode_hardlink_diagnostic_fixture(
        tmp_path
    )
    monkeypatch.setattr(harness, constant, value)

    with pytest.raises(ToolchainSupportLockError, match=match):
        _xcode_hardlink_alias_message(
            harness,
            boundary=boundary,
            target_relative_path=target_relative_path,
        )


def _xcode_hardlink_topology_fixture(
    tmp_path: Path,
) -> tuple[Path, Path, tuple[Path, ...]]:
    app_boundary = tmp_path / "secret-Xcode.app"
    support_root = (
        app_boundary
        / "Contents/Developer/Toolchains/XcodeDefault.xctoolchain"
        / "usr/lib/clang/21"
    )
    first_group = (
        support_root / "include/secret-first-member.h",
        support_root / "share/secret-first-copy.h",
        app_boundary / "Contents/Shared/secret-first-third.h",
    )
    second_group = (
        support_root / "lib/secret-second-member.a",
        app_boundary / "Contents/Other/secret-second-copy.a",
    )
    paths = (*first_group, *second_group)
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)
    first_group[0].write_bytes(b"first opaque hardlink topology group")
    second_group[0].write_bytes(b"second opaque hardlink topology group")
    try:
        for path in first_group[1:]:
            os.link(first_group[0], path)
        os.link(second_group[0], second_group[1])
        (support_root / "secret-file-symlink").symlink_to(first_group[0])
        (support_root / "secret-directory-symlink").symlink_to(
            first_group[0].parent,
            target_is_directory=True,
        )
    except OSError as exc:
        pytest.skip(f"hardlink or symlink creation unavailable: {exc}")
    return support_root, app_boundary, paths


def test_xcode_hardlink_topology_is_deterministic_opaque_and_nofollow(
    tmp_path: Path,
) -> None:
    harness = _load_harness_module()
    support_root, app_boundary, paths = _xcode_hardlink_topology_fixture(
        tmp_path
    )

    topology = harness._bounded_xcode_hardlink_topology_message(
        support_root=support_root,
        app_boundary=app_boundary,
        structured=True,
    )
    assert type(topology) is harness._XcodeHardlinkTopology
    message = harness._format_xcode_hardlink_topology_message(topology)
    repeated = harness._bounded_xcode_hardlink_topology_message(
        support_root=support_root,
        app_boundary=app_boundary,
    )

    assert repeated == message
    assert topology.group_count == 2
    assert topology.support_member_count == 3
    assert topology.alias_count == 5
    assert len(topology.policy_merkle) == 64
    assert len(topology.observation_merkle) == 64
    assert message.startswith(
        "toolchain support xcode hardlink topology "
        "(groups=2,support_members=3,aliases=5,policy_merkle="
    )
    assert message.endswith(")")
    policy_merkle, observation_merkle = (
        message.removesuffix(")")
        .rsplit("policy_merkle=", 1)[1]
        .split(",observation_merkle=", 1)
    )
    for merkle in (policy_merkle, observation_merkle):
        assert len(merkle) == 64
        assert all(character in "0123456789abcdef" for character in merkle)
    assert message.isascii()
    assert len(message) <= 278
    assert str(app_boundary) not in message
    assert str(support_root) not in message
    for path in paths:
        assert path.name not in message
    assert "secret-file-symlink" not in message
    assert "secret-directory-symlink" not in message
    diagnostic = harness._format_support_lock_diagnostic(
        ToolchainSupportLockError(message)
    )
    assert f"ToolchainSupportLockError={message}" in diagnostic
    assert len(diagnostic.encode("ascii")) <= 512


def test_xcode_hardlink_topology_merkle_binds_group_stamp(
    tmp_path: Path,
) -> None:
    harness = _load_harness_module()
    support_root, app_boundary, paths = _xcode_hardlink_topology_fixture(
        tmp_path
    )
    before = harness._bounded_xcode_hardlink_topology_message(
        support_root=support_root,
        app_boundary=app_boundary,
    )

    with paths[0].open("ab") as stream:
        stream.write(b" changed")

    after = harness._bounded_xcode_hardlink_topology_message(
        support_root=support_root,
        app_boundary=app_boundary,
    )
    before_policy, before_observation = (
        before.removesuffix(")")
        .rsplit("policy_merkle=", 1)[1]
        .split(",observation_merkle=", 1)
    )
    after_policy, after_observation = (
        after.removesuffix(")")
        .rsplit("policy_merkle=", 1)[1]
        .split(",observation_merkle=", 1)
    )
    assert after_policy == before_policy
    assert after_observation != before_observation
    assert "groups=2,support_members=3,aliases=5" in after


@pytest.mark.parametrize(
    ("constant", "value", "match"),
    [
        ("_XCODE_HARDLINK_MAX_ENTRIES", 1, "entry bound"),
        ("_XCODE_HARDLINK_APP_MAX_ENTRIES", 1, "entry bound"),
        ("_XCODE_HARDLINK_MAX_DEPTH", 2, "path bound"),
        ("_XCODE_HARDLINK_MAX_PATH_BYTES", 10, "path bound"),
        ("_XCODE_HARDLINK_TOPOLOGY_MAX_GROUPS", 1, "group bound"),
        ("_XCODE_HARDLINK_TOPOLOGY_MAX_MEMBERS", 2, "alias bound"),
    ],
)
def test_xcode_hardlink_topology_enforces_bounds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    constant: str,
    value: int,
    match: str,
) -> None:
    harness = _load_harness_module()
    support_root, app_boundary, _paths = _xcode_hardlink_topology_fixture(
        tmp_path
    )
    monkeypatch.setattr(harness, constant, value)

    with pytest.raises(ToolchainSupportLockError, match=match):
        harness._bounded_xcode_hardlink_topology_message(
            support_root=support_root,
            app_boundary=app_boundary,
        )


def test_xcode_hardlink_topology_rejects_drift_after_scans(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _load_harness_module()
    support_root, app_boundary, paths = _xcode_hardlink_topology_fixture(
        tmp_path
    )
    original = harness._open_xcode_topology_regular
    mutated = False

    def mutate_before_final_stamp(**kwargs: object) -> None:
        nonlocal mutated
        if not mutated:
            mutated = True
            paths[2].unlink()
            paths[2].write_bytes(b"replacement after completed scans")
        original(**kwargs)

    monkeypatch.setattr(
        harness,
        "_open_xcode_topology_regular",
        mutate_before_final_stamp,
    )

    with pytest.raises(ToolchainSupportLockError, match="final stamp changed"):
        harness._bounded_xcode_hardlink_topology_message(
            support_root=support_root,
            app_boundary=app_boundary,
        )
    assert mutated


def test_xcode_hardlink_topology_rejects_drift_between_scans(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from rextio.build import toolchain_support_lock as support_lock

    harness = _load_harness_module()
    support_root, app_boundary, paths = _xcode_hardlink_topology_fixture(
        tmp_path
    )
    original = support_lock._open_directory_chain
    support_scan_count = 0

    def mutate_before_second_support_scan(path: Path) -> object:
        nonlocal support_scan_count
        if path == support_root:
            support_scan_count += 1
            if support_scan_count == 2:
                with paths[0].open("ab") as stream:
                    stream.write(b" changed between scans")
        return original(path)

    monkeypatch.setattr(
        support_lock,
        "_open_directory_chain",
        mutate_before_second_support_scan,
    )

    with pytest.raises(ToolchainSupportLockError, match="changed across scans"):
        harness._bounded_xcode_hardlink_topology_message(
            support_root=support_root,
            app_boundary=app_boundary,
        )
    assert support_scan_count == 2


def test_xcode_generic_hardlink_trigger_is_exact_and_wire_safe() -> None:
    harness = _load_harness_module()
    message = (
        "toolchain support regular tree member is a shared hardlink "
        "(logical_role=xcode-clang-resource, "
        f"relative_path_sha256={'b' * 64}, st_uid=0, st_gid=0, "
        "st_mode=33188, st_nlink=3, "
        "in_root_inode_observation_count=1)"
    )

    assert harness._XCODE_GENERIC_HARDLINK_ERROR_RE.fullmatch(message) is not None
    assert (
        harness._XCODE_GENERIC_HARDLINK_ERROR_RE.fullmatch(
            message.replace("xcode-clang-resource", "xcode-sdk")
        )
        is None
    )
    topology = (
        "toolchain support xcode hardlink topology "
        f"(groups=999,support_members=9999,aliases=9999,"
        f"policy_merkle={'e' * 64},observation_merkle={'f' * 64})"
    )
    diagnostic = harness._format_support_lock_diagnostic(
        ToolchainSupportLockError(topology)
    )
    assert f"ToolchainSupportLockError={topology}" in diagnostic
    assert len(diagnostic.encode("ascii")) <= 512


def _xcode_topology_diagnostic_plan(
    *,
    target: str = "aarch64-apple-darwin",
    role: str = "xcode-clang-resource",
    root: Path | None = None,
    duplicate_root: bool = False,
    manifest_role: str = "xcode-version-plist",
    manifest_path: Path = Path("/Applications/Xcode.app/Contents/version.plist"),
    duplicate_manifest: bool = False,
    omit_manifest: bool = False,
) -> object:
    from rextio.build import full_c6_toolchain_support as support

    class Locator:
        pass

    locator = Locator()
    locator.logical_role = role
    locator._absolute_path = root or Path(
        "/Applications/Xcode.app/Contents/Developer/Toolchains/"
        "XcodeDefault.xctoolchain/usr/lib/clang/21"
    )
    plan = object.__new__(support.FullC6ToolchainSupportPlan)
    object.__setattr__(plan, "_target_triple", target)
    object.__setattr__(
        plan,
        "_root_locators",
        (locator, locator) if duplicate_root else (locator,),
    )
    manifest = Locator()
    manifest.logical_role = manifest_role
    manifest._absolute_path = manifest_path
    object.__setattr__(
        plan,
        "_manifest_locators",
        ()
        if omit_manifest
        else ((manifest, manifest) if duplicate_manifest else (manifest,)),
    )
    return plan


def test_xcode_topology_diagnostic_accepts_only_exact_fixed_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _load_harness_module()
    plan = _xcode_topology_diagnostic_plan()
    error = ToolchainSupportLockError(
        "toolchain support regular tree member is a shared hardlink "
        "(logical_role=xcode-clang-resource, "
        f"relative_path_sha256={'b' * 64}, st_uid=0, st_gid=0, "
        "st_mode=33188, st_nlink=3, "
        "in_root_inode_observation_count=1)"
    )
    observed: list[tuple[Path, Path, bool]] = []
    captured: list[object] = []

    def topology(
        *,
        support_root: Path,
        app_boundary: Path,
        structured: bool = False,
    ) -> object:
        observed.append((support_root, app_boundary, structured))
        return harness._XcodeHardlinkTopology(
            group_count=121,
            support_member_count=121,
            alias_count=361,
            policy_merkle=harness._XCODE_HARDLINK_POLICY_MERKLE,
            observation_merkle="f" * 64,
        )

    class Receipt:
        raw_sha256 = "a" * 64

    def capture(locator: object) -> Receipt:
        captured.append(locator)
        return Receipt()

    monkeypatch.setattr(
        harness,
        "_bounded_xcode_hardlink_topology_message",
        topology,
    )
    monkeypatch.setattr(
        "rextio.build.toolchain_support_lock.capture_toolchain_support_file",
        capture,
    )

    message = harness._diagnose_xcode_hardlink_topology(plan, error)
    assert message == (
        "toolchain support xcode topology identity "
        "(groups=121,members=121,aliases=361,"
        f"policy={harness._XCODE_HARDLINK_POLICY_MERKLE},clang=21,"
        f"version_raw={'a' * 64})"
    )
    assert observed == [
        (
            Path(
                "/Applications/Xcode.app/Contents/Developer/Toolchains/"
                "XcodeDefault.xctoolchain/usr/lib/clang/21"
            ),
            Path("/Applications/Xcode.app"),
            True,
        )
    ]
    assert captured == [plan._manifest_locators[0]]
    assert message.isascii()
    assert len(message) <= 278
    assert "observation" not in message
    assert "/Applications" not in message


@pytest.mark.parametrize(
    "plan",
    [
        object(),
        _xcode_topology_diagnostic_plan(target="x86_64-unknown-linux-gnu"),
        _xcode_topology_diagnostic_plan(role="xcode-sdk"),
        _xcode_topology_diagnostic_plan(duplicate_root=True),
        _xcode_topology_diagnostic_plan(omit_manifest=True),
        _xcode_topology_diagnostic_plan(manifest_role="xcode-sdk-settings"),
        _xcode_topology_diagnostic_plan(duplicate_manifest=True),
        _xcode_topology_diagnostic_plan(
            manifest_path=Path("/private/secret/version.plist")
        ),
        _xcode_topology_diagnostic_plan(root=Path("/private/secret/clang/21")),
        _xcode_topology_diagnostic_plan(
            root=Path(
                "/Applications/Xcode.app/Contents/Developer/Toolchains/"
                "XcodeDefault.xctoolchain/usr/lib/clang/not-a-version"
            )
        ),
    ],
)
def test_xcode_topology_diagnostic_rejects_near_miss_plan(
    monkeypatch: pytest.MonkeyPatch,
    plan: object,
) -> None:
    harness = _load_harness_module()
    error = ToolchainSupportLockError(
        "toolchain support regular tree member is a shared hardlink "
        "(logical_role=xcode-clang-resource, "
        f"relative_path_sha256={'b' * 64}, st_uid=0, st_gid=0, "
        "st_mode=33188, st_nlink=3, "
        "in_root_inode_observation_count=1)"
    )

    def forbidden(**_kwargs: object) -> object:
        raise AssertionError("near-miss plan reached Xcode app scan")

    monkeypatch.setattr(
        harness,
        "_bounded_xcode_hardlink_topology_message",
        forbidden,
    )

    assert harness._diagnose_xcode_hardlink_topology(plan, error) is None


def _install_test_folded_alias(monkeypatch: pytest.MonkeyPatch) -> None:
    from rextio.build import toolchain_support_lock as support_lock

    original = support_lock._alias

    def alias(value: str) -> str:
        if value in {"collision-left", "collision-right"}:
            return "collision-key"
        return original(value)

    monkeypatch.setattr(support_lock, "_alias", alias)


def _linux_folded_name_group(directory: Path) -> tuple[str, str]:
    directory.mkdir(parents=True, exist_ok=True)
    names = ("collision-left", "collision-right")
    for name in names:
        (directory / name).write_bytes(name.encode("utf-8"))
    return names


def test_linux_folded_name_topology_is_deterministic_bounded_and_opaque(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _load_harness_module()
    _install_test_folded_alias(monkeypatch)
    root = tmp_path / "secret-linux-runtime-root"
    group_directory = root / "secret-collision-directory"
    names = _linux_folded_name_group(group_directory)

    message = harness._bounded_linux_folded_name_topology_message(root)
    repeated = harness._bounded_linux_folded_name_topology_message(root)

    assert repeated == message
    assert message.startswith(
        "toolchain support linux folded-name topology "
        "(groups=1,members=2,merkle="
    )
    assert message.endswith(")")
    merkle = message.removesuffix(")").rsplit("merkle=", 1)[1]
    assert len(merkle) == 64
    assert all(character in "0123456789abcdef" for character in merkle)
    assert message.isascii()
    assert len(message) == 137
    assert str(root) not in message
    assert group_directory.name not in message
    for name in names:
        assert name not in message
    diagnostic = harness._format_support_lock_diagnostic(
        ToolchainSupportLockError(message)
    )
    assert f"ToolchainSupportLockError={message}" in diagnostic
    assert len(diagnostic.encode("ascii")) <= 512


def test_linux_folded_name_topology_binds_multiple_groups(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _load_harness_module()
    _install_test_folded_alias(monkeypatch)
    root = tmp_path / "runtime"
    _linux_folded_name_group(root / "first-secret-group")
    single = harness._bounded_linux_folded_name_topology_message(root)
    _linux_folded_name_group(root / "second-secret-group")

    multiple = harness._bounded_linux_folded_name_topology_message(root)

    assert "groups=1" in single
    assert "members=2" in single
    assert "groups=2" in multiple
    assert "members=4" in multiple
    assert multiple != single


def test_linux_folded_name_topology_never_follows_symlink_directories(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _load_harness_module()
    _install_test_folded_alias(monkeypatch)
    root = tmp_path / "runtime"
    _linux_folded_name_group(root / "in-root-group")
    outside = tmp_path / "outside-secret"
    outside_names = _linux_folded_name_group(outside)
    link = root / "outside-secret-link"
    link.symlink_to(outside, target_is_directory=True)

    with_link = harness._bounded_linux_folded_name_topology_message(root)
    link.unlink()
    without_link = harness._bounded_linux_folded_name_topology_message(root)

    assert with_link == without_link
    assert "groups=1" in with_link
    assert str(outside) not in with_link
    for name in outside_names:
        assert name not in with_link


def test_linux_folded_name_topology_detects_race_between_scans(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _load_harness_module()
    _install_test_folded_alias(monkeypatch)
    root = tmp_path / "runtime"
    group = root / "group"
    _first, second = _linux_folded_name_group(group)
    from rextio.build import toolchain_support_lock as support_lock

    original = support_lock._open_directory_chain
    scan_count = 0

    def mutate_before_second_scan(path: Path) -> object:
        nonlocal scan_count
        scan_count += 1
        if scan_count == 2:
            (group / second).rename(group / "unique-member")
        return original(path)

    monkeypatch.setattr(
        support_lock,
        "_open_directory_chain",
        mutate_before_second_scan,
    )

    with pytest.raises(ToolchainSupportLockError, match="changed across scans"):
        harness._bounded_linux_folded_name_topology_message(root)
    assert scan_count == 2


@pytest.mark.parametrize(
    ("constant", "value", "match"),
    [
        ("_LINUX_FOLDED_NAME_MAX_GROUPS", 1, "group bound"),
        ("_LINUX_FOLDED_NAME_MAX_ENTRIES", 1, "entry bound"),
        ("_LINUX_FOLDED_NAME_MAX_DEPTH", 1, "path bound"),
        ("_LINUX_FOLDED_NAME_MAX_PATH_BYTES", 2, "path bound"),
    ],
)
def test_linux_folded_name_topology_enforces_bounds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    constant: str,
    value: int,
    match: str,
) -> None:
    harness = _load_harness_module()
    _install_test_folded_alias(monkeypatch)
    root = tmp_path / "runtime"
    _linux_folded_name_group(root / "first-group")
    _linux_folded_name_group(root / "second-group")
    monkeypatch.setattr(harness, constant, value)

    with pytest.raises(ToolchainSupportLockError, match=match):
        harness._bounded_linux_folded_name_topology_message(root)


@pytest.mark.parametrize(
    "raw_path",
    [
        "/private/secret/toolchain/member",
        "private:secret",
        r"private\secret",
    ],
)
def test_support_lock_diagnostic_rejects_full_c6_raw_path_message(
    raw_path: str,
) -> None:
    harness = _load_harness_module()

    diagnostic = harness._format_support_lock_diagnostic(
        FullC6ToolchainSupportError(f"Full C6 support root is {raw_path}")
    )

    assert diagnostic.endswith("OtherErrorMessage=<unavailable>")
    assert raw_path not in diagnostic
    assert "secret" not in diagnostic


@pytest.mark.parametrize(
    "message",
    [
        "toolchain support directory contains an NFC/casefold alias",
        "toolchain support tree contains an NFC/casefold path alias",
        "toolchain support lock contains an NFC/casefold role alias",
        "toolchain support locators contain an NFC/casefold role alias",
    ],
)
def test_support_lock_diagnostic_preserves_exact_semantic_slash_messages(
    message: str,
) -> None:
    harness = _load_harness_module()

    diagnostic = harness._format_support_lock_diagnostic(
        ToolchainSupportLockError(message)
    )

    assert diagnostic == (
        "[full-c6-e2e] support-lock diagnostic: "
        f"ToolchainSupportLockError={message}; "
        "OSError=<unavailable>; errno=<unavailable>; "
        "OtherErrorType=<unavailable>; OtherErrorMessage=<unavailable>"
    )
    assert len(diagnostic.encode("ascii")) <= 512


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
        "OSError=<unavailable>; errno=<unavailable>; "
        "OtherErrorType=<unavailable>; OtherErrorMessage=<unavailable>"
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
        "symlink-free directory walk; OSError=NotADirectoryError; errno=20; "
        "OtherErrorType=<unavailable>; OtherErrorMessage=<unavailable>"
    )
    assert observed == {
        "load": (tmp_path, harness._SUPPORT_LOCK_OUTPUT, inherited_environment),
        "discover": (tmp_path, config, inherited_environment),
        "generate": plan,
    }
    assert list(tmp_path.iterdir()) == []


def test_support_lock_diagnostic_compares_two_path_free_generation_receipts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _load_harness_module()
    from rextio.build import full_c6_toolchain_support as support
    from rextio.build.toolchain_support_lock import (
        create_toolchain_support_locator,
        generate_toolchain_support_lock,
    )

    manifest = tmp_path / "version.plist"
    manifest.write_bytes(b"fixed manifest\n")
    root = tmp_path / "runtime"
    root.mkdir()
    member = root / "member"
    member.write_bytes(b"first\n")
    manifests = [
        create_toolchain_support_locator(
            logical_role="xcode-version-plist",
            path=manifest,
            kind="file",
        )
    ]
    roots = [
        create_toolchain_support_locator(
            logical_role="rust-sysroot",
            path=root,
            kind="tree",
        )
    ]
    first = generate_toolchain_support_lock(
        target_triple="aarch64-apple-darwin",
        manifests=manifests,
        roots=roots,
    )
    member.write_bytes(b"second\n")
    second = generate_toolchain_support_lock(
        target_triple="aarch64-apple-darwin",
        manifests=manifests,
        roots=roots,
    )
    plan = object()
    generated = iter((first, second))
    observed: list[object] = []

    monkeypatch.setattr(
        support,
        "_load_full_c6_support_bootstrap_config",
        lambda *_args, **_kwargs: (object(), None),
    )
    monkeypatch.setattr(
        support,
        "_discover_full_c6_bootstrap_plan",
        lambda **_kwargs: plan,
    )

    def generate(candidate: object) -> object:
        observed.append(candidate)
        return next(generated)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("diagnostic attempted output materialization")

    monkeypatch.setattr(support, "generate_full_c6_toolchain_support_lock", generate)
    monkeypatch.setattr(support, "materialize_full_c6_toolchain_support_lock", forbidden)
    monkeypatch.setattr(support, "bootstrap_full_c6_toolchain_support_lock", forbidden)

    diagnostic = harness._diagnose_support_lock_generation(
        tmp_path,
        inherited_environment={},
    )

    assert observed == [plan, plan]
    assert diagnostic == (
        "[full-c6-e2e] support-lock diagnostic: verification-recapture-drift "
        "manifests=0 roots=1 kind=root role=rust-sysroot "
        f"before={first.roots[0].merkle_sha256} "
        f"after={second.roots[0].merkle_sha256} "
        "hardlink_before=- hardlink_after=-"
    )
    assert str(tmp_path) not in diagnostic
    assert len(diagnostic.encode("ascii")) <= 512


@pytest.mark.parametrize("failure_stage", ["load", "discover"])
def test_support_lock_diagnostic_preserves_preplan_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
) -> None:
    harness = _load_harness_module()
    from rextio.build import full_c6_toolchain_support as support

    original = ToolchainSupportLockError(
        "toolchain support bootstrap configuration is invalid"
    )
    config = object()

    def load(*_args: object, **_kwargs: object) -> tuple[object, None]:
        if failure_stage == "load":
            raise original
        return config, None

    def discover(*_args: object, **_kwargs: object) -> object:
        raise original

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("pre-plan failure continued into generation")

    monkeypatch.setattr(support, "_load_full_c6_support_bootstrap_config", load)
    monkeypatch.setattr(support, "_discover_full_c6_bootstrap_plan", discover)
    monkeypatch.setattr(support, "generate_full_c6_toolchain_support_lock", forbidden)
    monkeypatch.setattr(harness, "_diagnose_xcode_hardlink_topology", forbidden)

    diagnostic = harness._diagnose_support_lock_generation(
        tmp_path,
        inherited_environment={},
    )

    assert diagnostic.endswith(
        "ToolchainSupportLockError=toolchain support bootstrap configuration "
        "is invalid; OSError=<unavailable>; errno=<unavailable>; "
        "OtherErrorType=<unavailable>; OtherErrorMessage=<unavailable>"
    )


def test_support_lock_diagnostic_does_not_repeat_production_topology_scans(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _load_harness_module()
    from rextio.build import full_c6_toolchain_support as support

    plan = object()

    def load_config(*_args: object, **_kwargs: object) -> tuple[object, None]:
        return object(), None

    def discover(*_args: object, **_kwargs: object) -> object:
        return plan

    def generate(_plan: object) -> None:
        raise RuntimeError("original private failure")

    def diagnose(candidate: object, _error: BaseException) -> str | None:
        raise AssertionError(f"duplicate diagnostic scan invoked for {candidate!r}")

    monkeypatch.setattr(support, "_load_full_c6_support_bootstrap_config", load_config)
    monkeypatch.setattr(support, "_discover_full_c6_bootstrap_plan", discover)
    monkeypatch.setattr(support, "generate_full_c6_toolchain_support_lock", generate)
    monkeypatch.setattr(harness, "_diagnose_exact_xcode_hardlink_aliases", diagnose)

    diagnostic = harness._diagnose_support_lock_generation(
        tmp_path,
        inherited_environment={},
    )

    assert diagnostic == (
        "[full-c6-e2e] support-lock diagnostic: "
        "ToolchainSupportLockError=<unavailable>; "
        "OSError=<unavailable>; errno=<unavailable>; "
        "OtherErrorType=RuntimeError; OtherErrorMessage=<unavailable>"
    )
    assert "original private failure" not in diagnostic


def test_support_lock_diagnostic_prefers_generic_xcode_topology(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _load_harness_module()
    from rextio.build import full_c6_toolchain_support as support

    plan = object()
    original = ToolchainSupportLockError(
        "toolchain support regular tree member is a shared hardlink "
        "(logical_role=xcode-clang-resource, "
        f"relative_path_sha256={'b' * 64}, st_uid=0, st_gid=0, "
        "st_mode=33188, st_nlink=3, "
        "in_root_inode_observation_count=1)"
    )
    topology = (
        "toolchain support xcode hardlink topology "
        f"(groups=2,support_members=3,aliases=5,"
        f"policy_merkle={'e' * 64},observation_merkle={'f' * 64})"
    )
    observed: list[tuple[object, BaseException]] = []

    monkeypatch.setattr(
        support,
        "_load_full_c6_support_bootstrap_config",
        lambda *_args, **_kwargs: (object(), None),
    )
    monkeypatch.setattr(
        support,
        "_discover_full_c6_bootstrap_plan",
        lambda **_kwargs: plan,
    )

    def generate(_plan: object) -> None:
        raise original

    def diagnose(candidate: object, error: BaseException) -> str:
        observed.append((candidate, error))
        return topology

    monkeypatch.setattr(support, "generate_full_c6_toolchain_support_lock", generate)
    monkeypatch.setattr(harness, "_diagnose_xcode_hardlink_topology", diagnose)

    diagnostic = harness._diagnose_support_lock_generation(
        tmp_path,
        inherited_environment={},
    )

    assert observed == [(plan, original)]
    assert f"ToolchainSupportLockError={topology}" in diagnostic
    assert "regular tree member is a shared hardlink" not in diagnostic
    assert len(diagnostic.encode("ascii")) <= 512


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


def test_fresh_rextio_reuses_valid_initial_support_lock_diagnostic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    harness = _load_harness_module()
    diagnostic = (
        "toolchain support verification differs "
        "(manifests=0,roots=1,kind=root,role=rust-sysroot,"
        f"before={'a' * 64},after={'b' * 64},hbefore=none,hafter=none,"
        "fields=2000)"
    )

    def forbidden(*_args: object, **_kwargs: object) -> str:
        raise AssertionError("valid initial diagnostic triggered a rerun")

    monkeypatch.setattr(
        harness,
        "_diagnose_support_lock_generation",
        forbidden,
    )

    script = (
        "import sys; "
        f"sys.stderr.write({'Diagnostic: ' + diagnostic + chr(10)!r}); "
        "raise SystemExit(7)"
    )
    with pytest.raises(AssertionError, match="bootstrap-support-lock failed with 7"):
        harness._run_fresh_rextio(
            [sys.executable, "-c", script],
            cwd=tmp_path,
            stage="policy/bootstrap-support-lock",
            timeout=10,
            expect_two_cargo_builds=False,
            support_lock_diagnostic_project=tmp_path,
        )

    captured = capsys.readouterr()
    assert captured.err == (
        f"[full-c6-e2e] support-lock diagnostic: {diagnostic}\n"
    )


def test_fresh_rextio_rejects_forged_initial_diagnostic_and_reruns(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    harness = _load_harness_module()
    forged_role = "private-host-secret"
    forged = (
        "toolchain support verification differs "
        f"(manifests=0,roots=1,kind=root,role={forged_role},"
        f"before={'a' * 64},after={'b' * 64},hbefore=none,hafter=none,"
        "fields=2000)"
    )
    observed: list[Path] = []

    def diagnose(
        project: Path,
        *,
        inherited_environment: dict[str, str],
    ) -> str:
        assert inherited_environment["PYTHONNOUSERSITE"] == "1"
        observed.append(project)
        return "[full-c6-e2e] support-lock diagnostic: bounded-rerun-cause"

    monkeypatch.setattr(harness, "_diagnose_support_lock_generation", diagnose)

    script = (
        "import sys; "
        f"sys.stderr.write({'Diagnostic: ' + forged + chr(10)!r}); "
        "raise SystemExit(8)"
    )
    with pytest.raises(AssertionError, match="bootstrap-support-lock failed with 8"):
        harness._run_fresh_rextio(
            [sys.executable, "-c", script],
            cwd=tmp_path,
            stage="policy/bootstrap-support-lock",
            timeout=10,
            expect_two_cargo_builds=False,
            support_lock_diagnostic_project=tmp_path,
        )

    assert observed == [tmp_path]
    captured = capsys.readouterr()
    assert captured.err == (
        "[full-c6-e2e] support-lock diagnostic: bounded-rerun-cause\n"
    )
    assert forged_role not in captured.err


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
