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
from pathlib import Path, PurePosixPath
import signal
import subprocess
import sys
import time
from types import ModuleType

import pytest

from rextio.build.full_c6_toolchain_support import FullC6ToolchainSupportError
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
        "symlink-free directory walk; OSError=NotADirectoryError; errno=20; "
        "OtherErrorType=RuntimeError; OtherErrorMessage=<unavailable>"
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
    target = boundary.joinpath(*target_relative_path.parts)
    observed = target.stat()
    return harness._bounded_xcode_hardlink_alias_message(
        boundary=boundary,
        target_relative_path=target_relative_path,
        expected_uid=observed.st_uid,
        expected_gid=observed.st_gid,
        expected_mode=observed.st_mode,
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
    assert len(message) == 261
    assert message.startswith(
        "toolchain support xcode hardlink aliases (nlink=3,count=3,digests="
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
        "toolchain support regular tree member is a shared hardlink "
        "(logical_role=xcode-clang-resource, "
        f"relative_path_sha256={harness._XCODE_HARDLINK_RELATIVE_PATH_SHA256}, "
        "st_uid=501, st_gid=20, st_mode=33188, st_nlink=3, "
        "in_root_inode_observation_count=1)"
    )
    assert harness._XCODE_HARDLINK_ERROR_RE.fullmatch(exact) is not None
    if changed_field.startswith("logical_role="):
        changed = exact.replace("logical_role=xcode-clang-resource", changed_field)
    elif changed_field.startswith("relative_path_sha256="):
        changed = exact.replace(
            f"relative_path_sha256={harness._XCODE_HARDLINK_RELATIVE_PATH_SHA256}",
            changed_field,
        )
    elif changed_field.startswith("st_nlink="):
        changed = exact.replace("st_nlink=3", changed_field)
    else:
        changed = exact.replace("in_root_inode_observation_count=1", changed_field)
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
