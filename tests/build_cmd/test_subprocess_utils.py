from __future__ import annotations

import os
import signal
import subprocess
import sys
import time

import pytest

from rextio.build import subprocess_utils
from rextio.build.subprocess_utils import run_build_tool


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:  # pragma: no cover - alive but not ours.
        return True
    return True


def test_run_build_tool_captures_output(tmp_path) -> None:
    result = run_build_tool(
        [sys.executable, "-c", "import sys; print('out'); print('err', file=sys.stderr)"],
        cwd=tmp_path,
    )
    assert result.returncode == 0
    assert "out" in result.stdout
    assert "err" in result.stderr


def test_run_build_tool_times_out_into_a_failed_result(tmp_path) -> None:
    # A tool that hangs must not block the build forever: the helper terminates it
    # and returns a failed CompletedProcess so normal failure handling reports it.
    result = run_build_tool(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        cwd=tmp_path,
        timeout=0.5,
    )
    assert result.returncode != 0
    assert "timed out" in result.stderr.lower()


@pytest.mark.skipif(os.name != "posix", reason="process-group kill path is POSIX-specific")
def test_run_build_tool_terminates_the_whole_process_tree(tmp_path) -> None:
    # On timeout the tool AND everything it spawned must die — killing only the
    # direct child would leave a reparented grandchild (e.g. rustc) running. The
    # grandchild records its PID; after the timeout it must no longer be alive.
    pid_file = tmp_path / "grandchild.pid"
    grandchild = (
        "import os, time; "
        f"open({str(pid_file)!r}, 'w').write(str(os.getpid())); "
        "time.sleep(60)"
    )
    parent = (
        "import subprocess, sys, time; "
        f"subprocess.Popen([sys.executable, '-c', {grandchild!r}]); "
        "time.sleep(60)"
    )

    result = run_build_tool([sys.executable, "-c", parent], cwd=tmp_path, timeout=1.0)
    assert result.returncode != 0
    assert "timed out" in result.stderr.lower()

    deadline = time.monotonic() + 5
    while not pid_file.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert pid_file.exists(), "grandchild never started"
    grandchild_pid = int(pid_file.read_text())

    while _pid_alive(grandchild_pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not _pid_alive(grandchild_pid), "grandchild survived the timeout kill"


@pytest.mark.parametrize("bad", [0, -1.0, float("nan"), None])
def test_run_build_tool_rejects_invalid_timeout(tmp_path, bad) -> None:
    # None/NaN/non-positive are caller bugs (config/CLI already reject them for real
    # callers); the reusable entry point fails fast with a clear ValueError instead
    # of a TypeError or an instantly-failing build.
    with pytest.raises(ValueError):
        run_build_tool([sys.executable, "-c", "pass"], cwd=tmp_path, timeout=bad)


def test_run_build_tool_clamps_an_over_cap_timeout_to_the_maximum(tmp_path, monkeypatch) -> None:
    # Prove the clamp value is actually used on the wait path (not just "no crash"):
    # cap the maximum to a tiny value and pass a huge timeout to a slow command — it
    # must time out at the clamped value, promptly. Without the clamp it would wait
    # ~forever; an over-cap timeout would also raise OverflowError unclamped.
    monkeypatch.setattr(subprocess_utils, "MAX_BUILD_TIMEOUT_SECONDS", 0.3)
    monkeypatch.setattr(subprocess_utils, "_TERM_GRACE_SECONDS", 0.5)
    monkeypatch.setattr(subprocess_utils, "_KILL_GRACE_SECONDS", 0.5)

    start = time.monotonic()
    result = run_build_tool(
        [sys.executable, "-c", "import time; time.sleep(10)"],
        cwd=tmp_path,
        timeout=1e100,
    )
    elapsed = time.monotonic() - start

    assert result.returncode != 0
    assert "timed out" in result.stderr.lower()
    assert elapsed < 5, f"clamp not applied (took {elapsed:.1f}s)"


@pytest.mark.skipif(os.name != "posix", reason="process-group escape is POSIX-specific")
def test_run_build_tool_timeout_is_bounded_when_a_grandchild_escapes_the_group(
    tmp_path, monkeypatch
) -> None:
    # A grandchild that detaches into its own session (`setsid`) survives the
    # process-group kill and keeps the inherited stdout/stderr write-ends open, so
    # the parent's pipes never see EOF. The cleanup must still return promptly
    # (strictly bounded by the grace period), not block until the grandchild dies.
    monkeypatch.setattr(subprocess_utils, "_TERM_GRACE_SECONDS", 1.0)
    monkeypatch.setattr(subprocess_utils, "_KILL_GRACE_SECONDS", 1.0)
    # The grandchild records its PID before sleeping so the test can clean it up:
    # it detached into its own session, so the code under test cannot kill it, and
    # we must not leak a 30s sleeper into the CI run.
    pid_file = tmp_path / "grandchild.pid"
    grandchild = (
        "import os, time; os.setsid(); "
        f"open({str(pid_file)!r}, 'w').write(str(os.getpid())); "
        "time.sleep(30)"
    )
    parent = (
        "import subprocess, sys, time; "
        f"subprocess.Popen([sys.executable, '-c', {grandchild!r}]); "
        "time.sleep(30)"
    )

    try:
        start = time.monotonic()
        result = run_build_tool([sys.executable, "-c", parent], cwd=tmp_path, timeout=0.5)
        elapsed = time.monotonic() - start

        assert result.returncode != 0
        assert "timed out" in result.stderr.lower()
        # The escaped grandchild keeps the pipes open, so the drain is abandoned and
        # the truncation is surfaced.
        assert "truncated" in result.stderr.lower()
        # Bounded: timeout (0.5s) + a few 1s grace windows, far below the 30s the
        # escaped grandchild would otherwise hold the pipes open. Generous margin so
        # a loaded CI box does not make it flaky.
        assert elapsed < 15, f"timeout cleanup hung for {elapsed:.1f}s"
    finally:
        deadline = time.monotonic() + 5
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        if pid_file.exists():
            try:
                os.kill(int(pid_file.read_text()), signal.SIGKILL)
            except (FileNotFoundError, ProcessLookupError, ValueError):
                pass


def test_run_build_tool_forges_returncode_when_the_child_cannot_be_reaped(
    tmp_path, monkeypatch
) -> None:
    # Exercise the poll()-is-None branch directly. _terminate_process_tree is mocked
    # to give up WITHOUT killing, so the child is still alive: poll() returns None and
    # the code must forge process.returncode so Popen.__exit__'s untimed wait()
    # short-circuits (the call stays bounded) and the stray note is surfaced.
    created: list[subprocess.Popen] = []
    real_start = subprocess_utils._start_process

    def capturing_start(command, cwd):
        proc = real_start(command, cwd)
        created.append(proc)
        return proc

    monkeypatch.setattr(subprocess_utils, "_start_process", capturing_start)
    monkeypatch.setattr(subprocess_utils, "_terminate_process_tree", lambda process: False)
    monkeypatch.setattr(subprocess_utils, "_drain_after_kill", lambda process: ("", "", True))

    try:
        start = time.monotonic()
        result = run_build_tool(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            cwd=tmp_path,
            timeout=0.5,
        )
        elapsed = time.monotonic() - start

        assert result.returncode == subprocess_utils.TIMEOUT_EXIT_CODE
        assert "could not be fully terminated" in result.stderr.lower()
        # The still-alive child means poll() was None, so the branch forged the code
        # onto the Popen (which let __exit__'s wait() short-circuit -> bounded).
        assert created and created[0].returncode == subprocess_utils.TIMEOUT_EXIT_CODE
        assert elapsed < 5, f"timeout path hung for {elapsed:.1f}s"
    finally:
        # Reap directly: Popen.kill()/wait() would no-op on the forged returncode.
        for proc in created:
            try:
                os.kill(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, OSError):
                pass
            try:
                os.waitpid(proc.pid, 0)
            except (ChildProcessError, OSError):
                pass


def test_run_build_tool_does_not_use_a_shell(tmp_path) -> None:
    # Arguments are passed as a list, so shell metacharacters are literal, not
    # interpreted — `$(...)` is just an argument, never a command substitution.
    result = run_build_tool(
        [sys.executable, "-c", "import sys; print(sys.argv[1])", "$(echo pwned)"],
        cwd=tmp_path,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "$(echo pwned)"
