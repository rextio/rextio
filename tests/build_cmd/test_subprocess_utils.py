from __future__ import annotations

import os
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


def test_run_build_tool_clamps_an_overflowing_timeout(tmp_path) -> None:
    # A direct caller (test/library) bypassing the config-layer cap must not crash:
    # an enormous or non-finite timeout would otherwise raise OverflowError in the
    # C-level wait. The clamp keeps a fast command working normally.
    result = run_build_tool(
        [sys.executable, "-c", "print('ok')"],
        cwd=tmp_path,
        timeout=1e100,
    )
    assert result.returncode == 0
    assert "ok" in result.stdout


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
    grandchild = "import os, time; os.setsid(); time.sleep(30)"
    parent = (
        "import subprocess, sys, time; "
        f"subprocess.Popen([sys.executable, '-c', {grandchild!r}]); "
        "time.sleep(30)"
    )

    start = time.monotonic()
    result = run_build_tool([sys.executable, "-c", parent], cwd=tmp_path, timeout=0.5)
    elapsed = time.monotonic() - start

    assert result.returncode != 0
    assert "timed out" in result.stderr.lower()
    # The escaped grandchild keeps the pipes open, so the drain is abandoned and the
    # truncation is surfaced.
    assert "truncated" in result.stderr.lower()
    # Bounded: timeout (0.5s) + a few 1s grace windows, far below the 30s the
    # escaped grandchild would otherwise hold the pipes open. Generous margin so a
    # loaded CI box does not make it flaky.
    assert elapsed < 15, f"timeout cleanup hung for {elapsed:.1f}s"


def test_run_build_tool_surfaces_giveup_when_cleanup_reports_failure(tmp_path, monkeypatch) -> None:
    # When _terminate_process_tree gives up (returns False), the synthetic timeout
    # result must surface the stray-process note (and still be bounded). The fake
    # still kills the child so the test does not leak it.
    def fake_terminate(process):
        process.kill()
        return False

    monkeypatch.setattr(subprocess_utils, "_terminate_process_tree", fake_terminate)
    result = run_build_tool(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        cwd=tmp_path,
        timeout=0.5,
    )
    assert result.returncode != 0
    assert "could not be fully terminated" in result.stderr.lower()


def test_run_build_tool_does_not_use_a_shell(tmp_path) -> None:
    # Arguments are passed as a list, so shell metacharacters are literal, not
    # interpreted — `$(...)` is just an argument, never a command substitution.
    result = run_build_tool(
        [sys.executable, "-c", "import sys; print(sys.argv[1])", "$(echo pwned)"],
        cwd=tmp_path,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "$(echo pwned)"
