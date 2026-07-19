from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

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


@pytest.mark.parametrize("max_output_bytes", [None, 4096])
def test_run_build_tool_can_replace_parent_environment_exactly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    max_output_bytes: int | None,
) -> None:
    monkeypatch.setenv("REXTIO_PARENT_ONLY_SECRET", "must-not-reach-child")
    result = run_build_tool(
        [
            sys.executable,
            "-c",
            "import os; print(os.environ.get('REXTIO_PARENT_ONLY_SECRET', 'missing')); "
            "print(os.environ['REXTIO_CHILD_ONLY'])",
        ],
        cwd=tmp_path,
        env={"REXTIO_CHILD_ONLY": "present"},
        inherit_env=False,
        max_output_bytes=max_output_bytes,
    )

    assert result.returncode == 0
    assert result.stdout.splitlines() == ["missing", "present"]
    assert "must-not-reach-child" not in result.stdout
    assert "must-not-reach-child" not in result.stderr


def test_run_build_tool_default_environment_behavior_remains_overlay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("REXTIO_PARENT_VISIBLE", "parent")
    result = run_build_tool(
        [
            sys.executable,
            "-c",
            "import os; print(os.environ['REXTIO_PARENT_VISIBLE']); "
            "print(os.environ['REXTIO_CHILD_VISIBLE'])",
        ],
        cwd=tmp_path,
        env={"REXTIO_CHILD_VISIBLE": "child"},
    )

    assert result.returncode == 0
    assert result.stdout.splitlines() == ["parent", "child"]


def test_run_build_tool_rejects_non_boolean_inherit_env(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="inherit_env"):
        run_build_tool(
            [sys.executable, "-c", "pass"],
            cwd=tmp_path,
            inherit_env=0,  # type: ignore[arg-type]
        )


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
        f"import os, time; open({str(pid_file)!r}, 'w').write(str(os.getpid())); time.sleep(60)"
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


@pytest.mark.parametrize(
    "bad",
    [0, -1.0, float("nan"), None, True, "10", __import__("decimal").Decimal("1.0")],
)
def test_run_build_tool_rejects_invalid_timeout(tmp_path, bad) -> None:
    # Non-positive / NaN / None are caller bugs, and so are non-float types: `bool`
    # would silently become a 0/1s timeout, and `str`/`Decimal` would raise a
    # TypeError deeper in. The reusable entry point fails fast with a clear
    # ValueError (config/CLI already reject these for real callers).
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


@pytest.mark.skipif(os.name != "posix", reason="process-group signalling is POSIX-specific")
def test_run_build_tool_sigkills_a_sigterm_ignoring_in_group_grandchild(
    tmp_path, monkeypatch
) -> None:
    # The direct child exits on SIGTERM, but an in-group grandchild ignores SIGTERM.
    # The cleanup must still escalate to a group SIGKILL (which cannot be ignored)
    # rather than returning as soon as the direct child is reaped.
    monkeypatch.setattr(subprocess_utils, "_TERM_GRACE_SECONDS", 0.5)
    monkeypatch.setattr(subprocess_utils, "_KILL_GRACE_SECONDS", 1.0)
    pid_file = tmp_path / "grandchild.pid"
    grandchild = (
        "import os, signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        f"open({str(pid_file)!r}, 'w').write(str(os.getpid())); time.sleep(30)"
    )
    parent = (  # default SIGTERM disposition -> dies on SIGTERM
        "import subprocess, sys, time; "
        f"subprocess.Popen([sys.executable, '-c', {grandchild!r}]); time.sleep(30)"
    )

    try:
        result = run_build_tool([sys.executable, "-c", parent], cwd=tmp_path, timeout=0.5)
        assert result.returncode != 0

        deadline = time.monotonic() + 5
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert pid_file.exists(), "grandchild never started"
        grandchild_pid = int(pid_file.read_text())
        while _pid_alive(grandchild_pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not _pid_alive(grandchild_pid), "SIGTERM-ignoring grandchild was not SIGKILLed"
    finally:
        if pid_file.exists():
            try:
                os.kill(int(pid_file.read_text()), signal.SIGKILL)
            except (FileNotFoundError, ProcessLookupError, ValueError):
                pass


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


@pytest.mark.skipif(
    os.name != "posix", reason="reaps the captured child via POSIX os.kill/os.waitpid"
)
def test_run_build_tool_forges_returncode_when_the_child_cannot_be_reaped(
    tmp_path, monkeypatch
) -> None:
    # Exercise the poll()-is-None branch directly. _terminate_process_tree is mocked
    # to give up WITHOUT killing, so the child is still alive: poll() returns None and
    # the code must forge process.returncode so Popen.__exit__'s untimed wait()
    # short-circuits (the call stays bounded) and the stray note is surfaced.
    created: list[subprocess.Popen] = []
    real_start = subprocess_utils._start_process

    def capturing_start(command, cwd, env=None, *, inherit_env=True):
        proc = real_start(command, cwd, env, inherit_env=inherit_env)
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
        # `_drain_after_kill` was mocked to a no-op, so the production code never
        # closed the captured pipes — close them here to avoid leaking FDs across
        # repeated runs. Then reap the child directly: Popen.kill()/wait() would
        # no-op on the forged returncode.
        for proc in created:
            for stream in (proc.stdout, proc.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass
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


def test_run_build_tool_caps_streaming_output_and_terminates(tmp_path: Path) -> None:
    from rextio.build.subprocess_utils import OUTPUT_OVERFLOW_EXIT_CODE, run_build_tool

    # Emit more than the cap without relying on post-buffer measurement.
    result = run_build_tool(
        [
            sys.executable,
            "-c",
            "import sys; sys.stdout.write('x' * 20000); sys.stdout.flush(); "
            "import time; time.sleep(30)",
        ],
        cwd=tmp_path,
        timeout=10.0,
        max_output_bytes=1000,
    )
    assert result.returncode == OUTPUT_OVERFLOW_EXIT_CODE
    assert result.stdout == ""
    assert "exceeded the allowed 1000 byte bound" in result.stderr
    assert result.stderr.count("\n") < 5


def test_run_build_tool_rejects_invalid_max_output_bytes(tmp_path: Path) -> None:
    from rextio.build.subprocess_utils import run_build_tool

    with pytest.raises(ValueError, match="max_output_bytes"):
        run_build_tool([sys.executable, "-c", "pass"], cwd=tmp_path, max_output_bytes=0)
    with pytest.raises(ValueError, match="max_output_bytes"):
        run_build_tool([sys.executable, "-c", "pass"], cwd=tmp_path, max_output_bytes=True)  # type: ignore[arg-type]


def test_run_build_tool_overflow_is_prompt_when_child_writes_cap_plus_one_then_sleeps(
    tmp_path: Path,
) -> None:
    """Overflow must return 125 promptly without waiting for the full timeout.

    The child writes cap+1 bytes then sleeps; the event-aware / short-poll
    capture path must kill the tree and finish far below the caller timeout.
    """
    from rextio.build.subprocess_utils import OUTPUT_OVERFLOW_EXIT_CODE

    start = time.monotonic()
    result = run_build_tool(
        [
            sys.executable,
            "-c",
            "import sys, time; sys.stdout.write('x' * 1001); sys.stdout.flush(); time.sleep(60)",
        ],
        cwd=tmp_path,
        timeout=30.0,
        max_output_bytes=1000,
    )
    elapsed = time.monotonic() - start
    assert result.returncode == OUTPUT_OVERFLOW_EXIT_CODE
    assert result.stdout == ""
    assert "exceeded the allowed 1000 byte bound" in result.stderr
    # Prompt: well under the 30s caller timeout (and under the 60s sleep).
    assert elapsed < 5.0, f"overflow was not prompt (took {elapsed:.2f}s)"


@pytest.mark.skipif(os.name != "posix", reason="setsid pipe-holder escape is POSIX-specific")
def test_capped_capture_stops_promptly_when_escaped_holder_keeps_pipes_open(
    tmp_path: Path, monkeypatch
) -> None:
    """Direct child exits after writing under the cap; a setsid grandchild holds pipes.

    POSIX select must poll in short intervals and stop after the post-exit drain
    window rather than burning the full timeout.
    """
    from rextio.build import subprocess_utils as su

    monkeypatch.setattr(su, "_CAPPED_POST_EXIT_DRAIN_SECONDS", 0.2)
    monkeypatch.setattr(su, "_CAPPED_POLL_SECONDS", 0.05)
    pid_file = tmp_path / "holder.pid"
    # Parent writes a little under the cap, spawns a detached holder that keeps
    # the inherited write ends open, then exits. Without early stop the drain
    # would wait until timeout while the holder lives.
    script = (
        "import os, subprocess, sys, time\n"
        f"pid_path = {str(pid_file)!r}\n"
        "sys.stdout.write('hello'); sys.stdout.flush()\n"
        "holder = (\n"
        "    'import os, time; os.setsid(); '\n"
        "    f'open({pid_path!r}, \"w\").write(str(os.getpid())); '\n"
        "    'time.sleep(60)'\n"
        ")\n"
        "subprocess.Popen([sys.executable, '-c', holder])\n"
        "time.sleep(0.3)\n"
    )
    try:
        start = time.monotonic()
        result = run_build_tool(
            [sys.executable, "-c", script],
            cwd=tmp_path,
            timeout=20.0,
            max_output_bytes=1_000_000,
        )
        elapsed = time.monotonic() - start
        # Child exit + short drain; must not consume the full 20s timeout.
        assert elapsed < 5.0, f"escaped pipe holder burned timeout ({elapsed:.2f}s)"
        assert result.returncode == 0
        assert "hello" in result.stdout
    finally:
        deadline = time.monotonic() + 5
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        if pid_file.exists():
            try:
                os.kill(int(pid_file.read_text()), signal.SIGKILL)
            except (FileNotFoundError, ProcessLookupError, ValueError, OSError):
                pass


def test_windows_capped_path_overflow_prompt_on_this_host(tmp_path: Path) -> None:
    """Call _run_build_tool_capped_windows directly (not the POSIX dispatcher).

    Proves the Windows reader-thread path returns 125 promptly for cap+1 then
    sleep, even when the host OS is not Windows.
    """
    from rextio.build.subprocess_utils import (
        OUTPUT_OVERFLOW_EXIT_CODE,
        _run_build_tool_capped_windows,
    )

    start = time.monotonic()
    result = _run_build_tool_capped_windows(
        [
            sys.executable,
            "-c",
            "import sys, time; sys.stdout.write('x' * 1001); sys.stdout.flush(); time.sleep(60)",
        ],
        cwd=tmp_path,
        timeout=30.0,
        env=None,
        max_output_bytes=1000,
    )
    elapsed = time.monotonic() - start
    assert result.returncode == OUTPUT_OVERFLOW_EXIT_CODE
    assert result.stdout == ""
    assert "exceeded the allowed 1000 byte bound" in result.stderr
    assert elapsed < 5.0, f"Windows capped path was not prompt (took {elapsed:.2f}s)"


def test_read_one_raw_chunk_prefers_read1() -> None:
    from rextio.build.subprocess_utils import _read_one_raw_chunk

    class FakeStream:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def read1(self, n: int) -> bytes:
            self.calls.append(f"read1:{n}")
            return b"abc"

        def read(self, n: int) -> bytes:
            self.calls.append(f"read:{n}")
            return b"zzz"

    stream = FakeStream()
    assert _read_one_raw_chunk(stream, 8) == b"abc"
    assert stream.calls == ["read1:8"]
