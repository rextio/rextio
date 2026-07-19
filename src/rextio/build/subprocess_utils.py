"""Hardened subprocess execution for external build tools.

Rextio shells out to `cargo`, `maturin`, `nuitka`, etc. All invocations:

* pass the command as an argument **list** (never a shell string), so there is no
  shell interpolation/injection of user-derived paths or names;
* capture stdout/stderr as text so failures become diagnostics rather than noise
  on the user's terminal;
* run under a bounded **timeout**, so a hung or wedged toolchain fails the build
  with a clear message instead of blocking indefinitely.

The tool is started in its own process group (POSIX session / Windows process
group) so that on timeout the **whole process tree** is terminated, not just the
direct child: `cargo`/`maturin` spawn `rustc`, linkers, and `python`, and killing
only the parent would leave those grandchildren holding CPU, memory, and file
locks.

On timeout the helper returns a synthetic *failed* ``CompletedProcess`` (non-zero
return code, an explanatory stderr) so existing return-code-based failure
handling reports it like any other tool failure.
"""

from __future__ import annotations

import math
import os
import select
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Mapping

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]

# Re-exported here so the builders that already import them from this module keep
# working; the source of truth is the dependency-free ``rextio.limits`` so the
# config layer can validate against them without depending on the build layer.
from rextio.limits import DEFAULT_BUILD_TIMEOUT_SECONDS, MAX_BUILD_TIMEOUT_SECONDS

__all__ = [
    "DEFAULT_BUILD_TIMEOUT_SECONDS",
    "MAX_BUILD_TIMEOUT_SECONDS",
    "OUTPUT_OVERFLOW_EXIT_CODE",
    "TIMEOUT_EXIT_CODE",
    "run_build_tool",
]

# Conventional exit code for "terminated by timeout" (matches GNU `timeout(1)`),
# used for the synthetic CompletedProcess returned on timeout.
TIMEOUT_EXIT_CODE = 124
# Non-zero status when a caller-imposed stdout/stderr byte cap is exceeded and
# the process group is terminated. Distinct from TIMEOUT_EXIT_CODE.
OUTPUT_OVERFLOW_EXIT_CODE = 125

# Grace periods (seconds) for the timeout-cleanup path. Kept short because the
# build has *already* exceeded its (much larger) timeout by the time we get here.
_TERM_GRACE_SECONDS = 5  # let SIGTERM land + the tool clean up, then escalate
_KILL_GRACE_SECONDS = 3  # reap after SIGKILL / drain the pipes, then give up


def run_build_tool(
    command: list[str],
    *,
    cwd: Path | str,
    timeout: float = DEFAULT_BUILD_TIMEOUT_SECONDS,
    env: Mapping[str, str] | None = None,
    max_output_bytes: int | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run an external build tool with no shell, captured output, and a timeout.

    ``command`` must be an argument list (enforces ``shell=False``). The tool runs
    in its own process group so a timeout terminates the whole tree. Returns the
    completed process; on timeout, returns a synthetic process with a non-zero
    return code (:data:`TIMEOUT_EXIT_CODE`) and an explanatory stderr.

    When ``max_output_bytes`` is set, stdout and stderr are streamed with a hard
    combined byte cap. Crossing the cap terminates the process group immediately
    and returns :data:`OUTPUT_OVERFLOW_EXIT_CODE` with a sanitized stderr note.
    Output is never fully buffered first and then measured.
    """
    # Validate/clamp at this reusable entry point (config/env/CLI already do for
    # real callers; this guards direct callers and tests). The type guard comes
    # first so `None`/`str`/`Decimal` fail with a clear ValueError rather than a
    # `TypeError` inside `math`, and `bool` (a subclass of `int`) is rejected rather
    # than silently treated as a 0/1-second timeout. Reject non-positive values
    # (they fail the build instantly) and clamp `inf`/over-cap down to the maximum.
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool):
        raise ValueError(f"build timeout must be a finite positive number, got {timeout!r}")
    if math.isnan(timeout) or timeout <= 0:
        raise ValueError(f"build timeout must be a finite positive number, got {timeout!r}")
    if timeout > MAX_BUILD_TIMEOUT_SECONDS:
        timeout = float(MAX_BUILD_TIMEOUT_SECONDS)
    if max_output_bytes is not None:
        if not isinstance(max_output_bytes, int) or isinstance(max_output_bytes, bool):
            raise ValueError(
                f"max_output_bytes must be a positive int when set, got {max_output_bytes!r}"
            )
        if max_output_bytes <= 0:
            raise ValueError(
                f"max_output_bytes must be a positive int when set, got {max_output_bytes!r}"
            )
        return _run_build_tool_capped(
            command, cwd=cwd, timeout=timeout, env=env, max_output_bytes=max_output_bytes
        )
    with _start_process(command, cwd, env) as process:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
        except subprocess.TimeoutExpired:
            reaped = _terminate_process_tree(process)
            stdout, stderr, output_abandoned = _drain_after_kill(process)
            # Guarantee the `with` block's ``Popen.__exit__`` can never block: it
            # calls ``self.wait()`` with no timeout, which short-circuits only once
            # ``returncode`` is set. ``poll()`` first does a non-blocking ``waitpid``
            # — reaping the child (and setting ``returncode``) if it has exited — so
            # we forge the code only for a genuinely stuck child (D-state /
            # ``PermissionError``) instead of orphaning a reapable zombie.
            if process.poll() is None:
                process.returncode = TIMEOUT_EXIT_CODE
            tool = command[0] if command else "build tool"
            notes = [f"rextio: `{tool}` timed out after {timeout:g}s and was terminated."]
            # Two independent conditions, each with accurate wording: `not reaped`
            # is a stuck *direct* child (D-state / `PermissionError`), nothing
            # detached; `output_abandoned` is a child that escaped the group (held
            # the pipe past the grace period) and is still running.
            if not reaped:
                notes.append(
                    "rextio: the build process tree could not be fully terminated; "
                    "stray processes may still be running."
                )
            if output_abandoned:
                notes.append(
                    "rextio: captured output was truncated because a process kept the output "
                    "pipe open after the timeout (it likely detached into its own session and "
                    "may still be running)."
                )
            stderr = (f"{stderr}\n" if stderr else "") + "\n".join(notes)
            return subprocess.CompletedProcess(
                command, returncode=TIMEOUT_EXIT_CODE, stdout=stdout, stderr=stderr
            )


def _run_build_tool_capped(
    command: list[str],
    *,
    cwd: Path | str,
    timeout: float,
    env: Mapping[str, str] | None,
    max_output_bytes: int,
) -> subprocess.CompletedProcess[str]:
    """Stream stdout/stderr with a combined hard byte cap; never buffer-then-size.

    POSIX uses nonblocking pipes + ``select``. Windows uses bounded reader
    threads. Either path terminates the process group on overflow or timeout.
    """
    if os.name == "nt":  # pragma: no cover - exercised on Windows only.
        return _run_build_tool_capped_windows(
            command, cwd=cwd, timeout=timeout, env=env, max_output_bytes=max_output_bytes
        )
    if fcntl is None:  # pragma: no cover - defensive
        return subprocess.CompletedProcess(
            command,
            returncode=OUTPUT_OVERFLOW_EXIT_CODE,
            stdout="",
            stderr=(
                "rextio: capped subprocess capture is unavailable on this platform "
                "and evidence collection was skipped."
            ),
        )
    return _run_build_tool_capped_posix(
        command, cwd=cwd, timeout=timeout, env=env, max_output_bytes=max_output_bytes
    )


def _set_nonblocking(stream: Any) -> None:
    """Mark a pipe stream nonblocking (POSIX)."""
    assert fcntl is not None
    fd = stream.fileno()
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)


# Short poll so overflow and early child exit are observed promptly without
# waiting for the full caller timeout when pipes stay open (detached holders).
_CAPPED_POLL_SECONDS = 0.05
_CAPPED_POST_EXIT_DRAIN_SECONDS = 0.2
_CAPPED_READ_CHUNK = 8192


def _run_build_tool_capped_posix(
    command: list[str],
    *,
    cwd: Path | str,
    timeout: float,
    env: Mapping[str, str] | None,
    max_output_bytes: int,
) -> subprocess.CompletedProcess[str]:
    with _start_process_bytes(command, cwd, env) as process:
        assert process.stdout is not None and process.stderr is not None
        _set_nonblocking(process.stdout)
        _set_nonblocking(process.stderr)
        stdout_chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []
        total = 0
        deadline = time.monotonic() + timeout
        streams: dict[Any, list[bytes]] = {
            process.stdout: stdout_chunks,
            process.stderr: stderr_chunks,
        }
        overflow = False
        child_exited_at: float | None = None
        try:
            while streams:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout)
                if process.poll() is not None:
                    if child_exited_at is None:
                        child_exited_at = time.monotonic()
                    elif (
                        time.monotonic() - child_exited_at
                        > _CAPPED_POST_EXIT_DRAIN_SECONDS
                    ):
                        # Direct child is gone; stop even if a detached holder
                        # keeps pipes open so we never burn the full timeout.
                        break
                poll = min(_CAPPED_POLL_SECONDS, remaining)
                readable, _, _ = select.select(list(streams.keys()), [], [], poll)
                if not readable:
                    if process.poll() is not None:
                        # Brief nonblocking drain after exit, then stop.
                        for stream, chunks in list(streams.items()):
                            try:
                                chunk = stream.read(_CAPPED_READ_CHUNK)
                            except BlockingIOError:
                                continue
                            if not chunk:
                                streams.pop(stream, None)
                                continue
                            total += len(chunk)
                            if total > max_output_bytes:
                                overflow = True
                                break
                            chunks.append(chunk)
                        if overflow:
                            break
                        if child_exited_at is None:
                            child_exited_at = time.monotonic()
                        if (
                            time.monotonic() - child_exited_at
                            > _CAPPED_POST_EXIT_DRAIN_SECONDS
                        ):
                            break
                    continue
                for stream in readable:
                    try:
                        chunk = stream.read(_CAPPED_READ_CHUNK)
                    except BlockingIOError:
                        continue
                    if chunk == b"" or chunk is None:
                        streams.pop(stream, None)
                        continue
                    total += len(chunk)
                    if total > max_output_bytes:
                        overflow = True
                        break
                    streams[stream].append(chunk)
                if overflow:
                    break
                if process.poll() is not None and not streams:
                    break
        except subprocess.TimeoutExpired:
            reaped = _terminate_process_tree(process)
            if process.poll() is None:
                process.returncode = TIMEOUT_EXIT_CODE
            tool = command[0] if command else "build tool"
            notes = [f"rextio: `{tool}` timed out after {timeout:g}s and was terminated."]
            if not reaped:
                notes.append(
                    "rextio: the build process tree could not be fully terminated; "
                    "stray processes may still be running."
                )
            return subprocess.CompletedProcess(
                command,
                returncode=TIMEOUT_EXIT_CODE,
                stdout="",
                stderr="\n".join(notes),
            )

        if overflow:
            _terminate_process_tree(process)
            if process.poll() is None:
                process.returncode = OUTPUT_OVERFLOW_EXIT_CODE
            tool = command[0] if command else "build tool"
            return subprocess.CompletedProcess(
                command,
                returncode=OUTPUT_OVERFLOW_EXIT_CODE,
                stdout="",
                stderr=(
                    f"rextio: `{tool}` output exceeded the allowed {max_output_bytes} "
                    "byte bound and was terminated."
                ),
            )

        if process.poll() is None:
            try:
                process.wait(timeout=max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                _terminate_process_tree(process)
                if process.poll() is None:
                    process.returncode = TIMEOUT_EXIT_CODE
                return subprocess.CompletedProcess(
                    command,
                    returncode=TIMEOUT_EXIT_CODE,
                    stdout="",
                    stderr="rextio: build tool timed out after output drain and was terminated.",
                )

        stdout = b"".join(stdout_chunks).decode("utf-8", errors="replace")
        stderr = b"".join(stderr_chunks).decode("utf-8", errors="replace")
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def _read_one_raw_chunk(stream: Any, size: int) -> bytes:
    """Perform one bounded raw read (prefer ``read1`` over buffered ``read``).

    Buffered ``stream.read(n)`` may issue multiple underlying reads until ``n``
    bytes arrive, which delays overflow observation. ``read1`` (or a single
    raw read) returns available data after one system call when possible.
    """
    read1 = getattr(stream, "read1", None)
    if callable(read1):
        try:
            chunk = read1(size)
        except (OSError, ValueError, TypeError):
            chunk = None
        if chunk is not None:
            return bytes(chunk)
    raw = getattr(stream, "raw", None)
    if raw is not None:
        raw_read = getattr(raw, "read", None)
        if callable(raw_read):
            try:
                chunk = raw_read(size)
            except (OSError, ValueError, TypeError):
                chunk = None
            if chunk:
                return bytes(chunk)
            if chunk == b"":
                return b""
    try:
        chunk = stream.read(size)
    except OSError:
        return b""
    if not chunk:
        return b""
    return bytes(chunk)


def _run_build_tool_capped_windows(
    command: list[str],
    *,
    cwd: Path | str,
    timeout: float,
    env: Mapping[str, str] | None,
    max_output_bytes: int,
) -> subprocess.CompletedProcess[str]:
    """Windows capped capture via bounded reader threads (no blocking hang).

    Overflow is observed through a short event-aware wait loop so the process
    tree is killed and code 125 is returned promptly without waiting for the
    full caller timeout. Readers use one-raw-read operations and must report
    completion explicitly; hung readers fail closed promptly.
    """
    with _start_process_bytes(command, cwd, env) as process:
        assert process.stdout is not None and process.stderr is not None
        lock = threading.Lock()
        total = [0]
        overflow = threading.Event()
        stdout_chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []
        stdout_done = threading.Event()
        stderr_done = threading.Event()

        def _reader(
            stream: Any, chunks: list[bytes], done: threading.Event
        ) -> None:
            try:
                while not overflow.is_set():
                    try:
                        chunk = _read_one_raw_chunk(stream, _CAPPED_READ_CHUNK)
                    except OSError:
                        return
                    if not chunk:
                        return
                    with lock:
                        total[0] += len(chunk)
                        if total[0] > max_output_bytes:
                            overflow.set()
                            return
                        chunks.append(chunk)
            finally:
                done.set()

        threads = [
            threading.Thread(
                target=_reader,
                args=(process.stdout, stdout_chunks, stdout_done),
                daemon=True,
            ),
            threading.Thread(
                target=_reader,
                args=(process.stderr, stderr_chunks, stderr_done),
                daemon=True,
            ),
        ]
        for thread in threads:
            thread.start()

        deadline = time.monotonic() + timeout
        tool = command[0] if command else "build tool"
        done_events = (stdout_done, stderr_done)

        def _join_readers(*, join_timeout: float = 1.0) -> bool:
            for thread in threads:
                thread.join(timeout=join_timeout)
            return all(event.is_set() for event in done_events) and all(
                not thread.is_alive() for thread in threads
            )

        def _fail_closed_incomplete_readers() -> subprocess.CompletedProcess[str]:
            _terminate_process_tree(process)
            if process.poll() is None:
                process.returncode = TIMEOUT_EXIT_CODE
            return subprocess.CompletedProcess(
                command,
                returncode=TIMEOUT_EXIT_CODE,
                stdout="",
                stderr=(
                    f"rextio: `{tool}` output readers did not complete and capture "
                    "failed closed."
                ),
            )

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate_process_tree(process)
                if process.poll() is None:
                    process.returncode = TIMEOUT_EXIT_CODE
                if not _join_readers():
                    return _fail_closed_incomplete_readers()
                return subprocess.CompletedProcess(
                    command,
                    returncode=TIMEOUT_EXIT_CODE,
                    stdout="",
                    stderr=(
                        f"rextio: `{tool}` timed out after {timeout:g}s and was terminated."
                    ),
                )
            # Event-aware short wait: overflow is acted on immediately.
            if overflow.wait(timeout=min(_CAPPED_POLL_SECONDS, remaining)):
                _terminate_process_tree(process)
                if process.poll() is None:
                    process.returncode = OUTPUT_OVERFLOW_EXIT_CODE
                if not _join_readers():
                    return _fail_closed_incomplete_readers()
                return subprocess.CompletedProcess(
                    command,
                    returncode=OUTPUT_OVERFLOW_EXIT_CODE,
                    stdout="",
                    stderr=(
                        f"rextio: `{tool}` output exceeded the allowed {max_output_bytes} "
                        "byte bound and was terminated."
                    ),
                )
            if process.poll() is not None:
                break

        # Confirm readers finish after the direct child exits.
        if not _join_readers(join_timeout=1.0):
            return _fail_closed_incomplete_readers()

        if overflow.is_set():
            _terminate_process_tree(process)
            if process.poll() is None:
                process.returncode = OUTPUT_OVERFLOW_EXIT_CODE
            return subprocess.CompletedProcess(
                command,
                returncode=OUTPUT_OVERFLOW_EXIT_CODE,
                stdout="",
                stderr=(
                    f"rextio: `{tool}` output exceeded the allowed {max_output_bytes} "
                    "byte bound and was terminated."
                ),
            )

        stdout = b"".join(stdout_chunks).decode("utf-8", errors="replace")
        stderr = b"".join(stderr_chunks).decode("utf-8", errors="replace")
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def _start_process_bytes(
    command: list[str], cwd: Path | str, env: Mapping[str, str] | None = None
) -> subprocess.Popen[bytes]:
    """Start the tool with binary pipes for exact byte-cap streaming."""
    merged_env = {**os.environ, **env} if env else None
    if os.name == "nt":  # pragma: no cover - exercised on Windows only.
        new_group = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        return subprocess.Popen(
            command,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            creationflags=new_group,
            env=merged_env,
        )
    return subprocess.Popen(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        start_new_session=True,
        env=merged_env,
    )


def _start_process(
    command: list[str], cwd: Path | str, env: Mapping[str, str] | None = None
) -> subprocess.Popen[str]:
    """Start the tool in its own process group so the whole tree can be killed.

    ``env`` entries are overlaid on the current environment (they extend it,
    never replace it), so tool discovery via PATH keeps working.
    """
    merged_env = {**os.environ, **env} if env else None
    if os.name == "nt":  # pragma: no cover - exercised on Windows only.
        new_group = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        return subprocess.Popen(
            command,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=new_group,
            env=merged_env,
        )
    # POSIX: a new session makes the child a process-group leader, so we can signal
    # the entire group (the tool and everything it spawns) on timeout.
    return subprocess.Popen(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
        env=merged_env,
    )


def _signal_group(process: subprocess.Popen[Any], sig: int) -> bool:
    """Send ``sig`` to the child's process group (POSIX, pid == pgid).

    Returns ``False`` only when we lack permission to signal the group — in which
    case it best-effort kills the direct child — and ``True`` when the signal was
    delivered or the group is already gone.
    """
    try:
        os.killpg(process.pid, sig)
    except ProcessLookupError:
        return True  # Group already gone.
    except PermissionError:
        # Rare (child changed credentials): fall back to the direct child.
        try:
            process.kill()
        except OSError:
            pass
        return False
    return True


def _terminate_process_tree(process: subprocess.Popen[Any]) -> bool:
    """Kill the process and everything it spawned. Bounded and idempotent.

    Returns:
        ``True`` when the whole process group was signalled and the child reaped
        (a clean teardown with no expected strays). ``False`` when the teardown is
        not fully accounted for — the child is still running after SIGKILL, or we
        lacked permission to signal the group — so the caller can warn that stray
        processes may still be running.
    """
    if os.name == "posix":
        # ``_start_process`` uses ``start_new_session=True``, so the child is its
        # own process-group leader and its PID *is* the group id. Signal the group
        # via ``process.pid`` directly rather than ``os.getpgid()``: if the leader
        # has just exited, ``getpgid`` would raise and we would skip killing the
        # still-running grandchildren in the group. (Invariant: pid == pgid; do not
        # change ``_start_process`` to drop the new session without revisiting this.)
        #
        # SIGTERM the group for a graceful shutdown, then *always* SIGKILL the group
        # — even if the direct child already exited — because a grandchild that
        # ignored SIGTERM would otherwise survive un-killed. On a (rare)
        # PermissionError, `_signal_group` has best-effort killed the direct child;
        # skip the group SIGKILL (it would fail the same way) but still fall through
        # to reap so we never leak an unreaped child.
        group_signalled = _signal_group(process, signal.SIGTERM)
        if group_signalled:
            try:
                process.wait(timeout=_TERM_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                pass  # Did not exit gracefully; SIGKILL below.
            _signal_group(process, signal.SIGKILL)
        try:
            process.wait(timeout=_KILL_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            return False  # Stuck (e.g. uninterruptible-sleep `D` state); give up.
        # Reaped: report True only if we could actually signal the whole group.
        return group_signalled
    else:  # pragma: no cover - exercised on Windows only.
        # `Popen.kill()` only kills the direct child on Windows; taskkill /T walks
        # the tree.
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                check=False,
                capture_output=True,
            )
        except OSError:
            process.kill()
        try:
            process.wait(timeout=_KILL_GRACE_SECONDS)
            return True
        except subprocess.TimeoutExpired:
            process.kill()
            return False


def _drain_after_kill(process: subprocess.Popen[Any]) -> tuple[str, str, bool]:
    """Collect output buffered before the tree was killed, strictly bounded.

    Returns ``(stdout, stderr, abandoned)``. A grandchild that escaped the process
    group (e.g. it called ``setsid`` or was moved to another group) can keep a copy
    of the stdout/stderr write-ends open, so the parent's read-ends would never see
    EOF. We therefore wait only up to the grace period and then give up rather than
    block forever — the timeout path must itself stay bounded — signalling
    ``abandoned=True`` so the caller can note the truncation.
    """
    try:
        stdout_raw, stderr_raw = process.communicate(timeout=_KILL_GRACE_SECONDS)
        stdout = "" if stdout_raw is None else str(stdout_raw)
        stderr = "" if stderr_raw is None else str(stderr_raw)
        return stdout, stderr, False
    except subprocess.TimeoutExpired:
        # Closing the read-ends unblocks the abandoned drain. This is only done on
        # POSIX, where ``communicate`` selects in this thread; on Windows reader
        # threads own the pipes (and ``taskkill /T`` already killed the tree, so
        # this branch is effectively unreachable there).
        if os.name == "posix":
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass
        return "", "", True
