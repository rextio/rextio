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
import signal
import subprocess
from pathlib import Path

# Generous upper bound: a real cargo/maturin/nuitka build can take minutes, but
# should never run for ten minutes in CI or a developer loop without something
# being wrong.
DEFAULT_BUILD_TIMEOUT_SECONDS = 600

# A finite but absurd timeout (e.g. 1e100) both effectively disables the bound and
# overflows the timeout plumbing: POSIX `select` raises `OverflowError: timestamp
# too large to convert to C PyTime_t`, and Windows `WaitForSingleObject` takes
# milliseconds as a `DWORD` (max ~4.29e9 ms ≈ 49.7 days). 7 days is comfortably
# below the Windows millisecond limit yet far past any sane build, so it is a
# cross-platform-safe ceiling; beyond it, a build timeout is a config mistake.
MAX_BUILD_TIMEOUT_SECONDS = 604_800  # 7 days

# Conventional exit code for "terminated by timeout" (matches GNU `timeout(1)`),
# used for the synthetic CompletedProcess returned on timeout.
TIMEOUT_EXIT_CODE = 124

# Grace periods (seconds) for the timeout-cleanup path. Kept short because the
# build has *already* exceeded its (much larger) timeout by the time we get here.
_TERM_GRACE_SECONDS = 5  # let SIGTERM land + the tool clean up, then escalate
_KILL_GRACE_SECONDS = 3  # reap after SIGKILL / drain the pipes, then give up


def run_build_tool(
    command: list[str],
    *,
    cwd: Path | str,
    timeout: float = DEFAULT_BUILD_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[str]:
    """Run an external build tool with no shell, captured output, and a timeout.

    ``command`` must be an argument list (enforces ``shell=False``). The tool runs
    in its own process group so a timeout terminates the whole tree. Returns the
    completed process; on timeout, returns a synthetic process with a non-zero
    return code (:data:`TIMEOUT_EXIT_CODE`) and an explanatory stderr.
    """
    # Validate/clamp at this reusable entry point (config/env/CLI already do for
    # real callers; this guards direct callers and tests). The type guard comes
    # first so `None`/`str`/`Decimal` fail with a clear ValueError rather than a
    # `TypeError` inside `math`, and `bool` (a subclass of `int`) is rejected rather
    # than silently treated as a 0/1-second timeout. Reject non-positive values
    # (they fail the build instantly) and clamp `inf`/over-cap down to the maximum.
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool):
        raise ValueError(f"build timeout must be a positive number, got {timeout!r}")
    if math.isnan(timeout) or timeout <= 0:
        raise ValueError(f"build timeout must be a positive number, got {timeout!r}")
    if timeout > MAX_BUILD_TIMEOUT_SECONDS:
        timeout = float(MAX_BUILD_TIMEOUT_SECONDS)
    with _start_process(command, cwd) as process:
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


def _start_process(command: list[str], cwd: Path | str) -> subprocess.Popen[str]:
    """Start the tool in its own process group so the whole tree can be killed."""
    if os.name == "nt":  # pragma: no cover - exercised on Windows only.
        new_group = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        return subprocess.Popen(
            command,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=new_group,
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
    )


def _terminate_process_tree(process: subprocess.Popen[str]) -> bool:
    """Kill the process and everything it spawned. Bounded and idempotent.

    Returns ``True`` if the direct child was confirmed gone/reaped, ``False`` if we
    had to give up (still running after SIGKILL, or no permission to signal it) so
    the caller can surface that in diagnostics.
    """
    if os.name == "posix":
        # ``_start_process`` uses ``start_new_session=True``, so the child is its
        # own process-group leader and its PID *is* the group id. Signal the group
        # via ``process.pid`` directly rather than ``os.getpgid()``: if the leader
        # has just exited, ``getpgid`` would raise and we would skip killing the
        # still-running grandchildren in the group. (Invariant: pid == pgid; do not
        # change ``_start_process`` to drop the new session without revisiting this.)
        for sig, grace in ((signal.SIGTERM, _TERM_GRACE_SECONDS), (signal.SIGKILL, _KILL_GRACE_SECONDS)):
            try:
                os.killpg(process.pid, sig)
            except ProcessLookupError:
                return True  # Group already gone.
            except PermissionError:
                # Cannot signal the group (rare: child changed credentials). Fall
                # back to killing at least the direct child so it does not linger.
                try:
                    process.kill()
                except OSError:
                    pass
                return False
            try:
                process.wait(timeout=grace)
                return True
            except subprocess.TimeoutExpired:
                continue  # Escalate SIGTERM -> SIGKILL, then give up.
        return False  # SIGKILL did not reap within the grace period.
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


def _drain_after_kill(process: subprocess.Popen[str]) -> tuple[str, str, bool]:
    """Collect output buffered before the tree was killed, strictly bounded.

    Returns ``(stdout, stderr, abandoned)``. A grandchild that escaped the process
    group (e.g. it called ``setsid`` or was moved to another group) can keep a copy
    of the stdout/stderr write-ends open, so the parent's read-ends would never see
    EOF. We therefore wait only up to the grace period and then give up rather than
    block forever — the timeout path must itself stay bounded — signalling
    ``abandoned=True`` so the caller can note the truncation.
    """
    try:
        stdout, stderr = process.communicate(timeout=_KILL_GRACE_SECONDS)
        return stdout or "", stderr or "", False
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
