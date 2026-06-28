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

import os
import signal
import subprocess
from pathlib import Path

# Generous upper bound: a real cargo/maturin/nuitka build can take minutes, but
# should never run for ten minutes in CI or a developer loop without something
# being wrong.
DEFAULT_BUILD_TIMEOUT_SECONDS = 600

# Conventional exit code for "terminated by timeout" (matches GNU `timeout(1)`),
# used for the synthetic CompletedProcess returned on timeout.
TIMEOUT_EXIT_CODE = 124

# Grace period (seconds) for a killed process tree to be reaped before we give up
# collecting its buffered output.
_REAP_GRACE_SECONDS = 10


def run_build_tool(
    command: list[str],
    *,
    cwd: Path | str,
    timeout: float | None = DEFAULT_BUILD_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[str]:
    """Run an external build tool with no shell, captured output, and a timeout.

    ``command`` must be an argument list (enforces ``shell=False``). The tool runs
    in its own process group so a timeout terminates the whole tree. Returns the
    completed process; on timeout, returns a synthetic process with a non-zero
    return code (:data:`TIMEOUT_EXIT_CODE`) and an explanatory stderr.
    """
    with _start_process(command, cwd) as process:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
        except subprocess.TimeoutExpired:
            _terminate_process_tree(process)
            stdout, stderr = _drain_after_kill(process)
            tool = command[0] if command else "build tool"
            timeout_note = f"rextio: `{tool}` timed out after {timeout:g}s and was terminated."
            stderr = (f"{stderr}\n" if stderr else "") + timeout_note
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


def _terminate_process_tree(process: subprocess.Popen[str]) -> None:
    """Kill the process and everything it spawned, best-effort and idempotent."""
    if os.name == "posix":
        # With ``start_new_session=True`` the child is its own process-group
        # leader, so its PID *is* the group id. Signal the group via ``process.pid``
        # directly rather than ``os.getpgid()``: if the leader has just exited,
        # ``getpgid`` would raise and we would skip killing the still-running
        # grandchildren in the group.
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(process.pid, sig)
            except (ProcessLookupError, PermissionError):
                return  # Group already gone (or not ours to signal).
            try:
                # Bounded on both passes: never block unboundedly even after
                # SIGKILL (a process can sit in uninterruptible-sleep `D` state).
                process.wait(timeout=_REAP_GRACE_SECONDS)
                return
            except subprocess.TimeoutExpired:
                continue  # Escalate SIGTERM -> SIGKILL, then give up.
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
            process.wait(timeout=_REAP_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()


def _drain_after_kill(process: subprocess.Popen[str]) -> tuple[str, str]:
    """Collect any output buffered before the tree was killed, strictly bounded.

    A grandchild that escaped the process group (e.g. it called ``setsid`` or was
    moved to another group) can keep a copy of the stdout/stderr write-ends open,
    so the parent's read-ends would never see EOF. We therefore wait only up to
    the grace period and then abandon the buffered tail by closing the pipes,
    rather than block forever — the timeout path must itself stay bounded.
    """
    try:
        stdout, stderr = process.communicate(timeout=_REAP_GRACE_SECONDS)
        return stdout or "", stderr or ""
    except subprocess.TimeoutExpired:
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        return "", ""
