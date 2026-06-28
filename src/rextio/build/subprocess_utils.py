"""Hardened subprocess execution for external build tools.

Rextio shells out to `cargo`, `maturin`, `nuitka`, etc. All invocations:

* pass the command as an argument **list** (never a shell string), so there is no
  shell interpolation/injection of user-derived paths or names;
* capture stdout/stderr as text so failures become diagnostics rather than noise
  on the user's terminal;
* run under a bounded **timeout**, so a hung or wedged toolchain fails the build
  with a clear message instead of blocking indefinitely.

On timeout the helper returns a synthetic *failed* ``CompletedProcess`` (non-zero
return code, an explanatory stderr) so existing return-code-based failure
handling reports it like any other tool failure.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

# Generous upper bound: a real cargo/maturin/nuitka build can take minutes, but
# should never run for ten minutes in CI or a developer loop without something
# being wrong.
DEFAULT_BUILD_TIMEOUT_SECONDS = 600


def run_build_tool(
    command: list[str],
    *,
    cwd: Path | str,
    timeout: float | None = DEFAULT_BUILD_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[str]:
    """Run an external build tool with no shell, captured output, and a timeout.

    ``command`` must be an argument list (enforces ``shell=False``). Returns the
    completed process; on timeout, returns a synthetic process with a non-zero
    return code and an explanatory stderr.
    """
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as expired:
        stdout = expired.stdout or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", "replace")
        stderr = expired.stderr or ""
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", "replace")
        tool = command[0] if command else "build tool"
        stderr = (
            f"{stderr}\n" if stderr else ""
        ) + f"rextio: `{tool}` timed out after {timeout:g}s and was terminated."
        return subprocess.CompletedProcess(command, returncode=124, stdout=stdout, stderr=stderr)
