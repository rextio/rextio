from __future__ import annotations

import sys

from rextio.build.subprocess_utils import run_build_tool


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


def test_run_build_tool_does_not_use_a_shell(tmp_path) -> None:
    # Arguments are passed as a list, so shell metacharacters are literal, not
    # interpreted — `$(...)` is just an argument, never a command substitution.
    result = run_build_tool(
        [sys.executable, "-c", "import sys; print(sys.argv[1])", "$(echo pwned)"],
        cwd=tmp_path,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "$(echo pwned)"
