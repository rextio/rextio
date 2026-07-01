from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from rextio.cli.main import main


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for the Rust executable e2e")
def test_real_cargo_builds_rust_main_executable_and_it_runs(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[rust]
build_tool = "cargo"
""",
        encoding="utf-8",
    )
    source = tmp_path / "src" / "cli_app" / "run.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
import rextio

@rextio.native
def helper(argv: list[str]) -> int:
    return len(argv)

@rextio.native
def main(argv: list[str]) -> int:
    # Body may print (lowered to println! in the native binary), and the entry
    # calls another direct-native function (the graph is fully native).
    print("rextio native binary")
    return helper(argv) - 1
""",
        encoding="utf-8",
    )

    exit_code = main(
        [
            "build",
            str(tmp_path),
            "--fallback=cpython",
            "--executable-backend=rust",
            "--entrypoint=cli_app.run:main",
        ]
    )
    assert exit_code == 0
    capsys.readouterr()

    report = json.loads((tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8"))
    executable = report["executable_build"]
    assert executable["status"] == "built", executable
    assert executable["backend"] == "rust"

    binary = Path(executable["path"])
    assert binary.exists()

    # The binary is a standalone native executable: run it and check argv handling,
    # stdout, and the exit code (len(argv) - 1 == the number of extra arguments).
    completed = subprocess.run(
        [str(binary), "one", "two", "three"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert "rextio native binary" in completed.stdout
    assert completed.returncode == 3

    empty = subprocess.run([str(binary)], capture_output=True, text=True, timeout=60)
    assert empty.returncode == 0
