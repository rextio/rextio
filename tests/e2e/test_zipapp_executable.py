from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from rextio.cli.main import main


def test_zipapp_executable_runs_generated_hybrid_package(
    tmp_path: Path,
    capsys,
    fake_cargo: Path,
) -> None:
    package = tmp_path / "src" / "zipapp_app"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "cli.py").write_text(
        """
import rextio

@rextio.native
def add(a: int, b: int) -> int:
    return a + b

def main() -> int:
    print(add(2, 3))
    return 0
""",
        encoding="utf-8",
    )

    exit_code = main(
        [
            "build",
            str(tmp_path),
            "--fallback=cpython",
            "--entrypoint=zipapp_app.cli:main",
            "--executable-name=zipapp-demo",
        ]
    )

    capsys.readouterr()
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )
    executable = tmp_path / "dist" / "zipapp-demo.pyz"

    assert exit_code == 0
    assert report["executable_build"]["status"] == "built"
    assert report["executable_build"]["path"] == str(executable)
    completed = subprocess.run(
        [sys.executable, str(executable)],
        check=True,
        capture_output=True,
        text=True,
    )
    assert completed.stdout.strip() == "5"
