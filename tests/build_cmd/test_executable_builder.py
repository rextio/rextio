from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path

from rextio.build.executable_builder import build_zipapp_executable


def test_build_zipapp_executable_runs_entrypoint(tmp_path: Path) -> None:
    python_dir = tmp_path / "python"
    dist_dir = tmp_path / "dist"
    package = python_dir / "demo_app"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "cli.py").write_text(
        """
def main() -> int:
    print("hello from zipapp")
    return 0
""",
        encoding="utf-8",
    )

    result = build_zipapp_executable(
        python_dir,
        dist_dir,
        entrypoint="demo_app.cli:main",
        executable_name="demo-tool",
    )

    assert result.status == "built"
    assert result.entrypoint == "demo_app.cli:main"
    executable = Path(result.path or "")
    assert executable == dist_dir / "demo-tool.pyz"
    assert executable.exists()
    with zipfile.ZipFile(executable) as archive:
        assert "__main__.py" in archive.namelist()
        assert "demo_app/cli.py" in archive.namelist()

    completed = subprocess.run(
        [sys.executable, str(executable)],
        check=True,
        capture_output=True,
        text=True,
    )
    assert completed.stdout.strip() == "hello from zipapp"


def test_build_zipapp_executable_skips_without_entrypoint(tmp_path: Path) -> None:
    result = build_zipapp_executable(tmp_path / "python", tmp_path / "dist", entrypoint=None)

    assert result.status == "skipped"
    assert result.path is None
    assert result.entrypoint is None


def test_build_zipapp_executable_rejects_invalid_entrypoint(tmp_path: Path) -> None:
    python_dir = tmp_path / "python"
    python_dir.mkdir()

    result = build_zipapp_executable(
        python_dir,
        tmp_path / "dist",
        entrypoint="not-a-module",
    )

    assert result.status == "failed"
    assert "Use module:function" in result.message


def test_build_zipapp_executable_reports_missing_python_artifact(tmp_path: Path) -> None:
    result = build_zipapp_executable(
        tmp_path / "missing",
        tmp_path / "dist",
        entrypoint="demo.cli:main",
    )

    assert result.status == "failed"
    assert "Python build artifact was missing" in result.message
