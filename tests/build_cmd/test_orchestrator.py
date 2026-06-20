from __future__ import annotations

import json
from pathlib import Path

from rextio.cli.main import main


def test_build_generates_rust_project_for_accepted_native_only(tmp_path: Path, capsys) -> None:
    (tmp_path / "app.py").write_text(
        """
import rextio

@rextio.native
def add(a: int, b: int) -> int:
    return a + b

def helper(x: int) -> int:
    return x + 1

@rextio.native
def rejected(x: int) -> int:
    return helper(x)
""",
        encoding="utf-8",
    )

    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])

    captured = capsys.readouterr()
    rust_dir = tmp_path / ".rextio" / "generated" / "rust"
    lib_rs = rust_dir / "src" / "lib.rs"
    build_report = tmp_path / ".rextio" / "reports" / "build.json"

    assert exit_code == 0
    assert "generated Rust project" in captured.out
    assert (rust_dir / "Cargo.toml").exists()
    assert (rust_dir / "pyproject.toml").exists()
    assert lib_rs.exists()
    assert "fn add(a: i64, b: i64) -> PyResult<i64>" in lib_rs.read_text(encoding="utf-8")
    assert "fn rejected" not in lib_rs.read_text(encoding="utf-8")
    data = json.loads(build_report.read_text(encoding="utf-8"))
    assert data["status"] == "generated"
    assert data["accepted_native_count"] == 1
    assert data["rejected_native_count"] == 1
