from __future__ import annotations

import json
from pathlib import Path

from rextio.cli.main import main


def test_generate_writes_sources_without_running_rust_or_nuitka_builds(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setenv("PATH", "")
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

    exit_code = main(["generate", str(tmp_path), "--fallback=nuitka"])

    captured = capsys.readouterr()
    rust_dir = tmp_path / ".rextio" / "generated" / "rust"
    python_dir = tmp_path / ".rextio" / "generated" / "python"
    rust_source = rust_dir / "src" / "lib.rs"
    wrapper = python_dir / "app.py"
    fallback = python_dir / "_fallback_app.py"
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "generate.json").read_text(encoding="utf-8")
    )

    assert exit_code == 0
    assert "Rextio generate" in captured.out
    assert "fallback: nuitka" in captured.out
    assert "native source: generated" in captured.out
    assert report["status"] == "generated"
    assert report["fallback"] == "nuitka"
    assert report["native_source"]["status"] == "generated"
    assert report["accepted_native_count"] == 1
    assert report["rejected_native_count"] == 1
    assert rust_source.exists()
    assert "fn app__add(a: i64, b: i64) -> PyResult<i64>" in rust_source.read_text(
        encoding="utf-8"
    )
    assert "fn rejected" not in rust_source.read_text(encoding="utf-8")
    assert wrapper.exists()
    assert fallback.exists()
    assert "def add(a: int, b: int) -> int:" in wrapper.read_text(encoding="utf-8")
    assert "def rejected" in fallback.read_text(encoding="utf-8")
    assert not (tmp_path / ".rextio" / "build").exists()
    assert not (tmp_path / "dist").exists()
    assert not list(tmp_path.rglob("*.so"))
