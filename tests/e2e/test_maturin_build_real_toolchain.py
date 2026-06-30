from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

from rextio.cli.main import main


def test_real_maturin_build_produces_native_module(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # The conftest skips this when maturin/cargo are unavailable; in CI the
    # `maturin-e2e` job installs `.[build]` so the real maturin path is gated.
    (tmp_path / "rextio.toml").write_text(
        """
[rust]
build_tool = "maturin"
""",
        encoding="utf-8",
    )
    source = tmp_path / "src" / "maturin_app" / "ops.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
import rextio

@rextio.native
def add(a: int, b: int) -> int:
    return a + b
""",
        encoding="utf-8",
    )

    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])

    capsys.readouterr()
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )

    assert exit_code == 0
    assert report["native_build"]["status"] == "built"
    assert report["native_build"]["tool"] == "maturin"

    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    importlib.invalidate_caches()
    module = importlib.import_module("maturin_app.ops")
    assert module.add(2, 3) == 5
