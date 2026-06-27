from __future__ import annotations

import importlib
import json
import shutil
from pathlib import Path

import pytest

from rextio.cli.main import main


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_real_cargo_sequence_indexing_matches_python_semantics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[rust]
build_tool = "cargo"
""",
        encoding="utf-8",
    )
    source = tmp_path / "src" / "index_app" / "seq_ops.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
import rextio

@rextio.native
def at(xs: list[int], i: int) -> int:
    return xs[i]
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

    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    importlib.invalidate_caches()
    module = importlib.import_module("index_app.seq_ops")

    xs = [10, 20, 30]
    # Differential check against CPython semantics for the same inputs.
    for i in (0, 1, 2, -1, -2, -3):
        assert module.at(xs, i) == xs[i], f"native at(xs, {i}) diverged from Python"

    # Out-of-range (positive and negative) raises IndexError, not a panic.
    for bad in (3, 100, -4):
        with pytest.raises(IndexError):
            module.at(xs, bad)
