from __future__ import annotations

import importlib
import json
import shutil
from pathlib import Path

import pytest

from rextio.cli.main import main


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_real_cargo_build_handles_phase2_batch_region_subset(
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
    source = tmp_path / "src" / "phase2_app" / "batch_ops.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
import rextio

@rextio.native
def double_value(x: int) -> int:
    return x * 2

@rextio.native
def indexed_doubles(xs: list[int]) -> list[int]:
    out: list[int] = []
    for i, x in enumerate(xs):
        out.append(double_value(x) + i)
    return out

@rextio.native
def dot_zip(xs: list[float], ys: list[float]) -> float:
    total = 0.0
    for x, y in zip(xs, ys):
        total += x * y
    return total
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
    module = importlib.import_module("phase2_app.batch_ops")

    assert module.indexed_doubles([3, 4, 5]) == [6, 9, 12]
    assert module.dot_zip([1.0, 2.0, 3.0], [4.0, 5.0]) == pytest.approx(14.0)
