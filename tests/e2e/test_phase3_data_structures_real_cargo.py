from __future__ import annotations

import importlib
import json
import shutil
from pathlib import Path

import pytest

from rextio.cli.main import main


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_real_cargo_build_handles_phase3_limited_data_structures(
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
    source = tmp_path / "src" / "phase3_app" / "data_ops.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
from typing import Optional
import rextio

@rextio.native
def first_value(pair: tuple[int, float]) -> int:
    return pair[0]

@rextio.native
def make_pair(x: int, y: float) -> tuple[int, float]:
    return (x, y)

@rextio.native
def build_scores() -> dict[str, int]:
    scores: dict[str, int] = {}
    scores["a"] = 3
    scores["b"] = 5
    return scores

@rextio.native
def read_score(scores: dict[str, int], key: str) -> int:
    return scores[key]

@rextio.native
def maybe(flag: bool, x: int) -> Optional[int]:
    if flag:
        return x
    return None

@rextio.native
def echo(value: int | None) -> int | None:
    if value is None:
        return None
    return value
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
    module = importlib.import_module("phase3_app.data_ops")

    assert module.first_value((7, 2.5)) == 7
    assert module.make_pair(4, 1.5) == (4, 1.5)
    assert module.build_scores() == {"a": 3, "b": 5}
    assert module.read_score({"a": 9}, "a") == 9
    assert module.maybe(True, 11) == 11
    assert module.maybe(False, 11) is None
    assert module.echo(None) is None
    assert module.echo(6) == 6
