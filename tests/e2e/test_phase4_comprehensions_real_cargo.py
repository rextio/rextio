from __future__ import annotations

import importlib
import json
import shutil
from pathlib import Path

import pytest

from rextio.cli.main import main


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_real_cargo_build_handles_phase4_comprehensions(
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
    source = tmp_path / "src" / "phase4_app" / "ops.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
import rextio

@rextio.native
def inc(x: int) -> int:
    return x + 1

@rextio.native
def squares(xs: list[int]) -> list[int]:
    return [inc(x) for x in xs if x > 0]

@rextio.native
def indexed(xs: list[int]) -> list[int]:
    return [i + x for i, x in enumerate(xs)]

@rextio.native
def zipped(xs: list[int], ys: list[int]) -> list[int]:
    return [x + y for x, y in zip(xs, ys)]

@rextio.native
def ranged(n: int) -> list[int]:
    return [i for i in range(1, n, 2)]

@rextio.native
def flatten(rows: list[list[int]]) -> list[int]:
    return [x for row in rows for x in row]

@rextio.native
def nested(rows: list[list[int]]) -> list[list[int]]:
    return [[x + 1 for x in row] for row in rows]

@rextio.native
def labels(xs: list[str]) -> dict[str, str]:
    return {x: x for x in xs}

@rextio.native
def lookup(scores: dict[str, int], xs: list[str]) -> list[int]:
    return [scores[x] for x in xs]

@rextio.native
def unique(xs: list[int]) -> set[int]:
    return {x for x in xs if x > 0}

@rextio.native
def last_positive(xs: list[int]) -> int:
    out = [y for x in xs if (y := x) > 0]
    return y
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
    assert report["accepted_native_count"] == 11

    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    importlib.invalidate_caches()
    module = importlib.import_module("phase4_app.ops")

    assert module.squares([-1, 2, 3]) == [3, 4]
    assert module.indexed([3, 4]) == [3, 5]
    assert module.zipped([1, 2], [10, 20]) == [11, 22]
    assert module.ranged(6) == [1, 3, 5]
    assert module.flatten([[1, 2], [3]]) == [1, 2, 3]
    assert module.nested([[1], [2, 3]]) == [[2], [3, 4]]
    assert module.labels(["a", "b"]) == {"a": "a", "b": "b"}
    assert module.lookup({"a": 1, "b": 2}, ["b", "a"]) == [2, 1]
    assert module.unique([-1, 1, 1, 2]) == {1, 2}
    assert module.last_positive([-1, 0, 5]) == 5
