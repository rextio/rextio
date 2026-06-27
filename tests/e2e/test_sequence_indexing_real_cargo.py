from __future__ import annotations

import importlib
import json
import shutil
import sys
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

@rextio.native
def lookup(scores: dict[int, float], keys: list[int], i: int) -> float:
    return scores[keys[i]]

@rextio.native
def count_seq(xs: list[int], ys: list[int], i: int) -> int:
    return xs.count(ys[i])

@rextio.native
def nested(rows: list[int], idx: list[int], i: int) -> int:
    return rows[idx[i]]
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

    # Force the native path so a native runtime fault raises instead of silently
    # falling back to Python (which would mask codegen bugs).
    monkeypatch.setenv("REXTIO_NATIVE_MODE", "native")
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    # The generated native extension is always named `_rextio_native`; evict any
    # build cached by a previous e2e so this build's module is loaded fresh.
    for module_name in ("_rextio_native", "index_app.seq_ops", "index_app._fallback_seq_ops"):
        sys.modules.pop(module_name, None)
    importlib.invalidate_caches()
    module = importlib.import_module("index_app.seq_ops")

    xs = [10, 20, 30]
    # Differential check against CPython semantics, including negative indexing.
    for i in (0, 1, 2, -1, -2, -3):
        assert module.at(xs, i) == xs[i], f"native at(xs, {i}) diverged from Python"

    # Out-of-range (positive and negative, incl. -len-1) raises IndexError, not a panic.
    for bad in (3, 100, -4, -97):
        with pytest.raises(IndexError):
            module.at(xs, bad)

    # Empty list: any index raises IndexError.
    for bad in (0, -1):
        with pytest.raises(IndexError):
            module.at([], bad)

    # Closure-composition cases that previously failed to compile (B3): a `?`-bearing
    # sequence index embedded inside a dict KeyError closure / list.count predicate /
    # another index, now hoisted out of the closure.
    assert module.lookup({1: 1.5, 2: 2.5}, [2, 1], 0) == 2.5  # scores[keys[0]] = scores[2]
    assert module.lookup({1: 1.5, 2: 2.5}, [2, 1], -1) == 1.5  # scores[keys[-1]] = scores[1]
    assert module.count_seq([1, 2, 2, 3], [2], 0) == 2  # xs.count(ys[0]) = count of 2
    assert module.nested([10, 20, 30], [2, 0, -1], 0) == 30  # rows[idx[0]] = rows[2]
    assert module.nested([10, 20, 30], [2, 0, -1], 2) == 30  # rows[idx[-1]] = rows[-1]
    with pytest.raises(IndexError):
        module.nested([10, 20, 30], [5], 0)  # rows[idx[0]] = rows[5] -> IndexError
