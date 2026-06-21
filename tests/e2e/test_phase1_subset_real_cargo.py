from __future__ import annotations

import importlib
import json
import math
import shutil
from pathlib import Path

import pytest

from rextio.cli.main import main


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_real_cargo_build_handles_phase1_subset_expansion(
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
    source = tmp_path / "src" / "phase1_app" / "math_ops.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
import math
import rextio

@rextio.native
def collect_odds(n: int) -> list[int]:
    out: list[int] = []
    for i in range(1, n, 2):
        if i > 7:
            break
        if i == 5:
            continue
        out.append(i)
    return out

@rextio.native
def labels() -> list[str]:
    return ["ready", "set"]

@rextio.native
def numeric(values: list[float], x: float) -> float:
    total: float = sum(values)
    total += math.sqrt(x)
    total += math.sin(x)
    total += math.cos(x)
    total += max(abs(x), 1.0)
    return total

@rextio.native
def lower(x: float, y: float) -> int:
    return min(math.floor(x), math.floor(y))
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
    module = importlib.import_module("phase1_app.math_ops")

    assert module.collect_odds(10) == [1, 3, 7]
    assert module.labels() == ["ready", "set"]
    assert module.lower(3.8, 4.2) == 3
    assert module.numeric([1.0, 2.0], 4.0) == pytest.approx(
        3.0 + math.sqrt(4.0) + math.sin(4.0) + math.cos(4.0) + max(abs(4.0), 1.0)
    )
