from __future__ import annotations

import importlib
import json
import shutil
from pathlib import Path

import pytest

from rextio.cli.main import main


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_real_cargo_build_handles_context_and_pyi_type_inference(
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
    package = tmp_path / "src" / "infer_app"
    package.mkdir(parents=True)
    (package / "context_ops.py").write_text(
        """
def add_one(x):
    return x + 1

def sum_squares(xs):
    total = 0
    for x in xs:
        total += x * x
    return total
""",
        encoding="utf-8",
    )
    (package / "stub_ops.py").write_text(
        """
def dot(xs, ys):
    total = 0.0
    for x, y in zip(xs, ys):
        total += x * y
    return total
""",
        encoding="utf-8",
    )
    (package / "stub_ops.pyi").write_text(
        """
def dot(xs: list[float], ys: list[float]) -> float: ...
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
    assert report["accepted_native_count"] == 3

    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    importlib.invalidate_caches()
    context_ops = importlib.import_module("infer_app.context_ops")
    stub_ops = importlib.import_module("infer_app.stub_ops")

    assert context_ops.add_one(4) == 5
    assert context_ops.sum_squares([2, 3, 4]) == 29
    assert stub_ops.dot([1.5, 2.0], [2.0, 3.0]) == 9.0
