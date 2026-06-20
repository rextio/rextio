from __future__ import annotations

import importlib
import json
import shutil
from pathlib import Path

import pytest

from rextio.cli.main import main


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_real_cargo_build_handles_native_calls_with_reused_list_arguments(
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
    source = tmp_path / "src" / "ownership_app" / "math_ops.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
import rextio

@rextio.native
def total(values: list[float]) -> float:
    result = 0.0
    for value in values:
        result += value
    return result

@rextio.native
def compute(values: list[float]) -> float:
    subtotal = total(values)
    return subtotal + values[0]
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
    module = importlib.import_module("ownership_app.math_ops")

    assert module.compute([1.0, 2.0, 3.0]) == 7.0
