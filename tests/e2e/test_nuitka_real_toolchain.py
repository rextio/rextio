from __future__ import annotations

import importlib
import json
import shutil
import sys
from pathlib import Path

import pytest

from rextio.cli.main import main


@pytest.mark.skipif(shutil.which("nuitka") is None, reason="nuitka is required for fallback e2e")
def test_nuitka_fallback_build_records_real_compiled_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[policy]
native_marker = "decorator"
""",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        """
def add(a: int, b: int) -> int:
    return a + b
""",
        encoding="utf-8",
    )

    exit_code = main(["build", str(tmp_path), "--fallback=nuitka"])

    captured = capsys.readouterr()
    build_python = tmp_path / ".rextio" / "build" / "python"
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )

    assert exit_code == 0
    assert "fallback: nuitka" in captured.out
    assert report["native_build"]["status"] == "skipped"
    assert report["fallback_build"]["status"] == "built"
    assert report["fallback_build"]["compiled_artifacts"]
    for artifact in report["fallback_build"]["compiled_artifacts"]:
        assert Path(artifact).exists()

    monkeypatch.syspath_prepend(str(build_python))
    importlib.invalidate_caches()
    sys.modules.pop("app", None)

    module = importlib.import_module("app")

    assert module.add(2, 3) == 5
