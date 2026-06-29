from __future__ import annotations

import importlib
import json
import shutil
import sys
from pathlib import Path

import pytest

from rextio.cli.main import main


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_real_cargo_is_none_against_optional(
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
    source = tmp_path / "src" / "none_app" / "ops.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
import rextio

@rextio.native
def is_none(x: int | None) -> bool:
    return x is None

@rextio.native
def is_not_none(x: str | None) -> bool:
    return x is not None
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
    for cached in ("_rextio_native", "none_app", "none_app.ops"):
        sys.modules.pop(cached, None)
    importlib.invalidate_caches()
    module = importlib.import_module("none_app.ops")

    assert module.is_none(None) is True
    assert module.is_none(5) is False
    assert module.is_not_none("hi") is True
    assert module.is_not_none(None) is False
