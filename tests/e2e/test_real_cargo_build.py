from __future__ import annotations

import importlib
import json
import shutil
import sys
from pathlib import Path

import pytest

from rextio.cli.main import main


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_real_cargo_build_imports_native_and_preserves_fallback(
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
    source = tmp_path / "src" / "e2e_app" / "math_ops.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
import rextio

@rextio.native
def add(a: int, b: int) -> int:
    return a + b

def helper(x: int) -> int:
    return x + 10

@rextio.native
def rejected(x: int) -> int:
    return helper(x)
""",
        encoding="utf-8",
    )

    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])

    capsys.readouterr()
    build_python = tmp_path / ".rextio" / "build" / "python"
    build_report = tmp_path / ".rextio" / "reports" / "build.json"
    report = json.loads(build_report.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert report["accepted_native_count"] == 1
    assert report["rejected_native_count"] == 1
    assert report["native_build"]["tool"] == "cargo"
    assert report["native_build"]["status"] == "built"
    assert Path(report["native_build"]["installed_path"]).exists()

    monkeypatch.syspath_prepend(str(build_python))
    importlib.invalidate_caches()
    for module_name in ("_rextio_native", "e2e_app.math_ops", "e2e_app._fallback_math_ops"):
        sys.modules.pop(module_name, None)

    native_module = importlib.import_module("_rextio_native")
    assert native_module.e2e_app__math_ops__add(2, 3) == 5

    module = importlib.import_module("e2e_app.math_ops")
    assert module.add(2, 3) == 5
    assert module.rejected(5) == 15

    monkeypatch.setattr(module, "_native_add", lambda a, b: a + b + 100)
    assert module.add(2, 3) == 105

    monkeypatch.setenv("REXTIO_DISABLE_NATIVE", "1")
    assert module.add(2, 3) == 5
