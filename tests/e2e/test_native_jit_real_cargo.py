from __future__ import annotations

import importlib
import json
import shutil
import sys
from pathlib import Path

import pytest

from rextio.cli.main import main


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_embedded_helper_compiles_and_runs_when_enabled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[rust]
build_tool = "cargo"

[policy]
native_marker = "decorator"

[jit]
enabled = true
""",
        encoding="utf-8",
    )
    source = tmp_path / "src" / "jit_app" / "math_ops.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
import rextio

def helper(x: float) -> float:
    return x * 2.0

@rextio.native
def compute(x: float) -> float:
    return helper(x) + 1.0
""",
        encoding="utf-8",
    )

    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])

    capsys.readouterr()
    build_python = tmp_path / ".rextio" / "build" / "python"
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )
    lib_rs = (
        tmp_path / ".rextio" / "generated" / "rust" / "src" / "lib.rs"
    ).read_text(encoding="utf-8")

    assert exit_code == 0
    assert report["native_build"]["status"] == "built"
    assert report["accepted_native_count"] == 1
    assert report["jit_candidate_count"] == 1
    # The helper is embedded as an ordinary internal native function - no
    # runtime-compilation machinery and no Python export.
    assert "fn jit_app__math_ops__helper(x: f64) -> PyResult<f64> {" in lib_rs
    assert "wrap_pyfunction!(jit_app__math_ops__helper" not in lib_rs

    monkeypatch.syspath_prepend(str(build_python))
    importlib.invalidate_caches()
    for module_name in ("_rextio_native", "jit_app.math_ops", "jit_app._fallback_math_ops"):
        sys.modules.pop(module_name, None)

    native_module = importlib.import_module("_rextio_native")
    assert native_module.jit_app__math_ops__compute(3.0) == 7.0

    module = importlib.import_module("jit_app.math_ops")
    assert module.compute(4.0) == 9.0
