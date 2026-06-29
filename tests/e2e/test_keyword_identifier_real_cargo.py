from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

from rextio.cli.main import main


def test_real_cargo_rust_keyword_identifiers_compile_and_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Parameters and locals named after Rust keywords are carried as raw
    # identifiers (`r#match`/`r#fn`). If the escaping were wrong the crate would not
    # compile; this proves the generated Rust builds and returns the right value.
    (tmp_path / "rextio.toml").write_text('[rust]\nbuild_tool = "cargo"\n', encoding="utf-8")
    source = tmp_path / "src" / "kw_app" / "calc.py"
    source.parent.mkdir(parents=True)
    (source.parent / "__init__.py").write_text("", encoding="utf-8")
    source.write_text(
        "import rextio\n\n"
        "@rextio.native\n"
        "def combine(match: int, type: int) -> int:\n"
        "    fn = match + type\n"
        "    loop = fn * 2\n"
        "    return loop\n",
        encoding="utf-8",
    )

    assert main(["build", str(tmp_path), "--fallback=cpython"]) == 0
    capsys.readouterr()
    report = json.loads((tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8"))
    assert report["native_build"]["status"] == "built"

    monkeypatch.setenv("REXTIO_NATIVE_MODE", "native")
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    for name in ("_rextio_native", "kw_app.calc", "kw_app._fallback_calc"):
        sys.modules.pop(name, None)
    importlib.invalidate_caches()
    module = importlib.import_module("kw_app.calc")

    assert module.combine(3, 4) == (3 + 4) * 2
    # PyO3 exposes the `r#`-escaped parameters under their plain Python names, so a
    # keyword-argument call must bind correctly too.
    assert module.combine(match=3, type=4) == (3 + 4) * 2
