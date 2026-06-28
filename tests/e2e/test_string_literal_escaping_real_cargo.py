from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

from rextio.cli.main import main

# A literal exercising the escaping edge cases: non-ASCII (BMP + astral), quotes,
# backslash, and whitespace control characters. If the generated Rust mis-escaped
# any of these, the crate would not compile (or would return the wrong bytes).
_MOTTO = 'café 🦀 "quoted" back\\slash\ttab'


def test_real_cargo_string_literal_escaping_round_trips(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "rextio.toml").write_text(
        '[rust]\nbuild_tool = "cargo"\n', encoding="utf-8"
    )
    source = tmp_path / "src" / "escape_app" / "text.py"
    source.parent.mkdir(parents=True)
    (source.parent / "__init__.py").write_text("", encoding="utf-8")
    # Embed the literal with `repr` (a faithful Python literal that keeps the
    # astral char as a real scalar value, not surrogate escapes); the source file
    # is written as UTF-8.
    source.write_text(
        "import rextio\n\n"
        "@rextio.native\n"
        "def motto() -> str:\n"
        f"    return {_MOTTO!r}\n",
        encoding="utf-8",
    )

    assert main(["build", str(tmp_path), "--fallback=cpython"]) == 0
    capsys.readouterr()
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )
    assert report["native_build"]["status"] == "built"

    monkeypatch.setenv("REXTIO_NATIVE_MODE", "native")
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    for name in ("_rextio_native", "escape_app.text", "escape_app._fallback_text"):
        sys.modules.pop(name, None)
    importlib.invalidate_caches()
    module = importlib.import_module("escape_app.text")

    # The native function returns exactly the Python string — proving the
    # generated Rust both compiled and preserved every character.
    assert module.motto() == _MOTTO
