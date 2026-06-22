from __future__ import annotations

import asyncio
import importlib
import json
import shutil
import sys
from pathlib import Path

import pytest

from rextio.cli.main import main


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_real_cargo_build_preserves_python_runtime_semantics(
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
""",
        encoding="utf-8",
    )
    source = tmp_path / "runtime_app.py"
    source.write_text(
        """
import rextio


class Box:
    def __init__(self, value):
        self.value = value

    @rextio.native
    def bump(self, amount: int) -> int:
        self.value += amount
        return self.value


class Manager:
    def __enter__(self):
        return 7

    def __exit__(self, exc_type, exc, traceback):
        return False


@rextio.native
def dynamic_attr(box: Box, amount: int):
    return getattr(box, "value") + amount


@rextio.native
def with_value() -> int:
    with Manager() as value:
        return value


@rextio.native
def catch_value(x: int) -> int:
    try:
        if x < 0:
            raise ValueError("negative")
        return x
    except ValueError:
        return 0


@rextio.native
def numbers(n: int):
    for i in range(n):
        yield i


@rextio.native
async def async_add(x: int) -> int:
    return x + 3
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
    assert report["accepted_native_count"] == 6
    assert report["rejected_native_count"] == 0

    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    importlib.invalidate_caches()
    for module_name in ("_rextio_native", "runtime_app", "_fallback_runtime_app"):
        sys.modules.pop(module_name, None)

    module = importlib.import_module("runtime_app")
    box = module.Box(10)

    assert box.bump(5) == 15
    assert module.dynamic_attr(box, 2) == 17
    assert module.with_value() == 7
    assert module.catch_value(-1) == 0
    assert module.catch_value(4) == 4
    assert list(module.numbers(3)) == [0, 1, 2]
    assert asyncio.run(module.async_add(4)) == 7
