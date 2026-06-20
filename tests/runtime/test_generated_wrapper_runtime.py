from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import ModuleType

from rextio.cli.main import main


def test_generated_wrapper_falls_back_when_native_missing(
    tmp_path: Path,
    monkeypatch,
    fake_cargo: Path,
) -> None:
    source = tmp_path / "src" / "demo_runtime" / "scoring.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
import rextio

@rextio.native
def add(a: int, b: int) -> int:
    return a + b

def helper(x: int) -> int:
    return add(x, 10)
""",
        encoding="utf-8",
    )

    assert main(["build", str(tmp_path), "--fallback=cpython"]) == 0
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "generated" / "python"))
    importlib.invalidate_caches()

    module = importlib.import_module("demo_runtime.scoring")

    assert module.add(2, 3) == 5
    assert module.helper(7) == 17


def test_generated_wrapper_respects_disable_native_flag(
    tmp_path: Path,
    monkeypatch,
    fake_cargo: Path,
) -> None:
    source = tmp_path / "src" / "demo_disable" / "scoring.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
import rextio

@rextio.native
def add(a: int, b: int) -> int:
    return a + b
""",
        encoding="utf-8",
    )
    native_module = ModuleType("_rextio_native")
    native_module.add = lambda a, b: 999
    monkeypatch.setitem(sys.modules, "_rextio_native", native_module)
    monkeypatch.setenv("REXTIO_DISABLE_NATIVE", "1")

    assert main(["build", str(tmp_path), "--fallback=cpython"]) == 0
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "generated" / "python"))
    importlib.invalidate_caches()

    module = importlib.import_module("demo_disable.scoring")

    assert module.add(2, 3) == 5


def test_generated_wrapper_uses_native_when_available(
    tmp_path: Path,
    monkeypatch,
    fake_cargo: Path,
) -> None:
    source = tmp_path / "src" / "demo_native" / "scoring.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
import rextio

@rextio.native
def add(a: int, b: int) -> int:
    return a + b
""",
        encoding="utf-8",
    )
    native_module = ModuleType("_rextio_native")
    native_module.add = lambda a, b: 999
    monkeypatch.setitem(sys.modules, "_rextio_native", native_module)

    assert main(["build", str(tmp_path), "--fallback=cpython"]) == 0
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "generated" / "python"))
    importlib.invalidate_caches()

    module = importlib.import_module("demo_native.scoring")

    assert module.add(2, 3) == 999
