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


def test_generated_wrapper_falls_back_when_native_import_crashes(
    tmp_path: Path,
    monkeypatch,
    fake_cargo: Path,
) -> None:
    source = tmp_path / "src" / "demo_broken_native" / "scoring.py"
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

    assert main(["build", str(tmp_path), "--fallback=cpython"]) == 0
    build_python = tmp_path / ".rextio" / "build" / "python"
    for native_artifact in build_python.glob("_rextio_native*"):
        native_artifact.unlink()
    (build_python / "_rextio_native.py").write_text(
        "raise RuntimeError('broken native import')\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(build_python))
    importlib.invalidate_caches()

    module = importlib.import_module("demo_broken_native.scoring")

    assert module.add(2, 3) == 5


def test_build_python_artifact_imports_generated_wrapper(
    tmp_path: Path,
    monkeypatch,
    fake_cargo: Path,
) -> None:
    source = tmp_path / "src" / "demo_artifact" / "scoring.py"
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
    native_module.demo_artifact__scoring__add = lambda a, b: a + b + 100
    monkeypatch.setitem(sys.modules, "_rextio_native", native_module)

    assert main(["build", str(tmp_path), "--fallback=cpython"]) == 0
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    importlib.invalidate_caches()

    module = importlib.import_module("demo_artifact.scoring")

    assert module.add(2, 3) == 105


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
    native_module.demo_disable__scoring__add = lambda a, b: 999
    monkeypatch.setitem(sys.modules, "_rextio_native", native_module)
    monkeypatch.setenv("REXTIO_DISABLE_NATIVE", "1")

    assert main(["build", str(tmp_path), "--fallback=cpython"]) == 0
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "generated" / "python"))
    importlib.invalidate_caches()

    module = importlib.import_module("demo_disable.scoring")

    assert module.add(2, 3) == 5


def test_generated_wrapper_respects_native_mode_fallback(
    tmp_path: Path,
    monkeypatch,
    fake_cargo: Path,
) -> None:
    source = tmp_path / "src" / "demo_mode_fallback" / "scoring.py"
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
    native_module.demo_mode_fallback__scoring__add = lambda a, b: 999
    monkeypatch.setitem(sys.modules, "_rextio_native", native_module)
    monkeypatch.setenv("REXTIO_NATIVE_MODE", "fallback")

    assert main(["build", str(tmp_path), "--fallback=cpython"]) == 0
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "generated" / "python"))
    importlib.invalidate_caches()

    module = importlib.import_module("demo_mode_fallback.scoring")

    assert module.add(2, 3) == 5


def test_generated_wrapper_native_mode_requires_native_function(
    tmp_path: Path,
    monkeypatch,
    fake_cargo: Path,
) -> None:
    source = tmp_path / "src" / "demo_mode_native" / "scoring.py"
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
    monkeypatch.setenv("REXTIO_NATIVE_MODE", "native")

    assert main(["build", str(tmp_path), "--fallback=cpython"]) == 0
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "generated" / "python"))
    importlib.invalidate_caches()

    module = importlib.import_module("demo_mode_native.scoring")

    try:
        module.add(2, 3)
    except RuntimeError as exc:
        assert "native mode requires generated native function" in str(exc)
    else:
        raise AssertionError("native mode should fail when native function is unavailable")


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
    native_module.demo_native__scoring__add = lambda a, b: 999
    monkeypatch.setitem(sys.modules, "_rextio_native", native_module)

    assert main(["build", str(tmp_path), "--fallback=cpython"]) == 0
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "generated" / "python"))
    importlib.invalidate_caches()

    module = importlib.import_module("demo_native.scoring")

    assert module.add(2, 3) == 999


def test_fallback_functions_call_native_wrappers_when_available(
    tmp_path: Path,
    monkeypatch,
    fake_cargo: Path,
) -> None:
    source = tmp_path / "src" / "demo_bridge" / "scoring.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
import rextio

@rextio.native
def score_one(x: int) -> int:
    return x + 1

def process_all(xs: list[int]) -> list[int]:
    out = []
    for x in xs:
        out.append(score_one(x))
    return out
""",
        encoding="utf-8",
    )
    native_module = ModuleType("_rextio_native")
    native_module.demo_bridge__scoring__score_one = lambda x: x + 100
    monkeypatch.setitem(sys.modules, "_rextio_native", native_module)

    assert main(["build", str(tmp_path), "--fallback=cpython"]) == 0
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "generated" / "python"))
    importlib.invalidate_caches()

    module = importlib.import_module("demo_bridge.scoring")

    assert module.process_all([1, 2, 3]) == [101, 102, 103]


def test_cross_module_fallback_calls_imported_native_wrapper(
    tmp_path: Path,
    monkeypatch,
    fake_cargo: Path,
) -> None:
    math_ops = tmp_path / "src" / "demo_cross_module" / "math_ops.py"
    scoring = tmp_path / "src" / "demo_cross_module" / "scoring.py"
    math_ops.parent.mkdir(parents=True)
    math_ops.write_text(
        """
import rextio

@rextio.native
def square(x: float) -> float:
    return x * x
""",
        encoding="utf-8",
    )
    scoring.write_text(
        """
import rextio

from .math_ops import square

@rextio.native
def score(x: float) -> float:
    return square(x) + 1.0
""",
        encoding="utf-8",
    )
    native_module = ModuleType("_rextio_native")
    native_module.demo_cross_module__math_ops__square = lambda x: x + 100.0
    monkeypatch.setitem(sys.modules, "_rextio_native", native_module)

    assert main(["build", str(tmp_path), "--fallback=cpython"]) == 0
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "generated" / "python"))
    importlib.invalidate_caches()

    module = importlib.import_module("demo_cross_module.scoring")

    assert module.score(2.0) == 103.0


def test_native_wrapper_can_replace_package_init(
    tmp_path: Path,
    monkeypatch,
    fake_cargo: Path,
) -> None:
    source = tmp_path / "src" / "demo_init" / "__init__.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
import rextio

@rextio.native
def ping(x: int) -> int:
    return x + 1
""",
        encoding="utf-8",
    )
    native_module = ModuleType("_rextio_native")
    native_module.demo_init__ping = lambda x: x + 50
    monkeypatch.setitem(sys.modules, "_rextio_native", native_module)

    assert main(["build", str(tmp_path), "--fallback=cpython"]) == 0
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "generated" / "python"))
    importlib.invalidate_caches()

    module = importlib.import_module("demo_init")

    assert module.ping(2) == 52


def test_native_export_names_do_not_collide_across_modules(
    tmp_path: Path,
    monkeypatch,
    fake_cargo: Path,
) -> None:
    first = tmp_path / "src" / "same_name" / "first.py"
    second = tmp_path / "src" / "same_name" / "second.py"
    first.parent.mkdir(parents=True)
    first.write_text(
        """
import rextio

@rextio.native
def compute(x: int) -> int:
    return x + 1
""",
        encoding="utf-8",
    )
    second.write_text(
        """
import rextio

@rextio.native
def compute(x: int) -> int:
    return x + 2
""",
        encoding="utf-8",
    )
    native_module = ModuleType("_rextio_native")
    native_module.same_name__first__compute = lambda x: x + 10
    native_module.same_name__second__compute = lambda x: x + 20
    monkeypatch.setitem(sys.modules, "_rextio_native", native_module)

    assert main(["build", str(tmp_path), "--fallback=cpython"]) == 0
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    importlib.invalidate_caches()

    first_module = importlib.import_module("same_name.first")
    second_module = importlib.import_module("same_name.second")

    assert first_module.compute(1) == 11
    assert second_module.compute(1) == 21
