from __future__ import annotations

import importlib
import json
import shutil
import sys
from pathlib import Path

import pytest

from rextio.cli.main import main


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_real_cargo_build_handles_native_top_level_init(
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
native_top_level = true
""",
        encoding="utf-8",
    )
    package = tmp_path / "src" / "top_app"
    package.mkdir(parents=True)
    (package / "state.py").write_text(
        """
total: int = 0
i: int = 0
while i < 5:
    total += i
    i += 1

def read_total() -> int:
    return total
""",
        encoding="utf-8",
    )

    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])

    capsys.readouterr()
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )
    build_python = tmp_path / ".rextio" / "build" / "python"
    elided_fallback = build_python / "top_app" / "_native_top_level_fallback_state.py"

    assert exit_code == 0
    assert report["accepted_native_count"] == 1
    assert report["plan"]["native"]["accepted_top_levels"] == ["top_app.state.__rextio_top_level__"]
    assert report["native_build"]["status"] == "built"
    assert elided_fallback.exists()
    assert "while i < 5" not in elided_fallback.read_text(encoding="utf-8")

    monkeypatch.syspath_prepend(str(build_python))
    importlib.invalidate_caches()
    _drop_modules()

    native = importlib.import_module("_rextio_native")
    assert native.top_app__state____rextio_top_level() == {"i": 5, "total": 10}

    state = importlib.import_module("top_app.state")
    assert state.i == 5
    assert state.total == 10
    assert state.read_total() == 10
    assert "top_app._native_top_level_fallback_state" in sys.modules
    assert "top_app._fallback_state" not in sys.modules

    monkeypatch.setenv("REXTIO_NATIVE_MODE", "fallback")
    _drop_modules()
    fallback_state = importlib.import_module("top_app.state")
    assert fallback_state.i == 5
    assert fallback_state.total == 10
    assert fallback_state.read_total() == 10
    assert "top_app._fallback_state" in sys.modules


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_native_top_level_collisions_preserve_final_class_and_function_bindings(
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
native_top_level = true
""",
        encoding="utf-8",
    )
    source = tmp_path / "collision_app.py"
    source.write_text(
        """
import rextio

C_before: int = 7

class C_before:
    @rextio.native
    def m(self, value: int) -> int:
        return value + 1

class C_after:
    @rextio.native
    def m(self, value: int) -> int:
        return value + 2

C_after: int = 7

foo_before: int = 7

@rextio.native
def foo_before(value: int) -> int:
    return value + 3

@rextio.native
def foo_after(value: int) -> int:
    return value + 4

foo_after: int = 7
""",
        encoding="utf-8",
    )

    assert main(["build", str(tmp_path), "--fallback=cpython"]) == 0
    capsys.readouterr()
    build_python = tmp_path / ".rextio" / "build" / "python"
    monkeypatch.syspath_prepend(str(build_python))
    importlib.invalidate_caches()

    def import_fresh():
        for name in (
            "_rextio_native",
            "collision_app",
            "_fallback_collision_app",
            "_native_top_level_fallback_collision_app",
        ):
            sys.modules.pop(name, None)
        return importlib.import_module("collision_app")

    native_module = import_fresh()
    assert native_module.C_before().m(3) == 4
    assert native_module.foo_before(3) == 6
    assert native_module.C_after == 7
    assert native_module.foo_after == 7

    monkeypatch.setenv("REXTIO_NATIVE_MODE", "fallback")
    fallback_module = import_fresh()
    assert fallback_module.C_before().m(3) == 4
    assert fallback_module.foo_before(3) == 6
    assert fallback_module.C_after == 7
    assert fallback_module.foo_after == 7


def _drop_modules() -> None:
    for module_name in (
        "_rextio_native",
        "top_app.state",
        "top_app._fallback_state",
        "top_app._native_top_level_fallback_state",
    ):
        sys.modules.pop(module_name, None)
