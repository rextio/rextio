from __future__ import annotations

import importlib
import json
import shutil
from pathlib import Path

import pytest

from rextio.cli.main import main


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_real_cargo_build_keeps_uncompilable_shapes_off_native(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # These three shapes would each emit Rust that fails ``cargo build`` if accepted
    # natively (E0308 for a float->int call argument, E0282 for a bare-None local and
    # a None tuple item). The analyzer must keep their callers/owners on the Python
    # fallback so the native module still builds, while a type-matching caller and an
    # all-scalar tuple stay native and produce CPython-equivalent results.
    (tmp_path / "rextio.toml").write_text(
        """
[rust]
build_tool = "cargo"
""",
        encoding="utf-8",
    )
    package = tmp_path / "src" / "guard_app"
    package.mkdir(parents=True)
    (package / "ops.py").write_text(
        """
from typing import Optional


def callee(x: int) -> int:
    return x + 1


def bad_caller() -> int:
    return callee(1.2)


def good_caller() -> int:
    return callee(1)


def bare_local() -> Optional[int]:
    x = None
    return x


def scalar_tuple() -> tuple[int, float]:
    return (1, 2.0)
""",
        encoding="utf-8",
    )

    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])

    capsys.readouterr()
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )

    assert exit_code == 0
    # The native module must still compile even though the uncompilable shapes are
    # present in the source; they are routed to the Python fallback, not built.
    assert report["native_build"]["status"] == "built"

    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    importlib.invalidate_caches()
    ops = importlib.import_module("guard_app.ops")

    # Every function still runs with CPython-equivalent semantics regardless of the
    # native/fallback split.
    assert ops.callee(4) == 5
    assert ops.good_caller() == 2
    assert ops.bad_caller() == pytest.approx(2.2)
    assert ops.bare_local() is None
    assert ops.scalar_tuple() == (1, 2.0)
