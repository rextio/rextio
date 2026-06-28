from __future__ import annotations

import importlib
import json
import math
import sys
from pathlib import Path

import pytest

from rextio.cli.main import main


def test_real_cargo_float_division_and_modulo_match_python(
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
    source = tmp_path / "src" / "fdiv_app" / "math_ops.py"
    source.parent.mkdir(parents=True)
    (source.parent / "__init__.py").write_text("", encoding="utf-8")
    source.write_text(
        """
import math

import rextio

@rextio.native
def divide(a: float, b: float) -> float:
    return a / b

@rextio.native
def modulo(a: float, b: float) -> float:
    return a % b

@rextio.native
def floor_to_int(x: float) -> int:
    return math.floor(x)
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

    monkeypatch.setenv("REXTIO_NATIVE_MODE", "native")
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    for module_name in ("_rextio_native", "fdiv_app.math_ops", "fdiv_app._fallback_math_ops"):
        sys.modules.pop(module_name, None)
    importlib.invalidate_caches()
    module = importlib.import_module("fdiv_app.math_ops")

    # In-range arithmetic matches Python.
    assert module.divide(7.0, 2.0) == 3.5
    # Float `%` is floored (takes the divisor's sign), like Python, not Rust's
    # truncated fmod.
    assert module.modulo(-7.0, 3.0) == 2.0
    assert module.modulo(7.0, -3.0) == -2.0

    # When the remainder is exactly zero, CPython gives it the divisor's sign.
    assert math.copysign(1.0, module.modulo(-6.0, 3.0)) == 1.0
    assert math.copysign(1.0, module.modulo(6.0, -3.0)) == -1.0

    # Float division/modulo by zero is a catchable ZeroDivisionError (Python
    # semantics) instead of Rust's silent inf/NaN.
    with pytest.raises(ZeroDivisionError):
        module.divide(1.0, 0.0)
    with pytest.raises(ZeroDivisionError):
        module.modulo(1.0, 0.0)

    # math.floor returns an int; an in-range float converts, but an out-of-range
    # float raises OverflowError and NaN raises ValueError instead of silently
    # saturating via `as i64`.
    assert module.floor_to_int(3.7) == 3
    assert module.floor_to_int(-3.2) == -4
    with pytest.raises(OverflowError):
        module.floor_to_int(1e30)
    with pytest.raises(ValueError):
        module.floor_to_int(float("nan"))
