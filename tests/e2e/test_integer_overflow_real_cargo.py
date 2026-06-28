from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

from rextio.cli.main import main


def test_real_cargo_integer_overflow_raises_instead_of_wrapping(
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
    source = tmp_path / "src" / "overflow_app" / "math_ops.py"
    source.parent.mkdir(parents=True)
    (source.parent / "__init__.py").write_text("", encoding="utf-8")
    source.write_text(
        """
import rextio

@rextio.native
def square(a: int) -> int:
    return a * a
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
    for module_name in ("_rextio_native", "overflow_app.math_ops", "overflow_app._fallback_math_ops"):
        sys.modules.pop(module_name, None)
    importlib.invalidate_caches()
    module = importlib.import_module("overflow_app.math_ops")

    # In-range arithmetic is unchanged.
    assert module.square(3) == 9

    # An i64 overflow is a real error (Python ints are arbitrary precision), so the
    # release build is compiled with overflow-checks and PyO3 turns the resulting
    # panic into a Python exception instead of silently wrapping to a wrong value.
    with pytest.raises(BaseException):  # noqa: PT011 - PyO3 PanicException is not an Exception subclass on all versions
        module.square(2**40)
