from __future__ import annotations

import json
import math
import shutil
from pathlib import Path

import pytest

from rextio.cli.main import main


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_real_cargo_min_max_match_cpython_on_nan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fresh_import,
) -> None:
    # Rust's f64::min/max return the non-NaN operand, but CPython's min/max keep
    # the first operand whenever the comparison is False -- which it always is
    # when either operand is NaN. So `min(nan, 1.0)` is `nan` in CPython but
    # `1.0` under f64::min: a silent wrong value. The native path must emit
    # CPython's own comparison form and match it exactly.
    (tmp_path / "rextio.toml").write_text(
        """
[rust]
build_tool = "cargo"
""",
        encoding="utf-8",
    )
    source = tmp_path / "src" / "minmax_app" / "ops.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
import rextio

@rextio.native
def min_f(a: float, b: float) -> float:
    return min(a, b)

@rextio.native
def max_f(a: float, b: float) -> float:
    return max(a, b)

@rextio.native
def min_i(a: int, b: int) -> int:
    return min(a, b)

@rextio.native
def max_i(a: int, b: int) -> int:
    return max(a, b)
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
    # Every function must compile natively (not silently fall back to CPython),
    # otherwise the NaN assertions below would pass via the fallback.
    assert report["accepted_native_count"] == 4
    assert report["rejected_native_count"] == 0

    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    module = fresh_import("minmax_app.ops")

    nan = float("nan")

    # Ordinary values match CPython.
    assert module.min_f(1.0, 2.0) == 1.0
    assert module.max_f(1.0, 2.0) == 2.0
    assert module.min_i(3, -1) == -1
    assert module.max_i(3, -1) == 3

    # NaN is order-dependent in CPython: min/max keep the first operand because
    # every comparison against NaN is False. The native path must do the same.
    for native_fn, cpython_fn in ((module.min_f, min), (module.max_f, max)):
        # First operand NaN -> result is NaN (CPython), NOT the other operand.
        assert math.isnan(native_fn(nan, 1.0)) == math.isnan(cpython_fn(nan, 1.0))
        assert math.isnan(native_fn(nan, 1.0))
        # Second operand NaN -> result is the first operand.
        assert native_fn(1.0, nan) == cpython_fn(1.0, nan) == 1.0
