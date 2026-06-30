from __future__ import annotations

import json
import math
import shutil
from pathlib import Path

import pytest

from rextio.cli.main import main


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_real_cargo_math_domain_matches_cpython(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fresh_import,
) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[rust]
build_tool = "cargo"
""",
        encoding="utf-8",
    )
    source = tmp_path / "src" / "math_app" / "ops.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
import math
import rextio

@rextio.native
def sqrt_f(x: float) -> float:
    return math.sqrt(x)

@rextio.native
def log_f(x: float) -> float:
    return math.log(x)

@rextio.native
def acos_f(x: float) -> float:
    return math.acos(x)

@rextio.native
def log2_f(x: float) -> float:
    return math.log2(x)

@rextio.native
def log10_f(x: float) -> float:
    return math.log10(x)

@rextio.native
def asin_f(x: float) -> float:
    return math.asin(x)

@rextio.native
def logbase_f(x: float, base: float) -> float:
    return math.log(x, base)

@rextio.native
def logbase_div(x: float, a: float, b: float) -> float:
    return math.log(x, a / b)
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
    # Every function must be compiled natively (not silently rejected to the
    # fallback), otherwise the assertions below would pass via CPython.
    assert report["accepted_native_count"] == 8
    assert report["rejected_native_count"] == 0

    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    module = fresh_import("math_app.ops")

    inf = float("inf")
    nan = float("nan")

    # The native path must match CPython exactly: a domain error depends on the
    # INPUT, so nan/inf inputs return nan/inf (not ValueError), and only
    # genuinely out-of-domain inputs raise.
    cases = [
        (module.sqrt_f, math.sqrt, [4.0, 0.0, inf, nan]),
        (module.log_f, math.log, [math.e, 1.0, inf, nan]),
        (module.log2_f, math.log2, [8.0, 1.0, inf, nan]),
        (module.log10_f, math.log10, [100.0, 1.0, inf, nan]),
        (module.acos_f, math.acos, [0.5, -1.0, 1.0, nan]),
        (module.asin_f, math.asin, [0.5, -1.0, 1.0, nan]),
    ]
    for native_fn, cpython_fn, ok_inputs in cases:
        for value in ok_inputs:
            native = native_fn(value)
            expected = cpython_fn(value)
            if math.isnan(expected):
                assert math.isnan(native), (native_fn, value)
            else:
                assert native == expected, (native_fn, value)

    # 2-arg math.log(x, base): the base is also constrained — nan and +inf bases
    # are valid (CPython returns nan / 0.0), while base <= 0 (including -inf)
    # raises ValueError and base == 1 raises ZeroDivisionError.
    assert module.logbase_f(8.0, 2.0) == math.log(8.0, 2.0)
    assert module.logbase_f(8.0, inf) == math.log(8.0, inf)  # 0.0
    assert math.isnan(module.logbase_f(8.0, nan))

    # Out-of-domain inputs must raise the same exception natively as CPython.
    for native_fn, bad in [
        (module.sqrt_f, -1.0),
        (module.log_f, 0.0),
        (module.log_f, -1.0),
        (module.log2_f, 0.0),
        (module.log10_f, -1.0),
        (module.acos_f, 2.0),
        (module.asin_f, -2.0),
    ]:
        with pytest.raises(ValueError):
            native_fn(bad)
    for bad_base in (0.0, -1.0, -inf):
        with pytest.raises(ValueError):
            module.logbase_f(8.0, bad_base)
    with pytest.raises(ZeroDivisionError):
        module.logbase_f(8.0, 1.0)

    # x's domain is checked before the base's (CPython checks log(x) first), so a
    # bad x wins over a bad literal base.
    with pytest.raises(ValueError):
        module.logbase_f(-1.0, 1.0)  # CPython: ValueError (x), not ZeroDivisionError
    with pytest.raises(ZeroDivisionError):
        module.logbase_f(nan, 1.0)  # x (nan) passes; base==1 -> ZeroDivisionError

    # ...but BOTH argument expressions are evaluated before any domain check, so
    # a raising base expression (a / 0.0) raises ZeroDivisionError even when x is
    # itself out of domain — the argument-evaluation-order case.
    with pytest.raises(ZeroDivisionError):
        module.logbase_div(-1.0, 1.0, 0.0)
    assert module.logbase_div(8.0, 4.0, 2.0) == math.log(8.0, 4.0 / 2.0)
