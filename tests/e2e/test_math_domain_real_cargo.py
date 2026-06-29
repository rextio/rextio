from __future__ import annotations

import importlib
import json
import math
import shutil
import sys
from pathlib import Path

import pytest

from rextio.cli.main import main


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_real_cargo_math_domain_matches_cpython(
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

    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    # Evict any cached `_rextio_native` from a prior e2e so this build's module
    # (not another test's) is the one imported and measured.
    for cached in ("_rextio_native", "math_app", "math_app.ops"):
        sys.modules.pop(cached, None)
    importlib.invalidate_caches()
    module = importlib.import_module("math_app.ops")

    inf = float("inf")
    nan = float("nan")

    # The native path must match CPython exactly: a domain error depends on the
    # INPUT, so nan/inf inputs return nan/inf (not ValueError), and only
    # genuinely out-of-domain inputs raise.
    cases = [
        (module.sqrt_f, math.sqrt, [4.0, 0.0, inf, nan]),
        (module.log_f, math.log, [math.e, 1.0, inf, nan]),
        (module.acos_f, math.acos, [0.5, -1.0, 1.0, nan]),
    ]
    for native_fn, cpython_fn, ok_inputs in cases:
        for value in ok_inputs:
            native = native_fn(value)
            expected = cpython_fn(value)
            if math.isnan(expected):
                assert math.isnan(native), (native_fn, value)
            else:
                assert native == expected, (native_fn, value)

    # Out-of-domain inputs must raise ValueError natively, just like CPython.
    for native_fn, bad in [
        (module.sqrt_f, -1.0),
        (module.log_f, 0.0),
        (module.log_f, -1.0),
        (module.acos_f, 2.0),
    ]:
        with pytest.raises(ValueError):
            native_fn(bad)
