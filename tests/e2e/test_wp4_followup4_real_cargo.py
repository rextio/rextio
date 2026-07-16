"""WP-4 follow-up 4 real-Cargo controls: sections 1, 7, and 9.

Each builds a real crate with cargo and imports the generated module, proving the
analysis verdicts hold through codegen: a same-module sibling shadow lowers to the
sibling (not the builtin), a non-finite source float falls back instead of
emitting invalid Rust (``inf``), and a type-changing rebinding falls back before
Cargo while a same-type one stays native.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from rextio.cli.main import main

_TOML = """
[rust]
build_tool = "cargo"
"""


def _build(tmp_path: Path, source: str, package: str) -> dict:
    (tmp_path / "rextio.toml").write_text(_TOML, encoding="utf-8")
    src = tmp_path / "src" / package / "ops.py"
    src.parent.mkdir(parents=True)
    src.write_text(source, encoding="utf-8")
    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )
    assert exit_code == 0, report
    assert report["native_build"]["status"] == "built"
    return report


def _statuses(tmp_path: Path) -> dict[str, str]:
    main(["check", str(tmp_path)])
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "check.json").read_text(encoding="utf-8")
    )
    return {
        function["qualname"]: function["native_status"]
        for module in report["modules"]
        for function in module["functions"]
    }


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_same_module_sibling_lowers_to_sibling_not_builtin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fresh_import,
) -> None:
    _build(
        tmp_path,
        """
import rextio

@rextio.native
def abs(x: int) -> int:
    return x + 100

@rextio.native
def udf(x: int) -> int:
    return abs(x)
""",
        package="wp4sib",
    )
    capsys.readouterr()
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    module = fresh_import("wp4sib.ops")
    # The sibling `abs` (x + 100), NOT the builtin abs (which would give 5).
    assert module.udf(-5) == 95
    assert module.abs(3) == 103


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_non_finite_source_float_falls_back_and_builds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fresh_import,
) -> None:
    # Before the fix `return 1e400` emitted `Ok(inf)` and cargo failed E0425; now
    # it falls back so the build succeeds, while the largest finite float stays
    # native.
    _build(
        tmp_path,
        """
import rextio

@rextio.native
def overflow() -> float:
    return 1e400

@rextio.native
def neg_overflow() -> float:
    return -1e400

@rextio.native
def largest_finite() -> float:
    return 1.7976931348623157e308
""",
        package="wp4flt",
    )
    statuses = _statuses(tmp_path)
    assert statuses["wp4flt.ops.overflow"] == "rejected"
    assert statuses["wp4flt.ops.neg_overflow"] == "rejected"
    assert statuses["wp4flt.ops.largest_finite"] == "accepted"
    capsys.readouterr()
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    module = fresh_import("wp4flt.ops")
    assert module.overflow() == float("inf")
    assert module.neg_overflow() == float("-inf")
    assert module.largest_finite() == 1.7976931348623157e308


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_scalar_rebinding_type_change_falls_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fresh_import,
) -> None:
    _build(
        tmp_path,
        """
import rextio

@rextio.native
def widen(x: int) -> float:
    y = x
    y = 1.5
    return y

@rextio.native
def stable(x: int) -> int:
    y = x
    y = y + 1
    return y
""",
        package="wp4reb",
    )
    statuses = _statuses(tmp_path)
    # The int->float rebinding falls back BEFORE cargo (never emits E0308 Rust);
    # the same-type rebinding stays native and compiles.
    assert statuses["wp4reb.ops.widen"] == "rejected"
    assert statuses["wp4reb.ops.stable"] == "accepted"
    capsys.readouterr()
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    module = fresh_import("wp4reb.ops")
    assert module.widen(3) == 1.5
    assert module.stable(41) == 42
