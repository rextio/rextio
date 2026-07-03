"""Real-cargo e2e for in-process scalar boundary calls (RXT075)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from rextio.cli.main import main
from rextio.runtime.boundary_fallback import (
    boundary_fallback_count,
    reset_boundary_fallback_state,
)

_SOURCE = """
import rextio

@rextio.exempt
def rate(income: float) -> float:
    return income * 0.15 + 1200.0

@rextio.exempt
def shout(text: str) -> str:
    return text.upper() + "!"

@rextio.exempt
def guard(x: int) -> int:
    if x < 0:
        raise ValueError(f"negative: {x}")
    return x

@rextio.native
def net_income(income: float) -> float:
    return income - rate(income)

@rextio.native
def banner(text: str) -> str:
    return shout(text)

@rextio.native
def checked(x: int) -> int:
    return guard(x) + 1
"""


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_real_cargo_boundary_calls_are_cpython_exact(
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
    source = tmp_path / "src" / "bc_app" / "ops.py"
    source.parent.mkdir(parents=True)
    source.write_text(_SOURCE, encoding="utf-8")

    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])

    capsys.readouterr()
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )

    assert exit_code == 0
    assert report["native_build"]["status"] == "built"
    assert report["accepted_native_count"] == 3

    reset_boundary_fallback_state()
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    module = fresh_import("bc_app.ops")

    # Values match CPython exactly: the fallback callee runs in the host
    # interpreter.
    assert module.net_income(10000.0) == 10000.0 - (10000.0 * 0.15 + 1200.0)
    assert module.banner("go") == "GO!"
    assert module.checked(41) == 42

    # The exception raised by the fallback callee propagates as the same
    # Python exception with the same message.
    with pytest.raises(ValueError, match="negative: -3"):
        module.checked(-3)

    # Each native call crossed the boundary once, counted against the caller.
    assert boundary_fallback_count("bc_app.ops.net_income") >= 1

    # The native path resolves the callee at call time: replacing the module
    # attribute is honored exactly like a Python caller would honor it.
    monkeypatch.setattr(module, "shout", lambda text: text + "?")
    assert module.banner("go") == "go?"
    reset_boundary_fallback_state()


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_real_cargo_boundary_chatter_demotes_via_threshold(
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
    source = tmp_path / "src" / "bc_demote" / "ops.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
import rextio

@rextio.exempt
def bump(x: int) -> int:
    return x + 1

@rextio.native
def total(x: int) -> int:
    return bump(x) * 2
""",
        encoding="utf-8",
    )

    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])
    capsys.readouterr()
    assert exit_code == 0

    reset_boundary_fallback_state()
    monkeypatch.setenv("REXTIO_BOUNDARY_FALLBACK_THRESHOLD", "3")
    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    module = fresh_import("bc_demote.ops")

    # Every wrapper entry AND every native boundary call counts one crossing
    # for `total`; after enough chatter the wrapper demotes it to the Python
    # fallback permanently - values stay identical either way.
    for i in range(6):
        assert module.total(i) == (i + 1) * 2

    assert boundary_fallback_count("bc_demote.ops.total") > 3
    reset_boundary_fallback_state()
