from __future__ import annotations

import importlib
import math
import shutil
from pathlib import Path

import pytest

from rextio.cli.main import main


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_native_print_of_bool_and_float_matches_cpython(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    # print of bool/float was a documented divergence (true/false, NaN, 1e16);
    # both are now lowered to CPython-exact text (True/False and
    # __rextio_repr_float's shortest correctly-rounded repr). Rust's println!
    # writes to the OS-level stdout, so capture with capfd, not capsys.
    (tmp_path / "rextio.toml").write_text(
        """
[rust]
build_tool = "cargo"
""",
        encoding="utf-8",
    )
    source = tmp_path / "src" / "printfmt_app" / "render.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
import rextio

@rextio.native
def render(flag: bool, x: float) -> None:
    print(flag, x)
""",
        encoding="utf-8",
    )

    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])
    assert exit_code == 0

    monkeypatch.syspath_prepend(str(tmp_path / ".rextio" / "build" / "python"))
    importlib.invalidate_caches()
    module = importlib.import_module("printfmt_app.render")

    battery = [
        1.0,
        -1.5,
        0.1,
        1e15,
        1e16,
        0.0001,
        0.00001,
        1.5e-5,
        5e-324,
        1e308,
        -0.0,
        2.7907518603480913e14,  # Ryu/Gay shortest-repr tie-break case
        math.nan,
        math.inf,
        -math.inf,
    ]
    capfd.readouterr()
    for flag in (True, False):
        for value in battery:
            module.render(flag, value)
            captured = capfd.readouterr()
            assert captured.out == f"{flag} {value!r}\n", (flag, value)
