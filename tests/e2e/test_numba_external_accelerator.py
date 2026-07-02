"""Integration test for Numba as a supported external accelerator.

Skipped when numba is not installed: the recognition itself is AST-based and
covered by analyzer unit tests; this exercises the real composition - a numba
function riding through Rextio's generated fallback packaging unchanged.
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

numba = pytest.importorskip("numba")

from rextio.cli.main import main  # noqa: E402


@pytest.mark.no_toolchain
def test_numba_function_survives_fallback_packaging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "nb_app").mkdir(parents=True)
    (tmp_path / "nb_app" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "nb_app" / "kernels.py").write_text(
        """
from numba import njit

@njit(cache=False)
def total(n: int) -> int:
    acc = 0
    for i in range(n):
        acc += i
    return acc
""",
        encoding="utf-8",
    )

    # No native candidates exist (the only function is numba-decorated), so the
    # build needs no Rust toolchain and packages the fallback tree only.
    exit_code = main(["build", str(tmp_path), "--fallback=cpython"])
    capsys.readouterr()
    assert exit_code == 0

    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )
    assert report["fallback_build"]["status"] == "built"

    build_python = tmp_path / ".rextio" / "build" / "python"
    monkeypatch.syspath_prepend(str(build_python))
    importlib.invalidate_caches()
    for name in ("nb_app.kernels", "nb_app"):
        sys.modules.pop(name, None)

    module = importlib.import_module("nb_app.kernels")
    # The decorator re-applies at import; numba compiles on first call and the
    # result matches CPython for this kernel.
    assert module.total(100) == 4950
