from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType

from rextio.cli.main import main


def test_bench_compares_fallback_and_native(
    tmp_path: Path,
    monkeypatch,
    fake_cargo: Path,
    capsys,
) -> None:
    (tmp_path / "bench_app.py").write_text(
        """
import rextio

@rextio.native
def add(a: int, b: int) -> int:
    return a + b
""",
        encoding="utf-8",
    )
    native_module = ModuleType("_rextio_native")
    native_module.add = lambda a, b: a + b
    monkeypatch.setitem(sys.modules, "_rextio_native", native_module)

    exit_code = main(["bench", "bench_app.add", "--project-root", str(tmp_path)])

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Rextio bench bench_app.add" in captured.out
    assert "Python fallback:" in captured.out
    assert "Rust native:" in captured.out
    assert "Speedup:" in captured.out


def test_bench_rejects_non_native_target(tmp_path: Path, capsys) -> None:
    (tmp_path / "bench_app.py").write_text(
        """
def add(a: int, b: int) -> int:
    return a + b
""",
        encoding="utf-8",
    )

    exit_code = main(["bench", "bench_app.add", "--project-root", str(tmp_path)])

    captured = capsys.readouterr()

    assert exit_code == 1
    assert "RXT060 Benchmark failed" in captured.out
