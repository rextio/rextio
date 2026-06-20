from __future__ import annotations

import json
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
    native_module.bench_app__add = lambda a, b: a + b
    monkeypatch.setitem(sys.modules, "_rextio_native", native_module)

    exit_code = main(["bench", "bench_app.add", "--project-root", str(tmp_path)])

    captured = capsys.readouterr()
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "bench.json").read_text(encoding="utf-8")
    )

    assert exit_code == 0
    assert "Rextio bench bench_app.add" in captured.out
    assert "Python fallback:" in captured.out
    assert "Rust native:" in captured.out
    assert "Speedup:" in captured.out
    assert "bench.json" in captured.out
    assert report["status"] == "benchmarked"
    assert report["target"] == "bench_app.add"
    assert report["iterations"] == 1000
    assert isinstance(report["fallback_ms"], float)
    assert isinstance(report["native_ms"], float)
    assert isinstance(report["speedup"], float)
    assert report["build"]["native_build"]["status"] == "built"


def test_bench_rejects_non_native_target(tmp_path: Path, capsys) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[policy]
native_marker = "decorator"
""",
        encoding="utf-8",
    )
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


def test_bench_reports_config_error(tmp_path: Path, capsys) -> None:
    (tmp_path / "rextio.toml").write_text(
        """
[policy]
require_type_hints = false
""",
        encoding="utf-8",
    )

    exit_code = main(["bench", "bench_app.add", "--project-root", str(tmp_path)])

    captured = capsys.readouterr()

    assert exit_code == 1
    assert "RXT060 Benchmark failed" in captured.out
    assert "configuration error" in captured.out
    assert "require_type_hints" in captured.out


def test_bench_supports_native_function_in_package_init(
    tmp_path: Path,
    monkeypatch,
    fake_cargo: Path,
    capsys,
) -> None:
    source = tmp_path / "src" / "bench_pkg" / "__init__.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        """
import rextio

@rextio.native
def add(a: int, b: int) -> int:
    return a + b
""",
        encoding="utf-8",
    )
    native_module = ModuleType("_rextio_native")
    native_module.bench_pkg__add = lambda a, b: a + b
    monkeypatch.setitem(sys.modules, "_rextio_native", native_module)

    exit_code = main(["bench", "bench_pkg.add", "--project-root", str(tmp_path)])

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Rextio bench bench_pkg.add" in captured.out
