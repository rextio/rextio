from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from rextio.cli.main import main


def _install_fake_native(monkeypatch, functions: dict[str, Callable]) -> None:
    # Patch the loader so the generated wrapper binds these fake native functions.
    # This survives bench's module eviction and works under forced native mode.
    def _fake_loader(module_name: str, function_name: str):
        if module_name == "_rextio_native":
            return functions.get(function_name)
        return None

    monkeypatch.setattr(
        "rextio.runtime.native_loader.load_native_function", _fake_loader
    )


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
    _install_fake_native(monkeypatch, {"bench_app__add": lambda a, b: a + b})

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
    _install_fake_native(monkeypatch, {"bench_pkg__add": lambda a, b: a + b})

    exit_code = main(["bench", "bench_pkg.add", "--project-root", str(tmp_path)])

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Rextio bench bench_pkg.add" in captured.out
