from __future__ import annotations

import importlib
import json
import shutil
import sys
from pathlib import Path

import pytest

from rextio.cli.main import main

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for native e2e")
def test_pure_math_example_builds_imports_and_benchmarks_with_real_cargo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project_root = tmp_path / "pure_math"
    shutil.copytree(REPO_ROOT / "examples" / "pure_math", project_root)
    _force_cargo_build_tool(project_root)

    build_exit = main(["build", str(project_root), "--fallback=cpython"])

    capsys.readouterr()
    build_python = project_root / ".rextio" / "build" / "python"
    build_report = json.loads(
        (project_root / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )

    assert build_exit == 0
    assert build_report["status"] == "built"
    assert build_report["native_build"]["status"] == "built"
    assert build_report["fallback_build"]["status"] == "built"
    assert Path(build_report["native_build"]["installed_path"]).exists()

    monkeypatch.syspath_prepend(str(build_python))
    importlib.invalidate_caches()
    _clear_modules("pure_math")

    native_module = importlib.import_module("_rextio_native")
    assert native_module.pure_math__math_ops__sum_squares([1.0, 2.0, 3.0]) == 14.0
    assert native_module.pure_math__math_ops__dot_simple([1.0, 2.0], [3.0, 4.0]) == 11.0
    assert native_module.pure_math__math_ops__count_positive([-2, 0, 3, 4]) == 2

    math_ops = importlib.import_module("pure_math.math_ops")
    assert math_ops.sum_squares([1.0, 2.0, 3.0]) == 14.0
    assert math_ops.dot_simple([1.0, 2.0], [3.0, 4.0]) == 11.0
    assert math_ops.count_positive([-2, 0, 3, 4]) == 2

    _clear_modules("pure_math")
    bench_exit = main(
        [
            "bench",
            "pure_math.math_ops.sum_squares",
            "--project-root",
            str(project_root),
        ]
    )

    captured = capsys.readouterr()
    bench_report = json.loads(
        (project_root / ".rextio" / "reports" / "bench.json").read_text(encoding="utf-8")
    )

    assert bench_exit == 0
    assert "Rextio bench pure_math.math_ops.sum_squares" in captured.out
    assert "Speedup:" in captured.out
    assert bench_report["status"] == "benchmarked"
    assert bench_report["target"] == "pure_math.math_ops.sum_squares"
    assert isinstance(bench_report["speedup"], float)


def _force_cargo_build_tool(project_root: Path) -> None:
    config = project_root / "rextio.toml"
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            'build_tool = "maturin"',
            'build_tool = "cargo"',
        ),
        encoding="utf-8",
    )


def _clear_modules(package_name: str) -> None:
    for module_name in list(sys.modules):
        if (
            module_name == "_rextio_native"
            or module_name == package_name
            or module_name.startswith(f"{package_name}.")
        ):
            sys.modules.pop(module_name, None)
