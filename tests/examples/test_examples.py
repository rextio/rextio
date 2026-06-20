from __future__ import annotations

import importlib
import json
import shutil
import sys
from pathlib import Path

from rextio.analyzer.project_scanner import analyze_project
from rextio.cli.main import main

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_pure_math_example_has_required_native_candidates() -> None:
    analysis = analyze_project(REPO_ROOT / "examples" / "pure_math")

    assert [function.qualname for function in analysis.accepted_native_functions] == [
        "pure_math.math_ops.count_positive",
        "pure_math.math_ops.dot_simple",
        "pure_math.math_ops.sum_squares",
    ]
    assert analysis.rejected_native_functions == []


def test_pure_math_readme_documents_benchmark_flow() -> None:
    readme = (REPO_ROOT / "examples" / "pure_math" / "README.md").read_text(
        encoding="utf-8"
    )

    assert "rextio bench pure_math.math_ops.sum_squares" in readme
    assert "speedup ratio" in readme
    assert "fixed benchmark claim" in readme


def test_fastapi_scoring_keeps_framework_shell_in_fallback() -> None:
    analysis = analyze_project(REPO_ROOT / "examples" / "fastapi_scoring")

    assert [function.qualname for function in analysis.accepted_native_functions] == [
        "fastapi_scoring.scoring.compute_score"
    ]
    assert analysis.rejected_native_functions == []


def test_fallback_demo_has_native_score_and_boundary_warning() -> None:
    analysis = analyze_project(REPO_ROOT / "examples" / "fallback_demo")

    assert [function.qualname for function in analysis.accepted_native_functions] == [
        "fallback_demo.scoring.score_one"
    ]
    assert [diagnostic.code for diagnostic in analysis.boundary_warnings] == ["RXT073"]


def test_boundary_demo_shows_rejection_and_warning() -> None:
    analysis = analyze_project(REPO_ROOT / "examples" / "boundary_demo")
    diagnostics = {diagnostic.code for diagnostic in analysis.diagnostics}

    assert "boundary_demo.pipeline.square" in [
        function.qualname for function in analysis.accepted_native_functions
    ]
    assert "boundary_demo.pipeline.sum_squares" in [
        function.qualname for function in analysis.accepted_native_functions
    ]
    assert [function.qualname for function in analysis.rejected_native_functions] == [
        "boundary_demo.pipeline.compute_rejected"
    ]
    assert {"RXT070", "RXT073"}.issubset(diagnostics)


def test_examples_build_and_import_from_hybrid_artifacts(
    tmp_path: Path,
    monkeypatch,
    fake_cargo: Path,
    capsys,
) -> None:
    checks = {
        "pure_math": _check_pure_math_artifact,
        "fastapi_scoring": _check_fastapi_scoring_artifact,
        "fallback_demo": _check_fallback_demo_artifact,
        "boundary_demo": _check_boundary_demo_artifact,
    }
    for example_name, check in checks.items():
        project_root = _copy_example(tmp_path, example_name)
        _force_cargo_build_tool(project_root)

        exit_code = main(["build", str(project_root), "--fallback=cpython"])

        capsys.readouterr()
        report = json.loads(
            (project_root / ".rextio" / "reports" / "build.json").read_text(
                encoding="utf-8"
            )
        )
        assert exit_code == 0
        assert report["status"] == "built"
        assert report["fallback_build"]["status"] == "built"
        _prepend_build_artifact(project_root, monkeypatch)
        _clear_imports(example_name)
        check()


def _copy_example(tmp_path: Path, example_name: str) -> Path:
    source = REPO_ROOT / "examples" / example_name
    destination = tmp_path / example_name
    shutil.copytree(source, destination)
    return destination


def _force_cargo_build_tool(project_root: Path) -> None:
    config = project_root / "rextio.toml"
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            'build_tool = "maturin"',
            'build_tool = "cargo"',
        ),
        encoding="utf-8",
    )


def _prepend_build_artifact(project_root: Path, monkeypatch) -> None:
    monkeypatch.syspath_prepend(str(project_root / ".rextio" / "build" / "python"))
    importlib.invalidate_caches()


def _clear_imports(package_name: str) -> None:
    for module_name in list(sys.modules):
        if (
            module_name == "_rextio_native"
            or module_name == package_name
            or module_name.startswith(f"{package_name}.")
        ):
            sys.modules.pop(module_name, None)


def _check_pure_math_artifact() -> None:
    module = importlib.import_module("pure_math.math_ops")

    assert module.sum_squares([1.0, 2.0, 3.0]) == 14.0
    assert module.dot_simple([1.0, 2.0], [3.0, 4.0]) == 11.0
    assert module.count_positive([-2, 0, 3, 4]) == 2


def _check_fastapi_scoring_artifact() -> None:
    module = importlib.import_module("fastapi_scoring.app")

    assert module.score_without_server([2.0, 3.0]) == {
        "message": "FastAPI stays Python. compute_score becomes Rust native.",
        "score": 13.0,
    }


def _check_fallback_demo_artifact() -> None:
    module = importlib.import_module("fallback_demo.scoring")

    assert module.score_one(10.0) == 21.0
    assert module.score_python_batch([1.0, 2.0, 3.0]) == [3.0, 5.0, 7.0]


def _check_boundary_demo_artifact() -> None:
    module = importlib.import_module("boundary_demo.pipeline")

    assert module.square(4.0) == 16.0
    assert module.sum_squares([2.0, 3.0]) == 13.0
    assert module.compute_rejected(5.0) == 15.0
    assert module.process_all([2.0, 3.0]) == [4.0, 9.0]
