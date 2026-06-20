from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from rextio.analyzer.models import ProjectAnalysis
from rextio.codegen.rust.cargo import render_cargo_toml, render_pyproject_toml
from rextio.codegen.rust.generator import generate_rust_module
from rextio.codegen.python_wrapper.wrapper_gen import render_wrapper_module
from rextio.fallback.cpython import (
    generated_path_for_module,
    write_cpython_fallback,
    write_plain_cpython_module,
)
from rextio.ir.lowering import lower_project
from rextio.build.artifact_layout import ArtifactLayout


@dataclass(frozen=True)
class BuildResult:
    fallback: str
    layout: ArtifactLayout
    accepted_native_count: int
    rejected_native_count: int

    def to_dict(self) -> dict[str, object]:
        return {
            "fallback": self.fallback,
            "generated_rust": str(self.layout.rust_dir),
            "generated_python": str(self.layout.python_dir),
            "accepted_native_count": self.accepted_native_count,
            "rejected_native_count": self.rejected_native_count,
        }


def build_hybrid_artifact(project_root: Path, analysis: ProjectAnalysis, fallback: str) -> BuildResult:
    layout = ArtifactLayout(project_root)
    _reset_generated_dir(layout.rust_dir)
    _reset_generated_dir(layout.python_dir)
    layout.rust_src_dir.mkdir(parents=True, exist_ok=True)
    layout.python_dir.mkdir(parents=True, exist_ok=True)
    layout.reports_dir.mkdir(parents=True, exist_ok=True)

    module_ir = lower_project(analysis)
    rust_source = generate_rust_module(module_ir)

    (layout.rust_dir / "Cargo.toml").write_text(render_cargo_toml(), encoding="utf-8")
    (layout.rust_dir / "pyproject.toml").write_text(render_pyproject_toml(), encoding="utf-8")
    (layout.rust_src_dir / "lib.rs").write_text(rust_source, encoding="utf-8")
    (layout.reports_dir / "check.json").write_text(
        json.dumps(analysis.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _write_python_fallback_tree(analysis, layout.python_dir)

    result = BuildResult(
        fallback=fallback,
        layout=layout,
        accepted_native_count=len(analysis.accepted_native_functions),
        rejected_native_count=len(analysis.rejected_native_functions),
    )
    (layout.reports_dir / "build.json").write_text(
        json.dumps({"status": "generated", **result.to_dict()}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return result


def _write_python_fallback_tree(analysis: ProjectAnalysis, python_root: Path) -> None:
    for module in sorted(analysis.modules, key=lambda item: item.module_name):
        accepted = [
            function
            for function in module.functions
            if function.is_native_candidate and function.accepted
        ]
        if not accepted:
            write_plain_cpython_module(module, python_root)
            continue
        write_cpython_fallback(module, python_root)
        wrapper_path = generated_path_for_module(module, python_root)
        wrapper_path.parent.mkdir(parents=True, exist_ok=True)
        wrapper_path.write_text(render_wrapper_module(module), encoding="utf-8")


def _reset_generated_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
