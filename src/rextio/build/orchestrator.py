from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from rextio.analyzer.models import ProjectAnalysis
from rextio.build.cargo_builder import (
    NativeBuildResult,
    build_native_extension_with_cargo,
    skipped_native_build,
)
from rextio.build.maturin_builder import build_native_extension_with_maturin
from rextio.codegen.rust.cargo import (
    render_cargo_config_toml,
    render_cargo_toml,
    render_pyproject_toml,
)
from rextio.codegen.rust.generator import generate_rust_module
from rextio.codegen.rust.generator import RustCodegenError
from rextio.codegen.python_wrapper.wrapper_gen import render_wrapper_module
from rextio.fallback.cpython import (
    generated_path_for_module,
    write_cpython_fallback,
    write_plain_cpython_module,
)
from rextio.ir.lowering import LoweringError, lower_project
from rextio.build.artifact_layout import ArtifactLayout


@dataclass(frozen=True)
class BuildResult:
    fallback: str
    layout: ArtifactLayout
    accepted_native_count: int
    rejected_native_count: int
    native_build: NativeBuildResult

    def to_dict(self) -> dict[str, object]:
        return {
            "fallback": self.fallback,
            "generated_rust": str(self.layout.rust_dir),
            "generated_python": str(self.layout.python_dir),
            "build_python": str(self.layout.build_python_dir),
            "accepted_native_count": self.accepted_native_count,
            "rejected_native_count": self.rejected_native_count,
            "native_build": self.native_build.to_dict(),
        }


def build_hybrid_artifact(
    project_root: Path,
    analysis: ProjectAnalysis,
    fallback: str,
    build_tool: str = "cargo",
) -> BuildResult:
    layout = ArtifactLayout(project_root)
    _reset_generated_dir(layout.build_dir)
    _reset_generated_dir(layout.rust_dir)
    _reset_generated_dir(layout.python_dir)
    layout.rust_src_dir.mkdir(parents=True, exist_ok=True)
    layout.python_dir.mkdir(parents=True, exist_ok=True)
    layout.reports_dir.mkdir(parents=True, exist_ok=True)

    (layout.reports_dir / "check.json").write_text(
        json.dumps(analysis.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _write_python_fallback_tree(analysis, layout.python_dir)
    native_build = _generate_and_build_native(analysis, layout, build_tool)
    _write_build_artifact(layout)

    result = BuildResult(
        fallback=fallback,
        layout=layout,
        accepted_native_count=len(analysis.accepted_native_functions),
        rejected_native_count=len(analysis.rejected_native_functions),
        native_build=native_build,
    )
    (layout.reports_dir / "build.json").write_text(
        json.dumps({"status": _build_status(native_build), **result.to_dict()}, indent=2, sort_keys=True) + "\n",
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


def _write_build_artifact(layout: ArtifactLayout) -> None:
    if layout.build_python_dir.exists():
        shutil.rmtree(layout.build_python_dir)
    shutil.copytree(layout.python_dir, layout.build_python_dir)


def _generate_and_build_native(
    analysis: ProjectAnalysis,
    layout: ArtifactLayout,
    build_tool: str,
) -> NativeBuildResult:
    if not analysis.accepted_native_functions:
        return skipped_native_build("No accepted native functions were found.")
    try:
        module_ir = lower_project(analysis)
        rust_source = generate_rust_module(module_ir)
    except (LoweringError, RustCodegenError) as exc:
        return NativeBuildResult(
            status="failed",
            tool="codegen",
            message=(
                "RXT050 Codegen failure while generating Rust for accepted native functions. "
                f"Cause: {exc}. Fallback Python files were still generated."
            ),
        )

    _write_rust_project(layout, rust_source)
    return _build_native_with_selected_tool(layout, build_tool)


def _build_native_with_selected_tool(layout: ArtifactLayout, build_tool: str) -> NativeBuildResult:
    normalized = build_tool.lower()
    if normalized == "cargo":
        return build_native_extension_with_cargo(layout.rust_dir, layout.python_dir)
    if normalized == "maturin":
        result = build_native_extension_with_maturin(layout.rust_dir, layout.python_dir)
        if result.status == "built":
            return result
        if "maturin was not found" not in result.message:
            return result
        cargo_result = build_native_extension_with_cargo(layout.rust_dir, layout.python_dir)
        if cargo_result.status == "built":
            return NativeBuildResult(
                status="built",
                tool="cargo",
                message=(
                    "maturin was not found, so Rextio built the generated native module "
                    "with Cargo fallback."
                ),
                command=cargo_result.command,
                artifact_path=cargo_result.artifact_path,
                installed_path=cargo_result.installed_path,
                stdout=cargo_result.stdout,
                stderr=cargo_result.stderr,
            )
        return NativeBuildResult(
            status="failed",
            tool="maturin",
            message=(
                "RXT060 Build failed while compiling generated Rust module. "
                "Cause: maturin was not found, and Cargo fallback also failed. "
                f"Cargo result: {cargo_result.message}"
            ),
            command=cargo_result.command,
            stdout=cargo_result.stdout,
            stderr=cargo_result.stderr,
        )
    return NativeBuildResult(
        status="failed",
        tool=build_tool,
        message=(
            "RXT060 Build failed while compiling generated Rust module. "
            f"Cause: unsupported Rust build tool: {build_tool}. "
            'Suggestion: use [rust] build_tool = "maturin" or "cargo".'
        ),
    )


def _write_rust_project(layout: ArtifactLayout, rust_source: str) -> None:
    layout.rust_src_dir.mkdir(parents=True, exist_ok=True)
    (layout.rust_dir / "Cargo.toml").write_text(render_cargo_toml(), encoding="utf-8")
    (layout.rust_dir / "pyproject.toml").write_text(render_pyproject_toml(), encoding="utf-8")
    (layout.rust_dir / ".cargo").mkdir(parents=True, exist_ok=True)
    (layout.rust_dir / ".cargo" / "config.toml").write_text(
        render_cargo_config_toml(),
        encoding="utf-8",
    )
    (layout.rust_src_dir / "lib.rs").write_text(rust_source, encoding="utf-8")


def _build_status(native_build: NativeBuildResult) -> str:
    if native_build.tool == "codegen" and native_build.status == "failed":
        return "codegen-failed"
    if native_build.status == "failed":
        return "native-build-failed"
    return "built"
