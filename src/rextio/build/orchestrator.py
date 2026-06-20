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
from rextio.build.wheel_builder import (
    WheelBuildResult,
    build_artifact_wheel,
    skipped_wheel,
)
from rextio.codegen.rust.generator import generate_rust_module
from rextio.codegen.rust.generator import RustCodegenError
from rextio.codegen.python_wrapper.wrapper_gen import render_wrapper_module
from rextio.fallback.build_result import FallbackBuildResult, cpython_fallback_build_result
from rextio.fallback.cpython import (
    generated_path_for_module,
    write_cpython_fallback,
    write_plain_cpython_module,
)
from rextio.fallback.nuitka import build_nuitka_fallback
from rextio.ir.lowering import LoweringError, lower_project
from rextio.build.artifact_layout import ArtifactLayout
from rextio.partition.build_plan import BuildPlan, create_build_plan
from rextio.partition.fallback_plan import FallbackPlan


@dataclass(frozen=True)
class BuildResult:
    fallback: str
    layout: ArtifactLayout
    plan: BuildPlan
    accepted_native_count: int
    rejected_native_count: int
    native_build: NativeBuildResult
    fallback_build: FallbackBuildResult
    wheel_build: WheelBuildResult

    def to_dict(self) -> dict[str, object]:
        return {
            "fallback": self.fallback,
            "generated_rust": str(self.layout.rust_dir),
            "generated_python": str(self.layout.python_dir),
            "build_python": str(self.layout.build_python_dir),
            "plan": self.plan.to_dict(),
            "accepted_native_count": self.accepted_native_count,
            "rejected_native_count": self.rejected_native_count,
            "native_build": self.native_build.to_dict(),
            "fallback_build": self.fallback_build.to_dict(),
            "wheel_build": self.wheel_build.to_dict(),
        }


def build_hybrid_artifact(
    project_root: Path,
    analysis: ProjectAnalysis,
    fallback: str,
    build_tool: str = "cargo",
) -> BuildResult:
    layout = ArtifactLayout(project_root)
    plan = create_build_plan(analysis, fallback)
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
    _write_python_fallback_tree(plan.fallback, layout.python_dir)
    _write_runtime_support(layout.python_dir)
    native_build = _generate_and_build_native(plan, layout, build_tool)
    _write_build_artifact(layout)
    fallback_build = _build_fallback_backend(fallback, layout)
    wheel_build = _build_wheel_artifact(project_root, layout, native_build, fallback_build)

    result = BuildResult(
        fallback=fallback,
        layout=layout,
        plan=plan,
        accepted_native_count=plan.native.accepted_count,
        rejected_native_count=plan.native.rejected_count,
        native_build=native_build,
        fallback_build=fallback_build,
        wheel_build=wheel_build,
    )
    (layout.reports_dir / "build.json").write_text(
        json.dumps(
            {"status": _build_status(native_build, fallback_build), **result.to_dict()},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return result


def _write_python_fallback_tree(plan: FallbackPlan, python_root: Path) -> None:
    for module_plan in plan.modules:
        if not module_plan.needs_wrapper:
            write_plain_cpython_module(module_plan.module, python_root)
            continue
        write_cpython_fallback(module_plan.module, python_root)
        wrapper_path = generated_path_for_module(module_plan.module, python_root)
        wrapper_path.parent.mkdir(parents=True, exist_ok=True)
        wrapper_path.write_text(render_wrapper_module(module_plan.module), encoding="utf-8")


def _reset_generated_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)


def _write_build_artifact(layout: ArtifactLayout) -> None:
    if layout.build_python_dir.exists():
        shutil.rmtree(layout.build_python_dir)
    shutil.copytree(layout.python_dir, layout.build_python_dir)


def _write_runtime_support(python_root: Path) -> None:
    package_root = Path(__file__).resolve().parents[1]
    rextio_root = python_root / "rextio"
    rextio_root.mkdir(parents=True, exist_ok=True)
    shutil.copy2(package_root / "__init__.py", rextio_root / "__init__.py")

    runtime_destination = rextio_root / "runtime"
    if runtime_destination.exists():
        shutil.rmtree(runtime_destination)
    shutil.copytree(
        package_root / "runtime",
        runtime_destination,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )


def _generate_and_build_native(
    plan: BuildPlan,
    layout: ArtifactLayout,
    build_tool: str,
) -> NativeBuildResult:
    if not plan.native.accepted_functions:
        return skipped_native_build("No accepted native functions were found.")
    try:
        module_ir = lower_project(plan.analysis)
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


def _build_fallback_backend(fallback: str, layout: ArtifactLayout) -> FallbackBuildResult:
    if fallback == "cpython":
        return cpython_fallback_build_result()
    if fallback == "nuitka":
        return build_nuitka_fallback(layout.build_python_dir)
    return FallbackBuildResult(
        status="failed",
        backend=fallback,
        message=(
            "RXT060 Build failed while preparing fallback backend. "
            f"Cause: unsupported fallback backend: {fallback}."
        ),
    )


def _build_wheel_artifact(
    project_root: Path,
    layout: ArtifactLayout,
    native_build: NativeBuildResult,
    fallback_build: FallbackBuildResult,
) -> WheelBuildResult:
    if fallback_build.status != "built":
        return skipped_wheel("Fallback packaging failed, so no wheel was generated.")
    if native_build.status == "failed":
        return skipped_wheel("Native build failed, so no wheel was generated.")
    return build_artifact_wheel(project_root, layout.build_python_dir, layout.dist_dir)


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


def _build_status(
    native_build: NativeBuildResult,
    fallback_build: FallbackBuildResult,
) -> str:
    if fallback_build.status == "failed":
        return "fallback-build-failed"
    if native_build.tool == "codegen" and native_build.status == "failed":
        return "codegen-failed"
    if native_build.status == "failed":
        return "native-build-failed"
    return "built"
