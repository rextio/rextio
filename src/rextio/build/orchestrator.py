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
from rextio.build.executable_builder import (
    ExecutableBuildResult,
    build_nuitka_executable,
    build_zipapp_executable,
    skipped_executable,
)
from rextio.build.maturin_builder import build_native_extension_with_maturin
from rextio.codegen.rust.cargo import (
    render_cargo_config_toml,
    render_cargo_toml,
    render_importable_cargo_toml,
    render_pyproject_toml,
)
from rextio.build.rust_crate_builder import (
    RustCrateBuildResult,
    build_importable_rust_crate,
    skipped_rust_crate_build,
)
from rextio.build.wheel_builder import (
    WheelBuildResult,
    build_artifact_wheel,
    skipped_wheel,
)
from rextio.codegen.rust.generator import generate_rust_crate_module, generate_rust_module
from rextio.codegen.rust.generator import RustCodegenError
from rextio.codegen.python_wrapper.wrapper_gen import render_wrapper_module
from rextio.fallback.build_result import FallbackBuildResult, cpython_fallback_build_result
from rextio.fallback.cpython import (
    generated_path_for_module,
    write_cpython_fallback,
    write_cpython_native_top_level_fallback,
    write_plain_cpython_module,
)
from rextio.fallback.nuitka import build_nuitka_fallback
from rextio.ir.lowering import LoweringError, lower_project
from rextio.build.artifact_layout import ArtifactLayout
from rextio.partition.build_plan import BuildPlan, create_build_plan
from rextio.partition.fallback_plan import FallbackPlan
from rextio.runtime.boundary_fallback import DEFAULT_BOUNDARY_FALLBACK_THRESHOLD
from rextio.targets.plan import TargetPlan, default_target_plan


@dataclass(frozen=True)
class NativeSourceResult:
    status: str
    message: str
    path: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "message": self.message,
            "path": self.path,
        }


@dataclass(frozen=True)
class GenerateResult:
    fallback: str
    boundary_fallback_threshold: int
    target_plan: TargetPlan
    layout: ArtifactLayout
    plan: BuildPlan
    accepted_native_count: int
    rejected_native_count: int
    native_source: NativeSourceResult
    rust_crate_source: NativeSourceResult

    def to_dict(self) -> dict[str, object]:
        return {
            "fallback": self.fallback,
            "boundary_fallback_threshold": self.boundary_fallback_threshold,
            "target": self.target_plan.to_dict(),
            "generated_native": str(self.layout.target_dir(self.target_plan.spec.language)),
            "generated_rust": str(self.layout.rust_dir),
            "generated_python": str(self.layout.python_dir),
            "plan": self.plan.to_dict(),
            "accepted_native_count": self.accepted_native_count,
            "rejected_native_count": self.rejected_native_count,
            "jit_candidate_count": len(self.plan.native.jit_functions),
            "native_source": self.native_source.to_dict(),
            "rust_crate_source": self.rust_crate_source.to_dict(),
        }


@dataclass(frozen=True)
class BuildResult:
    fallback: str
    boundary_fallback_threshold: int
    target_plan: TargetPlan
    layout: ArtifactLayout
    plan: BuildPlan
    accepted_native_count: int
    rejected_native_count: int
    native_build: NativeBuildResult
    fallback_build: FallbackBuildResult
    wheel_build: WheelBuildResult
    executable_build: ExecutableBuildResult
    rust_crate_build: RustCrateBuildResult

    def to_dict(self) -> dict[str, object]:
        return {
            "fallback": self.fallback,
            "boundary_fallback_threshold": self.boundary_fallback_threshold,
            "target": self.target_plan.to_dict(),
            "generated_native": str(self.layout.target_dir(self.target_plan.spec.language)),
            "generated_rust": str(self.layout.rust_dir),
            "generated_python": str(self.layout.python_dir),
            "build_python": str(self.layout.build_python_dir),
            "plan": self.plan.to_dict(),
            "accepted_native_count": self.accepted_native_count,
            "rejected_native_count": self.rejected_native_count,
            "jit_candidate_count": len(self.plan.native.jit_functions),
            "native_build": self.native_build.to_dict(),
            "fallback_build": self.fallback_build.to_dict(),
            "wheel_build": self.wheel_build.to_dict(),
            "executable_build": self.executable_build.to_dict(),
            "rust_crate_build": self.rust_crate_build.to_dict(),
        }


def build_hybrid_artifact(
    project_root: Path,
    analysis: ProjectAnalysis,
    fallback: str,
    build_tool: str = "cargo",
    boundary_fallback_threshold: int = DEFAULT_BOUNDARY_FALLBACK_THRESHOLD,
    executable_entrypoint: str | None = None,
    executable_name: str | None = None,
    executable_backend: str = "zipapp",
    nuitka_mode: str = "standalone",
    target_plan: TargetPlan | None = None,
    rust_importable: bool = False,
    rust_crate_name: str = "rextio_generated_rust",
    native_jit_enabled: bool = False,
    jit_hot_threshold: int = 25,
) -> BuildResult:
    target_plan = target_plan or default_target_plan()
    layout = ArtifactLayout(project_root)
    plan = create_build_plan(analysis, fallback)
    _reset_generated_dir(layout.build_dir)
    _prepare_generated_sources(layout, target_plan)
    _write_check_report(layout, analysis)
    _write_python_fallback_tree(plan.fallback, layout.python_dir, boundary_fallback_threshold)
    _write_runtime_support(layout.python_dir)
    native_build = _generate_and_build_native(
        plan,
        layout,
        build_tool,
        target_plan,
        native_jit_enabled=native_jit_enabled,
    )
    rust_crate_build = _generate_and_build_rust_crate(
        plan,
        layout,
        target_plan,
        enabled=rust_importable,
        crate_name=rust_crate_name,
    )
    _write_build_artifact(layout)
    fallback_build = _build_fallback_backend(fallback, layout)
    wheel_build = _build_wheel_artifact(project_root, layout, native_build, fallback_build)
    executable_build = _build_executable_artifact(
        layout,
        native_build,
        fallback_build,
        executable_entrypoint,
        executable_name,
        executable_backend,
        nuitka_mode,
    )

    result = BuildResult(
        fallback=fallback,
        boundary_fallback_threshold=boundary_fallback_threshold,
        target_plan=target_plan,
        layout=layout,
        plan=plan,
        accepted_native_count=plan.native.accepted_count,
        rejected_native_count=plan.native.rejected_count,
        native_build=native_build,
        fallback_build=fallback_build,
        wheel_build=wheel_build,
        executable_build=executable_build,
        rust_crate_build=rust_crate_build,
    )
    (layout.reports_dir / "build.json").write_text(
        json.dumps(
            {
                "status": _build_status(
                    native_build,
                    fallback_build,
                    executable_build,
                    rust_crate_build,
                ),
                **result.to_dict(),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return result


def generate_source_artifact(
    project_root: Path,
    analysis: ProjectAnalysis,
    fallback: str,
    boundary_fallback_threshold: int = DEFAULT_BOUNDARY_FALLBACK_THRESHOLD,
    target_plan: TargetPlan | None = None,
    rust_importable: bool = False,
    rust_crate_name: str = "rextio_generated_rust",
    native_jit_enabled: bool = False,
    jit_hot_threshold: int = 25,
) -> GenerateResult:
    target_plan = target_plan or default_target_plan()
    layout = ArtifactLayout(project_root)
    plan = create_build_plan(analysis, fallback)
    _prepare_generated_sources(layout, target_plan)
    _write_check_report(layout, analysis)
    _write_python_fallback_tree(plan.fallback, layout.python_dir, boundary_fallback_threshold)
    _write_runtime_support(layout.python_dir)
    native_source = _generate_native_source(
        plan,
        layout,
        target_plan,
        native_jit_enabled=native_jit_enabled,
    )
    rust_crate_source = _generate_rust_crate_source(
        plan,
        layout,
        target_plan,
        enabled=rust_importable,
        crate_name=rust_crate_name,
    )

    result = GenerateResult(
        fallback=fallback,
        boundary_fallback_threshold=boundary_fallback_threshold,
        target_plan=target_plan,
        layout=layout,
        plan=plan,
        accepted_native_count=plan.native.accepted_count,
        rejected_native_count=plan.native.rejected_count,
        native_source=native_source,
        rust_crate_source=rust_crate_source,
    )
    (layout.reports_dir / "generate.json").write_text(
        json.dumps(
            {"status": _generate_status(native_source, rust_crate_source), **result.to_dict()},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return result


def _prepare_generated_sources(layout: ArtifactLayout, target_plan: TargetPlan) -> None:
    _reset_generated_dir(layout.target_dir(target_plan.spec.language))
    _reset_generated_dir(layout.rust_crate_dir)
    _reset_generated_dir(layout.python_dir)
    if target_plan.spec.language == "rust":
        layout.rust_src_dir.mkdir(parents=True, exist_ok=True)
    else:
        layout.target_dir(target_plan.spec.language).mkdir(parents=True, exist_ok=True)
    layout.python_dir.mkdir(parents=True, exist_ok=True)
    layout.reports_dir.mkdir(parents=True, exist_ok=True)


def _write_check_report(layout: ArtifactLayout, analysis: ProjectAnalysis) -> None:
    (layout.reports_dir / "check.json").write_text(
        json.dumps(analysis.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _write_python_fallback_tree(
    plan: FallbackPlan,
    python_root: Path,
    boundary_fallback_threshold: int,
) -> None:
    for module_plan in plan.modules:
        if not module_plan.needs_wrapper:
            write_plain_cpython_module(module_plan.module, python_root)
            continue
        write_cpython_fallback(module_plan.module, python_root)
        if module_plan.accepted_native_top_level is not None:
            write_cpython_native_top_level_fallback(module_plan.module, python_root)
        wrapper_path = generated_path_for_module(module_plan.module, python_root)
        wrapper_path.parent.mkdir(parents=True, exist_ok=True)
        wrapper_path.write_text(
            render_wrapper_module(module_plan.module, boundary_fallback_threshold),
            encoding="utf-8",
        )


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
    target_plan: TargetPlan,
    *,
    native_jit_enabled: bool,
) -> NativeBuildResult:
    if not plan.native.has_native_artifacts:
        return skipped_native_build("No accepted native functions were found.")
    native_source = _generate_native_source(
        plan,
        layout,
        target_plan,
        native_jit_enabled=native_jit_enabled,
    )
    if native_source.status == "failed":
        return NativeBuildResult(
            status="failed",
            tool="codegen",
            message=(
                "RXT050 Codegen failure while generating native target code. "
                f"Cause: {native_source.message}. Fallback Python files were still generated."
            ),
        )

    if target_plan.spec.language == "rust":
        return _build_native_with_selected_tool(layout, build_tool)
    return NativeBuildResult(
        status="failed",
        tool=target_plan.spec.language,
        message=(
            "RXT060 Build failed while compiling generated native module. "
            f"Cause: target language {target_plan.spec.language!r} is not implemented."
        ),
    )


def _generate_and_build_rust_crate(
    plan: BuildPlan,
    layout: ArtifactLayout,
    target_plan: TargetPlan,
    *,
    enabled: bool,
    crate_name: str,
) -> RustCrateBuildResult:
    if not enabled:
        return skipped_rust_crate_build("Rust-importable crate was not requested.")
    source = _generate_rust_crate_source(
        plan,
        layout,
        target_plan,
        enabled=True,
        crate_name=crate_name,
    )
    if source.status != "generated":
        if source.status == "skipped":
            return skipped_rust_crate_build(source.message)
        return RustCrateBuildResult(
            status="failed",
            message=(
                "RXT050 Codegen failure while generating Rust-importable crate. "
                f"Cause: {source.message}."
            ),
        )
    return build_importable_rust_crate(layout.rust_crate_dir, layout.dist_dir, crate_name)


def _generate_native_source(
    plan: BuildPlan,
    layout: ArtifactLayout,
    target_plan: TargetPlan,
    *,
    native_jit_enabled: bool = False,
) -> NativeSourceResult:
    if not plan.native.has_native_artifacts:
        return NativeSourceResult(
            status="skipped",
            message="No accepted native functions were found.",
        )
    if target_plan.spec.language != "rust":
        return NativeSourceResult(
            status="failed",
            message=(
                f"target language {target_plan.spec.language!r} is configurable, but no "
                "codegen backend is implemented for it yet"
            ),
        )
    try:
        module_ir = lower_project(plan.analysis, include_jit=native_jit_enabled)
        rust_source = generate_rust_module(module_ir)
    except (LoweringError, RustCodegenError) as exc:
        return NativeSourceResult(
            status="failed",
            message=str(exc),
        )

    _write_rust_project(layout, rust_source, include_jit=bool(plan.native.jit_functions and native_jit_enabled))
    return NativeSourceResult(
        status="generated",
        message="Generated Rust source for accepted native functions.",
        path=str(layout.rust_src_dir / "lib.rs"),
    )


def _generate_rust_crate_source(
    plan: BuildPlan,
    layout: ArtifactLayout,
    target_plan: TargetPlan,
    *,
    enabled: bool,
    crate_name: str,
) -> NativeSourceResult:
    if not enabled:
        return NativeSourceResult(
            status="skipped",
            message="Rust-importable crate was not requested.",
        )
    if not plan.native.has_native_artifacts:
        return NativeSourceResult(
            status="skipped",
            message="No accepted native functions were found.",
        )
    if target_plan.spec.language != "rust":
        return NativeSourceResult(
            status="failed",
            message=(
                f"target language {target_plan.spec.language!r} is configurable, but a "
                "Rust-importable crate can only be generated for target language 'rust'"
            ),
        )
    try:
        module_ir = lower_project(plan.analysis)
        rust_source = generate_rust_crate_module(module_ir)
    except (LoweringError, RustCodegenError) as exc:
        return NativeSourceResult(
            status="failed",
            message=str(exc),
        )

    _write_rust_crate_project(layout, rust_source, crate_name)
    return NativeSourceResult(
        status="generated",
        message="Generated Rust-importable crate source for direct native functions.",
        path=str(layout.rust_crate_src_dir / "lib.rs"),
    )


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


def _build_executable_artifact(
    layout: ArtifactLayout,
    native_build: NativeBuildResult,
    fallback_build: FallbackBuildResult,
    entrypoint: str | None,
    executable_name: str | None,
    executable_backend: str,
    nuitka_mode: str,
) -> ExecutableBuildResult:
    if entrypoint is None:
        return skipped_executable("No executable entrypoint was requested.")
    if fallback_build.status != "built":
        return skipped_executable("Fallback packaging failed, so no executable was generated.")
    if native_build.status == "failed":
        return skipped_executable("Native build failed, so no executable was generated.")
    if executable_backend == "zipapp":
        return build_zipapp_executable(
            layout.build_python_dir,
            layout.dist_dir,
            entrypoint,
            executable_name,
        )
    if executable_backend == "nuitka":
        return build_nuitka_executable(
            layout.build_python_dir,
            layout.dist_dir,
            entrypoint,
            executable_name,
            nuitka_mode,
        )
    return ExecutableBuildResult(
        status="failed",
        path=None,
        message=(
            "RXT060 Executable build failed because the executable backend was unsupported. "
            'Use "zipapp" or "nuitka".'
        ),
        entrypoint=entrypoint,
        backend=executable_backend,
    )


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


def _write_rust_project(layout: ArtifactLayout, rust_source: str, *, include_jit: bool = False) -> None:
    layout.rust_src_dir.mkdir(parents=True, exist_ok=True)
    (layout.rust_dir / "Cargo.toml").write_text(
        render_cargo_toml(include_jit=include_jit),
        encoding="utf-8",
    )
    (layout.rust_dir / "pyproject.toml").write_text(render_pyproject_toml(), encoding="utf-8")
    (layout.rust_dir / ".cargo").mkdir(parents=True, exist_ok=True)
    (layout.rust_dir / ".cargo" / "config.toml").write_text(
        render_cargo_config_toml(),
        encoding="utf-8",
    )
    (layout.rust_src_dir / "lib.rs").write_text(rust_source, encoding="utf-8")


def _write_rust_crate_project(layout: ArtifactLayout, rust_source: str, crate_name: str) -> None:
    layout.rust_crate_src_dir.mkdir(parents=True, exist_ok=True)
    (layout.rust_crate_dir / "Cargo.toml").write_text(
        render_importable_cargo_toml(crate_name),
        encoding="utf-8",
    )
    (layout.rust_crate_src_dir / "lib.rs").write_text(rust_source, encoding="utf-8")


def _build_status(
    native_build: NativeBuildResult,
    fallback_build: FallbackBuildResult,
    executable_build: ExecutableBuildResult | None = None,
    rust_crate_build: RustCrateBuildResult | None = None,
) -> str:
    if fallback_build.status == "failed":
        return "fallback-build-failed"
    if native_build.tool == "codegen" and native_build.status == "failed":
        return "codegen-failed"
    if native_build.status == "failed":
        return "native-build-failed"
    if executable_build is not None and executable_build.status == "failed":
        return "executable-build-failed"
    if rust_crate_build is not None and rust_crate_build.status == "failed":
        return "rust-crate-build-failed"
    return "built"


def _generate_status(
    native_source: NativeSourceResult,
    rust_crate_source: NativeSourceResult | None = None,
) -> str:
    if native_source.status == "failed":
        return "codegen-failed"
    if rust_crate_source is not None and rust_crate_source.status == "failed":
        return "rust-crate-codegen-failed"
    return "generated"
