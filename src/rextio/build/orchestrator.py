"""Build/generate orchestration: ties analysis, lowering, codegen, and the builders together."""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from rextio.analyzer.call_resolution import FunctionResolver
from rextio.analyzer.models import FunctionAnalysis, ProjectAnalysis
from rextio.analyzer.native_marker import external_accelerator_for_source
from rextio.ir.types import RxtPluginType, normalize_type_name
from rextio.build.cargo_builder import (
    NativeBuildResult,
    build_native_extension_with_cargo,
    skipped_native_build,
)
from rextio.build.executable_builder import (
    ExecutableBuildResult,
    build_nuitka_executable,
    build_rust_executable,
    build_zipapp_executable,
    skipped_executable,
)
from rextio.build.maturin_builder import build_native_extension_with_maturin
from rextio.build.preflight import nuitka_toolchain_error
from rextio.build.subprocess_utils import DEFAULT_BUILD_TIMEOUT_SECONDS, run_build_tool
from rextio.build.toolchain import resolve_nuitka_command, resolve_python
from rextio.config.schema import ToolchainConfig
from rextio.codegen.rust.cargo import (
    render_binary_cargo_toml,
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
from rextio.codegen.rust.generator import (
    generate_rust_crate_module,
    generate_rust_main_binary,
    generate_rust_module,
)
from rextio.codegen.rust.generator import RustCodegenError
from rextio.codegen.rust.subprocess_client import RUNTIME_DIR_SUFFIX
from rextio.codegen.subprocess_dispatcher import DISPATCHER_STEM, render_dispatcher_script
from rextio.codegen.python_wrapper.wrapper_gen import render_wrapper_module
from rextio.fallback.build_result import FallbackBuildResult, cpython_fallback_build_result
from rextio.fallback.cpython import (
    generated_path_for_module,
    write_cpython_fallback,
    write_cpython_native_top_level_fallback,
    write_plain_cpython_module,
)
from rextio.fallback.nuitka import build_nuitka_fallback
from rextio.ir.nodes import ModuleIR
from rextio.ir.lowering import LoweringError, PluginTypeMaps, lower_project
from rextio.build.artifact_layout import ArtifactLayout
from rextio.partition.build_plan import BuildPlan, create_build_plan
from rextio.partition.fallback_plan import FallbackPlan
from rextio.runtime.boundary_fallback import DEFAULT_BOUNDARY_FALLBACK_THRESHOLD
from rextio.targets.plan import TargetPlan, default_target_plan


# Modules the generated fallback dispatcher imports at runtime; a project
# module whose TOP-LEVEL name matches one of these would shadow it under the
# dispatcher's sys.path[0] and break delegated fallback (council round 8).
_DISPATCHER_RESERVED_TOP_LEVEL_NAMES = frozenset(
    {"importlib", "json", "os", "sys", "types", "rextio"}
)


def _plugin_lowering_inputs(
    target_plan: TargetPlan,
) -> tuple[PluginTypeMaps | None, dict[str, object] | None, dict[str, RxtPluginType] | None]:
    """Build the lowering/codegen plugin inputs from the target plan's registry.

    Returns ``(plugin_type_maps, plugin_providers, plugin_types_by_key)``, all
    None when no active plugin provides lowering. The ``RxtPluginType``
    instances are constructed once per plugin type key and shared by both
    maps, so identity/equality checks agree across lowering and codegen.
    """
    registry = target_plan.plugins
    if not registry.providers:
        return None, None, None
    by_key: dict[str, RxtPluginType] = {}
    by_spelling: dict[str, RxtPluginType] = {}
    for binding in registry.types:
        plugin_type = binding.plugin_type
        rxt_type = by_key.get(plugin_type.key)
        if rxt_type is None:
            rxt_type = RxtPluginType(
                key=plugin_type.key,
                native_rust=plugin_type.rust_type,
                param_rust=plugin_type.conversion.param_rust,
                param_expr=plugin_type.conversion.param_expr,
                return_rust=plugin_type.conversion.return_rust,
                return_expr=plugin_type.conversion.return_expr,
            )
            by_key[plugin_type.key] = rxt_type
        for spelling in plugin_type.annotations:
            by_spelling[spelling] = rxt_type
    providers: dict[str, object] = {
        binding.plugin_id: binding.provider for binding in registry.providers
    }
    return PluginTypeMaps(by_key=by_key, by_spelling=by_spelling), providers, by_key


@dataclass(frozen=True)
class NativeSourceResult:
    """The outcome of generating native source (no compilation)."""

    status: str
    message: str
    path: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this result."""
        return {
            "status": self.status,
            "message": self.message,
            "path": self.path,
        }


@dataclass(frozen=True)
class GenerateResult:
    """The aggregate result of ``rextio generate``."""

    fallback: str
    boundary_fallback_threshold: int
    target_plan: TargetPlan
    layout: ArtifactLayout
    plan: BuildPlan
    accepted_native_count: int
    rejected_native_count: int
    native_source: NativeSourceResult
    rust_crate_source: NativeSourceResult
    plugin_crate_dependencies: tuple[dict[str, object], ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this result."""
        data: dict[str, object] = {
            "fallback": self.fallback,
            "boundary_fallback_threshold": self.boundary_fallback_threshold,
            "target": self.target_plan.to_dict(),
            "generated_native": str(self.layout.target_dir(self.target_plan.spec.language)),
            "generated_rust": str(self.layout.rust_dir),
            "generated_python": str(self.layout.python_dir),
            "plan": self.plan.to_dict(),
            "accepted_native_count": self.accepted_native_count,
            "rejected_native_count": self.rejected_native_count,
            "embedding_candidate_count": len(self.plan.native.embedded_functions),
            "native_source": self.native_source.to_dict(),
            "rust_crate_source": self.rust_crate_source.to_dict(),
        }
        # Mirror build.json's plugin dependency report so the two reports stay
        # consistent (council round 8).
        if self.plugin_crate_dependencies:
            data["plugin_crate_dependencies"] = [
                dict(dependency) for dependency in self.plugin_crate_dependencies
            ]
        return data


@dataclass(frozen=True)
class BuildResult:
    """The aggregate result of ``rextio build``."""

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
    # Plugin-injected crate dependencies actually compiled into the native
    # extension: {"plugin_id", "name", "version", "features"} dicts
    # (docs/specs/plugin-lowering.md section 5). Empty for plugin-free builds.
    plugin_crate_dependencies: tuple[dict[str, object], ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this result.

        ``plugin_crate_dependencies`` is emitted only when non-empty, so
        ``build.json`` keeps its existing shape for plugin-free builds.
        """
        data: dict[str, object] = {
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
            "embedding_candidate_count": len(self.plan.native.embedded_functions),
            "native_build": self.native_build.to_dict(),
            "fallback_build": self.fallback_build.to_dict(),
            "wheel_build": self.wheel_build.to_dict(),
            "executable_build": self.executable_build.to_dict(),
            "rust_crate_build": self.rust_crate_build.to_dict(),
        }
        if self.plugin_crate_dependencies:
            data["plugin_crate_dependencies"] = [
                dict(dependency) for dependency in self.plugin_crate_dependencies
            ]
        return data


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
    embedding_enabled: bool = False,
    build_timeout_seconds: float = DEFAULT_BUILD_TIMEOUT_SECONDS,
    executable_analysis: ProjectAnalysis | None = None,
    executable_python: str | None = None,
    executable_hybrid_runtime: str = "source",
    toolchain: ToolchainConfig | None = None,
) -> BuildResult:
    """Build the hybrid native+fallback artifact for a project.

    ``executable_analysis`` is the project analysis the ``rust`` executable
    backend uses; it is analyzed in delegate mode so the entrypoint can call
    project fallback functions through the external CPython dispatcher. It
    defaults to ``analysis`` for the other backends, which do not delegate.
    """
    if executable_analysis is None:
        executable_analysis = analysis
    toolchain = toolchain or ToolchainConfig()
    target_plan = target_plan or default_target_plan()
    layout = ArtifactLayout(project_root)
    plan = create_build_plan(analysis, fallback)
    _reset_generated_dir(layout.build_dir)
    _prepare_generated_sources(layout, target_plan)
    _write_check_report(layout, analysis)
    _write_python_fallback_tree(plan.fallback, layout.python_dir, boundary_fallback_threshold)
    _write_runtime_support(layout.python_dir)
    native_build, plugin_crate_dependencies = _generate_and_build_native(
        plan,
        layout,
        build_tool,
        target_plan,
        embedding_enabled=embedding_enabled,
        build_timeout=build_timeout_seconds,
        toolchain=toolchain,
    )
    rust_crate_build = _generate_and_build_rust_crate(
        plan,
        layout,
        target_plan,
        enabled=rust_importable,
        crate_name=rust_crate_name,
        build_timeout=build_timeout_seconds,
        toolchain=toolchain,
    )
    _write_build_artifact(layout)
    fallback_build = _build_fallback_backend(
        fallback, layout, build_timeout=build_timeout_seconds, toolchain=toolchain
    )
    wheel_build = _build_wheel_artifact(project_root, layout, native_build, fallback_build)
    executable_build = _build_executable_artifact(
        layout,
        native_build,
        fallback_build,
        executable_entrypoint,
        executable_name,
        executable_backend,
        nuitka_mode,
        plan,
        executable_analysis,
        executable_python,
        executable_hybrid_runtime,
        target_plan,
        build_timeout=build_timeout_seconds,
        toolchain=toolchain,
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
        plugin_crate_dependencies=plugin_crate_dependencies,
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
    embedding_enabled: bool = False,
) -> GenerateResult:
    """Generate native and Python source artifacts without compiling."""
    target_plan = target_plan or default_target_plan()
    layout = ArtifactLayout(project_root)
    plan = create_build_plan(analysis, fallback)
    _prepare_generated_sources(layout, target_plan)
    _write_check_report(layout, analysis)
    _write_python_fallback_tree(plan.fallback, layout.python_dir, boundary_fallback_threshold)
    _write_runtime_support(layout.python_dir)
    native_source, plugin_crate_dependencies = _generate_native_source(
        plan,
        layout,
        target_plan,
        embedding_enabled=embedding_enabled,
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
        plugin_crate_dependencies=plugin_crate_dependencies,
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


def _reset_report_files(reports_dir: Path) -> None:
    """Clear stale reports so a run leaves only its own reports.

    ``build`` writes build.json+check.json and ``generate`` writes
    generate.json+check.json; without clearing, `generate` then `build` leaves
    a stale generate.json beside a fresh build.json (council round 8).
    """
    reports_dir.mkdir(parents=True, exist_ok=True)
    for name in ("build.json", "generate.json", "check.json"):
        (reports_dir / name).unlink(missing_ok=True)


def _prepare_generated_sources(layout: ArtifactLayout, target_plan: TargetPlan) -> None:
    _reset_generated_dir(layout.target_dir(target_plan.spec.language))
    _reset_generated_dir(layout.rust_crate_dir)
    _reset_generated_dir(layout.python_dir)
    if target_plan.spec.language == "rust":
        layout.rust_src_dir.mkdir(parents=True, exist_ok=True)
    else:
        layout.target_dir(target_plan.spec.language).mkdir(parents=True, exist_ok=True)
    layout.python_dir.mkdir(parents=True, exist_ok=True)
    _reset_report_files(layout.reports_dir)


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
    # `__init__` imports the version from `__about__`, so it must travel with it.
    shutil.copy2(package_root / "__about__.py", rextio_root / "__about__.py")

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
    embedding_enabled: bool,
    build_timeout: float = DEFAULT_BUILD_TIMEOUT_SECONDS,
    toolchain: ToolchainConfig | None = None,
) -> tuple[NativeBuildResult, tuple[dict[str, object], ...]]:
    if not plan.native.has_native_artifacts:
        return skipped_native_build("No accepted native functions were found."), ()
    native_source, plugin_crate_dependencies = _generate_native_source(
        plan,
        layout,
        target_plan,
        embedding_enabled=embedding_enabled,
    )
    if native_source.status == "failed":
        return NativeBuildResult(
            status="failed",
            tool="codegen",
            message=(
                "RXT050 Codegen failure while generating native target code. "
                f"Cause: {native_source.message}. Fallback Python files were still generated."
            ),
        ), ()

    if target_plan.spec.language == "rust":
        return (
            _build_native_with_selected_tool(layout, build_tool, build_timeout, toolchain),
            plugin_crate_dependencies,
        )
    return NativeBuildResult(
        status="failed",
        tool=target_plan.spec.language,
        message=(
            "RXT060 Build failed while compiling generated native module. "
            f"Cause: target language {target_plan.spec.language!r} is not implemented."
        ),
    ), ()


def _generate_and_build_rust_crate(
    plan: BuildPlan,
    layout: ArtifactLayout,
    target_plan: TargetPlan,
    *,
    enabled: bool,
    crate_name: str,
    build_timeout: float = DEFAULT_BUILD_TIMEOUT_SECONDS,
    toolchain: ToolchainConfig | None = None,
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
    return build_importable_rust_crate(
        layout.rust_crate_dir, layout.dist_dir, crate_name, timeout=build_timeout, toolchain=toolchain
    )


def _used_plugin_ids(analysis: ProjectAnalysis) -> set[str]:
    """Plugin ids whose lowering an accepted native function actually uses.

    From the claims (each carries its plugin id) and plugin-typed signatures
    (the type key is namespaced ``<plugin_id>/<slug>``) of accepted functions.
    """
    used: set[str] = set()
    for function in analysis.accepted_native_functions:
        used.update(claim.plugin_id for claim in function.plugin_claims)
        used.update(key.split("/", 1)[0] for key in function.plugin_type_keys)
    return used


def _generate_native_source(
    plan: BuildPlan,
    layout: ArtifactLayout,
    target_plan: TargetPlan,
    *,
    embedding_enabled: bool = False,
) -> tuple[NativeSourceResult, tuple[dict[str, object], ...]]:
    """Generate the PyO3 extension source; return (result, plugin crate deps).

    The second element lists the plugin-injected crate dependencies actually
    written into the generated Cargo.toml (empty unless the lowered module
    contains a plugin-lowered function), for the build report.
    """
    if not plan.native.has_native_artifacts:
        return NativeSourceResult(
            status="skipped",
            message="No accepted native functions were found.",
        ), ()
    if target_plan.spec.language != "rust":
        return NativeSourceResult(
            status="failed",
            message=(
                f"target language {target_plan.spec.language!r} is configurable, but no "
                "codegen backend is implemented for it yet"
            ),
        ), ()
    plugin_types, plugin_providers, plugin_types_by_key = _plugin_lowering_inputs(target_plan)
    try:
        module_ir = lower_project(
            plan.analysis, include_embedding=embedding_enabled, plugin_types=plugin_types
        )
        rust_source = generate_rust_module(
            module_ir,
            boundary_call_return_types=_boundary_call_return_types(plan.analysis),
            plugin_providers=plugin_providers,
            plugin_types_by_key=plugin_types_by_key,
        )
    except (LoweringError, RustCodegenError) as exc:
        return NativeSourceResult(
            status="failed",
            message=str(exc),
        ), ()

    registry = target_plan.plugins
    extra_dependencies: tuple[tuple[str, str, tuple[str, ...]], ...] = ()
    plugin_crate_dependencies: tuple[dict[str, object], ...] = ()
    used_plugin_ids = _used_plugin_ids(plan.analysis)
    if registry.crate_dependencies and used_plugin_ids:
        # Only the plugins whose lowering an ACCEPTED function actually uses
        # contribute crates; an enabled-but-unused plugin's dependency must not
        # be injected (it could break an otherwise valid build and misrepresent
        # the compiled artifact -- council round 8).
        used_bindings = tuple(
            binding
            for binding in registry.crate_dependencies
            if binding.plugin_id in used_plugin_ids
        )
        extra_dependencies = tuple(
            (binding.dependency.name, binding.dependency.version, binding.dependency.features)
            for binding in used_bindings
        )
        plugin_crate_dependencies = tuple(
            {
                "plugin_id": binding.plugin_id,
                "name": binding.dependency.name,
                "version": binding.dependency.version,
                "features": list(binding.dependency.features),
            }
            for binding in used_bindings
        )
    _write_rust_project(layout, rust_source, extra_dependencies=extra_dependencies)
    return NativeSourceResult(
        status="generated",
        message="Generated Rust source for accepted native functions.",
        path=str(layout.rust_src_dir / "lib.rs"),
    ), plugin_crate_dependencies


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
        # Include embedded helpers: an exported native function may call one, and
        # the crate must carry the callee it references. Plugin types are passed
        # so plugin-typed signatures lower; plugin-lowered functions are then
        # excluded from the crate (they have no pure-Rust form), so the crate
        # needs no providers and no cargo dependency injection.
        plugin_types, _plugin_providers, _plugin_types_by_key = _plugin_lowering_inputs(
            target_plan
        )
        module_ir = lower_project(plan.analysis, include_embedding=True, plugin_types=plugin_types)
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


def _build_fallback_backend(
    fallback: str,
    layout: ArtifactLayout,
    *,
    build_timeout: float = DEFAULT_BUILD_TIMEOUT_SECONDS,
    toolchain: ToolchainConfig | None = None,
) -> FallbackBuildResult:
    if fallback == "cpython":
        return cpython_fallback_build_result()
    if fallback == "nuitka":
        # The CLI pre-gates the Nuitka version floor for the FALLBACK path,
        # so this builder's own probe is only reachable here for programmatic
        # callers. The hybrid dispatcher (_build_nuitka_dispatcher) is NOT
        # pre-gated and keeps its own point-of-use probe.
        return build_nuitka_fallback(layout.build_python_dir, timeout=build_timeout, toolchain=toolchain)
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
    # A native build failure is not fatal to packaging: the importable hybrid
    # tree still works through the Python fallback, so produce a fallback-only
    # (pure-Python, py3-none-any) wheel instead of skipping. The wheel tag
    # reflects the absence of the native extension automatically.
    return build_artifact_wheel(project_root, layout.build_python_dir, layout.dist_dir)


def _build_executable_artifact(
    layout: ArtifactLayout,
    native_build: NativeBuildResult,
    fallback_build: FallbackBuildResult,
    entrypoint: str | None,
    executable_name: str | None,
    executable_backend: str,
    nuitka_mode: str,
    plan: BuildPlan,
    executable_analysis: ProjectAnalysis,
    executable_python: str | None,
    executable_hybrid_runtime: str,
    target_plan: TargetPlan,
    *,
    build_timeout: float = DEFAULT_BUILD_TIMEOUT_SECONDS,
    toolchain: ToolchainConfig | None = None,
) -> ExecutableBuildResult:
    if entrypoint is None:
        return skipped_executable("No executable entrypoint was requested.")
    if executable_backend == "rust":
        # The native Rust binary does not depend on the fallback packaging or the
        # PyO3 extension build. It uses the delegate-mode analysis so the entry can
        # call project fallback functions through the external CPython dispatcher.
        return _build_rust_executable_artifact(
            layout,
            executable_analysis,
            entrypoint,
            executable_name,
            executable_python,
            executable_hybrid_runtime,
            target_plan,
            build_timeout=build_timeout,
            toolchain=toolchain,
        )
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
            timeout=build_timeout,
            toolchain=toolchain,
        )
    return ExecutableBuildResult(
        status="failed",
        path=None,
        message=(
            "RXT060 Executable build failed because the executable backend was unsupported. "
            'Use "zipapp", "nuitka", or "rust".'
        ),
        entrypoint=entrypoint,
        backend=executable_backend,
    )


def _entrypoint_to_qualname(entrypoint: str) -> str:
    """Map an executable entrypoint ``module:function`` to a Rextio qualname."""
    return entrypoint.replace(":", ".", 1)


def _rust_binary_name(executable_name: str | None, entry_qualname: str) -> str:
    """Return a valid Cargo binary name for the executable."""
    raw = executable_name or entry_qualname.replace(".", "_")
    sanitized = re.sub(r"[^0-9A-Za-z_-]", "_", raw)
    return sanitized or "rextio_app"


def _delegated_return_types(analysis: ProjectAnalysis) -> dict[str, str]:
    """Map every delegated callee's qualname to its return type across the project."""
    return _scalar_callee_return_types(analysis, "delegated_call_targets")


def _boundary_call_return_types(analysis: ProjectAnalysis) -> dict[str, str]:
    """Map every boundary-called callee's qualname to its return type."""
    return _scalar_callee_return_types(analysis, "boundary_call_targets")


def _scalar_callee_return_types(analysis: ProjectAnalysis, targets_attr: str) -> dict[str, str]:
    by_qualname = {
        function.qualname: function
        for module in analysis.modules
        for function in module.functions
    }
    delegated: dict[str, str] = {}
    for module in analysis.modules:
        for function in module.functions:
            for target in getattr(function, targets_attr):
                callee = by_qualname.get(target)
                if callee is None:
                    continue
                return_type = (
                    callee.signature_return_type
                    or callee.inferred_return_type
                    or callee.annotated_return_type
                )
                # Normalize any `typing.`-qualified/capitalized alias to the builtin
                # form the codegen understands. Delegated returns are immutable scalars
                # only (the boundary check rejects containers), so this is defensive:
                # it keeps the recorded type in the exact spelling that passed the gate.
                # Keep it — if a future gate ever recorded an un-normalized alias, this
                # is what stops it reaching `type_from_string` in codegen as a raw alias.
                normalized = normalize_type_name(return_type)
                if normalized is not None:
                    delegated[target] = normalized
    return delegated


def _entrypoint_reachable_native_graph(
    analysis: ProjectAnalysis,
    entry_qualname: str,
) -> tuple[set[str], dict[str, str]]:
    """Return direct-native functions and delegated callees reachable from entry."""
    by_qualname = {
        function.qualname: function
        for module in analysis.modules
        for function in module.functions
    }
    modules_by_name = {module.module_name: module for module in analysis.modules}
    entry = by_qualname.get(entry_qualname)
    if (
        entry is None
        or not entry.accepted
        or entry.native_runtime_semantics
        or entry.is_embedding_candidate
    ):
        return set(), {}

    resolver = FunctionResolver(analysis)
    reachable: set[str] = set()
    delegated: dict[str, str] = {}
    stack = [entry]
    while stack:
        function = stack.pop()
        if function.qualname in reachable:
            continue
        reachable.add(function.qualname)
        module = modules_by_name.get(function.module_name)
        if module is None:
            continue
        for call in function.calls:
            resolved = resolver.resolve(module, call.target).function
            if resolved is None:
                continue
            if resolved.qualname in function.delegated_call_targets:
                return_type = _normalized_function_return_type(resolved)
                if return_type is not None:
                    delegated[resolved.qualname] = return_type
                continue
            if resolved.is_embedding_candidate:
                # An embedded helper is a plain crate function the caller invokes
                # directly; keep it in the reachable set so the IR filter emits it.
                # Its candidacy shape (a single scalar expression) has no calls of
                # its own, so it is a leaf.
                reachable.add(resolved.qualname)
                continue
            if resolved.accepted and not resolved.native_runtime_semantics:
                stack.append(resolved)
    return reachable, delegated


def _normalized_function_return_type(function: FunctionAnalysis) -> str | None:
    return_type = (
        function.signature_return_type
        or function.inferred_return_type
        or function.annotated_return_type
    )
    return normalize_type_name(return_type)


def _filter_module_ir(module_ir: ModuleIR, reachable_qualnames: set[str]) -> ModuleIR:
    """Keep only entry-reachable functions when generating a Rust executable."""
    if not reachable_qualnames:
        # An empty set means the entry itself was not an accepted direct-native
        # function. Pass the full IR through so `_resolve_main_entry` can name the
        # REAL problem (missing entry / RXT080 shim / embedding) - filtering everything
        # out here would degrade those diagnostics to a generic "missing entry".
        return module_ir
    return ModuleIR(
        [function for function in module_ir.functions if function.qualname in reachable_qualnames]
    )


def _write_hybrid_runtime(
    runtime_dir: Path, analysis: ProjectAnalysis, allowed_qualnames: set[str]
) -> None:
    """Write ``<binary>.runtime``: the dispatcher plus the project's Python source.

    The dispatcher imports the project modules by qualname to execute a delegated
    fallback function, so the original source tree is reconstructed here (with
    ``__init__.py`` for packages). Requires a Python interpreter (and the project's
    dependencies) at runtime.
    """
    if runtime_dir.exists():
        shutil.rmtree(runtime_dir)
    runtime_dir.mkdir(parents=True, exist_ok=True)
    dispatcher_path = runtime_dir / f"{DISPATCHER_STEM}.py"
    (dispatcher_path).write_text(
        render_dispatcher_script(sorted(allowed_qualnames)), encoding="utf-8"
    )
    for module in analysis.modules:
        parts = module.module_name.split(".") if module.module_name else [Path(module.file_path).stem]
        source_path = Path(module.file_path)
        if source_path.name == "__init__.py":
            target = runtime_dir.joinpath(*parts, "__init__.py")
        else:
            target = runtime_dir.joinpath(*parts).with_suffix(".py")
        if target == dispatcher_path or parts[0] == DISPATCHER_STEM:
            # Reject both the file form (`_rextio_dispatcher.py`, which would
            # overwrite the generated script) and the package form
            # (`_rextio_dispatcher/__init__.py`, which Python's import machinery
            # would prefer over the sibling script of the same name).
            raise RustCodegenError(
                f"hybrid runtime source collision: project module {module.module_name!r} "
                f"conflicts with the generated dispatcher {DISPATCHER_STEM!r}"
            )
        if parts[0] in _DISPATCHER_RESERVED_TOP_LEVEL_NAMES:
            # runtime_dir is sys.path[0] at dispatch time, so a project module
            # whose top-level name shadows a module the dispatcher imports
            # (json/os/sys/importlib/types) - or the rextio package itself -
            # would be found before the real one and crash the long-lived
            # dispatcher on its first request (council round 8).
            raise RustCodegenError(
                f"hybrid runtime source collision: project module {module.module_name!r} "
                f"shadows a name the fallback dispatcher relies on "
                f"({parts[0]!r}); rename the module or build a wheel/PyO3 artifact"
            )
        target.parent.mkdir(parents=True, exist_ok=True)
        # Make every intermediate directory an importable package.
        package_dir = runtime_dir
        for part in parts[:-1]:
            package_dir = package_dir / part
            init = package_dir / "__init__.py"
            if not init.exists():
                init.write_text("", encoding="utf-8")
        shutil.copy2(source_path, target)


def _externally_accelerated_runtime_modules(analysis: ProjectAnalysis) -> list[str]:
    """Return project modules using an external accelerator (e.g. numba).

    The hybrid runtime copies EVERY project module next to the dispatcher, and a
    Nuitka onefile dispatcher follows imports from the delegated modules into
    their siblings — so a delegated-qualname check alone would miss a plain
    delegated function that transitively imports an accelerated module. Scan the
    whole tree instead: over-rejecting an unreachable accelerated module is the
    safe direction, and ``--hybrid-runtime=source`` is the escape hatch.
    """
    accelerated: list[str] = []
    project_modules = frozenset(
        (module.module_name or Path(module.file_path).stem).split(".", 1)[0]
        for module in analysis.modules
    )
    for module in analysis.modules:
        try:
            source = Path(module.file_path).read_text(encoding="utf-8")
        except OSError:
            continue
        if external_accelerator_for_source(source, project_modules) is not None:
            accelerated.append(module.module_name or Path(module.file_path).stem)
    return sorted(accelerated)


def _delegation_python(
    executable_python: str | None, toolchain: ToolchainConfig | None
) -> str:
    """Return the interpreter command baked into the hybrid binary for delegated calls.

    Explicit [executable] python wins; otherwise the [toolchain] python keeps
    the runtime on the same interpreter the build targeted; otherwise the
    portable default. REXTIO_RUNTIME_PYTHON still overrides at run time.
    """
    if executable_python is not None:
        return executable_python
    configured, _error = resolve_python(toolchain or ToolchainConfig())
    return configured or "python3"


def _build_nuitka_dispatcher(
    runtime_dir: Path,
    allowed_qualnames: set[str],
    timeout: float,
    toolchain: ToolchainConfig | None = None,
) -> str | None:
    """Compile the dispatcher into a self-contained executable; return an error or None.

    Produces `<runtime>/{stem}` (Nuitka onefile, where ``stem`` is
    ``DISPATCHER_STEM``) with the delegated fallback modules bundled, so the hybrid
    binary needs no separate Python install.
    """
    nuitka_command, resolve_error = resolve_nuitka_command(toolchain or ToolchainConfig())
    if nuitka_command is None:
        return resolve_error or (
            "Nuitka is not installed but --hybrid-runtime=nuitka was requested. "
            "Install Nuitka or use --hybrid-runtime=source."
        )
    version_error = nuitka_toolchain_error(nuitka_command, toolchain)
    if version_error is not None:
        return version_error
    modules = sorted({q.rpartition(".")[0] for q in allowed_qualnames if "." in q})
    command = [
        *nuitka_command,
        "--onefile",
        "--assume-yes-for-downloads",
        f"{DISPATCHER_STEM}.py",
        f"--output-dir={runtime_dir}",
        f"--output-filename={DISPATCHER_STEM}",
        "--remove-output",
        *(f"--include-module={module}" for module in modules),
    ]
    completed = run_build_tool(command, cwd=runtime_dir, timeout=timeout)
    if completed.returncode != 0:
        return f"Nuitka failed to compile the dispatcher (exit status {completed.returncode})."
    # Nuitka appends the OS executable extension (`.exe` on Windows), so accept both.
    if not any((runtime_dir / f"{DISPATCHER_STEM}{suffix}").exists() for suffix in ("", ".exe")):
        return "Nuitka completed but the compiled dispatcher was not found."
    return None


def _build_rust_executable_artifact(
    layout: ArtifactLayout,
    analysis: ProjectAnalysis,
    entrypoint: str,
    executable_name: str | None,
    executable_python: str | None,
    hybrid_runtime: str,
    target_plan: TargetPlan | None = None,
    *,
    build_timeout: float,
    toolchain: ToolchainConfig | None = None,
) -> ExecutableBuildResult:
    """Generate and build the native Rust executable for the entrypoint.

    The entrypoint must be an accepted direct-native ``def main(argv: list[str])
    -> int``. Any call it (or its native call graph) makes to a project fallback
    function is delegated to an external CPython dispatcher shipped next to the
    binary as ``<binary>.runtime``; a binary with no delegated calls needs no
    Python runtime at all.
    """
    configured_python, python_error = resolve_python(toolchain or ToolchainConfig())
    if (toolchain and toolchain.python is not None) and configured_python is None:
        # Do not silently degrade to "python3": programmatic callers skip the
        # CLI preflight, and a binary baked with the wrong interpreter fails
        # far from the cause.
        return ExecutableBuildResult(
            status="failed",
            path=None,
            message=f"RXT060 Executable build failed. {python_error}",
            entrypoint=entrypoint,
            backend="rust",
        )
    entry_qualname = _entrypoint_to_qualname(entrypoint)
    reachable_qualnames, delegated_return_types = _entrypoint_reachable_native_graph(
        analysis,
        entry_qualname,
    )
    nuitka_dispatcher = hybrid_runtime == "nuitka"
    if nuitka_dispatcher and delegated_return_types:
        accelerated = _externally_accelerated_runtime_modules(analysis)
        if accelerated:
            names = ", ".join(accelerated)
            return ExecutableBuildResult(
                status="failed",
                path=None,
                message=(
                    "RXT060 Executable build failed: project module(s) "
                    f"{names} use an external accelerator (e.g. Numba), which a "
                    "Nuitka-compiled dispatcher cannot serve (compiled functions "
                    "expose no bytecode for the accelerator and the accelerator "
                    "package is not bundled). Every project module ships in the "
                    "hybrid runtime and Nuitka follows imports into it, so this "
                    "applies even when no accelerated function is delegated "
                    "directly. Use --hybrid-runtime=source, whose dispatcher "
                    "runs real CPython with the project's environment."
                ),
                entrypoint=entrypoint,
                backend="rust",
            )
    try:
        # Plugin types let plugin-typed signatures lower; plugin-lowered
        # functions have no pure-Rust form, so the crate renderer's exclusion
        # and mode guard keep them out of the binary (never delegated either:
        # plugin types never cross the delegation wire).
        plugin_types, _plugin_providers, _plugin_types_by_key = _plugin_lowering_inputs(
            target_plan or default_target_plan()
        )
        module_ir = _filter_module_ir(
            lower_project(analysis, include_embedding=True, plugin_types=plugin_types),
            reachable_qualnames,
        )
        main_rs = generate_rust_main_binary(
            module_ir,
            entry_qualname,
            delegated_return_types,
            _delegation_python(executable_python, toolchain),
            nuitka_dispatcher=nuitka_dispatcher,
        )
    except (RustCodegenError, LoweringError) as exc:
        return ExecutableBuildResult(
            status="failed",
            path=None,
            message=f"RXT060 Executable build failed while generating the Rust binary. Cause: {exc}",
            entrypoint=entrypoint,
            backend="rust",
        )

    binary_name = _rust_binary_name(executable_name, entry_qualname)
    hybrid = bool(delegated_return_types)
    crate_dir = layout.rust_bin_dir
    if crate_dir.exists():
        shutil.rmtree(crate_dir)
    layout.rust_bin_src_dir.mkdir(parents=True, exist_ok=True)
    (crate_dir / "Cargo.toml").write_text(
        render_binary_cargo_toml("rextio_generated_bin", binary_name, hybrid=hybrid),
        encoding="utf-8",
    )
    (layout.rust_bin_src_dir / "main.rs").write_text(main_rs, encoding="utf-8")

    result = build_rust_executable(
        crate_dir, layout.dist_dir, binary_name, entrypoint, timeout=build_timeout, toolchain=toolchain
    )
    if result.status == "built" and hybrid:
        # Ship the dispatcher + project source as `<binary>.runtime` next to the
        # binary so the client can launch CPython for delegated calls.
        runtime_dir = layout.dist_dir / f"{binary_name}{RUNTIME_DIR_SUFFIX}"
        try:
            _write_hybrid_runtime(runtime_dir, analysis, set(delegated_return_types))
        except RustCodegenError as exc:
            _cleanup_rust_executable_outputs(result.path, runtime_dir)
            return ExecutableBuildResult(
                status="failed",
                path=None,
                message=f"RXT060 Executable build failed while packaging the dispatcher. Cause: {exc}",
                entrypoint=entrypoint,
                backend="rust",
            )
        if nuitka_dispatcher:
            error = _build_nuitka_dispatcher(
                runtime_dir, set(delegated_return_types), build_timeout, toolchain
            )
            if error is not None:
                _cleanup_rust_executable_outputs(result.path, runtime_dir)
                return ExecutableBuildResult(
                    status="failed",
                    path=None,
                    message=f"RXT060 Executable build failed while packaging the dispatcher. Cause: {error}",
                    entrypoint=entrypoint,
                    backend="rust",
                )
    return result


def _cleanup_rust_executable_outputs(binary_path: str | None, runtime_dir: Path) -> None:
    """Remove a copied binary and runtime directory after packaging failure."""
    if binary_path is not None:
        binary = Path(binary_path)
        if binary.exists():
            binary.unlink()
    if runtime_dir.exists():
        shutil.rmtree(runtime_dir)


def _build_native_with_selected_tool(
    layout: ArtifactLayout,
    build_tool: str,
    build_timeout: float = DEFAULT_BUILD_TIMEOUT_SECONDS,
    toolchain: ToolchainConfig | None = None,
) -> NativeBuildResult:
    normalized = build_tool.lower()
    if normalized == "cargo":
        return build_native_extension_with_cargo(
            layout.rust_dir, layout.python_dir, timeout=build_timeout, toolchain=toolchain
        )
    if normalized == "maturin":
        result = build_native_extension_with_maturin(
            layout.rust_dir, layout.python_dir, timeout=build_timeout, toolchain=toolchain
        )
        if result.status == "built":
            return result
        if "maturin was not found" not in result.message:
            return result
        cargo_result = build_native_extension_with_cargo(
            layout.rust_dir, layout.python_dir, timeout=build_timeout, toolchain=toolchain
        )
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


def _write_rust_project(
    layout: ArtifactLayout,
    rust_source: str,
    extra_dependencies: tuple[tuple[str, str, tuple[str, ...]], ...] = (),
) -> None:
    layout.rust_src_dir.mkdir(parents=True, exist_ok=True)
    (layout.rust_dir / "Cargo.toml").write_text(
        render_cargo_toml(extra_dependencies=extra_dependencies),
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
