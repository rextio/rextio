"""The ``rextio build`` command."""

from __future__ import annotations

import json
import os
import shutil
from argparse import Namespace
from pathlib import Path

from rextio.analyzer.project_scanner import analyze_project
from rextio.build.orchestrator import BuildResult, build_hybrid_artifact
from rextio.build.preflight import format_missing_tools, missing_build_tools, nuitka_version_error
from rextio.cli.config_overrides import key_value_overrides, package_policy_overrides, tuple_overrides
from rextio.cli.reporter import Reporter
from rextio.config.loader import ConfigError, load_config, override_config
from rextio.fallback.nuitka import nuitka_unavailable_message
from rextio.targets.plan import TargetPlanError, create_target_plan


def run(args: Namespace) -> int:
    """Run the build command; return the process exit code."""
    reporter = Reporter.from_args(args)
    project_root = Path(args.project_root).resolve()
    try:
        config = override_config(
            load_config(project_root, environ=os.environ),
            {
                ("build", "native_backend"): args.native_backend,
                ("build", "fallback_backend"): args.fallback,
                ("build", "fallback_threshold"): args.fallback_threshold,
                ("build", "build_timeout_seconds"): args.build_timeout,
                ("rust", "binding"): args.rust_binding,
                ("rust", "build_tool"): args.rust_build_tool,
                ("rust", "importable"): args.rust_importable,
                ("rust", "crate_name"): args.rust_crate_name,
                ("fallback", "nuitka"): args.nuitka_fallback,
                ("target", "version"): args.target_version,
                ("target", "build_options"): key_value_overrides(args.target_build_option),
                ("plugins", "enabled"): tuple_overrides(args.plugin_enabled),
                ("imports", "default_external_policy"): args.default_external_policy,
                ("imports", "packages"): package_policy_overrides(args.package_import_policy),
                ("jit", "enabled"): args.jit,
                ("executable", "entrypoint"): args.entrypoint,
                ("executable", "name"): args.executable_name,
                ("executable", "backend"): args.executable_backend,
                ("executable", "python"): args.executable_python,
                ("executable", "hybrid_runtime"): args.hybrid_runtime,
                ("executable", "nuitka_mode"): args.nuitka_mode,
                ("policy", "native_marker"): args.native_marker,
                ("policy", "require_type_hints"): args.require_type_hints,
                ("policy", "allow_dynamic_features"): args.allow_dynamic_features,
                ("policy", "boundary_warnings"): args.boundary_warnings,
                ("policy", "native_top_level"): args.native_top_level,
            },
        )
        target_plan = create_target_plan(project_root, config)
    except (ConfigError, TargetPlanError) as exc:
        reporter.error("RXT060 Build failed while loading configuration.")
        reporter.error(f"Cause: {exc}")
        reporter.error(f"Suggestion: fix {project_root / 'rextio.toml'} and rerun rextio build.")
        return 1
    fallback = config.build.fallback_backend
    if fallback not in {"cpython", "nuitka"}:
        reporter.error("RXT060 Build failed while preparing fallback backend.")
        reporter.error(f"Cause: unsupported fallback backend: {fallback}")
        reporter.error(
            'Suggestion: use fallback_backend = "cpython" or run rextio build --fallback=cpython'
        )
        return 1

    # Paths that ALWAYS invoke Nuitka when reached: the Nuitka fallback and a
    # Nuitka executable with an entrypoint. The rust-executable hybrid runtime
    # is deliberately NOT gated here: it only invokes Nuitka when analysis
    # finds delegated fallback calls, so a pre-analysis rejection would block
    # valid no-delegation builds that never touch Nuitka. The dispatcher
    # builder enforces the version floor at the point of real use.
    nuitka_requested = fallback == "nuitka" or (
        config.executable.entrypoint is not None and config.executable.backend == "nuitka"
    )
    if nuitka_requested:
        nuitka = shutil.which("nuitka")
        if nuitka is None:
            if fallback == "nuitka":
                reporter.error("RXT060 Build failed while preparing Nuitka fallback.")
                reporter.error(nuitka_unavailable_message())
                return 1
            # Executable/hybrid paths keep their existing missing-tool handling
            # (reported by the builder with path-specific guidance).
        else:
            # Fail before the (potentially slow) project analysis, not mid-build.
            # The builders re-probe later so they stay correct for non-CLI callers;
            # the extra `nuitka --version` is a deliberate, negligible cost.
            version_error = nuitka_version_error(nuitka)
            if version_error is not None:
                reporter.error("RXT060 Build failed while preparing the Nuitka toolchain.")
                reporter.error(version_error)
                return 1

    analysis = analyze_project(
        project_root,
        boundary_warnings=config.policy.boundary_warnings,
        native_marker=config.policy.native_marker,
        target_language=target_plan.spec.language,
        native_top_level=config.policy.native_top_level,
        imports_config=config.imports,
        active_plugins=target_plan.plugins.active,
        native_jit_enabled=config.jit.enabled,
    )
    has_parse_error = any(diagnostic.code == "RXT000" for diagnostic in analysis.diagnostics)
    if has_parse_error:
        reports_dir = project_root / ".rextio" / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        (reports_dir / "build.json").write_text(
            json.dumps(
                {
                    "fallback": fallback,
                    "analysis": analysis.to_dict(),
                    "status": "analysis-failed",
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        reporter.error("RXT060 Build failed during project analysis.")
        reporter.error(f"Cause: Python parse errors were found under {project_root}.")
        reporter.error(f"Suggestion: run rextio check {project_root}")
        return 1

    # Only require the native toolchain when there is actually native code to
    # compile; a pure-Python project still builds its CPython fallback artifact.
    if analysis.requires_native_build():
        missing_tools = missing_build_tools(native_backend=target_plan.spec.language)
        if missing_tools:
            reporter.error(format_missing_tools(missing_tools))
            return 1

    # The native Rust executable backend analyzes in delegate mode so the
    # entrypoint can call project fallback functions through the external CPython
    # dispatcher. This is a separate analysis, so it does not change the wheel /
    # PyO3 native build (which keeps rejecting native->fallback calls).
    executable_analysis = None
    if config.executable.backend == "rust" and config.executable.entrypoint is not None:
        executable_analysis = analyze_project(
            project_root,
            boundary_warnings=config.policy.boundary_warnings,
            native_marker=config.policy.native_marker,
            target_language=target_plan.spec.language,
            native_top_level=config.policy.native_top_level,
            imports_config=config.imports,
            active_plugins=target_plan.plugins.active,
            # Embedded helpers are ordinary direct-native crate functions now, so
            # the executable graph honors the embedding opt-in: an eligible
            # unmarked scalar helper compiles INTO the binary instead of being
            # delegated per call over IPC (bench gate: embedding beats delegation
            # by ~4-5 orders of magnitude per call).
            native_jit_enabled=config.jit.enabled,
                delegate_fallback=True,
        )

    result = build_hybrid_artifact(
        project_root,
        analysis,
        fallback,
        build_tool=config.rust.build_tool,
        boundary_fallback_threshold=config.build.fallback_threshold,
        executable_entrypoint=config.executable.entrypoint,
        executable_name=config.executable.name,
        executable_backend=config.executable.backend,
        nuitka_mode=config.executable.nuitka_mode,
        target_plan=target_plan,
        rust_importable=config.rust.importable,
        rust_crate_name=config.rust.crate_name,
        native_jit_enabled=config.jit.enabled,
        build_timeout_seconds=config.build.build_timeout_seconds,
        executable_analysis=executable_analysis,
        executable_python=config.executable.python,
        executable_hybrid_runtime=config.executable.hybrid_runtime,
    )
    lines = ["Rextio build", f"  target language: {target_plan.spec.language}"]
    if target_plan.spec.version:
        lines.append(f"  target version: {target_plan.spec.version}")
    lines.append(f"  active plugins: {len(target_plan.plugins.active)}")
    lines.append(f"  fallback: {fallback}")
    lines.append(f"  boundary fallback threshold: {config.build.fallback_threshold}")
    lines.append(f"  experimental helper embedding: {'enabled' if config.jit.enabled else 'disabled'}")
    lines.append(f"  rust build tool: {config.rust.build_tool}")
    lines.append(f"  accepted native functions: {result.accepted_native_count}")
    lines.append(f"  rejected native functions: {result.rejected_native_count}")
    lines.append(f"  embedding candidates: {len(result.plan.native.jit_functions)}")
    if target_plan.spec.language == "rust":
        lines.append(f"  generated Rust project: {result.layout.rust_dir}")
    else:
        lines.append(
            f"  generated native project: {result.layout.target_dir(target_plan.spec.language)}"
        )
    lines.append(f"  generated Python package tree: {result.layout.python_dir}")
    lines.append(f"  build artifact: {result.layout.build_python_dir}")
    lines.append(f"  native build: {result.native_build.status}")
    lines.append(f"  rust importable crate: {result.rust_crate_build.status}")
    lines.append(f"  fallback packaging: {result.fallback_build.status}")
    lines.append(f"  executable artifact: {result.executable_build.status}")
    if config.executable.entrypoint:
        lines.append(f"  executable backend: {config.executable.backend}")
    if result.native_build.installed_path:
        lines.append(f"  native module: {result.native_build.installed_path}")
    if result.wheel_build.path:
        lines.append(f"  wheel artifact: {result.wheel_build.path}")
    if result.executable_build.path:
        lines.append(f"  executable: {result.executable_build.path}")
    if result.rust_crate_build.crate_path:
        lines.append(f"  rust crate source artifact: {result.rust_crate_build.crate_path}")
    if result.rust_crate_build.artifact_path:
        lines.append(f"  rust crate build artifact: {result.rust_crate_build.artifact_path}")
    report_path = result.layout.reports_dir / "build.json"
    lines.append(f"  wrote {report_path}")

    failed_stage = _first_failed_stage(result)
    data = {
        "status": "failed" if failed_stage else "built",
        "target_language": target_plan.spec.language,
        "accepted_native_count": result.accepted_native_count,
        "rejected_native_count": result.rejected_native_count,
        "native_build": result.native_build.status,
        "fallback_build": result.fallback_build.status,
        "rust_crate_build": result.rust_crate_build.status,
        "executable_build": result.executable_build.status,
        "report": str(report_path),
    }
    reporter.print_result(text="\n".join(lines), data=data)

    if failed_stage is not None:
        message, stderr = failed_stage
        reporter.error(message)
        if stderr:
            reporter.error(stderr)
        return 1
    return 0


def _first_failed_stage(result: BuildResult) -> tuple[str, str | None] | None:
    # Surface the first failed build stage as (message, stderr) for stderr reporting,
    # preserving the original precedence. Every stage has `status`/`message`; only some
    # carry a `stderr` field, hence the defensive getattr.
    for stage in (
        result.fallback_build,
        result.native_build,
        result.rust_crate_build,
        result.executable_build,
    ):
        if stage.status == "failed":
            return stage.message, getattr(stage, "stderr", None)
    return None
