from __future__ import annotations

import json
import os
from argparse import Namespace
from pathlib import Path

from rextio.analyzer.project_scanner import analyze_project
from rextio.build.orchestrator import build_hybrid_artifact
from rextio.build.preflight import format_missing_tools, missing_build_tools
from rextio.cli.config_overrides import key_value_overrides, package_policy_overrides, tuple_overrides
from rextio.config.loader import ConfigError, load_config, override_config
from rextio.fallback.nuitka import nuitka_available, nuitka_unavailable_message
from rextio.targets.plan import TargetPlanError, create_target_plan


def run(args: Namespace) -> int:
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
                ("jit", "backend"): args.jit_backend,
                ("jit", "hot_threshold"): args.jit_hot_threshold,
                ("executable", "entrypoint"): args.entrypoint,
                ("executable", "name"): args.executable_name,
                ("executable", "backend"): args.executable_backend,
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
        print("RXT060 Build failed while loading configuration.")
        print(f"Cause: {exc}")
        print(f"Suggestion: fix {project_root / 'rextio.toml'} and rerun rextio build.")
        return 1
    fallback = config.build.fallback_backend
    if fallback not in {"cpython", "nuitka"}:
        print("RXT060 Build failed while preparing fallback backend.")
        print(f"Cause: unsupported fallback backend: {fallback}")
        print('Suggestion: use fallback_backend = "cpython" or run rextio build --fallback=cpython')
        return 1

    if fallback == "nuitka" and not nuitka_available():
        print("RXT060 Build failed while preparing Nuitka fallback.")
        print(nuitka_unavailable_message())
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
        jit_hot_threshold=config.jit.hot_threshold,
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
        print("RXT060 Build failed during project analysis.")
        print(f"Cause: Python parse errors were found under {project_root}.")
        print(f"Suggestion: run rextio check {project_root}")
        return 1

    # Only require the native toolchain when there is actually native code to
    # compile; a pure-Python project still builds its CPython fallback artifact.
    if analysis.requires_native_build():
        missing_tools = missing_build_tools(native_backend=target_plan.spec.language)
        if missing_tools:
            print(format_missing_tools(missing_tools))
            return 1

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
        jit_hot_threshold=config.jit.hot_threshold,
        build_timeout_seconds=config.build.build_timeout_seconds,
    )
    print("Rextio build")
    print(f"  target language: {target_plan.spec.language}")
    if target_plan.spec.version:
        print(f"  target version: {target_plan.spec.version}")
    print(f"  active plugins: {len(target_plan.plugins.active)}")
    print(f"  fallback: {fallback}")
    print(f"  boundary fallback threshold: {config.build.fallback_threshold}")
    print(f"  experimental JIT: {'enabled' if config.jit.enabled else 'disabled'}")
    if config.jit.enabled:
        print(f"  JIT backend: {config.jit.backend}")
        print(f"  JIT hot threshold: {config.jit.hot_threshold}")
    print(f"  rust build tool: {config.rust.build_tool}")
    print(f"  accepted native functions: {result.accepted_native_count}")
    print(f"  rejected native functions: {result.rejected_native_count}")
    print(f"  experimental JIT candidates: {len(result.plan.native.jit_functions)}")
    if target_plan.spec.language == "rust":
        print(f"  generated Rust project: {result.layout.rust_dir}")
    else:
        print(f"  generated native project: {result.layout.target_dir(target_plan.spec.language)}")
    print(f"  generated Python package tree: {result.layout.python_dir}")
    print(f"  build artifact: {result.layout.build_python_dir}")
    print(f"  native build: {result.native_build.status}")
    print(f"  rust importable crate: {result.rust_crate_build.status}")
    print(f"  fallback packaging: {result.fallback_build.status}")
    print(f"  executable artifact: {result.executable_build.status}")
    if config.executable.entrypoint:
        print(f"  executable backend: {config.executable.backend}")
    if result.native_build.installed_path:
        print(f"  native module: {result.native_build.installed_path}")
    if result.wheel_build.path:
        print(f"  wheel artifact: {result.wheel_build.path}")
    if result.executable_build.path:
        print(f"  executable: {result.executable_build.path}")
    if result.rust_crate_build.crate_path:
        print(f"  rust crate source artifact: {result.rust_crate_build.crate_path}")
    if result.rust_crate_build.artifact_path:
        print(f"  rust crate build artifact: {result.rust_crate_build.artifact_path}")
    print(f"  wrote {result.layout.reports_dir / 'build.json'}")
    if result.fallback_build.status == "failed":
        print(result.fallback_build.message)
        if result.fallback_build.stderr:
            print(result.fallback_build.stderr)
        return 1
    if result.native_build.status == "failed":
        print(result.native_build.message)
        if result.native_build.stderr:
            print(result.native_build.stderr)
        return 1
    if result.rust_crate_build.status == "failed":
        print(result.rust_crate_build.message)
        if result.rust_crate_build.stderr:
            print(result.rust_crate_build.stderr)
        return 1
    if result.executable_build.status == "failed":
        print(result.executable_build.message)
        return 1
    return 0
