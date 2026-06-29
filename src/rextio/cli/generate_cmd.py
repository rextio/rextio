from __future__ import annotations

import json
import os
from argparse import Namespace
from pathlib import Path

from rextio.analyzer.project_scanner import analyze_project
from rextio.build.orchestrator import generate_source_artifact
from rextio.cli.config_overrides import key_value_overrides, package_policy_overrides, tuple_overrides
from rextio.cli.reporter import Reporter
from rextio.config.loader import ConfigError, load_config, override_config
from rextio.targets.plan import TargetPlanError, create_target_plan


def run(args: Namespace) -> int:
    reporter = Reporter.from_args(args)
    project_root = Path(args.project_root).resolve()
    try:
        config = override_config(
            load_config(project_root, environ=os.environ),
            {
                ("build", "native_backend"): args.native_backend,
                ("build", "fallback_backend"): args.fallback,
                ("build", "fallback_threshold"): args.fallback_threshold,
                ("rust", "binding"): args.rust_binding,
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
                ("policy", "native_marker"): args.native_marker,
                ("policy", "require_type_hints"): args.require_type_hints,
                ("policy", "allow_dynamic_features"): args.allow_dynamic_features,
                ("policy", "boundary_warnings"): args.boundary_warnings,
                ("policy", "native_top_level"): args.native_top_level,
            },
        )
        target_plan = create_target_plan(project_root, config)
    except (ConfigError, TargetPlanError) as exc:
        reporter.error("RXT060 Generate failed while loading configuration.")
        reporter.error(f"Cause: {exc}")
        reporter.error(f"Suggestion: fix {project_root / 'rextio.toml'} and rerun rextio generate.")
        return 1

    fallback = config.build.fallback_backend
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
        (reports_dir / "generate.json").write_text(
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
        reporter.error("RXT060 Generate failed during project analysis.")
        reporter.error(f"Cause: Python parse errors were found under {project_root}.")
        reporter.error(f"Suggestion: run rextio check {project_root}")
        return 1

    result = generate_source_artifact(
        project_root,
        analysis,
        fallback,
        boundary_fallback_threshold=config.build.fallback_threshold,
        target_plan=target_plan,
        rust_importable=config.rust.importable,
        rust_crate_name=config.rust.crate_name,
        native_jit_enabled=config.jit.enabled,
        jit_hot_threshold=config.jit.hot_threshold,
    )
    lines = ["Rextio generate", f"  target language: {target_plan.spec.language}"]
    if target_plan.spec.version:
        lines.append(f"  target version: {target_plan.spec.version}")
    lines.append(f"  active plugins: {len(target_plan.plugins.active)}")
    lines.append(f"  fallback: {fallback}")
    lines.append(f"  boundary fallback threshold: {config.build.fallback_threshold}")
    lines.append(f"  experimental JIT: {'enabled' if config.jit.enabled else 'disabled'}")
    if config.jit.enabled:
        lines.append(f"  JIT backend: {config.jit.backend}")
        lines.append(f"  JIT hot threshold: {config.jit.hot_threshold}")
    lines.append(f"  accepted native functions: {result.accepted_native_count}")
    lines.append(f"  rejected native functions: {result.rejected_native_count}")
    lines.append(f"  experimental JIT candidates: {len(result.plan.native.jit_functions)}")
    if target_plan.spec.language == "rust":
        lines.append(f"  generated Rust project: {result.layout.rust_dir}")
    else:
        lines.append(
            f"  generated native project: {result.layout.target_dir(target_plan.spec.language)}"
        )
    lines.append(f"  generated Python package tree: {result.layout.python_dir}")
    lines.append(f"  native source: {result.native_source.status}")
    lines.append(f"  rust crate source: {result.rust_crate_source.status}")
    report_path = result.layout.reports_dir / "generate.json"
    lines.append(f"  wrote {report_path}")

    native_failed = result.native_source.status == "failed"
    crate_failed = result.rust_crate_source.status == "failed"
    data = {
        "status": "failed" if native_failed or crate_failed else "generated",
        "target_language": target_plan.spec.language,
        "accepted_native_count": result.accepted_native_count,
        "rejected_native_count": result.rejected_native_count,
        "native_source": result.native_source.status,
        "rust_crate_source": result.rust_crate_source.status,
        "report": str(report_path),
    }
    reporter.print_result(text="\n".join(lines), data=data)

    if native_failed:
        reporter.error("RXT050 Codegen failure while generating native target code.")
        reporter.error(f"Cause: {result.native_source.message}")
        return 1
    if crate_failed:
        reporter.error("RXT050 Codegen failure while generating Rust-importable crate source.")
        reporter.error(f"Cause: {result.rust_crate_source.message}")
        return 1
    return 0
