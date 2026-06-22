from __future__ import annotations

import json
import os
from argparse import Namespace
from pathlib import Path

from rextio.analyzer.project_scanner import analyze_project
from rextio.build.orchestrator import generate_source_artifact
from rextio.cli.config_overrides import key_value_overrides, tuple_overrides
from rextio.config.loader import ConfigError, load_config, override_config
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
                ("rust", "binding"): args.rust_binding,
                ("fallback", "nuitka"): args.nuitka_fallback,
                ("target", "version"): args.target_version,
                ("target", "build_options"): key_value_overrides(args.target_build_option),
                ("mappers", "paths"): tuple_overrides(args.mapper_path),
                ("mappers", "enabled"): tuple_overrides(args.mapper_enabled),
                ("mappers", "repository"): args.mapper_repository,
                ("policy", "native_marker"): args.native_marker,
                ("policy", "require_type_hints"): args.require_type_hints,
                ("policy", "allow_dynamic_features"): args.allow_dynamic_features,
                ("policy", "boundary_warnings"): args.boundary_warnings,
                ("policy", "native_top_level"): args.native_top_level,
            },
        )
        target_plan = create_target_plan(project_root, config)
    except (ConfigError, TargetPlanError) as exc:
        print("RXT060 Generate failed while loading configuration.")
        print(f"Cause: {exc}")
        print(f"Suggestion: fix {project_root / 'rextio.toml'} and rerun rextio generate.")
        return 1

    fallback = config.build.fallback_backend
    analysis = analyze_project(
        project_root,
        boundary_warnings=config.policy.boundary_warnings,
        native_marker=config.policy.native_marker,
        target_language=target_plan.spec.language,
        native_top_level=config.policy.native_top_level,
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
        print("RXT060 Generate failed during project analysis.")
        print(f"Cause: Python parse errors were found under {project_root}.")
        print(f"Suggestion: run rextio check {project_root}")
        return 1

    result = generate_source_artifact(
        project_root,
        analysis,
        fallback,
        boundary_fallback_threshold=config.build.fallback_threshold,
        target_plan=target_plan,
    )
    print("Rextio generate")
    print(f"  target language: {target_plan.spec.language}")
    if target_plan.spec.version:
        print(f"  target version: {target_plan.spec.version}")
    print(f"  active mappers: {len(target_plan.mappers.active)}")
    print(f"  fallback: {fallback}")
    print(f"  boundary fallback threshold: {config.build.fallback_threshold}")
    print(f"  accepted native functions: {result.accepted_native_count}")
    print(f"  rejected native functions: {result.rejected_native_count}")
    if target_plan.spec.language == "rust":
        print(f"  generated Rust project: {result.layout.rust_dir}")
    else:
        print(f"  generated native project: {result.layout.target_dir(target_plan.spec.language)}")
    print(f"  generated Python package tree: {result.layout.python_dir}")
    print(f"  native source: {result.native_source.status}")
    print(f"  wrote {result.layout.reports_dir / 'generate.json'}")
    if result.native_source.status == "failed":
        print("RXT050 Codegen failure while generating native target code.")
        print(f"Cause: {result.native_source.message}")
        return 1
    return 0
