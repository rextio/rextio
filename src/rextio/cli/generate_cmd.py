from __future__ import annotations

import json
from argparse import Namespace
from pathlib import Path

from rextio.analyzer.project_scanner import analyze_project
from rextio.build.orchestrator import generate_source_artifact
from rextio.config.loader import ConfigError, load_config


def run(args: Namespace) -> int:
    project_root = Path(args.project_root).resolve()
    try:
        config = load_config(project_root)
    except ConfigError as exc:
        print("RXT060 Generate failed while loading configuration.")
        print(f"Cause: {exc}")
        print(f"Suggestion: fix {project_root / 'rextio.toml'} and rerun rextio generate.")
        return 1

    fallback = args.fallback or config.build.fallback_backend
    analysis = analyze_project(
        project_root,
        boundary_warnings=config.policy.boundary_warnings,
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

    result = generate_source_artifact(project_root, analysis, fallback)
    print("Rextio generate")
    print(f"  fallback: {fallback}")
    print(f"  accepted native functions: {result.accepted_native_count}")
    print(f"  rejected native functions: {result.rejected_native_count}")
    print(f"  generated Rust project: {result.layout.rust_dir}")
    print(f"  generated Python package tree: {result.layout.python_dir}")
    print(f"  native source: {result.native_source.status}")
    print(f"  wrote {result.layout.reports_dir / 'generate.json'}")
    if result.native_source.status == "failed":
        print("RXT050 Codegen failure while generating Rust for accepted native functions.")
        print(f"Cause: {result.native_source.message}")
        return 1
    return 0
