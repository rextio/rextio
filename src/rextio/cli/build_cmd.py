from __future__ import annotations

import json
import shutil
from argparse import Namespace
from pathlib import Path

from rextio.analyzer.project_scanner import analyze_project
from rextio.build.orchestrator import build_hybrid_artifact
from rextio.config.loader import ConfigError, load_config
from rextio.fallback.nuitka import nuitka_not_implemented_message, nuitka_unavailable_message


def run(args: Namespace) -> int:
    project_root = Path(args.project_root).resolve()
    try:
        config = load_config(project_root)
    except ConfigError as exc:
        print("RXT060 Build failed while loading configuration.")
        print(f"Cause: {exc}")
        print(f"Suggestion: fix {project_root / 'rextio.toml'} and rerun rextio build.")
        return 1
    fallback = args.fallback or config.build.fallback_backend
    if fallback not in {"cpython", "nuitka"}:
        print("RXT060 Build failed while preparing fallback backend.")
        print(f"Cause: unsupported fallback backend: {fallback}")
        print('Suggestion: use fallback_backend = "cpython" or run rextio build --fallback=cpython')
        return 1

    if fallback == "nuitka" and shutil.which("nuitka") is None:
        print("RXT060 Build failed while preparing Nuitka fallback.")
        print(nuitka_unavailable_message())
        return 1
    if fallback == "nuitka":
        print("RXT060 Build failed while preparing Nuitka fallback.")
        print(nuitka_not_implemented_message())
        return 1

    analysis = analyze_project(
        project_root,
        boundary_warnings=config.policy.boundary_warnings,
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

    result = build_hybrid_artifact(
        project_root,
        analysis,
        fallback,
        build_tool=config.rust.build_tool,
    )
    print("Rextio build")
    print(f"  fallback: {fallback}")
    print(f"  rust build tool: {config.rust.build_tool}")
    print(f"  accepted native functions: {result.accepted_native_count}")
    print(f"  rejected native functions: {result.rejected_native_count}")
    print(f"  generated Rust project: {result.layout.rust_dir}")
    print(f"  generated Python package tree: {result.layout.python_dir}")
    print(f"  build artifact: {result.layout.build_python_dir}")
    print(f"  native build: {result.native_build.status}")
    if result.native_build.installed_path:
        print(f"  native module: {result.native_build.installed_path}")
    print(f"  wrote {result.layout.reports_dir / 'build.json'}")
    if result.native_build.status == "failed":
        print(result.native_build.message)
        if result.native_build.stderr:
            print(result.native_build.stderr)
        return 1
    return 0
