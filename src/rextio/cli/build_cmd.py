from __future__ import annotations

import json
import shutil
from argparse import Namespace
from pathlib import Path

from rextio.analyzer.project_scanner import analyze_project


def run(args: Namespace) -> int:
    project_root = Path(args.project_root).resolve()
    if args.fallback == "nuitka" and shutil.which("nuitka") is None:
        print("RXT060 Build failed while preparing Nuitka fallback.")
        print("Cause: Nuitka fallback was requested, but Nuitka is not installed.")
        print("Suggestion: install Nuitka or run: rextio build --fallback=cpython")
        return 1

    analysis = analyze_project(project_root)
    reports_dir = project_root / ".rextio" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    build_report = {
        "fallback": args.fallback,
        "analysis": analysis.to_dict(),
        "status": "analysis-complete",
    }
    (reports_dir / "build.json").write_text(
        json.dumps(build_report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print("Rextio build")
    print(f"  fallback: {args.fallback}")
    print(f"  accepted native functions: {len(analysis.accepted_native_functions)}")
    print(f"  rejected native functions: {len(analysis.rejected_native_functions)}")
    print(f"  wrote {reports_dir / 'build.json'}")
    print("  native code generation and packaging will be added in the next build slice")
    has_parse_error = any(diagnostic.code == "RXT000" for diagnostic in analysis.diagnostics)
    return 1 if has_parse_error else 0
