from __future__ import annotations

import json
from argparse import Namespace
from pathlib import Path

from rextio.analyzer.models import ProjectAnalysis
from rextio.analyzer.project_scanner import analyze_project


def format_check_report(analysis: ProjectAnalysis) -> str:
    lines: list[str] = ["Rextio check", ""]

    accepted = analysis.accepted_native_functions
    rejected = analysis.rejected_native_functions
    warnings = analysis.boundary_warnings

    lines.append("Native candidates:")
    if not analysis.native_candidates:
        lines.append("  none")
    else:
        for function in accepted:
            lines.append(f"  [ok] {function.qualname}")

    if rejected:
        lines.extend(["", "Rejected:"])
        for function in rejected:
            lines.append(f"  [rejected] {function.qualname}")
            for diagnostic in function.error_diagnostics:
                lines.append(f"    {diagnostic.code}: {diagnostic.message}")
                if diagnostic.suggestion:
                    lines.append(f"    suggestion: {diagnostic.suggestion}")

    if warnings:
        lines.extend(["", "Boundary warnings:"])
        for diagnostic in warnings:
            target = diagnostic.function_name or "<module>"
            lines.append(f"  [warning] {target}")
            lines.append(f"    {diagnostic.code}: {diagnostic.message}")
            if diagnostic.suggestion:
                lines.append(f"    suggestion: {diagnostic.suggestion}")

    return "\n".join(lines)


def run(args: Namespace) -> int:
    project_root = Path(args.project_root).resolve()
    analysis = analyze_project(project_root)
    if args.json:
        print(json.dumps(analysis.to_dict(), indent=2, sort_keys=True))
    else:
        print(format_check_report(analysis))
    return 1 if analysis.has_error_diagnostics else 0
