from __future__ import annotations

import json
import os
from argparse import Namespace
from pathlib import Path

from rextio.analyzer.models import ProjectAnalysis
from rextio.analyzer.project_scanner import analyze_project
from rextio.config.loader import ConfigError, load_config, override_config


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
    try:
        config = override_config(
            load_config(project_root, environ=os.environ),
            {
                ("policy", "native_marker"): args.native_marker,
                ("policy", "require_type_hints"): args.require_type_hints,
                ("policy", "allow_dynamic_features"): args.allow_dynamic_features,
                ("policy", "boundary_warnings"): args.boundary_warnings,
            },
        )
    except ConfigError as exc:
        print("Rextio check")
        print(f"RXT060 Configuration error: {exc}")
        return 1
    analysis = analyze_project(
        project_root,
        boundary_warnings=config.policy.boundary_warnings,
        native_marker=config.policy.native_marker,
    )
    write_check_report(project_root, analysis)
    if args.json:
        print(json.dumps(analysis.to_dict(), indent=2, sort_keys=True))
    else:
        print(format_check_report(analysis))
    return 1 if analysis.has_error_diagnostics else 0


def write_check_report(project_root: Path, analysis: ProjectAnalysis) -> Path:
    reports_dir = project_root / ".rextio" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / "check.json"
    report_path.write_text(
        json.dumps(analysis.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report_path
