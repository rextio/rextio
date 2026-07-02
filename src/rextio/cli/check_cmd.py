"""The ``rextio check`` command."""

from __future__ import annotations

import json
import os
from argparse import Namespace
from pathlib import Path

from rextio.analyzer.models import ProjectAnalysis
from rextio.analyzer.project_scanner import analyze_project
from rextio.cli.config_overrides import key_value_overrides, package_policy_overrides, tuple_overrides
from rextio.cli.reporter import Reporter
from rextio.config.loader import ConfigError, load_config, override_config
from rextio.targets.plan import TargetPlanError, create_target_plan


def format_check_report(analysis: ProjectAnalysis) -> str:
    """Format the analysis into the human-readable check report text."""
    lines: list[str] = ["Rextio check", ""]

    accepted = analysis.accepted_native_functions
    rejected = analysis.rejected_native_functions
    accepted_top_levels = analysis.accepted_native_top_levels
    rejected_top_levels = analysis.rejected_native_top_levels
    warnings = analysis.boundary_warnings
    external_imports = _external_import_policies(analysis)
    jit_candidates = analysis.jit_candidates

    lines.append("Native candidates:")
    if not analysis.native_candidates and not analysis.native_top_levels:
        lines.append("  none")
    else:
        for function in accepted:
            lines.append(f"  [ok] {function.qualname}")
        for top_level in accepted_top_levels:
            lines.append(f"  [ok] {top_level.qualname}")

    if rejected or rejected_top_levels:
        lines.extend(["", "Rejected:"])
        for function in rejected:
            lines.append(f"  [rejected] {function.qualname}")
            for diagnostic in function.error_diagnostics:
                lines.append(f"    {diagnostic.code}: {diagnostic.message}")
                if diagnostic.suggestion:
                    lines.append(f"    suggestion: {diagnostic.suggestion}")
        for top_level in rejected_top_levels:
            lines.append(f"  [rejected] {top_level.qualname}")
            for diagnostic in top_level.error_diagnostics:
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

    if jit_candidates:
        lines.extend(["", "Experimental JIT candidates:"])
        for function in jit_candidates:
            lines.append(f"  [jit] {function.qualname}")
            if function.jit_reason:
                lines.append(f"    reason: {function.jit_reason}")
            if function.jit_hot_threshold is not None:
                lines.append(f"    hot threshold: {function.jit_hot_threshold}")

    if external_imports:
        lines.extend(["", "Import policies:"])
        for package, policy, origin, reason in external_imports:
            lines.append(f"  [{policy}] {package} ({origin})")
            lines.append(f"    reason: {reason}")

    return "\n".join(lines)


def _external_import_policies(analysis: ProjectAnalysis) -> list[tuple[str, str, str, str]]:
    seen: set[tuple[str, str, str]] = set()
    rows: list[tuple[str, str, str, str]] = []
    for module in analysis.modules:
        for decision in module.import_policies:
            if not decision.origin.startswith("external"):
                continue
            key = (decision.package, decision.policy, decision.origin)
            if key in seen:
                continue
            seen.add(key)
            rows.append((decision.package, decision.policy, decision.origin, decision.reason))
    return sorted(rows)


def run(args: Namespace) -> int:
    """Run the check command; return the process exit code."""
    reporter = Reporter.from_args(args)
    project_root = Path(args.project_root).resolve()
    try:
        config = override_config(
            load_config(project_root, environ=os.environ),
            {
                ("build", "native_backend"): args.native_backend,
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
        reporter.error(f"RXT060 Configuration error: {exc}")
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
    if not getattr(args, "no_report", False):
        write_check_report(project_root, analysis)
    reporter.print_result(text=format_check_report(analysis), data=analysis.to_dict())
    # `check` is advisory: a rejected candidate stays on the Python fallback,
    # which is an expected outcome, so it does not fail the command. Only a
    # genuine parse failure (RXT000) — a candidate that could not be analyzed —
    # is reported as a non-zero exit so `check` is usable as a CI gate.
    return 1 if analysis.has_parse_errors else 0


def write_check_report(project_root: Path, analysis: ProjectAnalysis) -> Path:
    """Write the check JSON report and return its path."""
    reports_dir = project_root / ".rextio" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / "check.json"
    report_path.write_text(
        json.dumps(analysis.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report_path
