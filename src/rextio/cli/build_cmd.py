"""The ``rextio build`` command."""

from __future__ import annotations

import json
import os
import sys
from argparse import Namespace
from pathlib import Path

from rextio.analyzer.project_scanner import analyze_project
from rextio.artifacts.closure import closure_requires_prebuild_failure
from rextio.artifacts.entry_graph import executable_entry_graph
from rextio.build.orchestrator import BuildResult, build_hybrid_artifact
from rextio.build.preflight import (
    format_missing_tools,
    missing_build_tools,
    nuitka_toolchain_error,
)
from rextio.build.toolchain import (
    cargo_environment,
    rust_pin_error,
    python_toolchain_error,
    resolve_nuitka_command,
    resolve_python,
    resolve_tool,
)
from rextio.cli.config_overrides import (
    key_value_overrides,
    package_policy_overrides,
    tuple_overrides,
)
from rextio.cli.check_cmd import write_check_report
from rextio.cli.reporter import Reporter
from rextio.plugins.loader import PluginError
from rextio.config.loader import ConfigError, load_config, override_config
from rextio.config.schema import RextioConfig
from rextio.fallback.nuitka import nuitka_unavailable_message
from rextio.targets.plan import TargetPlanError, create_target_plan


def _toolchain_preflight_error(config: RextioConfig) -> str | None:
    """Verify the configured CPython before any analysis or build work.

    The configured CPython must resolve, be CPython, and share the build
    interpreter's minor version (the analyzer, wheel tags, and Nuitka output
    are all bound to it); its pin is enforced here because the interpreter is
    relevant to every build. Pins for cargo/maturin are enforced by
    _rust_toolchain_error only when the build actually compiles native code,
    and the Nuitka pin by the Nuitka gate and each Nuitka point of use, so a
    pure-Python build never probes tools it will not run. A configured tool
    path that does not resolve is always an error, wherever it is checked.
    """
    toolchain = config.toolchain
    python, python_error = resolve_python(toolchain)
    if toolchain.python is not None and python is None:
        return python_error
    if python is not None:
        python_toolchain_issue = python_toolchain_error(python, toolchain.python_version)
        if python_toolchain_issue is not None:
            return python_toolchain_issue
    elif toolchain.python_version is not None:
        # No configured interpreter: the pin describes the build interpreter.
        python_toolchain_issue = python_toolchain_error(sys.executable, toolchain.python_version)
        if python_toolchain_issue is not None:
            return python_toolchain_issue
    # Configured (not merely pinned) cargo/maturin paths must resolve even if
    # this build turns out not to need them - a broken explicit path is a
    # config error, not a skippable probe.
    for tool in ("cargo", "maturin"):
        if getattr(toolchain, tool) is None:
            continue
        path, resolve_error = resolve_tool(tool, getattr(toolchain, tool))
        if path is None:
            return resolve_error
    return None


def _rust_toolchain_error(config: RextioConfig, build_tool: str) -> str | None:
    """Enforce cargo/maturin version pins for a build that compiles native code.

    A pin is strict for a tool this build will use: pinned + unresolvable is
    an error (otherwise the maturin-missing -> cargo fallback would silently
    bypass a maturin pin). cargo is checked for both build tools because
    maturin wraps cargo and the orchestrator falls back to cargo when maturin
    is absent and unpinned.
    """
    toolchain = config.toolchain
    # Probe under the PyO3-extension environment: RUSTUP_TOOLCHAIN (the only
    # variable that changes what a rustup shim reports) is shared with the
    # pure-Rust builders' environment, so this gate's verdict matches every
    # builder's own point-of-use rust_pin_error.
    env = cargo_environment(toolchain)
    checked = ("cargo",) if build_tool == "cargo" else ("maturin", "cargo")
    for tool in checked:
        pin_error = rust_pin_error(toolchain, tool, env)
        if pin_error is not None:
            return pin_error
    return None


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
                ("embedding", "enabled"): args.embed_helpers,
                ("executable", "entrypoint"): args.entrypoint,
                ("executable", "name"): args.executable_name,
                ("executable", "backend"): args.executable_backend,
                ("executable", "python"): args.executable_python,
                ("executable", "fallback"): args.executable_fallback,
                ("toolchain", "cargo"): args.cargo,
                ("toolchain", "maturin"): args.maturin,
                ("toolchain", "nuitka"): args.nuitka,
                ("toolchain", "python"): args.python,
                ("toolchain", "rust_toolchain"): args.rust_toolchain,
                ("toolchain", "cargo_version"): args.cargo_version,
                ("toolchain", "maturin_version"): args.maturin_version,
                ("toolchain", "nuitka_version"): args.nuitka_version,
                ("toolchain", "python_version"): args.python_version,
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
    toolchain_error = _toolchain_preflight_error(config)
    if toolchain_error is not None:
        reporter.error("RXT060 Build failed while preparing the toolchain.")
        reporter.error(toolchain_error)
        return 1

    nuitka_requested = fallback == "nuitka" or (
        config.executable.entrypoint is not None and config.executable.backend == "nuitka"
    )
    if nuitka_requested:
        nuitka_command, resolve_error = resolve_nuitka_command(config.toolchain)
        if nuitka_command is None:
            if config.toolchain.nuitka_version is not None:
                # A pin is strict for a tool this build uses: absent means
                # the pin cannot be verified, so the build fails up front.
                reporter.error("RXT060 Build failed while preparing the Nuitka toolchain.")
                reporter.error(
                    resolve_error
                    or "Nuitka is pinned but not installed; install it or drop the pin."
                )
                return 1
            if fallback == "nuitka" or resolve_error is not None:
                reporter.error("RXT060 Build failed while preparing Nuitka fallback.")
                reporter.error(resolve_error or nuitka_unavailable_message())
                return 1
            # Executable/hybrid paths keep their existing missing-tool handling
            # (reported by the builder with path-specific guidance).
        else:
            # Fail before the (potentially slow) project analysis, not mid-build.
            # The builders re-probe later so they stay correct for non-CLI callers;
            # the extra `nuitka --version` is a deliberate, negligible cost.
            version_error = nuitka_toolchain_error(nuitka_command, config.toolchain)
            if version_error is not None:
                reporter.error("RXT060 Build failed while preparing the Nuitka toolchain.")
                reporter.error(version_error)
                return 1

    try:
        analysis = analyze_project(
            project_root,
            boundary_warnings=config.policy.boundary_warnings,
            native_marker=config.policy.native_marker,
            target_language=target_plan.spec.language,
            native_top_level=config.policy.native_top_level,
            imports_config=config.imports,
            active_plugins=target_plan.plugins.active,
            plugin_registry=target_plan.plugins,
            plugin_config=config,
            embedding_enabled=config.embedding.enabled,
        )
    except PluginError as exc:
        # A lowering plugin misbehaved during the claim pass; report the stable
        # RXT060 diagnostic instead of a raw traceback (council round 8).
        reporter.error(f"RXT060 Plugin error: {exc}")
        return 1
    has_parse_error = any(diagnostic.code == "RXT000" for diagnostic in analysis.diagnostics)
    if has_parse_error:
        reports_dir = project_root / ".rextio" / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        # Clear the other command's report and the prior check.json so the
        # failed run does not leave mismatched reports behind, then write a
        # check.json matching this build.json (council round 8).
        for _stale in ("build.json", "generate.json", "check.json"):
            (reports_dir / _stale).unlink(missing_ok=True)
        write_check_report(project_root, analysis)
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

    # The native Rust executable backend analyzes in delegate mode so the
    # entrypoint can call project fallback functions through the external CPython
    # dispatcher. This is a separate analysis, so it does not change the wheel /
    # PyO3 native build (which keeps rejecting native->fallback calls).
    executable_analysis = None
    if config.executable.backend == "rust" and config.executable.entrypoint is not None:
        try:
            executable_analysis = analyze_project(
                project_root,
                boundary_warnings=config.policy.boundary_warnings,
                native_marker=config.policy.native_marker,
                target_language=target_plan.spec.language,
                native_top_level=config.policy.native_top_level,
                imports_config=config.imports,
                active_plugins=target_plan.plugins.active,
                plugin_registry=target_plan.plugins,
                plugin_config=config,
                # Embedded helpers are ordinary direct-native crate functions now, so
                # the executable graph honors the embedding opt-in: an eligible
                # unmarked scalar helper compiles INTO the binary instead of being
                # delegated per call over IPC (bench gate: embedding beats delegation
                # by ~4-5 orders of magnitude per call).
                embedding_enabled=config.embedding.enabled,
                delegate_fallback=True,
            )
        except PluginError as exc:
            reporter.error(f"RXT060 Plugin error: {exc}")
            return 1

    executable_prebuild_failure = False
    if executable_analysis is not None and config.executable.entrypoint is not None:
        closure = executable_entry_graph(
            executable_analysis,
            config.executable.entrypoint.replace(":", ".", 1),
            config.executable.fallback,
        )
        executable_prebuild_failure = closure_requires_prebuild_failure(closure)

    # Only require the native toolchain when there is actually native code to
    # compile; a pure-Python project still builds its CPython fallback artifact.
    # A pre-build closure failure is reported before any Cargo preflight or
    # invocation, so users see the entry/edge reason even without a Rust toolchain.
    if analysis.requires_native_build() and not executable_prebuild_failure:
        missing_tools = missing_build_tools(
            native_backend=target_plan.spec.language, toolchain=config.toolchain
        )
        if missing_tools:
            reporter.error(format_missing_tools(missing_tools))
            return 1
        rust_toolchain_error = _rust_toolchain_error(config, config.rust.build_tool)
        if rust_toolchain_error is not None:
            reporter.error("RXT060 Build failed while preparing the Rust toolchain.")
            reporter.error(rust_toolchain_error)
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
        embedding_enabled=config.embedding.enabled,
        build_timeout_seconds=config.build.build_timeout_seconds,
        executable_analysis=executable_analysis,
        executable_python=config.executable.python,
        executable_fallback=config.executable.fallback,
        toolchain=config.toolchain,
    )
    lines = ["Rextio build", f"  target language: {target_plan.spec.language}"]
    if target_plan.spec.version:
        lines.append(f"  target version: {target_plan.spec.version}")
    lines.append(f"  active plugins: {len(target_plan.plugins.active)}")
    lines.append(f"  fallback: {fallback}")
    lines.append(f"  boundary fallback threshold: {config.build.fallback_threshold}")
    lines.append(
        f"  experimental helper embedding: {'enabled' if config.embedding.enabled else 'disabled'}"
    )
    lines.append(f"  rust build tool: {config.rust.build_tool}")
    lines.append(f"  accepted native functions: {result.accepted_native_count}")
    lines.append(f"  rejected native functions: {result.rejected_native_count}")
    lines.append(f"  embedding candidates: {len(result.plan.native.embedded_functions)}")
    if target_plan.spec.language == "rust":
        lines.append(f"  generated Rust project: {result.layout.rust_dir}")
    else:
        lines.append(
            f"  generated native project: {result.layout.target_dir(target_plan.spec.language)}"
        )
    lines.append(f"  generated Python package tree: {result.layout.python_dir}")
    lines.append(f"  build artifact: {result.layout.build_python_dir}")
    for dependency in result.plugin_crate_dependencies:
        lines.append(
            f"  plugin crate: {dependency['name']} {dependency['version']} "
            f"({dependency['plugin_id']})"
        )
    lines.append(f"  native build: {result.native_build.status}")
    lines.append(f"  rust importable crate: {result.rust_crate_build.status}")
    lines.append(f"  fallback packaging: {result.fallback_build.status}")
    lines.append(f"  executable artifact: {result.executable_build.status}")
    if config.executable.entrypoint:
        lines.append(f"  executable backend: {config.executable.backend}")
        if config.executable.backend == "rust":
            lines.append(f"  executable fallback: {config.executable.fallback.value}")
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
