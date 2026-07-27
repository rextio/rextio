"""The ``rextio build`` command."""

from __future__ import annotations

import json
import math
import os
import sys
from argparse import Namespace
from pathlib import Path
from typing import Any, cast

from rextio.analyzer.models import ProjectAnalysis
from rextio.analyzer.project_scanner import analyze_project
from rextio.artifacts.closure import (
    closure_requires_prebuild_failure,
    resolve_executable_fallback,
)
from rextio.artifacts.entry_graph import executable_entry_graph
from rextio.artifacts.authorization import (
    evaluate_artifact_distribution_authorization,
)
from rextio.artifacts.evidence import (
    ARTIFACT_EVIDENCE_POLICY_REQUIRED,
    ARTIFACT_EVIDENCE_GATE_UNAVAILABLE,
    ArtifactEvidence,
    ArtifactEvidenceGate,
)
from rextio.artifacts.models import ArtifactKind
from rextio.artifacts.profiles import (
    detect_host_target_triple,
    host_executable_profile,
)
from rextio.build.orchestrator import (
    ArtifactProfilePlanningError,
    ArtifactEvidenceRequiredError,
    BuildResult,
    build_hybrid_artifact,
    required_artifact_evidence_scope_is_valid,
)
from rextio.build.full_c6_host_inputs import (
    FullC6HostInputsError,
    collect_full_c6_analysis_scope,
    collect_full_c6_host_prerequisites,
)
from rextio.build.full_c6_gate import FullC6GateError
from rextio.build.full_c6_external_execution import FullC6ExternalExecutionError
from rextio.build.full_c6_executor import (
    FULL_C6_LINUX_SANDBOX_PERMISSION_REASONS,
    FULL_C6_MACOS_SANDBOX_PERMISSION_REASONS,
    FullC6ExecutorError,
)
from rextio.build.full_c6_linux_launcher import (
    FULL_C6_LINUX_LAUNCHER_FAILURE_STAGES,
)
from rextio.build.full_c6_pyo3_config import FullC6Pyo3ConfigError
from rextio.build.full_c6_pipeline import (
    FULL_C6_DISTRIBUTION_POLICY,
    FullC6ExternalPreflightResult,
    FullC6PipelineError,
    finalize_configured_full_c6_distribution,
    prepare_full_c6_external_build,
)
from rextio.build.full_c6_policy_bootstrap import (
    FullC6PolicyBootstrapError,
    materialize_full_c6_policy_bootstrap_request,
)
from rextio.build.full_c6_production import (
    FullC6ProductionError,
    collect_full_c6_production_authority,
)
from rextio.build.full_c6_publication import FullC6PublicationError
from rextio.build.full_c6_read_sandbox import FullC6ReadSandboxError
from rextio.build.full_c6_toolchain_support import FullC6ToolchainSupportError
from rextio.plugins.capabilities import (
    StandalonePluginContext,
    build_standalone_plugin_context,
)
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
from rextio.contract import TOOLING_CONTRACT_VERSION
from rextio.plugins.loader import PluginError
from rextio.config.loader import ConfigError, load_config, override_config
from rextio.config.schema import RextioConfig
from rextio.devices import (
    DeviceProviderError,
    DeviceProviderOptions,
    DeviceProviderSelection,
)
from rextio.fallback.nuitka import nuitka_unavailable_message
from rextio.source.external import (
    ExternalSourceBuildBlockedError,
    ExternalSourceC5NotImplementedError,
)
from rextio.source.planning import ensure_host_source_plan
from rextio.targets.plan import TargetPlanError, create_target_plan


_FULL_C6_UNCLASSIFIED_REASON = "production-authority-unclassified"
_FULL_C6_FAILURE_REASON_CODES: dict[tuple[type[BaseException], str], str] = {
    (
        FullC6ProductionError,
        "Full C6 production authority collection failed closed",
    ): "production-collection-failed",
    (
        FullC6ProductionError,
        "Full C6 production toolchain support authority is invalid",
    ): "production-toolchain-support-invalid",
    (
        FullC6ProductionError,
        "Full C6 production toolchain support authority failed closed",
    ): "production-toolchain-support",
    (
        FullC6ProductionError,
        "Full C6 production prerequisites are invalid",
    ): "production-prerequisites-invalid",
    (
        FullC6ProductionError,
        "toolchain and Cargo workspace differ",
    ): "production-cargo-workspace-mismatch",
    (
        FullC6ProductionError,
        "Full C6 production toolchain support authority was replaced",
    ): "production-toolchain-support-replaced",
    (
        FullC6ProductionError,
        "Full C6 effective config is not canonical",
    ): "production-config-noncanonical",
    (
        FullC6ProductionError,
        "Full C6 production lifecycle is disabled",
    ): "production-lifecycle-disabled",
    (
        FullC6ProductionError,
        "Full C6 production requires exact preflight",
    ): "production-preflight-invalid",
    (
        FullC6ProductionError,
        "project root differs from the exact preflight root",
    ): "production-project-root-mismatch",
    (
        FullC6ExternalExecutionError,
        "RXT060 external toolchain support authority failed closed",
    ): "external-toolchain-support",
    (
        FullC6ExternalExecutionError,
        "RXT060 execution reanalysis differs from the exact preflight analysis",
    ): "external-reanalysis-mismatch",
    (
        FullC6ExecutorError,
        "Full C6 toolchain support closure failed closed",
    ): "executor-toolchain-support",
    (
        FullC6ExecutorError,
        "Full C6 critical toolchain support binding failed closed",
    ): "executor-toolchain-support",
    (
        FullC6ExecutorError,
        "Full C6 native execution requires the fixed CPython 3.11 PyO3 profile",
    ): "executor-pyo3-profile",
    (
        FullC6ExecutorError,
        "Full C6 native read-sandbox plan failed closed",
    ): "executor-sandbox-plan",
    (
        FullC6ExecutorError,
        "Full C6 Linux seccomp lease failed closed",
    ): "executor-seccomp-setup",
    (
        FullC6ExecutorError,
        "Full C6 Linux read sandbox failed closed",
    ): "executor-sandbox-launch",
    (
        FullC6ExecutorError,
        "Full C6 native read sandbox failed closed",
    ): "executor-sandbox-execution",
    (
        FullC6ExecutorError,
        "strict Cargo build failed with exit status 1",
    ): "native-build-exit-1",
    (
        FullC6ExecutorError,
        "strict native sandbox build failed: native-sandbox-bubblewrap",
    ): "native-sandbox-bubblewrap",
    (
        FullC6ExecutorError,
        "strict native sandbox build failed: native-bwrap-user-namespace-denied",
    ): "native-bwrap-user-namespace-denied",
    (
        FullC6ExecutorError,
        "strict native sandbox build failed: native-bwrap-bind-path-missing",
    ): "native-bwrap-bind-path-missing",
    (
        FullC6ExecutorError,
        "strict native sandbox build failed: native-bwrap-mount-failed",
    ): "native-bwrap-mount-failed",
    (
        FullC6ExecutorError,
        "strict native sandbox build failed: native-bwrap-exec-failed",
    ): "native-bwrap-exec-failed",
    (
        FullC6ExecutorError,
        "strict native sandbox build failed: native-bwrap-seccomp-failed",
    ): "native-bwrap-seccomp-failed",
    (
        FullC6ExecutorError,
        "strict native sandbox build failed: native-cargo-dependency-config",
    ): "native-cargo-dependency-config",
    (
        FullC6ExecutorError,
        "strict native sandbox build failed: native-rustc",
    ): "native-rustc",
    (
        FullC6ExecutorError,
        "strict native sandbox build failed: native-linker",
    ): "native-linker",
    (
        FullC6ExecutorError,
        "strict native sandbox build failed: native-pyo3",
    ): "native-pyo3",
    (
        FullC6ExecutorError,
        "strict native sandbox build failed: native-permission",
    ): "native-permission",
    (
        FullC6ExecutorError,
        "strict native sandbox build failed: native-missing-path",
    ): "native-missing-path",
    (
        FullC6ExecutorError,
        "strict native sandbox build failed: native-compile",
    ): "native-compile",
    (
        FullC6ExecutorError,
        "strict Cargo build failed with exit status 101",
    ): "native-build-exit-101",
    (
        FullC6ExecutorError,
        "strict Cargo build failed with exit status 125",
    ): "linux-launcher-exit-125",
    (
        FullC6ReadSandboxError,
        "Full C6 bubblewrap is unavailable",
    ): "sandbox-bubblewrap-unavailable",
    (
        FullC6ReadSandboxError,
        "Full C6 bubblewrap executable is unsafe",
    ): "sandbox-bubblewrap-unsafe",
    (
        FullC6ReadSandboxError,
        "Full C6 Linux seccomp memfd is unavailable on this host",
    ): "sandbox-seccomp-unavailable",
    (
        FullC6ReadSandboxError,
        "Full C6 Linux sandbox path is unavailable",
    ): "sandbox-path-unavailable",
    (
        FullC6Pyo3ConfigError,
        "Full C6 PyO3 config target differs from the running host",
    ): "pyo3-target-mismatch",
    (
        FullC6Pyo3ConfigError,
        "Full C6 PyO3 config requires CPython 3.11",
    ): "pyo3-cpython-version-mismatch",
    (
        FullC6ToolchainSupportError,
        "Full C6 critical support path changed",
    ): "toolchain-critical-path-changed",
}
_FULL_C6_FAILURE_REASON_CODES.update(
    {
        (
            FullC6ExecutorError,
            f"strict native sandbox build failed: {reason}",
        ): reason
        for reason in FULL_C6_MACOS_SANDBOX_PERMISSION_REASONS
    }
)
_FULL_C6_FAILURE_REASON_CODES.update(
    {
        (
            FullC6ExecutorError,
            f"strict native sandbox build failed: {reason}",
        ): reason
        for reason in FULL_C6_LINUX_SANDBOX_PERMISSION_REASONS
    }
)
_FULL_C6_FAILURE_REASON_CODES.update(
    {
        (
            FullC6ExecutorError,
            f"strict native sandbox build failed: linux-launcher-{stage}",
        ): f"linux-launcher-{stage}"
        for stage in FULL_C6_LINUX_LAUNCHER_FAILURE_STAGES
    }
)


def _full_c6_failure_reason_code(error: BaseException) -> str:
    """Return only a static code for an exact known exception-chain member."""
    reason = _FULL_C6_UNCLASSIFIED_REASON
    current: BaseException | None = error
    seen: set[int] = set()
    for _depth in range(12):
        if current is None or id(current) in seen:
            break
        seen.add(id(current))
        current_type = type(current)
        if any(
            registered_type is current_type
            for registered_type, _message in _FULL_C6_FAILURE_REASON_CODES
        ):
            candidate = _FULL_C6_FAILURE_REASON_CODES.get(
                (current_type, str(current))
            )
            if candidate is not None:
                # A deeper exact cause is more diagnostic than its wrapping gate.
                reason = candidate
        current = current.__cause__ or current.__context__
    return reason


def _report_artifact_profile_failure(
    project_root: Path,
    analysis: ProjectAnalysis,
    fallback: str,
    error: ArtifactProfilePlanningError,
    reporter: Reporter,
) -> int:
    """Write the stable CLI failure shared by preflight and orchestration."""
    reports_dir = project_root / ".rextio" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    write_check_report(project_root, analysis)
    (reports_dir / "build.json").write_text(
        json.dumps(
            {
                "analysis": analysis.to_dict(),
                "contract_version": TOOLING_CONTRACT_VERSION,
                "error": {"code": "RXT060", "message": str(error)},
                "fallback": fallback,
                "status": "artifact-profile-unavailable",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    reporter.error(str(error))
    reporter.error(
        "Suggestion: run on a supported Rust host target or keep this project on fallback."
    )
    return 1


def _report_plugin_capability_failure(
    project_root: Path,
    analysis: ProjectAnalysis,
    fallback: str,
    error: PluginError,
    reporter: Reporter,
    *,
    command: str = "build",
) -> int:
    """Write a stable RXT060 failure for artifact_capability hook problems."""
    reports_dir = project_root / ".rextio" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    write_check_report(project_root, analysis)
    report_name = "build.json" if command == "build" else "generate.json"
    (reports_dir / report_name).write_text(
        json.dumps(
            {
                "analysis": analysis.to_dict(),
                "contract_version": TOOLING_CONTRACT_VERSION,
                "error": {"code": "RXT060", "message": f"Plugin error: {error}"},
                "fallback": fallback,
                "status": "plugin-capability-failed",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    reporter.error(f"RXT060 Plugin error: {error}")
    reporter.error(
        "Suggestion: fix the plugin artifact_capability() declaration or disable "
        "the plugin, then rerun."
    )
    return 1


def _report_external_source_build_blocked(
    project_root: Path,
    analysis: ProjectAnalysis,
    fallback: str,
    reporter: Reporter,
) -> int:
    """Stop external-source builds before toolchain or artifact work."""
    assert analysis.external_source_plan is not None
    plan = analysis.external_source_plan
    if plan.authorization_verified:
        error: Exception = ExternalSourceC5NotImplementedError(plan)
        status = "external-source-native-linkage-not-implemented"
        suggestion = (
            "Suggestion: SourceLock authorization succeeded, but source-native "
            "call-site linkage, body lowerability, Rust codegen, and packaging "
            "are not implemented. Keep using check/generate for inventory evidence only."
        )
    else:
        error = ExternalSourceBuildBlockedError(plan)
        status = "external-source-authorization-blocked"
        suggestion = (
            "Suggestion: add a verified project-owned "
            "rextio.external-source.lock.json authored from rextio check "
            "plan_snapshot material, or use rextio check/generate for preview "
            "evidence only."
        )
    reports_dir = project_root / ".rextio" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    for stale in ("build.json", "generate.json", "check.json"):
        (reports_dir / stale).unlink(missing_ok=True)
    write_check_report(project_root, analysis)
    # Authorization evidence is nested only under external_source_plan.authorization.
    report_body: dict[str, object] = {
        "analysis": analysis.to_dict(),
        "contract_version": TOOLING_CONTRACT_VERSION,
        "error": {"code": "RXT060", "message": str(error)},
        "external_source_plan": plan.to_dict(),
        "fallback": fallback,
        "status": status,
    }
    (reports_dir / "build.json").write_text(
        json.dumps(report_body, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    reporter.warn(
        "External source license warning: "
        f"{plan.license_warning}"
    )
    if plan.authorization is not None:
        auth = plan.authorization
        reporter.warn(
            "External source authorization: "
            f"status={auth.status}"
            + (f" reason={auth.reason}" if auth.reason else "")
        )
    reporter.error(str(error))
    reporter.error(suggestion)
    return 1


def _report_full_c6_pipeline_failure(
    project_root: Path,
    analysis: ProjectAnalysis,
    fallback: str,
    error: Exception,
    reporter: Reporter,
    *,
    stage: str,
) -> int:
    """Report one actionable strict artifact-contract fail-closed result."""
    reports_dir = project_root / ".rextio" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    for stale in ("build.json", "generate.json", "check.json"):
        (reports_dir / stale).unlink(missing_ok=True)
    try:
        analysis_data = _write_full_c6_check_report(
            reports_dir,
            project_root,
            analysis,
        )
    except FullC6PipelineError:
        return _report_full_c6_projection_failure(reports_dir, reporter)
    public_message = (
        f"RXT060 strict evidence distribution policy {stage} failed closed."
    )
    (reports_dir / "build.json").write_text(
        json.dumps(
            {
                "analysis": analysis_data,
                "contract_version": TOOLING_CONTRACT_VERSION,
                "error": {
                    "code": "RXT060",
                    "domain": type(error).__name__,
                    "message": public_message,
                    "reason_code": _full_c6_failure_reason_code(error),
                },
                "fallback": fallback,
                "lifecycle": "failed",
                "stage": stage,
                "status": "strict-evidence-failed",
                "distribution_authorized": False,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    reporter.error(public_message)
    reporter.error(
        "Suggestion: verify the strict configuration, pinned inputs, current lifecycle "
        "material, and unchanged project sources, then rerun."
    )
    return 1


def _report_full_c6_preanalysis_failure(
    project_root: Path,
    fallback: str,
    error: FullC6HostInputsError,
    reporter: Reporter,
) -> int:
    """Report strict pre-analysis failure without touching untrusted paths."""
    # No project-relative file transaction is safe yet: in particular,
    # ``.rextio`` may be an attacker-controlled symlink.  Keep this stage
    # stderr-only and never serialize host paths or attacker detail.
    del project_root, fallback, error
    public_message = (
        "RXT060 strict evidence distribution policy analysis scope failed closed."
    )
    reporter.error(public_message)
    reporter.error(
        "Suggestion: verify the exact project root, absent custom ignore file, "
        "and unchanged pinned Cargo lock/vendor inputs, then rerun."
    )
    return 1


def _full_c6_report_projection_error(reason: str) -> FullC6PipelineError:
    return FullC6PipelineError(
        "RXT060 strict evidence distribution policy analysis report projection "
        f"rejected {reason}"
    )


def _clear_full_c6_reports(reports_dir: Path) -> None:
    try:
        reports_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return
    for stale in ("build.json", "generate.json", "check.json"):
        try:
            (reports_dir / stale).unlink(missing_ok=True)
        except OSError:
            continue


def _report_full_c6_projection_failure(
    reports_dir: Path,
    reporter: Reporter,
) -> int:
    """Emit one fixed path-free boundary when strict report projection fails."""
    _clear_full_c6_reports(reports_dir)
    reporter.error(
        "RXT060 strict evidence distribution policy analysis report projection "
        "failed closed."
    )
    reporter.error(
        "Suggestion: keep analyzer report paths canonical and project-contained, "
        "then rerun."
    )
    return 1


def _project_full_c6_file_path(project_root: Path, value: object) -> str:
    if type(value) is not str or not value:
        raise _full_c6_report_projection_error("an invalid file_path")
    try:
        parsed = Path(value)
    except (OSError, UnicodeError, ValueError) as error:
        raise _full_c6_report_projection_error("an invalid file_path") from error
    if os.fspath(parsed) != value:
        raise _full_c6_report_projection_error("a non-canonical file_path")
    if parsed.is_absolute():
        candidate = parsed
    else:
        candidate = project_root / parsed
    try:
        relative = candidate.relative_to(project_root)
    except ValueError as error:
        raise _full_c6_report_projection_error("an outside-root file_path") from error
    if (
        not relative.parts
        or any(part in {"", os.curdir, os.pardir} for part in relative.parts)
        or relative.is_absolute()
    ):
        raise _full_c6_report_projection_error("a non-canonical file_path")
    try:
        resolved = candidate.resolve(strict=False)
    except (OSError, RuntimeError, UnicodeError, ValueError) as error:
        raise _full_c6_report_projection_error("an ambiguous file_path") from error
    if resolved != candidate:
        raise _full_c6_report_projection_error("an ambiguous file_path")
    return relative.as_posix()


def _project_full_c6_report_value(
    project_root: Path,
    value: object,
    *,
    active_containers: set[int],
) -> object:
    if isinstance(value, dict):
        if type(value) is not dict:
            raise _full_c6_report_projection_error("an unexpected mapping type")
        identity = id(value)
        if identity in active_containers:
            raise _full_c6_report_projection_error("a cyclic mapping")
        active_containers.add(identity)
        try:
            projected: dict[str, object] = {}
            for key, item in value.items():
                if type(key) is not str:
                    raise _full_c6_report_projection_error("a non-string mapping key")
                if key == "file_path":
                    projected[key] = _project_full_c6_file_path(project_root, item)
                else:
                    projected[key] = _project_full_c6_report_value(
                        project_root,
                        item,
                        active_containers=active_containers,
                    )
            return projected
        finally:
            active_containers.remove(identity)
    if isinstance(value, list):
        if type(value) is not list:
            raise _full_c6_report_projection_error("an unexpected sequence type")
        identity = id(value)
        if identity in active_containers:
            raise _full_c6_report_projection_error("a cyclic sequence")
        active_containers.add(identity)
        try:
            return [
                _project_full_c6_report_value(
                    project_root,
                    item,
                    active_containers=active_containers,
                )
                for item in value
            ]
        finally:
            active_containers.remove(identity)
    if value is None or type(value) in {bool, int, str}:
        return value
    if type(value) is float and math.isfinite(value):
        return value
    raise _full_c6_report_projection_error("an unexpected value type")


def _project_full_c6_analysis_report(
    project_root: Path,
    analysis: ProjectAnalysis,
) -> dict[str, object]:
    try:
        canonical_root = project_root.resolve(strict=True)
    except (OSError, RuntimeError, UnicodeError, ValueError) as error:
        raise _full_c6_report_projection_error("an invalid project root") from error
    if (
        not project_root.is_absolute()
        or canonical_root != project_root
        or not canonical_root.is_dir()
    ):
        raise _full_c6_report_projection_error("an ambiguous project root")
    raw = analysis.to_dict()
    if type(raw) is not dict or raw.get("project_root") != os.fspath(project_root):
        raise _full_c6_report_projection_error("a mismatched analysis root")
    raw["project_root"] = "."
    projected = _project_full_c6_report_value(
        project_root,
        raw,
        active_containers=set(),
    )
    if type(projected) is not dict:
        raise _full_c6_report_projection_error("an invalid top-level mapping")
    try:
        canonical_bytes = json.dumps(
            projected,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise _full_c6_report_projection_error("a non-canonical JSON value") from error
    root_spellings = {os.fspath(project_root)}
    if sys.platform == "darwin" and project_root.parts[:2] == ("/", "private"):
        alias = Path("/").joinpath(*project_root.parts[2:])
        try:
            if alias.resolve(strict=True) == project_root:
                root_spellings.add(os.fspath(alias))
        except (OSError, RuntimeError, UnicodeError, ValueError):
            pass
    for spelling in root_spellings:
        try:
            raw_bytes = spelling.encode("utf-8")
            escaped_bytes = json.dumps(spelling, ensure_ascii=True)[1:-1].encode(
                "utf-8"
            )
        except UnicodeError as error:
            raise _full_c6_report_projection_error(
                "an invalid project-root spelling"
            ) from error
        if raw_bytes in canonical_bytes or escaped_bytes in canonical_bytes:
            raise _full_c6_report_projection_error("residual project-root text")
    return projected


def _write_full_c6_check_report(
    reports_dir: Path,
    project_root: Path,
    analysis: ProjectAnalysis,
) -> dict[str, object]:
    """Write one strict report with only canonical project-relative source paths."""
    ensure_host_source_plan(analysis)
    data = _project_full_c6_analysis_report(project_root, analysis)
    (reports_dir / "check.json").write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return data


def _full_c6_lexical_project_root(raw_project_root: str) -> str:
    """Make ordinary relative CLI roots absolute without resolving lexical evidence."""
    candidate = Path(raw_project_root)
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    return os.fspath(candidate)


def _full_c6_typed_receipt(value: object, *, label: str) -> dict[str, object]:
    """Project one already-validated path-free receipt into a report."""
    to_dict = getattr(value, "to_dict", None)
    if not callable(to_dict):
        raise FullC6PipelineError(
            f"RXT060 strict evidence distribution policy {label} receipt is invalid"
        )
    payload = to_dict()
    if type(payload) is not dict:
        raise FullC6PipelineError(
            f"RXT060 strict evidence distribution policy {label} receipt is invalid"
        )
    return payload


def _report_full_c6_pipeline_success(
    project_root: Path,
    analysis: ProjectAnalysis,
    fallback: str,
    reporter: Reporter,
    *,
    lifecycle: str,
    status: str,
    distribution_authorized: bool,
    details: dict[str, object],
    next_action: str,
) -> int:
    """Publish one path-free strict lifecycle result after host cleanup succeeds."""
    reports_dir = project_root / ".rextio" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    for stale in ("build.json", "generate.json", "check.json"):
        (reports_dir / stale).unlink(missing_ok=True)
    try:
        analysis_data = _write_full_c6_check_report(
            reports_dir,
            project_root,
            analysis,
        )
    except FullC6PipelineError:
        return _report_full_c6_projection_failure(reports_dir, reporter)
    report = {
        "analysis": analysis_data,
        "contract_version": TOOLING_CONTRACT_VERSION,
        "distribution_authorized": distribution_authorized,
        "fallback": fallback,
        "artifact_contract": details,
        "lifecycle": lifecycle,
        "next_action": next_action,
        "status": status,
    }
    (reports_dir / "build.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    report_name = ".rextio/reports/build.json"
    reporter.print_result(
        text="\n".join(
            (
                "Rextio strict evidence distribution policy lifecycle:",
                f"  lifecycle: {lifecycle}",
                f"  status: {status}",
                "  distribution authorized: "
                f"{'true' if distribution_authorized else 'false'}",
                f"  next owner action: {next_action}",
                f"  wrote {report_name}",
            )
        ),
        data={
            "distribution_authorized": distribution_authorized,
            "artifact_contract": details,
            "lifecycle": lifecycle,
            "next_action": next_action,
            "report": report_name,
            "status": status,
        },
    )
    return 0


def _run_full_c6_cli_lifecycle(
    *,
    raw_project_root: str,
    project_root: Path,
    analysis: ProjectAnalysis,
    preflight: FullC6ExternalPreflightResult,
    config: RextioConfig,
    fallback: str,
    reporter: Reporter,
) -> int:
    """Run the closed bootstrap/signing/publication CLI state machine."""
    stage = "host-prerequisites"
    try:
        with collect_full_c6_host_prerequisites(
            raw_project_root,
            config=config,
        ) as prerequisites:
            stage = "production-authority"
            authority = collect_full_c6_production_authority(
                preflight,
                **cast(dict[str, Any], prerequisites.production_arguments()),
            )
            lifecycle = authority.lifecycle.status
            authority_report = authority.to_dict()
            status: str
            distribution_authorized: bool
            details: dict[str, object]
            next_action: str
            if lifecycle == "bootstrap-required":
                stage = "policy-bootstrap"
                request = authority.bootstrap_request
                if request is None:
                    raise FullC6ProductionError(
                        "Artifact-policy bootstrap lifecycle lacks its typed request"
                    )
                bootstrap = materialize_full_c6_policy_bootstrap_request(
                    state_directory=prerequisites.state_directory,
                    request=request,
                )
                status = "artifact-policy-bootstrap-required"
                distribution_authorized = False
                next_action = (
                    "complete and pin the owner policy manifest from the bootstrap request"
                )
                details = {
                    "policy_bootstrap": bootstrap.to_dict(),
                    "production_authority": authority_report,
                }
            elif lifecycle == "signing-required":
                stage = "signing-request"
                result = finalize_configured_full_c6_distribution(
                    project_root=project_root,
                    config=config,
                    authority=authority,
                )
                if result.status != "signing-required" or result.distribution_authorized:
                    raise FullC6PipelineError(
                        "RXT060 unsigned artifact lifecycle returned invalid authority"
                    )
                status = "artifact-signing-required"
                distribution_authorized = False
                next_action = (
                    "sign the canonical authorization request externally and configure "
                    "the detached signature"
                )
                details = {
                    "authorization_request": result.request.to_dict(),
                    "production_authority": authority_report,
                    "signing_request_receipt": _full_c6_typed_receipt(
                        result.signing_request_receipt,
                        label="signing-request",
                    ),
                }
            elif lifecycle == "publication-required":
                stage = "prepublication-cleanup"
                prerequisites.complete_prepublication_cleanup(authority)
                stage = "publication-plan"
                publication_plan = prerequisites.derive_publication_plan(authority)
                stage = "publication"
                result = finalize_configured_full_c6_distribution(
                    project_root=project_root,
                    config=config,
                    authority=authority,
                    publication_adapter=publication_plan.atomic_adapter(),
                )
                if (
                    result.status != "published"
                    or not result.distribution_authorized
                    or result.publication_receipt is None
                ):
                    raise FullC6PipelineError(
                        "RXT060 published artifact lifecycle returned invalid authority"
                    )
                status = "artifact-published"
                distribution_authorized = True
                next_action = "review and retain the atomic publication receipt"
                details = {
                    "authorization_request": result.request.to_dict(),
                    "publication_receipt": result.publication_receipt.to_dict(),
                    "production_authority": authority_report,
                    "signing_request_receipt": _full_c6_typed_receipt(
                        result.signing_request_receipt,
                        label="signing-request",
                    ),
                }
            else:
                raise FullC6ProductionError(
                    "Artifact production authority returned an invalid lifecycle"
                )
            stage = "host-cleanup"
    except (
        FullC6HostInputsError,
        FullC6GateError,
        FullC6PipelineError,
        FullC6PolicyBootstrapError,
        FullC6ProductionError,
        FullC6PublicationError,
    ) as error:
        return _report_full_c6_pipeline_failure(
            project_root,
            analysis,
            fallback,
            error,
            reporter,
            stage=stage,
        )
    return _report_full_c6_pipeline_success(
        project_root,
        analysis,
        fallback,
        reporter,
        lifecycle=lifecycle,
        status=status,
        distribution_authorized=distribution_authorized,
        details=details,
        next_action=next_action,
    )


def _report_required_evidence_failure(
    project_root: Path,
    analysis: ProjectAnalysis,
    fallback: str,
    error: ArtifactEvidenceRequiredError,
    reporter: Reporter,
) -> int:
    """Report the stable fail-closed required-evidence diagnostic and exit status."""
    if error.result is None:
        reports_dir = project_root / ".rextio" / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        for stale in ("build.json", "generate.json", "check.json"):
            (reports_dir / stale).unlink(missing_ok=True)
        write_check_report(project_root, analysis)
        report: dict[str, object] = {
            "analysis": analysis.to_dict(),
            "artifact_evidence_gate": error.gate.to_dict(),
            "contract_version": TOOLING_CONTRACT_VERSION,
            "error": {"code": "RXT060", "message": str(error)},
            "fallback": fallback,
            "status": "artifact-evidence-required-failed",
        }
        if (
            error.gate.reason == ARTIFACT_EVIDENCE_GATE_UNAVAILABLE
            and error.gate.evidence_reason is not None
        ):
            unavailable_evidence = ArtifactEvidence.unavailable(
                reason=error.gate.evidence_reason
            )
            report["artifact_evidence"] = unavailable_evidence.to_dict()
            report["artifact_distribution_authorization"] = (
                evaluate_artifact_distribution_authorization(unavailable_evidence).to_dict()
            )
        (reports_dir / "build.json").write_text(
            json.dumps(
                report,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
    reporter.error(f"RXT060 {error}")
    if (
        error.result is not None
        and "rollback was incomplete" in error.result.wheel_build.message
    ):
        reporter.error(error.result.wheel_build.message)
    reporter.error(
        "Suggestion: use --artifact-evidence-policy=best-effort, or request exactly one "
        "native host-extension + CPython wheel and resolve the evidence failure."
    )
    return 1


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


def _external_source_preview_declared(config: RextioConfig) -> bool:
    """Return whether config requests the external-source analysis preview path."""
    return any(
        policy.distribution is not None and policy.version is not None
        for policy in config.imports.packages.values()
    )


def _prepare_build_toolchain(
    config: RextioConfig,
    fallback: str,
    reporter: Reporter,
) -> bool:
    """Run build-wide Python/Nuitka probes and report stable failures."""
    toolchain_error = _toolchain_preflight_error(config)
    if toolchain_error is not None:
        reporter.error("RXT060 Build failed while preparing the toolchain.")
        reporter.error(toolchain_error)
        return False

    # Paths that ALWAYS invoke Nuitka when reached: the Nuitka fallback and a
    # Nuitka executable with an entrypoint. The rust-executable hybrid runtime
    # is deliberately NOT gated here: it only invokes Nuitka when analysis
    # finds delegated fallback calls, so a pre-analysis rejection would block
    # valid no-delegation builds that never touch Nuitka. The dispatcher
    # builder enforces the version floor at the point of real use.
    nuitka_requested = fallback == "nuitka" or (
        config.executable.entrypoint is not None and config.executable.backend == "nuitka"
    )
    if not nuitka_requested:
        return True

    nuitka_command, resolve_error = resolve_nuitka_command(config.toolchain)
    if nuitka_command is None:
        if config.toolchain.nuitka_version is not None:
            # A pin is strict for a tool this build uses: absent means the pin
            # cannot be verified, so the build fails up front.
            reporter.error("RXT060 Build failed while preparing the Nuitka toolchain.")
            reporter.error(
                resolve_error
                or "Nuitka is pinned but not installed; install it or drop the pin."
            )
            return False
        if fallback == "nuitka" or resolve_error is not None:
            reporter.error("RXT060 Build failed while preparing Nuitka fallback.")
            reporter.error(resolve_error or nuitka_unavailable_message())
            return False
        # Executable/hybrid paths keep their existing missing-tool handling
        # (reported by the builder with path-specific guidance).
        return True

    # The builders re-probe later so they stay correct for non-CLI callers;
    # the extra ``nuitka --version`` is a deliberate, negligible cost.
    version_error = nuitka_toolchain_error(nuitka_command, config.toolchain)
    if version_error is not None:
        reporter.error("RXT060 Build failed while preparing the Nuitka toolchain.")
        reporter.error(version_error)
        return False
    return True


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
    raw_project_root = os.fspath(args.project_root)
    if type(raw_project_root) is not str:
        reporter.error("RXT060 Build project path must be text.")
        return 1
    project_root = Path(raw_project_root).resolve()
    try:
        config = override_config(
            load_config(project_root, environ=os.environ),
            {
                ("build", "native_backend"): args.native_backend,
                ("build", "fallback_backend"): args.fallback,
                ("build", "fallback_threshold"): args.fallback_threshold,
                ("build", "build_timeout_seconds"): args.build_timeout,
                ("build", "artifact_evidence_policy"): args.artifact_evidence_policy,
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
    strict_distribution = (
        config.build.artifact_distribution_policy == FULL_C6_DISTRIBUTION_POLICY
    )
    fallback = config.build.fallback_backend
    if fallback not in {"cpython", "nuitka"}:
        reporter.error("RXT060 Build failed while preparing fallback backend.")
        reporter.error(f"Cause: unsupported fallback backend: {fallback}")
        reporter.error(
            'Suggestion: use fallback_backend = "cpython" or run rextio build --fallback=cpython'
        )
        return 1

    # Ordinary builds retain the early preflight. External-source declarations
    # defer executable probes until after analysis so a preview is always
    # stopped by the authorization gate before any configured tool is invoked.
    external_preview_declared = _external_source_preview_declared(config)
    required_evidence = (
        config.build.artifact_evidence_policy == ARTIFACT_EVIDENCE_POLICY_REQUIRED
    )
    if not (external_preview_declared or required_evidence) and not _prepare_build_toolchain(
        config, fallback, reporter
    ):
        return 1

    full_c6_analysis_scope = None
    if strict_distribution:
        try:
            full_c6_analysis_scope = collect_full_c6_analysis_scope(
                _full_c6_lexical_project_root(raw_project_root),
                config=config,
            )
        except FullC6HostInputsError as error:
            return _report_full_c6_preanalysis_failure(
                project_root,
                fallback,
                error,
                reporter,
            )

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
            full_c6_analysis_scope=full_c6_analysis_scope,
        )
    except FullC6HostInputsError as error:
        return _report_full_c6_preanalysis_failure(
            project_root,
            fallback,
            error,
            reporter,
        )
    except PluginError as exc:
        # A lowering plugin misbehaved during the claim pass; report the stable
        # RXT060 diagnostic instead of a raw traceback (council round 8).
        reporter.error(f"RXT060 Plugin error: {exc}")
        return 1
    has_parse_error = any(diagnostic.code == "RXT000" for diagnostic in analysis.diagnostics)
    if strict_distribution and not has_parse_error:
        analysis_scope = full_c6_analysis_scope
        if analysis_scope is None:
            return _report_full_c6_preanalysis_failure(
                project_root,
                fallback,
                FullC6HostInputsError("strict analysis scope unavailable"),
                reporter,
            )
        try:
            preflight = prepare_full_c6_external_build(
                project_root=project_root,
                initial_analysis=analysis,
                config=config,
                analysis_scope=analysis_scope,
                reanalyze=lambda registry: analyze_project(
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
                    external_native_registry=registry,
                    full_c6_analysis_scope=analysis_scope,
                ),
            )
            analysis = preflight.analysis
        except FullC6PipelineError as error:
            return _report_full_c6_pipeline_failure(
                project_root,
                analysis,
                fallback,
                error,
                reporter,
                stage="external-preflight",
            )
        return _run_full_c6_cli_lifecycle(
            raw_project_root=_full_c6_lexical_project_root(raw_project_root),
            project_root=project_root,
            analysis=analysis,
            preflight=preflight,
            config=config,
            fallback=fallback,
            reporter=reporter,
        )
    if analysis.external_source_plan is not None:
        return _report_external_source_build_blocked(
            project_root,
            analysis,
            fallback,
            reporter,
        )
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
                    "analysis": analysis.to_dict(),
                    "contract_version": TOOLING_CONTRACT_VERSION,
                    "fallback": fallback,
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

    if required_evidence and not required_artifact_evidence_scope_is_valid(
        native_extension=analysis.requires_native_build(),
        fallback=fallback,
        executable_entrypoint=config.executable.entrypoint,
        rust_importable=config.rust.importable,
    ):
        return _report_required_evidence_failure(
            project_root,
            analysis,
            fallback,
            ArtifactEvidenceRequiredError(ArtifactEvidenceGate.out_of_scope()),
            reporter,
        )

    # A declaration that was not actually imported produces no source plan.
    # Resume the ordinary build contract only after that has been established
    # without invoking configured Python/Nuitka tools.
    if (external_preview_declared or required_evidence) and not _prepare_build_toolchain(
        config, fallback, reporter
    ):
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
    # Pre-resolve host-executable capability once for this build command so the
    # preflight closure and orchestrator share the same immutable context
    # (plugin API 1.4: one hook call per exact ArtifactProfile).
    executable_standalone: StandalonePluginContext | None = None
    if executable_analysis is not None and config.executable.entrypoint is not None:
        try:
            fallback_strategy = resolve_executable_fallback(config.executable.fallback)
            try:
                triple = detect_host_target_triple()
            except ValueError as error:
                raise ArtifactProfilePlanningError(
                    f"RXT060 Artifact profile planning failed. Cause: {error}"
                ) from error
            executable_profile = host_executable_profile(
                triple, fallback=fallback_strategy
            )
            executable_standalone = build_standalone_plugin_context(
                profile=executable_profile,
                registry=target_plan.plugins,
                functions=[
                    function
                    for module in executable_analysis.modules
                    for function in module.functions
                ],
            )
            closure = executable_entry_graph(
                executable_analysis,
                config.executable.entrypoint.replace(":", ".", 1),
                fallback_strategy,
                profile=executable_profile,
                plugin_capabilities=executable_standalone.capabilities,
            )
        except ArtifactProfilePlanningError as error:
            return _report_artifact_profile_failure(
                project_root,
                analysis,
                fallback,
                error,
                reporter,
            )
        except PluginError as exc:
            return _report_plugin_capability_failure(
                project_root, analysis, fallback, exc, reporter, command="build"
            )
        executable_prebuild_failure = closure_requires_prebuild_failure(closure)

    # Only require the native toolchain when there is actually native code to
    # compile; a pure-Python project still builds its CPython fallback artifact.
    # A pre-build closure failure is reported before any Cargo preflight or
    # invocation, so users see the entry/edge reason even without a Rust toolchain.
    # Capability-aware closure keeps a valid plugin executable CLOSED so
    # toolchain diagnostics still run.
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

    try:
        device_selection = (
            DeviceProviderSelection(
                provider_id=config.target.device_provider,
                capability_id=config.target.device_capability,
            )
            if config.target.device_provider is not None
            and config.target.device_capability is not None
            else None
        )
        device_options = DeviceProviderOptions(
            tuple(sorted(config.target.device_options.items()))
        )
    except ValueError as error:
        reporter.error(f"RXT060 Invalid device provider configuration: {error}")
        return 1

    try:
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
            artifact_evidence_policy=config.build.artifact_evidence_policy,
            artifact_distribution_policy=config.build.artifact_distribution_policy,
            device_selection=device_selection,
            device_options=device_options,
            executable_standalone=executable_standalone,
            standalone_contexts=(
                {ArtifactKind.HOST_EXECUTABLE: executable_standalone}
                if executable_standalone is not None
                else None
            ),
        )
    except ArtifactEvidenceRequiredError as error:
        return _report_required_evidence_failure(
            project_root, analysis, fallback, error, reporter
        )
    except PluginError as exc:
        return _report_plugin_capability_failure(
            project_root, analysis, fallback, exc, reporter, command="build"
        )
    except DeviceProviderError as error:
        reporter.error(f"RXT060 Device provider error: {error}")
        return 1
    except ArtifactProfilePlanningError as error:
        return _report_artifact_profile_failure(
            project_root,
            analysis,
            fallback,
            error,
            reporter,
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
    lines.append(f"  artifact evidence policy: {config.build.artifact_evidence_policy}")
    if device_selection is not None:
        lines.append(
            "  device provider: "
            f"{device_selection.provider_id}/{device_selection.capability_id}"
        )
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
    artifact_evidence = getattr(result, "artifact_evidence", None)
    if artifact_evidence is not None:
        if artifact_evidence.status == "preview-ready":
            lines.append(
                "  artifact evidence: preview-ready incomplete unsigned "
                f"(authority=evidence-only; "
                f"sbom={artifact_evidence.sbom.logical_path if artifact_evidence.sbom else 'n/a'}; "
                f"provenance="
                f"{artifact_evidence.provenance.logical_path if artifact_evidence.provenance else 'n/a'})"
            )
        else:
            reason = artifact_evidence.reason or "unavailable"
            lines.append(
                "  artifact evidence: unavailable "
                f"(authority=evidence-only; composition=incomplete; "
                f"signature_status=unsigned; reason={reason})"
            )
    artifact_evidence_gate = getattr(result, "artifact_evidence_gate", None)
    if artifact_evidence_gate is not None:
        lines.append(
            "  artifact evidence gate: "
            f"{artifact_evidence_gate.status} "
            "(distribution_authorized=false; complete=false; signed=false)"
        )
    artifact_authorization = getattr(
        result, "artifact_distribution_authorization", None
    )
    if artifact_authorization is not None:
        lines.append(
            "  artifact distribution authorization: blocked "
            "(authority=readiness-assessment-only; preview evidence gate "
            "satisfaction is not distribution authorization; "
            "distribution_authorized=false; complete=false; signed=false)"
        )
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
