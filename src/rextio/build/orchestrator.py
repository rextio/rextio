"""Build/generate orchestration: ties analysis, lowering, codegen, and the builders together."""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path

from rextio.analyzer.models import ProjectAnalysis
from rextio.analyzer.native_marker import external_accelerator_for_source
from rextio.artifacts.closure import (
    ClosureStatus,
    NativeClosureReport,
    closure_requires_prebuild_failure,
    resolve_executable_fallback,
    strategy_from_compatibility_value,
)
from rextio.artifacts.entry_graph import executable_entry_graph
from rextio.artifacts.authorization import (
    ArtifactDistributionAuthorizationAssessment,
    evaluate_artifact_distribution_authorization,
)
from rextio.artifacts.evidence import (
    ARTIFACT_EVIDENCE_POLICY_BEST_EFFORT,
    ARTIFACT_EVIDENCE_POLICY_REQUIRED,
    MAX_EVIDENCE_FILE_BYTES,
    MAX_SIDECAR_BYTES,
    REASON_EVIDENCE_INTERNAL,
    REASON_RUNTIME_BINARY_MISMATCH,
    REASON_RUNTIME_BINARY_MISSING,
    REASON_RUNTIME_WHEEL_MEMBER_MISMATCH,
    REASON_SIDECAR_WRITE_FAILED,
    REASON_WHEEL_MUTATED,
    ArtifactEvidence,
    ArtifactEvidenceError,
    ArtifactEvidenceGate,
    _EntryIdentity,
    _FileReceipt,
    _dirfd_ops_available,
    _lstat_at,
    _open_pinned_parent_dirfd,
    _quarantine_and_dispose_owned_at,
    _quarantine_and_dispose_owned_path,
    _receipt_at,
    _receipt_matches_at,
    _receipt_matches_path,
    _receipt_path,
    hash_regular_file,
    load_wheel_snapshot,
    project_relative_logical_path,
)
from rextio.artifacts.models import (
    ArtifactKind,
    ArtifactProfile,
    DeviceRequirement,
    FallbackStrategy,
    RuntimeRequirement,
)
from rextio.contract import TOOLING_CONTRACT_VERSION
from rextio.artifacts.profiles import (
    ArtifactProfilePlanningError,
    detect_host_target_triple,
    host_executable_profile,
    host_extension_profile,
    rust_crate_profile,
)
from rextio.build.supply_chain import (
    EvidenceInputSnapshot,
    capture_cargo_lock_input,
    capture_generated_python_inputs,
    capture_generated_rust_inputs,
    capture_project_source_snapshot,
    emit_host_extension_wheel_evidence,
    is_in_scope_host_extension_cpython,
)
from rextio.ir.types import RxtPluginType, normalize_type_name
from rextio.build.cargo_builder import (
    NativeBuildResult,
    build_native_extension_with_cargo,
    skipped_native_build,
)
from rextio.build.executable_builder import (
    ExecutableBuildResult,
    build_nuitka_executable,
    build_rust_executable,
    build_zipapp_executable,
    skipped_executable,
)
from rextio.build.maturin_builder import build_native_extension_with_maturin
from rextio.build.preflight import nuitka_toolchain_error
from rextio.build.subprocess_utils import DEFAULT_BUILD_TIMEOUT_SECONDS, run_build_tool
from rextio.build.toolchain import resolve_nuitka_command, resolve_python
from rextio.config.schema import ToolchainConfig
from rextio.devices import (
    DeviceProviderError,
    DeviceProviderOptions,
    DeviceProviderSelection,
    ResolvedDevicePlan,
    derive_device_requirements,
    derive_device_runtime_requirements,
    load_selected_device_provider,
    resolve_device_plan,
)
from rextio.codegen.rust.cargo import (
    render_binary_cargo_toml,
    render_cargo_config_toml,
    render_cargo_toml,
    render_importable_cargo_toml,
    render_native_link_build_rs,
    render_pyproject_toml,
)
from rextio.build.rust_crate_builder import (
    RustCrateBuildResult,
    build_importable_rust_crate,
    skipped_rust_crate_build,
)
from rextio.build.wheel_builder import (
    ExternalWheelContract,
    WheelBuildResult,
    artifact_wheel_path,
    build_artifact_wheel,
    skipped_wheel,
)
from rextio.build.full_c6_pipeline import (
    FULL_C6_DISTRIBUTION_POLICY,
    FullC6ExternalBuildContext,
    FullC6PipelineError,
    validate_full_c6_external_context,
)
from rextio.codegen.rust.generator import (
    crate_emitted_qualnames,
    generate_rust_crate_module,
    generate_rust_main_binary,
    generate_rust_module,
)
from rextio.codegen.rust.generator import RustCodegenError
from rextio.codegen.rust.subprocess_client import RUNTIME_DIR_SUFFIX
from rextio.codegen.subprocess_dispatcher import DISPATCHER_STEM, render_dispatcher_script
from rextio.codegen.python_wrapper.wrapper_gen import render_wrapper_module
from rextio.fallback.build_result import FallbackBuildResult, cpython_fallback_build_result
from rextio.fallback.cpython import (
    generated_path_for_module,
    write_cpython_fallback,
    write_cpython_native_top_level_fallback,
    write_plain_cpython_module,
)
from rextio.fallback.nuitka import build_nuitka_fallback
from rextio.ir.nodes import ModuleIR
from rextio.ir.module_init import ModuleInitIR
from rextio.ir.lowering import LoweringError, PluginTypeMaps, lower_project
from rextio.build.artifact_layout import ArtifactLayout
from rextio.partition.build_plan import BuildPlan, create_build_plan
from rextio.partition.fallback_plan import FallbackPlan
from rextio.plugins.capabilities import (
    StandalonePluginContext,
    analysis_function_plugin_type_keys,
    build_standalone_plugin_context,
    profile_crate_dependencies,
)
from rextio.plugins.loader import PluginError
from rextio.runtime.boundary_fallback import DEFAULT_BOUNDARY_FALLBACK_THRESHOLD
from rextio.source.external import (
    ExternalSourceBuildBlockedError,
    ExternalSourceC5NotImplementedError,
)
from rextio.source.planning import ensure_host_source_plan
from rextio.targets.plan import TargetPlan, default_target_plan


# Modules the generated fallback dispatcher imports at runtime; a project
# module whose TOP-LEVEL name matches one of these would shadow it under the
# dispatcher's sys.path[0] and break delegated fallback (council round 8).
_DISPATCHER_RESERVED_TOP_LEVEL_NAMES = frozenset(
    {"importlib", "json", "os", "sys", "types", "rextio"}
)


def _required_host_target_triple() -> str:
    """Resolve a requested native host target through one actionable error."""
    try:
        return detect_host_target_triple()
    except ValueError as error:
        raise ArtifactProfilePlanningError(
            f"RXT060 Artifact profile planning failed. Cause: {error}"
        ) from error


def _plugin_lowering_inputs(
    target_plan: TargetPlan,
) -> tuple[PluginTypeMaps | None, dict[str, object] | None, dict[str, RxtPluginType] | None]:
    """Build the lowering/codegen plugin inputs from the target plan's registry.

    Returns ``(plugin_type_maps, plugin_providers, plugin_types_by_key)``, all
    None when no active plugin provides lowering. The ``RxtPluginType``
    instances are constructed once per plugin type key and shared by both
    maps, so identity/equality checks agree across lowering and codegen.
    """
    registry = target_plan.plugins
    if not registry.providers:
        return None, None, None
    by_key: dict[str, RxtPluginType] = {}
    by_spelling: dict[str, RxtPluginType] = {}
    for binding in registry.types:
        plugin_type = binding.plugin_type
        rxt_type = by_key.get(plugin_type.key)
        if rxt_type is None:
            conversion = plugin_type.conversion
            if conversion is None:
                # Resident type (plugin API 1.3): opaque native-only value, no
                # Python boundary conversion. The conversion fields stay empty,
                # but the type may still OWN a named Rust struct through its
                # module support.
                rxt_type = RxtPluginType(
                    key=plugin_type.key,
                    native_rust=plugin_type.rust_type,
                    resident=True,
                    uses=plugin_type.uses,
                    helpers=plugin_type.helpers,
                    device_value_metadata=plugin_type.device_value_metadata,
                )
            else:
                rxt_type = RxtPluginType(
                    key=plugin_type.key,
                    native_rust=plugin_type.rust_type,
                    param_rust=conversion.param_rust,
                    param_expr=conversion.param_expr,
                    return_rust=conversion.return_rust,
                    return_expr=conversion.return_expr,
                    uses=plugin_type.uses,
                    helpers=plugin_type.helpers,
                    device_value_metadata=plugin_type.device_value_metadata,
                )
            by_key[plugin_type.key] = rxt_type
        for spelling in plugin_type.annotations:
            by_spelling[spelling] = rxt_type
    providers: dict[str, object] = {
        binding.plugin_id: binding.provider for binding in registry.providers
    }
    return PluginTypeMaps(by_key=by_key, by_spelling=by_spelling), providers, by_key


@dataclass(frozen=True)
class NativeSourceResult:
    """The outcome of generating native source (no compilation)."""

    status: str
    message: str
    path: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this result."""
        return {
            "status": self.status,
            "message": self.message,
            "path": self.path,
        }


@dataclass(frozen=True)
class GenerateResult:
    """The aggregate result of ``rextio generate``."""

    fallback: str
    boundary_fallback_threshold: int
    target_plan: TargetPlan
    layout: ArtifactLayout
    plan: BuildPlan
    accepted_native_count: int
    rejected_native_count: int
    native_source: NativeSourceResult
    rust_crate_source: NativeSourceResult
    plugin_crate_dependencies: tuple[dict[str, object], ...] = ()
    # Plugin API 1.4: resolved per-profile standalone capability (generate only
    # for requested rust-crate / host-executable profiles). Additive; absence
    # means no standalone profile was resolved for this generate.
    standalone_plugin_capabilities: tuple[dict[str, object], ...] = ()
    # Device Provider API 1: present only for an explicitly selected and
    # successfully preflighted provider. Raw provider option values are never
    # serialized; each plan exposes option keys plus a binding digest.
    device_provider_plans: tuple[dict[str, object], ...] = ()
    # Train C5 preview evidence.  Presence never authorizes a build.
    external_source_plan: dict[str, object] | None = None

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this result."""
        data: dict[str, object] = {
            # Additive tooling contract version (2.7.0+); consumers may ignore.
            "contract_version": TOOLING_CONTRACT_VERSION,
            "fallback": self.fallback,
            "boundary_fallback_threshold": self.boundary_fallback_threshold,
            "target": self.target_plan.to_dict(),
            "generated_native": str(self.layout.target_dir(self.target_plan.spec.language)),
            "generated_rust": str(self.layout.rust_dir),
            "generated_python": str(self.layout.python_dir),
            "plan": self.plan.to_dict(),
            "accepted_native_count": self.accepted_native_count,
            "rejected_native_count": self.rejected_native_count,
            "embedding_candidate_count": len(self.plan.native.embedded_functions),
            "native_source": self.native_source.to_dict(),
            "rust_crate_source": self.rust_crate_source.to_dict(),
            "artifact_profiles": [profile.to_dict() for profile in self.plan.artifact_profiles],
        }
        # Mirror build.json's plugin dependency report so the two reports stay
        # consistent (council round 8).
        if self.plugin_crate_dependencies:
            data["plugin_crate_dependencies"] = [
                dict(dependency) for dependency in self.plugin_crate_dependencies
            ]
        if self.standalone_plugin_capabilities:
            data["standalone_plugin_capabilities"] = [
                dict(item) for item in self.standalone_plugin_capabilities
            ]
        if self.device_provider_plans:
            data["device_provider_plans"] = [
                dict(item) for item in self.device_provider_plans
            ]
        if self.external_source_plan is not None:
            data["external_source_plan"] = dict(self.external_source_plan)
        return data


@dataclass(frozen=True)
class BuildResult:
    """The aggregate result of ``rextio build``."""

    fallback: str
    boundary_fallback_threshold: int
    target_plan: TargetPlan
    layout: ArtifactLayout
    plan: BuildPlan
    accepted_native_count: int
    rejected_native_count: int
    native_build: NativeBuildResult
    fallback_build: FallbackBuildResult
    wheel_build: WheelBuildResult
    executable_build: ExecutableBuildResult
    rust_crate_build: RustCrateBuildResult
    # Plugin-injected crate dependencies actually compiled into the native
    # extension: {"plugin_id", "name", "version", "features"} dicts
    # (docs/specs/plugin-lowering.md section 5). Empty for plugin-free builds.
    plugin_crate_dependencies: tuple[dict[str, object], ...] = ()
    # Plugin API 1.4: resolved standalone capability details for requested
    # rust-crate / host-executable profiles (additive).
    standalone_plugin_capabilities: tuple[dict[str, object], ...] = ()
    # Device Provider API 1: resolved only for an explicit host-extension
    # selection. Omitted entirely from legacy no-selection reports.
    device_provider_plans: tuple[dict[str, object], ...] = ()
    # C6.2: bounded host-extension wheel SBOM/provenance preview (additive).
    # Absent when the build is outside the ordinary host-extension wheel path.
    artifact_evidence: ArtifactEvidence | None = None
    # C6.3: emitted only for the opt-in required evidence policy. Even a
    # satisfied gate remains incomplete, unsigned, and non-authorizing.
    artifact_evidence_gate: ArtifactEvidenceGate | None = None
    # C6.5-C6.9: derived only from final C6.2-C6.9 evidence. This readiness
    # report is always blocked and never authorizes distribution.
    artifact_distribution_authorization: (
        ArtifactDistributionAuthorizationAssessment | None
    ) = None

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this result.

        ``plugin_crate_dependencies`` is emitted only when non-empty, so
        ``build.json`` keeps its existing shape for plugin-free builds.
        ``artifact_evidence`` is emitted for in-scope host-extension+cpython
        wheels as preview-ready or unavailable; out-of-scope builds omit it.
        """
        data: dict[str, object] = {
            # Additive tooling contract version (2.7.0+); consumers may ignore.
            "contract_version": TOOLING_CONTRACT_VERSION,
            "fallback": self.fallback,
            "boundary_fallback_threshold": self.boundary_fallback_threshold,
            "target": self.target_plan.to_dict(),
            "generated_native": str(self.layout.target_dir(self.target_plan.spec.language)),
            "generated_rust": str(self.layout.rust_dir),
            "generated_python": str(self.layout.python_dir),
            "build_python": str(self.layout.build_python_dir),
            "plan": self.plan.to_dict(),
            "accepted_native_count": self.accepted_native_count,
            "rejected_native_count": self.rejected_native_count,
            "embedding_candidate_count": len(self.plan.native.embedded_functions),
            "native_build": self.native_build.to_dict(),
            "fallback_build": self.fallback_build.to_dict(),
            "wheel_build": self.wheel_build.to_dict(),
            "executable_build": self.executable_build.to_dict(),
            "rust_crate_build": self.rust_crate_build.to_dict(),
            "artifact_profiles": [profile.to_dict() for profile in self.plan.artifact_profiles],
        }
        if self.plugin_crate_dependencies:
            data["plugin_crate_dependencies"] = [
                dict(dependency) for dependency in self.plugin_crate_dependencies
            ]
        if self.standalone_plugin_capabilities:
            data["standalone_plugin_capabilities"] = [
                dict(item) for item in self.standalone_plugin_capabilities
            ]
        if self.device_provider_plans:
            data["device_provider_plans"] = [
                dict(item) for item in self.device_provider_plans
            ]
        if self.artifact_evidence is not None:
            data["artifact_evidence"] = self.artifact_evidence.to_dict()
        if self.artifact_evidence_gate is not None:
            data["artifact_evidence_gate"] = self.artifact_evidence_gate.to_dict()
        if self.artifact_distribution_authorization is not None:
            data["artifact_distribution_authorization"] = (
                self.artifact_distribution_authorization.to_dict()
            )
        return data


class ArtifactEvidenceRequiredError(RuntimeError):
    """Raised when the opt-in required evidence policy blocks a build."""

    def __init__(
        self,
        gate: ArtifactEvidenceGate,
        *,
        result: BuildResult | None = None,
    ) -> None:
        self.gate = gate
        self.result = result
        detail = gate.evidence_reason or gate.reason or "evidence-unavailable"
        super().__init__(f"required artifact evidence gate blocked: {detail}")


def _artifact_authorization_assessment_no_throw(
    evidence: ArtifactEvidence,
) -> ArtifactDistributionAuthorizationAssessment:
    """Keep report-only C6.5 incapable of changing build or C6.3 outcomes."""
    try:
        return evaluate_artifact_distribution_authorization(evidence)
    except Exception:
        # Defense in depth: the evaluator is itself total, but an unrelated
        # future regression still degrades only to a fixed sanitized record.
        return evaluate_artifact_distribution_authorization(
            ArtifactEvidence.unavailable(reason=REASON_EVIDENCE_INTERNAL)
        )


@dataclass(frozen=True)
class _RequiredEvidenceRollback:
    """No-throw rollback result used to avoid overstating output cleanup."""

    current_outputs_removed: bool
    previous_outputs_restored: bool
    backup_directory_removed: bool

    @property
    def complete(self) -> bool:
        return (
            self.current_outputs_removed
            and self.previous_outputs_restored
            and self.backup_directory_removed
        )


def _lstat_or_none(path: Path) -> os.stat_result | None:
    """Inspect one directory entry without following a symlink."""
    try:
        return path.lstat()
    except FileNotFoundError:
        return None


def _unlink_entry_no_follow(path: Path) -> bool:
    """Remove one non-directory entry without following symlinks."""
    try:
        entry = path.lstat()
    except FileNotFoundError:
        return True
    except OSError:
        return False
    if stat.S_ISDIR(entry.st_mode):
        return False
    try:
        path.unlink()
    except OSError:
        return False
    try:
        return _lstat_or_none(path) is None
    except OSError:
        return False


def _entry_presence_no_follow(path: Path) -> bool | None:
    """Return entry presence without following links, or None if inspection failed."""
    try:
        return _lstat_or_none(path) is not None
    except OSError:
        return None


def _real_contained_directory(path: Path, *, parent: Path) -> None:
    """Require an existing direct child directory without following a symlink."""
    try:
        entry = path.lstat()
        parent_entry = parent.lstat()
        if stat.S_ISLNK(parent_entry.st_mode) or not stat.S_ISDIR(parent_entry.st_mode):
            raise OSError("required evidence parent must be a real directory")
        if stat.S_ISLNK(entry.st_mode) or not stat.S_ISDIR(entry.st_mode):
            raise OSError("required evidence directory must be a real directory")
        resolved_parent = parent.resolve(strict=True)
        resolved_path = path.resolve(strict=True)
    except OSError as error:
        raise OSError("required evidence directory could not be inspected") from error
    if resolved_path.parent != resolved_parent:
        raise OSError("required evidence directory escapes its expected parent")


@dataclass
class _RequiredEvidenceOutputs:
    """Pinned required-output transaction with exact ownership receipts."""

    paths: tuple[Path, ...]
    backups: tuple[Path | None, ...]
    backup_dir: Path
    _backup_receipts: tuple[_FileReceipt | None, ...]
    _dist_parent: Path
    _dist_identity: _EntryIdentity
    _prepared_count: int
    _dist_fd: int | None = None
    _build_fd: int | None = None
    _backup_fd: int | None = None
    _claimed: dict[int, _FileReceipt] = field(default_factory=dict)
    _active: bool = True
    _last_rollback: _RequiredEvidenceRollback | None = None

    @classmethod
    def prepare(cls, layout: ArtifactLayout, wheel_path: Path) -> _RequiredEvidenceOutputs:
        paths = (
            wheel_path,
            wheel_path.with_suffix(wheel_path.suffix + ".cdx.json"),
            wheel_path.with_suffix(wheel_path.suffix + ".intoto.json"),
        )
        dist_parent = wheel_path.parent
        if dist_parent != layout.dist_dir:
            raise OSError("required evidence output parent is not the dist directory")
        dist_parent.mkdir(parents=True, exist_ok=True)
        _real_contained_directory(dist_parent, parent=layout.root)
        _real_contained_directory(layout.build_dir, parent=layout.rextio_dir)
        backup_dir = layout.build_dir / "required-evidence-output-backup"

        dist_fd: int | None = None
        build_fd: int | None = None
        backup_fd: int | None = None
        backup_created = False
        dist_entry = dist_parent.lstat()
        dist_identity = _EntryIdentity.from_stat(dist_entry)
        if _dirfd_ops_available():
            dist_fd, pinned_dist = _open_pinned_parent_dirfd(dist_parent)
            dist_identity = _EntryIdentity.from_stat(pinned_dist)
            build_fd, _ = _open_pinned_parent_dirfd(layout.build_dir)
            try:
                os.mkdir(backup_dir.name, 0o700, dir_fd=build_fd)
                backup_created = True
                flags = os.O_RDONLY
                if hasattr(os, "O_DIRECTORY"):
                    flags |= os.O_DIRECTORY
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                backup_fd = os.open(backup_dir.name, flags, dir_fd=build_fd)
            except OSError:
                if backup_fd is not None:
                    try:
                        os.close(backup_fd)
                    except OSError:
                        pass
                    backup_fd = None
                if backup_created and build_fd is not None:
                    try:
                        os.rmdir(backup_dir.name, dir_fd=build_fd)
                    except OSError:
                        pass
                for open_fd in (build_fd, dist_fd):
                    if open_fd is not None:
                        try:
                            os.close(open_fd)
                        except OSError:
                            pass
                raise
        else:
            backup_dir.mkdir(mode=0o700, exist_ok=False)
        try:
            _real_contained_directory(backup_dir, parent=layout.build_dir)
        except OSError:
            if backup_fd is not None:
                try:
                    os.close(backup_fd)
                except OSError:
                    pass
                backup_fd = None
            try:
                if build_fd is not None:
                    os.rmdir(backup_dir.name, dir_fd=build_fd)
                else:
                    backup_dir.rmdir()
            except OSError:
                pass
            for containment_fd in (build_fd, dist_fd):
                if containment_fd is not None:
                    try:
                        os.close(containment_fd)
                    except OSError:
                        pass
            raise

        backups: list[Path | None] = [None] * len(paths)
        receipts: list[_FileReceipt | None] = [None] * len(paths)
        transaction = cls(
            paths=paths,
            backups=tuple(backups),
            backup_dir=backup_dir,
            _backup_receipts=tuple(receipts),
            _dist_parent=dist_parent,
            _dist_identity=dist_identity,
            _prepared_count=0,
            _dist_fd=dist_fd,
            _build_fd=build_fd,
            _backup_fd=backup_fd,
        )
        try:
            for index, path in enumerate(paths):
                entry = (
                    _lstat_at(dist_fd, path.name) if dist_fd is not None else _lstat_or_none(path)
                )
                transaction._prepared_count = index + 1
                if entry is None:
                    continue
                if not stat.S_ISREG(entry.st_mode):
                    raise OSError("required evidence output path is not a regular file")
                receipt = (
                    _receipt_at(dist_fd, path.name, max_bytes=MAX_EVIDENCE_FILE_BYTES)
                    if dist_fd is not None
                    else _receipt_path(path, max_bytes=MAX_SIDECAR_BYTES * 4)
                )
                backup = backup_dir / f"{index}.previous"
                # Write-ahead recovery state must exist before rename. A
                # post-rename receipt failure can then enter ordinary rollback
                # without rediscovering ownership from a possibly changed file.
                backups[index] = backup
                receipts[index] = receipt
                transaction.backups = tuple(backups)
                transaction._backup_receipts = tuple(receipts)
                if dist_fd is not None:
                    assert backup_fd is not None
                    os.replace(
                        path.name,
                        backup.name,
                        src_dir_fd=dist_fd,
                        dst_dir_fd=backup_fd,
                    )
                    if not _receipt_matches_at(backup_fd, backup.name, receipt):
                        raise OSError("required evidence backup identity changed")
                else:
                    path.replace(backup)
                    if not _receipt_matches_path(backup, receipt):
                        raise OSError("required evidence backup identity changed")
        except BaseException as error:
            outcome = transaction.rollback()
            if not outcome.complete:
                raise OSError(
                    "required evidence output preparation rollback was incomplete"
                ) from error
            raise
        transaction.backups = tuple(backups)
        transaction._backup_receipts = tuple(receipts)
        return transaction

    def _parent_matches(self) -> bool:
        try:
            current = self._dist_parent.lstat()
        except OSError:
            return False
        return _EntryIdentity.from_stat(current) == self._dist_identity

    def _current_receipt(self, index: int) -> _FileReceipt | None:
        path = self.paths[index]
        try:
            entry = (
                _lstat_at(self._dist_fd, path.name)
                if self._dist_fd is not None
                else _lstat_or_none(path)
            )
            if entry is None:
                return None
            if not stat.S_ISREG(entry.st_mode):
                raise OSError("required evidence output is not a regular file")
            return (
                _receipt_at(self._dist_fd, path.name, max_bytes=MAX_EVIDENCE_FILE_BYTES)
                if self._dist_fd is not None
                else _receipt_path(path, max_bytes=MAX_EVIDENCE_FILE_BYTES)
            )
        except ArtifactEvidenceError as exc:
            # Transaction state machines use one error domain. Receipt helpers
            # deliberately raise ArtifactEvidenceError, but allowing it to
            # escape here would bypass commit/rollback's fixed-reason RXT060
            # path and could make defensive cleanup fail a second time.
            raise OSError("required evidence output receipt is unavailable") from exc

    def publish_wheel(self, staged_path: Path) -> _FileReceipt:
        """Publish the private wheel stage with create-if-absent ownership."""
        if not self._active:
            raise OSError("required evidence transaction is inactive")
        expected = self.paths[0]
        if staged_path.parent != self.backup_dir or staged_path.name != expected.name:
            raise OSError("required evidence wheel stage is outside the transaction")
        if self._backup_fd is not None:
            assert self._dist_fd is not None
            receipt = _receipt_at(
                self._backup_fd,
                staged_path.name,
                max_bytes=MAX_EVIDENCE_FILE_BYTES,
            )
            try:
                os.link(
                    staged_path.name,
                    expected.name,
                    src_dir_fd=self._backup_fd,
                    dst_dir_fd=self._dist_fd,
                    follow_symlinks=False,
                )
            except OSError as exc:
                if _receipt_matches_at(self._backup_fd, staged_path.name, receipt):
                    try:
                        os.unlink(staged_path.name, dir_fd=self._backup_fd)
                    except OSError:
                        pass
                raise OSError("required evidence wheel publication was not exclusive") from exc
            if not _receipt_matches_at(self._dist_fd, expected.name, receipt):
                raise OSError("required evidence wheel publication changed")
            self._claimed[0] = receipt
            if not _receipt_matches_at(self._backup_fd, staged_path.name, receipt):
                raise OSError("required evidence wheel stage changed after publication")
            os.unlink(staged_path.name, dir_fd=self._backup_fd)
            return receipt

        receipt = _receipt_path(staged_path, max_bytes=MAX_EVIDENCE_FILE_BYTES)
        try:
            os.link(staged_path, expected, follow_symlinks=False)
        except OSError as exc:
            if _receipt_matches_path(staged_path, receipt):
                try:
                    staged_path.unlink()
                except OSError:
                    pass
            raise OSError("required evidence wheel publication was not exclusive") from exc
        if not _receipt_matches_path(expected, receipt):
            raise OSError("required evidence wheel publication changed")
        self._claimed[0] = receipt
        if not _receipt_matches_path(staged_path, receipt):
            raise OSError("required evidence wheel stage changed after publication")
        staged_path.unlink()
        return receipt

    def claim(self, path: Path, receipt: _FileReceipt | None = None) -> None:
        """Claim one successfully produced exact output for later rollback."""
        if not self._active:
            raise OSError("required evidence transaction is inactive")
        if receipt is None:
            raise OSError("required evidence output claim requires a publication receipt")
        matches = [index for index, expected in enumerate(self.paths) if expected == path]
        if len(matches) != 1:
            raise OSError("required evidence output is outside the transaction")
        index = matches[0]
        current = self._current_receipt(index)
        if current is None or current != receipt:
            raise OSError("required evidence output ownership claim failed")
        self._claimed[index] = current

    def claim_many(self, outputs: tuple[tuple[Path, _FileReceipt], ...]) -> None:
        """Atomically validate and record a sidecar publication receipt set."""
        if len(outputs) != 2:
            raise OSError("required sidecar claim must contain the exact output pair")
        pending: dict[int, _FileReceipt] = {}
        for path, receipt in outputs:
            matches = [index for index, expected in enumerate(self.paths) if expected == path]
            if len(matches) != 1:
                raise OSError("required sidecar claim is outside the transaction")
            index = matches[0]
            current = self._current_receipt(index)
            if current != receipt:
                raise OSError("required sidecar ownership claim failed")
            pending[index] = receipt
        if set(pending) != {1, 2}:
            raise OSError("required sidecar claim did not name the exact output pair")
        self._claimed.update(pending)

    def commit(self) -> None:
        """Discard preserved prior outputs after required evidence succeeds."""
        if not self._active or not self._parent_matches():
            raise OSError("required evidence output parent changed before commit")
        if set(self._claimed) != set(range(len(self.paths))):
            raise OSError("required evidence outputs were not all claimed")
        for index, receipt in self._claimed.items():
            if self._current_receipt(index) != receipt:
                raise OSError("required evidence output changed before commit")
        for index, backup_receipt in enumerate(self._backup_receipts):
            if backup_receipt is None:
                continue
            backup = self.backups[index]
            assert backup is not None
            try:
                if self._backup_fd is not None:
                    if _receipt_matches_at(self._backup_fd, backup.name, backup_receipt):
                        os.unlink(backup.name, dir_fd=self._backup_fd)
                elif _receipt_matches_path(backup, backup_receipt):
                    backup.unlink()
            except OSError:
                pass
        self._active = False
        self._remove_backup_dir()
        self._close()

    def claim_mismatch_reason(self) -> str:
        """Return a fixed reason for a failed final ownership revalidation."""
        if not self._parent_matches():
            return REASON_SIDECAR_WRITE_FAILED
        for index in range(len(self.paths)):
            claimed = self._claimed.get(index)
            if claimed is None:
                return REASON_SIDECAR_WRITE_FAILED
            try:
                current = self._current_receipt(index)
            except OSError:
                current = None
            if current != claimed:
                return REASON_WHEEL_MUTATED if index == 0 else REASON_SIDECAR_WRITE_FAILED
        return REASON_SIDECAR_WRITE_FAILED

    def rollback(self) -> _RequiredEvidenceRollback:
        """Remove this run's outputs and restore prior entries without following links."""
        if not self._active:
            return self._last_rollback or _RequiredEvidenceRollback(True, True, True)
        removed = self._parent_matches()
        restored = True
        for index in range(self._prepared_count):
            claimed = self._claimed.get(index)
            if claimed is not None:
                quarantine_name = f"{index}.current-quarantine"
                if self._dist_fd is not None:
                    assert self._backup_fd is not None
                    cleaned = _quarantine_and_dispose_owned_at(
                        self._dist_fd,
                        self.paths[index].name,
                        self._backup_fd,
                        quarantine_name,
                        claimed,
                    )
                else:
                    cleaned = _quarantine_and_dispose_owned_path(
                        self.paths[index],
                        self.backup_dir / quarantine_name,
                        claimed,
                    )
                if not cleaned:
                    removed = False
            else:
                try:
                    current_present = (
                        _lstat_at(self._dist_fd, self.paths[index].name)
                        if self._dist_fd is not None
                        else _lstat_or_none(self.paths[index])
                    )
                except OSError:
                    current_present = None
                    removed = False
                if current_present is not None:
                    # Unknown output belongs to somebody else.
                    removed = False

            prior = self._backup_receipts[index]
            if prior is None:
                continue
            backup = self.backups[index]
            assert backup is not None
            try:
                current = self._current_receipt(index)
            except OSError:
                restored = False
                continue
            if current is not None:
                restored = False
                continue
            try:
                if self._backup_fd is not None:
                    assert self._dist_fd is not None
                    if not _receipt_matches_at(self._backup_fd, backup.name, prior):
                        restored = False
                        continue
                    os.link(
                        backup.name,
                        self.paths[index].name,
                        src_dir_fd=self._backup_fd,
                        dst_dir_fd=self._dist_fd,
                        follow_symlinks=False,
                    )
                    if not _receipt_matches_at(self._dist_fd, self.paths[index].name, prior):
                        restored = False
                        continue
                    os.unlink(backup.name, dir_fd=self._backup_fd)
                else:
                    if not _receipt_matches_path(backup, prior):
                        restored = False
                        continue
                    os.link(backup, self.paths[index], follow_symlinks=False)
                    if not _receipt_matches_path(self.paths[index], prior):
                        restored = False
                        continue
                    backup.unlink()
            except OSError:
                restored = False

        backup_removed = self._remove_backup_dir()
        result = _RequiredEvidenceRollback(removed, restored, backup_removed)
        self._active = False
        self._last_rollback = result
        self._close()
        return result

    def _remove_backup_dir(self) -> bool:
        if self._backup_fd is not None:
            try:
                os.close(self._backup_fd)
            except OSError:
                pass
            self._backup_fd = None
        try:
            if self._build_fd is not None:
                os.rmdir(self.backup_dir.name, dir_fd=self._build_fd)
            else:
                self.backup_dir.rmdir()
        except OSError:
            return False
        return True

    def _close(self) -> None:
        for name in ("_backup_fd", "_build_fd", "_dist_fd"):
            fd = getattr(self, name)
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
                setattr(self, name, None)


def _required_evidence_output_mismatch_reason(
    *,
    project_root: Path,
    layout: ArtifactLayout,
    expected_wheel: Path,
    wheel_build: WheelBuildResult,
    native_build: NativeBuildResult,
    evidence: ArtifactEvidence,
) -> str | None:
    """Revalidate the exact final files immediately before satisfying the gate."""
    if (
        evidence.status != "preview-ready"
        or evidence.subject is None
        or evidence.sbom is None
        or evidence.provenance is None
        or evidence.native_runtime_inventory is None
    ):
        return REASON_EVIDENCE_INTERNAL
    if wheel_build.status != "built" or wheel_build.path is None:
        return REASON_WHEEL_MUTATED
    if Path(wheel_build.path) != expected_wheel:
        return REASON_WHEEL_MUTATED

    expected_sbom = expected_wheel.with_suffix(expected_wheel.suffix + ".cdx.json")
    expected_provenance = expected_wheel.with_suffix(expected_wheel.suffix + ".intoto.json")
    for path, recorded in (
        (expected_sbom, evidence.sbom),
        (expected_provenance, evidence.provenance),
    ):
        try:
            logical = project_relative_logical_path(project_root, path)
            digest, size = hash_regular_file(path, max_bytes=MAX_SIDECAR_BYTES)
        except (ArtifactEvidenceError, OSError, ValueError):
            return REASON_SIDECAR_WRITE_FAILED
        if recorded.logical_path != logical or recorded.sha256 != digest or recorded.size != size:
            return REASON_SIDECAR_WRITE_FAILED

    native_mismatch = _required_native_runtime_mismatch_reason(
        layout=layout,
        native_build=native_build,
        evidence=evidence,
    )
    if native_mismatch is not None:
        return native_mismatch

    # Take one final immutable wheel snapshot after checking both sidecars and
    # the installed native binary. Besides binding the whole-wheel subject,
    # this lets required mode revalidate the exact native ZIP member rather
    # than trusting an earlier basename lookup.
    try:
        wheel_logical = project_relative_logical_path(project_root, expected_wheel)
        final_subject, final_entries = load_wheel_snapshot(
            expected_wheel,
            project_root=project_root,
        )
    except (ArtifactEvidenceError, OSError, ValueError):
        return REASON_WHEEL_MUTATED
    if (
        evidence.subject.logical_path != wheel_logical
        or evidence.subject.sha256 != final_subject.sha256
        or evidence.subject.size != final_subject.size
    ):
        return REASON_WHEEL_MUTATED

    runtime_inventory = evidence.native_runtime_inventory
    final_matches = tuple(
        entry for entry in final_entries if entry.name == runtime_inventory.wheel_member
    )
    recorded_matches = tuple(
        entry for entry in evidence.wheel_entries if entry.name == runtime_inventory.wheel_member
    )
    if len(final_matches) != 1 or len(recorded_matches) != 1:
        return REASON_RUNTIME_WHEEL_MEMBER_MISMATCH
    final_member = final_matches[0]
    recorded_member = recorded_matches[0]
    if (
        final_member != recorded_member
        or final_member.sha256 != runtime_inventory.wheel_member_sha256
        or final_member.uncompressed_size != runtime_inventory.wheel_member_size
    ):
        return REASON_RUNTIME_WHEEL_MEMBER_MISMATCH
    return None


def _required_native_runtime_mismatch_reason(
    *,
    layout: ArtifactLayout,
    native_build: NativeBuildResult,
    evidence: ArtifactEvidence,
) -> str | None:
    """Re-hash the exact contained installed binary recorded by C6.4."""
    runtime_inventory = evidence.native_runtime_inventory
    if runtime_inventory is None:
        return REASON_EVIDENCE_INTERNAL
    if native_build.status != "built" or native_build.installed_path is None:
        return REASON_RUNTIME_BINARY_MISSING

    installed = Path(native_build.installed_path)
    try:
        # The generated Python root itself must be the real directory created
        # by this build, not a symlink redirected elsewhere.
        _real_contained_directory(layout.python_dir, parent=layout.generated_dir)
        root = Path(os.path.abspath(layout.python_dir))
        binary = Path(os.path.abspath(installed))
        relative = binary.relative_to(root)
        if not relative.parts:
            return REASON_RUNTIME_BINARY_MISSING

        # Reject symlink ancestors as well as a symlink/non-regular leaf. This
        # keeps a path lexically below the generated root from redirecting the
        # final verification to another tree.
        current = root
        for part in relative.parts[:-1]:
            current = current / part
            entry = current.lstat()
            if stat.S_ISLNK(entry.st_mode) or not stat.S_ISDIR(entry.st_mode):
                return REASON_RUNTIME_BINARY_MISSING
        entry = binary.lstat()
        if stat.S_ISLNK(entry.st_mode) or not stat.S_ISREG(entry.st_mode):
            return REASON_RUNTIME_BINARY_MISSING
        resolved_root = root.resolve(strict=True)
        resolved_binary = binary.resolve(strict=True)
        resolved_binary.relative_to(resolved_root)
    except (OSError, ValueError):
        return REASON_RUNTIME_BINARY_MISSING
    try:
        digest, size = hash_regular_file(binary)
    except (ArtifactEvidenceError, OSError, ValueError):
        return REASON_RUNTIME_BINARY_MISMATCH

    expected_member = relative.as_posix()
    if (
        binary.name != runtime_inventory.subject_basename
        or expected_member != runtime_inventory.wheel_member
    ):
        return REASON_RUNTIME_WHEEL_MEMBER_MISMATCH
    if digest != runtime_inventory.subject_sha256 or size != runtime_inventory.subject_size:
        return REASON_RUNTIME_BINARY_MISMATCH
    if (
        digest != runtime_inventory.wheel_member_sha256
        or size != runtime_inventory.wheel_member_size
    ):
        return REASON_RUNTIME_WHEEL_MEMBER_MISMATCH

    recorded_matches = tuple(
        entry for entry in evidence.wheel_entries if entry.name == runtime_inventory.wheel_member
    )
    if len(recorded_matches) != 1:
        return REASON_RUNTIME_WHEEL_MEMBER_MISMATCH
    recorded_member = recorded_matches[0]
    if (
        recorded_member.sha256 != runtime_inventory.wheel_member_sha256
        or recorded_member.uncompressed_size != runtime_inventory.wheel_member_size
    ):
        return REASON_RUNTIME_WHEEL_MEMBER_MISMATCH
    return None


@dataclass(frozen=True)
class PlannedExecutableBuildResult(ExecutableBuildResult):
    """An executable result carrying its deterministic closure report."""

    closure: NativeClosureReport | None = None

    def to_dict(self) -> dict[str, object]:
        """Return the executable result with its closure report."""
        data = super().to_dict()
        data["closure"] = self.closure.to_dict() if self.closure is not None else None
        return data


def _generate_artifact_profiles(
    fallback: str,
    *,
    native_extension: bool,
    rust_importable: bool,
    runtime_requirements: tuple[RuntimeRequirement, ...] = (),
    device_requirements: tuple[DeviceRequirement, ...] = (),
) -> tuple[ArtifactProfile, ...]:
    if not native_extension and not rust_importable:
        return ()
    target_triple = _required_host_target_triple()
    profiles: list[ArtifactProfile] = []
    if native_extension:
        profiles.append(
            host_extension_profile(
                target_triple,
                python_fallback_backend=fallback,
                runtime_requirements=runtime_requirements,
                device_requirements=device_requirements,
            )
        )
    if rust_importable:
        profiles.append(
            rust_crate_profile(
                target_triple,
                runtime_requirements=runtime_requirements,
                device_requirements=device_requirements,
            )
        )
    return tuple(profiles)


def _build_artifact_profiles(
    fallback: str,
    executable_fallback: FallbackStrategy,
    *,
    executable_entrypoint: str | None,
    executable_backend: str,
    native_extension: bool,
    rust_importable: bool,
    runtime_requirements: tuple[RuntimeRequirement, ...] = (),
    device_requirements: tuple[DeviceRequirement, ...] = (),
) -> tuple[ArtifactProfile, ...]:
    rust_executable = executable_entrypoint is not None and executable_backend == "rust"
    if not native_extension and not rust_importable and not rust_executable:
        return ()
    target_triple = _required_host_target_triple()
    profiles: list[ArtifactProfile] = []
    if native_extension:
        profiles.append(
            host_extension_profile(
                target_triple,
                python_fallback_backend=fallback,
                runtime_requirements=runtime_requirements,
                device_requirements=device_requirements,
            )
        )
    if rust_executable:
        profiles.append(
            host_executable_profile(
                target_triple,
                fallback=executable_fallback,
                runtime_requirements=runtime_requirements,
                device_requirements=device_requirements,
            )
        )
    if rust_importable:
        profiles.append(
            rust_crate_profile(
                target_triple,
                runtime_requirements=runtime_requirements,
                device_requirements=device_requirements,
            )
        )
    return tuple(profiles)


def _accepted_device_profile_requirements(
    analysis: ProjectAnalysis,
    target_plan: TargetPlan,
    options: DeviceProviderOptions,
) -> tuple[tuple[RuntimeRequirement, ...], tuple[DeviceRequirement, ...]]:
    """Derive static device requirements from actually accepted plugin types."""
    used_keys: set[str] = set()
    for function in analysis.accepted_native_functions:
        used_keys.update(analysis_function_plugin_type_keys(function))
    if not used_keys:
        return (), ()
    metadata_by_key = {
        binding.plugin_type.key: binding.plugin_type.device_value_metadata
        for binding in target_plan.plugins.types
    }
    metadata = tuple(
        value
        for key in sorted(used_keys)
        if (value := metadata_by_key.get(key)) is not None
    )
    try:
        device_requirements = derive_device_requirements(metadata)
        runtime_requirements = derive_device_runtime_requirements(metadata)
    except ValueError as exc:
        raise DeviceProviderError(
            f"accepted plugin types have incompatible static device domains: {exc}"
        ) from exc
    # Architecture is a build/provider-selection fact, not a Python value-type
    # fact. Compose the existing explicit option into the exact profile that
    # the selected CUDA provider preflights.
    selected_sm = options.get("sm")
    if selected_sm is not None and device_requirements:
        if len(device_requirements) != 1 or device_requirements[0].backend != "cuda":
            raise DeviceProviderError(
                "device option 'sm' is valid only for one CUDA artifact requirement"
            )
        device_requirements = (
            replace(device_requirements[0], architectures=(selected_sm,)),
        )
    return runtime_requirements, device_requirements


def required_artifact_evidence_scope_is_valid(
    *,
    native_extension: bool,
    fallback: str,
    executable_entrypoint: str | None,
    rust_importable: bool,
) -> bool:
    """Check the exact C6.3 artifact set without probing any toolchain."""
    return (
        native_extension
        and fallback == "cpython"
        and executable_entrypoint is None
        and not rust_importable
    )


def _resolve_build_device_plans(
    artifact_profiles: tuple[ArtifactProfile, ...],
    *,
    selection: DeviceProviderSelection | None,
    options: DeviceProviderOptions,
    entry_points: Iterable[object] | None,
) -> tuple[ResolvedDevicePlan, ...]:
    """Resolve the bounded host-extension provider before build side effects."""
    if selection is None:
        if options.values:
            raise DeviceProviderError(
                "device provider options require an explicit provider selection"
            )
        # Apply the same no-selection contract to every exact profile. This is
        # normally a no-op for today's CPU profiles, but it must fail closed as
        # soon as any domain integration contributes a typed accelerator
        # requirement, regardless of that profile's position in a multi-output
        # plan. No provider entry point is discovered or imported here.
        for artifact_profile in artifact_profiles:
            resolved = resolve_device_plan(
                artifact_profile=artifact_profile,
                selection=None,
                providers={},
                options=options,
            )
            if resolved is not None:  # defensive: no selection never resolves
                raise DeviceProviderError(
                    "unselected device provider unexpectedly produced a resolved plan"
                )
        return ()
    if (
        len(artifact_profiles) != 1
        or artifact_profiles[0].kind is not ArtifactKind.HOST_EXTENSION
    ):
        raise DeviceProviderError(
            "Device Provider API 1 build integration currently supports exactly "
            "one host-extension artifact profile"
        )
    provider, source = load_selected_device_provider(
        selection,
        entry_points=entry_points,
    )
    resolved = resolve_device_plan(
        artifact_profile=artifact_profiles[0],
        selection=selection,
        providers={selection.provider_id: provider},
        provider_sources={selection.provider_id: source},
        options=options,
    )
    if resolved is None:  # explicit selection can never resolve to no plan
        raise DeviceProviderError("selected device provider produced no resolved plan")
    contribution = resolved.contribution
    unsupported_inputs: list[str] = []
    if contribution.cargo_features:
        unsupported_inputs.append("cargo_features")
    if contribution.package_references:
        unsupported_inputs.append("package_references")
    if contribution.generated_helper_ids:
        unsupported_inputs.append("generated_helper_ids")
    if contribution.runtime_check_ids:
        unsupported_inputs.append("runtime_check_ids")
    if unsupported_inputs:
        raise DeviceProviderError(
            "selected device provider contribution cannot be represented by "
            "the bounded host-extension integration: "
            + ", ".join(unsupported_inputs)
        )
    return (resolved,)


def build_hybrid_artifact(
    project_root: Path,
    analysis: ProjectAnalysis,
    fallback: str,
    build_tool: str = "cargo",
    boundary_fallback_threshold: int = DEFAULT_BOUNDARY_FALLBACK_THRESHOLD,
    executable_entrypoint: str | None = None,
    executable_name: str | None = None,
    executable_backend: str = "zipapp",
    nuitka_mode: str = "standalone",
    target_plan: TargetPlan | None = None,
    rust_importable: bool = False,
    rust_crate_name: str = "rextio_generated_rust",
    embedding_enabled: bool = False,
    build_timeout_seconds: float = DEFAULT_BUILD_TIMEOUT_SECONDS,
    executable_analysis: ProjectAnalysis | None = None,
    executable_python: str | None = None,
    executable_hybrid_runtime: str | None = None,
    executable_fallback: FallbackStrategy | str | None = None,
    toolchain: ToolchainConfig | None = None,
    artifact_evidence_policy: str = ARTIFACT_EVIDENCE_POLICY_BEST_EFFORT,
    artifact_distribution_policy: str = "disabled",
    full_c6_external_context: FullC6ExternalBuildContext | None = None,
    device_selection: DeviceProviderSelection | None = None,
    device_options: DeviceProviderOptions | None = None,
    device_entry_points: Iterable[object] | None = None,
    *,
    executable_standalone: StandalonePluginContext | None = None,
    standalone_contexts: dict[ArtifactKind, StandalonePluginContext] | None = None,
) -> BuildResult:
    """Build the hybrid native+fallback artifact for a project.

    ``executable_analysis`` is the project analysis the ``rust`` executable
    backend uses; it is analyzed in delegate mode so the entrypoint can call
    project fallback functions through the external CPython dispatcher. It
    defaults to ``analysis`` for the other backends, which do not delegate.

    ``executable_standalone`` / ``standalone_contexts`` allow the CLI preflight
    to resolve plugin API 1.4 capability once and reuse the same immutable
    context for closure, codegen, dependency selection, and reports.
    """
    if executable_analysis is None:
        executable_analysis = analysis
    blocked_plan = analysis.external_source_plan or executable_analysis.external_source_plan
    strict_distribution = artifact_distribution_policy == FULL_C6_DISTRIBUTION_POLICY
    if artifact_distribution_policy not in {"disabled", FULL_C6_DISTRIBUTION_POLICY}:
        raise ValueError("artifact_distribution_policy must be disabled or strict-evidence")
    if strict_distribution:
        if full_c6_external_context is None:
            raise FullC6PipelineError(
                "RXT060 strict evidence distribution policy lacks a same-transaction strict C5.2 context"
            )
        if blocked_plan is None:
            raise FullC6PipelineError(
                "RXT060 strict evidence distribution policy lacks an exact external source plan"
            )
        validate_full_c6_external_context(full_c6_external_context, analysis)
        strict_scope_failures = (
            fallback != "cpython"
            or build_tool != "cargo"
            or artifact_evidence_policy != ARTIFACT_EVIDENCE_POLICY_REQUIRED
            or executable_entrypoint is not None
            or rust_importable
            or embedding_enabled
            or device_selection is not None
        )
        if strict_scope_failures:
            raise FullC6PipelineError(
                "RXT060 strict evidence distribution policy is frozen to Cargo/PyO3 host-extension + "
                "CPython fallback, required evidence, no executable/importable crate, "
                "and no helper embedding"
            )
    elif full_c6_external_context is not None:
        raise FullC6PipelineError(
            "RXT060 strict C5.2 context cannot enter an ordinary or preview build"
        )
    if blocked_plan is not None and not strict_distribution:
        # External-source work must stop before target discovery, generated-
        # source cleanup, Cargo, Python fallback, wheel, executable, or
        # rust-crate work.  C6.1 verifies a project SourceLock; a verified lock
        # still cannot claim remaining C5.2 linkage/codegen/packaging.
        if blocked_plan.authorization_verified:
            raise ExternalSourceC5NotImplementedError(blocked_plan)
        raise ExternalSourceBuildBlockedError(blocked_plan)
    if artifact_evidence_policy not in {
        ARTIFACT_EVIDENCE_POLICY_BEST_EFFORT,
        ARTIFACT_EVIDENCE_POLICY_REQUIRED,
    }:
        raise ValueError("artifact_evidence_policy must be best-effort or required")
    ordinary_required_evidence = (
        artifact_evidence_policy == ARTIFACT_EVIDENCE_POLICY_REQUIRED
        and not strict_distribution
    )
    if ordinary_required_evidence and not (
        required_artifact_evidence_scope_is_valid(
            native_extension=analysis.requires_native_build(),
            fallback=fallback,
            executable_entrypoint=executable_entrypoint,
            rust_importable=rust_importable,
        )
    ):
        raise ArtifactEvidenceRequiredError(ArtifactEvidenceGate.out_of_scope())
    fallback_strategy = resolve_executable_fallback(executable_fallback, executable_hybrid_runtime)
    toolchain = toolchain or ToolchainConfig()
    target_plan = target_plan or default_target_plan()
    if strict_distribution and (
        target_plan.spec.language != "rust" or target_plan.plugins.active
    ):
        raise FullC6PipelineError(
            "RXT060 strict evidence distribution policy is frozen to Rust with no active plugins"
        )
    layout = ArtifactLayout(project_root)
    resolved_device_options = device_options or DeviceProviderOptions()
    runtime_requirements, device_requirements = _accepted_device_profile_requirements(
        analysis,
        target_plan,
        resolved_device_options,
    )
    artifact_profiles = _build_artifact_profiles(
        fallback,
        fallback_strategy,
        executable_entrypoint=executable_entrypoint,
        executable_backend=executable_backend,
        native_extension=analysis.requires_native_build(),
        rust_importable=rust_importable and analysis.requires_native_build(),
        runtime_requirements=runtime_requirements,
        device_requirements=device_requirements,
    )
    resolved_device_plans = _resolve_build_device_plans(
        artifact_profiles,
        selection=device_selection,
        options=resolved_device_options,
        entry_points=device_entry_points,
    )
    plan = create_build_plan(analysis, fallback, artifact_profiles=artifact_profiles)
    if ordinary_required_evidence and not (
        len(plan.artifact_profiles) == 1 and is_in_scope_host_extension_cpython(plan)
    ):
        raise ArtifactEvidenceRequiredError(ArtifactEvidenceGate.out_of_scope())
    # Resolve each exact ArtifactProfile's capability at most once for this command.
    contexts = _ensure_standalone_contexts(
        plan,
        target_plan,
        seed=standalone_contexts,
        executable_analysis=executable_analysis,
        executable_standalone=executable_standalone,
        include_executable=(executable_backend == "rust" and executable_entrypoint is not None),
    )
    closure_report: NativeClosureReport | None = None
    resolved_executable_standalone = contexts.get(ArtifactKind.HOST_EXECUTABLE)
    if executable_backend == "rust" and executable_entrypoint is not None:
        executable_profile = next(
            profile for profile in artifact_profiles if profile.kind is ArtifactKind.HOST_EXECUTABLE
        )
        assert resolved_executable_standalone is not None
        closure_report = executable_entry_graph(
            executable_analysis,
            _entrypoint_to_qualname(executable_entrypoint),
            fallback_strategy,
            profile=executable_profile,
            plugin_capabilities=resolved_executable_standalone.capabilities,
        )
    if closure_report is not None and closure_requires_prebuild_failure(closure_report):
        assert executable_entrypoint is not None
        return _failed_closure_build_result(
            layout,
            analysis,
            plan,
            fallback,
            boundary_fallback_threshold,
            target_plan,
            closure_report,
            executable_entrypoint,
            executable_name,
            rust_crate_name,
            standalone_contexts=contexts,
        )
    _reset_generated_dir(layout.build_dir)
    _prepare_generated_sources(layout, target_plan)
    _write_check_report(layout, analysis)
    _write_python_fallback_tree(plan.fallback, layout.python_dir, boundary_fallback_threshold)
    _write_runtime_support(layout.python_dir)
    # C6.2: only capture prebuild evidence snapshots for in-scope
    # host-extension+cpython builds. Out-of-scope paths skip the work entirely.
    evidence_snapshot: EvidenceInputSnapshot | None = None
    if is_in_scope_host_extension_cpython(plan):
        evidence_snapshot = capture_project_source_snapshot(project_root=project_root, plan=plan)
        evidence_snapshot = capture_generated_python_inputs(
            evidence_snapshot, project_root=project_root, layout=layout
        )
    native_build, plugin_crate_dependencies, updated_snapshot = _generate_and_build_native(
        plan,
        layout,
        build_tool,
        target_plan,
        embedding_enabled=embedding_enabled,
        build_timeout=build_timeout_seconds,
        toolchain=toolchain,
        evidence_snapshot=evidence_snapshot,
        project_root=project_root,
        full_c6_external_context=full_c6_external_context,
        device_plan=(
            resolved_device_plans[0] if resolved_device_plans else None
        ),
    )
    if updated_snapshot is not None:
        evidence_snapshot = updated_snapshot
    if evidence_snapshot is not None and native_build.status == "built":
        evidence_snapshot = capture_cargo_lock_input(
            evidence_snapshot, project_root=project_root, layout=layout
        )
    rust_crate_build = _generate_and_build_rust_crate(
        plan,
        layout,
        target_plan,
        enabled=rust_importable,
        crate_name=rust_crate_name,
        build_timeout=build_timeout_seconds,
        toolchain=toolchain,
        standalone_context=contexts.get(ArtifactKind.RUST_CRATE),
    )
    _write_build_artifact(layout)
    fallback_build = _build_fallback_backend(
        fallback, layout, build_timeout=build_timeout_seconds, toolchain=toolchain
    )
    required_outputs: _RequiredEvidenceOutputs | None = None
    expected_wheel: Path | None = None
    strict_candidate_dir: Path | None = None
    if strict_distribution:
        # A C5.2 candidate is build input for the separate two-build Full C6
        # executor, not a distributable artifact.  Keep it under the private
        # build tree; only the sealed publication adapter may create dist output.
        strict_candidate_dir = layout.build_dir / "full-c6-candidate"
        strict_candidate_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    if ordinary_required_evidence:
        expected_wheel = artifact_wheel_path(project_root, layout.build_python_dir, layout.dist_dir)
        try:
            required_outputs = _RequiredEvidenceOutputs.prepare(layout, expected_wheel)
        except (ArtifactEvidenceError, OSError):
            failed_evidence = ArtifactEvidence.unavailable(
                reason=REASON_SIDECAR_WRITE_FAILED,
                target_triple=plan.artifact_profiles[0].target_triple,
            )
            gate = ArtifactEvidenceGate.from_evidence(failed_evidence)
            raise ArtifactEvidenceRequiredError(gate) from None
    try:
        wheel_build = _build_wheel_artifact(
            project_root,
            layout,
            native_build,
            fallback_build,
            output_dir=(
                required_outputs.backup_dir
                if required_outputs is not None
                else strict_candidate_dir
            ),
            external_contract=(
                full_c6_external_context.wheel_contract
                if full_c6_external_context is not None
                else None
            ),
        )
        publication_failure_reason: str | None = None
        if required_outputs is not None:
            assert expected_wheel is not None
            if wheel_build.status == "built" and wheel_build.path is not None:
                staged_wheel = Path(wheel_build.path)
                try:
                    required_outputs.publish_wheel(staged_wheel)
                except (ArtifactEvidenceError, OSError):
                    publication_failure_reason = REASON_WHEEL_MUTATED
                else:
                    wheel_build = WheelBuildResult(
                        status=wheel_build.status,
                        path=str(expected_wheel),
                        message=wheel_build.message,
                    )
        # C6.2: after the ordinary host-extension+cpython wheel is finalized, emit
        # preview-ready or unavailable evidence. Out-of-scope builds omit the field.
        # Unavailability never raises into the ordinary build success path.
        artifact_evidence: ArtifactEvidence | None
        if strict_distribution:
            # C6.2-C6.15 preview records are intentionally not promoted or
            # interpreted inside the complete Full C6 path.
            artifact_evidence = None
        elif publication_failure_reason is not None:
            artifact_evidence = ArtifactEvidence.unavailable(
                reason=publication_failure_reason,
                target_triple=plan.artifact_profiles[0].target_triple,
            )
        else:
            artifact_evidence = emit_host_extension_wheel_evidence(
                project_root=project_root,
                layout=layout,
                plan=plan,
                wheel_build=wheel_build,
                native_build=native_build,
                input_snapshot=evidence_snapshot,
                embedding_enabled=embedding_enabled,
                timeout=build_timeout_seconds,
                toolchain=toolchain,
                output_claim=(
                    required_outputs.claim_many if required_outputs is not None else None
                ),
            )
        artifact_evidence_gate: ArtifactEvidenceGate | None = None
        if ordinary_required_evidence:
            assert required_outputs is not None
            assert expected_wheel is not None
            if artifact_evidence is None:
                artifact_evidence = ArtifactEvidence.unavailable(
                    reason=REASON_EVIDENCE_INTERNAL,
                    target_triple=plan.artifact_profiles[0].target_triple,
                )
            elif artifact_evidence.status == "preview-ready":
                mismatch = _required_evidence_output_mismatch_reason(
                    project_root=project_root,
                    layout=layout,
                    expected_wheel=expected_wheel,
                    wheel_build=wheel_build,
                    native_build=native_build,
                    evidence=artifact_evidence,
                )
                if mismatch is not None:
                    artifact_evidence = ArtifactEvidence.unavailable(
                        reason=mismatch,
                        target_triple=plan.artifact_profiles[0].target_triple,
                    )
            artifact_evidence_gate = ArtifactEvidenceGate.from_evidence(artifact_evidence)
            if artifact_evidence_gate.status == "blocked":
                rollback = required_outputs.rollback()
                if rollback.complete:
                    cleanup_message = (
                        "the wheel and sidecars created by this run were removed and "
                        "pre-existing outputs were restored."
                    )
                else:
                    cleanup_message = (
                        "output rollback was incomplete; files may remain and "
                        "pre-existing outputs may require manual recovery."
                    )
                wheel_build = WheelBuildResult(
                    status="failed",
                    path=None,
                    message=(
                        "RXT060 Required artifact evidence was unavailable; " + cleanup_message
                    ),
                )
            else:
                try:
                    required_outputs.commit()
                except OSError:
                    # A final output can still be replaced between the explicit
                    # evidence revalidation above and transaction commit. Convert
                    # that ownership failure into the required gate's fixed-reason
                    # RXT060 path; rollback will remove only still-matching outputs
                    # and preserve the concurrent replacement.
                    artifact_evidence = ArtifactEvidence.unavailable(
                        reason=required_outputs.claim_mismatch_reason(),
                        target_triple=plan.artifact_profiles[0].target_triple,
                    )
                    artifact_evidence_gate = ArtifactEvidenceGate.from_evidence(artifact_evidence)
                    rollback = required_outputs.rollback()
                    if rollback.complete:
                        cleanup_message = (
                            "the wheel and sidecars created by this run were removed and "
                            "pre-existing outputs were restored."
                        )
                    else:
                        cleanup_message = (
                            "output rollback was incomplete; files may remain and "
                            "pre-existing outputs may require manual recovery."
                        )
                    wheel_build = WheelBuildResult(
                        status="failed",
                        path=None,
                        message=(
                            "RXT060 Required artifact evidence was unavailable; " + cleanup_message
                        ),
                    )
    except BaseException as error:
        if required_outputs is not None and required_outputs._active:
            rollback = required_outputs.rollback()
            if not rollback.complete:
                raise OSError("required evidence output rollback was incomplete") from error
        raise
    # C6.5 is derived only after best-effort evidence has reached its final
    # shape or required mode has completed revalidation and its output
    # transaction. It cannot affect build success or gate semantics.
    artifact_distribution_authorization = (
        _artifact_authorization_assessment_no_throw(artifact_evidence)
        if artifact_evidence is not None
        else None
    )

    executable_build = _build_executable_artifact(
        layout,
        native_build,
        fallback_build,
        executable_entrypoint,
        executable_name,
        executable_backend,
        nuitka_mode,
        plan,
        executable_analysis,
        executable_python,
        fallback_strategy,
        target_plan,
        closure_report=closure_report,
        build_timeout=build_timeout_seconds,
        toolchain=toolchain,
        executable_standalone=resolved_executable_standalone,
    )

    result = BuildResult(
        fallback=fallback,
        boundary_fallback_threshold=boundary_fallback_threshold,
        target_plan=target_plan,
        layout=layout,
        plan=plan,
        accepted_native_count=plan.native.accepted_count,
        rejected_native_count=plan.native.rejected_count,
        native_build=native_build,
        fallback_build=fallback_build,
        wheel_build=wheel_build,
        executable_build=executable_build,
        rust_crate_build=rust_crate_build,
        plugin_crate_dependencies=plugin_crate_dependencies,
        standalone_plugin_capabilities=_standalone_capability_reports_from_contexts(contexts),
        device_provider_plans=tuple(
            device_plan.to_dict() for device_plan in resolved_device_plans
        ),
        artifact_evidence=artifact_evidence,
        artifact_evidence_gate=artifact_evidence_gate,
        artifact_distribution_authorization=artifact_distribution_authorization,
    )
    _write_build_result(layout, result)
    if artifact_evidence_gate is not None and artifact_evidence_gate.status == "blocked":
        raise ArtifactEvidenceRequiredError(artifact_evidence_gate, result=result)
    return result


def _failed_closure_build_result(
    layout: ArtifactLayout,
    analysis: ProjectAnalysis,
    plan: BuildPlan,
    fallback: str,
    boundary_fallback_threshold: int,
    target_plan: TargetPlan,
    closure: NativeClosureReport,
    entrypoint: str,
    executable_name: str | None,
    rust_crate_name: str,
    *,
    standalone_contexts: dict[ArtifactKind, StandalonePluginContext] | None = None,
) -> BuildResult:
    """Return an inspectable failure before any source, Cargo, or sidecar work."""
    _cleanup_failed_prebuild_outputs(
        layout,
        target_plan,
        entrypoint,
        executable_name,
        rust_crate_name,
    )
    executable_build = _closure_failure(entrypoint, closure)
    cause = (
        "Unavailable executable entry graph"
        if closure.status is ClosureStatus.UNAVAILABLE
        else "Open fallback=error executable closure"
    )
    result = BuildResult(
        fallback=fallback,
        boundary_fallback_threshold=boundary_fallback_threshold,
        target_plan=target_plan,
        layout=layout,
        plan=plan,
        accepted_native_count=plan.native.accepted_count,
        rejected_native_count=plan.native.rejected_count,
        native_build=skipped_native_build(f"{cause} prevented native build work."),
        fallback_build=FallbackBuildResult(
            status="skipped",
            backend=fallback,
            message=f"{cause} prevented fallback packaging.",
        ),
        wheel_build=skipped_wheel(f"{cause} prevented wheel packaging."),
        executable_build=executable_build,
        rust_crate_build=skipped_rust_crate_build(f"{cause} prevented Rust crate work."),
        standalone_plugin_capabilities=_standalone_capability_reports_from_contexts(
            standalone_contexts or {}
        ),
    )
    _reset_report_files(layout.reports_dir)
    _write_check_report(layout, analysis)
    _write_build_result(layout, result)
    return result


def _write_build_result(layout: ArtifactLayout, result: BuildResult) -> None:
    """Serialize one aggregate build result deterministically."""
    status = _build_status(
        result.native_build,
        result.fallback_build,
        result.executable_build,
        result.rust_crate_build,
    )
    if (
        result.artifact_evidence_gate is not None
        and result.artifact_evidence_gate.status == "blocked"
    ):
        status = "artifact-evidence-required-failed"
    (layout.reports_dir / "build.json").write_text(
        json.dumps(
            {
                "status": status,
                **result.to_dict(),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def generate_source_artifact(
    project_root: Path,
    analysis: ProjectAnalysis,
    fallback: str,
    boundary_fallback_threshold: int = DEFAULT_BOUNDARY_FALLBACK_THRESHOLD,
    target_plan: TargetPlan | None = None,
    rust_importable: bool = False,
    rust_crate_name: str = "rextio_generated_rust",
    embedding_enabled: bool = False,
    full_c6_external_context: FullC6ExternalBuildContext | None = None,
    device_selection: DeviceProviderSelection | None = None,
    device_options: DeviceProviderOptions | None = None,
    device_entry_points: Iterable[object] | None = None,
) -> GenerateResult:
    """Generate native and Python source artifacts without compiling."""
    if full_c6_external_context is not None:
        validate_full_c6_external_context(full_c6_external_context, analysis)
    target_plan = target_plan or default_target_plan()
    layout = ArtifactLayout(project_root)
    resolved_device_options = device_options or DeviceProviderOptions()
    runtime_requirements, device_requirements = _accepted_device_profile_requirements(
        analysis,
        target_plan,
        resolved_device_options,
    )
    artifact_profiles = _generate_artifact_profiles(
        fallback,
        native_extension=analysis.requires_native_build(),
        rust_importable=rust_importable and analysis.requires_native_build(),
        runtime_requirements=runtime_requirements,
        device_requirements=device_requirements,
    )
    resolved_device_plans = _resolve_build_device_plans(
        artifact_profiles,
        selection=device_selection,
        options=resolved_device_options,
        entry_points=device_entry_points,
    )
    plan = create_build_plan(analysis, fallback, artifact_profiles=artifact_profiles)
    # Resolve once per exact profile for this generate command; reuse for
    # crate codegen, dependency selection, and JSON serialization.
    contexts = _ensure_standalone_contexts(plan, target_plan, seed=None)
    _prepare_generated_sources(layout, target_plan)
    _write_check_report(layout, analysis)
    _write_python_fallback_tree(plan.fallback, layout.python_dir, boundary_fallback_threshold)
    _write_runtime_support(layout.python_dir)
    native_source, plugin_crate_dependencies = _generate_native_source(
        plan,
        layout,
        target_plan,
        embedding_enabled=embedding_enabled,
        full_c6_external_context=full_c6_external_context,
        device_plan=(
            resolved_device_plans[0] if resolved_device_plans else None
        ),
    )
    rust_crate_source = _generate_rust_crate_source(
        plan,
        layout,
        target_plan,
        enabled=rust_importable,
        crate_name=rust_crate_name,
        standalone_context=contexts.get(ArtifactKind.RUST_CRATE),
    )

    result = GenerateResult(
        fallback=fallback,
        boundary_fallback_threshold=boundary_fallback_threshold,
        target_plan=target_plan,
        layout=layout,
        plan=plan,
        accepted_native_count=plan.native.accepted_count,
        rejected_native_count=plan.native.rejected_count,
        native_source=native_source,
        rust_crate_source=rust_crate_source,
        plugin_crate_dependencies=plugin_crate_dependencies,
        standalone_plugin_capabilities=_standalone_capability_reports_from_contexts(contexts),
        device_provider_plans=tuple(
            device_plan.to_dict() for device_plan in resolved_device_plans
        ),
        external_source_plan=(
            analysis.external_source_plan.to_dict()
            if analysis.external_source_plan is not None
            else None
        ),
    )
    (layout.reports_dir / "generate.json").write_text(
        json.dumps(
            {"status": _generate_status(native_source, rust_crate_source), **result.to_dict()},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return result


def _reset_report_files(reports_dir: Path) -> None:
    """Clear stale reports so a run leaves only its own reports.

    ``build`` writes build.json+check.json and ``generate`` writes
    generate.json+check.json; without clearing, `generate` then `build` leaves
    a stale generate.json beside a fresh build.json (council round 8).
    """
    reports_dir.mkdir(parents=True, exist_ok=True)
    for name in ("build.json", "generate.json", "check.json"):
        (reports_dir / name).unlink(missing_ok=True)


def _prepare_generated_sources(layout: ArtifactLayout, target_plan: TargetPlan) -> None:
    _reset_generated_dir(layout.target_dir(target_plan.spec.language))
    _reset_generated_dir(layout.rust_crate_dir)
    _reset_generated_dir(layout.python_dir)
    if target_plan.spec.language == "rust":
        layout.rust_src_dir.mkdir(parents=True, exist_ok=True)
    else:
        layout.target_dir(target_plan.spec.language).mkdir(parents=True, exist_ok=True)
    layout.python_dir.mkdir(parents=True, exist_ok=True)
    _reset_report_files(layout.reports_dir)


def _write_check_report(layout: ArtifactLayout, analysis: ProjectAnalysis) -> None:
    ensure_host_source_plan(analysis)
    (layout.reports_dir / "check.json").write_text(
        json.dumps(analysis.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _write_python_fallback_tree(
    plan: FallbackPlan,
    python_root: Path,
    boundary_fallback_threshold: int,
) -> None:
    for module_plan in plan.modules:
        if not module_plan.needs_wrapper:
            write_plain_cpython_module(module_plan.module, python_root)
            continue
        write_cpython_fallback(module_plan.module, python_root)
        if module_plan.accepted_native_top_level is not None:
            write_cpython_native_top_level_fallback(module_plan.module, python_root)
        wrapper_path = generated_path_for_module(module_plan.module, python_root)
        wrapper_path.parent.mkdir(parents=True, exist_ok=True)
        wrapper_path.write_text(
            render_wrapper_module(module_plan.module, boundary_fallback_threshold),
            encoding="utf-8",
        )


def _reset_generated_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)


def _write_build_artifact(layout: ArtifactLayout) -> None:
    if layout.build_python_dir.exists():
        shutil.rmtree(layout.build_python_dir)
    shutil.copytree(layout.python_dir, layout.build_python_dir)


def _write_runtime_support(python_root: Path) -> None:
    package_root = Path(__file__).resolve().parents[1]
    rextio_root = python_root / "rextio"
    rextio_root.mkdir(parents=True, exist_ok=True)
    shutil.copy2(package_root / "__init__.py", rextio_root / "__init__.py")
    # `__init__` imports the version from `__about__`, so it must travel with it.
    shutil.copy2(package_root / "__about__.py", rextio_root / "__about__.py")

    runtime_destination = rextio_root / "runtime"
    if runtime_destination.exists():
        shutil.rmtree(runtime_destination)
    shutil.copytree(
        package_root / "runtime",
        runtime_destination,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )


def _generate_and_build_native(
    plan: BuildPlan,
    layout: ArtifactLayout,
    build_tool: str,
    target_plan: TargetPlan,
    *,
    embedding_enabled: bool,
    build_timeout: float = DEFAULT_BUILD_TIMEOUT_SECONDS,
    toolchain: ToolchainConfig | None = None,
    evidence_snapshot: EvidenceInputSnapshot | None = None,
    project_root: Path | None = None,
    full_c6_external_context: FullC6ExternalBuildContext | None = None,
    device_plan: ResolvedDevicePlan | None = None,
) -> tuple[NativeBuildResult, tuple[dict[str, object], ...], EvidenceInputSnapshot | None]:
    if not plan.native.has_native_artifacts:
        return (
            skipped_native_build("No accepted native functions were found."),
            (),
            evidence_snapshot,
        )
    native_source, plugin_crate_dependencies = _generate_native_source(
        plan,
        layout,
        target_plan,
        embedding_enabled=embedding_enabled,
        full_c6_external_context=full_c6_external_context,
        device_plan=device_plan,
    )
    if native_source.status == "failed":
        return (
            NativeBuildResult(
                status="failed",
                tool="codegen",
                message=(
                    "RXT050 Codegen failure while generating native target code. "
                    f"Cause: {native_source.message}. Fallback Python files were still generated."
                ),
            ),
            (),
            evidence_snapshot,
        )

    # Capture generated Rust inputs after write and before cargo compilation so
    # later evidence can prove the exact build inputs (or mark unavailable).
    if (
        evidence_snapshot is not None
        and project_root is not None
        and native_source.status == "generated"
    ):
        evidence_snapshot = capture_generated_rust_inputs(
            evidence_snapshot, project_root=project_root, layout=layout
        )

    if target_plan.spec.language == "rust":
        return (
            _build_native_with_selected_tool(layout, build_tool, build_timeout, toolchain),
            plugin_crate_dependencies,
            evidence_snapshot,
        )
    return (
        NativeBuildResult(
            status="failed",
            tool=target_plan.spec.language,
            message=(
                "RXT060 Build failed while compiling generated native module. "
                f"Cause: target language {target_plan.spec.language!r} is not implemented."
            ),
        ),
        (),
        evidence_snapshot,
    )


def _generate_and_build_rust_crate(
    plan: BuildPlan,
    layout: ArtifactLayout,
    target_plan: TargetPlan,
    *,
    enabled: bool,
    crate_name: str,
    build_timeout: float = DEFAULT_BUILD_TIMEOUT_SECONDS,
    toolchain: ToolchainConfig | None = None,
    standalone_context: StandalonePluginContext | None = None,
) -> RustCrateBuildResult:
    if not enabled:
        return skipped_rust_crate_build("Rust-importable crate was not requested.")
    source = _generate_rust_crate_source(
        plan,
        layout,
        target_plan,
        enabled=True,
        crate_name=crate_name,
        standalone_context=standalone_context,
    )
    if source.status != "generated":
        if source.status == "skipped":
            return skipped_rust_crate_build(source.message)
        return RustCrateBuildResult(
            status="failed",
            message=(
                "RXT050 Codegen failure while generating Rust-importable crate. "
                f"Cause: {source.message}."
            ),
        )
    return build_importable_rust_crate(
        layout.rust_crate_dir,
        layout.dist_dir,
        crate_name,
        timeout=build_timeout,
        toolchain=toolchain,
    )


def _used_plugin_ids(analysis: ProjectAnalysis) -> set[str]:
    """Plugin ids whose lowering an accepted native function actually uses.

    From the claims (each carries its plugin id) and plugin-typed signatures
    (the type key is namespaced ``<plugin_id>/<slug>``) of accepted functions.
    """
    used: set[str] = set()
    for function in analysis.accepted_native_functions:
        used.update(claim.plugin_id for claim in function.plugin_claims)
        used.update(key.split("/", 1)[0] for key in function.plugin_type_keys)
    return used


def _generate_native_source(
    plan: BuildPlan,
    layout: ArtifactLayout,
    target_plan: TargetPlan,
    *,
    embedding_enabled: bool = False,
    full_c6_external_context: FullC6ExternalBuildContext | None = None,
    device_plan: ResolvedDevicePlan | None = None,
) -> tuple[NativeSourceResult, tuple[dict[str, object], ...]]:
    """Generate the PyO3 extension source; return (result, plugin crate deps).

    The second element lists the plugin-injected crate dependencies actually
    written into the generated Cargo.toml (empty unless the lowered module
    contains a plugin-lowered function), for the build report.
    """
    if not plan.native.has_native_artifacts:
        return NativeSourceResult(
            status="skipped",
            message="No accepted native functions were found.",
        ), ()
    if target_plan.spec.language != "rust":
        return NativeSourceResult(
            status="failed",
            message=(
                f"target language {target_plan.spec.language!r} is configurable, but no "
                "codegen backend is implemented for it yet"
            ),
        ), ()
    plugin_types, plugin_providers, plugin_types_by_key = _plugin_lowering_inputs(target_plan)
    try:
        module_ir = lower_project(
            plan.analysis,
            include_embedding=embedding_enabled,
            plugin_types=plugin_types,
            external_native_registry=(
                full_c6_external_context.registry
                if full_c6_external_context is not None
                else None
            ),
        )
        rust_source = generate_rust_module(
            module_ir,
            boundary_call_return_types=_boundary_call_return_types(plan.analysis),
            plugin_providers=plugin_providers,
            plugin_types_by_key=plugin_types_by_key,
            external_runtime_guard=(
                full_c6_external_context.runtime_guard
                if full_c6_external_context is not None
                else None
            ),
            device_authorization=(
                device_plan.lowering_authorization()
                if device_plan is not None
                else None
            ),
        )
    except (LoweringError, RustCodegenError) as exc:
        return NativeSourceResult(
            status="failed",
            message=str(exc),
        ), ()

    registry = target_plan.plugins
    extra_dependencies: tuple[tuple[str, str, tuple[str, ...]], ...] = ()
    plugin_crate_dependencies: tuple[dict[str, object], ...] = ()
    used_plugin_ids = _used_plugin_ids(plan.analysis)
    if registry.crate_dependencies and used_plugin_ids:
        # Only the plugins whose lowering an ACCEPTED function actually uses
        # contribute crates; an enabled-but-unused plugin's dependency must not
        # be injected (it could break an otherwise valid build and misrepresent
        # the compiled artifact -- council round 8).
        used_bindings = tuple(
            binding
            for binding in registry.crate_dependencies
            if binding.plugin_id in used_plugin_ids
        )
        extra_dependencies = tuple(
            (binding.dependency.name, binding.dependency.version, binding.dependency.features)
            for binding in used_bindings
        )
        plugin_crate_dependencies = tuple(
            {
                "plugin_id": binding.plugin_id,
                "name": binding.dependency.name,
                "version": binding.dependency.version,
                "features": list(binding.dependency.features),
            }
            for binding in used_bindings
        )
    _write_rust_project(
        layout,
        rust_source,
        extra_dependencies=extra_dependencies,
        device_plan=device_plan,
    )
    return NativeSourceResult(
        status="generated",
        message="Generated Rust source for accepted native functions.",
        path=str(layout.rust_src_dir / "lib.rs"),
    ), plugin_crate_dependencies


def _analysis_functions(analysis: ProjectAnalysis) -> list[object]:
    return [function for module in analysis.modules for function in module.functions]


def _standalone_context_for_kind(
    plan: BuildPlan,
    target_plan: TargetPlan,
    kind: ArtifactKind,
    *,
    functions: list[object] | None = None,
) -> StandalonePluginContext | None:
    """Resolve plugin API 1.4 capability for one planned artifact profile kind."""
    profile = next((item for item in plan.artifact_profiles if item.kind is kind), None)
    if profile is None:
        return None
    return build_standalone_plugin_context(
        profile=profile,
        registry=target_plan.plugins,
        functions=functions if functions is not None else _analysis_functions(plan.analysis),
    )


def _ensure_standalone_contexts(
    plan: BuildPlan,
    target_plan: TargetPlan,
    *,
    seed: dict[ArtifactKind, StandalonePluginContext] | None,
    executable_analysis: ProjectAnalysis | None = None,
    executable_standalone: StandalonePluginContext | None = None,
    include_executable: bool = False,
) -> dict[ArtifactKind, StandalonePluginContext]:
    """Resolve each planned standalone profile at most once; reuse seed entries."""
    contexts: dict[ArtifactKind, StandalonePluginContext] = dict(seed or {})
    profiles_by_kind = {profile.kind: profile for profile in plan.artifact_profiles}

    def validate_context(kind: ArtifactKind, context: StandalonePluginContext) -> None:
        expected = profiles_by_kind.get(kind)
        if expected is None:
            raise PluginError(
                f"pre-resolved standalone context for {kind.value!r} has no "
                "matching planned artifact profile"
            )
        if context.profile != expected:
            raise PluginError(
                f"pre-resolved standalone context profile mismatch for {kind.value!r}: "
                f"expected {expected.to_dict()!r}, got {context.profile.to_dict()!r}"
            )

    for kind, context in contexts.items():
        validate_context(kind, context)
    if ArtifactKind.RUST_CRATE not in contexts:
        crate_ctx = _standalone_context_for_kind(plan, target_plan, ArtifactKind.RUST_CRATE)
        if crate_ctx is not None:
            contexts[ArtifactKind.RUST_CRATE] = crate_ctx
    if include_executable and ArtifactKind.HOST_EXECUTABLE not in contexts:
        if executable_standalone is not None:
            validate_context(ArtifactKind.HOST_EXECUTABLE, executable_standalone)
            contexts[ArtifactKind.HOST_EXECUTABLE] = executable_standalone
        else:
            analysis = executable_analysis or plan.analysis
            exec_ctx = _standalone_context_for_kind(
                plan,
                target_plan,
                ArtifactKind.HOST_EXECUTABLE,
                functions=_analysis_functions(analysis),
            )
            if exec_ctx is not None:
                contexts[ArtifactKind.HOST_EXECUTABLE] = exec_ctx
    return contexts


def _standalone_capability_reports_from_contexts(
    contexts: Mapping[ArtifactKind, StandalonePluginContext],
) -> tuple[dict[str, object], ...]:
    """Serialize pre-resolved contexts without re-invoking capability hooks."""
    reports: list[dict[str, object]] = []
    for kind in (ArtifactKind.RUST_CRATE, ArtifactKind.HOST_EXECUTABLE):
        context = contexts.get(kind)
        if context is not None:
            reports.append(context.to_dict())
    return tuple(reports)


def _plugin_ids_for_emitted_functions(
    *,
    analysis: ProjectAnalysis,
    emitted_qualnames: frozenset[str],
    standalone: StandalonePluginContext,
) -> set[str]:
    """Collect plugin ids only from functions actually emitted after exclusion."""
    used: set[str] = set()
    for function in analysis.accepted_native_functions:
        if function.qualname not in emitted_qualnames:
            continue
        if not standalone.is_capable(function.qualname):
            continue
        for claim in function.plugin_claims:
            used.add(claim.plugin_id)
        for key in analysis_function_plugin_type_keys(function):
            used.add(key.split("/", 1)[0])
    return used


def _generate_rust_crate_source(
    plan: BuildPlan,
    layout: ArtifactLayout,
    target_plan: TargetPlan,
    *,
    enabled: bool,
    crate_name: str,
    standalone_context: StandalonePluginContext | None = None,
) -> NativeSourceResult:
    if not enabled:
        return NativeSourceResult(
            status="skipped",
            message="Rust-importable crate was not requested.",
        )
    if not plan.native.has_native_artifacts:
        return NativeSourceResult(
            status="skipped",
            message="No accepted native functions were found.",
        )
    if target_plan.spec.language != "rust":
        return NativeSourceResult(
            status="failed",
            message=(
                f"target language {target_plan.spec.language!r} is configurable, but a "
                "Rust-importable crate can only be generated for target language 'rust'"
            ),
        )
    try:
        # Include embedded helpers: an exported native function may call one, and
        # the crate must carry the callee it references. Plugin types + providers
        # are passed so plugin API 1.4 standalone-capable functions can lower
        # with native Rust types only. Legacy (no capability) plugin functions
        # remain excluded transitively.
        plugin_types, plugin_providers, plugin_types_by_key = _plugin_lowering_inputs(target_plan)
        standalone = standalone_context
        if standalone is None:
            standalone = _standalone_context_for_kind(plan, target_plan, ArtifactKind.RUST_CRATE)
        module_ir = lower_project(plan.analysis, include_embedding=True, plugin_types=plugin_types)
        rust_source = generate_rust_crate_module(
            module_ir,
            plugin_providers=plugin_providers,
            plugin_types_by_key=plugin_types_by_key,
            standalone=standalone,
        )
        extra_dependencies: tuple[tuple[str, str, tuple[str, ...]], ...] = ()
        if standalone is not None:
            emitted = crate_emitted_qualnames(module_ir, standalone=standalone)
            used_plugin_ids = _plugin_ids_for_emitted_functions(
                analysis=plan.analysis,
                emitted_qualnames=emitted,
                standalone=standalone,
            )
            extra_dependencies = profile_crate_dependencies(
                standalone.capabilities, used_plugin_ids
            )
    except (LoweringError, RustCodegenError, PluginError) as exc:
        return NativeSourceResult(
            status="failed",
            message=str(exc),
        )

    _write_rust_crate_project(
        layout, rust_source, crate_name, extra_dependencies=extra_dependencies
    )
    return NativeSourceResult(
        status="generated",
        message="Generated Rust-importable crate source for direct native functions.",
        path=str(layout.rust_crate_src_dir / "lib.rs"),
    )


def _build_fallback_backend(
    fallback: str,
    layout: ArtifactLayout,
    *,
    build_timeout: float = DEFAULT_BUILD_TIMEOUT_SECONDS,
    toolchain: ToolchainConfig | None = None,
) -> FallbackBuildResult:
    if fallback == "cpython":
        return cpython_fallback_build_result()
    if fallback == "nuitka":
        # The CLI pre-gates the Nuitka version floor for the FALLBACK path,
        # so this builder's own probe is only reachable here for programmatic
        # callers. The hybrid dispatcher (_build_nuitka_dispatcher) is NOT
        # pre-gated and keeps its own point-of-use probe.
        return build_nuitka_fallback(
            layout.build_python_dir, timeout=build_timeout, toolchain=toolchain
        )
    return FallbackBuildResult(
        status="failed",
        backend=fallback,
        message=(
            "RXT060 Build failed while preparing fallback backend. "
            f"Cause: unsupported fallback backend: {fallback}."
        ),
    )


def _build_wheel_artifact(
    project_root: Path,
    layout: ArtifactLayout,
    native_build: NativeBuildResult,
    fallback_build: FallbackBuildResult,
    *,
    output_dir: Path | None = None,
    external_contract: ExternalWheelContract | None = None,
) -> WheelBuildResult:
    if fallback_build.status != "built":
        return skipped_wheel("Fallback packaging failed, so no wheel was generated.")
    # A native build failure is not fatal to packaging: the importable hybrid
    # tree still works through the Python fallback, so produce a fallback-only
    # (pure-Python, py3-none-any) wheel instead of skipping. The wheel tag
    # reflects the absence of the native extension automatically.
    return build_artifact_wheel(
        project_root,
        layout.build_python_dir,
        output_dir if output_dir is not None else layout.dist_dir,
        external_contract=external_contract,
    )


def _build_executable_artifact(
    layout: ArtifactLayout,
    native_build: NativeBuildResult,
    fallback_build: FallbackBuildResult,
    entrypoint: str | None,
    executable_name: str | None,
    executable_backend: str,
    nuitka_mode: str,
    plan: BuildPlan,
    executable_analysis: ProjectAnalysis,
    executable_python: str | None,
    executable_fallback: FallbackStrategy,
    target_plan: TargetPlan,
    *,
    closure_report: NativeClosureReport | None = None,
    build_timeout: float = DEFAULT_BUILD_TIMEOUT_SECONDS,
    toolchain: ToolchainConfig | None = None,
    executable_standalone: StandalonePluginContext | None = None,
) -> ExecutableBuildResult:
    if entrypoint is None:
        return skipped_executable("No executable entrypoint was requested.")
    if executable_backend == "rust":
        # The native Rust binary does not depend on the fallback packaging or the
        # PyO3 extension build. It uses the delegate-mode analysis so the entry can
        # call project fallback functions through the external CPython dispatcher.
        return _build_rust_executable_artifact(
            layout,
            executable_analysis,
            entrypoint,
            executable_name,
            executable_python,
            executable_fallback,
            target_plan,
            closure_report=closure_report,
            build_timeout=build_timeout,
            toolchain=toolchain,
            executable_standalone=executable_standalone,
        )
    if fallback_build.status != "built":
        return skipped_executable("Fallback packaging failed, so no executable was generated.")
    if native_build.status == "failed":
        return skipped_executable("Native build failed, so no executable was generated.")
    if executable_backend == "zipapp":
        return build_zipapp_executable(
            layout.build_python_dir,
            layout.dist_dir,
            entrypoint,
            executable_name,
        )
    if executable_backend == "nuitka":
        return build_nuitka_executable(
            layout.build_python_dir,
            layout.dist_dir,
            entrypoint,
            executable_name,
            nuitka_mode,
            timeout=build_timeout,
            toolchain=toolchain,
        )
    return ExecutableBuildResult(
        status="failed",
        path=None,
        message=(
            "RXT060 Executable build failed because the executable backend was unsupported. "
            'Use "zipapp", "nuitka", or "rust".'
        ),
        entrypoint=entrypoint,
        backend=executable_backend,
    )


def _entrypoint_to_qualname(entrypoint: str) -> str:
    """Map an executable entrypoint ``module:function`` to a Rextio qualname."""
    return entrypoint.replace(":", ".", 1)


def _rust_binary_name(executable_name: str | None, entry_qualname: str) -> str:
    """Return a valid Cargo binary name for the executable."""
    raw = executable_name or entry_qualname.replace(".", "_")
    sanitized = re.sub(r"[^0-9A-Za-z_-]", "_", raw)
    return sanitized or "rextio_app"


def _delegated_return_types(analysis: ProjectAnalysis) -> dict[str, str]:
    """Map every delegated callee's qualname to its return type across the project."""
    return _scalar_callee_return_types(analysis, "delegated_call_targets")


def _boundary_call_return_types(analysis: ProjectAnalysis) -> dict[str, str]:
    """Map every boundary-called callee's qualname to its return type."""
    return _scalar_callee_return_types(analysis, "boundary_call_targets")


def _scalar_callee_return_types(analysis: ProjectAnalysis, targets_attr: str) -> dict[str, str]:
    by_qualname = {
        function.qualname: function for module in analysis.modules for function in module.functions
    }
    delegated: dict[str, str] = {}
    for module in analysis.modules:
        for function in module.functions:
            for target in getattr(function, targets_attr):
                callee = by_qualname.get(target)
                if callee is None:
                    continue
                return_type = (
                    callee.signature_return_type
                    or callee.inferred_return_type
                    or callee.annotated_return_type
                )
                # Normalize any `typing.`-qualified/capitalized alias to the builtin
                # form the codegen understands. Delegated returns are immutable scalars
                # only (the boundary check rejects containers), so this is defensive:
                # it keeps the recorded type in the exact spelling that passed the gate.
                # Keep it — if a future gate ever recorded an un-normalized alias, this
                # is what stops it reaching `type_from_string` in codegen as a raw alias.
                normalized = normalize_type_name(return_type)
                if normalized is not None:
                    delegated[target] = normalized
    return delegated


def _entrypoint_reachable_native_graph(
    analysis: ProjectAnalysis,
    entry_qualname: str,
) -> tuple[set[str], dict[str, str]]:
    """Compatibility tuple derived from the reusable executable closure report."""
    closure = executable_entry_graph(analysis, entry_qualname)
    return set(closure.reachable_native_functions), closure.delegated_return_types


def _filter_module_ir(
    module_ir: ModuleIR,
    reachable_qualnames: set[str],
    initializer_qualnames: set[str] | None = None,
) -> ModuleIR:
    """Keep entry-reachable functions and explicitly planned initializers."""
    if not reachable_qualnames:
        # An empty set means the entry itself was not an accepted direct-native
        # function. Pass the full IR through so `_resolve_main_entry` can name the
        # REAL problem (missing entry / RXT080 shim / embedding) - filtering everything
        # out here would degrade those diagnostics to a generic "missing entry".
        return module_ir
    retained = reachable_qualnames | (initializer_qualnames or set())
    return ModuleIR([function for function in module_ir.functions if function.qualname in retained])


def _executable_initializer_plans(
    analysis: ProjectAnalysis,
    closure: NativeClosureReport,
) -> dict[str, ModuleInitIR]:
    """Resolve closure-authorized initializer names back to their exact plans."""
    if not closure.module_initializers:
        return {}
    source_plan = ensure_host_source_plan(analysis)
    plans_by_module = {plan.module_name: plan for plan in source_plan.module_initializers}
    resolved: dict[str, ModuleInitIR] = {}
    for qualname in closure.module_initializers:
        module_name, separator, _name = qualname.rpartition(".")
        plan = plans_by_module.get(module_name)
        if not separator or plan is None:
            raise LoweringError(
                f"closure-authorized module initializer has no source plan: {qualname}"
            )
        resolved[qualname] = plan
    return resolved


def _write_hybrid_runtime(
    runtime_dir: Path, analysis: ProjectAnalysis, allowed_qualnames: set[str]
) -> None:
    """Write ``<binary>.runtime``: the dispatcher plus the project's Python source.

    The dispatcher imports the project modules by qualname to execute a delegated
    fallback function, so the original source tree is reconstructed here (with
    ``__init__.py`` for packages). Requires a Python interpreter (and the project's
    dependencies) at runtime.
    """
    if runtime_dir.exists():
        shutil.rmtree(runtime_dir)
    runtime_dir.mkdir(parents=True, exist_ok=True)
    dispatcher_path = runtime_dir / f"{DISPATCHER_STEM}.py"
    (dispatcher_path).write_text(
        render_dispatcher_script(sorted(allowed_qualnames)), encoding="utf-8"
    )
    for module in analysis.modules:
        parts = (
            module.module_name.split(".") if module.module_name else [Path(module.file_path).stem]
        )
        source_path = Path(module.file_path)
        if source_path.name == "__init__.py":
            target = runtime_dir.joinpath(*parts, "__init__.py")
        else:
            target = runtime_dir.joinpath(*parts).with_suffix(".py")
        if target == dispatcher_path or parts[0] == DISPATCHER_STEM:
            # Reject both the file form (`_rextio_dispatcher.py`, which would
            # overwrite the generated script) and the package form
            # (`_rextio_dispatcher/__init__.py`, which Python's import machinery
            # would prefer over the sibling script of the same name).
            raise RustCodegenError(
                f"hybrid runtime source collision: project module {module.module_name!r} "
                f"conflicts with the generated dispatcher {DISPATCHER_STEM!r}"
            )
        if parts[0] in _DISPATCHER_RESERVED_TOP_LEVEL_NAMES:
            # runtime_dir is sys.path[0] at dispatch time, so a project module
            # whose top-level name shadows a module the dispatcher imports
            # (json/os/sys/importlib/types) - or the rextio package itself -
            # would be found before the real one and crash the long-lived
            # dispatcher on its first request (council round 8).
            raise RustCodegenError(
                f"hybrid runtime source collision: project module {module.module_name!r} "
                f"shadows a name the fallback dispatcher relies on "
                f"({parts[0]!r}); rename the module or build a wheel/PyO3 artifact"
            )
        target.parent.mkdir(parents=True, exist_ok=True)
        # Make every intermediate directory an importable package.
        package_dir = runtime_dir
        for part in parts[:-1]:
            package_dir = package_dir / part
            init = package_dir / "__init__.py"
            if not init.exists():
                init.write_text("", encoding="utf-8")
        shutil.copy2(source_path, target)


def _externally_accelerated_runtime_modules(analysis: ProjectAnalysis) -> list[str]:
    """Return project modules using an external accelerator (e.g. numba).

    The hybrid runtime copies EVERY project module next to the dispatcher, and a
    Nuitka onefile dispatcher follows imports from the delegated modules into
    their siblings — so a delegated-qualname check alone would miss a plain
    delegated function that transitively imports an accelerated module. Scan the
    whole tree instead: over-rejecting an unreachable accelerated module is the
    safe direction, and ``--hybrid-runtime=source`` is the escape hatch.
    """
    accelerated: list[str] = []
    project_modules = frozenset(
        (module.module_name or Path(module.file_path).stem).split(".", 1)[0]
        for module in analysis.modules
    )
    for module in analysis.modules:
        try:
            source = Path(module.file_path).read_text(encoding="utf-8")
        except OSError:
            continue
        if external_accelerator_for_source(source, project_modules) is not None:
            accelerated.append(module.module_name or Path(module.file_path).stem)
    return sorted(accelerated)


def _delegation_python(executable_python: str | None, toolchain: ToolchainConfig | None) -> str:
    """Return the interpreter command baked into the hybrid binary for delegated calls.

    Explicit [executable] python wins; otherwise the [toolchain] python keeps
    the runtime on the same interpreter the build targeted; otherwise the
    portable default. REXTIO_RUNTIME_PYTHON still overrides at run time.
    """
    if executable_python is not None:
        return executable_python
    configured, _error = resolve_python(toolchain or ToolchainConfig())
    return configured or "python3"


def _build_nuitka_dispatcher(
    runtime_dir: Path,
    allowed_qualnames: set[str],
    timeout: float,
    toolchain: ToolchainConfig | None = None,
) -> str | None:
    """Compile the dispatcher into a self-contained executable; return an error or None.

    Produces `<runtime>/{stem}` (Nuitka onefile, where ``stem`` is
    ``DISPATCHER_STEM``) with the delegated fallback modules bundled, so the hybrid
    binary needs no separate Python install.
    """
    nuitka_command, resolve_error = resolve_nuitka_command(toolchain or ToolchainConfig())
    if nuitka_command is None:
        return resolve_error or (
            "Nuitka is not installed but --hybrid-runtime=nuitka was requested. "
            "Install Nuitka or use --hybrid-runtime=source."
        )
    version_error = nuitka_toolchain_error(nuitka_command, toolchain)
    if version_error is not None:
        return version_error
    modules = sorted({q.rpartition(".")[0] for q in allowed_qualnames if "." in q})
    command = [
        *nuitka_command,
        "--onefile",
        "--assume-yes-for-downloads",
        f"{DISPATCHER_STEM}.py",
        f"--output-dir={runtime_dir}",
        f"--output-filename={DISPATCHER_STEM}",
        "--remove-output",
        *(f"--include-module={module}" for module in modules),
    ]
    completed = run_build_tool(command, cwd=runtime_dir, timeout=timeout)
    if completed.returncode != 0:
        return f"Nuitka failed to compile the dispatcher (exit status {completed.returncode})."
    # Nuitka appends the OS executable extension (`.exe` on Windows), so accept both.
    if not any((runtime_dir / f"{DISPATCHER_STEM}{suffix}").exists() for suffix in ("", ".exe")):
        return "Nuitka completed but the compiled dispatcher was not found."
    return None


def _build_rust_executable_artifact(
    layout: ArtifactLayout,
    analysis: ProjectAnalysis,
    entrypoint: str,
    executable_name: str | None,
    executable_python: str | None,
    executable_fallback: FallbackStrategy | str | None,
    target_plan: TargetPlan | None = None,
    *,
    closure_report: NativeClosureReport | None = None,
    build_timeout: float,
    toolchain: ToolchainConfig | None = None,
    executable_standalone: StandalonePluginContext | None = None,
) -> ExecutableBuildResult:
    """Generate and build the native Rust executable for the entrypoint.

    The entrypoint must be an accepted direct-native ``def main(argv: list[str])
    -> int``. Any call it (or its native call graph) makes to a project fallback
    function is delegated to an external CPython dispatcher shipped next to the
    binary as ``<binary>.runtime``; a binary with no delegated calls needs no
    Python runtime at all.
    """
    strategy = strategy_from_compatibility_value(executable_fallback)
    configured_python, python_error = resolve_python(toolchain or ToolchainConfig())
    if (toolchain and toolchain.python is not None) and configured_python is None:
        # Preserve the pre-closure toolchain gate for programmatic callers.  In
        # particular, callers may intentionally omit analysis while checking a
        # configured interpreter, and no source or entry graph is authoritative
        # until that prerequisite resolves.
        return ExecutableBuildResult(
            status="failed",
            path=None,
            message=f"RXT060 Executable build failed. {python_error}",
            entrypoint=entrypoint,
            backend="rust",
        )
    entry_qualname = _entrypoint_to_qualname(entrypoint)
    resolved_target_plan = target_plan or default_target_plan()
    # Reuse the pre-resolved capability context when provided (CLI preflight /
    # orchestrator) so the capability hook runs at most once per profile.
    standalone = executable_standalone
    if standalone is None:
        profile = (
            closure_report.profile
            if closure_report is not None
            else host_executable_profile(_required_host_target_triple(), fallback=strategy)
        )
        standalone = build_standalone_plugin_context(
            profile=profile,
            registry=resolved_target_plan.plugins,
            functions=_analysis_functions(analysis),
        )
    if closure_report is not None and closure_report.profile != standalone.profile:
        raise PluginError(
            "pre-resolved executable closure profile does not match the standalone "
            "plugin capability profile"
        )
    closure = closure_report or executable_entry_graph(
        analysis,
        entry_qualname,
        strategy,
        profile=standalone.profile,
        plugin_capabilities=standalone.capabilities,
    )
    if closure_requires_prebuild_failure(closure):
        _cleanup_failed_executable_outputs(layout, entrypoint, executable_name)
        return _closure_failure(entrypoint, closure)
    reachable_qualnames = set(closure.reachable_native_functions)
    delegated_return_types = closure.delegated_return_types
    nuitka_dispatcher = strategy is FallbackStrategy.NUITKA_SIDECAR
    if nuitka_dispatcher and delegated_return_types:
        accelerated = _externally_accelerated_runtime_modules(analysis)
        if accelerated:
            names = ", ".join(accelerated)
            return _with_closure(
                ExecutableBuildResult(
                    status="failed",
                    path=None,
                    message=(
                        "RXT060 Executable build failed: project module(s) "
                        f"{names} use an external accelerator (e.g. Numba), which a "
                        "Nuitka-compiled dispatcher cannot serve (compiled functions "
                        "expose no bytecode for the accelerator and the accelerator "
                        "package is not bundled). Every project module ships in the "
                        "hybrid runtime and Nuitka follows imports into it, so this "
                        "applies even when no accelerated function is delegated "
                        "directly. Use --executable-fallback=python-subprocess "
                        "(legacy: --hybrid-runtime=source), whose dispatcher runs "
                        "real CPython with the project's environment."
                    ),
                    entrypoint=entrypoint,
                    backend="rust",
                ),
                closure,
            )
    try:
        # Plugin types + providers enable plugin API 1.4 standalone-capable
        # functions in the binary (native Rust types only). Legacy plugin
        # functions without matching capability remain excluded / blocked by
        # the pre-Cargo closure.
        plugin_types, plugin_providers, plugin_types_by_key = _plugin_lowering_inputs(
            resolved_target_plan
        )
        initializer_plans = _executable_initializer_plans(analysis, closure)
        module_ir = _filter_module_ir(
            lower_project(
                analysis,
                include_embedding=True,
                plugin_types=plugin_types,
                executable_module_initializers=initializer_plans,
            ),
            reachable_qualnames,
            set(closure.module_initializers),
        )
        main_rs = generate_rust_main_binary(
            module_ir,
            entry_qualname,
            delegated_return_types,
            _delegation_python(executable_python, toolchain),
            nuitka_dispatcher=nuitka_dispatcher,
            initializer_qualnames=closure.module_initializers,
            plugin_providers=plugin_providers,
            plugin_types_by_key=plugin_types_by_key,
            standalone=standalone,
        )
        # Only functions that survive transitive exclusion and remain reachable
        # may inject profile-specific crate dependencies.
        emitted = crate_emitted_qualnames(module_ir, standalone=standalone) & frozenset(
            reachable_qualnames
        )
        used_plugin_ids = _plugin_ids_for_emitted_functions(
            analysis=analysis,
            emitted_qualnames=emitted,
            standalone=standalone,
        )
        extra_dependencies = profile_crate_dependencies(standalone.capabilities, used_plugin_ids)
    except (RustCodegenError, LoweringError, PluginError) as exc:
        return _with_closure(
            ExecutableBuildResult(
                status="failed",
                path=None,
                message=f"RXT060 Executable build failed while generating the Rust binary. Cause: {exc}",
                entrypoint=entrypoint,
                backend="rust",
            ),
            closure,
        )

    binary_name = _rust_binary_name(executable_name, entry_qualname)
    hybrid = bool(delegated_return_types)
    crate_dir = layout.rust_bin_dir
    if crate_dir.exists():
        shutil.rmtree(crate_dir)
    layout.rust_bin_src_dir.mkdir(parents=True, exist_ok=True)
    (crate_dir / "Cargo.toml").write_text(
        render_binary_cargo_toml(
            "rextio_generated_bin",
            binary_name,
            hybrid=hybrid,
            extra_dependencies=extra_dependencies,
        ),
        encoding="utf-8",
    )
    (layout.rust_bin_src_dir / "main.rs").write_text(main_rs, encoding="utf-8")

    result = build_rust_executable(
        crate_dir,
        layout.dist_dir,
        binary_name,
        entrypoint,
        timeout=build_timeout,
        toolchain=toolchain,
    )
    if result.status == "built" and hybrid:
        # Ship the dispatcher + project source as `<binary>.runtime` next to the
        # binary so the client can launch CPython for delegated calls.
        runtime_dir = layout.dist_dir / f"{binary_name}{RUNTIME_DIR_SUFFIX}"
        try:
            _write_hybrid_runtime(runtime_dir, analysis, set(delegated_return_types))
        except RustCodegenError as exc:
            _cleanup_rust_executable_outputs(result.path, runtime_dir)
            return _with_closure(
                ExecutableBuildResult(
                    status="failed",
                    path=None,
                    message=f"RXT060 Executable build failed while packaging the dispatcher. Cause: {exc}",
                    entrypoint=entrypoint,
                    backend="rust",
                ),
                closure,
            )
        if nuitka_dispatcher:
            error = _build_nuitka_dispatcher(
                runtime_dir, set(delegated_return_types), build_timeout, toolchain
            )
            if error is not None:
                _cleanup_rust_executable_outputs(result.path, runtime_dir)
                return _with_closure(
                    ExecutableBuildResult(
                        status="failed",
                        path=None,
                        message=f"RXT060 Executable build failed while packaging the dispatcher. Cause: {error}",
                        entrypoint=entrypoint,
                        backend="rust",
                    ),
                    closure,
                )
    return _with_closure(result, closure)


def _closure_failure(entrypoint: str, closure: NativeClosureReport) -> PlannedExecutableBuildResult:
    if closure.status is ClosureStatus.UNAVAILABLE:
        blocker_details = "; ".join(
            f"{blocker.source} -> {blocker.callee}: {blocker.reason}"
            if blocker.callee is not None
            else f"{blocker.source}: {blocker.reason}"
            for blocker in closure.blockers
        )
        reason = closure.entrypoint_reason or blocker_details or "entry graph is unavailable"
        details = f" Blockers: {blocker_details}." if blocker_details else ""
        if closure.entrypoint_reason is not None:
            guidance = (
                "Fallback sidecars cannot replace a non-native entrypoint. "
                "Suggestion: use a module:function entrypoint accepted as "
                "native-direct and run rextio check for promotion diagnostics."
            )
        else:
            guidance = (
                "Fallback sidecars cannot reproduce missing initialization inside "
                "the native process. Suggestion: simplify the module to the documented "
                "executable initializer slice, disable native_top_level, or keep a "
                "Python-hosted executable backend."
            )
        return PlannedExecutableBuildResult(
            status="failed",
            path=None,
            message=(
                "RXT060 Executable build failed because the Rust entry graph is "
                f"unavailable for {entrypoint!r}: {reason}.{details} "
                f"{guidance}"
            ),
            entrypoint=entrypoint,
            backend="rust",
            closure=closure,
        )

    edges = "; ".join(
        f"{edge.source} -> {edge.callee}: {edge.reason}" for edge in closure.fallback_edges
    )
    return PlannedExecutableBuildResult(
        status="failed",
        path=None,
        message=(
            "RXT060 Executable build failed because fallback='error' requires a "
            f"closed native entry graph. Reachable fallback edges: {edges}. "
            "Suggestion: make every listed callee direct-native, or select "
            "--executable-fallback=python-subprocess or nuitka-sidecar."
        ),
        entrypoint=entrypoint,
        backend="rust",
        closure=closure,
    )


def _cleanup_failed_prebuild_outputs(
    layout: ArtifactLayout,
    target_plan: TargetPlan,
    entrypoint: str,
    executable_name: str | None,
    rust_crate_name: str,
) -> None:
    """Invalidate only artifacts a successful run with this config would own."""
    for path in (
        layout.build_dir,
        layout.target_dir(target_plan.spec.language),
        layout.rust_crate_dir,
        layout.rust_bin_dir,
        layout.python_dir,
    ):
        _remove_path(path)
    _cleanup_failed_executable_outputs(layout, entrypoint, executable_name)
    _remove_path(layout.dist_dir / f"{rust_crate_name}-rust-crate")
    distribution = re.sub(r"[^A-Za-z0-9.]+", "_", layout.root.name).strip("._").lower()
    distribution = distribution or "rextio_hybrid_artifact"
    if layout.dist_dir.exists():
        for wheel in layout.dist_dir.glob(f"{distribution}-0.1.0-*.whl"):
            _remove_path(wheel)


def _cleanup_failed_executable_outputs(
    layout: ArtifactLayout,
    entrypoint: str,
    executable_name: str | None,
) -> None:
    _remove_path(layout.rust_bin_dir)
    binary_name = _rust_binary_name(executable_name, _entrypoint_to_qualname(entrypoint))
    for suffix in ("", ".exe"):
        _remove_path(layout.dist_dir / f"{binary_name}{suffix}")
    _remove_path(layout.dist_dir / f"{binary_name}{RUNTIME_DIR_SUFFIX}")


def _remove_path(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink(missing_ok=True)


def _with_closure(
    result: ExecutableBuildResult, closure: NativeClosureReport
) -> PlannedExecutableBuildResult:
    return PlannedExecutableBuildResult(
        status=result.status,
        path=result.path,
        message=result.message,
        entrypoint=result.entrypoint,
        backend=result.backend,
        command=result.command,
        stdout=result.stdout,
        stderr=result.stderr,
        closure=closure,
    )


def _cleanup_rust_executable_outputs(binary_path: str | None, runtime_dir: Path) -> None:
    """Remove a copied binary and runtime directory after packaging failure."""
    if binary_path is not None:
        binary = Path(binary_path)
        if binary.exists():
            binary.unlink()
    if runtime_dir.exists():
        shutil.rmtree(runtime_dir)


def _build_native_with_selected_tool(
    layout: ArtifactLayout,
    build_tool: str,
    build_timeout: float = DEFAULT_BUILD_TIMEOUT_SECONDS,
    toolchain: ToolchainConfig | None = None,
) -> NativeBuildResult:
    normalized = build_tool.lower()
    if normalized == "cargo":
        return build_native_extension_with_cargo(
            layout.rust_dir, layout.python_dir, timeout=build_timeout, toolchain=toolchain
        )
    if normalized == "maturin":
        result = build_native_extension_with_maturin(
            layout.rust_dir, layout.python_dir, timeout=build_timeout, toolchain=toolchain
        )
        if result.status == "built":
            return result
        if "maturin was not found" not in result.message:
            return result
        cargo_result = build_native_extension_with_cargo(
            layout.rust_dir, layout.python_dir, timeout=build_timeout, toolchain=toolchain
        )
        if cargo_result.status == "built":
            return NativeBuildResult(
                status="built",
                tool="cargo",
                message=(
                    "maturin was not found, so Rextio built the generated native module "
                    "with Cargo fallback."
                ),
                command=cargo_result.command,
                artifact_path=cargo_result.artifact_path,
                installed_path=cargo_result.installed_path,
                stdout=cargo_result.stdout,
                stderr=cargo_result.stderr,
            )
        return NativeBuildResult(
            status="failed",
            tool="maturin",
            message=(
                "RXT060 Build failed while compiling generated Rust module. "
                "Cause: maturin was not found, and Cargo fallback also failed. "
                f"Cargo result: {cargo_result.message}"
            ),
            command=cargo_result.command,
            stdout=cargo_result.stdout,
            stderr=cargo_result.stderr,
        )
    return NativeBuildResult(
        status="failed",
        tool=build_tool,
        message=(
            "RXT060 Build failed while compiling generated Rust module. "
            f"Cause: unsupported Rust build tool: {build_tool}. "
            'Suggestion: use [rust] build_tool = "maturin" or "cargo".'
        ),
    )


def _write_rust_project(
    layout: ArtifactLayout,
    rust_source: str,
    extra_dependencies: tuple[tuple[str, str, tuple[str, ...]], ...] = (),
    device_plan: ResolvedDevicePlan | None = None,
) -> None:
    contribution = (
        device_plan.contribution if device_plan is not None else None
    )
    layout.rust_src_dir.mkdir(parents=True, exist_ok=True)
    (layout.rust_dir / "Cargo.toml").write_text(
        render_cargo_toml(
            extra_dependencies=extra_dependencies,
        ),
        encoding="utf-8",
    )
    (layout.rust_dir / "pyproject.toml").write_text(render_pyproject_toml(), encoding="utf-8")
    (layout.rust_dir / ".cargo").mkdir(parents=True, exist_ok=True)
    (layout.rust_dir / ".cargo" / "config.toml").write_text(
        render_cargo_config_toml(),
        encoding="utf-8",
    )
    (layout.rust_src_dir / "lib.rs").write_text(rust_source, encoding="utf-8")
    if contribution is not None and contribution.native_libraries:
        (layout.rust_dir / "build.rs").write_text(
            render_native_link_build_rs(contribution.native_libraries),
            encoding="utf-8",
        )
    if device_plan is not None:
        (layout.rust_dir / "device-provider.lock.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "device_provider": device_plan.to_dict(),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )


def _write_rust_crate_project(
    layout: ArtifactLayout,
    rust_source: str,
    crate_name: str,
    *,
    extra_dependencies: tuple[tuple[str, str, tuple[str, ...]], ...] = (),
) -> None:
    layout.rust_crate_src_dir.mkdir(parents=True, exist_ok=True)
    (layout.rust_crate_dir / "Cargo.toml").write_text(
        render_importable_cargo_toml(crate_name, extra_dependencies=extra_dependencies),
        encoding="utf-8",
    )
    (layout.rust_crate_src_dir / "lib.rs").write_text(rust_source, encoding="utf-8")


def _build_status(
    native_build: NativeBuildResult,
    fallback_build: FallbackBuildResult,
    executable_build: ExecutableBuildResult | None = None,
    rust_crate_build: RustCrateBuildResult | None = None,
) -> str:
    if fallback_build.status == "failed":
        return "fallback-build-failed"
    if native_build.tool == "codegen" and native_build.status == "failed":
        return "codegen-failed"
    if native_build.status == "failed":
        return "native-build-failed"
    if executable_build is not None and executable_build.status == "failed":
        return "executable-build-failed"
    if rust_crate_build is not None and rust_crate_build.status == "failed":
        return "rust-crate-build-failed"
    return "built"


def _generate_status(
    native_source: NativeSourceResult,
    rust_crate_source: NativeSourceResult | None = None,
) -> str:
    if native_source.status == "failed":
        return "codegen-failed"
    if rust_crate_source is not None and rust_crate_source.status == "failed":
        return "rust-crate-codegen-failed"
    return "generated"
