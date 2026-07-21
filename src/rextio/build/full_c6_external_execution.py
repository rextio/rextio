"""Production C5.2 external call-site to Full C6 native execution bridge.

The strict preflight already owns SourceLock verification, fresh analysis,
private external IR, the runtime guard, and the output-wheel exclusion
contract.  This module accepts only that same transaction plus strong native
toolchain/Cargo receipts, regenerates the exact project itself, and hands the
result to the production two-build executor.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import math
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tomllib
import unicodedata

from rextio.build import full_c6_executor as _executor
from rextio.build import orchestrator as _orchestrator
from rextio.build.full_c6_cargo_workspace import (
    FullC6CargoDependencyWorkspaceReceipt,
    FullC6CargoWorkspaceError,
    _validated_full_c6_cargo_lock_payload,
    validate_full_c6_cargo_dependency_workspace_receipt,
)
from rextio.build.full_c6_executor import (
    FULL_C6_NATIVE_DRIVER_MANIFEST,
    MAX_FULL_C6_FILE_BYTES,
    MAX_FULL_C6_OUTPUT_BYTES,
    MAX_FULL_C6_TREE_BYTES,
    MAX_FULL_C6_TREE_FILES,
    FullC6NativeExecutionAuthority,
    FullC6NativeToolPaths,
    full_c6_native_driver_manifest_bytes,
    validate_full_c6_native_execution_authority,
)
from rextio.build.full_c6_license_materials import (
    FullC6LicenseMaterialsError,
    collect_full_c6_license_materials,
)
from rextio.build.full_c6_output_license import (
    FullC6OutputLicenseDerivationError,
    derive_full_c6_output_license_contract,
)
from rextio.build.full_c6_pipeline import (
    FullC6ExternalPreflightResult,
    FullC6PipelineError,
    validate_full_c6_external_context,
)
from rextio.build.toolchain_identity import BuildToolchainIdentity
from rextio.analyzer.project_scanner import analyze_project
from rextio.config.schema import ImportPackagePolicy, RextioConfig
from rextio.codegen.rust.cargo import (
    render_cargo_config_toml,
    render_cargo_toml,
    render_pyproject_toml,
)
from rextio.codegen.rust.generator import RustCodegenError, generate_rust_module
from rextio.ir.lowering import LoweringError, lower_project
from rextio.ir.nodes import FunctionIR
from rextio.plugins.loader import PluginError
from rextio.targets.plan import TargetPlanError, create_target_plan


FULL_C6_EXTERNAL_EXECUTION_DOMAIN = "rextio.full-c6-external-execution.v1"
_STRICT_CARGO_ARGV = (
    "cargo",
    "build",
    "--release",
    "--locked",
    "--offline",
    "--frozen",
)
_GENERATED_PACKAGE_NAME = "rextio_generated_native"
_GENERATED_DISTRIBUTION_NAME = "rextio-generated-native"
_MAX_STAGING_ENTRIES = 2048


class FullC6ExternalExecutionError(RuntimeError):
    """The strict external native execution slice failed closed."""


@dataclass(frozen=True, slots=True)
class _PythonTreeSnapshot:
    files: tuple[tuple[str, str, int], ...]
    directories: tuple[str, ...]

    @property
    def file_names(self) -> frozenset[str]:
        return frozenset(name for name, _digest, _size in self.files)


def execute_full_c6_external_build(
    preflight: FullC6ExternalPreflightResult,
    *,
    config: RextioConfig,
    first_quarantine_root: Path | str,
    second_quarantine_root: Path | str,
    base_environment: Mapping[str, str] | None,
    source_date_epoch: int,
    toolchain: BuildToolchainIdentity,
    native_tools: FullC6NativeToolPaths,
    cargo_workspace: FullC6CargoDependencyWorkspaceReceipt,
) -> FullC6NativeExecutionAuthority:
    """Generate and execute one exact linked external native vertical slice.

    Registry, guard, wheel contract, generated source, Cargo.lock, output
    licenses, wheel bytes, and executor receipts are all derived internally.
    The public caller cannot replace any of them.
    """
    if type(preflight) is not FullC6ExternalPreflightResult:
        raise FullC6ExternalExecutionError(
            "RXT060 external execution requires an exact preflight result"
        )
    analysis = preflight.analysis
    context = preflight.context
    config_profile = _require_strict_external_config(config, preflight)
    if (
        type(toolchain) is not BuildToolchainIdentity
        or type(native_tools) is not FullC6NativeToolPaths
        or type(cargo_workspace) is not FullC6CargoDependencyWorkspaceReceipt
        or not validate_full_c6_cargo_dependency_workspace_receipt(cargo_workspace)
    ):
        raise FullC6ExternalExecutionError(
            "RXT060 external execution requires strong production toolchain inputs"
        )
    if toolchain.cargo_sources.digest != cargo_workspace.cargo_sources.digest:
        raise FullC6ExternalExecutionError(
            "RXT060 toolchain and Cargo workspace select different Cargo.lock inputs"
        )
    if toolchain.argv.values != _STRICT_CARGO_ARGV:
        raise FullC6ExternalExecutionError(
            "RXT060 external execution requires the exact strict Cargo command"
        )

    try:
        validate_full_c6_external_context(context, analysis)
        target_plan = create_target_plan(analysis.project_root, config)
        if target_plan.spec.language != "rust" or target_plan.plugins.active:
            raise FullC6ExternalExecutionError(
                "RXT060 strict external execution forbids plugins and non-Rust targets"
            )
        if _require_strict_external_config(config, preflight) != config_profile:
            raise FullC6ExternalExecutionError(
                "RXT060 strict external execution config changed during target resolution"
            )
        fresh_analysis = analyze_project(
            analysis.project_root,
            boundary_warnings=config.policy.boundary_warnings,
            native_marker=config.policy.native_marker,
            target_language=target_plan.spec.language,
            native_top_level=config.policy.native_top_level,
            imports_config=config.imports,
            active_plugins=target_plan.plugins.active,
            plugin_registry=target_plan.plugins,
            plugin_config=config,
            embedding_enabled=config.embedding.enabled,
            external_native_registry=context.registry,
        )
        validate_full_c6_external_context(context, fresh_analysis)
        if fresh_analysis.to_dict() != analysis.to_dict():
            raise FullC6ExternalExecutionError(
                "RXT060 execution reanalysis differs from the exact preflight analysis"
            )
        transaction = FullC6ExternalPreflightResult(
            analysis=fresh_analysis,
            context=context,
        )
        analysis = fresh_analysis
        module_ir = lower_project(
            analysis,
            external_native_registry=context.registry,
        )
        _require_reachable_direct_external_ir(transaction, module_ir.functions)
        expected_rust = generate_rust_module(
            module_ir,
            boundary_call_return_types=_orchestrator._boundary_call_return_types(analysis),
            external_runtime_guard=context.runtime_guard,
        ).encode("utf-8")
        generated = _orchestrator.generate_source_artifact(
            analysis.project_root,
            analysis,
            "cpython",
            boundary_fallback_threshold=config.build.fallback_threshold,
            target_plan=target_plan,
            full_c6_external_context=context,
        )
        validate_full_c6_external_context(context, analysis)
        _require_generated_plan(transaction, generated)
        source_root = generated.layout.rust_dir
        expected_cargo = render_cargo_toml().encode("utf-8")
        expected_pyproject = render_pyproject_toml().encode("utf-8")
        _verify_fresh_generated_rust_project(
            source_root,
            expected_rust=expected_rust,
            expected_cargo=expected_cargo,
            expected_pyproject=expected_pyproject,
        )
        _require_cargo_identity(
            expected_cargo,
            cargo_workspace=cargo_workspace,
        )
        lock_payload = _validated_full_c6_cargo_lock_payload(cargo_workspace)
        license_materials = collect_full_c6_license_materials(
            project_root=analysis.project_root,
            cargo_workspace=cargo_workspace,
        )
        output_license = derive_full_c6_output_license_contract(license_materials)
        target_triple = _executor.detect_host_target_triple()
        driver_payload = full_c6_native_driver_manifest_bytes(
            target_triple=target_triple,
            distribution_name=_GENERATED_DISTRIBUTION_NAME,
            cargo_argv=toolchain.argv.values,
            external_contract=context.wheel_contract,
            output_license_contract=output_license,
        )
        python_snapshot = _prepare_executor_source_tree(
            generated.layout.python_dir,
            source_root,
            external_source_members=context.wheel_contract.source_members,
            cargo_lock=lock_payload,
            driver_manifest=driver_payload,
        )
        expected_files = {
            "Cargo.toml": expected_cargo,
            "Cargo.lock": lock_payload,
            "pyproject.toml": expected_pyproject,
            "src/lib.rs": expected_rust,
            FULL_C6_NATIVE_DRIVER_MANIFEST: driver_payload,
        }
        _require_known_execution_files(source_root, expected_files)
        expected_entries = _expected_execution_entries(
            expected_files,
            python_snapshot=python_snapshot,
        )
        authority = _executor.execute_full_c6_native_two_build(
            source_root,
            first_quarantine_root,
            second_quarantine_root,
            base_environment=base_environment,
            source_date_epoch=source_date_epoch,
            timeout_seconds=config.build.build_timeout_seconds,
            max_output_bytes=MAX_FULL_C6_OUTPUT_BYTES,
            toolchain=toolchain,
            native_tools=native_tools,
            cargo_workspace=cargo_workspace,
            output_license_contract=output_license,
        )
        if not validate_full_c6_native_execution_authority(authority):
            raise FullC6ExternalExecutionError(
                "RXT060 external native executor returned stale authority"
            )
        _require_authority_source_bindings(
            authority,
            expected_entries=expected_entries,
        )
        validate_full_c6_external_context(context, analysis)
        if _require_strict_external_config(config, transaction) != config_profile:
            raise FullC6ExternalExecutionError(
                "RXT060 strict external execution config changed during execution"
            )
        return authority
    except FullC6ExternalExecutionError:
        raise
    except (
        FullC6CargoWorkspaceError,
        _executor.FullC6ExecutorError,
        FullC6LicenseMaterialsError,
        FullC6OutputLicenseDerivationError,
        FullC6PipelineError,
        LoweringError,
        OSError,
        PluginError,
        RustCodegenError,
        TargetPlanError,
        TypeError,
        ValueError,
    ) as exc:
        raise FullC6ExternalExecutionError(
            "RXT060 strict external native execution failed closed"
        ) from exc


def _require_strict_external_config(
    config: RextioConfig,
    preflight: FullC6ExternalPreflightResult,
) -> str:
    if type(config) is not RextioConfig:
        raise FullC6ExternalExecutionError(
            "RXT060 external execution requires an exact typed config"
        )
    build = config.build
    rust = config.rust
    policy = config.policy
    package_items = tuple(config.imports.packages.items())
    source = preflight.context.source_verification.context
    if source is None or len(package_items) != 1:
        raise FullC6ExternalExecutionError(
            "RXT060 external execution requires one exact package config"
        )
    package_name, package = package_items[0]
    if type(package) is not ImportPackagePolicy:
        raise FullC6ExternalExecutionError(
            "RXT060 external execution package config is invalid"
        )
    admission = preflight.context.source_verification.admission
    strict = (
        build.native_backend == "rust"
        and build.fallback_backend == "cpython"
        and type(build.fallback_threshold) is int
        and build.fallback_threshold >= 0
        and type(build.build_timeout_seconds) in {int, float}
        and not isinstance(build.build_timeout_seconds, bool)
        and math.isfinite(build.build_timeout_seconds)
        and build.build_timeout_seconds > 0
        and build.artifact_evidence_policy == "required"
        and build.artifact_distribution_policy == "full-c6-required"
        and build.artifact_source_lock_manifest is not None
        and build.artifact_source_lock_signature is not None
        and build.artifact_trusted_public_key is not None
        and build.artifact_trusted_public_key_sha256 == admission.public_key_sha256
        and build.artifact_signing_request_output is not None
        and build.artifact_repeat_builds == 2
        and rust.binding == "pyo3"
        and rust.build_tool == "cargo"
        and rust.importable is False
        and config.plugins.enabled == ()
        and config.embedding.enabled is False
        and config.executable.entrypoint is None
        and policy.native_marker in {"auto", "decorator"}
        and policy.require_type_hints is True
        and policy.allow_dynamic_features is False
        and type(policy.boundary_warnings) is bool
        and policy.native_top_level is False
        and config.imports.default_external_policy == "fallback"
        and package_name == preflight.context.registry.package
        and package.policy == "try-native"
        and package.plugin is None
        and package.max_depth == 1
        and package.distribution == preflight.context.registry.distribution
        and package.version == preflight.context.registry.version
        and type(package.source_archive) is str
        and PurePosixPath(package.source_archive).name == source.wheel.archive.filename
        and package.source_archive_sha256 == source.wheel.archive.sha256
    )
    if not strict:
        raise FullC6ExternalExecutionError(
            "RXT060 config is outside the frozen external execution profile"
        )
    try:
        snapshot = json.dumps(
            {
                "domain": "rextio.full-c6-external-config-snapshot.v1",
                "config": asdict(config),
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RuntimeError) as exc:
        raise FullC6ExternalExecutionError(
            "RXT060 external execution config cannot be snapshotted exactly"
        ) from exc
    return hashlib.sha256(snapshot).hexdigest()


def _require_reachable_direct_external_ir(
    preflight: FullC6ExternalPreflightResult,
    functions: list[FunctionIR],
) -> None:
    context = preflight.context
    registry = context.registry
    registry.require_fresh_analysis(preflight.analysis)
    if not registry.linked_calls or not registry.private_functions:
        raise FullC6ExternalExecutionError(
            "RXT060 external execution has no linked project call-site"
        )
    accepted = {
        function.qualname: function
        for function in preflight.analysis.accepted_native_functions
    }
    ir_by_name = {function.qualname: function for function in functions}
    if len(ir_by_name) != len(functions):
        raise FullC6ExternalExecutionError(
            "RXT060 generated IR contains duplicate functions"
        )
    private_names = {function.qualname for function in registry.private_functions}
    observed_private = tuple(
        sorted(
            (function for function in functions if function.qualname in private_names),
            key=lambda item: item.qualname,
        )
    )
    if observed_private != registry.private_functions:
        raise FullC6ExternalExecutionError(
            "RXT060 generated IR differs from exact external private functions"
        )
    reached = 0
    for linked in registry.linked_calls:
        analysis_function = accepted.get(linked.caller_qualname)
        caller_ir = ir_by_name.get(linked.caller_qualname)
        if (
            analysis_function is None
            or caller_ir is None
            or analysis_function.route != "native-direct"
            or analysis_function.boundary_call_targets
            or analysis_function.delegated_call_targets
            or analysis_function.plugin_claims
            or analysis_function.plugin_type_keys
            or caller_ir.has_boundary_calls
            or caller_ir.native_runtime_semantics
            or caller_ir.plugin_lowered
            or not _ir_contains_direct_call(caller_ir, linked.target)
        ):
            raise FullC6ExternalExecutionError(
                "RXT060 linked external call would use fallback, plugin, or stale IR"
            )
        reached += 1
    if reached < 1:
        raise FullC6ExternalExecutionError(
            "RXT060 external execution has no reachable linked call"
        )
    if any(
        function.has_boundary_calls
        or function.native_runtime_semantics
        or function.plugin_lowered
        for function in observed_private
    ):
        raise FullC6ExternalExecutionError(
            "RXT060 external private functions must be pure direct Rust"
        )


def _ir_contains_direct_call(function: FunctionIR, target: str) -> bool:
    def visit(value: object) -> bool:
        if isinstance(value, dict):
            if value.get("kind") == "call" and value.get("function") == target:
                return True
            return any(visit(item) for item in value.values())
        if isinstance(value, list):
            return any(visit(item) for item in value)
        return False

    return visit(function.body.to_dict())


def _require_generated_plan(
    preflight: FullC6ExternalPreflightResult,
    generated: _orchestrator.GenerateResult,
) -> None:
    if (
        type(generated) is not _orchestrator.GenerateResult
        or generated.native_source.status != "generated"
        or generated.native_source.path is None
        or generated.plan.analysis is not preflight.analysis
        or generated.fallback != "cpython"
        or generated.plugin_crate_dependencies
        or generated.target_plan.plugins.active
    ):
        raise FullC6ExternalExecutionError(
            "RXT060 orchestrator did not produce the strict external source plan"
        )
    accepted = {item.qualname for item in generated.plan.native.accepted_functions}
    if any(
        linked.caller_qualname not in accepted
        for linked in preflight.context.registry.linked_calls
    ):
        raise FullC6ExternalExecutionError(
            "RXT060 linked external caller is absent from the native build plan"
        )


def _verify_fresh_generated_rust_project(
    source_root: Path,
    *,
    expected_rust: bytes,
    expected_cargo: bytes,
    expected_pyproject: bytes,
) -> None:
    _require_directory_inventory(
        source_root,
        {".cargo", "Cargo.toml", "pyproject.toml", "src"},
    )
    _require_directory_inventory(source_root / "src", {"lib.rs"})
    _require_directory_inventory(source_root / ".cargo", {"config.toml"})
    _require_exact_file(source_root / "src/lib.rs", expected_rust)
    _require_exact_file(source_root / "Cargo.toml", expected_cargo)
    _require_exact_file(source_root / "pyproject.toml", expected_pyproject)
    _require_exact_file(
        source_root / ".cargo/config.toml",
        render_cargo_config_toml().encode("utf-8"),
    )


def _require_cargo_identity(
    cargo_toml: bytes,
    *,
    cargo_workspace: FullC6CargoDependencyWorkspaceReceipt,
) -> None:
    try:
        document = tomllib.loads(cargo_toml.decode("utf-8"))
        package = document["package"]
        dependencies = document["dependencies"]
        package_name = package["name"]
    except (KeyError, TypeError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise FullC6ExternalExecutionError(
            "RXT060 generated Cargo.toml identity is invalid"
        ) from exc
    available = {item.name for item in cargo_workspace.cargo_sources.packages}
    if (
        package_name != _GENERATED_PACKAGE_NAME
        or cargo_workspace.cargo_sources.root_package != package_name
        or not isinstance(dependencies, dict)
        or not set(dependencies).issubset(available)
    ):
        raise FullC6ExternalExecutionError(
            "RXT060 owner-prepared Cargo.lock does not cover generated dependencies"
        )


def _prepare_executor_source_tree(
    generated_python: Path,
    source_root: Path,
    *,
    external_source_members: tuple[str, ...],
    cargo_lock: bytes,
    driver_manifest: bytes,
) -> _PythonTreeSnapshot:
    config = source_root / ".cargo/config.toml"
    _require_exact_file(config, render_cargo_config_toml().encode("utf-8"))
    config.unlink()
    (source_root / ".cargo").rmdir()
    python_snapshot = _require_regular_python_tree(generated_python)
    external_aliases = {
        unicodedata.normalize("NFC", name).casefold()
        for name in external_source_members
    }
    if external_aliases.intersection(
        unicodedata.normalize("NFC", name).casefold()
        for name in python_snapshot.file_names
    ):
        raise FullC6ExternalExecutionError(
            "RXT060 generated Python staging contains external package source"
        )
    python_staging = source_root / "python-staging"
    shutil.copytree(generated_python, python_staging, symlinks=True)
    staged_snapshot = _require_regular_python_tree(python_staging)
    final_source_snapshot = _require_regular_python_tree(generated_python)
    if staged_snapshot != python_snapshot or final_source_snapshot != python_snapshot:
        raise FullC6ExternalExecutionError(
            "RXT060 generated Python staging changed during copy"
        )
    _write_exclusive(source_root / "Cargo.lock", cargo_lock)
    _write_exclusive(source_root / FULL_C6_NATIVE_DRIVER_MANIFEST, driver_manifest)
    _require_directory_inventory(
        source_root,
        {
            "Cargo.lock",
            "Cargo.toml",
            FULL_C6_NATIVE_DRIVER_MANIFEST,
            "pyproject.toml",
            "python-staging",
            "src",
        },
    )
    return staged_snapshot


def _require_regular_python_tree(root: Path) -> _PythonTreeSnapshot:
    root_before = os.lstat(root)
    if not stat.S_ISDIR(root_before.st_mode) or stat.S_ISLNK(root_before.st_mode):
        raise FullC6ExternalExecutionError(
            "RXT060 generated Python staging root is unsafe"
        )
    files: dict[str, tuple[str, int]] = {}
    directories: set[str] = set()
    directory_stamps: dict[Path, tuple[int, ...]] = {}
    aliases: set[str] = set()
    entry_count = 0
    total_bytes = 0
    for directory, names, filenames in os.walk(root, followlinks=False):
        current = Path(directory)
        current_stat = os.lstat(current)
        if stat.S_ISLNK(current_stat.st_mode) or not stat.S_ISDIR(current_stat.st_mode):
            raise FullC6ExternalExecutionError(
                "RXT060 generated Python staging contains a symlink"
            )
        directory_stamps[current] = _filesystem_stamp(current_stat)
        if current != root:
            directories.add(current.relative_to(root).as_posix())
        local_aliases: set[str] = set()
        for name in (*names, *filenames):
            entry_count += 1
            if entry_count > _MAX_STAGING_ENTRIES:
                raise FullC6ExternalExecutionError(
                    "RXT060 generated Python staging exceeds its bound"
                )
            alias = unicodedata.normalize("NFC", name).casefold()
            if (
                not name
                or name != unicodedata.normalize("NFC", name)
                or alias in local_aliases
            ):
                raise FullC6ExternalExecutionError(
                    "RXT060 generated Python staging has a path alias"
                )
            local_aliases.add(alias)
            member = current / name
            observed = os.lstat(member)
            if name in names:
                if not stat.S_ISDIR(observed.st_mode) or stat.S_ISLNK(observed.st_mode):
                    raise FullC6ExternalExecutionError(
                        "RXT060 generated Python staging directory is unsafe"
                    )
                continue
            if (
                not stat.S_ISREG(observed.st_mode)
                or stat.S_ISLNK(observed.st_mode)
                or observed.st_nlink != 1
            ):
                raise FullC6ExternalExecutionError(
                    "RXT060 generated Python staging file is unsafe"
                )
            relative = member.relative_to(root).as_posix()
            logical_alias = unicodedata.normalize("NFC", relative).casefold()
            if logical_alias in aliases:
                raise FullC6ExternalExecutionError(
                    "RXT060 generated Python staging has aliased files"
                )
            aliases.add(logical_alias)
            if name.casefold().endswith((".so", ".dylib", ".dll", ".pyd")):
                raise FullC6ExternalExecutionError(
                    "RXT060 generated Python staging contains a native binary"
                )
            digest, size = _stable_regular_file_identity(member, observed)
            files[relative] = (digest, size)
            total_bytes += size
            if len(files) > MAX_FULL_C6_TREE_FILES or total_bytes > MAX_FULL_C6_TREE_BYTES:
                raise FullC6ExternalExecutionError(
                    "RXT060 generated Python staging exceeds its byte bound"
                )
    if not files:
        raise FullC6ExternalExecutionError(
            "RXT060 generated Python staging is empty"
        )
    for directory_path, expected in directory_stamps.items():
        if _filesystem_stamp(os.lstat(directory_path)) != expected:
            raise FullC6ExternalExecutionError(
                "RXT060 generated Python staging changed during capture"
            )
    if _filesystem_stamp(os.lstat(root)) != _filesystem_stamp(root_before):
        raise FullC6ExternalExecutionError(
            "RXT060 generated Python staging root changed during capture"
        )
    return _PythonTreeSnapshot(
        files=tuple(
            (name, digest, size)
            for name, (digest, size) in sorted(files.items(), key=lambda item: item[0])
        ),
        directories=tuple(sorted(directories)),
    )


def _stable_regular_file_identity(
    path: Path,
    before: os.stat_result,
) -> tuple[str, int]:
    if before.st_size < 0 or before.st_size > MAX_FULL_C6_FILE_BYTES:
        raise FullC6ExternalExecutionError(
            "RXT060 generated Python file exceeds its byte bound"
        )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        digest = hashlib.sha256()
        size = 0
        while size <= MAX_FULL_C6_FILE_BYTES:
            chunk = os.read(
                descriptor,
                min(65536, MAX_FULL_C6_FILE_BYTES + 1 - size),
            )
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
        final = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after = os.lstat(path)
    if (
        len(
            {
                _filesystem_stamp(item)
                for item in (before, opened, final, after)
            }
        )
        != 1
        or size != before.st_size
        or size > MAX_FULL_C6_FILE_BYTES
    ):
        raise FullC6ExternalExecutionError(
            "RXT060 generated Python file changed during capture"
        )
    return digest.hexdigest(), size


def _filesystem_stamp(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _require_known_execution_files(
    source_root: Path,
    expected_files: dict[str, bytes],
) -> None:
    for relative, expected in expected_files.items():
        _require_exact_file(source_root.joinpath(*PurePosixPath(relative).parts), expected)


def _expected_execution_entries(
    expected_files: dict[str, bytes],
    *,
    python_snapshot: _PythonTreeSnapshot,
) -> dict[str, tuple[str, str | None, int]]:
    entries: dict[str, tuple[str, str | None, int]] = {
        relative: ("file", hashlib.sha256(payload).hexdigest(), len(payload))
        for relative, payload in expected_files.items()
    }
    entries["src"] = ("directory", None, 0)
    entries["python-staging"] = ("directory", None, 0)
    entries.update(
        {
            f"python-staging/{relative}": ("directory", None, 0)
            for relative in python_snapshot.directories
        }
    )
    entries.update(
        {
            f"python-staging/{relative}": ("file", digest, size)
            for relative, digest, size in python_snapshot.files
        }
    )
    return entries


def _require_authority_source_bindings(
    authority: FullC6NativeExecutionAuthority,
    *,
    expected_entries: dict[str, tuple[str, str | None, int]],
) -> None:
    entries = {
        item.logical_name: item
        for item in authority.frozen_tree.entries
    }
    if set(entries) != set(expected_entries):
        raise FullC6ExternalExecutionError(
            "RXT060 executor authority contains an unexpected source member"
        )
    for relative, (kind, digest, size) in expected_entries.items():
        entry = entries.get(relative)
        if (
            entry is None
            or entry.kind != kind
            or entry.size != size
            or entry.sha256 != digest
        ):
            raise FullC6ExternalExecutionError(
                "RXT060 executor authority differs from generated source"
            )
    if authority.frozen_tree.cargo_lock_generated:
        raise FullC6ExternalExecutionError(
            "RXT060 executor authority substituted a generated Cargo.lock"
        )


def _require_directory_inventory(path: Path, expected: set[str]) -> None:
    observed = os.lstat(path)
    if not stat.S_ISDIR(observed.st_mode) or stat.S_ISLNK(observed.st_mode):
        raise FullC6ExternalExecutionError("RXT060 generated directory is unsafe")
    names = os.listdir(path)
    aliases = [unicodedata.normalize("NFC", name).casefold() for name in names]
    if (
        set(names) != expected
        or len(names) != len(expected)
        or len(aliases) != len(set(aliases))
        or any(name != unicodedata.normalize("NFC", name) for name in names)
    ):
        raise FullC6ExternalExecutionError(
            "RXT060 generated directory inventory is stale or unexpected"
        )


def _require_exact_file(path: Path, expected: bytes) -> None:
    before = os.lstat(path)
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or before.st_size != len(expected)
    ):
        raise FullC6ExternalExecutionError("RXT060 generated file identity is unsafe")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        data = b""
        while len(data) < len(expected):
            chunk = os.read(descriptor, min(1024 * 1024, len(expected) - len(data)))
            if not chunk:
                break
            data += chunk
        final = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after = os.lstat(path)
    stamps = tuple(
        (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_nlink,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        for item in (before, opened, final, after)
    )
    if len(set(stamps)) != 1 or not hmac.compare_digest(data, expected):
        raise FullC6ExternalExecutionError(
            "RXT060 generated file bytes changed or differ from codegen"
        )


def _write_exclusive(path: Path, data: bytes) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags, 0o644)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise FullC6ExternalExecutionError(
                    "RXT060 generated file write made no progress"
                )
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _require_exact_file(path, data)


__all__ = [
    "FULL_C6_EXTERNAL_EXECUTION_DOMAIN",
    "FullC6ExternalExecutionError",
    "execute_full_c6_external_build",
]
