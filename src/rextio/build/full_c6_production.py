"""Owner-only coordinator for the bounded Full C6 production transaction."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
import hashlib
import hmac
from pathlib import Path
import secrets
import tomllib
from typing import Literal, SupportsIndex, cast
import unicodedata

from rextio.build import full_c6_executor as _executor
from rextio.build import full_c6_native_runtime as _native_runtime
from rextio.build import orchestrator as _orchestrator
from rextio.artifacts.evidence import (
    ARTIFACT_POLICY_COVERAGE_CLASS_IDS,
    AnalysisInputVerification,
    ArtifactPolicyCoverageInventory,
    CargoPackageRef,
    ComponentLicensePolicyVerification,
    EvidenceFileRef,
    NativeRuntimeInventory,
    NativeRuntimeTransitiveClosureInventory,
    ProjectSourceLicensePolicyVerification,
    WheelEntryRef,
    canonical_json_bytes,
    artifact_policy_coverage_inventory_digest,
)
from rextio.build.analysis_input_verification import (
    collect_scoped_analysis_input_verification,
)
from rextio.build.cargo_license_policy import (
    collect_component_license_policy_verification,
)
from rextio.build.full_c6_analysis_transaction import (
    FullC6AnalysisIRTransaction,
    create_full_c6_analysis_ir_transaction,
    validate_full_c6_analysis_ir_transaction,
)
from rextio.build.full_c6_cargo_workspace import (
    FullC6CargoDependencyWorkspaceReceipt,
    validate_full_c6_cargo_dependency_workspace_receipt,
)
from rextio.build.full_c6_config_identity import (
    FullC6ConfigIdentityError,
    capture_effective_full_c6_config_identity,
)
from rextio.build.full_c6_executor import (
    FullC6ExecutorReceipt,
    FullC6NativeExecutionAuthority,
    FullC6NativeToolPaths,
    validate_full_c6_native_execution_authority,
)
from rextio.build.full_c6_external_execution import execute_full_c6_external_build
from rextio.build.full_c6_input_identity import (
    canonical_full_c6_build_input_name,
)
from rextio.build.full_c6_license_materials import (
    FullC6LicenseMaterialsTransaction,
    collect_full_c6_license_materials,
    validate_full_c6_license_materials_transaction,
)
from rextio.build.full_c6_native_output import (
    FullC6NativeOutputTransaction,
    full_c6_native_output_cargo_workspace,
    full_c6_native_output_executor_receipt,
    full_c6_native_output_subject,
    full_c6_native_output_wheel_entries,
    materialize_full_c6_native_output,
    validate_full_c6_native_output_transaction,
)
from rextio.build.full_c6_native_runtime import (
    FullC6NativeRuntimeAuthority,
    create_full_c6_native_runtime_authority,
    validate_full_c6_native_runtime_authority,
)
from rextio.build.full_c6_output_license import (
    OutputWheelLicenseContract,
    derive_full_c6_output_license_contract,
    validate_full_c6_output_license_contract,
)
from rextio.build.full_c6_pipeline import (
    FullC6ExternalPreflightResult,
    load_configured_full_c6_policy,
    validate_full_c6_external_context,
)
from rextio.build.full_c6_policy import (
    FULL_C6_EXTERNAL_POLICY_CLASS_IDS,
    FullC6ExternalAuthorityClass,
    FullC6ExternalAuthorityPartition,
    FullC6PolicyReceipt,
    FullC6PolicyFileIdentity,
    FullC6TransformationRecord,
    full_c6_analysis_receipt_digest,
    full_c6_artifact_authority_identity,
    full_c6_authority_partition_digest,
    full_c6_external_authority_identity,
    full_c6_external_authority_identity_set_digest,
    full_c6_external_authority_partition_digest,
    full_c6_license_detector_payload_digest,
    full_c6_lowered_ir_receipt_digest,
    full_c6_policy_identity_mode,
    full_c6_policy_license_disposition,
    full_c6_policy_transformation_disposition,
    full_c6_transformation_source_set_digest,
)
from rextio.build.full_c6_policy_bootstrap import (
    FullC6PolicyBootstrapInputs,
    FullC6PolicyBootstrapRequest,
    FullC6PolicyLifecycle,
    create_full_c6_policy_bootstrap_request,
    resolve_full_c6_policy_lifecycle,
)
from rextio.build.full_c6_policy_template import (
    FullC6ExternalLicenseObservation,
    FullC6InternalLicenseObservation,
    FullC6TechnicalPolicyRow,
    FullC6TechnicalPolicyTemplate,
)
from rextio.build.full_c6_subject_wheel import (
    FullC6SubjectWheelTransaction,
    validate_full_c6_subject_wheel_transaction,
)
from rextio.build.full_c6_supply_chain import (
    FullC6AuthorityAggregateBinding,
    FullC6CargoPathSource,
    FullC6SupplyChainReceipt,
    build_full_c6_supply_chain_receipt,
    verify_full_c6_supply_chain_receipt,
)
from rextio.build.input_closure import (
    BuildInputClosure,
    ExactFileIdentity,
    bind_build_input_aggregate,
    bind_full_c6_cargo_workspace_aggregates,
)
from rextio.build.license_inventory import collect_component_license_inventory
from rextio.build.policy_coverage import collect_artifact_policy_coverage_inventory
from rextio.build.runtime_authorization import RuntimeAuthorizationReceipt
from rextio.build.source_license_policy import (
    collect_project_source_license_policy_verification,
)
from rextio.build.supply_chain import (
    EvidenceInputSnapshot,
    capture_generated_python_inputs,
    capture_generated_rust_inputs,
    capture_project_source_snapshot,
)
from rextio.build.toolchain_identity import BuildToolchainIdentity
from rextio.build.transformation_inventory import (
    collect_source_transformation_inventory,
)
from rextio.build.transformation_verification import (
    collect_scoped_source_transformation_replay_authority,
)
from rextio.config.schema import RextioConfig
from rextio.targets.plan import create_target_plan
from rextio.source.wheel_authority import verify_source_wheel_license_detection


FULL_C6_PRODUCTION_AUTHORITY_DOMAIN = "rextio.full-c6-production-authority.v2"
_MAX_SOURCE_DATE_EPOCH = 2_147_483_647
_SEAL_KEY = secrets.token_bytes(32)


class FullC6ProductionError(RuntimeError):
    """The bounded production authority graph could not be collected."""


@dataclass(frozen=True, slots=True)
class _FullC6ProductionMaterial:
    """Exact retained graph; never exposed as a caller construction seam."""

    preflight: FullC6ExternalPreflightResult = field(repr=False)
    project_root: Path = field(repr=False)
    config: RextioConfig = field(repr=False)
    lifecycle: FullC6PolicyLifecycle
    analysis_ir_transaction: FullC6AnalysisIRTransaction = field(repr=False)
    license_materials_transaction: FullC6LicenseMaterialsTransaction = field(repr=False)
    output_license_contract: OutputWheelLicenseContract = field(repr=False)
    cargo_workspace: FullC6CargoDependencyWorkspaceReceipt = field(repr=False)
    native_execution_authority: FullC6NativeExecutionAuthority = field(repr=False)
    native_output_transaction: FullC6NativeOutputTransaction = field(repr=False)
    subject_wheel_transaction: FullC6SubjectWheelTransaction = field(repr=False)
    native_runtime_authority: FullC6NativeRuntimeAuthority = field(repr=False)
    runtime_authorization: RuntimeAuthorizationReceipt
    executor_receipt: FullC6ExecutorReceipt
    build_inputs: BuildInputClosure
    cargo_path_source: FullC6CargoPathSource
    artifact_coverage: ArtifactPolicyCoverageInventory
    external_authority: FullC6ExternalAuthorityPartition
    authority_aggregate: FullC6AuthorityAggregateBinding
    technical_policy_template: FullC6TechnicalPolicyTemplate
    bootstrap_inputs: FullC6PolicyBootstrapInputs
    bootstrap_request: FullC6PolicyBootstrapRequest
    policy: FullC6PolicyReceipt | None = None
    supply_chain: FullC6SupplyChainReceipt | None = None


class FullC6ProductionAuthority:
    """Immutable, process-sealed evidence bundle; never distribution authority."""

    __slots__ = ("_material", "_transaction_seal")

    _material: _FullC6ProductionMaterial
    _transaction_seal: bytes

    def __init__(self) -> None:
        raise TypeError("Full C6 production authority requires the collector")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise TypeError("Full C6 production authority is immutable")

    def __delattr__(self, _name: str) -> None:
        raise TypeError("Full C6 production authority is immutable")

    def __copy__(self) -> object:
        raise TypeError("Full C6 production authority cannot be copied")

    def __deepcopy__(self, _memo: object) -> object:
        raise TypeError("Full C6 production authority cannot be copied")

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("Full C6 production authority cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        raise TypeError("Full C6 production authority cannot be serialized")

    def __getstate__(self) -> object:
        raise TypeError("Full C6 production authority cannot be serialized")

    def __repr__(self) -> str:
        return "FullC6ProductionAuthority(material=<sealed>)"

    @property
    def digest(self) -> str:
        """Return the path-free semantic digest after complete revalidation."""
        _require_valid_authority(self)
        return _digest(_material_projection(self._material))

    @property
    def lifecycle(self) -> FullC6PolicyLifecycle:
        """Return the exact non-authorizing owner-policy lifecycle state."""
        _require_valid_authority(self)
        return self._material.lifecycle

    @property
    def authority_aggregate(self) -> FullC6AuthorityAggregateBinding:
        """Return the exact fixed-order ten-digest aggregate."""
        _require_valid_authority(self)
        return self._material.authority_aggregate

    @property
    def bootstrap_request(self) -> FullC6PolicyBootstrapRequest | None:
        """Return the non-authorizing owner-completion request, when required."""
        _require_valid_authority(self)
        return (
            self._material.bootstrap_request
            if self._material.lifecycle.status == "bootstrap-required"
            else None
        )

    def to_dict(self) -> dict[str, object]:
        """Return only path-free digests and an explicit non-authorizing posture."""
        _require_valid_authority(self)
        payload = _material_projection(self._material)
        return {**payload, "digest": _digest(payload)}


def collect_full_c6_production_authority(
    preflight: FullC6ExternalPreflightResult,
    *,
    project_root: Path | str,
    config: RextioConfig,
    toolchain: BuildToolchainIdentity,
    native_tools: FullC6NativeToolPaths,
    cargo_workspace: FullC6CargoDependencyWorkspaceReceipt,
    first_quarantine_root: Path | str,
    second_quarantine_root: Path | str,
    state_directory: Path | str,
    base_environment: Mapping[str, str] | None,
    source_date_epoch: int,
) -> FullC6ProductionAuthority:
    """Collect all typed Full C6 evidence without accepting derived authority."""
    try:
        material = _collect_full_c6_production_material(
            preflight,
            project_root=project_root,
            config=config,
            toolchain=toolchain,
            native_tools=native_tools,
            cargo_workspace=cargo_workspace,
            first_quarantine_root=first_quarantine_root,
            second_quarantine_root=second_quarantine_root,
            state_directory=state_directory,
            base_environment=base_environment,
            source_date_epoch=source_date_epoch,
        )
        authority = object.__new__(FullC6ProductionAuthority)
        object.__setattr__(authority, "_material", material)
        object.__setattr__(authority, "_transaction_seal", _seal(authority))
        if not validate_full_c6_production_authority(authority):
            raise FullC6ProductionError(
                "collected Full C6 production authority is stale"
            )
        return authority
    except FullC6ProductionError:
        raise
    except Exception as exc:
        raise FullC6ProductionError(
            "Full C6 production authority collection failed closed"
        ) from exc


def validate_full_c6_production_authority(
    value: FullC6ProductionAuthority,
) -> bool:
    """Return whether ``value`` is the unchanged complete process authority."""
    try:
        return (
            type(value) is FullC6ProductionAuthority
            and type(value._material) is _FullC6ProductionMaterial
            and _validate_material(value._material)
            and type(value._transaction_seal) is bytes
            and hmac.compare_digest(value._transaction_seal, _seal(value))
        )
    except Exception:
        return False


def _require_valid_authority(value: FullC6ProductionAuthority) -> None:
    if not validate_full_c6_production_authority(value):
        raise FullC6ProductionError("Full C6 production authority is stale")


def _validated_full_c6_production_material(
    value: FullC6ProductionAuthority,
) -> _FullC6ProductionMaterial:
    """Return the exact retained graph only to internal hard-gate consumers."""
    _require_valid_authority(value)
    return value._material


def _collect_full_c6_production_material(
    preflight: FullC6ExternalPreflightResult,
    *,
    project_root: Path | str,
    config: RextioConfig,
    toolchain: BuildToolchainIdentity,
    native_tools: FullC6NativeToolPaths,
    cargo_workspace: FullC6CargoDependencyWorkspaceReceipt,
    first_quarantine_root: Path | str,
    second_quarantine_root: Path | str,
    state_directory: Path | str,
    base_environment: Mapping[str, str] | None,
    source_date_epoch: int,
) -> _FullC6ProductionMaterial:
    """Derive the entire evidence graph from prerequisite authority only."""
    root = _require_production_inputs(
        preflight=preflight,
        project_root=project_root,
        config=config,
        toolchain=toolchain,
        native_tools=native_tools,
        cargo_workspace=cargo_workspace,
        source_date_epoch=source_date_epoch,
    )
    lifecycle = resolve_full_c6_policy_lifecycle(config)
    execution = execute_full_c6_external_build(
        preflight,
        config=config,
        first_quarantine_root=first_quarantine_root,
        second_quarantine_root=second_quarantine_root,
        base_environment=base_environment,
        source_date_epoch=source_date_epoch,
        toolchain=toolchain,
        native_tools=native_tools,
        cargo_workspace=cargo_workspace,
    )
    if not validate_full_c6_native_execution_authority(execution):
        raise FullC6ProductionError("native execution authority is stale")
    execution_material = _executor._validated_full_c6_native_output_material(
        execution
    )
    if (
        execution_material.toolchain is not toolchain
        or execution_material.cargo_workspace is not cargo_workspace
    ):
        raise FullC6ProductionError("native execution replaced prerequisite authority")

    license_materials = collect_full_c6_license_materials(
        project_root=root,
        cargo_workspace=cargo_workspace,
    )
    source_context = preflight.context.source_verification.context
    if source_context is None:
        raise FullC6ProductionError("output license SourceLock context is unavailable")
    output_license = derive_full_c6_output_license_contract(
        license_materials,
        source_context=source_context,
    )
    output_license_observation = validate_full_c6_output_license_contract(
        license_materials,
        output_license,
        source_context=source_context,
    )
    if execution_material.output_license_contract != output_license:
        raise FullC6ProductionError(
            "fresh license collection differs from the executed output contract"
        )

    native_output = materialize_full_c6_native_output(
        execution,
        state_directory=state_directory,
    )
    if not validate_full_c6_native_output_transaction(native_output):
        raise FullC6ProductionError("native output transaction is stale")
    subject_wheel = native_output._subject_wheel
    if not validate_full_c6_subject_wheel_transaction(subject_wheel):
        raise FullC6ProductionError("subject wheel transaction is stale")
    native_runtime = create_full_c6_native_runtime_authority(native_output)
    runtime_material = _native_runtime._validated_full_c6_native_runtime_material(
        native_runtime
    )
    if (
        runtime_material.output_transaction is not native_output
        or runtime_material.toolchain is not toolchain
    ):
        raise FullC6ProductionError("native runtime replaced retained authority")

    generated, input_snapshot = _regenerate_production_inputs(
        root=root,
        preflight=preflight,
        config=config,
        cargo_workspace=cargo_workspace,
        execution=execution,
    )
    transformation_inventory = collect_source_transformation_inventory(
        project_root=root,
        plan=generated.plan,
        input_snapshot=input_snapshot,
    )
    if transformation_inventory is None:
        raise FullC6ProductionError("source transformation inventory is incomplete")
    replay = collect_scoped_source_transformation_replay_authority(
        project_root=root,
        plan=generated.plan,
        input_snapshot=input_snapshot,
        transformation_inventory=transformation_inventory,
        embedding_enabled=False,
        boundary_fallback_threshold=config.build.fallback_threshold,
        external_native_registry=preflight.context.registry,
        external_runtime_guard=preflight.context.runtime_guard,
        full_c6_analysis_scope=preflight.context.analysis_scope,
        full_c6_config=config,
    )
    if replay is None:
        raise FullC6ProductionError("source transformation replay is incomplete")
    analysis_inputs = collect_scoped_analysis_input_verification(
        project_root=root,
        plan=generated.plan,
        source_transformation_verification=replay.verification,
    )
    if analysis_inputs is None:
        raise FullC6ProductionError("analysis input verification is incomplete")
    source_license_policy = collect_project_source_license_policy_verification(
        project_root=root,
        source_transformation_verification=replay.verification,
    )
    if source_license_policy is None:
        raise FullC6ProductionError("project source license policy is incomplete")

    cargo_packages = _cargo_package_refs(
        cargo_workspace,
        root_name=toolchain.cargo_sources.root_package,
    )
    component_inventory = collect_component_license_inventory(cargo_packages)
    if component_inventory is None:
        raise FullC6ProductionError("Cargo component license inventory is incomplete")
    component_license_policy = collect_component_license_policy_verification(
        project_root=root,
        component_license_inventory=component_inventory,
    )
    if component_license_policy is None:
        raise FullC6ProductionError("Cargo component license policy is incomplete")

    coverage_inputs = input_snapshot.all_inputs
    artifact_coverage = collect_artifact_policy_coverage_inventory(
        target_triple=execution.executor_receipt.target_triple or "",
        subject=full_c6_native_output_subject(native_output),
        inputs=coverage_inputs,
        wheel_entries=full_c6_native_output_wheel_entries(native_output),
        cargo_packages=cargo_packages,
        native_runtime_inventory=runtime_material.runtime_inventory,
        native_runtime_path_resolution=runtime_material.path_resolution.inventory,
        native_runtime_transitive_closure=runtime_material.transitive_closure.inventory,
        source_transformation_inventory=transformation_inventory,
        source_transformation_verification=replay.verification,
        analysis_input_verification=analysis_inputs,
        component_license_inventory=component_inventory,
        component_license_policy_verification=component_license_policy,
        project_source_license_policy_verification=source_license_policy,
    )
    if artifact_coverage is None:
        raise FullC6ProductionError("artifact policy coverage is incomplete")
    external_authority = _derive_external_authority(preflight)
    build_inputs = _build_input_closure(
        config=config,
        input_snapshot=input_snapshot,
        analysis_inputs=analysis_inputs,
        component_license_policy=component_license_policy,
        source_license_policy=source_license_policy,
        cargo_workspace=cargo_workspace,
    )
    analysis_transaction = _create_analysis_transaction(
        replay=replay,
        preflight=preflight,
        build_inputs=build_inputs,
    )
    executor_receipt = full_c6_native_output_executor_receipt(native_output)
    runtime_authorization = runtime_material.runtime_receipt
    aggregate = FullC6AuthorityAggregateBinding(
        analysis_ir_transaction_sha256=analysis_transaction.digest,
        license_materials_transaction_sha256=license_materials.digest,
        output_license_contract_sha256=(
            output_license_observation.output_contract_sha256
        ),
        cargo_workspace_sha256=cargo_workspace.digest,
        native_execution_authority_sha256=execution.digest,
        native_output_transaction_sha256=native_output.digest,
        subject_wheel_transaction_sha256=subject_wheel.digest,
        native_runtime_authority_sha256=native_runtime.digest,
        runtime_authorization_sha256=runtime_authorization.digest,
        executor_receipt_sha256=executor_receipt.digest,
    )
    cargo_path_source = FullC6CargoPathSource(
        name=toolchain.cargo_sources.root_package,
        version="0.1.0",
        source_tree_sha256=execution.frozen_tree.digest,
    )

    technical_template = _derive_technical_policy_template(
        preflight=preflight,
        license_materials=license_materials,
        coverage_inputs=coverage_inputs,
        analysis_inputs=analysis_inputs,
        component_license_policy=component_license_policy,
        source_license_policy=source_license_policy,
        cargo_packages=cargo_packages,
        cargo_path_source=cargo_path_source,
        subject=full_c6_native_output_subject(native_output),
        wheel_entries=full_c6_native_output_wheel_entries(native_output),
        native_runtime_inventory=runtime_material.runtime_inventory,
        native_runtime_closure=runtime_material.transitive_closure.inventory,
        artifact_coverage=artifact_coverage,
        external_authority=external_authority,
        analysis_transaction=analysis_transaction,
    )
    bootstrap_inputs = _bootstrap_inputs(
        preflight=preflight,
        analysis_transaction=analysis_transaction,
        artifact_coverage=artifact_coverage,
        external_authority=external_authority,
        build_inputs=build_inputs,
        cargo_workspace=cargo_workspace,
        license_materials=license_materials,
        target_triple=runtime_authorization.target_triple,
    )
    trusted_key_sha256 = config.build.artifact_trusted_public_key_sha256
    if type(trusted_key_sha256) is not str:
        raise FullC6ProductionError("trusted owner public-key digest is unavailable")
    bootstrap_request = create_full_c6_policy_bootstrap_request(
        inputs=bootstrap_inputs,
        trusted_owner_public_key_sha256=trusted_key_sha256,
        technical_template=technical_template,
    )

    policy: FullC6PolicyReceipt | None = None
    supply_chain: FullC6SupplyChainReceipt | None = None
    if lifecycle.status == "bootstrap-required":
        pass
    elif lifecycle.status in {"signing-required", "publication-required"}:
        policy = load_configured_full_c6_policy(project_root=root, config=config)
        _require_policy_matches_fresh_template(
            policy=policy,
            bootstrap_request=bootstrap_request,
        )
        _validate_analysis_transaction(
            analysis_transaction,
            preflight=preflight,
            build_inputs=build_inputs,
            policy=policy,
        )
        source = preflight.context.source_verification.context
        if source is None:
            raise FullC6ProductionError("SourceLock context is unavailable")
        supply_chain = build_full_c6_supply_chain_receipt(
            target_triple=runtime_authorization.target_triple,
            subject=full_c6_native_output_subject(native_output),
            build_inputs=build_inputs,
            wheel_entries=full_c6_native_output_wheel_entries(native_output),
            policy=policy,
            source_lock=source.manifest,
            source_admission=preflight.context.source_verification.admission,
            toolchain=toolchain,
            cargo_path_source=cargo_path_source,
            runtime_authorization=runtime_authorization,
            reproducibility=executor_receipt.reproducibility,
            authority_aggregate=aggregate,
            cargo_dependency_workspace=cargo_workspace,
        )
    else:
        raise FullC6ProductionError("Full C6 production lifecycle is disabled")

    return _FullC6ProductionMaterial(
        preflight=preflight,
        project_root=root,
        config=config,
        lifecycle=lifecycle,
        analysis_ir_transaction=analysis_transaction,
        license_materials_transaction=license_materials,
        output_license_contract=output_license,
        cargo_workspace=cargo_workspace,
        native_execution_authority=execution,
        native_output_transaction=native_output,
        subject_wheel_transaction=subject_wheel,
        native_runtime_authority=native_runtime,
        runtime_authorization=runtime_authorization,
        executor_receipt=executor_receipt,
        build_inputs=build_inputs,
        cargo_path_source=cargo_path_source,
        artifact_coverage=artifact_coverage,
        external_authority=external_authority,
        authority_aggregate=aggregate,
        technical_policy_template=technical_template,
        policy=policy,
        supply_chain=supply_chain,
        bootstrap_inputs=bootstrap_inputs,
        bootstrap_request=bootstrap_request,
    )


def _validate_material(material: _FullC6ProductionMaterial) -> bool:
    """Rebuild every retained digest and same-object authority binding."""
    if type(material) is not _FullC6ProductionMaterial:
        return False
    try:
        root = _require_project_root(material.preflight, material.project_root)
        if root != material.project_root or type(material.config) is not RextioConfig:
            return False
        if resolve_full_c6_policy_lifecycle(material.config) != material.lifecycle:
            return False
        validate_full_c6_external_context(
            material.preflight.context,
            material.preflight.analysis,
        )
        if not validate_full_c6_license_materials_transaction(
            material.license_materials_transaction
        ):
            return False
        if (
            not validate_full_c6_cargo_dependency_workspace_receipt(
                material.cargo_workspace
            )
            or type(material.build_inputs) is not BuildInputClosure
            or bind_full_c6_cargo_workspace_aggregates(
                bind_build_input_aggregate(
                    BuildInputClosure(files=material.build_inputs.files),
                    capture_effective_full_c6_config_identity(
                        material.config
                    ).to_build_input_aggregate(),
                ),
                material.cargo_workspace,
            )
            != material.build_inputs
            or type(material.artifact_coverage)
            is not ArtifactPolicyCoverageInventory
            or type(material.external_authority)
            is not FullC6ExternalAuthorityPartition
            or type(material.cargo_path_source) is not FullC6CargoPathSource
        ):
            return False
        source_context = material.preflight.context.source_verification.context
        if source_context is None:
            return False
        output_observation = validate_full_c6_output_license_contract(
            material.license_materials_transaction,
            material.output_license_contract,
            source_context=source_context,
        )
        if not validate_full_c6_native_execution_authority(
            material.native_execution_authority
        ):
            return False
        execution_material = _executor._validated_full_c6_native_output_material(
            material.native_execution_authority
        )
        if (
            execution_material.output_license_contract
            != material.output_license_contract
            or execution_material.cargo_workspace is not material.cargo_workspace
            or execution_material.toolchain.cargo_sources
            is not material.cargo_workspace.cargo_sources
            or material.cargo_path_source.name
            != execution_material.toolchain.cargo_sources.root_package
            or material.cargo_path_source.version != "0.1.0"
            or material.cargo_path_source.source_tree_sha256
            != material.native_execution_authority.frozen_tree.digest
        ):
            return False
        if not validate_full_c6_native_output_transaction(
            material.native_output_transaction
        ):
            return False
        if (
            material.native_output_transaction._authority
            is not material.native_execution_authority
            or material.native_output_transaction._subject_wheel
            is not material.subject_wheel_transaction
            or full_c6_native_output_cargo_workspace(
                material.native_output_transaction
            )
            is not material.cargo_workspace
            or full_c6_native_output_executor_receipt(
                material.native_output_transaction
            )
            is not material.executor_receipt
            or not validate_full_c6_subject_wheel_transaction(
                material.subject_wheel_transaction
            )
        ):
            return False
        if not validate_full_c6_native_runtime_authority(
            material.native_runtime_authority
        ):
            return False
        runtime_material = _native_runtime._validated_full_c6_native_runtime_material(
            material.native_runtime_authority
        )
        if (
            runtime_material.output_transaction
            is not material.native_output_transaction
            or runtime_material.runtime_receipt is not material.runtime_authorization
            or runtime_material.toolchain is not execution_material.toolchain
            or material.runtime_authorization.target_triple
            != material.executor_receipt.target_triple
        ):
            return False
        rebuilt_analysis = create_full_c6_analysis_ir_transaction(
            project_replay_authority=(
                material.analysis_ir_transaction._project_replay_authority
            ),
            source_verification=material.preflight.context.source_verification,
            build_inputs=material.build_inputs,
        )
        if rebuilt_analysis.to_dict() != material.analysis_ir_transaction.to_dict():
            return False
        expected_aggregate = FullC6AuthorityAggregateBinding(
            analysis_ir_transaction_sha256=material.analysis_ir_transaction.digest,
            license_materials_transaction_sha256=(
                material.license_materials_transaction.digest
            ),
            output_license_contract_sha256=(
                output_observation.output_contract_sha256
            ),
            cargo_workspace_sha256=material.cargo_workspace.digest,
            native_execution_authority_sha256=(
                material.native_execution_authority.digest
            ),
            native_output_transaction_sha256=(
                material.native_output_transaction.digest
            ),
            subject_wheel_transaction_sha256=(
                material.subject_wheel_transaction.digest
            ),
            native_runtime_authority_sha256=(
                material.native_runtime_authority.digest
            ),
            runtime_authorization_sha256=material.runtime_authorization.digest,
            executor_receipt_sha256=material.executor_receipt.digest,
        )
        if expected_aggregate != material.authority_aggregate:
            return False
        expected_inputs = _bootstrap_inputs(
            preflight=material.preflight,
            analysis_transaction=material.analysis_ir_transaction,
            artifact_coverage=material.artifact_coverage,
            external_authority=material.external_authority,
            build_inputs=material.build_inputs,
            cargo_workspace=material.cargo_workspace,
            license_materials=material.license_materials_transaction,
            target_triple=material.runtime_authorization.target_triple,
        )
        trusted_key = material.config.build.artifact_trusted_public_key_sha256
        if type(trusted_key) is not str:
            return False
        expected_request = create_full_c6_policy_bootstrap_request(
            inputs=expected_inputs,
            trusted_owner_public_key_sha256=trusted_key,
            technical_template=material.technical_policy_template,
        )
        if (
            material.bootstrap_inputs != expected_inputs
            or material.bootstrap_request != expected_request
            or type(material.bootstrap_request) is not FullC6PolicyBootstrapRequest
            or material.bootstrap_request.inputs is not material.bootstrap_inputs
            or material.bootstrap_request.technical_template
            is not material.technical_policy_template
        ):
            return False
        if material.lifecycle.status == "bootstrap-required":
            return (
                material.policy is None
                and material.supply_chain is None
            )
        if material.lifecycle.status not in {"signing-required", "publication-required"}:
            return False
        if (
            type(material.policy) is not FullC6PolicyReceipt
        ):
            return False
        _require_policy_matches_fresh_template(
            policy=material.policy,
            bootstrap_request=material.bootstrap_request,
        )
        _validate_analysis_transaction(
            material.analysis_ir_transaction,
            preflight=material.preflight,
            build_inputs=material.build_inputs,
            policy=material.policy,
        )
        return (
            type(material.supply_chain) is FullC6SupplyChainReceipt
            and verify_full_c6_supply_chain_receipt(
                material.supply_chain,
                cargo_dependency_workspace=material.cargo_workspace,
            )
            is not None
            and material.supply_chain.authority_aggregate
            == material.authority_aggregate
        )
    except Exception:
        return False


def _require_production_inputs(
    *,
    preflight: FullC6ExternalPreflightResult,
    project_root: Path | str,
    config: RextioConfig,
    toolchain: BuildToolchainIdentity,
    native_tools: FullC6NativeToolPaths,
    cargo_workspace: FullC6CargoDependencyWorkspaceReceipt,
    source_date_epoch: int,
) -> Path:
    if (
        type(config) is not RextioConfig
        or type(toolchain) is not BuildToolchainIdentity
        or type(native_tools) is not FullC6NativeToolPaths
        or type(cargo_workspace) is not FullC6CargoDependencyWorkspaceReceipt
        or not validate_full_c6_cargo_dependency_workspace_receipt(cargo_workspace)
        or type(source_date_epoch) is not int
        or isinstance(source_date_epoch, bool)
        # The executor binds this value into both invocation environments.
        or not (0 <= source_date_epoch <= _MAX_SOURCE_DATE_EPOCH)
    ):
        raise FullC6ProductionError("Full C6 production prerequisites are invalid")
    if toolchain.cargo_sources is not cargo_workspace.cargo_sources:
        raise FullC6ProductionError("toolchain and Cargo workspace differ")
    try:
        capture_effective_full_c6_config_identity(config)
    except FullC6ConfigIdentityError as exc:
        raise FullC6ProductionError(
            "Full C6 effective config is not canonical"
        ) from exc
    root = _require_project_root(preflight, project_root)
    validate_full_c6_external_context(preflight.context, preflight.analysis)
    lifecycle = resolve_full_c6_policy_lifecycle(config)
    if lifecycle.status == "disabled":
        raise FullC6ProductionError("Full C6 production lifecycle is disabled")
    return root


def _require_project_root(
    preflight: FullC6ExternalPreflightResult,
    project_root: Path | str,
) -> Path:
    if type(preflight) is not FullC6ExternalPreflightResult:
        raise FullC6ProductionError("Full C6 production requires exact preflight")
    candidate = Path(project_root)
    authority_root = preflight.analysis.project_root
    if (
        not isinstance(authority_root, Path)
        or candidate != authority_root
        or candidate.resolve(strict=True) != authority_root.resolve(strict=True)
    ):
        raise FullC6ProductionError(
            "project root differs from the exact preflight root"
        )
    return candidate


def _regenerate_production_inputs(
    *,
    root: Path,
    preflight: FullC6ExternalPreflightResult,
    config: RextioConfig,
    cargo_workspace: FullC6CargoDependencyWorkspaceReceipt,
    execution: FullC6NativeExecutionAuthority,
) -> tuple[_orchestrator.GenerateResult, EvidenceInputSnapshot]:
    target_plan = create_target_plan(root, config)
    generated = _orchestrator.generate_source_artifact(
        root,
        preflight.analysis,
        "cpython",
        boundary_fallback_threshold=config.build.fallback_threshold,
        target_plan=target_plan,
        full_c6_external_context=preflight.context,
    )
    if (
        type(generated) is not _orchestrator.GenerateResult
        or generated.plan.analysis is not preflight.analysis
        or generated.native_source.status != "generated"
        or generated.plugin_crate_dependencies
    ):
        raise FullC6ProductionError("deterministic source regeneration failed")
    snapshot = capture_project_source_snapshot(
        project_root=root,
        plan=generated.plan,
    )
    snapshot = capture_generated_python_inputs(
        snapshot,
        project_root=root,
        layout=generated.layout,
    )
    snapshot = capture_generated_rust_inputs(
        snapshot,
        project_root=root,
        layout=generated.layout,
    )
    # The template config is deliberately removed before C5.2 execution; the
    # owner-prepared sealed workspace config is bound as a Cargo aggregate.
    generated_rust = tuple(
        item
        for item in snapshot.generated_rust
        if not item.logical_path.endswith("/.cargo/config.toml")
    )
    lock = cargo_workspace.cargo_sources.lock_file
    snapshot = replace(
        snapshot,
        generated_rust=generated_rust,
        cargo_lock=EvidenceFileRef(
            logical_path=lock.logical_name,
            sha256=lock.sha256,
            size=lock.size,
            role="generated-cargo-lock",
        ),
    )
    if snapshot.unavailable_reason is not None:
        raise FullC6ProductionError("production build-input snapshot is unavailable")
    _require_regenerated_execution_bindings(
        generated=generated,
        snapshot=snapshot,
        execution=execution,
    )
    return generated, snapshot


def _require_regenerated_execution_bindings(
    *,
    generated: _orchestrator.GenerateResult,
    snapshot: EvidenceInputSnapshot,
    execution: FullC6NativeExecutionAuthority,
) -> None:
    expected: dict[str, tuple[str, int, bool]] = {}
    for item in snapshot.generated_python:
        relative = (generated.layout.root / item.logical_path).relative_to(
            generated.layout.python_dir
        )
        expected[f"python-staging/{relative.as_posix()}"] = (
            item.sha256,
            item.size,
            False,
        )
    for item in snapshot.generated_rust:
        relative = (generated.layout.root / item.logical_path).relative_to(
            generated.layout.rust_dir
        )
        expected[relative.as_posix()] = (item.sha256, item.size, item.executable if hasattr(item, "executable") else False)
    if snapshot.cargo_lock is None:
        raise FullC6ProductionError("production Cargo.lock identity is absent")
    expected["Cargo.lock"] = (
        snapshot.cargo_lock.sha256,
        snapshot.cargo_lock.size,
        False,
    )
    observed = {
        item.logical_name: (
            item.sha256 or "",
            item.size,
            item.mode == 0o755,
        )
        for item in execution.frozen_tree.entries
        if item.kind == "file"
        and item.logical_name != _executor.FULL_C6_NATIVE_DRIVER_MANIFEST
    }
    if expected != observed:
        raise FullC6ProductionError(
            "regenerated sources differ from the executed frozen tree"
        )


def _cargo_package_refs(
    workspace: FullC6CargoDependencyWorkspaceReceipt,
    *,
    root_name: str,
) -> tuple[CargoPackageRef, ...]:
    payloads = dict(workspace.metadata_payloads())
    packages: list[CargoPackageRef] = [
        CargoPackageRef(
            name=root_name,
            version="0.1.0",
            source=None,
            checksum=None,
            kind="path-root",
            features=(),
            license=None,
            package_id="path-root",
        )
    ]
    for receipt in workspace.packages:
        payload = payloads.get(receipt.cargo_toml)
        if payload is None:
            raise FullC6ProductionError("Cargo package manifest is unavailable")
        document = tomllib.loads(payload.decode("utf-8"))
        package = document.get("package")
        if not isinstance(package, dict):
            raise FullC6ProductionError("Cargo package manifest is invalid")
        license_value = package.get("license")
        if license_value is not None and not isinstance(license_value, str):
            raise FullC6ProductionError("Cargo package license is invalid")
        source = receipt.package
        packages.append(
            CargoPackageRef(
                name=source.name,
                version=source.version,
                source=source.source,
                checksum=source.checksum,
                kind="registry",
                features=(),
                license=license_value,
                package_id="registry",
            )
        )
    return tuple(sorted(packages, key=lambda item: item.bom_ref()))


def _build_input_closure(
    *,
    config: RextioConfig,
    input_snapshot: EvidenceInputSnapshot,
    analysis_inputs: object,
    component_license_policy: object,
    source_license_policy: object,
    cargo_workspace: FullC6CargoDependencyWorkspaceReceipt,
) -> BuildInputClosure:
    refs = list(input_snapshot.all_inputs)
    records = getattr(analysis_inputs, "records")
    refs.extend(
        record.stub
        for record in records
        if record.state == "present" and record.stub is not None
    )
    refs.extend(
        (
            getattr(component_license_policy, "lock_file"),
            getattr(source_license_policy, "lock_file"),
        )
    )
    aliases: set[str] = set()
    canonical_refs: list[tuple[EvidenceFileRef, str]] = []
    for item in refs:
        if type(item) is not EvidenceFileRef:
            raise FullC6ProductionError("production build input is invalid")
        logical_name = canonical_full_c6_build_input_name(
            item.logical_path,
            item.role,
        )
        alias = unicodedata.normalize("NFC", logical_name).casefold()
        if alias in aliases:
            raise FullC6ProductionError("production build inputs overlap")
        aliases.add(alias)
        canonical_refs.append((item, logical_name))
    files = [
        ExactFileIdentity(
            logical_name=logical_name,
            role=item.role,
            sha256=item.sha256,
            size=item.size,
            executable=False,
        )
        for item, logical_name in canonical_refs
    ]
    closure = BuildInputClosure(
        files=tuple(sorted(files, key=lambda item: (item.role, item.logical_name)))
    )
    closure = bind_build_input_aggregate(
        closure,
        capture_effective_full_c6_config_identity(
            config
        ).to_build_input_aggregate(),
    )
    return bind_full_c6_cargo_workspace_aggregates(closure, cargo_workspace)


def _create_analysis_transaction(
    *,
    replay: object,
    preflight: FullC6ExternalPreflightResult,
    build_inputs: BuildInputClosure,
) -> FullC6AnalysisIRTransaction:
    return create_full_c6_analysis_ir_transaction(
        project_replay_authority=replay,  # type: ignore[arg-type]
        source_verification=preflight.context.source_verification,
        build_inputs=build_inputs,
    )


def _validate_analysis_transaction(
    transaction: FullC6AnalysisIRTransaction,
    *,
    preflight: FullC6ExternalPreflightResult,
    build_inputs: BuildInputClosure,
    policy: FullC6PolicyReceipt,
) -> None:
    validate_full_c6_analysis_ir_transaction(
        transaction,
        source_verification=preflight.context.source_verification,
        build_inputs=build_inputs,
        policy=policy,
    )


def _derive_external_authority(
    preflight: FullC6ExternalPreflightResult,
) -> FullC6ExternalAuthorityPartition:
    source = preflight.context.source_verification.context
    if source is None:
        raise FullC6ProductionError("SourceLock context is unavailable")
    values: dict[str, list[dict[str, object]]] = {
        class_id: [] for class_id in FULL_C6_EXTERNAL_POLICY_CLASS_IDS
    }
    archive = source.manifest.archive
    values["external-source:wheel-archive"].append(
        {
            "logical_name": f"external/{archive.filename}",
            "sha256": archive.sha256,
            "size": archive.size,
        }
    )
    source_paths = set(source.wheel.source_entry_paths)
    license_paths = set(source.wheel.license_entry_paths)
    for entry in source.manifest.entries:
        if entry.path in source_paths:
            class_id = "external-source:python-source"
        elif entry.path in license_paths:
            class_id = "external-source:license-file"
        else:
            class_id = "external-source:distribution-metadata"
        values[class_id].append(
            {
                "logical_name": f"external/{entry.path}",
                "sha256": entry.sha256,
                "size": entry.size,
            }
        )
    classes: list[FullC6ExternalAuthorityClass] = []
    for class_id in FULL_C6_EXTERNAL_POLICY_CLASS_IDS:
        identities = tuple(
            sorted(
                full_c6_external_authority_identity(class_id, value)
                for value in values[class_id]
            )
        )
        classes.append(
            FullC6ExternalAuthorityClass(
                class_id=class_id,
                observed_count=len(identities),
                canonical_identity_set_sha256=(
                    full_c6_external_authority_identity_set_digest(
                        class_id,
                        identities,
                    )
                ),
            )
        )
    frozen = tuple(classes)
    return FullC6ExternalAuthorityPartition(
        classes=frozen,
        observed_component_count=sum(item.observed_count for item in frozen),
        canonical_partition_sha256=(
            full_c6_external_authority_partition_digest(frozen)
        ),
    )


def _derive_technical_policy_template(
    *,
    preflight: FullC6ExternalPreflightResult,
    license_materials: FullC6LicenseMaterialsTransaction,
    coverage_inputs: tuple[EvidenceFileRef, ...],
    analysis_inputs: AnalysisInputVerification,
    component_license_policy: ComponentLicensePolicyVerification,
    source_license_policy: ProjectSourceLicensePolicyVerification,
    cargo_packages: tuple[CargoPackageRef, ...],
    cargo_path_source: FullC6CargoPathSource,
    subject: EvidenceFileRef,
    wheel_entries: tuple[WheelEntryRef, ...],
    native_runtime_inventory: NativeRuntimeInventory,
    native_runtime_closure: NativeRuntimeTransitiveClosureInventory,
    artifact_coverage: ArtifactPolicyCoverageInventory,
    external_authority: FullC6ExternalAuthorityPartition,
    analysis_transaction: FullC6AnalysisIRTransaction,
) -> FullC6TechnicalPolicyTemplate:
    """Derive the serializable owner handoff from the same retained graph."""
    internal_license_observations = _derive_internal_license_observations(
        license_materials
    )
    project_license = next(
        item
        for item in internal_license_observations
        if item.subject_kind == "project"
    )
    cargo_licenses = {
        item.subject_canonical_identity: item
        for item in internal_license_observations
        if item.subject_kind == "cargo-registry-package"
    }
    rows: list[FullC6TechnicalPolicyRow] = []

    def add_artifact(
        class_id: str,
        canonical_identity: str,
        payload: object,
        sha256: str | None,
        size: int | None,
    ) -> None:
        license_observation = (
            cargo_licenses.get(canonical_identity)
            if class_id == "cargo-component:registry-package"
            else project_license
        )
        if license_observation is None:
            raise FullC6ProductionError(
                "technical row lacks exact Cargo license materials"
            )
        rows.append(
            _technical_row(
                class_id=class_id,
                canonical_identity=canonical_identity,
                authority_identity=full_c6_artifact_authority_identity(
                    class_id,
                    payload,
                ),
                sha256=sha256,
                size=size,
                license_observation_sha256=(
                    license_observation.observation_sha256
                ),
            )
        )

    for item in coverage_inputs:
        if item.role == "project-python-source":
            class_id = "file-input:project-python-source"
        elif item.role == "generated-python-input":
            class_id = "file-input:generated-python-input"
        elif item.role == "generated-rust-input":
            class_id = (
                "file-input:generated-rust-lib"
                if Path(item.logical_path).parts[-2:] == ("src", "lib.rs")
                else "file-input:generated-rust-build-input"
            )
        elif item.role == "generated-cargo-lock":
            class_id = "file-input:generated-cargo-lock"
        else:
            raise FullC6ProductionError("technical template input role is unsupported")
        add_artifact(
            class_id,
            canonical_full_c6_build_input_name(item.logical_path, item.role),
            item.to_dict(),
            item.sha256,
            item.size,
        )
    for record in analysis_inputs.records:
        if record.state == "present":
            if record.stub is None:
                raise FullC6ProductionError("technical template present stub is absent")
            item = record.stub
            add_artifact(
                "file-input:present-project-python-stub",
                canonical_full_c6_build_input_name(item.logical_path, item.role),
                item.to_dict(),
                item.sha256,
                item.size,
            )
    for item in (component_license_policy.lock_file, source_license_policy.lock_file):
        add_artifact(
            "file-input:policy-lock",
            canonical_full_c6_build_input_name(item.logical_path, item.role),
            item.to_dict(),
            item.sha256,
            item.size,
        )
    for package in cargo_packages:
        if package.kind == "registry":
            class_id = "cargo-component:registry-package"
            canonical_identity = f"cargo:{package.name}@{package.version}#registry"
            package_sha256 = package.checksum
        elif package.kind == "path-root":
            class_id = "cargo-component:path-root-package"
            canonical_identity = cargo_path_source.canonical_identity
            package_sha256 = cargo_path_source.source_tree_sha256
        else:
            raise FullC6ProductionError("technical template Cargo package is unsupported")
        add_artifact(
            class_id,
            canonical_identity,
            package.to_dict(),
            package_sha256,
            None,
        )
    packaged_members = {native_runtime_inventory.wheel_member}
    packaged_members.update(
        node.wheel_member
        for node in native_runtime_closure.nodes
        if node.kind == "wheel-member" and node.wheel_member is not None
    )
    for entry in wheel_entries:
        class_id = (
            "wheel-entry:packaged-native-runtime-member"
            if entry.name in packaged_members
            else "wheel-entry:other"
        )
        add_artifact(
            class_id,
            f"wheel/{entry.name}",
            entry.to_dict(),
            entry.sha256,
            entry.uncompressed_size,
        )
    for node in native_runtime_closure.nodes:
        if node.kind == "system-logical":
            add_artifact(
                "native-runtime:logical-system-leaf",
                f"system:{node.name}",
                node.to_dict(),
                None,
                None,
            )
    add_artifact(
        "wheel-output:subject",
        subject.logical_path,
        subject.to_dict(),
        subject.sha256,
        subject.size,
    )

    source = preflight.context.source_verification.context
    if source is None:
        raise FullC6ProductionError("technical template SourceLock context is unavailable")
    archive = source.manifest.archive
    external_values: list[tuple[str, dict[str, object]]] = [
        (
            "external-source:wheel-archive",
            {
                "logical_name": f"external/{archive.filename}",
                "sha256": archive.sha256,
                "size": archive.size,
            },
        )
    ]
    source_paths = set(source.wheel.source_entry_paths)
    license_paths = set(source.wheel.license_entry_paths)
    for source_entry in source.manifest.entries:
        class_id = (
            "external-source:python-source"
            if source_entry.path in source_paths
            else (
                "external-source:license-file"
                if source_entry.path in license_paths
                else "external-source:distribution-metadata"
            )
        )
        external_values.append(
            (
                class_id,
                {
                    "logical_name": f"external/{source_entry.path}",
                    "sha256": source_entry.sha256,
                    "size": source_entry.size,
                },
            )
        )
    external_license_observation = _derive_external_license_observation(preflight)
    for class_id, payload in external_values:
        payload_size = payload["size"]
        if type(payload_size) is not int:
            raise FullC6ProductionError("external technical row size is invalid")
        rows.append(
            _technical_row(
                class_id=class_id,
                canonical_identity=str(payload["logical_name"]),
                authority_identity=full_c6_external_authority_identity(
                    class_id,
                    payload,
                ),
                sha256=str(payload["sha256"]),
                size=payload_size,
                license_observation_sha256=(
                    external_license_observation.observation_sha256
                ),
            )
        )

    class_order = {
        class_id: index for index, class_id in enumerate(
            (*ARTIFACT_POLICY_COVERAGE_CLASS_IDS, *FULL_C6_EXTERNAL_POLICY_CLASS_IDS)
        )
    }
    frozen_rows = tuple(
        sorted(
            rows,
            key=lambda item: (
                class_order[item.class_id],
                item.authority_identity,
                item.canonical_identity.casefold(),
            ),
        )
    )
    transformations = _derive_technical_transformations(
        frozen_rows,
        analysis_transaction=analysis_transaction,
        authority_partition_sha256=full_c6_authority_partition_digest(
            artifact_coverage,
            external_authority,
        ),
    )
    return FullC6TechnicalPolicyTemplate(
        artifact_coverage=artifact_coverage,
        external_authority=external_authority,
        rows=frozen_rows,
        transformations=transformations,
        internal_license_observations=internal_license_observations,
        external_license_observation=external_license_observation,
        observed_owner_identity=source.manifest.owner,
    )


def _technical_row(
    *,
    class_id: str,
    canonical_identity: str,
    authority_identity: str,
    sha256: str | None,
    size: int | None,
    license_observation_sha256: str,
) -> FullC6TechnicalPolicyRow:
    license_disposition = full_c6_policy_license_disposition(class_id)
    return FullC6TechnicalPolicyRow(
        class_id=class_id,
        canonical_identity=canonical_identity,
        authority_identity=authority_identity,
        identity_mode=full_c6_policy_identity_mode(class_id),
        sha256=sha256,
        size=size,
        required_license_disposition=license_disposition,
        transformation_disposition=full_c6_policy_transformation_disposition(class_id),
        license_evidence_origin=(
            "not-applicable"
            if license_disposition != "owner-approved-allow"
            else (
                "production-external-observation"
                if class_id in FULL_C6_EXTERNAL_POLICY_CLASS_IDS
                else "owner-project-observation"
            )
        ),
        license_observation_sha256=(
            None
            if license_disposition != "owner-approved-allow"
            else license_observation_sha256
        ),
    )


def _derive_technical_transformations(
    rows: tuple[FullC6TechnicalPolicyRow, ...],
    *,
    analysis_transaction: FullC6AnalysisIRTransaction,
    authority_partition_sha256: str,
) -> tuple[FullC6TransformationRecord, ...]:
    source_classes = {
        "file-input:project-python-source",
        "file-input:present-project-python-stub",
        "external-source:python-source",
    }
    output_kinds = {
        "file-input:generated-python-input": "python-wrapper-generation-v1",
        "file-input:generated-rust-lib": "python-to-rust-lowering-v1",
        "file-input:generated-rust-build-input": "python-to-rust-lowering-v1",
    }
    sources = tuple(
        sorted(
            (row for row in rows if row.class_id in source_classes),
            key=lambda item: item.authority_identity,
        )
    )
    source_identities = tuple(item.authority_identity for item in sources)
    source_sha256s = tuple(item.canonical_identity_sha256 for item in sources)
    source_set_sha256 = full_c6_transformation_source_set_digest(
        source_identities,
        source_sha256s,
    )
    outputs = tuple(item for item in rows if item.class_id in output_kinds)
    records: list[FullC6TransformationRecord] = []
    for index, output in enumerate(outputs, start=1):
        kind = output_kinds[output.class_id]
        analysis_receipt = full_c6_analysis_receipt_digest(
            authority_partition_sha256=authority_partition_sha256,
            source_identity_set_sha256=source_set_sha256,
            output_identity_sha256=output.canonical_identity_sha256,
            analysis_sha256=analysis_transaction.analysis_sha256,
        )
        lowered_ir = analysis_transaction.lowered_ir_sha256(
            transformation_kind=kind,
            output_identity=output.authority_identity,
            output_identity_sha256=output.canonical_identity_sha256,
        )
        records.append(
            FullC6TransformationRecord(
                record_id=f"transformation/{index:04d}",
                kind=kind,
                source_identities=source_identities,
                source_identity_sha256s=source_sha256s,
                output_identity=output.authority_identity,
                output_identity_sha256=output.canonical_identity_sha256,
                authority_partition_sha256=authority_partition_sha256,
                source_identity_set_sha256=source_set_sha256,
                generator_sha256=analysis_transaction.generator_sha256,
                analysis_sha256=analysis_transaction.analysis_sha256,
                analysis_receipt_sha256=analysis_receipt,
                lowered_ir_sha256=lowered_ir,
                lowered_ir_receipt_sha256=full_c6_lowered_ir_receipt_digest(
                    authority_partition_sha256=authority_partition_sha256,
                    transformation_kind=kind,
                    source_identity_set_sha256=source_set_sha256,
                    output_identity_sha256=output.canonical_identity_sha256,
                    generator_sha256=analysis_transaction.generator_sha256,
                    analysis_receipt_sha256=analysis_receipt,
                    lowered_ir_sha256=lowered_ir,
                ),
            )
        )
    return tuple(records)


def _derive_external_license_observation(
    preflight: FullC6ExternalPreflightResult,
) -> FullC6ExternalLicenseObservation:
    source = preflight.context.source_verification.context
    if source is None:
        raise FullC6ProductionError("external license SourceLock context is unavailable")
    detection = source.wheel.license_detection
    if (
        not verify_source_wheel_license_detection(
            detection,
            source.wheel.license_entry_paths,
            source.wheel.license_payloads,
        )
        or detection.status != "detected"
        or detection.detected_spdx is None
    ):
        raise FullC6ProductionError("external license observation is incomplete")
    entries = {item.path: item for item in source.wheel.entries}
    files: list[FullC6PolicyFileIdentity] = []
    for path, payload in zip(
        source.wheel.license_entry_paths,
        source.wheel.license_payloads,
        strict=True,
    ):
        entry = entries.get(path)
        digest = hashlib.sha256(payload).hexdigest()
        if entry is None or entry.sha256 != digest or entry.size != len(payload):
            raise FullC6ProductionError("external license bytes changed")
        files.append(
            FullC6PolicyFileIdentity(
                logical_path=f"external/{path}",
                sha256=digest,
                size=len(payload),
                role="license-file",
            )
        )
    frozen = tuple(sorted(files, key=lambda item: item.logical_path.casefold()))
    source_receipt = detection.semantic_sha256
    return FullC6ExternalLicenseObservation(
        declared_spdx=source.manifest.declared_license,
        detected_spdx=detection.detected_spdx,
        source_detector_receipt_sha256=source_receipt,
        detector_payload_sha256=full_c6_license_detector_payload_digest(
            detection.detected_spdx,
            frozen,
            source_detector_receipt_sha256=source_receipt,
        ),
        license_files=frozen,
    )


def _derive_internal_license_observations(
    license_materials: FullC6LicenseMaterialsTransaction,
) -> tuple[FullC6InternalLicenseObservation, ...]:
    if not validate_full_c6_license_materials_transaction(license_materials):
        raise FullC6ProductionError("internal license materials are stale")
    observations: list[FullC6InternalLicenseObservation] = []
    for source in (license_materials.project, *license_materials.cargo_packages):
        files = tuple(
            sorted(
                (
                    FullC6PolicyFileIdentity(
                        logical_path=item.logical_name,
                        sha256=item.sha256,
                        size=item.size,
                        role="license-file",
                    )
                    for item in source.license_files
                ),
                key=lambda item: item.logical_path.casefold(),
            )
        )
        source_receipt = source.detector_receipt_sha256
        subject_identity = (
            f"project:{source.name}@{source.version or 'unversioned'}"
            if source.subject_kind == "project"
            else f"cargo:{source.name}@{source.version}#registry"
        )
        observations.append(
            FullC6InternalLicenseObservation(
                subject_kind=cast(
                    Literal["project", "cargo-registry-package"],
                    source.subject_kind,
                ),
                subject_canonical_identity=subject_identity,
                declared_spdx=source.declared_spdx,
                detected_spdx=source.observed_spdx,
                source_detector_receipt_sha256=source_receipt,
                detector_payload_sha256=full_c6_license_detector_payload_digest(
                    source.observed_spdx,
                    files,
                    source_detector_receipt_sha256=source_receipt,
                ),
                license_files=files,
            )
        )
    return tuple(
        sorted(
            observations,
            key=lambda item: (
                item.subject_kind,
                item.subject_canonical_identity.casefold(),
                item.observation_sha256,
            ),
        )
    )


def _require_policy_matches_fresh_template(
    *,
    policy: FullC6PolicyReceipt,
    bootstrap_request: FullC6PolicyBootstrapRequest,
) -> None:
    template = bootstrap_request.technical_template
    if policy.bootstrap_request_sha256 != bootstrap_request.request_sha256:
        raise FullC6ProductionError("owner policy bootstrap lineage is stale")
    if (
        policy.artifact_coverage != template.artifact_coverage
        or policy.external_authority != template.external_authority
        or policy.transformations != template.transformations
        or len(policy.rows) != len(template.rows)
    ):
        raise FullC6ProductionError("owner policy differs from fresh technical template")
    for actual, observed in zip(policy.rows, template.rows, strict=True):
        if (
            actual.class_id,
            actual.canonical_identity,
            actual.authority_identity,
            actual.identity_mode,
            actual.sha256,
            actual.size,
            actual.license_disposition,
            actual.transformation_disposition,
        ) != (
            observed.class_id,
            observed.canonical_identity,
            observed.authority_identity,
            observed.identity_mode,
            observed.sha256,
            observed.size,
            observed.required_license_disposition,
            observed.transformation_disposition,
        ):
            raise FullC6ProductionError("owner policy row differs from fresh observation")
        if observed.required_license_disposition == "owner-approved-allow":
            observation: (
                FullC6ExternalLicenseObservation | FullC6InternalLicenseObservation
            )
            if observed.license_evidence_origin == "production-external-observation":
                observation = template.external_license_observation
            else:
                matches = tuple(
                    item
                    for item in template.internal_license_observations
                    if item.observation_sha256
                    == observed.license_observation_sha256
                )
                if len(matches) != 1:
                    raise FullC6ProductionError(
                        "owner policy internal license observation is stale"
                    )
                observation = matches[0]
            evidence = actual.license_evidence
            if (
                evidence is None
                or evidence.declared_spdx != observation.declared_spdx
                or evidence.detected_spdx != observation.detected_spdx
                or evidence.source_detector_receipt_sha256
                != observation.source_detector_receipt_sha256
                or evidence.detector_payload_sha256
                != observation.detector_payload_sha256
                or evidence.license_files != observation.license_files
            ):
                raise FullC6ProductionError(
                    "owner policy evidence differs from fresh exact license bytes"
                )


def _bootstrap_inputs(
    *,
    preflight: FullC6ExternalPreflightResult,
    analysis_transaction: FullC6AnalysisIRTransaction,
    artifact_coverage: ArtifactPolicyCoverageInventory,
    external_authority: FullC6ExternalAuthorityPartition,
    build_inputs: BuildInputClosure,
    cargo_workspace: FullC6CargoDependencyWorkspaceReceipt,
    license_materials: FullC6LicenseMaterialsTransaction,
    target_triple: str,
) -> FullC6PolicyBootstrapInputs:
    transformation_classes = {
        "file-input:generated-python-input",
        "file-input:generated-rust-lib",
        "file-input:generated-rust-build-input",
    }
    required_transformations = sum(
        item.observed_count
        for item in artifact_coverage.classes
        if item.class_id in transformation_classes
    )
    return FullC6PolicyBootstrapInputs(
        analysis_ir_transaction_sha256=analysis_transaction.digest,
        artifact_coverage_inventory_sha256=(
            artifact_policy_coverage_inventory_digest(artifact_coverage)
        ),
        artifact_authority_partition_sha256=(
            artifact_coverage.canonical_partition_sha256
        ),
        build_input_closure_sha256=build_inputs.digest,
        cargo_workspace_sha256=cargo_workspace.digest,
        combined_authority_partition_sha256=full_c6_authority_partition_digest(
            artifact_coverage,
            external_authority,
        ),
        external_authority_partition_sha256=(
            external_authority.canonical_partition_sha256
        ),
        license_materials_transaction_sha256=license_materials.digest,
        source_lock_verification_sha256=_digest(
            preflight.context.source_verification.to_dict()
        ),
        artifact_class_observed_counts=tuple(
            item.observed_count for item in artifact_coverage.classes
        ),
        external_class_observed_counts=tuple(
            item.observed_count for item in external_authority.classes
        ),
        artifact_observed_component_count=(
            artifact_coverage.observed_component_count
        ),
        external_observed_component_count=(
            external_authority.observed_component_count
        ),
        required_transformation_count=required_transformations,
        target_triple=target_triple,
    )


def _material_projection(material: _FullC6ProductionMaterial) -> dict[str, object]:
    lifecycle = material.lifecycle
    aggregate = material.authority_aggregate
    return {
        "domain": FULL_C6_PRODUCTION_AUTHORITY_DOMAIN,
        "authority": "process-sealed-production-evidence-only",
        "lifecycle_status": lifecycle.status,
        "authority_aggregate": aggregate.to_dict(),
        "build_input_closure_sha256": material.build_inputs.digest,
        "artifact_coverage_inventory_sha256": (
            artifact_policy_coverage_inventory_digest(material.artifact_coverage)
        ),
        "external_authority_partition_sha256": (
            material.external_authority.canonical_partition_sha256
        ),
        "policy_sha256": material.policy.digest if material.policy is not None else None,
        "supply_chain_sha256": (
            material.supply_chain.digest if material.supply_chain is not None else None
        ),
        "bootstrap_request_sha256": (
            material.bootstrap_request.request_sha256
        ),
        "technical_policy_template_sha256": (
            material.technical_policy_template.template_sha256
        ),
        "executor_invocation_count": len(material.executor_receipt.invocations),
        "complete_for_scope": True,
        "signed": False,
        "distribution_authorized": False,
        "authorizes_distribution": False,
    }


def _seal(authority: FullC6ProductionAuthority) -> bytes:
    material = authority._material
    payload = {
        "semantic": _material_projection(material),
        "object_ids": {
            "material": id(material),
            **{
            name: id(getattr(material, name))
            for name in (
                "preflight",
                "config",
                "analysis_ir_transaction",
                "license_materials_transaction",
                "output_license_contract",
                "cargo_workspace",
                "native_execution_authority",
                "native_output_transaction",
                "subject_wheel_transaction",
                "native_runtime_authority",
                "runtime_authorization",
                "executor_receipt",
                "build_inputs",
                "authority_aggregate",
                "technical_policy_template",
                "bootstrap_inputs",
                "bootstrap_request",
            )
            },
        },
        "project_root_sha256": hashlib.sha256(
            str(material.project_root).encode("utf-8")
        ).hexdigest(),
    }
    return hmac.new(_SEAL_KEY, canonical_json_bytes(payload), hashlib.sha256).digest()


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


__all__ = [
    "FULL_C6_PRODUCTION_AUTHORITY_DOMAIN",
    "FullC6ProductionAuthority",
    "FullC6ProductionError",
    "collect_full_c6_production_authority",
    "validate_full_c6_production_authority",
]
