"""Strict C5.2 preflight and Full C6 signing/publication coordination.

This module is the bridge between the deliberately small C5.2 external-source
surface and the Full C6 hard gate.  It has two independent responsibilities:

* verify one exact SourceLock v2 transaction, construct the external native
  call registry/runtime guard/output-wheel contract, and require a fresh
  project analysis before any of those objects may enter the build
  orchestrator; and
* turn an already completed strict two-build transaction plus an explicit
  :class:`FullC6PolicyReceipt` into the canonical final signing request.  An
  unsigned run writes only that request.  A signed run must pass the sealed
  gate before the atomic publication adapter is called.

The policy receipt is intentionally a typed programmatic input.  C6 preview
evidence and ``rextio.toml`` do not contain enough authority to reconstruct a
complete SPDX/license/transformation policy, so this module never guesses one.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
import hmac
import os
from pathlib import Path, PurePosixPath
import stat
from typing import TypeAlias, cast

from rextio.analyzer.models import ProjectAnalysis
from rextio.artifacts.evidence import EvidenceFileRef, WheelEntryRef, canonical_json_bytes
from rextio.artifacts.full_authorization import full_c6_preauthorization_evidence_digest
from rextio.build.full_c6_executor import FullC6ExecutorReceipt
from rextio.build.full_c6_gate import (
    FullC6GateResult,
    authorize_full_c6_distribution,
    prepare_full_c6_preauthorization_evidence,
)
from rextio.build.full_c6_policy import FullC6PolicyReceipt
from rextio.build.full_c6_publication import FullC6PublicationReceipt
from rextio.build.full_c6_supply_chain import (
    FullC6CargoPathSource,
    FullC6SupplyChainReceipt,
)
from rextio.build.input_closure import BuildInputClosure
from rextio.build.runtime_authorization import RuntimeAuthorizationReceipt
from rextio.build.signing import FinalAuthorizationRequest
from rextio.build.toolchain_identity import BuildToolchainIdentity
from rextio.build.wheel_builder import (
    ExternalWheelContract,
    ExternalWheelMemberIdentity,
)
from rextio.config.schema import RextioConfig
from rextio.source.external import ExternalSourcePlan
from rextio.source.external_linkage import (
    ExternalNativeRegistry,
    ExternalRuntimeGuard,
    build_external_native_registry,
    build_external_runtime_guard,
)
from rextio.source.source_lock_v2 import (
    SourceLockV2Verification,
    validate_source_lock_v2_verified_context,
    verify_source_lock_v2_with_context,
)
from rextio.source.wheel_authority import SourceWheelEntryIdentity


FULL_C6_DISTRIBUTION_POLICY = "full-c6-required"
FULL_C6_SIGNING_REQUEST_FILENAME = "rextio.full-c6-final-authorization-request.json"
_MAX_PRIVATE_MATERIAL_BYTES = 16 * 1024 * 1024
_CONTEXT_SEAL = object()
_PUBLICATION_ADAPTER_SEAL = object()


class FullC6PipelineError(RuntimeError):
    """A strict C5.2/Full C6 pipeline invariant failed closed."""


class FullC6TypedPolicyRequiredError(FullC6PipelineError):
    """The caller tried to finalize without a complete typed policy receipt."""


@dataclass(frozen=True, slots=True)
class FullC6ExternalBuildContext:
    """Sealed same-transaction C5.2 material accepted by the orchestrator.

    Source bytes and host paths remain available only through the in-memory
    SourceLock verified context.  ``to_dict`` deliberately exposes no such
    material and cannot be deserialized back into build authority.
    """

    source_verification: SourceLockV2Verification = field(repr=False)
    registry: ExternalNativeRegistry = field(repr=False)
    runtime_guard: ExternalRuntimeGuard = field(repr=False)
    wheel_contract: ExternalWheelContract
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _CONTEXT_SEAL:
            raise TypeError("Full C6 external context must come from strict preflight")
        if (
            type(self.source_verification) is not SourceLockV2Verification
            or self.source_verification.context is None
            or self.source_verification.admission.status != "admitted"
            or type(self.registry) is not ExternalNativeRegistry
            or type(self.runtime_guard) is not ExternalRuntimeGuard
            or type(self.wheel_contract) is not ExternalWheelContract
        ):
            raise TypeError("Full C6 external context contains invalid material")
        source = self.source_verification.context
        if (
            self.registry.package != source.plan.package
            or self.registry.distribution != source.plan.distribution
            or self.registry.version != source.plan.requested_version
            or self.runtime_guard.distribution != self.registry.distribution
            or self.runtime_guard.version != self.registry.version
            or self.wheel_contract.package != self.registry.package
            or self.wheel_contract.distribution != self.registry.distribution
            or self.wheel_contract.version != self.registry.version
            or self.wheel_contract.source_members != source.wheel.source_entry_paths
            or self.wheel_contract.external_members
            != _external_wheel_members(source.wheel.entries)
        ):
            raise ValueError("Full C6 external context identity bindings disagree")

    def to_dict(self) -> dict[str, object]:
        """Return a path/source-free observation, never reusable authority."""
        context = self.source_verification.context
        assert context is not None
        return {
            "authority": "same-transaction-in-memory-only",
            "source_lock_admission": self.source_verification.admission.to_dict(),
            "package": self.registry.package,
            "distribution": self.registry.distribution,
            "version": self.registry.version,
            "linked_call_count": len(self.registry.linked_calls),
            "private_function_count": len(self.registry.private_functions),
            "source_wheel_sha256": context.wheel.archive.sha256,
            "runtime_guard_module_count": len(self.runtime_guard.modules),
            "authorizes_distribution": False,
        }


@dataclass(frozen=True, slots=True)
class FullC6ExternalPreflightResult:
    """Fresh strict analysis and the only context valid for that analysis."""

    analysis: ProjectAnalysis = field(repr=False)
    context: FullC6ExternalBuildContext

    def __post_init__(self) -> None:
        if type(self.analysis) is not ProjectAnalysis:
            raise TypeError("Full C6 strict analysis has an invalid type")
        validate_full_c6_external_context(self.context, self.analysis)


FullC6Reanalyzer: TypeAlias = Callable[[ExternalNativeRegistry], ProjectAnalysis]


def prepare_full_c6_external_build(
    *,
    project_root: Path | str,
    initial_analysis: ProjectAnalysis,
    config: RextioConfig,
    reanalyze: FullC6Reanalyzer,
) -> FullC6ExternalPreflightResult:
    """Verify SourceLock v2 and return one freshly reanalyzed C5.2 context.

    The initial analysis locates the exact installed-distribution preview.  It
    is not build authority.  SourceLock verification securely reopens the
    configured source wheel and reconstructs all analyses from those bytes.
    The registry is then supplied to a caller-owned fresh analyzer invocation;
    the result is independently rebuilt before it is sealed.
    """
    if type(initial_analysis) is not ProjectAnalysis or type(config) is not RextioConfig:
        raise FullC6PipelineError("RXT060 Full C6 preflight input is invalid")
    if config.build.artifact_distribution_policy != FULL_C6_DISTRIBUTION_POLICY:
        raise FullC6PipelineError(
            "RXT060 strict external-source build requires "
            'artifact_distribution_policy = "full-c6-required"'
        )
    root = Path(project_root).resolve()
    if initial_analysis.project_root.resolve() != root:
        raise FullC6PipelineError("RXT060 Full C6 analysis root is stale")
    plan = _require_exact_external_plan(initial_analysis, config)
    package_policy = config.imports.packages[plan.package]
    build = config.build
    required_paths = (
        build.artifact_source_lock_manifest,
        build.artifact_source_lock_signature,
        build.artifact_trusted_public_key,
        package_policy.source_archive,
    )
    if any(type(value) is not str for value in required_paths):
        raise FullC6PipelineError("RXT060 Full C6 authority paths are incomplete")
    if (
        type(build.artifact_trusted_public_key_sha256) is not str
        or type(package_policy.source_archive_sha256) is not str
    ):
        raise FullC6PipelineError("RXT060 Full C6 authority digests are incomplete")
    lock_path, lock_signature_path, public_key_path, wheel_path = (
        _project_path(root, cast(str, value)) for value in required_paths
    )
    verification = verify_source_lock_v2_with_context(
        lock_path=lock_path,
        signature_path=lock_signature_path,
        public_key_path=public_key_path,
        wheel_path=wheel_path,
        expected_wheel_sha256=package_policy.source_archive_sha256,
        expected_public_key_sha256=build.artifact_trusted_public_key_sha256,
        plan=plan,
    )
    if verification.admission.status != "admitted" or verification.context is None:
        raise FullC6PipelineError(
            "RXT060 SourceLock v2 verification rejected the exact external source wheel"
        )
    trusted = verification.context
    try:
        provisional_registry = build_external_native_registry(
            initial_analysis,
            trusted.analyses,
            package=trusted.plan.package,
            distribution=trusted.plan.distribution,
            version=trusted.plan.requested_version,
        )
        fresh_analysis = reanalyze(provisional_registry)
        if type(fresh_analysis) is not ProjectAnalysis:
            raise TypeError("reanalyzer result is invalid")
        if fresh_analysis.project_root.resolve() != root:
            raise ValueError("reanalyzer root changed")
        fresh_plan = fresh_analysis.external_source_plan
        if (
            type(fresh_plan) is not ExternalSourcePlan
            or fresh_plan.plan_snapshot_sha256() != trusted.plan.plan_snapshot_sha256()
        ):
            raise ValueError("external source plan changed during reanalysis")
        registry = build_external_native_registry(
            fresh_analysis,
            trusted.analyses,
            package=trusted.plan.package,
            distribution=trusted.plan.distribution,
            version=trusted.plan.requested_version,
        )
        if registry != provisional_registry:
            raise ValueError("external linkage changed during reanalysis")
        runtime_guard = build_external_runtime_guard(registry, trusted.analyses)
        wheel_contract = ExternalWheelContract(
            package=trusted.plan.package,
            distribution=trusted.plan.distribution,
            version=trusted.plan.requested_version,
            source_members=trusted.wheel.source_entry_paths,
            external_members=_external_wheel_members(trusted.wheel.entries),
        )
        context = FullC6ExternalBuildContext(
            source_verification=verification,
            registry=registry,
            runtime_guard=runtime_guard,
            wheel_contract=wheel_contract,
            _seal=_CONTEXT_SEAL,
        )
        validate_full_c6_external_context(context, fresh_analysis)
        return FullC6ExternalPreflightResult(analysis=fresh_analysis, context=context)
    except FullC6PipelineError:
        raise
    except Exception as exc:
        raise FullC6PipelineError(
            "RXT060 strict C5.2 linkage or fresh project analysis failed closed"
        ) from exc


def validate_full_c6_external_context(
    value: FullC6ExternalBuildContext,
    analysis: ProjectAnalysis,
) -> FullC6ExternalBuildContext:
    """Rebuild every derived C5.2 object for one exact fresh analysis."""
    if type(value) is not FullC6ExternalBuildContext or value._seal is not _CONTEXT_SEAL:
        raise FullC6PipelineError("RXT060 direct orchestrator call lacks strict C5.2 context")
    if type(analysis) is not ProjectAnalysis:
        raise FullC6PipelineError("RXT060 strict project analysis is invalid")
    source = value.source_verification.context
    if (
        source is None
        or value.source_verification.admission.status != "admitted"
        or not validate_source_lock_v2_verified_context(source)
    ):
        raise FullC6PipelineError("RXT060 SourceLock v2 context is unavailable")
    try:
        current_plan = analysis.external_source_plan
        if (
            type(current_plan) is not ExternalSourcePlan
            or current_plan.plan_snapshot_sha256() != source.plan.plan_snapshot_sha256()
        ):
            raise ValueError("external source plan is stale")
        rebuilt_registry = build_external_native_registry(
            analysis,
            source.analyses,
            package=source.plan.package,
            distribution=source.plan.distribution,
            version=source.plan.requested_version,
        )
        rebuilt_guard = build_external_runtime_guard(rebuilt_registry, source.analyses)
        rebuilt_contract = ExternalWheelContract(
            package=source.plan.package,
            distribution=source.plan.distribution,
            version=source.plan.requested_version,
            source_members=source.wheel.source_entry_paths,
            external_members=_external_wheel_members(source.wheel.entries),
        )
        if (
            rebuilt_registry != value.registry
            or rebuilt_guard != value.runtime_guard
            or rebuilt_contract != value.wheel_contract
        ):
            raise ValueError("strict C5.2 context is stale")
        value.registry.require_fresh_analysis(analysis)
    except FullC6PipelineError:
        raise
    except Exception as exc:
        raise FullC6PipelineError(
            "RXT060 strict C5.2 context does not match the exact project analysis"
        ) from exc
    return value


@dataclass(frozen=True, slots=True)
class FullC6FinalizationMaterials:
    """Complete exact inputs required after one strict two-build execution."""

    target_triple: str
    subject_path: Path
    subject: EvidenceFileRef
    build_inputs: BuildInputClosure
    wheel_entries: tuple[WheelEntryRef, ...]
    policy: FullC6PolicyReceipt
    source_verification: SourceLockV2Verification = field(repr=False)
    toolchain: BuildToolchainIdentity
    cargo_path_source: FullC6CargoPathSource
    runtime_authorization: RuntimeAuthorizationReceipt
    supply_chain: FullC6SupplyChainReceipt
    executor: FullC6ExecutorReceipt

    def __post_init__(self) -> None:
        if (
            type(self.target_triple) is not str
            or not isinstance(self.subject_path, Path)
            or type(self.subject) is not EvidenceFileRef
            or type(self.build_inputs) is not BuildInputClosure
            or type(self.wheel_entries) is not tuple
            or any(type(item) is not WheelEntryRef for item in self.wheel_entries)
            or type(self.source_verification) is not SourceLockV2Verification
            or type(self.toolchain) is not BuildToolchainIdentity
            or type(self.cargo_path_source) is not FullC6CargoPathSource
            or type(self.runtime_authorization) is not RuntimeAuthorizationReceipt
            or type(self.supply_chain) is not FullC6SupplyChainReceipt
        ):
            raise TypeError("Full C6 finalization material type is invalid")
        if type(self.policy) is not FullC6PolicyReceipt:
            raise FullC6TypedPolicyRequiredError(
                "RXT060 Full C6 finalization requires an explicit typed FullC6PolicyReceipt"
            )
        if type(self.executor) is not FullC6ExecutorReceipt:
            raise TypeError("Full C6 executor receipt is invalid")
        if self.executor.reproducibility != self.supply_chain_reproducibility:
            raise ValueError("Full C6 supply-chain reproducibility is not the executor receipt")
        if self.executor.reproducibility.wheel_sha256 != self.subject.sha256:
            raise ValueError("Full C6 subject is not the reproducible executor wheel")
        if self.toolchain.argv.digest != self.executor.invocations[0].argv_sha256:
            raise ValueError("Full C6 toolchain argv is not the executor argv")

    @property
    def supply_chain_reproducibility(self):
        """Return the exact reproducibility object bound by the supply-chain receipt."""
        # The receipt stores its digest.  The executor retains the typed object;
        # checking both here avoids accepting an unrelated same-shaped object.
        value = self.executor.reproducibility
        if self.supply_chain.reproducibility_sha256 != value.digest:
            raise ValueError("Full C6 supply chain is stale against the executor")
        return value


@dataclass(frozen=True, slots=True)
class FullC6PipelineResult:
    """Outcome of one finalization call; unsigned and published states are disjoint."""

    status: str
    request: FinalAuthorizationRequest
    signing_request_receipt: object
    gate: FullC6GateResult | None = None
    publication_receipt: FullC6PublicationReceipt | None = None

    def __post_init__(self) -> None:
        if self.status == "signing-required":
            if self.gate is not None or self.publication_receipt is not None:
                raise ValueError("unsigned Full C6 result cannot contain publication authority")
        elif self.status == "published":
            if (
                self.gate is None
                or type(self.publication_receipt) is not FullC6PublicationReceipt
            ):
                raise ValueError("published Full C6 result requires gate and publication receipts")
        else:
            raise ValueError("Full C6 pipeline status is invalid")

    @property
    def distribution_authorized(self) -> bool:
        """Return whether the sealed hard gate minted distribution authority."""
        return self.gate is not None


def finalize_full_c6_distribution(
    *,
    materials: FullC6FinalizationMaterials,
    signing_request_path: Path | str,
    public_key_path: Path | str,
    expected_public_key_sha256: str,
    final_signature_path: Path | str | None,
    publication_adapter: FullC6PublicationAdapter | None = None,
) -> FullC6PipelineResult:
    """Create a signing request, then gate and publish only when signed.

    The function never accepts a private key.  ``publication_adapter`` is
    mandatory in the signed state and is invoked only after the sole sealed
    gate has minted ``FullC6DistributionAuthorization``.
    """
    if type(materials) is not FullC6FinalizationMaterials:
        raise FullC6PipelineError(
            "RXT060 Full C6 finalization requires complete typed materials"
        )
    materials.supply_chain_reproducibility
    preauthorization = prepare_full_c6_preauthorization_evidence(
        target_triple=materials.target_triple,
        subject_path=materials.subject_path,
        subject=materials.subject,
        build_inputs=materials.build_inputs,
        wheel_entries=materials.wheel_entries,
        policy=materials.policy,
        source_verification=materials.source_verification,
        toolchain=materials.toolchain,
        cargo_path_source=materials.cargo_path_source,
        runtime_authorization=materials.runtime_authorization,
        executor=materials.executor,
        supply_chain=materials.supply_chain,
        expected_public_key_sha256=expected_public_key_sha256,
    )
    request = FinalAuthorizationRequest(
        target_triple=materials.target_triple,
        project_sha256=materials.build_inputs.digest,
        artifact_sha256=materials.subject.sha256,
        evidence_sha256=full_c6_preauthorization_evidence_digest(preauthorization),
        reproducibility_sha256=materials.executor.digest,
        policy_sha256=materials.policy.digest,
    )
    request_path = Path(signing_request_path)
    if request_path.name != FULL_C6_SIGNING_REQUEST_FILENAME:
        raise FullC6PipelineError(
            f"RXT060 signing-request output must end with {FULL_C6_SIGNING_REQUEST_FILENAME}"
        )
    from rextio.build.full_c6_publication import materialize_full_c6_signing_request

    signing_receipt = materialize_full_c6_signing_request(
        state_directory=request_path.parent,
        request=request,
    )
    if final_signature_path is None:
        return FullC6PipelineResult(
            status="signing-required",
            request=request,
            signing_request_receipt=signing_receipt,
        )
    signature_path = Path(final_signature_path)
    if not signature_path.exists():
        raise FullC6PipelineError("RXT060 configured final detached signature is missing")
    gate = authorize_full_c6_distribution(
        target_triple=materials.target_triple,
        subject_path=materials.subject_path,
        subject=materials.subject,
        build_inputs=materials.build_inputs,
        wheel_entries=materials.wheel_entries,
        policy=materials.policy,
        source_verification=materials.source_verification,
        toolchain=materials.toolchain,
        cargo_path_source=materials.cargo_path_source,
        runtime_authorization=materials.runtime_authorization,
        executor=materials.executor,
        supply_chain=materials.supply_chain,
        request=request,
        signature_envelope_path=signature_path,
        public_key_path=public_key_path,
        expected_public_key_sha256=expected_public_key_sha256,
    )
    if type(publication_adapter) is not FullC6PublicationAdapter:
        raise FullC6PipelineError(
            "RXT060 a signed Full C6 run requires the sealed atomic publication adapter"
        )
    publication_receipt = publication_adapter(request, gate, materials.supply_chain)
    if type(publication_receipt) is not FullC6PublicationReceipt:
        raise FullC6PipelineError("RXT060 Full C6 publication returned an invalid receipt")
    return FullC6PipelineResult(
        status="published",
        request=request,
        signing_request_receipt=signing_receipt,
        gate=gate,
        publication_receipt=publication_receipt,
    )


def finalize_configured_full_c6_distribution(
    *,
    project_root: Path | str,
    config: RextioConfig,
    materials: FullC6FinalizationMaterials,
    publication_adapter: FullC6PublicationAdapter | None = None,
) -> FullC6PipelineResult:
    """Resolve the explicit project-relative signing paths and finalize.

    This is the configuration-facing programmatic entrypoint.  The typed
    policy remains part of ``materials``; no file or preview report is parsed
    into policy authority.  An omitted configured final signature selects the
    request-only state.
    """
    if type(config) is not RextioConfig or (
        config.build.artifact_distribution_policy != FULL_C6_DISTRIBUTION_POLICY
    ):
        raise FullC6PipelineError(
            "RXT060 configured finalization requires full-c6-required policy"
        )
    request_output = config.build.artifact_signing_request_output
    public_key = config.build.artifact_trusted_public_key
    public_key_sha256 = config.build.artifact_trusted_public_key_sha256
    if (
        type(request_output) is not str
        or type(public_key) is not str
        or type(public_key_sha256) is not str
    ):
        raise FullC6PipelineError("RXT060 configured Full C6 signing paths are incomplete")
    root = Path(project_root).resolve()
    final_signature = config.build.artifact_final_signature
    return finalize_full_c6_distribution(
        materials=materials,
        signing_request_path=_project_path(root, request_output),
        public_key_path=_project_path(root, public_key),
        expected_public_key_sha256=public_key_sha256,
        final_signature_path=(
            _project_path(root, final_signature)
            if type(final_signature) is str
            else None
        ),
        publication_adapter=publication_adapter,
    )


@dataclass(frozen=True, slots=True)
class FullC6PublicationAdapter:
    """Sealed production adapter for the sole atomic publication sink."""

    state_directory: Path
    publication_root: Path
    bundle_name: str
    subject_path: Path
    final_signature_path: Path
    public_key_path: Path
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _PUBLICATION_ADAPTER_SEAL:
            raise TypeError("Full C6 publication adapter must come from its factory")
        if (
            any(
                not isinstance(value, Path)
                for value in (
                    self.state_directory,
                    self.publication_root,
                    self.subject_path,
                    self.final_signature_path,
                    self.public_key_path,
                )
            )
            or type(self.bundle_name) is not str
            or not self.bundle_name
        ):
            raise TypeError("Full C6 publication adapter configuration is invalid")

    def __call__(
        self,
        request: FinalAuthorizationRequest,
        gate: FullC6GateResult,
        supply_chain: FullC6SupplyChainReceipt,
    ) -> FullC6PublicationReceipt:
        """Materialize signed evidence and enter the hardened publication sink."""
        from rextio.build.full_c6_publication import (
            ROLE_CYCLONEDX,
            ROLE_DETACHED_SIGNATURE,
            ROLE_DISTRIBUTION_AUTHORIZATION,
            ROLE_FINAL_EVIDENCE,
            ROLE_SLSA_PROVENANCE,
            ROLE_WHEEL,
            publish_full_c6_bundle,
        )

        payloads = {
            "rextio.cyclonedx.json": supply_chain.sbom_json,
            "rextio.slsa-provenance.json": supply_chain.provenance_json,
            "rextio.full-c6-evidence.json": canonical_json_bytes(gate.evidence.to_dict()),
            "rextio.full-c6-authorization.json": canonical_json_bytes(
                gate.authorization.to_dict()
            ),
        }
        materialized = {
            name: _materialize_private_bytes(self.state_directory, name, data)
            for name, data in payloads.items()
        }
        return publish_full_c6_bundle(
            publication_root=self.publication_root,
            bundle_name=self.bundle_name,
            bundle_files={
                ROLE_WHEEL: self.subject_path,
                ROLE_CYCLONEDX: materialized["rextio.cyclonedx.json"],
                ROLE_SLSA_PROVENANCE: materialized["rextio.slsa-provenance.json"],
                ROLE_FINAL_EVIDENCE: materialized["rextio.full-c6-evidence.json"],
                ROLE_DETACHED_SIGNATURE: self.final_signature_path,
                ROLE_DISTRIBUTION_AUTHORIZATION: materialized[
                    "rextio.full-c6-authorization.json"
                ],
            },
            request=request,
            gate_result=gate,
            public_key_path=self.public_key_path,
        )


def full_c6_atomic_publication_adapter(
    *,
    state_directory: Path | str,
    publication_root: Path | str,
    bundle_name: str,
    subject_path: Path | str,
    final_signature_path: Path | str,
    public_key_path: Path | str,
) -> FullC6PublicationAdapter:
    """Return the sealed production adapter for atomic signed publication."""
    return FullC6PublicationAdapter(
        state_directory=Path(state_directory),
        publication_root=Path(publication_root),
        bundle_name=bundle_name,
        subject_path=Path(subject_path),
        final_signature_path=Path(final_signature_path),
        public_key_path=Path(public_key_path),
        _seal=_PUBLICATION_ADAPTER_SEAL,
    )


def _require_exact_external_plan(
    analysis: ProjectAnalysis,
    config: RextioConfig,
) -> ExternalSourcePlan:
    plan = analysis.external_source_plan
    if type(plan) is not ExternalSourcePlan or plan.status != "preview-ready":
        raise FullC6PipelineError(
            "RXT060 Full C6 requires one preview-ready exact external source plan"
        )
    if len(config.imports.packages) != 1 or plan.package not in config.imports.packages:
        raise FullC6PipelineError("RXT060 Full C6 external package declaration changed")
    package_policy = config.imports.packages[plan.package]
    if (
        package_policy.policy != "try-native"
        or package_policy.max_depth != 1
        or package_policy.plugin is not None
        or package_policy.distribution != plan.distribution
        or package_policy.version != plan.requested_version
    ):
        raise FullC6PipelineError("RXT060 Full C6 external package identity changed")
    return plan


def _external_wheel_members(
    entries: tuple[SourceWheelEntryIdentity, ...],
) -> tuple[ExternalWheelMemberIdentity, ...]:
    """Project the verified source wheel's complete exact member inventory."""
    if type(entries) is not tuple or any(
        type(entry) is not SourceWheelEntryIdentity for entry in entries
    ):
        raise FullC6PipelineError("RXT060 external source-wheel inventory is invalid")
    return tuple(
        ExternalWheelMemberIdentity(
            path=entry.path,
            sha256=entry.sha256,
            size=entry.size,
        )
        for entry in entries
    )


def _project_path(root: Path, value: str) -> Path:
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or "\\" in value
    ):
        raise FullC6PipelineError("RXT060 Full C6 path is not project-relative")
    result = root.joinpath(*path.parts)
    try:
        result.relative_to(root)
    except ValueError as exc:  # defensive if pathlib semantics ever widen
        raise FullC6PipelineError("RXT060 Full C6 path escapes the project") from exc
    return result


def _materialize_private_bytes(root: Path, name: str, data: bytes) -> Path:
    if (
        type(data) is not bytes
        or not data
        or len(data) > _MAX_PRIVATE_MATERIAL_BYTES
        or PurePosixPath(name).name != name
    ):
        raise FullC6PipelineError("RXT060 Full C6 private material is invalid")
    _require_private_directory(root)
    path = root / name
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        existing = _read_private_file(path)
        if not hmac.compare_digest(existing, data):
            raise FullC6PipelineError("RXT060 Full C6 private material already differs") from None
        return path
    except OSError as exc:
        raise FullC6PipelineError("RXT060 Full C6 private material cannot be created") from exc
    try:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise FullC6PipelineError("RXT060 Full C6 private material write failed")
            offset += written
        os.fsync(descriptor)
        observed = os.fstat(descriptor)
        if not stat.S_ISREG(observed.st_mode) or observed.st_size != len(data):
            raise FullC6PipelineError("RXT060 Full C6 private material changed")
    finally:
        os.close(descriptor)
    if not hmac.compare_digest(_read_private_file(path), data):
        raise FullC6PipelineError("RXT060 Full C6 private material final bytes changed")
    return path


def _require_private_directory(path: Path) -> None:
    try:
        observed = path.lstat()
    except OSError as exc:
        raise FullC6PipelineError("RXT060 Full C6 state directory is unavailable") from exc
    if (
        not stat.S_ISDIR(observed.st_mode)
        or stat.S_IMODE(observed.st_mode) != 0o700
        or observed.st_uid != os.getuid()
    ):
        raise FullC6PipelineError(
            "RXT060 Full C6 state directory must be owner-owned mode 0700"
        )


def _read_private_file(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise FullC6PipelineError("RXT060 Full C6 private material cannot be opened") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > _MAX_PRIVATE_MATERIAL_BYTES
        ):
            raise FullC6PipelineError("RXT060 Full C6 private material is unsafe")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise FullC6PipelineError("RXT060 Full C6 private material was truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        def identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
            return (
                value.st_dev,
                value.st_ino,
                value.st_mode,
                value.st_nlink,
                value.st_size,
                value.st_mtime_ns,
            )
        if identity(before) != identity(after):
            raise FullC6PipelineError("RXT060 Full C6 private material changed while reading")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


__all__ = [
    "FULL_C6_DISTRIBUTION_POLICY",
    "FULL_C6_SIGNING_REQUEST_FILENAME",
    "FullC6ExternalBuildContext",
    "FullC6ExternalPreflightResult",
    "FullC6FinalizationMaterials",
    "FullC6PipelineError",
    "FullC6PipelineResult",
    "FullC6PublicationAdapter",
    "FullC6TypedPolicyRequiredError",
    "finalize_full_c6_distribution",
    "finalize_configured_full_c6_distribution",
    "full_c6_atomic_publication_adapter",
    "prepare_full_c6_external_build",
    "validate_full_c6_external_context",
]
