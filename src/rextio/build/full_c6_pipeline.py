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
import hashlib
import hmac
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
from typing import TYPE_CHECKING, TypeAlias, cast
import unicodedata

from rextio.analyzer.models import ProjectAnalysis
from rextio.artifacts.evidence import canonical_json_bytes
from rextio.artifacts.full_authorization import full_c6_preauthorization_evidence_digest
from rextio.build.full_c6_gate import (
    FullC6GateResult,
    _validated_production_gate_inputs,
    authorize_full_c6_distribution,
    prepare_full_c6_preauthorization_evidence,
)
from rextio.build.full_c6_policy import FullC6PolicyReceipt
from rextio.build.full_c6_policy_manifest import (
    FullC6PolicyManifestError,
    load_full_c6_policy_manifest,
)
from rextio.build.full_c6_publication import FullC6PublicationReceipt
from rextio.build.signing import FinalAuthorizationRequest
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


if TYPE_CHECKING:
    from rextio.build.full_c6_production import (
        FullC6ProductionAuthority,
        _FullC6ProductionMaterial,
    )


FULL_C6_DISTRIBUTION_POLICY = "full-c6-required"
FULL_C6_SIGNING_REQUEST_FILENAME = "rextio.full-c6-final-authorization-request.json"
_MAX_PRIVATE_MATERIAL_BYTES = 16 * 1024 * 1024
_CONTEXT_SEAL = object()
_PUBLICATION_ADAPTER_SEAL = object()
_PUBLICATION_ADAPTER_KEY = secrets.token_bytes(32)
_WHEEL_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,254}\.whl$")


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
    authority: FullC6ProductionAuthority,
    signing_request_path: Path | str,
    public_key_path: Path | str,
    final_signature_path: Path | str | None,
    publication_adapter: FullC6PublicationAdapter | None = None,
) -> FullC6PipelineResult:
    """Create a signing request, then gate and publish only when signed.

    The function never accepts a private key.  ``publication_adapter`` is
    mandatory in the signed state and is invoked only after the sole sealed
    gate has minted ``FullC6DistributionAuthorization``.
    """
    material = _validated_full_c6_finalization_material(authority)
    request_path, trusted_public_key_path, trusted_signature_path = (
        _require_configured_finalization_paths(
            material,
            signing_request_path=signing_request_path,
            public_key_path=public_key_path,
            final_signature_path=final_signature_path,
        )
    )
    request = _full_c6_finalization_request(authority)
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
    if trusted_signature_path is None:
        raise FullC6PipelineError("RXT060 configured final detached signature is missing")
    signature_path = trusted_signature_path
    if not signature_path.exists():
        raise FullC6PipelineError("RXT060 configured final detached signature is missing")
    gate = authorize_full_c6_distribution(
        authority,
        request=request,
        signature_envelope_path=signature_path,
        public_key_path=trusted_public_key_path,
    )
    if type(publication_adapter) is not FullC6PublicationAdapter:
        raise FullC6PipelineError(
            "RXT060 a signed Full C6 run requires the sealed atomic publication adapter"
        )
    publication_receipt = publication_adapter(authority, request, gate)
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
    authority: FullC6ProductionAuthority,
    publication_adapter: FullC6PublicationAdapter | None = None,
) -> FullC6PipelineResult:
    """Resolve the explicit project-relative signing paths and finalize.

    This is the configuration-facing programmatic entrypoint.  The typed
    policy remains inside ``authority``; no file or preview report is parsed
    into evidence authority.  An omitted configured final signature selects
    the request-only state.
    """
    if type(config) is not RextioConfig or (
        config.build.artifact_distribution_policy != FULL_C6_DISTRIBUTION_POLICY
    ):
        raise FullC6PipelineError(
            "RXT060 configured finalization requires full-c6-required policy"
        )
    material = _validated_full_c6_finalization_material(authority)
    root = Path(project_root).resolve()
    if root != material.project_root or config is not material.config:
        raise FullC6PipelineError(
            "RXT060 configured finalization does not match retained production inputs"
        )
    configured_policy = load_configured_full_c6_policy(
        project_root=project_root,
        config=config,
    )
    if material.policy is None or configured_policy != material.policy:
        raise FullC6PipelineError(
            "RXT060 Full C6 production authority does not match the pinned owner policy"
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
    final_signature = config.build.artifact_final_signature
    return finalize_full_c6_distribution(
        authority=authority,
        signing_request_path=_project_path(root, request_output),
        public_key_path=_project_path(root, public_key),
        final_signature_path=(
            _project_path(root, final_signature)
            if type(final_signature) is str
            else None
        ),
        publication_adapter=publication_adapter,
    )


def load_configured_full_c6_policy(
    *,
    project_root: Path | str,
    config: RextioConfig,
) -> FullC6PolicyReceipt:
    """Load one exact owner-authored policy pinned by strict build config."""
    if type(config) is not RextioConfig or (
        config.build.artifact_distribution_policy != FULL_C6_DISTRIBUTION_POLICY
    ):
        raise FullC6PipelineError(
            "RXT060 configured owner policy requires full-c6-required mode"
        )
    policy_path = config.build.artifact_policy_manifest
    policy_sha256 = config.build.artifact_policy_manifest_sha256
    trusted_key_sha256 = config.build.artifact_trusted_public_key_sha256
    if (
        type(policy_path) is not str
        or type(policy_sha256) is not str
        or type(trusted_key_sha256) is not str
    ):
        raise FullC6PipelineError(
            "RXT060 configured Full C6 owner policy path and digest are incomplete"
        )
    root = Path(project_root).resolve()
    try:
        receipt = load_full_c6_policy_manifest(
            _project_path(root, policy_path),
            expected_sha256=policy_sha256,
        )
    except (FullC6PolicyManifestError, OSError, TypeError, ValueError) as exc:
        raise FullC6PipelineError(
            "RXT060 configured Full C6 owner policy manifest failed closed"
        ) from exc
    if not hmac.compare_digest(
        receipt.trusted_owner_public_key_sha256,
        trusted_key_sha256,
    ):
        raise FullC6PipelineError(
            "RXT060 Full C6 owner policy and trusted public-key pin disagree"
        )
    return receipt


def _validated_full_c6_finalization_material(
    authority: FullC6ProductionAuthority,
) -> _FullC6ProductionMaterial:
    """Return the one retained production graph accepted by finalization."""
    try:
        from rextio.build.full_c6_production import (
            FullC6ProductionAuthority,
            _validated_full_c6_production_material,
        )

        if type(authority) is not FullC6ProductionAuthority:
            raise FullC6PipelineError(
                "RXT060 Full C6 finalization requires exact production authority"
            )
        material = _validated_full_c6_production_material(authority)
        gate_inputs = _validated_production_gate_inputs(authority)
        if (
            material.lifecycle.status not in {"signing-required", "publication-required"}
            or type(material.project_root) is not Path
            or material.project_root.resolve() != material.project_root
            or type(material.config) is not RextioConfig
            or type(material.policy) is not FullC6PolicyReceipt
            or material.policy is not gate_inputs.policy
            or material.supply_chain is not gate_inputs.supply_chain
            or material.build_inputs is not gate_inputs.build_inputs
            or material.analysis_ir_transaction is not gate_inputs.analysis_ir_transaction
            or material.runtime_authorization is not gate_inputs.runtime_authorization
            or material.executor_receipt is not gate_inputs.executor
            or material.cargo_path_source is not gate_inputs.cargo_path_source
            or material.cargo_workspace is not gate_inputs.cargo_dependency_workspace
            or material.runtime_authorization.target_triple != gate_inputs.target_triple
            or material.policy.trusted_owner_public_key_sha256
            != gate_inputs.expected_public_key_sha256
            or material.config.build.artifact_trusted_public_key_sha256
            != gate_inputs.expected_public_key_sha256
        ):
            raise FullC6PipelineError(
                "RXT060 Full C6 production authority is split or incomplete"
            )
        return material
    except FullC6PipelineError:
        raise
    except Exception as exc:
        raise FullC6PipelineError(
            "RXT060 Full C6 production authority failed finalization validation"
        ) from exc


def _require_configured_finalization_paths(
    material: _FullC6ProductionMaterial,
    *,
    signing_request_path: Path | str,
    public_key_path: Path | str,
    final_signature_path: Path | str | None,
) -> tuple[Path, Path, Path | None]:
    """Reject any path injection outside the retained production config."""
    build = material.config.build
    request_value = build.artifact_signing_request_output
    public_key_value = build.artifact_trusted_public_key
    signature_value = build.artifact_final_signature
    if (
        type(request_value) is not str
        or type(public_key_value) is not str
        or (signature_value is not None and type(signature_value) is not str)
    ):
        raise FullC6PipelineError("RXT060 configured Full C6 signing paths are incomplete")
    expected_request = _project_path(material.project_root, request_value)
    expected_public_key = _project_path(material.project_root, public_key_value)
    expected_signature = (
        _project_path(material.project_root, signature_value)
        if type(signature_value) is str
        else None
    )
    observed_signature = (
        Path(final_signature_path) if final_signature_path is not None else None
    )
    if (
        Path(signing_request_path) != expected_request
        or Path(public_key_path) != expected_public_key
        or observed_signature != expected_signature
    ):
        raise FullC6PipelineError(
            "RXT060 finalization paths do not match retained production config"
        )
    return expected_request, expected_public_key, expected_signature


@dataclass(frozen=True, slots=True)
class FullC6PublicationAdapter:
    """Sealed production adapter for the sole atomic publication sink."""

    authority: FullC6ProductionAuthority = field(repr=False, compare=False)
    state_directory: Path
    publication_root: Path
    bundle_name: str
    subject_path: Path
    final_signature_path: Path
    public_key_path: Path
    _seal: object = field(repr=False, compare=False)
    _binding: bytes = field(init=False, repr=False, compare=False)

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
        _validated_full_c6_finalization_material(self.authority)
        object.__setattr__(self, "_binding", _publication_adapter_binding(self))

    def __call__(
        self,
        authority: FullC6ProductionAuthority,
        request: FinalAuthorizationRequest,
        gate: FullC6GateResult,
    ) -> FullC6PublicationReceipt:
        """Materialize signed evidence and enter the hardened publication sink."""
        from rextio.build.full_c6_publication import (
            ROLE_CYCLONEDX,
            ROLE_DETACHED_SIGNATURE,
            ROLE_DISTRIBUTION_AUTHORIZATION,
            ROLE_FINAL_EVIDENCE,
            ROLE_SLSA_PROVENANCE,
            ROLE_WHEEL,
            _publish_full_c6_bundle,
            _rebuild_gate_result,
            _rebuild_request,
        )

        _require_valid_publication_adapter(self)
        if authority is not self.authority:
            raise FullC6PipelineError(
                "RXT060 Full C6 publication authority is not the retained authority"
            )
        material = _validated_full_c6_finalization_material(authority)
        gate_inputs = _validated_production_gate_inputs(authority)
        _require_publication_adapter_paths(self, material, gate_inputs.subject_path)
        if material.supply_chain is not gate_inputs.supply_chain:
            raise FullC6PipelineError("RXT060 Full C6 publication authority is split")
        trusted_request = _rebuild_request(request)
        trusted_gate = _rebuild_gate_result(gate)
        expected_request = _full_c6_finalization_request(authority)
        expected_preauthorization = prepare_full_c6_preauthorization_evidence(authority)
        if (
            trusted_request != expected_request
            or trusted_gate.preauthorization_evidence != expected_preauthorization
        ):
            raise FullC6PipelineError(
                "RXT060 Full C6 publication request or gate replaced retained authority"
            )
        supply_chain = gate_inputs.supply_chain
        payloads = {
            "rextio.cyclonedx.json": supply_chain.sbom_json,
            "rextio.slsa-provenance.json": supply_chain.provenance_json,
            "rextio.full-c6-evidence.json": canonical_json_bytes(
                trusted_gate.evidence.to_dict()
            ),
            "rextio.full-c6-authorization.json": canonical_json_bytes(
                trusted_gate.authorization.to_dict()
            ),
        }
        materialized = {
            name: _materialize_private_bytes(self.state_directory, name, data)
            for name, data in payloads.items()
        }
        return _publish_full_c6_bundle(
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
            request=trusted_request,
            gate_result=trusted_gate,
            public_key_path=self.public_key_path,
        )


def _full_c6_atomic_publication_adapter(
    *,
    authority: FullC6ProductionAuthority,
    state_directory: Path | str,
    publication_root: Path | str,
    bundle_name: str,
    subject_path: Path | str,
    final_signature_path: Path | str,
    public_key_path: Path | str,
) -> FullC6PublicationAdapter:
    """Return the sealed production adapter for atomic signed publication."""
    return FullC6PublicationAdapter(
        authority=authority,
        state_directory=Path(state_directory),
        publication_root=Path(publication_root),
        bundle_name=bundle_name,
        subject_path=Path(subject_path),
        final_signature_path=Path(final_signature_path),
        public_key_path=Path(public_key_path),
        _seal=_PUBLICATION_ADAPTER_SEAL,
    )


def _require_publication_adapter_paths(
    adapter: FullC6PublicationAdapter,
    material: _FullC6ProductionMaterial,
    retained_subject_path: Path,
) -> None:
    """Bind injected publication paths back to the exact retained graph."""
    build = material.config.build
    request_value = build.artifact_signing_request_output
    public_key_value = build.artifact_trusted_public_key
    signature_value = build.artifact_final_signature
    if (
        material.lifecycle.status != "publication-required"
        or type(request_value) is not str
        or type(public_key_value) is not str
        or type(signature_value) is not str
    ):
        raise FullC6PipelineError(
            "RXT060 Full C6 publication requires retained publication config"
        )
    expected_request = _project_path(material.project_root, request_value)
    expected_public_key = _project_path(material.project_root, public_key_value)
    expected_signature = _project_path(material.project_root, signature_value)
    wheel_name = retained_subject_path.name
    expected_publication_root = material.project_root / "dist"
    expected_bundle_name = f"{wheel_name.removesuffix('.whl')}.full-c6"
    if (
        not retained_subject_path.is_absolute()
        or _WHEEL_FILENAME_RE.fullmatch(wheel_name) is None
        or unicodedata.normalize("NFC", wheel_name) != wheel_name
        or adapter.state_directory != expected_request.parent
        or adapter.publication_root != expected_publication_root
        or adapter.bundle_name != expected_bundle_name
        or adapter.subject_path != retained_subject_path
        or adapter.final_signature_path != expected_signature
        or adapter.public_key_path != expected_public_key
    ):
        raise FullC6PipelineError(
            "RXT060 publication paths do not match retained production authority"
        )


def _publication_adapter_binding(adapter: FullC6PublicationAdapter) -> bytes:
    payload = {
        "authority_identity": id(adapter.authority),
        "state_directory": adapter.state_directory.as_posix(),
        "publication_root": adapter.publication_root.as_posix(),
        "bundle_name": adapter.bundle_name,
        "subject_path": adapter.subject_path.as_posix(),
        "final_signature_path": adapter.final_signature_path.as_posix(),
        "public_key_path": adapter.public_key_path.as_posix(),
    }
    return hmac.new(
        _PUBLICATION_ADAPTER_KEY,
        canonical_json_bytes(payload),
        hashlib.sha256,
    ).digest()


def _require_valid_publication_adapter(value: FullC6PublicationAdapter) -> None:
    try:
        valid = (
            type(value) is FullC6PublicationAdapter
            and value._seal is _PUBLICATION_ADAPTER_SEAL
            and type(value._binding) is bytes
            and hmac.compare_digest(value._binding, _publication_adapter_binding(value))
        )
    except Exception as exc:
        raise FullC6PipelineError(
            "RXT060 Full C6 publication adapter seal is invalid"
        ) from exc
    if not valid:
        raise FullC6PipelineError("RXT060 Full C6 publication adapter seal is invalid")


def _full_c6_finalization_request(
    authority: FullC6ProductionAuthority,
) -> FinalAuthorizationRequest:
    """Derive the sole signing request from validated retained authority."""
    inputs = _validated_production_gate_inputs(authority)
    preauthorization = prepare_full_c6_preauthorization_evidence(authority)
    return FinalAuthorizationRequest(
        target_triple=inputs.target_triple,
        project_sha256=inputs.build_inputs.digest,
        artifact_sha256=inputs.subject.sha256,
        evidence_sha256=full_c6_preauthorization_evidence_digest(preauthorization),
        reproducibility_sha256=inputs.executor.digest,
        policy_sha256=inputs.policy.digest,
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
    "FullC6PipelineError",
    "FullC6PipelineResult",
    "FullC6PublicationAdapter",
    "FullC6TypedPolicyRequiredError",
    "finalize_full_c6_distribution",
    "finalize_configured_full_c6_distribution",
    "load_configured_full_c6_policy",
    "prepare_full_c6_external_build",
    "validate_full_c6_external_context",
]
