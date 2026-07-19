"""C6.5 distribution-authorization readiness assessment.

This module deliberately sits between the C6.2-C6.4 preview evidence record
and any future distribution authorization.  It converts only a validated
``ArtifactEvidence`` instance into a deterministic, closed-vocabulary report.
The report is readiness information, never an authorization decision: every
instance is blocked, incomplete, unsigned, and non-authorizing.

C6.5 does not implement native-runtime path resolution, transitive dependency
closure, runtime ``dlopen`` observation, Windows PE inspection, runtime-bearing
plugins, executables, Rust crates, Nuitka/WASM evidence, signatures, or final
distribution authorization.
"""

from __future__ import annotations

from dataclasses import dataclass

from rextio.artifacts.evidence import (
    ARTIFACT_EVIDENCE_SCOPE,
    REASON_EVIDENCE_INTERNAL,
    UNAVAILABLE_REASONS,
    ArtifactEvidence,
    CargoDepEdge,
    CargoPackageRef,
    EvidenceFileRef,
    NativeRuntimeDependency,
    NativeRuntimeInventory,
    SidecarArtifact,
    WheelEntryRef,
    canonicalize_registry_source,
)

ARTIFACT_AUTHORIZATION_KIND = "artifact-distribution-authorization"
ARTIFACT_AUTHORIZATION_POLICY = ARTIFACT_EVIDENCE_SCOPE
ARTIFACT_AUTHORIZATION_POLICY_VERSION = 1
ARTIFACT_AUTHORIZATION_STATUS = "blocked"
ARTIFACT_AUTHORIZATION_AUTHORITY = "readiness-assessment-only"

_OBSERVATION_CHECK_IDS: tuple[str, ...] = (
    "artifact-subject-bound",
    "declared-input-snapshot-bound",
    "cargo-resolve-graph-bound",
    "direct-native-linkage-observed",
)
_READINESS_CHECK_IDS: tuple[str, ...] = (
    "component-license-policy-complete",
    "native-runtime-resolution-complete",
    "native-runtime-transitive-closure-complete",
    "runtime-dynamic-loading-verified",
    "build-input-closure-complete",
    "source-transformation-provenance-complete",
    "builder-toolchain-identity-bound",
    "reproducibility-verified",
    "attestation-signed",
    "sbom-composition-complete",
)
ARTIFACT_AUTHORIZATION_CHECK_IDS: tuple[str, ...] = (
    *_OBSERVATION_CHECK_IDS,
    *_READINESS_CHECK_IDS,
)

ARTIFACT_AUTHORIZATION_PREVIEW_BLOCKERS: tuple[str, ...] = (
    "component-license-policy-incomplete",
    "native-runtime-resolution-incomplete",
    "native-runtime-transitive-closure-incomplete",
    "runtime-dynamic-loading-unverified",
    "build-input-closure-incomplete",
    "source-transformation-provenance-incomplete",
    "builder-toolchain-identity-unbound",
    "reproducibility-unverified",
    "attestation-unsigned",
    "sbom-composition-incomplete",
)
ARTIFACT_AUTHORIZATION_EVIDENCE_UNAVAILABLE = "evidence-unavailable"
ARTIFACT_AUTHORIZATION_READINESS_UNAVAILABLE = "readiness-assessment-unavailable"
_ALLOWED_BLOCKERS = frozenset(
    {
        *ARTIFACT_AUTHORIZATION_PREVIEW_BLOCKERS,
        ARTIFACT_AUTHORIZATION_EVIDENCE_UNAVAILABLE,
        ARTIFACT_AUTHORIZATION_READINESS_UNAVAILABLE,
    }
)
_CHECK_STATUSES = frozenset({"satisfied", "blocked", "unavailable", "not-evaluated"})
_REQUIRED_INPUT_ROLES = frozenset(
    {
        "project-python-source",
        "generated-python-input",
        "generated-rust-input",
        "generated-cargo-lock",
    }
)


@dataclass(frozen=True, slots=True)
class ArtifactAuthorizationCheck:
    """One closed-vocabulary readiness requirement and its fixed status."""

    id: str
    status: str

    def __post_init__(self) -> None:
        if self.id not in ARTIFACT_AUTHORIZATION_CHECK_IDS:
            raise ValueError("artifact authorization check id is not in the allowlist")
        if self.status not in _CHECK_STATUSES:
            raise ValueError("artifact authorization check status is not in the allowlist")

    def to_dict(self) -> dict[str, str]:
        """Return the canonical tooling-contract item shape."""
        return {"id": self.id, "status": self.status}


@dataclass(frozen=True, slots=True)
class ArtifactDistributionAuthorizationAssessment:
    """Immutable, fail-closed C6.5 distribution-readiness report.

    Callers should use :meth:`from_evidence`.  The public fields remain
    validate-on-construction so malformed, reordered, duplicated, or
    free-text policy records cannot accidentally become contract output.
    """

    kind: str
    policy: str
    policy_version: int
    scope: str
    status: str
    authority: str
    evidence_status: str
    evidence_reason: str | None
    checks: tuple[ArtifactAuthorizationCheck, ...]
    blockers: tuple[str, ...]
    complete: bool = False
    signed: bool = False
    distribution_authorized: bool = False

    def __post_init__(self) -> None:
        if self.kind != ARTIFACT_AUTHORIZATION_KIND:
            raise ValueError("artifact authorization kind is invalid")
        if self.policy != ARTIFACT_AUTHORIZATION_POLICY:
            raise ValueError("artifact authorization policy is invalid")
        if self.policy_version != ARTIFACT_AUTHORIZATION_POLICY_VERSION:
            raise ValueError("artifact authorization policy version is invalid")
        if self.scope != ARTIFACT_EVIDENCE_SCOPE:
            raise ValueError("artifact authorization scope is invalid")
        if self.status != ARTIFACT_AUTHORIZATION_STATUS:
            raise ValueError("artifact authorization status must remain blocked")
        if self.authority != ARTIFACT_AUTHORIZATION_AUTHORITY:
            raise ValueError("artifact authorization authority is invalid")
        if self.evidence_status not in {"preview-ready", "unavailable"}:
            raise ValueError("artifact authorization evidence status is invalid")

        checks = tuple(self.checks)
        if not all(isinstance(item, ArtifactAuthorizationCheck) for item in checks):
            raise TypeError("artifact authorization checks must use the closed check model")
        check_ids = tuple(item.id for item in checks)
        if len(check_ids) != len(set(check_ids)):
            raise ValueError("artifact authorization check ids must be unique")
        if check_ids != ARTIFACT_AUTHORIZATION_CHECK_IDS:
            raise ValueError("artifact authorization checks must use canonical order and coverage")

        blockers = tuple(self.blockers)
        if not all(isinstance(item, str) for item in blockers):
            raise TypeError("artifact authorization blockers must be identifiers")
        if len(blockers) != len(set(blockers)):
            raise ValueError("artifact authorization blockers must be unique")
        if any(item not in _ALLOWED_BLOCKERS for item in blockers):
            raise ValueError("artifact authorization blocker is not in the allowlist")

        if self.evidence_status == "preview-ready":
            if self.evidence_reason is not None:
                raise ValueError("preview-ready authorization assessment has no evidence reason")
            if blockers == ARTIFACT_AUTHORIZATION_PREVIEW_BLOCKERS:
                expected_statuses = (
                    *("satisfied" for _ in _OBSERVATION_CHECK_IDS),
                    *("blocked" for _ in _READINESS_CHECK_IDS),
                )
            elif blockers == (ARTIFACT_AUTHORIZATION_READINESS_UNAVAILABLE,):
                expected_statuses = tuple(
                    "not-evaluated" for _ in ARTIFACT_AUTHORIZATION_CHECK_IDS
                )
            else:
                raise ValueError("preview-ready authorization blockers are not canonical")
        else:
            if self.evidence_reason not in UNAVAILABLE_REASONS:
                raise ValueError("unavailable authorization assessment needs a fixed evidence reason")
            expected_statuses = (
                *("unavailable" for _ in _OBSERVATION_CHECK_IDS),
                *("not-evaluated" for _ in _READINESS_CHECK_IDS),
            )
            # Do not speculate about downstream readiness when the source
            # evidence itself is unavailable.
            if blockers != (ARTIFACT_AUTHORIZATION_EVIDENCE_UNAVAILABLE,):
                raise ValueError("unavailable authorization blockers are not canonical")

        if tuple(item.status for item in checks) != expected_statuses:
            raise ValueError("artifact authorization check statuses are not canonical")

        object.__setattr__(self, "checks", checks)
        object.__setattr__(self, "blockers", blockers)
        # Inputs cannot promote this readiness-only record.  These fields are
        # forced false even if a caller supplies truthy constructor values.
        object.__setattr__(self, "complete", False)
        object.__setattr__(self, "signed", False)
        object.__setattr__(self, "distribution_authorized", False)

    @classmethod
    def from_evidence(
        cls,
        evidence: ArtifactEvidence,
    ) -> ArtifactDistributionAuthorizationAssessment:
        """Return the total, no-throw C6.5 evaluation for ``evidence``."""
        return evaluate_artifact_distribution_authorization(evidence)

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic additive ``build.json`` shape."""
        return {
            "kind": ARTIFACT_AUTHORIZATION_KIND,
            "policy": ARTIFACT_AUTHORIZATION_POLICY,
            "policy_version": ARTIFACT_AUTHORIZATION_POLICY_VERSION,
            "scope": ARTIFACT_EVIDENCE_SCOPE,
            "status": ARTIFACT_AUTHORIZATION_STATUS,
            "authority": ARTIFACT_AUTHORIZATION_AUTHORITY,
            "evidence_status": self.evidence_status,
            "evidence_reason": self.evidence_reason,
            "checks": [item.to_dict() for item in self.checks],
            "blockers": list(self.blockers),
            "complete": False,
            "signed": False,
            "distribution_authorized": False,
        }


def evaluate_artifact_distribution_authorization(
    evidence: ArtifactEvidence,
) -> ArtifactDistributionAuthorizationAssessment:
    """Evaluate C6.5 without ever changing the surrounding build outcome.

    A structurally invalid preview remains reported as preview evidence, but
    no readiness check is claimed: the closed fallback shape contains only
    ``readiness-assessment-unavailable``. Exception text is intentionally
    discarded. Invalid unavailable evidence degrades to the existing fixed
    internal-error reason.
    """
    observed_status = _observed_evidence_status(evidence)
    try:
        trusted = _reconstruct_evidence(evidence)
        if trusted.status == "preview-ready":
            _validate_preview_observations(trusted)
            return _build_assessment(
                evidence_status="preview-ready",
                evidence_reason=None,
                statuses=(
                    *("satisfied" for _ in _OBSERVATION_CHECK_IDS),
                    *("blocked" for _ in _READINESS_CHECK_IDS),
                ),
                blockers=ARTIFACT_AUTHORIZATION_PREVIEW_BLOCKERS,
            )
        return _build_assessment(
            evidence_status="unavailable",
            evidence_reason=trusted.reason,
            statuses=(
                *("unavailable" for _ in _OBSERVATION_CHECK_IDS),
                *("not-evaluated" for _ in _READINESS_CHECK_IDS),
            ),
            blockers=(ARTIFACT_AUTHORIZATION_EVIDENCE_UNAVAILABLE,),
        )
    except Exception:
        if observed_status == "preview-ready":
            return _build_assessment(
                evidence_status="preview-ready",
                evidence_reason=None,
                statuses=tuple(
                    "not-evaluated" for _ in ARTIFACT_AUTHORIZATION_CHECK_IDS
                ),
                blockers=(ARTIFACT_AUTHORIZATION_READINESS_UNAVAILABLE,),
            )
        return _build_assessment(
            evidence_status="unavailable",
            evidence_reason=REASON_EVIDENCE_INTERNAL,
            statuses=(
                *("unavailable" for _ in _OBSERVATION_CHECK_IDS),
                *("not-evaluated" for _ in _READINESS_CHECK_IDS),
            ),
            blockers=(ARTIFACT_AUTHORIZATION_EVIDENCE_UNAVAILABLE,),
        )


def _observed_evidence_status(evidence: object) -> str | None:
    """Read only the closed status token without trusting any other field."""
    try:
        status = object.__getattribute__(evidence, "status")
    except Exception:
        return None
    if type(status) is not str:
        return None
    return status if status in {"preview-ready", "unavailable"} else None


def _build_assessment(
    *,
    evidence_status: str,
    evidence_reason: str | None,
    statuses: tuple[str, ...],
    blockers: tuple[str, ...],
) -> ArtifactDistributionAuthorizationAssessment:
    """Build one internal canonical shape from constants only."""
    checks = tuple(
        ArtifactAuthorizationCheck(id=check_id, status=check_status)
        for check_id, check_status in zip(
            ARTIFACT_AUTHORIZATION_CHECK_IDS,
            statuses,
            strict=True,
        )
    )
    return ArtifactDistributionAuthorizationAssessment(
        kind=ARTIFACT_AUTHORIZATION_KIND,
        policy=ARTIFACT_AUTHORIZATION_POLICY,
        policy_version=ARTIFACT_AUTHORIZATION_POLICY_VERSION,
        scope=ARTIFACT_EVIDENCE_SCOPE,
        status=ARTIFACT_AUTHORIZATION_STATUS,
        authority=ARTIFACT_AUTHORIZATION_AUTHORITY,
        evidence_status=evidence_status,
        evidence_reason=evidence_reason,
        checks=checks,
        blockers=blockers,
    )


def _reconstruct_evidence(evidence: ArtifactEvidence) -> ArtifactEvidence:
    """Deeply reconstruct every nested evidence model and rerun invariants."""
    if type(evidence) is not ArtifactEvidence:
        raise TypeError("authorization assessment requires ArtifactEvidence")
    rebuilt = ArtifactEvidence(
        kind=evidence.kind,
        status=evidence.status,
        authority=evidence.authority,
        signature_status=evidence.signature_status,
        composition=evidence.composition,
        reason=evidence.reason,
        target_triple=evidence.target_triple,
        subject=_copy_optional_file_ref(evidence.subject),
        sbom=_copy_sidecar(evidence.sbom),
        provenance=_copy_sidecar(evidence.provenance),
        inputs=tuple(_copy_file_ref(item) for item in evidence.inputs),
        wheel_entries=tuple(_copy_wheel_entry(item) for item in evidence.wheel_entries),
        cargo_packages=tuple(
            _copy_cargo_package(item) for item in evidence.cargo_packages
        ),
        cargo_dependencies=tuple(
            _copy_cargo_edge(item) for item in evidence.cargo_dependencies
        ),
        native_runtime_inventory=_copy_runtime_inventory(
            evidence.native_runtime_inventory
        ),
        limitations=tuple(evidence.limitations),
        preview=evidence.preview,
        complete=evidence.complete,
        signed=evidence.signed,
        distribution_authorized=evidence.distribution_authorized,
    )
    # Constructors normalize a few bounded strings/collections. A difference
    # means low-level mutation or a noncanonical nested value was repaired;
    # readiness must not silently accept that repair.
    if rebuilt != evidence:
        raise ValueError("artifact evidence is not in canonical model form")
    return rebuilt


def _copy_optional_file_ref(value: EvidenceFileRef | None) -> EvidenceFileRef | None:
    if value is None:
        return None
    return _copy_file_ref(value)


def _copy_file_ref(value: EvidenceFileRef) -> EvidenceFileRef:
    if type(value) is not EvidenceFileRef:
        raise TypeError("evidence file reference model is invalid")
    return EvidenceFileRef(
        logical_path=value.logical_path,
        sha256=value.sha256,
        size=value.size,
        role=value.role,
    )


def _copy_sidecar(value: SidecarArtifact | None) -> SidecarArtifact | None:
    if value is None:
        return None
    if type(value) is not SidecarArtifact:
        raise TypeError("sidecar model is invalid")
    if type(value.extra) is not dict:
        raise TypeError("sidecar extra model is invalid")
    return SidecarArtifact(
        format=value.format,
        logical_path=value.logical_path,
        sha256=value.sha256,
        size=value.size,
        extra=dict(value.extra),
    )


def _copy_wheel_entry(value: WheelEntryRef) -> WheelEntryRef:
    if type(value) is not WheelEntryRef:
        raise TypeError("wheel entry model is invalid")
    return WheelEntryRef(
        name=value.name,
        sha256=value.sha256,
        compressed_size=value.compressed_size,
        uncompressed_size=value.uncompressed_size,
    )


def _copy_cargo_package(value: CargoPackageRef) -> CargoPackageRef:
    if type(value) is not CargoPackageRef:
        raise TypeError("Cargo package model is invalid")
    return CargoPackageRef(
        name=value.name,
        version=value.version,
        source=value.source,
        checksum=value.checksum,
        kind=value.kind,
        features=tuple(value.features),
        license=value.license,
        package_id=value.package_id,
    )


def _copy_cargo_edge(value: CargoDepEdge) -> CargoDepEdge:
    if type(value) is not CargoDepEdge:
        raise TypeError("Cargo dependency model is invalid")
    return CargoDepEdge(
        dependent_ref=value.dependent_ref,
        dependency_ref=value.dependency_ref,
    )


def _copy_runtime_inventory(
    value: NativeRuntimeInventory | None,
) -> NativeRuntimeInventory | None:
    if value is None:
        return None
    if type(value) is not NativeRuntimeInventory:
        raise TypeError("native runtime inventory model is invalid")
    return NativeRuntimeInventory(
        format=value.format,
        architecture=value.architecture,
        inspector=value.inspector,
        subject_basename=value.subject_basename,
        subject_sha256=value.subject_sha256,
        subject_size=value.subject_size,
        wheel_member=value.wheel_member,
        wheel_member_sha256=value.wheel_member_sha256,
        wheel_member_size=value.wheel_member_size,
        dependencies=tuple(_copy_runtime_dependency(item) for item in value.dependencies),
    )


def _copy_runtime_dependency(value: NativeRuntimeDependency) -> NativeRuntimeDependency:
    if type(value) is not NativeRuntimeDependency:
        raise TypeError("native runtime dependency model is invalid")
    return NativeRuntimeDependency(name=value.name, origin=value.origin)


def _validate_preview_observations(evidence: ArtifactEvidence) -> None:
    """Require structural/model bindings before marking observations satisfied.

    This intentionally does not reopen or re-inspect output bytes. C6.2-C6.4
    own those observations; C6.5 validates their immutable model bindings.
    """
    if evidence.kind != "host-extension-wheel":
        raise ValueError("preview authorization evidence kind is invalid")
    if evidence.subject is None or evidence.subject.role != "host-extension-wheel":
        raise ValueError("preview authorization requires the bound wheel subject")
    if not evidence.subject.logical_path.endswith(".whl"):
        raise ValueError("preview authorization wheel subject is invalid")
    if evidence.sbom is None or evidence.provenance is None:
        raise ValueError("preview authorization requires both sidecar bindings")
    if (
        evidence.sbom.format != "CycloneDX"
        or evidence.sbom.logical_path != evidence.subject.logical_path + ".cdx.json"
        or evidence.sbom.extra
        != {"spec_version": "1.6", "aggregate": "incomplete", "signed": False}
    ):
        raise ValueError("preview authorization SBOM binding is invalid")
    if (
        evidence.provenance.format != "in-toto-Statement"
        or evidence.provenance.logical_path
        != evidence.subject.logical_path + ".intoto.json"
        or evidence.provenance.extra
        != {
            "predicate_type": "https://slsa.dev/provenance/v1",
            "statement_type": "https://in-toto.io/Statement/v1",
            "signed": False,
        }
    ):
        raise ValueError("preview authorization provenance binding is invalid")

    input_roles = {item.role for item in evidence.inputs}
    input_paths = tuple(item.logical_path for item in evidence.inputs)
    if input_roles != _REQUIRED_INPUT_ROLES:
        raise ValueError("preview authorization requires all declared input snapshots")
    if len(input_paths) != len(set(input_paths)):
        raise ValueError("preview authorization input snapshots must be unique")

    packages = evidence.cargo_packages
    roots = tuple(package for package in packages if package.kind == "path-root")
    if len(roots) != 1:
        raise ValueError("preview authorization requires one Cargo resolve root")
    if any(package.kind not in {"path-root", "registry"} for package in packages):
        raise ValueError("preview authorization Cargo package kind is invalid")
    root = roots[0]
    if root.source is not None or root.checksum is not None:
        raise ValueError("preview authorization Cargo root identity is invalid")
    for package in packages:
        if package.kind == "registry" and (
            package.source is None or package.checksum is None
        ):
            raise ValueError("preview authorization registry package is unbound")
        if package.kind == "registry" and package.source is not None:
            if canonicalize_registry_source(package.source) != package.source:
                raise ValueError("preview authorization registry source is noncanonical")

    package_refs = {package.bom_ref() for package in packages}
    adjacency: dict[str, set[str]] = {reference: set() for reference in package_refs}
    for edge in evidence.cargo_dependencies:
        adjacency[edge.dependent_ref].add(edge.dependency_ref)
    edge_pairs = tuple(
        (edge.dependent_ref, edge.dependency_ref) for edge in evidence.cargo_dependencies
    )
    if len(edge_pairs) != len(set(edge_pairs)):
        raise ValueError("preview authorization Cargo resolve edges must be unique")
    reachable: set[str] = set()
    pending = [root.bom_ref()]
    while pending:
        current = pending.pop()
        if current in reachable:
            continue
        reachable.add(current)
        pending.extend(sorted(adjacency[current] - reachable, reverse=True))
    if reachable != package_refs:
        raise ValueError("preview authorization Cargo resolve graph is not reachable")

    wheel_names = tuple(item.name for item in evidence.wheel_entries)
    if len(wheel_names) != len(set(wheel_names)):
        raise ValueError("preview authorization wheel entries must be unique")
    runtime = evidence.native_runtime_inventory
    if runtime is None or evidence.target_triple is None:
        raise ValueError("preview authorization requires native runtime binding")
    normalized_target = evidence.target_triple.strip().lower()
    if "apple-darwin" in normalized_target:
        expected_format = ("mach-o", "otool")
    elif "linux" in normalized_target:
        expected_format = ("elf", "readelf")
    else:
        raise ValueError("preview authorization target runtime is unsupported")
    if (runtime.format, runtime.inspector) != expected_format:
        raise ValueError("preview authorization target/runtime binding is invalid")
    if runtime.architecture != _target_architecture(evidence.target_triple):
        raise ValueError("preview authorization target architecture is invalid")


def _target_architecture(target_triple: str) -> str:
    """Map the closed C6.4 host-triple architecture vocabulary."""
    token = target_triple.strip().lower().split("-", 1)[0]
    if token in {"aarch64", "arm64"}:
        return "aarch64"
    if token.startswith("arm") or token.startswith("thumb"):
        return "arm"
    if token in {"i386", "i486", "i586", "i686", "x86"}:
        return "x86"
    if token == "x86_64":
        return "x86_64"
    if token in {"powerpc", "ppc"}:
        return "powerpc"
    if token in {"powerpc64", "powerpc64le", "ppc64", "ppc64le"}:
        return "powerpc64"
    if token == "s390x":
        return "s390x"
    if token in {"riscv64gc", "riscv64"}:
        return "riscv64"
    raise ValueError("preview authorization target architecture is unsupported")
