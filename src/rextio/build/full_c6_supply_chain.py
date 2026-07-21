"""Complete, deterministic supply-chain documents for the first Full C6 scope.

This module is deliberately separate from the C6 preview evidence builders.
It consumes only the strict final receipts, reconstructs every public model,
and cross-binds their exact identities before emitting CycloneDX 1.6 and
in-toto Statement v1 / SLSA Provenance v1 documents.  The resulting receipt is
evidence for a later signature and hard gate; it never grants distribution
authority by itself.

The frozen scope remains intentionally narrow: one CPython host-extension
wheel, one depth-1 pure-Python source wheel, no plugins, and either macOS
AArch64 or Linux x86-64.  Platform-cache runtime leaves on macOS receive an
explicit platform identity derived from the target, platform-base digest, and
canonical image path.  Every other dependency/runtime leaf must carry exact
content or registry checksum identity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import re
import unicodedata
from pathlib import PurePosixPath

from rextio.artifacts.evidence import (
    EvidenceFileRef,
    WheelEntryRef,
    canonical_json_bytes,
    content_uuid_urn,
    sha256_hex,
)
from rextio.artifacts.full_authorization import FULL_C6_SCOPE
from rextio.build.full_c6_policy import (
    FULL_C6_POLICY_CLASS_IDS,
    FullC6LicenseEvidence,
    FullC6OwnerDeclaration,
    FullC6PolicyFileIdentity,
    FullC6PolicyInputRow,
    FullC6PolicyReceipt,
    FullC6TransformationRecord,
)
from rextio.build.full_c6_cargo_workspace import (
    FullC6CargoDependencyWorkspaceReceipt,
    validate_full_c6_cargo_dependency_workspace_receipt,
)
from rextio.build.full_c6_config_identity import (
    EffectiveFullC6ConfigIdentity,
    FULL_C6_EFFECTIVE_CONFIG_AGGREGATE_ID,
    FullC6ConfigIdentityError,
    effective_full_c6_config_identity_from_aggregate,
)
from rextio.build.input_closure import (
    FULL_C6_CARGO_INPUT_AGGREGATE_IDS,
    BuildInputAggregateIdentity,
    BuildInputClosure,
    ExactFileIdentity,
    bind_full_c6_cargo_workspace_aggregates,
)
from rextio.build.reproducibility import (
    ReproducibilityBuildReceipt,
    ReproducibilityReceipt,
)
from rextio.build.runtime_authorization import (
    RuntimeAuthorizationReceipt,
    RuntimeLoadedImage,
)
from rextio.build.toolchain_identity import (
    ArgvIdentity,
    BuildToolchainIdentity,
    CargoSourceIdentity,
    CargoSourcesIdentity,
    EnvironmentVariableIdentity,
    RextioIdentity,
    ToolIdentity,
)
from rextio.source.source_lock_v2 import (
    SourceLockV2Admission,
    SourceLockV2AnalysisIdentity,
    SourceLockV2FunctionIdentity,
    SourceLockV2Manifest,
)
from rextio.source.wheel_authority import (
    SourceWheelArchiveIdentity,
    SourceWheelEntryIdentity,
)


FULL_C6_SUPPLY_CHAIN_DOMAIN = "rextio.full-c6-supply-chain.v1"
FULL_C6_SBOM_KIND = "full-c6-cyclonedx-sbom"
FULL_C6_PROVENANCE_KIND = "full-c6-slsa-provenance"
FULL_C6_BUILD_TYPE = "https://rextio.dev/buildtypes/full-c6-host-extension-wheel/v1"
FULL_C6_BUILDER_ID = "https://rextio.dev/builder/full-c6-host-extension-wheel/v1"
FULL_C6_PLATFORM_IDENTITY_DOMAIN = "rextio.full-c6-runtime-platform-identity.v1"
FULL_C6_CARGO_INPUT_AGGREGATE_BINDING_DOMAIN = (
    "rextio.full-c6-cargo-input-aggregate-binding.v1"
)
FULL_C6_EFFECTIVE_CONFIG_AGGREGATE_BINDING_DOMAIN = (
    "rextio.full-c6-effective-config-aggregate-binding.v1"
)
FULL_C6_AUTHORITY_AGGREGATE_BINDING_DOMAIN = (
    "rextio.full-c6-authority-aggregate-binding.v1"
)
FULL_C6_AUTHORITY_AGGREGATE_MATERIAL_NAME = "full-c6-authority-aggregate"
FULL_C6_AUTHORITY_AGGREGATE_BINDING_FIELDS = (
    "analysis_ir_transaction_sha256",
    "license_materials_transaction_sha256",
    "output_license_contract_sha256",
    "cargo_workspace_sha256",
    "native_execution_authority_sha256",
    "native_output_transaction_sha256",
    "subject_wheel_transaction_sha256",
    "native_runtime_authority_sha256",
    "runtime_authorization_sha256",
    "executor_receipt_sha256",
)
FULL_C6_AUTHORITY_AGGREGATE_MATERIAL_NAMES = (
    "full-c6-analysis-ir-transaction",
    "full-c6-license-materials-transaction",
    "full-c6-output-license-contract",
    "full-c6-cargo-workspace",
    "full-c6-native-execution-authority",
    "full-c6-native-output-transaction",
    "full-c6-subject-wheel-transaction",
    "full-c6-native-runtime-authority",
    "runtime-authorization",
    "full-c6-executor-receipt",
)

MAX_FULL_C6_SUPPLY_CHAIN_COMPONENTS = 4096
MAX_FULL_C6_SUPPLY_CHAIN_DOCUMENT_BYTES = 8 * 1024 * 1024
MAX_FULL_C6_SUPPLY_CHAIN_JSON_DEPTH = 64
MAX_FULL_C6_SUPPLY_CHAIN_JSON_NODES = 150_000
MAX_FULL_C6_SUPPLY_CHAIN_STRING_CHARS = 4096

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:-]{0,127}$")
_TARGETS = frozenset({"aarch64-apple-darwin", "x86_64-unknown-linux-gnu"})
_FILE_INPUT_CLASSES = frozenset(
    class_id for class_id in FULL_C6_POLICY_CLASS_IDS if class_id.startswith("file-input:")
)
_WHEEL_ENTRY_CLASSES = frozenset(
    {
        "wheel-entry:packaged-native-runtime-member",
        "wheel-entry:other",
    }
)
_EXTERNAL_ENTRY_CLASSES = frozenset(
    {
        "external-source:python-source",
        "external-source:distribution-metadata",
        "external-source:license-file",
    }
)
_FULL_C6_CARGO_INPUT_AGGREGATE_ORDER = tuple(
    sorted(FULL_C6_CARGO_INPUT_AGGREGATE_IDS)
)
_FULL_C6_EFFECTIVE_CONFIG_MATERIAL_NAME = "full-c6-effective-config"


class FullC6SupplyChainError(ValueError):
    """A Full C6 evidence universe or canonical document failed closed."""


def _require_sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise FullC6SupplyChainError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _identity_alias(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def _bounded_text(value: object, label: str) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > MAX_FULL_C6_SUPPLY_CHAIN_STRING_CHARS
        or unicodedata.normalize("NFC", value) != value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise FullC6SupplyChainError(f"{label} is invalid")
    return value


def _digest(value: object) -> str:
    return sha256_hex(canonical_json_bytes(value))


@dataclass(frozen=True, slots=True)
class FullC6AuthorityAggregateBinding:
    """Closed digest identity for the typed Full C6 authority graph.

    This record is deliberately constructible and non-authorizing.  A later
    production collector must derive every value from the corresponding typed
    transaction or authority; this layer only freezes the evidence schema that
    supply-chain documents and the hard gate must bind without omission.
    """

    analysis_ir_transaction_sha256: str
    license_materials_transaction_sha256: str
    output_license_contract_sha256: str
    cargo_workspace_sha256: str
    native_execution_authority_sha256: str
    native_output_transaction_sha256: str
    subject_wheel_transaction_sha256: str
    native_runtime_authority_sha256: str
    runtime_authorization_sha256: str
    executor_receipt_sha256: str
    domain: str = field(
        default=FULL_C6_AUTHORITY_AGGREGATE_BINDING_DOMAIN,
        init=False,
    )
    schema_version: int = field(default=1, init=False)
    complete_for_scope: bool = field(default=True, init=False)
    distribution_authorized: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        if (
            self.domain != FULL_C6_AUTHORITY_AGGREGATE_BINDING_DOMAIN
            or self.schema_version != 1
            or self.complete_for_scope is not True
            or self.distribution_authorized is not False
        ):
            raise FullC6SupplyChainError(
                "Full C6 authority aggregate posture is invalid"
            )
        for field_name in FULL_C6_AUTHORITY_AGGREGATE_BINDING_FIELDS:
            _require_sha256(
                getattr(self, field_name),
                f"Full C6 authority aggregate {field_name}",
            )

    @property
    def bindings(self) -> dict[str, str]:
        """Return the exact fixed-order digest map."""
        return {
            field_name: getattr(self, field_name)
            for field_name in FULL_C6_AUTHORITY_AGGREGATE_BINDING_FIELDS
        }

    @property
    def digest(self) -> str:
        """Return the canonical semantic identity of all ten bindings."""
        return _digest(self._payload())

    def _payload(self) -> dict[str, object]:
        return {
            "domain": self.domain,
            "schema_version": self.schema_version,
            "bindings": self.bindings,
            "complete_for_scope": True,
            "distribution_authorized": False,
        }

    def to_dict(self) -> dict[str, object]:
        """Return the canonical non-authorizing evidence identity."""
        return {**self._payload(), "digest": self.digest}


def _rebuild_authority_aggregate(
    value: FullC6AuthorityAggregateBinding,
) -> FullC6AuthorityAggregateBinding:
    if type(value) is not FullC6AuthorityAggregateBinding:
        raise TypeError("Full C6 authority aggregate has an invalid type")
    try:
        rebuilt = FullC6AuthorityAggregateBinding(
            **{
                field_name: getattr(value, field_name)
                for field_name in FULL_C6_AUTHORITY_AGGREGATE_BINDING_FIELDS
            }
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise FullC6SupplyChainError(
            "Full C6 authority aggregate is not in canonical model form"
        ) from exc
    if rebuilt != value:
        raise FullC6SupplyChainError(
            "Full C6 authority aggregate is not in canonical model form"
        )
    return rebuilt


@dataclass(frozen=True, slots=True)
class FullC6CargoPathSource:
    """Exact generated Cargo root package and source-tree identity."""

    name: str
    version: str
    source_tree_sha256: str

    def __post_init__(self) -> None:
        if type(self.name) is not str or _NAME.fullmatch(self.name) is None:
            raise FullC6SupplyChainError("Cargo path root name is invalid")
        if type(self.version) is not str or _VERSION.fullmatch(self.version) is None:
            raise FullC6SupplyChainError("Cargo path root version is invalid")
        _require_sha256(self.source_tree_sha256, "Cargo path root source tree")

    @property
    def canonical_identity(self) -> str:
        """Return the identity shared with the Full C6 policy partition."""
        return f"cargo:{self.name}@{self.version}#path-root"

    def to_dict(self) -> dict[str, str]:
        """Return the deterministic path-root component identity."""
        return {
            "name": self.name,
            "version": self.version,
            "canonical_identity": self.canonical_identity,
            "source_tree_sha256": self.source_tree_sha256,
        }


@dataclass(frozen=True, slots=True)
class FullC6PartitionIdentity:
    """One canonical policy identity in an explicit class bucket."""

    canonical_identity: str
    canonical_identity_sha256: str

    def __post_init__(self) -> None:
        _bounded_text(self.canonical_identity, "Full C6 partition identity")
        _require_sha256(
            self.canonical_identity_sha256,
            "Full C6 partition identity digest",
        )

    def to_dict(self) -> dict[str, str]:
        """Return the deterministic partition member."""
        return {
            "canonical_identity": self.canonical_identity,
            "canonical_identity_sha256": self.canonical_identity_sha256,
        }


@dataclass(frozen=True, slots=True)
class FullC6ClassPartition:
    """One explicit frozen class bucket; an empty tuple means explicit zero."""

    class_id: str
    identities: tuple[FullC6PartitionIdentity, ...]

    def __post_init__(self) -> None:
        if type(self.class_id) is not str or self.class_id not in FULL_C6_POLICY_CLASS_IDS:
            raise FullC6SupplyChainError("Full C6 partition class is outside the vocabulary")
        if type(self.identities) is not tuple or any(
            type(item) is not FullC6PartitionIdentity for item in self.identities
        ):
            raise TypeError("Full C6 partition identities must be an exact tuple")
        aliases = [_identity_alias(item.canonical_identity) for item in self.identities]
        if aliases != sorted(aliases) or len(aliases) != len(set(aliases)):
            raise FullC6SupplyChainError(
                "Full C6 partition identities are noncanonical or aliased"
            )

    def to_dict(self) -> dict[str, object]:
        """Return the explicit count and exact identities for this class."""
        return {
            "class_id": self.class_id,
            "count": len(self.identities),
            "explicit_zero": not self.identities,
            "identities": [item.to_dict() for item in self.identities],
        }


@dataclass(frozen=True, slots=True)
class FullC6SupplyChainReceipt:
    """Canonical complete supply-chain documents, without distribution authority."""

    target_triple: str
    subject: EvidenceFileRef
    partition: tuple[FullC6ClassPartition, ...]
    policy_sha256: str
    source_lock_manifest_sha256: str
    source_lock_signature_sha256: str
    build_input_closure_sha256: str
    toolchain_sha256: str
    cargo_path_source_sha256: str
    runtime_authorization_sha256: str
    reproducibility_sha256: str
    reproducible_sbom_input_sha256: str
    reproducible_provenance_input_sha256: str
    authority_aggregate: FullC6AuthorityAggregateBinding
    sbom_json: bytes = field(repr=False)
    provenance_json: bytes = field(repr=False)
    cargo_input_aggregates: tuple[BuildInputAggregateIdentity, ...] = ()
    effective_config: EffectiveFullC6ConfigIdentity | None = None
    domain: str = FULL_C6_SUPPLY_CHAIN_DOMAIN
    scope: str = FULL_C6_SCOPE

    def __post_init__(self) -> None:
        if self.domain != FULL_C6_SUPPLY_CHAIN_DOMAIN or self.scope != FULL_C6_SCOPE:
            raise FullC6SupplyChainError("Full C6 supply-chain domain or scope is invalid")
        if self.target_triple not in _TARGETS:
            raise FullC6SupplyChainError("Full C6 supply-chain target is unsupported")
        subject = _rebuild_evidence_file(self.subject)
        if (
            subject.role != "host-extension-wheel"
            or subject.size <= 0
            or not subject.logical_path.endswith(".whl")
        ):
            raise FullC6SupplyChainError("Full C6 subject is not one host-extension wheel")
        partition = _rebuild_partition(self.partition)
        for value, label in (
            (self.policy_sha256, "policy"),
            (self.source_lock_manifest_sha256, "SourceLock manifest"),
            (self.source_lock_signature_sha256, "SourceLock signature"),
            (self.build_input_closure_sha256, "build-input closure"),
            (self.toolchain_sha256, "toolchain"),
            (self.cargo_path_source_sha256, "Cargo path source"),
            (self.runtime_authorization_sha256, "runtime authorization"),
            (self.reproducibility_sha256, "reproducibility"),
            (self.reproducible_sbom_input_sha256, "reproducible SBOM input"),
            (
                self.reproducible_provenance_input_sha256,
                "reproducible provenance input",
            ),
        ):
            _require_sha256(value, label)
        cargo_input_aggregates = _rebuild_cargo_input_aggregates(
            self.cargo_input_aggregates,
            allow_legacy_empty=True,
        )
        effective_config = _rebuild_effective_config_identity(
            self.effective_config,
            allow_legacy_none=True,
        )
        if bool(cargo_input_aggregates) != (effective_config is not None):
            raise FullC6SupplyChainError(
                "Full C6 Cargo and effective-config aggregate identities are incomplete"
            )
        authority_aggregate = _rebuild_authority_aggregate(
            self.authority_aggregate
        )
        if (
            authority_aggregate.runtime_authorization_sha256
            != self.runtime_authorization_sha256
        ):
            raise FullC6SupplyChainError(
                "Full C6 authority aggregate runtime authorization is stale"
            )
        sbom = validate_full_c6_supply_chain_document(self.sbom_json, document_kind="sbom")
        provenance = validate_full_c6_supply_chain_document(
            self.provenance_json,
            document_kind="provenance",
        )
        object.__setattr__(self, "subject", subject)
        object.__setattr__(self, "partition", partition)
        object.__setattr__(self, "authority_aggregate", authority_aggregate)
        object.__setattr__(self, "cargo_input_aggregates", cargo_input_aggregates)
        object.__setattr__(self, "effective_config", effective_config)
        _validate_receipt_documents(self, sbom=sbom, provenance=provenance)

    @property
    def partition_sha256(self) -> str:
        """Return the exact explicit policy-partition digest."""
        return _digest([item.to_dict() for item in self.partition])

    @property
    def sbom_sha256(self) -> str:
        """Return the canonical CycloneDX document digest."""
        return hashlib.sha256(self.sbom_json).hexdigest()

    @property
    def provenance_sha256(self) -> str:
        """Return the canonical in-toto/SLSA document digest."""
        return hashlib.sha256(self.provenance_json).hexdigest()

    @property
    def complete_for_scope(self) -> bool:
        """The reconstructed frozen partition and both documents are complete."""
        return True

    @property
    def distribution_authorized(self) -> bool:
        """Supply-chain documents are evidence, never the final hard-gate decision."""
        return False

    @property
    def digest(self) -> str:
        """Return the canonical semantic receipt digest."""
        return _digest(self._payload())

    def _payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "domain": FULL_C6_SUPPLY_CHAIN_DOMAIN,
            "scope": FULL_C6_SCOPE,
            "target_triple": self.target_triple,
            "subject": self.subject.to_dict(),
            "partition_sha256": self.partition_sha256,
            "partition": [item.to_dict() for item in self.partition],
            "authority_aggregate": self.authority_aggregate.to_dict(),
            "bindings": _receipt_bindings(self),
            "sbom": {
                "kind": FULL_C6_SBOM_KIND,
                "sha256": self.sbom_sha256,
                "size": len(self.sbom_json),
            },
            "provenance": {
                "kind": FULL_C6_PROVENANCE_KIND,
                "sha256": self.provenance_sha256,
                "size": len(self.provenance_json),
            },
            "complete_for_scope": True,
            "signed": False,
            "distribution_authorized": False,
        }
        if self.cargo_input_aggregates:
            payload["cargo_input_aggregates"] = [
                item.to_dict() for item in self.cargo_input_aggregates
            ]
        if self.effective_config is not None:
            payload["effective_config"] = self.effective_config.to_dict()
        return payload

    def to_dict(self) -> dict[str, object]:
        """Return the path-safe receipt with document hashes, not document bytes."""
        return {**self._payload(), "digest": self.digest}


def _rebuild_exact_file(value: ExactFileIdentity) -> ExactFileIdentity:
    if type(value) is not ExactFileIdentity:
        raise TypeError("exact file identity has an invalid type")
    return ExactFileIdentity(
        logical_name=value.logical_name,
        role=value.role,
        sha256=value.sha256,
        size=value.size,
        executable=value.executable,
    )


def _rebuild_build_input_aggregate(
    value: BuildInputAggregateIdentity,
) -> BuildInputAggregateIdentity:
    if type(value) is not BuildInputAggregateIdentity:
        raise TypeError("build-input aggregate identity has an invalid type")
    try:
        return BuildInputAggregateIdentity(
            aggregate_id=value.aggregate_id,
            kind=value.kind,
            digest=value.digest,
            member_count=value.member_count,
            metadata_digest=value.metadata_digest,
        )
    except (TypeError, ValueError) as exc:
        raise FullC6SupplyChainError(
            "build-input aggregate identity is not in canonical model form"
        ) from exc


def _rebuild_effective_config_identity(
    value: EffectiveFullC6ConfigIdentity | None,
    *,
    allow_legacy_none: bool,
) -> EffectiveFullC6ConfigIdentity | None:
    if value is None:
        if allow_legacy_none:
            return None
        raise FullC6SupplyChainError(
            "Full C6 requires one effective-config aggregate identity"
        )
    if type(value) is not EffectiveFullC6ConfigIdentity:
        raise TypeError("Full C6 effective-config identity has an invalid type")
    try:
        rebuilt = EffectiveFullC6ConfigIdentity(
            digest=value.digest,
            member_count=value.member_count,
            domain=value.domain,
        )
    except (TypeError, ValueError) as exc:
        raise FullC6SupplyChainError(
            "Full C6 effective-config identity is not canonical"
        ) from exc
    if rebuilt != value:
        raise FullC6SupplyChainError(
            "Full C6 effective-config identity is not canonical"
        )
    return rebuilt


def _rebuild_cargo_input_aggregates(
    value: tuple[BuildInputAggregateIdentity, ...],
    *,
    allow_legacy_empty: bool,
) -> tuple[BuildInputAggregateIdentity, ...]:
    if type(value) is not tuple:
        raise TypeError("build-input aggregates must be an exact tuple")
    if not value:
        if allow_legacy_empty:
            return ()
        raise FullC6SupplyChainError(
            "Full C6 requires all seven Cargo input aggregates"
        )
    rebuilt = tuple(_rebuild_build_input_aggregate(item) for item in value)
    aggregate_ids = tuple(item.aggregate_id for item in rebuilt)
    if aggregate_ids != _FULL_C6_CARGO_INPUT_AGGREGATE_ORDER:
        raise FullC6SupplyChainError(
            "Full C6 Cargo input aggregates are missing, extra, aliased, or reordered"
        )
    if rebuilt != tuple(
        sorted(rebuilt, key=lambda item: (item.kind, item.aggregate_id))
    ):
        raise FullC6SupplyChainError(
            "Full C6 Cargo input aggregates are not in canonical order"
        )
    if rebuilt != value:
        raise FullC6SupplyChainError(
            "build-input aggregates are not in canonical model form"
        )
    return rebuilt


def _rebuild_build_input_aggregates(
    value: tuple[BuildInputAggregateIdentity, ...],
) -> tuple[BuildInputAggregateIdentity, ...]:
    if type(value) is not tuple:
        raise TypeError("build-input aggregates must be an exact tuple")
    rebuilt = tuple(_rebuild_build_input_aggregate(item) for item in value)
    if rebuilt != tuple(
        sorted(rebuilt, key=lambda item: (item.kind, item.aggregate_id))
    ):
        raise FullC6SupplyChainError(
            "build-input aggregates are not in canonical order"
        )
    aliases = tuple(_identity_alias(item.aggregate_id) for item in rebuilt)
    if len(aliases) != len(set(aliases)) or rebuilt != value:
        raise FullC6SupplyChainError(
            "build-input aggregates are aliased or noncanonical"
        )
    return rebuilt


def _cargo_aggregate_subset(
    value: tuple[BuildInputAggregateIdentity, ...],
) -> tuple[BuildInputAggregateIdentity, ...]:
    return tuple(
        item
        for item in value
        if item.aggregate_id in FULL_C6_CARGO_INPUT_AGGREGATE_IDS
    )


def _effective_config_from_aggregates(
    value: tuple[BuildInputAggregateIdentity, ...],
) -> EffectiveFullC6ConfigIdentity:
    matches = tuple(
        item
        for item in value
        if item.aggregate_id == FULL_C6_EFFECTIVE_CONFIG_AGGREGATE_ID
    )
    expected_ids = {
        *FULL_C6_CARGO_INPUT_AGGREGATE_IDS,
        FULL_C6_EFFECTIVE_CONFIG_AGGREGATE_ID,
    }
    if len(matches) != 1 or {item.aggregate_id for item in value} != expected_ids:
        raise FullC6SupplyChainError(
            "Full C6 build-input aggregates have a missing, extra, or aliased "
            "effective-config row"
        )
    try:
        return effective_full_c6_config_identity_from_aggregate(matches[0])
    except FullC6ConfigIdentityError as exc:
        raise FullC6SupplyChainError(
            "Full C6 effective-config aggregate is noncanonical"
        ) from exc


def _rebuild_evidence_file(value: EvidenceFileRef) -> EvidenceFileRef:
    if type(value) is not EvidenceFileRef:
        raise TypeError("evidence file identity has an invalid type")
    return EvidenceFileRef(
        logical_path=value.logical_path,
        sha256=value.sha256,
        size=value.size,
        role=value.role,
    )


def _rebuild_wheel_entry(value: WheelEntryRef) -> WheelEntryRef:
    if type(value) is not WheelEntryRef:
        raise TypeError("wheel entry identity has an invalid type")
    return WheelEntryRef(
        name=value.name,
        sha256=value.sha256,
        compressed_size=value.compressed_size,
        uncompressed_size=value.uncompressed_size,
    )


def _rebuild_build_inputs(value: BuildInputClosure) -> BuildInputClosure:
    if type(value) is not BuildInputClosure:
        raise TypeError("build-input closure has an invalid type")
    aggregates = _rebuild_build_input_aggregates(value.aggregates)
    try:
        rebuilt = BuildInputClosure(
            files=tuple(_rebuild_exact_file(item) for item in value.files),
            domain=value.domain,
            scope=value.scope,
            complete_for_scope=value.complete_for_scope,
            aggregates=aggregates,
        )
    except (TypeError, ValueError) as exc:
        raise FullC6SupplyChainError(
            "build-input closure is not in canonical model form"
        ) from exc
    if rebuilt != value:
        raise FullC6SupplyChainError("build-input closure is not in canonical model form")
    return rebuilt


def _expected_full_c6_cargo_input_aggregates(
    cargo_dependency_workspace: FullC6CargoDependencyWorkspaceReceipt,
) -> tuple[BuildInputAggregateIdentity, ...]:
    if (
        type(cargo_dependency_workspace) is not FullC6CargoDependencyWorkspaceReceipt
        or not validate_full_c6_cargo_dependency_workspace_receipt(
            cargo_dependency_workspace
        )
    ):
        raise FullC6SupplyChainError(
            "Full C6 Cargo input aggregates require a process-sealed workspace"
        )
    # The binder's seven rows depend only on the process-sealed workspace.  A
    # fixed path-free sentinel lets receipt verification reuse that one
    # authoritative derivation without retaining arbitrary build-input files.
    sentinel = BuildInputClosure(
        files=(
            ExactFileIdentity(
                logical_name="full-c6/cargo-aggregate-authority",
                role="cargo-aggregate-authority",
                sha256="0" * 64,
                size=0,
                executable=False,
            ),
        )
    )
    try:
        expected = bind_full_c6_cargo_workspace_aggregates(
            sentinel,
            cargo_dependency_workspace,
        ).aggregates
    except (TypeError, ValueError, RuntimeError) as exc:
        raise FullC6SupplyChainError(
            "Full C6 Cargo input aggregate authority could not be derived"
        ) from exc
    return _rebuild_cargo_input_aggregates(expected, allow_legacy_empty=False)


def _require_authoritative_cargo_input_aggregates(
    aggregates: tuple[BuildInputAggregateIdentity, ...],
    cargo_dependency_workspace: FullC6CargoDependencyWorkspaceReceipt,
) -> tuple[BuildInputAggregateIdentity, ...]:
    trusted = _rebuild_cargo_input_aggregates(
        aggregates,
        allow_legacy_empty=False,
    )
    expected = _expected_full_c6_cargo_input_aggregates(cargo_dependency_workspace)
    if trusted != expected:
        raise FullC6SupplyChainError(
            "Full C6 Cargo input aggregates do not match the process-sealed workspace"
        )
    return trusted


def validate_full_c6_cargo_input_aggregates(
    build_inputs: BuildInputClosure,
    cargo_dependency_workspace: FullC6CargoDependencyWorkspaceReceipt,
) -> BuildInputClosure:
    """Cross-bind all seven digest-only Cargo rows to one sealed workspace.

    This is the explicit gate-facing bridge.  It does not trust caller-supplied
    aggregate digests, counts, or metadata digests and retains no workspace
    bytes or filesystem paths.
    """
    trusted = _rebuild_build_inputs(build_inputs)
    _effective_config_from_aggregates(trusted.aggregates)
    _require_authoritative_cargo_input_aggregates(
        _cargo_aggregate_subset(trusted.aggregates),
        cargo_dependency_workspace,
    )
    return trusted


def _rebuild_policy_file(value: FullC6PolicyFileIdentity) -> FullC6PolicyFileIdentity:
    if type(value) is not FullC6PolicyFileIdentity:
        raise TypeError("policy file identity has an invalid type")
    return FullC6PolicyFileIdentity(value.logical_path, value.sha256, value.size, value.role)


def _rebuild_license(value: FullC6LicenseEvidence) -> FullC6LicenseEvidence:
    if type(value) is not FullC6LicenseEvidence:
        raise TypeError("license evidence has an invalid type")
    return FullC6LicenseEvidence(
        declared_spdx=value.declared_spdx,
        detected_spdx=value.detected_spdx,
        subject_authority_identity=value.subject_authority_identity,
        subject_identity_sha256=value.subject_identity_sha256,
        authority_partition_sha256=value.authority_partition_sha256,
        source_detector_receipt_sha256=value.source_detector_receipt_sha256,
        detector_payload_sha256=value.detector_payload_sha256,
        license_files=tuple(_rebuild_policy_file(item) for item in value.license_files),
        detector_receipt_kind=value.detector_receipt_kind,
    )


def _rebuild_policy_row(value: FullC6PolicyInputRow) -> FullC6PolicyInputRow:
    if type(value) is not FullC6PolicyInputRow:
        raise TypeError("policy input row has an invalid type")
    return FullC6PolicyInputRow(
        class_id=value.class_id,
        canonical_identity=value.canonical_identity,
        authority_identity=value.authority_identity,
        identity_mode=value.identity_mode,
        sha256=value.sha256,
        size=value.size,
        license_disposition=value.license_disposition,
        transformation_disposition=value.transformation_disposition,
        license_evidence=(
            None if value.license_evidence is None else _rebuild_license(value.license_evidence)
        ),
    )


def _rebuild_transformation(value: FullC6TransformationRecord) -> FullC6TransformationRecord:
    if type(value) is not FullC6TransformationRecord:
        raise TypeError("transformation record has an invalid type")
    return FullC6TransformationRecord(
        record_id=value.record_id,
        kind=value.kind,
        source_identities=tuple(value.source_identities),
        source_identity_sha256s=tuple(value.source_identity_sha256s),
        output_identity=value.output_identity,
        output_identity_sha256=value.output_identity_sha256,
        authority_partition_sha256=value.authority_partition_sha256,
        source_identity_set_sha256=value.source_identity_set_sha256,
        generator_sha256=value.generator_sha256,
        analysis_sha256=value.analysis_sha256,
        analysis_receipt_sha256=value.analysis_receipt_sha256,
        lowered_ir_sha256=value.lowered_ir_sha256,
        lowered_ir_receipt_sha256=value.lowered_ir_receipt_sha256,
        analysis_receipt_kind=value.analysis_receipt_kind,
        lowered_ir_receipt_kind=value.lowered_ir_receipt_kind,
    )


def _rebuild_owner(value: FullC6OwnerDeclaration) -> FullC6OwnerDeclaration:
    if type(value) is not FullC6OwnerDeclaration:
        raise TypeError("owner declaration has an invalid type")
    return FullC6OwnerDeclaration(
        owner_identity=value.owner_identity,
        owner_role=value.owner_role,
        trusted_public_key_sha256=value.trusted_public_key_sha256,
        decision=value.decision,
        action_scopes=tuple(value.action_scopes),
        acknowledgement=value.acknowledgement,
        authentication=value.authentication,
    )


def _rebuild_policy(value: FullC6PolicyReceipt) -> FullC6PolicyReceipt:
    if type(value) is not FullC6PolicyReceipt:
        raise TypeError("Full C6 policy receipt has an invalid type")
    rebuilt = FullC6PolicyReceipt(
        rows=tuple(_rebuild_policy_row(item) for item in value.rows),
        transformations=tuple(_rebuild_transformation(item) for item in value.transformations),
        owner_declaration=_rebuild_owner(value.owner_declaration),
        artifact_coverage=value.artifact_coverage,
        external_authority=value.external_authority,
        bootstrap_request_sha256=value.bootstrap_request_sha256,
    )
    if rebuilt != value:
        raise FullC6SupplyChainError("Full C6 policy is not in canonical model form")
    return rebuilt


def _rebuild_source_entry(value: SourceWheelEntryIdentity) -> SourceWheelEntryIdentity:
    if type(value) is not SourceWheelEntryIdentity:
        raise TypeError("source-wheel entry identity has an invalid type")
    return SourceWheelEntryIdentity(
        path=value.path,
        sha256=value.sha256,
        size=value.size,
        compressed_size=value.compressed_size,
        crc32=value.crc32,
        unix_mode=value.unix_mode,
    )


def _rebuild_source_analysis(value: SourceLockV2AnalysisIdentity) -> SourceLockV2AnalysisIdentity:
    if type(value) is not SourceLockV2AnalysisIdentity:
        raise TypeError("SourceLock analysis identity has an invalid type")
    return SourceLockV2AnalysisIdentity(
        module_name=value.module_name,
        source_sha256=value.source_sha256,
        semantic_sha256=value.semantic_sha256,
        functions=tuple(
            SourceLockV2FunctionIdentity(
                qualname=item.qualname,
                semantic_ast_sha256=item.semantic_ast_sha256,
                lowered_ir_sha256=item.lowered_ir_sha256,
            )
            for item in value.functions
            if type(item) is SourceLockV2FunctionIdentity
        ),
    )


def _rebuild_source_lock(value: SourceLockV2Manifest) -> SourceLockV2Manifest:
    if type(value) is not SourceLockV2Manifest:
        raise TypeError("SourceLock v2 manifest has an invalid type")
    if type(value.archive) is not SourceWheelArchiveIdentity:
        raise TypeError("SourceLock archive identity has an invalid type")
    archive = SourceWheelArchiveIdentity(
        filename=value.archive.filename,
        sha256=value.archive.sha256,
        size=value.archive.size,
    )
    rebuilt = SourceLockV2Manifest(
        package=value.package,
        distribution=value.distribution,
        version=value.version,
        plan_snapshot_sha256=value.plan_snapshot_sha256,
        wheel_authority_sha256=value.wheel_authority_sha256,
        archive=archive,
        entries=tuple(_rebuild_source_entry(item) for item in value.entries),
        analyses=tuple(_rebuild_source_analysis(item) for item in value.analyses),
        declared_license=value.declared_license,
        observed_license=value.observed_license,
        license_material_sha256=value.license_material_sha256,
        license_evidence_sha256=value.license_evidence_sha256,
        owner=value.owner,
        allow=value.allow,
        redistribute=value.redistribute,
        transform=value.transform,
        trusted_public_key_sha256=value.trusted_public_key_sha256,
    )
    if rebuilt != value:
        raise FullC6SupplyChainError("SourceLock manifest is not in canonical model form")
    return rebuilt


def _rebuild_source_admission(value: SourceLockV2Admission) -> SourceLockV2Admission:
    if type(value) is not SourceLockV2Admission:
        raise TypeError("SourceLock admission has an invalid type")
    rebuilt = SourceLockV2Admission(
        status=value.status,
        reason=value.reason,
        manifest_sha256=value.manifest_sha256,
        public_key_sha256=value.public_key_sha256,
        signature_sha256=value.signature_sha256,
        domain=value.domain,
        prebuild_admitted=value.prebuild_admitted,
        authorizes_build=value.authorizes_build,
        authorizes_distribution=value.authorizes_distribution,
    )
    if rebuilt != value:
        raise FullC6SupplyChainError("SourceLock admission is not in canonical model form")
    return rebuilt


def _rebuild_tool(value: ToolIdentity) -> ToolIdentity:
    if type(value) is not ToolIdentity:
        raise TypeError("tool identity has an invalid type")
    return ToolIdentity(
        name=value.name,
        executable=_rebuild_exact_file(value.executable),
        reported_version=value.reported_version,
    )


def _rebuild_toolchain(value: BuildToolchainIdentity) -> BuildToolchainIdentity:
    if type(value) is not BuildToolchainIdentity:
        raise TypeError("build toolchain identity has an invalid type")
    if type(value.rextio) is not RextioIdentity:
        raise TypeError("Rextio toolchain identity has an invalid type")
    rextio = RextioIdentity(
        version=value.rextio.version,
        files=tuple(_rebuild_exact_file(item) for item in value.rextio.files),
        content_digest=value.rextio.content_digest,
        name=value.rextio.name,
    )
    if type(value.argv) is not ArgvIdentity:
        raise TypeError("toolchain argv identity has an invalid type")
    argv = ArgvIdentity(values=tuple(value.argv.values))
    environment = tuple(
        EnvironmentVariableIdentity(item.name, item.value_sha256, item.value_size)
        for item in value.environment
        if type(item) is EnvironmentVariableIdentity
    )
    if type(value.cargo_sources) is not CargoSourcesIdentity:
        raise TypeError("Cargo sources identity has an invalid type")
    cargo_sources = CargoSourcesIdentity(
        root_package=value.cargo_sources.root_package,
        lock_file=_rebuild_exact_file(value.cargo_sources.lock_file),
        packages=tuple(
            CargoSourceIdentity(item.name, item.version, item.source, item.checksum)
            for item in value.cargo_sources.packages
            if type(item) is CargoSourceIdentity
        ),
        complete_for_scope=value.cargo_sources.complete_for_scope,
    )
    rebuilt = BuildToolchainIdentity(
        python=_rebuild_tool(value.python),
        rextio=rextio,
        cargo=_rebuild_tool(value.cargo),
        rustc=_rebuild_tool(value.rustc),
        linker=_rebuild_tool(value.linker),
        inspectors=tuple(_rebuild_tool(item) for item in value.inspectors),
        argv=argv,
        environment=environment,
        cargo_sources=cargo_sources,
        domain=value.domain,
        scope=value.scope,
        complete_for_scope=value.complete_for_scope,
    )
    if rebuilt != value:
        raise FullC6SupplyChainError("toolchain identity is not in canonical model form")
    return rebuilt


def _rebuild_runtime_image(value: RuntimeLoadedImage) -> RuntimeLoadedImage:
    if type(value) is not RuntimeLoadedImage:
        raise TypeError("runtime image identity has an invalid type")
    return RuntimeLoadedImage(value.path, value.device, value.inode, value.sha256, value.size)


def _rebuild_runtime(value: RuntimeAuthorizationReceipt) -> RuntimeAuthorizationReceipt:
    if type(value) is not RuntimeAuthorizationReceipt:
        raise TypeError("runtime authorization receipt has an invalid type")
    rebuilt = RuntimeAuthorizationReceipt(
        target_triple=value.target_triple,
        extension=_rebuild_runtime_image(value.extension),
        platform_base_sha256=value.platform_base_sha256,
        declared_system_images=tuple(
            _rebuild_runtime_image(item) for item in value.declared_system_images
        ),
        declared_system_platform_images=tuple(value.declared_system_platform_images),
        newly_loaded_images=tuple(_rebuild_runtime_image(item) for item in value.newly_loaded_images),
        newly_loaded_platform_images=tuple(value.newly_loaded_platform_images),
        path_resolution_sha256=value.path_resolution_sha256,
        transitive_closure_sha256=value.transitive_closure_sha256,
        load_commands_sha256=value.load_commands_sha256,
        imported_symbols_sha256=value.imported_symbols_sha256,
        final_snapshot_sha256=value.final_snapshot_sha256,
        verification_mode=value.verification_mode,
    )
    if rebuilt != value:
        raise FullC6SupplyChainError("runtime authorization is not in canonical model form")
    return rebuilt


def _rebuild_repro_build(value: ReproducibilityBuildReceipt) -> ReproducibilityBuildReceipt:
    if type(value) is not ReproducibilityBuildReceipt:
        raise TypeError("reproducibility build receipt has an invalid type")
    return ReproducibilityBuildReceipt(
        ordinal=value.ordinal,
        unsigned_wheel=_rebuild_exact_file(value.unsigned_wheel),
        sbom_json=_rebuild_exact_file(value.sbom_json),
        provenance_input_json=_rebuild_exact_file(value.provenance_input_json),
        sbom_canonical_sha256=value.sbom_canonical_sha256,
        provenance_input_canonical_sha256=value.provenance_input_canonical_sha256,
    )


def _rebuild_reproducibility(value: ReproducibilityReceipt) -> ReproducibilityReceipt:
    if type(value) is not ReproducibilityReceipt:
        raise TypeError("reproducibility receipt has an invalid type")
    builds = tuple(_rebuild_repro_build(item) for item in value.builds)
    if len(builds) != 2:
        raise FullC6SupplyChainError("reproducibility receipt must contain two builds")
    rebuilt = ReproducibilityReceipt(
        builds=(builds[0], builds[1]),
        domain=value.domain,
        scope=value.scope,
        reproducible=value.reproducible,
        complete_for_scope=value.complete_for_scope,
        authorizes_distribution=value.authorizes_distribution,
    )
    if rebuilt != value:
        raise FullC6SupplyChainError("reproducibility receipt is not in canonical model form")
    return rebuilt


def _rebuild_partition(
    value: tuple[FullC6ClassPartition, ...],
) -> tuple[FullC6ClassPartition, ...]:
    if type(value) is not tuple:
        raise TypeError("Full C6 class partition must be an exact tuple")
    rebuilt = tuple(
        FullC6ClassPartition(
            class_id=item.class_id,
            identities=tuple(
                FullC6PartitionIdentity(
                    canonical_identity=identity.canonical_identity,
                    canonical_identity_sha256=identity.canonical_identity_sha256,
                )
                for identity in item.identities
                if type(identity) is FullC6PartitionIdentity
            ),
        )
        for item in value
        if type(item) is FullC6ClassPartition
    )
    if tuple(item.class_id for item in rebuilt) != FULL_C6_POLICY_CLASS_IDS:
        raise FullC6SupplyChainError(
            "Full C6 class partition lacks exact frozen coverage and order"
        )
    aliases = [
        _identity_alias(identity.canonical_identity)
        for item in rebuilt
        for identity in item.identities
    ]
    if len(aliases) != len(set(aliases)):
        raise FullC6SupplyChainError("Full C6 partition contains a cross-class alias")
    if rebuilt != value:
        raise FullC6SupplyChainError("Full C6 partition is not in canonical model form")
    return rebuilt


def _partition_from_policy(
    policy: FullC6PolicyReceipt,
) -> tuple[FullC6ClassPartition, ...]:
    rows_by_class: dict[str, list[FullC6PolicyInputRow]] = {
        class_id: [] for class_id in FULL_C6_POLICY_CLASS_IDS
    }
    for row in policy.rows:
        rows_by_class[row.class_id].append(row)
    return tuple(
        FullC6ClassPartition(
            class_id=class_id,
            identities=tuple(
                FullC6PartitionIdentity(
                    canonical_identity=row.canonical_identity,
                    canonical_identity_sha256=row.canonical_identity_sha256,
                )
                for row in sorted(
                    rows_by_class[class_id],
                    key=lambda item: _identity_alias(item.canonical_identity),
                )
            ),
        )
        for class_id in FULL_C6_POLICY_CLASS_IDS
    )


def _row_map(
    rows: tuple[FullC6PolicyInputRow, ...],
    classes: frozenset[str],
) -> dict[str, FullC6PolicyInputRow]:
    return {
        _identity_alias(row.canonical_identity): row
        for row in rows
        if row.class_id in classes
    }


def _require_exact_file_set(
    expected: dict[str, FullC6PolicyInputRow],
    observed: dict[str, tuple[str, str, int]],
    *,
    label: str,
) -> None:
    if set(expected) != set(observed):
        raise FullC6SupplyChainError(f"{label} does not match the exact policy partition")
    for alias, row in expected.items():
        canonical_identity, digest, size = observed[alias]
        if (
            row.canonical_identity != canonical_identity
            or row.sha256 != digest
            or row.size != size
        ):
            raise FullC6SupplyChainError(f"{label} contains a stale content identity")


@dataclass(frozen=True, slots=True)
class _RuntimeBinding:
    canonical_identity: str
    digest: str
    size: int | None
    identity_mode: str
    path: str


def _system_identity(path: str) -> str:
    name = PurePosixPath(path).name
    if not name:
        raise FullC6SupplyChainError("runtime system leaf has no canonical basename")
    return f"system:{name}"


def _runtime_bindings(runtime: RuntimeAuthorizationReceipt) -> dict[str, _RuntimeBinding]:
    result: dict[str, _RuntimeBinding] = {}
    for image in runtime.declared_system_images:
        identity = _system_identity(image.path)
        alias = _identity_alias(identity)
        binding = _RuntimeBinding(identity, image.sha256, image.size, "content-sha256", image.path)
        if alias in result:
            raise FullC6SupplyChainError("runtime system images contain a basename alias")
        result[alias] = binding
    for path in runtime.declared_system_platform_images:
        identity = _system_identity(path)
        alias = _identity_alias(identity)
        platform = {
            "domain": FULL_C6_PLATFORM_IDENTITY_DOMAIN,
            "target_triple": runtime.target_triple,
            "platform_base_sha256": runtime.platform_base_sha256,
            "path": path,
        }
        binding = _RuntimeBinding(identity, _digest(platform), None, "platform-identity", path)
        if alias in result:
            raise FullC6SupplyChainError("runtime platform images contain a basename alias")
        result[alias] = binding
    return result


def _validate_bindings(
    *,
    subject: EvidenceFileRef,
    policy: FullC6PolicyReceipt,
    build_inputs: BuildInputClosure,
    wheel_entries: tuple[WheelEntryRef, ...],
    source_lock: SourceLockV2Manifest,
    source_admission: SourceLockV2Admission,
    toolchain: BuildToolchainIdentity,
    cargo_root: FullC6CargoPathSource,
    runtime: RuntimeAuthorizationReceipt,
    reproducibility: ReproducibilityReceipt,
) -> dict[str, _RuntimeBinding]:
    rows = policy.rows
    subjects = tuple(row for row in rows if row.class_id == "wheel-output:subject")
    if (
        len(subjects) != 1
        or subjects[0].canonical_identity != subject.logical_path
        or subjects[0].sha256 != subject.sha256
        or subjects[0].size != subject.size
    ):
        raise FullC6SupplyChainError("subject wheel is stale or missing from the policy partition")

    expected_inputs = _row_map(rows, _FILE_INPUT_CLASSES)
    observed_inputs = {
        _identity_alias(item.logical_name): (item.logical_name, item.sha256, item.size)
        for item in build_inputs.files
    }
    _require_exact_file_set(expected_inputs, observed_inputs, label="build-input closure")

    expected_wheel_entries = _row_map(rows, _WHEEL_ENTRY_CLASSES)
    observed_wheel_entries = {
        _identity_alias(f"wheel/{item.name}"): (
            f"wheel/{item.name}",
            item.sha256,
            item.uncompressed_size,
        )
        for item in wheel_entries
    }
    _require_exact_file_set(
        expected_wheel_entries,
        observed_wheel_entries,
        label="subject wheel entries",
    )

    archive_rows = tuple(row for row in rows if row.class_id == "external-source:wheel-archive")
    expected_archive_identity = f"external/{source_lock.archive.filename}"
    if (
        len(archive_rows) != 1
        or archive_rows[0].canonical_identity != expected_archive_identity
        or archive_rows[0].sha256 != source_lock.archive.sha256
        or archive_rows[0].size != source_lock.archive.size
    ):
        raise FullC6SupplyChainError("external source archive binding is stale")
    expected_external_entries = _row_map(rows, _EXTERNAL_ENTRY_CLASSES)
    observed_external_entries = {
        _identity_alias(f"external/{item.path}"): (
            f"external/{item.path}",
            item.sha256,
            item.size,
        )
        for item in source_lock.entries
    }
    if len(observed_external_entries) != len(source_lock.entries):
        raise FullC6SupplyChainError("external source wheel entries contain an alias")
    _require_exact_file_set(
        expected_external_entries,
        observed_external_entries,
        label="external source wheel entries",
    )
    source_rows = tuple(row for row in rows if row.class_id == "external-source:python-source")
    if sorted(row.sha256 or "" for row in source_rows) != sorted(
        item.source_sha256 for item in source_lock.analyses
    ):
        raise FullC6SupplyChainError("external source analysis does not bind every source entry")
    if (
        source_admission.status != "admitted"
        or source_admission.prebuild_admitted is not True
        or source_admission.manifest_sha256 != source_lock.manifest_sha256
        or source_admission.public_key_sha256 != source_lock.trusted_public_key_sha256
        or source_admission.signature_sha256 is None
    ):
        raise FullC6SupplyChainError("SourceLock v2 admission does not bind the exact manifest")

    registry_rows = {
        _identity_alias(row.canonical_identity): row
        for row in rows
        if row.class_id == "cargo-component:registry-package"
    }
    registry_packages = {
        _identity_alias(f"cargo:{item.name}@{item.version}#registry"): item
        for item in toolchain.cargo_sources.packages
    }
    if len(registry_packages) != len(toolchain.cargo_sources.packages):
        raise FullC6SupplyChainError("Cargo registry source identities contain an alias")
    if set(registry_rows) != set(registry_packages):
        raise FullC6SupplyChainError("Cargo registry sources do not match the policy partition")
    for alias, package in registry_packages.items():
        identity = f"cargo:{package.name}@{package.version}#registry"
        if (
            registry_rows[alias].canonical_identity != identity
            or registry_rows[alias].sha256 != package.checksum
        ):
            raise FullC6SupplyChainError("Cargo registry checksum is stale")
    root_rows = tuple(row for row in rows if row.class_id == "cargo-component:path-root-package")
    if (
        len(root_rows) != 1
        or root_rows[0].canonical_identity != cargo_root.canonical_identity
        or root_rows[0].sha256 != cargo_root.source_tree_sha256
        or toolchain.cargo_sources.root_package != cargo_root.name
    ):
        raise FullC6SupplyChainError("Cargo path-root source identity is stale")
    lock_rows = tuple(row for row in rows if row.class_id == "file-input:generated-cargo-lock")
    lock = toolchain.cargo_sources.lock_file
    if (
        len(lock_rows) != 1
        or lock_rows[0].canonical_identity != lock.logical_name
        or lock_rows[0].sha256 != lock.sha256
        or lock_rows[0].size != lock.size
    ):
        raise FullC6SupplyChainError("toolchain Cargo.lock binding is stale")

    native_rows = tuple(
        row for row in rows if row.class_id == "wheel-entry:packaged-native-runtime-member"
    )
    if (
        len(native_rows) != 1
        or native_rows[0].sha256 != runtime.extension.sha256
        or native_rows[0].size != runtime.extension.size
    ):
        raise FullC6SupplyChainError("runtime extension does not bind the packaged native member")
    runtime_bindings = _runtime_bindings(runtime)
    system_rows = {
        _identity_alias(row.canonical_identity): row
        for row in rows
        if row.class_id == "native-runtime:logical-system-leaf"
    }
    if set(system_rows) != set(runtime_bindings):
        raise FullC6SupplyChainError("runtime leaves lack exact content/checksum/platform identity")
    if any(
        row.canonical_identity != runtime_bindings[alias].canonical_identity
        for alias, row in system_rows.items()
    ):
        raise FullC6SupplyChainError("runtime leaf is a noncanonical path alias")

    if reproducibility.wheel_sha256 != subject.sha256 or any(
        build.unsigned_wheel.size != subject.size for build in reproducibility.builds
    ):
        raise FullC6SupplyChainError("two-build reproducibility identity has a stale subject")
    return runtime_bindings


def _receipt_materials(
    *,
    policy: FullC6PolicyReceipt,
    source_lock: SourceLockV2Manifest,
    source_admission: SourceLockV2Admission,
    build_inputs: BuildInputClosure,
    toolchain: BuildToolchainIdentity,
    cargo_root: FullC6CargoPathSource,
    runtime: RuntimeAuthorizationReceipt,
    reproducibility: ReproducibilityReceipt,
    authority_aggregate: FullC6AuthorityAggregateBinding,
) -> tuple[tuple[str, str], ...]:
    signature = source_admission.signature_sha256
    if signature is None:  # guarded before document construction
        raise FullC6SupplyChainError("SourceLock signature identity is missing")
    base = (
        ("full-c6-license-transformation-policy", policy.digest),
        ("source-lock-v2-manifest", source_lock.manifest_sha256),
        ("source-lock-v2-signature", signature),
        ("build-input-closure", build_inputs.digest),
        ("builder-toolchain", toolchain.digest),
        ("cargo-path-source", cargo_root.source_tree_sha256),
        (FULL_C6_AUTHORITY_AGGREGATE_MATERIAL_NAME, authority_aggregate.digest),
        *_authority_aggregate_materials(authority_aggregate),
        ("two-build-reproducibility", reproducibility.digest),
        ("reproducible-sbom-input", reproducibility.sbom_canonical_sha256),
        (
            "reproducible-provenance-input",
            reproducibility.provenance_input_canonical_sha256,
        ),
    )
    return base + tuple(
        (
            _cargo_aggregate_material_name(item),
            _cargo_aggregate_identity_digest(item),
        )
        for item in build_inputs.aggregates
    )


def _authority_aggregate_materials(
    value: FullC6AuthorityAggregateBinding,
) -> tuple[tuple[str, str], ...]:
    return tuple(
        (material_name, getattr(value, field_name))
        for material_name, field_name in zip(
            FULL_C6_AUTHORITY_AGGREGATE_MATERIAL_NAMES,
            FULL_C6_AUTHORITY_AGGREGATE_BINDING_FIELDS,
            strict=True,
        )
    )


def _evidence_sbom_component(name: str, digest: str) -> dict[str, object]:
    return {
        "type": "data",
        "bom-ref": f"urn:rextio:full-c6-evidence:{name}:{digest}",
        "name": name,
        "hashes": [{"alg": "SHA-256", "content": digest}],
        "properties": [
            {"name": "rextio:role", "value": "non-authorizing-evidence-receipt"}
        ],
    }


def _evidence_provenance_dependency(name: str, digest: str) -> dict[str, object]:
    return {
        "uri": f"urn:rextio:full-c6-evidence:{name}",
        "digest": {"sha256": digest},
        "annotations": {"rextio:role": "non-authorizing-evidence-receipt"},
    }


def _cargo_aggregate_material_name(item: BuildInputAggregateIdentity) -> str:
    if item.aggregate_id == FULL_C6_EFFECTIVE_CONFIG_AGGREGATE_ID:
        return _FULL_C6_EFFECTIVE_CONFIG_MATERIAL_NAME
    return f"full-c6-cargo-input-aggregate:{item.aggregate_id}"


def _cargo_aggregate_identity_digest(item: BuildInputAggregateIdentity) -> str:
    domain = (
        FULL_C6_EFFECTIVE_CONFIG_AGGREGATE_BINDING_DOMAIN
        if item.aggregate_id == FULL_C6_EFFECTIVE_CONFIG_AGGREGATE_ID
        else FULL_C6_CARGO_INPUT_AGGREGATE_BINDING_DOMAIN
    )
    return _digest(
        {
            "domain": domain,
            "aggregate": item.to_dict(),
        }
    )


def _cargo_aggregate_annotations(
    item: BuildInputAggregateIdentity,
) -> dict[str, str]:
    annotations = {
        "rextio:role": (
            "resolved-full-c6-effective-config"
            if item.aggregate_id == FULL_C6_EFFECTIVE_CONFIG_AGGREGATE_ID
            else "process-sealed-cargo-input-aggregate"
        ),
        "rextio:aggregate_id": item.aggregate_id,
        "rextio:aggregate_kind": item.kind,
        "rextio:aggregate_digest": item.digest,
        "rextio:member_count": str(item.member_count),
    }
    if item.metadata_digest is not None:
        annotations["rextio:metadata_digest"] = item.metadata_digest
    return annotations


def _effective_config_aggregate_from_identity(
    value: EffectiveFullC6ConfigIdentity,
) -> BuildInputAggregateIdentity:
    rebuilt = _rebuild_effective_config_identity(
        value,
        allow_legacy_none=False,
    )
    if rebuilt is None:  # pragma: no cover - excluded by allow_legacy_none=False
        raise FullC6SupplyChainError("Full C6 effective-config identity is missing")
    return rebuilt.to_build_input_aggregate()


def _cargo_aggregate_sbom_component(
    item: BuildInputAggregateIdentity,
) -> dict[str, object]:
    name = _cargo_aggregate_material_name(item)
    digest = _cargo_aggregate_identity_digest(item)
    return {
        "type": "data",
        "bom-ref": f"urn:rextio:full-c6-evidence:{name}:{digest}",
        "name": name,
        "hashes": [{"alg": "SHA-256", "content": digest}],
        "properties": [
            {"name": key, "value": value}
            for key, value in _cargo_aggregate_annotations(item).items()
        ],
    }


def _cargo_aggregate_provenance_dependency(
    item: BuildInputAggregateIdentity,
) -> dict[str, object]:
    name = _cargo_aggregate_material_name(item)
    return {
        "uri": f"urn:rextio:full-c6-evidence:{name}",
        "digest": {"sha256": _cargo_aggregate_identity_digest(item)},
        "annotations": _cargo_aggregate_annotations(item),
    }


def _runtime_row_binding(
    row: FullC6PolicyInputRow,
    runtime_bindings: dict[str, _RuntimeBinding],
) -> tuple[str, int | None, str, str | None]:
    if row.class_id != "native-runtime:logical-system-leaf":
        if row.sha256 is None:
            raise FullC6SupplyChainError("dependency row has no exact digest")
        return row.sha256, row.size, row.identity_mode, None
    binding = runtime_bindings[_identity_alias(row.canonical_identity)]
    return binding.digest, binding.size, binding.identity_mode, binding.path


def _component_from_row(
    row: FullC6PolicyInputRow,
    *,
    runtime_bindings: dict[str, _RuntimeBinding],
    registry: dict[str, CargoSourceIdentity],
    cargo_root: FullC6CargoPathSource,
) -> dict[str, object]:
    digest, size, identity_mode, runtime_path = _runtime_row_binding(row, runtime_bindings)
    bom_ref = (
        f"urn:rextio:full-c6-component:{row.class_id}:"
        f"{row.canonical_identity_sha256}"
    )
    properties: list[dict[str, str]] = [
        {"name": "rextio:class_id", "value": row.class_id},
        {"name": "rextio:canonical_identity", "value": row.canonical_identity},
        {"name": "rextio:identity_mode", "value": identity_mode},
        {"name": "rextio:license_disposition", "value": row.license_disposition},
        {
            "name": "rextio:transformation_disposition",
            "value": row.transformation_disposition,
        },
    ]
    if size is not None:
        properties.append({"name": "rextio:size", "value": str(size)})
    if runtime_path is not None:
        properties.append({"name": "rextio:runtime_path", "value": runtime_path})
    component: dict[str, object] = {
        "type": (
            "library"
            if row.class_id.startswith(("cargo-component:", "native-runtime:"))
            else "file"
        ),
        "bom-ref": bom_ref,
        "name": row.canonical_identity,
        "hashes": [{"alg": "SHA-256", "content": digest}],
        "properties": properties,
    }
    if row.license_evidence is not None:
        component["licenses"] = [{"expression": row.license_evidence.declared_spdx}]
    if row.class_id == "cargo-component:registry-package":
        package = registry[_identity_alias(row.canonical_identity)]
        component["name"] = package.name
        component["version"] = package.version
        component["purl"] = f"pkg:cargo/{package.name}@{package.version}"
        component["externalReferences"] = [
            {"type": "distribution", "url": package.source.removeprefix("registry+")}
        ]
    elif row.class_id == "cargo-component:path-root-package":
        component["name"] = cargo_root.name
        component["version"] = cargo_root.version
        component["purl"] = f"pkg:cargo/{cargo_root.name}@{cargo_root.version}"
    return component


def _material_from_row(
    row: FullC6PolicyInputRow,
    runtime_bindings: dict[str, _RuntimeBinding],
) -> dict[str, object]:
    digest, size, identity_mode, runtime_path = _runtime_row_binding(row, runtime_bindings)
    annotations: dict[str, str] = {
        "rextio:class_id": row.class_id,
        "rextio:identity_mode": identity_mode,
        "rextio:canonical_identity_sha256": row.canonical_identity_sha256,
    }
    if size is not None:
        annotations["rextio:size"] = str(size)
    if runtime_path is not None:
        annotations["rextio:runtime_path"] = runtime_path
    return {
        "uri": (
            f"urn:rextio:full-c6-input:{row.class_id}:"
            f"{row.canonical_identity_sha256}"
        ),
        "digest": {"sha256": digest},
        "annotations": annotations,
    }


def _build_sbom(
    *,
    target_triple: str,
    subject: EvidenceFileRef,
    policy: FullC6PolicyReceipt,
    source_lock: SourceLockV2Manifest,
    source_admission: SourceLockV2Admission,
    build_inputs: BuildInputClosure,
    toolchain: BuildToolchainIdentity,
    cargo_root: FullC6CargoPathSource,
    runtime: RuntimeAuthorizationReceipt,
    reproducibility: ReproducibilityReceipt,
    authority_aggregate: FullC6AuthorityAggregateBinding,
    partition: tuple[FullC6ClassPartition, ...],
    runtime_bindings: dict[str, _RuntimeBinding],
) -> dict[str, object]:
    registry = {
        _identity_alias(f"cargo:{item.name}@{item.version}#registry"): item
        for item in toolchain.cargo_sources.packages
    }
    components = [
        _component_from_row(
            row,
            runtime_bindings=runtime_bindings,
            registry=registry,
            cargo_root=cargo_root,
        )
        for row in policy.rows
        if row.class_id != "wheel-output:subject"
    ]
    materials = _receipt_materials(
        policy=policy,
        source_lock=source_lock,
        source_admission=source_admission,
        build_inputs=build_inputs,
        toolchain=toolchain,
        cargo_root=cargo_root,
        runtime=runtime,
        reproducibility=reproducibility,
        authority_aggregate=authority_aggregate,
    )
    cargo_aggregates = {
        _cargo_aggregate_material_name(item): item
        for item in build_inputs.aggregates
    }
    for name, digest in materials:
        cargo_aggregate = cargo_aggregates.get(name)
        if cargo_aggregate is not None:
            components.append(_cargo_aggregate_sbom_component(cargo_aggregate))
            continue
        components.append(_evidence_sbom_component(name, digest))
    for tool in (
        toolchain.python,
        toolchain.cargo,
        toolchain.rustc,
        toolchain.linker,
        *toolchain.inspectors,
    ):
        components.append(
            {
                "type": "application",
                "bom-ref": f"urn:rextio:full-c6-tool:{tool.name}:{tool.executable.sha256}",
                "name": tool.name,
                "version": tool.reported_version,
                "hashes": [{"alg": "SHA-256", "content": tool.executable.sha256}],
                "properties": [
                    {"name": "rextio:size", "value": str(tool.executable.size)},
                    {"name": "rextio:role", "value": "builder-toolchain"},
                ],
            }
        )
    if len(components) + 1 > MAX_FULL_C6_SUPPLY_CHAIN_COMPONENTS:
        raise FullC6SupplyChainError("Full C6 SBOM component count exceeds the bound")
    refs = [str(component["bom-ref"]) for component in components]
    if len(refs) != len(set(refs)):
        raise FullC6SupplyChainError("Full C6 SBOM component identity is duplicated")
    subject_ref = f"urn:rextio:full-c6-wheel:{subject.sha256}"
    partition_sha256 = _digest([item.to_dict() for item in partition])
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": content_uuid_urn(subject.sha256),
        "version": 1,
        "metadata": {
            "component": {
                "type": "library",
                "bom-ref": subject_ref,
                "name": PurePosixPath(subject.logical_path).name,
                "hashes": [{"alg": "SHA-256", "content": subject.sha256}],
                "properties": [
                    {"name": "rextio:role", "value": "host-extension-wheel"},
                    {"name": "rextio:logical_path", "value": subject.logical_path},
                    {"name": "rextio:size", "value": str(subject.size)},
                ],
            },
            "properties": [
                {"name": "rextio:evidence_kind", "value": FULL_C6_SBOM_KIND},
                {"name": "rextio:scope", "value": FULL_C6_SCOPE},
                {"name": "rextio:target_triple", "value": target_triple},
                {"name": "rextio:composition", "value": "complete"},
                {"name": "rextio:partition_sha256", "value": partition_sha256},
                {
                    "name": "rextio:authority_aggregate_sha256",
                    "value": authority_aggregate.digest,
                },
                *(
                    {
                        "name": f"rextio:{field_name}",
                        "value": getattr(authority_aggregate, field_name),
                    }
                    for field_name in FULL_C6_AUTHORITY_AGGREGATE_BINDING_FIELDS
                ),
                {
                    "name": "rextio:reproducible_sbom_input_sha256",
                    "value": reproducibility.sbom_canonical_sha256,
                },
                {
                    "name": "rextio:reproducible_provenance_input_sha256",
                    "value": reproducibility.provenance_input_canonical_sha256,
                },
                {"name": "rextio:signed", "value": "false"},
                {"name": "rextio:distribution_authorized", "value": "false"},
            ],
        },
        "components": components,
        "dependencies": [
            {"ref": subject_ref, "dependsOn": sorted(refs)},
            *({"ref": ref, "dependsOn": []} for ref in sorted(refs)),
        ],
        "compositions": [{"aggregate": "complete", "assemblies": [subject_ref]}],
    }


def _build_provenance(
    *,
    target_triple: str,
    subject: EvidenceFileRef,
    sbom_sha256: str,
    policy: FullC6PolicyReceipt,
    source_lock: SourceLockV2Manifest,
    source_admission: SourceLockV2Admission,
    build_inputs: BuildInputClosure,
    toolchain: BuildToolchainIdentity,
    cargo_root: FullC6CargoPathSource,
    runtime: RuntimeAuthorizationReceipt,
    reproducibility: ReproducibilityReceipt,
    authority_aggregate: FullC6AuthorityAggregateBinding,
    partition: tuple[FullC6ClassPartition, ...],
    runtime_bindings: dict[str, _RuntimeBinding],
) -> dict[str, object]:
    partition_sha256 = _digest([item.to_dict() for item in partition])
    bindings = {
        name: digest
        for name, digest in _receipt_materials(
            policy=policy,
            source_lock=source_lock,
            source_admission=source_admission,
            build_inputs=build_inputs,
            toolchain=toolchain,
            cargo_root=cargo_root,
            runtime=runtime,
            reproducibility=reproducibility,
            authority_aggregate=authority_aggregate,
        )
    }
    resolved_dependencies = [
        _material_from_row(row, runtime_bindings)
        for row in policy.rows
        if row.class_id != "wheel-output:subject"
    ]
    cargo_aggregates = {
        _cargo_aggregate_material_name(item): item
        for item in build_inputs.aggregates
    }
    for name, digest in bindings.items():
        cargo_aggregate = cargo_aggregates.get(name)
        if cargo_aggregate is not None:
            resolved_dependencies.append(
                _cargo_aggregate_provenance_dependency(cargo_aggregate)
            )
        else:
            resolved_dependencies.append(
                _evidence_provenance_dependency(name, digest)
            )
    for tool in (
        toolchain.python,
        toolchain.cargo,
        toolchain.rustc,
        toolchain.linker,
        *toolchain.inspectors,
    ):
        resolved_dependencies.append(
            {
                "uri": f"urn:rextio:toolchain:{tool.name}",
                "digest": {"sha256": tool.executable.sha256},
                "annotations": {
                    "rextio:reported_version": tool.reported_version,
                    "rextio:size": str(tool.executable.size),
                },
            }
        )
    if len(resolved_dependencies) > MAX_FULL_C6_SUPPLY_CHAIN_COMPONENTS:
        raise FullC6SupplyChainError("Full C6 provenance dependency count exceeds the bound")
    uris = [str(item["uri"]) for item in resolved_dependencies]
    if len(uris) != len(set(uris)):
        raise FullC6SupplyChainError("Full C6 provenance dependency identity is duplicated")
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {"name": subject.logical_path, "digest": {"sha256": subject.sha256}},
            {
                "name": f"{subject.logical_path}.full-c6.cdx.json",
                "digest": {"sha256": sbom_sha256},
            },
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": FULL_C6_BUILD_TYPE,
                "externalParameters": {
                    "artifact_kind": "host-extension",
                    "packaging_backend": "wheel",
                    "python_fallback_backend": "cpython",
                    "external_source_max_depth": 1,
                    "plugin_ids": [],
                    "target_triple": target_triple,
                },
                "internalParameters": {
                    "scope": FULL_C6_SCOPE,
                    "partition_sha256": partition_sha256,
                    "receipt_bindings": bindings,
                    "reproducibility_input_projection": {
                        "sbom_canonical_sha256": (
                            reproducibility.sbom_canonical_sha256
                        ),
                        "provenance_input_canonical_sha256": (
                            reproducibility.provenance_input_canonical_sha256
                        ),
                    },
                    "cargo_argv_sha256": toolchain.argv.digest,
                    "environment": [item.to_dict() for item in toolchain.environment],
                    "complete_for_scope": True,
                    "build_input_closure_complete": True,
                    "native_runtime_closure_complete": True,
                    "source_lock_v2_verified": True,
                    "two_builds_reproducible": True,
                    "signed": False,
                    "distribution_authorized": False,
                },
                "resolvedDependencies": resolved_dependencies,
            },
            "runDetails": {
                "builder": {
                    "id": FULL_C6_BUILDER_ID,
                    "version": {
                        "rextio": toolchain.rextio.version,
                        "python": toolchain.python.reported_version,
                        "cargo": toolchain.cargo.reported_version,
                        "rustc": toolchain.rustc.reported_version,
                    },
                },
                "metadata": {
                    "rextio:policy": policy.to_dict(),
                    "rextio:source_lock_v2": source_lock.to_dict(),
                    "rextio:source_lock_admission": source_admission.to_dict(),
                    "rextio:build_input_closure": build_inputs.to_dict(),
                    "rextio:toolchain": toolchain.to_dict(),
                    "rextio:cargo_path_source": cargo_root.to_dict(),
                    "rextio:runtime_authorization": runtime.to_dict(),
                    "rextio:authority_aggregate": authority_aggregate.to_dict(),
                    "rextio:two_build_reproducibility": reproducibility.to_dict(),
                    "rextio:class_partition": [item.to_dict() for item in partition],
                    "rextio:complete_for_scope": True,
                    "rextio:distribution_authorized": False,
                },
            },
        },
    }


def build_full_c6_supply_chain_receipt(
    *,
    target_triple: str,
    subject: EvidenceFileRef,
    build_inputs: BuildInputClosure,
    wheel_entries: tuple[WheelEntryRef, ...],
    policy: FullC6PolicyReceipt,
    source_lock: SourceLockV2Manifest,
    source_admission: SourceLockV2Admission,
    toolchain: BuildToolchainIdentity,
    cargo_path_source: FullC6CargoPathSource,
    runtime_authorization: RuntimeAuthorizationReceipt,
    reproducibility: ReproducibilityReceipt,
    authority_aggregate: FullC6AuthorityAggregateBinding,
    cargo_dependency_workspace: FullC6CargoDependencyWorkspaceReceipt | None = None,
) -> FullC6SupplyChainReceipt:
    """Reconstruct and bind the complete frozen universe, then emit both documents."""
    if target_triple not in _TARGETS:
        raise FullC6SupplyChainError("Full C6 supply-chain target is unsupported")
    trusted_subject = _rebuild_evidence_file(subject)
    trusted_inputs = _rebuild_build_inputs(build_inputs)
    trusted_effective_config: EffectiveFullC6ConfigIdentity | None = None
    if trusted_inputs.aggregates:
        if cargo_dependency_workspace is None:
            raise FullC6SupplyChainError(
                "aggregate-aware Full C6 supply-chain construction requires "
                "a process-sealed Cargo workspace"
            )
        trusted_inputs = validate_full_c6_cargo_input_aggregates(
            trusted_inputs,
            cargo_dependency_workspace,
        )
        trusted_effective_config = _effective_config_from_aggregates(
            trusted_inputs.aggregates
        )
    elif cargo_dependency_workspace is not None:
        raise FullC6SupplyChainError(
            "legacy build-input closure cannot consume Cargo aggregate authority"
        )
    if type(wheel_entries) is not tuple:
        raise TypeError("subject wheel entries must be an exact tuple")
    trusted_wheel_entries = tuple(_rebuild_wheel_entry(item) for item in wheel_entries)
    if (
        not trusted_wheel_entries
        or trusted_wheel_entries
        != tuple(sorted(trusted_wheel_entries, key=lambda item: item.name))
        or len({item.name for item in trusted_wheel_entries}) != len(trusted_wheel_entries)
        or len({_identity_alias(item.name) for item in trusted_wheel_entries})
        != len(trusted_wheel_entries)
    ):
        raise FullC6SupplyChainError("subject wheel entries are not unique canonical records")
    trusted_policy = _rebuild_policy(policy)
    trusted_source_lock = _rebuild_source_lock(source_lock)
    trusted_source_admission = _rebuild_source_admission(source_admission)
    trusted_toolchain = _rebuild_toolchain(toolchain)
    if type(cargo_path_source) is not FullC6CargoPathSource:
        raise TypeError("Cargo path source identity has an invalid type")
    trusted_cargo_root = FullC6CargoPathSource(
        cargo_path_source.name,
        cargo_path_source.version,
        cargo_path_source.source_tree_sha256,
    )
    if trusted_cargo_root != cargo_path_source:
        raise FullC6SupplyChainError("Cargo path source is not in canonical model form")
    trusted_runtime = _rebuild_runtime(runtime_authorization)
    trusted_reproducibility = _rebuild_reproducibility(reproducibility)
    trusted_authority_aggregate = _rebuild_authority_aggregate(
        authority_aggregate
    )
    if trusted_runtime.target_triple != target_triple:
        raise FullC6SupplyChainError("runtime authorization target does not match the build")
    if (
        trusted_authority_aggregate.runtime_authorization_sha256
        != trusted_runtime.digest
    ):
        raise FullC6SupplyChainError(
            "Full C6 authority aggregate does not bind the runtime authorization"
        )
    if (
        cargo_dependency_workspace is not None
        and trusted_authority_aggregate.cargo_workspace_sha256
        != cargo_dependency_workspace.digest
    ):
        raise FullC6SupplyChainError(
            "Full C6 authority aggregate does not bind the Cargo workspace"
        )
    runtime_bindings = _validate_bindings(
        subject=trusted_subject,
        policy=trusted_policy,
        build_inputs=trusted_inputs,
        wheel_entries=trusted_wheel_entries,
        source_lock=trusted_source_lock,
        source_admission=trusted_source_admission,
        toolchain=trusted_toolchain,
        cargo_root=trusted_cargo_root,
        runtime=trusted_runtime,
        reproducibility=trusted_reproducibility,
    )
    partition = _partition_from_policy(trusted_policy)
    partition = _rebuild_partition(partition)
    sbom_document = _build_sbom(
        target_triple=target_triple,
        subject=trusted_subject,
        policy=trusted_policy,
        source_lock=trusted_source_lock,
        source_admission=trusted_source_admission,
        build_inputs=trusted_inputs,
        toolchain=trusted_toolchain,
        cargo_root=trusted_cargo_root,
        runtime=trusted_runtime,
        reproducibility=trusted_reproducibility,
        authority_aggregate=trusted_authority_aggregate,
        partition=partition,
        runtime_bindings=runtime_bindings,
    )
    sbom_json = canonical_json_bytes(sbom_document)
    if len(sbom_json) > MAX_FULL_C6_SUPPLY_CHAIN_DOCUMENT_BYTES:
        raise FullC6SupplyChainError("Full C6 SBOM exceeds the byte bound")
    provenance_document = _build_provenance(
        target_triple=target_triple,
        subject=trusted_subject,
        sbom_sha256=hashlib.sha256(sbom_json).hexdigest(),
        policy=trusted_policy,
        source_lock=trusted_source_lock,
        source_admission=trusted_source_admission,
        build_inputs=trusted_inputs,
        toolchain=trusted_toolchain,
        cargo_root=trusted_cargo_root,
        runtime=trusted_runtime,
        reproducibility=trusted_reproducibility,
        authority_aggregate=trusted_authority_aggregate,
        partition=partition,
        runtime_bindings=runtime_bindings,
    )
    provenance_json = canonical_json_bytes(provenance_document)
    if len(provenance_json) > MAX_FULL_C6_SUPPLY_CHAIN_DOCUMENT_BYTES:
        raise FullC6SupplyChainError("Full C6 provenance exceeds the byte bound")
    signature_sha256 = trusted_source_admission.signature_sha256
    if signature_sha256 is None:  # guarded by the exact admission check
        raise FullC6SupplyChainError("SourceLock signature identity is missing")
    return FullC6SupplyChainReceipt(
        target_triple=target_triple,
        subject=trusted_subject,
        partition=partition,
        policy_sha256=trusted_policy.digest,
        source_lock_manifest_sha256=trusted_source_lock.manifest_sha256,
        source_lock_signature_sha256=signature_sha256,
        build_input_closure_sha256=trusted_inputs.digest,
        toolchain_sha256=trusted_toolchain.digest,
        cargo_path_source_sha256=trusted_cargo_root.source_tree_sha256,
        runtime_authorization_sha256=trusted_runtime.digest,
        reproducibility_sha256=trusted_reproducibility.digest,
        reproducible_sbom_input_sha256=(
            trusted_reproducibility.sbom_canonical_sha256
        ),
        reproducible_provenance_input_sha256=(
            trusted_reproducibility.provenance_input_canonical_sha256
        ),
        authority_aggregate=trusted_authority_aggregate,
        sbom_json=sbom_json,
        provenance_json=provenance_json,
        cargo_input_aggregates=_cargo_aggregate_subset(trusted_inputs.aggregates),
        effective_config=trusted_effective_config,
    )


def _validate_json_tree(value: object) -> None:
    stack: list[tuple[object, int]] = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if depth > MAX_FULL_C6_SUPPLY_CHAIN_JSON_DEPTH:
            raise FullC6SupplyChainError("Full C6 JSON exceeds the depth bound")
        if nodes > MAX_FULL_C6_SUPPLY_CHAIN_JSON_NODES:
            raise FullC6SupplyChainError("Full C6 JSON exceeds the node bound")
        if isinstance(current, dict):
            if not all(type(key) is str for key in current):
                raise FullC6SupplyChainError("Full C6 JSON has a non-string object key")
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
        elif current is not None and type(current) not in (str, int, bool):
            raise FullC6SupplyChainError("Full C6 JSON has an unsupported value")


def validate_full_c6_supply_chain_document(
    data: bytes,
    *,
    document_kind: str,
) -> dict[str, object]:
    """Parse only exact canonical bytes for one supported final document kind."""
    if type(data) is not bytes:
        raise TypeError("Full C6 supply-chain document must be exact bytes")
    if not data or len(data) > MAX_FULL_C6_SUPPLY_CHAIN_DOCUMENT_BYTES:
        raise FullC6SupplyChainError("Full C6 supply-chain document size is invalid")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise FullC6SupplyChainError("Full C6 JSON contains a duplicate object key")
            result[key] = value
        return result

    def reject_constant(_value: str) -> object:
        raise FullC6SupplyChainError("Full C6 JSON contains a non-finite number")

    try:
        document = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except FullC6SupplyChainError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise FullC6SupplyChainError("Full C6 supply-chain JSON is invalid") from exc
    if type(document) is not dict:
        raise FullC6SupplyChainError("Full C6 supply-chain document must be an object")
    _validate_json_tree(document)
    try:
        canonical = canonical_json_bytes(document)
    except (TypeError, ValueError, RecursionError) as exc:
        raise FullC6SupplyChainError("Full C6 supply-chain JSON cannot be canonicalized") from exc
    if canonical != data:
        raise FullC6SupplyChainError("Full C6 supply-chain JSON is not canonical")
    if document_kind == "sbom":
        if (
            document.get("bomFormat") != "CycloneDX"
            or document.get("specVersion") != "1.6"
            or document.get("version") != 1
        ):
            raise FullC6SupplyChainError("Full C6 SBOM identity is invalid")
    elif document_kind == "provenance":
        if (
            document.get("_type") != "https://in-toto.io/Statement/v1"
            or document.get("predicateType") != "https://slsa.dev/provenance/v1"
        ):
            raise FullC6SupplyChainError("Full C6 provenance identity is invalid")
    else:
        raise FullC6SupplyChainError("Full C6 document kind is unsupported")
    return document


def _property_map(value: object) -> dict[str, str]:
    if not isinstance(value, list):
        raise FullC6SupplyChainError("Full C6 SBOM properties are invalid")
    result: dict[str, str] = {}
    for item in value:
        if (
            not isinstance(item, dict)
            or set(item) != {"name", "value"}
            or type(item.get("name")) is not str
            or type(item.get("value")) is not str
        ):
            raise FullC6SupplyChainError("Full C6 SBOM property is invalid")
        name = item["name"]
        if name in result:
            raise FullC6SupplyChainError("Full C6 SBOM property is duplicated")
        result[name] = item["value"]
    return result


def _receipt_bindings(value: FullC6SupplyChainReceipt) -> dict[str, str]:
    bindings = {
        "full-c6-license-transformation-policy": value.policy_sha256,
        "source-lock-v2-manifest": value.source_lock_manifest_sha256,
        "source-lock-v2-signature": value.source_lock_signature_sha256,
        "build-input-closure": value.build_input_closure_sha256,
        "builder-toolchain": value.toolchain_sha256,
        "cargo-path-source": value.cargo_path_source_sha256,
        FULL_C6_AUTHORITY_AGGREGATE_MATERIAL_NAME: (
            value.authority_aggregate.digest
        ),
        **dict(_authority_aggregate_materials(value.authority_aggregate)),
        "two-build-reproducibility": value.reproducibility_sha256,
        "reproducible-sbom-input": value.reproducible_sbom_input_sha256,
        "reproducible-provenance-input": (
            value.reproducible_provenance_input_sha256
        ),
    }
    bindings.update(
        {
            _cargo_aggregate_material_name(item): (
                _cargo_aggregate_identity_digest(item)
            )
            for item in value.cargo_input_aggregates
        }
    )
    if value.effective_config is not None:
        effective = _effective_config_aggregate_from_identity(
            value.effective_config
        )
        bindings[_FULL_C6_EFFECTIVE_CONFIG_MATERIAL_NAME] = (
            _cargo_aggregate_identity_digest(effective)
        )
    return bindings


def _validate_authority_aggregate_document_materials(
    value: FullC6SupplyChainReceipt,
    *,
    sbom: dict[str, object],
    predicate: dict[str, object],
    definition: dict[str, object],
) -> None:
    components = sbom.get("components")
    resolved_dependencies = definition.get("resolvedDependencies")
    if not isinstance(components, list) or not isinstance(
        resolved_dependencies, list
    ):
        raise FullC6SupplyChainError(
            "Full C6 authority aggregate document materials are missing"
        )
    authority_materials = (
        (
            FULL_C6_AUTHORITY_AGGREGATE_MATERIAL_NAME,
            value.authority_aggregate.digest,
        ),
        *_authority_aggregate_materials(value.authority_aggregate),
    )
    material_names = {name for name, _digest_value in authority_materials}
    evidence_uri_prefix = "urn:rextio:full-c6-evidence:"
    observed_components = [
        item
        for item in components
        if isinstance(item, dict) and item.get("name") in material_names
    ]
    observed_dependencies = [
        item
        for item in resolved_dependencies
        if isinstance(item, dict)
        and isinstance(item.get("uri"), str)
        and str(item["uri"]).removeprefix(evidence_uri_prefix) in material_names
    ]
    expected_components = [
        _evidence_sbom_component(name, digest)
        for name, digest in authority_materials
    ]
    expected_dependencies = [
        _evidence_provenance_dependency(name, digest)
        for name, digest in authority_materials
    ]
    if (
        observed_components != expected_components
        or observed_dependencies != expected_dependencies
    ):
        raise FullC6SupplyChainError(
            "Full C6 authority aggregate document materials do not bind the receipt"
        )

    metadata = sbom.get("metadata")
    if not isinstance(metadata, dict):
        raise FullC6SupplyChainError("Full C6 SBOM metadata is invalid")
    raw_properties = metadata.get("properties")
    if not isinstance(raw_properties, list):
        raise FullC6SupplyChainError("Full C6 SBOM properties are invalid")
    authority_property_names = {
        "rextio:authority_aggregate_sha256",
        *(
            f"rextio:{field_name}"
            for field_name in FULL_C6_AUTHORITY_AGGREGATE_BINDING_FIELDS
        ),
    }
    observed_properties = [
        item
        for item in raw_properties
        if isinstance(item, dict) and item.get("name") in authority_property_names
    ]
    expected_properties = [
        {
            "name": "rextio:authority_aggregate_sha256",
            "value": value.authority_aggregate.digest,
        },
        *(
            {
                "name": f"rextio:{field_name}",
                "value": getattr(value.authority_aggregate, field_name),
            }
            for field_name in FULL_C6_AUTHORITY_AGGREGATE_BINDING_FIELDS
        ),
    ]
    if observed_properties != expected_properties:
        raise FullC6SupplyChainError(
            "Full C6 authority aggregate SBOM properties do not bind the receipt"
        )

    run_details = predicate.get("runDetails")
    if not isinstance(run_details, dict):
        raise FullC6SupplyChainError("Full C6 provenance run details are invalid")
    provenance_metadata = run_details.get("metadata")
    if (
        not isinstance(provenance_metadata, dict)
        or provenance_metadata.get("rextio:authority_aggregate")
        != value.authority_aggregate.to_dict()
    ):
        raise FullC6SupplyChainError(
            "Full C6 provenance authority aggregate projection is stale"
        )


def _validate_cargo_aggregate_document_materials(
    value: FullC6SupplyChainReceipt,
    *,
    sbom: dict[str, object],
    predicate: dict[str, object],
    definition: dict[str, object],
) -> None:
    components = sbom.get("components")
    resolved_dependencies = definition.get("resolvedDependencies")
    if not isinstance(components, list) or not isinstance(
        resolved_dependencies, list
    ):
        raise FullC6SupplyChainError(
            "Full C6 Cargo aggregate document materials are missing"
        )
    name_prefix = "full-c6-cargo-input-aggregate:"
    uri_prefix = f"urn:rextio:full-c6-evidence:{name_prefix}"
    observed_components = [
        item
        for item in components
        if isinstance(item, dict)
        and isinstance(item.get("name"), str)
        and str(item["name"]).startswith(name_prefix)
    ]
    observed_dependencies = [
        item
        for item in resolved_dependencies
        if isinstance(item, dict)
        and isinstance(item.get("uri"), str)
        and str(item["uri"]).startswith(uri_prefix)
    ]
    expected_components = [
        _cargo_aggregate_sbom_component(item)
        for item in value.cargo_input_aggregates
    ]
    expected_dependencies = [
        _cargo_aggregate_provenance_dependency(item)
        for item in value.cargo_input_aggregates
    ]
    if (
        observed_components != expected_components
        or observed_dependencies != expected_dependencies
    ):
        raise FullC6SupplyChainError(
            "Full C6 Cargo aggregate document materials do not bind the receipt"
        )

    run_details = predicate.get("runDetails")
    if not isinstance(run_details, dict):
        raise FullC6SupplyChainError("Full C6 provenance run details are invalid")
    metadata = run_details.get("metadata")
    if not isinstance(metadata, dict):
        raise FullC6SupplyChainError("Full C6 provenance metadata is invalid")
    build_input_projection = metadata.get("rextio:build_input_closure")
    if not isinstance(build_input_projection, dict):
        raise FullC6SupplyChainError(
            "Full C6 provenance build-input projection is invalid"
        )
    observed_aggregates = build_input_projection.get("aggregates")
    aggregate_rows: tuple[BuildInputAggregateIdentity, ...] = (
        value.cargo_input_aggregates
    )
    if value.effective_config is not None:
        aggregate_rows = tuple(
            sorted(
                (
                    *aggregate_rows,
                    _effective_config_aggregate_from_identity(
                        value.effective_config
                    ),
                ),
                key=lambda item: (item.kind, item.aggregate_id),
            )
        )
    expected_aggregates = [item.to_dict() for item in aggregate_rows]
    if (
        (expected_aggregates and observed_aggregates != expected_aggregates)
        or (not expected_aggregates and "aggregates" in build_input_projection)
    ):
        raise FullC6SupplyChainError(
            "Full C6 provenance Cargo aggregate projection is stale"
        )


def _validate_effective_config_document_material(
    value: FullC6SupplyChainReceipt,
    *,
    sbom: dict[str, object],
    definition: dict[str, object],
) -> None:
    components = sbom.get("components")
    resolved_dependencies = definition.get("resolvedDependencies")
    if not isinstance(components, list) or not isinstance(
        resolved_dependencies, list
    ):
        raise FullC6SupplyChainError(
            "Full C6 effective-config document material is missing"
        )
    observed_components = [
        item
        for item in components
        if isinstance(item, dict)
        and item.get("name") == _FULL_C6_EFFECTIVE_CONFIG_MATERIAL_NAME
    ]
    expected_uri = (
        "urn:rextio:full-c6-evidence:"
        f"{_FULL_C6_EFFECTIVE_CONFIG_MATERIAL_NAME}"
    )
    observed_dependencies = [
        item
        for item in resolved_dependencies
        if isinstance(item, dict) and item.get("uri") == expected_uri
    ]
    expected_components: list[dict[str, object]] = []
    expected_dependencies: list[dict[str, object]] = []
    if value.effective_config is not None:
        aggregate = _effective_config_aggregate_from_identity(
            value.effective_config
        )
        expected_components.append(_cargo_aggregate_sbom_component(aggregate))
        expected_dependencies.append(
            _cargo_aggregate_provenance_dependency(aggregate)
        )
    if (
        observed_components != expected_components
        or observed_dependencies != expected_dependencies
    ):
        raise FullC6SupplyChainError(
            "Full C6 effective-config document material does not bind the receipt"
        )


def _validate_receipt_documents(
    value: FullC6SupplyChainReceipt,
    *,
    sbom: dict[str, object],
    provenance: dict[str, object],
) -> None:
    try:
        metadata = sbom["metadata"]
        if not isinstance(metadata, dict):
            raise KeyError("metadata")
        component = metadata["component"]
        if not isinstance(component, dict):
            raise KeyError("component")
        properties = _property_map(metadata["properties"])
        hashes = component["hashes"]
        compositions = sbom["compositions"]
        if (
            not isinstance(hashes, list)
            or hashes != [{"alg": "SHA-256", "content": value.subject.sha256}]
            or component.get("name") != PurePosixPath(value.subject.logical_path).name
            or not isinstance(compositions, list)
            or len(compositions) != 1
            or not isinstance(compositions[0], dict)
            or compositions[0].get("aggregate") != "complete"
            or properties.get("rextio:evidence_kind") != FULL_C6_SBOM_KIND
            or properties.get("rextio:scope") != FULL_C6_SCOPE
            or properties.get("rextio:target_triple") != value.target_triple
            or properties.get("rextio:composition") != "complete"
            or properties.get("rextio:partition_sha256") != value.partition_sha256
            or properties.get("rextio:reproducible_sbom_input_sha256")
            != value.reproducible_sbom_input_sha256
            or properties.get("rextio:reproducible_provenance_input_sha256")
            != value.reproducible_provenance_input_sha256
            or properties.get("rextio:signed") != "false"
            or properties.get("rextio:distribution_authorized") != "false"
        ):
            raise FullC6SupplyChainError("Full C6 SBOM does not bind the receipt")
        subjects = provenance["subject"]
        predicate = provenance["predicate"]
        if not isinstance(subjects, list) or len(subjects) != 2 or not isinstance(predicate, dict):
            raise KeyError("provenance")
        definition = predicate["buildDefinition"]
        if not isinstance(definition, dict):
            raise KeyError("buildDefinition")
        parameters = definition["internalParameters"]
        if not isinstance(parameters, dict):
            raise KeyError("internalParameters")
        _validate_cargo_aggregate_document_materials(
            value,
            sbom=sbom,
            predicate=predicate,
            definition=definition,
        )
        _validate_effective_config_document_material(
            value,
            sbom=sbom,
            definition=definition,
        )
        _validate_authority_aggregate_document_materials(
            value,
            sbom=sbom,
            predicate=predicate,
            definition=definition,
        )
        if (
            subjects[0]
            != {"name": value.subject.logical_path, "digest": {"sha256": value.subject.sha256}}
            or subjects[1]
            != {
                "name": f"{value.subject.logical_path}.full-c6.cdx.json",
                "digest": {"sha256": value.sbom_sha256},
            }
            or definition.get("buildType") != FULL_C6_BUILD_TYPE
            or parameters.get("scope") != FULL_C6_SCOPE
            or parameters.get("partition_sha256") != value.partition_sha256
            or parameters.get("receipt_bindings") != _receipt_bindings(value)
            or parameters.get("reproducibility_input_projection")
            != {
                "sbom_canonical_sha256": value.reproducible_sbom_input_sha256,
                "provenance_input_canonical_sha256": (
                    value.reproducible_provenance_input_sha256
                ),
            }
            or parameters.get("complete_for_scope") is not True
            or parameters.get("signed") is not False
            or parameters.get("distribution_authorized") is not False
        ):
            raise FullC6SupplyChainError("Full C6 provenance does not bind the receipt")
    except (KeyError, IndexError, TypeError) as exc:
        raise FullC6SupplyChainError("Full C6 supply-chain document shape is invalid") from exc


def verify_full_c6_supply_chain_receipt(
    value: FullC6SupplyChainReceipt,
    *,
    cargo_dependency_workspace: FullC6CargoDependencyWorkspaceReceipt | None = None,
) -> FullC6SupplyChainReceipt:
    """Deeply reconstruct one non-authorizing receipt and reject forged model state."""
    if type(value) is not FullC6SupplyChainReceipt:
        raise TypeError("Full C6 supply-chain receipt has an invalid type")
    rebuilt = FullC6SupplyChainReceipt(
        target_triple=value.target_triple,
        subject=_rebuild_evidence_file(value.subject),
        partition=_rebuild_partition(value.partition),
        policy_sha256=value.policy_sha256,
        source_lock_manifest_sha256=value.source_lock_manifest_sha256,
        source_lock_signature_sha256=value.source_lock_signature_sha256,
        build_input_closure_sha256=value.build_input_closure_sha256,
        toolchain_sha256=value.toolchain_sha256,
        cargo_path_source_sha256=value.cargo_path_source_sha256,
        runtime_authorization_sha256=value.runtime_authorization_sha256,
        reproducibility_sha256=value.reproducibility_sha256,
        reproducible_sbom_input_sha256=value.reproducible_sbom_input_sha256,
        reproducible_provenance_input_sha256=(
            value.reproducible_provenance_input_sha256
        ),
        authority_aggregate=_rebuild_authority_aggregate(
            value.authority_aggregate
        ),
        sbom_json=bytes(value.sbom_json),
        provenance_json=bytes(value.provenance_json),
        cargo_input_aggregates=_rebuild_cargo_input_aggregates(
            value.cargo_input_aggregates,
            allow_legacy_empty=True,
        ),
        effective_config=_rebuild_effective_config_identity(
            value.effective_config,
            allow_legacy_none=True,
        ),
        domain=value.domain,
        scope=value.scope,
    )
    if rebuilt != value:
        raise FullC6SupplyChainError("Full C6 supply-chain receipt is forged")
    if rebuilt.cargo_input_aggregates:
        if cargo_dependency_workspace is None:
            raise FullC6SupplyChainError(
                "aggregate-aware Full C6 receipt verification requires "
                "a process-sealed Cargo workspace"
            )
        _require_authoritative_cargo_input_aggregates(
            rebuilt.cargo_input_aggregates,
            cargo_dependency_workspace,
        )
        if rebuilt.effective_config is None:
            raise FullC6SupplyChainError(
                "Full C6 effective-config aggregate identity is missing"
            )
        if (
            rebuilt.authority_aggregate.cargo_workspace_sha256
            != cargo_dependency_workspace.digest
        ):
            raise FullC6SupplyChainError(
                "Full C6 authority aggregate does not bind the Cargo workspace"
            )
    elif cargo_dependency_workspace is not None:
        raise FullC6SupplyChainError(
            "legacy Full C6 receipt cannot consume Cargo aggregate authority"
        )
    return rebuilt


__all__ = [
    "FULL_C6_AUTHORITY_AGGREGATE_BINDING_DOMAIN",
    "FULL_C6_AUTHORITY_AGGREGATE_BINDING_FIELDS",
    "FULL_C6_AUTHORITY_AGGREGATE_MATERIAL_NAMES",
    "FULL_C6_AUTHORITY_AGGREGATE_MATERIAL_NAME",
    "FULL_C6_BUILDER_ID",
    "FULL_C6_BUILD_TYPE",
    "FULL_C6_CARGO_INPUT_AGGREGATE_BINDING_DOMAIN",
    "FULL_C6_EFFECTIVE_CONFIG_AGGREGATE_BINDING_DOMAIN",
    "FULL_C6_PROVENANCE_KIND",
    "FULL_C6_SBOM_KIND",
    "FULL_C6_SUPPLY_CHAIN_DOMAIN",
    "FullC6CargoPathSource",
    "FullC6AuthorityAggregateBinding",
    "FullC6ClassPartition",
    "FullC6PartitionIdentity",
    "FullC6SupplyChainError",
    "FullC6SupplyChainReceipt",
    "MAX_FULL_C6_SUPPLY_CHAIN_COMPONENTS",
    "MAX_FULL_C6_SUPPLY_CHAIN_DOCUMENT_BYTES",
    "build_full_c6_supply_chain_receipt",
    "validate_full_c6_supply_chain_document",
    "validate_full_c6_cargo_input_aggregates",
    "verify_full_c6_supply_chain_receipt",
]
