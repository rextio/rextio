"""Exact non-authorizing technical template for Full C6 owner policy.

The production collector may serialize this value across the bootstrap process
boundary.  It intentionally contains the exact technical universe required to
author a policy, but contains no owner decision, legal approval, source bytes,
host path, signature, private key, or distribution authority.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from pathlib import PurePosixPath, PureWindowsPath
import re
from typing import Literal

from rextio.artifacts.contract_dialects import (
    CURRENT,
    POLICY_TEMPLATE,
    ArtifactContractDialect,
    resolve_artifact_contract_dialect,
)
import unicodedata

from rextio.artifacts.evidence import (
    ARTIFACT_POLICY_COVERAGE_CLASS_IDS,
    ArtifactPolicyCoverageInventory,
    artifact_policy_identity_set_digest,
    canonical_json_bytes,
)
from rextio.build.full_c6_policy import (
    FULL_C6_EXTERNAL_POLICY_CLASS_IDS,
    FULL_C6_POLICY_CLASS_IDS,
    MAX_FULL_C6_LICENSE_FILES_PER_ROW,
    MAX_FULL_C6_POLICY_ROWS,
    MAX_FULL_C6_POLICY_SERIALIZED_BYTES,
    MAX_FULL_C6_POLICY_TRANSFORMATIONS,
    FullC6ExternalAuthorityPartition,
    FullC6PolicyError,
    FullC6PolicyFileIdentity,
    FullC6TransformationRecord,
    full_c6_authority_partition_digest,
    full_c6_external_authority_identity_set_digest,
    full_c6_license_detector_payload_digest,
    full_c6_policy_identity_mode,
    full_c6_policy_license_disposition,
    full_c6_policy_transformation_disposition,
)
from rextio.build.full_c6_policy_manifest import (
    parse_full_c6_artifact_coverage_document,
    parse_full_c6_external_authority_document,
    parse_full_c6_transformation_document,
)


class FullC6PolicyTemplateError(ValueError):
    """The technical template is incomplete, stale, or noncanonical."""


@dataclass(frozen=True, slots=True)
class FullC6TechnicalPolicyRow:
    """One exact technical row before an owner supplies a license decision."""

    class_id: str
    canonical_identity: str
    authority_identity: str
    identity_mode: str
    sha256: str | None
    size: int | None
    required_license_disposition: str
    transformation_disposition: str
    license_evidence_origin: Literal[
        "owner-project-observation",
        "production-external-observation",
        "not-applicable",
    ]
    license_observation_sha256: str | None

    def __post_init__(self) -> None:
        if type(self.class_id) is not str or self.class_id not in FULL_C6_POLICY_CLASS_IDS:
            raise FullC6PolicyTemplateError("Full C6 technical row class is invalid")
        _require_identity(self.canonical_identity, "technical row canonical identity")
        _require_identity(self.authority_identity, "technical row authority identity")
        prefix = (
            f"urn:rextio:artifact-component:{self.class_id}:"
            if self.class_id in ARTIFACT_POLICY_COVERAGE_CLASS_IDS
            else f"urn:rextio:full-c6-external-authority-component:v1:{self.class_id}:"
        )
        if not self.authority_identity.startswith(prefix) or not _is_sha256(
            self.authority_identity.removeprefix(prefix)
        ):
            raise FullC6PolicyTemplateError("Full C6 technical row authority is invalid")
        if self.identity_mode != full_c6_policy_identity_mode(self.class_id):
            raise FullC6PolicyTemplateError("Full C6 technical row identity mode is invalid")
        expected_license = full_c6_policy_license_disposition(self.class_id)
        if self.required_license_disposition != expected_license:
            raise FullC6PolicyTemplateError("Full C6 technical row license requirement is invalid")
        if self.transformation_disposition != full_c6_policy_transformation_disposition(
            self.class_id
        ):
            raise FullC6PolicyTemplateError(
                "Full C6 technical row transformation disposition is invalid"
            )
        expected_origin = (
            "not-applicable"
            if expected_license != "owner-approved-allow"
            else (
                "production-external-observation"
                if self.class_id in FULL_C6_EXTERNAL_POLICY_CLASS_IDS
                else "owner-project-observation"
            )
        )
        if self.license_evidence_origin != expected_origin:
            raise FullC6PolicyTemplateError("Full C6 technical row evidence origin is invalid")
        if expected_origin == "not-applicable":
            if self.license_observation_sha256 is not None:
                raise FullC6PolicyTemplateError(
                    "Full C6 non-applicable row cannot bind a license observation"
                )
        elif not _is_sha256(self.license_observation_sha256):
            raise FullC6PolicyTemplateError(
                "Full C6 technical row license observation is invalid"
            )
        if self.identity_mode == "content-sha256":
            if not _is_sha256(self.sha256) or type(self.size) is not int or self.size < 0:
                raise FullC6PolicyTemplateError("Full C6 technical content identity is invalid")
        elif self.identity_mode in {"cargo-registry-checksum", "source-tree-sha256"}:
            if not _is_sha256(self.sha256) or self.size is not None:
                raise FullC6PolicyTemplateError("Full C6 technical package identity is invalid")
        elif self.identity_mode == "logical-system-leaf":
            if self.sha256 is not None or self.size is not None:
                raise FullC6PolicyTemplateError("Full C6 logical leaf cannot claim file bytes")
        else:  # pragma: no cover - frozen policy vocabulary protects this branch
            raise FullC6PolicyTemplateError("Full C6 technical identity mode is unsupported")

    @property
    def canonical_identity_sha256(self) -> str:
        """Return the exact digest embedded in the authority identity."""
        return self.authority_identity.rsplit(":", 1)[-1]

    def to_dict(self) -> dict[str, object]:
        """Return the canonical, explicitly incomplete row document."""
        return {
            "class_id": self.class_id,
            "canonical_identity": self.canonical_identity,
            "authority_identity": self.authority_identity,
            "identity_mode": self.identity_mode,
            "sha256": self.sha256,
            "size": self.size,
            "canonical_identity_sha256": self.canonical_identity_sha256,
            "required_license_disposition": self.required_license_disposition,
            "transformation_disposition": self.transformation_disposition,
            "license_evidence_origin": self.license_evidence_origin,
            "license_observation_sha256": self.license_observation_sha256,
            "owner_decision": None,
        }


@dataclass(frozen=True, slots=True)
class FullC6ExternalLicenseObservation:
    """Independent exact-byte observation shared by every external-source row."""

    declared_spdx: str
    detected_spdx: str
    source_detector_receipt_sha256: str
    detector_payload_sha256: str
    license_files: tuple[FullC6PolicyFileIdentity, ...]

    def __post_init__(self) -> None:
        if (
            type(self.declared_spdx) is not str
            or not self.declared_spdx
            or type(self.detected_spdx) is not str
            or not self.detected_spdx
        ):
            raise FullC6PolicyTemplateError("Full C6 external SPDX observation is missing")
        if not _is_sha256(self.source_detector_receipt_sha256):
            raise FullC6PolicyTemplateError("Full C6 external detector receipt is invalid")
        if type(self.license_files) is not tuple or not self.license_files:
            raise FullC6PolicyTemplateError("Full C6 external license files are missing")
        if len(self.license_files) > MAX_FULL_C6_LICENSE_FILES_PER_ROW or any(
            type(item) is not FullC6PolicyFileIdentity for item in self.license_files
        ):
            raise FullC6PolicyTemplateError("Full C6 external license files are invalid")
        canonical = tuple(sorted(self.license_files, key=lambda item: item.logical_path.casefold()))
        if canonical != self.license_files:
            raise FullC6PolicyTemplateError("Full C6 external license files are noncanonical")
        expected = full_c6_license_detector_payload_digest(
            self.detected_spdx,
            self.license_files,
            source_detector_receipt_sha256=self.source_detector_receipt_sha256,
        )
        if self.detector_payload_sha256 != expected:
            raise FullC6PolicyTemplateError("Full C6 external detector payload is stale")

    def to_dict(self) -> dict[str, object]:
        """Return the byte-free external observation."""
        return {
            "authority": "independent-exact-wheel-byte-observation",
            "declared_spdx": self.declared_spdx,
            "detected_spdx": self.detected_spdx,
            "source_detector_receipt_sha256": self.source_detector_receipt_sha256,
            "detector_payload_sha256": self.detector_payload_sha256,
            "license_files": [item.to_dict() for item in self.license_files],
            "legal_approval_inferred": False,
            "distribution_authorized": False,
            "observation_sha256": self.observation_sha256,
        }

    @property
    def observation_sha256(self) -> str:
        """Return the exact technical identity of the external observation."""
        return _digest(
            {
                "domain": FULL_C6_EXTERNAL_LICENSE_OBSERVATION_DOMAIN,
                "declared_spdx": self.declared_spdx,
                "detected_spdx": self.detected_spdx,
                "source_detector_receipt_sha256": (
                    self.source_detector_receipt_sha256
                ),
                "detector_payload_sha256": self.detector_payload_sha256,
                "license_files": [item.to_dict() for item in self.license_files],
            }
        )


@dataclass(frozen=True, slots=True)
class FullC6InternalLicenseObservation:
    """Exact project/Cargo license material observed by the production collector."""

    subject_kind: Literal["project", "cargo-registry-package"]
    subject_canonical_identity: str
    declared_spdx: str
    detected_spdx: str
    source_detector_receipt_sha256: str
    detector_payload_sha256: str
    license_files: tuple[FullC6PolicyFileIdentity, ...]

    def __post_init__(self) -> None:
        if self.subject_kind not in {"project", "cargo-registry-package"}:
            raise FullC6PolicyTemplateError("Full C6 internal license subject is invalid")
        _require_identity(
            self.subject_canonical_identity,
            "internal license subject identity",
        )
        if (
            type(self.declared_spdx) is not str
            or not self.declared_spdx
            or type(self.detected_spdx) is not str
            or not self.detected_spdx
            or not _is_sha256(self.source_detector_receipt_sha256)
        ):
            raise FullC6PolicyTemplateError(
                "Full C6 internal license observation is incomplete"
            )
        if (
            type(self.license_files) is not tuple
            or not self.license_files
            or len(self.license_files) > MAX_FULL_C6_LICENSE_FILES_PER_ROW
            or any(
                type(item) is not FullC6PolicyFileIdentity
                for item in self.license_files
            )
        ):
            raise FullC6PolicyTemplateError("Full C6 internal license files are invalid")
        canonical = tuple(
            sorted(self.license_files, key=lambda item: item.logical_path.casefold())
        )
        if canonical != self.license_files:
            raise FullC6PolicyTemplateError(
                "Full C6 internal license files are noncanonical"
            )
        expected = full_c6_license_detector_payload_digest(
            self.detected_spdx,
            self.license_files,
            source_detector_receipt_sha256=self.source_detector_receipt_sha256,
        )
        if self.detector_payload_sha256 != expected:
            raise FullC6PolicyTemplateError(
                "Full C6 internal license detector payload is stale"
            )

    @property
    def observation_sha256(self) -> str:
        """Return the exact byte-observation identity referenced by policy rows."""
        return _digest(
            {
                "domain": FULL_C6_INTERNAL_LICENSE_OBSERVATION_DOMAIN,
                **self._payload(),
            }
        )

    def _payload(self) -> dict[str, object]:
        return {
            "subject_kind": self.subject_kind,
            "subject_canonical_identity": self.subject_canonical_identity,
            "declared_spdx": self.declared_spdx,
            "detected_spdx": self.detected_spdx,
            "source_detector_receipt_sha256": self.source_detector_receipt_sha256,
            "detector_payload_sha256": self.detector_payload_sha256,
            "license_files": [item.to_dict() for item in self.license_files],
        }

    def to_dict(self) -> dict[str, object]:
        """Return an exact non-legal, non-authorizing technical observation."""
        return {
            "authority": "production-exact-license-material-observation",
            **self._payload(),
            "observation_sha256": self.observation_sha256,
            "legal_approval_inferred": False,
            "distribution_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class FullC6TechnicalPolicyTemplate:
    """Exact bounded technical universe awaiting explicit owner completion."""

    artifact_coverage: ArtifactPolicyCoverageInventory
    external_authority: FullC6ExternalAuthorityPartition
    rows: tuple[FullC6TechnicalPolicyRow, ...]
    transformations: tuple[FullC6TransformationRecord, ...]
    internal_license_observations: tuple[FullC6InternalLicenseObservation, ...]
    external_license_observation: FullC6ExternalLicenseObservation
    observed_owner_identity: str
    kind: str = field(
        default=CURRENT.identity(POLICY_TEMPLATE).kind,
        init=False,
    )
    schema_version: int = field(
        default=CURRENT.identity(POLICY_TEMPLATE).schema_version,
        init=False,
    )
    domain: str = field(
        default=CURRENT.identity(POLICY_TEMPLATE).domain,
        init=False,
    )
    _artifact_contract_dialect: str = field(
        default=CURRENT.name,
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if type(self.artifact_coverage) is not ArtifactPolicyCoverageInventory:
            raise FullC6PolicyTemplateError("Full C6 technical C6.14 coverage is invalid")
        if type(self.external_authority) is not FullC6ExternalAuthorityPartition:
            raise FullC6PolicyTemplateError("Full C6 technical C5.2 partition is invalid")
        if type(self.rows) is not tuple or len(self.rows) > MAX_FULL_C6_POLICY_ROWS or any(
            type(item) is not FullC6TechnicalPolicyRow for item in self.rows
        ):
            raise FullC6PolicyTemplateError("Full C6 technical rows are invalid")
        if type(self.transformations) is not tuple or len(
            self.transformations
        ) > MAX_FULL_C6_POLICY_TRANSFORMATIONS or any(
            type(item) is not FullC6TransformationRecord for item in self.transformations
        ):
            raise FullC6PolicyTemplateError("Full C6 technical transformations are invalid")
        if type(self.external_license_observation) is not FullC6ExternalLicenseObservation:
            raise FullC6PolicyTemplateError("Full C6 external license observation is invalid")
        if (
            type(self.internal_license_observations) is not tuple
            or not self.internal_license_observations
            or len(self.internal_license_observations) > MAX_FULL_C6_POLICY_ROWS
            or any(
                type(item) is not FullC6InternalLicenseObservation
                for item in self.internal_license_observations
            )
        ):
            raise FullC6PolicyTemplateError(
                "Full C6 internal license observations are invalid"
            )
        canonical_observations = tuple(
            sorted(
                self.internal_license_observations,
                key=lambda item: (
                    item.subject_kind,
                    item.subject_canonical_identity.casefold(),
                    item.observation_sha256,
                ),
            )
        )
        observation_digests = tuple(
            item.observation_sha256 for item in self.internal_license_observations
        )
        if (
            canonical_observations != self.internal_license_observations
            or len(observation_digests) != len(set(observation_digests))
        ):
            raise FullC6PolicyTemplateError(
                "Full C6 internal license observations are noncanonical"
            )
        _require_owner_identity(self.observed_owner_identity)
        _validate_rows_and_partitions(self.rows, self.artifact_coverage, self.external_authority)
        _validate_license_observation_bindings(
            self.rows,
            self.internal_license_observations,
            self.external_license_observation,
        )
        _validate_transformations(self.rows, self.transformations, self.authority_partition_sha256)
        if len(canonical_json_bytes(self._payload())) > MAX_FULL_C6_POLICY_TEMPLATE_BYTES:
            raise FullC6PolicyTemplateError("Full C6 technical template exceeds byte bound")

    @property
    def authority_partition_sha256(self) -> str:
        """Return the exact combined C6.14 plus C5.2 partition identity."""
        return full_c6_authority_partition_digest(
            self.artifact_coverage,
            self.external_authority,
        )

    @property
    def transformation_set_sha256(self) -> str:
        """Return the exact technical transformation-set identity."""
        return _digest(
            {
                "domain": FULL_C6_TECHNICAL_TRANSFORMATION_SET_DOMAIN,
                "transformations": [item.to_dict() for item in self.transformations],
            }
        )

    @property
    def template_sha256(self) -> str:
        """Return the semantic identity of the non-authorizing template."""
        return _digest(self._payload())

    def _payload(self) -> dict[str, object]:
        return {
            "kind": _template_dialect(self).identity(POLICY_TEMPLATE).kind,
            "schema_version": (
                _template_dialect(self).identity(POLICY_TEMPLATE).schema_version
            ),
            "domain": _template_dialect(self).identity(POLICY_TEMPLATE).domain,
            "authority": "non-authorizing-technical-observation",
            "artifact_coverage": self.artifact_coverage.to_dict(),
            "external_authority": self.external_authority.to_dict(),
            "authority_partition_sha256": self.authority_partition_sha256,
            "rows": [item.to_dict() for item in self.rows],
            "transformations": [item.to_dict() for item in self.transformations],
            "transformation_set_sha256": self.transformation_set_sha256,
            "internal_license_observations": [
                item.to_dict() for item in self.internal_license_observations
            ],
            "external_license_observation": self.external_license_observation.to_dict(),
            "owner_completion_requirements": {
                "observed_owner_identity": self.observed_owner_identity,
                "owner_identity_required": True,
                "owner_role_required": True,
                "trusted_public_key_sha256_required": True,
                "per_license_row_explicit_allow_required": True,
                "declared_spdx_required": True,
                "exact_transformation_set_acceptance_required": True,
            },
            "owner_completed": False,
            "legal_approval_inferred": False,
            "signed": False,
            "distribution_authorized": False,
        }

    def to_dict(self) -> dict[str, object]:
        """Return the sole canonical technical-template document."""
        return {**self._payload(), "template_sha256": self.template_sha256}


def parse_full_c6_technical_policy_template(
    value: object,
) -> FullC6TechnicalPolicyTemplate:
    """Parse one exact dict produced by :meth:`FullC6TechnicalPolicyTemplate.to_dict`."""
    data = _exact_dict(value, _TEMPLATE_FIELDS, "technical template")
    try:
        dialect = resolve_artifact_contract_dialect(
            POLICY_TEMPLATE,
            kind=data["kind"],
            schema_version=data["schema_version"],
            domain=data["domain"],
        )
    except ValueError as exc:
        raise FullC6PolicyTemplateError(
            "Full C6 technical template claims invalid authority"
        ) from exc
    if (
        data["authority"] != "non-authorizing-technical-observation"
        or data["owner_completed"] is not False
        or data["legal_approval_inferred"] is not False
        or data["signed"] is not False
        or data["distribution_authorized"] is not False
    ):
        raise FullC6PolicyTemplateError("Full C6 technical template claims invalid authority")
    requirements = _exact_dict(
        data["owner_completion_requirements"],
        _OWNER_REQUIREMENT_FIELDS,
        "owner completion requirements",
    )
    for requirement_field in _OWNER_REQUIREMENT_BOOLEAN_FIELDS:
        if requirements[requirement_field] is not True:
            raise FullC6PolicyTemplateError("Full C6 owner completion requirement is weakened")
    rows_value = _exact_list(data["rows"], "technical rows")
    transformations_value = _exact_list(data["transformations"], "transformations")
    internal_observations_value = _exact_list(
        data["internal_license_observations"],
        "internal license observations",
    )
    template = FullC6TechnicalPolicyTemplate(
        artifact_coverage=parse_full_c6_artifact_coverage_document(data["artifact_coverage"]),
        external_authority=parse_full_c6_external_authority_document(
            data["external_authority"]
        ),
        rows=tuple(_parse_row(item) for item in rows_value),
        transformations=tuple(
            parse_full_c6_transformation_document(item) for item in transformations_value
        ),
        internal_license_observations=tuple(
            _parse_internal_license_observation(item)
            for item in internal_observations_value
        ),
        external_license_observation=_parse_external_license_observation(
            data["external_license_observation"]
        ),
        observed_owner_identity=_string(
            requirements["observed_owner_identity"], "observed owner identity"
        ),
    )
    _apply_template_dialect(template, dialect)
    if (
        data["authority_partition_sha256"] != template.authority_partition_sha256
        or data["transformation_set_sha256"] != template.transformation_set_sha256
        or data["template_sha256"] != template.template_sha256
        or canonical_json_bytes(template.to_dict()) != canonical_json_bytes(data)
    ):
        raise FullC6PolicyTemplateError("Full C6 technical template is stale or noncanonical")
    return template


def _template_dialect(
    value: FullC6TechnicalPolicyTemplate,
) -> ArtifactContractDialect:
    dialect = resolve_artifact_contract_dialect(
        POLICY_TEMPLATE,
        kind=value.kind,
        schema_version=value.schema_version,
        domain=value.domain,
    )
    if value._artifact_contract_dialect != dialect.name:
        raise ValueError("policy template dialect marker is inconsistent")
    return dialect


def _apply_template_dialect(
    value: FullC6TechnicalPolicyTemplate,
    dialect: ArtifactContractDialect,
) -> None:
    object.__setattr__(value, "_artifact_contract_dialect", dialect.name)
    identity = dialect.identity(POLICY_TEMPLATE)
    object.__setattr__(value, "kind", identity.kind)
    object.__setattr__(value, "schema_version", identity.schema_version)
    object.__setattr__(value, "domain", identity.domain)


def _validate_rows_and_partitions(
    rows: tuple[FullC6TechnicalPolicyRow, ...],
    artifact: ArtifactPolicyCoverageInventory,
    external: FullC6ExternalAuthorityPartition,
) -> None:
    order = {class_id: index for index, class_id in enumerate(FULL_C6_POLICY_CLASS_IDS)}
    canonical = tuple(
        sorted(
            rows,
            key=lambda item: (
                order[item.class_id],
                item.authority_identity,
                _alias(item.canonical_identity),
            ),
        )
    )
    aliases = tuple(_alias(item.canonical_identity) for item in rows)
    authorities = tuple(item.authority_identity for item in rows)
    if rows != canonical or len(aliases) != len(set(aliases)) or len(authorities) != len(
        set(authorities)
    ):
        raise FullC6PolicyTemplateError("Full C6 technical rows are noncanonical")
    by_class: dict[str, list[str]] = {
        class_id: [] for class_id in FULL_C6_POLICY_CLASS_IDS
    }
    for row in rows:
        by_class[row.class_id].append(row.authority_identity)
    for item in artifact.classes:
        identities = tuple(sorted(by_class[item.class_id]))
        if item.observed_count != len(
            identities
        ) or item.canonical_identity_set_sha256 != artifact_policy_identity_set_digest(
            item.class_id, identities
        ):
            raise FullC6PolicyTemplateError("Full C6 technical rows differ from C6.14")
    for external_item in external.classes:
        identities = tuple(sorted(by_class[external_item.class_id]))
        if external_item.observed_count != len(
            identities
        ) or external_item.canonical_identity_set_sha256 != (
            full_c6_external_authority_identity_set_digest(
                external_item.class_id, identities
            )
        ):
            raise FullC6PolicyTemplateError("Full C6 technical rows differ from C5.2")


def _validate_license_observation_bindings(
    rows: tuple[FullC6TechnicalPolicyRow, ...],
    internal: tuple[FullC6InternalLicenseObservation, ...],
    external: FullC6ExternalLicenseObservation,
) -> None:
    project = tuple(item for item in internal if item.subject_kind == "project")
    cargo = {
        item.subject_canonical_identity: item
        for item in internal
        if item.subject_kind == "cargo-registry-package"
    }
    if len(project) != 1 or len(cargo) != sum(
        item.subject_kind == "cargo-registry-package" for item in internal
    ):
        raise FullC6PolicyTemplateError(
            "Full C6 internal license subject coverage is ambiguous"
        )
    required_cargo = {
        row.canonical_identity
        for row in rows
        if row.class_id == "cargo-component:registry-package"
    }
    if set(cargo) != required_cargo:
        raise FullC6PolicyTemplateError(
            "Full C6 Cargo license observations differ from technical rows"
        )
    for row in rows:
        if row.required_license_disposition != "owner-approved-allow":
            expected = None
        elif row.license_evidence_origin == "production-external-observation":
            expected = external.observation_sha256
        elif row.class_id == "cargo-component:registry-package":
            observation = cargo.get(row.canonical_identity)
            expected = (
                observation.observation_sha256 if observation is not None else None
            )
        else:
            expected = project[0].observation_sha256
        if row.license_observation_sha256 != expected:
            raise FullC6PolicyTemplateError(
                "Full C6 policy row binds a stale license-material observation"
            )


def _validate_transformations(
    rows: tuple[FullC6TechnicalPolicyRow, ...],
    transformations: tuple[FullC6TransformationRecord, ...],
    authority_partition_sha256: str,
) -> None:
    source_classes = {
        "file-input:project-python-source",
        "file-input:present-project-python-stub",
        "external-source:python-source",
    }
    output_classes = {
        "file-input:generated-python-input",
        "file-input:generated-rust-lib",
        "file-input:generated-rust-build-input",
    }
    source_by_authority = {
        row.authority_identity: row.canonical_identity_sha256
        for row in rows
        if row.class_id in source_classes
    }
    output_by_authority = {
        row.authority_identity: row.canonical_identity_sha256
        for row in rows
        if row.class_id in output_classes
    }
    used_outputs: set[str] = set()
    for record in transformations:
        if record.authority_partition_sha256 != authority_partition_sha256:
            raise FullC6PolicyTemplateError("Full C6 transformation partition is stale")
        if record.output_identity not in output_by_authority or output_by_authority[
            record.output_identity
        ] != record.output_identity_sha256:
            raise FullC6PolicyTemplateError("Full C6 transformation output is stale")
        if record.output_identity in used_outputs:
            raise FullC6PolicyTemplateError("Full C6 transformation output is duplicated")
        for identity, digest in zip(
            record.source_identities,
            record.source_identity_sha256s,
            strict=True,
        ):
            if source_by_authority.get(identity) != digest:
                raise FullC6PolicyTemplateError("Full C6 transformation source is stale")
        used_outputs.add(record.output_identity)
    if used_outputs != set(output_by_authority):
        raise FullC6PolicyTemplateError("Full C6 transformation coverage is incomplete")


def _parse_row(value: object) -> FullC6TechnicalPolicyRow:
    data = _exact_dict(value, _ROW_FIELDS, "technical row")
    if data["owner_decision"] is not None:
        raise FullC6PolicyTemplateError("Full C6 technical row cannot contain owner decision")
    row = FullC6TechnicalPolicyRow(
        class_id=_string(data["class_id"], "technical row class"),
        canonical_identity=_string(data["canonical_identity"], "canonical identity"),
        authority_identity=_string(data["authority_identity"], "authority identity"),
        identity_mode=_string(data["identity_mode"], "identity mode"),
        sha256=_optional_string(data["sha256"], "row SHA-256"),
        size=_optional_integer(data["size"], "row size"),
        required_license_disposition=_string(
            data["required_license_disposition"], "required license disposition"
        ),
        transformation_disposition=_string(
            data["transformation_disposition"], "transformation disposition"
        ),
        license_evidence_origin=_string(
            data["license_evidence_origin"], "license evidence origin"
        ),  # type: ignore[arg-type]
        license_observation_sha256=_optional_string(
            data["license_observation_sha256"],
            "license observation SHA-256",
        ),
    )
    if data["canonical_identity_sha256"] != row.canonical_identity_sha256:
        raise FullC6PolicyTemplateError("Full C6 technical row digest is stale")
    return row


def _parse_external_license_observation(value: object) -> FullC6ExternalLicenseObservation:
    data = _exact_dict(value, _EXTERNAL_LICENSE_FIELDS, "external license observation")
    if (
        data["authority"] != "independent-exact-wheel-byte-observation"
        or data["legal_approval_inferred"] is not False
        or data["distribution_authorized"] is not False
    ):
        raise FullC6PolicyTemplateError("Full C6 external observation claims authority")
    files = _exact_list(data["license_files"], "external license files")
    observation = FullC6ExternalLicenseObservation(
        declared_spdx=_string(data["declared_spdx"], "external declared SPDX"),
        detected_spdx=_string(data["detected_spdx"], "external detected SPDX"),
        source_detector_receipt_sha256=_string(
            data["source_detector_receipt_sha256"], "external detector receipt"
        ),
        detector_payload_sha256=_string(
            data["detector_payload_sha256"], "external detector payload"
        ),
        license_files=tuple(_parse_policy_file(item) for item in files),
    )
    if data["observation_sha256"] != observation.observation_sha256:
        raise FullC6PolicyTemplateError("Full C6 external observation digest is stale")
    return observation


def _parse_internal_license_observation(
    value: object,
) -> FullC6InternalLicenseObservation:
    data = _exact_dict(value, _INTERNAL_LICENSE_FIELDS, "internal license observation")
    if (
        data["authority"] != "production-exact-license-material-observation"
        or data["legal_approval_inferred"] is not False
        or data["distribution_authorized"] is not False
    ):
        raise FullC6PolicyTemplateError("Full C6 internal observation claims authority")
    files = _exact_list(data["license_files"], "internal license files")
    observation = FullC6InternalLicenseObservation(
        subject_kind=_string(
            data["subject_kind"], "internal license subject kind"
        ),  # type: ignore[arg-type]
        subject_canonical_identity=_string(
            data["subject_canonical_identity"],
            "internal license subject identity",
        ),
        declared_spdx=_string(data["declared_spdx"], "internal declared SPDX"),
        detected_spdx=_string(data["detected_spdx"], "internal detected SPDX"),
        source_detector_receipt_sha256=_string(
            data["source_detector_receipt_sha256"],
            "internal detector receipt",
        ),
        detector_payload_sha256=_string(
            data["detector_payload_sha256"],
            "internal detector payload",
        ),
        license_files=tuple(_parse_policy_file(item) for item in files),
    )
    if data["observation_sha256"] != observation.observation_sha256:
        raise FullC6PolicyTemplateError("Full C6 internal observation digest is stale")
    return observation


def _parse_policy_file(value: object) -> FullC6PolicyFileIdentity:
    data = _exact_dict(value, _POLICY_FILE_FIELDS, "license file")
    return FullC6PolicyFileIdentity(
        logical_path=_string(data["logical_path"], "license path"),
        sha256=_string(data["sha256"], "license SHA-256"),
        size=_integer(data["size"], "license size"),
        role=_string(data["role"], "license role"),
    )


def _exact_dict(value: object, fields: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != fields:
        raise FullC6PolicyTemplateError(f"Full C6 {label} schema is invalid")
    return value


def _exact_list(value: object, label: str) -> list[object]:
    if type(value) is not list:
        raise FullC6PolicyTemplateError(f"Full C6 {label} must be an array")
    return value


def _string(value: object, label: str) -> str:
    if type(value) is not str:
        raise FullC6PolicyTemplateError(f"Full C6 {label} must be a string")
    return value


def _optional_string(value: object, label: str) -> str | None:
    return None if value is None else _string(value, label)


def _integer(value: object, label: str) -> int:
    if type(value) is not int:
        raise FullC6PolicyTemplateError(f"Full C6 {label} must be an integer")
    return value


def _optional_integer(value: object, label: str) -> int | None:
    return None if value is None else _integer(value, label)


def _require_owner_identity(value: object) -> None:
    if (
        type(value) is not str
        or not value
        or len(value) > 512
        or unicodedata.normalize("NFC", value) != value
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 .,_+@:-]*", value) is None
    ):
        raise FullC6PolicyTemplateError("Full C6 observed owner identity is invalid")


def _require_identity(value: object, label: str) -> None:
    if (
        type(value) is not str
        or not value
        or len(value) > 512
        or unicodedata.normalize("NFC", value) != value
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+@%:=/#-]*", value) is None
        or value.startswith(("/", "\\"))
        or value.endswith("/")
        or ".." in PurePosixPath(value).parts
        or PureWindowsPath(value).drive
    ):
        raise FullC6PolicyTemplateError(f"Full C6 {label} is invalid")


def _alias(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def _is_sha256(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _digest(value: object) -> str:
    try:
        return hashlib.sha256(canonical_json_bytes(value)).hexdigest()
    except (TypeError, ValueError, RecursionError, FullC6PolicyError) as exc:
        raise FullC6PolicyTemplateError("Full C6 technical template cannot be hashed") from exc


_CURRENT_TEMPLATE_IDENTITY = CURRENT.identity(POLICY_TEMPLATE)
FULL_C6_TECHNICAL_POLICY_TEMPLATE_KIND = _CURRENT_TEMPLATE_IDENTITY.kind
FULL_C6_TECHNICAL_POLICY_TEMPLATE_DOMAIN = _CURRENT_TEMPLATE_IDENTITY.domain
FULL_C6_TECHNICAL_POLICY_TEMPLATE_SCHEMA_VERSION = (
    _CURRENT_TEMPLATE_IDENTITY.schema_version
)
FULL_C6_TECHNICAL_TRANSFORMATION_SET_DOMAIN = "rextio.full-c6-transformation-set.v1"
FULL_C6_INTERNAL_LICENSE_OBSERVATION_DOMAIN = (
    "rextio.full-c6-internal-license-observation.v1"
)
FULL_C6_EXTERNAL_LICENSE_OBSERVATION_DOMAIN = (
    "rextio.full-c6-external-license-observation.v1"
)
MAX_FULL_C6_POLICY_TEMPLATE_BYTES = MAX_FULL_C6_POLICY_SERIALIZED_BYTES + 512 * 1024

_ROW_FIELDS = {
    "class_id",
    "canonical_identity",
    "authority_identity",
    "identity_mode",
    "sha256",
    "size",
    "canonical_identity_sha256",
    "required_license_disposition",
    "transformation_disposition",
    "license_evidence_origin",
    "license_observation_sha256",
    "owner_decision",
}
_POLICY_FILE_FIELDS = {"logical_path", "sha256", "size", "role"}
_EXTERNAL_LICENSE_FIELDS = {
    "authority",
    "declared_spdx",
    "detected_spdx",
    "source_detector_receipt_sha256",
    "detector_payload_sha256",
    "license_files",
    "legal_approval_inferred",
    "distribution_authorized",
    "observation_sha256",
}
_INTERNAL_LICENSE_FIELDS = {
    "authority",
    "subject_kind",
    "subject_canonical_identity",
    "declared_spdx",
    "detected_spdx",
    "source_detector_receipt_sha256",
    "detector_payload_sha256",
    "license_files",
    "observation_sha256",
    "legal_approval_inferred",
    "distribution_authorized",
}
_OWNER_REQUIREMENT_FIELDS = {
    "observed_owner_identity",
    "owner_identity_required",
    "owner_role_required",
    "trusted_public_key_sha256_required",
    "per_license_row_explicit_allow_required",
    "declared_spdx_required",
    "exact_transformation_set_acceptance_required",
}
_OWNER_REQUIREMENT_BOOLEAN_FIELDS = _OWNER_REQUIREMENT_FIELDS - {"observed_owner_identity"}
_TEMPLATE_FIELDS = {
    "kind",
    "schema_version",
    "domain",
    "authority",
    "artifact_coverage",
    "external_authority",
    "authority_partition_sha256",
    "rows",
    "transformations",
    "transformation_set_sha256",
    "internal_license_observations",
    "external_license_observation",
    "owner_completion_requirements",
    "owner_completed",
    "legal_approval_inferred",
    "signed",
    "distribution_authorized",
    "template_sha256",
}

__all__ = [
    "FULL_C6_TECHNICAL_POLICY_TEMPLATE_DOMAIN",
    "FULL_C6_TECHNICAL_POLICY_TEMPLATE_KIND",
    "FULL_C6_TECHNICAL_POLICY_TEMPLATE_SCHEMA_VERSION",
    "FullC6ExternalLicenseObservation",
    "FullC6InternalLicenseObservation",
    "FullC6PolicyTemplateError",
    "FullC6TechnicalPolicyRow",
    "FullC6TechnicalPolicyTemplate",
    "MAX_FULL_C6_POLICY_TEMPLATE_BYTES",
    "parse_full_c6_technical_policy_template",
]
