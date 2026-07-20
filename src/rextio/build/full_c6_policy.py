"""Strict final Full C6 license and source-transformation policy receipt.

This module is intentionally separate from the preview C6.10--C6.15 models.
It validates the complete, frozen first Full C6 policy universe supplied by a
caller, but it never grants distribution authority.  In particular, license
allow decisions are accepted only as an exact owner declaration included in
the canonical policy payload.  Rextio does not infer a legal conclusion.

The declaration remains unauthenticated here.  The final Full C6 artifact
signature binds this policy digest; the hard gate must additionally require
that signature's verified trusted-key hash to equal the key hash declared here.
That avoids a separate policy signature and its circular receipt dependency.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
import unicodedata

from rextio.artifacts.evidence import (
    ARTIFACT_POLICY_COVERAGE_CLASS_IDS,
    canonical_json_bytes,
    sha256_hex,
)
from rextio.artifacts.full_authorization import FULL_C6_SCOPE


FULL_C6_POLICY_RECEIPT_DOMAIN = "rextio.full-c6-license-transformation-policy.v1"
FULL_C6_POLICY_PAYLOAD_DOMAIN = "rextio.full-c6-policy-owner-declaration-payload.v1"
FULL_C6_LICENSE_PROJECTION_DOMAIN = "rextio.full-c6-license-policy.v1"
FULL_C6_TRANSFORMATION_PROJECTION_DOMAIN = "rextio.full-c6-transformation-policy.v1"
FULL_C6_POLICY_RECEIPT_KIND = "full-c6-license-transformation-policy-receipt"
FULL_C6_OWNER_ACKNOWLEDGEMENT = "REXTIO_FULL_C6_OWNER_LEGAL_RESPONSIBILITY_ACK_V1"
FULL_C6_OWNER_AUTHENTICATION = "pending-final-full-c6-signature"
FULL_C6_OWNER_ACTION_SCOPES: tuple[str, ...] = (
    "local-build",
    "package",
    "redistribution",
)

MAX_FULL_C6_POLICY_ROWS = 1024
MAX_FULL_C6_POLICY_TRANSFORMATIONS = 1024
MAX_FULL_C6_POLICY_SOURCES_PER_TRANSFORMATION = 256
MAX_FULL_C6_LICENSE_FILES_PER_ROW = 64
MAX_FULL_C6_POLICY_STRING_CHARS = 512
MAX_FULL_C6_POLICY_FILE_BYTES = 64 * 1024 * 1024
MAX_FULL_C6_POLICY_SERIALIZED_BYTES = 4 * 1024 * 1024

FULL_C6_EXTERNAL_POLICY_CLASS_IDS: tuple[str, ...] = (
    "external-source:wheel-archive",
    "external-source:python-source",
    "external-source:distribution-metadata",
    "external-source:license-file",
)
FULL_C6_POLICY_CLASS_IDS: tuple[str, ...] = (
    *ARTIFACT_POLICY_COVERAGE_CLASS_IDS,
    *FULL_C6_EXTERNAL_POLICY_CLASS_IDS,
)

_CONTENT_CLASSES = frozenset(
    {
        "file-input:project-python-source",
        "file-input:present-project-python-stub",
        "file-input:generated-python-input",
        "file-input:generated-rust-lib",
        "file-input:generated-rust-build-input",
        "file-input:generated-cargo-lock",
        "wheel-entry:packaged-native-runtime-member",
        "file-input:policy-lock",
        "wheel-output:subject",
        "wheel-entry:other",
        "external-source:wheel-archive",
        "external-source:python-source",
        "external-source:distribution-metadata",
        "external-source:license-file",
    }
)
_IDENTITY_MODES = {
    **{class_id: "content-sha256" for class_id in _CONTENT_CLASSES},
    "cargo-component:registry-package": "cargo-registry-checksum",
    "cargo-component:path-root-package": "source-tree-sha256",
    "native-runtime:logical-system-leaf": "logical-system-leaf",
}
_LICENSE_NOT_APPLICABLE = {
    "file-input:generated-cargo-lock": "not-applicable-build-input",
    "native-runtime:logical-system-leaf": "not-applicable-system-leaf",
    "file-input:policy-lock": "not-applicable-build-input",
}
_TRANSFORMATION_SOURCE_CLASSES = frozenset(
    {
        "file-input:project-python-source",
        "file-input:present-project-python-stub",
        "external-source:python-source",
    }
)
_TRANSFORMATION_OUTPUT_CLASSES = frozenset(
    {
        "file-input:generated-python-input",
        "file-input:generated-rust-lib",
        "file-input:generated-rust-build-input",
    }
)
_TRANSFORMATION_BUILD_INPUT_CLASSES = frozenset(
    {"file-input:generated-cargo-lock", "file-input:policy-lock"}
)
_TRANSFORMATION_KINDS = frozenset(
    {
        "python-to-rust-lowering-v1",
        "python-wrapper-generation-v1",
    }
)
_OWNER_ROLES = frozenset({"individual-owner", "organization-owner", "authorized-representative"})
_FILE_ROLES = frozenset({"license-file"})
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+@%:=/#-]*$")
_SAFE_OWNER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 .,_+@:-]*$")
_SAFE_SPDX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 .()+:-]*$")
_UNKNOWN_LICENSE_TOKENS = frozenset(
    {"none", "noassertion", "unknown", "unassessed", "unspecified", "n/a", "na"}
)


class FullC6PolicyError(ValueError):
    """The final Full C6 policy universe is incomplete or noncanonical."""


def _require_sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise FullC6PolicyError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _require_bounded_string(
    value: object,
    *,
    label: str,
    pattern: re.Pattern[str],
) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > MAX_FULL_C6_POLICY_STRING_CHARS
        or unicodedata.normalize("NFC", value) != value
        or pattern.fullmatch(value) is None
    ):
        raise FullC6PolicyError(f"{label} is invalid")
    return value


def _identity_alias(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def _require_canonical_identity(value: object, label: str) -> str:
    result = _require_bounded_string(value, label=label, pattern=_SAFE_IDENTITY)
    if (
        result.startswith(("/", "#"))
        or result.endswith("/")
        or "\\" in result
        or any(part in {"", ".", ".."} for part in result.split("/"))
    ):
        raise FullC6PolicyError(f"{label} is not canonical")
    return result


def _require_spdx(value: object, label: str) -> str:
    result = _require_bounded_string(value, label=label, pattern=_SAFE_SPDX)
    folded_tokens = {token.casefold() for token in re.split(r"[^A-Za-z0-9]+", result) if token}
    if folded_tokens.intersection(_UNKNOWN_LICENSE_TOKENS):
        raise FullC6PolicyError(f"{label} contains an unknown license state")
    return result


@dataclass(frozen=True, slots=True)
class FullC6PolicyFileIdentity:
    """Exact immutable identity for license-file bytes."""

    logical_path: str
    sha256: str
    size: int
    role: str

    def __post_init__(self) -> None:
        _require_canonical_identity(self.logical_path, "Full C6 policy file path")
        _require_sha256(self.sha256, "Full C6 policy file sha256")
        if type(self.size) is not int:
            raise TypeError("Full C6 policy file size must be an integer")
        if self.size <= 0 or self.size > MAX_FULL_C6_POLICY_FILE_BYTES:
            raise FullC6PolicyError("Full C6 policy file size is outside the bound")
        if type(self.role) is not str or self.role not in _FILE_ROLES:
            raise FullC6PolicyError("Full C6 policy file role is invalid")

    def to_dict(self) -> dict[str, object]:
        """Return the canonical exact-file identity."""
        return {
            "logical_path": self.logical_path,
            "sha256": self.sha256,
            "size": self.size,
            "role": self.role,
        }


@dataclass(frozen=True, slots=True)
class FullC6LicenseEvidence:
    """Owner declaration plus an independent exact license observation."""

    declared_spdx: str
    detected_spdx: str
    detector_receipt_sha256: str
    license_files: tuple[FullC6PolicyFileIdentity, ...]

    def __post_init__(self) -> None:
        declared = _require_spdx(self.declared_spdx, "declared SPDX expression")
        detected = _require_spdx(self.detected_spdx, "detected SPDX expression")
        if declared != detected:
            raise FullC6PolicyError(
                "declared and independently detected SPDX expressions must match exactly"
            )
        _require_sha256(self.detector_receipt_sha256, "license detector receipt sha256")
        if type(self.license_files) is not tuple:
            raise TypeError("Full C6 license files must be an exact tuple")
        if not self.license_files or len(self.license_files) > MAX_FULL_C6_LICENSE_FILES_PER_ROW:
            raise FullC6PolicyError("Full C6 license file count is outside the bound")
        if any(type(item) is not FullC6PolicyFileIdentity for item in self.license_files):
            raise TypeError("Full C6 license file identity has an invalid type")
        if any(item.role != "license-file" for item in self.license_files):
            raise FullC6PolicyError("Full C6 license evidence requires license-file roles")
        canonical = tuple(
            sorted(self.license_files, key=lambda item: _identity_alias(item.logical_path))
        )
        if self.license_files != canonical:
            raise FullC6PolicyError("Full C6 license files are not canonically ordered")
        aliases = [_identity_alias(item.logical_path) for item in self.license_files]
        if len(aliases) != len(set(aliases)):
            raise FullC6PolicyError("Full C6 license files contain an alias or duplicate")

    def to_dict(self) -> dict[str, object]:
        """Return the canonical declared-and-detected license evidence."""
        return {
            "declared_spdx": self.declared_spdx,
            "detected_spdx": self.detected_spdx,
            "detector_receipt_sha256": self.detector_receipt_sha256,
            "license_files": [item.to_dict() for item in self.license_files],
        }


def _expected_license_disposition(class_id: str) -> str:
    return _LICENSE_NOT_APPLICABLE.get(class_id, "owner-approved-allow")


def _expected_transformation_disposition(class_id: str) -> str:
    if class_id in _TRANSFORMATION_SOURCE_CLASSES:
        return "exact-source-input"
    if class_id in _TRANSFORMATION_OUTPUT_CLASSES:
        return "exact-generated-output"
    if class_id in _TRANSFORMATION_BUILD_INPUT_CLASSES:
        return "not-applicable-build-input"
    if class_id == "native-runtime:logical-system-leaf":
        return "not-applicable-system-leaf"
    return "not-applicable-nontransformable"


@dataclass(frozen=True, slots=True)
class FullC6PolicyInputRow:
    """One exact member of the frozen Full C6 license/transformation universe."""

    class_id: str
    canonical_identity: str
    identity_mode: str
    sha256: str | None
    size: int | None
    license_disposition: str
    transformation_disposition: str
    license_evidence: FullC6LicenseEvidence | None

    def __post_init__(self) -> None:
        if type(self.class_id) is not str or self.class_id not in FULL_C6_POLICY_CLASS_IDS:
            raise FullC6PolicyError("Full C6 policy class is outside the frozen vocabulary")
        _require_canonical_identity(self.canonical_identity, "Full C6 canonical identity")
        expected_mode = _IDENTITY_MODES[self.class_id]
        if type(self.identity_mode) is not str or self.identity_mode != expected_mode:
            raise FullC6PolicyError("Full C6 identity mode does not match its class")
        if expected_mode == "content-sha256":
            _require_sha256(self.sha256, "Full C6 content sha256")
            if type(self.size) is not int:
                raise TypeError("Full C6 content size must be an integer")
            if self.size < 0 or self.size > MAX_FULL_C6_POLICY_FILE_BYTES:
                raise FullC6PolicyError("Full C6 content size is outside the bound")
        elif expected_mode in {"cargo-registry-checksum", "source-tree-sha256"}:
            _require_sha256(self.sha256, "Full C6 component sha256")
            if self.size is not None:
                raise FullC6PolicyError("Full C6 component digest must not claim a file size")
        elif self.sha256 is not None or self.size is not None:
            raise FullC6PolicyError("Full C6 logical system leaf must not claim file bytes")

        expected_license = _expected_license_disposition(self.class_id)
        if (
            type(self.license_disposition) is not str
            or self.license_disposition != expected_license
        ):
            raise FullC6PolicyError("Full C6 license disposition is not closed for its class")
        expected_transformation = _expected_transformation_disposition(self.class_id)
        if (
            type(self.transformation_disposition) is not str
            or self.transformation_disposition != expected_transformation
        ):
            raise FullC6PolicyError(
                "Full C6 transformation disposition is not closed for its class"
            )
        if expected_license == "owner-approved-allow":
            if type(self.license_evidence) is not FullC6LicenseEvidence:
                raise FullC6PolicyError(
                    "license-applicable Full C6 rows require exact license evidence"
                )
        elif self.license_evidence is not None:
            raise FullC6PolicyError(
                "non-applicable Full C6 rows must not carry inferred license evidence"
            )

    @property
    def canonical_identity_sha256(self) -> str:
        """Return the digest of this row's class-qualified exact identity."""
        return sha256_hex(canonical_json_bytes(self._identity_dict()))

    def _identity_dict(self) -> dict[str, object]:
        return {
            "class_id": self.class_id,
            "canonical_identity": self.canonical_identity,
            "identity_mode": self.identity_mode,
            "sha256": self.sha256,
            "size": self.size,
        }

    def to_dict(self) -> dict[str, object]:
        """Return the canonical closed policy row."""
        return {
            **self._identity_dict(),
            "canonical_identity_sha256": self.canonical_identity_sha256,
            "license_disposition": self.license_disposition,
            "transformation_disposition": self.transformation_disposition,
            "license_evidence": (
                self.license_evidence.to_dict() if self.license_evidence is not None else None
            ),
        }


@dataclass(frozen=True, slots=True)
class FullC6TransformationRecord:
    """Exact source-row identities that produced one generated output row."""

    record_id: str
    kind: str
    source_identities: tuple[str, ...]
    source_identity_sha256s: tuple[str, ...]
    output_identity: str
    output_identity_sha256: str
    generator_sha256: str
    analysis_sha256: str
    lowered_ir_sha256: str

    def __post_init__(self) -> None:
        _require_canonical_identity(self.record_id, "Full C6 transformation record id")
        if type(self.kind) is not str or self.kind not in _TRANSFORMATION_KINDS:
            raise FullC6PolicyError("Full C6 transformation kind is invalid")
        if (
            type(self.source_identities) is not tuple
            or type(self.source_identity_sha256s) is not tuple
        ):
            raise TypeError("Full C6 transformation sources must be exact tuples")
        if (
            not self.source_identities
            or len(self.source_identities) > MAX_FULL_C6_POLICY_SOURCES_PER_TRANSFORMATION
            or len(self.source_identities) != len(self.source_identity_sha256s)
        ):
            raise FullC6PolicyError("Full C6 transformation source count is invalid")
        for identity in self.source_identities:
            _require_canonical_identity(identity, "Full C6 transformation source identity")
        for digest in self.source_identity_sha256s:
            _require_sha256(digest, "Full C6 transformation source identity sha256")
        aliases = [_identity_alias(value) for value in self.source_identities]
        if aliases != sorted(aliases) or len(aliases) != len(set(aliases)):
            raise FullC6PolicyError("Full C6 transformation sources are noncanonical or duplicated")
        _require_canonical_identity(self.output_identity, "Full C6 transformation output")
        _require_sha256(self.output_identity_sha256, "Full C6 output identity sha256")
        _require_sha256(self.generator_sha256, "Full C6 generator sha256")
        _require_sha256(self.analysis_sha256, "Full C6 analysis sha256")
        _require_sha256(self.lowered_ir_sha256, "Full C6 lowered IR sha256")
        if _identity_alias(self.output_identity) in set(aliases):
            raise FullC6PolicyError("Full C6 transformation output aliases a source")

    def to_dict(self) -> dict[str, object]:
        """Return the canonical source-to-generated transformation binding."""
        return {
            "record_id": self.record_id,
            "kind": self.kind,
            "sources": [
                {"canonical_identity": identity, "canonical_identity_sha256": digest}
                for identity, digest in zip(
                    self.source_identities,
                    self.source_identity_sha256s,
                    strict=True,
                )
            ],
            "output": {
                "canonical_identity": self.output_identity,
                "canonical_identity_sha256": self.output_identity_sha256,
            },
            "generator_sha256": self.generator_sha256,
            "analysis_sha256": self.analysis_sha256,
            "lowered_ir_sha256": self.lowered_ir_sha256,
        }


@dataclass(frozen=True, slots=True)
class FullC6OwnerDeclaration:
    """Owner allow declaration included in, but not authenticating, the policy.

    The later final artifact signature authenticates the complete policy digest.
    The hard gate must compare its verified key hash with
    ``trusted_public_key_sha256`` before granting authority.
    """

    owner_identity: str
    owner_role: str
    trusted_public_key_sha256: str
    decision: str = "allow"
    action_scopes: tuple[str, ...] = FULL_C6_OWNER_ACTION_SCOPES
    acknowledgement: str = FULL_C6_OWNER_ACKNOWLEDGEMENT
    authentication: str = FULL_C6_OWNER_AUTHENTICATION

    def __post_init__(self) -> None:
        _require_bounded_string(
            self.owner_identity,
            label="Full C6 owner identity",
            pattern=_SAFE_OWNER,
        )
        if type(self.owner_role) is not str or self.owner_role not in _OWNER_ROLES:
            raise FullC6PolicyError("Full C6 owner role is invalid")
        _require_sha256(self.trusted_public_key_sha256, "Full C6 trusted key sha256")
        if type(self.decision) is not str or self.decision != "allow":
            raise FullC6PolicyError("Full C6 owner decision must be an explicit allow")
        if type(self.action_scopes) is not tuple:
            raise TypeError("Full C6 owner action scopes must be an exact tuple")
        if self.action_scopes != FULL_C6_OWNER_ACTION_SCOPES:
            raise FullC6PolicyError("Full C6 owner action scopes are incomplete")
        if (
            type(self.acknowledgement) is not str
            or self.acknowledgement != FULL_C6_OWNER_ACKNOWLEDGEMENT
        ):
            raise FullC6PolicyError("Full C6 owner legal acknowledgement is invalid")
        if (
            type(self.authentication) is not str
            or self.authentication != FULL_C6_OWNER_AUTHENTICATION
        ):
            raise FullC6PolicyError("Full C6 owner authentication state is invalid")

    def to_dict(self) -> dict[str, object]:
        """Return the canonical pending-authentication owner declaration."""
        return {
            "owner_identity": self.owner_identity,
            "owner_role": self.owner_role,
            "trusted_public_key_sha256": self.trusted_public_key_sha256,
            "decision": "allow",
            "action_scopes": list(FULL_C6_OWNER_ACTION_SCOPES),
            "acknowledgement": FULL_C6_OWNER_ACKNOWLEDGEMENT,
            "authentication": FULL_C6_OWNER_AUTHENTICATION,
        }


def _rebuild_file(value: FullC6PolicyFileIdentity) -> FullC6PolicyFileIdentity:
    if type(value) is not FullC6PolicyFileIdentity:
        raise TypeError("Full C6 policy file identity has an invalid type")
    return FullC6PolicyFileIdentity(
        logical_path=value.logical_path,
        sha256=value.sha256,
        size=value.size,
        role=value.role,
    )


def _rebuild_license(value: FullC6LicenseEvidence) -> FullC6LicenseEvidence:
    if type(value) is not FullC6LicenseEvidence:
        raise TypeError("Full C6 license evidence has an invalid type")
    return FullC6LicenseEvidence(
        declared_spdx=value.declared_spdx,
        detected_spdx=value.detected_spdx,
        detector_receipt_sha256=value.detector_receipt_sha256,
        license_files=tuple(_rebuild_file(item) for item in value.license_files),
    )


def _rebuild_row(value: FullC6PolicyInputRow) -> FullC6PolicyInputRow:
    if type(value) is not FullC6PolicyInputRow:
        raise TypeError("Full C6 policy row has an invalid type")
    return FullC6PolicyInputRow(
        class_id=value.class_id,
        canonical_identity=value.canonical_identity,
        identity_mode=value.identity_mode,
        sha256=value.sha256,
        size=value.size,
        license_disposition=value.license_disposition,
        transformation_disposition=value.transformation_disposition,
        license_evidence=(
            _rebuild_license(value.license_evidence) if value.license_evidence is not None else None
        ),
    )


def _rebuild_transformation(
    value: FullC6TransformationRecord,
) -> FullC6TransformationRecord:
    if type(value) is not FullC6TransformationRecord:
        raise TypeError("Full C6 transformation record has an invalid type")
    return FullC6TransformationRecord(
        record_id=value.record_id,
        kind=value.kind,
        source_identities=tuple(value.source_identities),
        source_identity_sha256s=tuple(value.source_identity_sha256s),
        output_identity=value.output_identity,
        output_identity_sha256=value.output_identity_sha256,
        generator_sha256=value.generator_sha256,
        analysis_sha256=value.analysis_sha256,
        lowered_ir_sha256=value.lowered_ir_sha256,
    )


def _rebuild_owner(value: FullC6OwnerDeclaration) -> FullC6OwnerDeclaration:
    if type(value) is not FullC6OwnerDeclaration:
        raise TypeError("Full C6 owner declaration has an invalid type")
    return FullC6OwnerDeclaration(
        owner_identity=value.owner_identity,
        owner_role=value.owner_role,
        trusted_public_key_sha256=value.trusted_public_key_sha256,
        decision=value.decision,
        action_scopes=tuple(value.action_scopes),
        acknowledgement=value.acknowledgement,
        authentication=value.authentication,
    )


def _validate_and_rebuild_universe(
    rows: tuple[FullC6PolicyInputRow, ...],
    transformations: tuple[FullC6TransformationRecord, ...],
) -> tuple[tuple[FullC6PolicyInputRow, ...], tuple[FullC6TransformationRecord, ...]]:
    if type(rows) is not tuple:
        raise TypeError("Full C6 policy rows must be an exact tuple")
    if len(rows) < len(FULL_C6_POLICY_CLASS_IDS) or len(rows) > MAX_FULL_C6_POLICY_ROWS:
        raise FullC6PolicyError("Full C6 policy row count is outside the bound")
    rebuilt_rows = tuple(_rebuild_row(item) for item in rows)
    class_order = {class_id: index for index, class_id in enumerate(FULL_C6_POLICY_CLASS_IDS)}
    canonical_rows = tuple(
        sorted(
            rebuilt_rows,
            key=lambda item: (
                class_order[item.class_id],
                _identity_alias(item.canonical_identity),
            ),
        )
    )
    if rebuilt_rows != canonical_rows:
        raise FullC6PolicyError("Full C6 policy rows are not canonically ordered")
    aliases = [_identity_alias(item.canonical_identity) for item in rebuilt_rows]
    if len(aliases) != len(set(aliases)):
        raise FullC6PolicyError("Full C6 policy rows contain an alias or duplicate")
    observed_classes = {item.class_id for item in rebuilt_rows}
    if observed_classes != set(FULL_C6_POLICY_CLASS_IDS):
        raise FullC6PolicyError("Full C6 policy rows do not cover the exact frozen classes")

    license_files: dict[str, FullC6PolicyFileIdentity] = {}
    for row in rebuilt_rows:
        if row.license_evidence is None:
            continue
        for item in row.license_evidence.license_files:
            alias = _identity_alias(item.logical_path)
            previous = license_files.setdefault(alias, item)
            if previous != item:
                raise FullC6PolicyError("Full C6 license file identity conflicts across rows")

    if type(transformations) is not tuple:
        raise TypeError("Full C6 transformations must be an exact tuple")
    if not transformations or len(transformations) > MAX_FULL_C6_POLICY_TRANSFORMATIONS:
        raise FullC6PolicyError("Full C6 transformation count is outside the bound")
    rebuilt_transformations = tuple(_rebuild_transformation(item) for item in transformations)
    canonical_transformations = tuple(
        sorted(rebuilt_transformations, key=lambda item: _identity_alias(item.record_id))
    )
    if rebuilt_transformations != canonical_transformations:
        raise FullC6PolicyError("Full C6 transformations are not canonically ordered")
    record_aliases = [_identity_alias(item.record_id) for item in rebuilt_transformations]
    if len(record_aliases) != len(set(record_aliases)):
        raise FullC6PolicyError("Full C6 transformations contain an alias or duplicate")

    row_by_alias = {_identity_alias(item.canonical_identity): item for item in rebuilt_rows}
    used_sources: set[str] = set()
    used_outputs: set[str] = set()
    for record in rebuilt_transformations:
        for identity, digest in zip(
            record.source_identities,
            record.source_identity_sha256s,
            strict=True,
        ):
            alias = _identity_alias(identity)
            source = row_by_alias.get(alias)
            if (
                source is None
                or source.class_id not in _TRANSFORMATION_SOURCE_CLASSES
                or source.canonical_identity != identity
                or source.canonical_identity_sha256 != digest
            ):
                raise FullC6PolicyError("Full C6 transformation source binding is stale")
            used_sources.add(alias)
        output_alias = _identity_alias(record.output_identity)
        output = row_by_alias.get(output_alias)
        if (
            output is None
            or output.class_id not in _TRANSFORMATION_OUTPUT_CLASSES
            or output.canonical_identity != record.output_identity
            or output.canonical_identity_sha256 != record.output_identity_sha256
        ):
            raise FullC6PolicyError("Full C6 transformation output binding is stale")
        if output_alias in used_outputs:
            raise FullC6PolicyError("Full C6 generated output has multiple transformations")
        used_outputs.add(output_alias)

    required_sources = {
        _identity_alias(item.canonical_identity)
        for item in rebuilt_rows
        if item.class_id in _TRANSFORMATION_SOURCE_CLASSES
    }
    required_outputs = {
        _identity_alias(item.canonical_identity)
        for item in rebuilt_rows
        if item.class_id in _TRANSFORMATION_OUTPUT_CLASSES
    }
    if used_sources != required_sources or used_outputs != required_outputs:
        raise FullC6PolicyError("Full C6 source-to-generated transformation coverage is incomplete")
    return rebuilt_rows, rebuilt_transformations


def _policy_payload(
    rows: tuple[FullC6PolicyInputRow, ...],
    transformations: tuple[FullC6TransformationRecord, ...],
    owner_declaration: FullC6OwnerDeclaration,
) -> dict[str, object]:
    return {
        "domain": FULL_C6_POLICY_PAYLOAD_DOMAIN,
        "scope": FULL_C6_SCOPE,
        "rows": [item.to_dict() for item in rows],
        "transformations": [item.to_dict() for item in transformations],
        "owner_declaration": owner_declaration.to_dict(),
    }


def _require_serialized_bound(value: object) -> bytes:
    encoded = canonical_json_bytes(value)
    if len(encoded) > MAX_FULL_C6_POLICY_SERIALIZED_BYTES:
        raise FullC6PolicyError("Full C6 policy receipt exceeds the serialized byte bound")
    return encoded


def full_c6_policy_digest(
    rows: tuple[FullC6PolicyInputRow, ...],
    transformations: tuple[FullC6TransformationRecord, ...],
    owner_declaration: FullC6OwnerDeclaration,
) -> str:
    """Return the final-signature policy digest after strict reconstruction."""
    trusted_rows, trusted_transformations = _validate_and_rebuild_universe(
        rows,
        transformations,
    )
    trusted_owner = _rebuild_owner(owner_declaration)
    return sha256_hex(
        _require_serialized_bound(
            _policy_payload(trusted_rows, trusted_transformations, trusted_owner)
        )
    )


@dataclass(frozen=True, slots=True)
class FullC6PolicyReceipt:
    """Complete-for-scope policy evidence that still cannot authorize distribution."""

    rows: tuple[FullC6PolicyInputRow, ...]
    transformations: tuple[FullC6TransformationRecord, ...]
    owner_declaration: FullC6OwnerDeclaration
    kind: str = field(default=FULL_C6_POLICY_RECEIPT_KIND, init=False)
    domain: str = field(default=FULL_C6_POLICY_RECEIPT_DOMAIN, init=False)
    scope: str = field(default=FULL_C6_SCOPE, init=False)

    def __post_init__(self) -> None:
        rows, transformations = _validate_and_rebuild_universe(
            self.rows,
            self.transformations,
        )
        owner = _rebuild_owner(self.owner_declaration)
        object.__setattr__(self, "rows", rows)
        object.__setattr__(self, "transformations", transformations)
        object.__setattr__(self, "owner_declaration", owner)
        _require_serialized_bound(self._payload())

    @property
    def policy_sha256(self) -> str:
        """Return the policy digest authenticated by the final artifact signature."""
        return sha256_hex(
            _require_serialized_bound(
                _policy_payload(
                    self.rows,
                    self.transformations,
                    self.owner_declaration,
                )
            )
        )

    @property
    def license_policy_sha256(self) -> str:
        """Return the hard-gate digest for the complete license projection."""
        value = {
            "domain": FULL_C6_LICENSE_PROJECTION_DOMAIN,
            "scope": FULL_C6_SCOPE,
            "policy_sha256": self.policy_sha256,
            "rows": [
                {
                    "canonical_identity_sha256": row.canonical_identity_sha256,
                    "license_disposition": row.license_disposition,
                    "license_evidence": (
                        row.license_evidence.to_dict() if row.license_evidence is not None else None
                    ),
                }
                for row in self.rows
            ],
            "owner_declaration": self.owner_declaration.to_dict(),
        }
        return sha256_hex(_require_serialized_bound(value))

    @property
    def transformation_policy_sha256(self) -> str:
        """Return the hard-gate digest for the transformation projection."""
        value = {
            "domain": FULL_C6_TRANSFORMATION_PROJECTION_DOMAIN,
            "scope": FULL_C6_SCOPE,
            "policy_sha256": self.policy_sha256,
            "row_dispositions": [
                {
                    "canonical_identity_sha256": row.canonical_identity_sha256,
                    "transformation_disposition": row.transformation_disposition,
                }
                for row in self.rows
            ],
            "transformations": [item.to_dict() for item in self.transformations],
            "owner_declaration_sha256": sha256_hex(
                canonical_json_bytes(self.owner_declaration.to_dict())
            ),
        }
        return sha256_hex(_require_serialized_bound(value))

    def _payload(self) -> dict[str, object]:
        return {
            "kind": FULL_C6_POLICY_RECEIPT_KIND,
            "domain": FULL_C6_POLICY_RECEIPT_DOMAIN,
            "scope": FULL_C6_SCOPE,
            "policy_sha256": self.policy_sha256,
            "license_policy_sha256": self.license_policy_sha256,
            "transformation_policy_sha256": self.transformation_policy_sha256,
            "rows": [item.to_dict() for item in self.rows],
            "transformations": [item.to_dict() for item in self.transformations],
            "owner_declaration": self.owner_declaration.to_dict(),
            "complete_for_scope": True,
            "all_dispositions_closed": True,
            "authentication": FULL_C6_OWNER_AUTHENTICATION,
            "owner_allow_declaration_bound": True,
            "owner_allow_declaration_authenticated": False,
            "legal_advice_inferred": False,
            "distribution_authorized": False,
        }

    @property
    def digest(self) -> str:
        """Return the canonical semantic receipt digest."""
        return sha256_hex(_require_serialized_bound(self._payload()))

    @property
    def distribution_authorized(self) -> bool:
        """Keep this complete policy receipt strictly non-authorizing."""
        return False

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic non-authorizing receipt."""
        return {**self._payload(), "digest": self.digest}


__all__ = [
    "FULL_C6_OWNER_ACKNOWLEDGEMENT",
    "FULL_C6_OWNER_ACTION_SCOPES",
    "FULL_C6_OWNER_AUTHENTICATION",
    "FULL_C6_EXTERNAL_POLICY_CLASS_IDS",
    "FULL_C6_POLICY_CLASS_IDS",
    "FULL_C6_POLICY_RECEIPT_DOMAIN",
    "FULL_C6_POLICY_RECEIPT_KIND",
    "FullC6LicenseEvidence",
    "FullC6PolicyError",
    "FullC6PolicyFileIdentity",
    "FullC6PolicyInputRow",
    "FullC6PolicyReceipt",
    "FullC6OwnerDeclaration",
    "FullC6TransformationRecord",
    "MAX_FULL_C6_LICENSE_FILES_PER_ROW",
    "MAX_FULL_C6_POLICY_ROWS",
    "MAX_FULL_C6_POLICY_SERIALIZED_BYTES",
    "MAX_FULL_C6_POLICY_SOURCES_PER_TRANSFORMATION",
    "MAX_FULL_C6_POLICY_TRANSFORMATIONS",
    "full_c6_policy_digest",
]
