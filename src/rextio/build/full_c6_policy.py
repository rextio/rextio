"""Strict final artifact build license and source-transformation policy receipt.

This module is intentionally separate from the preview artifact-evidence models.
It validates the complete, frozen first artifact build policy universe supplied by a
caller, but it never grants distribution authority.  In particular, license
allow decisions are accepted only as an exact owner declaration included in
the canonical policy payload.  Rextio does not infer a legal conclusion.

The declaration remains unauthenticated here.  The final artifact build artifact
signature binds this policy digest; the hard gate must additionally require
that signature's verified trusted-key hash to equal the key hash declared here.
That avoids a separate policy signature and its circular receipt dependency.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import cast
import unicodedata

from rextio.artifacts.evidence import (
    ARTIFACT_POLICY_COVERAGE_CLASS_IDS,
    ArtifactPolicyCoverageClass,
    ArtifactPolicyCoverageInventory,
    artifact_policy_coverage_inventory_digest,
    artifact_policy_identity_set_digest,
    canonical_json_bytes,
    sha256_hex,
)
from rextio.artifacts.contract_dialects import (
    ANALYSIS_RECEIPT_DOMAIN,
    ANALYSIS_RECEIPT_KIND,
    ARTIFACT_COMPONENT_URN_PREFIX,
    ARTIFACT_CONTRACT_DIALECTS,
    AUTHORITY_PARTITION_DOMAIN,
    CURRENT,
    EXTERNAL_AUTHORITY_IDENTITY_SCHEME,
    EXTERNAL_AUTHORITY_PARTITION_DOMAIN,
    LICENSE_FILE_SET_DOMAIN,
    LICENSE_PROJECTION_DOMAIN,
    LOWERED_IR_RECEIPT_DOMAIN,
    LOWERED_IR_RECEIPT_KIND,
    OWNER_ACKNOWLEDGEMENT,
    OWNER_AUTHENTICATION,
    POLICY_LICENSE_DETECTOR_PAYLOAD_DOMAIN,
    POLICY_LICENSE_DETECTOR_RECEIPT_DOMAIN,
    POLICY_LICENSE_DETECTOR_RECEIPT_KIND,
    POLICY_PAYLOAD_DOMAIN,
    POLICY_RECEIPT_DOMAIN,
    POLICY_RECEIPT_KIND,
    TRANSFORMATION_PROJECTION_DOMAIN,
    TRANSFORMATION_SOURCE_SET_DOMAIN,
    ArtifactContractDialect,
)
from rextio.artifacts.full_authorization import FULL_C6_SCOPE


FULL_C6_POLICY_RECEIPT_DOMAIN = CURRENT.string_value(POLICY_RECEIPT_DOMAIN)
FULL_C6_POLICY_PAYLOAD_DOMAIN = CURRENT.string_value(POLICY_PAYLOAD_DOMAIN)
FULL_C6_LICENSE_PROJECTION_DOMAIN = CURRENT.string_value(LICENSE_PROJECTION_DOMAIN)
FULL_C6_TRANSFORMATION_PROJECTION_DOMAIN = CURRENT.string_value(
    TRANSFORMATION_PROJECTION_DOMAIN
)
FULL_C6_POLICY_RECEIPT_KIND = CURRENT.string_value(POLICY_RECEIPT_KIND)
FULL_C6_EXTERNAL_AUTHORITY_PARTITION_DOMAIN = CURRENT.string_value(
    EXTERNAL_AUTHORITY_PARTITION_DOMAIN
)
FULL_C6_EXTERNAL_AUTHORITY_IDENTITY_SCHEME = CURRENT.string_value(
    EXTERNAL_AUTHORITY_IDENTITY_SCHEME
)
FULL_C6_AUTHORITY_PARTITION_DOMAIN = CURRENT.string_value(
    AUTHORITY_PARTITION_DOMAIN
)
FULL_C6_LICENSE_FILE_SET_DOMAIN = CURRENT.string_value(LICENSE_FILE_SET_DOMAIN)
FULL_C6_LICENSE_DETECTOR_PAYLOAD_DOMAIN = (
    CURRENT.string_value(POLICY_LICENSE_DETECTOR_PAYLOAD_DOMAIN)
)
FULL_C6_LICENSE_DETECTOR_RECEIPT_DOMAIN = CURRENT.string_value(
    POLICY_LICENSE_DETECTOR_RECEIPT_DOMAIN
)
FULL_C6_LICENSE_DETECTOR_RECEIPT_KIND = CURRENT.string_value(
    POLICY_LICENSE_DETECTOR_RECEIPT_KIND
)
FULL_C6_TRANSFORMATION_SOURCE_SET_DOMAIN = CURRENT.string_value(
    TRANSFORMATION_SOURCE_SET_DOMAIN
)
FULL_C6_ANALYSIS_RECEIPT_DOMAIN = CURRENT.string_value(ANALYSIS_RECEIPT_DOMAIN)
FULL_C6_ANALYSIS_RECEIPT_KIND = CURRENT.string_value(ANALYSIS_RECEIPT_KIND)
FULL_C6_LOWERED_IR_RECEIPT_DOMAIN = CURRENT.string_value(LOWERED_IR_RECEIPT_DOMAIN)
FULL_C6_LOWERED_IR_RECEIPT_KIND = CURRENT.string_value(LOWERED_IR_RECEIPT_KIND)
FULL_C6_OWNER_ACKNOWLEDGEMENT = CURRENT.string_value(OWNER_ACKNOWLEDGEMENT)
FULL_C6_OWNER_AUTHENTICATION = CURRENT.string_value(OWNER_AUTHENTICATION)
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
_TRANSFORMATION_KIND_BY_OUTPUT_CLASS = {
    "file-input:generated-python-input": "python-wrapper-generation-v1",
    "file-input:generated-rust-lib": "python-to-rust-lowering-v1",
    "file-input:generated-rust-build-input": "python-to-rust-lowering-v1",
}
_OWNER_ROLES = frozenset({"individual-owner", "organization-owner", "authorized-representative"})
_FILE_ROLES = frozenset({"license-file"})
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+@%:=/#-]*$")
_SAFE_OWNER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 .,_+@:-]*$")
_SAFE_SPDX = re.compile(r"^[A-Za-z0-9(][A-Za-z0-9 .()+:-]*$")
_SPDX_TOKEN = re.compile(r"\(|\)|AND|OR|WITH|[A-Za-z0-9][A-Za-z0-9.-]*")
_INITIAL_SPDX_LICENSE_IDS = frozenset(
    {
        "0BSD",
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "BSL-1.0",
        "CC0-1.0",
        "GPL-2.0-only",
        "GPL-2.0-or-later",
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "ISC",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
        "MIT",
        "MPL-2.0",
        "OFL-1.1",
        "PSF-2.0",
        "Python-2.0",
        "Unicode-3.0",
        "Unlicense",
        "Zlib",
    }
)
_INITIAL_SPDX_EXCEPTION_IDS = frozenset(
    {
        "Classpath-exception-2.0",
        "GCC-exception-3.1",
        "LLVM-exception",
    }
)


def _contract_dialect(name: str) -> ArtifactContractDialect:
    try:
        return ARTIFACT_CONTRACT_DIALECTS[name]
    except KeyError as exc:
        raise FullC6PolicyError("artifact policy dialect is invalid") from exc


def _dialect_value(dialect_name: str, key: str) -> str:
    return _contract_dialect(dialect_name).string_value(key)


class FullC6PolicyError(ValueError):
    """The final artifact build policy universe is incomplete or noncanonical."""


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


def _render_spdx(node: tuple[object, ...], parent_precedence: int = 0) -> str:
    kind = node[0]
    if kind == "license":
        return str(node[1])
    if kind == "with":
        return f"{_render_spdx(cast(tuple[object, ...], node[1]))} WITH {node[2]}"
    precedence = 2 if kind == "and" else 1
    operator = " AND " if kind == "and" else " OR "
    rendered = operator.join(
        _render_spdx(cast(tuple[object, ...], child), precedence) for child in node[1:]
    )
    return f"({rendered})" if precedence < parent_precedence else rendered


def _parse_spdx(value: object, label: str) -> tuple[object, ...]:
    """Parse one canonical expression from the intentionally bounded v1 SPDX set."""
    result = _require_bounded_string(value, label=label, pattern=_SAFE_SPDX)
    tokens = tuple(_SPDX_TOKEN.findall(result))
    if not tokens or len(tokens) > 63 or "".join(tokens) != re.sub(r"\s+", "", result):
        raise FullC6PolicyError(f"{label} is not a bounded SPDX expression")
    index = 0

    def parse_primary() -> tuple[object, ...]:
        nonlocal index
        if index >= len(tokens):
            raise FullC6PolicyError(f"{label} is incomplete")
        token = tokens[index]
        if token == "(":
            index += 1
            nested = parse_or()
            if index >= len(tokens) or tokens[index] != ")":
                raise FullC6PolicyError(f"{label} has unbalanced parentheses")
            index += 1
            return nested
        if token not in _INITIAL_SPDX_LICENSE_IDS:
            raise FullC6PolicyError(f"{label} uses a license outside the initial allowlist")
        index += 1
        return ("license", token)

    def parse_with() -> tuple[object, ...]:
        nonlocal index
        left = parse_primary()
        if index < len(tokens) and tokens[index] == "WITH":
            if left[0] != "license":
                raise FullC6PolicyError(f"{label} applies WITH to a compound expression")
            index += 1
            if index >= len(tokens) or tokens[index] not in _INITIAL_SPDX_EXCEPTION_IDS:
                raise FullC6PolicyError(f"{label} uses an exception outside the allowlist")
            exception = tokens[index]
            index += 1
            return ("with", left, exception)
        return left

    def parse_and() -> tuple[object, ...]:
        nonlocal index
        values = [parse_with()]
        while index < len(tokens) and tokens[index] == "AND":
            index += 1
            values.append(parse_with())
        return values[0] if len(values) == 1 else ("and", *values)

    def parse_or() -> tuple[object, ...]:
        nonlocal index
        values = [parse_and()]
        while index < len(tokens) and tokens[index] == "OR":
            index += 1
            values.append(parse_and())
        return values[0] if len(values) == 1 else ("or", *values)

    parsed = parse_or()
    if index != len(tokens) or _render_spdx(parsed) != result:
        raise FullC6PolicyError(f"{label} is not a canonical SPDX expression")
    return parsed


def _require_spdx(value: object, label: str) -> str:
    _parse_spdx(value, label)
    assert isinstance(value, str)  # narrowed by _require_bounded_string
    return value


def canonicalize_full_c6_spdx_expression(value: object) -> str:
    """Validate and return one canonical expression from the bounded SPDX set.

    artifact build intentionally recognizes only the initial allowlist owned by this
    module.  Callers must not grow a second parser or silently normalize an
    otherwise noncanonical declaration before it is bound into evidence.
    """
    parsed = _parse_spdx(value, "artifact build SPDX expression")
    return _render_spdx(parsed)


def _require_artifact_authority_identity(
    class_id: str,
    value: object,
    *,
    dialect_name: str = CURRENT.name,
) -> str:
    identity = _require_bounded_string(
        value,
        label="artifact build artifact authority identity",
        pattern=_SAFE_IDENTITY,
    )
    prefix = (
        f"{_dialect_value(dialect_name, ARTIFACT_COMPONENT_URN_PREFIX)}"
        f"{class_id}:"
    )
    if not identity.startswith(prefix) or _SHA256.fullmatch(identity.removeprefix(prefix)) is None:
        raise FullC6PolicyError("artifact build artifact authority identity is invalid")
    return identity


def _external_authority_prefix(
    class_id: str,
    *,
    dialect_name: str = CURRENT.name,
) -> str:
    scheme = _dialect_value(dialect_name, EXTERNAL_AUTHORITY_IDENTITY_SCHEME)
    return f"{scheme}:{class_id}:"


def _require_external_authority_identity(
    class_id: str,
    value: object,
    *,
    dialect_name: str = CURRENT.name,
) -> str:
    identity = _require_bounded_string(
        value,
        label="artifact build external authority identity",
        pattern=_SAFE_IDENTITY,
    )
    prefix = _external_authority_prefix(class_id, dialect_name=dialect_name)
    if not identity.startswith(prefix) or _SHA256.fullmatch(identity.removeprefix(prefix)) is None:
        raise FullC6PolicyError("artifact build external authority identity is invalid")
    return identity


def full_c6_external_authority_identity(class_id: str, value: object) -> str:
    """Return the exact domain-qualified identity for one external-source authority authority object."""
    if class_id not in FULL_C6_EXTERNAL_POLICY_CLASS_IDS:
        raise FullC6PolicyError("artifact build external authority class is invalid")
    return (
        f"{_external_authority_prefix(class_id)}"
        f"{sha256_hex(canonical_json_bytes(value))}"
    )


def full_c6_external_authority_identity_set_digest(
    class_id: str,
    identities: tuple[str, ...],
    *,
    _artifact_contract_dialect: str = CURRENT.name,
) -> str:
    """Hash one frozen, sorted external-source authority authority identity set, including the empty set."""
    if class_id not in FULL_C6_EXTERNAL_POLICY_CLASS_IDS:
        raise FullC6PolicyError("artifact build external authority class is invalid")
    if type(identities) is not tuple:
        raise TypeError("artifact build external authority identities must be an exact tuple")
    if len(identities) > MAX_FULL_C6_POLICY_ROWS:
        raise FullC6PolicyError("artifact build external authority identity count exceeds the bound")
    for identity in identities:
        _require_external_authority_identity(
            class_id,
            identity,
            dialect_name=_artifact_contract_dialect,
        )
    if identities != tuple(sorted(set(identities))):
        raise FullC6PolicyError("artifact build external authority identities are not canonical")
    return sha256_hex(
        canonical_json_bytes(
            {
                "domain": _dialect_value(
                    _artifact_contract_dialect,
                    EXTERNAL_AUTHORITY_PARTITION_DOMAIN,
                ),
                "identity_scheme": _dialect_value(
                    _artifact_contract_dialect,
                    EXTERNAL_AUTHORITY_IDENTITY_SCHEME,
                ),
                "class_id": class_id,
                "identities": list(identities),
            }
        )
    )


@dataclass(frozen=True, slots=True)
class FullC6ExternalAuthorityClass:
    """Exact count/set summary for one frozen external-source authority source-authority class."""

    class_id: str
    observed_count: int
    canonical_identity_set_sha256: str

    def __post_init__(self) -> None:
        if type(self.class_id) is not str or self.class_id not in (
            FULL_C6_EXTERNAL_POLICY_CLASS_IDS
        ):
            raise FullC6PolicyError("artifact build external authority class is invalid")
        if (
            type(self.observed_count) is not int
            or self.observed_count < 0
            or self.observed_count > MAX_FULL_C6_POLICY_ROWS
        ):
            raise FullC6PolicyError("artifact build external authority count is invalid")
        _require_sha256(
            self.canonical_identity_set_sha256,
            "artifact build external authority identity-set sha256",
        )

    def to_dict(self) -> dict[str, object]:
        """Return the canonical exact-class summary."""
        return {
            "class_id": self.class_id,
            "observed_count": self.observed_count,
            "canonical_identity_set_sha256": self.canonical_identity_set_sha256,
        }


def full_c6_external_authority_partition_digest(
    classes: tuple[FullC6ExternalAuthorityClass, ...],
    *,
    _artifact_contract_dialect: str = CURRENT.name,
) -> str:
    """Hash the four-class exact external-source authority authority partition."""
    if type(classes) is not tuple:
        raise TypeError("artifact build external authority partition must be an exact tuple")
    if (
        len(classes) != len(FULL_C6_EXTERNAL_POLICY_CLASS_IDS)
        or any(type(item) is not FullC6ExternalAuthorityClass for item in classes)
        or tuple(item.class_id for item in classes) != FULL_C6_EXTERNAL_POLICY_CLASS_IDS
    ):
        raise FullC6PolicyError("artifact build external authority partition is not frozen")
    return sha256_hex(
        canonical_json_bytes(
            {
                "domain": _dialect_value(
                    _artifact_contract_dialect,
                    EXTERNAL_AUTHORITY_PARTITION_DOMAIN,
                ),
                "identity_scheme": _dialect_value(
                    _artifact_contract_dialect,
                    EXTERNAL_AUTHORITY_IDENTITY_SCHEME,
                ),
                "classes": [item.to_dict() for item in classes],
            }
        )
    )


@dataclass(frozen=True, slots=True)
class FullC6ExternalAuthorityPartition:
    """Deeply validated, exact four-class external-source authority authority partition."""

    classes: tuple[FullC6ExternalAuthorityClass, ...]
    observed_component_count: int
    canonical_partition_sha256: str
    _artifact_contract_dialect: str = field(
        default=CURRENT.name,
        repr=False,
        compare=False,
        kw_only=True,
    )

    def __post_init__(self) -> None:
        if type(self.classes) is not tuple:
            raise TypeError("artifact build external authority classes must be an exact tuple")
        rebuilt = tuple(
            FullC6ExternalAuthorityClass(
                class_id=item.class_id,
                observed_count=item.observed_count,
                canonical_identity_set_sha256=item.canonical_identity_set_sha256,
            )
            if type(item) is FullC6ExternalAuthorityClass
            else (_raise_external_class_type())
            for item in self.classes
        )
        if tuple(item.class_id for item in rebuilt) != FULL_C6_EXTERNAL_POLICY_CLASS_IDS:
            raise FullC6PolicyError("artifact build external authority classes are not canonical")
        expected_count = sum(item.observed_count for item in rebuilt)
        if type(self.observed_component_count) is not int:
            raise TypeError("artifact build external authority observed count must be an integer")
        if self.observed_component_count != expected_count:
            raise FullC6PolicyError("artifact build external authority observed count is inconsistent")
        _contract_dialect(self._artifact_contract_dialect)
        expected_partition = full_c6_external_authority_partition_digest(
            rebuilt,
            _artifact_contract_dialect=self._artifact_contract_dialect,
        )
        if self.canonical_partition_sha256 != expected_partition:
            raise FullC6PolicyError("artifact build external authority partition digest is inconsistent")
        object.__setattr__(self, "classes", rebuilt)

    def to_dict(self) -> dict[str, object]:
        """Return the canonical four-class authority partition."""
        return {
            "domain": _dialect_value(
                self._artifact_contract_dialect,
                EXTERNAL_AUTHORITY_PARTITION_DOMAIN,
            ),
            "identity_scheme": _dialect_value(
                self._artifact_contract_dialect,
                EXTERNAL_AUTHORITY_IDENTITY_SCHEME,
            ),
            "class_count": len(self.classes),
            "observed_component_count": self.observed_component_count,
            "canonical_partition_sha256": self.canonical_partition_sha256,
            "classes": [item.to_dict() for item in self.classes],
        }


def _raise_external_class_type() -> FullC6ExternalAuthorityClass:
    raise TypeError("artifact build external authority class has an invalid type")


@dataclass(frozen=True, slots=True)
class FullC6PolicyFileIdentity:
    """Exact immutable identity for license-file bytes."""

    logical_path: str
    sha256: str
    size: int
    role: str

    def __post_init__(self) -> None:
        _require_canonical_identity(self.logical_path, "artifact build policy file path")
        _require_sha256(self.sha256, "artifact build policy file sha256")
        if type(self.size) is not int:
            raise TypeError("artifact build policy file size must be an integer")
        if self.size <= 0 or self.size > MAX_FULL_C6_POLICY_FILE_BYTES:
            raise FullC6PolicyError("artifact build policy file size is outside the bound")
        if type(self.role) is not str or self.role not in _FILE_ROLES:
            raise FullC6PolicyError("artifact build policy file role is invalid")

    def to_dict(self) -> dict[str, object]:
        """Return the canonical exact-file identity."""
        return {
            "logical_path": self.logical_path,
            "sha256": self.sha256,
            "size": self.size,
            "role": self.role,
        }


def _license_file_identity_set_digest(
    files: tuple[FullC6PolicyFileIdentity, ...],
    *,
    dialect_name: str = CURRENT.name,
) -> str:
    return sha256_hex(
        canonical_json_bytes(
            {
                "domain": _dialect_value(dialect_name, LICENSE_FILE_SET_DOMAIN),
                "files": [item.to_dict() for item in files],
            }
        )
    )


def full_c6_license_detector_payload_digest(
    detected_spdx: str,
    files: tuple[FullC6PolicyFileIdentity, ...],
    *,
    source_detector_receipt_sha256: str,
    _artifact_contract_dialect: str = CURRENT.name,
) -> str:
    """Hash one independently observed SPDX result and exact license bytes.

    The hard gate reconstructs ``files`` from the immutable license payloads
    retained by the same SourceLock wheel-verification transaction.  Keeping
    this preimage separate from the row-specific detector receipt lets one
    exact external license observation be bound to every applicable row
    without treating an owner-authored digest as detector authority.
    """
    parsed = _parse_spdx(detected_spdx, "detected SPDX expression")
    _require_sha256(
        source_detector_receipt_sha256,
        "source license detector receipt sha256",
    )
    if type(files) is not tuple or not files:
        raise FullC6PolicyError("artifact build license detector files are invalid")
    if any(type(item) is not FullC6PolicyFileIdentity for item in files):
        raise TypeError("artifact build license detector file identity has an invalid type")
    canonical = tuple(sorted(files, key=lambda item: _identity_alias(item.logical_path)))
    if files != canonical or any(item.role != "license-file" for item in files):
        raise FullC6PolicyError("artifact build license detector files are noncanonical")
    aliases = tuple(_identity_alias(item.logical_path) for item in files)
    if len(aliases) != len(set(aliases)):
        raise FullC6PolicyError("artifact build license detector files contain an alias")
    return sha256_hex(
        canonical_json_bytes(
            {
                "domain": _dialect_value(
                    _artifact_contract_dialect,
                    POLICY_LICENSE_DETECTOR_PAYLOAD_DOMAIN,
                ),
                "source_detector_receipt_sha256": source_detector_receipt_sha256,
                "detected_spdx_projection": parsed,
                "license_files": [item.to_dict() for item in files],
            }
        )
    )


@dataclass(frozen=True, slots=True)
class FullC6LicenseEvidence:
    """Owner declaration plus an independent exact license observation."""

    declared_spdx: str
    detected_spdx: str
    subject_authority_identity: str
    subject_identity_sha256: str
    authority_partition_sha256: str
    source_detector_receipt_sha256: str
    detector_payload_sha256: str
    license_files: tuple[FullC6PolicyFileIdentity, ...]
    detector_receipt_kind: str = FULL_C6_LICENSE_DETECTOR_RECEIPT_KIND
    _artifact_contract_dialect: str = field(
        default=CURRENT.name,
        repr=False,
        compare=False,
        kw_only=True,
    )

    def __post_init__(self) -> None:
        declared = _parse_spdx(self.declared_spdx, "declared SPDX expression")
        detected = _parse_spdx(self.detected_spdx, "detected SPDX expression")
        if declared != detected:
            raise FullC6PolicyError(
                "declared and independently detected SPDX expressions must be equivalent"
            )
        _require_bounded_string(
            self.subject_authority_identity,
            label="artifact build license subject authority identity",
            pattern=_SAFE_IDENTITY,
        )
        _require_sha256(self.subject_identity_sha256, "license subject identity sha256")
        _require_sha256(self.authority_partition_sha256, "license authority partition sha256")
        _require_sha256(
            self.source_detector_receipt_sha256,
            "source license detector receipt sha256",
        )
        _require_sha256(self.detector_payload_sha256, "license detector payload sha256")
        detector_kind = _dialect_value(
            self._artifact_contract_dialect,
            POLICY_LICENSE_DETECTOR_RECEIPT_KIND,
        )
        if (
            type(self.detector_receipt_kind) is not str
            or self.detector_receipt_kind != detector_kind
        ):
            raise FullC6PolicyError("artifact build license detector receipt kind is invalid")
        if type(self.license_files) is not tuple:
            raise TypeError("artifact build license files must be an exact tuple")
        if not self.license_files or len(self.license_files) > MAX_FULL_C6_LICENSE_FILES_PER_ROW:
            raise FullC6PolicyError("artifact build license file count is outside the bound")
        if any(type(item) is not FullC6PolicyFileIdentity for item in self.license_files):
            raise TypeError("artifact build license file identity has an invalid type")
        if any(item.role != "license-file" for item in self.license_files):
            raise FullC6PolicyError("artifact build license evidence requires license-file roles")
        canonical = tuple(
            sorted(self.license_files, key=lambda item: _identity_alias(item.logical_path))
        )
        if self.license_files != canonical:
            raise FullC6PolicyError("artifact build license files are not canonically ordered")
        aliases = [_identity_alias(item.logical_path) for item in self.license_files]
        if len(aliases) != len(set(aliases)):
            raise FullC6PolicyError("artifact build license files contain an alias or duplicate")

    @property
    def license_file_identity_set_sha256(self) -> str:
        """Return the exact set digest bound into the independent detector receipt."""
        return _license_file_identity_set_digest(
            self.license_files,
            dialect_name=self._artifact_contract_dialect,
        )

    @property
    def detector_receipt_sha256(self) -> str:
        """Return a non-replayable detector identity bound to subject and file set."""
        return sha256_hex(
            canonical_json_bytes(
                {
                    "domain": _dialect_value(
                        self._artifact_contract_dialect,
                        POLICY_LICENSE_DETECTOR_RECEIPT_DOMAIN,
                    ),
                    "kind": _dialect_value(
                        self._artifact_contract_dialect,
                        POLICY_LICENSE_DETECTOR_RECEIPT_KIND,
                    ),
                    "subject_authority_identity": self.subject_authority_identity,
                    "subject_identity_sha256": self.subject_identity_sha256,
                    "authority_partition_sha256": self.authority_partition_sha256,
                    "detected_spdx": self.detected_spdx,
                    "source_detector_receipt_sha256": (
                        self.source_detector_receipt_sha256
                    ),
                    "detector_payload_sha256": self.detector_payload_sha256,
                    "license_file_identity_set_sha256": (self.license_file_identity_set_sha256),
                }
            )
        )

    def to_dict(self) -> dict[str, object]:
        """Return the canonical declared-and-detected license evidence."""
        return {
            "declared_spdx": self.declared_spdx,
            "detected_spdx": self.detected_spdx,
            "subject_authority_identity": self.subject_authority_identity,
            "subject_identity_sha256": self.subject_identity_sha256,
            "authority_partition_sha256": self.authority_partition_sha256,
            "detector_receipt_kind": _dialect_value(
                self._artifact_contract_dialect,
                POLICY_LICENSE_DETECTOR_RECEIPT_KIND,
            ),
            "source_detector_receipt_sha256": self.source_detector_receipt_sha256,
            "detector_payload_sha256": self.detector_payload_sha256,
            "detector_receipt_sha256": self.detector_receipt_sha256,
            "license_file_identity_set_sha256": self.license_file_identity_set_sha256,
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


def full_c6_policy_identity_mode(class_id: str) -> str:
    """Return the frozen identity mode for one artifact build policy class."""
    if type(class_id) is not str or class_id not in FULL_C6_POLICY_CLASS_IDS:
        raise FullC6PolicyError("artifact build policy class is outside the frozen vocabulary")
    return _IDENTITY_MODES[class_id]


def full_c6_policy_license_disposition(class_id: str) -> str:
    """Return the sole closed license disposition for one policy class."""
    if type(class_id) is not str or class_id not in FULL_C6_POLICY_CLASS_IDS:
        raise FullC6PolicyError("artifact build policy class is outside the frozen vocabulary")
    return _expected_license_disposition(class_id)


def full_c6_policy_transformation_disposition(class_id: str) -> str:
    """Return the sole closed transformation disposition for one policy class."""
    if type(class_id) is not str or class_id not in FULL_C6_POLICY_CLASS_IDS:
        raise FullC6PolicyError("artifact build policy class is outside the frozen vocabulary")
    return _expected_transformation_disposition(class_id)


def full_c6_artifact_authority_identity(class_id: str, value: object) -> str:
    """Return the exact artifact-evidence authority identity for one observed component."""
    if class_id not in ARTIFACT_POLICY_COVERAGE_CLASS_IDS:
        raise FullC6PolicyError("artifact build artifact authority class is invalid")
    return (
        f"{CURRENT.string_value(ARTIFACT_COMPONENT_URN_PREFIX)}{class_id}:"
        f"{sha256_hex(canonical_json_bytes(value))}"
    )


@dataclass(frozen=True, slots=True)
class FullC6PolicyInputRow:
    """One exact member of the frozen artifact build license/transformation universe."""

    class_id: str
    canonical_identity: str
    authority_identity: str
    identity_mode: str
    sha256: str | None
    size: int | None
    license_disposition: str
    transformation_disposition: str
    license_evidence: FullC6LicenseEvidence | None
    _artifact_contract_dialect: str = field(
        default=CURRENT.name,
        repr=False,
        compare=False,
        kw_only=True,
    )

    def __post_init__(self) -> None:
        if type(self.class_id) is not str or self.class_id not in FULL_C6_POLICY_CLASS_IDS:
            raise FullC6PolicyError("artifact build policy class is outside the frozen vocabulary")
        _require_canonical_identity(self.canonical_identity, "artifact build canonical identity")
        if self.class_id in ARTIFACT_POLICY_COVERAGE_CLASS_IDS:
            _require_artifact_authority_identity(
                self.class_id,
                self.authority_identity,
                dialect_name=self._artifact_contract_dialect,
            )
        else:
            _require_external_authority_identity(
                self.class_id,
                self.authority_identity,
                dialect_name=self._artifact_contract_dialect,
            )
        if (
            self.license_evidence is not None
            and self.license_evidence._artifact_contract_dialect
            != self._artifact_contract_dialect
        ):
            raise FullC6PolicyError(
                "artifact policy row contains a mixed contract dialect"
            )
        expected_mode = _IDENTITY_MODES[self.class_id]
        if type(self.identity_mode) is not str or self.identity_mode != expected_mode:
            raise FullC6PolicyError("artifact build identity mode does not match its class")
        if expected_mode == "content-sha256":
            _require_sha256(self.sha256, "artifact build content sha256")
            if type(self.size) is not int:
                raise TypeError("artifact build content size must be an integer")
            if self.size < 0 or self.size > MAX_FULL_C6_POLICY_FILE_BYTES:
                raise FullC6PolicyError("artifact build content size is outside the bound")
        elif expected_mode in {"cargo-registry-checksum", "source-tree-sha256"}:
            _require_sha256(self.sha256, "artifact build component sha256")
            if self.size is not None:
                raise FullC6PolicyError("artifact build component digest must not claim a file size")
        elif self.sha256 is not None or self.size is not None:
            raise FullC6PolicyError("artifact build logical system leaf must not claim file bytes")

        expected_license = _expected_license_disposition(self.class_id)
        if (
            type(self.license_disposition) is not str
            or self.license_disposition != expected_license
        ):
            raise FullC6PolicyError("artifact build license disposition is not closed for its class")
        expected_transformation = _expected_transformation_disposition(self.class_id)
        if (
            type(self.transformation_disposition) is not str
            or self.transformation_disposition != expected_transformation
        ):
            raise FullC6PolicyError(
                "artifact build transformation disposition is not closed for its class"
            )
        if expected_license == "owner-approved-allow":
            if type(self.license_evidence) is not FullC6LicenseEvidence:
                raise FullC6PolicyError(
                    "license-applicable artifact build rows require exact license evidence"
                )
            if (
                self.license_evidence.subject_authority_identity != self.authority_identity
                or self.license_evidence.subject_identity_sha256 != self.canonical_identity_sha256
            ):
                raise FullC6PolicyError("artifact build license evidence does not bind the row identity")
        elif self.license_evidence is not None:
            raise FullC6PolicyError(
                "non-applicable artifact build rows must not carry inferred license evidence"
            )

    @property
    def canonical_identity_sha256(self) -> str:
        """Return the upstream digest embedded in the exact authority identity."""
        return self.authority_identity.rsplit(":", 1)[-1]

    def _identity_dict(self) -> dict[str, object]:
        return {
            "class_id": self.class_id,
            "canonical_identity": self.canonical_identity,
            "authority_identity": self.authority_identity,
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


def full_c6_transformation_source_set_digest(
    source_identities: tuple[str, ...],
    source_identity_sha256s: tuple[str, ...],
    *,
    _artifact_contract_dialect: str = CURRENT.name,
) -> str:
    """Hash one exact ordered source set for an individual generated output."""
    if type(source_identities) is not tuple or type(source_identity_sha256s) is not tuple:
        raise TypeError("artifact build transformation sources must be exact tuples")
    if (
        not source_identities
        or len(source_identities) != len(source_identity_sha256s)
        or len(source_identities) > MAX_FULL_C6_POLICY_SOURCES_PER_TRANSFORMATION
    ):
        raise FullC6PolicyError("artifact build transformation source count is invalid")
    aliases: list[str] = []
    for identity, digest in zip(
        source_identities,
        source_identity_sha256s,
        strict=True,
    ):
        _require_canonical_identity(identity, "artifact build transformation source identity")
        _require_sha256(digest, "artifact build transformation source identity sha256")
        aliases.append(_identity_alias(identity))
    if aliases != sorted(aliases) or len(aliases) != len(set(aliases)):
        raise FullC6PolicyError("artifact build transformation sources are noncanonical or duplicated")
    return sha256_hex(
        canonical_json_bytes(
            {
                "domain": _dialect_value(
                    _artifact_contract_dialect,
                    TRANSFORMATION_SOURCE_SET_DOMAIN,
                ),
                "sources": [
                    {
                        "canonical_identity": identity,
                        "canonical_identity_sha256": digest,
                    }
                    for identity, digest in zip(
                        source_identities,
                        source_identity_sha256s,
                        strict=True,
                    )
                ],
            }
        )
    )


def full_c6_analysis_receipt_digest(
    *,
    authority_partition_sha256: str,
    source_identity_set_sha256: str,
    output_identity_sha256: str,
    analysis_sha256: str,
    _artifact_contract_dialect: str = CURRENT.name,
) -> str:
    """Bind an analysis payload to one authority partition, source set, and output."""
    for value, label in (
        (authority_partition_sha256, "artifact build analysis authority partition"),
        (source_identity_set_sha256, "artifact build analysis source set"),
        (output_identity_sha256, "artifact build analysis output identity"),
        (analysis_sha256, "artifact build analysis payload"),
    ):
        _require_sha256(value, label)
    return sha256_hex(
        canonical_json_bytes(
            {
                "domain": _dialect_value(
                    _artifact_contract_dialect,
                    ANALYSIS_RECEIPT_DOMAIN,
                ),
                "kind": _dialect_value(
                    _artifact_contract_dialect,
                    ANALYSIS_RECEIPT_KIND,
                ),
                "authority_partition_sha256": authority_partition_sha256,
                "source_identity_set_sha256": source_identity_set_sha256,
                "output_identity_sha256": output_identity_sha256,
                "analysis_sha256": analysis_sha256,
            }
        )
    )


def full_c6_lowered_ir_receipt_digest(
    *,
    authority_partition_sha256: str,
    transformation_kind: str,
    source_identity_set_sha256: str,
    output_identity_sha256: str,
    generator_sha256: str,
    analysis_receipt_sha256: str,
    lowered_ir_sha256: str,
    _artifact_contract_dialect: str = CURRENT.name,
) -> str:
    """Bind lowered IR to its exact analysis, sources, output, and generator."""
    if transformation_kind not in _TRANSFORMATION_KINDS:
        raise FullC6PolicyError("artifact build transformation kind is invalid")
    for value, label in (
        (authority_partition_sha256, "artifact build IR authority partition"),
        (source_identity_set_sha256, "artifact build IR source set"),
        (output_identity_sha256, "artifact build IR output identity"),
        (generator_sha256, "artifact build IR generator"),
        (analysis_receipt_sha256, "artifact build IR analysis receipt"),
        (lowered_ir_sha256, "artifact build IR payload"),
    ):
        _require_sha256(value, label)
    return sha256_hex(
        canonical_json_bytes(
            {
                "domain": _dialect_value(
                    _artifact_contract_dialect,
                    LOWERED_IR_RECEIPT_DOMAIN,
                ),
                "kind": _dialect_value(
                    _artifact_contract_dialect,
                    LOWERED_IR_RECEIPT_KIND,
                ),
                "authority_partition_sha256": authority_partition_sha256,
                "transformation_kind": transformation_kind,
                "source_identity_set_sha256": source_identity_set_sha256,
                "output_identity_sha256": output_identity_sha256,
                "generator_sha256": generator_sha256,
                "analysis_receipt_sha256": analysis_receipt_sha256,
                "lowered_ir_sha256": lowered_ir_sha256,
            }
        )
    )


@dataclass(frozen=True, slots=True)
class FullC6TransformationRecord:
    """Exact source-row identities that produced one generated output row."""

    record_id: str
    kind: str
    source_identities: tuple[str, ...]
    source_identity_sha256s: tuple[str, ...]
    output_identity: str
    output_identity_sha256: str
    authority_partition_sha256: str
    source_identity_set_sha256: str
    generator_sha256: str
    analysis_sha256: str
    analysis_receipt_sha256: str
    lowered_ir_sha256: str
    lowered_ir_receipt_sha256: str
    analysis_receipt_kind: str = FULL_C6_ANALYSIS_RECEIPT_KIND
    lowered_ir_receipt_kind: str = FULL_C6_LOWERED_IR_RECEIPT_KIND
    _artifact_contract_dialect: str = field(
        default=CURRENT.name,
        repr=False,
        compare=False,
        kw_only=True,
    )

    def __post_init__(self) -> None:
        _require_canonical_identity(self.record_id, "artifact build transformation record id")
        if type(self.kind) is not str or self.kind not in _TRANSFORMATION_KINDS:
            raise FullC6PolicyError("artifact build transformation kind is invalid")
        if (
            type(self.source_identities) is not tuple
            or type(self.source_identity_sha256s) is not tuple
        ):
            raise TypeError("artifact build transformation sources must be exact tuples")
        if (
            not self.source_identities
            or len(self.source_identities) > MAX_FULL_C6_POLICY_SOURCES_PER_TRANSFORMATION
            or len(self.source_identities) != len(self.source_identity_sha256s)
        ):
            raise FullC6PolicyError("artifact build transformation source count is invalid")
        expected_source_set = full_c6_transformation_source_set_digest(
            self.source_identities,
            self.source_identity_sha256s,
            _artifact_contract_dialect=self._artifact_contract_dialect,
        )
        if self.source_identity_set_sha256 != expected_source_set:
            raise FullC6PolicyError("artifact build transformation source-set receipt is stale")
        _require_canonical_identity(self.output_identity, "artifact build transformation output")
        _require_sha256(self.output_identity_sha256, "artifact build output identity sha256")
        _require_sha256(self.authority_partition_sha256, "artifact build authority partition sha256")
        _require_sha256(self.generator_sha256, "artifact build generator sha256")
        _require_sha256(self.analysis_sha256, "artifact build analysis sha256")
        _require_sha256(self.lowered_ir_sha256, "artifact build lowered IR sha256")
        if self.analysis_receipt_kind != _dialect_value(
            self._artifact_contract_dialect,
            ANALYSIS_RECEIPT_KIND,
        ):
            raise FullC6PolicyError("artifact build analysis receipt kind is invalid")
        expected_analysis = full_c6_analysis_receipt_digest(
            authority_partition_sha256=self.authority_partition_sha256,
            source_identity_set_sha256=self.source_identity_set_sha256,
            output_identity_sha256=self.output_identity_sha256,
            analysis_sha256=self.analysis_sha256,
            _artifact_contract_dialect=self._artifact_contract_dialect,
        )
        if self.analysis_receipt_sha256 != expected_analysis:
            raise FullC6PolicyError("artifact build analysis receipt identity is stale")
        if self.lowered_ir_receipt_kind != _dialect_value(
            self._artifact_contract_dialect,
            LOWERED_IR_RECEIPT_KIND,
        ):
            raise FullC6PolicyError("artifact build lowered IR receipt kind is invalid")
        expected_ir = full_c6_lowered_ir_receipt_digest(
            authority_partition_sha256=self.authority_partition_sha256,
            transformation_kind=self.kind,
            source_identity_set_sha256=self.source_identity_set_sha256,
            output_identity_sha256=self.output_identity_sha256,
            generator_sha256=self.generator_sha256,
            analysis_receipt_sha256=self.analysis_receipt_sha256,
            lowered_ir_sha256=self.lowered_ir_sha256,
            _artifact_contract_dialect=self._artifact_contract_dialect,
        )
        if self.lowered_ir_receipt_sha256 != expected_ir:
            raise FullC6PolicyError("artifact build lowered IR receipt identity is stale")
        aliases = {_identity_alias(value) for value in self.source_identities}
        if _identity_alias(self.output_identity) in aliases:
            raise FullC6PolicyError("artifact build transformation output aliases a source")

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
            "authority_partition_sha256": self.authority_partition_sha256,
            "source_identity_set_sha256": self.source_identity_set_sha256,
            "generator_sha256": self.generator_sha256,
            "analysis_sha256": self.analysis_sha256,
            "analysis_receipt_kind": _dialect_value(
                self._artifact_contract_dialect,
                ANALYSIS_RECEIPT_KIND,
            ),
            "analysis_receipt_sha256": self.analysis_receipt_sha256,
            "lowered_ir_sha256": self.lowered_ir_sha256,
            "lowered_ir_receipt_kind": _dialect_value(
                self._artifact_contract_dialect,
                LOWERED_IR_RECEIPT_KIND,
            ),
            "lowered_ir_receipt_sha256": self.lowered_ir_receipt_sha256,
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
    _artifact_contract_dialect: str = field(
        default=CURRENT.name,
        repr=False,
        compare=False,
        kw_only=True,
    )

    def __post_init__(self) -> None:
        _require_bounded_string(
            self.owner_identity,
            label="artifact build owner identity",
            pattern=_SAFE_OWNER,
        )
        if type(self.owner_role) is not str or self.owner_role not in _OWNER_ROLES:
            raise FullC6PolicyError("artifact build owner role is invalid")
        _require_sha256(self.trusted_public_key_sha256, "artifact build trusted key sha256")
        if type(self.decision) is not str or self.decision != "allow":
            raise FullC6PolicyError("artifact build owner decision must be an explicit allow")
        if type(self.action_scopes) is not tuple:
            raise TypeError("artifact build owner action scopes must be an exact tuple")
        if self.action_scopes != FULL_C6_OWNER_ACTION_SCOPES:
            raise FullC6PolicyError("artifact build owner action scopes are incomplete")
        if (
            type(self.acknowledgement) is not str
            or self.acknowledgement
            != _dialect_value(
                self._artifact_contract_dialect,
                OWNER_ACKNOWLEDGEMENT,
            )
        ):
            raise FullC6PolicyError("artifact build owner legal acknowledgement is invalid")
        if (
            type(self.authentication) is not str
            or self.authentication
            != _dialect_value(
                self._artifact_contract_dialect,
                OWNER_AUTHENTICATION,
            )
        ):
            raise FullC6PolicyError("artifact build owner authentication state is invalid")

    def to_dict(self) -> dict[str, object]:
        """Return the canonical pending-authentication owner declaration."""
        return {
            "owner_identity": self.owner_identity,
            "owner_role": self.owner_role,
            "trusted_public_key_sha256": self.trusted_public_key_sha256,
            "decision": "allow",
            "action_scopes": list(FULL_C6_OWNER_ACTION_SCOPES),
            "acknowledgement": _dialect_value(
                self._artifact_contract_dialect,
                OWNER_ACKNOWLEDGEMENT,
            ),
            "authentication": _dialect_value(
                self._artifact_contract_dialect,
                OWNER_AUTHENTICATION,
            ),
        }


def _rebuild_file(value: FullC6PolicyFileIdentity) -> FullC6PolicyFileIdentity:
    if type(value) is not FullC6PolicyFileIdentity:
        raise TypeError("artifact build policy file identity has an invalid type")
    return FullC6PolicyFileIdentity(
        logical_path=value.logical_path,
        sha256=value.sha256,
        size=value.size,
        role=value.role,
    )


def _rebuild_license(
    value: FullC6LicenseEvidence,
    *,
    dialect_name: str,
) -> FullC6LicenseEvidence:
    if type(value) is not FullC6LicenseEvidence:
        raise TypeError("artifact build license evidence has an invalid type")
    return FullC6LicenseEvidence(
        declared_spdx=value.declared_spdx,
        detected_spdx=value.detected_spdx,
        subject_authority_identity=value.subject_authority_identity,
        subject_identity_sha256=value.subject_identity_sha256,
        authority_partition_sha256=value.authority_partition_sha256,
        source_detector_receipt_sha256=value.source_detector_receipt_sha256,
        detector_payload_sha256=value.detector_payload_sha256,
        license_files=tuple(_rebuild_file(item) for item in value.license_files),
        detector_receipt_kind=value.detector_receipt_kind,
        _artifact_contract_dialect=dialect_name,
    )


def _rebuild_row(
    value: FullC6PolicyInputRow,
    *,
    dialect_name: str,
) -> FullC6PolicyInputRow:
    if type(value) is not FullC6PolicyInputRow:
        raise TypeError("artifact build policy row has an invalid type")
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
            _rebuild_license(
                value.license_evidence,
                dialect_name=dialect_name,
            )
            if value.license_evidence is not None
            else None
        ),
        _artifact_contract_dialect=dialect_name,
    )


def _rebuild_transformation(
    value: FullC6TransformationRecord,
    *,
    dialect_name: str,
) -> FullC6TransformationRecord:
    if type(value) is not FullC6TransformationRecord:
        raise TypeError("artifact build transformation record has an invalid type")
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
        _artifact_contract_dialect=dialect_name,
    )


def _rebuild_owner(
    value: FullC6OwnerDeclaration,
    *,
    dialect_name: str,
) -> FullC6OwnerDeclaration:
    if type(value) is not FullC6OwnerDeclaration:
        raise TypeError("artifact build owner declaration has an invalid type")
    return FullC6OwnerDeclaration(
        owner_identity=value.owner_identity,
        owner_role=value.owner_role,
        trusted_public_key_sha256=value.trusted_public_key_sha256,
        decision=value.decision,
        action_scopes=tuple(value.action_scopes),
        acknowledgement=value.acknowledgement,
        authentication=value.authentication,
        _artifact_contract_dialect=dialect_name,
    )


def _rebuild_artifact_coverage_class(
    value: ArtifactPolicyCoverageClass,
) -> ArtifactPolicyCoverageClass:
    if type(value) is not ArtifactPolicyCoverageClass:
        raise TypeError("artifact build artifact-evidence coverage class has an invalid type")
    return ArtifactPolicyCoverageClass(
        class_id=value.class_id,
        observed_count=value.observed_count,
        canonical_identity_set_sha256=value.canonical_identity_set_sha256,
        identity_state=value.identity_state,
        license_policy_state=value.license_policy_state,
        transformation_provenance_state=value.transformation_provenance_state,
        license_policy_receipt_kind=value.license_policy_receipt_kind,
        license_policy_receipt_sha256=value.license_policy_receipt_sha256,
        transformation_provenance_receipt_kind=(value.transformation_provenance_receipt_kind),
        transformation_provenance_receipt_sha256=(value.transformation_provenance_receipt_sha256),
    )


def _rebuild_artifact_coverage(
    value: ArtifactPolicyCoverageInventory,
) -> ArtifactPolicyCoverageInventory:
    if type(value) is not ArtifactPolicyCoverageInventory:
        raise TypeError("artifact build artifact-evidence coverage inventory has an invalid type")
    return ArtifactPolicyCoverageInventory(
        classes=tuple(_rebuild_artifact_coverage_class(item) for item in value.classes),
        observed_component_count=value.observed_component_count,
        canonical_partition_sha256=value.canonical_partition_sha256,
        kind=value.kind,
        schema_version=value.schema_version,
        scope=value.scope,
        identity_scheme=value.identity_scheme,
        authority=value.authority,
        scope_complete=value.scope_complete,
        global_license_policy_complete=value.global_license_policy_complete,
        global_transformation_provenance_complete=(value.global_transformation_provenance_complete),
        complete=value.complete,
        signed=value.signed,
        distribution_authorized=value.distribution_authorized,
    )


def _rebuild_external_authority_partition(
    value: FullC6ExternalAuthorityPartition,
    *,
    dialect_name: str,
) -> FullC6ExternalAuthorityPartition:
    if type(value) is not FullC6ExternalAuthorityPartition:
        raise TypeError("artifact build external authority partition has an invalid type")
    return FullC6ExternalAuthorityPartition(
        classes=tuple(
            FullC6ExternalAuthorityClass(
                class_id=item.class_id,
                observed_count=item.observed_count,
                canonical_identity_set_sha256=item.canonical_identity_set_sha256,
            )
            if type(item) is FullC6ExternalAuthorityClass
            else _raise_external_class_type()
            for item in value.classes
        ),
        observed_component_count=value.observed_component_count,
        canonical_partition_sha256=value.canonical_partition_sha256,
        _artifact_contract_dialect=dialect_name,
    )


def full_c6_authority_partition_digest(
    artifact_coverage: ArtifactPolicyCoverageInventory,
    external_authority: FullC6ExternalAuthorityPartition,
    *,
    _artifact_contract_dialect: str = CURRENT.name,
) -> str:
    """Bind the actual artifact-evidence partition and the frozen external-source authority authority partition."""
    trusted_artifact = _rebuild_artifact_coverage(artifact_coverage)
    trusted_external = _rebuild_external_authority_partition(
        external_authority,
        dialect_name=_artifact_contract_dialect,
    )
    return sha256_hex(
        canonical_json_bytes(
            {
                "domain": _dialect_value(
                    _artifact_contract_dialect,
                    AUTHORITY_PARTITION_DOMAIN,
                ),
                "artifact_policy_coverage_inventory_sha256": (
                    artifact_policy_coverage_inventory_digest(trusted_artifact)
                ),
                "artifact_canonical_partition_sha256": (
                    trusted_artifact.canonical_partition_sha256
                ),
                "external_canonical_partition_sha256": (
                    trusted_external.canonical_partition_sha256
                ),
            }
        )
    )


def _validate_and_rebuild_universe(
    rows: tuple[FullC6PolicyInputRow, ...],
    transformations: tuple[FullC6TransformationRecord, ...],
    artifact_coverage: ArtifactPolicyCoverageInventory,
    external_authority: FullC6ExternalAuthorityPartition,
    *,
    dialect_name: str,
) -> tuple[
    tuple[FullC6PolicyInputRow, ...],
    tuple[FullC6TransformationRecord, ...],
    ArtifactPolicyCoverageInventory,
    FullC6ExternalAuthorityPartition,
]:
    if type(external_authority) is not FullC6ExternalAuthorityPartition:
        raise TypeError(
            "artifact build external authority partition has an invalid type"
        )
    if (
        external_authority._artifact_contract_dialect != dialect_name
        or any(
            item._artifact_contract_dialect != dialect_name
            for item in rows
            if type(item) is FullC6PolicyInputRow
        )
        or any(
            item._artifact_contract_dialect != dialect_name
            for item in transformations
            if type(item) is FullC6TransformationRecord
        )
    ):
        raise FullC6PolicyError(
            "artifact policy contains a mixed nested contract dialect"
        )
    trusted_artifact = _rebuild_artifact_coverage(artifact_coverage)
    trusted_external = _rebuild_external_authority_partition(
        external_authority,
        dialect_name=dialect_name,
    )
    expected_authority_partition = full_c6_authority_partition_digest(
        trusted_artifact,
        trusted_external,
        _artifact_contract_dialect=dialect_name,
    )
    if type(rows) is not tuple:
        raise TypeError("artifact build policy rows must be an exact tuple")
    if len(rows) > MAX_FULL_C6_POLICY_ROWS:
        raise FullC6PolicyError("artifact build policy row count is outside the bound")
    rebuilt_rows = tuple(
        _rebuild_row(item, dialect_name=dialect_name) for item in rows
    )
    class_order = {class_id: index for index, class_id in enumerate(FULL_C6_POLICY_CLASS_IDS)}
    canonical_rows = tuple(
        sorted(
            rebuilt_rows,
            key=lambda item: (
                class_order[item.class_id],
                item.authority_identity,
                _identity_alias(item.canonical_identity),
            ),
        )
    )
    if rebuilt_rows != canonical_rows:
        raise FullC6PolicyError("artifact build policy rows are not canonically ordered")
    aliases = [_identity_alias(item.canonical_identity) for item in rebuilt_rows]
    if len(aliases) != len(set(aliases)):
        raise FullC6PolicyError("artifact build policy rows contain an alias or duplicate")
    authority_identities = [item.authority_identity for item in rebuilt_rows]
    if len(authority_identities) != len(set(authority_identities)):
        raise FullC6PolicyError("artifact build policy authority rows contain a duplicate")

    artifact_identities: dict[str, list[str]] = {
        class_id: [] for class_id in ARTIFACT_POLICY_COVERAGE_CLASS_IDS
    }
    external_identities: dict[str, list[str]] = {
        class_id: [] for class_id in FULL_C6_EXTERNAL_POLICY_CLASS_IDS
    }
    for row in rebuilt_rows:
        target = (
            artifact_identities
            if row.class_id in ARTIFACT_POLICY_COVERAGE_CLASS_IDS
            else external_identities
        )
        target[row.class_id].append(row.authority_identity)
    for coverage_class in trusted_artifact.classes:
        identities = tuple(sorted(artifact_identities[coverage_class.class_id]))
        if coverage_class.observed_count != len(
            identities
        ) or coverage_class.canonical_identity_set_sha256 != artifact_policy_identity_set_digest(
            coverage_class.class_id,
            identities,
            _artifact_contract_dialect=dialect_name,
        ):
            raise FullC6PolicyError("artifact build rows differ from the exact artifact-evidence coverage partition")
    for authority_class in trusted_external.classes:
        identities = tuple(sorted(external_identities[authority_class.class_id]))
        if (
            authority_class.observed_count != len(identities)
            or authority_class.canonical_identity_set_sha256
            != full_c6_external_authority_identity_set_digest(
                authority_class.class_id,
                identities,
                _artifact_contract_dialect=dialect_name,
            )
        ):
            raise FullC6PolicyError("artifact build rows differ from the exact external-source authority authority partition")

    license_files: dict[str, FullC6PolicyFileIdentity] = {}
    for row in rebuilt_rows:
        if row.license_evidence is None:
            continue
        if row.license_evidence.authority_partition_sha256 != expected_authority_partition:
            raise FullC6PolicyError(
                "artifact build license detector receipt binds a stale authority partition"
            )
        for item in row.license_evidence.license_files:
            alias = _identity_alias(item.logical_path)
            previous = license_files.setdefault(alias, item)
            if previous != item:
                raise FullC6PolicyError("artifact build license file identity conflicts across rows")

    if type(transformations) is not tuple:
        raise TypeError("artifact build transformations must be an exact tuple")
    if len(transformations) > MAX_FULL_C6_POLICY_TRANSFORMATIONS:
        raise FullC6PolicyError("artifact build transformation count is outside the bound")
    rebuilt_transformations = tuple(
        _rebuild_transformation(item, dialect_name=dialect_name)
        for item in transformations
    )
    canonical_transformations = tuple(
        sorted(rebuilt_transformations, key=lambda item: _identity_alias(item.record_id))
    )
    if rebuilt_transformations != canonical_transformations:
        raise FullC6PolicyError("artifact build transformations are not canonically ordered")
    record_aliases = [_identity_alias(item.record_id) for item in rebuilt_transformations]
    if len(record_aliases) != len(set(record_aliases)):
        raise FullC6PolicyError("artifact build transformations contain an alias or duplicate")

    row_by_alias = {_identity_alias(item.authority_identity): item for item in rebuilt_rows}
    used_outputs: set[str] = set()
    required_source_rows = tuple(
        sorted(
            (item for item in rebuilt_rows if item.class_id in _TRANSFORMATION_SOURCE_CLASSES),
            key=lambda item: item.authority_identity,
        )
    )
    required_source_pairs = tuple(
        (item.authority_identity, item.canonical_identity_sha256) for item in required_source_rows
    )
    for record in rebuilt_transformations:
        if record.authority_partition_sha256 != expected_authority_partition:
            raise FullC6PolicyError("artifact build transformation binds a stale authority partition")
        observed_source_pairs = tuple(
            zip(
                record.source_identities,
                record.source_identity_sha256s,
                strict=True,
            )
        )
        if observed_source_pairs != required_source_pairs:
            raise FullC6PolicyError("artifact build transformation omits the per-output exact source set")
        output_alias = _identity_alias(record.output_identity)
        output = row_by_alias.get(output_alias)
        if (
            output is None
            or output.class_id not in _TRANSFORMATION_OUTPUT_CLASSES
            or output.authority_identity != record.output_identity
            or output.canonical_identity_sha256 != record.output_identity_sha256
        ):
            raise FullC6PolicyError("artifact build transformation output binding is stale")
        if record.kind != _TRANSFORMATION_KIND_BY_OUTPUT_CLASS[output.class_id]:
            raise FullC6PolicyError("artifact build transformation kind does not match the output class")
        if output_alias in used_outputs:
            raise FullC6PolicyError("artifact build generated output has multiple transformations")
        used_outputs.add(output_alias)

    required_outputs = {
        _identity_alias(item.authority_identity)
        for item in rebuilt_rows
        if item.class_id in _TRANSFORMATION_OUTPUT_CLASSES
    }
    if used_outputs != required_outputs:
        raise FullC6PolicyError("artifact build source-to-generated transformation coverage is incomplete")
    return rebuilt_rows, rebuilt_transformations, trusted_artifact, trusted_external


def _policy_payload(
    rows: tuple[FullC6PolicyInputRow, ...],
    transformations: tuple[FullC6TransformationRecord, ...],
    owner_declaration: FullC6OwnerDeclaration,
    artifact_coverage: ArtifactPolicyCoverageInventory,
    external_authority: FullC6ExternalAuthorityPartition,
    bootstrap_request_sha256: str | None,
    *,
    dialect_name: str,
) -> dict[str, object]:
    return {
        "domain": _dialect_value(dialect_name, POLICY_PAYLOAD_DOMAIN),
        "scope": FULL_C6_SCOPE,
        "artifact_policy_coverage_inventory_sha256": (
            artifact_policy_coverage_inventory_digest(artifact_coverage)
        ),
        "artifact_canonical_partition_sha256": (artifact_coverage.canonical_partition_sha256),
        "external_authority_partition": external_authority.to_dict(),
        "authority_partition_sha256": full_c6_authority_partition_digest(
            artifact_coverage,
            external_authority,
            _artifact_contract_dialect=dialect_name,
        ),
        "bootstrap_request_sha256": bootstrap_request_sha256,
        "rows": [item.to_dict() for item in rows],
        "transformations": [item.to_dict() for item in transformations],
        "owner_declaration": owner_declaration.to_dict(),
    }


def _require_serialized_bound(value: object) -> bytes:
    encoded = canonical_json_bytes(value)
    if len(encoded) > MAX_FULL_C6_POLICY_SERIALIZED_BYTES:
        raise FullC6PolicyError("artifact build policy receipt exceeds the serialized byte bound")
    return encoded


def full_c6_policy_digest(
    rows: tuple[FullC6PolicyInputRow, ...],
    transformations: tuple[FullC6TransformationRecord, ...],
    owner_declaration: FullC6OwnerDeclaration,
    artifact_coverage: ArtifactPolicyCoverageInventory,
    external_authority: FullC6ExternalAuthorityPartition,
    bootstrap_request_sha256: str | None = None,
    *,
    _artifact_contract_dialect: str = CURRENT.name,
) -> str:
    """Return the final-signature policy digest after strict reconstruction."""
    if bootstrap_request_sha256 is not None:
        _require_sha256(
            bootstrap_request_sha256,
            "artifact build bootstrap request lineage",
        )
    (
        trusted_rows,
        trusted_transformations,
        trusted_artifact,
        trusted_external,
    ) = _validate_and_rebuild_universe(
        rows,
        transformations,
        artifact_coverage,
        external_authority,
        dialect_name=_artifact_contract_dialect,
    )
    trusted_owner = _rebuild_owner(
        owner_declaration,
        dialect_name=_artifact_contract_dialect,
    )
    return sha256_hex(
        _require_serialized_bound(
            _policy_payload(
                trusted_rows,
                trusted_transformations,
                trusted_owner,
                trusted_artifact,
                trusted_external,
                bootstrap_request_sha256,
                dialect_name=_artifact_contract_dialect,
            )
        )
    )


@dataclass(frozen=True, slots=True)
class FullC6PolicyReceipt:
    """Complete-for-scope policy evidence that still cannot authorize distribution."""

    rows: tuple[FullC6PolicyInputRow, ...]
    transformations: tuple[FullC6TransformationRecord, ...]
    owner_declaration: FullC6OwnerDeclaration
    artifact_coverage: ArtifactPolicyCoverageInventory
    external_authority: FullC6ExternalAuthorityPartition
    bootstrap_request_sha256: str | None = None
    kind: str = field(default=FULL_C6_POLICY_RECEIPT_KIND, init=False)
    domain: str = field(default=FULL_C6_POLICY_RECEIPT_DOMAIN, init=False)
    scope: str = field(default=FULL_C6_SCOPE, init=False)
    _artifact_contract_dialect: str = field(
        default=CURRENT.name,
        repr=False,
        compare=False,
        kw_only=True,
    )

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "kind",
            _dialect_value(self._artifact_contract_dialect, POLICY_RECEIPT_KIND),
        )
        object.__setattr__(
            self,
            "domain",
            _dialect_value(self._artifact_contract_dialect, POLICY_RECEIPT_DOMAIN),
        )
        if type(self.owner_declaration) is not FullC6OwnerDeclaration:
            raise TypeError(
                "artifact build owner declaration has an invalid type"
            )
        if self.owner_declaration._artifact_contract_dialect != (
            self._artifact_contract_dialect
        ):
            raise FullC6PolicyError(
                "artifact policy contains a mixed owner-declaration dialect"
            )
        rows, transformations, artifact_coverage, external_authority = (
            _validate_and_rebuild_universe(
                self.rows,
                self.transformations,
                self.artifact_coverage,
                self.external_authority,
                dialect_name=self._artifact_contract_dialect,
            )
        )
        owner = _rebuild_owner(
            self.owner_declaration,
            dialect_name=self._artifact_contract_dialect,
        )
        if self.bootstrap_request_sha256 is not None:
            _require_sha256(
                self.bootstrap_request_sha256,
                "artifact build bootstrap request lineage",
            )
        object.__setattr__(self, "rows", rows)
        object.__setattr__(self, "transformations", transformations)
        object.__setattr__(self, "owner_declaration", owner)
        object.__setattr__(self, "artifact_coverage", artifact_coverage)
        object.__setattr__(self, "external_authority", external_authority)
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
                    self.artifact_coverage,
                    self.external_authority,
                    self.bootstrap_request_sha256,
                    dialect_name=self._artifact_contract_dialect,
                )
            )
        )

    @property
    def artifact_policy_coverage_inventory_sha256(self) -> str:
        """Return the exact semantic identity of the actual artifact-evidence inventory."""
        return artifact_policy_coverage_inventory_digest(self.artifact_coverage)

    @property
    def external_authority_partition_sha256(self) -> str:
        """Return the exact frozen four-class external-source authority authority partition digest."""
        return self.external_authority.canonical_partition_sha256

    @property
    def authority_partition_sha256(self) -> str:
        """Return the combined artifact-evidence plus external-source authority authority identity."""
        return full_c6_authority_partition_digest(
            self.artifact_coverage,
            self.external_authority,
            _artifact_contract_dialect=self._artifact_contract_dialect,
        )

    @property
    def trusted_owner_public_key_sha256(self) -> str:
        """Expose the owner key hash the later final signature must match exactly."""
        return self.owner_declaration.trusted_public_key_sha256

    @property
    def license_policy_sha256(self) -> str:
        """Return the hard-gate digest for the complete license projection."""
        value = {
            "domain": _dialect_value(
                self._artifact_contract_dialect,
                LICENSE_PROJECTION_DOMAIN,
            ),
            "scope": FULL_C6_SCOPE,
            "policy_sha256": self.policy_sha256,
            "rows": [
                {
                    "authority_identity": row.authority_identity,
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
            "domain": _dialect_value(
                self._artifact_contract_dialect,
                TRANSFORMATION_PROJECTION_DOMAIN,
            ),
            "scope": FULL_C6_SCOPE,
            "policy_sha256": self.policy_sha256,
            "row_dispositions": [
                {
                    "authority_identity": row.authority_identity,
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
            "kind": _dialect_value(
                self._artifact_contract_dialect,
                POLICY_RECEIPT_KIND,
            ),
            "domain": _dialect_value(
                self._artifact_contract_dialect,
                POLICY_RECEIPT_DOMAIN,
            ),
            "scope": FULL_C6_SCOPE,
            "policy_sha256": self.policy_sha256,
            "artifact_policy_coverage_inventory_sha256": (
                self.artifact_policy_coverage_inventory_sha256
            ),
            "artifact_canonical_partition_sha256": (
                self.artifact_coverage.canonical_partition_sha256
            ),
            "external_authority_partition_sha256": (self.external_authority_partition_sha256),
            "authority_partition_sha256": self.authority_partition_sha256,
            "bootstrap_request_sha256": self.bootstrap_request_sha256,
            "license_policy_sha256": self.license_policy_sha256,
            "transformation_policy_sha256": self.transformation_policy_sha256,
            "rows": [item.to_dict() for item in self.rows],
            "transformations": [item.to_dict() for item in self.transformations],
            "owner_declaration": self.owner_declaration.to_dict(),
            "trusted_owner_public_key_sha256": (self.trusted_owner_public_key_sha256),
            "complete_for_scope": True,
            "all_dispositions_closed": True,
            "authentication": _dialect_value(
                self._artifact_contract_dialect,
                OWNER_AUTHENTICATION,
            ),
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
    "FULL_C6_ANALYSIS_RECEIPT_KIND",
    "FULL_C6_EXTERNAL_AUTHORITY_IDENTITY_SCHEME",
    "FULL_C6_OWNER_ACKNOWLEDGEMENT",
    "FULL_C6_OWNER_ACTION_SCOPES",
    "FULL_C6_OWNER_AUTHENTICATION",
    "FULL_C6_EXTERNAL_POLICY_CLASS_IDS",
    "FULL_C6_LICENSE_DETECTOR_RECEIPT_KIND",
    "FULL_C6_LOWERED_IR_RECEIPT_KIND",
    "FULL_C6_POLICY_CLASS_IDS",
    "FULL_C6_POLICY_RECEIPT_DOMAIN",
    "FULL_C6_POLICY_RECEIPT_KIND",
    "FullC6ExternalAuthorityClass",
    "FullC6ExternalAuthorityPartition",
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
    "full_c6_analysis_receipt_digest",
    "full_c6_artifact_authority_identity",
    "full_c6_authority_partition_digest",
    "canonicalize_full_c6_spdx_expression",
    "full_c6_external_authority_identity",
    "full_c6_external_authority_identity_set_digest",
    "full_c6_external_authority_partition_digest",
    "full_c6_license_detector_payload_digest",
    "full_c6_lowered_ir_receipt_digest",
    "full_c6_policy_digest",
    "full_c6_policy_identity_mode",
    "full_c6_policy_license_disposition",
    "full_c6_policy_transformation_disposition",
    "full_c6_transformation_source_set_digest",
]
