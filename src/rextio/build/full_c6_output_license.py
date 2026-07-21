"""Typed PEP 639 material for the bounded Full C6 output-wheel profile."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import json
from pathlib import PurePosixPath, PureWindowsPath
import re
import unicodedata

from rextio.build.full_c6_license_materials import (
    FullC6LicenseMaterialFile,
    FullC6LicenseMaterialsTransaction,
    validate_full_c6_license_materials_transaction,
)
from rextio.build.full_c6_policy import (
    FullC6PolicyError,
    canonicalize_full_c6_spdx_expression,
)


MAX_OUTPUT_WHEEL_LICENSE_FILES = 64
MAX_OUTPUT_WHEEL_LICENSE_FILE_BYTES = 64 * 1024 * 1024
MAX_OUTPUT_WHEEL_LICENSE_TOTAL_BYTES = 64 * 1024 * 1024
MAX_OUTPUT_WHEEL_LICENSE_PATH_CHARS = 512

FULL_C6_OUTPUT_LICENSE_DERIVATION_DOMAIN = (
    "rextio.full-c6-output-license-derivation.v1"
)
FULL_C6_OUTPUT_LICENSE_EXPRESSION_DOMAIN = (
    "rextio.full-c6-output-license-expression.v1"
)
FULL_C6_OUTPUT_LICENSE_CONTRACT_DOMAIN = "rextio.full-c6-output-license-contract.v1"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class FullC6OutputLicenseDerivationError(RuntimeError):
    """The sealed license inputs cannot derive this exact output contract."""


@dataclass(frozen=True, slots=True)
class OutputWheelLicenseFile:
    """One exact license payload and its PEP 639 relative path."""

    path: str
    data: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not _is_canonical_license_path(self.path):
            raise ValueError("output wheel license-file path is invalid")
        if (
            type(self.data) is not bytes
            or not self.data
            or len(self.data) > MAX_OUTPUT_WHEEL_LICENSE_FILE_BYTES
        ):
            raise ValueError("output wheel license-file payload is invalid")


@dataclass(frozen=True, slots=True)
class OutputWheelLicenseContract:
    """Exact PEP 639 expression and license bytes for one generated wheel."""

    expression: str
    files: tuple[OutputWheelLicenseFile, ...]

    def __post_init__(self) -> None:
        try:
            expression = canonicalize_full_c6_spdx_expression(self.expression)
        except FullC6PolicyError as error:
            raise ValueError(str(error)) from error
        if expression != self.expression:
            raise ValueError("output wheel license expression is noncanonical")
        if (
            type(self.files) is not tuple
            or not self.files
            or len(self.files) > MAX_OUTPUT_WHEEL_LICENSE_FILES
            or any(type(item) is not OutputWheelLicenseFile for item in self.files)
            or self.files != tuple(sorted(self.files, key=lambda item: item.path))
        ):
            raise ValueError("output wheel license-file set is invalid")
        paths = tuple(item.path for item in self.files)
        aliases = tuple(_alias(path) for path in paths)
        if len(paths) != len(set(paths)) or len(aliases) != len(set(aliases)):
            raise ValueError("output wheel license-file set contains aliases")
        if sum(len(item.data) for item in self.files) > MAX_OUTPUT_WHEEL_LICENSE_TOTAL_BYTES:
            raise ValueError("output wheel license-file set is outside the byte bound")

    @property
    def paths(self) -> tuple[str, ...]:
        """Return the canonical ordered ``License-File`` values."""
        return tuple(item.path for item in self.files)


@dataclass(frozen=True, slots=True)
class OutputWheelLicenseMemberIdentity:
    """One exact license member rederived from the completed output wheel."""

    path: str
    sha256: str
    size: int

    def __post_init__(self) -> None:
        if not _is_canonical_member_path(self.path):
            raise ValueError("output wheel license member path is invalid")
        if type(self.sha256) is not str or _SHA256.fullmatch(self.sha256) is None:
            raise ValueError("output wheel license member digest is invalid")
        if (
            type(self.size) is not int
            or isinstance(self.size, bool)
            or self.size <= 0
            or self.size > MAX_OUTPUT_WHEEL_LICENSE_FILE_BYTES
        ):
            raise ValueError("output wheel license member size is invalid")


@dataclass(frozen=True, slots=True)
class OutputWheelLicenseVerification:
    """Exact PEP 639 identities rederived from one completed wheel."""

    expression: str
    metadata_member: str
    metadata_sha256: str
    license_members: tuple[OutputWheelLicenseMemberIdentity, ...]
    record_member: str
    wheel_sha256: str

    def __post_init__(self) -> None:
        try:
            expression = canonicalize_full_c6_spdx_expression(self.expression)
        except FullC6PolicyError as error:
            raise ValueError(str(error)) from error
        if (
            expression != self.expression
            or not _is_canonical_member_path(self.metadata_member)
            or not self.metadata_member.endswith(".dist-info/METADATA")
            or not _is_canonical_member_path(self.record_member)
            or not self.record_member.endswith(".dist-info/RECORD")
            or type(self.metadata_sha256) is not str
            or _SHA256.fullmatch(self.metadata_sha256) is None
            or type(self.wheel_sha256) is not str
            or _SHA256.fullmatch(self.wheel_sha256) is None
            or type(self.license_members) is not tuple
            or not self.license_members
            or len(self.license_members) > MAX_OUTPUT_WHEEL_LICENSE_FILES
            or any(
                type(item) is not OutputWheelLicenseMemberIdentity
                for item in self.license_members
            )
        ):
            raise ValueError("output wheel license verification is invalid")
        metadata_root = self.metadata_member.rsplit("/", 1)[0]
        member_paths = tuple(item.path for item in self.license_members)
        aliases = tuple(_alias(path) for path in member_paths)
        if (
            self.license_members
            != tuple(sorted(self.license_members, key=lambda item: item.path))
            or len(member_paths) != len(set(member_paths))
            or len(aliases) != len(set(aliases))
            or sum(item.size for item in self.license_members)
            > MAX_OUTPUT_WHEEL_LICENSE_TOTAL_BYTES
            or any(
                not path.startswith(f"{metadata_root}/licenses/")
                for path in member_paths
            )
            or self.record_member.rsplit("/", 1)[0] != metadata_root
        ):
            raise ValueError("output wheel license verification is invalid")


@dataclass(frozen=True, slots=True)
class FullC6OutputLicenseMaterialMapping:
    """One source observation mapped to one exact PEP 639 output identity."""

    source_subject_identity: str
    source_observation_sha256: str
    source_logical_name: str
    output_path: str
    sha256: str
    size: int

    def __post_init__(self) -> None:
        if (
            type(self.source_subject_identity) is not str
            or not self.source_subject_identity.startswith(
                "urn:rextio:full-c6-license-material:"
            )
            or type(self.source_observation_sha256) is not str
            or _SHA256.fullmatch(self.source_observation_sha256) is None
            or not _is_canonical_member_path(self.source_logical_name)
            or not _is_canonical_license_path(self.output_path)
            or type(self.sha256) is not str
            or _SHA256.fullmatch(self.sha256) is None
            or type(self.size) is not int
            or isinstance(self.size, bool)
            or not 1 <= self.size <= MAX_OUTPUT_WHEEL_LICENSE_FILE_BYTES
        ):
            raise ValueError("Full C6 output license material mapping is invalid")

    def to_dict(self) -> dict[str, object]:
        """Return logical paths and content identities, never retained bytes."""
        return {
            "source_subject_identity": self.source_subject_identity,
            "source_observation_sha256": self.source_observation_sha256,
            "source_logical_name": self.source_logical_name,
            "output_path": self.output_path,
            "sha256": self.sha256,
            "size": self.size,
        }


@dataclass(frozen=True, slots=True)
class FullC6OutputLicenseObservation:
    """Safe, non-authorizing projection of a sealed license derivation."""

    license_transaction_sha256: str
    output_contract_sha256: str
    expression_sha256: str
    mappings: tuple[FullC6OutputLicenseMaterialMapping, ...]
    output_verification_sha256: str | None = None
    domain: str = FULL_C6_OUTPUT_LICENSE_DERIVATION_DOMAIN
    complete_coverage: bool = True
    legal_approval_inferred: bool = False
    authorizes_build: bool = False
    authorizes_distribution: bool = False

    def __post_init__(self) -> None:
        digests = (
            self.license_transaction_sha256,
            self.output_contract_sha256,
            self.expression_sha256,
        )
        if (
            self.domain != FULL_C6_OUTPUT_LICENSE_DERIVATION_DOMAIN
            or any(type(value) is not str or _SHA256.fullmatch(value) is None for value in digests)
            or (
                self.output_verification_sha256 is not None
                and (
                    type(self.output_verification_sha256) is not str
                    or _SHA256.fullmatch(self.output_verification_sha256) is None
                )
            )
            or type(self.mappings) is not tuple
            or not self.mappings
            or len(self.mappings) > MAX_OUTPUT_WHEEL_LICENSE_FILES
            or any(type(item) is not FullC6OutputLicenseMaterialMapping for item in self.mappings)
            or self.mappings
            != tuple(sorted(self.mappings, key=lambda item: item.output_path))
            or self.complete_coverage is not True
            or self.legal_approval_inferred is not False
            or self.authorizes_build is not False
            or self.authorizes_distribution is not False
        ):
            raise ValueError("Full C6 output license observation is invalid")
        output_aliases = tuple(_alias(item.output_path) for item in self.mappings)
        source_aliases = tuple(_alias(item.source_logical_name) for item in self.mappings)
        if (
            len(output_aliases) != len(set(output_aliases))
            or len(source_aliases) != len(set(source_aliases))
        ):
            raise ValueError("Full C6 output license observation contains aliases")

    @property
    def digest(self) -> str:
        """Return the canonical digest of this public projection."""
        return _digest(self._payload())

    def _payload(self) -> dict[str, object]:
        return {
            "domain": self.domain,
            "license_transaction_sha256": self.license_transaction_sha256,
            "output_contract_sha256": self.output_contract_sha256,
            "expression_sha256": self.expression_sha256,
            "mappings": [item.to_dict() for item in self.mappings],
            "output_verification_sha256": self.output_verification_sha256,
            "complete_coverage": True,
            "legal_approval_inferred": False,
            "authorizes_build": False,
            "authorizes_distribution": False,
        }

    def to_dict(self) -> dict[str, object]:
        """Return the byte-free, path-safe derivation observation."""
        return {**self._payload(), "digest": self.digest}


def rebuild_output_wheel_license_contract(
    value: OutputWheelLicenseContract,
) -> OutputWheelLicenseContract:
    """Rebuild an exact typed contract without trusting subclassed containers."""
    if type(value) is not OutputWheelLicenseContract:
        raise TypeError("output wheel license contract has an invalid type")
    try:
        if type(value.files) is not tuple:
            raise TypeError("output wheel license-file set has an invalid type")
        files = tuple(
            OutputWheelLicenseFile(path=item.path, data=item.data)
            for item in value.files
            if type(item) is OutputWheelLicenseFile
        )
        if len(files) != len(value.files):
            raise TypeError("output wheel license-file has an invalid type")
        return OutputWheelLicenseContract(
            expression=value.expression,
            files=files,
        )
    except (TypeError, ValueError) as error:
        raise ValueError("output wheel license contract is invalid") from error


def derive_full_c6_output_license_contract(
    transaction: FullC6LicenseMaterialsTransaction,
) -> OutputWheelLicenseContract:
    """Derive exact PEP 639 output bytes from one valid process-sealed transaction.

    The project expression is the distribution expression.  Dependency SPDX
    declarations remain separate source observations and are deliberately not
    combined into a synthetic expression.
    """
    contract, _mappings = _derive_full_c6_output_license(transaction)
    return contract


def validate_full_c6_output_license_contract(
    transaction: FullC6LicenseMaterialsTransaction,
    contract: OutputWheelLicenseContract,
    verification: OutputWheelLicenseVerification | None = None,
) -> FullC6OutputLicenseObservation:
    """Require exact sealed-input derivation and return a byte-free projection.

    ``verification`` may be supplied after the completed wheel has been
    independently inspected.  Its expression and every license member must
    exactly match the derived contract; unrelated caller-authored observation
    mappings are never accepted.
    """
    expected, mappings = _derive_full_c6_output_license(transaction)
    try:
        actual = rebuild_output_wheel_license_contract(contract)
    except (TypeError, ValueError) as error:
        raise FullC6OutputLicenseDerivationError(
            "output wheel license contract is malformed"
        ) from error
    if actual.expression != expected.expression or len(actual.files) != len(
        expected.files
    ):
        raise FullC6OutputLicenseDerivationError(
            "output wheel license contract differs from sealed license inputs"
        )
    for actual_file, expected_file in zip(actual.files, expected.files, strict=True):
        if (
            actual_file.path != expected_file.path
            or len(actual_file.data) != len(expected_file.data)
            or not hmac.compare_digest(actual_file.data, expected_file.data)
        ):
            raise FullC6OutputLicenseDerivationError(
                "output wheel license contract differs from sealed license inputs"
            )

    verification_sha256: str | None = None
    if verification is not None:
        checked = _rebuild_output_wheel_license_verification(verification)
        if checked.expression != expected.expression:
            raise FullC6OutputLicenseDerivationError(
                "output wheel license verification has the wrong expression"
            )
        dist_info = checked.metadata_member.rsplit("/", 1)[0]
        expected_members = tuple(
            OutputWheelLicenseMemberIdentity(
                path=f"{dist_info}/licenses/{item.path}",
                sha256=hashlib.sha256(item.data).hexdigest(),
                size=len(item.data),
            )
            for item in expected.files
        )
        if checked.license_members != expected_members:
            raise FullC6OutputLicenseDerivationError(
                "output wheel license verification differs from the derived contract"
            )
        verification_sha256 = _output_verification_digest(checked)

    return FullC6OutputLicenseObservation(
        license_transaction_sha256=transaction.digest,
        output_contract_sha256=_output_contract_digest(expected),
        expression_sha256=_expression_digest(expected.expression),
        mappings=mappings,
        output_verification_sha256=verification_sha256,
    )


def _derive_full_c6_output_license(
    transaction: FullC6LicenseMaterialsTransaction,
) -> tuple[
    OutputWheelLicenseContract,
    tuple[FullC6OutputLicenseMaterialMapping, ...],
]:
    if (
        type(transaction) is not FullC6LicenseMaterialsTransaction
        or not validate_full_c6_license_materials_transaction(transaction)
    ):
        raise FullC6OutputLicenseDerivationError(
            "Full C6 license materials transaction is invalid or stale"
        )

    derived: list[
        tuple[
            str,
            bytes,
            FullC6LicenseMaterialFile,
            str,
            str,
        ]
    ] = []
    project_payloads = transaction._project_payloads[1:]
    if len(project_payloads) != len(transaction.project.license_files):
        raise FullC6OutputLicenseDerivationError(
            "project retained license byte coverage is incomplete"
        )
    for material, payload in zip(
        transaction.project.license_files,
        project_payloads,
        strict=True,
    ):
        _require_exact_material_payload(material, payload)
        if not material.logical_name.startswith("project/"):
            raise FullC6OutputLicenseDerivationError(
                "project license material has a noncanonical logical path"
            )
        derived.append(
            (
                material.logical_name,
                payload,
                material,
                transaction.project.subject_identity,
                transaction.project.observation_sha256,
            )
        )

    try:
        cargo_pairs = transaction._cargo_workspace.metadata_payloads()
    except (TypeError, ValueError, RuntimeError) as error:
        raise FullC6OutputLicenseDerivationError(
            "sealed Cargo license payloads are unavailable"
        ) from error
    if len(cargo_pairs) != len({name for name, _payload in cargo_pairs}):
        raise FullC6OutputLicenseDerivationError(
            "sealed Cargo license payload identities are duplicated"
        )
    cargo_payloads = dict(cargo_pairs)
    for observation in transaction.cargo_packages:
        for material in observation.license_files:
            cargo_payload = cargo_payloads.get(material.logical_name)
            if cargo_payload is None:
                raise FullC6OutputLicenseDerivationError(
                    "sealed Cargo license payload coverage is incomplete"
                )
            _require_exact_material_payload(material, cargo_payload)
            parts = PurePosixPath(material.logical_name).parts
            if len(parts) < 3 or parts[0] != "vendor":
                raise FullC6OutputLicenseDerivationError(
                    "Cargo license material has a noncanonical vendor path"
                )
            output_path = PurePosixPath("cargo", *parts[1:]).as_posix()
            derived.append(
                (
                    output_path,
                    cargo_payload,
                    material,
                    observation.subject_identity,
                    observation.observation_sha256,
                )
            )

    derived.sort(key=lambda item: item[0])
    files = tuple(
        OutputWheelLicenseFile(path=output_path, data=payload)
        for output_path, payload, _material, _subject, _observation in derived
    )
    mappings = tuple(
        FullC6OutputLicenseMaterialMapping(
            source_subject_identity=subject,
            source_observation_sha256=observation_sha256,
            source_logical_name=material.logical_name,
            output_path=output_path,
            sha256=material.sha256,
            size=material.size,
        )
        for output_path, _payload, material, subject, observation_sha256 in derived
    )
    try:
        contract = OutputWheelLicenseContract(
            expression=transaction.project.observed_spdx,
            files=files,
        )
    except ValueError as error:
        raise FullC6OutputLicenseDerivationError(
            "derived output license material is outside the bounded profile"
        ) from error
    if not validate_full_c6_license_materials_transaction(transaction):
        raise FullC6OutputLicenseDerivationError(
            "Full C6 license materials transaction changed during derivation"
        )
    return contract, mappings


def _require_exact_material_payload(
    material: FullC6LicenseMaterialFile,
    payload: bytes,
) -> None:
    if (
        type(material) is not FullC6LicenseMaterialFile
        or type(payload) is not bytes
        or len(payload) != material.size
        or not hmac.compare_digest(hashlib.sha256(payload).hexdigest(), material.sha256)
    ):
        raise FullC6OutputLicenseDerivationError(
            "retained license payload differs from its sealed identity"
        )


def _rebuild_output_wheel_license_verification(
    value: OutputWheelLicenseVerification,
) -> OutputWheelLicenseVerification:
    if type(value) is not OutputWheelLicenseVerification:
        raise FullC6OutputLicenseDerivationError(
            "output wheel license verification has an invalid type"
        )
    try:
        members = tuple(
            OutputWheelLicenseMemberIdentity(
                path=item.path,
                sha256=item.sha256,
                size=item.size,
            )
            for item in value.license_members
            if type(item) is OutputWheelLicenseMemberIdentity
        )
        if len(members) != len(value.license_members):
            raise ValueError("output wheel license member has an invalid type")
        return OutputWheelLicenseVerification(
            expression=value.expression,
            metadata_member=value.metadata_member,
            metadata_sha256=value.metadata_sha256,
            license_members=members,
            record_member=value.record_member,
            wheel_sha256=value.wheel_sha256,
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise FullC6OutputLicenseDerivationError(
            "output wheel license verification is malformed"
        ) from error


def _output_contract_digest(contract: OutputWheelLicenseContract) -> str:
    return _digest(
        {
            "domain": FULL_C6_OUTPUT_LICENSE_CONTRACT_DOMAIN,
            "expression": contract.expression,
            "files": [
                {
                    "path": item.path,
                    "sha256": hashlib.sha256(item.data).hexdigest(),
                    "size": len(item.data),
                }
                for item in contract.files
            ],
        }
    )


def _expression_digest(expression: str) -> str:
    return _digest(
        {
            "domain": FULL_C6_OUTPUT_LICENSE_EXPRESSION_DOMAIN,
            "expression": expression,
        }
    )


def _output_verification_digest(verification: OutputWheelLicenseVerification) -> str:
    return _digest(
        {
            "domain": "rextio.full-c6-output-license-wheel-verification.v1",
            "expression": verification.expression,
            "metadata_member": verification.metadata_member,
            "metadata_sha256": verification.metadata_sha256,
            "license_members": [
                {
                    "path": item.path,
                    "sha256": item.sha256,
                    "size": item.size,
                }
                for item in verification.license_members
            ],
            "record_member": verification.record_member,
            "wheel_sha256": verification.wheel_sha256,
        }
    )


def _alias(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def _is_canonical_license_path(value: object) -> bool:
    return _is_canonical_member_path(value)


def _is_canonical_member_path(value: object) -> bool:
    if (
        type(value) is not str
        or not value
        or len(value) > MAX_OUTPUT_WHEEL_LICENSE_PATH_CHARS
        or value != unicodedata.normalize("NFC", value)
        or value.endswith("/")
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        return False
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    return not (
        posix.is_absolute()
        or windows.is_absolute()
        or bool(windows.drive)
        or "//" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
        or posix.as_posix() != value
    )


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


__all__ = [
    "FULL_C6_OUTPUT_LICENSE_CONTRACT_DOMAIN",
    "FULL_C6_OUTPUT_LICENSE_DERIVATION_DOMAIN",
    "FULL_C6_OUTPUT_LICENSE_EXPRESSION_DOMAIN",
    "MAX_OUTPUT_WHEEL_LICENSE_FILES",
    "MAX_OUTPUT_WHEEL_LICENSE_FILE_BYTES",
    "MAX_OUTPUT_WHEEL_LICENSE_TOTAL_BYTES",
    "FullC6OutputLicenseDerivationError",
    "FullC6OutputLicenseMaterialMapping",
    "FullC6OutputLicenseObservation",
    "OutputWheelLicenseContract",
    "OutputWheelLicenseFile",
    "OutputWheelLicenseMemberIdentity",
    "OutputWheelLicenseVerification",
    "derive_full_c6_output_license_contract",
    "rebuild_output_wheel_license_contract",
    "validate_full_c6_output_license_contract",
]
