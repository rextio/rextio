"""Typed PEP 639 material for the bounded artifact build output-wheel profile."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import json
from pathlib import PurePosixPath, PureWindowsPath
import re
import unicodedata

from rextio.artifacts.contract_dialects import (
    CURRENT,
    OUTPUT_LICENSE_CONTRACT_DOMAIN,
    OUTPUT_LICENSE_DERIVATION_DOMAIN,
    OUTPUT_LICENSE_EXPRESSION_DOMAIN,
    OUTPUT_LICENSE_MAPPING_DOMAIN,
    OUTPUT_LICENSE_SOURCE_LOCK_DOMAIN,
)
from rextio.build.full_c6_license_materials import (
    FullC6LicenseMaterialFile,
    FullC6LicenseMaterialsTransaction,
    validate_full_c6_license_materials_transaction,
)
from rextio.build.full_c6_policy import (
    FullC6PolicyError,
    canonicalize_full_c6_spdx_expression,
)
from rextio.source.external import _canonical_name
from rextio.source.source_lock_v2 import (
    SourceLockV2VerifiedContext,
    validate_source_lock_v2_verified_context,
)
from rextio.source.wheel_authority import (
    SourceWheelEntryIdentity,
    verify_source_wheel_license_detection,
)


MAX_OUTPUT_WHEEL_LICENSE_FILES = 128
MAX_OUTPUT_WHEEL_LICENSE_FILE_BYTES = 64 * 1024 * 1024
MAX_OUTPUT_WHEEL_LICENSE_TOTAL_BYTES = 64 * 1024 * 1024
MAX_OUTPUT_WHEEL_LICENSE_PATH_CHARS = 512

FULL_C6_OUTPUT_LICENSE_DERIVATION_DOMAIN = CURRENT.string_value(
    OUTPUT_LICENSE_DERIVATION_DOMAIN
)
FULL_C6_OUTPUT_LICENSE_EXPRESSION_DOMAIN = CURRENT.string_value(
    OUTPUT_LICENSE_EXPRESSION_DOMAIN
)
FULL_C6_OUTPUT_LICENSE_CONTRACT_DOMAIN = CURRENT.string_value(
    OUTPUT_LICENSE_CONTRACT_DOMAIN
)
FULL_C6_OUTPUT_LICENSE_MAPPING_DOMAIN = CURRENT.string_value(
    OUTPUT_LICENSE_MAPPING_DOMAIN
)
FULL_C6_OUTPUT_LICENSE_SOURCE_LOCK_DOMAIN = (
    CURRENT.string_value(OUTPUT_LICENSE_SOURCE_LOCK_DOMAIN)
)

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
    external_source_distribution: str | None = None
    external_source_version: str | None = None
    source_lock_verification_sha256: str | None = None

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
        binding = (
            self.external_source_distribution,
            self.external_source_version,
            self.source_lock_verification_sha256,
        )
        if any(item is not None for item in binding):
            if (
                not all(type(item) is str for item in binding)
                or self.external_source_distribution
                != _canonical_name(self.external_source_distribution or "")
                or not _is_canonical_identity_segment(self.external_source_distribution)
                or not _is_canonical_identity_segment(self.external_source_version)
                or type(self.source_lock_verification_sha256) is not str
                or _SHA256.fullmatch(self.source_lock_verification_sha256) is None
            ):
                raise ValueError("output wheel external source binding is invalid")
            prefix = f"external/{self.external_source_distribution}/{self.external_source_version}/"
            external_paths = tuple(
                item.path for item in self.files if item.path.startswith("external/")
            )
            if not external_paths:
                raise ValueError("output wheel external license-file coverage is missing")
            if any(not path.startswith(prefix) for path in external_paths):
                raise ValueError(
                    "output wheel external license-file path escapes its source binding"
                )
        elif any(item.path.startswith("external/") for item in self.files):
            raise ValueError("output wheel external license-file binding is missing")

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
                type(item) is not OutputWheelLicenseMemberIdentity for item in self.license_members
            )
        ):
            raise ValueError("output wheel license verification is invalid")
        metadata_root = self.metadata_member.rsplit("/", 1)[0]
        member_paths = tuple(item.path for item in self.license_members)
        aliases = tuple(_alias(path) for path in member_paths)
        if (
            self.license_members != tuple(sorted(self.license_members, key=lambda item: item.path))
            or len(member_paths) != len(set(member_paths))
            or len(aliases) != len(set(aliases))
            or sum(item.size for item in self.license_members)
            > MAX_OUTPUT_WHEEL_LICENSE_TOTAL_BYTES
            or any(not path.startswith(f"{metadata_root}/licenses/") for path in member_paths)
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
    domain: str = FULL_C6_OUTPUT_LICENSE_MAPPING_DOMAIN

    def __post_init__(self) -> None:
        if (
            self.domain != FULL_C6_OUTPUT_LICENSE_MAPPING_DOMAIN
            or type(self.source_subject_identity) is not str
            or re.fullmatch(
                r"urn:rextio:artifact-evidence:license-material:"
                r"(?:project|cargo|external):[0-9a-f]{64}",
                self.source_subject_identity,
            )
            is None
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
            raise ValueError("artifact build output license material mapping is invalid")

    def to_dict(self) -> dict[str, object]:
        """Return logical paths and content identities, never retained bytes."""
        payload: dict[str, object] = {
            "domain": self.domain,
            "source_subject_identity": self.source_subject_identity,
            "source_observation_sha256": self.source_observation_sha256,
            "source_logical_name": self.source_logical_name,
            "output_path": self.output_path,
            "sha256": self.sha256,
            "size": self.size,
        }
        return {**payload, "mapping_sha256": _digest(payload)}


@dataclass(frozen=True, slots=True)
class FullC6OutputLicenseObservation:
    """Safe, non-authorizing projection of a sealed license derivation."""

    license_transaction_sha256: str
    source_lock_verification_sha256: str
    external_source_distribution: str
    external_source_version: str
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
            self.source_lock_verification_sha256,
            self.output_contract_sha256,
            self.expression_sha256,
        )
        if (
            self.domain != FULL_C6_OUTPUT_LICENSE_DERIVATION_DOMAIN
            or any(type(value) is not str or _SHA256.fullmatch(value) is None for value in digests)
            or self.external_source_distribution
            != _canonical_name(self.external_source_distribution)
            or not _is_canonical_identity_segment(self.external_source_distribution)
            or not _is_canonical_identity_segment(self.external_source_version)
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
            or self.mappings != tuple(sorted(self.mappings, key=lambda item: item.output_path))
            or self.complete_coverage is not True
            or self.legal_approval_inferred is not False
            or self.authorizes_build is not False
            or self.authorizes_distribution is not False
        ):
            raise ValueError("artifact build output license observation is invalid")
        output_aliases = tuple(_alias(item.output_path) for item in self.mappings)
        source_aliases = tuple(_alias(item.source_logical_name) for item in self.mappings)
        if len(output_aliases) != len(set(output_aliases)) or len(source_aliases) != len(
            set(source_aliases)
        ):
            raise ValueError("artifact build output license observation contains aliases")

    @property
    def digest(self) -> str:
        """Return the canonical digest of this public projection."""
        return _digest(self._payload())

    def _payload(self) -> dict[str, object]:
        return {
            "domain": self.domain,
            "license_transaction_sha256": self.license_transaction_sha256,
            "source_lock_verification_sha256": self.source_lock_verification_sha256,
            "external_source_distribution": self.external_source_distribution,
            "external_source_version": self.external_source_version,
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
            external_source_distribution=value.external_source_distribution,
            external_source_version=value.external_source_version,
            source_lock_verification_sha256=value.source_lock_verification_sha256,
        )
    except (TypeError, ValueError) as error:
        raise ValueError("output wheel license contract is invalid") from error


def derive_full_c6_output_license_contract(
    transaction: FullC6LicenseMaterialsTransaction,
    *,
    source_context: SourceLockV2VerifiedContext,
) -> OutputWheelLicenseContract:
    """Derive exact PEP 639 output bytes from one valid process-sealed transaction.

    The project expression is the distribution expression.  Dependency SPDX
    declarations remain separate source observations and are deliberately not
    combined into a synthetic expression.
    """
    contract, _mappings, _source_lock_sha256 = _derive_full_c6_output_license(
        transaction,
        source_context,
    )
    return contract


def validate_full_c6_output_license_contract(
    transaction: FullC6LicenseMaterialsTransaction,
    contract: OutputWheelLicenseContract,
    verification: OutputWheelLicenseVerification | None = None,
    *,
    source_context: SourceLockV2VerifiedContext,
) -> FullC6OutputLicenseObservation:
    """Require exact sealed-input derivation and return a byte-free projection.

    ``verification`` may be supplied after the completed wheel has been
    independently inspected.  Its expression and every license member must
    exactly match the derived contract; unrelated caller-authored observation
    mappings are never accepted.
    """
    expected, mappings, source_lock_sha256 = _derive_full_c6_output_license(
        transaction,
        source_context,
    )
    try:
        actual = rebuild_output_wheel_license_contract(contract)
    except (TypeError, ValueError) as error:
        raise FullC6OutputLicenseDerivationError(
            "output wheel license contract is malformed"
        ) from error
    if (
        actual.expression != expected.expression
        or len(actual.files) != len(expected.files)
        or (
            actual.external_source_distribution,
            actual.external_source_version,
            actual.source_lock_verification_sha256,
        )
        != (
            expected.external_source_distribution,
            expected.external_source_version,
            expected.source_lock_verification_sha256,
        )
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
        source_lock_verification_sha256=source_lock_sha256,
        external_source_distribution=expected.external_source_distribution or "",
        external_source_version=expected.external_source_version or "",
        output_contract_sha256=_output_contract_digest(expected),
        expression_sha256=_expression_digest(expected.expression),
        mappings=mappings,
        output_verification_sha256=verification_sha256,
    )


def _derive_full_c6_output_license(
    transaction: FullC6LicenseMaterialsTransaction,
    source_context: SourceLockV2VerifiedContext,
) -> tuple[
    OutputWheelLicenseContract,
    tuple[FullC6OutputLicenseMaterialMapping, ...],
    str,
]:
    if (
        type(transaction) is not FullC6LicenseMaterialsTransaction
        or not validate_full_c6_license_materials_transaction(transaction)
    ):
        raise FullC6OutputLicenseDerivationError(
            "artifact build license materials transaction is invalid or stale"
        )

    source_lock_sha256 = _source_lock_verification_digest(source_context)
    external_distribution = _canonical_name(source_context.wheel.distribution)
    external_version = source_context.wheel.version
    derived: list[tuple[str, bytes, str, str, str, str, int]] = []
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
                transaction.project.subject_identity,
                transaction.project.observation_sha256,
                material.logical_name,
                material.sha256,
                material.size,
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
                    observation.subject_identity,
                    observation.observation_sha256,
                    material.logical_name,
                    material.sha256,
                    material.size,
                )
            )

    external_subject_identity = _external_source_subject_identity(
        source_context,
        source_lock_sha256=source_lock_sha256,
    )
    for source_path, relative_path, payload, sha256, size in _external_license_payloads(
        source_context
    ):
        derived.append(
            (
                PurePosixPath(
                    "external",
                    external_distribution,
                    external_version,
                    relative_path,
                ).as_posix(),
                payload,
                external_subject_identity,
                source_lock_sha256,
                PurePosixPath(
                    "external",
                    external_distribution,
                    source_path,
                ).as_posix(),
                sha256,
                size,
            )
        )

    derived.sort(key=lambda item: item[0])
    files = tuple(
        OutputWheelLicenseFile(path=output_path, data=payload)
        for output_path, payload, _subject, _observation, _logical, _sha, _size in derived
    )
    mappings = tuple(
        FullC6OutputLicenseMaterialMapping(
            source_subject_identity=subject,
            source_observation_sha256=observation_sha256,
            source_logical_name=logical_name,
            output_path=output_path,
            sha256=sha256,
            size=size,
        )
        for (
            output_path,
            _payload,
            subject,
            observation_sha256,
            logical_name,
            sha256,
            size,
        ) in derived
    )
    try:
        contract = OutputWheelLicenseContract(
            expression=transaction.project.observed_spdx,
            files=files,
            external_source_distribution=external_distribution,
            external_source_version=external_version,
            source_lock_verification_sha256=source_lock_sha256,
        )
    except ValueError as error:
        raise FullC6OutputLicenseDerivationError(
            "derived output license material is outside the bounded profile"
        ) from error
    if not validate_full_c6_license_materials_transaction(transaction):
        raise FullC6OutputLicenseDerivationError(
            "artifact build license materials transaction changed during derivation"
        )
    if not _validate_external_source_context(source_context):
        raise FullC6OutputLicenseDerivationError(
            "SourceLock v2 external license context changed during derivation"
        )
    return contract, mappings, source_lock_sha256


def _external_license_payloads(
    source_context: SourceLockV2VerifiedContext,
) -> tuple[tuple[str, str, bytes, str, int], ...]:
    """Rebuild exact external license identities from sealed SourceLock bytes."""
    if not _validate_external_source_context(source_context):
        raise FullC6OutputLicenseDerivationError(
            "SourceLock v2 external license context is invalid or stale"
        )
    wheel = source_context.wheel
    metadata_roots = tuple(
        path.removesuffix("/METADATA")
        for path in wheel.metadata_entry_paths
        if path.endswith(".dist-info/METADATA")
    )
    if len(metadata_roots) != 1:
        raise FullC6OutputLicenseDerivationError(
            "SourceLock v2 external distribution metadata coverage is invalid"
        )
    prefix = f"{metadata_roots[0]}/licenses/"
    entries = {item.path: item for item in wheel.entries}
    manifest_entries = {item.path: item for item in source_context.manifest.entries}
    result: list[tuple[str, str, bytes, str, int]] = []
    for path, payload in zip(
        wheel.license_entry_paths,
        wheel.license_payloads,
        strict=True,
    ):
        if not path.startswith(prefix):
            raise FullC6OutputLicenseDerivationError(
                "SourceLock v2 external license path is outside dist-info/licenses"
            )
        relative = path.removeprefix(prefix)
        entry = entries.get(path)
        manifest_entry = manifest_entries.get(path)
        digest = hashlib.sha256(payload).hexdigest() if type(payload) is bytes else ""
        if (
            not _is_canonical_license_path(relative)
            or type(entry) is not SourceWheelEntryIdentity
            or type(manifest_entry) is not SourceWheelEntryIdentity
            or entry != manifest_entry
            or type(payload) is not bytes
            or not payload
            or len(payload) > MAX_OUTPUT_WHEEL_LICENSE_FILE_BYTES
            or entry.size != len(payload)
            or not hmac.compare_digest(entry.sha256, digest)
        ):
            raise FullC6OutputLicenseDerivationError(
                "SourceLock v2 external license bytes are missing or stale"
            )
        result.append((path, relative, payload, digest, len(payload)))
    return tuple(result)


def _validate_external_source_context(
    source_context: SourceLockV2VerifiedContext,
) -> bool:
    try:
        if type(
            source_context
        ) is not SourceLockV2VerifiedContext or not validate_source_lock_v2_verified_context(
            source_context
        ):
            return False
        wheel = source_context.wheel
        manifest = source_context.manifest
        if (
            wheel.package != manifest.package
            or wheel.distribution != manifest.distribution
            or wheel.version != manifest.version
            or wheel.semantic_sha256 != manifest.wheel_authority_sha256
            or type(wheel.license_entry_paths) is not tuple
            or not wheel.license_entry_paths
            or type(wheel.license_payloads) is not tuple
            or len(wheel.license_entry_paths) != len(wheel.license_payloads)
            or len({_alias(item) for item in wheel.license_entry_paths})
            != len(wheel.license_entry_paths)
            or not verify_source_wheel_license_detection(
                wheel.license_detection,
                wheel.license_entry_paths,
                wheel.license_payloads,
            )
            or wheel.license_detection.status != "detected"
            or wheel.license_detection.detected_spdx != manifest.declared_license
        ):
            return False
        entries = {item.path: item for item in wheel.entries}
        manifest_entries = {item.path: item for item in manifest.entries}
        if len(entries) != len(wheel.entries) or len(manifest_entries) != len(manifest.entries):
            return False
        for path, payload in zip(
            wheel.license_entry_paths,
            wheel.license_payloads,
            strict=True,
        ):
            entry = entries.get(path)
            if (
                type(entry) is not SourceWheelEntryIdentity
                or manifest_entries.get(path) != entry
                or type(payload) is not bytes
                or not payload
                or len(payload) != entry.size
                or not hmac.compare_digest(
                    hashlib.sha256(payload).hexdigest(),
                    entry.sha256,
                )
            ):
                return False
        return True
    except Exception:
        return False


def _source_lock_verification_digest(
    source_context: SourceLockV2VerifiedContext,
) -> str:
    if not _validate_external_source_context(source_context):
        raise FullC6OutputLicenseDerivationError(
            "SourceLock v2 external license context is invalid or stale"
        )
    return _digest(
        {
            "domain": FULL_C6_OUTPUT_LICENSE_SOURCE_LOCK_DOMAIN,
            "verified_context": source_context.to_dict(),
        }
    )


def _external_source_subject_identity(
    source_context: SourceLockV2VerifiedContext,
    *,
    source_lock_sha256: str,
) -> str:
    identity_sha256 = _digest(
        {
            "domain": "rextio.artifact-output-license-external-subject.v2",
            "package": source_context.wheel.package,
            "distribution": _canonical_name(source_context.wheel.distribution),
            "version": source_context.wheel.version,
            "wheel_authority_sha256": source_context.wheel.semantic_sha256,
            "source_lock_verification_sha256": source_lock_sha256,
        }
    )
    return f"urn:rextio:artifact-evidence:license-material:external:{identity_sha256}"


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
            "external_source_distribution": contract.external_source_distribution,
            "external_source_version": contract.external_source_version,
            "source_lock_verification_sha256": (contract.source_lock_verification_sha256),
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
            "domain": "rextio.artifact-output-license-wheel-verification.v3",
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


def _is_canonical_identity_segment(value: object) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= 128
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+!-]{0,127}", value) is not None
        and value == unicodedata.normalize("NFC", value)
    )


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
    "FULL_C6_OUTPUT_LICENSE_MAPPING_DOMAIN",
    "FULL_C6_OUTPUT_LICENSE_SOURCE_LOCK_DOMAIN",
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
