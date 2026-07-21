"""Process-sealed license materials for the bounded first Full C6 profile.

This collector observes machine-readable SPDX declarations and the exact
metadata/license bytes that accompany the project and every locked Cargo
registry dependency.  It does not inspect legal meaning, infer ownership, or
authorize building or distribution.  Public projections contain only logical
identities and digests; filesystem locations and retained bytes stay inside a
process-local transaction.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import secrets
import stat
import tomllib
from typing import SupportsIndex
import unicodedata

from rextio.build.full_c6_cargo_workspace import (
    FullC6CargoDependencyWorkspaceReceipt,
    FullC6CargoWorkspaceError,
    validate_full_c6_cargo_dependency_workspace_receipt,
)
from rextio.build.full_c6_policy import (
    FullC6PolicyError,
    canonicalize_full_c6_spdx_expression,
)


FULL_C6_LICENSE_MATERIALS_DOMAIN = "rextio.full-c6-license-materials.v1"
FULL_C6_LICENSE_OBSERVATION_DOMAIN = "rextio.full-c6-license-observation.v1"
FULL_C6_LICENSE_DETECTOR_PAYLOAD_DOMAIN = (
    "rextio.full-c6-machine-readable-license-detector-payload.v1"
)
FULL_C6_LICENSE_DETECTOR_RECEIPT_DOMAIN = (
    "rextio.full-c6-machine-readable-license-detector-receipt.v1"
)
FULL_C6_LICENSE_DETECTOR_KIND = "full-c6-machine-readable-spdx-metadata-observation"
FULL_C6_LICENSE_MATERIALS_SCOPE = (
    "project-pep621-pep639-and-locked-cargo-registry-packages-v1"
)

MAX_FULL_C6_PROJECT_METADATA_BYTES = 2 * 1024 * 1024
MAX_FULL_C6_LICENSE_FILE_BYTES = 8 * 1024 * 1024
MAX_FULL_C6_LICENSE_TOTAL_BYTES = 64 * 1024 * 1024
MAX_FULL_C6_PROJECT_LICENSE_FILES = 32
MAX_FULL_C6_LICENSE_PATH_CHARS = 512

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PROJECT_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+!-]{0,127}$")
_LOGICAL_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+@=-]{0,254}$")
_SUBJECT_IDENTITY = re.compile(
    r"^urn:rextio:full-c6-license-material:(?:project|cargo):[0-9a-f]{64}$"
)
_LICENSE_BASENAMES = ("LICENSE", "LICENCE", "COPYING", "NOTICE")
_CARGO_LEGACY_MIT_APACHE_SPDX = "MIT/Apache-2.0"
_CARGO_CANONICAL_MIT_APACHE_SPDX = "MIT OR Apache-2.0"
_PROJECT_METADATA_LOGICAL_NAME = "project/pyproject.toml"
_SEAL_KEY = secrets.token_bytes(32)


class FullC6LicenseMaterialsError(RuntimeError):
    """License metadata or exact file material is incomplete or stale."""


@dataclass(frozen=True, slots=True)
class FullC6LicenseMaterialFile:
    """One path-sanitized exact metadata or license-file identity."""

    logical_name: str
    role: str
    sha256: str
    size: int

    def __post_init__(self) -> None:
        _validate_logical_name(self.logical_name)
        if self.role not in {
            "project-license-metadata",
            "project-license-file",
            "cargo-license-metadata",
            "cargo-license-file",
        }:
            raise ValueError("Full C6 license material role is invalid")
        if type(self.sha256) is not str or _SHA256.fullmatch(self.sha256) is None:
            raise ValueError("Full C6 license material SHA-256 is invalid")
        if (
            type(self.size) is not int
            or isinstance(self.size, bool)
            or not 1 <= self.size <= MAX_FULL_C6_LICENSE_FILE_BYTES
        ):
            raise ValueError("Full C6 license material size is outside the bound")

    def to_dict(self) -> dict[str, object]:
        """Return the safe exact-file identity without bytes or local paths."""
        return {
            "logical_name": self.logical_name,
            "role": self.role,
            "sha256": self.sha256,
            "size": self.size,
        }


@dataclass(frozen=True, slots=True)
class FullC6LicenseObservation:
    """One metadata-derived SPDX observation bound to exact license bytes."""

    subject_kind: str
    subject_identity: str
    name: str
    version: str | None
    registry_source: str | None
    registry_checksum: str | None
    declared_spdx: str
    observed_spdx: str
    metadata_file: FullC6LicenseMaterialFile
    license_files: tuple[FullC6LicenseMaterialFile, ...]
    detector_kind: str = FULL_C6_LICENSE_DETECTOR_KIND

    def __post_init__(self) -> None:
        if self.subject_kind not in {"project", "cargo-registry-package"}:
            raise ValueError("Full C6 license subject kind is invalid")
        if (
            type(self.subject_identity) is not str
            or _SUBJECT_IDENTITY.fullmatch(self.subject_identity) is None
        ):
            raise ValueError("Full C6 license subject identity is invalid")
        if type(self.name) is not str or _PROJECT_NAME.fullmatch(self.name) is None:
            raise ValueError("Full C6 license subject name is invalid")
        if self.version is not None and (
            type(self.version) is not str or _VERSION.fullmatch(self.version) is None
        ):
            raise ValueError("Full C6 license subject version is invalid")
        if self.detector_kind != FULL_C6_LICENSE_DETECTOR_KIND:
            raise ValueError("Full C6 license detector kind is invalid")
        try:
            declared = canonicalize_full_c6_spdx_expression(self.declared_spdx)
            observed = canonicalize_full_c6_spdx_expression(self.observed_spdx)
        except FullC6PolicyError as exc:
            raise ValueError("Full C6 license SPDX expression is invalid") from exc
        if declared != observed:
            raise ValueError("Full C6 declared and observed SPDX expressions differ")
        if type(self.metadata_file) is not FullC6LicenseMaterialFile:
            raise TypeError("Full C6 license metadata identity is invalid")
        expected_metadata_role = (
            "project-license-metadata"
            if self.subject_kind == "project"
            else "cargo-license-metadata"
        )
        expected_license_role = (
            "project-license-file"
            if self.subject_kind == "project"
            else "cargo-license-file"
        )
        if self.metadata_file.role != expected_metadata_role:
            raise ValueError("Full C6 license metadata role differs from its subject")
        if (
            type(self.license_files) is not tuple
            or not self.license_files
            or len(self.license_files) > MAX_FULL_C6_PROJECT_LICENSE_FILES
            or any(type(item) is not FullC6LicenseMaterialFile for item in self.license_files)
            or any(item.role != expected_license_role for item in self.license_files)
        ):
            raise ValueError("Full C6 license file identities are invalid")
        canonical = tuple(
            sorted(self.license_files, key=lambda item: _logical_alias(item.logical_name))
        )
        aliases = tuple(_logical_alias(item.logical_name) for item in self.license_files)
        if self.license_files != canonical or len(aliases) != len(set(aliases)):
            raise ValueError("Full C6 license file identities are noncanonical")
        if self.subject_kind == "project":
            if (
                self.registry_source is not None
                or self.registry_checksum is not None
                or self.metadata_file.logical_name != _PROJECT_METADATA_LOGICAL_NAME
            ):
                raise ValueError("Full C6 project license subject has Cargo metadata")
        elif (
            type(self.version) is not str
            or type(self.registry_source) is not str
            or not self.registry_source
            or type(self.registry_checksum) is not str
            or _SHA256.fullmatch(self.registry_checksum) is None
        ):
            raise ValueError("Full C6 Cargo license subject identity is incomplete")

    @property
    def license_file_set_sha256(self) -> str:
        """Return the canonical exact license-file identity-set digest."""
        return _digest(
            {
                "domain": "rextio.full-c6-license-material-file-set.v1",
                "files": [item.to_dict() for item in self.license_files],
            }
        )

    @property
    def observation_sha256(self) -> str:
        """Return the digest of the declaration and exact observed materials."""
        return _digest({"domain": FULL_C6_LICENSE_OBSERVATION_DOMAIN, **self._payload()})

    @property
    def detector_payload_sha256(self) -> str:
        """Bind the bounded machine-readable observation to exact file bytes."""
        return _digest(
            {
                "domain": FULL_C6_LICENSE_DETECTOR_PAYLOAD_DOMAIN,
                "detector_kind": FULL_C6_LICENSE_DETECTOR_KIND,
                "subject_identity": self.subject_identity,
                "observed_spdx": self.observed_spdx,
                "metadata_file": self.metadata_file.to_dict(),
                "license_files": [item.to_dict() for item in self.license_files],
            }
        )

    @property
    def detector_receipt_sha256(self) -> str:
        """Return the receipt digest for this exact metadata observation."""
        return _digest(
            {
                "domain": FULL_C6_LICENSE_DETECTOR_RECEIPT_DOMAIN,
                "detector_kind": FULL_C6_LICENSE_DETECTOR_KIND,
                "subject_identity": self.subject_identity,
                "observation_sha256": self.observation_sha256,
                "detector_payload_sha256": self.detector_payload_sha256,
            }
        )

    def _payload(self) -> dict[str, object]:
        return {
            "subject_kind": self.subject_kind,
            "subject_identity": self.subject_identity,
            "name": self.name,
            "version": self.version,
            "registry_source": self.registry_source,
            "registry_checksum": self.registry_checksum,
            "declared_spdx": self.declared_spdx,
            "observed_spdx": self.observed_spdx,
            "metadata_file": self.metadata_file.to_dict(),
            "license_files": [item.to_dict() for item in self.license_files],
            "license_file_set_sha256": self.license_file_set_sha256,
            "legal_approval_inferred": False,
        }

    def to_dict(self) -> dict[str, object]:
        """Return path-free identities and non-authorizing observation digests."""
        return {
            **self._payload(),
            "observation_sha256": self.observation_sha256,
            "detector_kind": FULL_C6_LICENSE_DETECTOR_KIND,
            "detector_payload_sha256": self.detector_payload_sha256,
            "detector_receipt_sha256": self.detector_receipt_sha256,
        }


class FullC6LicenseMaterialsTransaction:
    """Immutable process-local authority over exact Full C6 license materials."""

    __slots__ = (
        "project",
        "cargo_packages",
        "cargo_workspace_sha256",
        "_project_root",
        "_project_payloads",
        "_cargo_workspace",
        "_transaction_seal",
    )

    project: FullC6LicenseObservation
    cargo_packages: tuple[FullC6LicenseObservation, ...]
    cargo_workspace_sha256: str
    _project_root: Path
    _project_payloads: tuple[bytes, ...]
    _cargo_workspace: FullC6CargoDependencyWorkspaceReceipt
    _transaction_seal: bytes

    def __init__(self) -> None:
        raise TypeError("Full C6 license materials transaction requires the collector")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise TypeError("Full C6 license materials transaction is immutable")

    def __delattr__(self, _name: str) -> None:
        raise TypeError("Full C6 license materials transaction is immutable")

    def __copy__(self) -> object:
        raise TypeError("Full C6 license materials transaction cannot be copied")

    def __deepcopy__(self, _memo: object) -> object:
        raise TypeError("Full C6 license materials transaction cannot be copied")

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("Full C6 license materials transaction cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        raise TypeError("Full C6 license materials transaction cannot be serialized")

    def __getstate__(self) -> object:
        raise TypeError("Full C6 license materials transaction cannot be serialized")

    def __repr__(self) -> str:
        return (
            "FullC6LicenseMaterialsTransaction("
            f"digest={self.digest!r}, retained_materials=<sealed>)"
        )

    @property
    def digest(self) -> str:
        """Return the public semantic transaction digest."""
        return _digest(_semantic_payload(self))

    @property
    def observation_set_sha256(self) -> str:
        """Return the ordered project-plus-Cargo observation-set digest."""
        return _digest(
            {
                "domain": "rextio.full-c6-license-observation-set.v1",
                "observations": [
                    self.project.observation_sha256,
                    *(item.observation_sha256 for item in self.cargo_packages),
                ],
            }
        )

    def to_dict(self) -> dict[str, object]:
        """Return safe identities only; local paths and retained bytes stay private."""
        return {**_semantic_payload(self), "digest": self.digest}


@dataclass(frozen=True, slots=True)
class _ProjectSnapshot:
    observation: FullC6LicenseObservation
    payloads: tuple[bytes, ...]


@dataclass(frozen=True, slots=True)
class _FilesystemStamp:
    device: int
    inode: int
    size: int
    ctime_ns: int
    mtime_ns: int
    mode: int
    links: int


def collect_full_c6_license_materials(
    *,
    project_root: Path | str,
    cargo_workspace: FullC6CargoDependencyWorkspaceReceipt,
) -> FullC6LicenseMaterialsTransaction:
    """Collect project and all locked Cargo license materials into one seal."""
    if not validate_full_c6_cargo_dependency_workspace_receipt(cargo_workspace):
        raise FullC6LicenseMaterialsError("Full C6 Cargo workspace receipt is stale")
    root = Path(os.path.abspath(project_root))
    first = _capture_project_snapshot(root)
    second = _capture_project_snapshot(root)
    if first != second:
        raise FullC6LicenseMaterialsError("project license materials changed during capture")
    cargo = _capture_cargo_observations(cargo_workspace)
    transaction = object.__new__(FullC6LicenseMaterialsTransaction)
    object.__setattr__(transaction, "project", first.observation)
    object.__setattr__(transaction, "cargo_packages", cargo)
    object.__setattr__(transaction, "cargo_workspace_sha256", cargo_workspace.digest)
    object.__setattr__(transaction, "_project_root", root)
    object.__setattr__(transaction, "_project_payloads", first.payloads)
    object.__setattr__(transaction, "_cargo_workspace", cargo_workspace)
    object.__setattr__(transaction, "_transaction_seal", b"")
    object.__setattr__(transaction, "_transaction_seal", _seal(transaction))
    if not validate_full_c6_license_materials_transaction(transaction):
        raise FullC6LicenseMaterialsError("license materials changed before capture completed")
    return transaction


def validate_full_c6_license_materials_transaction(
    transaction: FullC6LicenseMaterialsTransaction,
) -> bool:
    """Reobserve all exact materials and validate the process-local seal."""
    if type(transaction) is not FullC6LicenseMaterialsTransaction:
        return False
    try:
        _validate_transaction_shape(transaction)
        if not hmac.compare_digest(transaction._transaction_seal, _seal(transaction)):
            return False
        if not validate_full_c6_cargo_dependency_workspace_receipt(
            transaction._cargo_workspace
        ):
            return False
        project = _capture_project_snapshot(transaction._project_root)
        cargo = _capture_cargo_observations(transaction._cargo_workspace)
    except (
        FullC6LicenseMaterialsError,
        FullC6CargoWorkspaceError,
        FullC6PolicyError,
        TypeError,
        ValueError,
        AttributeError,
        OSError,
    ):
        return False
    return (
        project.observation == transaction.project
        and project.payloads == transaction._project_payloads
        and cargo == transaction.cargo_packages
        and transaction._cargo_workspace.digest == transaction.cargo_workspace_sha256
        and hmac.compare_digest(transaction._transaction_seal, _seal(transaction))
    )


def _capture_project_snapshot(root: Path) -> _ProjectSnapshot:
    handles = _open_absolute_directory_chain(root)
    try:
        root_fd = handles[-1][0]
        pyproject_bytes = _read_relative_file(
            root_fd,
            PurePosixPath("pyproject.toml"),
            max_bytes=MAX_FULL_C6_PROJECT_METADATA_BYTES,
        )
        metadata = _material_file(
            _PROJECT_METADATA_LOGICAL_NAME,
            "project-license-metadata",
            pyproject_bytes,
        )
        project, declared_paths = _parse_project_metadata(pyproject_bytes)
        license_pairs = tuple(
            (
                path,
                _read_relative_file(
                    root_fd,
                    PurePosixPath(path),
                    max_bytes=MAX_FULL_C6_LICENSE_FILE_BYTES,
                ),
            )
            for path in declared_paths
        )
        if sum(len(payload) for _path, payload in license_pairs) > MAX_FULL_C6_LICENSE_TOTAL_BYTES:
            raise FullC6LicenseMaterialsError("project license material bytes exceed the bound")
        license_files = tuple(
            _material_file(
                f"project/{path}",
                "project-license-file",
                payload,
            )
            for path, payload in license_pairs
        )
        _verify_directory_chain(handles)
    finally:
        for handle, _parent, _name, _expected in reversed(handles):
            try:
                os.close(handle)
            except OSError:
                pass
    name, version, expression = project
    subject_identity = (
        "urn:rextio:full-c6-license-material:project:"
        + _digest(
            {
                "name": _normalized_project_name(name),
                "metadata_file": metadata.to_dict(),
            }
        )
    )
    observation = FullC6LicenseObservation(
        subject_kind="project",
        subject_identity=subject_identity,
        name=name,
        version=version,
        registry_source=None,
        registry_checksum=None,
        declared_spdx=expression,
        observed_spdx=expression,
        metadata_file=metadata,
        license_files=license_files,
    )
    return _ProjectSnapshot(
        observation=observation,
        payloads=(pyproject_bytes, *(payload for _path, payload in license_pairs)),
    )


def _parse_project_metadata(payload: bytes) -> tuple[tuple[str, str | None, str], tuple[str, ...]]:
    try:
        document = tomllib.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise FullC6LicenseMaterialsError("project pyproject.toml is invalid") from exc
    project = document.get("project")
    if not isinstance(project, dict):
        raise FullC6LicenseMaterialsError("project pyproject.toml lacks [project]")
    name = project.get("name")
    if type(name) is not str or _PROJECT_NAME.fullmatch(name) is None:
        raise FullC6LicenseMaterialsError("project name is missing or outside scope")
    raw_version = project.get("version")
    version: str | None
    if raw_version is None:
        dynamic = project.get("dynamic")
        if (
            not isinstance(dynamic, list)
            or any(type(item) is not str for item in dynamic)
            or "version" not in dynamic
        ):
            raise FullC6LicenseMaterialsError("project version is neither static nor dynamic")
        version = None
    elif type(raw_version) is str and _VERSION.fullmatch(raw_version) is not None:
        version = raw_version
    else:
        raise FullC6LicenseMaterialsError("project version is outside the bounded profile")
    expression = _canonical_spdx(project.get("license"), subject="project")
    raw_files = project.get("license-files")
    if (
        not isinstance(raw_files, list)
        or not 1 <= len(raw_files) <= MAX_FULL_C6_PROJECT_LICENSE_FILES
        or any(type(item) is not str for item in raw_files)
    ):
        raise FullC6LicenseMaterialsError(
            "project requires bounded explicit PEP 639 license-files"
        )
    declared = tuple(str(item) for item in raw_files)
    for path in declared:
        _validate_declared_project_path(path)
    aliases = tuple(_logical_alias(path) for path in declared)
    if len(aliases) != len(set(aliases)):
        raise FullC6LicenseMaterialsError("project license-files contain an alias")
    return (name, version, expression), tuple(sorted(declared, key=_logical_alias))


def _capture_cargo_observations(
    workspace: FullC6CargoDependencyWorkspaceReceipt,
) -> tuple[FullC6LicenseObservation, ...]:
    if not validate_full_c6_cargo_dependency_workspace_receipt(workspace):
        raise FullC6LicenseMaterialsError("Full C6 Cargo workspace receipt is stale")
    try:
        payload_pairs = workspace.metadata_payloads()
    except (FullC6CargoWorkspaceError, TypeError, ValueError) as exc:
        raise FullC6LicenseMaterialsError("Cargo license metadata could not be read") from exc
    if len(payload_pairs) != len({name for name, _payload in payload_pairs}):
        raise FullC6LicenseMaterialsError("Cargo metadata payload identities are duplicated")
    payload_by_name = dict(payload_pairs)
    expected_metadata = {
        logical_name for package in workspace.packages for logical_name in package.metadata_files
    }
    if set(payload_by_name) != expected_metadata:
        raise FullC6LicenseMaterialsError("Cargo metadata payload coverage is incomplete")
    observations: list[FullC6LicenseObservation] = []
    total_license_bytes = 0
    for package in workspace.packages:
        try:
            manifest_payload = payload_by_name[package.cargo_toml]
        except KeyError as exc:
            raise FullC6LicenseMaterialsError("Cargo package metadata is missing") from exc
        try:
            document = tomllib.loads(manifest_payload.decode("utf-8"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            raise FullC6LicenseMaterialsError("Cargo package metadata is invalid") from exc
        package_table = document.get("package")
        if not isinstance(package_table, dict):
            raise FullC6LicenseMaterialsError("Cargo package metadata lacks [package]")
        if (
            package_table.get("name") != package.package.name
            or package_table.get("version") != package.package.version
        ):
            raise FullC6LicenseMaterialsError(
                "Cargo package name/version differs from the workspace receipt"
            )
        expression = _canonical_cargo_spdx(
            package_table.get("license"),
            subject=f"Cargo package {package.package.name}",
        )
        declared_license = package_table.get("license-file")
        if declared_license is not None and type(declared_license) is not str:
            raise FullC6LicenseMaterialsError("Cargo package license-file is invalid")
        prefix = PurePosixPath("vendor") / package.directory
        declared_logical: str | None = None
        if isinstance(declared_license, str):
            _validate_declared_project_path(declared_license)
            declared_logical = (prefix / PurePosixPath(declared_license)).as_posix()
        license_names = tuple(
            sorted(
                (
                    name
                    for name in package.metadata_files
                    if name != package.cargo_toml
                    and (
                        _is_license_basename(PurePosixPath(name).name)
                        or name == declared_logical
                    )
                ),
                key=_logical_alias,
            )
        )
        if not license_names or (
            declared_logical is not None and declared_logical not in license_names
        ):
            raise FullC6LicenseMaterialsError(
                "Cargo package requires actual declared or conventional license bytes"
            )
        aliases = tuple(_logical_alias(name) for name in license_names)
        if len(aliases) != len(set(aliases)):
            raise FullC6LicenseMaterialsError("Cargo license material paths contain an alias")
        metadata = _material_file(
            package.cargo_toml,
            "cargo-license-metadata",
            manifest_payload,
        )
        license_files: list[FullC6LicenseMaterialFile] = []
        for logical_name in license_names:
            try:
                license_payload = payload_by_name[logical_name]
            except KeyError as exc:
                raise FullC6LicenseMaterialsError("Cargo license material is missing") from exc
            total_license_bytes += len(license_payload)
            if total_license_bytes > MAX_FULL_C6_LICENSE_TOTAL_BYTES:
                raise FullC6LicenseMaterialsError("Cargo license material bytes exceed the bound")
            license_files.append(
                _material_file(logical_name, "cargo-license-file", license_payload)
            )
        package_projection = package.package.to_dict()
        subject_identity = (
            "urn:rextio:full-c6-license-material:cargo:"
            + _digest(package_projection)
        )
        observations.append(
            FullC6LicenseObservation(
                subject_kind="cargo-registry-package",
                subject_identity=subject_identity,
                name=package.package.name,
                version=package.package.version,
                registry_source=package.package.source,
                registry_checksum=package.package.checksum,
                declared_spdx=expression,
                observed_spdx=expression,
                metadata_file=metadata,
                license_files=tuple(license_files),
            )
        )
    canonical = tuple(sorted(observations, key=lambda item: item.subject_identity))
    if len(canonical) != len(workspace.packages):
        raise FullC6LicenseMaterialsError("Cargo license observation coverage is incomplete")
    return canonical


def _canonical_spdx(value: object, *, subject: str) -> str:
    if type(value) is not str:
        raise FullC6LicenseMaterialsError(
            f"{subject} requires a machine-readable SPDX license expression"
        )
    try:
        return canonicalize_full_c6_spdx_expression(value)
    except FullC6PolicyError as exc:
        raise FullC6LicenseMaterialsError(
            f"{subject} SPDX license expression is unsupported or noncanonical"
        ) from exc


def _canonical_cargo_spdx(value: object, *, subject: str) -> str:
    """Accept Cargo's one historical MIT/Apache alias at metadata ingestion."""
    if type(value) is str and value == _CARGO_LEGACY_MIT_APACHE_SPDX:
        value = _CARGO_CANONICAL_MIT_APACHE_SPDX
    return _canonical_spdx(value, subject=subject)


def _material_file(logical_name: str, role: str, payload: bytes) -> FullC6LicenseMaterialFile:
    if type(payload) is not bytes or not payload or len(payload) > MAX_FULL_C6_LICENSE_FILE_BYTES:
        raise FullC6LicenseMaterialsError("license material bytes are empty or outside the bound")
    return FullC6LicenseMaterialFile(
        logical_name=logical_name,
        role=role,
        sha256=hashlib.sha256(payload).hexdigest(),
        size=len(payload),
    )


def _validate_transaction_shape(transaction: FullC6LicenseMaterialsTransaction) -> None:
    if type(transaction.project) is not FullC6LicenseObservation:
        raise TypeError("Full C6 project license observation is invalid")
    if transaction.project.subject_kind != "project":
        raise ValueError("Full C6 project license observation has the wrong subject")
    if (
        type(transaction.cargo_packages) is not tuple
        or not transaction.cargo_packages
        or any(type(item) is not FullC6LicenseObservation for item in transaction.cargo_packages)
        or any(item.subject_kind != "cargo-registry-package" for item in transaction.cargo_packages)
        or transaction.cargo_packages
        != tuple(sorted(transaction.cargo_packages, key=lambda item: item.subject_identity))
    ):
        raise ValueError("Full C6 Cargo license observations are invalid")
    subjects = tuple(item.subject_identity for item in transaction.cargo_packages)
    if len(subjects) != len(set(subjects)):
        raise ValueError("Full C6 Cargo license observations contain a duplicate")
    if (
        type(transaction.cargo_workspace_sha256) is not str
        or _SHA256.fullmatch(transaction.cargo_workspace_sha256) is None
        or not isinstance(transaction._project_root, Path)
        or type(transaction._project_payloads) is not tuple
        or not transaction._project_payloads
        or any(type(item) is not bytes for item in transaction._project_payloads)
        or type(transaction._cargo_workspace)
        is not FullC6CargoDependencyWorkspaceReceipt
        or type(transaction._transaction_seal) is not bytes
    ):
        raise ValueError("Full C6 license transaction private material is invalid")
    expected_payload_count = 1 + len(transaction.project.license_files)
    if len(transaction._project_payloads) != expected_payload_count:
        raise ValueError("Full C6 project license retained-byte coverage is incomplete")
    project_files = (transaction.project.metadata_file, *transaction.project.license_files)
    for identity, payload in zip(project_files, transaction._project_payloads, strict=True):
        if identity.size != len(payload) or not hmac.compare_digest(
            identity.sha256,
            hashlib.sha256(payload).hexdigest(),
        ):
            raise ValueError("Full C6 project retained license bytes are stale")


def _semantic_payload(transaction: FullC6LicenseMaterialsTransaction) -> dict[str, object]:
    return {
        "domain": FULL_C6_LICENSE_MATERIALS_DOMAIN,
        "scope": FULL_C6_LICENSE_MATERIALS_SCOPE,
        "complete_for_scope": True,
        "machine_readable_spdx_required": True,
        "exact_metadata_and_license_bytes_observed": True,
        "legal_approval_inferred": False,
        "authorizes_build": False,
        "authorizes_distribution": False,
        "cargo_workspace_sha256": transaction.cargo_workspace_sha256,
        "observation_set_sha256": transaction.observation_set_sha256,
        "project": transaction.project.to_dict(),
        "cargo_packages": [item.to_dict() for item in transaction.cargo_packages],
    }


def _seal(transaction: FullC6LicenseMaterialsTransaction) -> bytes:
    payload = {
        "semantic": _semantic_payload(transaction),
        "project_root_binding_sha256": hashlib.sha256(
            os.fsencode(transaction._project_root)
        ).hexdigest(),
    }
    return hmac.new(_SEAL_KEY, _canonical_json(payload), hashlib.sha256).digest()


def _read_relative_file(root_fd: int, relative: PurePosixPath, *, max_bytes: int) -> bytes:
    _validate_declared_project_path(relative.as_posix())
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None:
        raise FullC6LicenseMaterialsError("no-follow license traversal is unavailable")
    directory_flags = os.O_RDONLY | nofollow | directory | getattr(os, "O_CLOEXEC", 0)
    file_flags = os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NONBLOCK"):
        file_flags |= os.O_NONBLOCK
    opened_directories: list[tuple[int, int, str, _FilesystemStamp]] = []
    parent_fd = root_fd
    file_fd = -1
    try:
        for segment in relative.parts[:-1]:
            child_fd = os.open(segment, directory_flags, dir_fd=parent_fd)
            expected = _stamp(os.fstat(child_fd))
            linked = _stamp(os.stat(segment, dir_fd=parent_fd, follow_symlinks=False))
            if expected != linked or not stat.S_ISDIR(expected.mode):
                raise FullC6LicenseMaterialsError("license material directory changed")
            opened_directories.append((child_fd, parent_fd, segment, expected))
            parent_fd = child_fd
        name = relative.parts[-1]
        file_fd = os.open(name, file_flags, dir_fd=parent_fd)
        expected_file = _stamp(os.fstat(file_fd))
        linked_file = _stamp(os.stat(name, dir_fd=parent_fd, follow_symlinks=False))
        if (
            expected_file != linked_file
            or not stat.S_ISREG(expected_file.mode)
            or expected_file.links != 1
            or not 1 <= expected_file.size <= max_bytes
        ):
            raise FullC6LicenseMaterialsError("license material file identity is unsafe")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(file_fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) != expected_file.size or len(payload) > max_bytes:
            raise FullC6LicenseMaterialsError("license material file size changed")
        if _stamp(os.fstat(file_fd)) != expected_file or _stamp(
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        ) != expected_file:
            raise FullC6LicenseMaterialsError("license material file changed during read")
        for handle, parent, segment, expected in reversed(opened_directories):
            if _stamp(os.fstat(handle)) != expected or _stamp(
                os.stat(segment, dir_fd=parent, follow_symlinks=False)
            ) != expected:
                raise FullC6LicenseMaterialsError("license material directory changed")
        return payload
    except OSError as exc:
        raise FullC6LicenseMaterialsError(
            "license material path is missing, linked, or unreadable"
        ) from exc
    finally:
        if file_fd >= 0:
            try:
                os.close(file_fd)
            except OSError:
                pass
        for handle, _parent, _segment, _expected in reversed(opened_directories):
            try:
                os.close(handle)
            except OSError:
                pass


def _open_absolute_directory_chain(
    root: Path,
) -> list[tuple[int, int | None, str | None, _FilesystemStamp]]:
    absolute = Path(os.path.abspath(root))
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None or not absolute.is_absolute() or not absolute.anchor:
        raise FullC6LicenseMaterialsError("secure project-root traversal is unavailable")
    flags = os.O_RDONLY | nofollow | directory | getattr(os, "O_CLOEXEC", 0)
    handles: list[tuple[int, int | None, str | None, _FilesystemStamp]] = []
    try:
        current_fd = os.open(absolute.anchor, flags)
        anchor_stamp = _stamp(os.fstat(current_fd))
        handles.append((current_fd, None, None, anchor_stamp))
        if not stat.S_ISDIR(anchor_stamp.mode):
            raise FullC6LicenseMaterialsError("project-root anchor is unsafe")
        for segment in absolute.parts[1:]:
            if (
                not segment
                or segment in {".", ".."}
                or "/" in segment
                or "\\" in segment
                or "\0" in segment
            ):
                raise FullC6LicenseMaterialsError("project-root component is unsafe")
            child_fd = os.open(segment, flags, dir_fd=current_fd)
            expected = _stamp(os.fstat(child_fd))
            linked = _stamp(os.stat(segment, dir_fd=current_fd, follow_symlinks=False))
            handles.append((child_fd, current_fd, segment, expected))
            if expected != linked or not stat.S_ISDIR(expected.mode):
                raise FullC6LicenseMaterialsError("project-root component changed")
            current_fd = child_fd
        return handles
    except OSError as exc:
        for handle, _parent, _segment, _expected in reversed(handles):
            try:
                os.close(handle)
            except OSError:
                pass
        raise FullC6LicenseMaterialsError("project root contains a linked component") from exc
    except Exception:
        for handle, _parent, _segment, _expected in reversed(handles):
            try:
                os.close(handle)
            except OSError:
                pass
        raise


def _verify_directory_chain(
    handles: list[tuple[int, int | None, str | None, _FilesystemStamp]],
) -> None:
    for handle, parent, segment, expected in handles:
        if _stamp(os.fstat(handle)) != expected:
            raise FullC6LicenseMaterialsError("project-root directory changed")
        if parent is not None and segment is not None and _stamp(
            os.stat(segment, dir_fd=parent, follow_symlinks=False)
        ) != expected:
            raise FullC6LicenseMaterialsError("project-root path changed")


def _stamp(value: os.stat_result) -> _FilesystemStamp:
    return _FilesystemStamp(
        device=value.st_dev,
        inode=value.st_ino,
        size=value.st_size,
        ctime_ns=value.st_ctime_ns,
        mtime_ns=value.st_mtime_ns,
        mode=value.st_mode,
        links=value.st_nlink,
    )


def _validate_declared_project_path(value: str) -> None:
    if (
        type(value) is not str
        or not value
        or len(value) > MAX_FULL_C6_LICENSE_PATH_CHARS
        or value != value.strip()
        or unicodedata.normalize("NFC", value) != value
        or any(character in value for character in "*?[]{}")
    ):
        raise FullC6LicenseMaterialsError("license-file path is not bounded and explicit")
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if (
        posix.is_absolute()
        or windows.is_absolute()
        or bool(windows.drive)
        or posix.as_posix() != value
        or "\\" in value
        or not posix.parts
        or any(part in {"", ".", ".."} for part in posix.parts)
    ):
        raise FullC6LicenseMaterialsError("license-file path is noncanonical")
    for segment in posix.parts:
        if _LOGICAL_SEGMENT.fullmatch(segment) is None:
            raise FullC6LicenseMaterialsError("license-file path segment is outside scope")


def _validate_logical_name(value: str) -> None:
    if type(value) is not str or not value or len(value) > MAX_FULL_C6_LICENSE_PATH_CHARS:
        raise ValueError("Full C6 license logical name is invalid")
    try:
        _validate_declared_project_path(value)
    except FullC6LicenseMaterialsError as exc:
        raise ValueError("Full C6 license logical name is noncanonical") from exc


def _is_license_basename(value: str) -> bool:
    upper = value.upper()
    return any(
        upper == prefix
        or upper.startswith(prefix + "-")
        or upper.startswith(prefix + ".")
        or upper.startswith(prefix + "_")
        for prefix in _LICENSE_BASENAMES
    )


def _normalized_project_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _logical_alias(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


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
    "FULL_C6_LICENSE_DETECTOR_KIND",
    "FULL_C6_LICENSE_MATERIALS_DOMAIN",
    "FULL_C6_LICENSE_MATERIALS_SCOPE",
    "FullC6LicenseMaterialFile",
    "FullC6LicenseMaterialsError",
    "FullC6LicenseMaterialsTransaction",
    "FullC6LicenseObservation",
    "collect_full_c6_license_materials",
    "validate_full_c6_license_materials_transaction",
]
