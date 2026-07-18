"""Train C5 external pure-Python source inventory preview.

This module is intentionally non-executing: it reads installed distribution
metadata and source bytes, but never imports the selected package.  The result
is planning evidence only.  C6.1 verifies a project SourceLock against exact
authority material; remaining C5.2 source-native linkage/codegen is unimplemented.
"""

from __future__ import annotations

import ast
import base64
import csv
import hashlib
import importlib.metadata as metadata
import io
import json
import re
import stat
from collections.abc import Callable
from dataclasses import dataclass
from email.message import Message
from email.parser import BytesParser
from email.policy import compat32
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import TYPE_CHECKING

from rextio.artifacts import ArtifactProvenance
from rextio.config.schema import ImportPackagePolicy, ImportsConfig
from rextio.source.models import SourceModule, SourceOrigin

if TYPE_CHECKING:
    from rextio.analyzer.models import ProjectAnalysis
    from rextio.source.authorization import ExternalSourceAuthorization


EXTERNAL_SOURCE_LICENSE_WARNING = (
    "External package source-native work can create redistribution and derivative-work "
    "obligations. Review the exact package license with particular care for GNU/copyleft "
    "terms before enabling any future build; Rextio's inventory is not legal advice."
)

EXTERNAL_SOURCE_C5_NOT_IMPLEMENTED_REASON = (
    "C6.1 SourceLock authorization is verified, but C5.2 source-native call-site "
    "linkage, body lowerability, Rust codegen, and packaging are not implemented"
)

# Domain-separated inventory/schema identifiers for the C5.1 plan snapshot.
INVENTORY_SCHEMA_ID = "rextio-external-source-inventory-v1"
PLAN_SNAPSHOT_DOMAIN = "rextio.external-source-plan-snapshot.v1"
LICENSE_MATERIAL_DOMAIN = "rextio.external-source-license-material.v1"

_METADATA_ROLES = frozenset({"record", "metadata", "wheel", "license-file"})

# Bounds shared with the C6.1 SourceLock verifier so every preview-ready plan
# can have an exact accepted lock under the same limits.
MAX_SOURCE_MODULES = 256
MAX_AUTHORITY_FILES = 512
MAX_FILE_BYTES = 50_000_000
MAX_SOURCE_LOCK_BYTES = 256 * 1024
# Identity / path string limits shared with SourceLock verification (exact).
MAX_PACKAGE_LEN = 128
MAX_DISTRIBUTION_LEN = 128
MAX_VERSION_LEN = 64
MAX_AUTHORITY_PATH_LEN = 512
MAX_MODULE_NAME_LEN = 256
# Depth-1 PoC RECORD inventory bound (rows, not source modules).
MAX_RECORD_ENTRIES = 4096
# Fixed SourceLock acknowledgement; must match authorization.LICENSE_ACKNOWLEDGEMENT_V1.
_SOURCE_LOCK_ACKNOWLEDGEMENT = "REXTIO_EXTERNAL_SOURCE_LICENSE_ACK_V1"
_SOURCE_LOCK_ACTION_SCOPES = (
    "analysis",
    "translation",
    "local-build",
    "package",
    "redistribution",
)
_SOURCE_LOCK_EVIDENCE = (
    "installed-distribution-record",
    "project-vcs-review",
)

# Sentinel / non-authorizable license tokens (casefold). SPDX "Unlicense" is
# a real license identifier and must NOT appear here. SPDX NOASSERTION is a
# sentinel and must never become preview-ready or verify.
_UNKNOWN_LICENSE_SENTINELS = frozenset(
    {
        "unknown",
        "none",
        "n/a",
        "na",
        "null",
        "undefined",
        "unspecified",
        "tbd",
        "todo",
        "see license",
        "see license file",
        "noassertion",
    }
)


@dataclass(frozen=True)
class AuthorityFile:
    """One sanitized, verified distribution file bound into plan authority."""

    path: str
    sha256: str
    size: int
    role: str
    module_name: str | None = None

    def __post_init__(self) -> None:
        if self.size < 0:
            raise ValueError("authority file size must be non-negative")
        if self.size > MAX_FILE_BYTES:
            raise ValueError("authority file size exceeds the maximum verified file size")
        if len(self.sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.sha256
        ):
            raise ValueError("authority file SHA-256 must be 64 lowercase hex characters")
        if not self.path.startswith("distributions/"):
            raise ValueError("authority file path must be a sanitized distributions/ reference")
        if len(self.path) > MAX_AUTHORITY_PATH_LEN:
            raise ValueError("authority file path exceeds the maximum length")
        if self.module_name is not None and len(self.module_name) > MAX_MODULE_NAME_LEN:
            raise ValueError("authority module_name exceeds the maximum length")

    def to_dict(self) -> dict[str, object]:
        """Return deterministic JSON-serializable authority material."""
        data: dict[str, object] = {
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "role": self.role,
        }
        if self.module_name is not None:
            data["module_name"] = self.module_name
        return data


@dataclass(frozen=True)
class ExternalSourcePlan:
    """One exact installed-distribution source preview, never build authority."""

    package: str
    distribution: str
    requested_version: str
    installed_version: str | None
    max_depth: int
    status: str
    license: str | None = None
    modules: tuple[SourceModule, ...] = ()
    candidate_functions: tuple[str, ...] = ()
    reason: str | None = None
    # Exact verified material used for C6.1 SourceLock binding.
    source_files: tuple[AuthorityFile, ...] = ()
    metadata_files: tuple[AuthorityFile, ...] = ()
    inventory_schema: str = INVENTORY_SCHEMA_ID
    authorization: ExternalSourceAuthorization | None = None

    @property
    def build_blocked(self) -> bool:
        """C5/C6 never grants build or redistribution authority in this train."""
        return True

    @property
    def authorization_verified(self) -> bool:
        """Return whether C6.1 verified a lock against an available plan."""
        return (
            self.status == "preview-ready"
            and self.authorization is not None
            and self.authorization.verified
        )

    @property
    def license_warning(self) -> str:
        """Return the mandatory non-legal-advice warning for this preview."""
        return EXTERNAL_SOURCE_LICENSE_WARNING

    def plan_snapshot_document(self) -> dict[str, object]:
        """Return the exact domain-separated document hashed into plan_snapshot_sha256.

        Free-text fields (reason, license_warning) and authorization status are
        intentionally excluded so projects can author locks from check JSON.
        """
        source_files = [
            {
                "module_name": item.module_name,
                "path": item.path,
                "role": item.role,
                "sha256": item.sha256,
                "size": item.size,
            }
            for item in sorted(self.source_files, key=lambda entry: entry.path)
        ]
        metadata_files = [
            {
                "path": item.path,
                "role": item.role,
                "sha256": item.sha256,
                "size": item.size,
            }
            for item in sorted(self.metadata_files, key=lambda entry: entry.path)
        ]
        return {
            "candidate_functions": sorted(self.candidate_functions),
            "distribution": self.distribution,
            "domain": PLAN_SNAPSHOT_DOMAIN,
            "installed_version": self.installed_version,
            "inventory_schema": self.inventory_schema,
            "license_material_sha256": self.license_material_sha256(),
            "license_observed": self.license,
            "max_depth": self.max_depth,
            "metadata_files": metadata_files,
            "package": self.package,
            "requested_version": self.requested_version,
            "source_files": source_files,
        }

    def license_material_document(self) -> dict[str, object]:
        """Return the canonical license-material document for digest binding."""
        files = [
            {
                "path": item.path,
                "role": item.role,
                "sha256": item.sha256,
                "size": item.size,
            }
            for item in sorted(self.metadata_files, key=lambda entry: entry.path)
            if item.role in {"metadata", "license-file"}
        ]
        return {
            "domain": LICENSE_MATERIAL_DOMAIN,
            "files": files,
            "license_observed": self.license,
        }

    def license_material_sha256(self) -> str | None:
        """Return the shared license-material digest, or None when incomplete."""
        if self.status != "preview-ready" or self.license is None:
            return None
        if not any(item.role == "metadata" for item in self.metadata_files):
            return None
        payload = json.dumps(
            self.license_material_document(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def plan_snapshot_sha256(self) -> str | None:
        """Return the canonical snapshot digest, or None when material is incomplete."""
        if self.status != "preview-ready" or not self.source_files:
            return None
        if self.license_material_sha256() is None:
            return None
        payload = json.dumps(
            self.plan_snapshot_document(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, object]:
        """Return deterministic tooling-contract external-source evidence."""
        c6_gate = (
            "authorization-verified"
            if self.authorization_verified
            else "required"
        )
        ready = self.status == "preview-ready" and bool(self.source_files)
        data: dict[str, object] = {
            "status": self.status,
            "execution_authority": "preview-only",
            "distributable": False,
            "c6_gate": c6_gate,
            "package": self.package,
            "distribution": self.distribution,
            "requested_version": self.requested_version,
            "installed_version": self.installed_version,
            "max_depth": self.max_depth,
            "license_observed": self.license,
            "license_material_sha256": self.license_material_sha256() if ready else None,
            "inventory_schema": self.inventory_schema,
            "modules": [module.to_dict() for module in self.modules],
            "source_files": [item.to_dict() for item in self.source_files],
            "metadata_files": [item.to_dict() for item in self.metadata_files],
            "candidate_functions": list(self.candidate_functions),
            "plan_snapshot": self.plan_snapshot_document() if ready else None,
            "plan_snapshot_sha256": self.plan_snapshot_sha256() if ready else None,
            "reason": self.reason,
            "license_warning": self.license_warning,
        }
        if self.authorization is not None:
            data["authorization"] = self.authorization.to_dict()
        return data


@dataclass(frozen=True)
class _RecordEntry:
    relative: PurePosixPath
    sha256: str | None
    size: int | None


@dataclass(frozen=True)
class _VerifiedDistributionMetadata:
    name: str
    version: str
    license: str | None
    license_files: tuple[str, ...] = ()


class ExternalSourceBuildBlockedError(RuntimeError):
    """A C5 preview failed the C6.1 SourceLock authorization gate."""

    def __init__(self, plan: ExternalSourcePlan) -> None:
        self.plan = plan
        auth = plan.authorization
        if plan.status != "preview-ready":
            detail = (
                plan.reason
                or "the external source plan is unavailable"
            )
            message = (
                "RXT060 External source build blocked: external source plan is "
                f"unavailable for {plan.distribution}=={plan.requested_version} "
                f"({detail}). A verified C6.1 SourceLock cannot authorize an "
                "unavailable plan."
            )
        elif auth is None or auth.status == "missing":
            message = (
                "RXT060 External source build blocked: missing verified C6.1 "
                f"SourceLock for {plan.distribution}=={plan.requested_version}. "
                "A project-owned rextio.external-source.lock.json with exact "
                "content hashes, source inventory, provenance, and closed license "
                "attestation is required before any source-native build path."
            )
        else:
            reason = auth.reason or auth.status
            message = (
                "RXT060 External source build blocked: C6.1 SourceLock verification "
                f"failed for {plan.distribution}=={plan.requested_version} "
                f"({reason})."
            )
        super().__init__(message)


class ExternalSourceC5NotImplementedError(RuntimeError):
    """C6.1 SourceLock verified, but remaining C5.2 source-native work is absent."""

    def __init__(self, plan: ExternalSourcePlan) -> None:
        self.plan = plan
        super().__init__(
            "RXT060 External source build blocked: "
            f"{EXTERNAL_SOURCE_C5_NOT_IMPLEMENTED_REASON} "
            f"({plan.distribution}=={plan.requested_version})."
        )


def resolve_external_source_plan(
    config: ImportsConfig,
    analysis: ProjectAnalysis,
    *,
    distribution_getter: Callable[[str], metadata.Distribution] | None = None,
) -> ExternalSourcePlan | None:
    """Resolve the one used, fully pinned C5 declaration without importing it."""
    declarations = [
        (package, policy)
        for package, policy in sorted(config.packages.items())
        if _is_source_preview_declaration(policy) and _package_is_used(package, analysis)
    ]
    if not declarations:
        return None
    if len(declarations) != 1:
        # The config loader prevents this; retain a defensive programmatic gate.
        package, policy = declarations[0]
        return _unavailable(package, policy, "multiple source-native declarations are active")

    package, policy = declarations[0]
    assert policy.distribution is not None and policy.version is not None
    if not _valid_preview_identity(package, policy.distribution, policy.version):
        return _unavailable(
            package,
            policy,
            "source-native preview identity fields are not safe exact names",
        )
    if _package_uses_plugin(package, analysis):
        return _unavailable(
            package,
            policy,
            "source-native preview conflicts with an active plugin route",
        )
    getter = distribution_getter or metadata.distribution
    try:
        distribution = getter(policy.distribution)
    except metadata.PackageNotFoundError:
        return _unavailable(package, policy, "the exact distribution is not installed")
    except Exception:  # metadata providers are third-party inputs; never leak paths
        return _unavailable(package, policy, "distribution metadata could not be read")

    try:
        (
            base_raw,
            base,
            inventory,
            wheel_text,
            verified_metadata,
            record_bytes,
            metadata_bytes,
            wheel_bytes,
        ) = _verified_distribution_inventory(
            distribution,
            expected_name=policy.distribution,
            expected_version=policy.version,
        )
    except ValueError as exc:
        return _unavailable(
            package,
            policy,
            str(exc),
        )
    except Exception:
        return _unavailable(
            package,
            policy,
            "distribution inventory could not be verified",
        )
    installed_version = verified_metadata.version
    if _canonical_name(verified_metadata.name) != _canonical_name(
        policy.distribution
    ):
        return _unavailable(
            package,
            policy,
            "installed distribution name does not match the exact configured distribution",
            installed_version=installed_version,
        )
    if installed_version != policy.version:
        return _unavailable(
            package,
            policy,
            "installed distribution version does not match the exact configured version",
            installed_version=installed_version,
        )
    if not _is_pure_universal_wheel(wheel_text):
        return _unavailable(
            package,
            policy,
            "distribution is not recorded as a py3-none-any pure-Python wheel",
            installed_version=installed_version,
        )
    license_text = verified_metadata.license
    if license_text is None or is_unknown_license(license_text):
        return _unavailable(
            package,
            policy,
            "distribution license is missing or unknown",
            installed_version=installed_version,
            license_text=license_text,
        )
    try:
        modules, functions, source_files, metadata_files = _read_authority_material(
            distribution,
            package,
            policy,
            base_raw=base_raw,
            base=base,
            inventory=inventory,
            license_text=license_text,
            license_file_names=verified_metadata.license_files,
            dist_info_root=_dist_info_root(
                verified_metadata.name,
                verified_metadata.version,
            ),
            record_bytes=record_bytes,
            metadata_bytes=metadata_bytes,
            wheel_bytes=wheel_bytes,
        )
    except ValueError as exc:
        return _unavailable(
            package,
            policy,
            str(exc),
            installed_version=installed_version,
            license_text=license_text,
        )
    except Exception:
        return _unavailable(
            package,
            policy,
            "distribution source inventory could not be read",
            installed_version=installed_version,
            license_text=license_text,
        )
    if not modules:
        return _unavailable(
            package,
            policy,
            "no contained depth-1 Python source modules were found",
            installed_version=installed_version,
            license_text=license_text,
        )
    if not functions:
        return _unavailable(
            package,
            policy,
            "no top-level fully annotated scalar function candidates were found",
            installed_version=installed_version,
            license_text=license_text,
        )
    try:
        _enforce_authority_bounds(
            package=package,
            distribution=policy.distribution,
            version=policy.version,
            license_observed=license_text,
            source_files=source_files,
            metadata_files=metadata_files,
        )
    except ValueError as exc:
        return _unavailable(
            package,
            policy,
            str(exc),
            installed_version=installed_version,
            license_text=license_text,
        )
    return ExternalSourcePlan(
        package=package,
        distribution=policy.distribution,
        requested_version=policy.version,
        installed_version=installed_version,
        max_depth=policy.max_depth,
        status="preview-ready",
        license=license_text,
        modules=modules,
        candidate_functions=functions,
        source_files=source_files,
        metadata_files=metadata_files,
    )


def _is_source_preview_declaration(policy: ImportPackagePolicy) -> bool:
    return (
        policy.policy == "try-native"
        and policy.max_depth == 1
        and policy.distribution is not None
        and policy.version is not None
    )


def _valid_preview_identity(package: str, distribution: str, version: str) -> bool:
    """Reject identity that the SourceLock verifier cannot accept (shape + length)."""
    if len(package) > MAX_PACKAGE_LEN:
        return False
    if len(distribution) > MAX_DISTRIBUTION_LEN:
        return False
    if len(version) > MAX_VERSION_LEN:
        return False
    return bool(
        re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*",
            package,
        )
        and re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?",
            distribution,
        )
        and re.fullmatch(r"[A-Za-z0-9]+(?:[._+-][A-Za-z0-9]+)*", version)
    )


def _package_is_used(package: str, analysis: ProjectAnalysis) -> bool:
    return any(
        decision.origin in {"external", "external-plugin"}
        and (decision.package == package or decision.target == package)
        for module in analysis.modules
        for decision in module.import_policies
    )


def _package_uses_plugin(package: str, analysis: ProjectAnalysis) -> bool:
    return any(
        decision.origin == "external-plugin"
        and (decision.package == package or decision.target == package)
        for module in analysis.modules
        for decision in module.import_policies
    )


def _is_pure_universal_wheel(wheel: str) -> bool:
    try:
        message = BytesParser(policy=compat32).parsebytes(wheel.encode("utf-8"))
    except Exception:
        return False
    if message.defects or message.is_multipart():
        return False
    payload = message.get_payload()
    if not isinstance(payload, str) or payload.strip():
        return False
    wheel_versions = _header_values(message, "Wheel-Version")
    roots = tuple(value.lower() for value in _header_values(message, "Root-Is-Purelib"))
    tags = tuple(value.lower() for value in _header_values(message, "Tag"))
    return wheel_versions == ("1.0",) and roots == ("true",) and tags == ("py3-none-any",)


def _record_path(raw: str) -> PurePosixPath:
    raw = raw.replace("\\", "/")
    posix = PurePosixPath(raw)
    windows = PureWindowsPath(raw)
    if (
        not raw
        or posix.is_absolute()
        or windows.is_absolute()
        or bool(windows.drive)
        or not posix.parts
        or ".." in posix.parts
        or ".." in windows.parts
    ):
        raise ValueError("distribution RECORD contains an unsafe path")
    return posix


def _one_metadata_entry(
    inventory: tuple[_RecordEntry, ...],
    dist_info_root: PurePosixPath,
    name: str,
) -> _RecordEntry:
    matches = tuple(
        entry
        for entry in inventory
        if entry.relative == dist_info_root / name
    )
    if len(matches) != 1:
        raise ValueError(f"distribution RECORD must contain exactly one {name} entry")
    return matches[0]


def _inspect_contained_path(
    base_raw: Path,
    base: Path,
    relative: PurePosixPath,
    *,
    label: str,
) -> Path:
    """Return the raw path after symlink/containment checks (no content read)."""
    raw_path = base_raw.joinpath(*relative.parts)
    try:
        if not raw_path.exists():
            raise ValueError(f"distribution {label} is missing")
    except OSError as exc:
        raise ValueError(f"distribution {label} path could not be inspected") from exc
    try:
        resolved = raw_path.resolve()
    except Exception as exc:
        raise ValueError(f"distribution {label} path could not be resolved") from exc
    try:
        resolved.relative_to(base)
    except ValueError as exc:
        raise ValueError(f"distribution {label} escapes its installed root") from exc
    current = base_raw
    try:
        for part in relative.parts:
            current /= part
            if current.is_symlink():
                raise ValueError(f"distribution {label} is a symlink or non-regular file")
    except OSError as exc:
        raise ValueError(f"distribution {label} path could not be inspected") from exc
    if raw_path.is_symlink() or not resolved.is_file():
        raise ValueError(f"distribution {label} is a symlink or non-regular file")
    return raw_path


def _read_bounded_file(path: Path, *, label: str) -> bytes:
    """Read at most MAX_FILE_BYTES from a regular non-symlink file."""
    try:
        link_stat = path.lstat()
    except OSError as exc:
        raise ValueError(f"distribution {label} path could not be inspected") from exc
    if stat.S_ISLNK(link_stat.st_mode) or not stat.S_ISREG(link_stat.st_mode):
        raise ValueError(f"distribution {label} is a symlink or non-regular file")
    if link_stat.st_size > MAX_FILE_BYTES:
        raise ValueError(f"distribution {label} exceeds the maximum verified file size")
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise ValueError(f"distribution {label} could not be read") from exc
    if len(data) > MAX_FILE_BYTES:
        raise ValueError(f"distribution {label} exceeds the maximum verified file size")
    return data


def _recorded_bytes(
    distribution: metadata.Distribution,
    base_raw: Path,
    base: Path,
    entry: _RecordEntry,
    *,
    label: str,
    verify_hash: bool = True,
) -> bytes:
    """Read a RECORD path with pre-read size/symlink checks and a byte cap."""
    # Reject oversized RECORD size claims before any content read.
    if entry.size is not None and entry.size > MAX_FILE_BYTES:
        raise ValueError(f"distribution {label} exceeds the maximum verified file size")
    try:
        located_path = Path(str(distribution.locate_file(entry.relative.as_posix())))
    except Exception as exc:
        raise ValueError(f"distribution {label} path could not be located") from exc
    raw_path = _inspect_contained_path(
        base_raw, base, entry.relative, label=label
    )
    if located_path.absolute() != raw_path.absolute():
        raise ValueError(f"distribution {label} path does not match its RECORD entry")
    data = _read_bounded_file(raw_path, label=label)
    if not verify_hash:
        return data

    if entry.sha256 is None:
        raise ValueError(f"distribution RECORD has no SHA-256 for {label}")
    actual_hash = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode("ascii")
    if actual_hash.rstrip("=") != entry.sha256.rstrip("="):
        raise ValueError(f"distribution RECORD SHA-256 drift detected for {label}")
    if entry.size is None or entry.size != len(data):
        raise ValueError(f"distribution RECORD size drift detected for {label}")
    return data


def _verified_distribution_inventory(
    distribution: metadata.Distribution,
    *,
    expected_name: str,
    expected_version: str,
) -> tuple[
    Path,
    Path,
    tuple[_RecordEntry, ...],
    str,
    _VerifiedDistributionMetadata,
    bytes,
    bytes,
    bytes,
]:
    """Validate contained RECORD metadata without importing distribution code.

    Reads expected dist-info files directly under the installed root with
    bounded I/O. Does not call Distribution.read_text (unbounded).
    """
    try:
        base_raw = Path(str(distribution.locate_file(""))).absolute()
        base = base_raw.resolve()
    except Exception as exc:
        raise ValueError("distribution installed root could not be resolved") from exc
    if not base.is_dir():
        raise ValueError("distribution installed root is not a directory")

    # Configured exact identity selects the dist-info directory before any
    # content is parsed.
    dist_info_root = _dist_info_root(expected_name, expected_version)
    dist_info_dir = base_raw.joinpath(*dist_info_root.parts)
    try:
        if not dist_info_dir.is_dir() or dist_info_dir.is_symlink():
            raise ValueError(
                "the exact configured distribution version is not installed"
            )
    except OSError as exc:
        raise ValueError("distribution dist-info directory could not be inspected") from exc
    metadata_rel = dist_info_root / "METADATA"
    wheel_rel = dist_info_root / "WHEEL"
    record_rel = dist_info_root / "RECORD"

    metadata_path = _inspect_contained_path(
        base_raw, base, metadata_rel, label="METADATA"
    )
    metadata_bytes = _read_bounded_file(metadata_path, label="METADATA")
    # Strict UTF-8 for the complete bounded payload (headers and body). BytesParser
    # alone can accept a valid header block followed by non-UTF-8 body bytes.
    try:
        metadata_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("distribution METADATA is not valid UTF-8") from exc
    try:
        preliminary_metadata = _parse_distribution_metadata(metadata_bytes)
    except ValueError:
        raise
    if _canonical_name(preliminary_metadata.name) != _canonical_name(expected_name):
        raise ValueError(
            "installed distribution name does not match the exact configured distribution"
        )
    if preliminary_metadata.version != expected_version:
        raise ValueError(
            "installed distribution version does not match the exact configured version"
        )
    # METADATA Name may normalize differently; recompute dist-info from verified
    # metadata and require it match the configured path we already read.
    verified_root = _dist_info_root(
        preliminary_metadata.name, preliminary_metadata.version
    )
    if verified_root != dist_info_root:
        raise ValueError(
            "installed distribution dist-info root does not match configured identity"
        )

    wheel_path = _inspect_contained_path(base_raw, base, wheel_rel, label="WHEEL")
    wheel_bytes = _read_bounded_file(wheel_path, label="WHEEL")
    record_path = _inspect_contained_path(base_raw, base, record_rel, label="RECORD")
    record_bytes = _read_bounded_file(record_path, label="RECORD")
    try:
        record_text = record_bytes.decode("utf-8")
        wheel_text = wheel_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("distribution dist-info metadata is not UTF-8") from exc

    inventory: list[_RecordEntry] = []
    seen: set[PurePosixPath] = set()
    try:
        rows = csv.reader(io.StringIO(record_text))
        for row_index, row in enumerate(rows, start=1):
            if row_index > MAX_RECORD_ENTRIES:
                raise ValueError("distribution RECORD exceeds the maximum entry count")
            if len(row) != 3:
                raise ValueError("distribution RECORD contains a malformed row")
            relative = _record_path(row[0])
            if relative in seen:
                raise ValueError("distribution RECORD contains a duplicate path")
            seen.add(relative)
            hash_field = row[1]
            if hash_field:
                algorithm, separator, digest = hash_field.partition("=")
                if separator != "=" or algorithm.lower() != "sha256" or not digest:
                    raise ValueError("distribution RECORD contains a non-SHA-256 hash")
                sha256 = digest
            else:
                sha256 = None
            if row[2]:
                if not row[2].isdigit():
                    raise ValueError("distribution RECORD contains an invalid size")
                size = int(row[2])
                if size > MAX_FILE_BYTES:
                    raise ValueError(
                        "distribution RECORD claims a file over the maximum size"
                    )
            else:
                size = None
            inventory.append(_RecordEntry(relative=relative, sha256=sha256, size=size))
    except csv.Error as exc:
        raise ValueError("distribution RECORD could not be parsed") from exc
    if not inventory:
        raise ValueError("distribution RECORD source inventory is empty")
    inventory_tuple = tuple(inventory)
    for entry in inventory_tuple:
        dist_info_parts = tuple(
            (index, part)
            for index, part in enumerate(entry.relative.parts)
            if part.endswith(".dist-info")
        )
        if dist_info_parts and dist_info_parts != ((0, dist_info_root.name),):
            raise ValueError("distribution RECORD contains a foreign dist-info root")
    record_entry = _one_metadata_entry(inventory_tuple, dist_info_root, "RECORD")
    metadata_entry = _one_metadata_entry(inventory_tuple, dist_info_root, "METADATA")
    wheel_entry = _one_metadata_entry(inventory_tuple, dist_info_root, "WHEEL")

    # Re-read METADATA/WHEEL through RECORD path identity + hash verification.
    verified_metadata_bytes = _recorded_bytes(
        distribution,
        base_raw,
        base,
        metadata_entry,
        label="METADATA",
    )
    verified_wheel_bytes = _recorded_bytes(
        distribution,
        base_raw,
        base,
        wheel_entry,
        label="WHEEL",
    )
    # RECORD itself is typically unhashed in the inventory; re-read for identity.
    verified_record_bytes = _recorded_bytes(
        distribution,
        base_raw,
        base,
        record_entry,
        label="RECORD",
        verify_hash=False,
    )
    if verified_metadata_bytes != metadata_bytes:
        raise ValueError("distribution METADATA changed during inventory")
    if verified_wheel_bytes != wheel_bytes:
        raise ValueError("distribution WHEEL changed during inventory")
    if verified_record_bytes != record_bytes:
        raise ValueError("distribution RECORD changed during inventory")
    verified_metadata = _parse_distribution_metadata(verified_metadata_bytes)
    if (
        verified_metadata.name != preliminary_metadata.name
        or verified_metadata.version != preliminary_metadata.version
        or verified_metadata.license != preliminary_metadata.license
        or verified_metadata.license_files != preliminary_metadata.license_files
    ):
        raise ValueError("distribution METADATA changed during inventory")
    return (
        base_raw,
        base,
        inventory_tuple,
        wheel_text,
        verified_metadata,
        verified_record_bytes,
        verified_metadata_bytes,
        verified_wheel_bytes,
    )


def _authority_path(distribution_name: str, relative: PurePosixPath) -> str:
    return f"distributions/{_canonical_name(distribution_name)}/{relative.as_posix()}"


def _hex_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_authority_material(
    distribution: metadata.Distribution,
    package: str,
    policy: ImportPackagePolicy,
    *,
    base_raw: Path,
    base: Path,
    inventory: tuple[_RecordEntry, ...],
    license_text: str | None,
    license_file_names: tuple[str, ...],
    dist_info_root: PurePosixPath,
    record_bytes: bytes,
    metadata_bytes: bytes,
    wheel_bytes: bytes,
) -> tuple[
    tuple[SourceModule, ...],
    tuple[str, ...],
    tuple[AuthorityFile, ...],
    tuple[AuthorityFile, ...],
]:
    assert policy.distribution is not None and policy.version is not None
    package_path = PurePosixPath(*package.split("."))
    modules: list[SourceModule] = []
    functions: list[str] = []
    source_files: list[AuthorityFile] = []
    selected_sources = 0
    for entry in sorted(inventory, key=lambda item: str(item.relative)):
        relative = entry.relative
        if relative.suffix != ".py":
            continue
        try:
            under_package = relative.relative_to(package_path)
        except ValueError:
            continue
        # depth 1: package __init__.py and direct package modules only.
        if len(under_package.parts) != 1:
            continue
        # Reject before reading/AST-processing the 257th selected source.
        selected_sources += 1
        if selected_sources > MAX_SOURCE_MODULES:
            raise ValueError("distribution source inventory exceeds the maximum module count")
        data = _recorded_bytes(distribution, base_raw, base, entry, label="source")
        try:
            source_text = data.decode("utf-8")
            tree = ast.parse(source_text, filename=relative.as_posix())
        except (SyntaxError, UnicodeDecodeError) as exc:
            raise ValueError("distribution source is not parseable UTF-8 Python") from exc
        if any(isinstance(node, (ast.Import, ast.ImportFrom)) for node in ast.walk(tree)):
            raise ValueError("depth-1 preview source contains an unresolved import")
        module_name = (
            package
            if under_package.name == "__init__.py"
            else f"{package}.{under_package.stem}"
        )
        if len(module_name) > MAX_MODULE_NAME_LEN:
            raise ValueError("authority module_name exceeds the maximum length")
        reference = _authority_path(policy.distribution, relative)
        if len(reference) > MAX_AUTHORITY_PATH_LEN:
            raise ValueError("authority file path exceeds the maximum length")
        digest = _hex_sha256(data)
        size = len(data)
        modules.append(
            SourceModule(
                module_name=module_name,
                path=reference,
                is_package_init=under_package.name == "__init__.py",
                source_origin=SourceOrigin.DISTRIBUTION,
                sha256=digest,
                dependency_depth=1,
                distribution=policy.distribution,
                version=policy.version,
                license=license_text,
                provenance=ArtifactProvenance(source_references=(reference,)),
            )
        )
        source_files.append(
            AuthorityFile(
                path=reference,
                sha256=digest,
                size=size,
                role="source-module",
                module_name=module_name,
            )
        )
        functions.extend(f"{module_name}.{name}" for name in _typed_scalar_functions(tree))

    for label, payload in (
        ("RECORD", record_bytes),
        ("METADATA", metadata_bytes),
        ("WHEEL", wheel_bytes),
    ):
        if len(payload) > MAX_FILE_BYTES:
            raise ValueError(
                f"distribution {label} exceeds the maximum verified file size"
            )

    metadata_files: list[AuthorityFile] = [
        AuthorityFile(
            path=_authority_path(policy.distribution, dist_info_root / "RECORD"),
            sha256=_hex_sha256(record_bytes),
            size=len(record_bytes),
            role="record",
        ),
        AuthorityFile(
            path=_authority_path(policy.distribution, dist_info_root / "METADATA"),
            sha256=_hex_sha256(metadata_bytes),
            size=len(metadata_bytes),
            role="metadata",
        ),
        AuthorityFile(
            path=_authority_path(policy.distribution, dist_info_root / "WHEEL"),
            sha256=_hex_sha256(wheel_bytes),
            size=len(wheel_bytes),
            role="wheel",
        ),
    ]
    # Base metadata roles are RECORD/METADATA/WHEEL (3). Bound license-file
    # count before reading any license content.
    if 3 + len(source_files) + len(license_file_names) > MAX_AUTHORITY_FILES:
        raise ValueError("distribution authority inventory exceeds the maximum file count")
    seen_license_paths: set[PurePosixPath] = set()
    for raw_name in license_file_names:
        # PEP 639: License-File values use '/' separators only; backslashes reject.
        if "\\" in raw_name:
            raise ValueError("distribution METADATA License-File must not contain backslashes")
        relative_value = _record_path(raw_name)
        # Installed wheel location is always under <dist-info>/licenses/<value>.
        relative = dist_info_root / "licenses" / relative_value
        if relative in seen_license_paths:
            raise ValueError("distribution METADATA references a duplicate License-File")
        seen_license_paths.add(relative)
        matches = tuple(entry for entry in inventory if entry.relative == relative)
        if len(matches) != 1:
            raise ValueError("distribution License-File is missing from RECORD")
        entry = matches[0]
        if entry.sha256 is None or entry.size is None:
            raise ValueError("distribution License-File has no RECORD hash or size")
        if entry.size > MAX_FILE_BYTES:
            raise ValueError("distribution license-file exceeds the maximum verified file size")
        data = _recorded_bytes(
            distribution,
            base_raw,
            base,
            entry,
            label="license-file",
        )
        try:
            data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("distribution License-File is not valid UTF-8") from exc
        authority_path = _authority_path(policy.distribution, relative)
        if len(authority_path) > MAX_AUTHORITY_PATH_LEN:
            raise ValueError("authority file path exceeds the maximum length")
        metadata_files.append(
            AuthorityFile(
                path=authority_path,
                sha256=_hex_sha256(data),
                size=len(data),
                role="license-file",
            )
        )
    return (
        tuple(sorted(modules, key=lambda item: item.module_name)),
        tuple(sorted(functions)),
        tuple(sorted(source_files, key=lambda item: item.path)),
        tuple(sorted(metadata_files, key=lambda item: item.path)),
    )


def _source_entry_dict(item: AuthorityFile) -> dict[str, object]:
    return {
        "module_name": item.module_name,
        "path": item.path,
        "role": item.role,
        "sha256": item.sha256,
        "size": item.size,
    }


def _metadata_entry_dict(item: AuthorityFile) -> dict[str, object]:
    return {
        "path": item.path,
        "role": item.role,
        "sha256": item.sha256,
        "size": item.size,
    }


def _inventory_entry_dict(item: AuthorityFile) -> dict[str, object]:
    return {
        "path": item.path,
        "role": item.role,
        "sha256": item.sha256,
        "size": item.size,
    }


def compact_valid_source_lock_document(
    *,
    package: str,
    distribution: str,
    version: str,
    license_observed: str,
    source_files: tuple[AuthorityFile, ...],
    metadata_files: tuple[AuthorityFile, ...],
) -> dict[str, object]:
    """Return one exact compact valid SourceLock skeleton for size gating.

    An accepted lock repeats authority material: each source entry appears in
    ``content_hashes.source_files`` and ``source_inventory.files`` (×2); each
    metadata entry appears in ``content_hashes.metadata_files``,
    ``source_inventory.files``, and ``provenance.installed_wheel.metadata_files``
    (×3). Fixed wrapper fields use the shortest legal attestor values so any
    plan that fits has at least one exact compact lock under the verifier limit.
    """
    ordered_sources = tuple(sorted(source_files, key=lambda entry: entry.path))
    ordered_metadata = tuple(sorted(metadata_files, key=lambda entry: entry.path))
    source_entries = [_source_entry_dict(item) for item in ordered_sources]
    metadata_entries = [_metadata_entry_dict(item) for item in ordered_metadata]
    inventory_files = [
        *[_inventory_entry_dict(item) for item in ordered_sources],
        *[_inventory_entry_dict(item) for item in ordered_metadata],
    ]
    digest = "0" * 64
    # Shortest legal producer/attestor under the verifier name alphabet.
    attestor = "a"
    return {
        "content_hashes": {
            "metadata_files": metadata_entries,
            "snapshot_sha256": digest,
            "source_files": source_entries,
        },
        "distribution": distribution,
        "kind": "rextio.external-source-authorization",
        "license_attestation": {
            "acknowledgement": _SOURCE_LOCK_ACKNOWLEDGEMENT,
            "action_scopes": list(_SOURCE_LOCK_ACTION_SCOPES),
            "attestor": attestor,
            "attestor_kind": "human",
            "decision": "allow",
            "reviewed_license": license_observed,
            "reviewed_license_material_sha256": digest,
        },
        "package": package,
        "provenance": {
            "attestor_relationship": "human-owner",
            "evidence": list(_SOURCE_LOCK_EVIDENCE),
            "installed_wheel": {
                "distribution": distribution,
                "metadata_files": metadata_entries,
                "version": version,
            },
            "producer": attestor,
            "subject_snapshot_sha256": digest,
        },
        "schema_version": "1",
        "source_inventory": {
            "components": [
                {
                    "files": inventory_files,
                    "license_observed": license_observed,
                    "name": distribution,
                    "type": "pypi-distribution",
                    "version": version,
                }
            ],
            "format": "rextio-source-inventory-v1",
        },
        "version": version,
    }


def compact_valid_source_lock_size(
    *,
    package: str,
    distribution: str,
    version: str,
    license_observed: str,
    source_files: tuple[AuthorityFile, ...],
    metadata_files: tuple[AuthorityFile, ...],
) -> int:
    """Return the UTF-8 byte size of the compact valid SourceLock skeleton."""
    document = compact_valid_source_lock_document(
        package=package,
        distribution=distribution,
        version=version,
        license_observed=license_observed,
        source_files=source_files,
        metadata_files=metadata_files,
    )
    return len(
        json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
            "utf-8"
        )
    )


def _enforce_authority_bounds(
    *,
    package: str,
    distribution: str,
    version: str,
    license_observed: str,
    source_files: tuple[AuthorityFile, ...],
    metadata_files: tuple[AuthorityFile, ...],
) -> None:
    """Reject authority that cannot fit any exact compact valid SourceLock."""
    if len(source_files) > MAX_SOURCE_MODULES:
        raise ValueError("distribution source inventory exceeds the maximum module count")
    total_files = len(source_files) + len(metadata_files)
    if total_files > MAX_AUTHORITY_FILES:
        raise ValueError("distribution authority inventory exceeds the maximum file count")
    for item in (*source_files, *metadata_files):
        if item.size > MAX_FILE_BYTES:
            raise ValueError("distribution authority file exceeds the maximum verified file size")
    # Exact size of one minimal accepted lock (sources ×2, metadata ×3), not a
    # single-list estimate. Plans that fail this check must not be preview-ready.
    lock_bytes = compact_valid_source_lock_size(
        package=package,
        distribution=distribution,
        version=version,
        license_observed=license_observed,
        source_files=source_files,
        metadata_files=metadata_files,
    )
    if lock_bytes > MAX_SOURCE_LOCK_BYTES:
        raise ValueError(
            "distribution authority material exceeds the SourceLock size limit"
        )


def _typed_scalar_functions(tree: ast.Module) -> tuple[str, ...]:
    scalar_names = {"bool", "float", "int", "str"}
    names: list[str] = []
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef) or node.decorator_list or node.returns is None:
            continue
        if node.args.vararg is not None or node.args.kwarg is not None:
            continue
        arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        annotations = [argument.annotation for argument in arguments]
        annotations.append(node.returns)
        if all(isinstance(item, ast.Name) and item.id in scalar_names for item in annotations):
            names.append(node.name)
    return tuple(sorted(names))


def _canonical_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _normalize_newlines(value: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n")


def _dist_info_root(name: str, version: str) -> PurePosixPath:
    normalized_name = re.sub(r"[-_.]+", "_", name).lower()
    # Wheel escaping preserves the PEP 440 local-version '+' separator. Runs
    # of hyphens are escaped because '-' separates wheel/dist-info fields.
    normalized_version = re.sub(r"-+", "_", version).lower()
    return PurePosixPath(f"{normalized_name}-{normalized_version}.dist-info")


def _header_values(message: Message, key: str) -> tuple[str, ...]:
    raw_values = message.get_all(key, [])
    values: list[str] = []
    for value in raw_values:
        if not isinstance(value, str):
            return ()
        values.append(value.strip())
    return tuple(values)


def _parse_distribution_metadata(data: bytes) -> _VerifiedDistributionMetadata:
    try:
        message = BytesParser(policy=compat32).parsebytes(data)
    except Exception as exc:
        raise ValueError("distribution METADATA could not be parsed") from exc
    if message.defects or message.is_multipart():
        raise ValueError("distribution METADATA has malformed RFC822 structure")
    metadata_versions = _header_values(message, "Metadata-Version")
    names = _header_values(message, "Name")
    versions = _header_values(message, "Version")
    if len(metadata_versions) != 1 or re.fullmatch(r"[1-9][0-9]*\.[0-9]+", metadata_versions[0]) is None:
        raise ValueError("distribution METADATA must contain one Metadata-Version")
    if len(names) != 1:
        raise ValueError("distribution METADATA must contain one Name")
    if len(versions) != 1:
        raise ValueError("distribution METADATA must contain one Version")
    name = names[0]
    version = versions[0]
    if not re.fullmatch(
        r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?",
        name,
    ):
        raise ValueError("distribution METADATA has an invalid Name")
    if not re.fullmatch(
        r"[A-Za-z0-9]+(?:[._+-][A-Za-z0-9]+)*",
        version,
    ):
        raise ValueError("distribution METADATA has an invalid Version")
    metadata_version = metadata_versions[0]
    major_s, _, minor_s = metadata_version.partition(".")
    try:
        metadata_major = int(major_s)
        metadata_minor = int(minor_s)
    except ValueError as exc:
        raise ValueError("distribution METADATA has an invalid Metadata-Version") from exc
    license_expressions = _header_values(message, "License-Expression")
    legacy_licenses = _header_values(message, "License")
    license_files = _header_values(message, "License-File")
    if len(license_expressions) > 1 or len(legacy_licenses) > 1:
        raise ValueError("distribution METADATA contains duplicate license headers")
    if license_expressions and legacy_licenses:
        # PEP 639: License-Expression and legacy License must not both appear.
        raise ValueError(
            "distribution METADATA must not combine License-Expression and License"
        )
    uses_pep639 = bool(license_expressions) or bool(license_files)
    if uses_pep639 and (metadata_major, metadata_minor) < (2, 4):
        raise ValueError(
            "distribution METADATA License-Expression/License-File require Metadata-Version >= 2.4"
        )
    raw_license = (
        license_expressions[0]
        if license_expressions
        else legacy_licenses[0]
        if legacy_licenses
        else None
    )
    license_text = _sanitize_license(raw_license)
    if len(license_files) != len(set(license_files)):
        raise ValueError("distribution METADATA contains duplicate License-File headers")
    for license_file in license_files:
        if "\\" in license_file:
            raise ValueError(
                "distribution METADATA License-File must not contain backslashes"
            )
        try:
            _record_path(license_file)
        except ValueError as exc:
            raise ValueError("distribution METADATA has an unsafe License-File path") from exc
    return _VerifiedDistributionMetadata(
        name=name,
        version=version,
        license=license_text,
        license_files=license_files,
    )


def _sanitize_license(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = " ".join(value.split())
    if not normalized or len(normalized) > 256:
        return None
    if re.fullmatch(r"[A-Za-z0-9 .,+()_:-]+", normalized) is None:
        return None
    if is_unknown_license(normalized):
        return None
    return normalized


def is_unknown_license(value: str) -> bool:
    """Return whether a license string is a missing/sentinel value."""
    collapsed = " ".join(value.split()).casefold()
    return collapsed in _UNKNOWN_LICENSE_SENTINELS


def _unavailable(
    package: str,
    policy: ImportPackagePolicy,
    reason: str,
    *,
    installed_version: str | None = None,
    license_text: str | None = None,
) -> ExternalSourcePlan:
    assert policy.distribution is not None and policy.version is not None
    return ExternalSourcePlan(
        package=package,
        distribution=policy.distribution,
        requested_version=policy.version,
        installed_version=installed_version,
        max_depth=policy.max_depth,
        status="unavailable",
        license=license_text,
        reason=reason,
    )
