"""External-source authorization (SourceLock) gate.

This module verifies a project-owned lock document that binds one available
``external_source_plan`` to exact distribution identity, verified content
hashes and sizes, a custom source inventory, provenance, and a closed
license attestation.  Verification never imports or executes external
packages, never contacts the network, and never grants legal advice or
automatic license approval.

Even a verified lock does not authorize source-native lowering, packaging, or
redistribution: call-site linkage, body lowerability, Rust codegen, and
packaging must still be available and authorized.

Trust boundary: the project/VCS review that authors the lock. This preview has
no cryptographic signature verification.
"""

from __future__ import annotations

import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from rextio.source.external import (
    MAX_AUTHORITY_FILES,
    MAX_AUTHORITY_PATH_LEN,
    MAX_DISTRIBUTION_LEN,
    MAX_FILE_BYTES,
    MAX_MODULE_NAME_LEN,
    MAX_PACKAGE_LEN,
    MAX_SOURCE_LOCK_BYTES,
    MAX_VERSION_LEN,
    ExternalSourcePlan,
    is_unknown_license,
)

SOURCE_LOCK_FILENAME = "rextio.external-source.lock.json"
SOURCE_LOCK_KIND = "rextio.external-source-authorization"
SOURCE_LOCK_SCHEMA_VERSION = "1"
SOURCE_INVENTORY_FORMAT = "rextio-source-inventory-v1"

# Exact fixed acknowledgement constant — not free text, not legal advice.
LICENSE_ACKNOWLEDGEMENT_V1 = "REXTIO_EXTERNAL_SOURCE_LICENSE_ACK_V1"

_MAX_LOCK_BYTES = MAX_SOURCE_LOCK_BYTES
_MAX_STRING = 512
_MAX_EVIDENCE = 2
_MAX_FILES = MAX_AUTHORITY_FILES
_MAX_JSON_DEPTH = 32
_REQUIRED_EVIDENCE = (
    "installed-distribution-record",
    "project-vcs-review",
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9 .,_+-]*[A-Za-z0-9])?$")
_PACKAGE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
_DISTRIBUTION_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9]+(?:[._+-][A-Za-z0-9]+)*$")
_LICENSE_EXPR_RE = re.compile(r"^[A-Za-z0-9 .,+()_:-]+$")

_REQUIRED_TOP_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "package",
        "distribution",
        "version",
        "content_hashes",
        "source_inventory",
        "provenance",
        "license_attestation",
    }
)
_ATTESTOR_KINDS = frozenset({"human", "organization"})
_ATTESTOR_RELATIONSHIPS = frozenset(
    {
        "human-owner",
        "organization-owner",
        "project-maintainer",
        "security-reviewer",
    }
)
_ACTION_SCOPES = (
    "analysis",
    "translation",
    "local-build",
    "package",
    "redistribution",
)
_SOURCE_ROLES = frozenset({"source-module"})
_METADATA_ROLES = frozenset({"record", "metadata", "wheel", "license-file"})
_FILE_ROLES = _SOURCE_ROLES | _METADATA_ROLES

# Fixed sanitized failure reasons — never embed attacker-controlled strings.
_REASON_INVALID_JSON = "project SourceLock is not valid JSON"
_REASON_DUPLICATE_KEY = "project SourceLock contains a duplicate JSON object key"
_REASON_NONFINITE = "project SourceLock contains a non-finite JSON number"
_REASON_RECURSION = "project SourceLock JSON nesting exceeds the allowed depth"
_REASON_OVERSIZED = "project SourceLock size is outside the allowed range"
_REASON_MALFORMED_UTF8 = "project SourceLock is not readable UTF-8 JSON"
_REASON_UNEXPECTED_KEYS = "project SourceLock has unexpected keys"
_REASON_INCOMPLETE_KEYS = "project SourceLock is missing required keys"
_REASON_INVALID_STRUCTURE = "project SourceLock has an invalid structure"
_REASON_UNSAFE_PATH = "project SourceLock contains an unsafe path reference"
_REASON_SYMLINK = "project SourceLock is a symlink or non-regular path"
_REASON_ESCAPE = "project SourceLock escapes the project root"
_REASON_MISSING = "project SourceLock is absent"
_REASON_NULL_LICENSE = "observed license is unknown and cannot be authorized"
_REASON_STALE_IDENTITY = "project SourceLock identity does not match the plan"
_REASON_STALE_MATERIAL = "project SourceLock material does not match the plan snapshot"
_REASON_STALE_SNAPSHOT = "project SourceLock snapshot does not match the plan digest"
_REASON_PLAN_UNAVAILABLE = "external source plan is unavailable and cannot be authorized"


@dataclass(frozen=True)
class ExternalSourceAuthorization:
    """Sanitized SourceLock verification evidence (never absolute paths)."""

    status: str
    path: str = SOURCE_LOCK_FILENAME
    reason: str | None = None
    snapshot_sha256: str | None = None
    attestor: str | None = None
    attestor_kind: str | None = None
    license_observed: str | None = None
    license_attestation_verified: bool = False
    source_inventory_verified: bool = False
    provenance_verified: bool = False

    @property
    def verified(self) -> bool:
        """Return whether the lock fully matches the available plan snapshot."""
        return self.status == "verified"

    def to_dict(self) -> dict[str, object]:
        """Return deterministic tooling-contract authorization evidence."""
        return {
            "status": self.status,
            "path": self.path,
            "reason": self.reason,
            "snapshot_sha256": self.snapshot_sha256,
            "attestor": self.attestor,
            "attestor_kind": self.attestor_kind,
            "license_observed": self.license_observed,
            "license_attestation_verified": self.license_attestation_verified,
            "source_inventory_verified": self.source_inventory_verified,
            "provenance_verified": self.provenance_verified,
        }


def plan_snapshot_sha256(plan: ExternalSourcePlan) -> str | None:
    """Return the plan's canonical snapshot digest (shared with check JSON)."""
    return plan.plan_snapshot_sha256()


def license_material_digest(plan: ExternalSourcePlan) -> str:
    """Return the canonical digest of observed license + license material files.

    Shares the exact document/hash implementation with
    ``ExternalSourcePlan.license_material_sha256``.
    """
    digest = plan.license_material_sha256()
    if digest is None:
        raise ValueError("license material digest is unavailable for this plan")
    return digest


def verify_external_source_authorization(
    project_root: Path | str,
    plan: ExternalSourcePlan,
) -> ExternalSourceAuthorization:
    """Verify the project SourceLock against one resolved external-source plan.

    Fail closed for absent, malformed, unsafe, duplicate-key, symlink,
    outside-project, stale, incomplete, mismatched, null-license, or
    unavailable plans.
    """
    if plan.status != "preview-ready":
        return ExternalSourceAuthorization(
            status="plan-unavailable",
            reason=plan.reason or _REASON_PLAN_UNAVAILABLE,
        )
    if (
        plan.license is None
        or not plan.license.strip()
        or is_unknown_license(plan.license)
    ):
        return ExternalSourceAuthorization(
            status="incomplete",
            reason=_REASON_NULL_LICENSE,
        )
    expected_snapshot = plan.plan_snapshot_sha256()
    if expected_snapshot is None or not plan.source_files or not plan.metadata_files:
        return ExternalSourceAuthorization(
            status="plan-unavailable",
            reason="external source plan authority material is incomplete",
        )

    try:
        data = _read_lock_bytes_safely(project_root)
    except _LockReadFailure as exc:
        return ExternalSourceAuthorization(status=exc.status, reason=exc.reason)

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return ExternalSourceAuthorization(
            status="invalid",
            reason=_REASON_MALFORMED_UTF8,
        )

    try:
        document = _load_strict_json(text)
    except _AuthorizationFailure as exc:
        return ExternalSourceAuthorization(status=exc.status, reason=exc.reason)

    try:
        return _verify_document(document, plan, expected_snapshot)
    except _AuthorizationFailure as exc:
        return ExternalSourceAuthorization(
            status=exc.status,
            reason=exc.reason,
            license_attestation_verified=exc.license_attestation_verified,
            source_inventory_verified=exc.source_inventory_verified,
            provenance_verified=exc.provenance_verified,
            attestor=exc.attestor,
            attestor_kind=exc.attestor_kind,
            license_observed=exc.license_observed,
            snapshot_sha256=exc.snapshot_sha256,
        )


class _LockReadFailure(Exception):
    def __init__(self, status: str, reason: str) -> None:
        self.status = status
        self.reason = reason
        super().__init__(reason)


class _AuthorizationFailure(Exception):
    def __init__(
        self,
        status: str,
        reason: str,
        *,
        license_attestation_verified: bool = False,
        source_inventory_verified: bool = False,
        provenance_verified: bool = False,
        attestor: str | None = None,
        attestor_kind: str | None = None,
        license_observed: str | None = None,
        snapshot_sha256: str | None = None,
    ) -> None:
        self.status = status
        self.reason = reason
        self.license_attestation_verified = license_attestation_verified
        self.source_inventory_verified = source_inventory_verified
        self.provenance_verified = provenance_verified
        self.attestor = attestor
        self.attestor_kind = attestor_kind
        self.license_observed = license_observed
        self.snapshot_sha256 = snapshot_sha256
        super().__init__(reason)


def _read_lock_bytes_safely(project_root: Path | str) -> bytes:
    """Open, fstat, and read the lock from one descriptor without following links."""
    try:
        root_resolved = Path(project_root).resolve()
    except OSError as exc:
        raise _LockReadFailure("invalid", "project root could not be resolved") from exc

    lock_path = root_resolved / SOURCE_LOCK_FILENAME
    # Containment: fixed basename under resolved root cannot escape by path parts.
    try:
        lock_path.resolve().relative_to(root_resolved)
    except (OSError, ValueError):
        # resolve() may follow a symlink; treat as unsafe before open.
        if lock_path.is_symlink() or not lock_path.exists():
            if not lock_path.exists() and not lock_path.is_symlink():
                raise _LockReadFailure("missing", _REASON_MISSING) from None
            raise _LockReadFailure("invalid", _REASON_SYMLINK) from None
        raise _LockReadFailure("invalid", _REASON_ESCAPE) from None

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    # Nonblocking open fails closed on FIFO replacement races (EAGAIN/ENXIO)
    # instead of hanging on a pipe swapped in between lstat and open.
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if sys.platform == "win32" and hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY

    try:
        # lstat first: reject obvious symlinks/non-regular paths before open.
        try:
            link_stat = os.lstat(lock_path)
        except FileNotFoundError as exc:
            raise _LockReadFailure("missing", _REASON_MISSING) from exc
        except OSError as exc:
            raise _LockReadFailure(
                "invalid", "project SourceLock path could not be inspected"
            ) from exc
        if stat.S_ISLNK(link_stat.st_mode):
            raise _LockReadFailure("invalid", _REASON_SYMLINK)
        if not stat.S_ISREG(link_stat.st_mode):
            raise _LockReadFailure("invalid", _REASON_SYMLINK)

        try:
            fd = os.open(str(lock_path), flags)
        except FileNotFoundError as exc:
            raise _LockReadFailure("missing", _REASON_MISSING) from exc
        except OSError as exc:
            # O_NOFOLLOW/O_NONBLOCK may raise ELOOP / EPERM / EAGAIN on races.
            raise _LockReadFailure("invalid", _REASON_SYMLINK) from exc

        try:
            file_stat = os.fstat(fd)
            # Descriptor identity is authoritative against FIFO/symlink races.
            if not stat.S_ISREG(file_stat.st_mode):
                raise _LockReadFailure("invalid", _REASON_SYMLINK)
            if hasattr(link_stat, "st_ino") and hasattr(file_stat, "st_ino"):
                if (
                    link_stat.st_ino != file_stat.st_ino
                    or link_stat.st_dev != file_stat.st_dev
                ):
                    raise _LockReadFailure("invalid", _REASON_SYMLINK)
            if file_stat.st_size <= 0 or file_stat.st_size > _MAX_LOCK_BYTES:
                raise _LockReadFailure("invalid", _REASON_OVERSIZED)
            chunks: list[bytes] = []
            remaining = _MAX_LOCK_BYTES + 1
            while remaining > 0:
                try:
                    chunk = os.read(fd, min(65536, remaining))
                except BlockingIOError as exc:
                    raise _LockReadFailure("invalid", _REASON_SYMLINK) from exc
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            if len(data) > _MAX_LOCK_BYTES:
                raise _LockReadFailure("invalid", _REASON_OVERSIZED)
            if not data:
                raise _LockReadFailure("invalid", _REASON_OVERSIZED)
            return data
        finally:
            os.close(fd)
    except _LockReadFailure:
        raise
    except OSError as exc:
        raise _LockReadFailure(
            "invalid", "project SourceLock could not be read"
        ) from exc


def _load_strict_json(text: str) -> Any:
    """Parse JSON rejecting duplicates, NaN/Infinity, and excessive recursion."""

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        seen: set[str] = set()
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in seen:
                raise _AuthorizationFailure("invalid", _REASON_DUPLICATE_KEY)
            seen.add(key)
            result[key] = value
        return result

    def parse_constant(value: str) -> Any:
        raise _AuthorizationFailure("invalid", _REASON_NONFINITE)

    try:
        document = json.loads(
            text,
            object_pairs_hook=object_pairs,
            parse_constant=parse_constant,
        )
    except _AuthorizationFailure:
        raise
    except RecursionError as exc:
        raise _AuthorizationFailure("invalid", _REASON_RECURSION) from exc
    except json.JSONDecodeError as exc:
        raise _AuthorizationFailure("invalid", _REASON_INVALID_JSON) from exc
    except ValueError as exc:
        # json may raise ValueError for some non-finite cases depending on version.
        message = str(exc).lower()
        if "nan" in message or "inf" in message:
            raise _AuthorizationFailure("invalid", _REASON_NONFINITE) from exc
        raise _AuthorizationFailure("invalid", _REASON_INVALID_JSON) from exc
    except Exception as exc:
        raise _AuthorizationFailure("invalid", _REASON_INVALID_JSON) from exc

    try:
        _assert_json_depth(document, 0)
    except RecursionError as exc:
        raise _AuthorizationFailure("invalid", _REASON_RECURSION) from exc
    return document


def _assert_json_depth(value: Any, depth: int) -> None:
    if depth > _MAX_JSON_DEPTH:
        raise _AuthorizationFailure("invalid", _REASON_RECURSION)
    if isinstance(value, dict):
        for item in value.values():
            _assert_json_depth(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _assert_json_depth(item, depth + 1)


def _verify_document(
    document: Any,
    plan: ExternalSourcePlan,
    expected_snapshot: str,
) -> ExternalSourceAuthorization:
    if not isinstance(document, dict):
        raise _AuthorizationFailure("invalid", _REASON_INVALID_STRUCTURE)
    keys = set(document)
    if keys != _REQUIRED_TOP_KEYS:
        if _REQUIRED_TOP_KEYS - keys:
            raise _AuthorizationFailure("incomplete", _REASON_INCOMPLETE_KEYS)
        raise _AuthorizationFailure("invalid", _REASON_UNEXPECTED_KEYS)

    schema_version = _require_string(document, "schema_version", max_len=16)
    kind = _require_string(document, "kind", max_len=64)
    if schema_version != SOURCE_LOCK_SCHEMA_VERSION or kind != SOURCE_LOCK_KIND:
        raise _AuthorizationFailure("invalid", _REASON_INVALID_STRUCTURE)

    package = _require_string(
        document, "package", max_len=MAX_PACKAGE_LEN, pattern=_PACKAGE_RE
    )
    distribution = _require_string(
        document, "distribution", max_len=MAX_DISTRIBUTION_LEN, pattern=_DISTRIBUTION_RE
    )
    version = _require_string(
        document, "version", max_len=MAX_VERSION_LEN, pattern=_VERSION_RE
    )
    if (
        package != plan.package
        or distribution != plan.distribution
        or version != plan.requested_version
    ):
        raise _AuthorizationFailure("stale", _REASON_STALE_IDENTITY)
    if plan.installed_version is not None and plan.installed_version != version:
        raise _AuthorizationFailure("stale", _REASON_STALE_IDENTITY)

    content_hashes = document["content_hashes"]
    if not isinstance(content_hashes, dict):
        raise _AuthorizationFailure("invalid", _REASON_INVALID_STRUCTURE)
    _require_exact_keys(
        content_hashes,
        {"source_files", "metadata_files", "snapshot_sha256"},
        incomplete_ok=False,
    )

    lock_sources = _parse_file_list(
        content_hashes["source_files"],
        require_module_name=True,
        allowed_roles=_SOURCE_ROLES,
    )
    lock_metadata = _parse_file_list(
        content_hashes["metadata_files"],
        require_module_name=False,
        allowed_roles=_METADATA_ROLES,
    )
    declared_snapshot = _require_string(
        content_hashes, "snapshot_sha256", max_len=64, pattern=_SHA256_RE
    )
    if declared_snapshot != expected_snapshot:
        raise _AuthorizationFailure(
            "stale",
            _REASON_STALE_SNAPSHOT,
            snapshot_sha256=expected_snapshot,
        )

    expected_sources = {
        item.path: (item.module_name, item.sha256, item.size)
        for item in plan.source_files
    }
    expected_metadata = {
        item.path: (item.role, item.sha256, item.size) for item in plan.metadata_files
    }
    if set(lock_sources) != set(expected_sources) or set(lock_metadata) != set(
        expected_metadata
    ):
        raise _AuthorizationFailure("stale", _REASON_STALE_MATERIAL)
    for path, (module_name, sha256, size) in lock_sources.items():
        expected_name, expected_hash, expected_size = expected_sources[path]
        if (
            module_name != expected_name
            or sha256 != expected_hash
            or size != expected_size
        ):
            raise _AuthorizationFailure("stale", _REASON_STALE_MATERIAL)
    for path, (role, sha256, size) in lock_metadata.items():
        expected_role, expected_hash, expected_size = expected_metadata[path]
        if role != expected_role or sha256 != expected_hash or size != expected_size:
            raise _AuthorizationFailure("stale", _REASON_STALE_MATERIAL)

    # --- source_inventory (custom, not a full SBOM) ---
    inventory = document["source_inventory"]
    if not isinstance(inventory, dict):
        raise _AuthorizationFailure("incomplete", _REASON_INCOMPLETE_KEYS)
    _require_exact_keys(inventory, {"format", "components"}, incomplete_ok=False)
    inv_format = _require_string(inventory, "format", max_len=64)
    if inv_format != SOURCE_INVENTORY_FORMAT:
        raise _AuthorizationFailure("invalid", _REASON_INVALID_STRUCTURE)
    components = inventory["components"]
    if not isinstance(components, list) or len(components) != 1:
        raise _AuthorizationFailure("incomplete", _REASON_INCOMPLETE_KEYS)
    component = components[0]
    if not isinstance(component, dict):
        raise _AuthorizationFailure("invalid", _REASON_INVALID_STRUCTURE)
    _require_exact_keys(
        component,
        {"type", "name", "version", "license_observed", "files"},
        incomplete_ok=False,
    )
    if _require_string(component, "type", max_len=64) != "pypi-distribution":
        raise _AuthorizationFailure("invalid", _REASON_INVALID_STRUCTURE)
    if (
        _require_string(
            component, "name", max_len=MAX_DISTRIBUTION_LEN, pattern=_DISTRIBUTION_RE
        )
        != plan.distribution
        or _require_string(
            component, "version", max_len=MAX_VERSION_LEN, pattern=_VERSION_RE
        )
        != plan.requested_version
    ):
        raise _AuthorizationFailure("stale", _REASON_STALE_IDENTITY)
    component_license = _require_license_expression(
        component["license_observed"], required=True
    )
    if component_license != plan.license:
        raise _AuthorizationFailure("stale", _REASON_STALE_MATERIAL)
    inv_files = _parse_inventory_files(component["files"])
    # Inventory must cover all authority files with exact path/hash/size/role.
    all_expected: dict[str, tuple[str, str, int]] = {
        **{
            path: ("source-module", sha, size)
            for path, (_n, sha, size) in expected_sources.items()
        },
        **{
            path: (role, sha, size)
            for path, (role, sha, size) in expected_metadata.items()
        },
    }
    if set(inv_files) != set(all_expected):
        raise _AuthorizationFailure("stale", _REASON_STALE_MATERIAL)
    for path, (sha256, size, role) in inv_files.items():
        expected_role, expected_hash, expected_size = all_expected[path]
        if role != expected_role or sha256 != expected_hash or size != expected_size:
            raise _AuthorizationFailure("stale", _REASON_STALE_MATERIAL)
    source_inventory_verified = True

    # --- provenance ---
    provenance = document["provenance"]
    if not isinstance(provenance, dict):
        raise _AuthorizationFailure("incomplete", _REASON_INCOMPLETE_KEYS)
    _require_exact_keys(
        provenance,
        {
            "subject_snapshot_sha256",
            "producer",
            "attestor_relationship",
            "installed_wheel",
            "evidence",
        },
        incomplete_ok=False,
    )
    subject = _require_string(
        provenance, "subject_snapshot_sha256", max_len=64, pattern=_SHA256_RE
    )
    if subject != expected_snapshot:
        raise _AuthorizationFailure(
            "stale",
            _REASON_STALE_SNAPSHOT,
            source_inventory_verified=source_inventory_verified,
            snapshot_sha256=expected_snapshot,
        )
    producer = _require_string(
        provenance, "producer", max_len=_MAX_STRING, pattern=_SAFE_NAME_RE
    )
    if producer == "rextio":
        raise _AuthorizationFailure(
            "invalid",
            "provenance.producer must identify the project human or organization",
            source_inventory_verified=source_inventory_verified,
            snapshot_sha256=expected_snapshot,
        )
    relationship = _require_string(provenance, "attestor_relationship", max_len=64)
    if relationship not in _ATTESTOR_RELATIONSHIPS:
        raise _AuthorizationFailure(
            "invalid",
            _REASON_INVALID_STRUCTURE,
            source_inventory_verified=source_inventory_verified,
            snapshot_sha256=expected_snapshot,
        )
    # Relationship-to-attestor_kind is enforced after attestation is parsed.
    installed_wheel = provenance["installed_wheel"]
    if not isinstance(installed_wheel, dict):
        raise _AuthorizationFailure(
            "invalid",
            _REASON_INVALID_STRUCTURE,
            source_inventory_verified=source_inventory_verified,
            snapshot_sha256=expected_snapshot,
        )
    _require_exact_keys(
        installed_wheel,
        {"distribution", "version", "metadata_files"},
        incomplete_ok=False,
    )
    if (
        _require_string(
            installed_wheel,
            "distribution",
            max_len=MAX_DISTRIBUTION_LEN,
            pattern=_DISTRIBUTION_RE,
        )
        != plan.distribution
        or _require_string(
            installed_wheel, "version", max_len=MAX_VERSION_LEN, pattern=_VERSION_RE
        )
        != plan.requested_version
    ):
        raise _AuthorizationFailure(
            "stale",
            _REASON_STALE_IDENTITY,
            source_inventory_verified=source_inventory_verified,
            snapshot_sha256=expected_snapshot,
        )
    wheel_metadata = _parse_file_list(
        installed_wheel["metadata_files"],
        require_module_name=False,
        allowed_roles=_METADATA_ROLES,
    )
    if wheel_metadata != {
        path: (role, sha, size) for path, (role, sha, size) in expected_metadata.items()
    }:
        # Compare as dict of path -> role/sha/size
        if set(wheel_metadata) != set(expected_metadata):
            raise _AuthorizationFailure(
                "stale",
                _REASON_STALE_MATERIAL,
                source_inventory_verified=source_inventory_verified,
                snapshot_sha256=expected_snapshot,
            )
        for path, (role, sha, size) in wheel_metadata.items():
            exp_role, exp_sha, exp_size = expected_metadata[path]
            if role != exp_role or sha != exp_sha or size != exp_size:
                raise _AuthorizationFailure(
                    "stale",
                    _REASON_STALE_MATERIAL,
                    source_inventory_verified=source_inventory_verified,
                    snapshot_sha256=expected_snapshot,
                )
    evidence = provenance["evidence"]
    if not isinstance(evidence, list):
        raise _AuthorizationFailure(
            "incomplete",
            _REASON_INCOMPLETE_KEYS,
            source_inventory_verified=source_inventory_verified,
            snapshot_sha256=expected_snapshot,
        )
    if len(evidence) != len(_REQUIRED_EVIDENCE):
        raise _AuthorizationFailure(
            "incomplete",
            "provenance.evidence must list the exact closed evidence set",
            source_inventory_verified=source_inventory_verified,
            snapshot_sha256=expected_snapshot,
        )
    normalized_evidence: list[str] = []
    for item in evidence:
        if not isinstance(item, str):
            raise _AuthorizationFailure(
                "invalid",
                _REASON_INVALID_STRUCTURE,
                source_inventory_verified=source_inventory_verified,
                snapshot_sha256=expected_snapshot,
            )
        value = item.strip()
        if not value or len(value) > _MAX_STRING or not _SAFE_NAME_RE.fullmatch(value):
            raise _AuthorizationFailure(
                "invalid",
                _REASON_INVALID_STRUCTURE,
                source_inventory_verified=source_inventory_verified,
                snapshot_sha256=expected_snapshot,
            )
        normalized_evidence.append(value)
    if tuple(normalized_evidence) != _REQUIRED_EVIDENCE:
        raise _AuthorizationFailure(
            "incomplete",
            "provenance.evidence must be exactly installed-distribution-record "
            "then project-vcs-review",
            source_inventory_verified=source_inventory_verified,
            snapshot_sha256=expected_snapshot,
        )
    provenance_verified = True

    # --- closed license attestation ---
    attestation = document["license_attestation"]
    if not isinstance(attestation, dict):
        raise _AuthorizationFailure(
            "incomplete",
            _REASON_INCOMPLETE_KEYS,
            source_inventory_verified=source_inventory_verified,
            provenance_verified=provenance_verified,
            snapshot_sha256=expected_snapshot,
        )
    _require_exact_keys(
        attestation,
        {
            "attestor",
            "attestor_kind",
            "reviewed_license",
            "reviewed_license_material_sha256",
            "decision",
            "action_scopes",
            "acknowledgement",
        },
        incomplete_ok=False,
    )
    attestor = _require_string(
        attestation, "attestor", max_len=_MAX_STRING, pattern=_SAFE_NAME_RE
    )
    attestor_kind = _require_string(attestation, "attestor_kind", max_len=32)
    if attestor_kind not in _ATTESTOR_KINDS:
        raise _AuthorizationFailure(
            "invalid",
            _REASON_INVALID_STRUCTURE,
            source_inventory_verified=source_inventory_verified,
            provenance_verified=provenance_verified,
            attestor=attestor,
            snapshot_sha256=expected_snapshot,
        )
    # Closed relationship/kind matrix (fail closed):
    # organization-owner -> organization; all other relationships require human.
    expected_kind = (
        "organization" if relationship == "organization-owner" else "human"
    )
    if attestor_kind != expected_kind:
        raise _AuthorizationFailure(
            "invalid",
            "provenance.attestor_relationship does not match license_attestation.attestor_kind",
            source_inventory_verified=source_inventory_verified,
            provenance_verified=provenance_verified,
            attestor=attestor,
            attestor_kind=attestor_kind,
            snapshot_sha256=expected_snapshot,
        )
    reviewed_license = _require_license_expression(
        attestation["reviewed_license"], required=True
    )
    if is_unknown_license(reviewed_license) or reviewed_license != plan.license:
        raise _AuthorizationFailure(
            "stale",
            _REASON_STALE_MATERIAL,
            source_inventory_verified=source_inventory_verified,
            provenance_verified=provenance_verified,
            attestor=attestor,
            attestor_kind=attestor_kind,
            license_observed=reviewed_license,
            snapshot_sha256=expected_snapshot,
        )
    material_digest = _require_string(
        attestation,
        "reviewed_license_material_sha256",
        max_len=64,
        pattern=_SHA256_RE,
    )
    expected_material = plan.license_material_sha256()
    if expected_material is None or material_digest != expected_material:
        raise _AuthorizationFailure(
            "stale",
            _REASON_STALE_MATERIAL,
            source_inventory_verified=source_inventory_verified,
            provenance_verified=provenance_verified,
            attestor=attestor,
            attestor_kind=attestor_kind,
            license_observed=plan.license,
            snapshot_sha256=expected_snapshot,
        )
    if attestation.get("decision") != "allow":
        raise _AuthorizationFailure(
            "incomplete",
            "license_attestation.decision must be exactly 'allow'",
            source_inventory_verified=source_inventory_verified,
            provenance_verified=provenance_verified,
            attestor=attestor,
            attestor_kind=attestor_kind,
            license_observed=plan.license,
            snapshot_sha256=expected_snapshot,
        )
    scopes = attestation.get("action_scopes")
    if not isinstance(scopes, list) or tuple(scopes) != _ACTION_SCOPES:
        raise _AuthorizationFailure(
            "incomplete",
            "license_attestation.action_scopes must list the exact closed scope set",
            source_inventory_verified=source_inventory_verified,
            provenance_verified=provenance_verified,
            attestor=attestor,
            attestor_kind=attestor_kind,
            license_observed=plan.license,
            snapshot_sha256=expected_snapshot,
        )
    acknowledgement = attestation.get("acknowledgement")
    if acknowledgement != LICENSE_ACKNOWLEDGEMENT_V1:
        raise _AuthorizationFailure(
            "incomplete",
            "license_attestation.acknowledgement must be the exact fixed constant",
            source_inventory_verified=source_inventory_verified,
            provenance_verified=provenance_verified,
            attestor=attestor,
            attestor_kind=attestor_kind,
            license_observed=plan.license,
            snapshot_sha256=expected_snapshot,
        )
    # Producer in provenance should match attestor identity for this preview.
    if producer != attestor:
        raise _AuthorizationFailure(
            "stale",
            "provenance.producer must match license_attestation.attestor",
            source_inventory_verified=source_inventory_verified,
            provenance_verified=provenance_verified,
            attestor=attestor,
            attestor_kind=attestor_kind,
            license_observed=plan.license,
            snapshot_sha256=expected_snapshot,
        )

    return ExternalSourceAuthorization(
        status="verified",
        reason=None,
        snapshot_sha256=expected_snapshot,
        attestor=attestor,
        attestor_kind=attestor_kind,
        license_observed=plan.license,
        license_attestation_verified=True,
        source_inventory_verified=True,
        provenance_verified=True,
    )


def _require_exact_keys(
    value: dict[str, Any],
    expected: set[str],
    *,
    incomplete_ok: bool,
) -> None:
    del incomplete_ok  # retained for call-site clarity
    keys = set(value)
    if keys != expected:
        if expected - keys:
            raise _AuthorizationFailure("incomplete", _REASON_INCOMPLETE_KEYS)
        raise _AuthorizationFailure("invalid", _REASON_UNEXPECTED_KEYS)


def _require_string(
    mapping: dict[str, Any],
    key: str,
    *,
    max_len: int,
    pattern: re.Pattern[str] | None = None,
) -> str:
    value = mapping.get(key)
    if not isinstance(value, str):
        raise _AuthorizationFailure("invalid", _REASON_INVALID_STRUCTURE)
    text = value.strip()
    if not text or len(text) > max_len:
        raise _AuthorizationFailure("invalid", _REASON_INVALID_STRUCTURE)
    if pattern is not None and pattern.fullmatch(text) is None:
        raise _AuthorizationFailure("invalid", _REASON_INVALID_STRUCTURE)
    return text


def _require_license_expression(value: Any, *, required: bool) -> str:
    if value is None:
        if required:
            raise _AuthorizationFailure("incomplete", _REASON_NULL_LICENSE)
        raise _AuthorizationFailure("invalid", _REASON_INVALID_STRUCTURE)
    if not isinstance(value, str):
        raise _AuthorizationFailure("invalid", _REASON_INVALID_STRUCTURE)
    normalized = " ".join(value.split())
    if not normalized or len(normalized) > 256:
        raise _AuthorizationFailure("invalid", _REASON_INVALID_STRUCTURE)
    if _LICENSE_EXPR_RE.fullmatch(normalized) is None:
        raise _AuthorizationFailure("invalid", _REASON_INVALID_STRUCTURE)
    return normalized


def _validate_distribution_path(path: str) -> None:
    posix = PurePosixPath(path)
    windows = PureWindowsPath(path)
    if (
        not path
        or posix.is_absolute()
        or windows.is_absolute()
        or bool(windows.drive)
        or ".." in posix.parts
        or ".." in windows.parts
        or not path.startswith("distributions/")
    ):
        raise _AuthorizationFailure("invalid", _REASON_UNSAFE_PATH)


def _parse_file_list(
    raw: Any,
    *,
    require_module_name: bool,
    allowed_roles: frozenset[str],
) -> dict[str, tuple[str | None, str, int]] | dict[str, tuple[str, str, int]]:
    if not isinstance(raw, list) or not raw:
        raise _AuthorizationFailure("incomplete", _REASON_INCOMPLETE_KEYS)
    if len(raw) > _MAX_FILES:
        raise _AuthorizationFailure("invalid", _REASON_INVALID_STRUCTURE)
    result: dict[str, tuple[Any, ...]] = {}
    for item in raw:
        if not isinstance(item, dict):
            raise _AuthorizationFailure("invalid", _REASON_INVALID_STRUCTURE)
        expected_keys = {"path", "sha256", "size", "role"}
        if require_module_name:
            expected_keys = expected_keys | {"module_name"}
        if set(item) != expected_keys:
            if expected_keys - set(item):
                raise _AuthorizationFailure("incomplete", _REASON_INCOMPLETE_KEYS)
            raise _AuthorizationFailure("invalid", _REASON_UNEXPECTED_KEYS)
        path = _require_string(item, "path", max_len=MAX_AUTHORITY_PATH_LEN)
        _validate_distribution_path(path)
        sha256 = _require_string(item, "sha256", max_len=64, pattern=_SHA256_RE)
        size = item["size"]
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or size > MAX_FILE_BYTES
        ):
            raise _AuthorizationFailure("invalid", _REASON_INVALID_STRUCTURE)
        role = _require_string(item, "role", max_len=32)
        if role not in allowed_roles:
            raise _AuthorizationFailure("invalid", _REASON_INVALID_STRUCTURE)
        module_name: str | None = None
        if require_module_name:
            module_name = _require_string(
                item, "module_name", max_len=MAX_MODULE_NAME_LEN, pattern=_PACKAGE_RE
            )
        if path in result:
            raise _AuthorizationFailure(
                "invalid", "content_hashes contains a duplicate path"
            )
        if require_module_name:
            result[path] = (module_name, sha256, size)
        else:
            result[path] = (role, sha256, size)
    return result


def _parse_inventory_files(
    raw: Any,
) -> dict[str, tuple[str, int, str]]:
    if not isinstance(raw, list) or not raw:
        raise _AuthorizationFailure("incomplete", _REASON_INCOMPLETE_KEYS)
    if len(raw) > _MAX_FILES:
        raise _AuthorizationFailure("invalid", _REASON_INVALID_STRUCTURE)
    result: dict[str, tuple[str, int, str]] = {}
    for item in raw:
        if not isinstance(item, dict):
            raise _AuthorizationFailure("invalid", _REASON_INVALID_STRUCTURE)
        if set(item) != {"path", "sha256", "size", "role"}:
            if {"path", "sha256", "size", "role"} - set(item):
                raise _AuthorizationFailure("incomplete", _REASON_INCOMPLETE_KEYS)
            raise _AuthorizationFailure("invalid", _REASON_UNEXPECTED_KEYS)
        path = _require_string(item, "path", max_len=MAX_AUTHORITY_PATH_LEN)
        _validate_distribution_path(path)
        sha256 = _require_string(item, "sha256", max_len=64, pattern=_SHA256_RE)
        size = item["size"]
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or size > MAX_FILE_BYTES
        ):
            raise _AuthorizationFailure("invalid", _REASON_INVALID_STRUCTURE)
        role = _require_string(item, "role", max_len=32)
        if role not in _FILE_ROLES:
            raise _AuthorizationFailure("invalid", _REASON_INVALID_STRUCTURE)
        if path in result:
            raise _AuthorizationFailure(
                "invalid", "source_inventory contains a duplicate path"
            )
        result[path] = (sha256, size, role)
    return result
