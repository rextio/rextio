"""Bounded C6.11 verification of one project-owned Cargo license lock."""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rextio.artifacts.evidence import (
    CARGO_LICENSE_POLICY,
    CARGO_LICENSE_POLICY_ACKNOWLEDGEMENT,
    CARGO_LICENSE_POLICY_ACTION_SCOPES,
    CARGO_LICENSE_POLICY_LOCK_FILENAME,
    CARGO_LICENSE_POLICY_LOCK_KIND,
    CARGO_LICENSE_POLICY_LOCK_ROLE,
    CARGO_LICENSE_POLICY_LOCK_SCHEMA_VERSION,
    COMPONENT_LICENSE_POLICY_VERIFICATION_SCOPE,
    MAX_CARGO_LICENSE_LOCK_BYTES,
    ComponentLicenseInventory,
    ComponentLicensePolicyVerification,
    ComponentLicenseRecord,
    EvidenceFileRef,
    cargo_license_metadata_is_unknown,
    canonical_json_bytes,
    sha256_hex,
)

_MAX_JSON_DEPTH = 32


@dataclass(frozen=True, slots=True)
class _FilesystemStamp:
    device: int
    inode: int
    size: int
    ctime_ns: int
    mtime_ns: int
    mode: int
    links: int


@dataclass(frozen=True, slots=True)
class _LockReceipt:
    data: bytes
    stamp: _FilesystemStamp

    @property
    def sha256(self) -> str:
        return sha256_hex(self.data)


def collect_component_license_policy_verification(
    *,
    project_root: Path,
    component_license_inventory: ComponentLicenseInventory,
) -> ComponentLicensePolicyVerification | None:
    """Verify the exact scoped owner lock, returning ``None`` on any failure."""
    try:
        return _collect_component_license_policy_verification(
            project_root=project_root,
            component_license_inventory=component_license_inventory,
        )
    except Exception:
        # C6.11 is an additive observation. Lock failures never perturb an
        # ordinary build or the independently configured C6.3 evidence gate.
        return None


def _collect_component_license_policy_verification(
    *,
    project_root: Path,
    component_license_inventory: ComponentLicenseInventory,
) -> ComponentLicensePolicyVerification:
    if type(component_license_inventory) is not ComponentLicenseInventory:
        raise TypeError("Cargo license policy inventory is invalid")
    registry_records = tuple(
        record
        for record in component_license_inventory.records
        if record.kind == "registry"
    )
    if not registry_records:
        raise ValueError("Cargo license policy requires registry components")
    if not all(type(record) is ComponentLicenseRecord for record in registry_records):
        raise TypeError("Cargo license policy record is invalid")
    if any(
        record.license_observed is None
        or record.license_observation != "declared-unvalidated"
        or cargo_license_metadata_is_unknown(record.license_observed)
        for record in registry_records
    ):
        raise ValueError("Cargo license policy contains an unknown license")

    inventory_digest = sha256_hex(
        canonical_json_bytes(component_license_inventory.to_dict())
    )
    root = Path(os.path.abspath(project_root))
    lock_receipt = _read_lock_file(root)
    try:
        text = lock_receipt.data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Cargo license policy lock is not UTF-8") from exc
    document = _load_strict_json(text)
    attestation = _verify_lock_document(
        document=document,
        inventory_digest=inventory_digest,
        registry_records=registry_records,
    )
    lock_ref = EvidenceFileRef(
        logical_path=CARGO_LICENSE_POLICY_LOCK_FILENAME,
        sha256=lock_receipt.sha256,
        size=len(lock_receipt.data),
        role=CARGO_LICENSE_POLICY_LOCK_ROLE,
    )
    return ComponentLicensePolicyVerification(
        component_license_inventory_sha256=inventory_digest,
        lock_file=lock_ref,
        policy_snapshot_sha256=sha256_hex(canonical_json_bytes(document)),
        registry_component_bom_refs=tuple(record.bom_ref for record in registry_records),
        attestor=attestation["attestor"],
        attestor_kind=attestation["attestor_kind"],
        attestor_relationship=attestation["attestor_relationship"],
    )


def _verify_lock_document(
    *,
    document: object,
    inventory_digest: str,
    registry_records: tuple[ComponentLicenseRecord, ...],
) -> dict[str, str]:
    if not isinstance(document, dict):
        raise ValueError("Cargo license policy lock root is invalid")
    _require_exact_keys(
        document,
        {
            "schema_version",
            "kind",
            "scope",
            "policy",
            "component_license_inventory_sha256",
            "registry_components",
            "attestation",
        },
    )
    if (
        document["schema_version"] != CARGO_LICENSE_POLICY_LOCK_SCHEMA_VERSION
        or document["kind"] != CARGO_LICENSE_POLICY_LOCK_KIND
        or document["scope"] != COMPONENT_LICENSE_POLICY_VERIFICATION_SCOPE
        or document["policy"] != CARGO_LICENSE_POLICY
        or document["component_license_inventory_sha256"] != inventory_digest
    ):
        raise ValueError("Cargo license policy lock identity is stale")
    expected_records = [record.to_dict() for record in registry_records]
    if document["registry_components"] != expected_records:
        raise ValueError("Cargo license policy registry records are stale")

    raw_attestation = document["attestation"]
    if not isinstance(raw_attestation, dict):
        raise ValueError("Cargo license policy attestation is invalid")
    _require_exact_keys(
        raw_attestation,
        {
            "attestor",
            "attestor_kind",
            "attestor_relationship",
            "decision",
            "action_scopes",
            "acknowledgement",
        },
    )
    for field in ("attestor", "attestor_kind", "attestor_relationship"):
        if type(raw_attestation[field]) is not str:
            raise TypeError("Cargo license policy attestation string is invalid")
    if raw_attestation["decision"] != "allow":
        raise ValueError("Cargo license policy decision is not allow")
    if raw_attestation["action_scopes"] != list(CARGO_LICENSE_POLICY_ACTION_SCOPES):
        raise ValueError("Cargo license policy scopes are invalid")
    if raw_attestation["acknowledgement"] != CARGO_LICENSE_POLICY_ACKNOWLEDGEMENT:
        raise ValueError("Cargo license policy acknowledgement is invalid")
    return {
        "attestor": raw_attestation["attestor"],
        "attestor_kind": raw_attestation["attestor_kind"],
        "attestor_relationship": raw_attestation["attestor_relationship"],
    }


def _require_exact_keys(value: dict[str, object], expected: set[str]) -> None:
    if set(value) != expected:
        raise ValueError("Cargo license policy lock keys are invalid")


def _load_strict_json(text: str) -> object:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Cargo license policy lock has a duplicate key")
            result[key] = value
        return result

    def parse_constant(_value: str) -> object:
        raise ValueError("Cargo license policy lock has a non-finite value")

    try:
        document = json.loads(
            text,
            object_pairs_hook=object_pairs,
            parse_constant=parse_constant,
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Cargo license policy lock JSON is invalid") from exc
    _assert_json_depth(document, depth=0)
    return document


def _assert_json_depth(value: object, *, depth: int) -> None:
    if depth > _MAX_JSON_DEPTH:
        raise ValueError("Cargo license policy lock nesting is too deep")
    if isinstance(value, dict):
        for child in value.values():
            _assert_json_depth(child, depth=depth + 1)
    elif isinstance(value, list):
        for child in value:
            _assert_json_depth(child, depth=depth + 1)


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


def _directory_open_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None:
        raise OSError("secure Cargo license lock traversal is unavailable")
    return os.O_RDONLY | nofollow | directory | getattr(os, "O_CLOEXEC", 0)


def _open_absolute_directory_chain(
    root: Path,
) -> list[tuple[int, int | None, str | None, _FilesystemStamp]]:
    """Pin every project-root ancestor through no-follow directory handles."""
    absolute = Path(os.path.abspath(root))
    if not absolute.is_absolute() or not absolute.anchor:
        raise OSError("Cargo license policy root is not absolute")
    handles: list[tuple[int, int | None, str | None, _FilesystemStamp]] = []
    try:
        current_fd = os.open(absolute.anchor, _directory_open_flags())
        anchor_stamp = _stamp(os.fstat(current_fd))
        handles.append((current_fd, None, None, anchor_stamp))
        if not stat.S_ISDIR(anchor_stamp.mode):
            raise OSError("Cargo license policy root anchor is unsafe")
        for part in absolute.parts[1:]:
            if not part or part in {".", ".."} or "/" in part or "\\" in part:
                raise OSError("Cargo license policy root component is unsafe")
            next_fd = os.open(part, _directory_open_flags(), dir_fd=current_fd)
            next_stamp = _stamp(os.fstat(next_fd))
            handles.append((next_fd, current_fd, part, next_stamp))
            linked_stamp = _stamp(
                os.stat(part, dir_fd=current_fd, follow_symlinks=False)
            )
            if next_stamp != linked_stamp or not stat.S_ISDIR(next_stamp.mode):
                raise OSError("Cargo license policy root component changed")
            current_fd = next_fd
        return handles
    except Exception:
        for handle, _parent, _name, _expected in reversed(handles):
            try:
                os.close(handle)
            except OSError:
                pass
        raise


def _verify_directory_chain(
    handles: list[tuple[int, int | None, str | None, _FilesystemStamp]],
) -> None:
    for handle, parent, name, expected in handles:
        actual = _stamp(os.fstat(handle))
        if actual != expected or not stat.S_ISDIR(actual.mode):
            raise OSError("Cargo license policy root directory changed")
        if parent is None or name is None:
            continue
        linked = _stamp(os.stat(name, dir_fd=parent, follow_symlinks=False))
        if linked != expected or not stat.S_ISDIR(linked.mode):
            raise OSError("Cargo license policy root path changed")


def _read_lock_file(root: Path) -> _LockReceipt:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise OSError("secure Cargo license lock traversal is unavailable")
    file_flags = os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NONBLOCK"):
        file_flags |= os.O_NONBLOCK

    directory_chain: list[
        tuple[int, int | None, str | None, _FilesystemStamp]
    ] = []
    file_fd = -1
    try:
        directory_chain = _open_absolute_directory_chain(root)
        root_fd = directory_chain[-1][0]
        file_fd = os.open(CARGO_LICENSE_POLICY_LOCK_FILENAME, file_flags, dir_fd=root_fd)
        file_stamp = _stamp(os.fstat(file_fd))
        linked_file = _stamp(
            os.stat(
                CARGO_LICENSE_POLICY_LOCK_FILENAME,
                dir_fd=root_fd,
                follow_symlinks=False,
            )
        )
        if (
            file_stamp != linked_file
            or not stat.S_ISREG(file_stamp.mode)
            or file_stamp.links != 1
            or file_stamp.size <= 0
            or file_stamp.size > MAX_CARGO_LICENSE_LOCK_BYTES
        ):
            raise OSError("Cargo license policy lock identity is unsafe")
        chunks: list[bytes] = []
        remaining = MAX_CARGO_LICENSE_LOCK_BYTES + 1
        while remaining > 0:
            chunk = os.read(file_fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) != file_stamp.size or len(data) > MAX_CARGO_LICENSE_LOCK_BYTES:
            raise OSError("Cargo license policy lock size changed")
        if _stamp(os.fstat(file_fd)) != file_stamp:
            raise OSError("Cargo license policy lock changed during read")
        if _stamp(
            os.stat(
                CARGO_LICENSE_POLICY_LOCK_FILENAME,
                dir_fd=root_fd,
                follow_symlinks=False,
            )
        ) != file_stamp:
            raise OSError("Cargo license policy lock link changed during read")
        _verify_directory_chain(directory_chain)
        return _LockReceipt(data=data, stamp=file_stamp)
    finally:
        if file_fd >= 0:
            try:
                os.close(file_fd)
            except OSError:
                pass
        for handle, _parent, _name, _expected in reversed(directory_chain):
            try:
                os.close(handle)
            except OSError:
                pass


__all__ = ["collect_component_license_policy_verification"]
