"""Focused adversarial tests for the C6.1 SourceLock authorization gate."""

from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path

import pytest

from rextio.artifacts import ArtifactProvenance
from rextio.source.authorization import (
    LICENSE_ACKNOWLEDGEMENT_V1,
    SOURCE_LOCK_FILENAME,
    license_material_digest,
    plan_snapshot_sha256,
    verify_external_source_authorization,
)
from rextio.source.authorization import ExternalSourceAuthorization
from rextio.source.external import (
    INVENTORY_SCHEMA_ID,
    MAX_SOURCE_LOCK_BYTES,
    MAX_SOURCE_MODULES,
    AuthorityFile,
    ExternalSourcePlan,
    _enforce_authority_bounds,
    compact_valid_source_lock_size,
)
from rextio.source.models import SourceModule, SourceOrigin


PACKAGE = "demo_pkg"
DIST = "demo-pkg"
VERSION = "1.0.0"
MODULE_PATH = f"distributions/{DIST}/{PACKAGE}/__init__.py"
DIST_INFO = f"distributions/{DIST}/demo_pkg-1.0.0.dist-info"
MODULE_SHA = "a" * 64
MODULE_SIZE = 42
META_SHA = "b" * 64
RECORD_SHA = "c" * 64
WHEEL_SHA = "d" * 64
LICENSE_SHA = "e" * 64
META_SIZE = 100
RECORD_SIZE = 50
WHEEL_SIZE = 40
LICENSE_SIZE = 20
# Literal golden digest for the fixed fixture below. Must change only when the
# canonical snapshot document/serialization intentionally changes.
GOLDEN_PLAN_SNAPSHOT_SHA256 = (
    "6dac7af8edd7772ac866a94c8ace41d8aaa8a19dd73d76f4f00e820b7ab3c4a6"
)


def _module() -> SourceModule:
    return SourceModule(
        module_name=PACKAGE,
        path=MODULE_PATH,
        is_package_init=True,
        source_origin=SourceOrigin.DISTRIBUTION,
        sha256=MODULE_SHA,
        dependency_depth=1,
        distribution=DIST,
        version=VERSION,
        license="MIT",
        provenance=ArtifactProvenance(source_references=(MODULE_PATH,)),
    )


def _plan(**overrides: object) -> ExternalSourcePlan:
    source_files = (
        AuthorityFile(
            path=MODULE_PATH,
            sha256=MODULE_SHA,
            size=MODULE_SIZE,
            role="source-module",
            module_name=PACKAGE,
        ),
    )
    metadata_files = (
        AuthorityFile(
            path=f"{DIST_INFO}/METADATA",
            sha256=META_SHA,
            size=META_SIZE,
            role="metadata",
        ),
        AuthorityFile(
            path=f"{DIST_INFO}/RECORD",
            sha256=RECORD_SHA,
            size=RECORD_SIZE,
            role="record",
        ),
        AuthorityFile(
            path=f"{DIST_INFO}/WHEEL",
            sha256=WHEEL_SHA,
            size=WHEEL_SIZE,
            role="wheel",
        ),
        AuthorityFile(
            path=f"{DIST_INFO}/licenses/LICENSE",
            sha256=LICENSE_SHA,
            size=LICENSE_SIZE,
            role="license-file",
        ),
    )
    base = dict(
        package=PACKAGE,
        distribution=DIST,
        requested_version=VERSION,
        installed_version=VERSION,
        max_depth=1,
        status="preview-ready",
        license="MIT",
        modules=(_module(),),
        candidate_functions=(f"{PACKAGE}.affine",),
        source_files=source_files,
        metadata_files=metadata_files,
    )
    base.update(overrides)
    return ExternalSourcePlan(**base)  # type: ignore[arg-type]


def _valid_lock(
    plan: ExternalSourcePlan,
    *,
    relationship: str = "organization-owner",
    attestor_kind: str = "organization",
    attestor: str = "Acme Engineering",
) -> dict[str, object]:
    snapshot = plan_snapshot_sha256(plan)
    assert snapshot is not None
    material = license_material_digest(plan)
    source_entries = [
        {
            "module_name": item.module_name,
            "path": item.path,
            "sha256": item.sha256,
            "size": item.size,
            "role": "source-module",
        }
        for item in plan.source_files
    ]
    metadata_entries = [
        {
            "path": item.path,
            "sha256": item.sha256,
            "size": item.size,
            "role": item.role,
        }
        for item in plan.metadata_files
    ]
    all_files = [
        {
            "path": item.path,
            "sha256": item.sha256,
            "size": item.size,
            "role": item.role,
        }
        for item in (*plan.source_files, *plan.metadata_files)
    ]
    return {
        "schema_version": "1",
        "kind": "rextio.external-source-authorization",
        "package": plan.package,
        "distribution": plan.distribution,
        "version": plan.requested_version,
        "content_hashes": {
            "source_files": source_entries,
            "metadata_files": metadata_entries,
            "snapshot_sha256": snapshot,
        },
        "source_inventory": {
            "format": "rextio-source-inventory-v1",
            "components": [
                {
                    "type": "pypi-distribution",
                    "name": plan.distribution,
                    "version": plan.requested_version,
                    "license_observed": plan.license,
                    "files": all_files,
                }
            ],
        },
        "provenance": {
            "subject_snapshot_sha256": snapshot,
            "producer": attestor,
            "attestor_relationship": relationship,
            "installed_wheel": {
                "distribution": plan.distribution,
                "version": plan.requested_version,
                "metadata_files": metadata_entries,
            },
            "evidence": [
                "installed-distribution-record",
                "project-vcs-review",
            ],
        },
        "license_attestation": {
            "attestor": attestor,
            "attestor_kind": attestor_kind,
            "reviewed_license": plan.license,
            "reviewed_license_material_sha256": material,
            "decision": "allow",
            "action_scopes": [
                "analysis",
                "translation",
                "local-build",
                "package",
                "redistribution",
            ],
            "acknowledgement": LICENSE_ACKNOWLEDGEMENT_V1,
        },
    }


def _write_lock(project: Path, document: dict[str, object] | str) -> Path:
    path = project / SOURCE_LOCK_FILENAME
    if isinstance(document, str):
        path.write_text(document, encoding="utf-8")
    else:
        path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def test_verified_source_lock_matches_plan_snapshot(tmp_path: Path) -> None:
    plan = _plan()
    _write_lock(tmp_path, _valid_lock(plan))
    auth = verify_external_source_authorization(tmp_path, plan)
    assert auth.verified
    assert auth.license_attestation_verified
    assert auth.source_inventory_verified
    assert auth.provenance_verified


def test_known_answer_canonical_snapshot_digest() -> None:
    plan = _plan()
    document = plan.plan_snapshot_document()
    assert document["domain"] == "rextio.external-source-plan-snapshot.v1"
    assert document["inventory_schema"] == INVENTORY_SCHEMA_ID
    assert document["candidate_functions"] == sorted(plan.candidate_functions)
    assert "reason" not in document
    assert "license_warning" not in document
    assert "authorization" not in document
    # Hardcoded golden digest for the fixed fixture (fails on field/order drift).
    assert plan.plan_snapshot_sha256() == GOLDEN_PLAN_SNAPSHOT_SHA256
    # Determinism: recompute equals the same golden literal.
    assert plan.plan_snapshot_sha256() == GOLDEN_PLAN_SNAPSHOT_SHA256


def test_shared_license_material_digest() -> None:
    plan = _plan()
    assert plan.license_material_sha256() == license_material_digest(plan)
    assert plan.to_dict()["license_material_sha256"] == plan.license_material_sha256()


def test_string_project_root_is_accepted(tmp_path: Path) -> None:
    plan = _plan()
    _write_lock(tmp_path, _valid_lock(plan))
    assert verify_external_source_authorization(str(tmp_path), plan).verified


def test_missing_source_lock(tmp_path: Path) -> None:
    assert verify_external_source_authorization(tmp_path, _plan()).status == "missing"


def test_unavailable_plan_cannot_be_authorized(tmp_path: Path) -> None:
    plan = _plan(status="unavailable", reason="not installed", modules=(), source_files=())
    _write_lock(tmp_path, _valid_lock(_plan()))
    auth = verify_external_source_authorization(tmp_path, plan)
    assert auth.status == "plan-unavailable"


def test_null_and_unknown_license_never_verify(tmp_path: Path) -> None:
    for license_value in (
        None,
        "UNKNOWN",
        " unknown ",
        "N/A",
        "NOASSERTION",
        " noassertion ",
        "NoAssertion",
    ):
        plan = _plan(license=license_value)
        _write_lock(tmp_path, _valid_lock(_plan()))
        auth = verify_external_source_authorization(tmp_path, plan)
        assert auth.status in {"incomplete", "plan-unavailable"}
        assert not auth.verified


def test_unlicense_is_not_a_sentinel_and_can_verify(tmp_path: Path) -> None:
    plan = _plan(license="Unlicense")
    _write_lock(tmp_path, _valid_lock(plan))
    auth = verify_external_source_authorization(tmp_path, plan)
    assert auth.verified


def test_arbitrary_but_self_consistent_size_is_stale(tmp_path: Path) -> None:
    plan = _plan()
    lock = _valid_lock(plan)
    lock["content_hashes"]["source_files"][0]["size"] = MODULE_SIZE + 9  # type: ignore[index]
    for file_entry in lock["source_inventory"]["components"][0]["files"]:  # type: ignore[index]
        if file_entry["path"] == MODULE_PATH:
            file_entry["size"] = MODULE_SIZE + 9
    _write_lock(tmp_path, lock)
    assert verify_external_source_authorization(tmp_path, plan).status == "stale"


@pytest.mark.parametrize(
    ("role", "replacement"),
    (
        ("source-module", "record"),
        ("record", "metadata"),
        ("metadata", "wheel"),
        ("wheel", "license-file"),
        ("license-file", "source-module"),
    ),
)
def test_source_inventory_role_must_match_authority(
    tmp_path: Path,
    role: str,
    replacement: str,
) -> None:
    plan = _plan()
    lock = _valid_lock(plan)
    matched = False
    for file_entry in lock["source_inventory"]["components"][0]["files"]:  # type: ignore[index]
        if file_entry["role"] == role:
            # Preserve path/hash/size; only role drifts.
            file_entry["role"] = replacement
            matched = True
            break
    assert matched, f"fixture missing authority role {role}"
    _write_lock(tmp_path, lock)
    assert verify_external_source_authorization(tmp_path, plan).status == "stale"


@pytest.mark.parametrize("role", ("record", "metadata", "wheel", "license-file"))
def test_metadata_role_hash_drift_is_stale(tmp_path: Path, role: str) -> None:
    plan = _plan()
    lock = _valid_lock(plan)
    # Distinct from fixture digests (a/b/c/d/e * 64).
    bogus = "1" * 64
    matched = False
    for entry in lock["content_hashes"]["metadata_files"]:  # type: ignore[index]
        if entry["role"] == role:
            entry["sha256"] = bogus
            matched = True
    for entry in lock["source_inventory"]["components"][0]["files"]:  # type: ignore[index]
        if entry["role"] == role:
            entry["sha256"] = bogus
    for entry in lock["provenance"]["installed_wheel"]["metadata_files"]:  # type: ignore[index]
        if entry["role"] == role:
            entry["sha256"] = bogus
    assert matched, f"fixture missing authority role {role}"
    _write_lock(tmp_path, lock)
    assert verify_external_source_authorization(tmp_path, plan).status == "stale"


def test_duplicate_json_object_key_is_rejected(tmp_path: Path) -> None:
    plan = _plan()
    text = json.dumps(_valid_lock(plan))
    text = text.replace('"package":', '"package": "ignored", "package":', 1)
    _write_lock(tmp_path, text)
    auth = verify_external_source_authorization(tmp_path, plan)
    assert auth.status == "invalid"
    assert "duplicate" in (auth.reason or "")


def test_nan_and_infinity_rejected(tmp_path: Path) -> None:
    plan = _plan()
    for token in ("NaN", "Infinity", "-Infinity"):
        raw = (
            '{"schema_version":"1","kind":"rextio.external-source-authorization",'
            f'"package":"demo_pkg","distribution":"demo-pkg","version":"1.0.0",'
            f'"evil":{token},'
            '"content_hashes":{},"source_inventory":{},"provenance":{},'
            '"license_attestation":{}}'
        )
        _write_lock(tmp_path, raw)
        auth = verify_external_source_authorization(tmp_path, plan)
        assert auth.status == "invalid"
        assert "non-finite" in (auth.reason or "") or "valid JSON" in (auth.reason or "")


def test_deep_json_proves_depth_rejection(tmp_path: Path) -> None:
    plan = _plan()
    lock = _valid_lock(plan)
    nested: object = "leaf"
    for _ in range(40):
        nested = {"x": nested}
    # Keep a valid top-level shape; nest only under an unexpected allowed container
    # by replacing content_hashes with a deep tree that still looks like an object
    # until depth check fires.
    lock["content_hashes"] = nested  # type: ignore[assignment]
    _write_lock(tmp_path, lock)
    auth = verify_external_source_authorization(tmp_path, plan)
    assert auth.status == "invalid"
    assert "nesting" in (auth.reason or "") or "depth" in (auth.reason or "")


def test_malicious_extra_key_does_not_leak_into_reason(tmp_path: Path) -> None:
    plan = _plan()
    lock = _valid_lock(plan)
    secret = "EXFILTRATE_SECRET_TOKEN_xyz"
    lock[secret] = "value"
    _write_lock(tmp_path, lock)
    auth = verify_external_source_authorization(tmp_path, plan)
    assert auth.status == "invalid"
    assert secret not in (auth.reason or "")


def test_forged_free_text_attestation_is_rejected(tmp_path: Path) -> None:
    plan = _plan()
    lock = _valid_lock(plan)
    lock["license_attestation"] = {  # type: ignore[assignment]
        "attestor": "Acme Engineering",
        "attestor_kind": "organization",
        "license_observed": "MIT",
        "accepted": True,
        "not_legal_advice_acknowledged": True,
        "statement": "I accept responsibility. This is not legal advice.",
    }
    _write_lock(tmp_path, lock)
    auth = verify_external_source_authorization(tmp_path, plan)
    assert auth.status in {"incomplete", "invalid"}
    assert not auth.verified


def test_evidence_must_be_exact_closed_ordered_set(tmp_path: Path) -> None:
    plan = _plan()
    lock = _valid_lock(plan)
    # Wrong order.
    lock["provenance"]["evidence"] = [  # type: ignore[index]
        "project-vcs-review",
        "installed-distribution-record",
    ]
    _write_lock(tmp_path, lock)
    assert verify_external_source_authorization(tmp_path, plan).status == "incomplete"
    # Extra entry.
    lock = _valid_lock(plan)
    lock["provenance"]["evidence"] = [  # type: ignore[index]
        "installed-distribution-record",
        "project-vcs-review",
        "extra-evidence",
    ]
    _write_lock(tmp_path, lock)
    assert verify_external_source_authorization(tmp_path, plan).status == "incomplete"


@pytest.mark.parametrize(
    ("relationship", "kind", "ok"),
    (
        ("organization-owner", "organization", True),
        ("organization-owner", "human", False),
        ("human-owner", "human", True),
        ("human-owner", "organization", False),
        ("project-maintainer", "human", True),
        ("project-maintainer", "organization", False),
        ("security-reviewer", "human", True),
        ("security-reviewer", "organization", False),
    ),
)
def test_attestor_relationship_kind_matrix(
    tmp_path: Path,
    relationship: str,
    kind: str,
    ok: bool,
) -> None:
    plan = _plan()
    lock = _valid_lock(plan, relationship=relationship, attestor_kind=kind)
    _write_lock(tmp_path, lock)
    auth = verify_external_source_authorization(tmp_path, plan)
    if ok:
        assert auth.verified
    else:
        assert auth.status == "invalid"
        assert not auth.verified


def test_provenance_subject_mismatch_is_stale(tmp_path: Path) -> None:
    plan = _plan()
    lock = _valid_lock(plan)
    lock["provenance"]["subject_snapshot_sha256"] = "f" * 64  # type: ignore[index]
    _write_lock(tmp_path, lock)
    assert verify_external_source_authorization(tmp_path, plan).status == "stale"


def test_provenance_producer_attestor_mismatch_is_stale(tmp_path: Path) -> None:
    plan = _plan()
    lock = _valid_lock(plan)
    lock["provenance"]["producer"] = "Other Org"  # type: ignore[index]
    _write_lock(tmp_path, lock)
    auth = verify_external_source_authorization(tmp_path, plan)
    assert auth.status == "stale"


def test_symlink_lock_is_rejected(tmp_path: Path) -> None:
    plan = _plan()
    real = tmp_path / "real-lock.json"
    real.write_text(json.dumps(_valid_lock(plan)), encoding="utf-8")
    (tmp_path / SOURCE_LOCK_FILENAME).symlink_to(real)
    auth = verify_external_source_authorization(tmp_path, plan)
    assert auth.status == "invalid"


def test_oversized_lock_rejected(tmp_path: Path) -> None:
    plan = _plan()
    path = tmp_path / SOURCE_LOCK_FILENAME
    path.write_bytes(b"{" + b"a" * (256 * 1024) + b"}")
    auth = verify_external_source_authorization(tmp_path, plan)
    assert auth.status == "invalid"
    assert "size" in (auth.reason or "")


def test_fifo_lock_rejected(tmp_path: Path) -> None:
    plan = _plan()
    path = tmp_path / SOURCE_LOCK_FILENAME
    try:
        os.mkfifo(path)
    except (AttributeError, OSError):
        pytest.skip("FIFO not supported on this platform")
    try:
        auth = verify_external_source_authorization(tmp_path, plan)
        assert auth.status == "invalid"
    finally:
        path.unlink(missing_ok=True)


def test_forged_verified_on_unavailable_plan_via_property() -> None:
    plan = _plan(status="unavailable", reason="broken", source_files=(), modules=())
    forged = ExternalSourceAuthorization(status="verified")
    plan = replace(plan, authorization=forged)
    assert not plan.authorization_verified


def test_authority_bounds_constants_align() -> None:
    assert MAX_SOURCE_MODULES == 256
    assert MAX_SOURCE_LOCK_BYTES == 256 * 1024


def test_module_wire_shape_has_no_size() -> None:
    module = _module()
    assert "size" not in module.to_dict()


def test_authority_path_and_module_name_limits() -> None:
    from rextio.source.external import MAX_AUTHORITY_PATH_LEN, MAX_MODULE_NAME_LEN

    ok_path = "distributions/d/" + ("p" * (MAX_AUTHORITY_PATH_LEN - len("distributions/d/")))
    AuthorityFile(
        path=ok_path,
        sha256="a" * 64,
        size=1,
        role="source-module",
        module_name="m",
    )
    with pytest.raises(ValueError, match="path exceeds"):
        AuthorityFile(
            path=ok_path + "x",
            sha256="a" * 64,
            size=1,
            role="source-module",
            module_name="m",
        )
    ok_name = "m" * MAX_MODULE_NAME_LEN
    AuthorityFile(
        path="distributions/d/x.py",
        sha256="a" * 64,
        size=1,
        role="source-module",
        module_name=ok_name,
    )
    with pytest.raises(ValueError, match="module_name exceeds"):
        AuthorityFile(
            path="distributions/d/x.py",
            sha256="a" * 64,
            size=1,
            role="source-module",
            module_name=ok_name + "x",
        )


def _synthetic_authority(
    *,
    source_count: int,
    metadata_count: int,
    path_pad: int = 0,
) -> tuple[tuple[AuthorityFile, ...], tuple[AuthorityFile, ...]]:
    """Build deterministic synthetic authority entries for lock-size bounds."""
    sources: list[AuthorityFile] = []
    for index in range(source_count):
        name = f"m{index:03d}"
        path = (
            f"distributions/{DIST}/{name}/{'x' * path_pad}__init__.py"
            if path_pad
            else f"distributions/{DIST}/{name}/__init__.py"
        )
        sources.append(
            AuthorityFile(
                path=path,
                sha256=f"{index:064x}"[-64:],
                size=1,
                role="source-module",
                module_name=name,
            )
        )
    metadata: list[AuthorityFile] = []
    roles_cycle = ("record", "metadata", "wheel", "license-file")
    for index in range(metadata_count):
        role = roles_cycle[index % len(roles_cycle)]
        path = (
            f"distributions/{DIST}/meta{'y' * path_pad}{index:03d}/{role}"
            if path_pad
            else f"distributions/{DIST}/meta{index:03d}/{role}"
        )
        metadata.append(
            AuthorityFile(
                path=path,
                sha256=f"{index + 1000:064x}"[-64:],
                size=1,
                role=role,
            )
        )
    return tuple(sources), tuple(metadata)


def test_compact_lock_size_accounts_for_repeated_lists() -> None:
    """Single-list estimates under-count; exact skeleton uses sources×2, metadata×3."""
    sources, metadata = _synthetic_authority(source_count=10, metadata_count=10)
    size = compact_valid_source_lock_size(
        package=PACKAGE,
        distribution=DIST,
        version=VERSION,
        license_observed="MIT",
        source_files=sources,
        metadata_files=metadata,
    )
    # A one-list serialization of the same entries is strictly smaller.
    one_list = {
        "source_files": [
            {
                "module_name": item.module_name,
                "path": item.path,
                "role": item.role,
                "sha256": item.sha256,
                "size": item.size,
            }
            for item in sources
        ],
        "metadata_files": [
            {
                "path": item.path,
                "role": item.role,
                "sha256": item.sha256,
                "size": item.size,
            }
            for item in metadata
        ],
    }
    one_list_bytes = len(
        json.dumps(one_list, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
            "utf-8"
        )
    )
    assert size > one_list_bytes + 4096


def test_authority_bounds_accept_near_limit_exact_lock() -> None:
    # Grow synthetic authority with the same path padding as the one-over case
    # until just under the limit, so the accepted lock is near MAX_SOURCE_LOCK_BYTES.
    accepted_sources: tuple[AuthorityFile, ...] | None = None
    accepted_metadata: tuple[AuthorityFile, ...] | None = None
    accepted_size = 0
    for count in range(1, MAX_SOURCE_MODULES + 1):
        sources, metadata = _synthetic_authority(
            source_count=count,
            metadata_count=count,
            path_pad=100,
        )
        size = compact_valid_source_lock_size(
            package=PACKAGE,
            distribution=DIST,
            version=VERSION,
            license_observed="MIT",
            source_files=sources,
            metadata_files=metadata,
        )
        if size <= MAX_SOURCE_LOCK_BYTES:
            accepted_sources, accepted_metadata, accepted_size = sources, metadata, size
        else:
            break
    assert accepted_sources is not None and accepted_metadata is not None
    assert accepted_size <= MAX_SOURCE_LOCK_BYTES
    # Near-limit: within one typical entry-step of the ceiling (practical, non-huge).
    assert accepted_size > MAX_SOURCE_LOCK_BYTES - 4096
    # Must not raise for a near-limit plan that still fits exactly.
    _enforce_authority_bounds(
        package=PACKAGE,
        distribution=DIST,
        version=VERSION,
        license_observed="MIT",
        source_files=accepted_sources,
        metadata_files=accepted_metadata,
    )


def test_authority_bounds_reject_one_over_exact_lock() -> None:
    # Find the smallest repeated-list count that exceeds the verifier limit.
    # Modest path padding keeps the case practical while crossing 256 KiB via
    # the sources×2 / metadata×3 repetition in the exact compact lock.
    over_sources: tuple[AuthorityFile, ...] | None = None
    over_metadata: tuple[AuthorityFile, ...] | None = None
    over_size = 0
    for count in range(1, MAX_SOURCE_MODULES + 1):
        sources, metadata = _synthetic_authority(
            source_count=count,
            metadata_count=count,
            path_pad=100,
        )
        size = compact_valid_source_lock_size(
            package=PACKAGE,
            distribution=DIST,
            version=VERSION,
            license_observed="MIT",
            source_files=sources,
            metadata_files=metadata,
        )
        if size > MAX_SOURCE_LOCK_BYTES:
            over_sources, over_metadata, over_size = sources, metadata, size
            break
    assert over_sources is not None and over_metadata is not None
    assert over_size > MAX_SOURCE_LOCK_BYTES
    with pytest.raises(ValueError, match="SourceLock size limit"):
        _enforce_authority_bounds(
            package=PACKAGE,
            distribution=DIST,
            version=VERSION,
            license_observed="MIT",
            source_files=over_sources,
            metadata_files=over_metadata,
        )
