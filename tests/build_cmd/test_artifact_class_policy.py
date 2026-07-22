"""Focused C6.15 artifact-class owner-policy tests."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from rextio.artifacts.evidence import (
    ANALYSIS_INPUT_VERIFICATION_KIND,
    ARTIFACT_CLASS_POLICY,
    ARTIFACT_CLASS_POLICY_ACKNOWLEDGEMENT,
    ARTIFACT_CLASS_POLICY_ACTION_SCOPES,
    ARTIFACT_CLASS_POLICY_LOCK_FILENAME,
    ARTIFACT_CLASS_POLICY_LOCK_KIND,
    ARTIFACT_CLASS_POLICY_LOCK_SCHEMA_VERSION,
    ARTIFACT_EVIDENCE_SCOPE,
    ARTIFACT_POLICY_COVERAGE_CLASS_IDS,
    COMPONENT_LICENSE_POLICY_VERIFICATION_KIND,
    MAX_ARTIFACT_CLASS_POLICY_LOCK_BYTES,
    PROJECT_SOURCE_LICENSE_POLICY_VERIFICATION_KIND,
    SOURCE_TRANSFORMATION_VERIFICATION_KIND,
    ArtifactClassPolicyDeclaration,
    ArtifactPolicyCoverageClass,
    ArtifactPolicyCoverageInventory,
    artifact_class_policy_dispositions,
    artifact_policy_coverage_inventory_digest,
    artifact_policy_partition_digest,
    canonical_json_bytes,
    sha256_hex,
)
from rextio.build.artifact_class_policy import (
    collect_artifact_class_policy_verification,
)


def _coverage() -> ArtifactPolicyCoverageInventory:
    specs = (
        (
            1,
            "byte-bound",
            "scoped-owner-declaration-bound",
            PROJECT_SOURCE_LICENSE_POLICY_VERIFICATION_KIND,
            "scoped-replay-input-bound",
            SOURCE_TRANSFORMATION_VERIFICATION_KIND,
        ),
        (
            0,
            "byte-bound",
            "unassessed",
            None,
            "scoped-analysis-input-projection-bound",
            ANALYSIS_INPUT_VERIFICATION_KIND,
        ),
        (1, "byte-bound", "unassessed", None, "unassessed", None),
        (
            1,
            "byte-bound",
            "scoped-owner-declaration-bound",
            PROJECT_SOURCE_LICENSE_POLICY_VERIFICATION_KIND,
            "scoped-replay-output-verified",
            SOURCE_TRANSFORMATION_VERIFICATION_KIND,
        ),
        (0, "byte-bound", "unassessed", None, "unassessed", None),
        (1, "byte-bound", "unassessed", None, "unassessed", None),
        (
            1,
            "declared-checksum-bound",
            "scoped-cargo-owner-receipt-bound",
            COMPONENT_LICENSE_POLICY_VERIFICATION_KIND,
            "not-applicable",
            None,
        ),
        (1, "logical-only", "unassessed", None, "not-applicable", None),
        (1, "byte-bound", "unassessed", None, "not-applicable", None),
        (1, "logical-only", "unassessed", None, "not-applicable", None),
        (2, "byte-bound", "unassessed", None, "unassessed", None),
        (1, "byte-bound", "unassessed", None, "unassessed", None),
        (0, "byte-bound", "unassessed", None, "unassessed", None),
    )
    rows = tuple(
        ArtifactPolicyCoverageClass(
            class_id=class_id,
            observed_count=count,
            canonical_identity_set_sha256=sha256_hex(class_id.encode()),
            identity_state=identity_state,
            license_policy_state=license_state,
            license_policy_receipt_kind=license_kind,
            license_policy_receipt_sha256=("a" * 64 if license_kind else None),
            transformation_provenance_state=transformation_state,
            transformation_provenance_receipt_kind=transformation_kind,
            transformation_provenance_receipt_sha256=(
                "b" * 64 if transformation_kind else None
            ),
        )
        for class_id, (
            count,
            identity_state,
            license_state,
            license_kind,
            transformation_state,
            transformation_kind,
        ) in zip(ARTIFACT_POLICY_COVERAGE_CLASS_IDS, specs, strict=True)
    )
    return ArtifactPolicyCoverageInventory(
        classes=rows,
        observed_component_count=sum(row.observed_count for row in rows),
        canonical_partition_sha256=artifact_policy_partition_digest(rows),
    )


def _document(coverage: ArtifactPolicyCoverageInventory) -> dict[str, object]:
    declarations = tuple(
        ArtifactClassPolicyDeclaration(
            coverage=row,
            license_policy_disposition=artifact_class_policy_dispositions(row)[0],
            transformation_provenance_disposition=(
                artifact_class_policy_dispositions(row)[1]
            ),
        )
        for row in coverage.classes
    )
    return {
        "schema_version": ARTIFACT_CLASS_POLICY_LOCK_SCHEMA_VERSION,
        "kind": ARTIFACT_CLASS_POLICY_LOCK_KIND,
        "scope": ARTIFACT_EVIDENCE_SCOPE,
        "policy": ARTIFACT_CLASS_POLICY,
        "artifact_policy_coverage_inventory_sha256": (
            artifact_policy_coverage_inventory_digest(coverage)
        ),
        "canonical_partition_sha256": coverage.canonical_partition_sha256,
        "classes": [item.to_dict() for item in declarations],
        "attestation": {
            "attestor": "Acme Engineering",
            "attestor_kind": "organization",
            "attestor_relationship": "organization-owner",
            "decision": "allow",
            "action_scopes": list(ARTIFACT_CLASS_POLICY_ACTION_SCOPES),
            "acknowledgement": ARTIFACT_CLASS_POLICY_ACKNOWLEDGEMENT,
        },
    }


def _write(root: Path, document: object) -> bytes:
    root.mkdir(parents=True, exist_ok=True)
    data = canonical_json_bytes(document)
    (root / ARTIFACT_CLASS_POLICY_LOCK_FILENAME).write_bytes(data)
    return data


def _collect(
    root: Path,
    coverage: ArtifactPolicyCoverageInventory,
    *,
    occupied_logical_paths: tuple[str, ...] = (),
):
    return collect_artifact_class_policy_verification(
        project_root=root,
        artifact_policy_coverage_inventory=coverage,
        occupied_logical_paths=occupied_logical_paths,
    )


def test_valid_lock_binds_exact_c614_partition_and_remains_non_authorizing(
    tmp_path: Path,
) -> None:
    coverage = _coverage()
    document = _document(coverage)
    lock_bytes = _write(tmp_path, document)

    receipt = _collect(tmp_path, coverage)

    assert receipt is not None
    assert receipt.artifact_policy_coverage_inventory_sha256 == (
        artifact_policy_coverage_inventory_digest(coverage)
    )
    assert receipt.canonical_partition_sha256 == coverage.canonical_partition_sha256
    assert tuple(item.coverage for item in receipt.classes) == coverage.classes
    assert receipt.lock_file.sha256 == hashlib.sha256(lock_bytes).hexdigest()
    assert receipt.policy_snapshot_sha256 == sha256_hex(canonical_json_bytes(document))
    payload = receipt.to_dict()
    assert json.loads(json.dumps(payload, sort_keys=True)) == payload
    assert payload["complete_for_observed_classes"] is True
    assert payload["scope_complete"] is False
    assert payload["declarations_only"] is True
    assert payload["attestor_identity_verified"] is False
    assert payload["spdx_verified"] is False
    assert payload["license_files_verified"] is False
    assert payload["notice_files_verified"] is False
    assert payload["obligations_verified"] is False
    assert payload["license_compatibility_verified"] is False
    assert payload["source_ownership_verified"] is False
    assert payload["derivative_work_rights_verified"] is False
    assert payload["legal_approval_verified"] is False
    assert payload["technical_provenance_verified"] is False
    assert payload["global_license_policy_complete"] is False
    assert payload["global_transformation_provenance_complete"] is False
    assert payload["complete"] is False
    assert payload["signed"] is False
    assert payload["distribution_authorized"] is False
    assert "app.py" not in json.dumps(payload, sort_keys=True)
    with pytest.raises(ValueError, match="safety claim"):
        replace(receipt, license_files_verified=True)
    with pytest.raises(FrozenInstanceError):
        receipt.complete = True  # type: ignore[misc]


def test_missing_lock_is_an_optional_omission(tmp_path: Path) -> None:
    assert _collect(tmp_path, _coverage()) is None


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "extra", "reordered"])
def test_nonexact_or_noncanonical_class_rows_fail_closed(
    tmp_path: Path,
    mutation: str,
) -> None:
    coverage = _coverage()
    document = _document(coverage)
    classes = document["classes"]
    assert isinstance(classes, list)
    if mutation == "missing":
        classes.pop()
    elif mutation == "duplicate":
        classes[1] = copy.deepcopy(classes[0])
    elif mutation == "extra":
        classes.append(copy.deepcopy(classes[-1]))
    else:
        classes.reverse()
    _write(tmp_path, document)

    assert _collect(tmp_path, coverage) is None


@pytest.mark.parametrize(
    "mutation",
    ["coverage-digest", "partition-digest", "coverage-row", "boolean-count"],
)
def test_stale_or_type_confused_c614_binding_fails_closed(
    tmp_path: Path,
    mutation: str,
) -> None:
    coverage = _coverage()
    document = _document(coverage)
    if mutation == "coverage-digest":
        document["artifact_policy_coverage_inventory_sha256"] = "0" * 64
    elif mutation == "partition-digest":
        document["canonical_partition_sha256"] = "0" * 64
    else:
        classes = document["classes"]
        assert isinstance(classes, list)
        first = classes[0]
        assert isinstance(first, dict)
        row = first["coverage"]
        assert isinstance(row, dict)
        if mutation == "coverage-row":
            row["canonical_identity_set_sha256"] = "0" * 64
        else:
            row["observed_count"] = True
    _write(tmp_path, document)

    assert _collect(tmp_path, coverage) is None


def test_lock_for_another_valid_c614_inventory_fails_closed(tmp_path: Path) -> None:
    coverage = _coverage()
    _write(tmp_path, _document(coverage))
    changed_rows = (replace(coverage.classes[0], observed_count=2), *coverage.classes[1:])
    changed = replace(
        coverage,
        classes=changed_rows,
        observed_component_count=coverage.observed_component_count + 1,
        canonical_partition_sha256=artifact_policy_partition_digest(changed_rows),
    )

    assert _collect(tmp_path, changed) is None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("license_policy_disposition", "owner-declared-allow"),
        ("transformation_provenance_disposition", "owner-declared-unverified"),
        ("license_policy_disposition", "unknown"),
    ],
)
def test_invalid_or_weakened_disposition_fails_closed(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    coverage = _coverage()
    document = _document(coverage)
    classes = document["classes"]
    assert isinstance(classes, list)
    first = classes[0]
    assert isinstance(first, dict)
    first[field] = value
    _write(tmp_path, document)

    assert _collect(tmp_path, coverage) is None


def test_duplicate_key_json_fails_closed(tmp_path: Path) -> None:
    (tmp_path / ARTIFACT_CLASS_POLICY_LOCK_FILENAME).write_bytes(
        b'{"schema_version":"1","schema_version":"1"}'
    )

    assert _collect(tmp_path, _coverage()) is None


def test_deep_empty_and_oversized_locks_fail_closed(tmp_path: Path) -> None:
    coverage = _coverage()
    deep_root = tmp_path / "deep"
    deep_root.mkdir()
    (deep_root / ARTIFACT_CLASS_POLICY_LOCK_FILENAME).write_bytes(
        ("[" * 34 + "0" + "]" * 34).encode()
    )
    assert _collect(deep_root, coverage) is None

    empty_root = tmp_path / "empty"
    empty_root.mkdir()
    (empty_root / ARTIFACT_CLASS_POLICY_LOCK_FILENAME).write_bytes(b"")
    assert _collect(empty_root, coverage) is None

    oversized_root = tmp_path / "oversized"
    oversized_root.mkdir()
    (oversized_root / ARTIFACT_CLASS_POLICY_LOCK_FILENAME).write_bytes(
        b"x" * (MAX_ARTIFACT_CLASS_POLICY_LOCK_BYTES + 1)
    )
    assert _collect(oversized_root, coverage) is None


def test_symlink_and_hardlink_locks_fail_closed(tmp_path: Path) -> None:
    coverage = _coverage()
    target_root = tmp_path / "target"
    target = target_root / ARTIFACT_CLASS_POLICY_LOCK_FILENAME
    _write(target_root, _document(coverage))

    symlink_root = tmp_path / "symlink"
    symlink_root.mkdir()
    try:
        (symlink_root / ARTIFACT_CLASS_POLICY_LOCK_FILENAME).symlink_to(target)
    except OSError as exc:  # pragma: no cover - platform policy
        pytest.skip(f"symlink creation unavailable: {exc}")
    assert _collect(symlink_root, coverage) is None

    hardlink_root = tmp_path / "hardlink"
    hardlink_root.mkdir()
    try:
        os.link(target, hardlink_root / ARTIFACT_CLASS_POLICY_LOCK_FILENAME)
    except OSError as exc:  # pragma: no cover - filesystem policy
        pytest.skip(f"hardlink creation unavailable: {exc}")
    assert _collect(hardlink_root, coverage) is None
    assert _collect(target_root, coverage) is None


@pytest.mark.parametrize(
    "occupied",
    [
        ARTIFACT_CLASS_POLICY_LOCK_FILENAME,
        "REXTIO.ARTIFACT-POLICY.LOCK.JSON",
    ],
)
def test_occupied_policy_lock_path_or_alias_fails_closed(
    tmp_path: Path,
    occupied: str,
) -> None:
    coverage = _coverage()
    _write(tmp_path, _document(coverage))

    assert _collect(tmp_path, coverage, occupied_logical_paths=(occupied,)) is None
