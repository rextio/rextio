"""Focused C6.12 project-source/generated-Rust owner-policy tests."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from rextio.artifacts.evidence import (
    MAX_PROJECT_SOURCE_LICENSE_LOCK_BYTES,
    PROJECT_SOURCE_LICENSE_POLICY,
    PROJECT_SOURCE_LICENSE_POLICY_ACKNOWLEDGEMENT,
    PROJECT_SOURCE_LICENSE_POLICY_ACTION_SCOPES,
    PROJECT_SOURCE_LICENSE_POLICY_LOCK_FILENAME,
    PROJECT_SOURCE_LICENSE_POLICY_LOCK_KIND,
    PROJECT_SOURCE_LICENSE_POLICY_LOCK_SCHEMA_VERSION,
    PROJECT_SOURCE_LICENSE_POLICY_VERIFICATION_SCOPE,
    EvidenceFileRef,
    ProjectSourceLicensePolicyVerification,
    SourceTransformationVerification,
    build_intoto_provenance_document,
    canonical_json_bytes,
    sha256_hex,
)
from rextio.build.source_license_policy import (
    collect_project_source_license_policy_verification,
)


def _verification() -> SourceTransformationVerification:
    source_inputs = (
        EvidenceFileRef(
            logical_path="app.py",
            sha256="1" * 64,
            size=23,
            role="project-python-source",
        ),
        EvidenceFileRef(
            logical_path="pkg/mod.py",
            sha256="2" * 64,
            size=31,
            role="project-python-source",
        ),
    )
    generated = EvidenceFileRef(
        logical_path=".rextio/generated/rust/src/lib.rs",
        sha256="3" * 64,
        size=47,
        role="generated-rust-input",
    )
    return SourceTransformationVerification(
        source_transformation_inventory_sha256="4" * 64,
        source_input_set_sha256=sha256_hex(
            canonical_json_bytes([item.to_dict() for item in source_inputs])
        ),
        module_ir_sha256="5" * 64,
        function_qualnames=("app.alpha", "pkg.mod.beta"),
        source_inputs=source_inputs,
        generated_rust=generated,
        regenerated_rust_sha256=generated.sha256,
        regenerated_rust_size=generated.size,
        generator_backend="rextio-core-rust-pyo3-v1",
    )


def _verification_digest(verification: SourceTransformationVerification) -> str:
    return sha256_hex(canonical_json_bytes(verification.to_dict()))


def _document(
    verification: SourceTransformationVerification,
    *,
    project_license: str = "MIT",
    generated_license: str = "MIT",
    attestor: str = "Acme Engineering",
    attestor_kind: str = "organization",
    relationship: str = "organization-owner",
) -> dict[str, object]:
    return {
        "schema_version": PROJECT_SOURCE_LICENSE_POLICY_LOCK_SCHEMA_VERSION,
        "kind": PROJECT_SOURCE_LICENSE_POLICY_LOCK_KIND,
        "scope": PROJECT_SOURCE_LICENSE_POLICY_VERIFICATION_SCOPE,
        "policy": PROJECT_SOURCE_LICENSE_POLICY,
        "source_transformation_verification_sha256": _verification_digest(verification),
        "source_input_set_sha256": verification.source_input_set_sha256,
        "project_sources": [item.to_dict() for item in verification.source_inputs],
        "generated_rust": verification.generated_rust.to_dict(),
        "license_declarations": {
            "project_sources": project_license,
            "generated_rust": generated_license,
        },
        "attestation": {
            "attestor": attestor,
            "attestor_kind": attestor_kind,
            "attestor_relationship": relationship,
            "decision": "allow",
            "action_scopes": list(PROJECT_SOURCE_LICENSE_POLICY_ACTION_SCOPES),
            "acknowledgement": PROJECT_SOURCE_LICENSE_POLICY_ACKNOWLEDGEMENT,
        },
    }


def _write(root: Path, document: object, *, pretty: bool = False) -> bytes:
    root.mkdir(parents=True, exist_ok=True)
    data = (
        (json.dumps(document, indent=2, ensure_ascii=True) + "\n").encode()
        if pretty
        else canonical_json_bytes(document)
    )
    (root / PROJECT_SOURCE_LICENSE_POLICY_LOCK_FILENAME).write_bytes(data)
    return data


def _collect(
    root: Path,
    verification: SourceTransformationVerification,
) -> ProjectSourceLicensePolicyVerification | None:
    return collect_project_source_license_policy_verification(
        project_root=root,
        source_transformation_verification=verification,
    )


def test_valid_lock_binds_exact_c610_scope_and_is_immutable(tmp_path: Path) -> None:
    verification = _verification()
    document = _document(verification)
    compact_root = tmp_path / "compact"
    compact_bytes = _write(compact_root, document)
    receipt = _collect(compact_root, verification)
    assert receipt is not None
    assert receipt.source_transformation_verification_sha256 == _verification_digest(verification)
    assert receipt.source_inputs == verification.source_inputs
    assert receipt.source_input_set_sha256 == verification.source_input_set_sha256
    assert receipt.generated_rust == verification.generated_rust
    assert receipt.lock_file.sha256 == hashlib.sha256(compact_bytes).hexdigest()
    assert receipt.policy_document() == document
    assert receipt.policy_snapshot_sha256 == sha256_hex(canonical_json_bytes(document))
    payload = receipt.to_dict()
    assert json.loads(json.dumps(payload, sort_keys=True)) == payload
    assert payload["complete_for_scope"] is True
    assert payload["global_license_policy_complete"] is False
    assert payload["license_declarations_only"] is True
    assert payload["source_ownership_verified"] is False
    assert payload["generated_output_rights_verified"] is False
    assert payload["derivative_work_rights_verified"] is False
    assert payload["spdx_verified"] is False
    assert payload["notice_files_verified"] is False
    assert payload["obligations_verified"] is False
    assert payload["license_compatibility_verified"] is False
    assert payload["legal_approval_verified"] is False
    assert payload["signed"] is False
    assert payload["distribution_authorized"] is False
    with pytest.raises(FrozenInstanceError):
        receipt.complete = True  # type: ignore[misc]

    pretty_root = tmp_path / "pretty"
    pretty_bytes = _write(pretty_root, document, pretty=True)
    pretty = _collect(pretty_root, verification)
    assert pretty is not None
    assert pretty.policy_snapshot_sha256 == receipt.policy_snapshot_sha256
    assert pretty.lock_file.sha256 == hashlib.sha256(pretty_bytes).hexdigest()
    assert pretty.lock_file.sha256 != receipt.lock_file.sha256
    assert _collect(pretty_root, verification) == pretty


def test_stale_nonexact_or_ambiguous_scope_fails_closed(tmp_path: Path) -> None:
    verification = _verification()
    base = _document(verification)
    variants: list[dict[str, object]] = []

    stale_receipt = copy.deepcopy(base)
    stale_receipt["source_transformation_verification_sha256"] = "0" * 64
    variants.append(stale_receipt)

    stale_set = copy.deepcopy(base)
    stale_set["source_input_set_sha256"] = "0" * 64
    variants.append(stale_set)

    missing_source = copy.deepcopy(base)
    sources = missing_source["project_sources"]
    assert isinstance(sources, list)
    sources.pop()
    variants.append(missing_source)

    reordered_sources = copy.deepcopy(base)
    reordered = reordered_sources["project_sources"]
    assert isinstance(reordered, list)
    reordered.reverse()
    variants.append(reordered_sources)

    changed_generated = copy.deepcopy(base)
    generated = changed_generated["generated_rust"]
    assert isinstance(generated, dict)
    generated["sha256"] = "9" * 64
    variants.append(changed_generated)

    extra_top = copy.deepcopy(base)
    extra_top["comment"] = "not in the closed schema"
    variants.append(extra_top)

    extra_declaration = copy.deepcopy(base)
    declarations = extra_declaration["license_declarations"]
    assert isinstance(declarations, dict)
    declarations["fallback"] = "MIT"
    variants.append(extra_declaration)

    for index, variant in enumerate(variants):
        root = tmp_path / f"variant-{index}"
        _write(root, variant)
        assert _collect(root, verification) is None


@pytest.mark.parametrize(
    "license_value",
    [
        "",
        " ",
        " MIT",
        "MIT ",
        "UNKNOWN",
        "unknown license",
        "NOASSERTION",
        "MIT OR NONE",
        "Apache-2.0 AND NULL",
        "undefined WITH LLVM-exception",
    ],
)
@pytest.mark.parametrize("field", ["project_sources", "generated_rust"])
def test_blank_noncanonical_or_unknown_license_declaration_fails_closed(
    tmp_path: Path,
    field: str,
    license_value: str,
) -> None:
    verification = _verification()
    document = _document(verification)
    declarations = document["license_declarations"]
    assert isinstance(declarations, dict)
    declarations[field] = license_value
    _write(tmp_path, document)
    assert _collect(tmp_path, verification) is None


@pytest.mark.parametrize(
    ("kind", "relationship", "accepted"),
    [
        ("human", "human-owner", True),
        ("organization", "organization-owner", True),
        ("human", "organization-owner", False),
        ("organization", "human-owner", False),
        ("robot", "human-owner", False),
    ],
)
def test_owner_attestation_relationship_and_fixed_claims(
    tmp_path: Path,
    kind: str,
    relationship: str,
    accepted: bool,
) -> None:
    verification = _verification()
    document = _document(
        verification,
        attestor="Ada Lovelace" if kind == "human" else "Acme Engineering",
        attestor_kind=kind,
        relationship=relationship,
    )
    _write(tmp_path, document)
    assert (_collect(tmp_path, verification) is not None) is accepted


@pytest.mark.parametrize(
    "raw",
    [
        b'{"kind":"first","kind":"second"}',
        b'{"value":NaN}',
        b'{"value":Infinity}',
        b'{"unterminated":',
        b"\xff\xfe\xfd",
    ],
)
def test_malformed_or_ambiguous_json_fails_closed(tmp_path: Path, raw: bytes) -> None:
    (tmp_path / PROJECT_SOURCE_LICENSE_POLICY_LOCK_FILENAME).write_bytes(raw)
    assert _collect(tmp_path, _verification()) is None


def test_deep_empty_and_oversized_locks_fail_closed(tmp_path: Path) -> None:
    verification = _verification()
    deep_root = tmp_path / "deep"
    deep_root.mkdir()
    (deep_root / PROJECT_SOURCE_LICENSE_POLICY_LOCK_FILENAME).write_bytes(
        ("[" * 34 + "0" + "]" * 34).encode()
    )
    assert _collect(deep_root, verification) is None

    empty_root = tmp_path / "empty"
    empty_root.mkdir()
    (empty_root / PROJECT_SOURCE_LICENSE_POLICY_LOCK_FILENAME).write_bytes(b"")
    assert _collect(empty_root, verification) is None

    oversized_root = tmp_path / "oversized"
    oversized_root.mkdir()
    (oversized_root / PROJECT_SOURCE_LICENSE_POLICY_LOCK_FILENAME).write_bytes(
        b"x" * (MAX_PROJECT_SOURCE_LICENSE_LOCK_BYTES + 1)
    )
    assert _collect(oversized_root, verification) is None


def test_symlink_hardlink_and_symlinked_ancestor_fail_closed(tmp_path: Path) -> None:
    verification = _verification()
    document = _document(verification)
    target_root = tmp_path / "target"
    target = target_root / PROJECT_SOURCE_LICENSE_POLICY_LOCK_FILENAME
    _write(target_root, document)

    symlink_root = tmp_path / "symlink-file"
    symlink_root.mkdir()
    (symlink_root / PROJECT_SOURCE_LICENSE_POLICY_LOCK_FILENAME).symlink_to(target)
    assert _collect(symlink_root, verification) is None

    hardlink_root = tmp_path / "hardlink-file"
    hardlink_root.mkdir()
    os.link(target, hardlink_root / PROJECT_SOURCE_LICENSE_POLICY_LOCK_FILENAME)
    assert _collect(hardlink_root, verification) is None
    assert _collect(target_root, verification) is None

    real_parent = tmp_path / "real-parent"
    real_root = real_parent / "project"
    _write(real_root, document)
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    assert _collect(linked_parent / "project", verification) is None


def test_forged_c610_or_noncanonical_receipt_model_fails_closed(tmp_path: Path) -> None:
    verification = _verification()
    _write(tmp_path, _document(verification))
    receipt = _collect(tmp_path, verification)
    assert receipt is not None

    forged = _verification()
    object.__setattr__(forged, "source_inputs", list(forged.source_inputs))
    assert _collect(tmp_path, forged) is None

    normalized_forgery = _verification()
    object.__setattr__(
        normalized_forgery,
        "generator_backend",
        f" {normalized_forgery.generator_backend} ",
    )
    assert _collect(tmp_path, normalized_forgery) is None

    boolean_schema_forgery = _verification()
    object.__setattr__(boolean_schema_forgery, "schema_version", True)
    assert _collect(tmp_path, boolean_schema_forgery) is None

    with pytest.raises(ValueError, match="snapshot digest differs"):
        replace(receipt, policy_snapshot_sha256="0" * 64)
    with pytest.raises(ValueError, match="input-set digest differs"):
        replace(receipt, source_input_set_sha256="0" * 64)
    with pytest.raises(ValueError, match="safety claim"):
        replace(receipt, source_ownership_verified=True)
    for field in (
        "notice_files_verified",
        "obligations_verified",
        "license_compatibility_verified",
        "derivative_work_rights_verified",
    ):
        with pytest.raises(ValueError, match="safety claim"):
            replace(receipt, **{field: True})
    with pytest.raises(ValueError, match="safety claim"):
        replace(receipt, complete=0)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="lock binding"):
        replace(
            receipt,
            lock_file=replace(receipt.lock_file, logical_path="other.json"),
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "declaration",
        "policy-digest",
        "fixed-bool",
        "lock-ref",
        "source-ref",
        "generated-ref",
    ],
)
def test_provenance_binding_reconstructs_low_level_mutated_receipt(
    tmp_path: Path,
    mutation: str,
) -> None:
    verification = _verification()
    _write(tmp_path, _document(verification))
    receipt = _collect(tmp_path, verification)
    assert receipt is not None
    forged = copy.deepcopy(receipt)
    if mutation == "declaration":
        object.__setattr__(forged, "project_source_license_declared", "Apache-2.0")
    elif mutation == "policy-digest":
        object.__setattr__(forged, "policy_snapshot_sha256", "f" * 64)
    elif mutation == "fixed-bool":
        object.__setattr__(forged, "source_ownership_verified", True)
    elif mutation == "lock-ref":
        object.__setattr__(forged.lock_file, "logical_path", "other.json")
    elif mutation == "source-ref":
        object.__setattr__(forged.source_inputs[0], "sha256", "e" * 64)
    elif mutation == "generated-ref":
        object.__setattr__(forged.generated_rust, "sha256", "d" * 64)
    else:  # pragma: no cover - closed parametrization guard
        raise AssertionError(mutation)

    with pytest.raises((TypeError, ValueError)):
        build_intoto_provenance_document(
            subject=EvidenceFileRef(
                logical_path="dist/demo.whl",
                sha256="6" * 64,
                size=1,
                role="host-extension-wheel",
            ),
            sbom=EvidenceFileRef(
                logical_path="dist/demo.whl.cdx.json",
                sha256="7" * 64,
                size=1,
                role="cyclonedx-sbom",
            ),
            inputs=verification.source_inputs,
            cargo_packages=(),
            target_triple="x86_64-unknown-linux-gnu",
            source_transformation_verification=verification,
            project_source_license_policy_verification=forged,
        )
