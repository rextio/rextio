"""Focused C6.11 scoped Cargo license-policy receipt tests."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

import rextio.artifacts.evidence as evidence_mod
import rextio.build.cargo_license_policy as policy_mod
from rextio.artifacts.evidence import (
    CARGO_LICENSE_POLICY,
    CARGO_LICENSE_POLICY_ACKNOWLEDGEMENT,
    CARGO_LICENSE_POLICY_ACTION_SCOPES,
    CARGO_LICENSE_POLICY_LOCK_FILENAME,
    CARGO_LICENSE_POLICY_LOCK_KIND,
    CARGO_LICENSE_POLICY_LOCK_SCHEMA_VERSION,
    COMPONENT_LICENSE_POLICY_VERIFICATION_SCOPE,
    MAX_CARGO_LICENSE_LOCK_BYTES,
    ArtifactEvidence,
    CargoDepEdge,
    CargoPackageRef,
    ComponentLicenseInventory,
    ComponentLicensePolicyVerification,
    EvidenceFileRef,
    NativeRuntimeInventory,
    SidecarArtifact,
    WheelEntryRef,
    build_intoto_provenance_document,
    canonical_json_bytes,
)
from rextio.build.cargo_license_policy import (
    collect_component_license_policy_verification,
)
from rextio.build.license_inventory import collect_component_license_inventory


def _inventory(
    *,
    first_license: str | None = " MIT/Apache-2.0 ",
    second_license: str | None = "Unicode-3.0",
    root_license: str | None = None,
) -> ComponentLicenseInventory:
    packages = (
        CargoPackageRef(
            name="rextio-generated-native",
            version="0.1.0",
            source=None,
            checksum=None,
            kind="path-root",
            license=root_license,
        ),
        CargoPackageRef(
            name="pyo3",
            version="0.23.5",
            source="registry+https://github.com/rust-lang/crates.io-index",
            checksum="7" * 64,
            kind="registry",
            license=first_license,
        ),
        CargoPackageRef(
            name="unicode-ident",
            version="1.0.18",
            source="registry+https://github.com/rust-lang/crates.io-index",
            checksum="8" * 64,
            kind="registry",
            license=second_license,
        ),
    )
    inventory = collect_component_license_inventory(packages)
    assert inventory is not None
    return inventory


def _inventory_digest(inventory: ComponentLicenseInventory) -> str:
    return hashlib.sha256(canonical_json_bytes(inventory.to_dict())).hexdigest()


def _document(
    inventory: ComponentLicenseInventory,
    *,
    attestor: str = "Acme Engineering",
    attestor_kind: str = "organization",
    attestor_relationship: str = "organization-owner",
) -> dict[str, object]:
    return {
        "schema_version": CARGO_LICENSE_POLICY_LOCK_SCHEMA_VERSION,
        "kind": CARGO_LICENSE_POLICY_LOCK_KIND,
        "scope": COMPONENT_LICENSE_POLICY_VERIFICATION_SCOPE,
        "policy": CARGO_LICENSE_POLICY,
        "component_license_inventory_sha256": _inventory_digest(inventory),
        "registry_components": [
            record.to_dict()
            for record in inventory.records
            if record.kind == "registry"
        ],
        "attestation": {
            "attestor": attestor,
            "attestor_kind": attestor_kind,
            "attestor_relationship": attestor_relationship,
            "decision": "allow",
            "action_scopes": list(CARGO_LICENSE_POLICY_ACTION_SCOPES),
            "acknowledgement": CARGO_LICENSE_POLICY_ACKNOWLEDGEMENT,
        },
    }


def _write_document(
    root: Path,
    document: object,
    *,
    pretty: bool = False,
) -> bytes:
    root.mkdir(parents=True, exist_ok=True)
    if pretty:
        data = (json.dumps(document, indent=2, ensure_ascii=True) + "\n").encode()
    else:
        data = canonical_json_bytes(document)
    (root / CARGO_LICENSE_POLICY_LOCK_FILENAME).write_bytes(data)
    return data


def _collect(
    root: Path,
    inventory: ComponentLicenseInventory,
) -> ComponentLicensePolicyVerification | None:
    return collect_component_license_policy_verification(
        project_root=root,
        component_license_inventory=inventory,
    )


def _artifact_evidence(
    *,
    inventory: ComponentLicenseInventory,
    verification: ComponentLicensePolicyVerification | None,
) -> ArtifactEvidence:
    packages = tuple(
        CargoPackageRef(
            name=record.name,
            version=record.version,
            source=(
                "registry+https://github.com/rust-lang/crates.io-index"
                if record.kind == "registry"
                else None
            ),
            checksum=(
                ("7" if record.name == "pyo3" else "8") * 64
                if record.kind == "registry"
                else None
            ),
            kind=record.kind,
            license=record.license_observed,
        )
        for record in inventory.records
    )
    root = next(package for package in packages if package.kind == "path-root")
    dependencies = tuple(
        CargoDepEdge(
            dependent_ref=root.bom_ref(),
            dependency_ref=package.bom_ref(),
        )
        for package in packages
        if package.kind == "registry"
    )
    native_entry = WheelEntryRef(
        name="_rextio_native.so",
        sha256="9" * 64,
        compressed_size=1,
        uncompressed_size=1,
    )
    return ArtifactEvidence(
        kind="host-extension-wheel",
        status="preview-ready",
        target_triple="x86_64-unknown-linux-gnu",
        subject=EvidenceFileRef(
            logical_path="dist/demo.whl",
            sha256="0" * 64,
            size=1,
            role="host-extension-wheel",
        ),
        sbom=SidecarArtifact(
            format="CycloneDX",
            logical_path="dist/demo.whl.cdx.json",
            sha256="1" * 64,
            size=1,
        ),
        provenance=SidecarArtifact(
            format="in-toto-Statement",
            logical_path="dist/demo.whl.intoto.json",
            sha256="2" * 64,
            size=1,
        ),
        wheel_entries=(native_entry,),
        cargo_packages=packages,
        cargo_dependencies=dependencies,
        native_runtime_inventory=NativeRuntimeInventory(
            format="elf",
            architecture="x86_64",
            inspector="readelf",
            subject_basename=native_entry.name,
            subject_sha256=native_entry.sha256,
            subject_size=native_entry.uncompressed_size,
            wheel_member=native_entry.name,
            wheel_member_sha256=native_entry.sha256,
            wheel_member_size=native_entry.uncompressed_size,
            dependencies=(),
        ),
        component_license_inventory=inventory,
        component_license_policy_verification=verification,
    )


def test_valid_lock_is_exact_deterministic_immutable_and_recollectable(
    tmp_path: Path,
) -> None:
    inventory = _inventory()
    document = _document(inventory)
    compact_root = tmp_path / "compact"
    compact_bytes = _write_document(compact_root, document)

    compact = _collect(compact_root, inventory)
    assert compact is not None
    assert compact.component_license_inventory_sha256 == _inventory_digest(inventory)
    assert compact.lock_file.sha256 == hashlib.sha256(compact_bytes).hexdigest()
    assert compact.lock_file.size == len(compact_bytes)
    assert compact.policy_snapshot_sha256 == hashlib.sha256(
        canonical_json_bytes(document)
    ).hexdigest()
    assert compact.registry_component_bom_refs == tuple(
        sorted(
            record.bom_ref for record in inventory.records if record.kind == "registry"
        )
    )
    payload = compact.to_dict()
    assert json.loads(json.dumps(payload, sort_keys=True)) == payload
    assert payload["complete_for_scope"] is True
    assert payload["global_license_policy_complete"] is False
    assert payload["metadata_only"] is True
    assert payload["generated_root_excluded"] is True
    assert payload["attestor_identity_verified"] is False
    assert payload["signed"] is False
    assert payload["distribution_authorized"] is False
    with pytest.raises(FrozenInstanceError):
        compact.complete = True  # type: ignore[misc]

    pretty_root = tmp_path / "pretty"
    pretty_bytes = _write_document(pretty_root, document, pretty=True)
    pretty = _collect(pretty_root, inventory)
    assert pretty is not None
    assert pretty.policy_snapshot_sha256 == compact.policy_snapshot_sha256
    assert pretty.lock_file.sha256 == hashlib.sha256(pretty_bytes).hexdigest()
    assert pretty.lock_file.sha256 != compact.lock_file.sha256
    # A caller can make its final pre-emission read exact by recollecting and
    # comparing the immutable receipt, including the raw-byte lock reference.
    assert _collect(pretty_root, inventory) == pretty


def test_registry_records_preserve_raw_license_bytes_and_exact_order(
    tmp_path: Path,
) -> None:
    inventory = _inventory(first_license=" MIT OR Apache-2.0 ")
    document = _document(inventory)
    root = tmp_path / "raw"
    _write_document(root, document)
    assert _collect(root, inventory) is not None

    changed = copy.deepcopy(document)
    records = changed["registry_components"]
    assert isinstance(records, list)
    first = records[0]
    assert isinstance(first, dict)
    first["license_observed"] = str(first["license_observed"]).strip()
    _write_document(root, changed)
    assert _collect(root, inventory) is None


def test_artifact_evidence_cross_binds_and_serializes_scoped_receipt(
    tmp_path: Path,
) -> None:
    inventory = _inventory()
    _write_document(tmp_path, _document(inventory))
    receipt = _collect(tmp_path, inventory)
    assert receipt is not None

    evidence = _artifact_evidence(inventory=inventory, verification=receipt)
    assert evidence.to_dict()["component_license_policy_verification"] == (
        receipt.to_dict()
    )

    with pytest.raises(ValueError, match="requires its inventory"):
        replace(
            evidence,
            component_license_inventory=None,
        )
    with pytest.raises(ValueError, match="inventory digest differs"):
        replace(
            evidence,
            component_license_policy_verification=replace(
                receipt,
                component_license_inventory_sha256="0" * 64,
            ),
        )
    with pytest.raises(ValueError, match="registry coverage differs"):
        replace(
            evidence,
            component_license_policy_verification=replace(
                receipt,
                registry_component_bom_refs=(
                    receipt.registry_component_bom_refs[0],
                ),
            ),
        )


def test_provenance_includes_exact_receipt_and_lock_material_only_when_present(
    tmp_path: Path,
) -> None:
    inventory = _inventory()
    lock_bytes = _write_document(tmp_path, _document(inventory))
    receipt = _collect(tmp_path, inventory)
    assert receipt is not None
    evidence = _artifact_evidence(inventory=inventory, verification=receipt)
    assert evidence.subject is not None
    assert evidence.sbom is not None
    sbom_ref = EvidenceFileRef(
        logical_path=evidence.sbom.logical_path,
        sha256=evidence.sbom.sha256,
        size=evidence.sbom.size,
        role="cyclonedx-sbom",
    )

    provenance = build_intoto_provenance_document(
        subject=evidence.subject,
        sbom=sbom_ref,
        inputs=(),
        cargo_packages=evidence.cargo_packages,
        target_triple=evidence.target_triple or "",
        component_license_inventory=inventory,
        component_license_policy_verification=receipt,
    )
    predicate = provenance["predicate"]
    assert isinstance(predicate, dict)
    build_definition = predicate["buildDefinition"]
    run_details = predicate["runDetails"]
    assert isinstance(build_definition, dict)
    assert isinstance(run_details, dict)
    materials = build_definition["resolvedDependencies"]
    internal = build_definition["internalParameters"]
    metadata = run_details["metadata"]
    assert isinstance(materials, list)
    assert isinstance(internal, dict)
    assert isinstance(metadata, dict)
    lock_materials = [
        item
        for item in materials
        if item["uri"] == f"file:{CARGO_LICENSE_POLICY_LOCK_FILENAME}"
    ]
    assert lock_materials == [
        {
            "uri": f"file:{CARGO_LICENSE_POLICY_LOCK_FILENAME}",
            "digest": {"sha256": hashlib.sha256(lock_bytes).hexdigest()},
            "annotations": {
                "rextio:role": "cargo-license-policy-lock",
                "rextio:size": str(len(lock_bytes)),
            },
        }
    ]
    assert internal["scoped_component_license_policy_verified"] is True
    assert internal["component_license_policy_complete"] is False
    assert metadata["rextio:component_license_policy_verification_observed"] is True
    assert metadata["rextio:component_license_policy_verification"] == receipt.to_dict()

    without_receipt = build_intoto_provenance_document(
        subject=evidence.subject,
        sbom=sbom_ref,
        inputs=(),
        cargo_packages=evidence.cargo_packages,
        target_triple=evidence.target_triple or "",
        component_license_inventory=inventory,
    )
    without_predicate = without_receipt["predicate"]
    assert isinstance(without_predicate, dict)
    without_build = without_predicate["buildDefinition"]
    without_run = without_predicate["runDetails"]
    assert isinstance(without_build, dict)
    assert isinstance(without_run, dict)
    without_materials = without_build["resolvedDependencies"]
    without_internal = without_build["internalParameters"]
    without_metadata = without_run["metadata"]
    assert isinstance(without_materials, list)
    assert isinstance(without_internal, dict)
    assert isinstance(without_metadata, dict)
    assert not any(
        item["uri"] == f"file:{CARGO_LICENSE_POLICY_LOCK_FILENAME}"
        for item in without_materials
    )
    assert without_internal["scoped_component_license_policy_verified"] is False
    assert (
        without_metadata["rextio:component_license_policy_verification_observed"]
        is False
    )
    assert "rextio:component_license_policy_verification" not in without_metadata

    with pytest.raises(ValueError, match="requires its inventory"):
        build_intoto_provenance_document(
            subject=evidence.subject,
            sbom=sbom_ref,
            inputs=(),
            cargo_packages=evidence.cargo_packages,
            target_triple=evidence.target_triple or "",
            component_license_policy_verification=receipt,
        )


def test_stale_or_nonexact_lock_document_fails_closed(tmp_path: Path) -> None:
    inventory = _inventory()
    base = _document(inventory)
    variants: list[dict[str, object]] = []

    stale_digest = copy.deepcopy(base)
    stale_digest["component_license_inventory_sha256"] = "0" * 64
    variants.append(stale_digest)

    missing_record = copy.deepcopy(base)
    missing_records = missing_record["registry_components"]
    assert isinstance(missing_records, list)
    missing_records.pop()
    variants.append(missing_record)

    extra_record = copy.deepcopy(base)
    extra_records = extra_record["registry_components"]
    assert isinstance(extra_records, list)
    extra_records.append(copy.deepcopy(extra_records[0]))
    variants.append(extra_record)

    reordered = copy.deepcopy(base)
    reordered_records = reordered["registry_components"]
    assert isinstance(reordered_records, list)
    reordered_records.reverse()
    variants.append(reordered)

    changed_record = copy.deepcopy(base)
    changed_records = changed_record["registry_components"]
    assert isinstance(changed_records, list)
    assert isinstance(changed_records[0], dict)
    changed_records[0]["version"] = "999.0.0"
    variants.append(changed_record)

    extra_top_level = copy.deepcopy(base)
    extra_top_level["comment"] = "not part of the closed lock schema"
    variants.append(extra_top_level)

    extra_attestation = copy.deepcopy(base)
    attestation = extra_attestation["attestation"]
    assert isinstance(attestation, dict)
    attestation["comment"] = "not part of the closed attestation schema"
    variants.append(extra_attestation)

    for index, variant in enumerate(variants):
        root = tmp_path / f"variant-{index}"
        _write_document(root, variant)
        assert _collect(root, inventory) is None


@pytest.mark.parametrize(
    "license_value",
    [
        None,
        "UNKNOWN",
        "unknown license",
        "NOASSERTION",
        "MIT OR NOASSERTION",
        "MIT OR NONE",
        "MIT OR N/A",
        "Apache-2.0 AND NULL",
        "MIT AND unspecified",
        "undefined WITH LLVM-exception",
    ],
)
def test_missing_or_unknown_registry_license_fails_closed(
    tmp_path: Path,
    license_value: str | None,
) -> None:
    inventory = _inventory(first_license=license_value)
    _write_document(tmp_path, _document(inventory))
    assert _collect(tmp_path, inventory) is None


@pytest.mark.parametrize(
    ("attestor_kind", "relationship", "accepted"),
    [
        ("human", "human-owner", True),
        ("organization", "organization-owner", True),
        ("human", "organization-owner", False),
        ("organization", "human-owner", False),
        ("robot", "human-owner", False),
    ],
)
def test_exact_owner_relationship_matrix(
    tmp_path: Path,
    attestor_kind: str,
    relationship: str,
    accepted: bool,
) -> None:
    inventory = _inventory()
    document = _document(
        inventory,
        attestor="Ada Lovelace" if attestor_kind == "human" else "Acme Engineering",
        attestor_kind=attestor_kind,
        attestor_relationship=relationship,
    )
    _write_document(tmp_path, document)
    assert (_collect(tmp_path, inventory) is not None) is accepted


def test_decision_scopes_and_acknowledgement_are_closed(tmp_path: Path) -> None:
    inventory = _inventory()
    base = _document(inventory)
    for index, (field, value) in enumerate(
        (
            ("decision", "deny"),
            ("action_scopes", ["local-build", "package"]),
            ("acknowledgement", "I understand"),
        )
    ):
        document = copy.deepcopy(base)
        attestation = document["attestation"]
        assert isinstance(attestation, dict)
        attestation[field] = value
        root = tmp_path / f"attestation-{index}"
        _write_document(root, document)
        assert _collect(root, inventory) is None


@pytest.mark.parametrize(
    "raw",
    [
        b'{"kind":"first","kind":"second"}',
        b'{"value":NaN}',
        b'{"value":Infinity}',
        b'{"value":-Infinity}',
        b'{"unterminated":',
        b"\xff\xfe\xfd",
    ],
)
def test_malformed_or_ambiguous_json_fails_closed(tmp_path: Path, raw: bytes) -> None:
    (tmp_path / CARGO_LICENSE_POLICY_LOCK_FILENAME).write_bytes(raw)
    assert _collect(tmp_path, _inventory()) is None


def test_deep_json_fails_closed(tmp_path: Path) -> None:
    raw = ("[" * 34 + "0" + "]" * 34).encode()
    (tmp_path / CARGO_LICENSE_POLICY_LOCK_FILENAME).write_bytes(raw)
    assert _collect(tmp_path, _inventory()) is None


def test_empty_and_oversized_locks_fail_closed(tmp_path: Path) -> None:
    empty_root = tmp_path / "empty"
    empty_root.mkdir()
    (empty_root / CARGO_LICENSE_POLICY_LOCK_FILENAME).write_bytes(b"")
    assert _collect(empty_root, _inventory()) is None

    oversized_root = tmp_path / "oversized"
    oversized_root.mkdir()
    (oversized_root / CARGO_LICENSE_POLICY_LOCK_FILENAME).write_bytes(
        b"x" * (MAX_CARGO_LICENSE_LOCK_BYTES + 1)
    )
    assert _collect(oversized_root, _inventory()) is None


def test_nonregular_or_linked_locks_and_symlinked_root_fail_closed(
    tmp_path: Path,
) -> None:
    inventory = _inventory()
    document = _document(inventory)

    symlink_root = tmp_path / "symlink-file"
    symlink_root.mkdir()
    target = symlink_root / "actual.json"
    target.write_bytes(canonical_json_bytes(document))
    (symlink_root / CARGO_LICENSE_POLICY_LOCK_FILENAME).symlink_to(target.name)
    assert _collect(symlink_root, inventory) is None

    hardlink_root = tmp_path / "hardlink-file"
    hardlink_root.mkdir()
    hardlink_target = hardlink_root / "actual.json"
    hardlink_target.write_bytes(canonical_json_bytes(document))
    os.link(hardlink_target, hardlink_root / CARGO_LICENSE_POLICY_LOCK_FILENAME)
    assert _collect(hardlink_root, inventory) is None

    directory_root = tmp_path / "directory-file"
    directory_root.mkdir()
    (directory_root / CARGO_LICENSE_POLICY_LOCK_FILENAME).mkdir()
    assert _collect(directory_root, inventory) is None

    if hasattr(os, "mkfifo"):
        fifo_root = tmp_path / "fifo-file"
        fifo_root.mkdir()
        os.mkfifo(fifo_root / CARGO_LICENSE_POLICY_LOCK_FILENAME)
        assert _collect(fifo_root, inventory) is None

    real_root = tmp_path / "real-root"
    _write_document(real_root, document)
    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(real_root, target_is_directory=True)
    assert _collect(linked_root, inventory) is None


@pytest.mark.skipif(
    os.name == "nt"
    or not hasattr(os, "O_NOFOLLOW")
    or not hasattr(os, "O_DIRECTORY"),
    reason="secure ancestor pinning is POSIX-specific",
)
def test_ancestor_swap_after_root_pin_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inventory = _inventory()
    container = tmp_path / "container"
    project_root = container / "project"
    _write_document(project_root, _document(inventory))

    attacker_container = tmp_path / "attacker-container"
    attacker_root = attacker_container / "project"
    _write_document(
        attacker_root,
        _document(
            inventory,
            attestor="Attacker Owner",
            attestor_kind="human",
            attestor_relationship="human-owner",
        ),
    )
    displaced = tmp_path / "displaced-container"
    original_open = policy_mod.os.open
    swapped = False

    def swapping_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        if (
            not swapped
            and path == CARGO_LICENSE_POLICY_LOCK_FILENAME
            and dir_fd is not None
        ):
            container.rename(displaced)
            container.symlink_to(attacker_container, target_is_directory=True)
            swapped = True
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(policy_mod.os, "open", swapping_open)
    assert _collect(project_root, inventory) is None
    assert swapped is True


def test_generated_path_root_is_excluded_from_rows_but_bound_by_full_digest(
    tmp_path: Path,
) -> None:
    inventory = _inventory(root_license=None)
    changed_root_inventory = _inventory(root_license="Apache-2.0")
    document = _document(inventory)
    _write_document(tmp_path, document)

    receipt = _collect(tmp_path, inventory)
    assert receipt is not None
    assert all(
        reference != next(
            record.bom_ref for record in inventory.records if record.kind == "path-root"
        )
        for reference in receipt.registry_component_bom_refs
    )
    assert receipt.component_license_inventory_sha256 == _inventory_digest(inventory)
    assert _inventory_digest(inventory) != _inventory_digest(changed_root_inventory)
    assert _collect(tmp_path, changed_root_inventory) is None


def test_artifact_binding_rejects_unreconstructable_or_unknown_policy(
    tmp_path: Path,
) -> None:
    inventory = _inventory()
    _write_document(tmp_path, _document(inventory))
    receipt = _collect(tmp_path, inventory)
    assert receipt is not None
    with pytest.raises(ValueError, match="snapshot digest differs"):
        _artifact_evidence(
            inventory=inventory,
            verification=replace(receipt, policy_snapshot_sha256="f" * 64),
        )

    unknown_inventory = _inventory(first_license="MIT OR NONE")
    unknown_document = _document(unknown_inventory)
    unknown_bytes = canonical_json_bytes(unknown_document)
    unknown_receipt = ComponentLicensePolicyVerification(
        component_license_inventory_sha256=_inventory_digest(unknown_inventory),
        lock_file=EvidenceFileRef(
            logical_path=CARGO_LICENSE_POLICY_LOCK_FILENAME,
            sha256=hashlib.sha256(unknown_bytes).hexdigest(),
            size=len(unknown_bytes),
            role="cargo-license-policy-lock",
        ),
        policy_snapshot_sha256=hashlib.sha256(unknown_bytes).hexdigest(),
        registry_component_bom_refs=tuple(
            record.bom_ref
            for record in unknown_inventory.records
            if record.kind == "registry"
        ),
        attestor="Acme Engineering",
        attestor_kind="organization",
        attestor_relationship="organization-owner",
    )
    with pytest.raises(ValueError, match="unknown license"):
        _artifact_evidence(
            inventory=unknown_inventory,
            verification=unknown_receipt,
        )


def test_receipt_model_rejects_type_confusion_and_noncanonical_claims(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inventory = _inventory()
    _write_document(tmp_path, _document(inventory))
    receipt = _collect(tmp_path, inventory)
    assert receipt is not None

    with pytest.raises(TypeError, match="schema"):
        replace(receipt, schema_version=True)
    with pytest.raises(TypeError, match="kind"):
        replace(receipt, kind=1)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="digest"):
        replace(receipt, policy_snapshot_sha256=True)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="tuple"):
        replace(
            receipt,
            registry_component_bom_refs=list(receipt.registry_component_bom_refs),  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError, match="sorted and unique"):
        replace(
            receipt,
            registry_component_bom_refs=tuple(
                reversed(receipt.registry_component_bom_refs)
            ),
        )
    with pytest.raises(ValueError, match="sorted and unique"):
        replace(
            receipt,
            registry_component_bom_refs=(
                receipt.registry_component_bom_refs[0],
                receipt.registry_component_bom_refs[0],
            ),
        )
    with pytest.raises(ValueError, match="attestor"):
        replace(receipt, attestor=" Acme Engineering")
    with pytest.raises(TypeError, match="action scopes"):
        replace(
            receipt,
            action_scopes=list(CARGO_LICENSE_POLICY_ACTION_SCOPES),  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError, match="lock binding"):
        replace(
            receipt,
            lock_file=replace(receipt.lock_file, logical_path="other.json"),
        )
    with pytest.raises(ValueError, match="lock binding"):
        replace(
            receipt,
            lock_file=replace(
                receipt.lock_file,
                size=MAX_CARGO_LICENSE_LOCK_BYTES + 1,
            ),
        )

    for field, bad_value in (
        ("owner_attestation_bound", False),
        ("attestor_identity_verified", True),
        ("metadata_only", False),
        ("generated_root_excluded", False),
        ("license_files_verified", True),
        ("legal_approval_verified", True),
        ("complete_for_scope", False),
        ("global_license_policy_complete", True),
        ("complete", True),
        ("signed", True),
        ("distribution_authorized", True),
    ):
        with pytest.raises(ValueError, match="safety claim"):
            replace(receipt, **{field: bad_value})

    with pytest.raises(ValueError, match="safety claim"):
        replace(receipt, complete=0)  # type: ignore[arg-type]

    monkeypatch.setattr(
        evidence_mod,
        "MAX_COMPONENT_LICENSE_POLICY_VERIFICATION_CHARS",
        1,
    )
    with pytest.raises(ValueError, match="character bound"):
        replace(receipt)
