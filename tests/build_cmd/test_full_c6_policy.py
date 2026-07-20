"""Focused adversarial tests for the strict final Full C6 policy receipt."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import json

import pytest

import rextio.build.full_c6_policy as policy_module
from rextio.artifacts.evidence import ARTIFACT_POLICY_COVERAGE_CLASS_IDS
from rextio.artifacts.full_authorization import FULL_C6_SCOPE
from rextio.build.full_c6_policy import (
    FULL_C6_EXTERNAL_POLICY_CLASS_IDS,
    FULL_C6_OWNER_ACKNOWLEDGEMENT,
    FULL_C6_OWNER_ACTION_SCOPES,
    FULL_C6_OWNER_AUTHENTICATION,
    FULL_C6_POLICY_CLASS_IDS,
    FullC6LicenseEvidence,
    FullC6OwnerDeclaration,
    FullC6PolicyError,
    FullC6PolicyFileIdentity,
    FullC6PolicyInputRow,
    FullC6PolicyReceipt,
    FullC6TransformationRecord,
    full_c6_policy_digest,
)


_NA_LICENSE = {
    "file-input:generated-cargo-lock": "not-applicable-build-input",
    "native-runtime:logical-system-leaf": "not-applicable-system-leaf",
    "file-input:policy-lock": "not-applicable-build-input",
}
_SOURCES = {
    "file-input:project-python-source",
    "file-input:present-project-python-stub",
    "external-source:python-source",
}
_OUTPUTS = {
    "file-input:generated-python-input",
    "file-input:generated-rust-lib",
    "file-input:generated-rust-build-input",
}
_CONTENT = set(FULL_C6_POLICY_CLASS_IDS) - {
    "cargo-component:registry-package",
    "cargo-component:path-root-package",
    "native-runtime:logical-system-leaf",
}
_IDENTITIES = {
    "file-input:project-python-source": "project/src/app.py",
    "file-input:present-project-python-stub": "project/src/app.pyi",
    "file-input:generated-python-input": "generated/python/wrapper.py",
    "file-input:generated-rust-lib": "generated/rust/src/lib.rs",
    "file-input:generated-rust-build-input": "generated/rust/build.rs",
    "file-input:generated-cargo-lock": "generated/rust/Cargo.lock",
    "cargo-component:registry-package": "cargo:serde@1.0.0#registry",
    "cargo-component:path-root-package": "cargo:rextio-generated@0.1.4#path-root",
    "wheel-entry:packaged-native-runtime-member": "wheel/rextio/libnative.so",
    "native-runtime:logical-system-leaf": "system:libc.so.6",
    "file-input:policy-lock": "policy/rextio.policy.lock.json",
    "wheel-output:subject": "dist/pkg-0.1.0-cp311-cp311-manylinux.whl",
    "wheel-entry:other": "wheel/pkg/__init__.py",
    "external-source:wheel-archive": "external/pkg-1.0-py3-none-any.whl",
    "external-source:python-source": "external/pkg/__init__.py",
    "external-source:distribution-metadata": "external/pkg-1.0.dist-info/METADATA",
    "external-source:license-file": "external/pkg-1.0.dist-info/licenses/LICENSE",
}


def _file(
    path: str,
    *,
    role: str = "license-file",
    digest: str = "a" * 64,
) -> FullC6PolicyFileIdentity:
    return FullC6PolicyFileIdentity(
        logical_path=path,
        sha256=digest,
        size=101,
        role=role,
    )


def _license(
    *,
    declared: str = "MIT",
    detected: str = "MIT",
    files: tuple[FullC6PolicyFileIdentity, ...] | None = None,
) -> FullC6LicenseEvidence:
    return FullC6LicenseEvidence(
        declared_spdx=declared,
        detected_spdx=detected,
        detector_receipt_sha256="b" * 64,
        license_files=files or (_file("licenses/PROJECT-LICENSE"),),
    )


def _disposition(class_id: str) -> str:
    if class_id in _SOURCES:
        return "exact-source-input"
    if class_id in _OUTPUTS:
        return "exact-generated-output"
    if class_id in {"file-input:generated-cargo-lock", "file-input:policy-lock"}:
        return "not-applicable-build-input"
    if class_id == "native-runtime:logical-system-leaf":
        return "not-applicable-system-leaf"
    return "not-applicable-nontransformable"


def _rows() -> tuple[FullC6PolicyInputRow, ...]:
    result: list[FullC6PolicyInputRow] = []
    for index, class_id in enumerate(FULL_C6_POLICY_CLASS_IDS, start=1):
        if class_id in _CONTENT:
            mode = "content-sha256"
            digest: str | None = f"{index:064x}"
            size: int | None = 100 + index
        elif class_id == "cargo-component:registry-package":
            mode = "cargo-registry-checksum"
            digest = f"{index:064x}"
            size = None
        elif class_id == "cargo-component:path-root-package":
            mode = "source-tree-sha256"
            digest = f"{index:064x}"
            size = None
        else:
            mode = "logical-system-leaf"
            digest = None
            size = None
        license_disposition = _NA_LICENSE.get(class_id, "owner-approved-allow")
        result.append(
            FullC6PolicyInputRow(
                class_id=class_id,
                canonical_identity=_IDENTITIES[class_id],
                identity_mode=mode,
                sha256=digest,
                size=size,
                license_disposition=license_disposition,
                transformation_disposition=_disposition(class_id),
                license_evidence=(
                    _license() if license_disposition == "owner-approved-allow" else None
                ),
            )
        )
    return tuple(result)


def _transformations(
    rows: tuple[FullC6PolicyInputRow, ...],
) -> tuple[FullC6TransformationRecord, ...]:
    by_id = {row.canonical_identity: row for row in rows}
    sources = tuple(
        sorted(
            (row.canonical_identity for row in rows if row.class_id in _SOURCES),
            key=str.casefold,
        )
    )
    source_digests = tuple(by_id[value].canonical_identity_sha256 for value in sources)
    outputs = tuple(row for row in rows if row.class_id in _OUTPUTS)
    return tuple(
        FullC6TransformationRecord(
            record_id=f"transform:{index:03d}",
            kind=(
                "python-wrapper-generation-v1"
                if output.class_id == "file-input:generated-python-input"
                else "python-to-rust-lowering-v1"
            ),
            source_identities=sources,
            source_identity_sha256s=source_digests,
            output_identity=output.canonical_identity,
            output_identity_sha256=output.canonical_identity_sha256,
            generator_sha256="c" * 64,
            analysis_sha256="d" * 64,
            lowered_ir_sha256="e" * 64,
        )
        for index, output in enumerate(outputs, start=1)
    )


def _owner(**changes: object) -> FullC6OwnerDeclaration:
    values: dict[str, object] = {
        "owner_identity": "Acme Engineering",
        "owner_role": "organization-owner",
        "trusted_public_key_sha256": "f" * 64,
    }
    values.update(changes)
    return FullC6OwnerDeclaration(**values)  # type: ignore[arg-type]


def _receipt() -> FullC6PolicyReceipt:
    rows = _rows()
    transformations = _transformations(rows)
    return FullC6PolicyReceipt(
        rows=rows,
        transformations=transformations,
        owner_declaration=_owner(),
    )


def test_frozen_vocabulary_is_exact_c615_classes_plus_c52_authority_inputs() -> None:
    assert FULL_C6_POLICY_CLASS_IDS == (
        *ARTIFACT_POLICY_COVERAGE_CLASS_IDS,
        *FULL_C6_EXTERNAL_POLICY_CLASS_IDS,
    )
    assert FULL_C6_EXTERNAL_POLICY_CLASS_IDS == (
        "external-source:wheel-archive",
        "external-source:python-source",
        "external-source:distribution-metadata",
        "external-source:license-file",
    )


def test_complete_receipt_is_deterministic_deeply_rebuilt_and_non_authorizing() -> None:
    rows = _rows()
    transformations = _transformations(rows)
    declaration = _owner()
    receipt = FullC6PolicyReceipt(rows, transformations, declaration)
    original = json.loads(json.dumps(receipt.to_dict(), sort_keys=True))

    assert receipt.scope == FULL_C6_SCOPE
    assert receipt.to_dict() == original
    assert len(receipt.digest) == 64
    assert len(receipt.license_policy_sha256) == 64
    assert len(receipt.transformation_policy_sha256) == 64
    assert receipt.distribution_authorized is False
    assert original["complete_for_scope"] is True
    assert original["all_dispositions_closed"] is True
    assert original["owner_allow_declaration_bound"] is True
    assert original["authentication"] == FULL_C6_OWNER_AUTHENTICATION
    assert original["owner_allow_declaration_authenticated"] is False
    assert original["legal_advice_inferred"] is False
    assert original["distribution_authorized"] is False
    with pytest.raises(FrozenInstanceError):
        receipt.rows = ()  # type: ignore[misc]

    object.__setattr__(rows[0], "canonical_identity", "attacker/replaced.py")
    object.__setattr__(declaration, "trusted_public_key_sha256", "0" * 64)
    assert receipt.to_dict() == original


@pytest.mark.parametrize("mutation", ["missing-class", "reordered", "alias", "extra-class-row"])
def test_nonexact_noncanonical_or_aliased_rows_fail_closed(mutation: str) -> None:
    rows = list(_rows())
    if mutation == "missing-class":
        rows.pop()
    elif mutation == "reordered":
        rows[0], rows[1] = rows[1], rows[0]
    elif mutation == "alias":
        rows[1] = replace(rows[1], canonical_identity=rows[0].canonical_identity.upper())
    else:
        rows.insert(1, replace(rows[0], canonical_identity="project/src/second.py"))
    candidate = tuple(rows)

    with pytest.raises(FullC6PolicyError):
        full_c6_policy_digest(candidate, _transformations(_rows()), _owner())


def test_boolean_size_and_invalid_identity_mode_are_rejected() -> None:
    row = _rows()[0]
    with pytest.raises(TypeError, match="integer"):
        replace(row, size=True)
    with pytest.raises(FullC6PolicyError, match="identity mode"):
        replace(row, identity_mode="logical-system-leaf")
    system = next(item for item in _rows() if item.class_id == "native-runtime:logical-system-leaf")
    with pytest.raises(FullC6PolicyError, match="must not claim"):
        replace(system, sha256="0" * 64)


def test_applicable_and_nonapplicable_license_dispositions_are_closed() -> None:
    applicable = _rows()[0]
    with pytest.raises(FullC6PolicyError, match="require exact license evidence"):
        replace(applicable, license_evidence=None)
    with pytest.raises(FullC6PolicyError, match="not closed"):
        replace(applicable, license_disposition="unassessed")
    cargo_lock = next(
        item for item in _rows() if item.class_id == "file-input:generated-cargo-lock"
    )
    with pytest.raises(FullC6PolicyError, match="must not carry"):
        replace(cargo_lock, license_evidence=_license())
    with pytest.raises(FullC6PolicyError, match="not closed"):
        replace(cargo_lock, license_disposition="owner-approved-allow")


@pytest.mark.parametrize(
    ("declared", "detected"),
    [
        ("MIT", "Apache-2.0"),
        ("NOASSERTION", "NOASSERTION"),
        ("unknown", "unknown"),
    ],
)
def test_unknown_or_disagreeing_license_detection_fails_closed(
    declared: str,
    detected: str,
) -> None:
    with pytest.raises(FullC6PolicyError):
        _license(declared=declared, detected=detected)


def test_license_files_require_exact_nonaliased_file_identities() -> None:
    with pytest.raises(FullC6PolicyError, match="license file count"):
        FullC6LicenseEvidence(
            declared_spdx="MIT",
            detected_spdx="MIT",
            detector_receipt_sha256="b" * 64,
            license_files=(),
        )
    with pytest.raises(FullC6PolicyError, match="alias or duplicate"):
        _license(
            files=(
                _file("licenses/LICENSE"),
                _file("LICENSES/license", digest="0" * 64),
            )
        )
    with pytest.raises(TypeError, match="integer"):
        FullC6PolicyFileIdentity("licenses/LICENSE", "a" * 64, True, "license-file")


def test_conflicting_shared_license_file_identity_fails_closed() -> None:
    rows = list(_rows())
    first = rows[0]
    second = rows[1]
    rows[0] = replace(
        first,
        license_evidence=_license(files=(_file("licenses/LICENSE", digest="1" * 64),)),
    )
    rows[1] = replace(
        second,
        license_evidence=_license(files=(_file("licenses/LICENSE", digest="2" * 64),)),
    )
    candidate = tuple(rows)
    with pytest.raises(FullC6PolicyError, match="conflicts"):
        full_c6_policy_digest(candidate, _transformations(candidate), _owner())


def test_transformation_disposition_vocabulary_is_class_exact() -> None:
    source = _rows()[0]
    with pytest.raises(FullC6PolicyError, match="not closed"):
        replace(source, transformation_disposition="unassessed")
    wheel = next(item for item in _rows() if item.class_id == "wheel-output:subject")
    with pytest.raises(FullC6PolicyError, match="not closed"):
        replace(wheel, transformation_disposition="exact-generated-output")


@pytest.mark.parametrize(
    "mutation",
    ["stale-source", "stale-output", "missing-output", "duplicate-output", "missing-source"],
)
def test_exact_source_to_generated_cross_bindings_fail_closed_on_tampering(
    mutation: str,
) -> None:
    rows = _rows()
    records = list(_transformations(rows))
    if mutation == "stale-source":
        records[0] = replace(
            records[0],
            source_identity_sha256s=("0" * 64, *records[0].source_identity_sha256s[1:]),
        )
    elif mutation == "stale-output":
        records[0] = replace(records[0], output_identity_sha256="0" * 64)
    elif mutation == "missing-output":
        records.pop()
    elif mutation == "duplicate-output":
        records[1] = replace(
            records[1],
            output_identity=records[0].output_identity,
            output_identity_sha256=records[0].output_identity_sha256,
        )
    else:
        records = [
            replace(
                item,
                source_identities=item.source_identities[1:],
                source_identity_sha256s=item.source_identity_sha256s[1:],
            )
            for item in records
        ]
    with pytest.raises(FullC6PolicyError):
        full_c6_policy_digest(rows, tuple(records), _owner())


def test_transformation_record_alias_order_and_boolean_free_hash_bindings() -> None:
    rows = _rows()
    record = _transformations(rows)[0]
    with pytest.raises(FullC6PolicyError, match="noncanonical"):
        replace(
            record,
            source_identities=tuple(reversed(record.source_identities)),
            source_identity_sha256s=tuple(reversed(record.source_identity_sha256s)),
        )
    with pytest.raises(TypeError, match="exact tuples"):
        replace(record, source_identities=list(record.source_identities))  # type: ignore[arg-type]


def test_owner_declaration_is_exact_allow_pending_final_authentication() -> None:
    with pytest.raises(FullC6PolicyError, match="explicit allow"):
        _owner(decision="deny")
    with pytest.raises(FullC6PolicyError, match="action scopes"):
        _owner(action_scopes=("redistribution",))
    with pytest.raises(FullC6PolicyError, match="acknowledgement"):
        _owner(acknowledgement="I guess this is fine")
    with pytest.raises(FullC6PolicyError, match="authentication state"):
        _owner(authentication="self-asserted-authenticated")
    assert _owner().acknowledgement == FULL_C6_OWNER_ACKNOWLEDGEMENT
    assert _owner().action_scopes == FULL_C6_OWNER_ACTION_SCOPES
    assert _owner().authentication == FULL_C6_OWNER_AUTHENTICATION


def test_policy_digest_binds_owner_declaration_for_one_final_signature() -> None:
    rows = _rows()
    transformations = _transformations(rows)
    digest = full_c6_policy_digest(rows, transformations, _owner())
    changed_owner_digest = full_c6_policy_digest(
        rows,
        transformations,
        _owner(owner_identity="Acme Release Engineering"),
    )
    changed_key_digest = full_c6_policy_digest(
        rows,
        transformations,
        _owner(trusted_public_key_sha256="0" * 64),
    )
    assert len({digest, changed_owner_digest, changed_key_digest}) == 3
    serialized = json.dumps(_receipt().to_dict(), sort_keys=True)
    assert "owner-policy-signature" not in serialized
    assert "signature_verification_receipt" not in serialized


def test_count_string_and_serialized_bounds_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(FullC6PolicyError, match="invalid"):
        replace(_rows()[0], canonical_identity="x" * 513)

    rows = _rows()
    transformations = _transformations(rows)
    monkeypatch.setattr(policy_module, "MAX_FULL_C6_POLICY_ROWS", len(rows) - 1)
    with pytest.raises(FullC6PolicyError, match="row count"):
        full_c6_policy_digest(rows, transformations, _owner())
    monkeypatch.setattr(policy_module, "MAX_FULL_C6_POLICY_ROWS", 1024)
    monkeypatch.setattr(policy_module, "MAX_FULL_C6_POLICY_SERIALIZED_BYTES", 100)
    with pytest.raises(FullC6PolicyError, match="serialized byte bound"):
        full_c6_policy_digest(rows, transformations, _owner())


def test_receipt_rejects_nonexact_tuple_and_nested_object_types() -> None:
    rows = _rows()
    transformations = _transformations(rows)
    with pytest.raises(TypeError, match="exact tuple"):
        FullC6PolicyReceipt(list(rows), transformations, _owner())  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="invalid type"):
        FullC6PolicyReceipt(rows, transformations, object())  # type: ignore[arg-type]
