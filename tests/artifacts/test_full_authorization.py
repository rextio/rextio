"""Focused tests for the separate strict Full-C6 final contract."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from rextio.artifacts.authorization import evaluate_artifact_distribution_authorization
from rextio.artifacts.evidence import ArtifactEvidence, EvidenceFileRef
from rextio.artifacts.full_authorization import (
    FULL_C6_AUTHORIZATION_CHECK_IDS,
    FULL_C6_RECEIPT_IDS,
    FullC6ArtifactEvidence,
    FullC6DistributionAuthorization,
    FullC6EvidenceReceipt,
    full_c6_evidence_digest,
)


def _ref(path: str, role: str, marker: str) -> EvidenceFileRef:
    return EvidenceFileRef(
        logical_path=path,
        sha256=marker * 64,
        size=128,
        role=role,
    )


def _receipts() -> tuple[FullC6EvidenceReceipt, ...]:
    return tuple(
        FullC6EvidenceReceipt(id=receipt_id, sha256=f"{index:064x}")
        for index, receipt_id in enumerate(FULL_C6_RECEIPT_IDS, start=1)
    )


def _evidence(**overrides: object) -> FullC6ArtifactEvidence:
    values: dict[str, object] = {
        "target_triple": "aarch64-apple-darwin",
        "subject": _ref(
            "dist/project-0.1.0-cp311-cp311-macosx_11_0_arm64.whl",
            "host-extension-wheel",
            "a",
        ),
        "external_package": "demo_math",
        "external_distribution": "demo-math",
        "external_version": "1.2.3",
        "external_source_archive": _ref(
            "vendor/demo_math-1.2.3-py3-none-any.whl",
            "external-source-wheel-archive",
            "b",
        ),
        "trusted_public_key_sha256": "c" * 64,
        "receipts": _receipts(),
    }
    values.update(overrides)
    return FullC6ArtifactEvidence(**values)  # type: ignore[arg-type]


def test_full_c6_evidence_serialization_and_digest_are_deterministic() -> None:
    first = _evidence()
    second = _evidence()

    assert first == second
    assert first.to_dict() == second.to_dict()
    assert full_c6_evidence_digest(first) == full_c6_evidence_digest(second)
    assert tuple(item["id"] for item in first.to_dict()["receipts"]) == FULL_C6_RECEIPT_IDS
    assert first.complete is True
    assert first.signed is True
    assert first.distribution_authorized is False
    assert first.repeat_build_count == 2


@pytest.mark.parametrize(
    "receipts",
    [
        _receipts()[:-1],
        (*_receipts()[:-1], _receipts()[0]),
        (_receipts()[1], _receipts()[0], *_receipts()[2:]),
    ],
)
def test_full_c6_evidence_rejects_incomplete_duplicate_or_reordered_receipts(
    receipts: tuple[FullC6EvidenceReceipt, ...],
) -> None:
    with pytest.raises(ValueError, match="canonical coverage and order"):
        _evidence(receipts=receipts)


def test_full_c6_receipt_rejects_unknown_id() -> None:
    with pytest.raises(ValueError, match="closed allowlist"):
        FullC6EvidenceReceipt(id="future-unverified-check", sha256="d" * 64)


def test_full_c6_evidence_rejects_wrong_roles_and_path_aliasing() -> None:
    with pytest.raises(ValueError, match="host-extension wheel"):
        _evidence(subject=_ref("dist/project.whl", "ordinary-wheel", "a"))
    with pytest.raises(ValueError, match="wheel archive"):
        _evidence(
            external_source_archive=_ref(
                "vendor/source.whl", "external-source-sdist", "b"
            )
        )
    subject = _ref("dist/SAME.whl", "host-extension-wheel", "a")
    with pytest.raises(ValueError, match="must not alias"):
        _evidence(
            subject=subject,
            external_source_archive=_ref(
                "dist/same.whl", "external-source-wheel-archive", "b"
            ),
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("target_triple", "i686-unknown-linux-gnu", "target triple"),
        ("target_triple", "x86_64-apple-darwin", "target triple"),
        ("target_triple", "aarch64-unknown-linux-gnu", "target triple"),
        ("target_triple", "x86_64-unknown-linux-musl", "target triple"),
        ("external_package", "bad-package", "external package"),
        ("external_distribution", "../bad", "external distribution"),
        ("external_version", ">=1.0", "external version"),
        ("trusted_public_key_sha256", "A" * 64, "public key sha256"),
    ],
)
def test_full_c6_evidence_rejects_values_outside_frozen_scope(
    field: str, value: str, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        _evidence(**{field: value})


def test_full_c6_final_claims_are_not_constructor_inputs_and_models_are_frozen() -> None:
    with pytest.raises(TypeError):
        _evidence(complete=True)
    with pytest.raises(TypeError):
        _evidence(signed=True)
    with pytest.raises(TypeError):
        _evidence(distribution_authorized=True)

    evidence = _evidence()
    authorization = FullC6DistributionAuthorization(evidence)
    with pytest.raises(TypeError):
        FullC6DistributionAuthorization(evidence, status="authorized")  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        FullC6DistributionAuthorization(evidence, blockers=())  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        FullC6DistributionAuthorization(evidence, complete=True)  # type: ignore[call-arg]
    with pytest.raises(FrozenInstanceError):
        evidence.target_triple = "x86_64-unknown-linux-gnu"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        authorization.evidence_sha256 = "0" * 64  # type: ignore[misc]


def test_full_c6_authorization_binds_evidence_and_has_exact_positive_checks() -> None:
    evidence = _evidence()
    authorization = FullC6DistributionAuthorization(evidence)
    payload = authorization.to_dict()

    assert authorization.evidence_sha256 == full_c6_evidence_digest(evidence)
    assert tuple(item["id"] for item in payload["checks"]) == FULL_C6_AUTHORIZATION_CHECK_IDS
    assert {item["status"] for item in payload["checks"]} == {"satisfied"}
    assert payload["blockers"] == []
    assert payload["complete"] is True
    assert payload["signed"] is True
    assert payload["distribution_authorized"] is True

    changed = _evidence(external_version="1.2.4")
    assert FullC6DistributionAuthorization(changed).evidence_sha256 != (
        authorization.evidence_sha256
    )


def test_preview_authorization_contract_remains_blocked_unsigned_and_incomplete() -> None:
    preview = ArtifactEvidence(
        kind="rextio-artifact-evidence",
        status="unavailable",
        reason="native-extension-not-built",
        complete=True,
        signed=True,
        distribution_authorized=True,
    )
    assessment = evaluate_artifact_distribution_authorization(preview)

    assert preview.complete is False
    assert preview.signed is False
    assert preview.distribution_authorized is False
    assert assessment.status == "blocked"
    assert assessment.complete is False
    assert assessment.signed is False
    assert assessment.distribution_authorized is False
