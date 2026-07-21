"""Focused tests for the split, sealed Full C6 authorization contracts."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from rextio.artifacts.authorization import evaluate_artifact_distribution_authorization
from rextio.artifacts.evidence import ArtifactEvidence, EvidenceFileRef
from rextio.artifacts.full_authorization import (
    FULL_C6_PREAUTHORIZATION_RECEIPT_IDS,
    FULL_C6_RECEIPT_IDS,
    FullC6ArtifactEvidence,
    FullC6DistributionAuthorization,
    FullC6EvidenceReceipt,
    FullC6PreauthorizationEvidence,
    full_c6_evidence_digest,
    full_c6_preauthorization_evidence_digest,
)


def _ref(path: str, role: str, marker: str) -> EvidenceFileRef:
    return EvidenceFileRef(path, marker * 64, 128, role)


def _receipts(ids: tuple[str, ...]) -> tuple[FullC6EvidenceReceipt, ...]:
    return tuple(
        FullC6EvidenceReceipt(id=receipt_id, sha256=f"{index:064x}")
        for index, receipt_id in enumerate(ids, start=1)
    )


def _preauthorization(**overrides: object) -> FullC6PreauthorizationEvidence:
    values: dict[str, object] = {
        "target_triple": "aarch64-apple-darwin",
        "subject": _ref("dist/project.whl", "host-extension-wheel", "a"),
        "external_package": "demo_math",
        "external_distribution": "demo-math",
        "external_version": "1.2.3",
        "external_source_archive": _ref(
            "external/demo_math-1.2.3-py3-none-any.whl",
            "external-source-wheel-archive",
            "b",
        ),
        "trusted_public_key_sha256": "c" * 64,
        "receipts": _receipts(FULL_C6_PREAUTHORIZATION_RECEIPT_IDS),
    }
    values.update(overrides)
    return FullC6PreauthorizationEvidence(**values)  # type: ignore[arg-type]


def _evidence(**overrides: object) -> FullC6ArtifactEvidence:
    preauthorization = _preauthorization()
    values: dict[str, object] = {
        "target_triple": preauthorization.target_triple,
        "subject": preauthorization.subject,
        "external_package": preauthorization.external_package,
        "external_distribution": preauthorization.external_distribution,
        "external_version": preauthorization.external_version,
        "external_source_archive": preauthorization.external_source_archive,
        "trusted_public_key_sha256": preauthorization.trusted_public_key_sha256,
        "preauthorization_evidence_sha256": (
            full_c6_preauthorization_evidence_digest(preauthorization)
        ),
        "authorization_request_sha256": "d" * 64,
        "receipts": _receipts(FULL_C6_RECEIPT_IDS),
    }
    values.update(overrides)
    return FullC6ArtifactEvidence(**values)  # type: ignore[arg-type]


def test_unsigned_digest_is_deterministic_and_excludes_post_signature_receipts() -> None:
    first = _preauthorization()
    second = _preauthorization()
    assert first == second
    assert full_c6_preauthorization_evidence_digest(first) == (
        full_c6_preauthorization_evidence_digest(second)
    )
    assert tuple(item["id"] for item in first.to_dict()["receipts"]) == (
        FULL_C6_PREAUTHORIZATION_RECEIPT_IDS
    )
    assert first.complete is True
    assert first.signed is False
    assert first.distribution_authorized is False

    final = _evidence()
    changed_signature = _receipts(FULL_C6_RECEIPT_IDS)
    changed_signature = (
        *changed_signature[:-2],
        FullC6EvidenceReceipt("attestation-signature-verified", "e" * 64),
        changed_signature[-1],
    )
    changed_final = _evidence(receipts=changed_signature)
    assert full_c6_evidence_digest(final) != full_c6_evidence_digest(changed_final)
    assert final.preauthorization_evidence_sha256 == (
        changed_final.preauthorization_evidence_sha256
    )


@pytest.mark.parametrize(
    "receipts",
    [
        _receipts(FULL_C6_PREAUTHORIZATION_RECEIPT_IDS)[:-1],
        _receipts(FULL_C6_RECEIPT_IDS),
        tuple(reversed(_receipts(FULL_C6_PREAUTHORIZATION_RECEIPT_IDS))),
    ],
)
def test_preauthorization_requires_exact_pre_signature_receipt_set(
    receipts: tuple[FullC6EvidenceReceipt, ...],
) -> None:
    with pytest.raises(ValueError, match="canonical coverage and order"):
        _preauthorization(receipts=receipts)


def test_final_evidence_requires_both_post_signature_receipts() -> None:
    with pytest.raises(ValueError, match="canonical coverage and order"):
        _evidence(receipts=_receipts(FULL_C6_PREAUTHORIZATION_RECEIPT_IDS))


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("target_triple", "i686-unknown-linux-gnu", "target triple"),
        ("target_triple", "aarch64-unknown-linux-gnu", "target triple"),
        ("external_package", "bad-package", "external package"),
        ("external_distribution", "../bad", "external distribution"),
        ("external_version", ">=1.0", "external version"),
        ("trusted_public_key_sha256", "A" * 64, "public key sha256"),
    ],
)
def test_evidence_rejects_values_outside_the_frozen_scope(
    field: str,
    value: str,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        _preauthorization(**{field: value})


def test_final_evidence_is_non_authorizing_and_authorization_is_factory_only() -> None:
    evidence = _evidence()
    assert evidence.complete is True
    assert evidence.signed is True
    assert evidence.distribution_authorized is False

    with pytest.raises(TypeError, match="hard gate"):
        FullC6DistributionAuthorization(evidence=evidence)
    with pytest.raises(TypeError, match="hard gate"):
        FullC6DistributionAuthorization(evidence)

    with pytest.raises(FrozenInstanceError):
        evidence.target_triple = "x86_64-unknown-linux-gnu"  # type: ignore[misc]


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
    assert assessment.distribution_authorized is False
