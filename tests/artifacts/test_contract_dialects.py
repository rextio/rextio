"""Exact-root and immutability tests for semantic artifact contract dialects."""

from __future__ import annotations

from types import MappingProxyType

import pytest

from rextio.artifacts.contract_dialects import (
    ARTIFACT_CONTRACT_DIALECTS,
    AUTHORIZATION_REQUEST,
    CURRENT,
    LEGACY_0_1_7,
    POLICY_MANIFEST,
    SOURCE_LOCK_MANIFEST,
    resolve_artifact_contract_dialect,
)


def test_registry_is_immutable_and_current_is_semantic_0_1_8() -> None:
    assert isinstance(ARTIFACT_CONTRACT_DIALECTS, MappingProxyType)
    assert isinstance(CURRENT.identities, MappingProxyType)
    assert CURRENT.semantic_version == "0.1.8"
    assert CURRENT.production_capable is True
    assert LEGACY_0_1_7.semantic_version == "0.1.7"
    assert LEGACY_0_1_7.production_capable is False
    with pytest.raises(TypeError):
        ARTIFACT_CONTRACT_DIALECTS["other"] = CURRENT  # type: ignore[index]
    with pytest.raises(TypeError):
        CURRENT.identities[POLICY_MANIFEST] = CURRENT.identity(  # type: ignore[index]
            POLICY_MANIFEST
        )


@pytest.mark.parametrize(
    "artifact",
    (AUTHORIZATION_REQUEST, POLICY_MANIFEST, SOURCE_LOCK_MANIFEST),
)
def test_exact_root_registry_rejects_every_hybrid_triple(artifact: str) -> None:
    current = CURRENT.identity(artifact)
    legacy = LEGACY_0_1_7.identity(artifact)
    assert (
        resolve_artifact_contract_dialect(
            artifact,
            kind=current.kind,
            schema_version=current.schema_version,
            domain=current.domain,
        )
        is CURRENT
    )
    assert (
        resolve_artifact_contract_dialect(
            artifact,
            kind=legacy.kind,
            schema_version=legacy.schema_version,
            domain=legacy.domain,
        )
        is LEGACY_0_1_7
    )
    for hybrid in (
        (legacy.kind, current.schema_version, current.domain),
        (current.kind, legacy.schema_version, current.domain),
        (current.kind, current.schema_version, legacy.domain),
    ):
        if hybrid in {current.triple, legacy.triple}:
            continue
        with pytest.raises(ValueError, match="unknown or hybrid"):
            resolve_artifact_contract_dialect(
                artifact,
                kind=hybrid[0],
                schema_version=hybrid[1],
                domain=hybrid[2],
            )

