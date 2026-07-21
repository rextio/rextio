"""Adversarial integration tests for the final Full C6 hard gate."""

from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
import runpy

import pytest

from rextio.artifacts.evidence import EvidenceFileRef
from rextio.artifacts.full_authorization import (
    FULL_C6_PREAUTHORIZATION_RECEIPT_IDS,
    FULL_C6_RECEIPT_IDS,
    full_c6_evidence_digest,
    full_c6_preauthorization_evidence_digest,
)
from rextio.build.full_c6_gate import (
    FullC6GateError,
    authorize_full_c6_distribution,
    prepare_full_c6_preauthorization_evidence,
)
from rextio.build.full_c6_policy import (
    FULL_C6_EXTERNAL_AUTHORITY_IDENTITY_SCHEME,
    FullC6PolicyReceipt,
    full_c6_authority_partition_digest,
)
from rextio.build.full_c6_supply_chain import (
    FullC6CargoPathSource,
    build_full_c6_supply_chain_receipt,
)
from rextio.build.signing import (
    SIGNED_MESSAGE_PREFIX,
    DetachedSignatureEnvelope,
    FinalAuthorizationRequest,
)
from rextio.source.source_lock_v2 import SourceLockV2Verification


TARGET = "x86_64-unknown-linux-gnu"
_THIS_DIR = Path(__file__).parent
_POLICY = runpy.run_path(str(_THIS_DIR / "test_full_c6_policy.py"))
_SUPPLY = runpy.run_path(str(_THIS_DIR / "test_full_c6_supply_chain.py"))
_SOURCE = runpy.run_path(
    str(_THIS_DIR.parent / "source" / "test_source_lock_v2.py")
)
_SIGNING = runpy.run_path(str(_THIS_DIR / "test_signing.py"))


def _row(policy: FullC6PolicyReceipt, class_id: str):
    matches = tuple(item for item in policy.rows if item.class_id == class_id)
    assert len(matches) == 1
    return matches[0]


def _policy_for(
    *,
    verification: SourceLockV2Verification,
    subject_bytes: bytes,
    key_hash: str,
) -> FullC6PolicyReceipt:
    assert verification.context is not None
    manifest = verification.context.manifest
    artifact_identities, _unused = _POLICY["_authority_sets"]()  # type: ignore[operator]
    raw_external_values: dict[str, list[tuple[str, str, int]]] = {
        class_id: []
        for class_id in (
            "external-source:wheel-archive",
            "external-source:python-source",
            "external-source:distribution-metadata",
            "external-source:license-file",
        )
    }

    archive_class = "external-source:wheel-archive"
    raw_external_values[archive_class].append(
        (
            f"external/{manifest.archive.filename}",
            manifest.archive.sha256,
            manifest.archive.size,
        )
    )
    source_paths = {item.path for item in manifest.entries if item.path.endswith(".py")}
    license_paths = {
        item.path for item in manifest.entries if "/licenses/" in item.path.lower()
    }
    for entry in manifest.entries:
        if entry.path in source_paths:
            class_id = "external-source:python-source"
        elif entry.path in license_paths:
            class_id = "external-source:license-file"
        else:
            class_id = "external-source:distribution-metadata"
        raw_external_values[class_id].append(
            (f"external/{entry.path}", entry.sha256, entry.size)
        )
    external_values: dict[str, list[tuple[str, str, str, int]]] = {}
    for class_id, raw_values in raw_external_values.items():
        external_values[class_id] = [
            (
                f"{FULL_C6_EXTERNAL_AUTHORITY_IDENTITY_SCHEME}:"
                f"{class_id}:{index:064x}",
                logical_name,
                digest,
                size,
            )
            for index, (logical_name, digest, size) in enumerate(
                sorted(raw_values, key=lambda item: item[0].casefold()),
                start=1,
            )
        ]

    external_identities = {
        class_id: tuple(item[0] for item in values)
        for class_id, values in external_values.items()
    }
    coverage = _POLICY["_coverage"](artifact_identities)  # type: ignore[operator]
    external = _POLICY["_external_partition"](external_identities)  # type: ignore[operator]
    partition = full_c6_authority_partition_digest(coverage, external)
    rows = _POLICY["_rows"](  # type: ignore[operator]
        artifact_identities,
        external_identities,
        partition,
    )
    values_by_authority = {
        authority: (logical_name, digest, size)
        for values in external_values.values()
        for authority, logical_name, digest, size in values
    }
    subject_sha256 = hashlib.sha256(subject_bytes).hexdigest()
    rebuilt_rows = []
    for row in rows:
        if row.authority_identity in values_by_authority:
            logical_name, digest, size = values_by_authority[row.authority_identity]
            row = replace(
                row,
                canonical_identity=logical_name,
                sha256=digest,
                size=size,
            )
        elif row.class_id == "wheel-output:subject":
            row = replace(row, sha256=subject_sha256, size=len(subject_bytes))
        rebuilt_rows.append(row)
    trusted_rows = tuple(rebuilt_rows)
    transformations = _POLICY["_transformations"](  # type: ignore[operator]
        trusted_rows,
        partition,
    )
    owner = _POLICY["_owner"](  # type: ignore[operator]
        trusted_public_key_sha256=key_hash
    )
    return FullC6PolicyReceipt(
        rows=trusted_rows,
        transformations=transformations,
        owner_declaration=owner,
        artifact_coverage=coverage,
        external_authority=external,
    )


def _fixture(tmp_path: Path) -> dict[str, object]:
    signed = _SOURCE["_write_signed"](tmp_path / "source-lock")  # type: ignore[operator]
    verification = _SOURCE["_verify_context"](signed)  # type: ignore[operator]
    assert isinstance(verification, SourceLockV2Verification)
    assert verification.context is not None
    subject_bytes = b"full-c6-test-wheel\n"
    subject_path = tmp_path / "subject.whl"
    subject_path.write_bytes(subject_bytes)
    policy = _policy_for(
        verification=verification,
        subject_bytes=subject_bytes,
        key_hash=signed.key_hash,
    )
    subject_row = _row(policy, "wheel-output:subject")
    subject = EvidenceFileRef(
        logical_path=subject_row.canonical_identity,
        sha256=subject_row.sha256 or "",
        size=subject_row.size or 0,
        role="host-extension-wheel",
    )
    build_inputs = _SUPPLY["_build_inputs"](policy)  # type: ignore[operator]
    wheel_entries = _SUPPLY["_wheel_entries"](policy)  # type: ignore[operator]
    toolchain = _SUPPLY["_toolchain"](policy)  # type: ignore[operator]
    runtime = _SUPPLY["_runtime"](policy)  # type: ignore[operator]
    reproducibility = _SUPPLY["_reproducibility"](policy)  # type: ignore[operator]
    root = _row(policy, "cargo-component:path-root-package")
    cargo_path_source = FullC6CargoPathSource(
        name="rextio-generated",
        version="0.1.4",
        source_tree_sha256=root.sha256 or "",
    )
    supply_chain = build_full_c6_supply_chain_receipt(
        target_triple=TARGET,
        subject=subject,
        build_inputs=build_inputs,
        wheel_entries=wheel_entries,
        policy=policy,
        source_lock=verification.context.manifest,
        source_admission=verification.admission,
        toolchain=toolchain,
        cargo_path_source=cargo_path_source,
        runtime_authorization=runtime,
        reproducibility=reproducibility,
    )
    return {
        "target_triple": TARGET,
        "subject_path": subject_path,
        "subject": subject,
        "build_inputs": build_inputs,
        "wheel_entries": wheel_entries,
        "policy": policy,
        "source_verification": verification,
        "toolchain": toolchain,
        "cargo_path_source": cargo_path_source,
        "runtime_authorization": runtime,
        "reproducibility": reproducibility,
        "supply_chain": supply_chain,
        "expected_public_key_sha256": signed.key_hash,
        "public_key": signed.key_path.read_bytes(),
    }


def _request(arguments: dict[str, object]):
    gate_arguments = {key: value for key, value in arguments.items() if key != "public_key"}
    preauthorization = prepare_full_c6_preauthorization_evidence(  # type: ignore[arg-type]
        **gate_arguments
    )
    build_inputs = arguments["build_inputs"]
    policy = arguments["policy"]
    reproducibility = arguments["reproducibility"]
    subject = arguments["subject"]
    return preauthorization, FinalAuthorizationRequest(
        target_triple=TARGET,
        project_sha256=build_inputs.digest,  # type: ignore[attr-defined]
        artifact_sha256=subject.sha256,  # type: ignore[attr-defined]
        evidence_sha256=full_c6_preauthorization_evidence_digest(preauthorization),
        reproducibility_sha256=reproducibility.digest,  # type: ignore[attr-defined]
        policy_sha256=policy.digest,  # type: ignore[attr-defined]
    )


def _sign_request(
    tmp_path: Path,
    *,
    request: FinalAuthorizationRequest,
    public_key: bytes,
) -> tuple[Path, Path]:
    signed_key, signature = _SIGNING["_test_only_sign"](  # type: ignore[operator]
        _SOURCE["SIGNING_SEED"],  # type: ignore[index]
        SIGNED_MESSAGE_PREFIX + request.canonical_manifest_bytes,
    )
    assert signed_key == public_key
    key_hash = hashlib.sha256(public_key).hexdigest()
    envelope = DetachedSignatureEnvelope.from_signature(
        public_key_sha256=key_hash,
        manifest_sha256=request.manifest_sha256,
        signature=signature,
    )
    signature_path = tmp_path / "final.sig.json"
    key_path = tmp_path / "owner.pub"
    signature_path.write_bytes(envelope.canonical_json_bytes)
    key_path.write_bytes(public_key)
    return signature_path, key_path


def _authorize(tmp_path: Path, arguments: dict[str, object]):
    preauthorization, request = _request(arguments)
    signature_path, key_path = _sign_request(
        tmp_path,
        request=request,
        public_key=arguments["public_key"],  # type: ignore[arg-type]
    )
    gate_arguments = {key: value for key, value in arguments.items() if key != "public_key"}
    result = authorize_full_c6_distribution(
        **gate_arguments,  # type: ignore[arg-type]
        request=request,
        signature_envelope_path=signature_path,
        public_key_path=key_path,
    )
    return preauthorization, request, result


def test_hard_gate_signs_only_unsigned_evidence_then_mints_final_authority(
    tmp_path: Path,
) -> None:
    arguments = _fixture(tmp_path)
    preauthorization, request, result = _authorize(tmp_path, arguments)

    assert request.evidence_sha256 == full_c6_preauthorization_evidence_digest(
        preauthorization
    )
    assert tuple(item.id for item in preauthorization.receipts) == (
        FULL_C6_PREAUTHORIZATION_RECEIPT_IDS
    )
    assert tuple(item.id for item in result.evidence.receipts) == FULL_C6_RECEIPT_IDS
    assert result.evidence.preauthorization_evidence_sha256 == request.evidence_sha256
    assert result.evidence.authorization_request_sha256 == request.manifest_sha256
    assert result.authorization.evidence_sha256 == full_c6_evidence_digest(result.evidence)
    assert result.authorization.distribution_authorized is True
    assert result.evidence.distribution_authorized is False
    assert result.signature_receipt.authorizes_distribution is False


@pytest.mark.parametrize(
    "field",
    (
        "project_sha256",
        "artifact_sha256",
        "evidence_sha256",
        "reproducibility_sha256",
        "policy_sha256",
    ),
)
def test_replayed_or_mutated_request_field_fails_closed(
    tmp_path: Path,
    field: str,
) -> None:
    arguments = _fixture(tmp_path)
    _preauthorization, request = _request(arguments)
    request = replace(request, **{field: "a" * 64})
    signature_path, key_path = _sign_request(
        tmp_path,
        request=request,
        public_key=arguments["public_key"],  # type: ignore[arg-type]
    )
    gate_arguments = {key: value for key, value in arguments.items() if key != "public_key"}
    with pytest.raises(FullC6GateError, match="stale or replayed"):
        authorize_full_c6_distribution(
            **gate_arguments,  # type: ignore[arg-type]
            request=request,
            signature_envelope_path=signature_path,
            public_key_path=key_path,
        )


def test_forged_policy_supply_chain_and_source_receipts_fail_closed(tmp_path: Path) -> None:
    arguments = _fixture(tmp_path)
    policy = arguments["policy"]
    object.__setattr__(policy.owner_declaration, "owner_identity", "Mallory")  # type: ignore[attr-defined]
    with pytest.raises(FullC6GateError):
        _request(arguments)

    arguments = _fixture(tmp_path / "fresh")
    supply_chain = arguments["supply_chain"]
    object.__setattr__(supply_chain, "policy_sha256", "0" * 64)
    with pytest.raises(FullC6GateError):
        _request(arguments)

    arguments = _fixture(tmp_path / "source-replay")
    verification = arguments["source_verification"]
    assert isinstance(verification, SourceLockV2Verification)
    object.__setattr__(verification.admission, "signature_sha256", "1" * 64)
    with pytest.raises(FullC6GateError):
        _request(arguments)


def test_wrong_or_changed_owner_key_and_signature_envelope_fail_closed(tmp_path: Path) -> None:
    arguments = _fixture(tmp_path)
    _preauthorization, request = _request(arguments)
    signature_path, key_path = _sign_request(
        tmp_path,
        request=request,
        public_key=arguments["public_key"],  # type: ignore[arg-type]
    )
    key_path.write_bytes(b"x" * 32)
    gate_arguments = {key: value for key, value in arguments.items() if key != "public_key"}
    with pytest.raises(FullC6GateError):
        authorize_full_c6_distribution(
            **gate_arguments,  # type: ignore[arg-type]
            request=request,
            signature_envelope_path=signature_path,
            public_key_path=key_path,
        )

    signature_path, key_path = _sign_request(
        tmp_path,
        request=request,
        public_key=arguments["public_key"],  # type: ignore[arg-type]
    )
    signature_path.write_bytes(signature_path.read_bytes() + b"\n")
    with pytest.raises(FullC6GateError):
        authorize_full_c6_distribution(
            **gate_arguments,  # type: ignore[arg-type]
            request=request,
            signature_envelope_path=signature_path,
            public_key_path=key_path,
        )


def test_subject_mutation_before_or_after_signature_verification_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments = _fixture(tmp_path)
    _preauthorization, request = _request(arguments)
    signature_path, key_path = _sign_request(
        tmp_path,
        request=request,
        public_key=arguments["public_key"],  # type: ignore[arg-type]
    )
    subject_path = arguments["subject_path"]
    assert isinstance(subject_path, Path)
    subject_path.write_bytes(b"mutated-before-signature-check\n")
    gate_arguments = {key: value for key, value in arguments.items() if key != "public_key"}
    with pytest.raises(FullC6GateError, match="subject"):
        authorize_full_c6_distribution(
            **gate_arguments,  # type: ignore[arg-type]
            request=request,
            signature_envelope_path=signature_path,
            public_key_path=key_path,
        )

    arguments = _fixture(tmp_path / "race")
    _preauthorization, request = _request(arguments)
    signature_path, key_path = _sign_request(
        tmp_path / "race",
        request=request,
        public_key=arguments["public_key"],  # type: ignore[arg-type]
    )
    import rextio.build.full_c6_gate as gate_module

    original = gate_module._revalidate_subject
    calls = 0

    def mutate_on_final(path: Path | str, expected: EvidenceFileRef) -> EvidenceFileRef:
        nonlocal calls
        calls += 1
        if calls == 2:
            Path(path).write_bytes(b"mutated-after-signature-check\n")
        return original(path, expected)

    monkeypatch.setattr(gate_module, "_revalidate_subject", mutate_on_final)
    gate_arguments = {key: value for key, value in arguments.items() if key != "public_key"}
    with pytest.raises(FullC6GateError, match="subject"):
        authorize_full_c6_distribution(
            **gate_arguments,  # type: ignore[arg-type]
            request=request,
            signature_envelope_path=signature_path,
            public_key_path=key_path,
        )
