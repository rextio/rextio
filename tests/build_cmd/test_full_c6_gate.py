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
from rextio.build.full_c6_executor import (
    FULL_C6_NATIVE_EXECUTION_DRIVER,
    FULL_C6_PREEXISTING_LOCK_DRIVER,
    FullC6ExecutorReceipt,
    FullC6FrozenTreeManifest,
    FullC6InvocationReceipt,
    FullC6TreeEntry,
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
from rextio.build.runtime_authorization import RUNTIME_VERIFICATION_NATIVE_FRESH
from rextio.source.source_lock_v2 import SourceLockV2Verification


TARGET = "x86_64-unknown-linux-gnu"
_THIS_DIR = Path(__file__).parent
_POLICY = runpy.run_path(str(_THIS_DIR / "test_full_c6_policy.py"))
_SUPPLY = runpy.run_path(str(_THIS_DIR / "test_full_c6_supply_chain.py"))
_SOURCE = runpy.run_path(
    str(_THIS_DIR.parent / "source" / "test_source_lock_v2.py")
)
_SIGNING = runpy.run_path(str(_THIS_DIR / "test_signing.py"))


@pytest.fixture(autouse=True)
def _accept_synthetic_native_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    """Model the native fresh recheck for this otherwise synthetic gate graph."""
    monkeypatch.setattr(
        "rextio.build.full_c6_gate.verify_native_runtime_authorization",
        lambda receipt: receipt.verification_mode == RUNTIME_VERIFICATION_NATIVE_FRESH,
    )


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
    lock = toolchain.cargo_sources.lock_file
    frozen_tree = FullC6FrozenTreeManifest(
        entries=(
            FullC6TreeEntry(
                logical_name="Cargo.lock",
                kind="file",
                sha256=lock.sha256,
                size=lock.size,
                mode=0o644,
            ),
            FullC6TreeEntry(
                logical_name="Cargo.toml",
                kind="file",
                sha256="a" * 64,
                size=64,
                mode=0o644,
            ),
        ),
        cargo_lock_generated=False,
    )
    invocations = tuple(
        FullC6InvocationReceipt(
            ordinal=ordinal,
            argv_sha256=toolchain.argv.digest,
            argv_count=len(toolchain.argv.values),
            environment=(),
            timeout_seconds=60,
            max_output_bytes=4096,
        )
        for ordinal in (1, 2)
    )
    executor = FullC6ExecutorReceipt(
        frozen_tree=frozen_tree,
        invocations=(invocations[0], invocations[1]),
        reproducibility=reproducibility,
        execution_driver=FULL_C6_NATIVE_EXECUTION_DRIVER,
        lock_driver=FULL_C6_PREEXISTING_LOCK_DRIVER,
        toolchain_sha256=toolchain.digest,
        cargo_executable_sha256=toolchain.cargo.executable.sha256,
    )
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
        "executor": executor,
        "supply_chain": supply_chain,
        "expected_public_key_sha256": signed.key_hash,
        "public_key": signed.key_path.read_bytes(),
}


def _gate_arguments(arguments: dict[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in arguments.items()
        if key not in {"public_key", "reproducibility"}
    }


def _request(arguments: dict[str, object]):
    gate_arguments = _gate_arguments(arguments)
    preauthorization = prepare_full_c6_preauthorization_evidence(  # type: ignore[arg-type]
        **gate_arguments
    )
    build_inputs = arguments["build_inputs"]
    policy = arguments["policy"]
    executor = arguments["executor"]
    subject = arguments["subject"]
    return preauthorization, FinalAuthorizationRequest(
        target_triple=TARGET,
        project_sha256=build_inputs.digest,  # type: ignore[attr-defined]
        artifact_sha256=subject.sha256,  # type: ignore[attr-defined]
        evidence_sha256=full_c6_preauthorization_evidence_digest(preauthorization),
        reproducibility_sha256=executor.digest,  # type: ignore[attr-defined]
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
    gate_arguments = _gate_arguments(arguments)
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
    executor = arguments["executor"]
    assert request.reproducibility_sha256 == executor.digest  # type: ignore[attr-defined]
    repeat_receipt = next(
        item
        for item in preauthorization.receipts
        if item.id == "repeat-builds-byte-identical"
    )
    assert repeat_receipt.sha256 == executor.digest  # type: ignore[attr-defined]


def test_gate_rejects_callback_or_unbound_executor_authority(tmp_path: Path) -> None:
    arguments = _fixture(tmp_path)
    executor = arguments["executor"]
    arguments["executor"] = replace(
        executor,  # type: ignore[arg-type]
        execution_driver="callback-test-seam",
        toolchain_sha256=None,
        cargo_executable_sha256=None,
    )
    with pytest.raises(FullC6GateError, match="callback and test-only"):
        _request(arguments)


@pytest.mark.parametrize(
    "mutation",
    ("toolchain", "executable", "argv", "tree"),
)
def test_gate_cross_binds_executor_tree_invocations_and_toolchain(
    tmp_path: Path,
    mutation: str,
) -> None:
    arguments = _fixture(tmp_path)
    executor = arguments["executor"]
    if mutation == "toolchain":
        changed = replace(executor, toolchain_sha256="1" * 64)  # type: ignore[arg-type]
    elif mutation == "executable":
        changed = replace(executor, cargo_executable_sha256="2" * 64)  # type: ignore[arg-type]
    elif mutation == "argv":
        invocations = tuple(
            replace(item, argv_sha256="3" * 64)
            for item in executor.invocations  # type: ignore[attr-defined]
        )
        changed = replace(executor, invocations=invocations)  # type: ignore[arg-type]
    else:
        tree = executor.frozen_tree  # type: ignore[attr-defined]
        entries = tuple(
            replace(item, sha256="4" * 64)
            if item.logical_name == "Cargo.lock"
            else item
            for item in tree.entries
        )
        changed = replace(executor, frozen_tree=replace(tree, entries=entries))  # type: ignore[arg-type]
    arguments["executor"] = changed
    with pytest.raises(FullC6GateError, match="tree, invocations, or toolchain"):
        _request(arguments)


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
    gate_arguments = _gate_arguments(arguments)
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
    gate_arguments = _gate_arguments(arguments)
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
    gate_arguments = _gate_arguments(arguments)
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
    gate_arguments = _gate_arguments(arguments)
    with pytest.raises(FullC6GateError, match="subject"):
        authorize_full_c6_distribution(
            **gate_arguments,  # type: ignore[arg-type]
            request=request,
            signature_envelope_path=signature_path,
            public_key_path=key_path,
        )
