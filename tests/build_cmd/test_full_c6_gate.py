"""Adversarial integration tests for the final Full C6 hard gate."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import inspect
from pathlib import Path
import runpy
from types import SimpleNamespace

import pytest

import rextio.build.full_c6_gate as gate_module
import rextio.build.full_c6_production as production_module
import rextio.build.full_c6_supply_chain as supply_chain_module
from rextio.artifacts.evidence import (
    EvidenceFileRef,
    SourceTransformationVerification,
    canonical_json_bytes,
    sha256_hex,
)
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
from rextio.build.full_c6_analysis_transaction import (
    FullC6AnalysisIRTransaction,
    FullC6AnalysisTransactionError,
    create_full_c6_analysis_ir_transaction,
)
from rextio.build.transformation_verification import (
    SourceTransformationReplayAuthority,
    _replay_authority_payload,
    _replay_authority_seal,
)
from rextio.build.full_c6_executor import (
    FULL_C6_NATIVE_DRIVER_MANIFEST,
    FULL_C6_NATIVE_EXECUTION_DRIVER,
    FULL_C6_NATIVE_POSTPROCESSOR,
    FULL_C6_PREEXISTING_LOCK_DRIVER,
    FullC6ExecutorReceipt,
    FullC6FrozenTreeManifest,
    FullC6InvocationReceipt,
    FullC6TreeEntry,
)
from rextio.build.full_c6_policy import (
    FULL_C6_EXTERNAL_AUTHORITY_IDENTITY_SCHEME,
    FullC6LicenseEvidence,
    FullC6PolicyFileIdentity,
    FullC6PolicyReceipt,
    full_c6_authority_partition_digest,
    full_c6_license_detector_payload_digest,
)
from rextio.build.full_c6_production import FullC6ProductionAuthority
from rextio.build.full_c6_supply_chain import (
    FullC6CargoPathSource,
    build_full_c6_supply_chain_receipt,
)
from rextio.build.input_closure import bind_full_c6_cargo_workspace_aggregates
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
_REAL_VALIDATE_GATE_INPUTS = gate_module._validated_production_gate_inputs
_TEST_GATE_INPUTS: dict[int, object] = {}


def test_hard_gate_public_api_accepts_only_production_authority_evidence() -> None:
    prepare = inspect.signature(prepare_full_c6_preauthorization_evidence)
    authorize = inspect.signature(authorize_full_c6_distribution)

    assert tuple(prepare.parameters) == ("authority",)
    assert tuple(authorize.parameters) == (
        "authority",
        "request",
        "signature_envelope_path",
        "public_key_path",
    )
    assert prepare.parameters["authority"].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert authorize.parameters["authority"].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert all(
        authorize.parameters[name].kind is inspect.Parameter.KEYWORD_ONLY
        for name in (
            "request",
            "signature_envelope_path",
            "public_key_path",
        )
    )
    raw_evidence = {
        "target_triple",
        "subject_path",
        "subject",
        "build_inputs",
        "wheel_entries",
        "policy",
        "source_verification",
        "analysis_ir_transaction",
        "toolchain",
        "cargo_path_source",
        "runtime_authorization",
        "executor",
        "supply_chain",
        "cargo_dependency_workspace",
        "expected_public_key_sha256",
    }
    assert raw_evidence.isdisjoint(prepare.parameters)
    assert raw_evidence.isdisjoint(authorize.parameters)


@pytest.fixture(autouse=True)
def _accept_synthetic_native_runtime(monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    """Model the native fresh recheck for this otherwise synthetic gate graph."""
    _TEST_GATE_INPUTS.clear()
    monkeypatch.setattr(
        "rextio.build.full_c6_gate.verify_native_runtime_authorization",
        lambda receipt: receipt.verification_mode == RUNTIME_VERIFICATION_NATIVE_FRESH,
    )
    monkeypatch.setattr(
        gate_module,
        "_validated_production_gate_inputs",
        lambda authority: _TEST_GATE_INPUTS[id(authority)],
    )
    yield
    _TEST_GATE_INPUTS.clear()


def _row(policy: FullC6PolicyReceipt, class_id: str):
    matches = tuple(item for item in policy.rows if item.class_id == class_id)
    assert len(matches) == 1
    return matches[0]


def _policy_for(
    *,
    verification: SourceLockV2Verification,
    subject_bytes: bytes,
    key_hash: str,
    cargo_workspace: object,
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
    wheel = verification.context.wheel
    wheel_entries = {item.path: item for item in wheel.entries}
    license_files = tuple(
        FullC6PolicyFileIdentity(
            logical_path=f"external/{path}",
            sha256=hashlib.sha256(payload).hexdigest(),
            size=len(payload),
            role="license-file",
        )
        for path, payload in zip(
            wheel.license_entry_paths,
            wheel.license_payloads,
            strict=True,
        )
        if wheel_entries[path].sha256 == hashlib.sha256(payload).hexdigest()
    )
    detector_payload_sha256 = full_c6_license_detector_payload_digest(
        wheel.license_detection.detected_spdx or "",
        license_files,
        source_detector_receipt_sha256=wheel.license_detection.semantic_sha256,
    )
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
            assert row.license_evidence is not None
            row = replace(
                row,
                license_evidence=FullC6LicenseEvidence(
                    declared_spdx=manifest.declared_license,
                    detected_spdx=wheel.license_detection.detected_spdx or "",
                    subject_authority_identity=row.authority_identity,
                    subject_identity_sha256=row.canonical_identity_sha256,
                    authority_partition_sha256=partition,
                    source_detector_receipt_sha256=(
                        wheel.license_detection.semantic_sha256
                    ),
                    detector_payload_sha256=detector_payload_sha256,
                    license_files=license_files,
                ),
            )
        elif row.class_id == "wheel-output:subject":
            row = replace(row, sha256=subject_sha256, size=len(subject_bytes))
        elif row.class_id == "file-input:generated-rust-lib":
            row = replace(
                row,
                canonical_identity="generated/rust/src/lib.rs",
                sha256="d" * 64,
                size=80,
            )
        elif row.class_id == "file-input:generated-rust-build-input":
            row = replace(
                row,
                canonical_identity="generated/rust/Cargo.toml",
                sha256="a" * 64,
                size=64,
            )
        elif row.class_id == "file-input:generated-cargo-lock":
            lock = cargo_workspace.cargo_sources.lock_file
            row = replace(
                row,
                canonical_identity=lock.logical_name,
                sha256=lock.sha256,
                size=lock.size,
            )
        elif row.class_id == "cargo-component:registry-package":
            packages = cargo_workspace.cargo_sources.packages
            assert len(packages) == 1
            package = packages[0]
            row = replace(
                row,
                canonical_identity=(
                    f"cargo:{package.name}@{package.version}#registry"
                ),
                sha256=package.checksum,
            )
        elif row.class_id == "cargo-component:path-root-package":
            row = replace(
                row,
                canonical_identity=(
                    f"cargo:{cargo_workspace.cargo_sources.root_package}"
                    "@0.1.4#path-root"
                ),
            )
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
        bootstrap_request_sha256="b" * 64,
    )


def _project_transformation(
    policy: FullC6PolicyReceipt,
) -> SourceTransformationVerification:
    project_source = _row(policy, "file-input:project-python-source")
    generated_rust = _row(policy, "file-input:generated-rust-lib")
    source_inputs = (
        EvidenceFileRef(
            logical_path=project_source.canonical_identity,
            sha256=project_source.sha256 or "",
            size=project_source.size or 0,
            role="project-python-source",
        ),
    )
    generated = EvidenceFileRef(
        logical_path=generated_rust.canonical_identity,
        sha256=generated_rust.sha256 or "",
        size=generated_rust.size or 0,
        role="generated-rust-input",
    )
    return SourceTransformationVerification(
        source_transformation_inventory_sha256="7" * 64,
        source_input_set_sha256=sha256_hex(
            canonical_json_bytes([item.to_dict() for item in source_inputs])
        ),
        module_ir_sha256="8" * 64,
        function_qualnames=("app.compute",),
        source_inputs=source_inputs,
        generated_rust=generated,
        regenerated_rust_sha256=generated.sha256,
        regenerated_rust_size=generated.size,
        generator_backend="rextio-core-rust-pyo3-v1",
    )


def _project_replay_authority(
    policy: FullC6PolicyReceipt,
) -> SourceTransformationReplayAuthority:
    verification = _project_transformation(policy)
    generated_python_row = _row(policy, "file-input:generated-python-input")
    cargo_row = _row(policy, "file-input:generated-rust-build-input")
    generated_python = (
        EvidenceFileRef(
            logical_path=generated_python_row.canonical_identity,
            sha256=generated_python_row.sha256 or "",
            size=generated_python_row.size or 0,
            role="generated-python-input",
        ),
    )
    generated_cargo_toml = EvidenceFileRef(
        logical_path=cargo_row.canonical_identity,
        sha256=cargo_row.sha256 or "",
        size=cargo_row.size or 0,
        role="generated-rust-input",
    )
    payload = _replay_authority_payload(
        verification=verification,
        generated_python=generated_python,
        generated_cargo_toml=generated_cargo_toml,
    )
    return SourceTransformationReplayAuthority(
        verification=verification,
        generated_python=generated_python,
        generated_cargo_toml=generated_cargo_toml,
        _authority_seal=_replay_authority_seal(payload),
    )


def _bind_policy_to_transaction(
    policy: FullC6PolicyReceipt,
    transaction: FullC6AnalysisIRTransaction,
) -> FullC6PolicyReceipt:
    transformations = tuple(
        _POLICY["_record"](  # type: ignore[operator]
            record_id=record.record_id,
            kind=record.kind,
            source_identities=record.source_identities,
            source_identity_sha256s=record.source_identity_sha256s,
            output_identity=record.output_identity,
            output_identity_sha256=record.output_identity_sha256,
            authority_partition_sha256=record.authority_partition_sha256,
            analysis_sha256=transaction.analysis_sha256,
            lowered_ir_sha256=transaction.lowered_ir_sha256(
                transformation_kind=record.kind,
                output_identity=record.output_identity,
                output_identity_sha256=record.output_identity_sha256,
            ),
            generator_sha256=transaction.generator_sha256,
        )
        for record in policy.transformations
    )
    return FullC6PolicyReceipt(
        rows=policy.rows,
        transformations=transformations,
        owner_declaration=policy.owner_declaration,
        artifact_coverage=policy.artifact_coverage,
        external_authority=policy.external_authority,
        bootstrap_request_sha256=policy.bootstrap_request_sha256,
    )


def _fixture(tmp_path: Path) -> dict[str, object]:
    signed = _SOURCE["_write_signed"](tmp_path / "source-lock")  # type: ignore[operator]
    verification = _SOURCE["_verify_context"](signed)  # type: ignore[operator]
    assert isinstance(verification, SourceLockV2Verification)
    assert verification.context is not None
    subject_bytes = b"full-c6-test-wheel\n"
    subject_path = tmp_path / "subject.whl"
    subject_path.write_bytes(subject_bytes)
    cargo_root = tmp_path / "cargo-workspace"
    cargo_root.mkdir()
    cargo_workspace = _SUPPLY["_sealed_cargo_workspace"](cargo_root)
    policy = _policy_for(
        verification=verification,
        subject_bytes=subject_bytes,
        key_hash=signed.key_hash,
        cargo_workspace=cargo_workspace,
    )
    build_inputs = bind_full_c6_cargo_workspace_aggregates(
        _SUPPLY["_build_inputs"](policy),  # type: ignore[operator]
        cargo_workspace,
    )
    transaction = create_full_c6_analysis_ir_transaction(
        project_replay_authority=_project_replay_authority(policy),
        source_verification=verification,
        build_inputs=build_inputs,
    )
    policy = _bind_policy_to_transaction(policy, transaction)
    subject_row = _row(policy, "wheel-output:subject")
    subject = EvidenceFileRef(
        logical_path=subject_row.canonical_identity,
        sha256=subject_row.sha256 or "",
        size=subject_row.size or 0,
        role="host-extension-wheel",
    )
    assert build_inputs.files == _SUPPLY["_build_inputs"](policy).files  # type: ignore[operator]
    wheel_entries = _SUPPLY["_wheel_entries"](policy)  # type: ignore[operator]
    toolchain = replace(
        _SUPPLY["_toolchain"](policy),  # type: ignore[operator]
        cargo_sources=cargo_workspace.cargo_sources,
    )
    runtime = _SUPPLY["_runtime"](policy)  # type: ignore[operator]
    reproducibility = _SUPPLY["_reproducibility"](policy)  # type: ignore[operator]
    lock = toolchain.cargo_sources.lock_file
    driver_manifest_sha256 = "e" * 64
    lib = _row(policy, "file-input:generated-rust-lib")
    generated_python = _row(policy, "file-input:generated-python-input")
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
            FullC6TreeEntry(
                logical_name="python-staging",
                kind="directory",
                sha256=None,
                size=0,
                mode=0o700,
            ),
            FullC6TreeEntry(
                logical_name="python-staging/wrapper.py",
                kind="file",
                sha256=generated_python.sha256,
                size=generated_python.size or 0,
                mode=0o644,
            ),
            FullC6TreeEntry(
                logical_name=FULL_C6_NATIVE_DRIVER_MANIFEST,
                kind="file",
                sha256=driver_manifest_sha256,
                size=256,
                mode=0o644,
            ),
            FullC6TreeEntry(
                logical_name="src/lib.rs",
                kind="file",
                sha256=lib.sha256,
                size=lib.size or 0,
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
        postprocessor=FULL_C6_NATIVE_POSTPROCESSOR,
        postprocessor_manifest_sha256=driver_manifest_sha256,
        target_triple=TARGET,
    )
    root = _row(policy, "cargo-component:path-root-package")
    cargo_path_source = FullC6CargoPathSource(
        name=cargo_workspace.cargo_sources.root_package,
        version="0.1.4",
        source_tree_sha256=root.sha256 or "",
    )
    authority_aggregate = _SUPPLY["_authority_aggregate"](  # type: ignore[operator]
        analysis_ir_transaction_sha256=transaction.digest,
        cargo_workspace_sha256=cargo_workspace.digest,
        runtime_authorization_sha256=runtime.digest,
        executor_receipt_sha256=executor.digest,
    )
    assert isinstance(
        authority_aggregate,
        supply_chain_module.FullC6AuthorityAggregateBinding,
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
        authority_aggregate=authority_aggregate,
        cargo_dependency_workspace=cargo_workspace,
    )
    authority = object.__new__(FullC6ProductionAuthority)
    _TEST_GATE_INPUTS[id(authority)] = gate_module._FullC6GateInputs(
        target_triple=TARGET,
        subject_path=subject_path,
        subject=subject,
        build_inputs=build_inputs,
        wheel_entries=wheel_entries,
        policy=policy,
        source_verification=verification,
        analysis_ir_transaction=transaction,
        toolchain=toolchain,
        cargo_path_source=cargo_path_source,
        runtime_authorization=runtime,
        executor=executor,
        supply_chain=supply_chain,
        cargo_dependency_workspace=cargo_workspace,
        authority_aggregate=authority_aggregate,
        expected_public_key_sha256=signed.key_hash,
    )
    return {
        "authority": authority,
        "target_triple": TARGET,
        "subject_path": subject_path,
        "subject": subject,
        "build_inputs": build_inputs,
        "wheel_entries": wheel_entries,
        "policy": policy,
        "source_verification": verification,
        "analysis_ir_transaction": transaction,
        "toolchain": toolchain,
        "cargo_path_source": cargo_path_source,
        "runtime_authorization": runtime,
        "reproducibility": reproducibility,
        "executor": executor,
        "supply_chain": supply_chain,
        "cargo_dependency_workspace": cargo_workspace,
        "authority_aggregate": authority_aggregate,
        "expected_public_key_sha256": signed.key_hash,
        "public_key": signed.key_path.read_bytes(),
}


def _gate_arguments(arguments: dict[str, object]) -> dict[str, object]:
    authority = arguments["authority"]
    current = _TEST_GATE_INPUTS[id(authority)]
    _TEST_GATE_INPUTS[id(authority)] = replace(
        current,
        target_triple=arguments["target_triple"],
        subject_path=arguments["subject_path"],
        subject=arguments["subject"],
        build_inputs=arguments["build_inputs"],
        wheel_entries=arguments["wheel_entries"],
        policy=arguments["policy"],
        source_verification=arguments["source_verification"],
        analysis_ir_transaction=arguments["analysis_ir_transaction"],
        toolchain=arguments["toolchain"],
        cargo_path_source=arguments["cargo_path_source"],
        runtime_authorization=arguments["runtime_authorization"],
        executor=arguments["executor"],
        supply_chain=arguments["supply_chain"],
        cargo_dependency_workspace=arguments["cargo_dependency_workspace"],
        authority_aggregate=arguments["authority_aggregate"],
        expected_public_key_sha256=arguments["expected_public_key_sha256"],
    )
    return {"authority": authority}


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


def test_gate_extracts_exact_retained_graph_and_rejects_split_cargo_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(FullC6GateError, match="exact production authority"):
        _REAL_VALIDATE_GATE_INPUTS(object())  # type: ignore[arg-type]
    arguments = _fixture(tmp_path)
    authority = arguments["authority"]
    aggregate = arguments["authority_aggregate"]
    native_output = SimpleNamespace(
        digest=aggregate.native_output_transaction_sha256
    )
    material = SimpleNamespace(
        lifecycle=SimpleNamespace(status="signing-required"),
        policy=arguments["policy"],
        supply_chain=arguments["supply_chain"],
        cargo_workspace=arguments["cargo_dependency_workspace"],
        build_inputs=arguments["build_inputs"],
        analysis_ir_transaction=arguments["analysis_ir_transaction"],
        runtime_authorization=arguments["runtime_authorization"],
        executor_receipt=arguments["executor"],
        cargo_path_source=arguments["cargo_path_source"],
        preflight=SimpleNamespace(
            context=SimpleNamespace(
                source_verification=arguments["source_verification"]
            )
        ),
        native_execution_authority=SimpleNamespace(
            digest=aggregate.native_execution_authority_sha256
        ),
        native_output_transaction=native_output,
        subject_wheel_transaction=SimpleNamespace(
            digest=aggregate.subject_wheel_transaction_sha256
        ),
        native_runtime_authority=SimpleNamespace(
            digest=aggregate.native_runtime_authority_sha256
        ),
        license_materials_transaction=SimpleNamespace(
            digest=aggregate.license_materials_transaction_sha256
        ),
        output_license_contract=object(),
        authority_aggregate=aggregate,
    )
    execution = SimpleNamespace(
        toolchain=arguments["toolchain"],
        cargo_workspace=arguments["cargo_dependency_workspace"],
    )
    monkeypatch.setattr(
        production_module,
        "_validated_full_c6_production_material",
        lambda value: material if value is authority else None,
    )
    monkeypatch.setattr(
        gate_module._executor,
        "_validated_full_c6_native_output_material",
        lambda _value: execution,
    )
    monkeypatch.setattr(
        gate_module,
        "full_c6_native_output_subject",
        lambda value: arguments["subject"] if value is native_output else None,
    )
    monkeypatch.setattr(
        gate_module,
        "full_c6_native_output_wheel_entries",
        lambda value: arguments["wheel_entries"] if value is native_output else (),
    )
    monkeypatch.setattr(
        gate_module,
        "full_c6_native_output_wheel_path",
        lambda value: arguments["subject_path"] if value is native_output else None,
    )
    monkeypatch.setattr(
        gate_module,
        "validate_full_c6_output_license_contract",
        lambda _materials, _contract, **_kwargs: SimpleNamespace(
            output_contract_sha256=aggregate.output_license_contract_sha256
        ),
    )

    inputs = _REAL_VALIDATE_GATE_INPUTS(authority)
    assert inputs.cargo_dependency_workspace is arguments["cargo_dependency_workspace"]
    assert inputs.authority_aggregate == aggregate

    cloned_sources = replace(arguments["toolchain"].cargo_sources)
    execution.toolchain = replace(  # type: ignore[misc]
        arguments["toolchain"],
        cargo_sources=cloned_sources,
    )
    assert cloned_sources == arguments["cargo_dependency_workspace"].cargo_sources
    assert cloned_sources is not arguments["cargo_dependency_workspace"].cargo_sources
    with pytest.raises(FullC6GateError, match="Cargo authority is split"):
        _REAL_VALIDATE_GATE_INPUTS(authority)

    execution.toolchain = arguments["toolchain"]
    equal_root = tmp_path / "equal-cargo-workspace"
    equal_root.mkdir()
    equal_workspace = _SUPPLY["_sealed_cargo_workspace"](equal_root)
    assert equal_workspace.digest == arguments["cargo_dependency_workspace"].digest
    assert equal_workspace is not arguments["cargo_dependency_workspace"]
    material.cargo_workspace = equal_workspace
    with pytest.raises(FullC6GateError, match="Cargo authority is split"):
        _REAL_VALIDATE_GATE_INPUTS(authority)


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
        postprocessor=None,
        postprocessor_manifest_sha256=None,
        target_triple=None,
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


def test_gate_rejects_non_lock_frozen_tree_bytes_outside_the_exact_closure(
    tmp_path: Path,
) -> None:
    arguments = _fixture(tmp_path)
    executor = arguments["executor"]
    tree = executor.frozen_tree  # type: ignore[attr-defined]
    entries = tuple(
        replace(item, sha256="4" * 64)
        if item.logical_name == "src/lib.rs"
        else item
        for item in tree.entries
    )
    arguments["executor"] = replace(
        executor,  # type: ignore[arg-type]
        frozen_tree=replace(tree, entries=entries),
    )
    with pytest.raises(FullC6GateError, match="bytes differ from the build-input closure"):
        _request(arguments)


def test_gate_rejects_generated_python_staging_bytes_outside_exact_closure(
    tmp_path: Path,
) -> None:
    arguments = _fixture(tmp_path)
    executor = arguments["executor"]
    tree = executor.frozen_tree  # type: ignore[attr-defined]
    entries = tuple(
        replace(item, sha256="4" * 64)
        if item.logical_name == "python-staging/wrapper.py"
        else item
        for item in tree.entries
    )
    arguments["executor"] = replace(
        executor,  # type: ignore[arg-type]
        frozen_tree=replace(tree, entries=entries),
    )
    with pytest.raises(FullC6GateError, match="bytes differ from the build-input closure"):
        _request(arguments)


def test_gate_rejects_unprojected_extra_executor_file(tmp_path: Path) -> None:
    arguments = _fixture(tmp_path)
    executor = arguments["executor"]
    tree = executor.frozen_tree  # type: ignore[attr-defined]
    extra = FullC6TreeEntry(
        logical_name="unexpected.txt",
        kind="file",
        sha256="4" * 64,
        size=12,
        mode=0o644,
    )
    arguments["executor"] = replace(
        executor,  # type: ignore[arg-type]
        frozen_tree=replace(
            tree,
            entries=tuple(sorted((*tree.entries, extra), key=lambda item: item.logical_name)),
        ),
    )
    with pytest.raises(FullC6GateError, match="differs from the generated closure"):
        _request(arguments)


def test_gate_rehashes_private_external_license_payload_bytes(tmp_path: Path) -> None:
    arguments = _fixture(tmp_path)
    verification = arguments["source_verification"]
    context = verification.context  # type: ignore[attr-defined]
    assert context is not None
    object.__setattr__(context.wheel, "license_payloads", (b"forged-license",))
    with pytest.raises(
        FullC6GateError,
        match="independent exact-byte license detection",
    ):
        _request(arguments)


def test_gate_requires_same_transaction_analysis_and_ir_projection(tmp_path: Path) -> None:
    arguments = _fixture(tmp_path)
    transaction = arguments["analysis_ir_transaction"]
    object.__setattr__(transaction, "analysis_sha256", "0" * 64)
    with pytest.raises(FullC6GateError, match="preauthorization evidence failed closed"):
        _request(arguments)


@pytest.mark.parametrize(
    "field",
    ("analysis_ir_transaction_sha256", "executor_receipt_sha256"),
)
def test_gate_rejects_authority_aggregate_source_drift(
    tmp_path: Path,
    field: str,
) -> None:
    arguments = _fixture(tmp_path)
    supply_chain = arguments["supply_chain"]
    binding = supply_chain.authority_aggregate  # type: ignore[attr-defined]
    assert isinstance(
        binding,
        supply_chain_module.FullC6AuthorityAggregateBinding,
    )
    changed = replace(binding, **{field: "f" * 64})
    verification = arguments["source_verification"]
    assert isinstance(verification, SourceLockV2Verification)
    assert verification.context is not None
    arguments["supply_chain"] = build_full_c6_supply_chain_receipt(
        target_triple=arguments["target_triple"],  # type: ignore[arg-type]
        subject=arguments["subject"],  # type: ignore[arg-type]
        build_inputs=arguments["build_inputs"],  # type: ignore[arg-type]
        wheel_entries=arguments["wheel_entries"],  # type: ignore[arg-type]
        policy=arguments["policy"],  # type: ignore[arg-type]
        source_lock=verification.context.manifest,
        source_admission=verification.admission,
        toolchain=arguments["toolchain"],  # type: ignore[arg-type]
        cargo_path_source=arguments["cargo_path_source"],  # type: ignore[arg-type]
        runtime_authorization=arguments["runtime_authorization"],  # type: ignore[arg-type]
            reproducibility=arguments["reproducibility"],  # type: ignore[arg-type]
            authority_aggregate=changed,
            cargo_dependency_workspace=arguments["cargo_dependency_workspace"],  # type: ignore[arg-type]
        )

    with pytest.raises(FullC6GateError, match="authority aggregate"):
        _request(arguments)


def test_analysis_transaction_rejects_raw_forged_replay_receipt(tmp_path: Path) -> None:
    arguments = _fixture(tmp_path)
    with pytest.raises(
        FullC6AnalysisTransactionError,
        match="collector-issued",
    ):
        create_full_c6_analysis_ir_transaction(
            project_replay_authority=_project_transformation(arguments["policy"]),  # type: ignore[arg-type]
            source_verification=arguments["source_verification"],  # type: ignore[arg-type]
            build_inputs=arguments["build_inputs"],  # type: ignore[arg-type]
        )


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
