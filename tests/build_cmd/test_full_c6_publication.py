from __future__ import annotations

import ctypes
from dataclasses import replace
import errno
import hashlib
import os
from pathlib import Path
import runpy

import pytest

import rextio.build.full_c6_gate as gate_module
from rextio.artifacts.evidence import canonical_json_bytes
from rextio.artifacts.full_authorization import FullC6DistributionAuthorization
from rextio.build.full_c6_gate import FullC6GateResult
from rextio.build.full_c6_publication import (
    FULL_C6_PUBLICATION_MANIFEST_FILENAME,
    FULL_C6_PUBLICATION_ROLES,
    FULL_C6_SIGNING_REQUEST_FILENAME,
    ROLE_CYCLONEDX,
    ROLE_DETACHED_SIGNATURE,
    ROLE_DISTRIBUTION_AUTHORIZATION,
    ROLE_FINAL_EVIDENCE,
    ROLE_SLSA_PROVENANCE,
    ROLE_WHEEL,
    FullC6PublicationError,
    materialize_full_c6_signing_request,
    _publish_full_c6_bundle,
)
from rextio.build.signing import DetachedSignatureEnvelope, FinalAuthorizationRequest


_THIS_DIR = Path(__file__).parent
_GATE = runpy.run_path(str(_THIS_DIR / "test_full_c6_gate.py"))


@pytest.fixture(autouse=True)
def _accept_synthetic_production_authority(monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    gate_inputs = _GATE["_TEST_GATE_INPUTS"]
    gate_inputs.clear()  # type: ignore[union-attr]
    monkeypatch.setattr(
        gate_module,
        "_validated_production_gate_inputs",
        lambda authority: gate_inputs[id(authority)],  # type: ignore[index]
    )
    yield
    gate_inputs.clear()  # type: ignore[union-attr]


def _authorized_bundle(
    tmp_path: Path,
) -> tuple[
    dict[str, Path],
    FinalAuthorizationRequest,
    FullC6GateResult,
]:
    fixture_root = tmp_path / "gate"
    fixture_root.mkdir()
    arguments = _GATE["_fixture"](fixture_root)
    import rextio.build.full_c6_gate as gate_module

    original_runtime_verifier = gate_module.verify_native_runtime_authorization
    gate_module.verify_native_runtime_authorization = lambda _receipt: True
    try:
        _preauthorization, request, result = _GATE["_authorize"](
            fixture_root,
            arguments,
        )
    finally:
        gate_module.verify_native_runtime_authorization = original_runtime_verifier
    assert isinstance(request, FinalAuthorizationRequest)
    assert isinstance(result, FullC6GateResult)
    supply_chain = arguments["supply_chain"]

    inputs = tmp_path / "payload"
    inputs.mkdir()
    sbom = inputs / "sbom.json"
    provenance = inputs / "provenance.json"
    evidence = inputs / "evidence.json"
    authorization = inputs / "authorization.json"
    signature = inputs / "signature.json"
    sbom.write_bytes(supply_chain.sbom_json)
    provenance.write_bytes(supply_chain.provenance_json)
    evidence.write_bytes(canonical_json_bytes(result.evidence.to_dict()))
    authorization.write_bytes(canonical_json_bytes(result.authorization.to_dict()))
    signature.write_bytes((fixture_root / "final.sig.json").read_bytes())
    return (
        {
            ROLE_WHEEL: arguments["subject_path"],
            ROLE_CYCLONEDX: sbom,
            ROLE_SLSA_PROVENANCE: provenance,
            ROLE_FINAL_EVIDENCE: evidence,
            ROLE_DETACHED_SIGNATURE: signature,
            ROLE_DISTRIBUTION_AUTHORIZATION: authorization,
        },
        request,
        result,
    )


def _publish(
    tmp_path: Path,
    files: dict[str, Path],
    request: FinalAuthorizationRequest,
    result: FullC6GateResult,
):
    publication_root = tmp_path / "dist"
    publication_root.mkdir(mode=0o700)
    receipt = _publish_full_c6_bundle(
        publication_root=publication_root,
        bundle_name="candidate",
        bundle_files=files,
        request=request,
        gate_result=result,
        public_key_path=tmp_path / "gate" / "owner.pub",
    )
    return publication_root, receipt


def test_signing_request_is_private_atomic_and_idempotent(tmp_path: Path) -> None:
    _files, request, _result = _authorized_bundle(tmp_path)
    state = tmp_path / "state"
    state.mkdir(mode=0o700)

    first = materialize_full_c6_signing_request(
        state_directory=state,
        request=request,
    )
    second = materialize_full_c6_signing_request(
        state_directory=state,
        request=request,
    )

    target = state / FULL_C6_SIGNING_REQUEST_FILENAME
    assert target.read_bytes() == request.canonical_manifest_bytes
    assert first.already_present is False
    assert second.already_present is True
    assert first.authorizes_distribution is False
    assert not tuple(state.glob("*.tmp"))


def test_signing_request_rejects_unsafe_state_and_different_existing(
    tmp_path: Path,
) -> None:
    _files, request, _result = _authorized_bundle(tmp_path)
    unsafe = tmp_path / "unsafe-state"
    unsafe.mkdir(mode=0o755)
    with pytest.raises(FullC6PublicationError, match="0700"):
        materialize_full_c6_signing_request(state_directory=unsafe, request=request)

    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    (state / FULL_C6_SIGNING_REQUEST_FILENAME).write_bytes(b"different")
    with pytest.raises(FullC6PublicationError, match="different bytes"):
        materialize_full_c6_signing_request(state_directory=state, request=request)

    state_link = tmp_path / "state-link"
    state_link.symlink_to(state, target_is_directory=True)
    with pytest.raises(FullC6PublicationError, match="symlink"):
        materialize_full_c6_signing_request(state_directory=state_link, request=request)


def test_signing_request_never_replaces_a_concurrent_different_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _files, request, _result = _authorized_bundle(tmp_path)
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    import rextio.build.full_c6_publication as module

    original = module._atomic_rename_noreplace

    def rename_after_race(
        directory_fd: int,
        *,
        source_name: str,
        destination_name: str,
    ) -> None:
        (state / destination_name).write_bytes(b"concurrent-different-request")
        original(
            directory_fd,
            source_name=source_name,
            destination_name=destination_name,
        )

    monkeypatch.setattr(module, "_atomic_rename_noreplace", rename_after_race)
    with pytest.raises(FullC6PublicationError, match="concurrently changed"):
        materialize_full_c6_signing_request(
            state_directory=state,
            request=request,
        )
    assert (state / FULL_C6_SIGNING_REQUEST_FILENAME).read_bytes() == (
        b"concurrent-different-request"
    )
    assert not tuple(state.glob("*.tmp"))


def test_unsigned_phase_creates_only_request_and_no_dist_output(tmp_path: Path) -> None:
    _files, request, _result = _authorized_bundle(tmp_path)
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    dist = tmp_path / "dist"
    dist.mkdir(mode=0o700)

    receipt = materialize_full_c6_signing_request(
        state_directory=state,
        request=request,
    )

    assert receipt.authorizes_distribution is False
    assert tuple(dist.iterdir()) == ()
    assert tuple(state.iterdir()) == (state / FULL_C6_SIGNING_REQUEST_FILENAME,)


def test_successful_publication_is_one_closed_atomic_bundle(tmp_path: Path) -> None:
    files, request, result = _authorized_bundle(tmp_path)
    publication_root, receipt = _publish(tmp_path, files, request, result)

    published = publication_root / "candidate"
    expected_names = {item.logical_name for item in receipt.files}
    expected_names.add(FULL_C6_PUBLICATION_MANIFEST_FILENAME)
    assert published.is_dir()
    assert {item.name for item in published.iterdir()} == expected_names
    assert tuple(item.role for item in receipt.files) == FULL_C6_PUBLICATION_ROLES
    assert receipt.publication_completed is True
    assert receipt.sealed_authorization_observed is True
    assert receipt.authorizes_distribution is False
    assert "tmp_path" not in str(receipt.to_dict())
    assert not tuple(publication_root.glob(".rextio-full-c6-stage-*"))


def test_exact_existing_publication_is_idempotently_reconciled(tmp_path: Path) -> None:
    files, request, result = _authorized_bundle(tmp_path)
    publication_root, first = _publish(tmp_path, files, request, result)

    second = _publish_full_c6_bundle(
        publication_root=publication_root,
        bundle_name="candidate",
        bundle_files=files,
        request=request,
        gate_result=result,
        public_key_path=tmp_path / "gate" / "owner.pub",
    )

    assert second == first
    assert not tuple(publication_root.glob(".rextio-full-c6-stage-*"))


def test_existing_target_reconciliation_rejects_source_drift_after_target_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files, request, result = _authorized_bundle(tmp_path)
    publication_root, _receipt = _publish(tmp_path, files, request, result)
    import rextio.build.full_c6_publication as module

    original = module._reconcile_existing_publication
    mutated = False

    def reconcile_then_mutate_source(**kwargs: object) -> bool:
        nonlocal mutated
        reconciled = original(**kwargs)  # type: ignore[arg-type]
        if reconciled and not mutated:
            files[ROLE_WHEEL].write_bytes(b"source-drift-after-target-check")
            mutated = True
        return reconciled

    monkeypatch.setattr(
        module,
        "_reconcile_existing_publication",
        reconcile_then_mutate_source,
    )
    with pytest.raises(FullC6PublicationError, match="input changed during"):
        _publish_full_c6_bundle(
            publication_root=publication_root,
            bundle_name="candidate",
            bundle_files=files,
            request=request,
            gate_result=result,
            public_key_path=tmp_path / "gate" / "owner.pub",
        )


def test_concurrent_target_reconciliation_rejects_public_key_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files, request, result = _authorized_bundle(tmp_path)
    publication_root = tmp_path / "dist"
    publication_root.mkdir(mode=0o700)
    public_key_path = tmp_path / "gate" / "owner.pub"
    import rextio.build.full_c6_publication as module

    original = module._atomic_rename_noreplace

    def commit_concurrently_then_mutate_key(
        directory_fd: int,
        *,
        source_name: str,
        destination_name: str,
    ) -> None:
        original(
            directory_fd,
            source_name=source_name,
            destination_name=destination_name,
        )
        public_key_path.write_bytes(b"x" * 32)
        raise module._FullC6TargetExists(
            "synthetic exact concurrent publication target"
        )

    monkeypatch.setattr(
        module,
        "_atomic_rename_noreplace",
        commit_concurrently_then_mutate_key,
    )
    with pytest.raises(FullC6PublicationError, match="public key changed during"):
        _publish_full_c6_bundle(
            publication_root=publication_root,
            bundle_name="candidate",
            bundle_files=files,
            request=request,
            gate_result=result,
            public_key_path=public_key_path,
        )

    assert (publication_root / "candidate").is_dir()
    assert not tuple(publication_root.glob(".rextio-full-c6-stage-*"))


@pytest.mark.parametrize("interruption", (KeyboardInterrupt, SystemExit))
def test_retry_recovers_exact_bundle_after_post_commit_async_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    interruption: type[BaseException],
) -> None:
    files, request, result = _authorized_bundle(tmp_path)
    publication_root = tmp_path / "dist"
    publication_root.mkdir(mode=0o700)
    import rextio.build.full_c6_publication as module

    original = module._atomic_rename_noreplace

    def rename_then_interrupt(
        directory_fd: int,
        *,
        source_name: str,
        destination_name: str,
    ) -> None:
        original(
            directory_fd,
            source_name=source_name,
            destination_name=destination_name,
        )
        raise interruption()

    monkeypatch.setattr(module, "_atomic_rename_noreplace", rename_then_interrupt)
    with pytest.raises(interruption):
        _publish_full_c6_bundle(
            publication_root=publication_root,
            bundle_name="candidate",
            bundle_files=files,
            request=request,
            gate_result=result,
            public_key_path=tmp_path / "gate" / "owner.pub",
        )

    monkeypatch.setattr(module, "_atomic_rename_noreplace", original)
    recovered = _publish_full_c6_bundle(
        publication_root=publication_root,
        bundle_name="candidate",
        bundle_files=files,
        request=request,
        gate_result=result,
        public_key_path=tmp_path / "gate" / "owner.pub",
    )
    repeated = _publish_full_c6_bundle(
        publication_root=publication_root,
        bundle_name="candidate",
        bundle_files=files,
        request=request,
        gate_result=result,
        public_key_path=tmp_path / "gate" / "owner.pub",
    )

    assert recovered == repeated
    assert recovered.publication_completed is True
    assert not tuple(publication_root.glob(".rextio-full-c6-stage-*"))


def test_direct_fake_authorization_is_rejected(tmp_path: Path) -> None:
    files, request, result = _authorized_bundle(tmp_path)
    publication_root = tmp_path / "dist"
    publication_root.mkdir(mode=0o700)
    fake = object.__new__(FullC6DistributionAuthorization)
    fake_result = object.__new__(FullC6GateResult)
    object.__setattr__(
        fake_result,
        "preauthorization_evidence",
        result.preauthorization_evidence,
    )
    object.__setattr__(fake_result, "signature_receipt", result.signature_receipt)
    object.__setattr__(fake_result, "evidence", result.evidence)
    object.__setattr__(fake_result, "authorization", fake)

    with pytest.raises(FullC6PublicationError, match="sealed authorization"):
        _publish_full_c6_bundle(
            publication_root=publication_root,
            bundle_name="candidate",
            bundle_files=files,
            request=request,
            gate_result=fake_result,
            public_key_path=tmp_path / "gate" / "owner.pub",
        )
    assert tuple(publication_root.iterdir()) == ()


@pytest.mark.parametrize("omit", FULL_C6_PUBLICATION_ROLES)
def test_missing_bundle_role_is_rejected(tmp_path: Path, omit: str) -> None:
    files, request, result = _authorized_bundle(tmp_path)
    files.pop(omit)
    publication_root = tmp_path / "dist"
    publication_root.mkdir(mode=0o700)
    with pytest.raises(FullC6PublicationError, match="closed six-file set"):
        _publish_full_c6_bundle(
            publication_root=publication_root,
            bundle_name="candidate",
            bundle_files=files,
            request=request,
            gate_result=result,
            public_key_path=tmp_path / "gate" / "owner.pub",
        )


def test_extra_bundle_role_is_rejected(tmp_path: Path) -> None:
    files, request, result = _authorized_bundle(tmp_path)
    files["unexpected"] = files[ROLE_CYCLONEDX]
    publication_root = tmp_path / "dist"
    publication_root.mkdir(mode=0o700)
    with pytest.raises(FullC6PublicationError, match="closed six-file set"):
        _publish_full_c6_bundle(
            publication_root=publication_root,
            bundle_name="candidate",
            bundle_files=files,
            request=request,
            gate_result=result,
            public_key_path=tmp_path / "gate" / "owner.pub",
        )


def test_symlink_hardlink_and_special_bundle_members_are_rejected(tmp_path: Path) -> None:
    files, request, result = _authorized_bundle(tmp_path)
    publication_root = tmp_path / "dist"
    publication_root.mkdir(mode=0o700)

    symlink = tmp_path / "signature-link"
    symlink.symlink_to(files[ROLE_DETACHED_SIGNATURE])
    symlink_files = {**files, ROLE_DETACHED_SIGNATURE: symlink}
    with pytest.raises(FullC6PublicationError, match="symlink"):
        _publish_full_c6_bundle(
            publication_root=publication_root,
            bundle_name="symlink",
            bundle_files=symlink_files,
            request=request,
            gate_result=result,
            public_key_path=tmp_path / "gate" / "owner.pub",
        )

    hardlink = tmp_path / "authorization-hardlink"
    os.link(files[ROLE_DISTRIBUTION_AUTHORIZATION], hardlink)
    hardlink_files = {**files, ROLE_DISTRIBUTION_AUTHORIZATION: hardlink}
    with pytest.raises(FullC6PublicationError, match="single-linked"):
        _publish_full_c6_bundle(
            publication_root=publication_root,
            bundle_name="hardlink",
            bundle_files=hardlink_files,
            request=request,
            gate_result=result,
            public_key_path=tmp_path / "gate" / "owner.pub",
        )
    hardlink.unlink()

    fifo = tmp_path / "signature.fifo"
    os.mkfifo(fifo)
    fifo_files = {**files, ROLE_DETACHED_SIGNATURE: fifo}
    with pytest.raises(FullC6PublicationError, match="regular"):
        _publish_full_c6_bundle(
            publication_root=publication_root,
            bundle_name="fifo",
            bundle_files=fifo_files,
            request=request,
            gate_result=result,
            public_key_path=tmp_path / "gate" / "owner.pub",
        )


def test_unsafe_or_preexisting_publication_target_is_rejected(tmp_path: Path) -> None:
    files, request, result = _authorized_bundle(tmp_path)
    unsafe = tmp_path / "unsafe-dist"
    unsafe.mkdir(mode=0o777)
    unsafe.chmod(0o777)
    with pytest.raises(FullC6PublicationError, match="group/world writable"):
        _publish_full_c6_bundle(
            publication_root=unsafe,
            bundle_name="candidate",
            bundle_files=files,
            request=request,
            gate_result=result,
            public_key_path=tmp_path / "gate" / "owner.pub",
        )

    actual_root = tmp_path / "actual-dist"
    actual_root.mkdir(mode=0o700)
    linked_root = tmp_path / "linked-dist"
    linked_root.symlink_to(actual_root, target_is_directory=True)
    with pytest.raises(FullC6PublicationError, match="symlink"):
        _publish_full_c6_bundle(
            publication_root=linked_root,
            bundle_name="candidate",
            bundle_files=files,
            request=request,
            gate_result=result,
            public_key_path=tmp_path / "gate" / "owner.pub",
        )

    publication_root = tmp_path / "dist"
    publication_root.mkdir(mode=0o700)
    (publication_root / "candidate").mkdir()
    with pytest.raises(FullC6PublicationError, match="already exists"):
        _publish_full_c6_bundle(
            publication_root=publication_root,
            bundle_name="candidate",
            bundle_files=files,
            request=request,
            gate_result=result,
            public_key_path=tmp_path / "gate" / "owner.pub",
        )


def test_native_atomic_rename_maps_cross_filesystem_to_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rextio.build.full_c6_publication as module

    class FakeRename:
        argtypes: object = None
        restype: object = None

        def __call__(self, *_args: object) -> int:
            ctypes.set_errno(errno.EXDEV)
            return -1

    class FakeLibc:
        renameatx_np = FakeRename()
        renameat2 = renameatx_np

    monkeypatch.setattr(module.ctypes, "CDLL", lambda *_args, **_kwargs: FakeLibc())
    with pytest.raises(FullC6PublicationError, match="crosses filesystem"):
        module._atomic_rename_noreplace(
            -1,
            source_name="source",
            destination_name="destination",
        )


def test_concurrent_target_creation_is_detected_before_rename(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files, request, result = _authorized_bundle(tmp_path)
    publication_root = tmp_path / "dist"
    publication_root.mkdir(mode=0o700)
    import rextio.build.full_c6_publication as module

    original = module._capture_sources
    calls = 0

    def capture_with_race(sources: dict[str, Path]):
        nonlocal calls
        calls += 1
        captured = original(sources)
        if calls == 2:
            (publication_root / "candidate").mkdir()
        return captured

    monkeypatch.setattr(module, "_capture_sources", capture_with_race)
    with pytest.raises(FullC6PublicationError, match="already exists"):
        _publish_full_c6_bundle(
            publication_root=publication_root,
            bundle_name="candidate",
            bundle_files=files,
            request=request,
            gate_result=result,
            public_key_path=tmp_path / "gate" / "owner.pub",
        )
    assert not tuple(publication_root.glob(".rextio-full-c6-stage-*"))


def test_target_created_after_last_check_is_never_replaced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files, request, result = _authorized_bundle(tmp_path)
    publication_root = tmp_path / "dist"
    publication_root.mkdir(mode=0o700)
    import rextio.build.full_c6_publication as module

    original = module._atomic_rename_noreplace

    def rename_after_race(
        directory_fd: int,
        *,
        source_name: str,
        destination_name: str,
    ) -> None:
        raced = publication_root / destination_name
        raced.mkdir()
        (raced / "concurrent-owner").write_text("keep", encoding="utf-8")
        original(
            directory_fd,
            source_name=source_name,
            destination_name=destination_name,
        )

    monkeypatch.setattr(module, "_atomic_rename_noreplace", rename_after_race)
    with pytest.raises(FullC6PublicationError, match="already exists"):
        _publish_full_c6_bundle(
            publication_root=publication_root,
            bundle_name="candidate",
            bundle_files=files,
            request=request,
            gate_result=result,
            public_key_path=tmp_path / "gate" / "owner.pub",
        )
    assert (publication_root / "candidate" / "concurrent-owner").read_text(
        encoding="utf-8"
    ) == "keep"
    assert not tuple(publication_root.glob(".rextio-full-c6-stage-*"))


def test_input_mutation_during_staging_fails_and_cleans_only_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files, request, result = _authorized_bundle(tmp_path)
    publication_root = tmp_path / "dist"
    publication_root.mkdir(mode=0o700)
    sentinel = publication_root / "keep-me"
    sentinel.write_text("owned by caller", encoding="utf-8")
    import rextio.build.full_c6_publication as module

    original = module._capture_sources
    calls = 0

    def capture_with_mutation(sources: dict[str, Path]):
        nonlocal calls
        calls += 1
        if calls == 2:
            sources[ROLE_WHEEL].write_bytes(b"mutated")
        return original(sources)

    monkeypatch.setattr(module, "_capture_sources", capture_with_mutation)
    with pytest.raises(FullC6PublicationError, match="changed during staging"):
        _publish_full_c6_bundle(
            publication_root=publication_root,
            bundle_name="candidate",
            bundle_files=files,
            request=request,
            gate_result=result,
            public_key_path=tmp_path / "gate" / "owner.pub",
        )
    assert sentinel.read_text(encoding="utf-8") == "owned by caller"
    assert not (publication_root / "candidate").exists()
    assert not tuple(publication_root.glob(".rextio-full-c6-stage-*"))


def test_noncanonical_or_mutated_semantic_files_fail_closed(tmp_path: Path) -> None:
    files, request, result = _authorized_bundle(tmp_path)
    publication_root = tmp_path / "dist"
    publication_root.mkdir(mode=0o700)
    files[ROLE_FINAL_EVIDENCE].write_bytes(b" " + files[ROLE_FINAL_EVIDENCE].read_bytes())
    with pytest.raises(FullC6PublicationError, match="canonical bytes"):
        _publish_full_c6_bundle(
            publication_root=publication_root,
            bundle_name="candidate",
            bundle_files=files,
            request=request,
            gate_result=result,
            public_key_path=tmp_path / "gate" / "owner.pub",
        )


def test_publication_independently_verifies_detached_ed25519_signature(
    tmp_path: Path,
) -> None:
    files, request, result = _authorized_bundle(tmp_path)
    forged = DetachedSignatureEnvelope.from_signature(
        public_key_sha256=result.authorization.trusted_public_key_sha256,
        manifest_sha256=request.manifest_sha256,
        signature=b"\0" * 64,
    )
    files[ROLE_DETACHED_SIGNATURE].write_bytes(forged.canonical_json_bytes)
    publication_root = tmp_path / "dist"
    publication_root.mkdir(mode=0o700)
    with pytest.raises(FullC6PublicationError, match="Ed25519"):
        _publish_full_c6_bundle(
            publication_root=publication_root,
            bundle_name="candidate",
            bundle_files=files,
            request=request,
            gate_result=result,
            public_key_path=tmp_path / "gate" / "owner.pub",
        )
    assert tuple(publication_root.iterdir()) == ()


def test_post_commit_tamper_cannot_turn_completed_rename_into_false_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files, request, result = _authorized_bundle(tmp_path)
    publication_root = tmp_path / "dist"
    publication_root.mkdir(mode=0o700)
    import rextio.build.full_c6_publication as module

    original = module._atomic_rename_noreplace

    def rename_then_tamper(
        directory_fd: int,
        *,
        source_name: str,
        destination_name: str,
    ) -> None:
        original(
            directory_fd,
            source_name=source_name,
            destination_name=destination_name,
        )
        (publication_root / destination_name / "rextio.full-c6-evidence.json").write_bytes(
            b"tampered-after-rename"
        )

    monkeypatch.setattr(module, "_atomic_rename_noreplace", rename_then_tamper)
    receipt = _publish_full_c6_bundle(
        publication_root=publication_root,
        bundle_name="candidate",
        bundle_files=files,
        request=request,
        gate_result=result,
        public_key_path=tmp_path / "gate" / "owner.pub",
    )

    published_evidence = (
        publication_root / "candidate" / "rextio.full-c6-evidence.json"
    )
    expected = next(item for item in receipt.files if item.role == ROLE_FINAL_EVIDENCE)
    assert receipt.publication_completed is True
    assert published_evidence.read_bytes() == b"tampered-after-rename"
    assert hashlib.sha256(published_evidence.read_bytes()).hexdigest() != expected.sha256
    with pytest.raises(FullC6PublicationError, match="already exists"):
        _publish_full_c6_bundle(
            publication_root=publication_root,
            bundle_name="candidate",
            bundle_files=files,
            request=request,
            gate_result=result,
            public_key_path=tmp_path / "gate" / "owner.pub",
        )


def test_post_commit_directory_fsync_failure_keeps_completed_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    files, request, result = _authorized_bundle(tmp_path)
    publication_root = tmp_path / "dist"
    publication_root.mkdir(mode=0o700)
    import rextio.build.full_c6_publication as module

    rename = module._atomic_rename_noreplace
    fsync = module.os.fsync
    committed = False

    def tracked_rename(
        directory_fd: int,
        *,
        source_name: str,
        destination_name: str,
    ) -> None:
        nonlocal committed
        rename(
            directory_fd,
            source_name=source_name,
            destination_name=destination_name,
        )
        committed = True

    def fail_only_after_commit(descriptor: int) -> None:
        if committed:
            raise OSError("synthetic post-commit durability uncertainty")
        fsync(descriptor)

    monkeypatch.setattr(module, "_atomic_rename_noreplace", tracked_rename)
    monkeypatch.setattr(module.os, "fsync", fail_only_after_commit)

    receipt = _publish_full_c6_bundle(
        publication_root=publication_root,
        bundle_name="candidate",
        bundle_files=files,
        request=request,
        gate_result=result,
        public_key_path=tmp_path / "gate" / "owner.pub",
    )

    assert committed is True
    assert receipt.publication_completed is True
    assert (publication_root / "candidate").is_dir()


def test_post_commit_durability_and_close_helpers_never_raise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rextio.build.full_c6_publication as module

    def fail(_descriptor: int) -> None:
        raise OSError("synthetic post-commit descriptor failure")

    monkeypatch.setattr(module.os, "fsync", fail)
    monkeypatch.setattr(module.os, "close", fail)

    module._best_effort_postcommit_fsync(-1)
    module._best_effort_close(-1)


def test_mutated_request_cannot_replay_authorization(tmp_path: Path) -> None:
    files, request, result = _authorized_bundle(tmp_path)
    publication_root = tmp_path / "dist"
    publication_root.mkdir(mode=0o700)
    replay = replace(request, project_sha256="f" * 64)
    with pytest.raises(FullC6PublicationError, match="bindings"):
        _publish_full_c6_bundle(
            publication_root=publication_root,
            bundle_name="candidate",
            bundle_files=files,
            request=replay,
            gate_result=result,
            public_key_path=tmp_path / "gate" / "owner.pub",
        )
