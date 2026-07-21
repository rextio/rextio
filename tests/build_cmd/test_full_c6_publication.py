from __future__ import annotations

import ctypes
from dataclasses import replace
import errno
import os
from pathlib import Path
import runpy

import pytest

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
    publish_full_c6_bundle,
)
from rextio.build.signing import FinalAuthorizationRequest


_THIS_DIR = Path(__file__).parent
_GATE = runpy.run_path(str(_THIS_DIR / "test_full_c6_gate.py"))


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
    _preauthorization, request, result = _GATE["_authorize"](
        fixture_root,
        arguments,
    )
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
    receipt = publish_full_c6_bundle(
        publication_root=publication_root,
        bundle_name="candidate",
        bundle_files=files,
        request=request,
        evidence=result.evidence,
        authorization=result.authorization,
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


def test_direct_fake_authorization_is_rejected(tmp_path: Path) -> None:
    files, request, result = _authorized_bundle(tmp_path)
    publication_root = tmp_path / "dist"
    publication_root.mkdir(mode=0o700)
    fake = object.__new__(FullC6DistributionAuthorization)

    with pytest.raises(FullC6PublicationError, match="sealed authorization"):
        publish_full_c6_bundle(
            publication_root=publication_root,
            bundle_name="candidate",
            bundle_files=files,
            request=request,
            evidence=result.evidence,
            authorization=fake,
        )
    assert tuple(publication_root.iterdir()) == ()


@pytest.mark.parametrize("omit", FULL_C6_PUBLICATION_ROLES)
def test_missing_bundle_role_is_rejected(tmp_path: Path, omit: str) -> None:
    files, request, result = _authorized_bundle(tmp_path)
    files.pop(omit)
    publication_root = tmp_path / "dist"
    publication_root.mkdir(mode=0o700)
    with pytest.raises(FullC6PublicationError, match="closed six-file set"):
        publish_full_c6_bundle(
            publication_root=publication_root,
            bundle_name="candidate",
            bundle_files=files,
            request=request,
            evidence=result.evidence,
            authorization=result.authorization,
        )


def test_extra_bundle_role_is_rejected(tmp_path: Path) -> None:
    files, request, result = _authorized_bundle(tmp_path)
    files["unexpected"] = files[ROLE_CYCLONEDX]
    publication_root = tmp_path / "dist"
    publication_root.mkdir(mode=0o700)
    with pytest.raises(FullC6PublicationError, match="closed six-file set"):
        publish_full_c6_bundle(
            publication_root=publication_root,
            bundle_name="candidate",
            bundle_files=files,
            request=request,
            evidence=result.evidence,
            authorization=result.authorization,
        )


def test_symlink_hardlink_and_special_bundle_members_are_rejected(tmp_path: Path) -> None:
    files, request, result = _authorized_bundle(tmp_path)
    publication_root = tmp_path / "dist"
    publication_root.mkdir(mode=0o700)

    symlink = tmp_path / "signature-link"
    symlink.symlink_to(files[ROLE_DETACHED_SIGNATURE])
    symlink_files = {**files, ROLE_DETACHED_SIGNATURE: symlink}
    with pytest.raises(FullC6PublicationError, match="symlink"):
        publish_full_c6_bundle(
            publication_root=publication_root,
            bundle_name="symlink",
            bundle_files=symlink_files,
            request=request,
            evidence=result.evidence,
            authorization=result.authorization,
        )

    hardlink = tmp_path / "authorization-hardlink"
    os.link(files[ROLE_DISTRIBUTION_AUTHORIZATION], hardlink)
    hardlink_files = {**files, ROLE_DISTRIBUTION_AUTHORIZATION: hardlink}
    with pytest.raises(FullC6PublicationError, match="single-linked"):
        publish_full_c6_bundle(
            publication_root=publication_root,
            bundle_name="hardlink",
            bundle_files=hardlink_files,
            request=request,
            evidence=result.evidence,
            authorization=result.authorization,
        )
    hardlink.unlink()

    fifo = tmp_path / "signature.fifo"
    os.mkfifo(fifo)
    fifo_files = {**files, ROLE_DETACHED_SIGNATURE: fifo}
    with pytest.raises(FullC6PublicationError, match="regular"):
        publish_full_c6_bundle(
            publication_root=publication_root,
            bundle_name="fifo",
            bundle_files=fifo_files,
            request=request,
            evidence=result.evidence,
            authorization=result.authorization,
        )


def test_unsafe_or_preexisting_publication_target_is_rejected(tmp_path: Path) -> None:
    files, request, result = _authorized_bundle(tmp_path)
    unsafe = tmp_path / "unsafe-dist"
    unsafe.mkdir(mode=0o777)
    unsafe.chmod(0o777)
    with pytest.raises(FullC6PublicationError, match="group/world writable"):
        publish_full_c6_bundle(
            publication_root=unsafe,
            bundle_name="candidate",
            bundle_files=files,
            request=request,
            evidence=result.evidence,
            authorization=result.authorization,
        )

    actual_root = tmp_path / "actual-dist"
    actual_root.mkdir(mode=0o700)
    linked_root = tmp_path / "linked-dist"
    linked_root.symlink_to(actual_root, target_is_directory=True)
    with pytest.raises(FullC6PublicationError, match="symlink"):
        publish_full_c6_bundle(
            publication_root=linked_root,
            bundle_name="candidate",
            bundle_files=files,
            request=request,
            evidence=result.evidence,
            authorization=result.authorization,
        )

    publication_root = tmp_path / "dist"
    publication_root.mkdir(mode=0o700)
    (publication_root / "candidate").mkdir()
    with pytest.raises(FullC6PublicationError, match="already exists"):
        publish_full_c6_bundle(
            publication_root=publication_root,
            bundle_name="candidate",
            bundle_files=files,
            request=request,
            evidence=result.evidence,
            authorization=result.authorization,
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
        publish_full_c6_bundle(
            publication_root=publication_root,
            bundle_name="candidate",
            bundle_files=files,
            request=request,
            evidence=result.evidence,
            authorization=result.authorization,
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
        publish_full_c6_bundle(
            publication_root=publication_root,
            bundle_name="candidate",
            bundle_files=files,
            request=request,
            evidence=result.evidence,
            authorization=result.authorization,
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
        publish_full_c6_bundle(
            publication_root=publication_root,
            bundle_name="candidate",
            bundle_files=files,
            request=request,
            evidence=result.evidence,
            authorization=result.authorization,
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
        publish_full_c6_bundle(
            publication_root=publication_root,
            bundle_name="candidate",
            bundle_files=files,
            request=request,
            evidence=result.evidence,
            authorization=result.authorization,
        )


def test_mutated_request_cannot_replay_authorization(tmp_path: Path) -> None:
    files, request, result = _authorized_bundle(tmp_path)
    publication_root = tmp_path / "dist"
    publication_root.mkdir(mode=0o700)
    replay = replace(request, project_sha256="f" * 64)
    with pytest.raises(FullC6PublicationError, match="bindings"):
        publish_full_c6_bundle(
            publication_root=publication_root,
            bundle_name="candidate",
            bundle_files=files,
            request=replay,
            evidence=result.evidence,
            authorization=result.authorization,
        )
