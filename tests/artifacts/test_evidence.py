"""Unit tests for the C6.2 bounded artifact-evidence preview helpers."""

from __future__ import annotations

import io
import json
import struct
import zipfile
from pathlib import Path

import pytest

from rextio.artifacts.evidence import (
    DEFAULT_LIMITATIONS,
    REASON_CARGO_GRAPH_INVALID,
    ArtifactEvidence,
    ArtifactEvidenceError,
    ArtifactEvidenceGate,
    CargoDepEdge,
    CargoPackageRef,
    EvidenceFileRef,
    SidecarArtifact,
    WheelEntryRef,
    build_cyclonedx_document,
    build_intoto_provenance_document,
    canonicalize_registry_source,
    canonicalize_zip_entry_name,
    cleanup_created_sidecars,
    cleanup_paths,
    hash_regular_file,
    inventory_wheel_zip,
    load_wheel_snapshot,
    pretty_json_bytes,
    project_relative_logical_path,
    read_regular_file_bytes,
    sha256_hex,
    validate_logical_reference,
    write_atomic_bytes,
)


def test_required_artifact_evidence_gate_is_non_authorizing() -> None:
    satisfied = ArtifactEvidenceGate.from_evidence(
        ArtifactEvidence(
            kind="host-extension-wheel",
            status="preview-ready",
            target_triple="x86_64-unknown-linux-gnu",
            subject=EvidenceFileRef(
                logical_path="dist/demo.whl", sha256="0" * 64, size=1, role="wheel"
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
        )
    )
    assert satisfied.to_dict() == {
        "mode": "required",
        "status": "satisfied",
        "scope": "host-extension-wheel-cpython-v1",
        "required_status": "preview-ready",
        "observed_status": "preview-ready",
        "reason": None,
        "evidence_reason": None,
        "distribution_authorized": False,
        "complete": False,
        "signed": False,
    }

    blocked = ArtifactEvidenceGate.from_evidence(
        ArtifactEvidence.unavailable(reason="cargo-metadata-failed")
    )
    assert blocked.status == "blocked"
    assert blocked.reason == "evidence-unavailable"
    assert blocked.evidence_reason == "cargo-metadata-failed"
    assert blocked.distribution_authorized is False


def test_validate_logical_reference_rejects_absolute_and_escape() -> None:
    validate_logical_reference("dist/demo.whl")
    with pytest.raises(ValueError):
        validate_logical_reference("/tmp/secret.whl")
    with pytest.raises(ValueError):
        validate_logical_reference("../escape.whl")
    with pytest.raises(ValueError):
        validate_logical_reference("C:\\Windows\\secret.whl")


def test_project_relative_logical_path_and_safe_read(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    target = root / "dist" / "demo.whl"
    target.parent.mkdir()
    payload = b"wheel-bytes"
    target.write_bytes(payload)

    logical = project_relative_logical_path(root, target)
    assert logical == "dist/demo.whl"
    assert read_regular_file_bytes(target) == payload
    digest, size = hash_regular_file(target)
    assert size == len(payload)
    assert digest == sha256_hex(payload)


def test_read_regular_file_rejects_symlink(tmp_path: Path) -> None:
    real = tmp_path / "real.bin"
    real.write_bytes(b"secret")
    link = tmp_path / "link.bin"
    link.symlink_to(real)
    with pytest.raises(ArtifactEvidenceError, match="regular non-symlink"):
        read_regular_file_bytes(link)


def test_write_atomic_bytes_randomized_temp_and_cleanup(tmp_path: Path) -> None:
    path = tmp_path / "out.cdx.json"
    data = pretty_json_bytes({"a": 1, "b": [2, 3]})
    write_atomic_bytes(path, data)
    assert path.read_bytes() == data
    assert not list(tmp_path.glob(".out.cdx.json.*.tmp"))
    cleanup_paths([path])
    assert not path.exists()


@pytest.mark.skipif(__import__("os").name == "nt", reason="dirfd write path is POSIX-only")
def test_dirfd_write_oserror_is_sanitized_and_exact_temp_is_cleaned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from rextio.artifacts import evidence as evidence_mod

    assert evidence_mod._dirfd_ops_available()
    target = tmp_path / "out.cdx.json"
    token = "forcedtoken"
    exact_temp = tmp_path / f".{target.name}.{token}.tmp"
    unrelated_temp = tmp_path / f".{target.name}.someone-else.tmp"
    unrelated_temp.write_bytes(b"preserve")
    monkeypatch.setattr(evidence_mod.secrets, "token_hex", lambda _size: token)

    def fail_write(_fd: int, _data: object) -> int:
        raise OSError("raw write failure must not escape")

    monkeypatch.setattr(evidence_mod.os, "write", fail_write)
    with pytest.raises(ArtifactEvidenceError) as exc:
        write_atomic_bytes(target, b'{"x":1}\n')
    assert exc.value.reason == "sidecar-write-failed"
    assert "raw write failure" not in str(exc.value)
    assert not exact_temp.exists()
    assert not target.exists()
    assert unrelated_temp.read_bytes() == b"preserve"


@pytest.mark.skipif(__import__("os").name == "nt", reason="dirfd write path is POSIX-only")
def test_pinned_parent_close_cannot_mask_verification_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from rextio.artifacts import evidence as evidence_mod

    assert evidence_mod._dirfd_ops_available()
    real_close = evidence_mod.os.close

    def fail_fstat(_fd: int):
        raise OSError("primary verification failure")

    def close_then_fail(fd: int) -> None:
        real_close(fd)
        raise OSError("secondary close failure")

    with monkeypatch.context() as scoped:
        scoped.setattr(evidence_mod.os, "fstat", fail_fstat)
        scoped.setattr(evidence_mod.os, "close", close_then_fail)
        with pytest.raises(ArtifactEvidenceError) as exc:
            evidence_mod._open_pinned_parent_dirfd(tmp_path)
    assert exc.value.reason == "sidecar-write-failed"
    assert "close failure" not in str(exc.value)


@pytest.mark.skipif(__import__("os").name == "nt", reason="dirfd write path is POSIX-only")
def test_dirfd_close_failure_after_replace_keeps_write_successful(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from rextio.artifacts import evidence as evidence_mod

    assert evidence_mod._dirfd_ops_available()
    target = tmp_path / "out.cdx.json"
    data = b'{"ok":true}\n'
    real_open_parent = evidence_mod._open_pinned_parent_dirfd
    real_close = evidence_mod.os.close
    pinned_fd: dict[str, int] = {}

    def capture_parent(parent: Path):
        result = real_open_parent(parent)
        pinned_fd["value"] = result[0]
        return result

    def close_then_fail_for_parent(fd: int) -> None:
        real_close(fd)
        if fd == pinned_fd.get("value"):
            raise OSError("post-replace directory close failure")

    monkeypatch.setattr(evidence_mod, "_open_pinned_parent_dirfd", capture_parent)
    monkeypatch.setattr(evidence_mod.os, "close", close_then_fail_for_parent)
    written = write_atomic_bytes(target, data)
    assert written == target
    assert target.read_bytes() == data
    assert not list(tmp_path.glob(".out.cdx.json.*.tmp"))


def test_canonicalize_registry_source_rejects_credentials_and_query() -> None:
    ok = canonicalize_registry_source(
        "registry+https://github.com/rust-lang/crates.io-index"
    )
    assert ok == "registry+https://github.com/rust-lang/crates.io-index"
    with pytest.raises(ArtifactEvidenceError) as exc:
        canonicalize_registry_source(
            "registry+https://user:token@github.com/rust-lang/crates.io-index"
        )
    assert exc.value.reason == REASON_CARGO_GRAPH_INVALID
    with pytest.raises(ArtifactEvidenceError):
        canonicalize_registry_source(
            "registry+https://github.com/rust-lang/crates.io-index?token=secret"
        )
    with pytest.raises(ArtifactEvidenceError):
        canonicalize_registry_source("registry+file:///tmp/index")
    with pytest.raises(ArtifactEvidenceError):
        canonicalize_registry_source("git+https://github.com/example/repo")


def test_unavailable_evidence_shape() -> None:
    evidence = ArtifactEvidence.unavailable(
        reason="cargo-lock-missing", target_triple="aarch64-apple-darwin"
    )
    data = evidence.to_dict()
    assert data["status"] == "unavailable"
    assert data["authority"] == "evidence-only"
    assert data["signature_status"] == "unsigned"
    assert data["composition"] == "incomplete"
    assert data["reason"] == "cargo-lock-missing"
    assert data["preview"] is True
    assert data["complete"] is False
    assert data["signed"] is False
    assert "subject" not in data
    assert "sbom" not in data


def test_cyclonedx_no_duplicate_root_and_real_version() -> None:
    subject = EvidenceFileRef(
        logical_path="dist/demo-1.2.3-py3-none-any.whl",
        sha256="a" * 64,
        size=12,
        role="host-extension-wheel",
    )
    inputs = (
        EvidenceFileRef(
            logical_path=".rextio/generated/rust/src/lib.rs",
            sha256="b" * 64,
            size=34,
            role="generated-rust-input",
        ),
    )
    packages = (
        CargoPackageRef(
            name="pyo3",
            version="0.29.0",
            source="registry+https://github.com/rust-lang/crates.io-index",
            checksum="d" * 64,
            kind="registry",
            features=("extension-module",),
        ),
    )
    edges: tuple[CargoDepEdge, ...] = ()
    wheel_entries = (
        WheelEntryRef(
            name="demo/__init__.py",
            sha256="c" * 64,
            compressed_size=10,
            uncompressed_size=20,
        ),
    )
    cdx = build_cyclonedx_document(
        subject=subject,
        inputs=inputs,
        wheel_entries=wheel_entries,
        cargo_packages=packages,
        cargo_dependencies=edges,
        target_triple="aarch64-apple-darwin",
    )
    assert cdx["metadata"]["component"]["version"] == "1.2.3"
    root_ref = cdx["metadata"]["component"]["bom-ref"]
    component_refs = [item["bom-ref"] for item in cdx["components"]]
    assert root_ref not in component_refs
    assert cdx["compositions"][0]["aggregate"] == "incomplete"
    assert "dependencies" in cdx
    assert any(item["ref"] == root_ref for item in cdx["dependencies"])
    pyo3 = next(c for c in cdx["components"] if c["name"] == "pyo3")
    dependency_rows = {item["ref"]: item["dependsOn"] for item in cdx["dependencies"]}
    assert set(dependency_rows) == {
        root_ref,
        *(component["bom-ref"] for component in cdx["components"]),
    }
    assert dependency_rows[pyo3["bom-ref"]] == []
    props = {p["name"]: p["value"] for p in pyo3["properties"]}
    assert "rextio:source" not in props
    assert "rextio:source_fingerprint" in props
    assert len(props["rextio:source_fingerprint"]) == 64
    text = json.dumps(cdx)
    assert "1.2.3" in text
    assert "github.com" not in text
    assert "/Users/" not in text
    assert "token" not in text


def test_intoto_sbom_is_subject_not_material() -> None:
    subject = EvidenceFileRef(
        logical_path="dist/demo-1.2.3-py3-none-any.whl",
        sha256="a" * 64,
        size=12,
        role="host-extension-wheel",
    )
    sbom = EvidenceFileRef(
        logical_path="dist/demo-1.2.3-py3-none-any.whl.cdx.json",
        sha256="f" * 64,
        size=99,
        role="cyclonedx-sbom",
    )
    inputs = (
        EvidenceFileRef(
            logical_path="src/app.py",
            sha256="c" * 64,
            size=56,
            role="project-python-source",
        ),
    )
    packages = (
        CargoPackageRef(
            name="base64",
            version="0.22.1",
            source="registry+https://github.com/rust-lang/crates.io-index",
            checksum="e" * 64,
            kind="registry",
        ),
    )
    prov = build_intoto_provenance_document(
        subject=subject,
        sbom=sbom,
        inputs=inputs,
        cargo_packages=packages,
        target_triple="aarch64-apple-darwin",
    )
    subjects = prov["subject"]
    assert len(subjects) == 2
    assert subjects[0]["name"] == subject.logical_path
    assert subjects[1]["name"] == sbom.logical_path
    materials = prov["predicate"]["buildDefinition"]["resolvedDependencies"]
    material_uris = [item["uri"] for item in materials]
    assert f"file:{sbom.logical_path}" not in material_uris
    assert f"file:{inputs[0].logical_path}" in material_uris
    assert "invocationId" not in prov["predicate"]["runDetails"]["metadata"]
    assert prov["predicate"]["buildDefinition"]["internalParameters"]["signed"] is False
    assert all(
        item in DEFAULT_LIMITATIONS
        for item in (
            "preview-only",
            "composition-incomplete",
            "unsigned",
            "not-external-source-authorization",
        )
    )


def _write_zip(path: Path, entries: list[tuple[str, bytes]]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries:
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)


def test_wheel_inventory_happy_path(tmp_path: Path) -> None:
    wheel = tmp_path / "demo-0.1.0-py3-none-any.whl"
    _write_zip(
        wheel,
        [
            ("demo/__init__.py", b"print(1)\n"),
            ("demo/mod.py", b"x = 2\n"),
        ],
    )
    entries = inventory_wheel_zip(wheel)
    assert [item.name for item in entries] == ["demo/__init__.py", "demo/mod.py"]
    assert all(len(item.sha256) == 64 for item in entries)


def test_wheel_inventory_rejects_absolute_and_parent_paths(tmp_path: Path) -> None:
    wheel = tmp_path / "bad.whl"
    _write_zip(wheel, [("../escape.py", b"x")])
    with pytest.raises(ArtifactEvidenceError, match="dot segment|escapes|invalid|noncanonical"):
        inventory_wheel_zip(wheel)

    wheel2 = tmp_path / "abs.whl"
    # zipfile normalizes leading slash on some platforms; craft via ZipInfo.
    with zipfile.ZipFile(wheel2, "w") as archive:
        info = zipfile.ZipInfo("/abs.py")
        archive.writestr(info, b"x")
    with pytest.raises(ArtifactEvidenceError):
        inventory_wheel_zip(wheel2)


def test_wheel_inventory_rejects_duplicates(tmp_path: Path) -> None:
    # Craft a STORED ZIP with two central-directory entries for the same name.
    import zlib

    wheel = tmp_path / "dup.whl"
    name = b"dup.py"
    data1 = b"one"
    data2 = b"two"

    def local_header(data: bytes) -> bytes:
        crc = zlib.crc32(data) & 0xFFFFFFFF
        return (
            struct.pack(
                "<IHHHHHIIIHH",
                0x04034B50,
                20,
                0,
                0,  # stored
                0,
                0,
                crc,
                len(data),
                len(data),
                len(name),
                0,
            )
            + name
            + data
        )

    local1 = local_header(data1)
    local2 = local_header(data2)

    def central(data: bytes, offset: int) -> bytes:
        crc = zlib.crc32(data) & 0xFFFFFFFF
        return (
            struct.pack(
                "<IHHHHHHIIIHHHHHII",
                0x02014B50,
                20,
                20,
                0,
                0,
                0,
                0,
                crc,
                len(data),
                len(data),
                len(name),
                0,
                0,
                0,
                0,
                0,
                offset,
            )
            + name
        )

    central_dir = central(data1, 0) + central(data2, len(local1))
    end = struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        2,
        2,
        len(central_dir),
        len(local1) + len(local2),
        0,
    )
    payload = local1 + local2 + central_dir + end
    # Confirm ZipFile sees both entries before inventory rejects.
    with zipfile.ZipFile(io.BytesIO(payload), "r") as archive:
        assert len(archive.infolist()) == 2
        assert archive.infolist()[0].filename == archive.infolist()[1].filename == "dup.py"
    wheel.write_bytes(payload)
    with pytest.raises(ArtifactEvidenceError, match="duplicate"):
        inventory_wheel_zip(wheel)

    with pytest.raises(ArtifactEvidenceError, match="noncanonical|invalid"):
        canonicalize_zip_entry_name("demo//a.py")

    wheel_bs = tmp_path / "bs.whl"
    with zipfile.ZipFile(wheel_bs, "w") as archive:
        info = zipfile.ZipInfo("demo\\a.py")
        archive.writestr(info, b"x")
    with pytest.raises(ArtifactEvidenceError):
        inventory_wheel_zip(wheel_bs)


def test_wheel_inventory_rejects_dot_segments_and_controls() -> None:
    with pytest.raises(ArtifactEvidenceError):
        canonicalize_zip_entry_name("./foo.py")
    with pytest.raises(ArtifactEvidenceError):
        canonicalize_zip_entry_name("a/../b.py")
    with pytest.raises(ArtifactEvidenceError):
        canonicalize_zip_entry_name("foo\x00.py")
    with pytest.raises(ArtifactEvidenceError):
        canonicalize_zip_entry_name("C:foo.py")


def test_load_wheel_snapshot_uses_one_byte_buffer(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    wheel = project / "demo-1.0.0-py3-none-any.whl"
    _write_zip(wheel, [("demo/__init__.py", b"print(1)\n")])
    subject, entries = load_wheel_snapshot(wheel, project_root=project)
    assert subject.sha256 == sha256_hex(wheel.read_bytes())
    assert subject.size == wheel.stat().st_size
    assert entries[0].name == "demo/__init__.py"


def test_cyclonedx_named_license_and_input_bomref_identity() -> None:
    subject = EvidenceFileRef(
        logical_path="dist/demo-9.9.9-py3-none-any.whl",
        sha256="1" * 64,
        size=1,
        role="host-extension-wheel",
    )
    inputs = (
        EvidenceFileRef(
            logical_path="src/app.py",
            sha256="2" * 64,
            size=2,
            role="project-python-source",
        ),
    )
    packages = (
        CargoPackageRef(
            name="log",
            version="0.4.0",
            source="registry+https://github.com/rust-lang/crates.io-index",
            checksum="3" * 64,
            kind="registry",
            license="custom internal license text",
        ),
    )
    cdx = build_cyclonedx_document(
        subject=subject,
        inputs=inputs,
        wheel_entries=(),
        cargo_packages=packages,
        cargo_dependencies=(),
        target_triple="x86_64-unknown-linux-gnu",
    )
    log = next(c for c in cdx["components"] if c["name"] == "log")
    assert log["licenses"] == [
        {"license": {"name": "custom internal license text"}}
    ]
    inp = next(c for c in cdx["components"] if c["name"] == "app.py")
    assert inp["bom-ref"] != f"urn:rextio:input:{'2' * 64}"
    assert inp["bom-ref"].startswith("urn:rextio:input:")


def test_cargo_dependency_edges_reject_self_and_dangling_endpoints() -> None:
    package = CargoPackageRef(
        name="root",
        version="1.0.0",
        source=None,
        checksum=None,
        kind="path-root",
    )
    with pytest.raises(ValueError, match="self"):
        CargoDepEdge(
            dependent_ref=package.bom_ref(), dependency_ref=package.bom_ref()
        )

    dangling = CargoDepEdge(
        dependent_ref=package.bom_ref(),
        dependency_ref="urn:rextio:cargo:missing",
    )
    subject = EvidenceFileRef(
        logical_path="dist/demo-1.0.0-py3-none-any.whl",
        sha256="1" * 64,
        size=1,
        role="host-extension-wheel",
    )
    with pytest.raises(ArtifactEvidenceError) as exc:
        build_cyclonedx_document(
            subject=subject,
            inputs=(),
            wheel_entries=(),
            cargo_packages=(package,),
            cargo_dependencies=(dangling,),
            target_triple="x86_64-unknown-linux-gnu",
        )
    assert exc.value.reason == REASON_CARGO_GRAPH_INVALID


def test_cargo_package_document_order_uses_full_identity() -> None:
    subject = EvidenceFileRef(
        logical_path="dist/demo-1.0.0-py3-none-any.whl",
        sha256="1" * 64,
        size=1,
        role="host-extension-wheel",
    )
    sbom = EvidenceFileRef(
        logical_path="dist/demo-1.0.0-py3-none-any.whl.cdx.json",
        sha256="2" * 64,
        size=2,
        role="cyclonedx-sbom",
    )
    first = CargoPackageRef(
        name="same",
        version="1.0.0",
        source="registry+https://a.example/index",
        checksum="a" * 64,
        kind="registry",
    )
    second = CargoPackageRef(
        name="same",
        version="1.0.0",
        source="registry+https://b.example/index",
        checksum="b" * 64,
        kind="registry",
    )

    cdx_forward = build_cyclonedx_document(
        subject=subject,
        inputs=(),
        wheel_entries=(),
        cargo_packages=(first, second),
        cargo_dependencies=(),
        target_triple="x86_64-unknown-linux-gnu",
    )
    cdx_reverse = build_cyclonedx_document(
        subject=subject,
        inputs=(),
        wheel_entries=(),
        cargo_packages=(second, first),
        cargo_dependencies=(),
        target_triple="x86_64-unknown-linux-gnu",
    )
    provenance_forward = build_intoto_provenance_document(
        subject=subject,
        sbom=sbom,
        inputs=(),
        cargo_packages=(first, second),
        target_triple="x86_64-unknown-linux-gnu",
    )
    provenance_reverse = build_intoto_provenance_document(
        subject=subject,
        sbom=sbom,
        inputs=(),
        cargo_packages=(second, first),
        target_triple="x86_64-unknown-linux-gnu",
    )
    assert cdx_forward == cdx_reverse
    assert provenance_forward == provenance_reverse


def test_wheel_inventory_rejects_symlink_entry(tmp_path: Path) -> None:
    wheel = tmp_path / "symlink.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        info = zipfile.ZipInfo("link.py")
        # Unix symlink mode in high 16 bits of external_attr.
        info.external_attr = 0o120777 << 16
        archive.writestr(info, b"target")
    with pytest.raises(ArtifactEvidenceError, match="symlink"):
        inventory_wheel_zip(wheel)


def test_wheel_inventory_rejects_encrypted_entry(tmp_path: Path) -> None:
    wheel = tmp_path / "enc.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        info = zipfile.ZipInfo("secret.py")
        info.flag_bits |= 0x1
        archive.writestr(info, b"secret")
    # ZipFile may clear encryption bit on writestr; if so, construct raw zip.
    # Re-open and check; if encryption not preserved, craft minimal encrypted flag.
    with zipfile.ZipFile(wheel, "r") as archive:
        infos = archive.infolist()
        if infos and (infos[0].flag_bits & 0x1):
            with pytest.raises(ArtifactEvidenceError, match="encrypted"):
                inventory_wheel_zip(wheel)
            return
    # Manual minimal ZIP with encryption flag set in local+central headers.
    # Local file header structure with flag bit 0 set.
    name = b"secret.py"
    data = b"x"
    # Store without compression.
    local = struct.pack(
        "<IHHHHHIIIHH",
        0x04034B50,
        20,
        0x1,  # encrypted
        0,
        0,
        0,
        0,
        len(data),
        len(data),
        len(name),
        0,
    )
    central = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        0x02014B50,
        20,
        20,
        0x1,
        0,
        0,
        0,
        0,
        len(data),
        len(data),
        len(name),
        0,
        0,
        0,
        0,
        0,
        0,
    )
    end = struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        1,
        1,
        len(central) + len(name),
        len(local) + len(name) + len(data),
        0,
    )
    wheel.write_bytes(local + name + data + central + name + end)
    with pytest.raises(ArtifactEvidenceError, match="encrypted|ZIP|invalid"):
        inventory_wheel_zip(wheel)


def test_wheel_inventory_rejects_zip_bomb_size(tmp_path: Path) -> None:
    from rextio.artifacts import evidence as evidence_mod

    wheel = tmp_path / "bomb.whl"
    _write_zip(wheel, [("big.bin", b"x" * 100)])
    original = evidence_mod.MAX_WHEEL_ENTRY_UNCOMPRESSED
    evidence_mod.MAX_WHEEL_ENTRY_UNCOMPRESSED = 50
    try:
        with pytest.raises(ArtifactEvidenceError, match="uncompressed size"):
            inventory_wheel_zip(wheel)
    finally:
        evidence_mod.MAX_WHEEL_ENTRY_UNCOMPRESSED = original


def test_error_message_redacts_absolute_paths_and_identities() -> None:
    error = ArtifactEvidenceError("failed to read /Users/me/secret/project/file.whl")
    message = str(error)
    assert "/Users/me" not in message
    assert "secret" not in message
    assert "redacted-path" in message


def test_content_uuid_urn_is_deterministic_rfc4122_uuidv5() -> None:
    from rextio.artifacts.evidence import content_uuid_urn
    import uuid

    digest = "a" * 64
    first = content_uuid_urn(digest)
    second = content_uuid_urn(digest)
    assert first == second
    assert first.startswith("urn:uuid:")
    value = uuid.UUID(first.removeprefix("urn:uuid:"))
    assert value.version == 5
    # Different digests yield different serial numbers.
    assert content_uuid_urn("b" * 64) != first


def test_cyclonedx_serial_number_uses_uuidv5() -> None:
    from rextio.artifacts.evidence import content_uuid_urn

    subject = EvidenceFileRef(
        logical_path="dist/demo-1.0.0-py3-none-any.whl",
        sha256="c" * 64,
        size=1,
        role="host-extension-wheel",
    )
    cdx = build_cyclonedx_document(
        subject=subject,
        inputs=(),
        wheel_entries=(),
        cargo_packages=(),
        cargo_dependencies=(),
        target_triple="x86_64-unknown-linux-gnu",
    )
    assert cdx["serialNumber"] == content_uuid_urn(subject.sha256)


def test_unavailable_reason_must_be_in_fixed_allowlist() -> None:
    from rextio.artifacts.evidence import UNAVAILABLE_REASONS, REASON_WHEEL_MUTATED

    assert REASON_WHEEL_MUTATED in UNAVAILABLE_REASONS
    with pytest.raises(ValueError, match="allowlist"):
        ArtifactEvidence.unavailable(reason="not-a-real-reason")
    ok = ArtifactEvidence.unavailable(reason=REASON_WHEEL_MUTATED)
    assert ok.reason == REASON_WHEEL_MUTATED


def test_preview_ready_and_unavailable_status_invariants() -> None:
    subject = EvidenceFileRef(
        logical_path="dist/demo.whl",
        sha256="a" * 64,
        size=1,
        role="host-extension-wheel",
    )
    sbom = SidecarArtifact(
        format="CycloneDX",
        logical_path="dist/demo.whl.cdx.json",
        sha256="b" * 64,
        size=2,
    )
    prov = SidecarArtifact(
        format="in-toto-Statement",
        logical_path="dist/demo.whl.intoto.json",
        sha256="c" * 64,
        size=3,
    )
    ready = ArtifactEvidence(
        kind="host-extension-wheel",
        status="preview-ready",
        target_triple="aarch64-apple-darwin",
        subject=subject,
        sbom=sbom,
        provenance=prov,
    )
    data = ready.to_dict()
    assert data["status"] == "preview-ready"
    assert "reason" not in data
    assert data["subject"]["sha256"] == "a" * 64

    with pytest.raises(ValueError, match="reason"):
        ArtifactEvidence(
            kind="host-extension-wheel",
            status="preview-ready",
            target_triple="aarch64-apple-darwin",
            subject=subject,
            sbom=sbom,
            provenance=prov,
            reason="source-snapshot-mismatch",
        )
    with pytest.raises(ValueError, match="subject|sidecars"):
        ArtifactEvidence(
            kind="host-extension-wheel",
            status="unavailable",
            reason="cargo-lock-missing",
            subject=subject,
        )


def test_wheel_entry_ref_rejects_noncanonical_name() -> None:
    with pytest.raises(ValueError, match="noncanonical|invalid"):
        WheelEntryRef(
            name="demo//a.py",
            sha256="a" * 64,
            compressed_size=1,
            uncompressed_size=1,
        )
    with pytest.raises(ValueError, match="directory|zero"):
        WheelEntryRef(
            name="demo/",
            sha256=sha256_hex(b""),
            compressed_size=0,
            uncompressed_size=5,
        )


def test_cargo_package_repr_hides_registry_source() -> None:
    pkg = CargoPackageRef(
        name="pyo3",
        version="0.29.0",
        source="registry+https://github.com/rust-lang/crates.io-index",
        checksum="d" * 64,
        kind="registry",
    )
    text = repr(pkg)
    assert "github.com" not in text
    assert "registry+" not in text
    assert "source_fingerprint=" in text
    assert pkg.source is not None  # still retained internally for lock binding


def test_artifact_evidence_rejects_duplicate_cargo_bom_refs() -> None:
    subject = EvidenceFileRef(
        logical_path="dist/demo.whl",
        sha256="a" * 64,
        size=1,
        role="host-extension-wheel",
    )
    sbom = SidecarArtifact(
        format="CycloneDX",
        logical_path="dist/demo.whl.cdx.json",
        sha256="b" * 64,
        size=2,
    )
    prov = SidecarArtifact(
        format="in-toto-Statement",
        logical_path="dist/demo.whl.intoto.json",
        sha256="c" * 64,
        size=3,
    )
    pkg = CargoPackageRef(
        name="log",
        version="0.4.0",
        source="registry+https://github.com/rust-lang/crates.io-index",
        checksum="e" * 64,
        kind="registry",
    )
    with pytest.raises(ValueError, match="bom-ref|unique"):
        ArtifactEvidence(
            kind="host-extension-wheel",
            status="preview-ready",
            target_triple="x86_64-unknown-linux-gnu",
            subject=subject,
            sbom=sbom,
            provenance=prov,
            cargo_packages=(pkg, pkg),
        )


def test_wheel_inventory_rejects_nonempty_directory_entry(tmp_path: Path) -> None:
    wheel = tmp_path / "dirpayload.whl"
    # Craft STORED ZIP where a directory name ends with / but has payload bytes.
    import zlib

    name = b"pkg/"
    data = b"not-empty"
    crc = zlib.crc32(data) & 0xFFFFFFFF
    local = (
        struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            20,
            0,
            0,
            0,
            0,
            crc,
            len(data),
            len(data),
            len(name),
            0,
        )
        + name
        + data
    )
    central = (
        struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,
            20,
            20,
            0,
            0,
            0,
            0,
            crc,
            len(data),
            len(data),
            len(name),
            0,
            0,
            0,
            0,
            0,
            0,
        )
        + name
    )
    end = struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        1,
        1,
        len(central),
        len(local),
        0,
    )
    wheel.write_bytes(local + central + end)
    with pytest.raises(ArtifactEvidenceError, match="directory entry|empty|invalid"):
        inventory_wheel_zip(wheel)


def test_wheel_inventory_rejects_zip64_locator(tmp_path: Path) -> None:
    import zlib

    wheel = tmp_path / "zip64.whl"
    # Structurally valid classic local+central, with ZIP64 locator in its
    # legal 20-byte slot immediately before EOCD (not a payload scan).
    name = b"ok.py"
    data = b"x"
    crc = zlib.crc32(data) & 0xFFFFFFFF
    local = (
        struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            20,
            0,
            0,
            0,
            0,
            crc,
            len(data),
            len(data),
            len(name),
            0,
        )
        + name
        + data
    )
    central = (
        struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,
            20,
            20,
            0,
            0,
            0,
            0,
            crc,
            len(data),
            len(data),
            len(name),
            0,
            0,
            0,
            0,
            0,
            0,
        )
        + name
    )
    locator = b"PK\x06\x07" + (b"\x00" * 16)
    eocd = struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        1,
        1,
        len(central),
        len(local),
        0,
    )
    wheel.write_bytes(local + central + locator + eocd)
    with pytest.raises(ArtifactEvidenceError, match="ZIP64"):
        inventory_wheel_zip(wheel)


def test_wheel_inventory_rejects_orig_filename_nul(tmp_path: Path) -> None:
    # Craft raw ZIP so ZipFile keeps orig_filename with an embedded NUL while
    # truncating the public filename — inventory must fail closed on the orig.
    import zlib

    wheel = tmp_path / "nul.whl"
    name = b"evil\x00.py"
    data = b"x"
    crc = zlib.crc32(data) & 0xFFFFFFFF
    local = (
        struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            20,
            0,
            0,
            0,
            0,
            crc,
            len(data),
            len(data),
            len(name),
            0,
        )
        + name
        + data
    )
    central = (
        struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,
            20,
            20,
            0,
            0,
            0,
            0,
            crc,
            len(data),
            len(data),
            len(name),
            0,
            0,
            0,
            0,
            0,
            0,
        )
        + name
    )
    end = struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        1,
        1,
        len(central),
        len(local),
        0,
    )
    wheel.write_bytes(local + central + end)
    with zipfile.ZipFile(wheel, "r") as archive:
        info = archive.infolist()[0]
        assert "\0" in getattr(info, "orig_filename", "")
    with pytest.raises(ArtifactEvidenceError, match="NUL|control|invalid|noncanonical"):
        inventory_wheel_zip(wheel)


def test_write_atomic_rejects_symlink_parent_and_outside_sentinel(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel.txt"
    sentinel.write_text("keep-me\n", encoding="utf-8")

    real_dist = project / "real-dist"
    real_dist.mkdir()
    # dist is a symlink pointing outside the project.
    dist_link = project / "dist"
    dist_link.symlink_to(outside, target_is_directory=True)

    target = dist_link / "demo.whl.cdx.json"
    with pytest.raises(ArtifactEvidenceError) as exc:
        write_atomic_bytes(
            target,
            b'{"ok":true}\n',
            project_root=project,
            expected_parent=dist_link,
        )
    assert exc.value.reason == "sidecar-write-failed"
    assert sentinel.read_text(encoding="utf-8") == "keep-me\n"
    # Outside directory must not gain our sidecar name either when rejected early.
    assert not (outside / "demo.whl.cdx.json").exists()


def test_cleanup_paths_only_removes_named_paths(tmp_path: Path) -> None:
    a = tmp_path / "a.cdx.json"
    b = tmp_path / "b.intoto.json"
    c = tmp_path / "unrelated.json"
    a.write_text("{}", encoding="utf-8")
    b.write_text("{}", encoding="utf-8")
    c.write_text("{}", encoding="utf-8")
    cleanup_paths([a, b])
    assert not a.exists()
    assert not b.exists()
    assert c.exists()


def test_cleanup_created_sidecars_is_no_throw(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from rextio.artifacts import evidence as evidence_mod

    target = tmp_path / "created.cdx.json"
    target.write_bytes(b"preserve-on-cleanup-error")

    def fail_cleanup(*_args, **_kwargs) -> None:
        raise OSError("cleanup failed")

    monkeypatch.setattr(evidence_mod, "_cleanup_created_sidecars_impl", fail_cleanup)
    cleanup_created_sidecars(
        [target.name], project_root=tmp_path, expected_parent=tmp_path
    )
    assert target.read_bytes() == b"preserve-on-cleanup-error"


@pytest.mark.skipif(
    __import__("os").name == "nt", reason="dirfd write path is POSIX-only"
)
def test_dirfd_write_path_executes_when_path_fallback_forced_to_fail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Force path fallback to fail and prove the real dir_fd path still writes."""
    from rextio.artifacts import evidence as evidence_mod

    assert evidence_mod._dirfd_ops_available()
    project = tmp_path / "project"
    dist = project / "dist"
    dist.mkdir(parents=True)
    target = dist / "demo.whl.cdx.json"
    data = b'{"ok": true}\n'

    def boom_path(*_a, **_k):
        raise AssertionError("path fallback must not run when dirfd is available")

    monkeypatch.setattr(evidence_mod, "_write_atomic_bytes_path", boom_path)
    written = write_atomic_bytes(
        target, data, project_root=project, expected_parent=dist
    )
    assert written.read_bytes() == data
    assert not list(dist.glob(".demo.whl.cdx.json.*.tmp"))


@pytest.mark.skipif(
    __import__("os").name == "nt", reason="symlink parent cleanup is POSIX-focused"
)
def test_cleanup_created_sidecars_refuses_symlink_parent_outside_sentinel(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel-sidecar.json"
    sentinel.write_text("keep\n", encoding="utf-8")
    real_dist = project / "real-dist"
    real_dist.mkdir()
    (real_dist / "created.cdx.json").write_text("{}", encoding="utf-8")
    dist_link = project / "dist"
    dist_link.symlink_to(outside, target_is_directory=True)
    # Plant a same-named file outside as if a naive path unlink would hit it.
    (outside / "created.cdx.json").write_text("outside\n", encoding="utf-8")

    cleanup_created_sidecars(
        ["created.cdx.json"],
        project_root=project,
        expected_parent=dist_link,
    )
    # Symlinked parent: cleanup must refuse; outside sentinel and planted file remain.
    assert sentinel.read_text(encoding="utf-8") == "keep\n"
    assert (outside / "created.cdx.json").read_text(encoding="utf-8") == "outside\n"
    # Real in-project child under a non-symlink parent is still cleanable.
    cleanup_created_sidecars(
        ["created.cdx.json"],
        project_root=project,
        expected_parent=real_dist,
    )
    assert not (real_dist / "created.cdx.json").exists()


def test_classic_zip_with_pk0607_in_payload_is_accepted(tmp_path: Path) -> None:
    """Payload bytes may contain the ZIP64 locator signature; only legal position matters."""
    wheel = tmp_path / "payload.whl"
    # Member body deliberately contains PK\\x06\\x07.
    payload = b"prefix" + b"PK\x06\x07" + b"suffix-data"
    _write_zip(wheel, [("pkg/data.bin", payload)])
    entries = inventory_wheel_zip(wheel)
    assert len(entries) == 1
    assert entries[0].name == "pkg/data.bin"
    assert entries[0].sha256 == sha256_hex(payload)


def test_eocd_signature_inside_comment_does_not_hijack_real_eocd() -> None:
    """A classic EOCD signature mid-comment must not win over the real EOCD.

    Comment length must reach EOF, so a forged EOCD sitting in the middle of the
    archive comment is ignored; only the real trailing record (count=1) is used.
    """
    import zlib

    from rextio.artifacts.evidence import _preflight_zip_eocd_entry_count

    name = b"ok.py"
    data = b"x"
    crc = zlib.crc32(data) & 0xFFFFFFFF
    local = (
        struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            20,
            0,
            0,
            0,
            0,
            crc,
            len(data),
            len(data),
            len(name),
            0,
        )
        + name
        + data
    )
    central = (
        struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,
            20,
            20,
            0,
            0,
            0,
            0,
            crc,
            len(data),
            len(data),
            len(name),
            0,
            0,
            0,
            0,
            0,
            0,
        )
        + name
    )
    # Fake EOCD mid-comment with absurd counts (99); real EOCD reports 1.
    fake_inner = struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        99,
        99,
        0,
        0,
        0,
    )
    comment = b"pad" + fake_inner + b"tail"
    real_eocd = (
        struct.pack(
            "<IHHHHIIH",
            0x06054B50,
            0,
            0,
            1,
            1,
            len(central),
            len(local),
            len(comment),
        )
        + comment
    )
    payload = local + central + real_eocd
    assert _preflight_zip_eocd_entry_count(payload) == 1


def test_terminal_eocd_embedded_in_real_comment_is_rejected(tmp_path: Path) -> None:
    """Two terminal EOCD candidates are ambiguous, even if ZipFile picks empty."""
    tail = b"tail"
    fake_terminal = struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        0,
        0,
        0,
        0,
        len(tail),
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("pkg/nonempty.py", b"x = 1\n")
        archive.comment = b"prefix" + fake_terminal + tail
    payload = buffer.getvalue()

    # This is the observed parser-confusion shape: the physical archive has a
    # real member, while stdlib ZipFile accepts the later forged empty EOCD.
    with zipfile.ZipFile(io.BytesIO(payload), "r") as archive:
        assert archive.infolist() == []
    wheel = tmp_path / "ambiguous-comment.whl"
    wheel.write_bytes(payload)
    with pytest.raises(ArtifactEvidenceError, match="ambiguous"):
        inventory_wheel_zip(wheel)


def test_eocd_count_must_equal_zipfile_inventory_count(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("pkg/nonempty.py", b"x = 1\n")
    payload = bytearray(buffer.getvalue())
    eocd = payload.rfind(b"PK\x05\x06")
    assert eocd >= 0
    # Preserve a non-empty central directory but falsely report zero entries.
    payload[eocd + 8 : eocd + 12] = b"\x00\x00\x00\x00"
    with zipfile.ZipFile(io.BytesIO(payload), "r") as archive:
        assert len(archive.infolist()) == 1
    wheel = tmp_path / "count-mismatch.whl"
    wheel.write_bytes(payload)
    with pytest.raises(ArtifactEvidenceError, match="does not match"):
        inventory_wheel_zip(wheel)


def test_eocd_malformed_entry_counts_rejected(tmp_path: Path) -> None:
    import zlib

    wheel = tmp_path / "bad-count.whl"
    name = b"ok.py"
    data = b"x"
    crc = zlib.crc32(data) & 0xFFFFFFFF
    local = (
        struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            20,
            0,
            0,
            0,
            0,
            crc,
            len(data),
            len(data),
            len(name),
            0,
        )
        + name
        + data
    )
    central = (
        struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,
            20,
            20,
            0,
            0,
            0,
            0,
            crc,
            len(data),
            len(data),
            len(name),
            0,
            0,
            0,
            0,
            0,
            0,
        )
        + name
    )
    # entries_on_disk=1, total_entries=2 — inconsistent.
    end = struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        1,
        2,
        len(central),
        len(local),
        0,
    )
    wheel.write_bytes(local + central + end)
    with pytest.raises(ArtifactEvidenceError, match="count|inconsistent|invalid"):
        inventory_wheel_zip(wheel)


def test_zip64_sentinel_in_eocd_fields_rejected(tmp_path: Path) -> None:
    import zlib

    wheel = tmp_path / "zip64-sentinel.whl"
    name = b"ok.py"
    data = b"x"
    crc = zlib.crc32(data) & 0xFFFFFFFF
    local = (
        struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            20,
            0,
            0,
            0,
            0,
            crc,
            len(data),
            len(data),
            len(name),
            0,
        )
        + name
        + data
    )
    central = (
        struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,
            20,
            20,
            0,
            0,
            0,
            0,
            crc,
            len(data),
            len(data),
            len(name),
            0,
            0,
            0,
            0,
            0,
            0,
        )
        + name
    )
    # total_entries = 0xFFFF ZIP64 sentinel
    end = struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        0xFFFF,
        0xFFFF,
        len(central),
        len(local),
        0,
    )
    wheel.write_bytes(local + central + end)
    with pytest.raises(ArtifactEvidenceError, match="ZIP64"):
        inventory_wheel_zip(wheel)
