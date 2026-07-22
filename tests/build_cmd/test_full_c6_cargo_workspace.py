"""Adversarial tests for the bounded Full C6 offline Cargo workspace."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import pickle
import shutil
from pathlib import Path

import pytest

from rextio.build.full_c6_cargo_workspace import (
    FULL_C6_CARGO_EXECUTOR_CONFIG,
    FULL_C6_CARGO_EXECUTOR_CONFIG_BYTES,
    FULL_C6_CARGO_LAYOUT_DEFAULT,
    FULL_C6_CARGO_LAYOUT_VERSIONED,
    FullC6CargoWorkspaceError,
    _validated_full_c6_cargo_lock_payload,
    collect_full_c6_cargo_dependency_workspace,
    compute_full_c6_cargo_vendor_tree_sha256,
    materialize_full_c6_cargo_dependency_workspace,
    validate_full_c6_cargo_dependency_workspace_receipt,
)
from rextio.build.toolchain_identity import CargoSourcesIdentity, capture_cargo_sources


PACKAGE = "demo-dep"
VERSION = "1.2.3"
PACKAGE_CHECKSUM = "a" * 64


def _cargo_sources(tmp_path: Path) -> tuple[Path, CargoSourcesIdentity]:
    lock = tmp_path / "Cargo.lock"
    lock.write_text(
        f"""
version = 4

[[package]]
name = "root"
version = "0.1.0"

[[package]]
name = "{PACKAGE}"
version = "{VERSION}"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "{PACKAGE_CHECKSUM}"
""".lstrip(),
        encoding="utf-8",
    )
    return lock, capture_cargo_sources(lock, root_package="root")


def _write_vendor_package(
    vendor: Path,
    *,
    name: str,
    version: str,
    checksum: str,
    directory: str,
) -> Path:
    package = vendor / directory
    source = package / "src"
    source.mkdir(parents=True)
    package.chmod(0o755)
    source.chmod(0o755)
    files = {
        "Cargo.toml": (
            f'[package]\nname = "{name}"\nversion = "{version}"\n'
            'license = "MIT"\nlicense-file = "LICENSE"\n'
        ).encode(),
        "LICENSE": b"MIT license evidence\n",
        "src/lib.rs": b"pub fn answer() -> u32 { 42 }\n",
    }
    for relative, payload in files.items():
        path = package.joinpath(*relative.split("/"))
        path.write_bytes(payload)
        path.chmod(0o644)
    checksum_document = {
        "files": {
            relative: hashlib.sha256(payload).hexdigest()
            for relative, payload in sorted(files.items(), key=lambda item: item[0].casefold())
        },
        "package": checksum,
    }
    checksum_path = package / ".cargo-checksum.json"
    checksum_path.write_text(
        json.dumps(checksum_document, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    checksum_path.chmod(0o644)
    return package


def _write_vendor(tmp_path: Path, *, layout: str = "versioned") -> Path:
    vendor = tmp_path / "cargo-vendor"
    directory = PACKAGE if layout == "default" else f"{PACKAGE}-{VERSION}"
    _write_vendor_package(
        vendor,
        name=PACKAGE,
        version=VERSION,
        checksum=PACKAGE_CHECKSUM,
        directory=directory,
    )
    return vendor


def _collect(tmp_path: Path):  # type: ignore[no-untyped-def]
    lock, sources = _cargo_sources(tmp_path)
    vendor = _write_vendor(tmp_path)
    pin = compute_full_c6_cargo_vendor_tree_sha256(vendor)
    receipt = collect_full_c6_cargo_dependency_workspace(
        vendor_root=vendor,
        cargo_lock=lock,
        cargo_sources=sources,
        expected_vendor_tree_sha256=pin,
    )
    return lock, sources, vendor, pin, receipt


def _checksum_document(vendor: Path) -> tuple[Path, dict[str, object]]:
    path = vendor / f"{PACKAGE}-{VERSION}" / ".cargo-checksum.json"
    return path, json.loads(path.read_text(encoding="utf-8"))


def test_collects_sealed_exact_workspace_and_materializes_executor_projection(
    tmp_path: Path,
) -> None:
    lock, sources, _, pin, receipt = _collect(tmp_path)

    assert receipt.cargo_sources.digest == sources.digest
    assert receipt.vendor_layout == FULL_C6_CARGO_LAYOUT_VERSIONED
    assert receipt.vendor_tree_sha256 == pin
    assert receipt.complete_for_scope is True
    assert receipt.authorizes_build is False
    assert receipt.authorizes_distribution is False
    assert validate_full_c6_cargo_dependency_workspace_receipt(receipt)
    assert receipt.executor_config.logical_name == FULL_C6_CARGO_EXECUTOR_CONFIG
    assert receipt.executor_config.sha256 == hashlib.sha256(
        FULL_C6_CARGO_EXECUTOR_CONFIG_BYTES
    ).hexdigest()
    assert {item.logical_name for item in receipt.executor_projection} >= {
        ".cargo",
        ".cargo/config.toml",
        "vendor",
        f"vendor/{PACKAGE}-{VERSION}/Cargo.toml",
        f"vendor/{PACKAGE}-{VERSION}/LICENSE",
        f"vendor/{PACKAGE}-{VERSION}/src/lib.rs",
    }
    metadata = dict(receipt.metadata_payloads())
    assert metadata[f"vendor/{PACKAGE}-{VERSION}/Cargo.toml"].startswith(b"[package]")
    assert metadata[f"vendor/{PACKAGE}-{VERSION}/LICENSE"] == b"MIT license evidence\n"
    assert str(tmp_path) not in repr(receipt.to_dict())
    assert "MIT license evidence" not in repr(receipt.to_dict())
    retained_lock = _validated_full_c6_cargo_lock_payload(receipt)
    assert retained_lock == lock.read_bytes()
    assert retained_lock is not receipt._cargo_lock_payload
    assert lock.read_text(encoding="utf-8") not in repr(receipt.to_dict())

    destination = tmp_path / "materialized"
    projection = materialize_full_c6_cargo_dependency_workspace(receipt, destination)

    assert projection == receipt.executor_projection
    assert (destination / ".cargo/config.toml").read_bytes() == (
        FULL_C6_CARGO_EXECUTOR_CONFIG_BYTES
    )
    assert (destination / f"vendor/{PACKAGE}-{VERSION}/src/lib.rs").read_bytes() == (
        b"pub fn answer() -> u32 { 42 }\n"
    )

    with pytest.raises(TypeError):
        copy.copy(receipt)
    with pytest.raises(TypeError):
        copy.deepcopy(receipt)
    with pytest.raises(TypeError):
        pickle.dumps(receipt)


def test_retained_payload_or_receipt_mutation_fails_seal(tmp_path: Path) -> None:
    *_, receipt = _collect(tmp_path)
    payloads = list(receipt._file_payloads)  # type: ignore[attr-defined]
    payloads[-1] = b"forged"
    object.__setattr__(receipt, "_file_payloads", tuple(payloads))

    assert not validate_full_c6_cargo_dependency_workspace_receipt(receipt)
    with pytest.raises(FullC6CargoWorkspaceError, match="stale"):
        materialize_full_c6_cargo_dependency_workspace(receipt, tmp_path / "output")


def test_retained_cargo_lock_tamper_and_identity_drift_fail_closed(
    tmp_path: Path,
) -> None:
    payload_root = tmp_path / "payload"
    payload_root.mkdir()
    *_, tampered = _collect(payload_root)
    payload = tampered._cargo_lock_payload
    object.__setattr__(tampered, "_cargo_lock_payload", b"X" + payload[1:])
    assert not validate_full_c6_cargo_dependency_workspace_receipt(tampered)
    with pytest.raises(FullC6CargoWorkspaceError, match="stale"):
        _validated_full_c6_cargo_lock_payload(tampered)

    identity_root = tmp_path / "identity"
    identity_root.mkdir()
    *_, drifted = _collect(identity_root)
    object.__setattr__(drifted.cargo_sources.lock_file, "sha256", "0" * 64)
    assert not validate_full_c6_cargo_dependency_workspace_receipt(drifted)
    with pytest.raises(FullC6CargoWorkspaceError, match="stale"):
        _validated_full_c6_cargo_lock_payload(drifted)


@pytest.mark.parametrize("mutation", ("file", "package-checksum", "missing", "extra"))
def test_checksum_and_complete_file_inventory_drift_fail_closed(
    tmp_path: Path,
    mutation: str,
) -> None:
    lock, sources = _cargo_sources(tmp_path)
    vendor = _write_vendor(tmp_path)
    package = vendor / f"{PACKAGE}-{VERSION}"
    if mutation == "file":
        (package / "src/lib.rs").write_bytes(b"drift\n")
    elif mutation == "package-checksum":
        checksum_path, document = _checksum_document(vendor)
        document["package"] = "b" * 64
        checksum_path.write_text(
            json.dumps(document, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
    elif mutation == "missing":
        (package / "src/lib.rs").unlink()
    else:
        (package / "rogue.rs").write_bytes(b"extra\n")
        (package / "rogue.rs").chmod(0o644)
    pin = compute_full_c6_cargo_vendor_tree_sha256(vendor)

    with pytest.raises(FullC6CargoWorkspaceError, match="checksum|file set"):
        collect_full_c6_cargo_dependency_workspace(
            vendor_root=vendor,
            cargo_lock=lock,
            cargo_sources=sources,
            expected_vendor_tree_sha256=pin,
        )


@pytest.mark.parametrize("mutation", ("missing", "extra", "renamed"))
def test_vendor_package_set_must_exactly_match_cargo_lock(
    tmp_path: Path,
    mutation: str,
) -> None:
    lock, sources = _cargo_sources(tmp_path)
    vendor = _write_vendor(tmp_path)
    package = vendor / f"{PACKAGE}-{VERSION}"
    if mutation == "missing":
        shutil.rmtree(package)
    elif mutation == "extra":
        (vendor / "extra-9.9.9").mkdir(mode=0o755)
    else:
        package.rename(vendor / f"{PACKAGE}-{VERSION}-renamed")
    pin = compute_full_c6_cargo_vendor_tree_sha256(vendor)

    with pytest.raises(FullC6CargoWorkspaceError, match="package set|extra package"):
        collect_full_c6_cargo_dependency_workspace(
            vendor_root=vendor,
            cargo_lock=lock,
            cargo_sources=sources,
            expected_vendor_tree_sha256=pin,
        )


@pytest.mark.parametrize("link_kind", ("symlink", "hardlink"))
def test_links_are_rejected_before_workspace_admission(
    tmp_path: Path,
    link_kind: str,
) -> None:
    vendor = _write_vendor(tmp_path)
    package = vendor / f"{PACKAGE}-{VERSION}"
    if link_kind == "symlink":
        (package / "linked.rs").symlink_to(package / "src/lib.rs")
        match = "symlink"
    else:
        os.link(package / "src/lib.rs", package / "linked.rs")
        match = "hardlink"

    with pytest.raises(FullC6CargoWorkspaceError, match=match):
        compute_full_c6_cargo_vendor_tree_sha256(vendor)


def test_special_file_is_rejected_before_workspace_admission(tmp_path: Path) -> None:
    vendor = _write_vendor(tmp_path)
    fifo = vendor / f"{PACKAGE}-{VERSION}" / "source.pipe"
    os.mkfifo(fifo, mode=0o644)

    with pytest.raises(FullC6CargoWorkspaceError, match="special file"):
        compute_full_c6_cargo_vendor_tree_sha256(vendor)


def test_default_cargo_vendor_layout_uses_bare_unique_package_name(tmp_path: Path) -> None:
    lock, sources = _cargo_sources(tmp_path)
    vendor = _write_vendor(tmp_path, layout="default")
    receipt = collect_full_c6_cargo_dependency_workspace(
        vendor_root=vendor,
        cargo_lock=lock,
        cargo_sources=sources,
        expected_vendor_tree_sha256=compute_full_c6_cargo_vendor_tree_sha256(vendor),
    )

    assert receipt.vendor_layout == FULL_C6_CARGO_LAYOUT_DEFAULT
    assert tuple(item.directory for item in receipt.packages) == (PACKAGE,)
    assert f"vendor/{PACKAGE}/Cargo.toml" in dict(receipt.metadata_payloads())


def test_cargo_checksum_file_order_is_not_treated_as_a_layout_contract(
    tmp_path: Path,
) -> None:
    lock, sources = _cargo_sources(tmp_path)
    vendor = _write_vendor(tmp_path)
    checksum_path, document = _checksum_document(vendor)
    files = document["files"]
    assert isinstance(files, dict)
    document["files"] = {
        name: files[name]
        for name in ("src/lib.rs", "Cargo.toml", "LICENSE")
    }
    checksum_path.write_text(
        json.dumps(document, separators=(",", ":")),
        encoding="utf-8",
    )
    receipt = collect_full_c6_cargo_dependency_workspace(
        vendor_root=vendor,
        cargo_lock=lock,
        cargo_sources=sources,
        expected_vendor_tree_sha256=compute_full_c6_cargo_vendor_tree_sha256(vendor),
    )

    assert receipt.vendor_layout == FULL_C6_CARGO_LAYOUT_VERSIONED


def test_default_layout_versions_duplicate_names_and_rejects_mixed_layout(
    tmp_path: Path,
) -> None:
    checksum_b = "b" * 64
    checksum_c = "c" * 64
    checksum_d = "d" * 64
    lock = tmp_path / "Cargo.lock"
    lock.write_text(
        f"""\
version = 4

[[package]]
name = "root"
version = "0.1.0"

[[package]]
name = "{PACKAGE}"
version = "{VERSION}"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "{PACKAGE_CHECKSUM}"

[[package]]
name = "{PACKAGE}"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "{checksum_b}"

[[package]]
name = "unique-dep"
version = "3.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "{checksum_c}"

[[package]]
name = "other-unique-dep"
version = "4.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "{checksum_d}"
""",
        encoding="utf-8",
    )
    sources = capture_cargo_sources(lock, root_package="root")
    vendor = tmp_path / "cargo-vendor"
    for name, version, checksum, directory in (
        (PACKAGE, VERSION, PACKAGE_CHECKSUM, f"{PACKAGE}-{VERSION}"),
        (PACKAGE, "2.0.0", checksum_b, f"{PACKAGE}-2.0.0"),
        ("unique-dep", "3.0.0", checksum_c, "unique-dep"),
        ("other-unique-dep", "4.0.0", checksum_d, "other-unique-dep"),
    ):
        _write_vendor_package(
            vendor,
            name=name,
            version=version,
            checksum=checksum,
            directory=directory,
        )
    pin = compute_full_c6_cargo_vendor_tree_sha256(vendor)
    receipt = collect_full_c6_cargo_dependency_workspace(
        vendor_root=vendor,
        cargo_lock=lock,
        cargo_sources=sources,
        expected_vendor_tree_sha256=pin,
    )

    assert receipt.vendor_layout == FULL_C6_CARGO_LAYOUT_DEFAULT
    assert tuple(item.directory for item in receipt.packages) == (
        f"{PACKAGE}-{VERSION}",
        f"{PACKAGE}-2.0.0",
        "other-unique-dep",
        "unique-dep",
    )

    (vendor / "unique-dep").rename(vendor / "unique-dep-3.0.0")
    mixed_pin = compute_full_c6_cargo_vendor_tree_sha256(vendor)
    with pytest.raises(FullC6CargoWorkspaceError, match="layout"):
        collect_full_c6_cargo_dependency_workspace(
            vendor_root=vendor,
            cargo_lock=lock,
            cargo_sources=sources,
            expected_vendor_tree_sha256=mixed_pin,
        )


def test_checksum_path_alias_is_rejected_before_missing_file_fallback(
    tmp_path: Path,
) -> None:
    lock, sources = _cargo_sources(tmp_path)
    vendor = _write_vendor(tmp_path)
    checksum_path, document = _checksum_document(vendor)
    files = document["files"]
    assert isinstance(files, dict)
    files["SRC/LIB.RS"] = files["src/lib.rs"]
    checksum_path.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    pin = compute_full_c6_cargo_vendor_tree_sha256(vendor)

    with pytest.raises(FullC6CargoWorkspaceError, match="alias"):
        collect_full_c6_cargo_dependency_workspace(
            vendor_root=vendor,
            cargo_lock=lock,
            cargo_sources=sources,
            expected_vendor_tree_sha256=pin,
        )


def test_tree_pin_and_cargo_lock_identity_drift_fail_closed(tmp_path: Path) -> None:
    lock, sources = _cargo_sources(tmp_path)
    vendor = _write_vendor(tmp_path)

    with pytest.raises(FullC6CargoWorkspaceError, match="config pin"):
        collect_full_c6_cargo_dependency_workspace(
            vendor_root=vendor,
            cargo_lock=lock,
            cargo_sources=sources,
            expected_vendor_tree_sha256="0" * 64,
        )

    lock.write_text(
        lock.read_text(encoding="utf-8").replace(PACKAGE_CHECKSUM, "b" * 64),
        encoding="utf-8",
    )
    pin = compute_full_c6_cargo_vendor_tree_sha256(vendor)
    with pytest.raises(FullC6CargoWorkspaceError, match="Cargo.lock differs"):
        collect_full_c6_cargo_dependency_workspace(
            vendor_root=vendor,
            cargo_lock=lock,
            cargo_sources=sources,
            expected_vendor_tree_sha256=pin,
        )


def test_caller_cargo_config_is_forbidden_and_executor_config_is_owned(
    tmp_path: Path,
) -> None:
    vendor = _write_vendor(tmp_path)
    cargo = vendor / ".cargo"
    cargo.mkdir(mode=0o755)
    (cargo / "config.toml").write_text("[net]\noffline = false\n", encoding="utf-8")
    (cargo / "config.toml").chmod(0o644)

    with pytest.raises(FullC6CargoWorkspaceError, match="caller-provided"):
        compute_full_c6_cargo_vendor_tree_sha256(vendor)


def test_materializer_rejects_existing_or_symlink_destination(tmp_path: Path) -> None:
    *_, receipt = _collect(tmp_path)
    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(FullC6CargoWorkspaceError, match="already exists"):
        materialize_full_c6_cargo_dependency_workspace(receipt, existing)

    target = tmp_path / "target"
    target.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(target, target_is_directory=True)
    with pytest.raises(FullC6CargoWorkspaceError, match="already exists"):
        materialize_full_c6_cargo_dependency_workspace(receipt, linked)
