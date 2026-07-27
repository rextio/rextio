"""Focused Full-C6 tests for immutable build-input capture."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import os

import pytest


def _sealed_cargo_workspace(tmp_path: Path):  # type: ignore[no-untyped-def]
    from rextio.build.full_c6_cargo_workspace import (
        collect_full_c6_cargo_dependency_workspace,
        compute_full_c6_cargo_vendor_tree_sha256,
    )
    from rextio.build.toolchain_identity import capture_cargo_sources

    checksum = "a" * 64
    lock = tmp_path / "Cargo.lock"
    lock.write_text(
        f"""\
version = 4

[[package]]
name = "root"
version = "0.1.0"

[[package]]
name = "demo-dep"
version = "1.2.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "{checksum}"
""",
        encoding="utf-8",
    )
    sources = capture_cargo_sources(lock, root_package="root")
    package = tmp_path / "cargo-vendor" / "demo-dep-1.2.3"
    source = package / "src"
    source.mkdir(parents=True)
    (tmp_path / "cargo-vendor").chmod(0o755)
    package.chmod(0o755)
    source.chmod(0o755)
    payloads = {
        "Cargo.toml": (
            b'[package]\nname = "demo-dep"\nversion = "1.2.3"\n'
            b'license = "MIT"\nlicense-file = "LICENSE"\n'
        ),
        "LICENSE": b"MIT aggregate fixture\n",
        "src/lib.rs": b"pub fn answer() -> u32 { 42 }\n",
    }
    for relative, payload in payloads.items():
        candidate = package.joinpath(*relative.split("/"))
        candidate.write_bytes(payload)
        candidate.chmod(0o644)
    checksum_manifest = package / ".cargo-checksum.json"
    checksum_manifest.write_text(
        json.dumps(
            {
                "files": {
                    relative: hashlib.sha256(payload).hexdigest()
                    for relative, payload in sorted(payloads.items())
                },
                "package": checksum,
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    checksum_manifest.chmod(0o644)
    vendor = tmp_path / "cargo-vendor"
    return collect_full_c6_cargo_dependency_workspace(
        vendor_root=vendor,
        cargo_lock=lock,
        cargo_sources=sources,
        expected_vendor_tree_sha256=compute_full_c6_cargo_vendor_tree_sha256(vendor),
    )


def test_exact_file_receipt_detects_content_mutation(tmp_path: Path) -> None:
    try:
        from rextio.build.input_closure import (
            BuildInputIdentityError,
            capture_exact_file,
            verify_exact_file,
        )
    except ImportError:
        pytest.fail("the immutable build-input closure module is missing")

    source = tmp_path / "app.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    receipt = capture_exact_file(
        source,
        logical_name="project/app.py",
        role="project-python-source",
    )

    assert receipt.logical_name == "project/app.py"
    assert receipt.role == "project-python-source"
    assert receipt.size == len(b"VALUE = 1\n")
    assert receipt.sha256

    source.write_text("VALUE = 2\n", encoding="utf-8")
    with pytest.raises(BuildInputIdentityError, match="changed"):
        verify_exact_file(source, receipt)


def test_exact_file_capture_rejects_missing_and_symlink_inputs(tmp_path: Path) -> None:
    from rextio.build.input_closure import BuildInputIdentityError, capture_exact_file

    with pytest.raises(BuildInputIdentityError, match="missing"):
        capture_exact_file(
            tmp_path / "missing",
            logical_name="input/missing",
            role="generated-rust-input",
        )

    target = tmp_path / "target"
    target.write_bytes(b"trusted")
    link = tmp_path / "link"
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable on this platform")
    with pytest.raises(BuildInputIdentityError, match="symlink"):
        capture_exact_file(
            link,
            logical_name="input/link",
            role="generated-rust-input",
        )


def test_build_input_closure_is_canonical_and_reverifiable(tmp_path: Path) -> None:
    from rextio.build.input_closure import (
        BuildInputIdentityError,
        InputFileSpec,
        capture_build_input_closure,
        verify_build_input_closure,
    )

    first = tmp_path / "app.py"
    second = tmp_path / "Cargo.lock"
    first.write_bytes(b"def answer() -> int:\n    return 42\n")
    second.write_bytes(b"version = 4\n")
    specs = (
        InputFileSpec(first, "project/app.py", "project-python-source"),
        InputFileSpec(second, "generated/Cargo.lock", "generated-cargo-lock"),
    )

    forward = capture_build_input_closure(specs)
    reverse = capture_build_input_closure(tuple(reversed(specs)))
    from rextio.artifacts.full_authorization import FULL_C6_SCOPE

    assert forward == reverse
    assert forward.scope == FULL_C6_SCOPE
    assert forward.digest == reverse.digest
    assert forward.complete_for_scope is True
    serialized = forward.to_dict()
    assert serialized["files"][0]["role"] == "generated-cargo-lock"
    assert str(tmp_path) not in repr(serialized)

    verify_build_input_closure(specs, forward)
    second.write_bytes(b"version = 3\n")
    with pytest.raises(BuildInputIdentityError, match="closure changed"):
        verify_build_input_closure(specs, forward)


def test_build_input_closure_rejects_casefold_path_aliases(tmp_path: Path) -> None:
    from rextio.build.input_closure import (
        BuildInputIdentityError,
        InputFileSpec,
        capture_build_input_closure,
    )

    first = tmp_path / "one"
    second = tmp_path / "two"
    first.write_bytes(os.urandom(4))
    second.write_bytes(os.urandom(4))
    with pytest.raises(BuildInputIdentityError, match="alias"):
        capture_build_input_closure(
            (
                InputFileSpec(first, "Project/App.py", "project-python-source"),
                InputFileSpec(second, "project/app.py", "project-python-source"),
        )
    )


def test_cargo_workspace_aggregates_bind_exact_seven_row_set(tmp_path: Path) -> None:
    from rextio.build.input_closure import (
        FULL_C6_CARGO_INPUT_AGGREGATE_IDS,
        FULL_C6_CARGO_METADATA_SET_DOMAIN,
        FULL_C6_CARGO_PACKAGE_RECEIPTS_DOMAIN,
        FULL_C6_CARGO_PACKAGE_SET_DOMAIN,
        InputFileSpec,
        bind_full_c6_cargo_workspace_aggregates,
        capture_build_input_closure,
    )

    source = tmp_path / "app.py"
    source.write_bytes(b"def answer() -> int:\n    return 42\n")
    base = capture_build_input_closure(
        (InputFileSpec(source, "project/app.py", "project-python-source"),)
    )
    workspace = _sealed_cargo_workspace(tmp_path)

    bound = bind_full_c6_cargo_workspace_aggregates(base, workspace)

    assert {item.aggregate_id for item in bound.aggregates} == (
        FULL_C6_CARGO_INPUT_AGGREGATE_IDS
    )
    assert bound.aggregates == tuple(
        sorted(bound.aggregates, key=lambda item: (item.kind, item.aggregate_id))
    )
    rows = {item.aggregate_id: item for item in bound.aggregates}
    package_count = len(workspace.packages)
    assert rows["artifact-evidence-cargo-workspace"].member_count == package_count
    assert rows["artifact-evidence-cargo-sources"].member_count == package_count
    assert rows["artifact-evidence-cargo-package-set"].member_count == package_count
    assert (
        rows["artifact-evidence-cargo-package-receipts"].member_count
        == package_count
    )
    assert rows["artifact-evidence-cargo-vendor-tree"].member_count == len(
        workspace.vendor_entries
    )
    assert rows["artifact-evidence-cargo-executor-config"].member_count == 1
    assert rows["artifact-evidence-cargo-metadata-set"].member_count == len(
        workspace.metadata_files
    )

    def digest(domain: str, members: list[dict[str, object]]) -> str:
        payload = json.dumps(
            {"domain": domain, "members": members},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    package_set_digest = digest(
        FULL_C6_CARGO_PACKAGE_SET_DOMAIN,
        [item.package.to_dict() for item in workspace.packages],
    )
    package_receipts_digest = digest(
        FULL_C6_CARGO_PACKAGE_RECEIPTS_DOMAIN,
        [item.to_dict() for item in workspace.packages],
    )
    metadata_names = set(workspace.metadata_files)
    metadata_set_digest = digest(
        FULL_C6_CARGO_METADATA_SET_DOMAIN,
        [
            item.to_dict()
            for item in workspace.vendor_entries
            if item.kind == "file" and item.logical_name in metadata_names
        ],
    )
    assert rows["artifact-evidence-cargo-package-set"].digest == package_set_digest
    assert (
        rows["artifact-evidence-cargo-package-receipts"].digest
        == package_receipts_digest
    )
    assert rows["artifact-evidence-cargo-metadata-set"].digest == metadata_set_digest
    assert (
        rows["artifact-evidence-cargo-package-receipts"].metadata_digest
        == metadata_set_digest
    )
    assert bound.digest != base.digest
    assert "aggregates" not in base.to_dict()
    assert len(bound.to_dict()["aggregates"]) == 7
    assert "MIT aggregate fixture" not in repr(bound.to_dict())


def test_build_input_aggregate_tamper_order_alias_and_stale_seal_fail_closed(
    tmp_path: Path,
) -> None:
    from rextio.build.input_closure import (
        BuildInputAggregateIdentity,
        BuildInputClosure,
        BuildInputIdentityError,
        InputFileSpec,
        bind_full_c6_cargo_workspace_aggregates,
        capture_build_input_closure,
    )

    source = tmp_path / "app.py"
    source.write_bytes(b"VALUE = 1\n")
    base = capture_build_input_closure(
        (InputFileSpec(source, "project/app.py", "project-python-source"),)
    )
    first = BuildInputAggregateIdentity(
        aggregate_id="Cargo",
        kind="test-aggregate",
        digest="a" * 64,
        member_count=1,
    )
    second = BuildInputAggregateIdentity(
        aggregate_id="cargo",
        kind="test-aggregate",
        digest="b" * 64,
        member_count=1,
    )
    with pytest.raises(ValueError, match="alias"):
        BuildInputClosure(files=base.files, aggregates=(first, second))

    alpha = BuildInputAggregateIdentity(
        aggregate_id="alpha",
        kind="test-alpha",
        digest="a" * 64,
        member_count=1,
    )
    omega = BuildInputAggregateIdentity(
        aggregate_id="omega",
        kind="test-omega",
        digest="b" * 64,
        member_count=1,
    )
    with pytest.raises(ValueError, match="canonical order"):
        BuildInputClosure(files=base.files, aggregates=(omega, alpha))
    original = BuildInputClosure(files=base.files, aggregates=(alpha, omega))
    tampered_alpha = BuildInputAggregateIdentity(
        aggregate_id="alpha",
        kind="test-alpha",
        digest="f" * 64,
        member_count=1,
    )
    tampered = BuildInputClosure(
        files=base.files,
        aggregates=(tampered_alpha, omega),
    )
    assert tampered.digest != original.digest

    workspace = _sealed_cargo_workspace(tmp_path)
    object.__setattr__(workspace, "_transaction_seal", b"stale")
    with pytest.raises(BuildInputIdentityError, match="not sealed"):
        bind_full_c6_cargo_workspace_aggregates(base, workspace)
