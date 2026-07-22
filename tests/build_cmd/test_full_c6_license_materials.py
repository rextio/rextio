"""Focused adversarial tests for process-sealed Full C6 license materials."""

from __future__ import annotations

import copy
import hashlib
import json
import pickle
from pathlib import Path, PurePosixPath
import runpy
from typing import cast
import zipfile

import pytest

import rextio.build.full_c6_license_materials as license_materials_module
import rextio.build.full_c6_output_license as output_license_module
from rextio.build.full_c6_cargo_workspace import (
    FullC6CargoDependencyWorkspaceReceipt,
    collect_full_c6_cargo_dependency_workspace,
    compute_full_c6_cargo_vendor_tree_sha256,
)
from rextio.build.full_c6_license_materials import (
    FULL_C6_LICENSE_DETECTOR_KIND,
    FullC6LicenseMaterialsError,
    collect_full_c6_license_materials,
    validate_full_c6_license_materials_transaction,
)
from rextio.build.full_c6_output_license import (
    MAX_OUTPUT_WHEEL_LICENSE_FILES,
    MAX_OUTPUT_WHEEL_LICENSE_TOTAL_BYTES,
    FullC6OutputLicenseDerivationError,
    OutputWheelLicenseContract,
    OutputWheelLicenseFile,
    OutputWheelLicenseMemberIdentity,
    OutputWheelLicenseVerification,
    derive_full_c6_output_license_contract,
    validate_full_c6_output_license_contract,
)
from rextio.build.full_c6_policy import (
    FullC6PolicyError,
    canonicalize_full_c6_spdx_expression,
)
from rextio.build.toolchain_identity import capture_cargo_sources
from rextio.build.wheel_builder import build_artifact_wheel
from rextio.source.source_lock_v2 import SourceLockV2VerifiedContext


PACKAGE = "demo-dep"
VERSION = "1.2.3"
PACKAGE_CHECKSUM = "a" * 64
_SOURCE_TESTS = runpy.run_path(
    str(Path(__file__).parent.parent / "source" / "test_source_lock_v2.py")
)


def _source_context(tmp_path: Path) -> SourceLockV2VerifiedContext:
    signed = _SOURCE_TESTS["_write_signed"](tmp_path / "external-authority")
    verification = _SOURCE_TESTS["_verify_context"](signed)
    assert verification.context is not None
    return cast(SourceLockV2VerifiedContext, verification.context)


def _write_project(
    root: Path,
    *,
    license_value: str = '"MIT"',
    license_files: str = '["LICENSE"]',
    extra_files: dict[str, bytes] | None = None,
) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "pyproject.toml").write_text(
        (
            '[project]\nname = "demo-project"\nversion = "0.1.0"\n'
            f"license = {license_value}\nlicense-files = {license_files}\n"
        ),
        encoding="utf-8",
    )
    (root / "LICENSE").write_text("project MIT license evidence\n", encoding="utf-8")
    for relative, payload in (extra_files or {}).items():
        path = root.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)


def _cargo_workspace(
    tmp_path: Path,
    *,
    license_expression: str | None = "MIT OR Apache-2.0",
    declared_license_file: bool = True,
    conventional_license_file: bool = True,
    extra_license_files: dict[str, bytes] | None = None,
) -> FullC6CargoDependencyWorkspaceReceipt:
    tmp_path.mkdir(parents=True, exist_ok=True)
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
""",
        encoding="utf-8",
    )
    sources = capture_cargo_sources(lock, root_package="root")
    vendor = tmp_path / "cargo-vendor"
    package = vendor / f"{PACKAGE}-{VERSION}"
    source = package / "src"
    source.mkdir(parents=True)
    vendor.chmod(0o755)
    package.chmod(0o755)
    source.chmod(0o755)
    manifest_lines = [
        "[package]",
        f'name = "{PACKAGE}"',
        f'version = "{VERSION}"',
    ]
    if license_expression is not None:
        manifest_lines.append(f'license = "{license_expression}"')
    if declared_license_file:
        manifest_lines.append('license-file = "LICENSE"')
    files: dict[str, bytes] = {
        "Cargo.toml": ("\n".join(manifest_lines) + "\n").encode(),
        "src/lib.rs": b"pub fn answer() -> u32 { 42 }\n",
    }
    if conventional_license_file:
        files["LICENSE"] = b"Cargo MIT or Apache license evidence\n"
    files.update(extra_license_files or {})
    for relative, payload in files.items():
        path = package.joinpath(*relative.split("/"))
        path.write_bytes(payload)
        path.chmod(0o644)
    checksum = {
        "files": {
            name: hashlib.sha256(payload).hexdigest()
            for name, payload in sorted(files.items(), key=lambda item: item[0].casefold())
        },
        "package": PACKAGE_CHECKSUM,
    }
    checksum_path = package / ".cargo-checksum.json"
    checksum_path.write_text(
        json.dumps(checksum, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    checksum_path.chmod(0o644)
    return collect_full_c6_cargo_dependency_workspace(
        vendor_root=vendor,
        cargo_lock=lock,
        cargo_sources=sources,
        expected_vendor_tree_sha256=compute_full_c6_cargo_vendor_tree_sha256(vendor),
    )


def test_collects_project_and_every_cargo_package_without_exposing_bytes_or_paths(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    _write_project(project)
    workspace = _cargo_workspace(tmp_path)

    transaction = collect_full_c6_license_materials(
        project_root=project,
        cargo_workspace=workspace,
    )

    assert validate_full_c6_license_materials_transaction(transaction)
    assert transaction.project.declared_spdx == "MIT"
    assert transaction.project.metadata_file.logical_name == "project/pyproject.toml"
    assert [item.logical_name for item in transaction.project.license_files] == ["project/LICENSE"]
    assert len(transaction.cargo_packages) == len(workspace.packages) == 1
    cargo = transaction.cargo_packages[0]
    assert cargo.name == PACKAGE
    assert cargo.version == VERSION
    assert cargo.declared_spdx == "MIT OR Apache-2.0"
    assert cargo.detector_kind == FULL_C6_LICENSE_DETECTOR_KIND
    assert len(cargo.observation_sha256) == 64
    assert len(cargo.detector_payload_sha256) == 64
    assert len(cargo.detector_receipt_sha256) == 64
    assert transaction.to_dict()["legal_approval_inferred"] is False
    rendered = repr(transaction.to_dict())
    assert str(tmp_path) not in rendered
    assert "project MIT license evidence" not in rendered
    assert "Cargo MIT or Apache license evidence" not in rendered

    with pytest.raises(TypeError):
        copy.copy(transaction)
    with pytest.raises(TypeError):
        copy.deepcopy(transaction)
    with pytest.raises(TypeError):
        pickle.dumps(transaction)


def test_project_or_cargo_retained_byte_tamper_makes_transaction_stale(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    _write_project(project)
    workspace = _cargo_workspace(tmp_path)
    transaction = collect_full_c6_license_materials(
        project_root=project,
        cargo_workspace=workspace,
    )

    (project / "LICENSE").write_text("changed project license\n", encoding="utf-8")
    assert not validate_full_c6_license_materials_transaction(transaction)

    project_two = tmp_path / "project-two"
    _write_project(project_two)
    workspace_two = _cargo_workspace(tmp_path / "second")
    transaction_two = collect_full_c6_license_materials(
        project_root=project_two,
        cargo_workspace=workspace_two,
    )
    payloads = list(workspace_two._file_payloads)
    payloads[-1] = b"forged Cargo material"
    object.__setattr__(workspace_two, "_file_payloads", tuple(payloads))
    assert not validate_full_c6_license_materials_transaction(transaction_two)


def test_revalidation_tolerates_unrelated_direct_ancestor_sibling_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ancestor = tmp_path / "workspace"
    project = ancestor / "project"
    _write_project(project)
    transaction = collect_full_c6_license_materials(
        project_root=project,
        cargo_workspace=_cargo_workspace(tmp_path / "cargo"),
    )
    before = ancestor.stat()
    original_read = license_materials_module._read_relative_file
    sibling_created = False

    def read_and_create_unrelated_sibling(
        root_fd: int,
        relative: PurePosixPath,
        *,
        max_bytes: int,
    ) -> bytes:
        nonlocal sibling_created
        payload = original_read(root_fd, relative, max_bytes=max_bytes)
        if not sibling_created:
            (ancestor / "unrelated-sibling.txt").write_bytes(b"ambient churn\n")
            sibling_created = True
        return payload

    monkeypatch.setattr(
        license_materials_module,
        "_read_relative_file",
        read_and_create_unrelated_sibling,
    )

    assert validate_full_c6_license_materials_transaction(transaction)
    assert sibling_created
    after = ancestor.stat()
    assert (after.st_dev, after.st_ino, after.st_mode) == (
        before.st_dev,
        before.st_ino,
        before.st_mode,
    )
    assert (
        after.st_size,
        after.st_ctime_ns,
        after.st_mtime_ns,
        after.st_nlink,
    ) != (
        before.st_size,
        before.st_ctime_ns,
        before.st_mtime_ns,
        before.st_nlink,
    )


def test_project_license_file_alias_is_rejected_before_path_lookup(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write_project(project, license_files='["LICENSE", "license"]')
    workspace = _cargo_workspace(tmp_path)

    with pytest.raises(FullC6LicenseMaterialsError, match="alias"):
        collect_full_c6_license_materials(
            project_root=project,
            cargo_workspace=workspace,
        )


def test_missing_project_or_cargo_metadata_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "LICENSE").write_text("orphan license bytes\n", encoding="utf-8")
    workspace = _cargo_workspace(tmp_path)

    with pytest.raises(FullC6LicenseMaterialsError, match="missing|unreadable"):
        collect_full_c6_license_materials(
            project_root=project,
            cargo_workspace=workspace,
        )

    _write_project(project)
    incomplete = tuple(
        (name, payload)
        for name, payload in workspace.metadata_payloads()
        if not name.endswith("/Cargo.toml")
    )
    monkeypatch.setattr(
        FullC6CargoDependencyWorkspaceReceipt,
        "metadata_payloads",
        lambda _self: incomplete,
    )
    with pytest.raises(FullC6LicenseMaterialsError, match="coverage is incomplete"):
        collect_full_c6_license_materials(
            project_root=project,
            cargo_workspace=workspace,
        )


def test_linked_project_metadata_or_license_material_is_rejected(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    _write_project(project)
    workspace = _cargo_workspace(tmp_path)
    target = project / "LICENSE.real"
    (project / "LICENSE").rename(target)
    (project / "LICENSE").symlink_to(target)

    with pytest.raises(FullC6LicenseMaterialsError, match="linked|unreadable"):
        collect_full_c6_license_materials(
            project_root=project,
            cargo_workspace=workspace,
        )

    (project / "LICENSE").unlink()
    target.unlink()
    real_metadata = project / "pyproject.real.toml"
    (project / "pyproject.toml").rename(real_metadata)
    (project / "pyproject.toml").symlink_to(real_metadata)
    with pytest.raises(FullC6LicenseMaterialsError, match="linked|unreadable"):
        collect_full_c6_license_materials(
            project_root=project,
            cargo_workspace=workspace,
        )


@pytest.mark.parametrize(
    ("license_value", "license_files", "match"),
    (
        ('{file = "LICENSE"}', '["LICENSE"]', "machine-readable SPDX"),
        ('"MIT"', "[]", "license-files"),
        ('"MIT"', '["MISSING"]', "missing|unreadable"),
        ('"MIT"', '["LICENSE*"]', "bounded and explicit"),
    ),
)
def test_project_requires_pep621_spdx_and_explicit_actual_pep639_files(
    tmp_path: Path,
    license_value: str,
    license_files: str,
    match: str,
) -> None:
    project = tmp_path / "project"
    _write_project(
        project,
        license_value=license_value,
        license_files=license_files,
    )
    workspace = _cargo_workspace(tmp_path)

    with pytest.raises(FullC6LicenseMaterialsError, match=match):
        collect_full_c6_license_materials(
            project_root=project,
            cargo_workspace=workspace,
        )


@pytest.mark.parametrize(
    ("license_expression", "declared", "conventional", "match"),
    (
        (None, True, True, "machine-readable SPDX"),
        ("MIT", False, False, "actual declared or conventional"),
    ),
)
def test_cargo_requires_expression_and_actual_license_bytes(
    tmp_path: Path,
    license_expression: str | None,
    declared: bool,
    conventional: bool,
    match: str,
) -> None:
    project = tmp_path / "project"
    _write_project(project)
    workspace = _cargo_workspace(
        tmp_path,
        license_expression=license_expression,
        declared_license_file=declared,
        conventional_license_file=conventional,
    )

    with pytest.raises(FullC6LicenseMaterialsError, match=match):
        collect_full_c6_license_materials(
            project_root=project,
            cargo_workspace=workspace,
        )


def test_cargo_manifest_name_and_version_are_rechecked_against_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    _write_project(project)
    workspace = _cargo_workspace(tmp_path)
    payloads = workspace.metadata_payloads()
    mismatched = tuple(
        (
            name,
            payload.replace(b'name = "demo-dep"', b'name = "other-dep"')
            if name.endswith("/Cargo.toml")
            else payload,
        )
        for name, payload in payloads
    )
    monkeypatch.setattr(
        FullC6CargoDependencyWorkspaceReceipt,
        "metadata_payloads",
        lambda _self: mismatched,
    )

    with pytest.raises(FullC6LicenseMaterialsError, match="name/version"):
        collect_full_c6_license_materials(
            project_root=project,
            cargo_workspace=workspace,
        )


def test_cargo_accepts_exact_legacy_mit_apache_alias_without_rewriting_manifest(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    _write_project(project)
    workspace = _cargo_workspace(
        tmp_path,
        license_expression="MIT/Apache-2.0",
    )
    manifest_name, manifest_payload = next(
        (name, payload)
        for name, payload in workspace.metadata_payloads()
        if name.endswith("/Cargo.toml")
    )
    assert b'license = "MIT/Apache-2.0"' in manifest_payload

    transaction = collect_full_c6_license_materials(
        project_root=project,
        cargo_workspace=workspace,
    )

    cargo = transaction.cargo_packages[0]
    assert cargo.declared_spdx == "MIT OR Apache-2.0"
    assert cargo.observed_spdx == "MIT OR Apache-2.0"
    assert cargo.metadata_file.logical_name == manifest_name
    assert cargo.metadata_file.sha256 == hashlib.sha256(manifest_payload).hexdigest()
    assert cargo.metadata_file.size == len(manifest_payload)
    assert transaction.cargo_workspace_sha256 == workspace.digest
    assert validate_full_c6_license_materials_transaction(transaction)


@pytest.mark.parametrize(
    "license_expression",
    (
        " MIT/Apache-2.0",
        "MIT/Apache-2.0 ",
        "Apache-2.0/MIT",
        "MIT / Apache-2.0",
        "MIT/BSD-3-Clause",
        "MIT/Apache-2.0.opt-1",
    ),
)
def test_cargo_rejects_nonexact_legacy_spdx_variants(
    tmp_path: Path,
    license_expression: str,
) -> None:
    project = tmp_path / "project"
    _write_project(project)
    workspace = _cargo_workspace(
        tmp_path,
        license_expression=license_expression,
    )

    with pytest.raises(FullC6LicenseMaterialsError, match="unsupported or noncanonical"):
        collect_full_c6_license_materials(
            project_root=project,
            cargo_workspace=workspace,
        )


def test_spdx_helper_uses_the_single_bounded_full_c6_allowlist() -> None:
    assert canonicalize_full_c6_spdx_expression("MIT OR Apache-2.0") == ("MIT OR Apache-2.0")
    with pytest.raises(FullC6PolicyError, match="canonical SPDX"):
        canonicalize_full_c6_spdx_expression("MIT or Apache-2.0")
    with pytest.raises(FullC6PolicyError, match="outside the initial allowlist"):
        canonicalize_full_c6_spdx_expression("LicenseRef-Proprietary")


@pytest.mark.parametrize(
    "invalid_shape",
    (
        "unsorted",
        "duplicate",
        "casefold-alias",
        "wrong-license-root",
        "record-root-mismatch",
        "total-size-overflow",
    ),
)
def test_output_license_verification_rejects_cross_field_mismatch(
    invalid_shape: str,
) -> None:
    dist_info = "demo_project-0.1.0.dist-info"
    first = OutputWheelLicenseMemberIdentity(
        path=f"{dist_info}/licenses/LICENSE-A",
        sha256="a" * 64,
        size=1,
    )
    second = OutputWheelLicenseMemberIdentity(
        path=f"{dist_info}/licenses/LICENSE-B",
        sha256="b" * 64,
        size=1,
    )
    members: tuple[OutputWheelLicenseMemberIdentity, ...] = (first, second)
    record_member = f"{dist_info}/RECORD"
    if invalid_shape == "unsorted":
        members = (second, first)
    elif invalid_shape == "duplicate":
        members = (first, first)
    elif invalid_shape == "casefold-alias":
        members = (
            OutputWheelLicenseMemberIdentity(
                path=f"{dist_info}/licenses/LICENSE",
                sha256="a" * 64,
                size=1,
            ),
            OutputWheelLicenseMemberIdentity(
                path=f"{dist_info}/licenses/license",
                sha256="b" * 64,
                size=1,
            ),
        )
    elif invalid_shape == "wrong-license-root":
        members = (
            OutputWheelLicenseMemberIdentity(
                path="other-1.0.dist-info/licenses/LICENSE",
                sha256="a" * 64,
                size=1,
            ),
        )
    elif invalid_shape == "record-root-mismatch":
        record_member = "other-1.0.dist-info/RECORD"
    else:
        members = (
            OutputWheelLicenseMemberIdentity(
                path=f"{dist_info}/licenses/LICENSE-A",
                sha256="a" * 64,
                size=(MAX_OUTPUT_WHEEL_LICENSE_TOTAL_BYTES // 2) + 1,
            ),
            OutputWheelLicenseMemberIdentity(
                path=f"{dist_info}/licenses/LICENSE-B",
                sha256="b" * 64,
                size=(MAX_OUTPUT_WHEEL_LICENSE_TOTAL_BYTES // 2) + 1,
            ),
        )

    with pytest.raises(ValueError, match="verification is invalid"):
        OutputWheelLicenseVerification(
            expression="MIT",
            metadata_member=f"{dist_info}/METADATA",
            metadata_sha256="c" * 64,
            license_members=members,
            record_member=record_member,
            wheel_sha256="d" * 64,
        )


def test_output_license_contract_accepts_real_full_c6_shaped_108_file_set() -> None:
    files = tuple(
        sorted(
            (
                OutputWheelLicenseFile("project/LICENSE", b"project license\n"),
                *(
                    OutputWheelLicenseFile(
                        f"cargo/package-{index:03d}/LICENSE",
                        f"cargo license {index}\n".encode(),
                    )
                    for index in range(106)
                ),
                OutputWheelLicenseFile(
                    "external/demo-pkg/1.0.0/LICENSE",
                    b"external license\n",
                ),
            ),
            key=lambda item: item.path,
        )
    )

    contract = OutputWheelLicenseContract(
        expression="MIT",
        files=files,
        external_source_distribution="demo-pkg",
        external_source_version="1.0.0",
        source_lock_verification_sha256="a" * 64,
    )

    assert len(contract.files) == 108
    assert sum(path.startswith("project/") for path in contract.paths) == 1
    assert sum(path.startswith("cargo/") for path in contract.paths) == 106
    assert sum(path.startswith("external/") for path in contract.paths) == 1


@pytest.mark.parametrize(("count", "accepted"), ((128, True), (129, False)))
def test_output_license_contract_enforces_bounded_128_file_cap(
    count: int,
    accepted: bool,
) -> None:
    files = tuple(
        OutputWheelLicenseFile(
            f"cargo/package-{index:03d}/LICENSE",
            b"license\n",
        )
        for index in range(count)
    )

    if accepted:
        contract = OutputWheelLicenseContract(expression="MIT", files=files)
        assert len(contract.files) == MAX_OUTPUT_WHEEL_LICENSE_FILES
    else:
        with pytest.raises(ValueError, match="license-file set is invalid"):
            OutputWheelLicenseContract(expression="MIT", files=files)


def test_output_license_count_cap_preserves_path_alias_and_total_byte_bounds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValueError, match="path is invalid"):
        OutputWheelLicenseFile("../LICENSE", b"license\n")

    with pytest.raises(ValueError, match="contains aliases"):
        OutputWheelLicenseContract(
            expression="MIT",
            files=(
                OutputWheelLicenseFile("project/LICENSE", b"one\n"),
                OutputWheelLicenseFile("project/license", b"two\n"),
            ),
        )

    assert MAX_OUTPUT_WHEEL_LICENSE_TOTAL_BYTES == 64 * 1024 * 1024
    monkeypatch.setattr(output_license_module, "MAX_OUTPUT_WHEEL_LICENSE_TOTAL_BYTES", 1)
    with pytest.raises(ValueError, match="outside the byte bound"):
        OutputWheelLicenseContract(
            expression="MIT",
            files=(OutputWheelLicenseFile("project/LICENSE", b"too large\n"),),
        )


def test_derives_exact_project_and_cargo_pep639_material_deterministically(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    _write_project(
        project,
        license_files='["LICENSE", "legal/NOTICE"]',
        extra_files={"legal/NOTICE": b"project notice bytes\n"},
    )
    workspace = _cargo_workspace(
        tmp_path,
        extra_license_files={"NOTICE.md": b"Cargo notice bytes\n"},
    )
    transaction = collect_full_c6_license_materials(
        project_root=project,
        cargo_workspace=workspace,
    )
    source_context = _source_context(tmp_path)

    first = derive_full_c6_output_license_contract(
        transaction,
        source_context=source_context,
    )
    second = derive_full_c6_output_license_contract(
        transaction,
        source_context=source_context,
    )

    assert first == second
    assert first.expression == "MIT"
    assert first.paths == (
        "cargo/demo-dep-1.2.3/LICENSE",
        "cargo/demo-dep-1.2.3/NOTICE.md",
        "external/demo-pkg/1.0.0/LICENSE",
        "project/LICENSE",
        "project/legal/NOTICE",
    )
    assert {item.path: item.data for item in first.files} == {
        "cargo/demo-dep-1.2.3/LICENSE": b"Cargo MIT or Apache license evidence\n",
        "cargo/demo-dep-1.2.3/NOTICE.md": b"Cargo notice bytes\n",
        "external/demo-pkg/1.0.0/LICENSE": _SOURCE_TESTS["LICENSE"],
        "project/LICENSE": b"project MIT license evidence\n",
        "project/legal/NOTICE": b"project notice bytes\n",
    }
    assert transaction.cargo_packages[0].declared_spdx == "MIT OR Apache-2.0"

    observation = validate_full_c6_output_license_contract(
        transaction,
        first,
        source_context=source_context,
    )
    rendered = json.dumps(observation.to_dict(), sort_keys=True)
    assert observation.license_transaction_sha256 == transaction.digest
    assert observation.source_lock_verification_sha256 == (first.source_lock_verification_sha256)
    assert observation.external_source_distribution == "demo-pkg"
    assert observation.external_source_version == "1.0.0"
    assert len(observation.output_contract_sha256) == 64
    assert len(observation.expression_sha256) == 64
    assert tuple(item.output_path for item in observation.mappings) == first.paths
    assert observation.complete_coverage is True
    assert observation.legal_approval_inferred is False
    assert observation.authorizes_build is False
    assert observation.authorizes_distribution is False
    assert str(tmp_path) not in rendered
    assert "project MIT license evidence" not in rendered
    assert "Cargo MIT or Apache license evidence" not in rendered


def test_derivation_rejects_stale_project_or_cargo_transaction(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write_project(project)
    transaction = collect_full_c6_license_materials(
        project_root=project,
        cargo_workspace=_cargo_workspace(tmp_path),
    )
    (project / "LICENSE").write_bytes(b"stale project bytes\n")
    with pytest.raises(FullC6OutputLicenseDerivationError, match="invalid or stale"):
        derive_full_c6_output_license_contract(
            transaction,
            source_context=_source_context(tmp_path / "stale-project"),
        )

    project_two = tmp_path / "project-two"
    _write_project(project_two)
    workspace_two = _cargo_workspace(tmp_path / "two")
    transaction_two = collect_full_c6_license_materials(
        project_root=project_two,
        cargo_workspace=workspace_two,
    )
    payloads = list(workspace_two._file_payloads)
    payloads[-1] = b"stale Cargo bytes\n"
    object.__setattr__(workspace_two, "_file_payloads", tuple(payloads))
    with pytest.raises(FullC6OutputLicenseDerivationError, match="invalid or stale"):
        derive_full_c6_output_license_contract(
            transaction_two,
            source_context=_source_context(tmp_path / "stale-cargo"),
        )


@pytest.mark.parametrize(
    "mutation",
    ("omitted", "extra", "substituted", "reordered", "aliased"),
)
def test_validator_rejects_nonexact_or_noncanonical_contract(
    tmp_path: Path,
    mutation: str,
) -> None:
    project = tmp_path / "project"
    _write_project(project)
    transaction = collect_full_c6_license_materials(
        project_root=project,
        cargo_workspace=_cargo_workspace(tmp_path),
    )
    source_context = _source_context(tmp_path)
    expected = derive_full_c6_output_license_contract(
        transaction,
        source_context=source_context,
    )
    if mutation == "omitted":
        candidate = OutputWheelLicenseContract(
            expression=expected.expression,
            files=expected.files[:-1],
            external_source_distribution=expected.external_source_distribution,
            external_source_version=expected.external_source_version,
            source_lock_verification_sha256=(expected.source_lock_verification_sha256),
        )
    elif mutation == "extra":
        candidate = OutputWheelLicenseContract(
            expression=expected.expression,
            files=tuple(
                sorted(
                    (*expected.files, OutputWheelLicenseFile("z-extra/LICENSE", b"extra")),
                    key=lambda item: item.path,
                )
            ),
            external_source_distribution=expected.external_source_distribution,
            external_source_version=expected.external_source_version,
            source_lock_verification_sha256=(expected.source_lock_verification_sha256),
        )
    elif mutation == "substituted":
        replacement = OutputWheelLicenseFile(
            expected.files[0].path,
            b"substituted bytes",
        )
        candidate = OutputWheelLicenseContract(
            expression=expected.expression,
            files=(replacement, *expected.files[1:]),
            external_source_distribution=expected.external_source_distribution,
            external_source_version=expected.external_source_version,
            source_lock_verification_sha256=(expected.source_lock_verification_sha256),
        )
    else:
        candidate = OutputWheelLicenseContract(
            expression=expected.expression,
            files=expected.files,
            external_source_distribution=expected.external_source_distribution,
            external_source_version=expected.external_source_version,
            source_lock_verification_sha256=(expected.source_lock_verification_sha256),
        )
        if mutation == "reordered":
            object.__setattr__(candidate, "files", tuple(reversed(candidate.files)))
        else:
            alias = OutputWheelLicenseFile("project/license", b"alias")
            object.__setattr__(
                candidate,
                "files",
                tuple(sorted((*candidate.files, alias), key=lambda item: item.path)),
            )

    with pytest.raises(FullC6OutputLicenseDerivationError):
        validate_full_c6_output_license_contract(
            transaction,
            candidate,
            source_context=source_context,
        )


def test_validator_rejects_wrong_distribution_expression(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write_project(project)
    transaction = collect_full_c6_license_materials(
        project_root=project,
        cargo_workspace=_cargo_workspace(tmp_path),
    )
    source_context = _source_context(tmp_path)
    expected = derive_full_c6_output_license_contract(
        transaction,
        source_context=source_context,
    )
    wrong = OutputWheelLicenseContract(
        expression="Apache-2.0",
        files=expected.files,
        external_source_distribution=expected.external_source_distribution,
        external_source_version=expected.external_source_version,
        source_lock_verification_sha256=expected.source_lock_verification_sha256,
    )

    with pytest.raises(FullC6OutputLicenseDerivationError, match="differs"):
        validate_full_c6_output_license_contract(
            transaction,
            wrong,
            source_context=source_context,
        )


def test_validator_binds_exact_completed_wheel_license_verification(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    _write_project(project)
    transaction = collect_full_c6_license_materials(
        project_root=project,
        cargo_workspace=_cargo_workspace(tmp_path),
    )
    source_context = _source_context(tmp_path)
    contract = derive_full_c6_output_license_contract(
        transaction,
        source_context=source_context,
    )
    dist_info = "demo_project-0.1.0.dist-info"
    members = tuple(
        OutputWheelLicenseMemberIdentity(
            path=f"{dist_info}/licenses/{item.path}",
            sha256=hashlib.sha256(item.data).hexdigest(),
            size=len(item.data),
        )
        for item in contract.files
    )
    verification = OutputWheelLicenseVerification(
        expression=contract.expression,
        metadata_member=f"{dist_info}/METADATA",
        metadata_sha256="a" * 64,
        license_members=members,
        record_member=f"{dist_info}/RECORD",
        wheel_sha256="b" * 64,
    )
    observed = validate_full_c6_output_license_contract(
        transaction,
        contract,
        verification,
        source_context=source_context,
    )
    assert observed.output_verification_sha256 is not None

    wrong_members = (
        OutputWheelLicenseMemberIdentity(
            path=members[0].path,
            sha256="c" * 64,
            size=members[0].size,
        ),
        *members[1:],
    )
    wrong = OutputWheelLicenseVerification(
        expression=verification.expression,
        metadata_member=verification.metadata_member,
        metadata_sha256=verification.metadata_sha256,
        license_members=wrong_members,
        record_member=verification.record_member,
        wheel_sha256=verification.wheel_sha256,
    )
    with pytest.raises(FullC6OutputLicenseDerivationError, match="verification differs"):
        validate_full_c6_output_license_contract(
            transaction,
            contract,
            wrong,
            source_context=source_context,
        )


@pytest.mark.parametrize("mutation", ("missing", "tampered", "duplicate-alias"))
def test_external_license_derivation_rejects_stale_sourcelock_payloads(
    tmp_path: Path,
    mutation: str,
) -> None:
    project = tmp_path / "project"
    _write_project(project)
    transaction = collect_full_c6_license_materials(
        project_root=project,
        cargo_workspace=_cargo_workspace(tmp_path),
    )
    source_context = _source_context(tmp_path)
    wheel = source_context.wheel
    if mutation == "missing":
        object.__setattr__(wheel, "license_payloads", ())
    elif mutation == "tampered":
        object.__setattr__(wheel, "license_payloads", (b"forged external license",))
    else:
        object.__setattr__(
            wheel,
            "license_entry_paths",
            (wheel.license_entry_paths[0], wheel.license_entry_paths[0]),
        )
        object.__setattr__(
            wheel,
            "license_payloads",
            (wheel.license_payloads[0], wheel.license_payloads[0]),
        )

    with pytest.raises(FullC6OutputLicenseDerivationError, match="SourceLock"):
        derive_full_c6_output_license_contract(
            transaction,
            source_context=source_context,
        )


def test_validator_rejects_rebound_sourcelock_digest(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write_project(project)
    transaction = collect_full_c6_license_materials(
        project_root=project,
        cargo_workspace=_cargo_workspace(tmp_path),
    )
    source_context = _source_context(tmp_path)
    contract = derive_full_c6_output_license_contract(
        transaction,
        source_context=source_context,
    )
    rebound = OutputWheelLicenseContract(
        expression=contract.expression,
        files=contract.files,
        external_source_distribution=contract.external_source_distribution,
        external_source_version=contract.external_source_version,
        source_lock_verification_sha256="f" * 64,
    )

    with pytest.raises(FullC6OutputLicenseDerivationError, match="differs"):
        validate_full_c6_output_license_contract(
            transaction,
            rebound,
            source_context=source_context,
        )


def test_contract_rejects_external_path_outside_bound_distribution(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    _write_project(project)
    transaction = collect_full_c6_license_materials(
        project_root=project,
        cargo_workspace=_cargo_workspace(tmp_path),
    )
    source_context = _source_context(tmp_path)
    contract = derive_full_c6_output_license_contract(
        transaction,
        source_context=source_context,
    )

    with pytest.raises(ValueError, match="escapes its source binding"):
        OutputWheelLicenseContract(
            expression=contract.expression,
            files=tuple(
                sorted(
                    (
                        *contract.files,
                        OutputWheelLicenseFile(
                            path="external/other-dist/9.9/LICENSE",
                            data=b"unbound external license bytes",
                        ),
                    ),
                    key=lambda item: item.path,
                )
            ),
            external_source_distribution=contract.external_source_distribution,
            external_source_version=contract.external_source_version,
            source_lock_verification_sha256=(contract.source_lock_verification_sha256),
        )


def test_external_license_bytes_are_exact_pep639_wheel_members(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    _write_project(project)
    transaction = collect_full_c6_license_materials(
        project_root=project,
        cargo_workspace=_cargo_workspace(tmp_path),
    )
    source_context = _source_context(tmp_path)
    contract = derive_full_c6_output_license_contract(
        transaction,
        source_context=source_context,
    )
    python_dir = tmp_path / "python"
    python_dir.mkdir()
    (python_dir / "app.py").write_text("VALUE = 1\n", encoding="utf-8")

    result = build_artifact_wheel(
        project,
        python_dir,
        tmp_path / "dist",
        output_license_contract=contract,
    )

    assert result.status == "built"
    assert result.path is not None
    with zipfile.ZipFile(result.path) as archive:
        names = archive.namelist()
        metadata_name = next(name for name in names if name.endswith(".dist-info/METADATA"))
        record_name = next(name for name in names if name.endswith(".dist-info/RECORD"))
        dist_info = metadata_name.rsplit("/", 1)[0]
        external_member = f"{dist_info}/licenses/external/demo-pkg/1.0.0/LICENSE"
        metadata = archive.read(metadata_name).decode("utf-8")
        record = archive.read(record_name).decode("utf-8")
        assert archive.read(external_member) == _SOURCE_TESTS["LICENSE"]
    assert "License-File: external/demo-pkg/1.0.0/LICENSE\n" in metadata
    assert f"{external_member},sha256=" in record
    assert names.count(external_member) == 1
