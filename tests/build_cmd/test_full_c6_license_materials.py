"""Focused adversarial tests for process-sealed Full C6 license materials."""

from __future__ import annotations

import copy
import hashlib
import json
import pickle
from pathlib import Path

import pytest

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
from rextio.build.full_c6_policy import (
    FullC6PolicyError,
    canonicalize_full_c6_spdx_expression,
)
from rextio.build.toolchain_identity import capture_cargo_sources


PACKAGE = "demo-dep"
VERSION = "1.2.3"
PACKAGE_CHECKSUM = "a" * 64


def _write_project(
    root: Path,
    *,
    license_value: str = '"MIT"',
    license_files: str = '["LICENSE"]',
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


def _cargo_workspace(
    tmp_path: Path,
    *,
    license_expression: str | None = "MIT OR Apache-2.0",
    declared_license_file: bool = True,
    conventional_license_file: bool = True,
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
    assert [item.logical_name for item in transaction.project.license_files] == [
        "project/LICENSE"
    ]
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
    payloads = list(workspace_two._file_payloads)  # type: ignore[attr-defined]
    payloads[-1] = b"forged Cargo material"
    object.__setattr__(workspace_two, "_file_payloads", tuple(payloads))
    assert not validate_full_c6_license_materials_transaction(transaction_two)


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


def test_spdx_helper_uses_the_single_bounded_full_c6_allowlist() -> None:
    assert canonicalize_full_c6_spdx_expression("MIT OR Apache-2.0") == (
        "MIT OR Apache-2.0"
    )
    with pytest.raises(FullC6PolicyError, match="canonical SPDX"):
        canonicalize_full_c6_spdx_expression("MIT or Apache-2.0")
    with pytest.raises(FullC6PolicyError, match="outside the initial allowlist"):
        canonicalize_full_c6_spdx_expression("LicenseRef-Proprietary")
