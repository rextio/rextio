from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

import rextio.cli.build_cmd as build_cmd
import rextio.source.external as external_source
from rextio.analyzer.project_scanner import analyze_project
from rextio.cli.main import main
from rextio.config.loader import load_config
from rextio.source.authorization import (
    LICENSE_ACKNOWLEDGEMENT_V1,
    SOURCE_LOCK_FILENAME,
    license_material_digest,
    plan_snapshot_sha256,
    verify_external_source_authorization,
)


PACKAGE = "rextio_c5_poc_math"
DIST_NAME = "rextio-c5-poc-math"
VERSION = "1.0.0"
SOURCE = """
raise RuntimeError("external distribution source must not be imported or copied")

def affine(x: int, scale: int, bias: int) -> int:
    return x * scale + bias
""".lstrip()


def _record_row(root: Path, relative: str) -> str:
    data = (root / relative).read_bytes()
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode("ascii")
    return f"{relative},sha256={digest.rstrip('=')},{len(data)}"


def _write_project(tmp_path: Path) -> Path:
    project = tmp_path / "project"
    project.mkdir()
    (project / "rextio.toml").write_text(
        f"""
[imports.packages.{PACKAGE}]
policy = "try-native"
max_depth = 1
distribution = "{DIST_NAME}"
version = "{VERSION}"
""".lstrip(),
        encoding="utf-8",
    )
    (project / "app.py").write_text(
        f"""
import {PACKAGE} as poc

def calculate(x: int) -> int:
    return poc.affine(x, 2, 3)
""".lstrip(),
        encoding="utf-8",
    )
    return project


def _write_distribution(
    root: Path,
    *,
    name: str = DIST_NAME,
    version: str = VERSION,
    source: str = SOURCE,
    metadata_text: str | None = None,
    wheel: str = "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    include_record: bool = True,
) -> external_source.metadata.Distribution:
    root.mkdir()
    package = root / PACKAGE
    package.mkdir()
    (package / "__init__.py").write_text(source, encoding="utf-8")
    dist_info = root / f"{PACKAGE}-{version}.dist-info"
    dist_info.mkdir()
    if metadata_text is None:
        metadata_text = "\n".join(
            (
                "Metadata-Version: 2.4",
                f"Name: {name}",
                f"Version: {version}",
                "License-Expression: MIT",
                "",
            )
        )
    (dist_info / "METADATA").write_text(metadata_text, encoding="utf-8")
    (dist_info / "WHEEL").write_text(wheel, encoding="utf-8")
    if include_record:
        source_relative = f"{PACKAGE}/__init__.py"
        metadata_relative = f"{dist_info.name}/METADATA"
        wheel_relative = f"{dist_info.name}/WHEEL"
        (dist_info / "RECORD").write_text(
            "\n".join(
                (
                    _record_row(root, source_relative),
                    _record_row(root, metadata_relative),
                    _record_row(root, wheel_relative),
                    f"{dist_info.name}/RECORD,,",
                    "",
                )
            ),
            encoding="utf-8",
        )
    return external_source.metadata.Distribution.at(dist_info)


def _install_distribution(
    monkeypatch: pytest.MonkeyPatch,
    distribution: external_source.metadata.Distribution,
) -> None:
    def get_distribution(name: str) -> external_source.metadata.Distribution:
        assert name == DIST_NAME
        return distribution

    monkeypatch.setattr(external_source.metadata, "distribution", get_distribution)


def _analyze(project: Path):
    config = load_config(project, environ={})
    return analyze_project(project, imports_config=config.imports)


def _write_valid_source_lock(project: Path, plan: external_source.ExternalSourcePlan) -> None:
    snapshot = plan_snapshot_sha256(plan)
    assert snapshot is not None
    assert plan.license is not None
    source_entries = [
        {
            "module_name": item.module_name,
            "path": item.path,
            "sha256": item.sha256,
            "size": item.size,
            "role": "source-module",
        }
        for item in plan.source_files
    ]
    metadata_entries = [
        {
            "path": item.path,
            "sha256": item.sha256,
            "size": item.size,
            "role": item.role,
        }
        for item in plan.metadata_files
    ]
    all_files = [
        {
            "path": item.path,
            "sha256": item.sha256,
            "size": item.size,
            "role": item.role,
        }
        for item in (*plan.source_files, *plan.metadata_files)
    ]
    attestor = "Integration Test Org"
    document = {
        "schema_version": "1",
        "kind": "rextio.external-source-authorization",
        "package": plan.package,
        "distribution": plan.distribution,
        "version": plan.requested_version,
        "content_hashes": {
            "source_files": source_entries,
            "metadata_files": metadata_entries,
            "snapshot_sha256": snapshot,
        },
        "source_inventory": {
            "format": "rextio-source-inventory-v1",
            "components": [
                {
                    "type": "pypi-distribution",
                    "name": plan.distribution,
                    "version": plan.requested_version,
                    "license_observed": plan.license,
                    "files": all_files,
                }
            ],
        },
        "provenance": {
            "subject_snapshot_sha256": snapshot,
            "producer": attestor,
            "attestor_relationship": "organization-owner",
            "installed_wheel": {
                "distribution": plan.distribution,
                "version": plan.requested_version,
                "metadata_files": metadata_entries,
            },
            "evidence": [
                "installed-distribution-record",
                "project-vcs-review",
            ],
        },
        "license_attestation": {
            "attestor": attestor,
            "attestor_kind": "organization",
            "reviewed_license": plan.license,
            "reviewed_license_material_sha256": license_material_digest(plan),
            "decision": "allow",
            "action_scopes": [
                "analysis",
                "translation",
                "local-build",
                "package",
                "redistribution",
            ],
            "acknowledgement": LICENSE_ACKNOWLEDGEMENT_V1,
        },
    }
    (project / SOURCE_LOCK_FILENAME).write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def test_analyze_project_creates_sanitized_external_source_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _write_project(tmp_path)
    installed_root = tmp_path / "fake-site-packages"
    distribution = _write_distribution(installed_root)
    _install_distribution(monkeypatch, distribution)

    analysis = _analyze(project)

    assert analysis.external_source_plan is not None
    assert analysis.external_source_plan.status == "preview-ready"
    assert analysis.external_source_plan.candidate_functions == (
        f"{PACKAGE}.affine",
    )
    payload = analysis.to_dict()["external_source_plan"]
    assert payload["execution_authority"] == "preview-only"
    assert payload["distributable"] is False
    assert payload["c6_gate"] == "required"
    assert payload["authorization"]["status"] == "missing"
    assert payload["modules"][0]["path"] == (
        f"distributions/{DIST_NAME}/{PACKAGE}/__init__.py"
    )
    assert "size" not in payload["modules"][0]
    assert payload["source_files"][0]["size"] == len(SOURCE.encode("utf-8"))
    assert payload["plan_snapshot_sha256"] is not None
    assert payload["license_material_sha256"] is not None
    assert payload["plan_snapshot"]["domain"] == "rextio.external-source-plan-snapshot.v1"
    assert payload["plan_snapshot"]["license_material_sha256"] == payload[
        "license_material_sha256"
    ]
    assert payload["source_files"]
    assert payload["metadata_files"]
    roles = {item["role"] for item in payload["metadata_files"]}
    assert roles >= {"record", "metadata", "wheel"}
    # Full 2.6 key surface for lock authoring from check JSON alone.
    for key in (
        "inventory_schema",
        "source_files",
        "metadata_files",
        "plan_snapshot",
        "plan_snapshot_sha256",
        "license_material_sha256",
    ):
        assert key in payload
    assert "GNU/copyleft" in payload["license_warning"]
    assert str(installed_root) not in json.dumps(payload)


def test_check_and_generate_serialize_preview_without_copying_distribution_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = _write_project(tmp_path)
    installed_root = tmp_path / "fake-site-packages"
    distribution = _write_distribution(installed_root)
    _install_distribution(monkeypatch, distribution)

    assert main(["check", str(project)]) == 0
    assert "GNU/copyleft" in capsys.readouterr().err
    check_payload = json.loads(
        (project / ".rextio" / "reports" / "check.json").read_text(encoding="utf-8")
    )
    assert check_payload["external_source_plan"]["status"] == "preview-ready"
    assert str(installed_root) not in json.dumps(check_payload)

    assert main(["generate", str(project), "--fallback=cpython"]) == 0
    assert "GNU/copyleft" in capsys.readouterr().err
    generate_payload = json.loads(
        (project / ".rextio" / "reports" / "generate.json").read_text(encoding="utf-8")
    )
    generated_check_payload = json.loads(
        (project / ".rextio" / "reports" / "check.json").read_text(encoding="utf-8")
    )
    assert generate_payload["external_source_plan"]["status"] == "preview-ready"
    assert generated_check_payload["external_source_plan"]["status"] == "preview-ready"
    assert str(installed_root) not in json.dumps(generate_payload)
    assert str(installed_root) not in json.dumps(generated_check_payload)

    generated_python = project / ".rextio" / "generated" / "python"
    assert not (generated_python / PACKAGE).exists()
    assert not (generated_python / f"{PACKAGE}.py").exists()
    generated_text = "\n".join(
        path.read_text(encoding="utf-8") for path in generated_python.rglob("*.py")
    )
    assert "external distribution source must not be imported or copied" not in generated_text


def test_cli_build_reports_c6_gate_without_starting_artifact_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = _write_project(tmp_path)
    installed_root = tmp_path / "fake-site-packages"
    distribution = _write_distribution(installed_root)
    _install_distribution(monkeypatch, distribution)

    def unexpected_artifact_work(*_args: object, **_kwargs: object) -> None:
        pytest.fail("the C6 gate must run before toolchain or artifact work")

    monkeypatch.setattr(build_cmd, "_prepare_build_toolchain", unexpected_artifact_work)
    monkeypatch.setattr(build_cmd, "build_hybrid_artifact", unexpected_artifact_work)

    assert main(["build", str(project), "--fallback=cpython"]) == 1
    captured = capsys.readouterr()
    report = json.loads(
        (project / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )
    assert "C6.1 SourceLock" in captured.err or "C6 SourceLock" in captured.err
    assert "GNU/copyleft" in captured.err
    assert "authorization: status=missing" in captured.err
    assert report["status"] == "external-source-c6-blocked"
    assert report["error"]["code"] == "RXT060"
    assert report["external_source_plan"]["execution_authority"] == "preview-only"
    assert report["external_source_plan"]["authorization"]["status"] == "missing"
    assert "external_source_authorization" not in report
    assert str(installed_root) not in json.dumps(report)
    assert not (project / ".rextio" / "generated").exists()
    assert not (project / ".rextio" / "build").exists()


def test_cli_build_verified_authorization_still_blocks_c5_not_implemented(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = _write_project(tmp_path)
    installed_root = tmp_path / "fake-site-packages"
    distribution = _write_distribution(installed_root)
    _install_distribution(monkeypatch, distribution)
    plan = _analyze(project).external_source_plan
    assert plan is not None
    _write_valid_source_lock(project, plan)

    def unexpected_artifact_work(*_args: object, **_kwargs: object) -> None:
        pytest.fail("verified C6 must not start toolchain or artifact work")

    monkeypatch.setattr(build_cmd, "_prepare_build_toolchain", unexpected_artifact_work)
    monkeypatch.setattr(build_cmd, "build_hybrid_artifact", unexpected_artifact_work)

    assert main(["build", str(project), "--fallback=cpython"]) == 1
    captured = capsys.readouterr()
    report = json.loads(
        (project / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )
    assert report["status"] == "external-source-c5-not-implemented"
    assert report["error"]["code"] == "RXT060"
    assert "not implemented" in report["error"]["message"]
    assert report["external_source_plan"]["c6_gate"] == "authorization-verified"
    assert report["external_source_plan"]["authorization"]["status"] == "verified"
    assert "external_source_authorization" not in report
    assert "call-site linkage" in captured.err
    assert "authorization: status=verified" in captured.err
    assert str(installed_root) not in json.dumps(report)
    assert not (project / ".rextio" / "generated").exists()
    assert not (project / ".rextio" / "build").exists()


def test_check_and_generate_report_verified_authorization_without_local_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = _write_project(tmp_path)
    installed_root = tmp_path / "fake-site-packages"
    distribution = _write_distribution(installed_root)
    _install_distribution(monkeypatch, distribution)
    plan = _analyze(project).external_source_plan
    assert plan is not None
    _write_valid_source_lock(project, plan)

    assert main(["check", str(project)]) == 0
    captured = capsys.readouterr()
    assert "authorization: status=verified" in captured.err
    check_payload = json.loads(
        (project / ".rextio" / "reports" / "check.json").read_text(encoding="utf-8")
    )
    auth = check_payload["external_source_plan"]["authorization"]
    assert auth["status"] == "verified"
    assert auth["path"] == SOURCE_LOCK_FILENAME
    assert auth["license_attestation_verified"] is True
    assert auth["source_inventory_verified"] is True
    assert auth["provenance_verified"] is True
    assert check_payload["external_source_plan"]["plan_snapshot_sha256"]
    assert "external_source_authorization" not in check_payload
    assert str(installed_root) not in json.dumps(check_payload)
    assert str(project) not in json.dumps(auth)

    assert main(["generate", str(project), "--fallback=cpython"]) == 0
    generate_payload = json.loads(
        (project / ".rextio" / "reports" / "generate.json").read_text(encoding="utf-8")
    )
    gen_auth = generate_payload["external_source_plan"]["authorization"]
    assert gen_auth["status"] == "verified"
    assert "external_source_authorization" not in generate_payload
    assert str(installed_root) not in json.dumps(generate_payload)


def _write_distribution_with_license_file(
    root: Path,
    *,
    license_value: str = "LICENSE",
    license_body: str | bytes = "MIT License text\n",
    metadata_version: str = "2.4",
    include_license_expression: bool = True,
    include_legacy_license: bool = False,
    record_license: bool = True,
    nested_license_path: str | None = None,
) -> external_source.metadata.Distribution:
    """Write a wheel-shaped layout with License-File under dist-info/licenses/."""
    root.mkdir(exist_ok=True)
    package = root / PACKAGE
    package.mkdir(exist_ok=True)
    (package / "__init__.py").write_text(SOURCE, encoding="utf-8")
    dist_info = root / f"{PACKAGE}-{VERSION}.dist-info"
    dist_info.mkdir(exist_ok=True)
    licenses_dir = dist_info / "licenses"
    if nested_license_path is not None:
        license_rel = nested_license_path
    else:
        license_rel = license_value
    license_path = licenses_dir.joinpath(*PurePosixPath(license_rel).parts)
    license_path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(license_body, bytes):
        license_path.write_bytes(license_body)
    else:
        license_path.write_text(license_body, encoding="utf-8")
    headers = [
        f"Metadata-Version: {metadata_version}",
        f"Name: {DIST_NAME}",
        f"Version: {VERSION}",
    ]
    if include_license_expression:
        headers.append("License-Expression: MIT")
    if include_legacy_license:
        headers.append("License: MIT")
    headers.append(f"License-File: {license_value}")
    headers.append("")
    (dist_info / "METADATA").write_text("\n".join(headers), encoding="utf-8")
    (dist_info / "WHEEL").write_text(
        "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        encoding="utf-8",
    )
    rows = [
        _record_row(root, f"{PACKAGE}/__init__.py"),
        _record_row(root, f"{dist_info.name}/METADATA"),
        _record_row(root, f"{dist_info.name}/WHEEL"),
    ]
    if record_license:
        rows.insert(
            1,
            _record_row(root, f"{dist_info.name}/licenses/{license_rel}"),
        )
    rows.append(f"{dist_info.name}/RECORD,,")
    rows.append("")
    (dist_info / "RECORD").write_text("\n".join(rows), encoding="utf-8")
    return external_source.metadata.Distribution.at(dist_info)


def test_analyze_project_includes_license_file_authority_material(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _write_project(tmp_path)
    installed_root = tmp_path / "fake-site-packages"
    distribution = _write_distribution_with_license_file(
        installed_root,
        license_value="docs/COPYING",
        nested_license_path="docs/COPYING",
        license_body="MIT nested license\n",
    )
    _install_distribution(monkeypatch, distribution)

    analysis = _analyze(project)
    plan = analysis.external_source_plan
    assert plan is not None
    assert plan.status == "preview-ready"
    license_roles = [item for item in plan.metadata_files if item.role == "license-file"]
    assert len(license_roles) == 1
    assert license_roles[0].path.endswith(
        f"/{PACKAGE}-{VERSION}.dist-info/licenses/docs/COPYING"
    )
    assert license_roles[0].size == len(b"MIT nested license\n")


def test_analyze_project_rejects_unrecorded_license_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _write_project(tmp_path)
    installed_root = tmp_path / "fake-site-packages"
    distribution = _write_distribution_with_license_file(
        installed_root,
        record_license=False,
    )
    _install_distribution(monkeypatch, distribution)

    analysis = _analyze(project)
    plan = analysis.external_source_plan
    assert plan is not None
    assert plan.status == "unavailable"
    assert "License-File" in (plan.reason or "")


def test_analyze_project_rejects_license_file_backslash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _write_project(tmp_path)
    installed_root = tmp_path / "fake-site-packages"
    distribution = _write_distribution(
        installed_root,
        metadata_text="\n".join(
            (
                "Metadata-Version: 2.4",
                f"Name: {DIST_NAME}",
                f"Version: {VERSION}",
                "License-Expression: MIT",
                r"License-File: lic\LICENSE",
                "",
            )
        ),
    )
    _install_distribution(monkeypatch, distribution)
    analysis = _analyze(project)
    plan = analysis.external_source_plan
    assert plan is not None
    assert plan.status == "unavailable"
    assert "backslash" in (plan.reason or "")


def test_analyze_project_rejects_pre_24_license_expression(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _write_project(tmp_path)
    installed_root = tmp_path / "fake-site-packages"
    distribution = _write_distribution(
        installed_root,
        metadata_text="\n".join(
            (
                "Metadata-Version: 2.1",
                f"Name: {DIST_NAME}",
                f"Version: {VERSION}",
                "License-Expression: MIT",
                "",
            )
        ),
    )
    _install_distribution(monkeypatch, distribution)
    analysis = _analyze(project)
    plan = analysis.external_source_plan
    assert plan is not None
    assert plan.status == "unavailable"
    assert "2.4" in (plan.reason or "")


def test_analyze_project_rejects_conflicting_license_headers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _write_project(tmp_path)
    installed_root = tmp_path / "fake-site-packages"
    distribution = _write_distribution(
        installed_root,
        metadata_text="\n".join(
            (
                "Metadata-Version: 2.4",
                f"Name: {DIST_NAME}",
                f"Version: {VERSION}",
                "License-Expression: MIT",
                "License: MIT",
                "",
            )
        ),
    )
    _install_distribution(monkeypatch, distribution)
    analysis = _analyze(project)
    plan = analysis.external_source_plan
    assert plan is not None
    assert plan.status == "unavailable"
    assert "combine" in (plan.reason or "")


def test_analyze_project_rejects_unknown_license(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _write_project(tmp_path)
    installed_root = tmp_path / "fake-site-packages"
    distribution = _write_distribution(
        installed_root,
        metadata_text="\n".join(
            (
                "Metadata-Version: 2.4",
                f"Name: {DIST_NAME}",
                f"Version: {VERSION}",
                "License-Expression: UNKNOWN",
                "",
            )
        ),
    )
    _install_distribution(monkeypatch, distribution)
    analysis = _analyze(project)
    plan = analysis.external_source_plan
    assert plan is not None
    assert plan.status == "unavailable"
    assert "unknown" in (plan.reason or "").lower()


def test_analyze_project_rejects_invalid_utf8_license_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _write_project(tmp_path)
    installed_root = tmp_path / "fake-site-packages"
    distribution = _write_distribution_with_license_file(
        installed_root,
        license_body=b"\xff\xfe not utf-8",
    )
    _install_distribution(monkeypatch, distribution)
    analysis = _analyze(project)
    plan = analysis.external_source_plan
    assert plan is not None
    assert plan.status == "unavailable"
    assert "UTF-8" in (plan.reason or "")


def test_json_only_lock_roundtrip_from_check_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Author a lock using only serialized plan fields (no internal helpers)."""
    project = _write_project(tmp_path)
    installed_root = tmp_path / "fake-site-packages"
    distribution = _write_distribution(installed_root)
    _install_distribution(monkeypatch, distribution)

    assert main(["check", str(project)]) == 0
    check_payload = json.loads(
        (project / ".rextio" / "reports" / "check.json").read_text(encoding="utf-8")
    )
    plan_json = check_payload["external_source_plan"]
    # Build lock exclusively from JSON authority surfaces.
    source_entries = [
        {
            "module_name": item["module_name"],
            "path": item["path"],
            "sha256": item["sha256"],
            "size": item["size"],
            "role": item["role"],
        }
        for item in plan_json["source_files"]
    ]
    metadata_entries = [
        {
            "path": item["path"],
            "sha256": item["sha256"],
            "size": item["size"],
            "role": item["role"],
        }
        for item in plan_json["metadata_files"]
    ]
    all_files = [
        {
            "path": item["path"],
            "sha256": item["sha256"],
            "size": item["size"],
            "role": item["role"],
        }
        for item in (*plan_json["source_files"], *plan_json["metadata_files"])
    ]
    attestor = "JSON Roundtrip Org"
    lock = {
        "schema_version": "1",
        "kind": "rextio.external-source-authorization",
        "package": plan_json["package"],
        "distribution": plan_json["distribution"],
        "version": plan_json["requested_version"],
        "content_hashes": {
            "source_files": source_entries,
            "metadata_files": metadata_entries,
            "snapshot_sha256": plan_json["plan_snapshot_sha256"],
        },
        "source_inventory": {
            "format": "rextio-source-inventory-v1",
            "components": [
                {
                    "type": "pypi-distribution",
                    "name": plan_json["distribution"],
                    "version": plan_json["requested_version"],
                    "license_observed": plan_json["license_observed"],
                    "files": all_files,
                }
            ],
        },
        "provenance": {
            "subject_snapshot_sha256": plan_json["plan_snapshot_sha256"],
            "producer": attestor,
            "attestor_relationship": "organization-owner",
            "installed_wheel": {
                "distribution": plan_json["distribution"],
                "version": plan_json["requested_version"],
                "metadata_files": metadata_entries,
            },
            "evidence": [
                "installed-distribution-record",
                "project-vcs-review",
            ],
        },
        "license_attestation": {
            "attestor": attestor,
            "attestor_kind": "organization",
            "reviewed_license": plan_json["license_observed"],
            "reviewed_license_material_sha256": plan_json["license_material_sha256"],
            "decision": "allow",
            "action_scopes": [
                "analysis",
                "translation",
                "local-build",
                "package",
                "redistribution",
            ],
            "acknowledgement": LICENSE_ACKNOWLEDGEMENT_V1,
        },
    }
    (project / SOURCE_LOCK_FILENAME).write_text(
        json.dumps(lock, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    # Re-analyze and verify without using plan_snapshot_sha256 helper APIs.
    analysis = _analyze(project)
    assert analysis.external_source_plan is not None
    auth = analysis.external_source_plan.authorization
    assert auth is not None
    assert auth.status == "verified"


def test_source_inventory_role_tampering_is_stale(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _write_project(tmp_path)
    installed_root = tmp_path / "fake-site-packages"
    distribution = _write_distribution(installed_root)
    _install_distribution(monkeypatch, distribution)
    plan = _analyze(project).external_source_plan
    assert plan is not None
    _write_valid_source_lock(project, plan)
    lock_path = project / SOURCE_LOCK_FILENAME
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    # Keep path/hash/size but flip the role on a metadata entry.
    for entry in lock["source_inventory"]["components"][0]["files"]:
        if entry["role"] == "wheel":
            entry["role"] = "source-module"
            break
    lock_path.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    auth = verify_external_source_authorization(project, plan)
    assert auth.status == "stale"


def test_cli_build_stale_lock_after_hash_drift_is_c6_blocked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _write_project(tmp_path)
    installed_root = tmp_path / "fake-site-packages"
    distribution = _write_distribution(installed_root)
    _install_distribution(monkeypatch, distribution)
    plan = _analyze(project).external_source_plan
    assert plan is not None
    _write_valid_source_lock(project, plan)
    # Mutate installed source after the lock was written so the plan hash drifts.
    (installed_root / PACKAGE / "__init__.py").write_text(
        SOURCE.replace("x * scale", "x + scale"),
        encoding="utf-8",
    )
    # Rebuild RECORD hashes so C5 inventory succeeds with new content; the lock
    # remains bound to the previous snapshot and must be stale.
    dist_info = installed_root / f"{PACKAGE}-{VERSION}.dist-info"
    (dist_info / "RECORD").write_text(
        "\n".join(
            (
                _record_row(installed_root, f"{PACKAGE}/__init__.py"),
                _record_row(installed_root, f"{dist_info.name}/METADATA"),
                _record_row(installed_root, f"{dist_info.name}/WHEEL"),
                f"{dist_info.name}/RECORD,,",
                "",
            )
        ),
        encoding="utf-8",
    )

    def unexpected_work(*_args: object, **_kwargs: object) -> None:
        pytest.fail("stale authorization must block before toolchain work")

    monkeypatch.setattr(build_cmd, "_prepare_build_toolchain", unexpected_work)
    monkeypatch.setattr(build_cmd, "build_hybrid_artifact", unexpected_work)

    assert main(["build", str(project), "--fallback=cpython"]) == 1
    report = json.loads(
        (project / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )
    assert report["status"] == "external-source-c6-blocked"
    assert report["external_source_plan"]["authorization"]["status"] == "stale"


def test_cli_build_unavailable_plan_still_precedes_toolchain_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = _write_project(tmp_path)
    distribution = _write_distribution(
        tmp_path / "fake-site-packages",
        version="1.0.1",
    )
    _install_distribution(monkeypatch, distribution)

    def unexpected_work(*_args: object, **_kwargs: object) -> None:
        pytest.fail("an unavailable plan must block before toolchain or artifact work")

    monkeypatch.setattr(build_cmd, "_prepare_build_toolchain", unexpected_work)
    monkeypatch.setattr(build_cmd, "build_hybrid_artifact", unexpected_work)

    assert main(["build", str(project), "--fallback=cpython"]) == 1
    captured = capsys.readouterr()
    report = json.loads(
        (project / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )
    assert report["status"] == "external-source-c6-blocked"
    assert report["external_source_plan"]["status"] == "unavailable"
    assert "GNU/copyleft" in captured.err


def test_cli_external_plan_precedes_unrelated_parse_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = _write_project(tmp_path)
    (project / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    distribution = _write_distribution(tmp_path / "fake-site-packages")
    _install_distribution(monkeypatch, distribution)

    def unexpected_work(*_args: object, **_kwargs: object) -> None:
        pytest.fail("the C6 plan gate must precede toolchain and artifact work")

    monkeypatch.setattr(build_cmd, "_prepare_build_toolchain", unexpected_work)
    monkeypatch.setattr(build_cmd, "build_hybrid_artifact", unexpected_work)

    assert main(["build", str(project), "--fallback=cpython"]) == 1
    captured = capsys.readouterr()
    report = json.loads(
        (project / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )
    assert report["status"] == "external-source-c6-blocked"
    assert any(
        diagnostic["code"] == "RXT000"
        for diagnostic in report["analysis"]["diagnostics"]
    )
    assert "GNU/copyleft" in captured.err


@pytest.mark.parametrize(
    ("distribution_options", "reason"),
    (
        (
            {
                "wheel": (
                    "Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: py3-none-any\n"
                )
            },
            "not recorded as a py3-none-any pure-Python wheel",
        ),
        (
            {"wheel": "Root-Is-Purelib: true\nTag: py3-none-any\n"},
            "not recorded as a py3-none-any pure-Python wheel",
        ),
        (
            {
                "wheel": (
                    "Wheel-Version: 1.0\n"
                    "Wheel-Version: 1.0\n"
                    "Root-Is-Purelib: true\n"
                    "Tag: py3-none-any\n"
                )
            },
            "not recorded as a py3-none-any pure-Python wheel",
        ),
        (
            {
                "wheel": (
                    "Wheel-Version: 1.0\n\n"
                    "Root-Is-Purelib: true\nTag: py3-none-any\n"
                )
            },
            "not recorded as a py3-none-any pure-Python wheel",
        ),
        (
            {
                "wheel": (
                    "Wheel-Version: 1.0\n"
                    "Root-Is-Purelib: false\n"
                    "Root-Is-Purelib: true\n"
                    "Tag: cp313-cp313-macosx_14_0_arm64\n"
                    "Tag: py3-none-any\n"
                )
            },
            "not recorded as a py3-none-any pure-Python wheel",
        ),
        ({"include_record": False}, "RECORD is missing"),
        (
            {"name": "totally-other"},
            "name does not match the exact configured distribution",
        ),
        (
            {"source": "import os\n\ndef affine(x: int) -> int:\n    return x + 1\n"},
            "contains an unresolved import",
        ),
        ({"version": "1.0.1"}, "version is not installed"),
    ),
)
def test_analyze_project_fails_closed_for_untrusted_distribution_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    distribution_options: dict[str, Any],
    reason: str,
) -> None:
    project = _write_project(tmp_path)
    distribution = _write_distribution(
        tmp_path / "fake-site-packages",
        **distribution_options,
    )
    _install_distribution(monkeypatch, distribution)

    analysis = _analyze(project)

    assert analysis.external_source_plan is not None
    assert analysis.external_source_plan.status == "unavailable"
    assert reason in (analysis.external_source_plan.reason or "")
    assert str(tmp_path / "fake-site-packages") not in json.dumps(analysis.to_dict())


def test_analyze_project_detects_record_sha256_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _write_project(tmp_path)
    installed_root = tmp_path / "fake-site-packages"
    distribution = _write_distribution(installed_root)
    (installed_root / PACKAGE / "__init__.py").write_text(
        SOURCE.replace("x * scale", "x + scale"),
        encoding="utf-8",
    )
    _install_distribution(monkeypatch, distribution)

    analysis = _analyze(project)

    assert analysis.external_source_plan is not None
    assert analysis.external_source_plan.status == "unavailable"
    assert analysis.external_source_plan.reason == (
        "distribution RECORD SHA-256 drift detected for source"
    )


def test_analyze_project_detects_record_size_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _write_project(tmp_path)
    installed_root = tmp_path / "fake-site-packages"
    distribution = _write_distribution(installed_root)
    record = installed_root / f"{PACKAGE}-{VERSION}.dist-info" / "RECORD"
    lines = record.read_text(encoding="utf-8").splitlines()
    path, digest, size = lines[0].split(",")
    lines[0] = f"{path},{digest},{int(size) + 1}"
    record.write_text("\n".join(lines) + "\n", encoding="utf-8")
    _install_distribution(monkeypatch, distribution)

    analysis = _analyze(project)

    assert analysis.external_source_plan is not None
    assert analysis.external_source_plan.status == "unavailable"
    assert analysis.external_source_plan.reason == (
        "distribution RECORD size drift detected for source"
    )


@pytest.mark.parametrize(("filename", "label"), (("METADATA", "METADATA"), ("WHEEL", "WHEEL")))
def test_analyze_project_detects_dist_info_hash_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    filename: str,
    label: str,
) -> None:
    project = _write_project(tmp_path)
    installed_root = tmp_path / "fake-site-packages"
    distribution = _write_distribution(installed_root)
    target = installed_root / f"{PACKAGE}-{VERSION}.dist-info" / filename
    with target.open("a", encoding="utf-8") as stream:
        stream.write("X-Rewritten: true\n")
    _install_distribution(monkeypatch, distribution)

    analysis = _analyze(project)

    assert analysis.external_source_plan is not None
    assert analysis.external_source_plan.status == "unavailable"
    assert analysis.external_source_plan.reason == (
        f"distribution RECORD SHA-256 drift detected for {label}"
    )


def test_analyze_project_rejects_duplicate_record_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _write_project(tmp_path)
    installed_root = tmp_path / "fake-site-packages"
    distribution = _write_distribution(installed_root)
    record = installed_root / f"{PACKAGE}-{VERSION}.dist-info" / "RECORD"
    first_row = record.read_text(encoding="utf-8").splitlines()[0]
    with record.open("a", encoding="utf-8") as stream:
        stream.write(first_row + "\n")
    _install_distribution(monkeypatch, distribution)

    analysis = _analyze(project)

    assert analysis.external_source_plan is not None
    assert analysis.external_source_plan.status == "unavailable"
    assert analysis.external_source_plan.reason == (
        "distribution RECORD contains a duplicate path"
    )


@pytest.mark.parametrize(
    "metadata_text",
    (
        f"Name: {DIST_NAME}\nVersion: {VERSION}\n",
        (
            f"Metadata-Version: 2.4\nName: {DIST_NAME}\n"
            f"Name: other\nVersion: {VERSION}\n"
        ),
        (
            f"Metadata-Version: 2.4\nName: {DIST_NAME}\n"
            f"Version: {VERSION}\nVersion: 2.0.0\n"
        ),
        (
            f"Metadata-Version: 2.4\nName: {DIST_NAME}\nVersion: {VERSION}\n"
            "malformed header\n"
        ),
    ),
)
def test_analyze_project_rejects_ambiguous_distribution_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    metadata_text: str,
) -> None:
    project = _write_project(tmp_path)
    distribution = _write_distribution(
        tmp_path / "fake-site-packages",
        metadata_text=metadata_text,
    )
    _install_distribution(monkeypatch, distribution)

    analysis = _analyze(project)

    assert analysis.external_source_plan is not None
    assert analysis.external_source_plan.status == "unavailable"
    assert "METADATA" in (analysis.external_source_plan.reason or "")


def test_analyze_project_rejects_unsafe_record_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _write_project(tmp_path)
    installed_root = tmp_path / "fake-site-packages"
    distribution = _write_distribution(installed_root)
    record = installed_root / f"{PACKAGE}-{VERSION}.dist-info" / "RECORD"
    with record.open("a", encoding="utf-8") as stream:
        stream.write("../outside.py,,\n")
    _install_distribution(monkeypatch, distribution)

    analysis = _analyze(project)

    assert analysis.external_source_plan is not None
    assert analysis.external_source_plan.status == "unavailable"
    assert analysis.external_source_plan.reason == (
        "distribution RECORD contains an unsafe path"
    )


def test_analyze_project_rejects_symlinked_package_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _write_project(tmp_path)
    installed_root = tmp_path / "fake-site-packages"
    distribution = _write_distribution(installed_root)
    package = installed_root / PACKAGE
    real_package = installed_root / "contained-real-package"
    package.rename(real_package)
    package.symlink_to(real_package, target_is_directory=True)
    _install_distribution(monkeypatch, distribution)

    analysis = _analyze(project)

    assert analysis.external_source_plan is not None
    assert analysis.external_source_plan.status == "unavailable"
    assert analysis.external_source_plan.reason == (
        "distribution source is a symlink or non-regular file"
    )


def test_analyze_project_rejects_shadow_dist_info_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _write_project(tmp_path)
    installed_root = tmp_path / "fake-site-packages"
    distribution = _write_distribution(installed_root)
    actual_dist_info = installed_root / f"{PACKAGE}-{VERSION}.dist-info"
    shadow_dist_info = installed_root / "shadow-1.0.0.dist-info"
    shadow_dist_info.mkdir()
    for name in ("METADATA", "WHEEL"):
        (shadow_dist_info / name).write_bytes((actual_dist_info / name).read_bytes())
    (shadow_dist_info / "RECORD").write_text("shadow-1.0.0.dist-info/RECORD,,\n")
    (actual_dist_info / "RECORD").write_text(
        "\n".join(
            (
                _record_row(installed_root, f"{PACKAGE}/__init__.py"),
                _record_row(installed_root, "shadow-1.0.0.dist-info/METADATA"),
                _record_row(installed_root, "shadow-1.0.0.dist-info/WHEEL"),
                "shadow-1.0.0.dist-info/RECORD,,",
                "",
            )
        ),
        encoding="utf-8",
    )
    _install_distribution(monkeypatch, distribution)

    analysis = _analyze(project)

    assert analysis.external_source_plan is not None
    assert analysis.external_source_plan.status == "unavailable"
    assert analysis.external_source_plan.reason == (
        "distribution RECORD contains a foreign dist-info root"
    )


@pytest.mark.parametrize(
    ("link_outside_root", "reason"),
    (
        (False, "distribution source is a symlink or non-regular file"),
        (True, "distribution source escapes its installed root"),
    ),
)
def test_analyze_project_fails_closed_for_distribution_source_links(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    link_outside_root: bool,
    reason: str,
) -> None:
    project = _write_project(tmp_path)
    installed_root = tmp_path / "fake-site-packages"
    distribution = _write_distribution(installed_root)
    source_path = installed_root / PACKAGE / "__init__.py"
    source_path.unlink()
    target = (
        tmp_path / "outside.py"
        if link_outside_root
        else installed_root / "contained-but-linked.py"
    )
    target.write_text(SOURCE, encoding="utf-8")
    source_path.symlink_to(target)
    _install_distribution(monkeypatch, distribution)

    analysis = _analyze(project)

    assert analysis.external_source_plan is not None
    assert analysis.external_source_plan.status == "unavailable"
    assert analysis.external_source_plan.reason == reason
    assert str(installed_root) not in json.dumps(analysis.to_dict())
