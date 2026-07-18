from __future__ import annotations

import base64
import hashlib
import importlib.metadata as metadata
import json
from pathlib import Path
from typing import cast

import pytest

from rextio.analyzer.models import ImportPolicyDecision, ModuleAnalysis, ProjectAnalysis
from rextio.build.orchestrator import build_hybrid_artifact
from rextio.config.schema import ImportPackagePolicy, ImportsConfig
from rextio.source.authorization import (
    LICENSE_ACKNOWLEDGEMENT_V1,
    SOURCE_LOCK_FILENAME,
    license_material_digest,
    plan_snapshot_sha256,
    verify_external_source_authorization,
)
from rextio.source.external import (
    MAX_DISTRIBUTION_LEN,
    MAX_PACKAGE_LEN,
    MAX_VERSION_LEN,
    ExternalSourceBuildBlockedError,
    ExternalSourceC5NotImplementedError,
    _valid_preview_identity,
    resolve_external_source_plan,
)
import rextio.source.external as external_source
from dataclasses import replace


def _record_row(root: Path, relative: str) -> str:
    data = (root / relative).read_bytes()
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode("ascii")
    return f"{relative},sha256={digest.rstrip('=')},{len(data)}"


def _fixture_distribution(
    tmp_path: Path,
    *,
    name: str = "rextio-c5-poc-math",
    version: str = "1.0.0",
) -> metadata.Distribution:
    package = tmp_path / "rextio_c5_poc_math"
    package.mkdir()
    (package / "__init__.py").write_text(
        """
raise RuntimeError("resolver imported fixture code")

def affine(x: int, scale: int, bias: int) -> int:
    return x * scale + bias

def unused(x: int) -> int:
    return x + 99
""".lstrip(),
        encoding="utf-8",
    )
    dist_info = tmp_path / f"rextio_c5_poc_math-{version}.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "\n".join(
            [
                "Metadata-Version: 2.4",
                f"Name: {name}",
                f"Version: {version}",
                "License-Expression: MIT",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (dist_info / "WHEEL").write_text(
        "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        encoding="utf-8",
    )
    source_relative = "rextio_c5_poc_math/__init__.py"
    metadata_relative = f"{dist_info.name}/METADATA"
    wheel_relative = f"{dist_info.name}/WHEEL"
    (dist_info / "RECORD").write_text(
        "\n".join(
            (
                _record_row(tmp_path, source_relative),
                _record_row(tmp_path, metadata_relative),
                _record_row(tmp_path, wheel_relative),
                f"{dist_info.name}/RECORD,,",
                "",
            )
        ),
        encoding="utf-8",
    )
    return metadata.Distribution.at(dist_info)


def _config(
    *,
    distribution: str = "rextio-c5-poc-math",
    version: str = "1.0.0",
) -> ImportsConfig:
    return ImportsConfig(
        packages={
            "rextio_c5_poc_math": ImportPackagePolicy(
                policy="try-native",
                max_depth=1,
                distribution=distribution,
                version=version,
            )
        }
    )


def _analysis(tmp_path: Path, *, origin: str = "external") -> ProjectAnalysis:
    decision = ImportPolicyDecision(
        visible_name="poc",
        target="rextio_c5_poc_math",
        package="rextio_c5_poc_math",
        origin=origin,
        policy="try-native",
        max_depth=1,
        distribution="rextio-c5-poc-math",
        version="1.0.0",
    )
    module = ModuleAnalysis(
        module_name="app",
        file_path="app.py",
        imports={"poc": "rextio_c5_poc_math"},
        import_policies=(decision,),
    )
    return ProjectAnalysis(project_root=tmp_path, modules=[module])


def test_external_source_preview_is_sanitized_deterministic_and_non_executing(
    tmp_path: Path,
) -> None:
    distribution = _fixture_distribution(tmp_path)
    analysis = _analysis(tmp_path)

    plan = resolve_external_source_plan(
        _config(), analysis, distribution_getter=lambda _name: distribution
    )

    assert plan is not None
    assert plan.status == "preview-ready"
    assert plan.license == "MIT"
    assert plan.candidate_functions == (
        "rextio_c5_poc_math.affine",
        "rextio_c5_poc_math.unused",
    )
    payload = plan.to_dict()
    assert payload["execution_authority"] == "preview-only"
    assert payload["distributable"] is False
    assert payload["c6_gate"] == "required"
    assert str(tmp_path) not in json.dumps(payload)
    assert payload["modules"][0]["source_origin"] == "distribution"
    assert len(payload["modules"][0]["sha256"]) == 64


def test_external_source_preview_reports_exact_version_drift(tmp_path: Path) -> None:
    distribution = _fixture_distribution(tmp_path, version="1.0.1")

    plan = resolve_external_source_plan(
        _config(), _analysis(tmp_path), distribution_getter=lambda _name: distribution
    )

    assert plan is not None
    assert plan.status == "unavailable"
    # Expected dist-info for the configured version is absent under the install root.
    assert "version is not installed" in (plan.reason or "")


@pytest.mark.parametrize(
    ("distribution_name", "version"),
    (
        ("REXTIO-C5-POC-MATH", "1.0.0"),
        ("rextio-c5-poc-math", "1.0+cpu"),
    ),
)
def test_external_source_preview_accepts_wheel_normalized_dist_info_names(
    tmp_path: Path,
    distribution_name: str,
    version: str,
) -> None:
    distribution = _fixture_distribution(
        tmp_path,
        name=distribution_name,
        version=version,
    )

    plan = resolve_external_source_plan(
        _config(distribution=distribution_name, version=version),
        _analysis(tmp_path),
        distribution_getter=lambda _name: distribution,
    )

    assert plan is not None
    assert plan.status == "preview-ready"


def test_external_source_preview_is_unused_when_package_is_not_imported(tmp_path: Path) -> None:
    analysis = ProjectAnalysis(project_root=tmp_path)

    assert resolve_external_source_plan(_config(), analysis) is None


def test_external_source_preview_blocks_an_active_plugin_conflict(tmp_path: Path) -> None:
    plan = resolve_external_source_plan(
        _config(),
        _analysis(tmp_path, origin="external-plugin"),
        distribution_getter=lambda _name: pytest.fail(
            "plugin conflict must block before installed metadata resolution"
        ),
    )

    assert plan is not None
    assert plan.status == "unavailable"
    assert plan.reason == "source-native preview conflicts with an active plugin route"


def test_external_source_metadata_exceptions_do_not_leak_provider_paths(tmp_path: Path) -> None:
    class LeakingDistribution:
        def locate_file(self, _path: str) -> str:
            raise RuntimeError("/private/site-packages/secret")

        def read_text(self, _filename: str) -> str | None:
            raise RuntimeError("/private/site-packages/secret")

    plan = resolve_external_source_plan(
        _config(),
        _analysis(tmp_path),
        distribution_getter=lambda _name: cast(
            metadata.Distribution,
            LeakingDistribution(),
        ),
    )

    assert plan is not None
    payload = json.dumps(plan.to_dict())
    assert plan.status == "unavailable"
    assert "installed root could not be resolved" in (plan.reason or "")
    assert "/private" not in payload
    assert "secret" not in payload


def test_preview_identity_exact_limit_and_one_over() -> None:
    package_ok = "a" * MAX_PACKAGE_LEN
    package_over = "a" * (MAX_PACKAGE_LEN + 1)
    dist_ok = "d" * MAX_DISTRIBUTION_LEN
    dist_over = "d" * (MAX_DISTRIBUTION_LEN + 1)
    version_ok = "1" + "0" * (MAX_VERSION_LEN - 1)
    version_over = "1" + "0" * MAX_VERSION_LEN
    assert _valid_preview_identity("pkg", "dist-name", "1.0.0")
    assert _valid_preview_identity(package_ok, "dist-name", "1.0.0")
    assert not _valid_preview_identity(package_over, "dist-name", "1.0.0")
    assert _valid_preview_identity("pkg", dist_ok, "1.0.0")
    assert not _valid_preview_identity("pkg", dist_over, "1.0.0")
    assert _valid_preview_identity("pkg", "dist-name", version_ok)
    assert not _valid_preview_identity("pkg", "dist-name", version_over)


def test_oversized_metadata_rejected_before_unbounded_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    distribution = _fixture_distribution(tmp_path)
    # Cap far below fixture METADATA size so the bounded reader must fail closed
    # without loading a multi-megabyte buffer.
    monkeypatch.setattr(external_source, "MAX_FILE_BYTES", 8)
    reads: list[int] = []
    original = external_source._read_bounded_file

    def tracking_read(path, *, label: str):  # type: ignore[no-untyped-def]
        data = original(path, label=label)
        reads.append(len(data))
        return data

    monkeypatch.setattr(external_source, "_read_bounded_file", tracking_read)
    plan = resolve_external_source_plan(
        _config(),
        _analysis(tmp_path),
        distribution_getter=lambda _name: distribution,
    )
    assert plan is not None
    assert plan.status == "unavailable"
    assert "maximum verified file size" in (plan.reason or "")
    # No successful full-file parse path after oversize rejection.
    assert not reads or max(reads) <= 8


def test_source_module_cap_rejects_before_extra_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = tmp_path / "rextio_c5_poc_math"
    package.mkdir()
    (package / "__init__.py").write_text(
        "def affine(x: int) -> int:\n    return x\n",
        encoding="utf-8",
    )
    (package / "extra.py").write_text(
        "def other(x: int) -> int:\n    return x\n",
        encoding="utf-8",
    )
    dist_info = tmp_path / "rextio_c5_poc_math-1.0.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.4\nName: rextio-c5-poc-math\nVersion: 1.0.0\n"
        "License-Expression: MIT\n",
        encoding="utf-8",
    )
    (dist_info / "WHEEL").write_text(
        "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        encoding="utf-8",
    )
    rows = [
        _record_row(tmp_path, "rextio_c5_poc_math/__init__.py"),
        _record_row(tmp_path, "rextio_c5_poc_math/extra.py"),
        _record_row(tmp_path, f"{dist_info.name}/METADATA"),
        _record_row(tmp_path, f"{dist_info.name}/WHEEL"),
        f"{dist_info.name}/RECORD,,",
        "",
    ]
    (dist_info / "RECORD").write_text("\n".join(rows), encoding="utf-8")
    distribution = metadata.Distribution.at(dist_info)
    monkeypatch.setattr(external_source, "MAX_SOURCE_MODULES", 1)
    read_labels: list[str] = []
    original = external_source._recorded_bytes

    def tracking_recorded(*args, label: str = "source", **kwargs):  # type: ignore[no-untyped-def]
        read_labels.append(label)
        return original(*args, label=label, **kwargs)

    monkeypatch.setattr(external_source, "_recorded_bytes", tracking_recorded)
    plan = resolve_external_source_plan(
        _config(),
        _analysis(tmp_path),
        distribution_getter=lambda _name: distribution,
    )
    assert plan is not None
    assert plan.status == "unavailable"
    assert "maximum module count" in (plan.reason or "")
    # Only one source body should be read before the cap rejects the second.
    assert read_labels.count("source") == 1


def test_noassertion_license_is_unavailable(tmp_path: Path) -> None:
    distribution = _fixture_distribution(tmp_path)
    # Rewrite METADATA to NOASSERTION while keeping RECORD hashes valid.
    dist_info = tmp_path / "rextio_c5_poc_math-1.0.0.dist-info"
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.4\nName: rextio-c5-poc-math\nVersion: 1.0.0\n"
        "License-Expression: NOASSERTION\n",
        encoding="utf-8",
    )
    (dist_info / "RECORD").write_text(
        "\n".join(
            (
                _record_row(tmp_path, "rextio_c5_poc_math/__init__.py"),
                _record_row(tmp_path, f"{dist_info.name}/METADATA"),
                _record_row(tmp_path, f"{dist_info.name}/WHEEL"),
                f"{dist_info.name}/RECORD,,",
                "",
            )
        ),
        encoding="utf-8",
    )
    distribution = metadata.Distribution.at(dist_info)
    plan = resolve_external_source_plan(
        _config(),
        _analysis(tmp_path),
        distribution_getter=lambda _name: distribution,
    )
    assert plan is not None
    assert plan.status == "unavailable"
    assert "unknown" in (plan.reason or "").lower()


def test_metadata_body_invalid_utf8_makes_plan_unavailable(tmp_path: Path) -> None:
    """Valid headers plus non-UTF-8 body bytes must not parse as preview-ready."""
    package = tmp_path / "rextio_c5_poc_math"
    package.mkdir()
    (package / "__init__.py").write_text(
        "def affine(x: int) -> int:\n    return x\n",
        encoding="utf-8",
    )
    dist_info = tmp_path / "rextio_c5_poc_math-1.0.0.dist-info"
    dist_info.mkdir()
    # Headers are valid ASCII/UTF-8; body ends with 0xff (invalid UTF-8).
    metadata_payload = (
        b"Metadata-Version: 2.4\n"
        b"Name: rextio-c5-poc-math\n"
        b"Version: 1.0.0\n"
        b"License-Expression: MIT\n"
        b"\n"
        b"Description-body\xff"
    )
    (dist_info / "METADATA").write_bytes(metadata_payload)
    (dist_info / "WHEEL").write_text(
        "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        encoding="utf-8",
    )
    (dist_info / "RECORD").write_text(
        "\n".join(
            (
                _record_row(tmp_path, "rextio_c5_poc_math/__init__.py"),
                _record_row(tmp_path, f"{dist_info.name}/METADATA"),
                _record_row(tmp_path, f"{dist_info.name}/WHEEL"),
                f"{dist_info.name}/RECORD,,",
                "",
            )
        ),
        encoding="utf-8",
    )
    distribution = metadata.Distribution.at(dist_info)
    plan = resolve_external_source_plan(
        _config(),
        _analysis(tmp_path),
        distribution_getter=lambda _name: distribution,
    )
    assert plan is not None
    assert plan.status == "unavailable"
    assert "UTF-8" in (plan.reason or "")


def test_unlicense_can_be_preview_ready(tmp_path: Path) -> None:
    dist_info = tmp_path / "rextio_c5_poc_math-1.0.0.dist-info"
    package = tmp_path / "rextio_c5_poc_math"
    package.mkdir()
    (package / "__init__.py").write_text(
        "def affine(x: int) -> int:\n    return x\n",
        encoding="utf-8",
    )
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.4\nName: rextio-c5-poc-math\nVersion: 1.0.0\n"
        "License-Expression: Unlicense\n",
        encoding="utf-8",
    )
    (dist_info / "WHEEL").write_text(
        "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        encoding="utf-8",
    )
    (dist_info / "RECORD").write_text(
        "\n".join(
            (
                _record_row(tmp_path, "rextio_c5_poc_math/__init__.py"),
                _record_row(tmp_path, f"{dist_info.name}/METADATA"),
                _record_row(tmp_path, f"{dist_info.name}/WHEEL"),
                f"{dist_info.name}/RECORD,,",
                "",
            )
        ),
        encoding="utf-8",
    )
    distribution = metadata.Distribution.at(dist_info)
    plan = resolve_external_source_plan(
        _config(),
        _analysis(tmp_path),
        distribution_getter=lambda _name: distribution,
    )
    assert plan is not None
    assert plan.status == "preview-ready"
    assert plan.license == "Unlicense"


def test_c5_external_source_plan_blocks_every_build_before_artifact_work(
    tmp_path: Path,
) -> None:
    distribution = _fixture_distribution(tmp_path)
    analysis = _analysis(tmp_path)
    plan = resolve_external_source_plan(
        _config(), analysis, distribution_getter=lambda _name: distribution
    )
    assert plan is not None
    analysis.external_source_plan = plan

    with pytest.raises(ExternalSourceBuildBlockedError, match="SourceLock"):
        build_hybrid_artifact(tmp_path, analysis, "cpython")

    assert not (tmp_path / ".rextio").exists()


def test_c5_executable_analysis_plan_also_blocks_programmatic_build(
    tmp_path: Path,
) -> None:
    distribution = _fixture_distribution(tmp_path)
    executable_analysis = _analysis(tmp_path)
    plan = resolve_external_source_plan(
        _config(),
        executable_analysis,
        distribution_getter=lambda _name: distribution,
    )
    assert plan is not None
    executable_analysis.external_source_plan = plan

    with pytest.raises(ExternalSourceBuildBlockedError, match="SourceLock"):
        build_hybrid_artifact(
            tmp_path,
            ProjectAnalysis(project_root=tmp_path),
            "cpython",
            executable_analysis=executable_analysis,
        )

    assert not (tmp_path / ".rextio").exists()


def _write_lock_for_plan(tmp_path: Path, plan: object) -> None:
    from rextio.source.external import ExternalSourcePlan as Plan

    assert isinstance(plan, Plan)
    snapshot = plan_snapshot_sha256(plan)
    assert snapshot is not None
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
    attestor = "Unit Test Org"
    lock = {
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
    (tmp_path / SOURCE_LOCK_FILENAME).write_text(
        json.dumps(lock, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def test_verified_authorization_raises_distinct_c5_not_implemented(
    tmp_path: Path,
) -> None:
    distribution = _fixture_distribution(tmp_path)
    analysis = _analysis(tmp_path)
    plan = resolve_external_source_plan(
        _config(), analysis, distribution_getter=lambda _name: distribution
    )
    assert plan is not None
    _write_lock_for_plan(tmp_path, plan)
    auth = verify_external_source_authorization(tmp_path, plan)
    assert auth.verified
    analysis.external_source_plan = replace(plan, authorization=auth)

    with pytest.raises(ExternalSourceC5NotImplementedError, match="not implemented"):
        build_hybrid_artifact(tmp_path, analysis, "cpython")

    assert not (tmp_path / ".rextio" / "generated").exists()


def test_executable_analysis_verified_auth_still_blocks_before_artifacts(
    tmp_path: Path,
) -> None:
    distribution = _fixture_distribution(tmp_path)
    executable_analysis = _analysis(tmp_path)
    plan = resolve_external_source_plan(
        _config(),
        executable_analysis,
        distribution_getter=lambda _name: distribution,
    )
    assert plan is not None
    _write_lock_for_plan(tmp_path, plan)
    auth = verify_external_source_authorization(tmp_path, plan)
    executable_analysis.external_source_plan = replace(plan, authorization=auth)

    with pytest.raises(ExternalSourceC5NotImplementedError, match="not implemented"):
        build_hybrid_artifact(
            tmp_path,
            ProjectAnalysis(project_root=tmp_path),
            "cpython",
            executable_analysis=executable_analysis,
        )
    assert not (tmp_path / ".rextio" / "generated").exists()
    assert not (tmp_path / ".rextio" / "build").exists()
