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
from rextio.source.external import (
    ExternalSourceBuildBlockedError,
    resolve_external_source_plan,
)


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
    assert plan.installed_version == "1.0.1"
    assert "does not match" in (plan.reason or "")


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
    assert "metadata snapshots could not be read" in (plan.reason or "")
    assert "/private" not in payload


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

    with pytest.raises(ExternalSourceBuildBlockedError, match="C6 SourceLock"):
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

    with pytest.raises(ExternalSourceBuildBlockedError, match="C6 SourceLock"):
        build_hybrid_artifact(
            tmp_path,
            ProjectAnalysis(project_root=tmp_path),
            "cpython",
            executable_analysis=executable_analysis,
        )

    assert not (tmp_path / ".rextio").exists()
