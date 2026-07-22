"""Strict Full C6 CLI lifecycle routing and report tests."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import io
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
from typing import cast

import pytest

import rextio.cli.build_cmd as build_cmd
from rextio.analyzer.diagnostics import Diagnostic
from rextio.analyzer.models import (
    FunctionAnalysis,
    ModuleAnalysis,
    ProjectAnalysis,
    TopLevelAnalysis,
)
from rextio.build.full_c6_gate import FullC6GateError
from rextio.build.full_c6_host_inputs import FullC6HostInputsError
from rextio.build.full_c6_pipeline import (
    FullC6ExternalPreflightResult,
    FullC6PipelineError,
)
from rextio.build.full_c6_publication import FullC6PublicationError
from rextio.cli.main import main
from rextio.cli.reporter import Reporter
from rextio.config.schema import BuildConfig, RextioConfig
from rextio.source.planning import HostSourcePlan


class _Receipt:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload

    def to_dict(self) -> dict[str, object]:
        return dict(self.payload)


class _Authority:
    def __init__(self, lifecycle: str, *, bootstrap_request: object | None = None) -> None:
        self.lifecycle = SimpleNamespace(status=lifecycle)
        self.bootstrap_request = bootstrap_request

    def to_dict(self) -> dict[str, object]:
        return {
            "authority": "production-evidence-only",
            "digest": "a" * 64,
            "distribution_authorized": False,
        }


def _analysis(project: Path) -> ProjectAnalysis:
    return ProjectAnalysis(project_root=project.resolve())


def _nested_analysis(project: Path) -> ProjectAnalysis:
    source = project / "pkg" / "app.py"
    source.parent.mkdir()
    source.write_text("seed = 1\n", encoding="utf-8")
    diagnostic = Diagnostic(
        code="RXT999",
        severity="warning",
        message="test diagnostic",
        file_path=os.fspath(source),
        line=1,
        column=0,
    )
    function = FunctionAnalysis(
        name="calculate",
        qualname="pkg.app.calculate",
        module_name="pkg.app",
        file_path=os.fspath(source),
        line=1,
        column=0,
        diagnostics=[diagnostic],
    )
    top_level = TopLevelAnalysis(
        name="<module>",
        qualname="pkg.app.<module>",
        module_name="pkg.app",
        file_path=os.fspath(source),
        diagnostics=[diagnostic],
    )
    analysis = ProjectAnalysis(
        project_root=project,
        modules=[
            ModuleAnalysis(
                module_name="pkg.app",
                file_path=os.fspath(source),
                functions=[function],
                diagnostics=[diagnostic],
                top_level=top_level,
            )
        ],
    )
    analysis.host_source_plan = HostSourcePlan(
        graph=None,
        module_initializers=(),
        unavailable_reason="focused report projection fixture",
    )
    return analysis


def _file_path_values(value: object) -> list[object]:
    values: list[object] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "file_path":
                values.append(item)
            values.extend(_file_path_values(item))
    elif isinstance(value, list):
        for item in value:
            values.extend(_file_path_values(item))
    return values


def _report(project: Path) -> dict[str, object]:
    return json.loads(
        (project / ".rextio" / "reports" / "build.json").read_text(
            encoding="utf-8"
        )
    )


def _reporter(*, output_format: str = "text") -> tuple[Reporter, io.StringIO, io.StringIO]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    return (
        Reporter(output_format=output_format, stdout=stdout, stderr=stderr),
        stdout,
        stderr,
    )


def _seed_stale_full_c6_reports(project: Path) -> Path:
    reports = project / ".rextio" / "reports"
    reports.mkdir(parents=True)
    for name in ("build.json", "generate.json", "check.json"):
        (reports / name).write_text(
            f"stale private material under {project}\n",
            encoding="utf-8",
        )
    return reports


def _assert_fixed_projection_failure(
    project: Path,
    reports: Path,
    *,
    stdout: io.StringIO,
    stderr: io.StringIO,
) -> None:
    assert stdout.getvalue() == ""
    message = stderr.getvalue()
    assert message == (
        "RXT060 strict Full C6 analysis report projection failed closed.\n"
        "Suggestion: keep analyzer report paths canonical and project-contained, "
        "then rerun.\n"
    )
    assert os.fspath(project) not in message
    assert "Traceback" not in message
    assert "private material" not in message
    assert not any((reports / name).exists() for name in ("build.json", "generate.json", "check.json"))


def _prerequisites(
    project: Path,
    config: RextioConfig,
    events: list[str],
    *,
    publication_adapter: object | None = None,
    prepublication_cleanup_error: Exception | None = None,
) -> SimpleNamespace:
    state = project / "state"
    state.mkdir(mode=0o700, exist_ok=True)
    cleanup_complete = False
    production_arguments_calls = 0

    def complete_prepublication_cleanup(_authority: object) -> None:
        nonlocal cleanup_complete
        events.append("prepublication-cleanup")
        if prepublication_cleanup_error is not None:
            raise prepublication_cleanup_error
        cleanup_complete = True

    def derive_plan(_authority: object) -> object:
        events.append("derive-publication-plan")

        def atomic_adapter() -> object:
            events.append("atomic-adapter")
            return publication_adapter

        return SimpleNamespace(atomic_adapter=atomic_adapter)

    def production_arguments() -> dict[str, object]:
        nonlocal production_arguments_calls
        production_arguments_calls += 1
        prerequisites.production_arguments_calls = production_arguments_calls
        return {
            "project_root": prerequisites.project_root,
            "config": prerequisites.config,
            "toolchain": prerequisites.toolchain,
            "native_tools": prerequisites.native_tools,
            "cargo_workspace": prerequisites.cargo_workspace,
            "toolchain_support_plan": prerequisites.toolchain_support_plan,
            "toolchain_support_lock": prerequisites.toolchain_support_lock,
            "first_quarantine_root": prerequisites.first_quarantine_root,
            "second_quarantine_root": prerequisites.second_quarantine_root,
            "state_directory": prerequisites.state_directory,
            "base_environment": dict(prerequisites.base_environment),
            "source_date_epoch": prerequisites.source_date_epoch,
        }

    prerequisites = SimpleNamespace(
        project_root=project,
        config=config,
        toolchain=object(),
        native_tools=object(),
        cargo_workspace=object(),
        toolchain_support_plan=object(),
        toolchain_support_lock=object(),
        first_quarantine_root=project / "quarantine-one",
        second_quarantine_root=project / "quarantine-two",
        state_directory=state,
        base_environment={"PATH": "/actual-cargo"},
        source_date_epoch=0,
        production_arguments=production_arguments,
        production_arguments_calls=0,
        complete_prepublication_cleanup=complete_prepublication_cleanup,
        derive_publication_plan=derive_plan,
    )
    prerequisites.cleanup_complete = lambda: cleanup_complete
    return prerequisites


def _install_authority_mocks(
    monkeypatch: pytest.MonkeyPatch,
    *,
    project: Path,
    config: RextioConfig,
    preflight: object,
    authority: _Authority,
    events: list[str],
    publication_adapter: object | None = None,
    cleanup_error: Exception | None = None,
    prepublication_cleanup_error: Exception | None = None,
) -> None:
    prerequisites = _prerequisites(
        project,
        config,
        events,
        publication_adapter=publication_adapter,
        prepublication_cleanup_error=prepublication_cleanup_error,
    )

    @contextmanager
    def collect_host(raw_root: str, *, config: RextioConfig) -> Iterator[object]:
        assert raw_root == os.fspath(project)
        assert config is prerequisites.config
        events.append("host-enter")
        try:
            yield prerequisites
        finally:
            events.append("host-exit")
            if cleanup_error is not None and not prerequisites.cleanup_complete():
                raise cleanup_error

    def collect_production(observed_preflight: object, **values: object) -> _Authority:
        assert observed_preflight is preflight
        assert prerequisites.production_arguments_calls == events.count("host-enter")
        assert values == {
            "base_environment": prerequisites.base_environment,
            "cargo_workspace": prerequisites.cargo_workspace,
            "config": config,
            "first_quarantine_root": prerequisites.first_quarantine_root,
            "native_tools": prerequisites.native_tools,
            "project_root": project,
            "second_quarantine_root": prerequisites.second_quarantine_root,
            "source_date_epoch": 0,
            "state_directory": prerequisites.state_directory,
            "toolchain": prerequisites.toolchain,
            "toolchain_support_lock": prerequisites.toolchain_support_lock,
            "toolchain_support_plan": prerequisites.toolchain_support_plan,
        }
        events.append("production-authority")
        return authority

    monkeypatch.setattr(build_cmd, "collect_full_c6_host_prerequisites", collect_host)
    monkeypatch.setattr(build_cmd, "collect_full_c6_production_authority", collect_production)


def _run_lifecycle(
    project: Path,
    config: RextioConfig,
    preflight: object,
    reporter: Reporter,
) -> int:
    return build_cmd._run_full_c6_cli_lifecycle(
        raw_project_root=os.fspath(project),
        project_root=project,
        analysis=_analysis(project),
        preflight=cast(FullC6ExternalPreflightResult, preflight),
        config=config,
        fallback="cpython",
        reporter=reporter,
    )


def test_bootstrap_lifecycle_preserves_context_and_writes_non_authorizing_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path.resolve()
    stale_generate = project / ".rextio" / "reports" / "generate.json"
    stale_generate.parent.mkdir(parents=True)
    stale_generate.write_text("stale", encoding="utf-8")
    config = RextioConfig()
    preflight = object()
    request = object()
    authority = _Authority("bootstrap-required", bootstrap_request=request)
    events: list[str] = []
    _install_authority_mocks(
        monkeypatch,
        project=project,
        config=config,
        preflight=preflight,
        authority=authority,
        events=events,
    )

    def materialize(*, state_directory: Path, request: object) -> _Receipt:
        assert state_directory == project / "state"
        assert request is authority.bootstrap_request
        events.append("policy-bootstrap")
        return _Receipt(
            {
                "created": True,
                "distribution_authorized": False,
                "filename": "rextio.full-c6-policy.bootstrap.json",
                "status": "bootstrap-required",
            }
        )

    monkeypatch.setattr(
        build_cmd,
        "materialize_full_c6_policy_bootstrap_request",
        materialize,
    )
    reporter, stdout, stderr = _reporter()

    assert _run_lifecycle(project, config, preflight, reporter) == 0

    report = _report(project)
    assert report["lifecycle"] == "bootstrap-required"
    assert report["status"] == "full-c6-bootstrap-required"
    assert report["distribution_authorized"] is False
    assert report["analysis"]["project_root"] == "."  # type: ignore[index]
    assert report["full_c6"]["production_authority"] == authority.to_dict()  # type: ignore[index]
    assert events == ["host-enter", "production-authority", "policy-bootstrap", "host-exit"]
    assert "next owner action" in stdout.getvalue()
    assert stderr.getvalue() == ""
    assert not stale_generate.exists()
    assert not (project / "dist").exists()
    assert os.fspath(project) not in json.dumps(report)


def test_strict_lifecycle_projects_every_nested_file_path_once_for_both_reports(
    tmp_path: Path,
) -> None:
    project = tmp_path.resolve()
    analysis = _nested_analysis(project)
    reporter, _stdout, _stderr = _reporter()

    assert (
        build_cmd._report_full_c6_pipeline_success(
            project,
            analysis,
            "cpython",
            reporter,
            lifecycle="bootstrap-required",
            status="full-c6-bootstrap-required",
            distribution_authorized=False,
            details={},
            next_action="complete the owner policy",
        )
        == 0
    )

    reports = project / ".rextio" / "reports"
    build_report = json.loads((reports / "build.json").read_text(encoding="utf-8"))
    check_report = json.loads((reports / "check.json").read_text(encoding="utf-8"))
    projected = build_report["analysis"]
    assert projected == check_report
    assert projected["project_root"] == "."
    assert set(_file_path_values(projected)) == {"pkg/app.py"}
    assert len(_file_path_values(projected)) >= 7
    assert os.fspath(project) not in json.dumps(build_report)
    assert set(_file_path_values(analysis.to_dict())) == {
        os.fspath(project / "pkg" / "app.py")
    }


def test_strict_success_projection_failure_uses_fixed_stderr_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path.resolve()
    reports = _seed_stale_full_c6_reports(project)
    analysis = _analysis(project)
    monkeypatch.setattr(
        analysis,
        "to_dict",
        lambda: {
            "project_root": os.fspath(project),
            "diagnostics": [{"message": f"private material at {project}/app.py"}],
        },
    )
    reporter, stdout, stderr = _reporter()

    assert (
        build_cmd._report_full_c6_pipeline_success(
            project,
            analysis,
            "cpython",
            reporter,
            lifecycle="bootstrap-required",
            status="full-c6-bootstrap-required",
            distribution_authorized=False,
            details={},
            next_action="must not be serialized",
        )
        == 1
    )
    _assert_fixed_projection_failure(
        project,
        reports,
        stdout=stdout,
        stderr=stderr,
    )


def test_existing_pipeline_failure_projection_failure_uses_fixed_stderr_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path.resolve()
    reports = _seed_stale_full_c6_reports(project)
    analysis = _analysis(project)
    monkeypatch.setattr(
        analysis,
        "to_dict",
        lambda: {
            "project_root": os.fspath(project),
            "nested": {"file_path": os.fspath(project.parent / "outside.py")},
        },
    )
    reporter, stdout, stderr = _reporter()

    assert (
        build_cmd._report_full_c6_pipeline_failure(
            project,
            analysis,
            "cpython",
            FullC6PipelineError(f"private cause under {project}"),
            reporter,
            stage="private-stage",
        )
        == 1
    )
    _assert_fixed_projection_failure(
        project,
        reports,
        stdout=stdout,
        stderr=stderr,
    )


@pytest.mark.parametrize(
    "file_path",
    [
        "",
        7,
        "bad\0.py",
        "../outside.py",
    ],
)
def test_strict_report_rejects_invalid_or_parent_file_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    file_path: object,
) -> None:
    project = tmp_path.resolve()
    analysis = _analysis(project)
    monkeypatch.setattr(
        analysis,
        "to_dict",
        lambda: {
            "project_root": os.fspath(project),
            "nested": {"file_path": file_path},
        },
    )

    with pytest.raises(FullC6PipelineError, match="report projection rejected"):
        build_cmd._project_full_c6_analysis_report(project, analysis)


def test_strict_report_rejects_absolute_outside_root_file_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path.resolve()
    analysis = _analysis(project)
    monkeypatch.setattr(
        analysis,
        "to_dict",
        lambda: {
            "project_root": os.fspath(project),
            "nested": {"file_path": os.fspath(project.parent / "outside.py")},
        },
    )

    with pytest.raises(FullC6PipelineError, match="outside-root file_path"):
        build_cmd._project_full_c6_analysis_report(project, analysis)


def test_strict_report_rejects_symlink_file_path_alias(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path.resolve()
    source = project / "app.py"
    source.write_text("value = 1\n", encoding="utf-8")
    alias = project / "alias.py"
    try:
        alias.symlink_to(source)
    except OSError as error:
        pytest.skip(f"symlink creation is unavailable: {error}")
    analysis = _analysis(project)
    monkeypatch.setattr(
        analysis,
        "to_dict",
        lambda: {
            "project_root": os.fspath(project),
            "nested": {"file_path": os.fspath(alias)},
        },
    )

    with pytest.raises(FullC6PipelineError, match="ambiguous file_path"):
        build_cmd._project_full_c6_analysis_report(project, analysis)


def test_strict_report_rejects_unexpected_nested_container(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path.resolve()
    analysis = _analysis(project)
    monkeypatch.setattr(
        analysis,
        "to_dict",
        lambda: {
            "project_root": os.fspath(project),
            "modules": ({"file_path": "app.py"},),
        },
    )

    with pytest.raises(FullC6PipelineError, match="unexpected value type"):
        build_cmd._project_full_c6_analysis_report(project, analysis)


def test_strict_report_rejects_project_root_text_outside_file_path_fields(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path.resolve()
    analysis = _analysis(project)
    monkeypatch.setattr(
        analysis,
        "to_dict",
        lambda: {
            "project_root": os.fspath(project),
            "diagnostics": [
                {
                    "message": f"analysis failed under {project}/pkg/app.py",
                }
            ],
        },
    )

    with pytest.raises(FullC6PipelineError, match="residual project-root text"):
        build_cmd._project_full_c6_analysis_report(project, analysis)


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS /private alias contract")
def test_strict_report_rejects_verified_macos_project_root_alias_text(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path.resolve()
    if project.parts[:2] != ("/", "private"):
        pytest.skip("temporary project does not use the canonical /private spelling")
    alias = Path("/").joinpath(*project.parts[2:])
    if alias.resolve(strict=True) != project:
        pytest.skip("the shorter macOS spelling is not an alias of this project")
    analysis = _analysis(project)
    monkeypatch.setattr(
        analysis,
        "to_dict",
        lambda: {
            "project_root": os.fspath(project),
            "diagnostics": [{"message": f"analysis failed under {alias}/app.py"}],
        },
    )

    with pytest.raises(FullC6PipelineError, match="residual project-root text"):
        build_cmd._project_full_c6_analysis_report(project, analysis)


def test_signing_lifecycle_is_idempotent_and_emits_json_primary_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path.resolve()
    config = RextioConfig()
    preflight = object()
    authority = _Authority("signing-required")
    events: list[str] = []
    _install_authority_mocks(
        monkeypatch,
        project=project,
        config=config,
        preflight=preflight,
        authority=authority,
        events=events,
    )
    finalizations = 0

    def finalize(**values: object) -> object:
        nonlocal finalizations
        assert values == {
            "authority": authority,
            "config": config,
            "project_root": project,
        }
        finalizations += 1
        events.append("signing-request")
        return SimpleNamespace(
            status="signing-required",
            distribution_authorized=False,
            request=_Receipt({"manifest_sha256": "b" * 64}),
            signing_request_receipt=_Receipt(
                {"already_present": finalizations > 1, "authorizes_distribution": False}
            ),
        )

    monkeypatch.setattr(build_cmd, "finalize_configured_full_c6_distribution", finalize)

    first, _first_stdout, _first_stderr = _reporter(output_format="json")
    second, second_stdout, second_stderr = _reporter(output_format="json")
    assert _run_lifecycle(project, config, preflight, first) == 0
    assert _run_lifecycle(project, config, preflight, second) == 0

    primary = json.loads(second_stdout.getvalue())
    report = _report(project)
    assert finalizations == 2
    assert primary["lifecycle"] == "signing-required"
    assert primary["status"] == "full-c6-signing-required"
    assert primary["distribution_authorized"] is False
    assert report["full_c6"]["signing_request_receipt"]["already_present"] is True  # type: ignore[index]
    assert second_stderr.getvalue() == ""
    assert not (project / "dist").exists()


def test_publication_lifecycle_uses_exact_adapter_and_reports_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path.resolve()
    config = RextioConfig()
    preflight = object()
    authority = _Authority("publication-required")
    adapter = object()
    events: list[str] = []
    _install_authority_mocks(
        monkeypatch,
        project=project,
        config=config,
        preflight=preflight,
        authority=authority,
        events=events,
        publication_adapter=adapter,
    )

    def finalize(**values: object) -> object:
        assert values == {
            "authority": authority,
            "config": config,
            "project_root": project,
            "publication_adapter": adapter,
        }
        events.append("publication")
        bundle = project / "dist" / "demo-0.1.0-cp311.full-c6"
        bundle.mkdir(parents=True)
        return SimpleNamespace(
            status="published",
            distribution_authorized=True,
            request=_Receipt({"manifest_sha256": "c" * 64}),
            signing_request_receipt=_Receipt(
                {"already_present": True, "authorizes_distribution": False}
            ),
            publication_receipt=_Receipt(
                {
                    "bundle_sha256": "d" * 64,
                    "publication_completed": True,
                }
            ),
        )

    monkeypatch.setattr(build_cmd, "finalize_configured_full_c6_distribution", finalize)
    reporter, stdout, stderr = _reporter(output_format="json")

    assert _run_lifecycle(project, config, preflight, reporter) == 0

    primary = json.loads(stdout.getvalue())
    report = _report(project)
    assert events == [
        "host-enter",
        "production-authority",
        "prepublication-cleanup",
        "derive-publication-plan",
        "atomic-adapter",
        "publication",
        "host-exit",
    ]
    assert primary["lifecycle"] == "publication-required"
    assert primary["status"] == "full-c6-published"
    assert primary["distribution_authorized"] is True
    assert report["full_c6"]["publication_receipt"]["publication_completed"] is True  # type: ignore[index]
    assert stderr.getvalue() == ""
    assert (project / "dist" / "demo-0.1.0-cp311.full-c6").is_dir()


def test_publication_cleanup_failure_precedes_adapter_and_leaves_no_dist(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path.resolve()
    config = RextioConfig()
    preflight = object()
    authority = _Authority("publication-required")
    events: list[str] = []
    _install_authority_mocks(
        monkeypatch,
        project=project,
        config=config,
        preflight=preflight,
        authority=authority,
        events=events,
        publication_adapter=object(),
        prepublication_cleanup_error=FullC6HostInputsError(
            "cleanup /private/quarantine failed"
        ),
    )
    monkeypatch.setattr(
        build_cmd,
        "finalize_configured_full_c6_distribution",
        lambda **_kwargs: pytest.fail("publication must not run before cleanup"),
    )
    reporter, stdout, stderr = _reporter()

    assert _run_lifecycle(project, config, preflight, reporter) == 1

    report = _report(project)
    assert events == [
        "host-enter",
        "production-authority",
        "prepublication-cleanup",
        "host-exit",
    ]
    assert report["stage"] == "prepublication-cleanup"
    assert report["distribution_authorized"] is False
    assert not (project / "dist").exists()
    assert stdout.getvalue() == ""
    assert "/private" not in stderr.getvalue()


def test_completed_publication_has_no_fallible_context_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path.resolve()
    config = RextioConfig()
    preflight = object()
    authority = _Authority("publication-required")
    adapter = object()
    events: list[str] = []
    _install_authority_mocks(
        monkeypatch,
        project=project,
        config=config,
        preflight=preflight,
        authority=authority,
        events=events,
        publication_adapter=adapter,
        cleanup_error=FullC6HostInputsError(
            "post-publication cleanup must be unreachable"
        ),
    )

    def finalize(**values: object) -> object:
        assert values["publication_adapter"] is adapter
        bundle = project / "dist" / "demo-0.1.0-cp311.full-c6"
        bundle.mkdir(parents=True)
        return SimpleNamespace(
            status="published",
            distribution_authorized=True,
            request=_Receipt({"manifest_sha256": "c" * 64}),
            signing_request_receipt=_Receipt(
                {"already_present": True, "authorizes_distribution": False}
            ),
            publication_receipt=_Receipt(
                {"bundle_sha256": "d" * 64, "publication_completed": True}
            ),
        )

    monkeypatch.setattr(build_cmd, "finalize_configured_full_c6_distribution", finalize)
    reporter, stdout, stderr = _reporter()

    assert _run_lifecycle(project, config, preflight, reporter) == 0

    report = _report(project)
    assert report["status"] == "full-c6-published"
    assert report["distribution_authorized"] is True
    assert events[-1] == "host-exit"
    assert stdout.getvalue()
    assert stderr.getvalue() == ""


@pytest.mark.parametrize(
    ("error", "expected_stage"),
    [
        (FullC6GateError("wrong signature /private/key bytes"), "publication"),
        (FullC6PublicationError("bundle already exists /private/dist"), "publication"),
    ],
)
def test_publication_domain_failures_are_redacted_and_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    expected_stage: str,
) -> None:
    project = tmp_path.resolve()
    config = RextioConfig()
    preflight = object()
    authority = _Authority("publication-required")
    events: list[str] = []
    _install_authority_mocks(
        monkeypatch,
        project=project,
        config=config,
        preflight=preflight,
        authority=authority,
        events=events,
        publication_adapter=object(),
    )
    monkeypatch.setattr(
        build_cmd,
        "finalize_configured_full_c6_distribution",
        lambda **_kwargs: (_ for _ in ()).throw(error),
    )
    reporter, stdout, stderr = _reporter()

    assert _run_lifecycle(project, config, preflight, reporter) == 1

    serialized = (project / ".rextio" / "reports" / "build.json").read_text(
        encoding="utf-8"
    )
    report = json.loads(serialized)
    assert report["stage"] == expected_stage
    assert report["status"] == "full-c6-required-failed"
    assert report["distribution_authorized"] is False
    assert "/private" not in serialized
    assert "key bytes" not in serialized
    assert stdout.getvalue() == ""
    assert "wrong signature" not in stderr.getvalue()
    assert report["error"]["reason_code"] == "production-authority-unclassified"  # type: ignore[index]


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        (
            "Full C6 production authority collection failed closed",
            "production-collection-failed",
        ),
        (
            "Full C6 production toolchain support authority is invalid",
            "production-toolchain-support-invalid",
        ),
        (
            "Full C6 production toolchain support authority failed closed",
            "production-toolchain-support",
        ),
        (
            "Full C6 production prerequisites are invalid",
            "production-prerequisites-invalid",
        ),
        (
            "toolchain and Cargo workspace differ",
            "production-cargo-workspace-mismatch",
        ),
        (
            "Full C6 production toolchain support authority was replaced",
            "production-toolchain-support-replaced",
        ),
        (
            "Full C6 effective config is not canonical",
            "production-config-noncanonical",
        ),
        (
            "Full C6 production lifecycle is disabled",
            "production-lifecycle-disabled",
        ),
        (
            "Full C6 production requires exact preflight",
            "production-preflight-invalid",
        ),
        (
            "project root differs from the exact preflight root",
            "production-project-root-mismatch",
        ),
    ],
)
def test_full_c6_failure_reason_codes_cover_direct_pre_cargo_production_gates(
    message: str,
    expected: str,
) -> None:
    error = build_cmd.FullC6ProductionError(message)

    assert build_cmd._full_c6_failure_reason_code(error) == expected


def test_full_c6_failure_reason_code_prefers_exact_deep_cause() -> None:
    executor = build_cmd.FullC6ExecutorError(
        "strict Cargo build failed with exit status 125"
    )
    external = build_cmd.FullC6ExternalExecutionError(
        "RXT060 strict external native execution failed closed"
    )
    external.__cause__ = executor
    production = build_cmd.FullC6ProductionError(
        "Full C6 production authority collection failed closed"
    )
    production.__cause__ = external

    assert (
        build_cmd._full_c6_failure_reason_code(production)
        == "linux-launcher-exit-125"
    )


def test_full_c6_failure_reason_code_classifies_normal_cargo_failure() -> None:
    error = build_cmd.FullC6ExecutorError(
        "strict Cargo build failed with exit status 101"
    )

    assert build_cmd._full_c6_failure_reason_code(error) == "native-build-exit-101"


@pytest.mark.parametrize(
    "reason_code",
    [
        "native-sandbox-bubblewrap",
        "native-bwrap-user-namespace-denied",
        "native-bwrap-bind-path-missing",
        "native-bwrap-mount-failed",
        "native-bwrap-exec-failed",
        "native-bwrap-seccomp-failed",
        "native-cargo-dependency-config",
        "native-rustc",
        "native-linker",
        "native-macos-permission-build-root",
        "native-macos-permission-denied-dev",
        "native-macos-permission-denied-library",
        "native-macos-permission-denied-preboot",
        "native-macos-permission-denied-private-var",
        "native-macos-permission-mach-lookup",
        "native-macos-permission-project-root",
        "native-macos-permission-sandbox-apply",
        "native-macos-permission-support",
        "native-macos-permission-sysctl-cpu-count",
        "native-macos-permission-toolchain",
        "native-macos-permission-unmatched",
        "native-pyo3",
        "native-permission",
        "native-missing-path",
        "native-compile",
        *(
            f"linux-launcher-{stage}"
            for stage in build_cmd.FULL_C6_LINUX_LAUNCHER_FAILURE_STAGES
        ),
    ],
)
def test_full_c6_failure_reason_code_prefers_static_native_stderr_category(
    reason_code: str,
) -> None:
    detail = build_cmd.FullC6ExecutorError(
        f"strict native sandbox build failed: {reason_code}"
    )
    error = build_cmd.FullC6ExecutorError(
        "strict Cargo build failed with exit status 1"
    )
    error.__cause__ = detail

    assert build_cmd._full_c6_failure_reason_code(error) == reason_code


def test_full_c6_failure_reason_code_never_returns_unknown_message() -> None:
    private = "/private/runner/project secret diagnostics"
    error = build_cmd.FullC6ProductionError(private)

    reason = build_cmd._full_c6_failure_reason_code(error)

    assert reason == "production-authority-unclassified"
    assert private not in reason


def test_full_c6_failure_report_serializes_only_static_deep_reason_code(
    tmp_path: Path,
) -> None:
    project = tmp_path.resolve()
    executor = build_cmd.FullC6ExecutorError(
        "strict Cargo build failed with exit status 125"
    )
    private = build_cmd.FullC6ProductionError("/private/runner/project secret")
    private.__cause__ = executor
    reporter, _stdout, _stderr = _reporter()

    assert (
        build_cmd._report_full_c6_pipeline_failure(
            project,
            _analysis(project),
            "cpython",
            private,
            reporter,
            stage="production-authority",
        )
        == 1
    )

    serialized = (project / ".rextio" / "reports" / "build.json").read_text(
        encoding="utf-8"
    )
    report = json.loads(serialized)
    assert report["error"]["reason_code"] == "linux-launcher-exit-125"
    assert "/private" not in serialized
    assert "secret" not in serialized


@pytest.mark.parametrize(
    "reason_code",
    (
        "native-sandbox-bubblewrap",
        "linux-launcher-landlock",
        "native-macos-permission-mach-lookup",
    ),
)
def test_full_c6_failure_report_serializes_only_static_native_stderr_category(
    tmp_path: Path, reason_code: str
) -> None:
    project = tmp_path.resolve()
    detail = build_cmd.FullC6ExecutorError(
        f"strict native sandbox build failed: {reason_code}"
    )
    executor = build_cmd.FullC6ExecutorError(
        "strict Cargo build failed with exit status 1"
    )
    executor.__cause__ = detail
    private = build_cmd.FullC6ProductionError(
        "/private/runner/project secret com.example.private-service"
    )
    private.__cause__ = executor
    reporter, _stdout, _stderr = _reporter()

    assert (
        build_cmd._report_full_c6_pipeline_failure(
            project,
            _analysis(project),
            "cpython",
            private,
            reporter,
            stage="production-authority",
        )
        == 1
    )

    serialized = (project / ".rextio" / "reports" / "build.json").read_text(
        encoding="utf-8"
    )
    report = json.loads(serialized)
    assert report["error"]["reason_code"] == reason_code
    assert "/private" not in serialized
    assert "secret" not in serialized
    assert "com.example.private-service" not in serialized


def test_host_cleanup_failure_replaces_provisional_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path.resolve()
    config = RextioConfig()
    preflight = object()
    authority = _Authority("bootstrap-required", bootstrap_request=object())
    events: list[str] = []
    _install_authority_mocks(
        monkeypatch,
        project=project,
        config=config,
        preflight=preflight,
        authority=authority,
        events=events,
        cleanup_error=FullC6HostInputsError("cleanup /private/quarantine failed"),
    )
    monkeypatch.setattr(
        build_cmd,
        "materialize_full_c6_policy_bootstrap_request",
        lambda **_kwargs: _Receipt(
            {"status": "bootstrap-required", "distribution_authorized": False}
        ),
    )
    reporter, stdout, _stderr = _reporter()

    assert _run_lifecycle(project, config, preflight, reporter) == 1

    report = _report(project)
    assert report["stage"] == "host-cleanup"
    assert report["distribution_authorized"] is False
    assert stdout.getvalue() == ""
    assert not (project / "dist").exists()


def test_strict_cli_root_preserves_parent_segments_and_symlinks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(target, target_is_directory=True)

    assert build_cmd._full_c6_lexical_project_root(".") == os.fspath(tmp_path)
    assert ".." in Path(
        build_cmd._full_c6_lexical_project_root("nested/../target")
    ).parts
    assert build_cmd._full_c6_lexical_project_root(os.fspath(alias)) == os.fspath(alias)


def test_run_routes_exact_strict_preflight_and_lexical_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    config = RextioConfig(
        build=BuildConfig(
            artifact_distribution_policy="full-c6-required",
            artifact_evidence_policy="required",
        )
    )
    analysis = _analysis(tmp_path)
    preflight = SimpleNamespace(analysis=analysis, context=object())
    target_plan = SimpleNamespace(
        spec=SimpleNamespace(language="rust", version=None),
        plugins=SimpleNamespace(active=()),
    )
    captured: dict[str, object] = {}
    scope = object()
    analysis_scopes: list[object] = []
    preflight_values: dict[str, object] = {}
    monkeypatch.setattr(build_cmd, "load_config", lambda *_args, **_kwargs: config)
    monkeypatch.setattr(build_cmd, "override_config", lambda value, _overrides: value)
    monkeypatch.setattr(build_cmd, "create_target_plan", lambda *_args: target_plan)
    monkeypatch.setattr(
        build_cmd,
        "collect_full_c6_analysis_scope",
        lambda *_args, **_kwargs: scope,
    )

    def analyze(*_args: object, **kwargs: object):  # type: ignore[no-untyped-def]
        analysis_scopes.append(kwargs["full_c6_analysis_scope"])
        return analysis

    monkeypatch.setattr(build_cmd, "analyze_project", analyze)
    monkeypatch.setattr(
        build_cmd,
        "prepare_full_c6_external_build",
        lambda **kwargs: (preflight_values.update(kwargs), preflight)[1],
    )

    def run_lifecycle(**values: object) -> int:
        captured.update(values)
        return 0

    monkeypatch.setattr(build_cmd, "_run_full_c6_cli_lifecycle", run_lifecycle)

    assert main(["build", "."]) == 0
    assert captured["preflight"] is preflight
    assert captured["analysis"] is analysis
    assert captured["raw_project_root"] == os.fspath(tmp_path)
    assert captured["project_root"] == tmp_path
    assert preflight_values["analysis_scope"] is scope
    reanalyze = preflight_values["reanalyze"]
    assert callable(reanalyze)
    assert reanalyze(object()) is analysis
    assert analysis_scopes == [scope, scope]


def test_scope_collection_failure_is_redacted_before_analysis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = tmp_path.resolve()
    reports = project / ".rextio" / "reports"
    reports.mkdir(parents=True)
    stale_payloads: dict[str, bytes] = {}
    for name in ("build.json", "check.json", "generate.json"):
        (reports / name).write_text('{"stale": true}\n', encoding="utf-8")
        stale_payloads[name] = (reports / name).read_bytes()
    config = RextioConfig(
        build=BuildConfig(
            artifact_distribution_policy="full-c6-required",
            artifact_evidence_policy="required",
        )
    )
    target_plan = SimpleNamespace(
        spec=SimpleNamespace(language="rust", version=None),
        plugins=SimpleNamespace(active=()),
    )
    monkeypatch.setattr(build_cmd, "load_config", lambda *_args, **_kwargs: config)
    monkeypatch.setattr(build_cmd, "override_config", lambda value, _overrides: value)
    monkeypatch.setattr(build_cmd, "create_target_plan", lambda *_args: target_plan)
    monkeypatch.setattr(
        build_cmd,
        "collect_full_c6_analysis_scope",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            FullC6HostInputsError("changed /private/owner/cargo-vendor")
        ),
    )
    monkeypatch.setattr(
        build_cmd,
        "analyze_project",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("analysis must not run")
        ),
    )

    assert main(["build", os.fspath(project)]) == 1

    for name, payload in stale_payloads.items():
        assert (reports / name).read_bytes() == payload
    captured = capsys.readouterr()
    assert "/private/owner" not in captured.err


def test_preanalysis_failure_never_follows_rextio_symlink(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    external = tmp_path / "external"
    reports = external / "reports"
    reports.mkdir(parents=True)
    sentinel = reports / "build.json"
    sentinel.write_bytes(b"external-owner-data\n")
    (project / ".rextio").symlink_to(external, target_is_directory=True)
    reporter, _stdout, stderr = _reporter()

    assert build_cmd._report_full_c6_preanalysis_failure(
        project,
        "cpython",
        FullC6HostInputsError("attacker detail /private/path"),
        reporter,
    ) == 1

    assert sentinel.read_bytes() == b"external-owner-data\n"
    assert tuple(reports.iterdir()) == (sentinel,)
    assert "/private/path" not in stderr.getvalue()
