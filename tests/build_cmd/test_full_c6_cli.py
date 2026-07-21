"""Strict Full C6 CLI lifecycle routing and report tests."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

import rextio.cli.build_cmd as build_cmd
from rextio.analyzer.models import ProjectAnalysis
from rextio.build.full_c6_gate import FullC6GateError
from rextio.build.full_c6_host_inputs import FullC6HostInputsError
from rextio.build.full_c6_pipeline import FullC6ExternalPreflightResult
from rextio.build.full_c6_publication import FullC6PublicationError
from rextio.cli.main import main
from rextio.cli.reporter import Reporter
from rextio.config.schema import BuildConfig, RextioConfig


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

    prerequisites = SimpleNamespace(
        project_root=project,
        config=config,
        toolchain=object(),
        native_tools=object(),
        cargo_workspace=object(),
        first_quarantine_root=project / "quarantine-one",
        second_quarantine_root=project / "quarantine-two",
        state_directory=state,
        base_environment={"PATH": "/actual-cargo"},
        source_date_epoch=0,
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
    monkeypatch.setattr(build_cmd, "load_config", lambda *_args, **_kwargs: config)
    monkeypatch.setattr(build_cmd, "override_config", lambda value, _overrides: value)
    monkeypatch.setattr(build_cmd, "create_target_plan", lambda *_args: target_plan)
    monkeypatch.setattr(build_cmd, "analyze_project", lambda *_args, **_kwargs: analysis)
    monkeypatch.setattr(
        build_cmd,
        "prepare_full_c6_external_build",
        lambda **_kwargs: preflight,
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
