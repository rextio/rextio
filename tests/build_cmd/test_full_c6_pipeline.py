"""Vertical-slice tests for strict C5.2 and Full C6 pipeline coordination."""

from __future__ import annotations

import json
from pathlib import Path
import runpy
from types import SimpleNamespace
import zipfile

import pytest

from rextio.analyzer.project_scanner import analyze_project
from rextio.artifacts.evidence import sha256_hex
from rextio.build.artifact_layout import ArtifactLayout
from rextio.build.full_c6_policy_manifest import full_c6_policy_manifest_bytes
from rextio.build.full_c6_pipeline import (
    FULL_C6_SIGNING_REQUEST_FILENAME,
    FullC6FinalizationMaterials,
    FullC6PipelineError,
    finalize_configured_full_c6_distribution,
    finalize_full_c6_distribution,
    full_c6_atomic_publication_adapter,
    load_configured_full_c6_policy,
    prepare_full_c6_external_build,
)
from rextio.build.orchestrator import _generate_native_source, build_hybrid_artifact
from rextio.build.runtime_authorization import RUNTIME_VERIFICATION_NATIVE_FRESH
from rextio.build.wheel_builder import build_artifact_wheel
from rextio.cli.main import main
from rextio.config.schema import (
    BuildConfig,
    ImportPackagePolicy,
    ImportsConfig,
    RextioConfig,
)
from rextio.partition.build_plan import create_build_plan
from rextio.targets.plan import default_target_plan


_THIS_DIR = Path(__file__).parent
_SOURCE = runpy.run_path(str(_THIS_DIR.parent / "source" / "test_source_lock_v2.py"))
_GATE = runpy.run_path(str(_THIS_DIR / "test_full_c6_gate.py"))


@pytest.fixture(autouse=True)
def _accept_synthetic_native_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    """Model native fresh revalidation for the synthetic finalization graph."""
    monkeypatch.setattr(
        "rextio.build.full_c6_gate.verify_native_runtime_authorization",
        lambda receipt: receipt.verification_mode == RUNTIME_VERIFICATION_NATIVE_FRESH,
    )


def _external_preflight(
    tmp_path: Path,
    *,
    source: str = """\
import demo_pkg as p

def calculate(x: int) -> int:
    return p.affine(x)
""",
):
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text(source, encoding="utf-8")
    signed = _SOURCE["_write_signed"](project / "authority")  # type: ignore[operator]
    initial = analyze_project(project)
    initial.external_source_plan = signed.plan
    request_path = f"state/{FULL_C6_SIGNING_REQUEST_FILENAME}"
    config = RextioConfig(
        build=BuildConfig(
            artifact_evidence_policy="required",
            artifact_distribution_policy="full-c6-required",
            artifact_source_lock_manifest=signed.lock_path.relative_to(project).as_posix(),
            artifact_source_lock_signature=signed.signature_path.relative_to(project).as_posix(),
            artifact_trusted_public_key=signed.key_path.relative_to(project).as_posix(),
            artifact_trusted_public_key_sha256=signed.key_hash,
            artifact_signing_request_output=request_path,
        ),
        imports=ImportsConfig(
            packages={
                "demo_pkg": ImportPackagePolicy(
                    policy="try-native",
                    max_depth=1,
                    distribution="demo-pkg",
                    version="1.0.0",
                    source_archive=signed.wheel_path.relative_to(project).as_posix(),
                    source_archive_sha256=signed.wheel_sha256,
                )
            }
        ),
    )

    def reanalyze(registry):
        fresh = analyze_project(project, external_native_registry=registry)
        fresh.external_source_plan = signed.plan
        return fresh

    return prepare_full_c6_external_build(
        project_root=project,
        initial_analysis=initial,
        config=config,
        reanalyze=reanalyze,
    )


def test_signed_source_preflight_threads_private_ir_guard_and_wheel_contract(
    tmp_path: Path,
) -> None:
    preflight = _external_preflight(tmp_path)
    project = preflight.analysis.project_root
    plan = create_build_plan(preflight.analysis, "cpython")
    layout = ArtifactLayout(project)

    generated, dependencies = _generate_native_source(
        plan,
        layout,
        default_target_plan(),
        full_c6_external_context=preflight.context,
    )

    assert generated.status == "generated"
    assert dependencies == ()
    rust = (layout.rust_src_dir / "lib.rs").read_text(encoding="utf-8")
    assert rust.count("demo_pkg__affine(") == 2
    assert "wrap_pyfunction!(app__calculate, m)" in rust
    assert "wrap_pyfunction!(demo_pkg__affine, m)" not in rust
    assert "__rextio_verify_external_source" in rust
    assert "demo-pkg" in rust and "1.0.0" in rust

    python_dir = tmp_path / "python-stage"
    python_dir.mkdir()
    (python_dir / "app.py").write_text("def calculate(x): return x\n", encoding="utf-8")
    wheel = build_artifact_wheel(
        project,
        python_dir,
        tmp_path / "candidate",
        external_contract=preflight.context.wheel_contract,
    )
    assert wheel.path is not None
    with zipfile.ZipFile(wheel.path) as archive:
        names = archive.namelist()
        metadata_name = next(name for name in names if name.endswith(".dist-info/METADATA"))
        metadata = archive.read(metadata_name).decode("utf-8")
    assert "Requires-Dist: demo-pkg==1.0.0\n" in metadata
    assert not any(name.startswith("demo_pkg/") and name.endswith(".py") for name in names)


def test_direct_orchestrator_requires_strict_context_and_policy_pair(tmp_path: Path) -> None:
    preflight = _external_preflight(tmp_path)
    with pytest.raises(FullC6PipelineError, match="same-transaction"):
        build_hybrid_artifact(
            preflight.analysis.project_root,
            preflight.analysis,
            "cpython",
            artifact_evidence_policy="required",
            artifact_distribution_policy="full-c6-required",
        )
    with pytest.raises(FullC6PipelineError, match="ordinary or preview"):
        build_hybrid_artifact(
            preflight.analysis.project_root,
            preflight.analysis,
            "cpython",
            full_c6_external_context=preflight.context,
        )


def test_strict_preflight_rejects_unsupported_external_call_shape(tmp_path: Path) -> None:
    with pytest.raises(FullC6PipelineError, match="linkage"):
        _external_preflight(
            tmp_path,
            source="""\
import demo_pkg as p

def calculate(x: int) -> int:
    return p.affine(x=x)
""",
        )


def _finalization_materials(tmp_path: Path):
    arguments = _GATE["_fixture"](tmp_path / "gate")  # type: ignore[operator]
    materials = FullC6FinalizationMaterials(
        target_triple=arguments["target_triple"],  # type: ignore[arg-type]
        subject_path=arguments["subject_path"],  # type: ignore[arg-type]
        subject=arguments["subject"],  # type: ignore[arg-type]
        build_inputs=arguments["build_inputs"],  # type: ignore[arg-type]
        wheel_entries=arguments["wheel_entries"],  # type: ignore[arg-type]
        policy=arguments["policy"],  # type: ignore[arg-type]
        source_verification=arguments["source_verification"],  # type: ignore[arg-type]
        toolchain=arguments["toolchain"],  # type: ignore[arg-type]
        cargo_path_source=arguments["cargo_path_source"],  # type: ignore[arg-type]
        runtime_authorization=arguments["runtime_authorization"],  # type: ignore[arg-type]
        supply_chain=arguments["supply_chain"],  # type: ignore[arg-type]
        executor=arguments["executor"],  # type: ignore[arg-type]
    )
    return arguments, materials


def _write_policy_manifest(
    root: Path,
    materials: FullC6FinalizationMaterials,
) -> tuple[str, str]:
    raw = full_c6_policy_manifest_bytes(materials.policy)
    relative = "policy/rextio.full-c6-policy.json"
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return relative, sha256_hex(raw)


def test_unsigned_pipeline_writes_only_request_and_never_publication(tmp_path: Path) -> None:
    arguments, materials = _finalization_materials(tmp_path)
    policy_path, policy_sha256 = _write_policy_manifest(tmp_path, materials)
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    publication = tmp_path / "dist"

    config = RextioConfig(
        build=BuildConfig(
            artifact_distribution_policy="full-c6-required",
            artifact_policy_manifest=policy_path,
            artifact_policy_manifest_sha256=policy_sha256,
            artifact_trusted_public_key="owner.pub",
            artifact_trusted_public_key_sha256=arguments[
                "expected_public_key_sha256"
            ],  # type: ignore[arg-type]
            artifact_signing_request_output=f"state/{FULL_C6_SIGNING_REQUEST_FILENAME}",
        )
    )
    result = finalize_configured_full_c6_distribution(
        project_root=tmp_path,
        config=config,
        materials=materials,
        publication_adapter=lambda *_args: pytest.fail("unsigned path called publication"),
    )

    assert result.status == "signing-required"
    assert result.distribution_authorized is False
    assert [path.name for path in state.iterdir()] == [FULL_C6_SIGNING_REQUEST_FILENAME]
    assert not publication.exists()


def test_configured_policy_loader_rejects_stale_pin_and_key_mismatch(tmp_path: Path) -> None:
    arguments, materials = _finalization_materials(tmp_path)
    policy_path, policy_sha256 = _write_policy_manifest(tmp_path, materials)
    trusted_key_sha256 = arguments["expected_public_key_sha256"]
    config = RextioConfig(
        build=BuildConfig(
            artifact_distribution_policy="full-c6-required",
            artifact_policy_manifest=policy_path,
            artifact_policy_manifest_sha256=policy_sha256,
            artifact_trusted_public_key="state/owner.pub",
            artifact_trusted_public_key_sha256=trusted_key_sha256,  # type: ignore[arg-type]
        )
    )

    assert load_configured_full_c6_policy(
        project_root=tmp_path,
        config=config,
    ).digest == materials.policy.digest

    stale = RextioConfig(
        build=BuildConfig(
            artifact_distribution_policy="full-c6-required",
            artifact_policy_manifest=policy_path,
            artifact_policy_manifest_sha256="0" * 64,
            artifact_trusted_public_key="state/owner.pub",
            artifact_trusted_public_key_sha256=trusted_key_sha256,  # type: ignore[arg-type]
        )
    )
    with pytest.raises(FullC6PipelineError, match="manifest failed closed"):
        load_configured_full_c6_policy(project_root=tmp_path, config=stale)

    wrong_key = RextioConfig(
        build=BuildConfig(
            artifact_distribution_policy="full-c6-required",
            artifact_policy_manifest=policy_path,
            artifact_policy_manifest_sha256=policy_sha256,
            artifact_trusted_public_key="state/owner.pub",
            artifact_trusted_public_key_sha256="0" * 64,
        )
    )
    with pytest.raises(FullC6PipelineError, match="public-key pin disagree"):
        load_configured_full_c6_policy(project_root=tmp_path, config=wrong_key)


def test_signed_pipeline_passes_sealed_gate_then_atomically_publishes(tmp_path: Path) -> None:
    arguments, materials = _finalization_materials(tmp_path)
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    request_path = state / FULL_C6_SIGNING_REQUEST_FILENAME
    unsigned = finalize_full_c6_distribution(
        materials=materials,
        signing_request_path=request_path,
        public_key_path=state / "unused.pub",
        expected_public_key_sha256=arguments["expected_public_key_sha256"],  # type: ignore[arg-type]
        final_signature_path=None,
    )
    signature_path, key_path = _GATE["_sign_request"](  # type: ignore[operator]
        state,
        request=unsigned.request,
        public_key=arguments["public_key"],
    )
    publication_root = tmp_path / "dist"
    publication_root.mkdir()
    adapter = full_c6_atomic_publication_adapter(
        state_directory=state,
        publication_root=publication_root,
        bundle_name="demo-full-c6",
        subject_path=materials.subject_path,
        final_signature_path=signature_path,
        public_key_path=key_path,
    )

    result = finalize_full_c6_distribution(
        materials=materials,
        signing_request_path=request_path,
        public_key_path=key_path,
        expected_public_key_sha256=arguments["expected_public_key_sha256"],  # type: ignore[arg-type]
        final_signature_path=signature_path,
        publication_adapter=adapter,
    )

    assert result.status == "published"
    assert result.distribution_authorized is True
    assert result.gate is not None
    assert result.gate.authorization.distribution_authorized is True
    bundle = publication_root / "demo-full-c6"
    assert bundle.is_dir()
    assert len(tuple(bundle.iterdir())) == 7  # six payload files + publication manifest


def test_cli_strict_mode_fails_actionably_without_typed_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "app.py").write_text("def value(x: int) -> int: return x\n", encoding="utf-8")
    (tmp_path / "rextio.toml").write_text(
        f"""\
[build]
artifact_evidence_policy = "required"
artifact_distribution_policy = "full-c6-required"
artifact_source_lock_manifest = "locks/source.json"
artifact_source_lock_signature = "locks/source.sig.json"
artifact_policy_manifest = "locks/rextio.full-c6-policy.json"
artifact_policy_manifest_sha256 = "{'3' * 64}"
artifact_trusted_public_key = "locks/owner.pub"
artifact_trusted_public_key_sha256 = "{'1' * 64}"
artifact_signing_request_output = "state/{FULL_C6_SIGNING_REQUEST_FILENAME}"

[rust]
build_tool = "cargo"
importable = false

[plugins]
enabled = []

[imports]
default_external_policy = "fallback"

[imports.packages.demo_pkg]
policy = "try-native"
max_depth = 1
distribution = "demo-pkg"
version = "1.0.0"
source_archive = "locks/demo_pkg-1.0.0-py3-none-any.whl"
source_archive_sha256 = "{'2' * 64}"
""",
        encoding="utf-8",
    )
    analysis = analyze_project(tmp_path)
    monkeypatch.setattr("rextio.cli.build_cmd.analyze_project", lambda *_a, **_k: analysis)
    monkeypatch.setattr(
        "rextio.cli.build_cmd.prepare_full_c6_external_build",
        lambda **_kwargs: SimpleNamespace(analysis=analysis),
    )
    monkeypatch.setattr(
        "rextio.cli.build_cmd.load_configured_full_c6_policy",
        lambda **_kwargs: object(),
    )

    exit_code = main(["build", str(tmp_path)])

    captured = capsys.readouterr()
    report = json.loads(
        (tmp_path / ".rextio" / "reports" / "build.json").read_text(encoding="utf-8")
    )
    assert exit_code == 1
    assert "RXT060" in captured.err
    assert "FullC6PolicyReceipt" in captured.err
    assert report["status"] == "full-c6-required-failed"
    assert report["distribution_authorized"] is False
    assert not (tmp_path / "dist").exists()
