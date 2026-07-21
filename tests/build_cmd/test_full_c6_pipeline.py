"""Vertical-slice tests for strict C5.2 and Full C6 pipeline coordination."""

from __future__ import annotations

import inspect
from pathlib import Path
import runpy
from types import SimpleNamespace
import zipfile

import pytest

import rextio.build.full_c6_gate as gate_module
import rextio.build.full_c6_pipeline as pipeline_module
from rextio.analyzer.project_scanner import analyze_project
from rextio.artifacts.evidence import sha256_hex
from rextio.build.artifact_layout import ArtifactLayout
from rextio.build.full_c6_policy_manifest import full_c6_policy_manifest_bytes
from rextio.build.full_c6_policy_bootstrap import (
    resolve_full_c6_policy_lifecycle,
)
from rextio.build.full_c6_pipeline import (
    FULL_C6_SIGNING_REQUEST_FILENAME,
    FullC6PipelineError,
    finalize_configured_full_c6_distribution,
    finalize_full_c6_distribution,
    _full_c6_atomic_publication_adapter,
    load_configured_full_c6_policy,
    prepare_full_c6_external_build,
)
from rextio.build.full_c6_production import FullC6ProductionAuthority
from rextio.build.orchestrator import (
    _generate_native_source,
    build_hybrid_artifact,
    generate_source_artifact,
)
from rextio.build.supply_chain import (
    capture_generated_python_inputs,
    capture_generated_rust_inputs,
    capture_project_source_snapshot,
)
from rextio.build.transformation_inventory import collect_source_transformation_inventory
from rextio.build.transformation_verification import (
    collect_scoped_source_transformation_verification,
)
from rextio.build.runtime_authorization import RUNTIME_VERIFICATION_NATIVE_FRESH
from rextio.build.wheel_builder import build_artifact_wheel
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
_FINALIZATION_MATERIALS: dict[int, object] = {}


def test_finalization_public_api_accepts_only_production_authority_evidence() -> None:
    assert not hasattr(pipeline_module, "FullC6FinalizationMaterials")
    assert not hasattr(pipeline_module, "full_c6_atomic_publication_adapter")
    finalize = inspect.signature(finalize_full_c6_distribution)
    configured = inspect.signature(finalize_configured_full_c6_distribution)
    adapter_call = inspect.signature(pipeline_module.FullC6PublicationAdapter.__call__)

    assert "authority" in finalize.parameters
    assert "authority" in configured.parameters
    assert "materials" not in finalize.parameters
    assert "materials" not in configured.parameters
    raw_evidence = {
        "subject",
        "build_inputs",
        "wheel_entries",
        "policy",
        "source_verification",
        "analysis_ir_transaction",
        "toolchain",
        "cargo_path_source",
        "runtime_authorization",
        "executor",
        "supply_chain",
        "expected_public_key_sha256",
    }
    assert raw_evidence.isdisjoint(finalize.parameters)
    assert raw_evidence.isdisjoint(configured.parameters)
    assert tuple(adapter_call.parameters) == ("self", "authority", "request", "gate")


@pytest.fixture(autouse=True)
def _accept_synthetic_native_runtime(monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    """Model native fresh revalidation for the synthetic finalization graph."""
    _FINALIZATION_MATERIALS.clear()
    monkeypatch.setattr(
        "rextio.build.full_c6_gate.verify_native_runtime_authorization",
        lambda receipt: receipt.verification_mode == RUNTIME_VERIFICATION_NATIVE_FRESH,
    )
    monkeypatch.setattr(
        gate_module,
        "_validated_production_gate_inputs",
        lambda authority: _GATE["_TEST_GATE_INPUTS"][id(authority)],  # type: ignore[index]
    )
    monkeypatch.setattr(
        pipeline_module,
        "_validated_production_gate_inputs",
        lambda authority: _GATE["_TEST_GATE_INPUTS"][id(authority)],  # type: ignore[index]
    )
    monkeypatch.setattr(
        pipeline_module,
        "_validated_full_c6_finalization_material",
        lambda authority: _FINALIZATION_MATERIALS[id(authority)],
    )
    yield
    _FINALIZATION_MATERIALS.clear()


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


def test_source_only_generation_replays_exact_external_c5_2_ir(tmp_path: Path) -> None:
    preflight = _external_preflight(tmp_path)
    project = preflight.analysis.project_root
    result = generate_source_artifact(
        project,
        preflight.analysis,
        "cpython",
        full_c6_external_context=preflight.context,
    )
    snapshot = capture_project_source_snapshot(project_root=project, plan=result.plan)
    snapshot = capture_generated_python_inputs(
        snapshot,
        project_root=project,
        layout=result.layout,
    )
    snapshot = capture_generated_rust_inputs(
        snapshot,
        project_root=project,
        layout=result.layout,
    )
    inventory = collect_source_transformation_inventory(
        project_root=project,
        plan=result.plan,
        input_snapshot=snapshot,
    )
    assert inventory is not None

    verification = collect_scoped_source_transformation_verification(
        project_root=project,
        plan=result.plan,
        input_snapshot=snapshot,
        transformation_inventory=inventory,
        embedding_enabled=False,
        external_native_registry=preflight.context.registry,
        external_runtime_guard=preflight.context.runtime_guard,
    )

    assert verification is not None
    assert any(
        item.logical_path.endswith("/src/lib.rs")
        and item.sha256 == verification.generated_rust.sha256
        for item in snapshot.generated_rust
    )


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


def _gate_arguments(tmp_path: Path) -> dict[str, object]:
    return _GATE["_fixture"](tmp_path / "gate")  # type: ignore[no-any-return,operator]


def _bind_finalization_authority(
    arguments: dict[str, object],
    *,
    project_root: Path,
    config: RextioConfig,
    authority: FullC6ProductionAuthority | None = None,
) -> FullC6ProductionAuthority:
    retained = authority or arguments["authority"]
    assert type(retained) is FullC6ProductionAuthority
    gate_inputs = _GATE["_TEST_GATE_INPUTS"][id(arguments["authority"])]  # type: ignore[index]
    _GATE["_TEST_GATE_INPUTS"][id(retained)] = gate_inputs  # type: ignore[index]
    _FINALIZATION_MATERIALS[id(retained)] = SimpleNamespace(
        lifecycle=resolve_full_c6_policy_lifecycle(config),
        project_root=project_root.resolve(),
        config=config,
        policy=arguments["policy"],
        supply_chain=arguments["supply_chain"],
        build_inputs=arguments["build_inputs"],
        analysis_ir_transaction=arguments["analysis_ir_transaction"],
        runtime_authorization=arguments["runtime_authorization"],
        executor_receipt=arguments["executor"],
        cargo_path_source=arguments["cargo_path_source"],
        cargo_workspace=arguments["cargo_dependency_workspace"],
    )
    return retained


def _write_policy_manifest(
    root: Path,
    policy: object,
) -> tuple[str, str]:
    raw = full_c6_policy_manifest_bytes(policy)  # type: ignore[arg-type]
    relative = "policy/rextio.full-c6-policy.json"
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return relative, sha256_hex(raw)


def test_unsigned_pipeline_writes_only_request_and_never_publication(tmp_path: Path) -> None:
    arguments = _gate_arguments(tmp_path)
    policy_path, policy_sha256 = _write_policy_manifest(tmp_path, arguments["policy"])
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
    authority = _bind_finalization_authority(
        arguments,
        project_root=tmp_path,
        config=config,
    )
    result = finalize_configured_full_c6_distribution(
        project_root=tmp_path,
        config=config,
        authority=authority,
        publication_adapter=lambda *_args: pytest.fail("unsigned path called publication"),
    )

    assert result.status == "signing-required"
    assert result.distribution_authorized is False
    assert [path.name for path in state.iterdir()] == [FULL_C6_SIGNING_REQUEST_FILENAME]
    assert not publication.exists()


def test_configured_finalization_rejects_equal_but_distinct_config(
    tmp_path: Path,
) -> None:
    arguments = _gate_arguments(tmp_path)
    policy_path, policy_sha256 = _write_policy_manifest(tmp_path, arguments["policy"])
    config = RextioConfig(
        build=BuildConfig(
            artifact_distribution_policy="full-c6-required",
            artifact_policy_manifest=policy_path,
            artifact_policy_manifest_sha256=policy_sha256,
            artifact_trusted_public_key="state/owner.pub",
            artifact_trusted_public_key_sha256=arguments[
                "expected_public_key_sha256"
            ],  # type: ignore[arg-type]
            artifact_signing_request_output=f"state/{FULL_C6_SIGNING_REQUEST_FILENAME}",
        )
    )
    authority = _bind_finalization_authority(
        arguments,
        project_root=tmp_path,
        config=config,
    )
    equal_config = RextioConfig(build=config.build)
    assert equal_config == config
    assert equal_config is not config

    with pytest.raises(FullC6PipelineError, match="retained production inputs"):
        finalize_configured_full_c6_distribution(
            project_root=tmp_path,
            config=equal_config,
            authority=authority,
        )
    assert not (tmp_path / "state").exists()


def test_configured_policy_loader_rejects_stale_pin_and_key_mismatch(tmp_path: Path) -> None:
    arguments = _gate_arguments(tmp_path)
    policy_path, policy_sha256 = _write_policy_manifest(tmp_path, arguments["policy"])
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
    ).digest == arguments["policy"].digest  # type: ignore[union-attr]

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


def test_policy_bootstrap_does_not_weaken_the_strict_policy_loader(
    tmp_path: Path,
) -> None:
    config = RextioConfig(
        build=BuildConfig(
            artifact_distribution_policy="full-c6-required",
            artifact_policy_manifest="policy/rextio.full-c6-policy.json",
            artifact_policy_manifest_sha256=None,
            artifact_trusted_public_key="state/owner.pub",
            artifact_trusted_public_key_sha256="a" * 64,
        )
    )

    lifecycle = resolve_full_c6_policy_lifecycle(config)
    assert lifecycle.status == "bootstrap-required"
    assert lifecycle.signing_request_allowed is False
    assert lifecycle.publication_attempt_allowed is False
    with pytest.raises(FullC6PipelineError, match="path and digest are incomplete"):
        load_configured_full_c6_policy(project_root=tmp_path, config=config)


def test_signed_pipeline_passes_sealed_gate_then_atomically_publishes(tmp_path: Path) -> None:
    arguments = _gate_arguments(tmp_path)
    policy_path, policy_sha256 = _write_policy_manifest(tmp_path, arguments["policy"])
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    request_path = state / FULL_C6_SIGNING_REQUEST_FILENAME
    unsigned_config = RextioConfig(
        build=BuildConfig(
            artifact_distribution_policy="full-c6-required",
            artifact_policy_manifest=policy_path,
            artifact_policy_manifest_sha256=policy_sha256,
            artifact_trusted_public_key="state/owner.pub",
            artifact_trusted_public_key_sha256=arguments[
                "expected_public_key_sha256"
            ],  # type: ignore[arg-type]
            artifact_signing_request_output=f"state/{FULL_C6_SIGNING_REQUEST_FILENAME}",
        )
    )
    unsigned_authority = _bind_finalization_authority(
        arguments,
        project_root=tmp_path,
        config=unsigned_config,
    )
    unsigned = finalize_full_c6_distribution(
        authority=unsigned_authority,
        signing_request_path=request_path,
        public_key_path=state / "owner.pub",
        final_signature_path=None,
    )
    signature_path, key_path = _GATE["_sign_request"](  # type: ignore[operator]
        state,
        request=unsigned.request,
        public_key=arguments["public_key"],
    )
    publication_root = tmp_path / "dist"
    publication_root.mkdir()
    signed_config = RextioConfig(
        build=BuildConfig(
            artifact_distribution_policy="full-c6-required",
            artifact_policy_manifest=policy_path,
            artifact_policy_manifest_sha256=policy_sha256,
            artifact_trusted_public_key="state/owner.pub",
            artifact_trusted_public_key_sha256=arguments[
                "expected_public_key_sha256"
            ],  # type: ignore[arg-type]
            artifact_signing_request_output=f"state/{FULL_C6_SIGNING_REQUEST_FILENAME}",
            artifact_final_signature="state/final.sig.json",
        )
    )
    signed_authority = object.__new__(FullC6ProductionAuthority)
    signed_authority = _bind_finalization_authority(
        arguments,
        project_root=tmp_path,
        config=signed_config,
        authority=signed_authority,
    )
    subject_path = Path(arguments["subject_path"])
    bundle_name = f"{subject_path.name.removesuffix('.whl')}.full-c6"
    adapter = _full_c6_atomic_publication_adapter(
        authority=signed_authority,
        state_directory=state,
        publication_root=publication_root,
        bundle_name=bundle_name,
        subject_path=subject_path,
        final_signature_path=signature_path,
        public_key_path=key_path,
    )

    result = finalize_full_c6_distribution(
        authority=signed_authority,
        signing_request_path=request_path,
        public_key_path=key_path,
        final_signature_path=signature_path,
        publication_adapter=adapter,
    )

    assert result.status == "published"
    assert result.distribution_authorized is True
    assert result.gate is not None
    assert result.gate.authorization.distribution_authorized is True
    bundle = publication_root / bundle_name
    assert bundle.is_dir()
    assert len(tuple(bundle.iterdir())) == 7  # six payload files + publication manifest

    equal_authority = object.__new__(FullC6ProductionAuthority)
    equal_authority = _bind_finalization_authority(
        arguments,
        project_root=tmp_path,
        config=signed_config,
        authority=equal_authority,
    )
    with pytest.raises(FullC6PipelineError, match="not the retained authority"):
        adapter(equal_authority, result.request, result.gate)

    copied_subject = tmp_path / "same-wheel-different-path.whl"
    copied_subject.write_bytes(Path(arguments["subject_path"]).read_bytes())
    wrong_path_adapter = _full_c6_atomic_publication_adapter(
        authority=signed_authority,
        state_directory=state,
        publication_root=publication_root,
        bundle_name=bundle_name,
        subject_path=copied_subject,
        final_signature_path=signature_path,
        public_key_path=key_path,
    )
    with pytest.raises(FullC6PipelineError, match="publication paths"):
        wrong_path_adapter(signed_authority, result.request, result.gate)

    alternate_root = tmp_path / "alternate-dist"
    alternate_root.mkdir()
    wrong_root_adapter = _full_c6_atomic_publication_adapter(
        authority=signed_authority,
        state_directory=state,
        publication_root=alternate_root,
        bundle_name=bundle_name,
        subject_path=subject_path,
        final_signature_path=signature_path,
        public_key_path=key_path,
    )
    with pytest.raises(FullC6PipelineError, match="publication paths"):
        wrong_root_adapter(signed_authority, result.request, result.gate)
    assert tuple(alternate_root.iterdir()) == ()

    wrong_name_adapter = _full_c6_atomic_publication_adapter(
        authority=signed_authority,
        state_directory=state,
        publication_root=publication_root,
        bundle_name="alternate-name.full-c6",
        subject_path=subject_path,
        final_signature_path=signature_path,
        public_key_path=key_path,
    )
    with pytest.raises(FullC6PipelineError, match="publication paths"):
        wrong_name_adapter(signed_authority, result.request, result.gate)
    assert not (publication_root / "alternate-name.full-c6").exists()

    mutated_name_adapter = _full_c6_atomic_publication_adapter(
        authority=signed_authority,
        state_directory=state,
        publication_root=publication_root,
        bundle_name=bundle_name,
        subject_path=subject_path,
        final_signature_path=signature_path,
        public_key_path=key_path,
    )
    object.__setattr__(mutated_name_adapter, "bundle_name", "mutated.full-c6")
    with pytest.raises(FullC6PipelineError, match="adapter seal"):
        mutated_name_adapter(signed_authority, result.request, result.gate)

    mutated_path_adapter = _full_c6_atomic_publication_adapter(
        authority=signed_authority,
        state_directory=state,
        publication_root=publication_root,
        bundle_name=bundle_name,
        subject_path=subject_path,
        final_signature_path=signature_path,
        public_key_path=key_path,
    )
    object.__setattr__(mutated_path_adapter, "publication_root", alternate_root)
    with pytest.raises(FullC6PipelineError, match="adapter seal"):
        mutated_path_adapter(signed_authority, result.request, result.gate)

    mutated_authority_adapter = _full_c6_atomic_publication_adapter(
        authority=signed_authority,
        state_directory=state,
        publication_root=publication_root,
        bundle_name=bundle_name,
        subject_path=subject_path,
        final_signature_path=signature_path,
        public_key_path=key_path,
    )
    object.__setattr__(mutated_authority_adapter, "authority", equal_authority)
    with pytest.raises(FullC6PipelineError, match="adapter seal"):
        mutated_authority_adapter(equal_authority, result.request, result.gate)
