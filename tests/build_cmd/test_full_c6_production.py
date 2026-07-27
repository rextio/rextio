"""Contract tests for the owner-only Full C6 production collector."""

from __future__ import annotations

import copy
from dataclasses import replace
import importlib
import importlib.util
import inspect
from pathlib import Path
import pickle
import runpy
from types import SimpleNamespace

import pytest

from rextio.artifacts.evidence import EvidenceFileRef, sha256_hex
from rextio.build.full_c6_policy import (
    FullC6PolicyFileIdentity,
    full_c6_license_detector_payload_digest,
)
from rextio.build.full_c6_policy_completion import finalize_full_c6_policy_manifest
from rextio.build.full_c6_policy_manifest import parse_full_c6_policy_manifest
from rextio.build.toolchain_support_lock import (
    ToolchainSupportLock,
    ToolchainSupportLockError,
)
from rextio.config.schema import RextioConfig


_EXTERNAL = runpy.run_path(
    str(Path(__file__).with_name("test_full_c6_external_execution.py"))
)
_POLICY = runpy.run_path(
    str(Path(__file__).with_name("test_full_c6_policy.py"))
)
_BOOTSTRAP = runpy.run_path(
    str(Path(__file__).with_name("test_full_c6_policy_bootstrap.py"))
)
_COMPLETION = runpy.run_path(
    str(Path(__file__).with_name("test_full_c6_policy_completion.py"))
)


def _collect_bounded_production_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    pinned_policy: bool = False,
) -> tuple[object, object]:
    production = importlib.import_module("rextio.build.full_c6_production")
    _rows, _transformations, coverage, external = _POLICY["_fixture"]()
    policy = _POLICY["_receipt"]()
    inputs = _EXTERNAL["_inputs"](
        tmp_path,
        monkeypatch,
        build_overrides={
            "artifact_policy_manifest": "locks/rextio.artifact-policy.json",
            "artifact_policy_manifest_sha256": (
                policy.digest if pinned_policy else None
            ),
        },
    )
    config = inputs.config
    state_directory = tmp_path / "production-state"
    state_directory.mkdir(mode=0o700)
    retained: dict[str, object] = {}

    class _RuntimeAuthority:
        digest = "d" * 64

    def create_runtime(output: object) -> object:
        execution = getattr(output, "_authority")
        execution_material = production._executor._validated_full_c6_native_output_material(
            execution
        )
        receipt = SimpleNamespace(
            digest="e" * 64,
            target_triple=execution.executor_receipt.target_triple,
        )
        authority = _RuntimeAuthority()
        material = SimpleNamespace(
            output_transaction=output,
            toolchain=execution_material.toolchain,
            runtime_receipt=receipt,
            runtime_inventory=object(),
            path_resolution=SimpleNamespace(inventory=object()),
            transitive_closure=SimpleNamespace(inventory=object()),
        )
        retained.update(runtime=authority, runtime_material=material)
        return authority

    def runtime_material(authority: object) -> object:
        assert authority is retained["runtime"]
        return retained["runtime_material"]

    monkeypatch.setattr(
        production,
        "create_full_c6_native_runtime_authority",
        create_runtime,
    )
    monkeypatch.setattr(
        production,
        "validate_full_c6_native_runtime_authority",
        lambda value: value is retained.get("runtime"),
    )
    monkeypatch.setattr(
        production._native_runtime,
        "_validated_full_c6_native_runtime_material",
        runtime_material,
    )
    monkeypatch.setattr(
        production,
        "collect_component_license_inventory",
        lambda _packages: object(),
    )
    monkeypatch.setattr(
        production,
        "collect_component_license_policy_verification",
        lambda **_kwargs: SimpleNamespace(
            lock_file=EvidenceFileRef(
                "rextio.cargo-license.lock.json",
                "1" * 64,
                10,
                "component-license-policy-lock",
            )
        ),
    )
    monkeypatch.setattr(
        production,
        "collect_project_source_license_policy_verification",
        lambda **_kwargs: SimpleNamespace(
            lock_file=EvidenceFileRef(
                "rextio.source-license.lock.json",
                "2" * 64,
                10,
                "project-source-license-policy-lock",
            )
        ),
    )
    monkeypatch.setattr(
        production,
        "collect_artifact_policy_coverage_inventory",
        lambda **_kwargs: coverage,
    )
    monkeypatch.setattr(
        production,
        "_derive_external_authority",
        lambda _preflight: external,
    )
    monkeypatch.setattr(
        production,
        "_derive_technical_policy_template",
        lambda **_kwargs: _BOOTSTRAP["_technical_template"](),
    )

    if pinned_policy:
        class _SupplyChain:
            def __init__(self, authority_aggregate: object) -> None:
                self.authority_aggregate = authority_aggregate
                self.digest = "f" * 64

        monkeypatch.setattr(production, "FullC6SupplyChainReceipt", _SupplyChain)
        monkeypatch.setattr(
            production,
            "load_configured_full_c6_policy",
            lambda **_kwargs: policy,
        )
        monkeypatch.setattr(
            production,
            "_validate_analysis_transaction",
            lambda *_args, **_kwargs: None,
        )
        monkeypatch.setattr(
            production,
            "_require_policy_matches_fresh_template",
            lambda **_kwargs: None,
        )
        monkeypatch.setattr(
            production,
            "build_full_c6_supply_chain_receipt",
            lambda **kwargs: _SupplyChain(kwargs["authority_aggregate"]),
        )
        monkeypatch.setattr(
            production,
            "verify_full_c6_supply_chain_receipt",
            lambda value, **_kwargs: value,
        )

    authority = production.collect_full_c6_production_authority(
        inputs.preflight,
        project_root=inputs.preflight.analysis.project_root,
        config=config,
        toolchain=inputs.toolchain,
        native_tools=inputs.native_tools,
        cargo_workspace=inputs.cargo_workspace,
        toolchain_support_plan=inputs.toolchain_support_plan,
        toolchain_support_lock=inputs.toolchain_support_lock,
        first_quarantine_root=inputs.roots[0],
        second_quarantine_root=inputs.roots[1],
        state_directory=state_directory,
        base_environment=inputs.base_environment,
        source_date_epoch=1,
    )
    return production, authority


def test_production_collector_exposes_only_the_frozen_owner_api() -> None:
    """The first production seam is explicit, narrow, and injection-resistant."""
    module_name = "rextio.build.full_c6_production"
    assert importlib.util.find_spec(module_name) is not None, (
        "the Full C6 production collector module must exist"
    )
    production = importlib.import_module(module_name)

    assert production.__all__ == [
        "FULL_C6_PRODUCTION_AUTHORITY_DOMAIN",
        "FullC6ProductionAuthority",
        "FullC6ProductionError",
        "collect_full_c6_production_authority",
        "validate_full_c6_production_authority",
    ]
    signature = inspect.signature(
        production.collect_full_c6_production_authority
    )
    assert tuple(signature.parameters) == (
        "preflight",
        "project_root",
        "config",
        "toolchain",
        "native_tools",
        "cargo_workspace",
        "toolchain_support_plan",
        "toolchain_support_lock",
        "first_quarantine_root",
        "second_quarantine_root",
        "state_directory",
        "base_environment",
        "source_date_epoch",
    )
    parameters = tuple(signature.parameters.values())
    assert parameters[0].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert all(
        parameter.kind is inspect.Parameter.KEYWORD_ONLY
        for parameter in parameters[1:]
    )
    assert "subject" not in signature.parameters
    assert "wheel_entries" not in signature.parameters
    assert "executor_receipt" not in signature.parameters
    assert "runtime_authorization" not in signature.parameters
    assert "supply_chain" not in signature.parameters
    assert not hasattr(production.FullC6ProductionAuthority, "finalization_materials")
    assert "_validated_full_c6_production_material" not in production.__all__


def test_exact_legacy_sourcelock_verifies_but_cannot_enter_production(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    production = importlib.import_module("rextio.build.full_c6_production")
    inputs = _EXTERNAL["_inputs"](
        tmp_path,
        monkeypatch,
        legacy_source_lock=True,
    )
    verification = inputs.preflight.context.source_verification
    assert verification.admission.status == "admitted"
    assert verification.context is not None

    reached_execution = False

    def forbidden_execution(*_args: object, **_kwargs: object) -> object:
        nonlocal reached_execution
        reached_execution = True
        raise AssertionError("legacy SourceLock must fail before native execution")

    monkeypatch.setattr(
        production,
        "execute_full_c6_external_build",
        forbidden_execution,
    )
    state_directory = tmp_path / "legacy-production-state"
    state_directory.mkdir(mode=0o700)
    with pytest.raises(
        production.FullC6ProductionError,
        match="requires current SourceLock manifest and signature dialects",
    ):
        production.collect_full_c6_production_authority(
            inputs.preflight,
            project_root=inputs.preflight.analysis.project_root,
            config=inputs.config,
            toolchain=inputs.toolchain,
            native_tools=inputs.native_tools,
            cargo_workspace=inputs.cargo_workspace,
            toolchain_support_plan=inputs.toolchain_support_plan,
            toolchain_support_lock=inputs.toolchain_support_lock,
            first_quarantine_root=inputs.roots[0],
            second_quarantine_root=inputs.roots[1],
            state_directory=state_directory,
            base_environment=inputs.base_environment,
            source_date_epoch=1,
        )
    assert reached_execution is False


def test_prerequisites_require_the_exact_cargo_source_authority_object(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    production = importlib.import_module("rextio.build.full_c6_production")
    inputs = _EXTERNAL["_inputs"](tmp_path, monkeypatch)
    config = replace(
        inputs.config,
        build=replace(
            inputs.config.build,
            artifact_policy_manifest="locks/rextio.artifact-policy.json",
        ),
    )
    cloned_sources = replace(inputs.toolchain.cargo_sources)
    cloned_toolchain = replace(inputs.toolchain, cargo_sources=cloned_sources)
    assert cloned_sources == inputs.cargo_workspace.cargo_sources
    assert cloned_sources.digest == inputs.cargo_workspace.cargo_sources.digest
    assert cloned_sources is not inputs.cargo_workspace.cargo_sources
    executed = False

    def forbidden_execution(*_args: object, **_kwargs: object) -> None:
        nonlocal executed
        executed = True
        raise AssertionError("executor must not receive split Cargo authority")

    monkeypatch.setattr(
        production,
        "execute_full_c6_external_build",
        forbidden_execution,
    )
    with pytest.raises(production.FullC6ProductionError, match="Cargo workspace differ"):
        production.collect_full_c6_production_authority(
            inputs.preflight,
            project_root=inputs.preflight.analysis.project_root,
            config=config,
            toolchain=cloned_toolchain,
            native_tools=inputs.native_tools,
            cargo_workspace=inputs.cargo_workspace,
            toolchain_support_plan=inputs.toolchain_support_plan,
            toolchain_support_lock=inputs.toolchain_support_lock,
            first_quarantine_root=inputs.roots[0],
            second_quarantine_root=inputs.roots[1],
            state_directory=tmp_path / "unused-state",
            base_environment=inputs.base_environment,
            source_date_epoch=1,
        )
    assert executed is False


def test_production_forwards_exact_support_objects_to_external_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    production = importlib.import_module("rextio.build.full_c6_production")
    inputs = _EXTERNAL["_inputs"](tmp_path, monkeypatch)
    config = replace(
        inputs.config,
        build=replace(
            inputs.config.build,
            artifact_policy_manifest="locks/rextio.artifact-policy.json",
        ),
    )
    observed = False

    def stop_after_boundary(*_args: object, **kwargs: object) -> None:
        nonlocal observed
        assert kwargs["toolchain_support_plan"] is inputs.toolchain_support_plan
        assert kwargs["toolchain_support_lock"] is inputs.toolchain_support_lock
        observed = True
        raise RuntimeError("stop after exact support propagation")

    monkeypatch.setattr(
        production,
        "execute_full_c6_external_build",
        stop_after_boundary,
    )

    with pytest.raises(production.FullC6ProductionError):
        production.collect_full_c6_production_authority(
            inputs.preflight,
            project_root=inputs.preflight.analysis.project_root,
            config=config,
            toolchain=inputs.toolchain,
            native_tools=inputs.native_tools,
            cargo_workspace=inputs.cargo_workspace,
            toolchain_support_plan=inputs.toolchain_support_plan,
            toolchain_support_lock=inputs.toolchain_support_lock,
            first_quarantine_root=inputs.roots[0],
            second_quarantine_root=inputs.roots[1],
            state_directory=tmp_path / "unused-state",
            base_environment=inputs.base_environment,
            source_date_epoch=1,
        )
    assert observed is True


def test_production_source_date_epoch_matches_the_executor_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    production = importlib.import_module("rextio.build.full_c6_production")
    inputs = _EXTERNAL["_inputs"](tmp_path, monkeypatch)
    config = replace(
        inputs.config,
        build=replace(
            inputs.config.build,
            artifact_policy_manifest="locks/rextio.artifact-policy.json",
        ),
    )
    arguments = {
        "preflight": inputs.preflight,
        "project_root": inputs.preflight.analysis.project_root,
        "config": config,
        "toolchain": inputs.toolchain,
        "native_tools": inputs.native_tools,
        "cargo_workspace": inputs.cargo_workspace,
        "toolchain_support_plan": inputs.toolchain_support_plan,
        "toolchain_support_lock": inputs.toolchain_support_lock,
    }

    assert production._require_production_inputs(
        **arguments,
        source_date_epoch=2_147_483_647,
    ) == inputs.preflight.analysis.project_root
    with pytest.raises(production.FullC6ProductionError, match="prerequisites"):
        production._require_production_inputs(
            **arguments,
            source_date_epoch=2_147_483_648,
        )


def test_production_support_boundary_revalidates_critical_leaves_without_full_walk(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    production = importlib.import_module("rextio.build.full_c6_production")
    support_closure = importlib.import_module(
        "rextio.build.full_c6_toolchain_support"
    )
    inputs = _EXTERNAL["_inputs"](tmp_path, monkeypatch)
    critical_calls = 0
    full_walk_calls = 0
    revalidate = production.revalidate_full_c6_toolchain_support_plan

    def observe_critical(plan: object) -> object:
        nonlocal critical_calls
        critical_calls += 1
        return revalidate(plan)

    def forbidden_full_walk(*_args: object, **_kwargs: object) -> bool:
        nonlocal full_walk_calls
        full_walk_calls += 1
        raise AssertionError("production boundary must not repeat the full support walk")

    monkeypatch.setattr(
        production,
        "revalidate_full_c6_toolchain_support_plan",
        observe_critical,
    )
    monkeypatch.setattr(
        support_closure,
        "verify_full_c6_toolchain_support_lock",
        forbidden_full_walk,
    )

    assert production._require_production_toolchain_support(
        inputs.toolchain_support_plan,
        inputs.toolchain_support_lock,
        toolchain=inputs.toolchain,
        revalidate_paths=True,
    ) is inputs.toolchain_support_plan
    assert critical_calls == 1
    assert full_walk_calls == 0


def test_production_support_boundary_normalizes_mutated_lock_property_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    production = importlib.import_module("rextio.build.full_c6_production")
    inputs = _EXTERNAL["_inputs"](tmp_path, monkeypatch)
    for error_type in (
        ToolchainSupportLockError,
        AttributeError,
        TypeError,
        ValueError,
    ):
        def fail_raw_digest(_lock: ToolchainSupportLock) -> str:
            raise error_type("simulated mutated support-lock property")

        with monkeypatch.context() as patch:
            patch.setattr(
                ToolchainSupportLock,
                "raw_sha256",
                property(fail_raw_digest),
            )
            with pytest.raises(
                production.FullC6ProductionError,
                match="toolchain support authority failed closed",
            ) as caught:
                production._require_production_toolchain_support(
                    inputs.toolchain_support_plan,
                    inputs.toolchain_support_lock,
                    toolchain=inputs.toolchain,
                    revalidate_paths=False,
                )
        assert isinstance(caught.value.__cause__, error_type)


def test_collector_mints_one_sealed_path_free_non_authorizing_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    production = importlib.import_module("rextio.build.full_c6_production")
    digest = "a" * 64

    class _Invocation:
        def __init__(self, ordinal: int) -> None:
            self.ordinal = ordinal
            self.private_host_path = tmp_path / f"private-{ordinal}"

        def to_dict(self) -> dict[str, object]:
            return {
                "ordinal": self.ordinal,
                "argv_sha256": digest,
                "argv_count": 6,
                "environment": [
                    {
                        "name": "HOME",
                        "value_sha256": digest,
                        "value_size": 18,
                    }
                ],
                "timeout_seconds": 60.0,
                "max_output_bytes": 4096,
                "inherit_env": False,
                "sandbox_engine": "linux-bwrap-landlock-v1",
                "sandbox_plan_sha256": digest,
                "sandbox_profile_sha256": digest,
                "sandbox_seccomp_sha256": digest,
            }

    class _Digest:
        def __init__(self, value: str = digest) -> None:
            self.digest = value

    class _Aggregate(_Digest):
        def to_dict(self) -> dict[str, object]:
            return {"bindings": {"analysis_ir_transaction_sha256": self.digest}}

    executor_receipt = _Digest()
    executor_receipt.toolchain_sha256 = digest
    executor_receipt.invocations = (_Invocation(1), _Invocation(2))

    material = production._FullC6ProductionMaterial(
        preflight=object(),
        project_root=tmp_path,
        config=object(),
        lifecycle=SimpleNamespace(status="signing-required"),
        analysis_ir_transaction=_Digest(),
        license_materials_transaction=_Digest(),
        output_license_contract=object(),
        cargo_workspace=_Digest(),
        toolchain_support_plan=SimpleNamespace(digest=digest),
        toolchain_support_lock=SimpleNamespace(
            raw_sha256=digest,
            merkle_sha256=digest,
        ),
        native_execution_authority=_Digest(),
        native_output_transaction=_Digest(),
        subject_wheel_transaction=_Digest(),
        native_runtime_authority=_Digest(),
        runtime_authorization=_Digest(),
        executor_receipt=executor_receipt,
        build_inputs=_Digest(),
        cargo_path_source=_Digest(),
        artifact_coverage=_Digest(),
        external_authority=SimpleNamespace(canonical_partition_sha256=digest),
        authority_aggregate=_Aggregate(),
        technical_policy_template=SimpleNamespace(template_sha256=digest),
        bootstrap_inputs=object(),
        bootstrap_request=SimpleNamespace(request_sha256=digest),
    )
    monkeypatch.setattr(
        production,
        "_collect_full_c6_production_material",
        lambda *_args, **_kwargs: material,
    )
    monkeypatch.setattr(production, "_validate_material", lambda value: value is material)
    monkeypatch.setattr(
        production,
        "artifact_policy_coverage_inventory_digest",
        lambda _value: digest,
    )

    authority = production.collect_full_c6_production_authority(
        object(),
        project_root=tmp_path,
        config=object(),
        toolchain=object(),
        native_tools=object(),
        cargo_workspace=object(),
        toolchain_support_plan=object(),
        toolchain_support_lock=object(),
        first_quarantine_root=tmp_path / "first",
        second_quarantine_root=tmp_path / "second",
        state_directory=tmp_path / "state",
        base_environment=None,
        source_date_epoch=1,
    )

    assert type(authority) is production.FullC6ProductionAuthority
    assert production.validate_full_c6_production_authority(authority)
    with pytest.raises(TypeError):
        production.FullC6ProductionAuthority()
    with pytest.raises(TypeError):
        copy.copy(authority)
    with pytest.raises(TypeError):
        copy.deepcopy(authority)
    with pytest.raises(TypeError):
        pickle.dumps(authority)

    projected = authority.to_dict()
    assert str(tmp_path) not in repr(projected)
    assert projected["executor_receipt_sha256"] == digest
    assert projected["executor_toolchain_sha256"] == digest
    assert projected["executor_invocations"] == [
        executor_receipt.invocations[0].to_dict(),
        executor_receipt.invocations[1].to_dict(),
    ]
    assert projected["complete_for_scope"] is True
    assert projected["signed"] is False
    assert projected["distribution_authorized"] is False
    assert projected["authorizes_distribution"] is False
    assert projected["executor_invocation_count"] == 2
    assert authority.lifecycle.status == "signing-required"

    object.__setattr__(authority, "_material", copy.copy(material))
    assert not production.validate_full_c6_production_authority(authority)
    with pytest.raises(production.FullC6ProductionError, match="stale"):
        authority.to_dict()


def test_real_c52_execution_mints_bootstrap_required_production_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    production, authority = _collect_bounded_production_authority(
        tmp_path,
        monkeypatch,
    )

    assert production.validate_full_c6_production_authority(authority)
    assert authority.lifecycle.status == "bootstrap-required"
    request = authority.bootstrap_request
    assert request is not None
    assert request.inputs is authority._material.bootstrap_inputs
    assert authority.to_dict()["bootstrap_request_sha256"] == request.request_sha256
    output_license = authority._material.output_license_contract
    assert output_license.external_source_distribution == "demo-pkg"
    assert output_license.external_source_version == "1.0.0"
    assert output_license.source_lock_verification_sha256 is not None
    assert any(
        item.path == "external/demo-pkg/1.0.0/LICENSE"
        for item in output_license.files
    )
    bindings = authority.authority_aggregate.to_dict()["bindings"]
    assert tuple(bindings) == (
        "analysis_ir_transaction_sha256",
        "license_materials_transaction_sha256",
        "output_license_contract_sha256",
        "cargo_workspace_sha256",
        "native_execution_authority_sha256",
        "native_output_transaction_sha256",
        "subject_wheel_transaction_sha256",
        "native_runtime_authority_sha256",
        "runtime_authorization_sha256",
        "executor_receipt_sha256",
    )
    assert production._validated_full_c6_production_material(authority) is authority._material


@pytest.mark.parametrize("nested", ("target-build-options", "import-packages"))
def test_nested_effective_config_mutation_stales_production_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    nested: str,
) -> None:
    production, authority = _collect_bounded_production_authority(
        tmp_path,
        monkeypatch,
    )
    config = authority._material.config
    if nested == "target-build-options":
        config.target.build_options["profile"] = "debug"
    else:
        package = config.imports.packages["demo_pkg"]
        config.imports.packages["demo_pkg"] = replace(package, version="1.0.1")

    assert not production.validate_full_c6_production_authority(authority)


def test_pinned_policy_authority_exposes_only_private_validated_material(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    production, authority = _collect_bounded_production_authority(
        tmp_path,
        monkeypatch,
        pinned_policy=True,
    )

    assert production.validate_full_c6_production_authority(authority)
    assert authority.lifecycle.status == "signing-required"
    assert authority.bootstrap_request is None
    projected = authority.to_dict()
    assert projected["policy_sha256"] is not None
    assert projected["supply_chain_sha256"] == "f" * 64
    assert projected["signed"] is False
    assert projected["distribution_authorized"] is False

    material = production._validated_full_c6_production_material(authority)
    assert material is authority._material
    assert material.policy is authority._material.policy
    assert material.supply_chain is authority._material.supply_chain
    assert material.runtime_authorization is authority._material.runtime_authorization
    assert material.executor_receipt is authority._material.executor_receipt


def test_fresh_template_accepts_only_the_exact_finalized_policy(tmp_path: Path) -> None:
    production = importlib.import_module("rextio.build.full_c6_production")
    bootstrap = _BOOTSTRAP["_request"](tmp_path)
    completion = _COMPLETION["_completion"](bootstrap)
    manifest = finalize_full_c6_policy_manifest(
        bootstrap=bootstrap,
        completion=completion,
    )
    policy = parse_full_c6_policy_manifest(
        manifest,
        expected_sha256=sha256_hex(manifest),
    )

    production._require_policy_matches_fresh_template(
        policy=policy,
        bootstrap_request=bootstrap,
    )

    row_index = next(
        index
        for index, row in enumerate(policy.rows)
        if row.class_id == "wheel-entry:other"
    )
    rows = list(policy.rows)
    rows[row_index] = replace(
        rows[row_index],
        canonical_identity=f"{rows[row_index].canonical_identity}.changed",
        size=(rows[row_index].size or 0) + 1,
    )
    changed = replace(policy, rows=tuple(rows))
    with pytest.raises(production.FullC6ProductionError, match="fresh observation"):
        production._require_policy_matches_fresh_template(
            policy=changed,
            bootstrap_request=bootstrap,
        )

    with pytest.raises(production.FullC6ProductionError, match="lineage is stale"):
        production._require_policy_matches_fresh_template(
            policy=replace(policy, bootstrap_request_sha256="0" * 64),
            bootstrap_request=bootstrap,
        )


def test_fresh_template_rejects_fabricated_internal_license_bytes(
    tmp_path: Path,
) -> None:
    production = importlib.import_module("rextio.build.full_c6_production")
    bootstrap = _BOOTSTRAP["_request"](tmp_path)
    completion = _COMPLETION["_completion"](bootstrap)
    manifest = finalize_full_c6_policy_manifest(
        bootstrap=bootstrap,
        completion=completion,
    )
    policy = parse_full_c6_policy_manifest(
        manifest,
        expected_sha256=sha256_hex(manifest),
    )
    row_index = next(
        index
        for index, row in enumerate(policy.rows)
        if row.class_id == "file-input:project-python-source"
    )
    row = policy.rows[row_index]
    evidence = row.license_evidence
    assert evidence is not None
    files = (
        FullC6PolicyFileIdentity(
            logical_path="licenses/FABRICATED-LICENSE",
            sha256="9" * 64,
            size=101,
            role="license-file",
        ),
    )
    changed_evidence = replace(
        evidence,
        license_files=files,
        detector_payload_sha256=full_c6_license_detector_payload_digest(
            evidence.detected_spdx,
            files,
            source_detector_receipt_sha256=(
                evidence.source_detector_receipt_sha256
            ),
        ),
    )
    rows = list(policy.rows)
    rows[row_index] = replace(row, license_evidence=changed_evidence)
    changed = replace(policy, rows=tuple(rows))

    with pytest.raises(production.FullC6ProductionError, match="exact license bytes"):
        production._require_policy_matches_fresh_template(
            policy=changed,
            bootstrap_request=bootstrap,
        )


def test_deep_validator_rejects_equal_retained_receipt_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    production, authority = _collect_bounded_production_authority(
        tmp_path,
        monkeypatch,
    )
    material = authority._material
    replacement = replace(material.executor_receipt)
    assert replacement == material.executor_receipt
    assert replacement is not material.executor_receipt
    forged_material = replace(material, executor_receipt=replacement)
    forged = object.__new__(production.FullC6ProductionAuthority)
    object.__setattr__(forged, "_material", forged_material)
    object.__setattr__(forged, "_transaction_seal", production._seal(forged))

    assert not production._validate_material(forged_material)
    assert not production.validate_full_c6_production_authority(forged)


def test_deep_validator_requires_execution_and_workspace_cargo_source_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    production, authority = _collect_bounded_production_authority(
        tmp_path,
        monkeypatch,
    )
    material = authority._material
    original = production._executor._validated_full_c6_native_output_material
    execution_material = original(material.native_execution_authority)
    cloned_sources = replace(execution_material.toolchain.cargo_sources)
    cloned_toolchain = replace(
        execution_material.toolchain,
        cargo_sources=cloned_sources,
    )
    split_execution_material = replace(
        execution_material,
        toolchain=cloned_toolchain,
    )
    assert cloned_sources == material.cargo_workspace.cargo_sources
    assert cloned_sources is not material.cargo_workspace.cargo_sources
    monkeypatch.setattr(
        production._executor,
        "_validated_full_c6_native_output_material",
        lambda value: (
            split_execution_material
            if value is material.native_execution_authority
            else original(value)
        ),
    )
    runtime_reached = False

    def forbidden_runtime(_value: object) -> object:
        nonlocal runtime_reached
        runtime_reached = True
        raise AssertionError("split Cargo authority must fail before runtime validation")

    monkeypatch.setattr(
        production._native_runtime,
        "_validated_full_c6_native_runtime_material",
        forbidden_runtime,
    )

    assert not production._validate_material(material)
    assert runtime_reached is False


def test_production_regeneration_rebinds_the_exact_executed_source_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    production = importlib.import_module("rextio.build.full_c6_production")
    inputs = _EXTERNAL["_inputs"](tmp_path, monkeypatch)
    execution = _EXTERNAL["_execute"](inputs)

    generated, snapshot = production._regenerate_production_inputs(
        root=inputs.preflight.analysis.project_root,
        preflight=inputs.preflight,
        config=inputs.config,
        cargo_workspace=inputs.cargo_workspace,
        execution=execution,
    )

    assert generated.plan.analysis is inputs.preflight.analysis
    assert snapshot.unavailable_reason is None
    assert snapshot.cargo_lock is not None
    assert snapshot.cargo_lock.sha256 == inputs.cargo_workspace.cargo_sources.lock_file.sha256
    assert not any(
        item.logical_path.endswith("/.cargo/config.toml")
        for item in snapshot.generated_rust
    )
    assert any(
        item.logical_path.endswith("/src/lib.rs")
        for item in snapshot.generated_rust
    )


def test_external_partition_is_derived_from_the_exact_sourcelock_universe(
    tmp_path: Path,
) -> None:
    production = importlib.import_module("rextio.build.full_c6_production")
    preflight, _config = _EXTERNAL["_project_preflight"](tmp_path)

    partition = production._derive_external_authority(preflight)
    context = preflight.context.source_verification.context
    assert context is not None
    counts = {item.class_id: item.observed_count for item in partition.classes}
    assert counts["external-source:wheel-archive"] == 1
    assert counts["external-source:python-source"] == len(
        context.wheel.source_entry_paths
    )
    assert counts["external-source:license-file"] == len(
        context.wheel.license_entry_paths
    )
    assert partition.observed_component_count == 1 + len(context.manifest.entries)


def test_production_root_must_preserve_preflight_lexical_and_resolved_identity(
    tmp_path: Path,
) -> None:
    production = importlib.import_module("rextio.build.full_c6_production")
    preflight, _config = _EXTERNAL["_project_preflight"](tmp_path)
    root = preflight.analysis.project_root
    assert production._require_project_root(preflight, root) == root

    with pytest.raises(production.FullC6ProductionError, match="project root"):
        production._require_project_root(preflight, root / ".." / root.name)


@pytest.mark.parametrize(
    ("captured_generated", "project_path"),
    (
        (
            ".rextio/generated/python/Wrapper.py",
            "generated/python/wrapper.py",
        ),
        (
            ".rextio/generated/python/caf\N{LATIN SMALL LETTER E WITH ACUTE}.py",
            "generated/python/cafe\N{COMBINING ACUTE ACCENT}.py",
        ),
    ),
)
def test_generated_build_input_mapping_rejects_casefold_and_nfc_aliases(
    captured_generated: str,
    project_path: str,
) -> None:
    production = importlib.import_module("rextio.build.full_c6_production")
    generated = EvidenceFileRef(
        "generated-python.py",
        "1" * 64,
        1,
        "generated-python-input",
    )
    project = EvidenceFileRef(
        "project.py",
        "2" * 64,
        1,
        "project-python-source",
    )
    # Model a forged/noncanonical retained reference to exercise the collector's
    # own alias barrier before ExactFileIdentity performs its ASCII validation.
    object.__setattr__(generated, "logical_path", captured_generated)
    object.__setattr__(project, "logical_path", project_path)
    cargo_lock = EvidenceFileRef(
        "rextio.cargo-license.lock.json",
        "3" * 64,
        1,
        "component-license-policy-lock",
    )
    source_lock = EvidenceFileRef(
        "rextio.source-license.lock.json",
        "4" * 64,
        1,
        "project-source-license-policy-lock",
    )

    with pytest.raises(production.FullC6ProductionError, match="overlap"):
        production._build_input_closure(
            config=RextioConfig(),
            input_snapshot=SimpleNamespace(all_inputs=(generated, project)),
            analysis_inputs=SimpleNamespace(records=()),
            component_license_policy=SimpleNamespace(lock_file=cargo_lock),
            source_license_policy=SimpleNamespace(lock_file=source_lock),
            cargo_workspace=object(),
        )
