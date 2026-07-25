"""Plugin API 1.6 static device-domain planning and lowering authorization."""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import rextio.build.orchestrator as orchestrator
from rextio.analyzer.project_scanner import analyze_project
from rextio.artifacts.models import (
    ArtifactKind,
    CertificationTier,
    RuntimeRequirement,
    TargetCapability,
)
from rextio.config.schema import RextioConfig
from rextio.codegen.rust.errors import RustCodegenError
from rextio.devices import (
    DEVICE_PROVIDER_ENTRY_POINT,
    DeviceBuildContribution,
    DeviceLoweringAuthorization,
    DevicePreflightRequest,
    DevicePreflightResult,
    DeviceProviderError,
    DeviceProviderManifest,
    DeviceProviderOptions,
    DeviceProviderSelection,
    DeviceValueMetadata,
    derive_device_requirements,
)
from rextio.ir.lowering import lower_project
from rextio.plugins.api import (
    BoundaryConversion,
    Claimed,
    ClaimSite,
    LoweredExpr,
    LoweringContext,
    PluginType,
)
from rextio.plugins.models import (
    PluginProviderBinding,
    PluginRegistry,
    PluginTypeBinding,
    RextioPlugin,
)
from rextio.targets.models import TargetSpec
from rextio.targets.plan import TargetPlan


PLUGIN_ID = "rextio-torch"
TYPE_KEY = f"{PLUGIN_ID}/cuda-f32-rank2"
LIBTORCH_REQUIREMENTS = (
    RuntimeRequirement("libtorch", "2.11.0", ("cuda", "pytorch-wheel")),
    RuntimeRequirement("tch", "0.24.0", ("cuda",)),
)
CUDA_METADATA = DeviceValueMetadata(
    logical_device="cuda:0",
    dtype="float32",
    rank=2,
    layout="strided",
    runtime="libtorch",
    runtime_version="2.11.0",
    reuse_domain_runtime=True,
    features=("inference", "no-grad"),
    memory_spaces=("device",),
    runtime_requirements=LIBTORCH_REQUIREMENTS,
)
CUDA_TYPE = PluginType(
    key=TYPE_KEY,
    annotations=("torch.Tensor",),
    rust_type="i64",
    conversion=BoundaryConversion(
        param_rust="i64",
        param_expr="*{param}",
        return_rust="i64",
        return_expr="{value}",
    ),
    device_value_metadata=CUDA_METADATA,
)


class _TorchProvider:
    plugin_id = PLUGIN_ID
    api_version = "1.6"

    def __init__(self) -> None:
        self.authorizations: list[DeviceLoweringAuthorization | None] = []

    def claim(self, site: ClaimSite, config: RextioConfig):
        del config
        if site.kind == "binop" and site.target == "+":
            return Claimed(rule_id=f"{PLUGIN_ID}/add", result_type=TYPE_KEY)
        raise AssertionError(f"unexpected claim site: {site.kind}/{site.target}")

    def lower(self, site: ClaimSite, ctx: LoweringContext) -> LoweredExpr:
        del site
        self.authorizations.append(ctx.device_authorization)
        return LoweredExpr(rust=f"({ctx.operands[0]} + {ctx.operands[1]})")


def _registry(provider: _TorchProvider) -> PluginRegistry:
    plugin = RextioPlugin(
        id=PLUGIN_ID,
        name="Torch test plugin",
        packages=("torch",),
        rules_provided=True,
        api_version="1.6",
        lowering_provided=True,
    )
    return PluginRegistry(
        enabled=(PLUGIN_ID,),
        discovered=(plugin,),
        active=(plugin,),
        types=(PluginTypeBinding(plugin_id=PLUGIN_ID, plugin_type=CUDA_TYPE),),
        providers=(PluginProviderBinding(plugin_id=PLUGIN_ID, provider=provider),),
    )


@dataclass
class _Dist:
    name: str = "rextio-device-test-cuda"
    version: str = "0.1.0"


class _EntryPoint:
    group = DEVICE_PROVIDER_ENTRY_POINT
    name = "test-cuda"
    value = "rextio_device_test_cuda:provider"
    dist = _Dist()

    def __init__(self, provider: object) -> None:
        self.provider = provider

    def load(self) -> object:
        return self.provider


class _CudaProvider:
    def __init__(self, target_triple: str, *, backend: str = "cuda") -> None:
        self.target_triple = target_triple
        self.backend = backend
        self.seen_profile = None

    def manifest(self) -> DeviceProviderManifest:
        return DeviceProviderManifest(
            provider_id="test-cuda",
            display_name="Test CUDA provider",
            backend=self.backend,
            capabilities=(
                TargetCapability(
                    id="libtorch-cuda",
                    target_triples=(self.target_triple,),
                    artifact_kinds=(ArtifactKind.HOST_EXTENSION,),
                    accelerator_backends=(self.backend,),
                    architectures=("sm_80",),
                    certification_tier=CertificationTier.BUILD_ONLY,
                    evidence_references=("tests/synthetic-build-only.json",),
                ),
            ),
        )

    def preflight(self, request: DevicePreflightRequest) -> DevicePreflightResult:
        self.seen_profile = request.artifact_profile
        [requirement] = request.artifact_profile.device_requirements
        assert requirement.runtime == "libtorch"
        assert requirement.features == ("inference", "no-grad")
        assert requirement.layouts == ("strided",)
        assert requirement.memory_spaces == ("device",)
        assert requirement.architectures == ("sm_80",)
        assert requirement.reuse_domain_runtime is True
        runtime_rows = {
            (item.name, item.version, item.features)
            for item in request.artifact_profile.runtime_requirements
        }
        assert {
            ("libtorch", "2.11.0", ("cuda", "pytorch-wheel")),
            ("tch", "0.24.0", ("cuda",)),
        }.issubset(runtime_rows)
        return DevicePreflightResult(provider_id="test-cuda", status="ready")

    def build_contribution(
        self, request: DevicePreflightRequest
    ) -> DeviceBuildContribution:
        del request
        return DeviceBuildContribution()


def _analysis_and_plan(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "from torch import Tensor\n"
        "\n"
        "def add(left: Tensor, right: Tensor) -> Tensor:\n"
        "    return left + right\n",
        encoding="utf-8",
    )
    provider = _TorchProvider()
    registry = _registry(provider)
    analysis = analyze_project(
        tmp_path,
        plugin_registry=registry,
        plugin_config=RextioConfig(),
    )
    return analysis, TargetPlan(TargetSpec(), registry), provider


def test_accepted_analysis_drives_profile_resolver_and_lowering_authorization(
    tmp_path: Path,
) -> None:
    analysis, target_plan, torch_provider = _analysis_and_plan(tmp_path)
    target_triple = orchestrator._required_host_target_triple()
    cuda_provider = _CudaProvider(target_triple)

    result = orchestrator.generate_source_artifact(
        tmp_path,
        analysis,
        "cpython",
        target_plan=target_plan,
        device_selection=DeviceProviderSelection("test-cuda", "libtorch-cuda"),
        device_options=DeviceProviderOptions((("sm", "sm_80"),)),
        device_entry_points=(_EntryPoint(cuda_provider),),
    )

    [profile] = result.plan.artifact_profiles
    assert profile == cuda_provider.seen_profile
    assert profile.device_requirements[0].backend == "cuda"
    [authorization] = torch_provider.authorizations
    assert authorization is not None
    assert authorization.provider_id == "test-cuda"
    assert authorization.capability_id == "libtorch-cuda"
    assert authorization.authorizes(CUDA_METADATA)
    assert not authorization.authorizes(
        replace(CUDA_METADATA, features=("inference",))
    )
    assert not authorization.authorizes(
        replace(CUDA_METADATA, layout="channels-last")
    )
    assert not authorization.authorizes(
        replace(CUDA_METADATA, memory_spaces=("host",))
    )
    assert authorization.to_dict()["features"] == ["inference", "no-grad"]
    assert authorization.to_dict()["layouts"] == ["strided"]
    assert authorization.to_dict()["memory_spaces"] == ["device"]
    assert result.device_provider_plans[0]["lowering_authorization"] == (
        authorization.to_dict()
    )


def test_accelerator_type_requires_explicit_provider_before_codegen(
    tmp_path: Path,
) -> None:
    analysis, target_plan, _provider = _analysis_and_plan(tmp_path)

    with pytest.raises(
        DeviceProviderError,
        match="requires an explicit device provider selection",
    ):
        orchestrator.generate_source_artifact(
            tmp_path,
            analysis,
            "cpython",
            target_plan=target_plan,
        )


def test_wrong_provider_backend_fails_before_codegen(tmp_path: Path) -> None:
    analysis, target_plan, torch_provider = _analysis_and_plan(tmp_path)
    target_triple = orchestrator._required_host_target_triple()

    with pytest.raises(
        DeviceProviderError,
        match="does not match artifact requirements|incompatible",
    ):
        orchestrator.generate_source_artifact(
            tmp_path,
            analysis,
            "cpython",
            target_plan=target_plan,
            device_selection=DeviceProviderSelection("test-cuda", "libtorch-cuda"),
            device_options=DeviceProviderOptions((("sm", "sm_80"),)),
            device_entry_points=(
                _EntryPoint(_CudaProvider(target_triple, backend="rocm")),
            ),
        )

    assert torch_provider.authorizations == []


def test_wrong_provider_capability_fails_before_codegen(tmp_path: Path) -> None:
    analysis, target_plan, torch_provider = _analysis_and_plan(tmp_path)
    target_triple = orchestrator._required_host_target_triple()

    with pytest.raises(DeviceProviderError, match="does not declare capability"):
        orchestrator.generate_source_artifact(
            tmp_path,
            analysis,
            "cpython",
            target_plan=target_plan,
            device_selection=DeviceProviderSelection("test-cuda", "wrong-lane"),
            device_options=DeviceProviderOptions((("sm", "sm_80"),)),
            device_entry_points=(_EntryPoint(_CudaProvider(target_triple)),),
        )

    assert torch_provider.authorizations == []


@pytest.mark.parametrize(
    ("values", "match"),
    [
        (
            (
                DeviceValueMetadata(logical_device="cpu"),
                CUDA_METADATA,
            ),
            "mix CPU and accelerator",
        ),
        (
            (
                CUDA_METADATA,
                DeviceValueMetadata(
                    logical_device="cuda:0",
                    runtime="cuda-driver",
                ),
            ),
            "conflicting accelerator",
        ),
        (
            (
                DeviceValueMetadata(
                    logical_device="cuda:1",
                    runtime="libtorch",
                    reuse_domain_runtime=True,
                ),
            ),
            "only static gpu:0",
        ),
    ],
)
def test_conflicting_static_device_domains_fail_closed(
    values: tuple[DeviceValueMetadata, ...],
    match: str,
) -> None:
    with pytest.raises(ValueError, match=match):
        derive_device_requirements(values)


def test_fallback_only_accelerator_type_does_not_require_provider() -> None:
    analysis = SimpleNamespace(
        accepted_native_functions=(),
        rejected_native_functions=(
            SimpleNamespace(plugin_type_keys=(TYPE_KEY,), plugin_claims=()),
        ),
    )
    target_plan = TargetPlan(TargetSpec(), _registry(_TorchProvider()))

    assert orchestrator._accepted_device_profile_requirements(
        analysis,
        target_plan,
        DeviceProviderOptions(),
    ) == ((), ())


def test_codegen_rejects_accelerator_claim_without_authorization(
    tmp_path: Path,
) -> None:
    analysis, target_plan, provider = _analysis_and_plan(tmp_path)
    plugin_types, plugin_providers, by_key = orchestrator._plugin_lowering_inputs(
        target_plan
    )
    module_ir = lower_project(analysis, plugin_types=plugin_types)

    with pytest.raises(
        RustCodegenError,
        match="without a Core-resolved device authorization",
    ):
        orchestrator.generate_rust_module(
            module_ir,
            plugin_providers=plugin_providers,
            plugin_types_by_key=by_key,
        )

    assert provider.authorizations == []
