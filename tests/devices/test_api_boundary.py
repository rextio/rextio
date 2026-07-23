from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from rextio.artifacts.models import (
    ArtifactKind,
    CertificationTier,
    DeviceRequirement,
    RuntimeRequirement,
    TargetCapability,
)
from rextio.artifacts.profiles import host_executable_profile, host_extension_profile
from rextio.devices import (
    DEVICE_PROVIDER_API_VERSION,
    DeviceBuildContribution,
    DevicePreflightRequest,
    DevicePreflightResult,
    DevicePreflightStatus,
    DeviceProvider,
    DeviceProviderError,
    DeviceProviderManifest,
    DeviceProviderOptions,
    DeviceProviderSelection,
    DeviceProviderSource,
    DeviceResourceAccess,
    DeviceResourceContract,
    DeviceResourceOwner,
    DeviceValueMetadata,
    normalize_device_id,
    resolve_device_plan,
)


def _manifest() -> DeviceProviderManifest:
    return DeviceProviderManifest(
        provider_id="example-device",
        display_name="Example Device",
        provider_version="1.2.3",
        backend="cuda",
        capabilities=(
            TargetCapability(
                id="windows-cuda-build-only",
                target_triples=("x86_64-pc-windows-msvc",),
                artifact_kinds=(ArtifactKind.HOST_EXECUTABLE,),
                cpu_feature_level="x86-64-v2",
                accelerator_backends=("cuda",),
                minimum_runtime_version="12.8",
                minimum_driver_version="570",
                architectures=("sm_80", "sm_90"),
                certification_tier=CertificationTier.BUILD_ONLY,
                evidence_references=("cuda-driver-probe",),
            ),
        ),
        runtime_requirements=(RuntimeRequirement("cuda-driver"),),
    )


class _StructuralProvider:
    def manifest(self) -> DeviceProviderManifest:
        return _manifest()

    def preflight(self, request: DevicePreflightRequest) -> DevicePreflightResult:
        assert request.artifact_profile.target_triple == "x86_64-pc-windows-msvc"
        return DevicePreflightResult(
            provider_id="example-device",
            status=DevicePreflightStatus.READY,
            observations=(("driver", "present"),),
        )

    def build_contribution(
        self, request: DevicePreflightRequest
    ) -> DeviceBuildContribution:
        assert request.selection == _selection()
        return DeviceBuildContribution(
            cargo_features=("cuda",),
            native_libraries=("nvcuda",),
            generated_helper_ids=("cuda-preflight",),
            runtime_check_ids=("driver-version",),
        )


class _LoweringPluginShape:
    def describe(self) -> tuple[object, ...]:
        return ()

    def covers(self) -> tuple[object, ...]:
        return ()


def _selection() -> DeviceProviderSelection:
    return DeviceProviderSelection(
        provider_id="example-device",
        capability_id="windows-cuda-build-only",
    )


def _request() -> DevicePreflightRequest:
    return DevicePreflightRequest(
        host_executable_profile(
            "x86_64-pc-windows-msvc",
            fallback="error",
        ),
        _selection(),
    )


def test_manifest_and_request_serialize_deterministically() -> None:
    manifest = _manifest()
    request = _request()

    assert manifest.api_version == DEVICE_PROVIDER_API_VERSION == "1.0"
    assert manifest.to_dict()["stability"] == "alpha"
    assert json.dumps(manifest.to_dict(), sort_keys=True) == json.dumps(
        _manifest().to_dict(), sort_keys=True
    )
    assert (
        request.to_dict()["artifact_profile"]["target_triple"]
        == "x86_64-pc-windows-msvc"
    )
    assert request.to_dict()["selection"] == {
        "provider_id": "example-device",
        "capability_id": "windows-cuda-build-only",
    }


def test_preflight_result_is_canonical_and_never_a_support_claim() -> None:
    result = DevicePreflightResult(
        provider_id="example-device",
        status="unavailable",
        reason_codes=("DRIVER_MISSING", "DRIVER_MISSING"),
        observations=(("target", "windows-msvc"), ("arch", "x86_64")),
    )

    assert result.reason_codes == ("DRIVER_MISSING",)
    assert result.observations == (("arch", "x86_64"), ("target", "windows-msvc"))
    assert result.to_dict() == {
        "provider_id": "example-device",
        "status": "unavailable",
        "reason_codes": ["DRIVER_MISSING"],
        "observations": [
            {"key": "arch", "value": "x86_64"},
            {"key": "target", "value": "windows-msvc"},
        ],
        "support_claim": False,
    }
    with pytest.raises(ValueError, match="support_claim=False"):
        DevicePreflightResult(
            provider_id="example-device",
            status="ready",
            support_claim=True,
        )


def test_non_ready_result_requires_a_stable_reason_code() -> None:
    with pytest.raises(ValueError, match="requires at least one reason code"):
        DevicePreflightResult(provider_id="example-device", status="error")


@pytest.mark.parametrize(
    "observation",
    [
        (("driver", "line one\nline two"),),
        (("report", "/Users/example/private.json"),),
        (("report", r"C:\\Users\\example\\private.json"),),
        (("Not Stable", "present"),),
    ],
)
def test_observations_reject_report_injection_and_absolute_paths(
    observation: tuple[tuple[str, str], ...],
) -> None:
    with pytest.raises(ValueError, match="observation"):
        DevicePreflightResult(
            provider_id="example-device",
            status="ready",
            observations=observation,
        )


def test_protocol_is_structural_and_separate_from_lowering_plugins() -> None:
    provider = _StructuralProvider()
    request = _request()

    assert isinstance(provider, DeviceProvider)
    assert not isinstance(_LoweringPluginShape(), DeviceProvider)
    assert provider.preflight(request).status is DevicePreflightStatus.READY
    assert DeviceProvider.__module__ == "rextio.devices.api"


def test_contract_records_are_frozen() -> None:
    manifest = _manifest()
    request = _request()
    result = DevicePreflightResult(provider_id="example-device", status="ready")

    assert len({manifest, _manifest()}) == 1
    assert len({request, request}) == 1
    assert len({result, result}) == 1
    with pytest.raises(FrozenInstanceError):
        setattr(manifest, "display_name", "Changed")


def test_conflicting_manifest_declarations_fail_closed() -> None:
    first = TargetCapability(id="same")
    second = TargetCapability(
        id="same",
        target_triples=("x86_64-pc-windows-msvc",),
        artifact_kinds=(ArtifactKind.HOST_EXECUTABLE,),
        certification_tier=CertificationTier.BUILD_ONLY,
        evidence_references=("probe",),
    )
    with pytest.raises(ValueError, match="conflicting provider capabilities"):
        DeviceProviderManifest(
            provider_id="example-device",
            display_name="Example",
            capabilities=(first, second),
        )


def test_device_ids_and_value_metadata_are_canonical_and_structured() -> None:
    assert normalize_device_id("cuda").to_dict() == {
        "logical_device": "gpu:0",
        "kind": "gpu",
        "index": 0,
        "backend": "cuda",
    }
    assert normalize_device_id("/device:GPU:2", backend="cuda").logical_device == "gpu:2"
    metadata = DeviceValueMetadata(
        logical_device="CUDA:1",
        dtype="float32",
        rank=2,
        layout="contiguous",
        runtime_version="12.8",
        static_shape=(None, 128),
    )
    assert metadata.to_dict() == {
        "logical_device": "gpu:1",
        "backend": "cuda",
        "dtype": "float32",
        "rank": 2,
        "layout": "contiguous",
        "runtime_version": "12.8",
        "static_shape": [None, 128],
    }
    with pytest.raises(ValueError, match="conflicts"):
        normalize_device_id("cuda:0", backend="rocm")
    with pytest.raises(ValueError, match="length must equal rank"):
        DeviceValueMetadata(logical_device="cpu", rank=2, static_shape=(4,))


def test_framework_resources_are_borrow_validate_only() -> None:
    borrowed = DeviceResourceContract(
        resource_kind="current-stream",
        owner=DeviceResourceOwner.FRAMEWORK,
        access=DeviceResourceAccess.BORROW_VALIDATE,
    )
    owned = DeviceResourceContract(
        resource_kind="driver-event",
        owner=DeviceResourceOwner.PROVIDER,
        access=DeviceResourceAccess.OWNED,
        may_allocate=True,
    )
    contribution = DeviceBuildContribution(resource_contracts=(owned, borrowed))

    assert [item["resource_kind"] for item in contribution.to_dict()["resource_contracts"]] == [
        "current-stream",
        "driver-event",
    ]
    with pytest.raises(ValueError, match="may not allocate, replace, or synchronize"):
        DeviceResourceContract(
            resource_kind="tensor",
            owner="framework",
            access="borrow-validate",
            may_synchronize=True,
        )


def test_resource_contract_order_is_stable_across_python_hash_seeds() -> None:
    script = """
import json
from rextio.devices import (
    DeviceBuildContribution,
    DeviceResourceAccess,
    DeviceResourceContract,
    DeviceResourceOwner,
)

contracts = (
    DeviceResourceContract(
        "driver-event",
        DeviceResourceOwner.PROVIDER,
        DeviceResourceAccess.OWNED,
        may_allocate=True,
    ),
    DeviceResourceContract(
        "driver-event",
        DeviceResourceOwner.PROVIDER,
        DeviceResourceAccess.OWNED,
        may_replace=True,
    ),
    DeviceResourceContract(
        "driver-event",
        DeviceResourceOwner.PROVIDER,
        DeviceResourceAccess.OWNED,
        may_synchronize=True,
    ),
)
print(json.dumps(
    DeviceBuildContribution(resource_contracts=contracts).to_dict(),
    sort_keys=True,
    separators=(",", ":"),
))
"""
    repo_root = Path(__file__).parents[2]
    outputs: set[str] = set()
    for seed in ("1", "2", "3", "17", "101"):
        env = {
            **os.environ,
            "PYTHONHASHSEED": seed,
            "PYTHONPATH": os.pathsep.join(
                filter(
                    None,
                    (str(repo_root / "src"), os.environ.get("PYTHONPATH")),
                )
            ),
        }
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=repo_root,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        outputs.add(completed.stdout.strip())

    assert len(outputs) == 1
    [payload] = outputs
    flags = [
        (
            item["may_allocate"],
            item["may_replace"],
            item["may_synchronize"],
        )
        for item in json.loads(payload)["resource_contracts"]
    ]
    assert flags == [
        (False, False, True),
        (False, True, False),
        (True, False, False),
    ]


def test_device_provider_options_bound_public_keys_and_entry_count() -> None:
    key_at_limit = "k" * 64
    assert DeviceProviderOptions(((key_at_limit, "value"),)).keys == (
        key_at_limit,
    )
    with pytest.raises(ValueError, match="bounded lowercase identifiers"):
        DeviceProviderOptions((("k" * 65, "value"),))

    at_limit = tuple((f"k{index}", "value") for index in range(64))
    assert len(DeviceProviderOptions(at_limit).keys) == 64
    with pytest.raises(ValueError, match="at most 64 entries"):
        DeviceProviderOptions(
            (*at_limit, ("overflow", "value")),
        )


def _cuda_profile():
    return host_executable_profile(
        "x86_64-pc-windows-msvc",
        fallback="error",
        device_requirements=(
            DeviceRequirement(
                logical_device="cuda:0",
                backend="cuda",
                architectures=("sm_80",),
            ),
        ),
    )


class _ExplodingProvider:
    def manifest(self) -> DeviceProviderManifest:
        raise AssertionError("an unselected provider must not be inspected")

    def preflight(self, request: DevicePreflightRequest) -> DevicePreflightResult:
        del request
        raise AssertionError("an unselected provider must not be inspected")

    def build_contribution(
        self, request: DevicePreflightRequest
    ) -> DeviceBuildContribution:
        del request
        raise AssertionError("an unselected provider must not be inspected")


def test_explicit_resolution_preflights_then_projects_lock_and_report() -> None:
    provider = _StructuralProvider()
    options = DeviceProviderOptions(
        (("toolkit_root", "/private/cuda-12.8"), ("probe_manifest", "locks/probe.json"))
    )
    plan = resolve_device_plan(
        artifact_profile=_cuda_profile(),
        selection=_selection(),
        providers={
            "ignored-provider": _ExplodingProvider(),
            "example-device": provider,
        },
        options=options,
    )

    assert plan is not None
    assert plan.capability.id == "windows-cuda-build-only"
    assert plan.contribution.native_libraries == ("nvcuda",)
    lock = plan.lock_record().to_dict()
    assert lock["provider_version"] == "1.2.3"
    assert lock["capability_id"] == "windows-cuda-build-only"
    assert re.fullmatch(r"[0-9a-f]{64}", str(lock["manifest_sha256"]))
    assert re.fullmatch(r"[0-9a-f]{64}", str(lock["artifact_profile_sha256"]))
    assert re.fullmatch(r"[0-9a-f]{64}", str(lock["contribution_sha256"]))
    assert lock["option_keys"] == ["probe_manifest", "toolkit_root"]
    assert re.fullmatch(r"[0-9a-f]{64}", str(lock["options_sha256"]))
    report = plan.report_record().to_dict()
    assert report["certification_tier"] == "build-only"
    assert report["support_claim"] is False
    assert report["evidence_references"] == ["cuda-driver-probe"]
    serialized = json.dumps(plan.to_dict(), sort_keys=True)
    assert "/private/cuda-12.8" not in serialized
    assert "locks/probe.json" not in serialized


class _DifferentContributionProvider(_StructuralProvider):
    def build_contribution(
        self, request: DevicePreflightRequest
    ) -> DeviceBuildContribution:
        del request
        return DeviceBuildContribution(native_libraries=("cuda",))


def test_provider_lock_binds_profile_contribution_and_private_options() -> None:
    baseline = resolve_device_plan(
        artifact_profile=_cuda_profile(),
        selection=_selection(),
        providers={"example-device": _StructuralProvider()},
        options=DeviceProviderOptions((("toolkit_root", "/opt/cuda-a"),)),
    )
    changed_profile = resolve_device_plan(
        artifact_profile=host_executable_profile(
            "x86_64-pc-windows-msvc",
            fallback="error",
            device_requirements=(
                DeviceRequirement(
                    logical_device="cuda:0",
                    backend="cuda",
                    architectures=("sm_90",),
                ),
            ),
        ),
        selection=_selection(),
        providers={"example-device": _StructuralProvider()},
        options=DeviceProviderOptions((("toolkit_root", "/opt/cuda-a"),)),
    )
    changed_contribution = resolve_device_plan(
        artifact_profile=_cuda_profile(),
        selection=_selection(),
        providers={"example-device": _DifferentContributionProvider()},
        options=DeviceProviderOptions((("toolkit_root", "/opt/cuda-a"),)),
    )
    changed_options = resolve_device_plan(
        artifact_profile=_cuda_profile(),
        selection=_selection(),
        providers={"example-device": _StructuralProvider()},
        options=DeviceProviderOptions((("toolkit_root", "/opt/cuda-b"),)),
    )

    assert baseline is not None
    assert changed_profile is not None
    assert changed_contribution is not None
    assert changed_options is not None
    base_lock = baseline.lock_record()
    assert (
        base_lock.artifact_profile_sha256
        != changed_profile.lock_record().artifact_profile_sha256
    )
    assert (
        base_lock.contribution_sha256
        != changed_contribution.lock_record().contribution_sha256
    )
    assert base_lock.options_sha256 != changed_options.lock_record().options_sha256


def test_provider_lock_binds_exact_entry_point_target_and_distribution() -> None:
    first_source = DeviceProviderSource(
        entry_point_group="rextio.device_providers",
        entry_point_name="example-device",
        entry_point_value="rextio_device_example:provider",
        distribution_name="rextio-device-example",
        distribution_version="1.2.3",
    )
    second_source = DeviceProviderSource(
        entry_point_group="rextio.device_providers",
        entry_point_name="example-device",
        entry_point_value="rextio_device_example:alternate_provider",
        distribution_name="rextio-device-example",
        distribution_version="1.2.3",
    )
    third_source = DeviceProviderSource(
        entry_point_group="rextio.device_providers",
        entry_point_name="example-device",
        entry_point_value="rextio_device_example:provider",
        distribution_name="rextio-device-example",
        distribution_version="1.2.4",
    )
    first = resolve_device_plan(
        artifact_profile=_cuda_profile(),
        selection=_selection(),
        providers={"example-device": _StructuralProvider()},
        provider_sources={"example-device": first_source},
    )
    second = resolve_device_plan(
        artifact_profile=_cuda_profile(),
        selection=_selection(),
        providers={"example-device": _StructuralProvider()},
        provider_sources={"example-device": second_source},
    )
    third = resolve_device_plan(
        artifact_profile=_cuda_profile(),
        selection=_selection(),
        providers={"example-device": _StructuralProvider()},
        provider_sources={"example-device": third_source},
    )

    assert first is not None
    assert second is not None
    assert third is not None
    assert first.lock_record().source_identity_sha256
    assert (
        first.lock_record().source_identity_sha256
        != second.lock_record().source_identity_sha256
    )
    assert (
        first.lock_record().source_identity_sha256
        != third.lock_record().source_identity_sha256
    )


def test_no_selection_preserves_cpu_only_and_rejects_accelerator_profiles() -> None:
    cpu_profile = host_extension_profile(
        "x86_64-unknown-linux-gnu",
        device_requirements=(DeviceRequirement("cpu"),),
    )
    assert (
        resolve_device_plan(
            artifact_profile=cpu_profile,
            selection=None,
            providers={},
        )
        is None
    )
    with pytest.raises(DeviceProviderError, match="explicit device provider"):
        resolve_device_plan(
            artifact_profile=_cuda_profile(),
            selection=None,
            providers={},
        )


def test_accelerator_provider_requires_typed_non_cpu_artifact_requirement() -> None:
    with pytest.raises(DeviceProviderError, match="typed non-CPU artifact"):
        resolve_device_plan(
            artifact_profile=host_executable_profile(
                "x86_64-pc-windows-msvc",
                fallback="error",
            ),
            selection=_selection(),
            providers={"example-device": _StructuralProvider()},
        )


def test_incompatible_capability_fails_before_preflight() -> None:
    with pytest.raises(DeviceProviderError, match="incompatible"):
        resolve_device_plan(
            artifact_profile=host_extension_profile(
                "x86_64-pc-windows-msvc",
                device_requirements=(
                    DeviceRequirement("cuda:0", backend="cuda"),
                ),
            ),
            selection=_selection(),
            providers={"example-device": _StructuralProvider()},
        )


class _ManifestProvider(_StructuralProvider):
    def __init__(self, manifest: DeviceProviderManifest) -> None:
        self._manifest = manifest

    def manifest(self) -> DeviceProviderManifest:
        return self._manifest


@pytest.mark.parametrize(
    ("manifest", "match"),
    [
        (
            DeviceProviderManifest(
                provider_id="example-device",
                display_name="Unsupported",
                provider_version="1",
                backend="cuda",
                capabilities=(TargetCapability(id="windows-cuda-build-only"),),
            ),
            "explicitly unsupported",
        ),
        (
            DeviceProviderManifest(
                provider_id="example-device",
                display_name="No backend",
                provider_version="1",
                backend="cuda",
                capabilities=(
                    TargetCapability(
                        id="windows-cuda-build-only",
                        target_triples=("x86_64-pc-windows-msvc",),
                        artifact_kinds=(ArtifactKind.HOST_EXECUTABLE,),
                        architectures=("sm_80",),
                        certification_tier=CertificationTier.BUILD_ONLY,
                        evidence_references=("evidence.json",),
                    ),
                ),
            ),
            "incompatible",
        ),
        (
            DeviceProviderManifest(
                provider_id="example-device",
                display_name="No architecture",
                provider_version="1",
                backend="cuda",
                capabilities=(
                    TargetCapability(
                        id="windows-cuda-build-only",
                        target_triples=("x86_64-pc-windows-msvc",),
                        artifact_kinds=(ArtifactKind.HOST_EXECUTABLE,),
                        accelerator_backends=("cuda",),
                        certification_tier=CertificationTier.BUILD_ONLY,
                        evidence_references=("evidence.json",),
                    ),
                ),
            ),
            "incompatible",
        ),
        (
            DeviceProviderManifest(
                provider_id="example-device",
                display_name="Backend mismatch",
                provider_version="1",
                backend="rocm",
                capabilities=(
                    TargetCapability(
                        id="windows-cuda-build-only",
                        target_triples=("x86_64-pc-windows-msvc",),
                        artifact_kinds=(ArtifactKind.HOST_EXECUTABLE,),
                        accelerator_backends=("cuda",),
                        architectures=("sm_80",),
                        certification_tier=CertificationTier.BUILD_ONLY,
                        evidence_references=("evidence.json",),
                    ),
                ),
            ),
            "does not match artifact requirements",
        ),
    ],
)
def test_unsupported_or_underdeclared_capabilities_fail_closed(
    manifest: DeviceProviderManifest,
    match: str,
) -> None:
    with pytest.raises(DeviceProviderError, match=match):
        resolve_device_plan(
            artifact_profile=_cuda_profile(),
            selection=_selection(),
            providers={"example-device": _ManifestProvider(manifest)},
        )


class _UnavailableProvider(_StructuralProvider):
    def preflight(self, request: DevicePreflightRequest) -> DevicePreflightResult:
        del request
        return DevicePreflightResult(
            provider_id="example-device",
            status="unavailable",
            reason_codes=("DRIVER_MISSING",),
        )

    def build_contribution(
        self, request: DevicePreflightRequest
    ) -> DeviceBuildContribution:
        del request
        raise AssertionError("contribution must not run after failed preflight")


def test_non_ready_preflight_fails_before_build_contribution() -> None:
    with pytest.raises(DeviceProviderError) as raised:
        resolve_device_plan(
            artifact_profile=_cuda_profile(),
            selection=_selection(),
            providers={"example-device": _UnavailableProvider()},
        )
    assert "status 'unavailable'" in str(raised.value)
    assert "DRIVER_MISSING" not in str(raised.value)


class _LeakingProvider(_StructuralProvider):
    def __init__(self, stage: str) -> None:
        self.stage = stage

    def manifest(self) -> DeviceProviderManifest:
        if self.stage == "manifest":
            raise RuntimeError("/private/provider-option")
        return super().manifest()

    def preflight(self, request: DevicePreflightRequest) -> DevicePreflightResult:
        if self.stage == "preflight":
            raise RuntimeError("/private/provider-option")
        return super().preflight(request)

    def build_contribution(
        self, request: DevicePreflightRequest
    ) -> DeviceBuildContribution:
        if self.stage == "build-contribution":
            raise RuntimeError("/private/provider-option")
        return super().build_contribution(request)


@pytest.mark.parametrize("stage", ["manifest", "preflight", "build-contribution"])
def test_provider_stage_errors_do_not_echo_private_exception_text(stage: str) -> None:
    with pytest.raises(DeviceProviderError) as raised:
        resolve_device_plan(
            artifact_profile=_cuda_profile(),
            selection=_selection(),
            providers={"example-device": _LeakingProvider(stage)},
            options=DeviceProviderOptions(
                (("toolkit_root", "/private/provider-option"),)
            ),
        )

    assert stage in str(raised.value)
    assert "/private/provider-option" not in str(raised.value)
    assert isinstance(raised.value.__cause__, RuntimeError)


def _strip_rust_line_comments(source: str) -> str:
    return "\n".join(line.split("//", 1)[0] for line in source.splitlines())


def _arch_candidate_block(source: str, arch: str) -> str:
    pattern = (
        rf'#\[cfg\(target_arch = "{re.escape(arch)}"\)\]\s*'
        r"const LIBCUDA_CANDIDATES: &\[&str\] = &\[(.*?)\];"
    )
    match = re.search(pattern, source, flags=re.DOTALL)
    assert match is not None, f"missing LIBCUDA_CANDIDATES for {arch}"
    return match.group(1)


def test_cuda_driver_probe_has_no_dependencies_and_only_the_reviewed_driver_symbols() -> None:
    repository_root = Path(__file__).resolve().parents[2]
    probe_root = repository_root / "tools" / "cuda-driver-probe"
    source = (probe_root / "src" / "main.rs").read_text(encoding="utf-8")
    cargo_toml = (probe_root / "Cargo.toml").read_text(encoding="utf-8")
    code = _strip_rust_line_comments(source)
    symbols = set(re.findall(r'resolve!\(\s*library,\s*"(cu[A-Za-z0-9_]+)"', source))

    # Exact six CUDA Driver API inventory symbols (resolve! surface only).
    assert symbols == {
        "cuInit",
        "cuDriverGetVersion",
        "cuDeviceGetCount",
        "cuDeviceGet",
        "cuDeviceGetName",
        "cuDeviceComputeCapability",
    }
    assert 'name = "rextio-cuda-driver-probe"' in cargo_toml
    assert cargo_toml.rstrip().endswith("[dependencies]")
    assert '"support_claim", "false"' in source
    assert 'PROBE_NAME: &str = "rextio-cuda-driver-probe"' in source

    # Windows: System32-only nvcuda.dll; never LoadLibraryW / PATH / cwd preload.
    assert "LoadLibraryExW" in source
    assert "LOAD_LIBRARY_SEARCH_SYSTEM32" in source
    assert "nvcuda.dll" in source
    assert "LoadLibraryW(" not in source

    # Linux: explicit RTLD_NOW | RTLD_LOCAL and path-free load reason codes.
    assert "RTLD_NOW" in source
    assert "RTLD_LOCAL" in source
    assert "RTLD_NOW | RTLD_LOCAL" in source or "DLOPEN_FLAGS" in source
    assert "LIBCUDA_SO_NOT_FOUND" in source
    assert "LIBCUDA_SO_LOAD_FAILED" in source
    assert "dlerror" not in code
    assert "canonicalize" in source
    assert "REVIEWED_SYSTEM_ROOTS" in source
    assert "is_group_or_world_writable_regular_file" in source
    assert "has_group_or_world_writable_path_ancestry" in source
    assert "0o022" in source
    assert "[0_u8; 256]" in source or "0_u8; 256" in source
    assert "cast::<c_char>()" in source
    assert 'set_var("CUDA_FORCE_PRELOAD_LIBRARIES", "0")' in code
    assert 'set_var("CUDA_DISABLE_JIT", "1")' in code

    # Arch-split candidates: specialized mounts before generic; no foreign arch.
    x86_block = _arch_candidate_block(source, "x86_64")
    aarch_block = _arch_candidate_block(source, "aarch64")
    x86_paths = re.findall(r'"(/[^"]+)"', x86_block)
    aarch_paths = re.findall(r'"(/[^"]+)"', aarch_block)
    assert x86_paths == [
        "/usr/lib/wsl/lib/libcuda.so.1",
        "/usr/local/nvidia/lib64/libcuda.so.1",
        "/usr/local/nvidia/lib/libcuda.so.1",
        "/usr/lib/x86_64-linux-gnu/libcuda.so.1",
        "/usr/lib64/libcuda.so.1",
        "/usr/lib/libcuda.so.1",
    ]
    assert aarch_paths == [
        "/usr/local/nvidia/lib64/libcuda.so.1",
        "/usr/local/nvidia/lib/libcuda.so.1",
        "/usr/lib/aarch64-linux-gnu/tegra/libcuda.so.1",
        "/usr/lib/aarch64-linux-gnu/libcuda.so.1",
        "/usr/lib64/libcuda.so.1",
        "/usr/lib/libcuda.so.1",
    ]
    assert "/usr/lib/aarch64-linux-gnu/libcuda.so.1" not in x86_paths
    assert "/usr/lib/x86_64-linux-gnu/libcuda.so.1" not in aarch_paths
    assert "/usr/lib/wsl/lib/libcuda.so.1" not in aarch_paths
    assert any("tegra" in path for path in aarch_paths)

    # Executable code must not load a bare soname or consult process env vars for
    # library path discovery (compile-time std::env::consts::* is OK; the two
    # CUDA_* set_var hardening keys above are intentional).
    assert 'dlopen("libcuda.so' not in code
    assert "dlopen(b" not in code
    assert "LD_LIBRARY_PATH" not in code
    assert "LD_PRELOAD" not in code  # docs/comments only may mention; strip comments
    assert "std::env::var" not in code
    assert "std::env::var_os" not in code
    assert "current_dir" not in code
    assert "getenv" not in code

    for forbidden in (
        "cuCtxCreate",
        "cuCtxDestroy",
        "cuMemAlloc",
        "cuMemFree",
        "cuMemcpy",
        "cuModuleLoad",
        "cuModuleGetFunction",
        "cuLaunchKernel",
        "cuStreamCreate",
        "nvcc",
        "cuda.h",
        "cudart",
    ):
        assert forbidden not in source


def test_cuda_driver_validation_scripts_and_ci_stay_non_support() -> None:
    repository_root = Path(__file__).resolve().parents[2]
    windows = (repository_root / "scripts" / "validate-windows-cuda.ps1").read_text(
        encoding="utf-8"
    )
    linux = (repository_root / "scripts" / "validate-linux-cuda.sh").read_text(
        encoding="utf-8"
    )
    ci = (repository_root / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    docs = (
        repository_root / "docs" / "testing" / "cuda-driver-validation.md"
    ).read_text(encoding="utf-8")
    e2e = (
        repository_root / "tests" / "e2e" / "test_linux_cuda_probe_real_toolchain.py"
    ).read_text(encoding="utf-8")

    assert "rextio-cuda-driver-probe" in windows
    assert "tools\\cuda-driver-probe\\Cargo.toml" in windows
    assert "support_claim" in windows
    assert "Win32NT" in windows

    assert "rextio-cuda-driver-probe" in linux
    assert "tools/cuda-driver-probe/Cargo.toml" in linux
    assert "support_claim" in linux
    assert "set -euo pipefail" in linux
    assert "--require-device" in linux
    assert "REXTIO_LINUX_CUDA_REQUIRE_DEVICE" in linux
    assert "probe-complete" in linux
    assert "driver_loaded" in linux
    assert "device_count" in linux
    assert "platform_supported" in linux
    assert "probe-complete|unavailable|error" in linux or (
        "probe-complete" in linux and "unavailable" in linux and "error" in linux
    )
    # Script must not dump private environment or invent support claims.
    assert "printenv" not in linux
    assert "support_claim: true" not in linux
    assert "support_claim=true" not in linux

    # Host cargo test on ubuntu/macOS and a GPU-free Windows compile/wrapper lane.
    assert "CUDA driver inventory probe cargo test (host; compile coverage)" in ci
    assert "CUDA driver inventory probe (loose Linux CI; not real-GPU evidence)" in ci
    assert "CUDA driver inventory probe (Windows; GPU-free contract)" in ci
    assert "windows-latest" in ci
    assert "x86_64-pc-windows-msvc" in ci
    assert "test_windows_cuda_probe_real_toolchain.py" in ci
    assert "REXTIO_WINDOWS_CUDA_PROBE" in ci
    assert "tools/cuda-driver-probe/Cargo.toml" in ci
    assert "validate-linux-cuda.sh" in ci
    assert "aarch64-unknown-linux-gnu" in ci
    assert "cargo check" in ci
    assert "not real-GPU" in ci or "not real-GPU evidence" in ci
    assert "REXTIO_LINUX_CUDA_REQUIRE_DEVICE" not in ci  # CI must stay loose
    assert "--require-device" not in ci
    # Wrapper builds the probe; CI must not add a redundant cargo build step.
    assert "cargo build --locked --manifest-path tools/cuda-driver-probe" not in ci

    assert "REXTIO_LINUX_CUDA_REQUIRE_DEVICE=1" in docs
    assert "--require-device" in docs
    assert "Jetson" in docs or "tegra" in docs
    assert "LIBCUDA_SO_NOT_FOUND" in docs
    assert "LIBCUDA_SO_LOAD_FAILED" in docs
    assert "provenance guard" in docs.lower()
    assert "group- or world-writable" in docs or "0o022" in docs
    assert "LD_PRELOAD" in docs
    assert "DT_NEEDED" in docs
    assert "ubuntu-latest" in docs
    assert "macos-latest" in docs
    assert "windows-latest" in docs
    assert "x86_64-pc-windows-msvc" in docs
    assert "aarch64-unknown-linux-gnu" in docs
    assert "compile coverage" in docs.lower() or "compile-only" in docs.lower()
    assert "real-GPU evidence" in docs
    assert "not" in docs.lower() and "real-gpu evidence" in docs.lower()

    assert "REXTIO_LINUX_CUDA_REQUIRE_DEVICE" in e2e
    assert "--require-device" in e2e
    assert "support_claim" in e2e
    assert "platform_supported" in e2e
    assert "probe-complete" in e2e and "unavailable" in e2e and "error" in e2e
