from __future__ import annotations

import json
import re
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from rextio.artifacts.models import (
    ArtifactKind,
    CertificationTier,
    RuntimeRequirement,
    TargetCapability,
)
from rextio.artifacts.profiles import host_executable_profile
from rextio.devices import (
    DEVICE_PROVIDER_API_VERSION,
    DevicePreflightRequest,
    DevicePreflightResult,
    DevicePreflightStatus,
    DeviceProvider,
    DeviceProviderManifest,
)


def _manifest() -> DeviceProviderManifest:
    return DeviceProviderManifest(
        provider_id="example-device",
        display_name="Example Device",
        capabilities=(
            TargetCapability(
                id="windows-cuda-build-only",
                target_triples=("x86_64-pc-windows-msvc",),
                artifact_kinds=(ArtifactKind.HOST_EXECUTABLE,),
                accelerator_backends=("cuda",),
                certification_tier=CertificationTier.BUILD_ONLY,
                evidence_references=("windows-cuda-probe",),
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


class _LoweringPluginShape:
    def describe(self) -> tuple[object, ...]:
        return ()

    def covers(self) -> tuple[object, ...]:
        return ()


def test_manifest_and_request_serialize_deterministically() -> None:
    manifest = _manifest()
    request = DevicePreflightRequest(
        host_executable_profile(
            "x86_64-pc-windows-msvc",
            fallback="error",
        )
    )

    assert manifest.api_version == DEVICE_PROVIDER_API_VERSION == "0.1-draft"
    assert manifest.to_dict()["stability"] == "draft-experimental"
    assert json.dumps(manifest.to_dict(), sort_keys=True) == json.dumps(
        _manifest().to_dict(), sort_keys=True
    )
    assert request.to_dict()["artifact_profile"]["target_triple"] == ("x86_64-pc-windows-msvc")


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
    request = DevicePreflightRequest(
        host_executable_profile("x86_64-pc-windows-msvc", fallback="error")
    )

    assert isinstance(provider, DeviceProvider)
    assert not isinstance(_LoweringPluginShape(), DeviceProvider)
    assert provider.preflight(request).status is DevicePreflightStatus.READY
    assert DeviceProvider.__module__ == "rextio.devices.api"


def test_contract_records_are_frozen() -> None:
    manifest = _manifest()
    request = DevicePreflightRequest(
        host_executable_profile("x86_64-pc-windows-msvc", fallback="error")
    )
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


def test_windows_probe_has_no_dependencies_and_only_the_reviewed_driver_symbols() -> None:
    repository_root = Path(__file__).resolve().parents[2]
    probe_root = repository_root / "tools" / "windows-cuda-probe"
    source = (probe_root / "src" / "main.rs").read_text(encoding="utf-8")
    cargo_toml = (probe_root / "Cargo.toml").read_text(encoding="utf-8")
    symbols = set(re.findall(r'resolve!\(\s*library,\s*"(cu[A-Za-z0-9_]+)"', source))

    assert symbols == {
        "cuInit",
        "cuDriverGetVersion",
        "cuDeviceGetCount",
        "cuDeviceGet",
        "cuDeviceGetName",
        "cuDeviceComputeCapability",
    }
    assert cargo_toml.rstrip().endswith("[dependencies]")
    assert '"support_claim", "false"' in source
    assert "LoadLibraryExW" in source
    assert "LOAD_LIBRARY_SEARCH_SYSTEM32" in source
    assert "LoadLibraryW(" not in source
    for forbidden in (
        "cuCtxCreate",
        "cuMemAlloc",
        "cuMemcpy",
        "cuModuleLoad",
        "cuLaunchKernel",
        "cuStreamCreate",
    ):
        assert forbidden not in source
