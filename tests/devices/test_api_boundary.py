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
