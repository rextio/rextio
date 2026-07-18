"""Pure compatibility resolvers for the current host artifact families."""

from __future__ import annotations

from rextio.artifacts.models import (
    ABIRequirement,
    ArtifactKind,
    ArtifactProfile,
    ArtifactProvenance,
    DeviceRequirement,
    FallbackStrategy,
    RuntimeRequirement,
)


def host_extension_profile(
    target_triple: str,
    *,
    packaging_backend: str = "wheel",
    python_fallback_backend: str = "cpython",
    abi_requirements: tuple[ABIRequirement, ...] = (),
    runtime_requirements: tuple[RuntimeRequirement, ...] = (),
    device_requirements: tuple[DeviceRequirement, ...] = (),
    provenance: ArtifactProvenance | None = None,
) -> ArtifactProfile:
    """Describe the existing importable host-extension output."""
    return ArtifactProfile(
        kind=ArtifactKind.HOST_EXTENSION,
        target_triple=target_triple,
        packaging_backend=packaging_backend,
        python_fallback_backend=python_fallback_backend,
        abi_requirements=_with_default_abi(abi_requirements, ABIRequirement("cpython")),
        runtime_requirements=_with_default_runtime(
            runtime_requirements, RuntimeRequirement("cpython")
        ),
        device_requirements=device_requirements,
        provenance=provenance or ArtifactProvenance(),
    )


def host_executable_profile(
    target_triple: str,
    *,
    fallback: FallbackStrategy = FallbackStrategy.PYTHON_SUBPROCESS,
    packaging_backend: str = "rust-binary",
    abi_requirements: tuple[ABIRequirement, ...] = (),
    runtime_requirements: tuple[RuntimeRequirement, ...] = (),
    device_requirements: tuple[DeviceRequirement, ...] = (),
    provenance: ArtifactProvenance | None = None,
) -> ArtifactProfile:
    """Describe the native Rust host-executable output."""
    required_abi = abi_requirements
    required_runtime = runtime_requirements
    if fallback is not FallbackStrategy.ERROR:
        required_abi = _with_default_abi(
            required_abi, ABIRequirement("rextio-scalar-ipc", "1")
        )
        runtime_name = (
            "cpython"
            if fallback is FallbackStrategy.PYTHON_SUBPROCESS
            else "nuitka-sidecar"
        )
        required_runtime = _with_default_runtime(
            required_runtime, RuntimeRequirement(runtime_name)
        )
    return ArtifactProfile(
        kind=ArtifactKind.HOST_EXECUTABLE,
        target_triple=target_triple,
        packaging_backend=packaging_backend,
        fallback=fallback,
        abi_requirements=required_abi,
        runtime_requirements=required_runtime,
        device_requirements=device_requirements,
        provenance=provenance or ArtifactProvenance(),
    )


def rust_crate_profile(
    target_triple: str,
    *,
    packaging_backend: str = "cargo-crate",
    abi_requirements: tuple[ABIRequirement, ...] = (),
    runtime_requirements: tuple[RuntimeRequirement, ...] = (),
    device_requirements: tuple[DeviceRequirement, ...] = (),
    provenance: ArtifactProvenance | None = None,
) -> ArtifactProfile:
    """Describe the existing boundary-free importable Rust-crate output."""
    return ArtifactProfile(
        kind=ArtifactKind.RUST_CRATE,
        target_triple=target_triple,
        packaging_backend=packaging_backend,
        abi_requirements=abi_requirements,
        runtime_requirements=runtime_requirements,
        device_requirements=device_requirements,
        provenance=provenance or ArtifactProvenance(),
    )


def _with_default_abi(
    requirements: tuple[ABIRequirement, ...], default: ABIRequirement
) -> tuple[ABIRequirement, ...]:
    """Add a required ABI unless the caller supplied that logical requirement."""
    if any(requirement.name == default.name for requirement in requirements):
        return requirements
    return (*requirements, default)


def _with_default_runtime(
    requirements: tuple[RuntimeRequirement, ...], default: RuntimeRequirement
) -> tuple[RuntimeRequirement, ...]:
    """Add a required runtime unless the caller supplied that logical requirement."""
    if any(requirement.name == default.name for requirement in requirements):
        return requirements
    return (*requirements, default)
