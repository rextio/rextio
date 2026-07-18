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
        abi_requirements=abi_requirements,
        runtime_requirements=runtime_requirements,
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
    return ArtifactProfile(
        kind=ArtifactKind.HOST_EXECUTABLE,
        target_triple=target_triple,
        packaging_backend=packaging_backend,
        fallback=fallback,
        abi_requirements=abi_requirements,
        runtime_requirements=runtime_requirements,
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
