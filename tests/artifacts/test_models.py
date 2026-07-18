from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from rextio.artifacts.models import (
    ABIRequirement,
    ArtifactKind,
    ArtifactProfile,
    ArtifactProvenance,
    CertificationTier,
    DeviceRequirement,
    FallbackStrategy,
    RuntimeRequirement,
    TargetCapability,
)


def test_artifact_profile_serialization_is_canonical() -> None:
    profile = ArtifactProfile(
        kind=ArtifactKind.HOST_EXECUTABLE,
        target_triple="aarch64-apple-darwin",
        packaging_backend="rust-binary",
        fallback=FallbackStrategy.ERROR,
        abi_requirements=(
            ABIRequirement("python", "3.11", ("limited", "limited")),
            ABIRequirement("libc"),
        ),
        runtime_requirements=(
            RuntimeRequirement("python", "3.11", ("subprocess",)),
            RuntimeRequirement("cargo"),
        ),
        device_requirements=(
            DeviceRequirement(
                "gpu",
                backend="cuda",
                architectures=("sm_90", "sm_80", "sm_80"),
            ),
        ),
        provenance=ArtifactProvenance(
            source_references=("b.py", "a.py", "a.py"),
            evidence=("z", "a"),
        ),
    )

    assert profile.to_dict() == {
        "kind": "host-executable",
        "target_triple": "aarch64-apple-darwin",
        "packaging_backend": "rust-binary",
        "fallback": "error",
        "abi_requirements": [
            {"name": "libc", "version": None, "features": []},
            {"name": "python", "version": "3.11", "features": ["limited"]},
        ],
        "runtime_requirements": [
            {"name": "cargo", "version": None, "features": []},
            {"name": "python", "version": "3.11", "features": ["subprocess"]},
        ],
        "device_requirements": [
            {
                "logical_device": "gpu",
                "backend": "cuda",
                "runtime": None,
                "features": [],
                "layouts": [],
                "memory_spaces": [],
                "architectures": ["sm_80", "sm_90"],
                "reuse_domain_runtime": False,
            }
        ],
        "provenance": {
            "producer": "rextio",
            "source_references": ["a.py", "b.py"],
            "evidence": ["a", "z"],
        },
    }


def test_fallback_is_required_only_for_host_executable() -> None:
    with pytest.raises(ValueError, match="requires an explicit fallback"):
        ArtifactProfile(
            kind=ArtifactKind.HOST_EXECUTABLE,
            target_triple="x86_64-unknown-linux-gnu",
            packaging_backend="rust-binary",
        )


def test_public_records_normalize_valid_string_enum_values() -> None:
    profile = ArtifactProfile(
        kind="host-executable",  # pyright-style runtime callers may originate in config.
        target_triple="x86_64-unknown-linux-gnu",
        packaging_backend="rust-binary",
        fallback="error",
    )
    capability = TargetCapability(
        id="host",
        artifact_kinds=("host-extension",),
        certification_tier="certified",
    )

    assert profile.kind is ArtifactKind.HOST_EXECUTABLE
    assert profile.fallback is FallbackStrategy.ERROR
    assert capability.artifact_kinds == (ArtifactKind.HOST_EXTENSION,)
    assert capability.certification_tier is CertificationTier.CERTIFIED

    with pytest.raises(ValueError, match="only valid"):
        ArtifactProfile(
            kind=ArtifactKind.RUST_CRATE,
            target_triple="x86_64-unknown-linux-gnu",
            packaging_backend="cargo-crate",
            fallback=FallbackStrategy.ERROR,
        )


def test_target_capability_is_declared_data_not_probe_state() -> None:
    capability = TargetCapability(
        id="cuda-build-contract",
        target_triples=("x86_64-pc-windows-msvc", "x86_64-pc-windows-msvc"),
        artifact_kinds=(ArtifactKind.HOST_EXECUTABLE, ArtifactKind.HOST_EXTENSION),
        accelerator_backends=("cuda",),
        certification_tier=CertificationTier.BUILD_ONLY,
        evidence_references=("windows-probe",),
    )

    assert capability.to_dict() == {
        "id": "cuda-build-contract",
        "target_triples": ["x86_64-pc-windows-msvc"],
        "artifact_kinds": ["host-executable", "host-extension"],
        "cpu_features": [],
        "accelerator_backends": ["cuda"],
        "certification_tier": "build-only",
        "evidence_references": ["windows-probe"],
    }


def test_records_are_frozen() -> None:
    requirement = DeviceRequirement("cpu")
    with pytest.raises(FrozenInstanceError):
        setattr(requirement, "logical_device", "gpu")
