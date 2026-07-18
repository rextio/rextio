from __future__ import annotations

from rextio.artifacts.models import ArtifactKind, FallbackStrategy
from rextio.artifacts.profiles import (
    host_executable_profile,
    host_extension_profile,
    rust_crate_profile,
)


def test_host_extension_profile_matches_current_wheel_family() -> None:
    profile = host_extension_profile("aarch64-apple-darwin")

    assert profile.kind is ArtifactKind.HOST_EXTENSION
    assert profile.packaging_backend == "wheel"
    assert profile.fallback is None


def test_host_executable_profile_keeps_current_subprocess_default() -> None:
    profile = host_executable_profile("x86_64-unknown-linux-gnu")

    assert profile.kind is ArtifactKind.HOST_EXECUTABLE
    assert profile.packaging_backend == "rust-binary"
    assert profile.fallback is FallbackStrategy.PYTHON_SUBPROCESS


def test_host_executable_profile_accepts_explicit_native_only_policy() -> None:
    profile = host_executable_profile(
        "x86_64-pc-windows-msvc",
        fallback=FallbackStrategy.ERROR,
    )

    assert profile.to_dict()["fallback"] == "error"


def test_rust_crate_profile_has_no_python_fallback() -> None:
    profile = rust_crate_profile("aarch64-apple-darwin")

    assert profile.kind is ArtifactKind.RUST_CRATE
    assert profile.packaging_backend == "cargo-crate"
    assert profile.fallback is None
