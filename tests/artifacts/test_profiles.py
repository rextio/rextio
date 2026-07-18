from __future__ import annotations

import pytest

from rextio.artifacts.models import ArtifactKind, FallbackStrategy
from rextio.artifacts.profiles import (
    detect_host_target_triple,
    host_executable_profile,
    host_extension_profile,
    rust_crate_profile,
)


def test_host_extension_profile_matches_current_wheel_family() -> None:
    profile = host_extension_profile("aarch64-apple-darwin")

    assert profile.kind is ArtifactKind.HOST_EXTENSION
    assert profile.packaging_backend == "wheel"
    assert profile.fallback is None
    assert profile.python_fallback_backend == "cpython"
    assert [item.name for item in profile.abi_requirements] == ["cpython"]
    assert [item.name for item in profile.runtime_requirements] == ["cpython"]


def test_host_executable_profile_keeps_current_subprocess_default() -> None:
    profile = host_executable_profile("x86_64-unknown-linux-gnu")

    assert profile.kind is ArtifactKind.HOST_EXECUTABLE
    assert profile.packaging_backend == "rust-binary"
    assert profile.fallback is FallbackStrategy.PYTHON_SUBPROCESS
    assert [item.name for item in profile.abi_requirements] == ["rextio-scalar-ipc"]
    assert [item.name for item in profile.runtime_requirements] == ["cpython"]


def test_host_executable_profile_accepts_explicit_native_only_policy() -> None:
    profile = host_executable_profile(
        "x86_64-pc-windows-msvc",
        fallback=FallbackStrategy.ERROR,
    )

    assert profile.to_dict()["fallback"] == "error"
    assert profile.abi_requirements == ()
    assert profile.runtime_requirements == ()


def test_rust_crate_profile_has_no_python_fallback() -> None:
    profile = rust_crate_profile("aarch64-apple-darwin")

    assert profile.kind is ArtifactKind.RUST_CRATE
    assert profile.packaging_backend == "cargo-crate"
    assert profile.fallback is None


@pytest.mark.parametrize(
    ("system", "machine", "linux_abi", "expected"),
    [
        ("Darwin", "arm64", None, "aarch64-apple-darwin"),
        ("Darwin", "x86_64", None, "x86_64-apple-darwin"),
        ("Linux", "AMD64", "glibc", "x86_64-unknown-linux-gnu"),
        ("Linux", "aarch64", "musl", "aarch64-unknown-linux-musl"),
        ("Windows", "AMD64", None, "x86_64-pc-windows-msvc"),
        ("Windows", "ARM64", None, "aarch64-pc-windows-msvc"),
    ],
)
def test_host_target_triple_mapping(
    system: str,
    machine: str,
    linux_abi: str | None,
    expected: str,
) -> None:
    assert (
        detect_host_target_triple(system=system, machine=machine, linux_abi=linux_abi) == expected
    )


def test_host_target_triple_fails_closed_for_unknown_platform() -> None:
    with pytest.raises(ValueError, match="unsupported host platform"):
        detect_host_target_triple(system="Plan9", machine="x86_64")
