from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class BuildConfig:
    native_backend: str = "rust"
    fallback_backend: str = "cpython"


@dataclass(frozen=True)
class RustConfig:
    binding: str = "pyo3"
    build_tool: str = "maturin"


@dataclass(frozen=True)
class FallbackConfig:
    nuitka: str = "experimental"


@dataclass(frozen=True)
class PolicyConfig:
    native_marker: str = "decorator"
    require_type_hints: bool = True
    allow_dynamic_features: bool = False
    boundary_warnings: bool = True


@dataclass(frozen=True)
class RextioConfig:
    build: BuildConfig = BuildConfig()
    rust: RustConfig = RustConfig()
    fallback: FallbackConfig = FallbackConfig()
    policy: PolicyConfig = PolicyConfig()
