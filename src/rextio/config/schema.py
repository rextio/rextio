from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class BuildConfig:
    native_backend: str = "rust"
    fallback_backend: str = "cpython"
    fallback_threshold: int = 1000


@dataclass(frozen=True)
class RustConfig:
    binding: str = "pyo3"
    build_tool: str = "maturin"


@dataclass(frozen=True)
class FallbackConfig:
    nuitka: str = "experimental"


@dataclass(frozen=True)
class TargetConfig:
    version: str | None = None
    build_options: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class MapperConfig:
    paths: tuple[str, ...] = ()
    enabled: tuple[str, ...] = ()
    repository: str | None = None


@dataclass(frozen=True)
class ExecutableConfig:
    entrypoint: str | None = None
    name: str | None = None
    backend: str = "zipapp"
    nuitka_mode: str = "standalone"


@dataclass(frozen=True)
class PolicyConfig:
    native_marker: str = "auto"
    require_type_hints: bool = True
    allow_dynamic_features: bool = False
    boundary_warnings: bool = True
    native_top_level: bool = False


@dataclass(frozen=True)
class RextioConfig:
    build: BuildConfig = BuildConfig()
    rust: RustConfig = RustConfig()
    fallback: FallbackConfig = FallbackConfig()
    target: TargetConfig = TargetConfig()
    mappers: MapperConfig = MapperConfig()
    executable: ExecutableConfig = ExecutableConfig()
    policy: PolicyConfig = PolicyConfig()
