from __future__ import annotations

from dataclasses import dataclass, field

from rextio.limits import DEFAULT_BUILD_TIMEOUT_SECONDS


@dataclass(frozen=True)
class BuildConfig:
    native_backend: str = "rust"
    fallback_backend: str = "cpython"
    fallback_threshold: int = 1000
    # Wall-clock timeout (seconds) for each external build-tool invocation
    # (cargo/maturin/nuitka). A hung toolchain fails the build instead of
    # blocking indefinitely.
    build_timeout_seconds: float = DEFAULT_BUILD_TIMEOUT_SECONDS


@dataclass(frozen=True)
class RustConfig:
    binding: str = "pyo3"
    build_tool: str = "maturin"
    importable: bool = False
    crate_name: str = "rextio_generated_rust"


@dataclass(frozen=True)
class FallbackConfig:
    nuitka: str = "experimental"


@dataclass(frozen=True)
class TargetConfig:
    version: str | None = None
    build_options: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class PluginConfig:
    enabled: tuple[str, ...] = ()


@dataclass(frozen=True)
class ImportPackagePolicy:
    policy: str = "fallback"
    plugin: str | None = None
    max_depth: int = 0


@dataclass(frozen=True)
class ImportsConfig:
    default_external_policy: str = "fallback"
    packages: dict[str, ImportPackagePolicy] = field(default_factory=dict)


@dataclass(frozen=True)
class JitConfig:
    enabled: bool = False
    backend: str = "cranelift"
    hot_threshold: int = 25


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
    plugins: PluginConfig = PluginConfig()
    imports: ImportsConfig = ImportsConfig()
    jit: JitConfig = JitConfig()
    executable: ExecutableConfig = ExecutableConfig()
    policy: PolicyConfig = PolicyConfig()
