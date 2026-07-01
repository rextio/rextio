"""The typed rextio.toml configuration schema."""

from __future__ import annotations

from dataclasses import dataclass, field

from rextio.limits import DEFAULT_BUILD_TIMEOUT_SECONDS


@dataclass(frozen=True)
class BuildConfig:
    """The [build] configuration section."""

    native_backend: str = "rust"
    fallback_backend: str = "cpython"
    fallback_threshold: int = 1000
    # Wall-clock timeout (seconds) for each external build-tool invocation
    # (cargo/maturin/nuitka). A hung toolchain fails the build instead of
    # blocking indefinitely.
    build_timeout_seconds: float = DEFAULT_BUILD_TIMEOUT_SECONDS


@dataclass(frozen=True)
class RustConfig:
    """The [rust] configuration section."""

    binding: str = "pyo3"
    build_tool: str = "cargo"
    importable: bool = False
    crate_name: str = "rextio_generated_rust"


@dataclass(frozen=True)
class FallbackConfig:
    """The [fallback] configuration section."""

    nuitka: str = "experimental"


@dataclass(frozen=True)
class TargetConfig:
    """The [target] configuration section."""

    version: str | None = None
    build_options: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class PluginConfig:
    """The [plugins] configuration section."""

    enabled: tuple[str, ...] = ()


@dataclass(frozen=True)
class ImportPackagePolicy:
    """The import policy configured for a single package."""

    policy: str = "fallback"
    plugin: str | None = None
    max_depth: int = 0


@dataclass(frozen=True)
class ImportsConfig:
    """The [imports] configuration section."""

    default_external_policy: str = "fallback"
    packages: dict[str, ImportPackagePolicy] = field(default_factory=dict)


@dataclass(frozen=True)
class JitConfig:
    """The [jit] configuration section."""

    enabled: bool = False
    backend: str = "cranelift"
    hot_threshold: int = 25


@dataclass(frozen=True)
class ExecutableConfig:
    """The [executable] configuration section."""

    entrypoint: str | None = None
    name: str | None = None
    backend: str = "zipapp"
    nuitka_mode: str = "standalone"
    # The interpreter the `rust` backend's binary launches for delegated CPython
    # calls (bare name on PATH, absolute path, or a relative path resolved against
    # `<binary>.runtime`). None -> the built-in default (`python3`).
    python: str | None = None
    # How the `rust` backend ships the delegated Python: "source" (dispatcher.py +
    # project source, run with `python`) or "nuitka" (a self-contained compiled
    # dispatcher executable, so no separate Python install is needed at runtime).
    hybrid_runtime: str = "source"


@dataclass(frozen=True)
class PolicyConfig:
    """The [policy] configuration section."""

    native_marker: str = "auto"
    require_type_hints: bool = True
    allow_dynamic_features: bool = False
    boundary_warnings: bool = True
    native_top_level: bool = False


@dataclass(frozen=True)
class RextioConfig:
    """The full, resolved Rextio configuration."""

    build: BuildConfig = BuildConfig()
    rust: RustConfig = RustConfig()
    fallback: FallbackConfig = FallbackConfig()
    target: TargetConfig = TargetConfig()
    plugins: PluginConfig = PluginConfig()
    imports: ImportsConfig = ImportsConfig()
    jit: JitConfig = JitConfig()
    executable: ExecutableConfig = ExecutableConfig()
    policy: PolicyConfig = PolicyConfig()
