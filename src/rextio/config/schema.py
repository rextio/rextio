"""The typed rextio.toml configuration schema."""

from __future__ import annotations

from dataclasses import dataclass, field

from rextio.artifacts.models import FallbackStrategy
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
    artifact_evidence_policy: str = "best-effort"
    # Final Full-C6 distribution is an independent, opt-in hard gate.  It does
    # not promote the preview artifact-evidence policy by implication.
    artifact_distribution_policy: str = "disabled"
    # Full-C6 signing is deliberately split into an owner-signed SourceLock v2
    # admission and a final artifact-authorization signature. Every path is
    # project-relative; private signing keys are never accepted by Rextio.
    artifact_source_lock_manifest: str | None = None
    artifact_source_lock_signature: str | None = None
    artifact_policy_manifest: str | None = None
    artifact_policy_manifest_sha256: str | None = None
    artifact_cargo_vendor: str | None = None
    artifact_cargo_vendor_sha256: str | None = None
    artifact_cargo_lock: str | None = None
    artifact_cargo_lock_sha256: str | None = None
    artifact_trusted_public_key: str | None = None
    artifact_trusted_public_key_sha256: str | None = None
    artifact_final_signature: str | None = None
    artifact_signing_request_output: str | None = None
    artifact_repeat_builds: int = 2


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
    # Train C5 source-native preview activation.  Both values must be present,
    # exact, and paired with ``policy = "try-native"`` / ``max_depth = 1``.
    # Older try-native declarations intentionally remain metadata-only.
    distribution: str | None = None
    version: str | None = None
    # Exact, project-owned source archive used by the strict Full-C6/C5.2
    # profile.  The hard gate securely opens and revalidates these bytes.
    source_archive: str | None = None
    source_archive_sha256: str | None = None


@dataclass(frozen=True)
class ImportsConfig:
    """The [imports] configuration section."""

    default_external_policy: str = "fallback"
    packages: dict[str, ImportPackagePolicy] = field(default_factory=dict)


@dataclass(frozen=True)
class EmbeddingConfig:
    """The [embedding] configuration section (experimental scalar-helper embedding)."""

    enabled: bool = False


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
    # Explicit fallback for the Rust executable entry graph.  This is separate
    # from [build].fallback_backend, which continues to control wheel fallback.
    fallback: FallbackStrategy = FallbackStrategy.PYTHON_SUBPROCESS
    # Compatibility input retained for old configs.  The loader maps source to
    # python-subprocess and nuitka to nuitka-sidecar, then uses ``fallback`` as
    # the canonical authority.
    hybrid_runtime: str | None = "source"


# One pattern shared by config validation and the pin matcher so the two can
# never drift: optional ==/>= operator followed by a dotted version.
VERSION_PIN_PATTERN = r"(==|>=)?(\d+(?:\.\d+)*)"


@dataclass(frozen=True)
class ToolchainConfig:
    """The [toolchain] configuration section.

    Paths accept either the tool binary itself or a home directory containing
    it (``bin/`` is searched). A configured path that does not resolve is a
    build error - it never silently falls back to PATH. ``*_version`` values
    are verification pins: the resolved tool's reported version must satisfy
    them (``X[.Y[.Z]]`` prefix match, or an explicit ``==``/``>=`` specifier).
    Pins verify; they never install or select a tool.
    """

    cargo: str | None = None
    maturin: str | None = None
    nuitka: str | None = None
    python: str | None = None
    # rustup channel/version forwarded as RUSTUP_TOOLCHAIN (only a rustup-managed
    # cargo honors it; a plain cargo ignores the variable).
    rust_toolchain: str | None = None
    cargo_version: str | None = None
    maturin_version: str | None = None
    nuitka_version: str | None = None
    python_version: str | None = None


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
    embedding: EmbeddingConfig = EmbeddingConfig()
    executable: ExecutableConfig = ExecutableConfig()
    toolchain: ToolchainConfig = ToolchainConfig()
    policy: PolicyConfig = PolicyConfig()
