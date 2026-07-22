"""Private fixed-profile discovery for Full C6 toolchain support inputs.

The configured support lock is useful only when its opaque roles are joined to
one independently discovered set of host paths.  This module owns that join.
It deliberately supports only the two Alpha host profiles already admitted by
Full C6: Xcode on macOS arm64 and a bounded GNU userspace on Linux x86_64.

Plans are process-sealed, path-private, immutable capabilities.  Generation
and verification consume the same plan so a future CLI cannot discover one
set of paths while production verifies another.  This is an input-closure
contract, not a claim that wall clocks, scheduling, randomness, or the kernel
itself are virtualized.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import secrets
import stat
import sys
import tomllib
from typing import SupportsIndex
import unicodedata

from rextio.build.full_c6_linux_launcher import (
    FULL_C6_LINUX_RUNTIME_SUPPORT_ROOT,
)
from rextio.build.full_c6_read_sandbox import (
    AppleAPFSPlatformAnchorProvider,
    FullC6ReadSandboxError,
    MacOSPlatformAnchor,
    capture_active_macos_platform_anchor,
)
from rextio.build.subprocess_utils import run_build_tool
from rextio.build.toolchain_identity import (
    ToolIdentity,
    ToolchainIdentityError,
    capture_tool_identity,
    verify_tool_identity,
)
from rextio.build.toolchain_support_lock import (
    MAX_TOOLCHAIN_SUPPORT_LOCK_BYTES,
    ToolchainSupportLocator,
    ToolchainSupportLock,
    ToolchainSupportLockError,
    create_toolchain_support_locator,
    generate_toolchain_support_lock,
    verify_toolchain_support_lock,
)
from rextio.config.schema import ImportPackagePolicy, ImportsConfig, RextioConfig


FULL_C6_TOOLCHAIN_SUPPORT_PLAN_DOMAIN = (
    "rextio.full-c6-toolchain-support-plan.v1"
)
FULL_C6_TOOLCHAIN_SUPPORT_VIRTUAL_ROOT = PurePosixPath("/rextio/support")
FULL_C6_TOOLCHAIN_VIRTUAL_ROOT = PurePosixPath("/rextio/toolchain")
FULL_C6_TOOLCHAIN_SUPPORT_TARGETS = (
    "aarch64-apple-darwin",
    "x86_64-unknown-linux-gnu",
)

MACOS_XCODE_APP = Path("/Applications/Xcode.app")
MACOS_DEVELOPER_DIR = MACOS_XCODE_APP / "Contents" / "Developer"
MACOS_XCODE_DEFAULT_TOOLCHAIN = (
    MACOS_DEVELOPER_DIR / "Toolchains" / "XcodeDefault.xctoolchain"
)
MACOS_XCODE_TOOL_BIN = MACOS_XCODE_DEFAULT_TOOLCHAIN / "usr" / "bin"
MACOS_XCODE_CLANG_RESOURCE_VERSION = "17"
MACOS_XCODE_CLANG_RESOURCE = (
    MACOS_XCODE_DEFAULT_TOOLCHAIN
    / "usr"
    / "lib"
    / "clang"
    / MACOS_XCODE_CLANG_RESOURCE_VERSION
)
MACOS_XCODE_VERSION_PLIST = MACOS_XCODE_APP / "Contents" / "version.plist"
MACOS_XCODE_SELECT = Path("/usr/bin/xcode-select")
MACOS_XCRUN = Path("/usr/bin/xcrun")
MACOS_OTOOL = Path("/usr/bin/otool")
MACOS_SANDBOX_SYSTEM_PROFILE = Path(
    "/System/Library/Sandbox/Profiles/system.sb"
)
MACOS_SANDBOX_DYLD_PROFILE = Path(
    "/System/Library/Sandbox/Profiles/dyld-support.sb"
)

LINUX_BWRAP = Path("/usr/bin/bwrap")
LINUX_READELF = Path("/usr/bin/readelf")
LINUX_CC = Path("/usr/bin/cc")
LINUX_AR = Path("/usr/bin/ar")
LINUX_RANLIB = Path("/usr/bin/ranlib")
LINUX_RUNTIME_ROOT = Path("/usr/lib/x86_64-linux-gnu")
LINUX_PYTHON_RUNTIME_LIBRARY_NAME = "libpython3.11.so.1.0"
LINUX_LANDLOCK_LAUNCHER = Path(__file__).with_name("full_c6_linux_launcher.py")

MACOS_MANIFEST_ROLES = (
    "macos-sandbox-dyld-profile",
    "macos-sandbox-system-profile",
    "python-runtime-library",
    "rustup-components",
    "xcode-ar",
    "xcode-clang",
    "xcode-ld",
    "xcode-ranlib",
    "xcode-sdk-settings",
    "xcode-version-plist",
)
MACOS_ROOT_ROLES = (
    "python-runtime",
    "rust-sysroot",
    "xcode-clang-resource",
    "xcode-sdk",
)
LINUX_MANIFEST_ROLES = (
    "landlock-launcher",
    "linux-ar",
    "linux-binutils-ld",
    "linux-bwrap",
    "linux-dynamic-loader",
    "linux-ranlib",
    "python-runtime-library",
    "rustup-components",
)
LINUX_ROOT_ROLES = (
    "linux-gcc-support",
    "linux-python-library-support",
    "linux-runtime-support",
    "python-runtime",
    "rust-sysroot",
)

MAX_FULL_C6_SUPPORT_OUTPUT_BYTES = 1024 * 1024
MAX_FULL_C6_ELF_RUNTIME_FILES = 256
MAX_FULL_C6_ELF_NEEDED_PER_IMAGE = 128
MAX_FULL_C6_SUPPORT_PATH_BYTES = 8192
MAX_FULL_C6_SUPPORT_ENV_BYTES = 64 * 1024
_SEAL_KEY = secrets.token_bytes(32)
_ELF_INTERP_RE = re.compile(
    r"\[Requesting program interpreter: (?P<path>/[^\]\n]+)\]"
)
_ELF_NEEDED_RE = re.compile(r"Shared library: \[(?P<name>[^\]\n]+)\]")
_ROLE_RE = re.compile(r"^[a-z][a-z0-9-]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PYTHON_RUNTIME_PROBE = (
    "import json,sys,sysconfig;"
    "print(json.dumps({"
    "'executable':sys.executable,"
    "'implementation':sys.implementation.name,"
    "'major':sys.version_info[0],"
    "'minor':sys.version_info[1],"
    "'isolated':sys.flags.isolated,"
    "'no_site':sys.flags.no_site,"
    "'stdlib':sysconfig.get_path('stdlib'),"
    "'platstdlib':sysconfig.get_path('platstdlib'),"
    "'libdir':sysconfig.get_config_var('LIBDIR'),"
    "'ldlibrary':sysconfig.get_config_var('LDLIBRARY'),"
    "'framework':sysconfig.get_config_var('PYTHONFRAMEWORK') or '',"
    "'framework_install_dir':sysconfig.get_config_var('PYTHONFRAMEWORKINSTALLDIR') or ''"
    "},sort_keys=True,separators=(',',':')))"
)


class FullC6ToolchainSupportError(RuntimeError):
    """The fixed support profile is missing, ambiguous, or stale."""


@dataclass(frozen=True, slots=True)
class FullC6ToolchainSupportBootstrapResult:
    """Path-private projection of one canonical support-lock transaction."""

    result: str
    target: str
    manifest_roles: tuple[str, ...]
    root_roles: tuple[str, ...]
    raw_sha256: str
    merkle_sha256: str
    output: str

    def __post_init__(self) -> None:
        expected_manifests, expected_roots = expected_full_c6_toolchain_support_roles(
            self.target
        )
        if (
            self.result not in {"created", "reused"}
            or self.manifest_roles != expected_manifests
            or self.root_roles != expected_roots
            or _SHA256_RE.fullmatch(self.raw_sha256) is None
            or _SHA256_RE.fullmatch(self.merkle_sha256) is None
            or _canonical_project_relative_output(self.output) != self.output
        ):
            raise FullC6ToolchainSupportError(
                "Full C6 support-lock bootstrap result is invalid"
            )

    @property
    def config(self) -> dict[str, str]:
        """Return only the two configuration fields the owner must pin."""
        return {
            "artifact_toolchain_support_lock": self.output,
            "artifact_toolchain_support_lock_sha256": self.raw_sha256,
        }

    def to_dict(self) -> dict[str, object]:
        """Return the host-path-free public bootstrap projection."""
        return {
            "status": "full-c6-toolchain-support-lock-bootstrapped",
            "result": self.result,
            "target": self.target,
            "manifest_roles": list(self.manifest_roles),
            "root_roles": list(self.root_roles),
            "raw_sha256": self.raw_sha256,
            "merkle_sha256": self.merkle_sha256,
            "config": self.config,
            "authorizes_build": False,
            "authorizes_distribution": False,
        }


@dataclass(frozen=True, slots=True)
class _PathBinding:
    path: Path
    kind: str
    device: int
    inode: int
    mode: int
    size: int
    mtime_ns: int
    ctime_ns: int
    raw_sha256: str | None

    @property
    def opaque_path_sha256(self) -> str:
        return _path_digest(self.path)


@dataclass(frozen=True, slots=True, repr=False)
class _PlatformAnchoredToolBinding:
    kind: str
    path: Path
    identity: ToolIdentity
    anchor_sha256: str

    def __post_init__(self) -> None:
        if (
            self.kind != "platform-anchored-tool"
            or not self.path.is_absolute()
            or type(self.identity) is not ToolIdentity
            or self.identity.name != "otool"
            or self.anchor_sha256 != self.anchor_sha256.lower()
            or re.fullmatch(r"[0-9a-f]{64}", self.anchor_sha256) is None
        ):
            raise ValueError("Full C6 platform-anchored tool binding is invalid")


@dataclass(frozen=True, slots=True, repr=False)
class FullC6SupportNamespaceMapping:
    """One private host path and its deterministic future namespace path."""

    logical_role: str
    host_path: Path
    virtual_path: PurePosixPath
    kind: str

    def __post_init__(self) -> None:
        if (
            _ROLE_RE.fullmatch(self.logical_role) is None
            or self.kind not in {"file", "tree"}
            or not self.host_path.is_absolute()
            or not self.virtual_path.is_absolute()
            or self.virtual_path
            != _support_virtual_path(
                self.logical_role,
                host_path=self.host_path,
            )
        ):
            raise ValueError("Full C6 support namespace mapping is invalid")
        expected_kind = {
            "runtime-loader-mirror": "file",
            "support-landlock-launcher": "file",
            "support-gcc-toolchain": "tree",
            "support-python-library-root": "tree",
            "support-runtime-libs": "tree",
            "toolchain-python311": "file",
            "toolchain-python311-runtime-library": "file",
            "toolchain-python311-stdlib": "tree",
            "toolchain-ar": "file",
            "toolchain-cargo": "file",
            "toolchain-ld": "file",
            "toolchain-linker": "file",
            "toolchain-ranlib": "file",
            "toolchain-rustc": "file",
            "toolchain-rust-sysroot": "tree",
        }.get(self.logical_role)
        if expected_kind is not None and self.kind != expected_kind:
            raise ValueError("Full C6 support namespace mapping kind is invalid")

    def __repr__(self) -> str:
        return (
            "FullC6SupportNamespaceMapping("
            f"logical_role={self.logical_role!r}, kind={self.kind!r}, "
            f"virtual_path={self.virtual_path.as_posix()!r}, host_path=<private>)"
        )


class FullC6ToolchainSupportPlan:
    """Immutable process-sealed join between fixed roles and private paths."""

    __slots__ = (
        "_anchor",
        "_base_environment",
        "_bindings",
        "_elf_runtime_files",
        "_inspector_path",
        "_linker_path",
        "_manifest_locators",
        "_mappings",
        "_platform_anchored_tools",
        "_root_locators",
        "_seal",
        "_target_triple",
    )

    _anchor: MacOSPlatformAnchor | None
    _base_environment: tuple[tuple[str, str], ...]
    _bindings: tuple[_PathBinding, ...]
    _elf_runtime_files: tuple[Path, ...]
    _inspector_path: Path
    _linker_path: Path
    _manifest_locators: tuple[ToolchainSupportLocator, ...]
    _mappings: tuple[FullC6SupportNamespaceMapping, ...]
    _platform_anchored_tools: tuple[_PlatformAnchoredToolBinding, ...]
    _root_locators: tuple[ToolchainSupportLocator, ...]
    _seal: bytes
    _target_triple: str

    def __init__(self) -> None:
        raise TypeError("Full C6 toolchain support plans require discovery")

    def __repr__(self) -> str:
        return (
            "FullC6ToolchainSupportPlan("
            f"target_triple={self._target_triple!r}, material=<sealed>)"
        )

    def __setattr__(self, _name: str, _value: object) -> None:
        raise TypeError("Full C6 toolchain support plans are immutable")

    def __delattr__(self, _name: str) -> None:
        raise TypeError("Full C6 toolchain support plans are immutable")

    def __copy__(self) -> object:
        raise TypeError("Full C6 toolchain support plans cannot be copied")

    def __deepcopy__(self, _memo: object) -> object:
        raise TypeError("Full C6 toolchain support plans cannot be copied")

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("Full C6 toolchain support plans cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[object, ...]:
        raise TypeError("Full C6 toolchain support plans cannot be serialized")

    def __getstate__(self) -> object:
        raise TypeError("Full C6 toolchain support plans cannot be serialized")

    @property
    def target_triple(self) -> str:
        """Return the exact frozen host target."""
        require_full_c6_toolchain_support_plan(self)
        return self._target_triple

    @property
    def linker_path(self) -> Path:
        """Return the private, exact linker path."""
        require_full_c6_toolchain_support_plan(self)
        return self._linker_path

    @property
    def inspector_path(self) -> Path:
        """Return the private, exact native-inspector path."""
        require_full_c6_toolchain_support_plan(self)
        return self._inspector_path

    @property
    def base_environment(self) -> dict[str, str]:
        """Return a fresh copy of the fixed discovery environment."""
        require_full_c6_toolchain_support_plan(self)
        return dict(self._base_environment)

    @property
    def manifest_locators(self) -> tuple[ToolchainSupportLocator, ...]:
        """Return the private exact-file support locators."""
        require_full_c6_toolchain_support_plan(self)
        return self._manifest_locators

    @property
    def root_locators(self) -> tuple[ToolchainSupportLocator, ...]:
        """Return the private exact-tree support locators."""
        require_full_c6_toolchain_support_plan(self)
        return self._root_locators

    @property
    def namespace_mappings(self) -> tuple[FullC6SupportNamespaceMapping, ...]:
        """Return deterministic private host-to-namespace mappings."""
        require_full_c6_toolchain_support_plan(self)
        return self._mappings

    @property
    def elf_runtime_files(self) -> tuple[Path, ...]:
        """Return the private exact Linux ELF runtime leaf set."""
        require_full_c6_toolchain_support_plan(self)
        return self._elf_runtime_files

    @property
    def platform_anchor_sha256(self) -> str:
        """Return the retained macOS SSV-anchor digest, or the zero digest."""
        require_full_c6_toolchain_support_plan(self)
        return self._anchor.digest if self._anchor is not None else "0" * 64

    @property
    def macos_platform_anchor(self) -> MacOSPlatformAnchor | None:
        """Return the exact retained macOS SSV anchor, or ``None`` on Linux."""
        require_full_c6_toolchain_support_plan(self)
        return self._anchor

    @property
    def platform_anchor(self) -> MacOSPlatformAnchor | None:
        """Compatibility name for the exact sealed platform anchor."""
        return self.macos_platform_anchor

    @property
    def digest(self) -> str:
        """Return the path-obscured semantic plan digest."""
        require_full_c6_toolchain_support_plan(self)
        return _plan_digest(self)


def expected_full_c6_toolchain_support_roles(
    target_triple: str,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return the exact ordered manifest/root role contract for one target."""
    if target_triple == "aarch64-apple-darwin":
        return MACOS_MANIFEST_ROLES, MACOS_ROOT_ROLES
    if target_triple == "x86_64-unknown-linux-gnu":
        return LINUX_MANIFEST_ROLES, LINUX_ROOT_ROLES
    raise FullC6ToolchainSupportError("Full C6 support target is unsupported")


def resolve_full_c6_linker_and_inspector(
    *,
    target_triple: str,
    cwd: Path,
) -> tuple[Path, Path]:
    """Resolve the actual strict linker leaf before tool identity capture."""
    if target_triple == "aarch64-apple-darwin":
        environment = _macos_discovery_environment()
        developer = _stable_one_line(
            [os.fspath(MACOS_XCODE_SELECT), "-p"],
            cwd=cwd,
            environment=environment,
        )
        if Path(developer) != MACOS_DEVELOPER_DIR:
            raise FullC6ToolchainSupportError(
                "Full C6 macOS requires the exact full Xcode.app developer root"
            )
        clang = _stable_absolute_output(
            [os.fspath(MACOS_XCRUN), "--find", "clang"],
            cwd=cwd,
            environment=environment,
        )
        expected = MACOS_XCODE_TOOL_BIN / "clang"
        if clang != expected:
            raise FullC6ToolchainSupportError(
                "Full C6 macOS Xcode clang selection is not canonical"
            )
        return _require_real_file(
            clang,
            executable=True,
        ), _require_platform_anchored_macos_tool(MACOS_OTOOL)
    if target_triple == "x86_64-unknown-linux-gnu":
        return _resolved_real_file(LINUX_CC, executable=True), _resolved_real_file(
            LINUX_READELF, executable=True
        )
    raise FullC6ToolchainSupportError("Full C6 support target is unsupported")


def discover_full_c6_toolchain_support(
    *,
    target_triple: str,
    cwd: Path,
    python: Path,
    cargo: Path,
    rustc: Path,
    linker: Path,
    inspector: Path,
    platform_inspector_identity: ToolIdentity | None,
) -> FullC6ToolchainSupportPlan:
    """Discover one fixed path-bearing support plan from selected exact tools."""
    if target_triple not in FULL_C6_TOOLCHAIN_SUPPORT_TARGETS:
        raise FullC6ToolchainSupportError("Full C6 support target is unsupported")
    selected = (
        *(
            _require_real_file(path, executable=True)
            for path in (python, cargo, rustc, linker)
        ),
        (
            _require_platform_anchored_macos_tool(inspector)
            if target_triple == "aarch64-apple-darwin"
            else _require_real_file(inspector, executable=True)
        ),
    )
    if len(set(selected)) != len(selected):
        raise FullC6ToolchainSupportError(
            "Full C6 selected support tools are aliased"
        )
    python, cargo, rustc, linker, inspector = selected
    if target_triple == "aarch64-apple-darwin":
        if type(platform_inspector_identity) is not ToolIdentity:
            raise FullC6ToolchainSupportError(
                "Full C6 macOS platform inspector identity is missing"
            )
        return _discover_macos_support(
            cwd=cwd,
            python=python,
            cargo=cargo,
            rustc=rustc,
            linker=linker,
            inspector=inspector,
            platform_inspector_identity=platform_inspector_identity,
        )
    if platform_inspector_identity is not None:
        raise FullC6ToolchainSupportError(
            "Full C6 Linux cannot accept a platform-anchored inspector"
        )
    return _discover_linux_support(
        cwd=cwd,
        python=python,
        cargo=cargo,
        rustc=rustc,
        linker=linker,
        inspector=inspector,
    )


def generate_full_c6_toolchain_support_lock(
    plan: FullC6ToolchainSupportPlan,
) -> ToolchainSupportLock:
    """Generate a lock from the same sealed discovery plan production uses."""
    revalidate_full_c6_toolchain_support_plan(plan)
    try:
        return generate_toolchain_support_lock(
            target_triple=plan._target_triple,
            manifests=plan._manifest_locators,
            roots=plan._root_locators,
        )
    except ToolchainSupportLockError as exc:
        raise FullC6ToolchainSupportError(
            "Full C6 support lock generation failed closed"
        ) from exc


def materialize_full_c6_toolchain_support_lock(
    *,
    project_root: Path | str,
    output: str,
    plan: FullC6ToolchainSupportPlan,
    configured_artifact_paths: Sequence[str],
    expected_raw_sha256: str | None = None,
) -> FullC6ToolchainSupportBootstrapResult:
    """Create or exactly reuse one project-contained canonical support lock."""
    trusted_plan = revalidate_full_c6_toolchain_support_plan(plan)
    relative = _canonical_project_relative_output(output)
    root = _canonical_absolute_project_root(project_root)
    _require_nonaliased_support_output(
        relative,
        configured_artifact_paths=configured_artifact_paths,
    )
    lock = generate_full_c6_toolchain_support_lock(trusted_plan)
    if expected_raw_sha256 is not None and (
        _SHA256_RE.fullmatch(expected_raw_sha256) is None
        or not hmac.compare_digest(lock.raw_sha256, expected_raw_sha256)
    ):
        raise FullC6ToolchainSupportError(
            "Full C6 generated support lock differs from the configured SHA-256"
        )
    if not verify_full_c6_toolchain_support_lock(trusted_plan, lock):
        raise FullC6ToolchainSupportError(
            "Full C6 generated support lock failed verification"
        )
    created = _atomic_create_or_exact_reuse_support_lock(
        project_root=root,
        relative_output=relative,
        payload=lock.canonical_bytes,
    )
    manifests, roots = expected_full_c6_toolchain_support_roles(
        trusted_plan.target_triple
    )
    return FullC6ToolchainSupportBootstrapResult(
        result="created" if created else "reused",
        target=trusted_plan.target_triple,
        manifest_roles=manifests,
        root_roles=roots,
        raw_sha256=lock.raw_sha256,
        merkle_sha256=lock.merkle_sha256,
        output=relative,
    )


def bootstrap_full_c6_toolchain_support_lock(
    *,
    project_root: Path | str,
    output: str,
    inherited_environment: Mapping[str, str] | None = None,
) -> FullC6ToolchainSupportBootstrapResult:
    """Discover and materialize one fixed host support lock without authority."""
    root = _canonical_absolute_project_root(project_root)
    relative = _canonical_project_relative_output(output)
    environment = (
        os.environ if inherited_environment is None else inherited_environment
    )
    config, configured_pin = _load_full_c6_support_bootstrap_config(
        root,
        output=relative,
        inherited_environment=environment,
    )
    plan = _discover_full_c6_bootstrap_plan(
        project_root=root,
        config=config,
        inherited_environment=environment,
    )
    return materialize_full_c6_toolchain_support_lock(
        project_root=root,
        output=relative,
        plan=plan,
        configured_artifact_paths=_configured_full_c6_artifact_paths(config),
        expected_raw_sha256=configured_pin,
    )


def _load_full_c6_support_bootstrap_config(
    project_root: Path,
    *,
    output: str,
    inherited_environment: Mapping[str, str] | None,
) -> tuple[RextioConfig, str | None]:
    """Load ordinary config, injecting only the missing bootstrap lock pair."""
    from rextio.config import loader

    path = project_root / "rextio.toml"
    raw: dict[str, object] = dict(loader.DEFAULT_CONFIG)
    if path.exists():
        try:
            parsed = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
            raise FullC6ToolchainSupportError(
                "Full C6 support-lock bootstrap could not load rextio.toml"
            ) from exc
        unknown_sections = set(parsed) - set(loader.CONFIG_KEYS)
        if unknown_sections:
            section = sorted(unknown_sections)[0]
            raise FullC6ToolchainSupportError(
                f"unsupported config section: [{section}]"
            )
        raw = {**raw, **parsed}
    build = {**loader.DEFAULT_CONFIG["build"], **loader._section(raw, "build")}
    rust = {**loader.DEFAULT_CONFIG["rust"], **loader._section(raw, "rust")}
    fallback = {
        **loader.DEFAULT_CONFIG["fallback"],
        **loader._section(raw, "fallback"),
    }
    target = {**loader.DEFAULT_CONFIG["target"], **loader._section(raw, "target")}
    plugins = {
        **loader.DEFAULT_CONFIG["plugins"],
        **loader._section(raw, "plugins"),
    }
    imports = {
        **loader.DEFAULT_CONFIG["imports"],
        **loader._section(raw, "imports"),
    }
    embedding = {
        **loader.DEFAULT_CONFIG["embedding"],
        **loader._section(raw, "embedding"),
    }
    executable = {
        **loader.DEFAULT_CONFIG["executable"],
        **loader._section(raw, "executable"),
    }
    toolchain = {
        **loader.DEFAULT_CONFIG["toolchain"],
        **loader._section(raw, "toolchain"),
    }
    policy = {**loader.DEFAULT_CONFIG["policy"], **loader._section(raw, "policy")}
    if inherited_environment is not None:
        loader._apply_environment_overrides(
            build,
            rust,
            fallback,
            target,
            plugins,
            imports,
            embedding,
            executable,
            toolchain,
            policy,
            inherited_environment,
        )
    configured_path = build["artifact_toolchain_support_lock"]
    configured_pin = build["artifact_toolchain_support_lock_sha256"]
    if (configured_path is None) != (configured_pin is None):
        raise FullC6ToolchainSupportError(
            "Full C6 support-lock path and SHA-256 must be configured together"
        )
    if configured_path is None:
        build["artifact_toolchain_support_lock"] = output
        build["artifact_toolchain_support_lock_sha256"] = "0" * 64
    elif configured_path != output:
        raise FullC6ToolchainSupportError(
            "Full C6 configured support-lock path differs from --output"
        )
    try:
        config = loader._build_config(
            build,
            rust,
            fallback,
            target,
            plugins,
            imports,
            embedding,
            executable,
            toolchain,
            policy,
        )
    except loader.ConfigError as exc:
        raise FullC6ToolchainSupportError(
            "Full C6 support-lock bootstrap configuration is invalid"
        ) from exc
    return config, configured_pin if isinstance(configured_pin, str) else None


def _configured_full_c6_artifact_paths(
    config: RextioConfig,
) -> tuple[str, ...]:
    if type(config) is not RextioConfig:
        raise FullC6ToolchainSupportError(
            "Full C6 support-lock bootstrap configuration is invalid"
        )
    imports = config.imports
    if type(imports) is not ImportsConfig or type(imports.packages) is not dict:
        raise FullC6ToolchainSupportError(
            "Full C6 support-lock bootstrap configuration is invalid"
        )
    packages = imports.packages
    if any(
        type(package) is not str or type(package_policy) is not ImportPackagePolicy
        for package, package_policy in packages.items()
    ):
        raise FullC6ToolchainSupportError(
            "Full C6 support-lock bootstrap configuration is invalid"
        )
    source_archives = tuple(
        package_policy.source_archive
        for package, package_policy in sorted(packages.items())
        if package_policy.source_archive is not None
    )
    build = config.build
    values = (
        "rextio.toml",
        build.artifact_source_lock_manifest,
        build.artifact_source_lock_signature,
        build.artifact_policy_manifest,
        build.artifact_cargo_vendor,
        build.artifact_cargo_lock,
        build.artifact_trusted_public_key,
        build.artifact_final_signature,
        build.artifact_signing_request_output,
        *source_archives,
    )
    if any(value is not None and type(value) is not str for value in values):
        raise FullC6ToolchainSupportError(
            "Full C6 configured artifact path is invalid"
        )
    return tuple(value for value in values if type(value) is str)


def _discover_full_c6_bootstrap_plan(
    *,
    project_root: Path,
    config: RextioConfig,
    inherited_environment: Mapping[str, str] | None,
) -> FullC6ToolchainSupportPlan:
    """Reuse production tool selection without requiring the lock it creates."""
    from rextio.build import full_c6_host_inputs as host

    try:
        root, binding = host._open_raw_project_root(project_root)
        host._verify_directory_binding(root, binding, label="project")
        target_triple = host._require_supported_host()
        inherited = host._validate_inherited_environment(inherited_environment)
        selected_python = host._resolve_python(config)
        selected_cargo = host._resolve_required_tool(
            "cargo",
            config.toolchain.cargo,
        )
        python_path = host._resolve_executable(selected_python)
        cargo_path, rustc_path = host._resolve_actual_rust_tools(
            selected_cargo,
            root=root,
            config=config,
            inherited=inherited,
        )
        linker_path, inspector_path = resolve_full_c6_linker_and_inspector(
            target_triple=target_triple,
            cwd=root,
        )
        if Path(sys.executable).resolve(strict=True) != python_path:
            raise FullC6ToolchainSupportError(
                "Full C6 bootstrap Python differs from the running interpreter"
            )
        preliminary_environment = host._minimal_build_environment(cargo_path)
        probe_environment = {
            **preliminary_environment,
            "LANG": "C",
            "LC_ALL": "C",
            "PYTHONHASHSEED": "0",
            "SOURCE_DATE_EPOCH": "0",
            "TZ": "UTC",
        }
        paths = (
            python_path,
            cargo_path,
            rustc_path,
            linker_path,
            inspector_path,
        )
        versions = tuple(
            host._probe_version(path, root=root, environment=probe_environment)
            for path in paths
        )
        if host._probe_rustc_host(
            rustc_path,
            root=root,
            environment=probe_environment,
        ) != target_triple:
            raise FullC6ToolchainSupportError(
                "Full C6 bootstrap rustc host differs from target triple"
            )
        host._require_version_pin(
            "CPython",
            versions[0],
            config.toolchain.python_version,
        )
        host._require_version_pin(
            "cargo",
            versions[1],
            config.toolchain.cargo_version,
        )
        inspector_name = (
            "otool" if target_triple.endswith("apple-darwin") else "readelf"
        )
        identities = (
            capture_tool_identity(
                "python",
                python_path,
                reported_version=versions[0],
            ),
            capture_tool_identity(
                "cargo",
                cargo_path,
                reported_version=versions[1],
            ),
            capture_tool_identity(
                "rustc",
                rustc_path,
                reported_version=versions[2],
            ),
            capture_tool_identity(
                "linker",
                linker_path,
                reported_version=versions[3],
            ),
            capture_tool_identity(
                inspector_name,
                inspector_path,
                reported_version=versions[4],
            ),
        )
        repeated_versions = tuple(
            host._probe_version(path, root=root, environment=probe_environment)
            for path in paths
        )
        if repeated_versions != versions or host._probe_rustc_host(
            rustc_path,
            root=root,
            environment=probe_environment,
        ) != target_triple:
            raise FullC6ToolchainSupportError(
                "Full C6 bootstrap tool version changed during identity capture"
            )
        for path, identity in zip(paths, identities, strict=True):
            verify_tool_identity(path, identity)
        plan = discover_full_c6_toolchain_support(
            target_triple=target_triple,
            cwd=root,
            python=python_path,
            cargo=cargo_path,
            rustc=rustc_path,
            linker=linker_path,
            inspector=inspector_path,
            platform_inspector_identity=(
                identities[-1]
                if target_triple.endswith("apple-darwin")
                else None
            ),
        )
        final_probe_environment = {
            **plan.base_environment,
            "LANG": "C",
            "LC_ALL": "C",
            "PYTHONHASHSEED": "0",
            "SOURCE_DATE_EPOCH": "0",
            "TZ": "UTC",
        }
        final_versions = tuple(
            host._probe_version(
                path,
                root=root,
                environment=final_probe_environment,
            )
            for path in paths
        )
        if final_versions != versions or host._probe_rustc_host(
            rustc_path,
            root=root,
            environment=final_probe_environment,
        ) != target_triple:
            raise FullC6ToolchainSupportError(
                "Full C6 bootstrap tool identity changed under the support environment"
            )
        return revalidate_full_c6_toolchain_support_plan(plan)
    except FullC6ToolchainSupportError:
        raise
    except (host.FullC6HostInputsError, ToolchainIdentityError, OSError, TypeError, ValueError) as exc:
        raise FullC6ToolchainSupportError(
            "Full C6 toolchain support bootstrap discovery failed closed"
        ) from exc


def verify_full_c6_toolchain_support_lock(
    plan: FullC6ToolchainSupportPlan,
    lock: ToolchainSupportLock,
) -> bool:
    """Require exact role/kind/target equality, then rewalk every locator."""
    revalidate_full_c6_toolchain_support_plan(plan)
    if type(lock) is not ToolchainSupportLock:
        raise FullC6ToolchainSupportError(
            "Full C6 support verification requires an exact typed lock"
        )
    expected_manifests, expected_roots = expected_full_c6_toolchain_support_roles(
        plan._target_triple
    )
    observed_manifests = tuple(item.logical_role for item in lock.manifests)
    observed_roots = tuple(item.logical_role for item in lock.roots)
    if (
        lock.scope.target_triple != plan._target_triple
        or observed_manifests != expected_manifests
        or observed_roots != expected_roots
        or tuple(item.logical_role for item in plan._manifest_locators)
        != expected_manifests
        or tuple(item.logical_role for item in plan._root_locators)
        != expected_roots
    ):
        raise FullC6ToolchainSupportError(
            "Full C6 support lock roles, kinds, or target differ from discovery"
        )
    try:
        return verify_toolchain_support_lock(
            lock,
            manifests=plan._manifest_locators,
            roots=plan._root_locators,
        )
    except ToolchainSupportLockError as exc:
        raise FullC6ToolchainSupportError(
            "Full C6 support bytes differ from the exact configured lock"
        ) from exc


def require_full_c6_toolchain_support_plan(
    value: object,
) -> FullC6ToolchainSupportPlan:
    """Validate only the immutable process seal without rewalking host roots."""
    if type(value) is not FullC6ToolchainSupportPlan:
        raise FullC6ToolchainSupportError("Full C6 support plan is invalid")
    try:
        seal_valid = type(value._seal) is bytes and hmac.compare_digest(
            value._seal,
            _plan_seal(value),
        )
    except Exception as exc:
        raise FullC6ToolchainSupportError(
            "Full C6 support plan seal is invalid"
        ) from exc
    if not seal_valid:
        raise FullC6ToolchainSupportError("Full C6 support plan seal is invalid")
    return value


def revalidate_full_c6_toolchain_support_plan(
    value: object,
) -> FullC6ToolchainSupportPlan:
    """Revalidate critical leaves and the macOS SSV anchor at a stage gate."""
    plan = require_full_c6_toolchain_support_plan(value)
    for expected in plan._bindings:
        if _capture_path_binding(expected.path, kind=expected.kind) != expected:
            raise FullC6ToolchainSupportError(
                "Full C6 critical support path changed"
            )
    if plan._anchor is not None:
        try:
            AppleAPFSPlatformAnchorProvider().verify_active_anchor(plan._anchor)
        except FullC6ReadSandboxError as exc:
            raise FullC6ToolchainSupportError(
                "Full C6 authenticated macOS platform anchor changed"
            ) from exc
    for binding in plan._platform_anchored_tools:
        if (
            plan._anchor is None
            or binding.anchor_sha256 != plan._anchor.digest
        ):
            raise FullC6ToolchainSupportError(
                "Full C6 platform-anchored tool lost its platform binding"
            )
        try:
            verify_tool_identity(binding.path, binding.identity)
        except ToolchainIdentityError as exc:
            raise FullC6ToolchainSupportError(
                "Full C6 platform-anchored tool bytes changed"
            ) from exc
    return plan


def _discover_python_runtime(
    python: Path,
    *,
    cwd: Path,
    environment: Mapping[str, str],
) -> tuple[Path, Path]:
    """Resolve the exact CPython 3.11 stdlib tree and shared runtime leaf."""
    raw = _stable_one_line(
        [os.fspath(python), "-I", "-B", "-S", "-c", _PYTHON_RUNTIME_PROBE],
        cwd=cwd,
        environment=environment,
    )
    try:
        document = json.loads(raw)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise FullC6ToolchainSupportError(
            "Full C6 Python runtime discovery returned invalid JSON"
        ) from exc
    fields = {
        "executable",
        "implementation",
        "major",
        "minor",
        "isolated",
        "no_site",
        "stdlib",
        "platstdlib",
        "libdir",
        "ldlibrary",
        "framework",
        "framework_install_dir",
    }
    if type(document) is not dict or set(document) != fields:
        raise FullC6ToolchainSupportError(
            "Full C6 Python runtime discovery shape is invalid"
        )
    if (
        document["implementation"] != "cpython"
        or type(document["major"]) is not int
        or type(document["minor"]) is not int
        or (document["major"], document["minor"]) != (3, 11)
        or document["isolated"] != 1
        or document["no_site"] != 1
    ):
        raise FullC6ToolchainSupportError(
            "Full C6 support runtime requires CPython 3.11 exactly"
        )
    text_fields = ("executable", "stdlib", "platstdlib", "libdir", "ldlibrary")
    if any(
        type(document[name]) is not str
        or not document[name]
        or len(document[name].encode("utf-8")) > MAX_FULL_C6_SUPPORT_PATH_BYTES
        or document[name] != unicodedata.normalize("NFC", document[name])
        or "\0" in document[name]
        for name in text_fields
    ):
        raise FullC6ToolchainSupportError(
            "Full C6 Python runtime discovery contains an invalid path"
        )
    executable = _resolved_real_file(Path(document["executable"]), executable=True)
    if executable != python:
        raise FullC6ToolchainSupportError(
            "Full C6 Python runtime executable differs from the selected tool"
        )
    optional_text_fields = ("framework", "framework_install_dir")
    if any(
        type(document[name]) is not str
        or len(document[name].encode("utf-8")) > MAX_FULL_C6_SUPPORT_PATH_BYTES
        or document[name] != unicodedata.normalize("NFC", document[name])
        or "\0" in document[name]
        for name in optional_text_fields
    ) or bool(document["framework"]) != bool(document["framework_install_dir"]):
        raise FullC6ToolchainSupportError(
            "Full C6 Python framework discovery is invalid"
        )
    stdlib = _resolved_real_directory(Path(document["stdlib"]))
    platstdlib = _resolved_real_directory(Path(document["platstdlib"]))
    if stdlib != platstdlib:
        raise FullC6ToolchainSupportError(
            "Full C6 Python stdlib and platform stdlib roots differ"
        )
    _require_within(_require_real_file(stdlib / "encodings" / "__init__.py"), stdlib)
    _require_within(_require_real_directory(stdlib / "lib-dynload"), stdlib)
    libdir = _resolved_real_directory(Path(document["libdir"]))
    library_name = document["ldlibrary"]
    framework_name = document["framework"]
    if framework_name:
        if (
            framework_name != Path(framework_name).name
            or "/" in framework_name
            or "\\" in framework_name
        ):
            raise FullC6ToolchainSupportError(
                "Full C6 Python framework name is unsafe"
            )
        framework = _resolved_real_directory(
            Path(document["framework_install_dir"])
        )
        library = _resolved_real_file(
            framework / "Versions" / "3.11" / framework_name
        )
        _require_within(library, framework)
    else:
        if (
            library_name != Path(library_name).name
            or "/" in library_name
            or "\\" in library_name
        ):
            raise FullC6ToolchainSupportError(
                "Full C6 Python runtime library name is unsafe"
            )
        library = _resolved_real_file(libdir / library_name)
        _require_within(library, libdir)
    return stdlib, library


def _discover_macos_support(
    *,
    cwd: Path,
    python: Path,
    cargo: Path,
    rustc: Path,
    linker: Path,
    inspector: Path,
    platform_inspector_identity: ToolIdentity,
) -> FullC6ToolchainSupportPlan:
    environment = _macos_discovery_environment()
    expected_linker, expected_inspector = resolve_full_c6_linker_and_inspector(
        target_triple="aarch64-apple-darwin",
        cwd=cwd,
    )
    if linker != expected_linker or inspector != expected_inspector:
        raise FullC6ToolchainSupportError(
            "Full C6 selected macOS linker or inspector differs from Xcode"
        )
    if (
        platform_inspector_identity.name != "otool"
        or platform_inspector_identity.executable.logical_name
        != "toolchain/otool"
    ):
        raise FullC6ToolchainSupportError(
            "Full C6 macOS platform inspector identity is invalid"
        )
    try:
        verify_tool_identity(inspector, platform_inspector_identity)
    except ToolchainIdentityError as exc:
        raise FullC6ToolchainSupportError(
            "Full C6 macOS platform inspector bytes differ from tool identity"
        ) from exc
    sysroot, components = _discover_rust_sysroot(
        rustc,
        cwd=cwd,
        environment=environment,
    )
    python_runtime, python_library = _discover_python_runtime(
        python,
        cwd=cwd,
        environment=environment,
    )
    xcode_bin = linker.parent
    expected_bin = MACOS_XCODE_TOOL_BIN
    if xcode_bin != expected_bin:
        raise FullC6ToolchainSupportError("Full C6 Xcode tool bin root changed")
    ld = _xcrun_tool("ld", cwd=cwd, environment=environment, root=xcode_bin)
    ar = _xcrun_tool("ar", cwd=cwd, environment=environment, root=xcode_bin)
    ranlib = _xcrun_tool(
        "ranlib",
        cwd=cwd,
        environment=environment,
        root=xcode_bin,
        allow_symlink=True,
    )
    ranlib_implementation = _require_real_file(
        _resolve_inside(ranlib, xcode_bin),
        executable=True,
    )
    raw_sdk = _stable_absolute_output(
        [os.fspath(MACOS_XCRUN), "--sdk", "macosx", "--show-sdk-path"],
        cwd=cwd,
        environment=environment,
    )
    sdk = _resolve_inside(raw_sdk, MACOS_DEVELOPER_DIR)
    canonical_sdk = (
        MACOS_DEVELOPER_DIR
        / "Platforms"
        / "MacOSX.platform"
        / "Developer"
        / "SDKs"
        / "MacOSX.sdk"
    )
    if sdk != canonical_sdk:
        raise FullC6ToolchainSupportError(
            "Full C6 Xcode macOS SDK selection is not canonical"
        )
    sdk = _require_real_directory(sdk)
    sdk_settings = _require_real_file(sdk / "SDKSettings.json")
    resource = _stable_absolute_output(
        [os.fspath(linker), "--print-resource-dir"],
        cwd=cwd,
        environment=environment,
    )
    resource = _require_fixed_macos_clang_resource(resource)
    resource = _require_real_directory(resource)
    version_plist = _require_real_file(MACOS_XCODE_VERSION_PLIST)
    system_profile = _require_real_file(MACOS_SANDBOX_SYSTEM_PROFILE)
    dyld_profile = _require_real_file(MACOS_SANDBOX_DYLD_PROFILE)
    if _sandbox_imports(system_profile) != ("dyld-support.sb",):
        raise FullC6ToolchainSupportError(
            "Full C6 system.sb import closure differs from the fixed profile"
        )
    try:
        anchor = capture_active_macos_platform_anchor()
    except FullC6ReadSandboxError as exc:
        raise FullC6ToolchainSupportError(
            "Full C6 macOS authenticated SSV anchor is unavailable"
        ) from exc
    manifests = _locators(
        {
            "macos-sandbox-dyld-profile": dyld_profile,
            "macos-sandbox-system-profile": system_profile,
            "python-runtime-library": python_library,
            "rustup-components": components,
            "xcode-ar": ar,
            "xcode-clang": linker,
            "xcode-ld": ld,
            "xcode-ranlib": ranlib_implementation,
            "xcode-sdk-settings": sdk_settings,
            "xcode-version-plist": version_plist,
        },
        kind="file",
    )
    roots = _locators(
        {
            "python-runtime": python_runtime,
            "rust-sysroot": sysroot,
            "xcode-clang-resource": resource,
            "xcode-sdk": sdk,
        },
        kind="tree",
    )
    base_environment = {
        "AR": os.fspath(ar),
        "CC": os.fspath(linker),
        "DEVELOPER_DIR": os.fspath(MACOS_DEVELOPER_DIR),
        "LD": os.fspath(ld),
        "PATH": os.pathsep.join((os.fspath(cargo.parent), os.fspath(xcode_bin), "/usr/bin")),
        "RANLIB": os.fspath(ranlib),
        "SDKROOT": os.fspath(sdk),
    }
    critical = (
        python,
        cargo,
        rustc,
        linker,
        ld,
        ar,
        ranlib,
        ranlib_implementation,
        components,
        sdk_settings,
        version_plist,
        system_profile,
        dyld_profile,
        python_runtime,
        python_library,
        sysroot,
        sdk,
        resource,
    )
    return _new_plan(
        target_triple="aarch64-apple-darwin",
        python=python,
        cargo=cargo,
        rustc=rustc,
        linker=linker,
        inspector=inspector,
        manifests=manifests,
        roots=roots,
        base_environment=base_environment,
        anchor=anchor,
        elf_runtime_files=(),
        critical_paths=critical,
        platform_inspector_identity=platform_inspector_identity,
    )


def _discover_linux_support(
    *,
    cwd: Path,
    python: Path,
    cargo: Path,
    rustc: Path,
    linker: Path,
    inspector: Path,
) -> FullC6ToolchainSupportPlan:
    expected_linker, expected_inspector = resolve_full_c6_linker_and_inspector(
        target_triple="x86_64-unknown-linux-gnu",
        cwd=cwd,
    )
    if linker != expected_linker or inspector != expected_inspector:
        raise FullC6ToolchainSupportError(
            "Full C6 selected Linux linker or inspector differs from policy"
        )
    bwrap = _require_real_file(LINUX_BWRAP, executable=True)
    runtime_root = _require_real_directory(LINUX_RUNTIME_ROOT)
    ar = _resolved_real_file(LINUX_AR, executable=True)
    ranlib = _resolved_real_file(LINUX_RANLIB, executable=True)
    environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin",
    }
    sysroot, components = _discover_rust_sysroot(
        rustc,
        cwd=cwd,
        environment=environment,
    )
    target_libdir = _stable_absolute_output(
        [os.fspath(rustc), "--print", "target-libdir"],
        cwd=cwd,
        environment=environment,
    )
    target_libdir = _resolved_real_directory(target_libdir)
    _require_within(target_libdir, sysroot)
    python_runtime, python_library = _discover_python_runtime(
        python,
        cwd=cwd,
        environment=environment,
    )
    if python_library.name != LINUX_PYTHON_RUNTIME_LIBRARY_NAME:
        raise FullC6ToolchainSupportError(
            "Full C6 Linux requires the exact CPython 3.11 runtime library basename"
        )
    python_library_root = _require_real_directory(python_library.parent)
    launcher = _require_real_file(LINUX_LANDLOCK_LAUNCHER)
    libgcc = _stable_absolute_output(
        [os.fspath(linker), "--print-libgcc-file-name"],
        cwd=cwd,
        environment=environment,
    )
    libgcc = _resolved_real_file(libgcc)
    gcc_root = _require_real_directory(libgcc.parent)
    for name in ("crtbeginS.o", "crtendS.o"):
        member = _stable_absolute_output(
            [os.fspath(linker), f"--print-file-name={name}"],
            cwd=cwd,
            environment=environment,
        )
        if _resolved_real_file(member).parent != gcc_root:
            raise FullC6ToolchainSupportError(
                "Full C6 GCC private CRT support escaped its exact root"
            )
    for name in ("crt1.o", "crti.o", "crtn.o"):
        member = _stable_resolved_file_output(
            [os.fspath(linker), f"--print-file-name={name}"],
            cwd=cwd,
            environment=environment,
        )
        _require_within(member, runtime_root)
    raw_ld = _stable_one_line(
        [os.fspath(linker), "-print-prog-name=ld"],
        cwd=cwd,
        environment=environment,
    )
    ld_candidate = Path(raw_ld) if raw_ld.startswith("/") else Path("/usr/bin") / raw_ld
    binutils_ld = _resolved_real_file(ld_candidate, executable=True)
    runtime_files, loader = _discover_linux_elf_runtime(
        seeds=(
            python,
            python_library,
            cargo,
            rustc,
            linker,
            inspector,
            bwrap,
            binutils_ld,
            ar,
            ranlib,
        ),
        inspector=inspector,
        runtime_root=runtime_root,
        search_roots=(
            runtime_root,
            python_library_root,
            _require_real_directory(sysroot / "lib"),
            target_libdir,
            gcc_root,
        ),
        cwd=cwd,
        environment=environment,
    )
    manifests = _locators(
        {
            "landlock-launcher": launcher,
            "linux-ar": ar,
            "linux-binutils-ld": binutils_ld,
            "linux-bwrap": bwrap,
            "linux-dynamic-loader": loader,
            "linux-ranlib": ranlib,
            "python-runtime-library": python_library,
            "rustup-components": components,
        },
        kind="file",
    )
    roots = _locators(
        {
            "linux-gcc-support": gcc_root,
            "linux-python-library-support": python_library_root,
            "linux-runtime-support": runtime_root,
            "python-runtime": python_runtime,
            "rust-sysroot": sysroot,
        },
        kind="tree",
    )
    base_environment = {
        "AR": os.fspath(ar),
        "CC": os.fspath(linker),
        "COMPILER_PATH": os.pathsep.join(
            (os.fspath(binutils_ld.parent), os.fspath(gcc_root))
        ),
        "LD": os.fspath(binutils_ld),
        "LD_LIBRARY_PATH": _joined_unique_paths(
            (
                sysroot / "lib",
                python_library_root,
                runtime_root,
            )
        ),
        "LIBRARY_PATH": _joined_unique_paths(
            (
                gcc_root,
                runtime_root,
            )
        ),
        "PATH": os.pathsep.join((os.fspath(cargo.parent), "/usr/bin")),
        "RANLIB": os.fspath(ranlib),
    }
    critical = (
        python,
        cargo,
        rustc,
        linker,
        inspector,
        bwrap,
        binutils_ld,
        ar,
        ranlib,
        launcher,
        loader,
        components,
        libgcc,
        python_runtime,
        python_library,
        python_library_root,
        sysroot,
        target_libdir,
        runtime_root,
        gcc_root,
        *runtime_files,
    )
    return _new_plan(
        target_triple="x86_64-unknown-linux-gnu",
        python=python,
        cargo=cargo,
        rustc=rustc,
        linker=linker,
        inspector=inspector,
        manifests=manifests,
        roots=roots,
        base_environment=base_environment,
        anchor=None,
        elf_runtime_files=runtime_files,
        critical_paths=critical,
        platform_inspector_identity=None,
    )


def _new_plan(
    *,
    target_triple: str,
    python: Path,
    cargo: Path,
    rustc: Path,
    linker: Path,
    inspector: Path,
    manifests: tuple[ToolchainSupportLocator, ...],
    roots: tuple[ToolchainSupportLocator, ...],
    base_environment: Mapping[str, str],
    anchor: MacOSPlatformAnchor | None,
    elf_runtime_files: Sequence[Path],
    critical_paths: Sequence[Path],
    platform_inspector_identity: ToolIdentity | None,
) -> FullC6ToolchainSupportPlan:
    expected_manifests, expected_roots = expected_full_c6_toolchain_support_roles(
        target_triple
    )
    if (
        tuple(item.logical_role for item in manifests) != expected_manifests
        or tuple(item.logical_role for item in roots) != expected_roots
        or any(item.kind != "file" for item in manifests)
        or any(item.kind != "tree" for item in roots)
    ):
        raise FullC6ToolchainSupportError(
            "Full C6 discovered support roles or kinds are incomplete"
        )
    environment = _validated_environment(base_environment)
    runtime_files = tuple(sorted(set(elf_runtime_files), key=os.fspath))
    if (
        len(runtime_files) > MAX_FULL_C6_ELF_RUNTIME_FILES
        or (target_triple.endswith("linux-gnu") and not runtime_files)
        or (target_triple.endswith("apple-darwin") and runtime_files)
    ):
        raise FullC6ToolchainSupportError(
            "Full C6 ELF runtime closure is outside its fixed bound"
        )
    platform_anchored_tools: tuple[_PlatformAnchoredToolBinding, ...]
    if target_triple.endswith("apple-darwin"):
        if (
            anchor is None
            or type(platform_inspector_identity) is not ToolIdentity
            or platform_inspector_identity.name != "otool"
        ):
            raise FullC6ToolchainSupportError(
                "Full C6 macOS platform-anchored tool binding is incomplete"
            )
        platform_anchored_tools = (
            _PlatformAnchoredToolBinding(
                kind="platform-anchored-tool",
                path=inspector,
                identity=platform_inspector_identity,
                anchor_sha256=anchor.digest,
            ),
        )
    elif anchor is not None or platform_inspector_identity is not None:
        raise FullC6ToolchainSupportError(
            "Full C6 Linux platform-anchored tool binding is invalid"
        )
    else:
        platform_anchored_tools = ()
    rust_sysroot_locator = next(
        (item for item in roots if item.logical_role == "rust-sysroot"),
        None,
    )
    if (
        rust_sysroot_locator is None
        or cargo != rust_sysroot_locator._absolute_path / "bin" / "cargo"
        or rustc != rust_sysroot_locator._absolute_path / "bin" / "rustc"
    ):
        raise FullC6ToolchainSupportError(
            "Full C6 selected Cargo or rustc differs from the exact Rust sysroot leaves"
        )
    unique_critical = tuple(dict.fromkeys(Path(item) for item in critical_paths))
    bindings = tuple(
        _capture_path_binding(
            path,
            kind=(
                "symlink"
                if path.is_symlink()
                else "tree" if path.is_dir() else "file"
            ),
        )
        for path in unique_critical
    )
    mapping_rows: list[FullC6SupportNamespaceMapping] = [
        FullC6SupportNamespaceMapping(
            logical_role="toolchain-python311",
            host_path=python,
            virtual_path=_support_virtual_path("toolchain-python311"),
            kind="file",
        ),
        FullC6SupportNamespaceMapping(
            logical_role="toolchain-cargo",
            host_path=cargo,
            virtual_path=_support_virtual_path("toolchain-cargo"),
            kind="file",
        ),
        FullC6SupportNamespaceMapping(
            logical_role="toolchain-rustc",
            host_path=rustc,
            virtual_path=_support_virtual_path("toolchain-rustc"),
            kind="file",
        ),
        FullC6SupportNamespaceMapping(
            logical_role="toolchain-linker",
            host_path=linker,
            virtual_path=_support_virtual_path("toolchain-linker"),
            kind="file",
        ),
    ]
    for locator in (*manifests, *roots):
        if locator.logical_role == "python-runtime":
            role = "toolchain-python311-stdlib"
        elif locator.logical_role == "python-runtime-library":
            role = "toolchain-python311-runtime-library"
        elif locator.logical_role == "landlock-launcher":
            role = "support-landlock-launcher"
        elif locator.logical_role == "linux-gcc-support":
            role = "support-gcc-toolchain"
        elif locator.logical_role == "linux-python-library-support":
            role = "support-python-library-root"
        elif locator.logical_role == "linux-runtime-support":
            role = "support-runtime-libs"
        elif locator.logical_role == "linux-dynamic-loader":
            role = "runtime-loader-mirror"
        elif locator.logical_role in {"linux-ar", "xcode-ar"}:
            role = "toolchain-ar"
        elif locator.logical_role in {"linux-binutils-ld", "xcode-ld"}:
            role = "toolchain-ld"
        elif locator.logical_role in {"linux-ranlib", "xcode-ranlib"}:
            role = "toolchain-ranlib"
        elif locator.logical_role == "rust-sysroot":
            role = "toolchain-rust-sysroot"
        else:
            role = f"support-{locator.logical_role}"
        mapping_rows.append(
            FullC6SupportNamespaceMapping(
                logical_role=role,
                host_path=locator._absolute_path,
                virtual_path=_support_virtual_path(
                    role,
                    host_path=locator._absolute_path,
                ),
                kind=locator.kind,
            )
        )
    mappings = tuple(
        sorted(
            mapping_rows,
            key=lambda item: (
                len(item.virtual_path.parts),
                item.virtual_path.as_posix(),
                item.logical_role,
            ),
        )
    )
    if len({item.logical_role for item in mappings}) != len(mappings) or len(
        {item.virtual_path for item in mappings}
    ) != len(mappings):
        raise FullC6ToolchainSupportError(
            "Full C6 support namespace mappings are ambiguous"
        )
    plan = object.__new__(FullC6ToolchainSupportPlan)
    object.__setattr__(plan, "_target_triple", target_triple)
    object.__setattr__(plan, "_linker_path", linker)
    object.__setattr__(plan, "_inspector_path", inspector)
    object.__setattr__(plan, "_manifest_locators", manifests)
    object.__setattr__(plan, "_root_locators", roots)
    object.__setattr__(plan, "_base_environment", environment)
    object.__setattr__(plan, "_anchor", anchor)
    object.__setattr__(plan, "_elf_runtime_files", runtime_files)
    object.__setattr__(plan, "_bindings", bindings)
    object.__setattr__(plan, "_mappings", mappings)
    object.__setattr__(
        plan,
        "_platform_anchored_tools",
        platform_anchored_tools,
    )
    object.__setattr__(plan, "_seal", _plan_seal(plan))
    require_full_c6_toolchain_support_plan(plan)
    return plan


def _discover_rust_sysroot(
    rustc: Path,
    *,
    cwd: Path,
    environment: Mapping[str, str],
) -> tuple[Path, Path]:
    sysroot = _stable_absolute_output(
        [os.fspath(rustc), "--print", "sysroot"],
        cwd=cwd,
        environment=environment,
    )
    sysroot = _require_real_directory(sysroot)
    components = _require_real_file(sysroot / "lib" / "rustlib" / "components")
    return sysroot, components


def _discover_linux_elf_runtime(
    *,
    seeds: Sequence[Path],
    inspector: Path,
    runtime_root: Path,
    search_roots: Sequence[Path],
    cwd: Path,
    environment: Mapping[str, str],
) -> tuple[tuple[Path, ...], Path]:
    roots = tuple(dict.fromkeys(_require_real_directory(path) for path in search_roots))
    if not roots or runtime_root not in roots:
        raise FullC6ToolchainSupportError(
            "Full C6 ELF dependency search roots are incomplete"
        )
    pending = list(dict.fromkeys(seeds))
    visited: set[Path] = set()
    runtime_files: set[Path] = set()
    loaders: set[Path] = set()
    while pending:
        image = pending.pop(0)
        if image in visited:
            continue
        visited.add(image)
        if len(visited) > MAX_FULL_C6_ELF_RUNTIME_FILES:
            raise FullC6ToolchainSupportError(
                "Full C6 ELF runtime closure exceeds its file bound"
            )
        program = _stable_output(
            [os.fspath(inspector), "-W", "-l", os.fspath(image)],
            cwd=cwd,
            environment=environment,
        )
        dynamic = _stable_output(
            [os.fspath(inspector), "-W", "-d", os.fspath(image)],
            cwd=cwd,
            environment=environment,
        )
        interpreter_rows = tuple(
            match.group("path") for match in _ELF_INTERP_RE.finditer(program)
        )
        if len(interpreter_rows) > 1:
            raise FullC6ToolchainSupportError(
                "Full C6 ELF image has ambiguous PT_INTERP"
            )
        if interpreter_rows:
            loader = _resolved_real_file(Path(interpreter_rows[0]), executable=True)
            _require_within(loader, runtime_root)
            loaders.add(loader)
            runtime_files.add(loader)
        needed = tuple(match.group("name") for match in _ELF_NEEDED_RE.finditer(dynamic))
        if len(needed) > MAX_FULL_C6_ELF_NEEDED_PER_IMAGE or len(set(needed)) != len(needed):
            raise FullC6ToolchainSupportError(
                "Full C6 ELF DT_NEEDED set is ambiguous or outside the bound"
            )
        for name in needed:
            if (
                not name
                or "/" in name
                or "\\" in name
                or name != unicodedata.normalize("NFC", name)
                or any(ord(character) < 33 or ord(character) > 126 for character in name)
            ):
                raise FullC6ToolchainSupportError(
                    "Full C6 ELF DT_NEEDED name is unsafe"
                )
            dependency = _resolve_linux_needed_dependency(name, roots)
            runtime_files.add(dependency)
            if dependency not in visited:
                pending.append(dependency)
    if len(loaders) != 1:
        raise FullC6ToolchainSupportError(
            "Full C6 ELF closure requires one exact dynamic loader"
        )
    return tuple(sorted(runtime_files, key=os.fspath)), next(iter(loaders))


def _resolve_linux_needed_dependency(
    name: str,
    search_roots: Sequence[Path],
) -> Path:
    """Resolve one safe DT_NEEDED basename uniquely across fixed direct roots."""
    matches: set[Path] = set()
    for root in tuple(dict.fromkeys(search_roots)):
        candidate = root / name
        try:
            os.lstat(candidate)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise FullC6ToolchainSupportError(
                "Full C6 ELF dependency candidate could not be inspected"
            ) from exc
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise FullC6ToolchainSupportError(
                "Full C6 ELF dependency candidate could not be resolved"
            ) from exc
        resolved = _require_real_file(resolved)
        _require_within(resolved, root)
        matches.add(resolved)
    if not matches:
        raise FullC6ToolchainSupportError(
            "Full C6 ELF dependency is missing from the fixed search roots"
        )
    if len(matches) != 1:
        raise FullC6ToolchainSupportError(
            "Full C6 ELF dependency resolution is ambiguous"
        )
    return next(iter(matches))


def _xcrun_tool(
    name: str,
    *,
    cwd: Path,
    environment: Mapping[str, str],
    root: Path,
    allow_symlink: bool = False,
) -> Path:
    path = _stable_absolute_output(
        [os.fspath(MACOS_XCRUN), "--find", name],
        cwd=cwd,
        environment=environment,
    )
    if path.parent != root or path.name != name:
        raise FullC6ToolchainSupportError(
            f"Full C6 Xcode {name} selection is not canonical"
        )
    if path.is_symlink():
        if not allow_symlink:
            raise FullC6ToolchainSupportError(
                f"Full C6 Xcode {name} selection is an unexpected symlink"
            )
        _require_support_symlink(path)
        _require_real_file(_resolve_inside(path, root), executable=True)
        return path
    return _require_real_file(path, executable=True)


def _require_fixed_macos_clang_resource(path: Path) -> Path:
    """Admit only clang 17 from the fixed XcodeDefault toolchain layout."""
    if path != MACOS_XCODE_CLANG_RESOURCE:
        raise FullC6ToolchainSupportError(
            "Full C6 Xcode clang resource differs from the fixed version profile"
        )
    return path


def _macos_discovery_environment() -> dict[str, str]:
    return {
        "DEVELOPER_DIR": os.fspath(MACOS_DEVELOPER_DIR),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/usr/sbin",
    }


def _stable_absolute_output(
    command: list[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
) -> Path:
    value = _stable_one_line(command, cwd=cwd, environment=environment)
    path = Path(value)
    if (
        not path.is_absolute()
        or value != os.path.abspath(value)
        or value != unicodedata.normalize("NFC", value)
        or len(os.fsencode(value)) > MAX_FULL_C6_SUPPORT_PATH_BYTES
    ):
        raise FullC6ToolchainSupportError(
            "Full C6 support discovery returned a noncanonical absolute path"
        )
    return path


def _stable_resolved_file_output(
    command: list[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
) -> Path:
    """Resolve one stable absolute file selection before exact leaf admission."""
    value = _stable_one_line(command, cwd=cwd, environment=environment)
    if (
        type(value) is not str
        or not Path(value).is_absolute()
        or value != unicodedata.normalize("NFC", value)
        or len(os.fsencode(value)) > MAX_FULL_C6_SUPPORT_PATH_BYTES
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise FullC6ToolchainSupportError(
            "Full C6 support discovery returned an invalid absolute file path"
        )
    try:
        resolved = Path(value).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise FullC6ToolchainSupportError(
            "Full C6 support discovery file could not be resolved"
        ) from exc
    return _require_real_file(resolved)


def _stable_one_line(
    command: list[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
) -> str:
    first = _stable_output(command, cwd=cwd, environment=environment)
    lines = tuple(line.strip() for line in first.splitlines() if line.strip())
    if len(lines) != 1:
        raise FullC6ToolchainSupportError(
            "Full C6 support discovery output is missing or ambiguous"
        )
    value = lines[0]
    if (
        len(value.encode("utf-8")) > MAX_FULL_C6_SUPPORT_PATH_BYTES
        or value != unicodedata.normalize("NFC", value)
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise FullC6ToolchainSupportError(
            "Full C6 support discovery output is invalid"
        )
    return value


def _stable_output(
    command: list[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
) -> str:
    outputs: list[str] = []
    for _ in range(2):
        completed = run_build_tool(
            command,
            cwd=cwd,
            timeout=30.0,
            env=environment,
            inherit_env=False,
            max_output_bytes=MAX_FULL_C6_SUPPORT_OUTPUT_BYTES,
        )
        if completed.returncode != 0:
            raise FullC6ToolchainSupportError(
                "Full C6 support discovery command failed closed"
            )
        output = completed.stdout or ""
        if not output or len(output.encode("utf-8")) > MAX_FULL_C6_SUPPORT_OUTPUT_BYTES:
            raise FullC6ToolchainSupportError(
                "Full C6 support discovery output is empty or too large"
            )
        outputs.append(output)
    if outputs[0] != outputs[1]:
        raise FullC6ToolchainSupportError(
            "Full C6 support discovery output changed across probes"
        )
    return outputs[0]


def _locators(
    paths: Mapping[str, Path],
    *,
    kind: str,
) -> tuple[ToolchainSupportLocator, ...]:
    try:
        return tuple(
            create_toolchain_support_locator(
                logical_role=role,
                path=paths[role],
                kind=kind,
            )
            for role in sorted(paths)
        )
    except ToolchainSupportLockError as exc:
        raise FullC6ToolchainSupportError(
            "Full C6 support locator discovery failed closed"
        ) from exc


def _sandbox_imports(path: Path) -> tuple[str, ...]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise FullC6ToolchainSupportError(
            "Full C6 sandbox support profile could not be read"
        ) from exc
    if len(data) > 1024 * 1024:
        raise FullC6ToolchainSupportError(
            "Full C6 sandbox support profile exceeds its bound"
        )
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FullC6ToolchainSupportError(
            "Full C6 sandbox support profile is not UTF-8"
        ) from exc
    imports = tuple(
        match.group(1)
        for match in re.finditer(r'^\s*\(import "([A-Za-z0-9._-]+\.sb)"\)\s*$', text, re.MULTILINE)
    )
    return imports


def _validated_environment(value: Mapping[str, str]) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, Mapping) or not value:
        raise FullC6ToolchainSupportError(
            "Full C6 support environment is missing"
        )
    rows: list[tuple[str, str]] = []
    for name, item in value.items():
        if (
            type(name) is not str
            or type(item) is not str
            or not name
            or "\0" in item
            or len(item.encode("utf-8")) > MAX_FULL_C6_SUPPORT_ENV_BYTES
        ):
            raise FullC6ToolchainSupportError(
                "Full C6 support environment is invalid"
            )
        rows.append((name, item))
    return tuple(sorted(rows))


def _capture_path_binding(path: Path, *, kind: str) -> _PathBinding:
    if kind not in {"file", "symlink", "tree"}:
        raise FullC6ToolchainSupportError("Full C6 support path kind is invalid")
    if kind == "file":
        expected = _require_real_file(path)
    elif kind == "symlink":
        expected = _require_support_symlink(path)
    else:
        expected = _require_real_directory(path)
    try:
        before = os.lstat(expected)
    except OSError as exc:
        raise FullC6ToolchainSupportError(
            "Full C6 critical support path is unavailable"
        ) from exc
    raw_sha256: str | None = None
    if kind == "file":
        digest = hashlib.sha256()
        try:
            with expected.open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    digest.update(chunk)
        except OSError as exc:
            raise FullC6ToolchainSupportError(
                "Full C6 critical support file could not be read"
            ) from exc
        raw_sha256 = digest.hexdigest()
    elif kind == "symlink":
        try:
            target = os.readlink(expected)
        except OSError as exc:
            raise FullC6ToolchainSupportError(
                "Full C6 critical support symlink could not be read"
            ) from exc
        raw_sha256 = hashlib.sha256(os.fsencode(target)).hexdigest()
    try:
        after = os.lstat(expected)
    except OSError as exc:
        raise FullC6ToolchainSupportError(
            "Full C6 critical support path changed"
        ) from exc
    if _stat_key(before) != _stat_key(after):
        raise FullC6ToolchainSupportError(
            "Full C6 critical support path changed during capture"
        )
    return _PathBinding(
        path=expected,
        kind=kind,
        device=after.st_dev,
        inode=after.st_ino,
        mode=stat.S_IMODE(after.st_mode),
        size=after.st_size,
        mtime_ns=getattr(after, "st_mtime_ns", int(after.st_mtime * 1_000_000_000)),
        ctime_ns=getattr(after, "st_ctime_ns", int(after.st_ctime * 1_000_000_000)),
        raw_sha256=raw_sha256,
    )


def _require_real_file(path: Path, *, executable: bool = False) -> Path:
    path = _canonical_absolute(path)
    try:
        observed = os.lstat(path)
    except OSError as exc:
        raise FullC6ToolchainSupportError(
            "Full C6 support file is unavailable"
        ) from exc
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISREG(observed.st_mode)
        or observed.st_nlink != 1
        or (executable and not os.access(path, os.X_OK))
    ):
        raise FullC6ToolchainSupportError(
            "Full C6 support file is unsafe or aliased"
        )
    return path


def _require_support_symlink(path: Path) -> Path:
    path = _canonical_absolute(path)
    try:
        observed = os.lstat(path)
        target = os.readlink(path)
    except OSError as exc:
        raise FullC6ToolchainSupportError(
            "Full C6 support symlink is unavailable"
        ) from exc
    if (
        not stat.S_ISLNK(observed.st_mode)
        or observed.st_nlink != 1
        or not target
        or target != Path(target).name
        or target in {".", ".."}
        or target != unicodedata.normalize("NFC", target)
        or len(os.fsencode(target)) > MAX_FULL_C6_SUPPORT_PATH_BYTES
    ):
        raise FullC6ToolchainSupportError(
            "Full C6 support symlink is unsafe or aliased"
        )
    return path


def _require_platform_anchored_macos_tool(path: Path) -> Path:
    """Admit only the exact read-only SSV inspector; its bytes bind elsewhere."""
    path = _canonical_absolute(path)
    if path != MACOS_OTOOL:
        raise FullC6ToolchainSupportError(
            "Full C6 platform-anchored macOS tool is outside the fixed profile"
        )
    try:
        observed = os.lstat(path)
    except OSError as exc:
        raise FullC6ToolchainSupportError(
            "Full C6 platform-anchored macOS tool is unavailable"
        ) from exc
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISREG(observed.st_mode)
        or observed.st_nlink < 1
        or not os.access(path, os.X_OK)
    ):
        raise FullC6ToolchainSupportError(
            "Full C6 platform-anchored macOS tool is unsafe"
        )
    return path


def _resolved_real_file(path: Path, *, executable: bool = False) -> Path:
    canonical = _canonical_absolute(path)
    try:
        resolved = canonical.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise FullC6ToolchainSupportError(
            "Full C6 support executable could not be resolved"
        ) from exc
    return _require_real_file(resolved, executable=executable)


def _resolved_real_directory(path: Path) -> Path:
    try:
        resolved = _canonical_absolute(path).resolve(strict=True)
    except OSError as exc:
        raise FullC6ToolchainSupportError(
            "Full C6 support directory could not be resolved"
        ) from exc
    return _require_real_directory(resolved)


def _require_real_directory(path: Path) -> Path:
    path = _canonical_absolute(path)
    try:
        observed = os.lstat(path)
    except OSError as exc:
        raise FullC6ToolchainSupportError(
            "Full C6 support directory is unavailable"
        ) from exc
    if stat.S_ISLNK(observed.st_mode) or not stat.S_ISDIR(observed.st_mode):
        raise FullC6ToolchainSupportError(
            "Full C6 support directory is unsafe or aliased"
        )
    return path


def _resolve_inside(path: Path, root: Path) -> Path:
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise FullC6ToolchainSupportError(
            "Full C6 support selection escaped its fixed root"
        ) from exc
    return resolved


def _require_within(path: Path, root: Path) -> None:
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise FullC6ToolchainSupportError(
            "Full C6 support dependency escaped its fixed root"
        ) from exc


def _canonical_absolute(path: Path) -> Path:
    value = os.fspath(path)
    if (
        type(value) is not str
        or not value
        or not value.startswith("/")
        or value != os.path.abspath(value)
        or value != unicodedata.normalize("NFC", value)
        or len(os.fsencode(value)) > MAX_FULL_C6_SUPPORT_PATH_BYTES
    ):
        raise FullC6ToolchainSupportError(
            "Full C6 support path is not canonical absolute NFC"
        )
    return Path(value)


def _stat_key(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        stat.S_IFMT(value.st_mode),
        stat.S_IMODE(value.st_mode),
        value.st_nlink,
        value.st_size,
        getattr(value, "st_mtime_ns", int(value.st_mtime * 1_000_000_000)),
        getattr(value, "st_ctime_ns", int(value.st_ctime * 1_000_000_000)),
    )


def _path_digest(path: Path) -> str:
    return hashlib.sha256(
        b"rextio.full-c6-support-private-path.v1\0" + os.fsencode(path)
    ).hexdigest()


def _support_virtual_path(
    logical_role: str,
    *,
    host_path: Path | None = None,
) -> PurePosixPath:
    special = {
        "runtime-loader-mirror": PurePosixPath(
            "/lib64/ld-linux-x86-64.so.2"
        ),
        "support-landlock-launcher": PurePosixPath(
            "/rextio/support/rextio/full_c6_linux_launcher.py"
        ),
        "support-runtime-libs": PurePosixPath(
            FULL_C6_LINUX_RUNTIME_SUPPORT_ROOT
        ),
        "toolchain-python311": PurePosixPath(
            "/rextio/toolchain/bin/python3.11"
        ),
        "toolchain-python311-stdlib": PurePosixPath(
            "/rextio/toolchain/lib/python3.11"
        ),
        "toolchain-ar": PurePosixPath("/rextio/toolchain/bin/ar"),
        "toolchain-cargo": PurePosixPath("/rextio/toolchain/bin/cargo"),
        "toolchain-ld": PurePosixPath("/rextio/toolchain/bin/ld"),
        "toolchain-linker": PurePosixPath("/rextio/toolchain/bin/linker"),
        "toolchain-ranlib": PurePosixPath(
            "/rextio/toolchain/bin/ranlib"
        ),
        "toolchain-rustc": PurePosixPath("/rextio/toolchain/bin/rustc"),
        "toolchain-rust-sysroot": PurePosixPath("/rextio/toolchain"),
    }
    if logical_role == "toolchain-python311-runtime-library":
        if (
            not isinstance(host_path, Path)
            or not host_path.is_absolute()
            or host_path.name != unicodedata.normalize("NFC", host_path.name)
            or not host_path.name
            or host_path.name in {".", ".."}
            or "/" in host_path.name
            or "\\" in host_path.name
        ):
            raise ValueError(
                "Full C6 Python runtime library namespace path is invalid"
            )
        return FULL_C6_TOOLCHAIN_VIRTUAL_ROOT / "lib" / host_path.name
    if logical_role in special:
        return special[logical_role]
    if not logical_role.startswith("support-"):
        raise ValueError("Full C6 support namespace role is invalid")
    leaf = logical_role.removeprefix("support-")
    if _ROLE_RE.fullmatch(leaf) is None:
        raise ValueError("Full C6 support namespace leaf is invalid")
    return FULL_C6_TOOLCHAIN_SUPPORT_VIRTUAL_ROOT / leaf


def _joined_unique_paths(paths: Sequence[Path]) -> str:
    canonical = tuple(dict.fromkeys(_require_real_directory(path) for path in paths))
    if not canonical:
        raise FullC6ToolchainSupportError(
            "Full C6 support path list is empty"
        )
    return os.pathsep.join(os.fspath(path) for path in canonical)


def _plan_payload(plan: FullC6ToolchainSupportPlan) -> dict[str, object]:
    return {
        "domain": FULL_C6_TOOLCHAIN_SUPPORT_PLAN_DOMAIN,
        "target_triple": plan._target_triple,
        "objects": {
            "manifests": [id(item) for item in plan._manifest_locators],
            "roots": [id(item) for item in plan._root_locators],
        },
        "linker_path_sha256": _path_digest(plan._linker_path),
        "inspector_path_sha256": _path_digest(plan._inspector_path),
        "manifests": [
            (item.logical_role, item.kind, _path_digest(item._absolute_path))
            for item in plan._manifest_locators
        ],
        "roots": [
            (item.logical_role, item.kind, _path_digest(item._absolute_path))
            for item in plan._root_locators
        ],
        "environment": [
            (name, hashlib.sha256(value.encode("utf-8")).hexdigest(), len(value.encode("utf-8")))
            for name, value in plan._base_environment
        ],
        "anchor_sha256": plan._anchor.digest if plan._anchor is not None else "0" * 64,
        "platform_anchored_tools": [
            {
                "kind": item.kind,
                "path_sha256": _path_digest(item.path),
                "identity": item.identity.to_dict(),
                "anchor_sha256": item.anchor_sha256,
            }
            for item in plan._platform_anchored_tools
        ],
        "elf_runtime_paths": [_path_digest(path) for path in plan._elf_runtime_files],
        "bindings": [
            (
                item.opaque_path_sha256,
                item.kind,
                item.device,
                item.inode,
                item.mode,
                item.size,
                item.mtime_ns,
                item.ctime_ns,
                item.raw_sha256,
            )
            for item in plan._bindings
        ],
        "mappings": [
            (
                item.logical_role,
                _path_digest(item.host_path),
                item.virtual_path.as_posix(),
                item.kind,
            )
            for item in plan._mappings
        ],
    }


def _plan_seal(plan: FullC6ToolchainSupportPlan) -> bytes:
    return hmac.new(_SEAL_KEY, _canonical_json(_plan_payload(plan)), hashlib.sha256).digest()


def _plan_digest(plan: FullC6ToolchainSupportPlan) -> str:
    payload = _plan_payload(plan)
    payload.pop("objects")
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _canonical_project_relative_output(value: object) -> str:
    path = _canonical_project_relative_path(
        value,
        label="support-lock output",
    )
    if not path.endswith(".json"):
        raise FullC6ToolchainSupportError(
            "Full C6 support-lock output is not a canonical project-relative JSON path"
        )
    return path


def _canonical_project_relative_path(value: object, *, label: str) -> str:
    if type(value) is not str:
        raise FullC6ToolchainSupportError(
            f"Full C6 {label} must be project-relative text"
        )
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if (
        not value
        or value != value.strip()
        or value != unicodedata.normalize("NFC", value)
        or len(value.encode("utf-8")) > 4096
        or "\\" in value
        or "\0" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or posix.is_absolute()
        or windows.is_absolute()
        or bool(windows.drive)
        or posix.as_posix() != value
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise FullC6ToolchainSupportError(
            f"Full C6 {label} is not a canonical project-relative path"
        )
    return value


def _canonical_absolute_project_root(value: Path | str) -> Path:
    try:
        text = os.fspath(value)
    except TypeError as exc:
        raise FullC6ToolchainSupportError(
            "Full C6 support-lock project root is invalid"
        ) from exc
    if (
        type(text) is not str
        or not text
        or "\0" in text
        or text != unicodedata.normalize("NFC", text)
    ):
        raise FullC6ToolchainSupportError(
            "Full C6 support-lock project root is invalid"
        )
    root = Path(os.path.abspath(text))
    if len(os.fsencode(root)) > MAX_FULL_C6_SUPPORT_PATH_BYTES:
        raise FullC6ToolchainSupportError(
            "Full C6 support-lock project root exceeds its path bound"
        )
    return root


def _require_nonaliased_support_output(
    output: str,
    *,
    configured_artifact_paths: Sequence[str],
) -> None:
    if isinstance(configured_artifact_paths, (str, bytes)):
        raise FullC6ToolchainSupportError(
            "Full C6 configured artifact paths are invalid"
        )
    candidate = _alias_path_parts(output)
    for configured in configured_artifact_paths:
        other = _canonical_project_relative_path(
            configured,
            label="configured artifact path",
        )
        other_parts = _alias_path_parts(other)
        if (
            candidate == other_parts
            or candidate[: len(other_parts)] == other_parts
            or other_parts[: len(candidate)] == candidate
        ):
            raise FullC6ToolchainSupportError(
                "Full C6 support-lock output aliases another configured artifact path"
            )


def _alias_path_parts(value: str) -> tuple[str, ...]:
    return tuple(
        unicodedata.normalize("NFC", part).casefold()
        for part in PurePosixPath(value).parts
    )


def _atomic_create_or_exact_reuse_support_lock(
    *,
    project_root: Path,
    relative_output: str,
    payload: bytes,
) -> bool:
    if (
        type(payload) is not bytes
        or not payload
        or len(payload) > MAX_TOOLCHAIN_SUPPORT_LOCK_BYTES
    ):
        raise FullC6ToolchainSupportError(
            "Full C6 support-lock output bytes are invalid"
        )
    parent_fd, name = _open_support_output_parent(
        project_root,
        relative_output,
    )
    temporary = (
        f".{name}.rextio-{os.getpid()}-{secrets.token_hex(8)}.tmp"
    )
    descriptor = -1
    created_temporary = False
    try:
        existing = _read_support_output(parent_fd, name)
        if existing is not None:
            if not hmac.compare_digest(existing, payload):
                raise FullC6ToolchainSupportError(
                    "existing Full C6 support-lock output bytes differ"
                )
            return False
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | _require_nofollow()
        )
        descriptor = os.open(temporary, flags, 0o600, dir_fd=parent_fd)
        created_temporary = True
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        observed = os.fstat(descriptor)
        if (
            not stat.S_ISREG(observed.st_mode)
            or observed.st_nlink != 1
            or observed.st_size != len(payload)
            or stat.S_IMODE(observed.st_mode) != 0o600
        ):
            raise FullC6ToolchainSupportError(
                "Full C6 support-lock temporary output is unsafe"
            )
        os.close(descriptor)
        descriptor = -1
        try:
            os.link(
                temporary,
                name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            concurrent = _read_support_output(parent_fd, name)
            if concurrent is None or not hmac.compare_digest(concurrent, payload):
                raise FullC6ToolchainSupportError(
                    "concurrent Full C6 support-lock output bytes differ"
                ) from None
            return False
        os.unlink(temporary, dir_fd=parent_fd)
        created_temporary = False
        os.fsync(parent_fd)
        final = _read_support_output(parent_fd, name)
        if final is None or not hmac.compare_digest(final, payload):
            raise FullC6ToolchainSupportError(
                "Full C6 support-lock final bytes changed"
            )
        return True
    except FullC6ToolchainSupportError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise FullC6ToolchainSupportError(
            "Full C6 support-lock output transaction failed"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if created_temporary:
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except OSError:
                pass
        os.close(parent_fd)


def _open_support_output_parent(
    project_root: Path,
    relative_output: str,
) -> tuple[int, str]:
    nofollow = _require_nofollow()
    flags = (
        os.O_RDONLY
        | nofollow
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(project_root.anchor, flags)
    except OSError as exc:
        raise FullC6ToolchainSupportError(
            "Full C6 support-lock project root is unavailable"
        ) from exc
    try:
        for part in project_root.parts[1:]:
            descriptor = _open_child_directory(descriptor, part, flags)
        output = PurePosixPath(relative_output)
        for part in output.parts[:-1]:
            descriptor = _open_child_directory(descriptor, part, flags)
        parent = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.getuid()
            or stat.S_IMODE(parent.st_mode) != 0o700
        ):
            raise FullC6ToolchainSupportError(
                "Full C6 support-lock output parent must be owner-private mode 0700"
            )
        return descriptor, output.name
    except Exception:
        os.close(descriptor)
        raise


def _open_child_directory(parent_fd: int, name: str, flags: int) -> int:
    if name in {"", ".", ".."} or "/" in name or "\\" in name:
        raise FullC6ToolchainSupportError(
            "Full C6 support-lock output parent is unsafe"
        )
    child = -1
    try:
        child = os.open(name, flags, dir_fd=parent_fd)
        opened = os.fstat(child)
        linked = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        if child >= 0:
            os.close(child)
        raise FullC6ToolchainSupportError(
            "Full C6 support-lock output parent is unavailable or linked"
        ) from exc
    if (
        not stat.S_ISDIR(opened.st_mode)
        or opened.st_dev != linked.st_dev
        or opened.st_ino != linked.st_ino
    ):
        os.close(child)
        raise FullC6ToolchainSupportError(
            "Full C6 support-lock output parent changed"
        )
    os.close(parent_fd)
    return child


def _read_support_output(parent_fd: int, name: str) -> bytes | None:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | _require_nofollow()
    )
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise FullC6ToolchainSupportError(
            "Full C6 support-lock output is unsafe"
        ) from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size <= 0
            or before.st_size > MAX_TOOLCHAIN_SUPPORT_LOCK_BYTES
        ):
            raise FullC6ToolchainSupportError(
                "Full C6 support-lock output is not one private regular file"
            )
        data = bytearray()
        while len(data) <= MAX_TOOLCHAIN_SUPPORT_LOCK_BYTES:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, MAX_TOOLCHAIN_SUPPORT_LOCK_BYTES + 1 - len(data)),
            )
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
        if (
            len(data) != before.st_size
            or len(data) > MAX_TOOLCHAIN_SUPPORT_LOCK_BYTES
            or _support_stat_key(before) != _support_stat_key(after)
        ):
            raise FullC6ToolchainSupportError(
                "Full C6 support-lock output changed while reading"
            )
        return bytes(data)
    finally:
        os.close(descriptor)


def _support_stat_key(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise FullC6ToolchainSupportError(
                "Full C6 support-lock output write stalled"
            )
        offset += written


def _require_nofollow() -> int:
    value = getattr(os, "O_NOFOLLOW", None)
    if type(value) is not int or value == 0:
        raise FullC6ToolchainSupportError(
            "Full C6 support-lock bootstrap requires O_NOFOLLOW"
        )
    return value


__all__ = [
    "FULL_C6_TOOLCHAIN_SUPPORT_PLAN_DOMAIN",
    "FULL_C6_TOOLCHAIN_SUPPORT_TARGETS",
    "FULL_C6_TOOLCHAIN_SUPPORT_VIRTUAL_ROOT",
    "FULL_C6_TOOLCHAIN_VIRTUAL_ROOT",
    "LINUX_MANIFEST_ROLES",
    "LINUX_ROOT_ROLES",
    "MACOS_MANIFEST_ROLES",
    "MACOS_ROOT_ROLES",
    "FullC6SupportNamespaceMapping",
    "FullC6ToolchainSupportBootstrapResult",
    "FullC6ToolchainSupportError",
    "FullC6ToolchainSupportPlan",
    "bootstrap_full_c6_toolchain_support_lock",
    "discover_full_c6_toolchain_support",
    "expected_full_c6_toolchain_support_roles",
    "generate_full_c6_toolchain_support_lock",
    "materialize_full_c6_toolchain_support_lock",
    "require_full_c6_toolchain_support_plan",
    "revalidate_full_c6_toolchain_support_plan",
    "resolve_full_c6_linker_and_inspector",
    "verify_full_c6_toolchain_support_lock",
]
