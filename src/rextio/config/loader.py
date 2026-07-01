"""Loading and overriding rextio.toml configuration."""

from __future__ import annotations

import math
import re
import tomllib
from dataclasses import asdict
from pathlib import Path
from typing import Any, Mapping

from rextio.limits import MAX_BUILD_TIMEOUT_SECONDS
from rextio.config.defaults import DEFAULT_CONFIG
from rextio.config.schema import (
    BuildConfig,
    ExecutableConfig,
    FallbackConfig,
    ImportPackagePolicy,
    ImportsConfig,
    JitConfig,
    PolicyConfig,
    PluginConfig,
    RextioConfig,
    RustConfig,
    TargetConfig,
)


class ConfigError(RuntimeError):
    """Raised when configuration is invalid or cannot be loaded."""

    pass


CONFIG_KEYS = {
    "build": {"native_backend", "fallback_backend", "fallback_threshold", "build_timeout_seconds"},
    "rust": {"binding", "build_tool", "importable", "crate_name"},
    "fallback": {"nuitka"},
    "target": {"version", "build_options"},
    "plugins": {"enabled"},
    "imports": {"default_external_policy", "packages"},
    "jit": {"enabled", "backend", "hot_threshold"},
    "executable": {"entrypoint", "name", "backend", "nuitka_mode", "python"},
    "policy": {
        "native_marker",
        "require_type_hints",
        "allow_dynamic_features",
        "boundary_warnings",
        "native_top_level",
    },
}

ENVIRONMENT_OVERRIDES = {
    "REXTIO_NATIVE_BACKEND": ("build", "native_backend", "string"),
    "REXTIO_TARGET_LANGUAGE": ("build", "native_backend", "string"),
    "REXTIO_FALLBACK_BACKEND": ("build", "fallback_backend", "string"),
    "REXTIO_BOUNDARY_FALLBACK_THRESHOLD": ("build", "fallback_threshold", "integer"),
    "REXTIO_BUILD_TIMEOUT": ("build", "build_timeout_seconds", "positive_number"),
    "REXTIO_RUST_BINDING": ("rust", "binding", "string"),
    "REXTIO_RUST_BUILD_TOOL": ("rust", "build_tool", "string"),
    "REXTIO_RUST_IMPORTABLE": ("rust", "importable", "boolean"),
    "REXTIO_RUST_CRATE_NAME": ("rust", "crate_name", "string"),
    "REXTIO_NUITKA_FALLBACK": ("fallback", "nuitka", "string"),
    "REXTIO_TARGET_VERSION": ("target", "version", "optional_string"),
    "REXTIO_TARGET_BUILD_OPTIONS": ("target", "build_options", "string_map"),
    "REXTIO_PLUGINS_ENABLED": ("plugins", "enabled", "string_list"),
    "REXTIO_IMPORTS_DEFAULT_EXTERNAL_POLICY": ("imports", "default_external_policy", "string"),
    "REXTIO_IMPORTS_PACKAGES": ("imports", "packages", "package_policy_map"),
    "REXTIO_JIT": ("jit", "enabled", "boolean"),
    "REXTIO_JIT_BACKEND": ("jit", "backend", "string"),
    "REXTIO_JIT_HOT_THRESHOLD": ("jit", "hot_threshold", "integer"),
    "REXTIO_EXECUTABLE_ENTRYPOINT": ("executable", "entrypoint", "optional_string"),
    "REXTIO_EXECUTABLE_NAME": ("executable", "name", "optional_string"),
    "REXTIO_EXECUTABLE_BACKEND": ("executable", "backend", "string"),
    "REXTIO_NUITKA_MODE": ("executable", "nuitka_mode", "string"),
    "REXTIO_EXECUTABLE_PYTHON": ("executable", "python", "optional_string"),
    "REXTIO_NATIVE_MARKER": ("policy", "native_marker", "string"),
    "REXTIO_REQUIRE_TYPE_HINTS": ("policy", "require_type_hints", "boolean"),
    "REXTIO_ALLOW_DYNAMIC_FEATURES": ("policy", "allow_dynamic_features", "boolean"),
    "REXTIO_BOUNDARY_WARNINGS": ("policy", "boundary_warnings", "boolean"),
    "REXTIO_NATIVE_TOP_LEVEL": ("policy", "native_top_level", "boolean"),
}


def _section(data: dict[str, object], name: str) -> dict[str, object]:
    value = data.get(name, {})
    if isinstance(value, dict):
        unknown = set(value) - CONFIG_KEYS[name]
        if unknown:
            key = sorted(unknown)[0]
            raise ConfigError(f"unsupported config key: [{name}].{key}")
        return value
    raise ConfigError(f"config section [{name}] must be a table")


def load_config(
    project_root: Path,
    environ: Mapping[str, str] | None = None,
) -> RextioConfig:
    """Load the project configuration from rextio.toml and the environment."""
    path = project_root / "rextio.toml"
    raw: dict[str, object] = dict(DEFAULT_CONFIG)
    if path.exists():
        try:
            parsed = tomllib.loads(path.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"failed to parse rextio.toml: {exc}") from exc
        unknown_sections = set(parsed) - set(CONFIG_KEYS)
        if unknown_sections:
            section = sorted(unknown_sections)[0]
            raise ConfigError(f"unsupported config section: [{section}]")
        raw = {**raw, **parsed}

    build = {**DEFAULT_CONFIG["build"], **_section(raw, "build")}
    rust = {**DEFAULT_CONFIG["rust"], **_section(raw, "rust")}
    fallback = {**DEFAULT_CONFIG["fallback"], **_section(raw, "fallback")}
    target = {**DEFAULT_CONFIG["target"], **_section(raw, "target")}
    plugins = {**DEFAULT_CONFIG["plugins"], **_section(raw, "plugins")}
    imports = {**DEFAULT_CONFIG["imports"], **_section(raw, "imports")}
    jit = {**DEFAULT_CONFIG["jit"], **_section(raw, "jit")}
    executable = {**DEFAULT_CONFIG["executable"], **_section(raw, "executable")}
    policy = {**DEFAULT_CONFIG["policy"], **_section(raw, "policy")}
    if environ is not None:
        _apply_environment_overrides(
            build,
            rust,
            fallback,
            target,
            plugins,
            imports,
            jit,
            executable,
            policy,
            environ,
        )
    return _build_config(build, rust, fallback, target, plugins, imports, jit, executable, policy)


def override_config(
    config: RextioConfig,
    overrides: Mapping[tuple[str, str], object | None],
) -> RextioConfig:
    """Apply CLI/programmatic overrides on top of a loaded config."""
    build = asdict(config.build)
    rust = asdict(config.rust)
    fallback = asdict(config.fallback)
    target = asdict(config.target)
    plugins = asdict(config.plugins)
    imports = _imports_asdict(config.imports)
    jit = asdict(config.jit)
    executable = asdict(config.executable)
    policy = asdict(config.policy)
    sections = {
        "build": build,
        "rust": rust,
        "fallback": fallback,
        "target": target,
        "plugins": plugins,
        "imports": imports,
        "jit": jit,
        "executable": executable,
        "policy": policy,
    }
    for (section, key), value in overrides.items():
        if value is None:
            continue
        if section not in sections or key not in CONFIG_KEYS[section]:
            raise ConfigError(f"unsupported config override: [{section}].{key}")
        sections[section][key] = value
    return _build_config(build, rust, fallback, target, plugins, imports, jit, executable, policy)


def _build_config(
    build: dict[str, Any],
    rust: dict[str, Any],
    fallback: dict[str, Any],
    target: dict[str, Any],
    plugins: dict[str, Any],
    imports: dict[str, Any],
    jit: dict[str, Any],
    executable: dict[str, Any],
    policy: dict[str, Any],
) -> RextioConfig:
    _validate_config_values(build, rust, fallback, target, plugins, imports, jit, executable, policy)
    return RextioConfig(
        build=BuildConfig(**build),
        rust=RustConfig(**rust),
        fallback=FallbackConfig(**fallback),
        target=TargetConfig(**target),
        plugins=PluginConfig(enabled=tuple(plugins["enabled"])),
        imports=_build_imports_config(imports),
        jit=JitConfig(**jit),
        executable=ExecutableConfig(**executable),
        policy=PolicyConfig(**policy),
    )


def _validate_config_values(
    build: dict[str, Any],
    rust: dict[str, Any],
    fallback: dict[str, Any],
    target: dict[str, Any],
    plugins: dict[str, Any],
    imports: dict[str, Any],
    jit: dict[str, Any],
    executable: dict[str, Any],
    policy: dict[str, Any],
) -> None:
    _require_string("build", "native_backend", build["native_backend"])
    _require_string("build", "fallback_backend", build["fallback_backend"])
    _require_non_negative_int("build", "fallback_threshold", build["fallback_threshold"])
    _require_positive_number(
        "build",
        "build_timeout_seconds",
        build["build_timeout_seconds"],
        maximum=MAX_BUILD_TIMEOUT_SECONDS,
    )
    _require_string("rust", "binding", rust["binding"])
    _require_string("rust", "build_tool", rust["build_tool"])
    _require_bool("rust", "importable", rust["importable"])
    _require_crate_name("rust", "crate_name", rust["crate_name"])
    _require_string("fallback", "nuitka", fallback["nuitka"])
    _require_optional_string("target", "version", target["version"])
    _require_string_map("target", "build_options", target["build_options"])
    _require_string_list("plugins", "enabled", plugins["enabled"])
    _require_string("imports", "default_external_policy", imports["default_external_policy"])
    _require_package_policy_map("imports", "packages", imports["packages"])
    _require_bool("jit", "enabled", jit["enabled"])
    _require_string("jit", "backend", jit["backend"])
    _require_non_negative_int("jit", "hot_threshold", jit["hot_threshold"])
    _require_optional_string("executable", "entrypoint", executable["entrypoint"])
    _require_optional_string("executable", "name", executable["name"])
    _require_optional_string("executable", "python", executable["python"])
    _require_string("executable", "backend", executable["backend"])
    _require_string("executable", "nuitka_mode", executable["nuitka_mode"])
    _require_string("policy", "native_marker", policy["native_marker"])
    _require_bool("policy", "require_type_hints", policy["require_type_hints"])
    _require_bool("policy", "allow_dynamic_features", policy["allow_dynamic_features"])
    _require_bool("policy", "boundary_warnings", policy["boundary_warnings"])
    _require_bool("policy", "native_top_level", policy["native_top_level"])

    _require_value("build", "native_backend", build["native_backend"], {"julia", "mojo", "rust"})
    _require_value("build", "fallback_backend", build["fallback_backend"], {"cpython", "nuitka"})
    _require_value("rust", "binding", rust["binding"], {"pyo3"})
    _require_value("rust", "build_tool", rust["build_tool"], {"cargo", "maturin"})
    _require_value("fallback", "nuitka", fallback["nuitka"], {"experimental"})
    _require_value(
        "imports",
        "default_external_policy",
        imports["default_external_policy"],
        {"analyze", "fallback", "try-native"},
    )
    _require_value("jit", "backend", jit["backend"], {"cranelift"})
    _require_value("executable", "backend", executable["backend"], {"zipapp", "nuitka", "rust"})
    _require_value("executable", "nuitka_mode", executable["nuitka_mode"], {"standalone", "onefile"})
    _require_value("policy", "native_marker", policy["native_marker"], {"auto", "decorator"})
    if policy["require_type_hints"] is not True:
        raise ConfigError("0.1.0 alpha requires [policy] require_type_hints = true")
    if policy["allow_dynamic_features"] is not False:
        raise ConfigError("0.1.0 alpha does not support [policy] allow_dynamic_features = true")


def _require_string(section: str, key: str, value: Any) -> None:
    if not isinstance(value, str):
        raise ConfigError(f"[{section}].{key} must be a string")


def _require_optional_string(section: str, key: str, value: Any) -> None:
    if value is not None and not isinstance(value, str):
        raise ConfigError(f"[{section}].{key} must be a string when set")


def _require_bool(section: str, key: str, value: Any) -> None:
    if not isinstance(value, bool):
        raise ConfigError(f"[{section}].{key} must be a boolean")


def _require_crate_name(section: str, key: str, value: Any) -> None:
    _require_string(section, key, value)
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", value):
        raise ConfigError(
            f"[{section}].{key} must be a valid Cargo crate name using letters, digits, "
            "underscores, or hyphens, and it must not start with a digit"
        )


def _require_non_negative_int(section: str, key: str, value: Any) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ConfigError(f"[{section}].{key} must be a non-negative integer")
    if value < 0:
        raise ConfigError(f"[{section}].{key} must be a non-negative integer")


def _require_positive_number(
    section: str,
    key: str,
    value: Any,
    *,
    maximum: float | None = None,
) -> None:
    # `math.isfinite` rejects NaN and inf: NaN slips past a bare `value <= 0`
    # comparison, and inf would disable the timeout entirely. `not isinstance(...)`
    # also rejects `None` here (before `math.isfinite` could raise `TypeError`).
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"[{section}].{key} must be a finite positive number")
    if not math.isfinite(value) or value <= 0:
        raise ConfigError(f"[{section}].{key} must be a finite positive number")
    if maximum is not None and value > maximum:
        raise ConfigError(f"[{section}].{key} must be at most {maximum:g}")


def _require_string_map(section: str, key: str, value: Any) -> None:
    if not isinstance(value, dict):
        raise ConfigError(f"[{section}].{key} must be a table")
    for option_key, option_value in value.items():
        if not isinstance(option_key, str) or not isinstance(option_value, str):
            raise ConfigError(f"[{section}].{key} must contain string keys and string values")


def _require_package_policy_map(section: str, key: str, value: Any) -> None:
    if not isinstance(value, dict):
        raise ConfigError(f"[{section}].{key} must be a table")
    for package, raw_policy in value.items():
        if not isinstance(package, str) or not package:
            raise ConfigError(f"[{section}].{key} must contain non-empty string package names")
        if isinstance(raw_policy, str):
            policy = raw_policy
            plugin = None
            max_depth = 0
        elif isinstance(raw_policy, dict):
            unknown = set(raw_policy) - {"policy", "plugin", "max_depth"}
            if unknown:
                unknown_key = sorted(unknown)[0]
                raise ConfigError(f"unsupported config key: [{section}.{key}.{package}].{unknown_key}")
            policy = raw_policy.get("policy", "fallback")
            plugin = raw_policy.get("plugin")
            max_depth = raw_policy.get("max_depth", 0)
        else:
            raise ConfigError(f"[{section}].{key}.{package} must be a string or table")
        _require_value(f"{section}.{key}.{package}", "policy", policy, {"analyze", "fallback", "plugin", "try-native"})
        if plugin is not None:
            _require_string(f"{section}.{key}.{package}", "plugin", plugin)
        _require_non_negative_int(f"{section}.{key}.{package}", "max_depth", max_depth)
        if policy == "plugin" and not plugin:
            raise ConfigError(f"[{section}].{key}.{package}.plugin is required when policy = \"plugin\"")


def _require_string_list(section: str, key: str, value: Any) -> None:
    if not isinstance(value, (list, tuple)):
        raise ConfigError(f"[{section}].{key} must be a list of strings")
    if not all(isinstance(item, str) for item in value):
        raise ConfigError(f"[{section}].{key} must be a list of strings")


def _require_value(section: str, key: str, value: str, allowed: set[str]) -> None:
    if value in allowed:
        return
    options = ", ".join(f'"{option}"' for option in sorted(allowed))
    raise ConfigError(f"unsupported config value for [{section}].{key}: {value!r}. Use {options}.")


def _apply_environment_overrides(
    build: dict[str, Any],
    rust: dict[str, Any],
    fallback: dict[str, Any],
    target: dict[str, Any],
    plugins: dict[str, Any],
    imports: dict[str, Any],
    jit: dict[str, Any],
    executable: dict[str, Any],
    policy: dict[str, Any],
    environ: Mapping[str, str],
) -> None:
    sections = {
        "build": build,
        "rust": rust,
        "fallback": fallback,
        "target": target,
        "plugins": plugins,
        "imports": imports,
        "jit": jit,
        "executable": executable,
        "policy": policy,
    }
    for env_name, (section, key, kind) in ENVIRONMENT_OVERRIDES.items():
        raw_value = environ.get(env_name)
        if raw_value is None or raw_value == "":
            continue
        sections[section][key] = _parse_environment_value(env_name, raw_value, kind)


def _parse_environment_value(env_name: str, raw_value: str, kind: str) -> object:
    if kind in {"string", "optional_string"}:
        return raw_value
    if kind == "integer":
        try:
            return int(raw_value)
        except ValueError as exc:
            raise ConfigError(f"environment variable {env_name} must be a non-negative integer") from exc
    if kind == "positive_number":
        try:
            number = float(raw_value)
        except ValueError as exc:
            raise ConfigError(f"environment variable {env_name} must be a finite positive number") from exc
        # `float()` accepts "inf"/"nan"; reject them so the timeout stays meaningful.
        if not math.isfinite(number) or number <= 0:
            raise ConfigError(f"environment variable {env_name} must be a finite positive number")
        if number > MAX_BUILD_TIMEOUT_SECONDS:
            raise ConfigError(f"environment variable {env_name} must be at most {MAX_BUILD_TIMEOUT_SECONDS:g}")
        return number
    if kind == "string_map":
        return _parse_string_map(env_name, raw_value)
    if kind == "package_policy_map":
        return _parse_package_policy_map(raw_value)
    if kind == "string_list":
        return _parse_string_list(raw_value, separator=",")
    if kind == "boolean":
        lowered = raw_value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
        raise ConfigError(f"environment variable {env_name} must be a boolean")
    raise ConfigError(f"unsupported environment override kind: {kind}")


def _parse_string_map(env_name: str, raw_value: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for item in _parse_string_list(raw_value, separator=","):
        if "=" not in item:
            raise ConfigError(f"environment variable {env_name} must use KEY=VALUE entries")
        key, value = item.split("=", 1)
        if not key:
            raise ConfigError(f"environment variable {env_name} must not contain empty keys")
        values[key] = value
    return values


def _parse_string_list(raw_value: str, separator: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in raw_value.split(separator) if item.strip())


def _parse_package_policy_map(raw_value: str) -> dict[str, dict[str, object]]:
    values: dict[str, dict[str, object]] = {}
    for item in _parse_string_list(raw_value, separator=","):
        if "=" not in item:
            raise ConfigError("environment variable REXTIO_IMPORTS_PACKAGES must use PACKAGE=POLICY entries")
        package, policy = item.split("=", 1)
        if not package:
            raise ConfigError("environment variable REXTIO_IMPORTS_PACKAGES must not contain empty package names")
        if policy == "plugin":
            raise ConfigError(
                f"REXTIO_IMPORTS_PACKAGES {package}=plugin is not supported: the 'plugin' "
                "policy needs a plugin name, so configure it in rextio.toml under "
                f'[imports.packages.{package}] with plugin = "..." instead.'
            )
        values[package] = {"policy": policy}
    return values


def _build_imports_config(imports: dict[str, Any]) -> ImportsConfig:
    packages: dict[str, ImportPackagePolicy] = {}
    for package, raw_policy in imports["packages"].items():
        if isinstance(raw_policy, str):
            packages[package] = ImportPackagePolicy(policy=raw_policy)
            continue
        packages[package] = ImportPackagePolicy(
            policy=raw_policy.get("policy", "fallback"),
            plugin=raw_policy.get("plugin"),
            max_depth=raw_policy.get("max_depth", 0),
        )
    return ImportsConfig(
        default_external_policy=imports["default_external_policy"],
        packages=packages,
    )


def _imports_asdict(imports: ImportsConfig) -> dict[str, Any]:
    return {
        "default_external_policy": imports.default_external_policy,
        "packages": {
            package: {
                "policy": policy.policy,
                "plugin": policy.plugin,
                "max_depth": policy.max_depth,
            }
            for package, policy in imports.packages.items()
        },
    }
