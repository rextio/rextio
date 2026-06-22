from __future__ import annotations

import os
import tomllib
from dataclasses import asdict
from pathlib import Path
from typing import Any, Mapping

from rextio.config.defaults import DEFAULT_CONFIG
from rextio.config.schema import (
    BuildConfig,
    ExecutableConfig,
    FallbackConfig,
    MapperConfig,
    PolicyConfig,
    RextioConfig,
    RustConfig,
    TargetConfig,
)


class ConfigError(RuntimeError):
    pass


CONFIG_KEYS = {
    "build": {"native_backend", "fallback_backend", "fallback_threshold"},
    "rust": {"binding", "build_tool"},
    "fallback": {"nuitka"},
    "target": {"version", "build_options"},
    "mappers": {"paths", "enabled", "repository"},
    "executable": {"entrypoint", "name", "backend", "nuitka_mode"},
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
    "REXTIO_RUST_BINDING": ("rust", "binding", "string"),
    "REXTIO_RUST_BUILD_TOOL": ("rust", "build_tool", "string"),
    "REXTIO_NUITKA_FALLBACK": ("fallback", "nuitka", "string"),
    "REXTIO_TARGET_VERSION": ("target", "version", "optional_string"),
    "REXTIO_TARGET_BUILD_OPTIONS": ("target", "build_options", "string_map"),
    "REXTIO_MAPPER_PATHS": ("mappers", "paths", "path_list"),
    "REXTIO_MAPPERS_ENABLED": ("mappers", "enabled", "string_list"),
    "REXTIO_MAPPER_REPOSITORY": ("mappers", "repository", "optional_string"),
    "REXTIO_EXECUTABLE_ENTRYPOINT": ("executable", "entrypoint", "optional_string"),
    "REXTIO_EXECUTABLE_NAME": ("executable", "name", "optional_string"),
    "REXTIO_EXECUTABLE_BACKEND": ("executable", "backend", "string"),
    "REXTIO_NUITKA_MODE": ("executable", "nuitka_mode", "string"),
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
    mappers = {**DEFAULT_CONFIG["mappers"], **_section(raw, "mappers")}
    executable = {**DEFAULT_CONFIG["executable"], **_section(raw, "executable")}
    policy = {**DEFAULT_CONFIG["policy"], **_section(raw, "policy")}
    if environ is not None:
        _apply_environment_overrides(build, rust, fallback, target, mappers, executable, policy, environ)
    return _build_config(build, rust, fallback, target, mappers, executable, policy)


def override_config(
    config: RextioConfig,
    overrides: Mapping[tuple[str, str], object | None],
) -> RextioConfig:
    build = asdict(config.build)
    rust = asdict(config.rust)
    fallback = asdict(config.fallback)
    target = asdict(config.target)
    mappers = asdict(config.mappers)
    executable = asdict(config.executable)
    policy = asdict(config.policy)
    sections = {
        "build": build,
        "rust": rust,
        "fallback": fallback,
        "target": target,
        "mappers": mappers,
        "executable": executable,
        "policy": policy,
    }
    for (section, key), value in overrides.items():
        if value is None:
            continue
        if section not in sections or key not in CONFIG_KEYS[section]:
            raise ConfigError(f"unsupported config override: [{section}].{key}")
        sections[section][key] = value
    return _build_config(build, rust, fallback, target, mappers, executable, policy)


def _build_config(
    build: dict[str, Any],
    rust: dict[str, Any],
    fallback: dict[str, Any],
    target: dict[str, Any],
    mappers: dict[str, Any],
    executable: dict[str, Any],
    policy: dict[str, Any],
) -> RextioConfig:
    _validate_config_values(build, rust, fallback, target, mappers, executable, policy)
    return RextioConfig(
        build=BuildConfig(**build),
        rust=RustConfig(**rust),
        fallback=FallbackConfig(**fallback),
        target=TargetConfig(**target),
        mappers=MapperConfig(
            paths=tuple(mappers["paths"]),
            enabled=tuple(mappers["enabled"]),
            repository=mappers["repository"],
        ),
        executable=ExecutableConfig(**executable),
        policy=PolicyConfig(**policy),
    )


def _validate_config_values(
    build: dict[str, Any],
    rust: dict[str, Any],
    fallback: dict[str, Any],
    target: dict[str, Any],
    mappers: dict[str, Any],
    executable: dict[str, Any],
    policy: dict[str, Any],
) -> None:
    _require_string("build", "native_backend", build["native_backend"])
    _require_string("build", "fallback_backend", build["fallback_backend"])
    _require_non_negative_int("build", "fallback_threshold", build["fallback_threshold"])
    _require_string("rust", "binding", rust["binding"])
    _require_string("rust", "build_tool", rust["build_tool"])
    _require_string("fallback", "nuitka", fallback["nuitka"])
    _require_optional_string("target", "version", target["version"])
    _require_string_map("target", "build_options", target["build_options"])
    _require_string_list("mappers", "paths", mappers["paths"])
    _require_string_list("mappers", "enabled", mappers["enabled"])
    _require_optional_string("mappers", "repository", mappers["repository"])
    _require_optional_string("executable", "entrypoint", executable["entrypoint"])
    _require_optional_string("executable", "name", executable["name"])
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
    _require_value("executable", "backend", executable["backend"], {"zipapp", "nuitka"})
    _require_value("executable", "nuitka_mode", executable["nuitka_mode"], {"standalone", "onefile"})
    _require_value("policy", "native_marker", policy["native_marker"], {"auto", "decorator"})
    if policy["require_type_hints"] is not True:
        raise ConfigError("Public 1 requires [policy] require_type_hints = true")
    if policy["allow_dynamic_features"] is not False:
        raise ConfigError("Public 1 does not support [policy] allow_dynamic_features = true")


def _require_string(section: str, key: str, value: Any) -> None:
    if not isinstance(value, str):
        raise ConfigError(f"[{section}].{key} must be a string")


def _require_optional_string(section: str, key: str, value: Any) -> None:
    if value is not None and not isinstance(value, str):
        raise ConfigError(f"[{section}].{key} must be a string when set")


def _require_bool(section: str, key: str, value: Any) -> None:
    if not isinstance(value, bool):
        raise ConfigError(f"[{section}].{key} must be a boolean")


def _require_non_negative_int(section: str, key: str, value: Any) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ConfigError(f"[{section}].{key} must be a non-negative integer")
    if value < 0:
        raise ConfigError(f"[{section}].{key} must be a non-negative integer")


def _require_string_map(section: str, key: str, value: Any) -> None:
    if not isinstance(value, dict):
        raise ConfigError(f"[{section}].{key} must be a table")
    for option_key, option_value in value.items():
        if not isinstance(option_key, str) or not isinstance(option_value, str):
            raise ConfigError(f"[{section}].{key} must contain string keys and string values")


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
    mappers: dict[str, Any],
    executable: dict[str, Any],
    policy: dict[str, Any],
    environ: Mapping[str, str],
) -> None:
    sections = {
        "build": build,
        "rust": rust,
        "fallback": fallback,
        "target": target,
        "mappers": mappers,
        "executable": executable,
        "policy": policy,
    }
    for env_name, (section, key, kind) in ENVIRONMENT_OVERRIDES.items():
        raw_value = environ.get(env_name)
        if raw_value in {None, ""}:
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
    if kind == "string_map":
        return _parse_string_map(env_name, raw_value)
    if kind == "string_list":
        return _parse_string_list(raw_value, separator=",")
    if kind == "path_list":
        return _parse_string_list(raw_value, separator=os.pathsep)
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
