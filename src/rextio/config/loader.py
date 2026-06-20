from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from rextio.config.defaults import DEFAULT_CONFIG
from rextio.config.schema import (
    BuildConfig,
    FallbackConfig,
    PolicyConfig,
    RextioConfig,
    RustConfig,
)


class ConfigError(RuntimeError):
    pass


CONFIG_KEYS = {
    "build": {"native_backend", "fallback_backend"},
    "rust": {"binding", "build_tool"},
    "fallback": {"nuitka"},
    "policy": {
        "native_marker",
        "require_type_hints",
        "allow_dynamic_features",
        "boundary_warnings",
    },
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


def load_config(project_root: Path) -> RextioConfig:
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
    policy = {**DEFAULT_CONFIG["policy"], **_section(raw, "policy")}
    _validate_config_values(build, rust, fallback, policy)
    return RextioConfig(
        build=BuildConfig(**build),
        rust=RustConfig(**rust),
        fallback=FallbackConfig(**fallback),
        policy=PolicyConfig(**policy),
    )


def _validate_config_values(
    build: dict[str, Any],
    rust: dict[str, Any],
    fallback: dict[str, Any],
    policy: dict[str, Any],
) -> None:
    _require_string("build", "native_backend", build["native_backend"])
    _require_string("build", "fallback_backend", build["fallback_backend"])
    _require_string("rust", "binding", rust["binding"])
    _require_string("rust", "build_tool", rust["build_tool"])
    _require_string("fallback", "nuitka", fallback["nuitka"])
    _require_string("policy", "native_marker", policy["native_marker"])
    _require_bool("policy", "require_type_hints", policy["require_type_hints"])
    _require_bool("policy", "allow_dynamic_features", policy["allow_dynamic_features"])
    _require_bool("policy", "boundary_warnings", policy["boundary_warnings"])

    _require_value("build", "native_backend", build["native_backend"], {"rust"})
    _require_value("build", "fallback_backend", build["fallback_backend"], {"cpython", "nuitka"})
    _require_value("rust", "binding", rust["binding"], {"pyo3"})
    _require_value("rust", "build_tool", rust["build_tool"], {"cargo", "maturin"})
    _require_value("fallback", "nuitka", fallback["nuitka"], {"experimental"})
    _require_value("policy", "native_marker", policy["native_marker"], {"auto", "decorator"})
    if policy["require_type_hints"] is not True:
        raise ConfigError("Public 1 requires [policy] require_type_hints = true")
    if policy["allow_dynamic_features"] is not False:
        raise ConfigError("Public 1 does not support [policy] allow_dynamic_features = true")


def _require_string(section: str, key: str, value: Any) -> None:
    if not isinstance(value, str):
        raise ConfigError(f"[{section}].{key} must be a string")


def _require_bool(section: str, key: str, value: Any) -> None:
    if not isinstance(value, bool):
        raise ConfigError(f"[{section}].{key} must be a boolean")


def _require_value(section: str, key: str, value: str, allowed: set[str]) -> None:
    if value in allowed:
        return
    options = ", ".join(f'"{option}"' for option in sorted(allowed))
    raise ConfigError(f"unsupported config value for [{section}].{key}: {value!r}. Use {options}.")
