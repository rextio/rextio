from __future__ import annotations

import tomllib
from pathlib import Path

from rextio.config.defaults import DEFAULT_CONFIG
from rextio.config.schema import (
    BuildConfig,
    FallbackConfig,
    PolicyConfig,
    RextioConfig,
    RustConfig,
)


def _section(data: dict[str, object], name: str) -> dict[str, object]:
    value = data.get(name, {})
    if isinstance(value, dict):
        return value
    return {}


def load_config(project_root: Path) -> RextioConfig:
    path = project_root / "rextio.toml"
    raw: dict[str, object] = dict(DEFAULT_CONFIG)
    if path.exists():
        parsed = tomllib.loads(path.read_text(encoding="utf-8"))
        raw = {**raw, **parsed}

    build = {**DEFAULT_CONFIG["build"], **_section(raw, "build")}
    rust = {**DEFAULT_CONFIG["rust"], **_section(raw, "rust")}
    fallback = {**DEFAULT_CONFIG["fallback"], **_section(raw, "fallback")}
    policy = {**DEFAULT_CONFIG["policy"], **_section(raw, "policy")}
    return RextioConfig(
        build=BuildConfig(**build),
        rust=RustConfig(**rust),
        fallback=FallbackConfig(**fallback),
        policy=PolicyConfig(**policy),
    )
