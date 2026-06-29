from __future__ import annotations

import warnings
from collections.abc import Iterable, Mapping
from importlib import metadata
from typing import Any

from rextio.config.schema import PluginConfig
from rextio.plugins.models import PluginRegistry, RextioPlugin
from rextio.targets.models import SUPPORTED_TARGET_LANGUAGES, TargetSpec


class PluginError(RuntimeError):
    pass


ENTRY_POINT_GROUP = "rextio.plugins"


def load_plugin_registry(
    config: PluginConfig,
    target: TargetSpec,
    *,
    entry_points: Iterable[Any] | None = None,
) -> PluginRegistry:
    discovered = tuple(_load_entry_point_plugin(entry_point) for entry_point in _plugin_entry_points(entry_points))
    _validate_enabled_plugins(discovered, config.enabled)
    active = tuple(
        plugin
        for plugin in discovered
        if _plugin_enabled(plugin, config.enabled) and plugin.matches(target)
    )
    return PluginRegistry(
        enabled=config.enabled,
        discovered=discovered,
        active=active,
    )


def _plugin_entry_points(entry_points: Iterable[Any] | None) -> tuple[Any, ...]:
    if entry_points is not None:
        return tuple(entry_points)
    discovered = metadata.entry_points()
    if hasattr(discovered, "select"):
        return tuple(discovered.select(group=ENTRY_POINT_GROUP))
    return tuple(discovered.get(ENTRY_POINT_GROUP, ()))


def _load_entry_point_plugin(entry_point: Any) -> RextioPlugin:
    entry_point_name = getattr(entry_point, "name", None) or "<unknown>"
    try:
        payload = entry_point.load()
    except Exception as exc:  # pragma: no cover - import failure detail is environment-specific.
        raise PluginError(f"failed to load plugin entry point {entry_point_name!r}: {exc}") from exc
    if callable(payload) and not isinstance(payload, RextioPlugin):
        payload = payload()
    if hasattr(payload, "to_rextio_plugin"):
        payload = payload.to_rextio_plugin()
    package = _entry_point_package(entry_point)
    entry_point_ref = f"{ENTRY_POINT_GROUP}:{entry_point_name}"
    if isinstance(payload, RextioPlugin):
        return payload.with_source_metadata(
            source="entry-point",
            package=package,
            entry_point=entry_point_ref,
        )
    if isinstance(payload, Mapping):
        return _parse_plugin_metadata(
            dict(payload),
            default_id=entry_point_name,
            source="entry-point",
            package=package,
            entry_point=entry_point_ref,
        )
    raise PluginError(
        f"plugin entry point {entry_point_name!r} must return a metadata dict or RextioPlugin"
    )


def _entry_point_package(entry_point: Any) -> str | None:
    distribution = getattr(entry_point, "dist", None)
    if distribution is None:
        return None
    metadata_ = getattr(distribution, "metadata", None)
    if metadata_ is None:
        return None
    return metadata_.get("Name")


def _parse_plugin_metadata(
    data: Mapping[str, Any],
    *,
    default_id: str | None = None,
    source: str,
    package: str | None = None,
    entry_point: str | None = None,
) -> RextioPlugin:
    plugin_id = _optional_string(data, "id", default_id)
    target_language = _required_string(data, "target_language").lower()
    if target_language not in SUPPORTED_TARGET_LANGUAGES:
        options = ", ".join(sorted(SUPPORTED_TARGET_LANGUAGES))
        raise PluginError(
            f"unsupported plugin target_language for {plugin_id!r}: "
            f"{target_language!r}. Use {options}."
        )
    source_language = _optional_string(data, "source_language", "python").lower()
    if source_language != "python":
        raise PluginError(f"unsupported plugin source_language for {plugin_id!r}: {source_language!r}")
    if "rules" in data:
        warnings.warn(
            f"Rextio plugin {plugin_id!r} (entry-point group {ENTRY_POINT_GROUP!r}) "
            "declares a 'rules' field, which is no longer used — plugins are "
            "metadata-only. Remove 'rules' from the plugin's entry-point metadata.",
            DeprecationWarning,
            stacklevel=2,
        )
    return RextioPlugin(
        id=plugin_id,
        name=_optional_string(data, "name", plugin_id),
        source_language=source_language,
        target_language=target_language,
        target_versions=_optional_string_tuple(data, "target_versions"),
        target_build_options=_optional_string_map(data, "target_build_options"),
        # Plugins are metadata-only; a legacy ``rules`` key is accepted but ignored.
        packages=_optional_string_tuple(data, "packages"),
        source=source,
        package=package,
        entry_point=entry_point,
    )


def _validate_enabled_plugins(
    discovered: tuple[RextioPlugin, ...],
    enabled: tuple[str, ...],
) -> None:
    ids: set[str] = set()
    for plugin in discovered:
        if plugin.id in ids:
            raise PluginError(f"duplicate plugin id: {plugin.id}")
        ids.add(plugin.id)
    missing = sorted(set(enabled) - ids)
    if missing:
        raise PluginError(f"enabled plugin was not discovered: {missing[0]}")


def _plugin_enabled(plugin: RextioPlugin, enabled: tuple[str, ...]) -> bool:
    return bool(enabled) and plugin.id in enabled


def _required_string(data: Mapping[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise PluginError(f"plugin.{key} must be a non-empty string")
    return value


def _optional_string(data: Mapping[str, Any], key: str, default: str | None) -> str:
    value = data.get(key, default)
    if not isinstance(value, str) or not value:
        raise PluginError(f"plugin.{key} must be a non-empty string")
    return value


def _optional_string_tuple(data: Mapping[str, Any], key: str) -> tuple[str, ...]:
    value = data.get(key, ())
    if not isinstance(value, (list, tuple)):
        raise PluginError(f"plugin.{key} must be a list of strings")
    if not all(isinstance(item, str) and item for item in value):
        raise PluginError(f"plugin.{key} must be a list of non-empty strings")
    return tuple(value)


def _optional_string_map(data: Mapping[str, Any], key: str) -> dict[str, str]:
    value = data.get(key, {})
    if not isinstance(value, dict):
        raise PluginError(f"plugin.{key} must be a table")
    for option_key, option_value in value.items():
        if not isinstance(option_key, str) or not isinstance(option_value, str):
            raise PluginError(f"plugin.{key} must contain string keys and string values")
    return dict(value)
