"""Discovery and loading of entry-point plugins."""

from __future__ import annotations

import warnings
from collections.abc import Iterable, Mapping
from dataclasses import replace
from importlib import metadata
from typing import Any

from rextio.config.schema import PluginConfig, RextioConfig
from rextio.plugins.api import (
    PLUGIN_API_VERSION,
    PLUGIN_DIAGNOSTIC_CODE_PATTERN,
    CoverageDecl,
    CrateDependency,
    PluginType,
    RuleRecord,
    plugin_code_segment,
)
from rextio.plugins.models import (
    PluginCoverage,
    PluginCrateDependency,
    PluginProviderBinding,
    PluginRegistry,
    PluginTypeBinding,
    RextioPlugin,
)
from rextio.targets.models import SUPPORTED_TARGET_LANGUAGES, TargetSpec


class PluginError(RuntimeError):
    """Raised when a plugin cannot be loaded or is misconfigured."""

    pass


ENTRY_POINT_GROUP = "rextio.plugins"


def load_plugin_registry(
    config: PluginConfig,
    target: TargetSpec,
    *,
    entry_points: Iterable[Any] | None = None,
    full_config: RextioConfig | None = None,
) -> PluginRegistry:
    """Discover entry-point plugins and return the resolved registry.

    ``full_config`` is the resolved project configuration handed to active v2
    plugins' ``describe()``; when omitted (legacy callers), plugins describe
    against a default configuration.
    """
    loaded = tuple(_load_entry_point_plugin(entry_point) for entry_point in _plugin_entry_points(entry_points))
    discovered = tuple(plugin for plugin, _provider in loaded)
    _validate_enabled_plugins(discovered, config.enabled)
    active_pairs = tuple(
        (plugin, provider)
        for plugin, provider in loaded
        if _plugin_enabled(plugin, config.enabled) and plugin.matches(target)
    )
    describe_config = full_config if full_config is not None else RextioConfig()
    active: list[RextioPlugin] = []
    rule_records: list[RuleRecord] = []
    coverages: list[PluginCoverage] = []
    type_bindings: list[PluginTypeBinding] = []
    crate_bindings: list[PluginCrateDependency] = []
    providers: list[PluginProviderBinding] = []
    for plugin, provider in active_pairs:
        if provider is None:
            active.append(plugin)
            continue
        coverage = _plugin_coverage(plugin, provider)
        records = _plugin_rule_records(plugin, provider, describe_config)
        # Coverage packages join the metadata packages so the import policy
        # and the RXT091 hint see one merged view.
        merged_packages = tuple(sorted({*plugin.packages, *coverage.packages}))
        annotated = replace(plugin, packages=merged_packages)
        if annotated.lowering_provided:
            type_bindings.extend(_plugin_type_bindings(annotated, provider))
            crate_bindings.extend(_plugin_crate_bindings(annotated, provider))
            providers.append(PluginProviderBinding(plugin_id=annotated.id, provider=provider))
        active.append(annotated)
        rule_records.extend(records)
        coverages.append(PluginCoverage(plugin_id=plugin.id, coverage=coverage))
    _validate_rule_codes_unique(tuple(rule_records))
    _validate_type_annotations_unique(tuple(type_bindings))
    _validate_crate_pins_compatible(tuple(crate_bindings))
    return PluginRegistry(
        enabled=config.enabled,
        discovered=discovered,
        active=tuple(active),
        rule_records=tuple(rule_records),
        coverages=tuple(coverages),
        types=tuple(type_bindings),
        crate_dependencies=tuple(crate_bindings),
        providers=tuple(providers),
    )


def _plugin_type_bindings(plugin: RextioPlugin, provider: Any) -> tuple[PluginTypeBinding, ...]:
    try:
        vocabulary = provider.type_vocabulary()
    except Exception as exc:
        raise PluginError(f"plugin {plugin.id!r} type_vocabulary() failed: {exc}") from exc
    bindings: list[PluginTypeBinding] = []
    seen_spellings: dict[str, str] = {}
    key_prefix = f"{plugin.id}/"
    for plugin_type in vocabulary:
        if not isinstance(plugin_type, PluginType):
            raise PluginError(
                f"plugin {plugin.id!r} type_vocabulary() must yield PluginType objects"
            )
        if not plugin_type.key.startswith(key_prefix):
            raise PluginError(
                f"plugin {plugin.id!r} type key {plugin_type.key!r} must be namespaced {key_prefix!r}"
            )
        if not plugin_type.annotations:
            raise PluginError(
                f"plugin {plugin.id!r} type {plugin_type.key!r} declares no annotation spellings"
            )
        for spelling in plugin_type.annotations:
            owner = seen_spellings.get(spelling)
            if owner is not None:
                raise PluginError(
                    f"plugin {plugin.id!r} declares annotation {spelling!r} on both "
                    f"{owner!r} and {plugin_type.key!r}"
                )
            seen_spellings[spelling] = plugin_type.key
        bindings.append(PluginTypeBinding(plugin_id=plugin.id, plugin_type=plugin_type))
    return tuple(bindings)


def _plugin_crate_bindings(
    plugin: RextioPlugin, provider: Any
) -> tuple[PluginCrateDependency, ...]:
    try:
        dependencies = provider.crate_dependencies()
    except Exception as exc:
        raise PluginError(f"plugin {plugin.id!r} crate_dependencies() failed: {exc}") from exc
    bindings: list[PluginCrateDependency] = []
    for dependency in dependencies:
        if not isinstance(dependency, CrateDependency):
            raise PluginError(
                f"plugin {plugin.id!r} crate_dependencies() must yield CrateDependency objects"
            )
        bindings.append(PluginCrateDependency(plugin_id=plugin.id, dependency=dependency))
    return tuple(bindings)


def _validate_type_annotations_unique(bindings: tuple[PluginTypeBinding, ...]) -> None:
    seen: dict[str, str] = {}
    for binding in bindings:
        for annotation in binding.plugin_type.annotations:
            owner = seen.get(annotation)
            if owner is not None and owner != binding.plugin_id:
                raise PluginError(
                    f"annotation {annotation!r} is claimed by both {owner!r} "
                    f"and {binding.plugin_id!r}"
                )
            seen.setdefault(annotation, binding.plugin_id)


def _validate_crate_pins_compatible(bindings: tuple[PluginCrateDependency, ...]) -> None:
    from rextio.codegen.rust.cargo import CORE_CRATE_NAMES

    seen: dict[str, tuple[str, str]] = {}
    for binding in bindings:
        dependency = binding.dependency
        if dependency.name in CORE_CRATE_NAMES:
            # Spec section 5 requires plugin-vs-core collisions to fail up
            # front with a configuration-style error, not a cargo resolver
            # error later (council round 4).
            raise PluginError(
                f"plugin {binding.plugin_id!r} declares crate dependency "
                f"{dependency.name!r}, which is reserved by the core-generated "
                "manifest; plugins may not inject or re-pin core crates"
            )
        previous = seen.get(dependency.name)
        if previous is not None and previous[1] != dependency.version:
            raise PluginError(
                f"crate {dependency.name!r} is pinned to {previous[1]} by {previous[0]!r} "
                f"but to {dependency.version} by {binding.plugin_id!r}"
            )
        seen.setdefault(dependency.name, (binding.plugin_id, dependency.version))


def _plugin_coverage(plugin: RextioPlugin, provider: Any) -> CoverageDecl:
    covers = getattr(provider, "covers", None)
    if not callable(covers):
        raise PluginError(f"plugin {plugin.id!r} provides describe() but no covers()")
    coverage = covers()
    if not isinstance(coverage, CoverageDecl):
        raise PluginError(f"plugin {plugin.id!r} covers() must return a CoverageDecl")
    return coverage


def _plugin_rule_records(
    plugin: RextioPlugin, provider: Any, config: RextioConfig
) -> tuple[RuleRecord, ...]:
    try:
        described = provider.describe(config)
    except PluginError:
        raise
    except Exception as exc:
        raise PluginError(f"plugin {plugin.id!r} describe() failed: {exc}") from exc
    records: list[RuleRecord] = []
    expected_segment = plugin_code_segment(plugin.id)
    id_prefix = f"{plugin.id}/"
    for record in described:
        if not isinstance(record, RuleRecord):
            raise PluginError(f"plugin {plugin.id!r} describe() must yield RuleRecord objects")
        if not record.id.startswith(id_prefix):
            raise PluginError(
                f"plugin {plugin.id!r} rule id {record.id!r} must be namespaced {id_prefix!r}"
            )
        if record.diagnostic_code is not None:
            match = PLUGIN_DIAGNOSTIC_CODE_PATTERN.match(record.diagnostic_code)
            if match is None:
                raise PluginError(
                    f"plugin {plugin.id!r} diagnostic code {record.diagnostic_code!r} "
                    f"must match RXTP-{expected_segment}-NNN"
                )
            if match.group(1) != expected_segment:
                raise PluginError(
                    f"plugin {plugin.id!r} diagnostic code {record.diagnostic_code!r} "
                    f"must use the plugin segment {expected_segment!r}"
                )
        records.append(replace(record, provider=plugin.id))
    return tuple(records)


def _validate_rule_codes_unique(records: tuple[RuleRecord, ...]) -> None:
    seen: dict[str, str] = {}
    for record in records:
        if record.diagnostic_code is None:
            continue
        owner = seen.get(record.diagnostic_code)
        if owner is not None and owner != record.provider:
            raise PluginError(
                f"duplicate plugin diagnostic code {record.diagnostic_code!r} "
                f"declared by {owner!r} and {record.provider!r}"
            )
        seen.setdefault(record.diagnostic_code, record.provider)


def _plugin_entry_points(entry_points: Iterable[Any] | None) -> tuple[Any, ...]:
    if entry_points is not None:
        return tuple(entry_points)
    discovered = metadata.entry_points()
    if hasattr(discovered, "select"):
        return tuple(discovered.select(group=ENTRY_POINT_GROUP))
    return tuple(discovered.get(ENTRY_POINT_GROUP, ()))


def _load_entry_point_plugin(entry_point: Any) -> tuple[RextioPlugin, Any | None]:
    entry_point_name = getattr(entry_point, "name", None) or "<unknown>"
    try:
        payload = entry_point.load()
    except Exception as exc:  # pragma: no cover - import failure detail is environment-specific.
        raise PluginError(f"failed to load plugin entry point {entry_point_name!r}: {exc}") from exc
    if callable(payload) and not isinstance(payload, RextioPlugin):
        payload = payload()
    # Protocol v2 is recognized by a callable ``describe`` on the resolved
    # object; the same object must still provide the v1 metadata below.
    provider = payload if callable(getattr(payload, "describe", None)) else None
    if provider is None and any(
        callable(getattr(payload, member, None))
        for member in ("claim", "lower", "type_vocabulary", "crate_dependencies")
    ):
        raise PluginError(
            f"plugin entry point {entry_point_name!r} implements lowering members "
            "but not describe(); lowering requires protocol v2"
        )
    if hasattr(payload, "to_rextio_plugin"):
        payload = payload.to_rextio_plugin()
    package = _entry_point_package(entry_point)
    entry_point_ref = f"{ENTRY_POINT_GROUP}:{entry_point_name}"
    if isinstance(payload, RextioPlugin):
        plugin = payload.with_source_metadata(
            source="entry-point",
            package=package,
            entry_point=entry_point_ref,
        )
    elif isinstance(payload, Mapping):
        plugin = _parse_plugin_metadata(
            dict(payload),
            default_id=entry_point_name,
            source="entry-point",
            package=package,
            entry_point=entry_point_ref,
        )
    else:
        raise PluginError(
            f"plugin entry point {entry_point_name!r} must return a metadata dict or RextioPlugin"
        )
    if provider is None:
        return plugin, None
    return _annotate_v2_plugin(plugin, provider), provider


def _annotate_v2_plugin(plugin: RextioPlugin, provider: Any) -> RextioPlugin:
    provider_id = getattr(provider, "plugin_id", None)
    if provider_id is not None and provider_id != plugin.id:
        raise PluginError(
            f"plugin {plugin.id!r} declares a mismatched plugin_id {provider_id!r}"
        )
    api_version = getattr(provider, "api_version", None)
    if not isinstance(api_version, str) or not api_version:
        raise PluginError(f"plugin {plugin.id!r} must declare a plugin-API api_version string")
    if api_version.split(".")[0] != PLUGIN_API_VERSION.split(".")[0]:
        raise PluginError(
            f"plugin {plugin.id!r} targets plugin-API {api_version!r}; "
            f"this rextio implements {PLUGIN_API_VERSION!r} (major must match)"
        )
    return replace(
        plugin,
        rules_provided=True,
        api_version=api_version,
        lowering_provided=_lowering_provided(plugin, provider),
    )


# The plugin API 1.1 lowering members. They arrive together: implementing a
# strict subset is a load error, so a half-wired plugin cannot look like a
# describe-only one.
_LOWERING_MEMBERS = ("type_vocabulary", "claim", "lower", "crate_dependencies")


def _lowering_provided(plugin: RextioPlugin, provider: Any) -> bool:
    implemented = tuple(
        member for member in _LOWERING_MEMBERS if callable(getattr(provider, member, None))
    )
    if not implemented:
        return False
    missing = tuple(member for member in _LOWERING_MEMBERS if member not in implemented)
    if missing:
        raise PluginError(
            f"plugin {plugin.id!r} implements {', '.join(implemented)} but is missing "
            f"{', '.join(missing)}; the lowering members arrive together (plugin API 1.1)"
        )
    declared = str(getattr(provider, "api_version", ""))
    if _version_tuple(declared) < (1, 1):
        raise PluginError(
            f"plugin {plugin.id!r} exposes lowering members but declares plugin-API "
            f"{declared!r}; lowering requires api_version >= 1.1"
        )
    return True


def _version_tuple(version: str) -> tuple[int, int]:
    parts = version.split(".")
    try:
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
    except (ValueError, IndexError):
        return (0, 0)
    return (major, minor)


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
            "declares a 'rules' field, which is ignored — plugins are "
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
