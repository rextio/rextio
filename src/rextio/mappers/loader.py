from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from rextio.config.schema import MapperConfig
from rextio.mappers.models import MapperPlugin, MapperRegistry
from rextio.targets.models import SUPPORTED_TARGET_LANGUAGES, TargetSpec


class MapperError(RuntimeError):
    pass


MAPPER_MANIFEST_NAMES = ("rextio-mapper.toml", "mapper.toml")


def load_mapper_registry(
    project_root: Path,
    config: MapperConfig,
    target: TargetSpec,
) -> MapperRegistry:
    discovered = tuple(_load_mapper_path(project_root, path) for path in config.paths)
    _validate_enabled_mappers(discovered, config.enabled)
    active = tuple(
        mapper
        for mapper in discovered
        if _mapper_enabled(mapper, config.enabled) and mapper.matches(target)
    )
    return MapperRegistry(
        discovered=discovered,
        active=active,
        repository=config.repository,
    )


def _load_mapper_path(project_root: Path, configured_path: str) -> MapperPlugin:
    mapper_path = Path(configured_path)
    if not mapper_path.is_absolute():
        mapper_path = project_root / mapper_path
    manifest_path = _find_manifest(mapper_path)
    if manifest_path is None:
        names = ", ".join(MAPPER_MANIFEST_NAMES)
        raise MapperError(f"mapper path does not contain a manifest ({names}): {mapper_path}")
    try:
        raw = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise MapperError(f"failed to parse mapper manifest {manifest_path}: {exc}") from exc
    mapper = raw.get("mapper")
    if not isinstance(mapper, dict):
        raise MapperError(f"mapper manifest must contain a [mapper] table: {manifest_path}")
    return _parse_mapper_manifest(mapper_path, mapper)


def _find_manifest(mapper_path: Path) -> Path | None:
    if mapper_path.is_file():
        return mapper_path
    for name in MAPPER_MANIFEST_NAMES:
        candidate = mapper_path / name
        if candidate.exists():
            return candidate
    return None


def _parse_mapper_manifest(mapper_path: Path, mapper: dict[str, Any]) -> MapperPlugin:
    mapper_id = _required_string(mapper, "id")
    target_language = _required_string(mapper, "target_language").lower()
    if target_language not in SUPPORTED_TARGET_LANGUAGES:
        options = ", ".join(sorted(SUPPORTED_TARGET_LANGUAGES))
        raise MapperError(
            f"unsupported mapper target_language for {mapper_id!r}: "
            f"{target_language!r}. Use {options}."
        )
    source_language = _optional_string(mapper, "source_language", "python").lower()
    if source_language != "python":
        raise MapperError(f"unsupported mapper source_language for {mapper_id!r}: {source_language!r}")
    return MapperPlugin(
        id=mapper_id,
        name=_optional_string(mapper, "name", mapper_id),
        path=mapper_path,
        source_language=source_language,
        target_language=target_language,
        target_versions=_optional_string_tuple(mapper, "target_versions"),
        target_build_options=_optional_string_map(mapper, "target_build_options"),
        rules=_optional_string_tuple(mapper, "rules"),
    )


def _validate_enabled_mappers(
    discovered: tuple[MapperPlugin, ...],
    enabled: tuple[str, ...],
) -> None:
    ids: set[str] = set()
    for mapper in discovered:
        if mapper.id in ids:
            raise MapperError(f"duplicate mapper id: {mapper.id}")
        ids.add(mapper.id)
    missing = sorted(set(enabled) - ids)
    if missing:
        raise MapperError(f"enabled mapper was not discovered: {missing[0]}")


def _mapper_enabled(mapper: MapperPlugin, enabled: tuple[str, ...]) -> bool:
    return not enabled or mapper.id in enabled


def _required_string(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise MapperError(f"mapper.{key} must be a non-empty string")
    return value


def _optional_string(data: dict[str, Any], key: str, default: str) -> str:
    value = data.get(key, default)
    if not isinstance(value, str) or not value:
        raise MapperError(f"mapper.{key} must be a non-empty string")
    return value


def _optional_string_tuple(data: dict[str, Any], key: str) -> tuple[str, ...]:
    value = data.get(key, ())
    if not isinstance(value, (list, tuple)):
        raise MapperError(f"mapper.{key} must be a list of strings")
    if not all(isinstance(item, str) and item for item in value):
        raise MapperError(f"mapper.{key} must be a list of non-empty strings")
    return tuple(value)


def _optional_string_map(data: dict[str, Any], key: str) -> dict[str, str]:
    value = data.get(key, {})
    if not isinstance(value, dict):
        raise MapperError(f"mapper.{key} must be a table")
    for option_key, option_value in value.items():
        if not isinstance(option_key, str) or not isinstance(option_value, str):
            raise MapperError(f"mapper.{key} must contain string keys and string values")
    return dict(value)

