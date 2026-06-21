from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from rextio.config.schema import RextioConfig
from rextio.mappers.loader import MapperError, load_mapper_registry
from rextio.mappers.models import MapperRegistry
from rextio.targets.models import SUPPORTED_TARGET_LANGUAGES, TargetSpec, normalize_target_language


class TargetPlanError(RuntimeError):
    pass


@dataclass(frozen=True)
class TargetPlan:
    spec: TargetSpec
    mappers: MapperRegistry

    def to_dict(self) -> dict[str, object]:
        return {
            "spec": self.spec.to_dict(),
            "mappers": self.mappers.to_dict(),
        }


def create_target_plan(project_root: Path, config: RextioConfig) -> TargetPlan:
    target = create_target_spec(config)
    try:
        mappers = load_mapper_registry(project_root, config.mappers, target)
    except MapperError as exc:
        raise TargetPlanError(str(exc)) from exc
    return TargetPlan(spec=target, mappers=mappers)


def create_target_spec(config: RextioConfig) -> TargetSpec:
    language = normalize_target_language(config.build.native_backend)
    if language not in SUPPORTED_TARGET_LANGUAGES:
        options = ", ".join(sorted(SUPPORTED_TARGET_LANGUAGES))
        raise TargetPlanError(f"unsupported target language: {language!r}. Use {options}.")
    return TargetSpec(
        language=language,
        version=config.target.version,
        build_options=dict(config.target.build_options),
    )

