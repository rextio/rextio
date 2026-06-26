from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from rextio.config.schema import RextioConfig
from rextio.plugins.loader import PluginError, load_plugin_registry
from rextio.plugins.models import PluginRegistry
from rextio.targets.models import SUPPORTED_TARGET_LANGUAGES, TargetSpec, normalize_target_language


class TargetPlanError(RuntimeError):
    pass


@dataclass(frozen=True)
class TargetPlan:
    spec: TargetSpec
    plugins: PluginRegistry

    def to_dict(self) -> dict[str, object]:
        return {
            "spec": self.spec.to_dict(),
            "plugins": self.plugins.to_dict(),
        }


def create_target_plan(project_root: Path, config: RextioConfig) -> TargetPlan:
    target = create_target_spec(config)
    try:
        plugins = load_plugin_registry(config.plugins, target)
    except PluginError as exc:
        raise TargetPlanError(str(exc)) from exc
    return TargetPlan(spec=target, plugins=plugins)


def default_target_plan() -> TargetPlan:
    return TargetPlan(spec=TargetSpec(), plugins=PluginRegistry())


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
