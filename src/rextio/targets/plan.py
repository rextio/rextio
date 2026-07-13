"""Resolution of the target plan (spec + active plugins)."""

from __future__ import annotations

import warnings
from dataclasses import dataclass
from pathlib import Path

from rextio.__about__ import __version__
from rextio.config.schema import RextioConfig
from rextio.plugins.loader import PluginError, load_plugin_registry
from rextio.plugins.models import PluginRegistry
from rextio.targets.models import SUPPORTED_TARGET_LANGUAGES, TargetSpec, normalize_target_language


class TargetPlanError(RuntimeError):
    """Raised when a target plan cannot be resolved."""

    pass


@dataclass(frozen=True)
class TargetPlan:
    """The resolved target plan: spec and active plugins."""

    spec: TargetSpec
    plugins: PluginRegistry

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this plan."""
        return {
            "spec": self.spec.to_dict(),
            "plugins": self.plugins.to_dict(),
        }


def create_target_plan(project_root: Path, config: RextioConfig) -> TargetPlan:
    """Resolve the target plan for a project and configuration."""
    target = create_target_spec(config)
    try:
        plugins = load_plugin_registry(config.plugins, target, full_config=config)
    except PluginError as exc:
        raise TargetPlanError(str(exc)) from exc
    _validate_import_plugin_policies(config, plugins)
    return TargetPlan(spec=target, plugins=plugins)


def default_target_plan() -> TargetPlan:
    """Return the default target plan (Rust, no plugins)."""
    return TargetPlan(spec=TargetSpec(), plugins=PluginRegistry())


def create_target_spec(config: RextioConfig) -> TargetSpec:
    """Resolve the target spec from configuration."""
    language = normalize_target_language(config.build.native_backend)
    if language not in SUPPORTED_TARGET_LANGUAGES:
        options = ", ".join(sorted(SUPPORTED_TARGET_LANGUAGES))
        raise TargetPlanError(f"unsupported target language: {language!r}. Use {options}.")
    if config.target.version is not None or config.target.build_options:
        # These are accepted as forward-looking config but have no effect on
        # codegen or the build yet; warn so users do not assume they control the
        # toolchain version or pass build options.
        warnings.warn(
            "[target].version and [target].build_options are accepted but have no "
            f"effect in {__version__}; they are reserved for a future release.",
            RuntimeWarning,
            stacklevel=2,
        )
    return TargetSpec(
        language=language,
        version=config.target.version,
        build_options=dict(config.target.build_options),
    )


def _validate_import_plugin_policies(config: RextioConfig, plugins: PluginRegistry) -> None:
    active_plugin_ids = {plugin.id for plugin in plugins.active}
    for package, import_policy in sorted(config.imports.packages.items()):
        if import_policy.policy != "plugin":
            continue
        if import_policy.plugin not in active_plugin_ids:
            raise TargetPlanError(
                f"[imports.packages.{package}] references plugin {import_policy.plugin!r}, "
                "but that plugin is not active"
            )
