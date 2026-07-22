"""Per-package import-policy classification for external dependencies."""

from __future__ import annotations

import sys
from collections.abc import Iterable

from rextio.analyzer.models import ImportPolicyDecision, ModuleAnalysis
from rextio.config.schema import ImportsConfig
from rextio.plugins.models import RextioPlugin

BUILTIN_IMPORT_POLICY = "builtin"
PROJECT_IMPORT_POLICY = "try-native"
PROJECT_IMPORT_ORIGIN = "project"
STDLIB_IMPORT_ORIGIN = "stdlib"
EXTERNAL_IMPORT_ORIGIN = "external"
PLUGIN_IMPORT_ORIGIN = "external-plugin"


def classify_import_policies(
    imports: dict[str, str],
    *,
    module_name: str,
    project_modules: set[str],
    imports_config: ImportsConfig | None = None,
    active_plugins: Iterable[RextioPlugin] = (),
) -> tuple[ImportPolicyDecision, ...]:
    """Classify each external import in a module into its resolved import policy."""
    config = imports_config or ImportsConfig()
    decisions: list[ImportPolicyDecision] = []
    for visible_name, target in sorted(imports.items()):
        configured_package, configured_policy = _matching_package_policy(target, config)
        plugin = _matching_active_plugin(target, active_plugins)
        package = configured_package or _root_package(target)

        if _is_project_import(target, module_name, project_modules):
            decisions.append(
                ImportPolicyDecision(
                    visible_name=visible_name,
                    target=target,
                    package=package,
                    origin=PROJECT_IMPORT_ORIGIN,
                    policy=PROJECT_IMPORT_POLICY,
                    reason="project-local imports are eligible for normal Rextio native analysis",
                )
            )
            continue

        if _is_stdlib_import(target):
            decisions.append(
                ImportPolicyDecision(
                    visible_name=visible_name,
                    target=target,
                    package=package,
                    origin=STDLIB_IMPORT_ORIGIN,
                    policy=BUILTIN_IMPORT_POLICY,
                    reason="standard library imports use built-in lowering rules when supported",
                )
            )
            continue

        if plugin is not None:
            decisions.append(
                ImportPolicyDecision(
                    visible_name=visible_name,
                    target=target,
                    package=package,
                    origin=PLUGIN_IMPORT_ORIGIN,
                    policy="plugin",
                    plugin=plugin.id,
                    reason=f"active plugin {plugin.id!r} declares support for this package",
                )
            )
            continue

        if configured_policy is not None:
            decisions.append(
                ImportPolicyDecision(
                    visible_name=visible_name,
                    target=target,
                    package=package,
                    origin=EXTERNAL_IMPORT_ORIGIN,
                    policy=configured_policy.policy,
                    plugin=configured_policy.plugin,
                    max_depth=configured_policy.max_depth,
                    distribution=configured_policy.distribution,
                    version=configured_policy.version,
                    reason="package-specific import policy from rextio.toml or CLI/environment override",
                )
            )
            continue

        decisions.append(
            ImportPolicyDecision(
                visible_name=visible_name,
                target=target,
                package=package,
                origin=EXTERNAL_IMPORT_ORIGIN,
                policy=config.default_external_policy,
                reason="external package without an active plugin uses the default external import policy",
            )
        )
    return tuple(decisions)


def decision_for_target(module: ModuleAnalysis, target: str) -> ImportPolicyDecision | None:
    """Return the import-policy decision that applies to a target, or None."""
    matches = [
        decision
        for decision in module.import_policies
        if _target_matches_package(target, decision.target)
        or _target_matches_package(target, decision.package)
    ]
    if not matches:
        return None
    return max(matches, key=lambda decision: len(decision.target))


def _matching_package_policy(target: str, config: ImportsConfig):
    matches = [package for package in config.packages if _target_matches_package(target, package)]
    if not matches:
        return None, None
    package = max(matches, key=len)
    return package, config.packages[package]


def _matching_active_plugin(
    target: str,
    active_plugins: Iterable[RextioPlugin],
) -> RextioPlugin | None:
    for plugin in active_plugins:
        if any(_target_matches_package(target, package) for package in plugin.packages):
            return plugin
    return None


def _is_project_import(target: str, module_name: str, project_modules: set[str]) -> bool:
    if target == module_name:
        return True
    return any(_target_matches_package(target, module) for module in project_modules)


def _is_stdlib_import(target: str) -> bool:
    root = _root_package(target)
    if root in sys.builtin_module_names:
        return True
    return root in getattr(sys, "stdlib_module_names", set())


def _target_matches_package(target: str, package: str) -> bool:
    return target == package or target.startswith(f"{package}.")


def _root_package(target: str) -> str:
    return target.split(".", 1)[0]
