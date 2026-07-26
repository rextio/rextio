"""The ``rextio capabilities`` command.

Emits the machine-readable capability manifest defined by
docs/specs/tooling-contract.md: the config-resolved answer to "in this
project, what can become native, and what should tooling suggest when it
can't?". External consumers (agent skills, LSP servers, editor extensions)
read the JSON form; the text form is a human summary.

The manifest is pure introspection of configuration: it never analyzes
project sources or writes report files. Resolving the plugin registry DOES
import and execute enabled plugin packages' module-level code, however —
plugins are compiler extensions, and building their manifest entries
requires loading them (docs/specs/tooling-contract.md).
"""

from __future__ import annotations

import hashlib
import json
import os
from argparse import Namespace
from dataclasses import asdict
from pathlib import Path

from rextio.__about__ import __version__
from rextio.analyzer.rule_records import core_rule_records
from rextio.artifacts.models import ArtifactKind, FallbackStrategy
from rextio.capabilities import (
    DICT_KEY_TYPES,
    LIST_ITEM_TYPES,
    NUMERIC_TYPES,
    SCALAR_TYPES,
    SET_ITEM_TYPES,
)
from rextio.cli.config_overrides import (
    key_value_overrides,
    package_policy_overrides,
    tuple_overrides,
)
from rextio.cli.reporter import Reporter
from rextio.config.loader import ConfigError, load_config, override_config
from rextio.config.schema import RextioConfig
from rextio.contract import TOOLING_CONTRACT_VERSION
from rextio.plugins.models import PluginRegistry
from rextio.targets.plan import TargetPlan, TargetPlanError, create_target_plan, create_target_spec


def config_fingerprint(config: RextioConfig) -> str:
    """Return the SHA-256 fingerprint of the fully resolved configuration.

    Consumers cache the manifest keyed on (fingerprint, rextio version, plugin
    versions): any change to the resolved config — from `rextio.toml`, an
    environment variable, or a CLI override — changes the fingerprint.
    """
    canonical = json.dumps(
        asdict(config), sort_keys=True, separators=(",", ":"), default=_fingerprint_default
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _fingerprint_default(value: object) -> object:
    """Normalize non-JSON-serializable config values for the fingerprint.

    The config schema is primitives/dicts/tuples today, but a future Path or
    Enum field would otherwise crash ``rextio capabilities`` (council round 8).
    """
    from enum import Enum
    from pathlib import Path as _Path

    if isinstance(value, _Path):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (set, frozenset)):
        return sorted(value, key=repr)
    if isinstance(value, bytes):
        return value.decode("utf-8", "backslashreplace")
    return repr(value)


def build_manifest(
    project_root: Path, config: RextioConfig, target_plan: TargetPlan
) -> dict[str, object]:
    """Assemble the capability manifest dict for the resolved project state."""
    # Deterministic order regardless of entry-point discovery order: core
    # records first (their in-registry order is canonical), then plugin
    # records sorted by (provider, id) (council round 4).
    plugin_rules = sorted(
        target_plan.plugins.rule_records, key=lambda record: (record.provider, record.id)
    )
    rules = (*core_rule_records(), *plugin_rules)
    device_provider_contract: dict[str, object] = {
        "status": "draft",
        "discovery": False,
        "provider_selected": False,
        "local_probe_performed": False,
    }
    if config.target.device_provider is not None:
        # The config loader requires provider/capability to appear together.
        # Capabilities reports only their public configured identity: it never
        # imports the provider, runs preflight, or exposes option keys/values.
        device_provider_contract = {
            "status": "configured",
            "discovery": False,
            "provider_selected": True,
            "selection": {
                "provider_id": config.target.device_provider,
                "capability_id": config.target.device_capability,
            },
            "local_probe_performed": False,
        }
    # Sorted by id (not entry-point discovery order) so the manifest is
    # byte-stable across environments, matching the rules array.
    active_plugins = sorted(target_plan.plugins.active, key=lambda plugin: (plugin.id, plugin.name))
    plugin_rows: list[dict[str, object]] = []
    for plugin in active_plugins:
        row: dict[str, object] = {
            "id": plugin.id,
            "name": plugin.name,
            # Distribution version: the manifest cache key is documented
            # as (fingerprint, rextio version, plugin versions), so the
            # manifest must supply the plugin-version component itself.
            "version": plugin.version,
            "packages": list(plugin.packages),
            "rules_provided": plugin.rules_provided,
            "api_version": plugin.api_version,
            "lowering_provided": plugin.lowering_provided,
            # Plugin API 1.4/1.7: presence only. Capabilities never executes
            # profile or function-scope hooks or resolves allow/deny.
            "artifact_capability_declared": plugin.artifact_capability_declared,
        }
        # Omit when false so pre-1.7 / no-hook rows keep prior exact keys.
        if plugin.function_scope_guard_declared:
            row["function_scope_guard_declared"] = True
        plugin_rows.append(row)
    return {
        "contract_version": TOOLING_CONTRACT_VERSION,
        "rextio_version": __version__,
        "project_root": str(project_root),
        "config_fingerprint": config_fingerprint(config),
        "target": {"language": target_plan.spec.language},
        # Capabilities is configuration introspection, not an analysis/build.
        # Declare the artifact vocabulary without probing the local host or
        # pretending every kind is requested. Resolved profiles live in
        # generate/build plans after source analysis.
        "artifact_contract": {
            "status": "experimental",
            "profile_resolution": "generate-build-only",
            "kinds": [kind.value for kind in ArtifactKind],
            "host_executable_fallbacks": [strategy.value for strategy in FallbackStrategy],
        },
        "device_provider_contract": device_provider_contract,
        "type_capabilities": {
            "scalar_types": sorted(SCALAR_TYPES),
            "numeric_types": sorted(NUMERIC_TYPES),
            "list_item_types": sorted(LIST_ITEM_TYPES),
            "dict_key_types": sorted(DICT_KEY_TYPES),
            "set_item_types": sorted(SET_ITEM_TYPES),
        },
        "rules": [record.to_dict() for record in rules],
        "plugins": plugin_rows,
    }


def format_capabilities_report(manifest: dict[str, object]) -> str:
    """Format the manifest into the human-readable capabilities report text."""
    target = manifest["target"]
    rules = manifest["rules"]
    plugins = manifest["plugins"]
    assert isinstance(target, dict) and isinstance(rules, list) and isinstance(plugins, list)
    lines: list[str] = [
        "Rextio capabilities",
        f"  contract version: {manifest['contract_version']}",
        f"  rextio version: {manifest['rextio_version']}",
        f"  target language: {target['language']}",
        f"  config fingerprint: {manifest['config_fingerprint']}",
        f"  active plugins: {len(plugins)}",
        f"  rules: {len(rules)}",
    ]
    if plugins:
        lines.extend(["", "Active plugins:"])
        for plugin in plugins:
            rules_note = "rules" if plugin["rules_provided"] else "metadata-only"
            lines.append(f"  [{rules_note}] {plugin['id']}")
    lines.extend(["", "Rules:"])
    for rule in rules:
        code = rule["diagnostic_code"] or "-"
        lines.append(f"  [{code}] {rule['id']}")
        lines.append(f"    {rule['constraint']}")
        lines.append(f"    guidance: {rule['guidance']}")
    return "\n".join(lines)


def run(args: Namespace) -> int:
    """Run the capabilities command; return the process exit code."""
    reporter = Reporter.from_args(args)
    project_root = Path(args.project_root).resolve()
    if not project_root.is_dir():
        # Without this a typo'd path silently reports default capabilities,
        # which downstream tooling would cache as the project's contract.
        reporter.error(f"RXT060 Configuration error: project root does not exist: {project_root}")
        return 1
    try:
        config = override_config(
            load_config(project_root, environ=os.environ),
            {
                ("build", "native_backend"): args.native_backend,
                ("target", "version"): args.target_version,
                ("target", "build_options"): key_value_overrides(args.target_build_option),
                ("plugins", "enabled"): tuple_overrides(args.plugin_enabled),
                ("imports", "default_external_policy"): args.default_external_policy,
                ("imports", "packages"): package_policy_overrides(args.package_import_policy),
                ("embedding", "enabled"): args.embed_helpers,
                ("policy", "native_marker"): args.native_marker,
                ("policy", "require_type_hints"): args.require_type_hints,
                ("policy", "allow_dynamic_features"): args.allow_dynamic_features,
                ("policy", "boundary_warnings"): args.boundary_warnings,
                ("policy", "native_top_level"): args.native_top_level,
            },
        )
        if getattr(args, "no_plugins", False):
            # Core-only manifest: entry-point discovery itself imports and
            # executes installed plugin packages, so --no-plugins must skip
            # registry loading entirely, not merely disable plugins. The
            # config override ALSO clears plugins.enabled so the emitted
            # config_fingerprint differs from the plugin-loaded manifest -
            # a consumer caching on the fingerprint must not collide the two
            # views (council round 7).
            config = override_config(config, {("plugins", "enabled"): ()})
            target_plan = TargetPlan(spec=create_target_spec(config), plugins=PluginRegistry())
        else:
            target_plan = create_target_plan(project_root, config)
    except (ConfigError, TargetPlanError) as exc:
        reporter.error(f"RXT060 Configuration error: {exc}")
        return 1
    manifest = build_manifest(project_root, config, target_plan)
    reporter.print_result(text=format_capabilities_report(manifest), data=manifest)
    return 0
