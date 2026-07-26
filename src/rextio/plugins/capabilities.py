"""Resolve plugin standalone-artifact capability declarations (plugin API 1.4).

Standalone (boundary-free) Rust artifacts — ``rust-crate`` and
``host-executable`` — never infer plugin support from host-extension surfaces.
A function is standalone-capable only when every claim rule and every plugin
type it uses (signature keys plus claim operand/result/receiver types) is
covered by an explicit, validated
:class:`~rextio.plugins.api.PluginArtifactCapability` for the exact resolved
:class:`~rextio.artifacts.models.ArtifactProfile`.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from typing import Any

from rextio.artifacts.models import ArtifactProfile
from rextio.codegen.rust.cargo import CORE_CRATE_NAMES
from rextio.plugins.api import PluginArtifactCapability, PluginArtifactTypeSupport
from rextio.plugins.loader import PluginError
from rextio.plugins.models import PluginRegistry, RextioPlugin


def _version_tuple(version: str) -> tuple[int, int]:
    parts = version.split(".")
    try:
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
    except (ValueError, IndexError):
        return (0, 0)
    return (major, minor)


def _is_protocol_class(cls: type) -> bool:
    """Return whether ``cls`` is a typing.Protocol (or subclass marker)."""
    return bool(getattr(cls, "_is_protocol", False))


def provider_declares_artifact_capability(provider: object) -> bool:
    """Return whether the provider has a *concrete* artifact_capability hook.

    Inheritance of a Protocol that lists ``artifact_capability`` must not count
    as a declaration: Protocol stubs are callable but are not real
    implementations. Only a non-Protocol class in the provider's MRO that
    defines the method counts.
    """
    for cls in type(provider).__mro__:
        if _is_protocol_class(cls):
            continue
        if "artifact_capability" not in cls.__dict__:
            continue
        attr = cls.__dict__["artifact_capability"]
        if isinstance(attr, (staticmethod, classmethod)):
            attr = attr.__func__
        if callable(attr):
            return True
    return False


def validate_capability_hook_version(plugin_id: str, api_version: str, provider: object) -> bool:
    """Validate that a present capability hook is version-gated.

    Returns True when the hook is present (and legal). Raises PluginError when a
    pre-1.4 provider exposes the hook. Returns False when the hook is absent.
    """
    if not provider_declares_artifact_capability(provider):
        return False
    if _version_tuple(api_version) < (1, 4):
        raise PluginError(
            f"plugin {plugin_id!r} implements artifact_capability() but declares "
            f"plugin-API {api_version!r}; standalone artifact capability requires "
            "api_version >= 1.4"
        )
    return True


def is_plugin_type_key(value: object) -> bool:
    """Return whether ``value`` looks like a namespaced plugin type key."""
    return isinstance(value, str) and "/" in value and bool(value.split("/", 1)[0])


def claim_plugin_type_keys(claim: object) -> frozenset[str]:
    """Collect every plugin type key referenced by one claim record/IR node.

    Includes result_type, each operand type, and the receiver type when present.
    Core type names (no ``/``) are ignored.
    """
    keys: set[str] = set()
    result_type = getattr(claim, "result_type", None)
    if is_plugin_type_key(result_type):
        keys.add(str(result_type))
    for operand in getattr(claim, "operand_types", ()) or ():
        if is_plugin_type_key(operand):
            keys.add(str(operand))
    receiver = getattr(claim, "receiver", None)
    if receiver is not None:
        arg_type = getattr(receiver, "arg_type", None)
        if is_plugin_type_key(arg_type):
            keys.add(str(arg_type))
    return frozenset(keys)


def function_plugin_type_keys(
    *,
    plugin_type_keys: Iterable[str] | None = None,
    plugin_claims: Iterable[object] | None = None,
) -> tuple[str, ...]:
    """Union signature plugin type keys with every type key used inside claims."""
    keys: set[str] = set()
    for key in plugin_type_keys or ():
        if is_plugin_type_key(key):
            keys.add(key)
        elif isinstance(key, str) and key:
            # Signature keys are already registered plugin keys even when the
            # defensive is_plugin_type_key check is conservative.
            keys.add(key)
    for claim in plugin_claims or ():
        keys.update(claim_plugin_type_keys(claim))
    return tuple(sorted(keys))


def analysis_function_plugin_type_keys(function: object) -> tuple[str, ...]:
    """Adapter over analysis-time FunctionAnalysis / FunctionIR-like objects."""
    return function_plugin_type_keys(
        plugin_type_keys=getattr(function, "plugin_type_keys", ()) or (),
        plugin_claims=getattr(function, "plugin_claims", ()) or (),
    )


def _dedupe_sorted(items: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted(set(items)))


def _dedupe_preserve_order(items: tuple[str, ...]) -> tuple[str, ...]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return tuple(ordered)


def _canonicalize_capability(
    plugin_id: str, capability: PluginArtifactCapability
) -> PluginArtifactCapability:
    """Validate namespace ownership, duplicates, and crate pins; return a sorted record."""
    key_prefix = f"{plugin_id}/"
    rule_ids = capability.rule_ids
    if len(set(rule_ids)) != len(rule_ids):
        raise PluginError(
            f"plugin {plugin_id!r} artifact_capability declares duplicate rule ids"
        )
    for rule_id in rule_ids:
        if not rule_id.startswith(key_prefix):
            raise PluginError(
                f"plugin {plugin_id!r} artifact capability rule id {rule_id!r} "
                f"must be namespaced {key_prefix!r}"
            )

    seen_type_keys: set[str] = set()
    canonical_types: list[PluginArtifactTypeSupport] = []
    for type_support in capability.types:
        if not type_support.type_key.startswith(key_prefix):
            raise PluginError(
                f"plugin {plugin_id!r} artifact capability type key "
                f"{type_support.type_key!r} must be namespaced {key_prefix!r}"
            )
        if type_support.type_key in seen_type_keys:
            raise PluginError(
                f"plugin {plugin_id!r} artifact capability declares type key "
                f"{type_support.type_key!r} twice"
            )
        seen_type_keys.add(type_support.type_key)
        # Deterministic: uses sorted unique; helpers first-seen unique order.
        canonical_types.append(
            replace(
                type_support,
                uses=_dedupe_sorted(type_support.uses),
                helpers=_dedupe_preserve_order(type_support.helpers),
            )
        )

    seen_crates: dict[str, str] = {}
    for dependency in capability.crate_dependencies:
        if dependency.name in CORE_CRATE_NAMES:
            raise PluginError(
                f"plugin {plugin_id!r} artifact capability declares crate dependency "
                f"{dependency.name!r}, which is reserved by the core-generated "
                "manifest; plugins may not inject or re-pin core crates"
            )
        previous = seen_crates.get(dependency.name)
        if previous is not None and previous != dependency.version:
            raise PluginError(
                f"plugin {plugin_id!r} artifact capability pins crate "
                f"{dependency.name!r} to both {previous} and {dependency.version}"
            )
        seen_crates[dependency.name] = dependency.version

    # Collapse duplicate same-name/same-version dep rows deterministically.
    dep_by_name: dict[str, Any] = {}
    for dependency in capability.crate_dependencies:
        existing = dep_by_name.get(dependency.name)
        if existing is None:
            dep_by_name[dependency.name] = dependency
            continue
        # Same pin: keep first features sorted uniquely for determinism.
        if existing.version != dependency.version:
            # Defensive: should have been caught above.
            raise PluginError(
                f"plugin {plugin_id!r} artifact capability pins crate "
                f"{dependency.name!r} to both {existing.version} and {dependency.version}"
            )
        merged_features = _dedupe_sorted(existing.features + dependency.features)
        dep_by_name[dependency.name] = replace(existing, features=merged_features)

    sorted_rules = tuple(sorted(rule_ids))
    sorted_types = tuple(sorted(canonical_types, key=lambda item: item.type_key))
    sorted_deps = tuple(
        sorted(
            dep_by_name.values(),
            key=lambda dep: (dep.name, dep.version, dep.features),
        )
    )
    return PluginArtifactCapability(
        rule_ids=sorted_rules,
        types=sorted_types,
        crate_dependencies=sorted_deps,
    )


def _validate_capability_against_registry(
    plugin_id: str,
    capability: PluginArtifactCapability,
    registry: PluginRegistry,
) -> None:
    """Reject capability rule ids / type keys unknown to the plugin's describe surface."""
    known_rules = {
        record.id
        for record in registry.rule_records
        if record.provider == plugin_id or record.id.startswith(f"{plugin_id}/")
    }
    known_types = {
        binding.plugin_type.key
        for binding in registry.types
        if binding.plugin_id == plugin_id
    }
    for rule_id in capability.rule_ids:
        if rule_id not in known_rules:
            raise PluginError(
                f"plugin {plugin_id!r} artifact_capability declares unknown rule id "
                f"{rule_id!r}; rule ids must match describe() rule records"
            )
    for type_key in capability.type_keys():
        if type_key not in known_types:
            raise PluginError(
                f"plugin {plugin_id!r} artifact_capability declares unknown type key "
                f"{type_key!r}; type keys must match type_vocabulary()"
            )


def resolve_provider_artifact_capability(
    plugin_id: str,
    provider: object,
    api_version: str | None,
    profile: ArtifactProfile,
    *,
    registry: PluginRegistry | None = None,
) -> PluginArtifactCapability | None:
    """Resolve standalone capability for one provider against an exact profile.

    * Missing hook → ``None`` (standalone unsupported).
    * Hook returns ``None`` → ``None``.
    * Hook returns a capability → validated/canonicalized record.
    * Hook exception, wrong return type, or invalid declaration → PluginError.
    """
    if not isinstance(profile, ArtifactProfile):
        raise PluginError(
            f"plugin {plugin_id!r} artifact_capability requires an ArtifactProfile, "
            f"got {type(profile).__name__}"
        )
    if not provider_declares_artifact_capability(provider):
        return None
    declared = str(api_version or "")
    validate_capability_hook_version(plugin_id, declared, provider)
    hook = getattr(provider, "artifact_capability")
    try:
        result = hook(profile)
    except PluginError:
        raise
    except Exception as exc:
        raise PluginError(
            f"plugin {plugin_id!r} artifact_capability() failed for profile "
            f"{profile.kind.value!r}/{profile.target_triple!r}: {exc}"
        ) from exc
    if result is None:
        return None
    if not isinstance(result, PluginArtifactCapability):
        raise PluginError(
            f"plugin {plugin_id!r} artifact_capability() must return "
            f"PluginArtifactCapability or None, got {type(result).__name__}"
        )
    try:
        canonical = _canonicalize_capability(plugin_id, result)
    except ValueError as exc:
        raise PluginError(
            f"plugin {plugin_id!r} artifact_capability() returned an invalid "
            f"capability for profile {profile.kind.value!r}: {exc}"
        ) from exc
    if registry is not None:
        _validate_capability_against_registry(plugin_id, canonical, registry)
    return canonical


def resolve_registry_artifact_capabilities(
    registry: PluginRegistry,
    profile: ArtifactProfile,
) -> dict[str, PluginArtifactCapability | None]:
    """Resolve per-plugin capability for one exact profile (generate/build only).

    Plugins without a declared hook map to ``None``. Capabilities introspection
    must not call this: it would execute profile hooks.
    """
    active_by_id = {plugin.id: plugin for plugin in registry.active}
    resolved: dict[str, PluginArtifactCapability | None] = {}
    for binding in registry.providers:
        plugin = active_by_id.get(binding.plugin_id)
        api_version = plugin.api_version if plugin is not None else None
        if plugin is not None and not plugin.artifact_capability_declared:
            resolved[binding.plugin_id] = None
            continue
        resolved[binding.plugin_id] = resolve_provider_artifact_capability(
            binding.plugin_id,
            binding.provider,
            api_version,
            profile,
            registry=registry,
        )
    return resolved


def coverage_for_function(
    *,
    claim_rule_ids: Iterable[tuple[str, str]],
    plugin_type_keys: Iterable[str],
    capabilities: Mapping[str, PluginArtifactCapability | None],
) -> tuple[bool, tuple[str, ...], tuple[str, ...], str | None]:
    """Return (supported, missing_rule_ids, missing_type_keys, denial_reason)."""
    claims = list(claim_rule_ids)
    type_keys = list(plugin_type_keys)
    if not claims and not type_keys:
        return True, (), (), None

    missing_rules: list[str] = []
    missing_types: list[str] = []
    involved_plugins: set[str] = {plugin_id for plugin_id, _rule_id in claims}
    for type_key in type_keys:
        plugin_id = type_key.split("/", 1)[0]
        involved_plugins.add(plugin_id)

    unsupported_plugins = tuple(
        plugin_id
        for plugin_id in sorted(involved_plugins)
        if capabilities.get(plugin_id) is None
    )
    unsupported_plugin_set = set(unsupported_plugins)
    for plugin_id, rule_id in claims:
        if plugin_id in unsupported_plugin_set:
            missing_rules.append(rule_id)
    for type_key in type_keys:
        plugin_id = type_key.split("/", 1)[0]
        if plugin_id in unsupported_plugin_set:
            missing_types.append(type_key)

    for plugin_id, rule_id in claims:
        capability = capabilities.get(plugin_id)
        if capability is None:
            continue
        if rule_id not in capability.rule_ids:
            missing_rules.append(rule_id)
    for type_key in type_keys:
        plugin_id = type_key.split("/", 1)[0]
        capability = capabilities.get(plugin_id)
        if capability is None:
            continue
        if type_key not in capability.type_keys():
            missing_types.append(type_key)

    if missing_rules or missing_types:
        parts: list[str] = []
        if unsupported_plugins:
            plugin_names = ", ".join(repr(plugin_id) for plugin_id in unsupported_plugins)
            parts.append(
                f"plugins {plugin_names} declare no standalone capability for "
                "the resolved artifact profile"
            )
        if missing_rules:
            parts.append(f"missing rule ids: {', '.join(sorted(set(missing_rules)))}")
        if missing_types:
            parts.append(f"missing type keys: {', '.join(sorted(set(missing_types)))}")
        return (
            False,
            tuple(sorted(set(missing_rules))),
            tuple(sorted(set(missing_types))),
            "; ".join(parts),
        )
    return True, (), (), None


def function_is_standalone_capable(
    *,
    claim_rule_ids: Iterable[tuple[str, str]],
    plugin_type_keys: Iterable[str],
    capabilities: Mapping[str, PluginArtifactCapability | None],
) -> bool:
    """Return whether every claim rule and plugin type is covered for the profile.

    Empty claim/type sets (no plugin involvement) are treated as capable for
    pure core functions — callers that only pass plugin-lowered functions avoid
    that case. A missing or partial capability fails closed.
    """
    supported, _missing_rules, _missing_types, _reason = coverage_for_function(
        claim_rule_ids=claim_rule_ids,
        plugin_type_keys=plugin_type_keys,
        capabilities=capabilities,
    )
    return supported


def analysis_function_is_standalone_capable(
    *,
    plugin_claims: Iterable[object],
    plugin_type_keys: Iterable[str],
    capabilities: Mapping[str, PluginArtifactCapability | None],
) -> bool:
    """Adapter over analysis-time claim/type fields (includes claim type keys)."""
    claim_pairs: list[tuple[str, str]] = []
    for claim in plugin_claims:
        plugin_id = getattr(claim, "plugin_id", None)
        rule_id = getattr(claim, "rule_id", None)
        if not isinstance(plugin_id, str) or not isinstance(rule_id, str):
            return False
        claim_pairs.append((plugin_id, rule_id))
    type_keys = function_plugin_type_keys(
        plugin_type_keys=plugin_type_keys,
        plugin_claims=plugin_claims,
    )
    return function_is_standalone_capable(
        claim_rule_ids=claim_pairs,
        plugin_type_keys=type_keys,
        capabilities=capabilities,
    )


@dataclass(frozen=True)
class FunctionCapabilityDecision:
    """Deterministic per-function standalone capability decision for reports."""

    qualname: str
    supported: bool
    used_rule_ids: tuple[str, ...]
    used_type_keys: tuple[str, ...]
    missing_rule_ids: tuple[str, ...]
    missing_type_keys: tuple[str, ...]
    denial_reason: str | None

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable form of this decision."""
        return {
            "qualname": self.qualname,
            "supported": self.supported,
            "used_rule_ids": list(self.used_rule_ids),
            "used_type_keys": list(self.used_type_keys),
            "missing_rule_ids": list(self.missing_rule_ids),
            "missing_type_keys": list(self.missing_type_keys),
            "denial_reason": self.denial_reason,
        }


def decide_function_capability(
    function: object,
    capabilities: Mapping[str, PluginArtifactCapability | None],
) -> FunctionCapabilityDecision | None:
    """Return a decision for an accepted plugin-touching function, or None if N/A."""
    qualname = getattr(function, "qualname", None)
    if not isinstance(qualname, str):
        return None
    # Rejected / fallback functions never appear in capable_functions reports.
    accepted = getattr(function, "accepted", None)
    if accepted is False:
        return None
    claims = list(getattr(function, "plugin_claims", ()) or ())
    signature_keys = list(getattr(function, "plugin_type_keys", ()) or ())
    if not claims and not signature_keys:
        route = getattr(function, "route", "") or ""
        plugin_lowered = bool(getattr(function, "plugin_lowered", False))
        if not plugin_lowered and not str(route).startswith("native-plugin:"):
            return None
    used_rules = tuple(
        sorted(
            {
                rule_id
                for claim in claims
                if isinstance((rule_id := getattr(claim, "rule_id", None)), str)
            }
        )
    )
    used_types = function_plugin_type_keys(
        plugin_type_keys=signature_keys,
        plugin_claims=claims,
    )
    if not used_rules and not used_types:
        return None
    claim_pairs = [
        (plugin_id, rule_id)
        for claim in claims
        if isinstance((plugin_id := getattr(claim, "plugin_id", None)), str)
        and isinstance((rule_id := getattr(claim, "rule_id", None)), str)
    ]
    supported, missing_rules, missing_types, reason = coverage_for_function(
        claim_rule_ids=claim_pairs,
        plugin_type_keys=used_types,
        capabilities=capabilities,
    )
    return FunctionCapabilityDecision(
        qualname=qualname,
        supported=supported,
        used_rule_ids=used_rules,
        used_type_keys=used_types,
        missing_rule_ids=missing_rules,
        missing_type_keys=missing_types,
        denial_reason=None if supported else reason,
    )


def collect_standalone_capable_qualnames(
    *,
    functions: Iterable[object],
    capabilities: Mapping[str, PluginArtifactCapability | None],
) -> frozenset[str]:
    """Return qualnames of accepted plugin-touching functions that pass coverage."""
    capable: set[str] = set()
    for function in functions:
        decision = decide_function_capability(function, capabilities)
        if decision is not None and decision.supported:
            capable.add(decision.qualname)
    return frozenset(capable)


def collect_function_decisions(
    *,
    functions: Iterable[object],
    capabilities: Mapping[str, PluginArtifactCapability | None],
) -> tuple[FunctionCapabilityDecision, ...]:
    """Return sorted per-function capability decisions for standalone reports."""
    decisions: list[FunctionCapabilityDecision] = []
    for function in functions:
        decision = decide_function_capability(function, capabilities)
        if decision is not None:
            decisions.append(decision)
    return tuple(sorted(decisions, key=lambda item: item.qualname))


def profile_crate_dependencies(
    capabilities: Mapping[str, PluginArtifactCapability | None],
    used_plugin_ids: Iterable[str],
) -> tuple[tuple[str, str, tuple[str, ...]], ...]:
    """Return profile-specific exact crate dependency triples for used plugins."""
    used = set(used_plugin_ids)
    triples: list[tuple[str, str, tuple[str, ...]]] = []
    seen: dict[str, tuple[str, str]] = {}
    for plugin_id in sorted(used):
        capability = capabilities.get(plugin_id)
        if capability is None:
            continue
        for dependency in capability.crate_dependencies:
            previous = seen.get(dependency.name)
            if previous is not None and previous[1] != dependency.version:
                raise PluginError(
                    f"crate {dependency.name!r} is pinned to {previous[1]} by "
                    f"{previous[0]!r} but to {dependency.version} by {plugin_id!r} "
                    "under the resolved artifact capability"
                )
            seen.setdefault(dependency.name, (plugin_id, dependency.version))
            triples.append((dependency.name, dependency.version, dependency.features))
    return tuple(triples)


@dataclass(frozen=True)
class StandalonePluginContext:
    """Resolved capability context threaded into boundary-free Rust codegen.

    Immutable after construction. Resolve once per exact ArtifactProfile per
    generate/build command and reuse for closure, codegen, dependency
    selection, and JSON serialization — never re-call the capability hook for
    reporting.
    """

    profile: ArtifactProfile
    capabilities: Mapping[str, PluginArtifactCapability | None]
    capable_qualnames: frozenset[str]
    function_decisions: tuple[FunctionCapabilityDecision, ...] = ()

    def is_capable(self, qualname: str) -> bool:
        """Return whether ``qualname`` may render in standalone mode."""
        return qualname in self.capable_qualnames

    def capability_for(self, plugin_id: str) -> PluginArtifactCapability | None:
        """Return the resolved capability for ``plugin_id``, if any."""
        return self.capabilities.get(plugin_id)

    def allowed_uses_for(self, plugin_id: str) -> frozenset[str]:
        """Return uses declared for ``plugin_id`` under this profile."""
        capability = self.capability_for(plugin_id)
        if capability is None:
            return frozenset()
        return capability.allowed_uses()

    def allowed_helpers_for(self, plugin_id: str) -> frozenset[str]:
        """Return helpers declared for ``plugin_id`` under this profile."""
        capability = self.capability_for(plugin_id)
        if capability is None:
            return frozenset()
        return capability.allowed_helpers()

    def type_support(
        self, plugin_id: str, type_key: str
    ) -> PluginArtifactTypeSupport | None:
        """Return the profile-specific type support for ``type_key``, if covered."""
        capability = self.capability_for(plugin_id)
        if capability is None:
            return None
        for item in capability.types:
            if item.type_key == type_key:
                return item
        return None

    def covers_type_keys(self, type_keys: Iterable[str]) -> bool:
        """Defense-in-depth: every plugin type key must be capability-covered."""
        for type_key in type_keys:
            if not is_plugin_type_key(type_key) and "/" not in str(type_key):
                continue
            plugin_id = type_key.split("/", 1)[0]
            capability = self.capability_for(plugin_id)
            if capability is None or type_key not in capability.type_keys():
                return False
        return True

    def to_dict(self) -> dict[str, object]:
        """Return deterministic resolved capability details for reports."""
        plugins: list[dict[str, object]] = []
        for plugin_id in sorted(self.capabilities):
            capability = self.capabilities[plugin_id]
            plugins.append(
                {
                    "plugin_id": plugin_id,
                    "supported": capability is not None,
                    "capability": None if capability is None else capability.to_dict(),
                }
            )
        return {
            "profile": self.profile.to_dict(),
            "capable_functions": sorted(self.capable_qualnames),
            "function_decisions": [decision.to_dict() for decision in self.function_decisions],
            "plugins": plugins,
        }


def build_standalone_plugin_context(
    *,
    profile: ArtifactProfile,
    registry: PluginRegistry,
    functions: Iterable[object],
) -> StandalonePluginContext:
    """Resolve capabilities and capable function set for one artifact profile.

    Call at most once per exact profile per generate/build command; reuse the
    returned immutable context for closure, codegen, deps, and reports.
    """
    function_list = list(functions)
    capabilities = resolve_registry_artifact_capabilities(registry, profile)
    decisions = collect_function_decisions(
        functions=function_list, capabilities=capabilities
    )
    capable = frozenset(
        decision.qualname for decision in decisions if decision.supported
    )
    return StandalonePluginContext(
        profile=profile,
        capabilities=capabilities,
        capable_qualnames=capable,
        function_decisions=decisions,
    )


def declaration_presence(plugins: Iterable[RextioPlugin]) -> list[dict[str, object]]:
    """Return additive capability-presence records for capabilities introspection.

    Does not call profile hooks or probe the host.
    """
    return [
        {
            "plugin_id": plugin.id,
            "api_version": plugin.api_version,
            "artifact_capability_declared": plugin.artifact_capability_declared,
            "function_scope_guard_declared": plugin.function_scope_guard_declared,
        }
        for plugin in sorted(plugins, key=lambda item: item.id)
    ]
