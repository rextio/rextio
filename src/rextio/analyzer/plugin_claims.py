"""The claim engine: offers analyzer sites to active lowering plugins.

Implements the analysis half of docs/specs/plugin-lowering.md: plugin
annotation-vocabulary resolution and the claim pass. The engine is built once
per analysis from the plugin registry and threaded to validators through
``FunctionAnalysis.claim_engine``. Claim results are cached on the site
signature — the spec's determinism contract makes the cache safe and keeps
``claim()`` from running once per probe and once per real function.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping
from dataclasses import replace

from rextio.analyzer.models import FunctionAnalysis, PluginClaim, PluginClaimRejection
from rextio.analyzer.native_marker import dotted_name
from rextio.capabilities import DICT_KEY_TYPES, LIST_ITEM_TYPES, SET_ITEM_TYPES
from rextio.config.schema import RextioConfig
from rextio.plugins.api import Claimed, ClaimSite, NotCovered, Rejected, plugin_code_segment
from rextio.plugins.loader import PluginError
from rextio.plugins.models import PluginRegistry

_BINOP_SYMBOLS: dict[type[ast.operator], str] = {
    ast.Add: "+",
    ast.Sub: "-",
    ast.Mult: "*",
    ast.Div: "/",
    ast.Mod: "%",
    ast.MatMult: "@",
}


class ClaimEngine:
    """Resolves plugin annotation vocabularies and runs the claim pass."""

    def __init__(self, registry: PluginRegistry, config: RextioConfig) -> None:
        self._config = config
        self._providers = {binding.plugin_id: binding.provider for binding in registry.providers}
        # Advertised rule ids per plugin: a describing plugin must claim
        # within its own manifest (council round 5) so check.json claims
        # always resolve to a capabilities rule. Plugins without records
        # (e.g. minimal test providers) are exempt.
        self._rule_ids: dict[str, set[str]] = {}
        self._rule_kinds: dict[tuple[str, str], str] = {}
        self._rule_codes: dict[str, set[str]] = {}
        for record in registry.rule_records:
            self._rule_ids.setdefault(record.provider, set()).add(record.id)
            self._rule_kinds[(record.provider, record.id)] = record.scope.kind
            if record.diagnostic_code is not None:
                self._rule_codes.setdefault(record.provider, set()).add(record.diagnostic_code)
        # annotation spelling -> (plugin_id, plugin type key)
        self._annotations: dict[str, tuple[str, str]] = {}
        self._type_keys: set[str] = set()
        for binding in registry.types:
            self._type_keys.add(binding.plugin_type.key)
            for spelling in binding.plugin_type.annotations:
                self._annotations[spelling] = (binding.plugin_id, binding.plugin_type.key)
        # plugin id -> covered top-level packages, lowering plugins only.
        self._packages: dict[str, frozenset[str]] = {
            plugin.id: frozenset(package.split(".")[0] for package in plugin.packages)
            for plugin in registry.active
            if plugin.lowering_provided
        }
        self._cache: dict[tuple[object, ...], object] = {}

    def is_plugin_type(self, type_name: str | None) -> bool:
        """Report whether a type-environment entry is a plugin type key."""
        return type_name is not None and type_name in self._type_keys

    def resolve_annotation(
        self, annotation: ast.AST, imports: Mapping[str, str]
    ) -> str | None:
        """Resolve an annotation node to a plugin type key, or None.

        The dotted spelling is resolved through the module's import map, so
        ``from rextio_numpy.types import F64Arr1`` and
        ``import rextio_numpy.types as t; t.F64Arr1`` both reach the
        vocabulary entry.
        """
        dotted = dotted_name(annotation)
        if dotted is None:
            return None
        head, separator, tail = dotted.partition(".")
        imported = imports.get(head)
        resolved = dotted if imported is None else (f"{imported}.{tail}" if separator else imported)
        entry = self._annotations.get(resolved)
        return entry[1] if entry is not None else None

    def claim_call(
        self,
        function: FunctionAnalysis,
        node: ast.Call,
        target: str,
        operand_types: tuple[str | None, ...],
    ) -> tuple[bool, str | None]:
        """Offer a call site to covering plugins; return (handled, result type)."""
        plugin_ids = self._call_plugins(target, operand_types)
        if not plugin_ids:
            return False, None
        site = ClaimSite(
            kind="call",
            target=target,
            operand_types=operand_types,
            file_path=function.file_path,
            line=getattr(node, "lineno", function.line),
            column=getattr(node, "col_offset", function.column),
        )
        return self._offer(function, site, plugin_ids, _node_end(node))

    def claim_binop(
        self,
        function: FunctionAnalysis,
        node: ast.AST,
        op: ast.operator,
        left: str,
        right: str,
    ) -> tuple[bool, str | None]:
        """Offer a binary operation to the operand types' plugins."""
        # The site target is the Python operator symbol (the spec's binop
        # vocabulary); operators outside _BINOP_SYMBOLS (e.g. **, //, bit ops)
        # are never offered and stay with core's own validation.
        symbol = _BINOP_SYMBOLS.get(type(op))
        if symbol is None:
            return False, None
        plugin_ids = tuple(
            sorted({key.split("/")[0] for key in (left, right) if key in self._type_keys})
        )
        plugin_ids = tuple(plugin_id for plugin_id in plugin_ids if plugin_id in self._providers)
        if not plugin_ids:
            return False, None
        site = ClaimSite(
            kind="binop",
            target=symbol,
            operand_types=(left, right),
            file_path=function.file_path,
            line=getattr(node, "lineno", function.line),
            column=getattr(node, "col_offset", function.column),
        )
        return self._offer(function, site, plugin_ids, _node_end(node))

    def _call_plugins(
        self, target: str, operand_types: tuple[str | None, ...]
    ) -> tuple[str, ...]:
        package = target.split(".")[0]
        matched = {
            plugin_id
            for plugin_id, packages in self._packages.items()
            if package in packages
        }
        # A call whose operands carry a plugin type is also that plugin's business
        # (e.g. a covered helper reached through a re-export the packages miss).
        for operand in operand_types:
            if operand is not None and operand in self._type_keys:
                owner = operand.split("/")[0]
                if owner in self._providers:
                    matched.add(owner)
        return tuple(sorted(matched))

    def _offer(
        self,
        function: FunctionAnalysis,
        site: ClaimSite,
        plugin_ids: tuple[str, ...],
        node_end: tuple[int | None, int | None] = (None, None),
    ) -> tuple[bool, str | None]:
        claims: list[tuple[str, Claimed]] = []
        rejections: list[tuple[str, Rejected]] = []
        for plugin_id in plugin_ids:
            result = self._claim(plugin_id, site)
            if isinstance(result, Claimed):
                claims.append((plugin_id, result))
            elif isinstance(result, Rejected):
                rejections.append((plugin_id, result))
        if len(claims) > 1:
            names = " and ".join(repr(plugin_id) for plugin_id, _claimed in claims)
            raise PluginError(
                f"site {site.target!r} at {site.file_path}:{site.line} is claimed by "
                f"multiple plugins: {names}"
            )
        if claims:
            plugin_id, claimed = claims[0]
            claim = PluginClaim(
                plugin_id=plugin_id,
                rule_id=claimed.rule_id,
                kind=site.kind,
                target=site.target,
                line=site.line,
                column=site.column,
                result_type=claimed.result_type,
                operand_types=site.operand_types,
                end_line=node_end[0],
                end_column=node_end[1],
            )
            if not any(
                existing.kind == claim.kind
                and existing.line == claim.line
                and existing.column == claim.column
                and existing.end_line == claim.end_line
                and existing.end_column == claim.end_column
                for existing in function.plugin_claims
            ):
                function.plugin_claims.append(claim)
            return True, claimed.result_type
        if rejections:
            plugin_id, rejected = rejections[0]
            diagnostic = replace(
                rejected.diagnostic,
                file_path=site.file_path,
                line=site.line,
                column=site.column,
                function_name=function.qualname,
            )
            # Deferred to the boundary pass (like RXT030): attaching the error
            # at parse time would divert marked functions onto the RXT080 shim
            # and silently drop auto candidates, hiding the plugin's guidance.
            if not any(
                existing.kind == site.kind
                and existing.diagnostic.line == diagnostic.line
                and existing.diagnostic.column == diagnostic.column
                for existing in function.plugin_claim_rejections
            ):
                function.plugin_claim_rejections.append(
                    PluginClaimRejection(kind=site.kind, diagnostic=diagnostic)
                )
            return True, None
        return False, None

    def _claim(self, plugin_id: str, site: ClaimSite) -> object:
        cache_key = (plugin_id, site.kind, site.target, site.operand_types)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
        provider = self._providers[plugin_id]
        try:
            result = provider.claim(  # type: ignore[attr-defined]
                replace(site, file_path="", line=0, column=0), self._config
            )
        except Exception as exc:
            raise PluginError(f"plugin {plugin_id!r} claim() failed: {exc}") from exc
        if not isinstance(result, (Claimed, NotCovered, Rejected)):
            raise PluginError(
                f"plugin {plugin_id!r} claim() must return Claimed, NotCovered, or Rejected"
            )
        # Claim validation happens HERE, before the result is cached, so the
        # cache never stores a verdict that is invalid by construction
        # (council round 6).
        if isinstance(result, Rejected):
            expected_prefix = f"RXTP-{plugin_code_segment(plugin_id)}-"
            if not result.diagnostic.code.startswith(expected_prefix):
                # A plugin must reject within its own namespace; a core-shaped
                # or foreign code would defeat the manifest's remediation
                # lookup (council round 7).
                raise PluginError(
                    f"plugin {plugin_id!r} rejected site {site.target!r} with "
                    f"diagnostic code {result.diagnostic.code!r}; plugin "
                    f"rejections must use the {expected_prefix!r} namespace"
                )
            declared = self._rule_codes.get(plugin_id)
            if declared is not None and result.diagnostic.code not in declared:
                # The rejection code must resolve to one of the plugin's own
                # rule records, or a manifest remediation lookup dangles
                # (council round 8).
                raise PluginError(
                    f"plugin {plugin_id!r} rejected site {site.target!r} with "
                    f"diagnostic code {result.diagnostic.code!r}, which is not "
                    "declared by any of its rule records"
                )
        if isinstance(result, Claimed):
            advertised = self._rule_ids.get(plugin_id)
            if advertised is not None and result.rule_id not in advertised:
                raise PluginError(
                    f"plugin {plugin_id!r} claimed site {site.target!r} with rule id "
                    f"{result.rule_id!r}, which is not among its described rule records"
                )
            rule_kind = self._rule_kinds.get((plugin_id, result.rule_id))
            if rule_kind is not None and rule_kind != site.kind:
                raise PluginError(
                    f"plugin {plugin_id!r} claimed a {site.kind!r} site under rule "
                    f"{result.rule_id!r}, whose scope kind is {rule_kind!r}"
                )
            if (
                result.result_type is not None
                and result.result_type not in self._type_keys
                and not _is_known_core_type(result.result_type)
            ):
                # A bogus result type would pass analysis and only fail deep
                # in codegen; the analyzer is the user-visible gate (council
                # round 7).
                raise PluginError(
                    f"plugin {plugin_id!r} claimed site {site.target!r} with result "
                    f"type {result.result_type!r}, which is neither a core type "
                    "nor a registered plugin type key"
                )
            if result.result_type is None:
                # Without a result type the enclosing expression stays
                # untyped, return validation is skipped, and `check` reports
                # accepted/native-plugin for a function the analyzer never
                # finished typing (council round 6).
                raise PluginError(
                    f"plugin {plugin_id!r} claimed site {site.target!r} without a "
                    "result_type; expression claims must state the type the "
                    "site produces"
                )
        self._cache[cache_key] = result
        return result


_CORE_RESULT_TYPES = frozenset(
    {"int", "float", "bool", "str", "bytes", "None"}
)


def _is_known_core_type(type_name: str) -> bool:
    """Report whether a claimed result type is a valid core scalar or container.

    Container ELEMENT types are validated against the supported vocabulary, not
    just the ``list[...]``/``dict[...]`` shape: previously any string with a
    recognized prefix and a closing bracket passed, so ``list[object]`` or a
    malformed ``list[`` was accepted at claim time and only failed deep in
    codegen (council round 8).
    """
    normalized = type_name.replace(" ", "")
    if normalized in _CORE_RESULT_TYPES:
        return True
    inner = _container_inner(normalized, "list[")
    if inner is not None:
        return inner in LIST_ITEM_TYPES
    inner = _container_inner(normalized, "set[")
    if inner is not None:
        return inner in SET_ITEM_TYPES
    inner = _container_inner(normalized, "dict[")
    if inner is not None:
        key, sep, value = inner.partition(",")
        return bool(sep) and key in DICT_KEY_TYPES and value in _CORE_RESULT_TYPES
    return False


def _container_inner(type_name: str, prefix: str) -> str | None:
    """Return the element string inside ``prefix...]``, or None if it does not match."""
    if type_name.startswith(prefix) and type_name.endswith("]"):
        return type_name[len(prefix):-1]
    return None


def _node_end(node: ast.AST) -> tuple[int | None, int | None]:
    """Return the node's end (line, column), or (None, None) when absent."""
    return (getattr(node, "end_lineno", None), getattr(node, "end_col_offset", None))
