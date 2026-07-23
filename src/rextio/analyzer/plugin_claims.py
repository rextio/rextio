"""The claim engine: offers analyzer sites to active lowering plugins.

Implements the analysis half of docs/specs/plugin-lowering.md: plugin
annotation-vocabulary resolution and the claim pass. The engine is built once
per analysis from the plugin registry and threaded to validators through
``FunctionAnalysis.claim_engine``. Claim results are cached on the site
signature — the spec's determinism contract makes the cache safe and keeps
``claim()`` from running once per probe and once per real function.

Plugin API 1.2 extends claim sites with static literal/keyword metadata and a
structured expression tree for fusion-aware lowering. Cache keys include that
metadata so distinct sites never share a verdict.
"""

from __future__ import annotations

import ast
from collections.abc import Callable, Collection, Mapping
from dataclasses import replace

from rextio.analyzer.callable_metadata import (
    FINAL_BINDING_CLASS,
    FINAL_BINDING_FUNCTION,
    ProjectSymbolIndex,
    build_schema_from_class,
    extract_callable_meta,
    resolve_symbol_qualname,
)
from rextio.analyzer.models import FunctionAnalysis, PluginClaim, PluginClaimRejection
from rextio.analyzer.native_marker import dotted_name
from rextio.analyzer.type_collector import annotation_name, is_supported_type
from rextio.capabilities import DICT_KEY_TYPES, LIST_ITEM_TYPES, SET_ITEM_TYPES
from rextio.config.schema import RextioConfig
from rextio.plugins.api import (
    CallableMeta,
    Claimed,
    ClaimExpr,
    ClaimLiteral,
    ClaimSite,
    KeywordArg,
    NON_LITERAL,
    NotCovered,
    ReceiverMeta,
    Rejected,
    SchemaMeta,
    plugin_code_segment,
)
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

_COMPARE_SYMBOLS: dict[type[ast.cmpop], str] = {
    ast.Eq: "==",
    ast.NotEq: "!=",
    ast.Lt: "<",
    ast.LtE: "<=",
    ast.Gt: ">",
    ast.GtE: ">=",
}

# i64 bounds for claim-literal signed ints (matches analyzer native range).
_I64_MIN = -(2**63)
_I64_MAX = 2**63 - 1


def _api_version_tuple(version: str) -> tuple[int, int]:
    """Parse a plugin-API SemVer major.minor (extra segments ignored)."""
    parts = version.split(".")
    try:
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
    except (ValueError, IndexError):
        return (0, 0)
    return (major, minor)


def extract_claim_literal(node: ast.AST, *, api_13: bool = False) -> ClaimLiteral:
    """Extract a supported static literal from an AST node without executing it.

    Returns :data:`NON_LITERAL` when the node is not a supported literal shape
    (signed int, ``None``, or a tuple of signed ints). With ``api_13=True``,
    bool and string constants are additionally accepted for API 1.3 keyword
    metadata. Unary ``-`` on an int constant is folded so negative axis values
    work. Tuples remain int-only in both versions.
    """
    if (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, ast.USub)
        and isinstance(node.operand, ast.Constant)
        and isinstance(node.operand.value, int)
        and not isinstance(node.operand.value, bool)
    ):
        value = -node.operand.value
        if _I64_MIN <= value <= _I64_MAX:
            return ClaimLiteral(is_literal=True, value=value)
        return NON_LITERAL
    if isinstance(node, ast.Constant):
        if node.value is None:
            return ClaimLiteral(is_literal=True, value=None)
        if isinstance(node.value, bool):
            if api_13:
                return ClaimLiteral(is_literal=True, value=node.value)
            return NON_LITERAL
        if isinstance(node.value, int) and not isinstance(node.value, bool):
            if _I64_MIN <= node.value <= _I64_MAX:
                return ClaimLiteral(is_literal=True, value=node.value)
            return NON_LITERAL
        if api_13 and isinstance(node.value, str):
            return ClaimLiteral(is_literal=True, value=node.value)
        return NON_LITERAL
    if isinstance(node, ast.Tuple):
        items: list[int] = []
        for element in node.elts:
            lit = extract_claim_literal(element)
            if not lit.is_literal or not isinstance(lit.value, int):
                return NON_LITERAL
            items.append(lit.value)
        return ClaimLiteral(is_literal=True, value=tuple(items))
    return NON_LITERAL


def call_has_dynamic_keywords(node: ast.Call) -> bool:
    """Return True when a call uses ``**kwargs`` or an unnamed keyword."""
    return any(keyword.arg is None for keyword in node.keywords)


def expression_is_leaves_safe(expression: ClaimExpr | None) -> bool:
    """Whether an expression is eligible for ``operand_mode="leaves"``.

    Leaves-mode trees may only contain name leaves, literals, and binops
    (nested calls are opaque atomic leaves and make the tree unsafe). A root
    call is allowed when every nested child is leaves-safe.
    """
    if expression is None:
        return False
    return _expr_is_leaves_safe(expression)


def _expr_is_leaves_safe(expression: ClaimExpr) -> bool:
    if expression.kind == "literal":
        return expression.literal.is_literal
    if expression.kind == "leaf":
        return expression.leaf_kind == "name"
    if expression.kind == "binop":
        return all(_expr_is_leaves_safe(child) for child in expression.children)
    if expression.kind == "call":
        # Root/nested call nodes are only leaves-safe when every positional
        # child is safe; nested *call ASTs* are never expanded (opaque leaves).
        return all(_expr_is_leaves_safe(child) for child in expression.children)
    return False


def classify_receiver(node: ast.AST) -> tuple[str, bool]:
    """Classify a method-call receiver expression's shape and evaluation safety.

    Returns ``(expr_kind, is_safe)``. Only a plain local ``ast.Name`` is
    intrinsically side-effect-free (``is_safe`` True): reading a Rust local is
    pure and repeatable, so core can render it as a bare reference. Every other
    shape is conservatively unsafe (``is_safe`` False) because Python evaluation
    of the receiver can run arbitrary user code that this compiler does not
    prove pure:

    * ``attribute`` (``obj.x``) can trigger a descriptor ``__get__`` or a
      ``__getattr__`` hook;
    * ``subscript`` (``obj[k]``) invokes ``__getitem__`` (and evaluates the key);
    * ``call`` (``f()``) evaluates a call;
    * ``opaque`` is any other shape core cannot classify.

    The classification never changes single-evaluation — core ALWAYS evaluates
    the receiver exactly once in Python order regardless. ``is_safe`` only tells
    a provider whether the rendered receiver text
    (:attr:`~rextio.plugins.api.LoweringContext.receiver`) is a bare reference
    or a bound single-use temporary.
    """
    if isinstance(node, ast.Name):
        return "name", True
    if isinstance(node, ast.Attribute):
        return "attribute", False
    if isinstance(node, ast.Subscript):
        return "subscript", False
    if isinstance(node, ast.Call):
        return "call", False
    return "opaque", False


class ClaimEngine:
    """Resolves plugin annotation vocabularies and runs the claim pass."""

    def __init__(
        self,
        registry: PluginRegistry,
        config: RextioConfig,
        symbol_index: ProjectSymbolIndex | None = None,
    ) -> None:
        self._config = config
        # Project-wide static function/class index (built before the claim pass,
        # so callable/schema resolution is order-independent across modules).
        self._symbol_index = symbol_index or ProjectSymbolIndex()
        # Declared schemas resolved from schema class nodes, cached by the class
        # qualname so a repeated ``Frame[Row]`` annotation yields the identical
        # (value-equal) SchemaMeta.
        self._schema_by_class: dict[str, SchemaMeta | None] = {}
        self._providers = {binding.plugin_id: binding.provider for binding in registry.providers}
        # plugin id -> (major, minor) API version from the provider (or plugin
        # metadata). Gates all 1.2 analyzer/codegen behavior.
        self._api_versions: dict[str, tuple[int, int]] = {}
        plugin_versions = {
            plugin.id: _api_version_tuple(str(plugin.api_version or "1.0"))
            for plugin in registry.active
        }
        for binding in registry.providers:
            declared = getattr(binding.provider, "api_version", None)
            if isinstance(declared, str) and declared:
                self._api_versions[binding.plugin_id] = _api_version_tuple(declared)
            else:
                self._api_versions[binding.plugin_id] = plugin_versions.get(
                    binding.plugin_id, (1, 0)
                )
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
        # Resident (opaque, no-boundary) plugin type keys (plugin API 1.3). A
        # native function whose plugin type keys are all resident is a
        # native-only helper the boundary pass may call native-to-native; a
        # materialized key keeps the RXT092 Python-entry-point restriction.
        self._resident_type_keys: set[str] = set()
        for type_binding in registry.types:
            self._type_keys.add(type_binding.plugin_type.key)
            if type_binding.plugin_type.is_resident:
                self._resident_type_keys.add(type_binding.plugin_type.key)
            for spelling in type_binding.plugin_type.annotations:
                self._annotations[spelling] = (
                    type_binding.plugin_id,
                    type_binding.plugin_type.key,
                )
        # plugin id -> covered top-level packages, lowering plugins only.
        self._packages: dict[str, frozenset[str]] = {
            plugin.id: frozenset(package.split(".")[0] for package in plugin.packages)
            for plugin in registry.active
            if plugin.lowering_provided
        }
        self._cache: dict[tuple[object, ...], object] = {}

    def provider_api_version(self, plugin_id: str) -> tuple[int, int]:
        """Return the declared plugin-API (major, minor) for a provider."""
        return self._api_versions.get(plugin_id, (1, 0))

    def provider_is_api_12(self, plugin_id: str) -> bool:
        """Whether the provider declared plugin API >= 1.2."""
        return self.provider_api_version(plugin_id) >= (1, 2)

    def provider_is_api_13(self, plugin_id: str) -> bool:
        """Whether the provider declared plugin API >= 1.3."""
        return self.provider_api_version(plugin_id) >= (1, 3)

    def provider_is_api_15(self, plugin_id: str) -> bool:
        """Whether the provider declared plugin API >= 1.5."""
        return self.provider_api_version(plugin_id) >= (1, 5)

    def is_plugin_type(self, type_name: str | None) -> bool:
        """Report whether a type-environment entry is a plugin type key."""
        return type_name is not None and type_name in self._type_keys

    def is_resident_type(self, type_name: str | None) -> bool:
        """Report whether a type key is a resident (opaque, no-boundary) type."""
        return type_name is not None and type_name in self._resident_type_keys

    def resolve_annotation(self, annotation: ast.AST, imports: Mapping[str, str]) -> str | None:
        """Resolve an annotation node to a plugin type key, or None.

        The dotted spelling is resolved through the module's import map, so
        ``from rextio_numpy.types import F64Arr1`` and
        ``import rextio_numpy.types as t; t.F64Arr1`` both reach the
        vocabulary entry.

        A schema-parameterized plugin annotation ``Frame[Row]`` (plugin API 1.3)
        resolves to the SAME plugin type key as the bare ``Frame``: the ``[Row]``
        subscript only carries the declared-schema association (see
        :meth:`resolve_declared_schema`) and never changes the resolved type, so
        every existing type-resolution path is preserved.
        """
        if isinstance(annotation, ast.Subscript):
            return self.resolve_annotation(annotation.value, imports)
        dotted = dotted_name(annotation)
        if dotted is None:
            return None
        head, separator, tail = dotted.partition(".")
        imported = imports.get(head)
        resolved = dotted if imported is None else (f"{imported}.{tail}" if separator else imported)
        entry = self._annotations.get(resolved)
        return entry[1] if entry is not None else None

    def _resolve_type(self, annotation: ast.expr, imports: Mapping[str, str]) -> str | None:
        """Resolve an annotation to a core type name or a plugin type key, or None."""
        if is_supported_type(annotation):
            return annotation_name(annotation)
        return self.resolve_annotation(annotation, imports)

    def resolve_declared_schema(
        self, annotation: ast.AST, imports: Mapping[str, str], module_name: str
    ) -> SchemaMeta | None:
        """Resolve a schema-parameterized plugin annotation to its declared schema.

        The documented source spelling is a plugin base annotation parameterized
        by a declared schema class — ``df: Frame[Row]`` — where ``Row`` is a
        project class whose body is only ``name: <type>`` field annotations. The
        schema is built statically from ``Row``'s class node (never executed) and
        associated with the annotated receiver/parameter. Returns ``None`` (no
        association, fail closed) when the annotation is not a parameterized
        plugin type, the schema class is unresolved, or its body violates the
        declared-schema grammar.
        """
        if not isinstance(annotation, ast.Subscript):
            return None
        # The base must be the DIRECT registered plugin spelling (``Frame[Row]``),
        # not another subscript: ``Frame[Row][Other]`` is a nested subscript whose
        # inner ``Frame[Row]`` would otherwise resolve (``resolve_annotation``
        # strips subscripts recursively) and wrongly associate ``Other`` with the
        # outer ``Frame``. A nested/parameterized base carries no declared schema.
        if isinstance(annotation.value, ast.Subscript):
            return None
        if self.resolve_annotation(annotation.value, imports) is None:
            return None  # base is not a registered plugin type
        slice_dotted = dotted_name(annotation.slice)
        if slice_dotted is None:
            return None
        qualname = resolve_symbol_qualname(
            slice_dotted,
            dict(imports),
            module_name,
            self._symbol_index.classes,
            # A schema annotation resolves at module scope, so there is no function
            # local to shadow it; but the shared final-binding model still fails
            # closed when the schema class name's final binder — in the annotating
            # module or the schema's own defining module — is not the ``class``
            # (``Row = int`` after ``class Row``, a later import, ``del``, or a
            # conditional rebind), so the indexed class node is never stale.
            kind=FINAL_BINDING_CLASS,
            final_bindings=self._symbol_index.final_bindings,
            project_mutations=self._symbol_index.project_mutations,
        )
        if qualname is None:
            return None
        if qualname not in self._schema_by_class:
            indexed = self._symbol_index.classes[qualname]
            self._schema_by_class[qualname] = build_schema_from_class(
                qualname, indexed, self._resolve_type, plugin_type_keys=self._type_keys
            )
        return self._schema_by_class[qualname]

    def peek_call_result_type(
        self,
        function: FunctionAnalysis,
        node: ast.Call,
        target: str,
        operand_types: tuple[str | None, ...],
        *,
        type_of: Callable[[ast.AST], str | None] | None = None,
    ) -> str | None:
        """Return a claimed call's result type without recording anything.

        Used by signature inference to type a local assigned from a claimed
        call (e.g. a resident value produced for native chaining) so the
        boundary pass sees its exact plugin type key. This is side-effect free:
        it never records a claim or rejection (the body validator remains the
        sole recorder) and is deliberately conservative — it returns ``None``
        for keyword calls and only reports a single unambiguous ``Claimed``
        result type. A ``None`` result simply leaves the local untyped, which
        keeps a downstream native caller on the Python fallback (fail closed).

        The offered site carries the SAME real metadata (``file_path``, ``line``,
        ``column``, operand literals, and expression) that the later authoritative
        ``claim_call`` builds for this exact node — a peek must never present a
        provider a different (e.g. zeroed) site than the one it will authoritatively
        rule on, so a path/position-sensitive provider stays consistent.
        """
        if node.keywords:
            return None
        type_lookup = type_of or (lambda _node: None)
        receiver_type = self._receiver_type(node, type_lookup)
        plugin_ids = self._call_plugins(target, operand_types, receiver_type=receiver_type)
        if not plugin_ids:
            return None
        any_12 = any(self.provider_is_api_12(pid) for pid in plugin_ids)
        if any_12:
            operand_literals = tuple(extract_claim_literal(arg) for arg in node.args)
            expression = self._build_call_expr(
                node,
                target=target,
                result_type=None,
                type_of=type_lookup,
                operand_types=operand_types,
                keywords=(),
            )
        else:
            operand_literals = ()
            expression = None
        any_13 = any(self.provider_is_api_13(pid) for pid in plugin_ids)
        schema_of = self._schema_lookup(function)
        receiver = self._receiver_meta(node, type_lookup, schema_of) if any_13 else None
        callables = (
            self._callable_metas(function, node, self._receiver_schema(node, schema_of))
            if any_13
            else ()
        )
        site = ClaimSite(
            kind="call",
            target=target,
            operand_types=operand_types,
            file_path=function.file_path,
            line=getattr(node, "lineno", function.line),
            column=getattr(node, "col_offset", function.column),
            operand_literals=operand_literals,
            keywords=(),
            expression=expression,
            receiver=receiver,
            callables=callables,
        )
        result_type: str | None = None
        for plugin_id in plugin_ids:
            try:
                verdict = self._claim(plugin_id, self._site_for_provider(site, plugin_id))
            except PluginError:
                # Any misconfiguration (bad rejection namespace, overlap, unknown
                # result type, …) is surfaced authoritatively by the recording
                # path with full metadata; a peek must never raise or pre-empt it.
                return None
            if isinstance(verdict, Claimed):
                if result_type is not None and verdict.result_type != result_type:
                    # Overlapping claims are an error the recording path reports;
                    # stay silent here rather than pick a winner.
                    return None
                result_type = verdict.result_type
        return result_type

    def claim_call(
        self,
        function: FunctionAnalysis,
        node: ast.Call,
        target: str,
        operand_types: tuple[str | None, ...],
        *,
        type_of: Callable[[ast.AST], str | None] | None = None,
    ) -> tuple[bool, str | None]:
        """Offer a call site to covering plugins; return (handled, result type).

        Plugin API 1.2/1.3 keyword policy (fail closed):

        * ``**kwargs`` / unnamed keywords are never offered.
        * Named keywords with non-literal values are never offered (no CallIR
          representation for runtime keyword operands yet).
        * Named keywords with supported static literals (signed int, ``None``,
          int tuples) are offered only to providers with ``api_version >= 1.2``.
        * Static bool and string keyword literals are offered only to providers
          with ``api_version >= 1.3``.
        * API 1.1 providers retain legacy semantics: any keyword call is not
          offered to them (pre-1.2 RXT010/fallback).
        """
        if call_has_dynamic_keywords(node):
            return False, None
        type_lookup_pre = type_of or (lambda _node: None)
        receiver_type = self._receiver_type(node, type_lookup_pre)
        plugin_ids = self._call_plugins(target, operand_types, receiver_type=receiver_type)
        if not plugin_ids:
            return False, None
        has_keywords = bool(node.keywords)
        # Keyword names whose value is a statically-resolved project-function
        # reference (plugin API 1.3): carried as compile-time CallableMeta, never
        # as a runtime keyword operand.
        callable_keyword_names: set[str] = set()
        has_api_13_literal = False
        if has_keywords:
            # Only 1.2+ providers may see keyword call sites.
            plugin_ids = tuple(pid for pid in plugin_ids if self.provider_is_api_12(pid))
            if not plugin_ids:
                return False, None
            for keyword in node.keywords:
                if keyword.arg is None:
                    return False, None
                if extract_claim_literal(keyword.value).is_literal:
                    continue
                if extract_claim_literal(keyword.value, api_13=True).is_literal:
                    has_api_13_literal = True
                    continue
                # A project-function keyword reference is compile-time callable
                # metadata, not a runtime keyword operand (there is no CallIR
                # representation for a runtime keyword value, but a callable ref
                # never becomes one — it names a native helper / closed body).
                # Any OTHER non-literal keyword value still fails closed.
                if self.is_project_callable(keyword.value, function):
                    callable_keyword_names.add(keyword.arg)
                    continue
                return False, None
            if callable_keyword_names or has_api_13_literal:
                # Keyword callables and bool/string literal metadata are
                # representable only for >= 1.3 providers. In a mixed-provider
                # registry, lower versions must not observe or claim the site.
                plugin_ids = tuple(pid for pid in plugin_ids if self.provider_is_api_13(pid))
                if not plugin_ids:
                    return False, None
        type_lookup = type_lookup_pre
        # Build full 1.2 metadata once; stripped per-provider for api < 1.2.
        any_12 = any(self.provider_is_api_12(pid) for pid in plugin_ids)
        any_13 = any(self.provider_is_api_13(pid) for pid in plugin_ids)
        if any_12:
            operand_literals = tuple(extract_claim_literal(arg) for arg in node.args)
            keywords = (
                self._keyword_args(
                    node,
                    type_lookup,
                    exclude=callable_keyword_names,
                    api_13=any_13,
                )
                if has_keywords
                else ()
            )
            expression = self._build_call_expr(
                node,
                target=target,
                result_type=None,
                type_of=type_lookup,
                operand_types=operand_types,
                keywords=keywords,
            )
        else:
            operand_literals = ()
            keywords = ()
            expression = None
        # Plugin API 1.3 receiver/callable metadata (stripped per-provider for
        # api < 1.3).
        schema_of = self._schema_lookup(function)
        receiver = self._receiver_meta(node, type_lookup, schema_of) if any_13 else None
        callables = (
            self._callable_metas(function, node, self._receiver_schema(node, schema_of))
            if any_13
            else ()
        )
        site = ClaimSite(
            kind="call",
            target=target,
            operand_types=operand_types,
            file_path=function.file_path,
            line=getattr(node, "lineno", function.line),
            column=getattr(node, "col_offset", function.column),
            operand_literals=operand_literals,
            keywords=keywords,
            expression=expression,
            receiver=receiver,
            callables=callables,
        )
        return self._offer(function, site, plugin_ids, _node_end(node))

    def claim_binop(
        self,
        function: FunctionAnalysis,
        node: ast.AST,
        op: ast.operator,
        left: str,
        right: str,
        *,
        type_of: Callable[[ast.AST], str | None] | None = None,
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
        type_lookup = type_of or (lambda _node: None)
        left_node = getattr(node, "left", None)
        right_node = getattr(node, "right", None)
        any_12 = any(self.provider_is_api_12(pid) for pid in plugin_ids)
        operand_literals: tuple[ClaimLiteral, ...]
        expression: ClaimExpr | None
        if any_12:
            operand_literals = (
                extract_claim_literal(left_node) if isinstance(left_node, ast.AST) else NON_LITERAL,
                extract_claim_literal(right_node)
                if isinstance(right_node, ast.AST)
                else NON_LITERAL,
            )
            expression = self._build_binop_expr(
                node,
                symbol=symbol,
                result_type=None,
                left_type=left,
                right_type=right,
                type_of=type_lookup,
            )
        else:
            operand_literals = ()
            expression = None
        site = ClaimSite(
            kind="binop",
            target=symbol,
            operand_types=(left, right),
            file_path=function.file_path,
            line=getattr(node, "lineno", function.line),
            column=getattr(node, "col_offset", function.column),
            operand_literals=operand_literals,
            keywords=(),
            expression=expression,
        )
        return self._offer(function, site, plugin_ids, _node_end(node))

    def peek_compare_result_type(
        self,
        function: FunctionAnalysis,
        node: ast.Compare,
        operand_types: tuple[str | None, ...],
    ) -> str | None:
        """Return one unambiguous API-1.5 comparison result type without recording.

        Only non-chained comparisons from the closed comparison vocabulary are
        eligible. Legacy providers are never offered the site. As with call
        peeking, any overlap or provider error is left to the authoritative
        recording path and this method fails closed to ``None``.
        """
        if len(node.ops) != 1 or len(operand_types) != 2:
            return None
        symbol = _COMPARE_SYMBOLS.get(type(node.ops[0]))
        if symbol is None:
            return None
        plugin_ids = self._compare_plugins(operand_types)
        if not plugin_ids:
            return None
        site = ClaimSite(
            kind="compare",
            target=symbol,
            operand_types=operand_types,
            file_path=function.file_path,
            line=getattr(node, "lineno", function.line),
            column=getattr(node, "col_offset", function.column),
            operand_literals=tuple(
                extract_claim_literal(item) for item in (node.left, *node.comparators)
            ),
        )
        result_type: str | None = None
        for plugin_id in plugin_ids:
            try:
                verdict = self._claim(plugin_id, site)
            except PluginError:
                return None
            if isinstance(verdict, Claimed):
                if result_type is not None and verdict.result_type != result_type:
                    return None
                result_type = verdict.result_type
        return result_type

    def claim_compare(
        self,
        function: FunctionAnalysis,
        node: ast.Compare,
        operand_types: tuple[str | None, ...],
    ) -> tuple[bool, str | None]:
        """Offer one non-chained comparison to API-1.5 operand-type plugins."""
        if len(node.ops) != 1 or len(operand_types) != 2:
            return False, None
        symbol = _COMPARE_SYMBOLS.get(type(node.ops[0]))
        if symbol is None:
            return False, None
        plugin_ids = self._compare_plugins(operand_types)
        if not plugin_ids:
            return False, None
        site = ClaimSite(
            kind="compare",
            target=symbol,
            operand_types=operand_types,
            file_path=function.file_path,
            line=getattr(node, "lineno", function.line),
            column=getattr(node, "col_offset", function.column),
            operand_literals=tuple(
                extract_claim_literal(item) for item in (node.left, *node.comparators)
            ),
        )
        return self._offer(function, site, plugin_ids, _node_end(node))

    def covers_call(self, target: str | None, receiver_type: str | None) -> bool:
        """Report whether any active plugin covers this call/method site.

        A cheap package/receiver coverage probe (no operand types, no provider
        ``claim`` call) used by argument inference to recognize a callable-
        reference argument at a plugin site — such an argument is lowered by the
        plugin and must not be rejected as an unbound value read.
        """
        if not self._providers:
            return False
        return bool(self._call_plugins(target or "", (), receiver_type=receiver_type))

    def is_project_callable(self, node: ast.AST, function: FunctionAnalysis) -> bool:
        """Report whether an argument statically resolves to an indexed project function.

        Scope/site-aware and conservative (plugin API 1.3): a reference shadowed
        by a function local, or whose name is reassigned at the caller's or the
        defining module's scope, is not a project callable (fail closed), so the
        cheap probe never disagrees with :meth:`_callable_metas`.
        """
        dotted = dotted_name(node)
        if dotted is None:
            return False
        return (
            resolve_symbol_qualname(
                dotted,
                dict(function.imports),
                function.module_name,
                self._symbol_index.functions,
                kind=FINAL_BINDING_FUNCTION,
                final_bindings=self._symbol_index.final_bindings,
                local_names=self._site_local_names(function, node),
                project_mutations=self._symbol_index.project_mutations,
            )
            is not None
        )

    def _site_local_names(self, function: FunctionAnalysis, node: ast.AST) -> frozenset[str]:
        """Local shadow names in scope at a callable-reference site.

        The function-scope locals UNION the comprehension ``for`` targets in scope
        at this exact node (Python 3 comprehension scoping), so a reference inside a
        comprehension is shadowed by that comprehension's targets while the same name
        used elsewhere in the function is not.
        """
        scoped = function.comprehension_scope_names.get(id(node))
        if not scoped:
            return function.local_binding_names
        return function.local_binding_names | scoped

    def _call_plugins(
        self,
        target: str,
        operand_types: tuple[str | None, ...],
        receiver_type: str | None = None,
    ) -> tuple[str, ...]:
        package = target.split(".")[0]
        matched = {
            plugin_id for plugin_id, packages in self._packages.items() if package in packages
        }
        # A call whose operands carry a plugin type is also that plugin's business
        # (e.g. a covered helper reached through a re-export the packages miss).
        for operand in operand_types:
            if operand is not None and operand in self._type_keys:
                owner = operand.split("/")[0]
                if owner in self._providers:
                    matched.add(owner)
        # A method call whose receiver carries a plugin type is that plugin's
        # business too (``df.method(...)`` on a plugin-typed ``df``). The
        # receiver is never in ``operand_types`` (it is not a positional arg),
        # so it must be matched explicitly. This receiver-type-only matching is a
        # plugin API 1.3 surface: gate it to providers declaring API >= 1.3, so a
        # legacy 1.1/1.2 provider is NEVER newly offered a method site solely
        # because its plugin type is the receiver (a site it was never offered
        # before 1.3). Legacy package and operand-type matching above are
        # unchanged, so a 1.1/1.2 provider keeps its exact pre-1.3 coverage.
        if receiver_type is not None and receiver_type in self._type_keys:
            owner = receiver_type.split("/")[0]
            if owner in self._providers and self.provider_is_api_13(owner):
                matched.add(owner)
        return tuple(sorted(matched))

    def _compare_plugins(
        self, operand_types: tuple[str | None, ...]
    ) -> tuple[str, ...]:
        """Return API-1.5 providers owning at least one comparison operand."""
        owners = {
            operand.split("/", 1)[0]
            for operand in operand_types
            if operand is not None and operand in self._type_keys
        }
        return tuple(
            sorted(
                owner
                for owner in owners
                if owner in self._providers and self.provider_is_api_15(owner)
            )
        )

    def _receiver_type(
        self, node: ast.Call, type_of: Callable[[ast.AST], str | None]
    ) -> str | None:
        """Return the resolved type of a method-call receiver value, or None.

        A receiver exists only when ``node.func`` is an attribute access whose
        base expression resolves to a value type — ``df.method(...)`` on a typed
        ``df``. A module-qualified call (``numpy.dot(...)``: the base ``numpy``
        has no value type) has no receiver.
        """
        func = node.func
        if not isinstance(func, ast.Attribute):
            return None
        return type_of(func.value)

    def _schema_lookup(self, function: FunctionAnalysis) -> Callable[[ast.AST], SchemaMeta | None]:
        """Return a receiver/parameter -> declared-schema resolver for a function.

        A schema is associated with a plain parameter/local name via its
        ``Frame[Row]`` annotation (recorded in ``function.declared_schemas``); a
        non-name expression carries no declared schema.
        """
        declared = function.declared_schemas

        def schema_of(node: ast.AST) -> SchemaMeta | None:
            if isinstance(node, ast.Name):
                return declared.get(node.id)
            return None

        return schema_of

    def _receiver_schema(
        self, node: ast.Call, schema_of: Callable[[ast.AST], SchemaMeta | None]
    ) -> SchemaMeta | None:
        """Return the declared schema of a method-call receiver, or None."""
        func = node.func
        if not isinstance(func, ast.Attribute):
            return None
        return schema_of(func.value)

    def _receiver_meta(
        self,
        node: ast.Call,
        type_of: Callable[[ast.AST], str | None],
        schema_of: Callable[[ast.AST], SchemaMeta | None],
    ) -> ReceiverMeta | None:
        """Build the receiver metadata for a method call, or None for plain calls."""
        func = node.func
        if not isinstance(func, ast.Attribute):
            return None
        receiver_type = type_of(func.value)
        if receiver_type is None:
            return None
        expr_kind, is_safe = classify_receiver(func.value)
        return ReceiverMeta(
            arg_type=receiver_type,
            expr_kind=expr_kind,
            is_safe=is_safe,
            schema=schema_of(func.value),
        )

    def _callable_metas(
        self,
        function: FunctionAnalysis,
        node: ast.Call,
        receiver_schema: SchemaMeta | None,
    ) -> tuple[CallableMeta, ...]:
        """Build ordered callable metadata for a call's project-function arguments.

        A positional or keyword argument that statically resolves — through the
        caller module's imports/aliases — to an indexed project function is
        exposed as a :class:`CallableMeta`. ``receiver_schema`` (the method
        receiver's declared schema, if any) is bound to each callable's first
        unannotated parameter, so a row UDF's field/subscript reads resolve. Args
        that do not resolve to a project function carry no metadata (omitted).

        arg_index is the positional index for a positional argument; a keyword
        callable takes the next index after the positional arguments, in keyword
        order, so every index stays unique.
        """
        if self._symbol_index is None:
            return ()
        metas: list[CallableMeta] = []

        def resolve(arg: ast.expr, arg_index: int, keyword: str = "") -> None:
            dotted = dotted_name(arg)
            if dotted is None:
                return
            qualname = resolve_symbol_qualname(
                dotted,
                dict(function.imports),
                function.module_name,
                self._symbol_index.functions,
                kind=FINAL_BINDING_FUNCTION,
                final_bindings=self._symbol_index.final_bindings,
                local_names=self._site_local_names(function, arg),
                project_mutations=self._symbol_index.project_mutations,
            )
            if qualname is None:
                return
            indexed = self._symbol_index.functions[qualname]
            meta = extract_callable_meta(
                arg_index,
                indexed,
                self._resolve_type,
                receiver_schema=receiver_schema,
                keyword=keyword,
            )
            if meta is not None:
                metas.append(meta)

        for index, arg in enumerate(node.args):
            resolve(arg, index)
        next_index = len(node.args)
        for offset, keyword in enumerate(node.keywords):
            if keyword.arg is None:
                continue  # **kwargs never reaches here (dynamic keywords fail closed)
            # A keyword callable takes the next synthetic index after the
            # positional arguments; its ``keyword`` name is the unambiguous
            # identifier (the index is only a slot for cache-key uniqueness).
            resolve(keyword.value, next_index + offset, keyword=keyword.arg)
        return tuple(metas)

    def _keyword_args(
        self,
        node: ast.Call,
        type_of: Callable[[ast.AST], str | None],
        exclude: Collection[str] = (),
        *,
        api_13: bool = False,
    ) -> tuple[KeywordArg, ...]:
        """Build ordered keyword metadata for a call (dynamic kwargs already excluded).

        ``exclude`` names keywords that are project-function references carried as
        compile-time :class:`CallableMeta` instead — they are not runtime keyword
        operands, so they never appear on this surface.
        """
        keywords: list[KeywordArg] = []
        for keyword in node.keywords:
            name = keyword.arg
            if name is None or name in exclude:
                continue
            keywords.append(
                KeywordArg(
                    name=name,
                    arg_type=type_of(keyword.value),
                    literal=extract_claim_literal(keyword.value, api_13=api_13),
                )
            )
        return tuple(keywords)

    def _build_call_expr(
        self,
        node: ast.Call,
        *,
        target: str,
        result_type: str | None,
        type_of: Callable[[ast.AST], str | None],
        operand_types: tuple[str | None, ...],
        keywords: tuple[KeywordArg, ...],
    ) -> ClaimExpr:
        counter = [0]
        children: list[ClaimExpr] = []
        for index, arg in enumerate(node.args):
            arg_type = operand_types[index] if index < len(operand_types) else type_of(arg)
            children.append(
                self._build_expr_node(arg, result_type=arg_type, type_of=type_of, counter=counter)
            )
        return ClaimExpr(
            kind="call",
            target=target,
            result_type=result_type,
            children=tuple(children),
            keywords=keywords,
        )

    def _build_binop_expr(
        self,
        node: ast.AST,
        *,
        symbol: str,
        result_type: str | None,
        left_type: str | None,
        right_type: str | None,
        type_of: Callable[[ast.AST], str | None],
    ) -> ClaimExpr:
        counter = [0]
        left_node = getattr(node, "left", None)
        right_node = getattr(node, "right", None)
        left_expr = (
            self._build_expr_node(
                left_node, result_type=left_type, type_of=type_of, counter=counter
            )
            if isinstance(left_node, ast.AST)
            else ClaimExpr(kind="leaf", result_type=left_type, leaf_index=0, leaf_kind="opaque")
        )
        right_expr = (
            self._build_expr_node(
                right_node, result_type=right_type, type_of=type_of, counter=counter
            )
            if isinstance(right_node, ast.AST)
            else ClaimExpr(kind="leaf", result_type=right_type, leaf_index=1, leaf_kind="opaque")
        )
        return ClaimExpr(
            kind="binop",
            target=symbol,
            result_type=result_type,
            children=(left_expr, right_expr),
        )

    def _build_expr_node(
        self,
        node: ast.AST,
        *,
        result_type: str | None,
        type_of: Callable[[ast.AST], str | None],
        counter: list[int],
    ) -> ClaimExpr:
        """Build one ClaimExpr node; fail closed to an opaque leaf when unsure."""
        lit = extract_claim_literal(node)
        if lit.is_literal:
            lit_type = result_type
            if lit_type is None:
                if lit.value is None:
                    lit_type = "None"
                elif isinstance(lit.value, tuple):
                    lit_type = (
                        f"tuple[{', '.join('int' for _ in lit.value)}]" if lit.value else "tuple"
                    )
                else:
                    lit_type = "int"
            return ClaimExpr(kind="literal", result_type=lit_type, literal=lit)

        if isinstance(node, ast.BinOp):
            symbol = _BINOP_SYMBOLS.get(type(node.op))
            if symbol is not None:
                left_type = type_of(node.left)
                right_type = type_of(node.right)
                left = self._build_expr_node(
                    node.left, result_type=left_type, type_of=type_of, counter=counter
                )
                right = self._build_expr_node(
                    node.right, result_type=right_type, type_of=type_of, counter=counter
                )
                return ClaimExpr(
                    kind="binop",
                    target=symbol,
                    result_type=result_type if result_type is not None else type_of(node),
                    children=(left, right),
                )

        # Nested calls are always opaque atomic leaves. Expanding them would
        # risk side-effectful / unclaimed call elision under fusion (Wave 2
        # allows root call trees + nested binop/name/literal only).
        if isinstance(node, ast.Call):
            leaf_index = counter[0]
            counter[0] += 1
            return ClaimExpr(
                kind="leaf",
                result_type=result_type if result_type is not None else type_of(node),
                leaf_index=leaf_index,
                leaf_kind="opaque",
            )

        leaf_index = counter[0]
        counter[0] += 1
        # Simple Name leaves are fusion-safe; everything else is opaque so a
        # provider can reject trees that hide subscripts/calls/etc.
        leaf_kind = "name" if isinstance(node, ast.Name) else "opaque"
        return ClaimExpr(
            kind="leaf",
            result_type=result_type if result_type is not None else type_of(node),
            leaf_index=leaf_index,
            leaf_kind=leaf_kind,
        )

    def _site_for_provider(self, site: ClaimSite, plugin_id: str) -> ClaimSite:
        """Return the claim site shape a provider may see for its API version.

        API < 1.2 providers always receive empty 1.2 metadata; API < 1.3
        providers additionally never see the 1.3 receiver/callable metadata
        (legacy shape, so lower-versioned providers stay behavior-compatible).
        """
        if self.provider_is_api_13(plugin_id):
            return site
        if self.provider_is_api_12(plugin_id):
            return replace(site, receiver=None, callables=())
        return replace(
            site,
            operand_literals=(),
            keywords=(),
            expression=None,
            receiver=None,
            callables=(),
        )

    def _offer(
        self,
        function: FunctionAnalysis,
        site: ClaimSite,
        plugin_ids: tuple[str, ...],
        node_end: tuple[int | None, int | None] = (None, None),
    ) -> tuple[bool, str | None]:
        claims: list[tuple[str, Claimed, ClaimSite]] = []
        rejections: list[tuple[str, Rejected]] = []
        for plugin_id in plugin_ids:
            offer_site = self._site_for_provider(site, plugin_id)
            result = self._claim(plugin_id, offer_site)
            if isinstance(result, Claimed):
                claims.append((plugin_id, result, offer_site))
            elif isinstance(result, Rejected):
                rejections.append((plugin_id, result))
        if len(claims) > 1:
            names = " and ".join(repr(plugin_id) for plugin_id, _claimed, _s in claims)
            raise PluginError(
                f"site {site.target!r} at {site.file_path}:{site.line} is claimed by "
                f"multiple plugins: {names}"
            )
        if claims:
            plugin_id, claimed, offer_site = claims[0]
            expression = offer_site.expression
            if expression is not None and claimed.result_type is not None:
                expression = replace(expression, result_type=claimed.result_type)
            # Strip 1.2 metadata for non-leaves direct claims from 1.1, and for
            # direct-mode when expression is unused... keep expression only when
            # the offer site had it (api >= 1.2).
            claim = PluginClaim(
                plugin_id=plugin_id,
                rule_id=claimed.rule_id,
                kind=offer_site.kind,
                target=offer_site.target,
                line=site.line,
                column=site.column,
                result_type=claimed.result_type,
                operand_types=offer_site.operand_types,
                end_line=node_end[0],
                end_column=node_end[1],
                operand_literals=offer_site.operand_literals,
                keywords=offer_site.keywords,
                expression=expression,
                operand_mode=claimed.operand_mode,
                receiver=offer_site.receiver,
                callables=offer_site.callables,
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
                and existing.end_line == node_end[0]
                and existing.end_column == node_end[1]
                for existing in function.plugin_claim_rejections
            ):
                function.plugin_claim_rejections.append(
                    PluginClaimRejection(
                        kind=site.kind,
                        diagnostic=diagnostic,
                        end_line=node_end[0],
                        end_column=node_end[1],
                    )
                )
            return True, None
        return False, None

    def _claim(self, plugin_id: str, site: ClaimSite) -> object:
        # Cache key includes 1.2 metadata so keyword/literal/tree differences
        # never share a verdict (determinism contract).
        cache_key = (
            plugin_id,
            site.kind,
            site.target,
            site.operand_types,
            site.operand_literals,
            site.keywords,
            site.expression,
            site.receiver,
            site.callables,
        )
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
            if result.operand_mode == "leaves":
                if not self.provider_is_api_12(plugin_id):
                    raise PluginError(
                        f"plugin {plugin_id!r} claimed site {site.target!r} with "
                        "operand_mode='leaves' but declares plugin-API "
                        f"{'.'.join(str(p) for p in self.provider_api_version(plugin_id))!r}; "
                        "leaves mode requires api_version >= 1.2"
                    )
                if not expression_is_leaves_safe(site.expression):
                    raise PluginError(
                        f"plugin {plugin_id!r} claimed site {site.target!r} with "
                        "operand_mode='leaves' but the expression is not "
                        "leaves-safe (opaque/unsafe leaves, missing tree, or "
                        "unsupported structure); fail closed rather than emit "
                        "incorrect fused code"
                    )
            elif result.operand_mode != "direct":
                # Claimed.__post_init__ already validates the closed set; this
                # is a defensive belt if a non-dataclass Claimed sneaks through.
                raise PluginError(
                    f"plugin {plugin_id!r} claimed site {site.target!r} with "
                    f"unsupported operand_mode {result.operand_mode!r}"
                )
        self._cache[cache_key] = result
        return result


_CORE_RESULT_TYPES = frozenset({"int", "float", "bool", "str", "bytes", "None"})


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
        return type_name[len(prefix) : -1]
    return None


def _node_end(node: ast.AST) -> tuple[int | None, int | None]:
    """Return the node's end (line, column), or (None, None) when absent."""
    return (getattr(node, "end_lineno", None), getattr(node, "end_col_offset", None))
