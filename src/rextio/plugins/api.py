"""Shared record types for the machine-readable tooling contract.

These dataclasses are the L2 "rule record" surface defined by
docs/specs/tooling-contract.md: structured, machine-readable descriptions of
the rules that decide whether code lowers to native. Core emits its own records
(see ``rextio.analyzer.rule_records``); plugin protocol v2 will emit plugin
records through ``describe()``. They live in the plugins package because the
record shape is the contract third-party plugins implement against.

Rule records are deliberately declarative data, not behavior: the analyzer
remains the authority on what actually lowers. A record's ``diagnostic_code``
ties it to the registry in ``rextio.analyzer.diagnostic_codes`` so consumers
can key remediation guidance off the codes that appear in ``rextio check``
output.
"""

from __future__ import annotations

import math
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ClassVar, Protocol, Union

from rextio.analyzer.diagnostics import Diagnostic
from rextio.artifacts.models import ArtifactProfile

if TYPE_CHECKING:
    from rextio.config.schema import RextioConfig

# "binop" and "compare" describe operator lowering surfaces (ClaimSite kinds
# with the same names), so a plugin can label element-wise arithmetic and
# comparison rules accurately instead of presenting them as calls.
RULE_SCOPE_KINDS = frozenset(
    {"type", "syntax", "call", "binop", "compare", "import", "decorator"}
)
RULE_OUTCOMES = frozenset({"native", "fallback", "reject", "shim", "boundary"})
RULE_STABILITY_TIERS = frozenset({"stable", "experimental"})

# The plugin-API version this core implements. SemVer over the protocol
# surface: a v2 plugin declares the api_version it was built against, and the
# loader accepts it when the major version matches. 1.1 added the optional
# lowering members (type_vocabulary/claim/lower/crate_dependencies) from
# docs/specs/plugin-lowering.md. 1.2 adds optional claim-site literal/keyword
# metadata and structured expression trees for fusion-aware lowering. 1.3 adds
# plugin-owned *resident* types (a PluginType with ``conversion=None``): opaque
# Rust values that live only inside generated native code, with no Python
# boundary conversion, enabling native-to-native chaining. 1.3 also finalizes
# three orthogonal static metadata surfaces carried on the claim site:
# method-receiver metadata (:class:`ReceiverMeta`), callable metadata for
# project-function arguments (:class:`CallableMeta` with a closed
# :class:`CallableBody`), and declared-schema metadata (:class:`SchemaMeta`).
# 1.4 adds the optional ``artifact_capability(profile)`` hook: an explicit,
# fail-closed declaration of standalone (boundary-free) Rust artifact support
# for rust-crate and host-executable profiles. The hook is NOT part of the
# all-or-none lowering member set; absence means standalone unsupported.
# 1.5 adds an explicitly version-gated ``compare`` expression claim kind.
# Providers below 1.5 are never offered comparison sites, so an installed
# legacy provider cannot change behavior merely because Core learned the new
# expression vocabulary.
# All additions are optional/defaulted, so 1.1–1.4 providers remain source-
# and behavior-compatible for host-extension builds (major must still match).
PLUGIN_API_VERSION = "1.5"

# Crate dependency pins are exact by decree of the lowering spec: a plugin
# without an exact pin fails to load.
CRATE_PIN_PATTERN = re.compile(r"^=\d+\.\d+\.\d+$")
# Cargo crate names: ASCII alphanumerics, `-` and `_` (crates.io rules).
# Feature names additionally allow `/` and `.` for `dep/feature` and
# `dep?/feature` style entries. Both are rendered as bare/quoted tokens
# into Cargo.toml, so anything outside these sets could break or inject
# TOML (council round 8).
CRATE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
CRATE_FEATURE_PATTERN = re.compile(r"^[A-Za-z0-9_./?-]+$")

# Plugin diagnostic codes are namespaced ``RXTP-<PLUGIN>-NNN`` where <PLUGIN>
# is the plugin's code segment (its id, uppercased, with a leading "rextio-"
# stripped and non-alphanumerics removed): rextio-numpy -> RXTP-NUMPY-001.
PLUGIN_DIAGNOSTIC_CODE_PATTERN = re.compile(r"^RXTP-([A-Z0-9]+)-\d{3}$")


def plugin_code_segment(plugin_id: str) -> str:
    """Return the ``<PLUGIN>`` segment plugin diagnostic codes must carry."""
    stem = plugin_id[len("rextio-") :] if plugin_id.startswith("rextio-") else plugin_id
    segment = re.sub(r"[^A-Z0-9]", "", stem.upper())
    if not segment:
        raise ValueError(
            f"plugin id {plugin_id!r} yields an empty diagnostic-code segment; "
            "plugin ids must contain at least one alphanumeric character "
            "(after the optional 'rextio-' prefix)"
        )
    return segment


@dataclass(frozen=True)
class RuleScope:
    """Where a rule applies: the construct kind and a human-readable pattern."""

    kind: str
    pattern: str

    def __post_init__(self) -> None:
        """Validate the scope kind against the contract's closed set."""
        if self.kind not in RULE_SCOPE_KINDS:
            options = ", ".join(sorted(RULE_SCOPE_KINDS))
            raise ValueError(f"unsupported rule scope kind: {self.kind!r}. Use {options}.")

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this scope."""
        return {"kind": self.kind, "pattern": self.pattern}


@dataclass(frozen=True)
class RuleRecord:
    """A single L2 rule record of the tooling contract.

    Required fields are the L2 tier (mandatory for every provider, including
    third-party plugins). ``fix_template`` and ``examples`` are the optional
    L3 tier — recommended, filled per rule as capacity allows.
    """

    id: str
    provider: str
    scope: RuleScope
    constraint: str
    outcome: str
    # The RXT/RXTP code emitted when the rule fires; None for rules that apply
    # silently (e.g. an accelerator decorator routing a function to fallback
    # without a diagnostic).
    diagnostic_code: str | None
    guidance: str
    stability: str = "stable"
    # Certification status (docs/specs/plugin-lowering.md section 6): True when
    # the rule's lowering passed the plugin certification kit, False when it
    # failed or was skipped, None when certification does not apply (e.g.
    # describe-only rules). Emitted only when set.
    verified: bool | None = None
    fix_template: Mapping[str, str] | None = None
    examples: tuple[Mapping[str, str], ...] = ()

    def __post_init__(self) -> None:
        """Validate the closed-set fields against the contract."""
        if self.outcome not in RULE_OUTCOMES:
            options = ", ".join(sorted(RULE_OUTCOMES))
            raise ValueError(f"unsupported rule outcome: {self.outcome!r}. Use {options}.")
        if self.stability not in RULE_STABILITY_TIERS:
            options = ", ".join(sorted(RULE_STABILITY_TIERS))
            raise ValueError(f"unsupported rule stability: {self.stability!r}. Use {options}.")

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this rule record.

        The optional L3 fields are emitted only when present, so L2-only
        records keep a stable, compact shape.
        """
        data: dict[str, object] = {
            "id": self.id,
            "provider": self.provider,
            "scope": self.scope.to_dict(),
            "constraint": self.constraint,
            "outcome": self.outcome,
            "diagnostic_code": self.diagnostic_code,
            "guidance": self.guidance,
            "stability": self.stability,
        }
        if self.verified is not None:
            data["verified"] = self.verified
        if self.fix_template is not None:
            data["fix_template"] = dict(self.fix_template)
        if self.examples:
            data["examples"] = [dict(example) for example in self.examples]
        return data


@dataclass(frozen=True)
class CoverageDecl:
    """What a plugin can lower: the packages, modules, and symbols it covers.

    ``packages`` drives the ``plugin`` import policy and the RXT091
    plugin-lowerable hint; ``modules`` and ``symbols`` refine coverage for
    future per-call-site decisions and may be empty.
    """

    packages: tuple[str, ...] = ()
    modules: tuple[str, ...] = ()
    symbols: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this coverage."""
        return {
            "packages": list(self.packages),
            "modules": list(self.modules),
            "symbols": list(self.symbols),
        }


@dataclass(frozen=True)
class BoundaryConversion:
    """How a plugin type crosses the Python<->Rust boundary of a PyO3 function.

    Placeholders: ``{param}`` in ``param_expr`` is the PyO3 parameter name;
    ``{value}`` in ``return_expr`` is the native result expression. Arguments
    are read-only borrows and returns transfer ownership of newly allocated
    values (docs/specs/plugin-lowering.md section 4).

    Both expressions are ``str.format`` templates: literal braces in the Rust
    text (closures, struct literals, blocks) must be doubled — ``{{`` and
    ``}}`` — or formatting fails at codegen.
    """

    param_rust: str
    param_expr: str
    return_rust: str
    return_expr: str

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this conversion."""
        return {
            "param_rust": self.param_rust,
            "param_expr": self.param_expr,
            "return_rust": self.return_rust,
            "return_expr": self.return_expr,
        }


@dataclass(frozen=True)
class PluginType:
    """A plugin-provided type the analyzer can resolve from annotations.

    ``annotations`` are the dotted spellings that resolve to this type (the
    plugin's explicit annotation vocabulary); ``rust_type`` is the native
    representation inside generated code. API 1.5 permits ``annotations=()``
    only for a resident type: that is a result-only vocabulary entry produced
    by one claim and consumed by later claims, never a source annotation.

    ``conversion`` describes how the value crosses the Python<->Rust boundary
    of a generated PyO3 function. Two kinds of plugin type exist:

    * **Materialized** (``conversion`` is a :class:`BoundaryConversion`): the
      value has a Python representation and may be a PyO3 parameter/return of an
      exported native function, exactly as in plugin API 1.1/1.2.
    * **Resident** (``conversion is None``, plugin API 1.3): an opaque Rust
      value that is valid ONLY inside generated native code. It has no Python
      boundary conversion, so it never crosses an exported PyO3 boundary; it is
      created by a claimed plugin expression, stored in locals, passed to
      another claimed plugin expression, and passed across accepted native
      helper calls without any Python round-trip. A plugin declaring a resident
      type must advertise ``api_version >= 1.3`` (enforced at load). Omitting
      every annotation spelling additionally requires ``api_version >= 1.5``;
      materialized and older resident types must keep at least one spelling.
    """

    key: str
    annotations: tuple[str, ...]
    rust_type: str
    conversion: BoundaryConversion | None = None
    # Optional exact-text Rust module support this type OWNS (plugin API 1.3).
    # ``uses`` are ``use`` lines and ``helpers`` are module-level items (fn /
    # struct / const) that DEFINE the symbols the type's native representation
    # or boundary conversion references. Type-level ownership is required
    # because a resident type has ``conversion=None`` yet may still use a
    # plugin-owned named Rust type; and a signature-only accepted function
    # (plugin-typed parameter/return, zero claims) renders the type's
    # conversion/struct without ever running ``lower()``. Both are deduplicated
    # by exact text against the module collectors and the same-shaped
    # :class:`LoweredExpr` support (docs/specs/plugin-lowering.md §3, §7).
    uses: tuple[str, ...] = ()
    helpers: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Validate optional module support as tuples of non-empty strings."""
        for label, support in (("uses", self.uses), ("helpers", self.helpers)):
            if not isinstance(support, tuple):
                raise ValueError(f"PluginType.{label} must be a tuple of strings")
            for item in support:
                if not isinstance(item, str) or not item:
                    raise ValueError(f"PluginType.{label} must contain only non-empty strings")

    @property
    def is_resident(self) -> bool:
        """Whether this is a resident type (no Python boundary conversion)."""
        return self.conversion is None

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this type.

        A materialized (1.1/1.2) type with no module support keeps its exact
        legacy byte-shape: no ``resident`` key, no ``uses``/``helpers`` keys,
        and ``conversion`` is the boundary conversion dict. Only a resident
        type (plugin API 1.3) adds ``resident: true`` and a ``conversion:
        null``; an API-1.5 result-only resident type honestly serializes
        ``annotations: []``. Non-empty support is serialized deterministically
        (order-preserving lists) so provider/report/cache identity moves when
        the support changes.
        """
        result: dict[str, object] = {
            "key": self.key,
            "annotations": list(self.annotations),
            "rust_type": self.rust_type,
        }
        # Narrow on the local `conversion` (not the `is_resident` property, which
        # mypy can't use to narrow the field): a None conversion is resident, a
        # concrete one materializes. This branch contains no ``assert``, so the
        # serialization is identical under ``python -O`` (which strips asserts).
        conversion = self.conversion
        if conversion is None:
            result["resident"] = True
            result["conversion"] = None
        else:
            result["conversion"] = conversion.to_dict()
        # Support keys are emitted only when non-empty, so a 1.1/1.2 type keeps
        # its exact pre-1.3 serialized bytes.
        if self.uses:
            result["uses"] = list(self.uses)
        if self.helpers:
            result["helpers"] = list(self.helpers)
        return result


@dataclass(frozen=True)
class ClaimLiteral:
    """Static literal metadata extractable without executing user code.

    Distinguishes four states for a claim-site argument or keyword value:

    * ``is_literal=False`` — not a supported static literal (dynamic name,
      call, unsupported constant shape, …). ``value`` is always ``None``.
    * ``is_literal=True, value=None`` — the Python literal ``None`` (distinct
      from "not a literal").
    * ``is_literal=True, value=<int | tuple[int, ...]>`` — a signed int
      (not ``bool``) or a tuple of signed ints, the API 1.2 shapes needed for
      NumPy ``axis=`` work.
    * ``is_literal=True, value=<bool | str>`` — the additive API 1.3 keyword
      shapes. Core only offers call sites containing these shapes to API 1.3
      providers.

    Floats, bytes, and other constants remain non-literal. Values are never
    produced by executing user code.
    """

    is_literal: bool = False
    value: bool | int | str | None | tuple[int, ...] = None
    # ``True == 1`` in Python. Keep the literal kind in equality/hash keys so
    # API 1.3 bool sites can never collide with legacy integer sites in the
    # deterministic plugin-claim cache. It is derived, not caller-controlled.
    _value_kind: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Validate the literal shape against the closed 1.3 surface."""
        if not self.is_literal:
            if self.value is not None:
                raise ValueError("non-literal ClaimLiteral must have value=None")
            object.__setattr__(self, "_value_kind", "non_literal")
            return
        if self.value is None:
            object.__setattr__(self, "_value_kind", "none")
            return
        if isinstance(self.value, bool):
            object.__setattr__(self, "_value_kind", "bool")
            return
        if isinstance(self.value, int):
            object.__setattr__(self, "_value_kind", "int")
            return
        if isinstance(self.value, str):
            object.__setattr__(self, "_value_kind", "str")
            return
        if isinstance(self.value, tuple):
            for item in self.value:
                if isinstance(item, bool) or not isinstance(item, int):
                    raise ValueError("int_tuple ClaimLiteral values must contain only ints")
            object.__setattr__(self, "_value_kind", "int_tuple")
            return
        raise ValueError(f"unsupported ClaimLiteral value type: {type(self.value).__name__}")

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this literal."""
        if not self.is_literal:
            return {"is_literal": False}
        if self.value is None:
            return {"is_literal": True, "value_kind": "none", "value": None}
        if isinstance(self.value, bool):
            return {"is_literal": True, "value_kind": "bool", "value": self.value}
        if isinstance(self.value, str):
            return {"is_literal": True, "value_kind": "str", "value": self.value}
        if isinstance(self.value, tuple):
            return {
                "is_literal": True,
                "value_kind": "int_tuple",
                "value": list(self.value),
            }
        return {"is_literal": True, "value_kind": "int", "value": self.value}


# Shared non-literal sentinel (immutable); prefer this over constructing a
# fresh ClaimLiteral() at every non-literal site for cache-key stability.
NON_LITERAL = ClaimLiteral()


@dataclass(frozen=True)
class KeywordArg:
    """One ordered keyword argument on a claim site.

    ``name`` is the keyword spelling; ``arg_type`` is the resolved value type
    (plugin type key or core type name, ``None`` when unresolved);
    ``literal`` carries static-literal metadata (see :class:`ClaimLiteral`).
    A missing keyword is simply absent from the site's ``keywords`` tuple —
    that is distinct from a present keyword whose value is literal ``None``.
    """

    name: str
    arg_type: str | None = None
    literal: ClaimLiteral = NON_LITERAL

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this keyword argument."""
        return {
            "name": self.name,
            "arg_type": self.arg_type,
            "literal": self.literal.to_dict(),
        }


# Closed sets for ClaimExpr structural validation (plugin API 1.2).
CLAIM_EXPR_KINDS = frozenset({"leaf", "literal", "call", "binop"})
CLAIM_EXPR_LEAF_KINDS = frozenset({"name", "opaque"})


@dataclass(frozen=True)
class ClaimExpr:
    """Structured expression tree carried from claim through IR to lower.

    ``kind`` is one of:

    * ``"leaf"`` — a non-literal leaf sub-expression. ``leaf_index`` indexes
      into :attr:`LoweringContext.leaf_operands` at lower time.
      ``leaf_kind`` is ``"name"`` for a simple ``ast.Name`` leaf or
      ``"opaque"`` for any other non-literal leaf (subscript, attribute,
      nested structure that could not be expanded safely, …). Fusion
      providers can accept only ``name`` leaves and reject unsafe trees.
    * ``"literal"`` — a supported static literal (see :class:`ClaimLiteral`).
    * ``"call"`` — nested call; ``target`` is the dotted name, ``children``
      are positional args in order, ``keywords`` are ordered keyword args.
    * ``"binop"`` — nested binary op; ``target`` is the operator symbol,
      ``children`` are ``(left, right)``.

    Trees are frozen and ordered so claim-cache keys and ``to_dict`` output
    are deterministic. Core builds the tree only for eligible nested
    call/binop structure; anything it cannot represent safely becomes an
    opaque ``"leaf"`` (fail closed to the pre-1.2 flat site).
    """

    kind: str
    target: str = ""
    result_type: str | None = None
    children: tuple["ClaimExpr", ...] = ()
    keywords: tuple[KeywordArg, ...] = ()
    literal: ClaimLiteral = NON_LITERAL
    leaf_index: int | None = None
    # Only meaningful for kind=="leaf": "name" | "opaque". None on non-leaves.
    leaf_kind: str | None = None

    def __post_init__(self) -> None:
        """Validate closed-set kinds and structural invariants (fail early)."""
        if self.kind not in CLAIM_EXPR_KINDS:
            options = ", ".join(sorted(CLAIM_EXPR_KINDS))
            raise ValueError(f"unsupported ClaimExpr kind: {self.kind!r}. Use {options}.")
        if self.kind == "leaf":
            if self.leaf_index is None or self.leaf_index < 0:
                raise ValueError(
                    f"ClaimExpr leaf requires a non-negative leaf_index, got {self.leaf_index!r}"
                )
            if self.leaf_kind not in CLAIM_EXPR_LEAF_KINDS:
                options = ", ".join(sorted(CLAIM_EXPR_LEAF_KINDS))
                raise ValueError(
                    f"ClaimExpr leaf requires leaf_kind in {{{options}}}, got {self.leaf_kind!r}"
                )
            if self.children:
                raise ValueError("ClaimExpr leaf must not have children")
            if self.keywords:
                raise ValueError("ClaimExpr leaf must not have keywords")
            if self.literal.is_literal:
                raise ValueError("ClaimExpr leaf must not carry a literal; use kind='literal'")
            return
        if self.leaf_kind is not None:
            raise ValueError(
                f"ClaimExpr kind {self.kind!r} must not set leaf_kind (got {self.leaf_kind!r})"
            )
        if self.leaf_index is not None:
            raise ValueError(
                f"ClaimExpr kind {self.kind!r} must not set leaf_index (got {self.leaf_index!r})"
            )
        if self.kind == "literal":
            if not self.literal.is_literal:
                raise ValueError("ClaimExpr literal requires literal.is_literal=True")
            if self.children:
                raise ValueError("ClaimExpr literal must not have children")
            if self.keywords:
                raise ValueError("ClaimExpr literal must not have keywords")
            return
        if self.kind == "binop":
            if len(self.children) != 2:
                raise ValueError(
                    f"ClaimExpr binop requires exactly 2 children, got {len(self.children)}"
                )
            if self.keywords:
                raise ValueError("ClaimExpr binop must not have keywords")
            return
        # kind == "call"
        if self.literal.is_literal:
            raise ValueError("ClaimExpr call must not carry a literal payload")

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this expression node."""
        data: dict[str, object] = {
            "kind": self.kind,
            "target": self.target,
            "result_type": self.result_type,
            "children": [child.to_dict() for child in self.children],
            "keywords": [keyword.to_dict() for keyword in self.keywords],
            "literal": self.literal.to_dict(),
            "leaf_index": self.leaf_index,
            "leaf_kind": self.leaf_kind,
        }
        return data


# ---------------------------------------------------------------------------
# Plugin API 1.3 static metadata surfaces.
#
# Three orthogonal, deterministic, static surfaces for method receivers,
# project-function callable arguments, and declared schemas. Every record is
# frozen (immutable), hashable/cache-safe, order-preserving, and
# JSON-serializable through ``to_dict()``. None of them ever carries raw source
# text, mutable AST nodes, closures/globals, or values produced by executing
# user code — they are derived only from resolved types and a documented static
# grammar. All are attached to :class:`ClaimSite` / :class:`PluginClaim`
# through defaulted fields, so plugin API 1.1/1.2 providers keep the exact
# pre-1.3 serialization shape.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SchemaField:
    """One field of a declared schema: a name plus its resolved static type.

    ``field_type`` is a core scalar type name (``int``/``float``/``bool``/
    ``str``/``bytes``) or a registered plugin type key. It is resolved from the
    static annotation grammar only — never inferred from a runtime object and
    never produced by executing the annotation expression.
    """

    name: str
    field_type: str

    def __post_init__(self) -> None:
        """Reject empty/non-string identities so a schema never carries a blank field."""
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("SchemaField.name must be a non-empty string")
        if not isinstance(self.field_type, str) or not self.field_type:
            raise ValueError(f"SchemaField {self.name!r} must carry a non-empty string field_type")

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this schema field."""
        return {"name": self.name, "field_type": self.field_type}


@dataclass(frozen=True)
class SchemaMeta:
    """An immutable ordered schema identity and its fields (plugin API 1.3).

    ``identity`` is a stable, order-preserving identity string for the schema
    (e.g. the resolved dotted name of the declaring class). ``fields`` are the
    ordered :class:`SchemaField` entries. Field names must be unique — a
    duplicate is a malformed schema and fails closed at construction.
    """

    identity: str
    fields: tuple[SchemaField, ...] = ()

    def __post_init__(self) -> None:
        """Reject duplicate/malformed fields so a claim never sees a bad schema."""
        if not isinstance(self.identity, str) or not self.identity:
            raise ValueError("SchemaMeta.identity must be a non-empty string")
        if not isinstance(self.fields, tuple):
            raise ValueError("SchemaMeta.fields must be a tuple of SchemaField")
        seen: set[str] = set()
        for schema_field in self.fields:
            if not isinstance(schema_field, SchemaField):
                raise ValueError("SchemaMeta.fields must contain SchemaField objects")
            if schema_field.name in seen:
                raise ValueError(f"duplicate schema field name: {schema_field.name!r}")
            seen.add(schema_field.name)

    def field_type(self, name: str) -> str | None:
        """Return the resolved type of a named field, or None when absent."""
        for schema_field in self.fields:
            if schema_field.name == name:
                return schema_field.field_type
        return None

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this schema."""
        return {
            "identity": self.identity,
            "fields": [schema_field.to_dict() for schema_field in self.fields],
        }


# The receiver-expression shape classes core recognizes. Only a plain local
# ``name`` is intrinsically side-effect-free; ``attribute`` (descriptor /
# ``__getattr__``), ``subscript`` (``__getitem__``), ``call``, and ``opaque``
# can all evaluate user code, so core cannot prove them pure.
RECEIVER_EXPR_KINDS = frozenset({"name", "attribute", "subscript", "call", "opaque"})


@dataclass(frozen=True)
class ReceiverMeta:
    """Method-call receiver metadata (plugin API 1.3).

    A method claim site (``obj.method(...)``) distinguishes the receiver from
    the ordinary positional arguments. ``arg_type`` is the receiver's resolved
    type (a plugin type key or core type name, ``None`` when unresolved);
    ``schema`` is its declared :class:`SchemaMeta` when the receiver type
    carries one; ``expr_kind`` classifies the receiver expression shape; and
    ``is_safe`` states whether the receiver is a side-effect-free reference
    that may be referenced without a single-evaluation temporary. Only a plain
    local name is intrinsically safe — an ``attribute`` access can fire a
    descriptor or ``__getattr__``, a ``subscript`` invokes ``__getitem__``, and
    ``call``/``opaque`` shapes evaluate user code — so every non-name receiver
    is unsafe. Codegen always renders the receiver exactly once in Python
    evaluation order regardless — ``is_safe`` only tells a provider whether the
    rendered receiver text is a bare reference or a bound temporary.
    """

    arg_type: str | None
    expr_kind: str
    is_safe: bool
    schema: SchemaMeta | None = None

    def __post_init__(self) -> None:
        """Validate the receiver kind and keep ``is_safe`` consistent with it."""
        if self.arg_type is not None and (not isinstance(self.arg_type, str) or not self.arg_type):
            raise ValueError("ReceiverMeta.arg_type must be a non-empty string or None")
        if not isinstance(self.expr_kind, str) or self.expr_kind not in RECEIVER_EXPR_KINDS:
            options = ", ".join(sorted(RECEIVER_EXPR_KINDS))
            raise ValueError(
                f"unsupported ReceiverMeta expr_kind: {self.expr_kind!r}. Use {options}."
            )
        if not isinstance(self.is_safe, bool):
            raise ValueError("ReceiverMeta.is_safe must be a bool")
        if self.schema is not None and not isinstance(self.schema, SchemaMeta):
            raise ValueError("ReceiverMeta.schema must be a SchemaMeta or None")
        # ``is_safe`` is not an independent flag: only a plain local ``name`` is
        # intrinsically side-effect-free, and every other shape is unsafe. A
        # payload that claims otherwise (a safe subscript, an unsafe name) is
        # contradictory and would make two cache keys disagree about the same
        # receiver, so reject it here rather than trust the flag.
        if self.is_safe != (self.expr_kind == "name"):
            raise ValueError(
                f"ReceiverMeta.is_safe must be {self.expr_kind == 'name'!r} for "
                f"expr_kind {self.expr_kind!r} (only a plain name is safe)"
            )

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this receiver metadata."""
        return {
            "arg_type": self.arg_type,
            "expr_kind": self.expr_kind,
            "is_safe": self.is_safe,
            "schema": self.schema.to_dict() if self.schema is not None else None,
        }


# Closed sets for the safe scalar/row-UDF callable body representation.
CALLABLE_BODY_KINDS = frozenset(
    {
        "param",
        "literal",
        "field",
        "subscript",
        "unary",
        "binop",
        "boolop",
        "compare",
        "cond",
        "call",
    }
)
CALLABLE_UNARY_OPS = frozenset({"-", "+", "~", "not"})
CALLABLE_BINOPS = frozenset({"+", "-", "*", "/", "%", "//", "**", "@", "&", "|", "^", "<<", ">>"})
CALLABLE_BOOLOPS = frozenset({"and", "or"})
CALLABLE_COMPARE_OPS = frozenset({"==", "!=", "<", "<=", ">", ">=", "is", "is not", "in", "not in"})
SCALAR_LITERAL_KINDS = frozenset({"int", "float", "bool", "str", "none"})

# Python ``int`` lowers to Rust ``i64``; a scalar literal outside this range has
# no ``i64`` representation, so it fails closed at construction just as the
# extractor rejects an out-of-range body literal.
_SCALAR_I64_MIN = -(2**63)
_SCALAR_I64_MAX = 2**63 - 1


@dataclass(frozen=True)
class ScalarLiteral:
    """A supported static scalar literal inside a closed callable body.

    ``kind`` is one of :data:`SCALAR_LITERAL_KINDS`; ``value`` is the hashable,
    JSON-serializable Python scalar (``None`` for ``kind="none"``). Values are
    read from AST constants without executing user code. bytes and other
    constant shapes are unsupported and make the body unavailable (fail
    closed).
    """

    kind: str
    value: int | float | bool | str | None = None

    def __post_init__(self) -> None:
        """Validate the literal kind matches its value's Python type."""
        if self.kind not in SCALAR_LITERAL_KINDS:
            options = ", ".join(sorted(SCALAR_LITERAL_KINDS))
            raise ValueError(f"unsupported ScalarLiteral kind: {self.kind!r}. Use {options}.")
        if self.kind == "none":
            if self.value is not None:
                raise ValueError("ScalarLiteral kind='none' must have value=None")
            return
        if self.kind == "bool":
            if not isinstance(self.value, bool):
                raise ValueError("ScalarLiteral kind='bool' requires a bool value")
            return
        # bool is an int subclass; guard it out of the int/float branches.
        if self.kind == "int":
            if not isinstance(self.value, int) or isinstance(self.value, bool):
                raise ValueError("ScalarLiteral kind='int' requires a non-bool int value")
            if not (_SCALAR_I64_MIN <= self.value <= _SCALAR_I64_MAX):
                # The extractor/core cannot lower an int outside i64, so a literal
                # such as ``ScalarLiteral("int", 2**63)`` must fail at construction
                # rather than serialize a value no Rust ``i64`` can hold.
                raise ValueError(
                    "ScalarLiteral kind='int' value is outside the supported i64 range"
                )
            return
        if self.kind == "float":
            if not isinstance(self.value, float):
                raise ValueError("ScalarLiteral kind='float' requires a float value")
            # NaN/inf have no JSON representation (json.dumps emits the invalid
            # tokens NaN/Infinity) and NaN breaks equality-based cache/hash keys
            # (NaN != NaN), so a non-finite float literal fails closed here.
            if not math.isfinite(self.value):
                raise ValueError(
                    "ScalarLiteral kind='float' requires a finite value (NaN/inf are not JSON-safe)"
                )
            return
        if not isinstance(self.value, str):  # kind == "str"
            raise ValueError("ScalarLiteral kind='str' requires a str value")

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this scalar literal."""
        return {"kind": self.kind, "value": self.value}


@dataclass(frozen=True)
class CallableBodyExpr:
    """One node of the closed scalar/row-UDF body representation (plugin API 1.3).

    A deliberately small, closed grammar — the only shapes that can be made
    stable and safe for an initial scalar/simple-row UDF. ``kind`` is one of
    :data:`CALLABLE_BODY_KINDS`:

    * ``"param"`` — a parameter read; ``param_index`` positions it, ``name`` is
      its spelling.
    * ``"literal"`` — a :class:`ScalarLiteral`.
    * ``"field"`` — a schema-bound field read on ``children[0]`` (a row param);
      ``name`` is the field name.
    * ``"subscript"`` — a schema-bound subscript read (``row["col"]``) on
      ``children[0]``; ``name`` is the resolved string key.
    * ``"unary"`` — ``op`` in :data:`CALLABLE_UNARY_OPS` over ``children[0]``.
    * ``"binop"`` — ``op`` in :data:`CALLABLE_BINOPS` over ``children`` (2).
    * ``"boolop"`` — ``op`` in :data:`CALLABLE_BOOLOPS` over ``children`` (>=2).
    * ``"compare"`` — ``ops`` (each in :data:`CALLABLE_COMPARE_OPS`) over
      ``children`` (len == len(ops)+1).
    * ``"cond"`` — conditional expression; ``children`` are (test, body, orelse).
    * ``"call"`` — an already-supported pure scalar call; ``target`` is the
      dotted name, ``children`` are positional args.

    ``result_type`` is the node's resolved scalar type when known. Trees are
    frozen and ordered so cache keys and ``to_dict`` output are deterministic.
    """

    kind: str
    result_type: str | None = None
    name: str = ""
    op: str = ""
    ops: tuple[str, ...] = ()
    target: str = ""
    param_index: int | None = None
    literal: ScalarLiteral | None = None
    children: tuple["CallableBodyExpr", ...] = ()

    # Per kind, the structural payload fields that carry meaning. Every other
    # field must stay at its default so two nodes that are semantically identical
    # never differ by an irrelevant payload (which would split their cache keys).
    _RELEVANT_FIELDS: ClassVar[dict[str, frozenset[str]]] = {
        "param": frozenset({"param_index", "name"}),
        "literal": frozenset({"literal"}),
        "field": frozenset({"name", "children"}),
        "subscript": frozenset({"name", "children"}),
        "unary": frozenset({"op", "children"}),
        "binop": frozenset({"op", "children"}),
        "boolop": frozenset({"op", "children"}),
        "compare": frozenset({"ops", "children"}),
        "cond": frozenset({"children"}),
        "call": frozenset({"target", "children"}),
    }

    def __post_init__(self) -> None:
        """Validate the closed grammar so a body never carries an unsafe shape."""
        if self.kind not in CALLABLE_BODY_KINDS:
            options = ", ".join(sorted(CALLABLE_BODY_KINDS))
            raise ValueError(f"unsupported CallableBodyExpr kind: {self.kind!r}. Use {options}.")
        # Container members must be immutable tuples of the declared member type
        # (a list would construct fine but make ``hash(record)`` raise later with
        # an unhashable-list TypeError, silently breaking every cache/dedup key).
        if not isinstance(self.ops, tuple):
            raise ValueError("CallableBodyExpr.ops must be a tuple")
        if not isinstance(self.children, tuple) or any(
            not isinstance(child, CallableBodyExpr) for child in self.children
        ):
            raise ValueError("CallableBodyExpr.children must be a tuple of CallableBodyExpr")
        if self.param_index is not None and (
            isinstance(self.param_index, bool) or not isinstance(self.param_index, int)
        ):
            raise ValueError("CallableBodyExpr.param_index must be a non-bool int or None")
        # Every string-typed field must carry an ACTUAL string (a truthy non-string
        # such as ``result_type=5`` must not slip through the non-empty checks and
        # split cache keys or break serialization). ``result_type`` is a non-empty
        # string or ``None``; ``name``/``op``/``target`` are strings (their
        # per-kind non-empty requirements are checked below); ``ops`` holds only
        # non-empty strings.
        if self.result_type is not None and (
            not isinstance(self.result_type, str) or not self.result_type
        ):
            raise ValueError("CallableBodyExpr.result_type must be a non-empty string or None")
        for attr in ("name", "op", "target"):
            if not isinstance(getattr(self, attr), str):
                raise ValueError(f"CallableBodyExpr.{attr} must be a string")
        if any(not isinstance(op, str) or not op for op in self.ops):
            raise ValueError("CallableBodyExpr.ops must contain only non-empty strings")
        if self.kind == "param":
            if self.param_index is None or self.param_index < 0:
                raise ValueError("CallableBodyExpr param requires a non-negative param_index")
            if not self.name:
                raise ValueError("CallableBodyExpr param requires a non-empty name")
        elif self.kind == "literal":
            if self.literal is None:
                raise ValueError("CallableBodyExpr literal requires a ScalarLiteral")
        elif self.kind in {"field", "subscript"}:
            if not self.name or len(self.children) != 1:
                raise ValueError(f"CallableBodyExpr {self.kind} requires a name and one child")
        elif self.kind == "unary":
            if self.op not in CALLABLE_UNARY_OPS or len(self.children) != 1:
                raise ValueError("CallableBodyExpr unary requires a unary op and one child")
        elif self.kind == "binop":
            if self.op not in CALLABLE_BINOPS or len(self.children) != 2:
                raise ValueError("CallableBodyExpr binop requires a binary op and two children")
        elif self.kind == "boolop":
            if self.op not in CALLABLE_BOOLOPS or len(self.children) < 2:
                raise ValueError("CallableBodyExpr boolop requires a bool op and >=2 children")
        elif self.kind == "compare":
            if not self.ops or any(op not in CALLABLE_COMPARE_OPS for op in self.ops):
                raise ValueError("CallableBodyExpr compare requires ops from the closed set")
            if len(self.children) != len(self.ops) + 1:
                raise ValueError("CallableBodyExpr compare needs len(children) == len(ops)+1")
        elif self.kind == "cond":
            if len(self.children) != 3:
                raise ValueError("CallableBodyExpr cond requires (test, body, orelse) children")
        else:  # kind == "call"
            if not self.target:
                raise ValueError("CallableBodyExpr call requires a dotted target")
        # Reject any structural payload irrelevant to this kind so cache keys are
        # canonical (a "binop" that also carried a stray ``name`` or ``literal``
        # would key differently from an otherwise-identical binop).
        relevant = self._RELEVANT_FIELDS[self.kind]
        irrelevant = {
            "name": bool(self.name),
            "op": bool(self.op),
            "ops": bool(self.ops),
            "target": bool(self.target),
            "param_index": self.param_index is not None,
            "literal": self.literal is not None,
            "children": bool(self.children),
        }
        for name, is_set in irrelevant.items():
            if is_set and name not in relevant:
                raise ValueError(
                    f"CallableBodyExpr {self.kind!r} must not carry a {name!r} payload"
                )

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this body node."""
        return {
            "kind": self.kind,
            "result_type": self.result_type,
            "name": self.name,
            "op": self.op,
            "ops": list(self.ops),
            "target": self.target,
            "param_index": self.param_index,
            "literal": self.literal.to_dict() if self.literal is not None else None,
            "children": [child.to_dict() for child in self.children],
        }


@dataclass(frozen=True)
class CallableBody:
    """The closed body representation of a callable, or its unavailability.

    * ``available=True`` — ``expression`` is a closed :class:`CallableBodyExpr`
      the plugin may lower as a scalar/row UDF.
    * ``available=False`` — ``unavailable_reason`` explains why no safe closed
      representation exists (unsupported statement, mutation, loop,
      comprehension, closure, dynamic default, varargs, async/generator, …);
      ``expression`` is ``None``. Claims that need a body MUST fail closed on
      an unavailable body rather than guess.
    """

    available: bool = False
    unavailable_reason: str | None = None
    expression: CallableBodyExpr | None = None

    def __post_init__(self) -> None:
        """Keep the availability flag and the expression consistent."""
        if not isinstance(self.available, bool):
            raise ValueError("CallableBody.available must be a bool")
        # ``unavailable_reason`` is the shared no-reason sentinel ``None`` or an
        # actual non-empty string — a truthy non-string (``5``, a dict) or an
        # empty string is not a canonical reason and must fail closed.
        if self.unavailable_reason is not None and (
            not isinstance(self.unavailable_reason, str) or not self.unavailable_reason
        ):
            raise ValueError("CallableBody.unavailable_reason must be a non-empty string or None")
        if self.expression is not None and not isinstance(self.expression, CallableBodyExpr):
            raise ValueError("CallableBody.expression must be a CallableBodyExpr or None")
        if self.available:
            if self.expression is None:
                raise ValueError("an available CallableBody must carry an expression")
            # An available body is representable, so it cannot also carry a
            # reason it is unavailable — a contradictory payload.
            if self.unavailable_reason is not None:
                raise ValueError("an available CallableBody must not carry an unavailable_reason")
        elif self.expression is not None:
            raise ValueError("an unavailable CallableBody must not carry an expression")

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this callable body."""
        return {
            "available": self.available,
            "unavailable_reason": self.unavailable_reason,
            "expression": self.expression.to_dict() if self.expression is not None else None,
        }


# Shared "no closed body" sentinel; immutable, so it is a stable default and
# cache-key element rather than a fresh instance per unavailable callable.
UNAVAILABLE_CALLABLE_BODY = CallableBody()


@dataclass(frozen=True)
class CallableParam:
    """One ordered parameter of a resolved callable: name plus resolved type."""

    name: str
    param_type: str | None = None

    def __post_init__(self) -> None:
        """Reject an empty or non-string parameter name/type (canonical-form invariant)."""
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("CallableParam.name must be a non-empty string")
        if self.param_type is not None and (
            not isinstance(self.param_type, str) or not self.param_type
        ):
            raise ValueError(
                f"CallableParam {self.name!r} param_type must be a non-empty string or None"
            )

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this callable parameter."""
        return {"name": self.name, "param_type": self.param_type}


@dataclass(frozen=True)
class CallableMeta:
    """Immutable metadata for a callable argument resolving to a project function.

    Exposed for callable arguments (e.g. a UDF passed to a method) that resolve
    to a project function. Never exposes raw source, mutable AST, closures, or
    executed Python objects — only resolved, static facts:

    * ``arg_index`` — the callable argument's positional index at the site.
    * ``qualname`` — the resolved project-function qualname.
    * ``params`` — ordered typed :class:`CallableParam` signature.
    * ``return_type`` — resolved return type (``None`` when unresolved).
    * ``accepts_native`` — True when the function is a proven accepted scalar
      native function (a direct native-callable UDF).
    * ``runtime_semantics`` — True when it carries the RXT080 runtime-shim
      semantics (documented CPython-divergence shim).
    * ``native_symbol`` — the codegen-resolved native Rust symbol when one
      exists (filled at lower time; ``None`` at claim time).
    * ``body`` — the closed :class:`CallableBody` for the safe scalar/row UDF
      subset, or an explicitly unavailable body (fail closed).
    * ``keyword`` — the keyword name when this callable was passed as a keyword
      argument (``obj.method(func=udf)``); empty for a positional callable. It
      names a keyword callable unambiguously, because a keyword's ``arg_index``
      is a synthetic slot after the positional arguments. Defaulted/omitted-when-
      empty so a positional-callable site keeps its exact pre-keyword shape.
    """

    arg_index: int
    qualname: str
    params: tuple[CallableParam, ...] = ()
    return_type: str | None = None
    accepts_native: bool = False
    runtime_semantics: bool = False
    native_symbol: str | None = None
    body: CallableBody = UNAVAILABLE_CALLABLE_BODY
    keyword: str = ""

    def __post_init__(self) -> None:
        """Enforce the canonical-form invariants so cache/hash keys stay unambiguous."""
        if isinstance(self.arg_index, bool) or not isinstance(self.arg_index, int):
            raise ValueError("CallableMeta.arg_index must be a non-bool int")
        if self.arg_index < 0:
            raise ValueError(f"CallableMeta.arg_index must be non-negative, got {self.arg_index}")
        if not isinstance(self.qualname, str) or not self.qualname:
            raise ValueError("CallableMeta.qualname must be a non-empty string")
        if not isinstance(self.keyword, str):
            raise ValueError("CallableMeta.keyword must be a string ('' for a positional callable)")
        # Container/member and flag types (a list ``params`` or a truthy non-bool
        # flag would construct but break ``hash(record)`` or split cache keys).
        if not isinstance(self.params, tuple) or any(
            not isinstance(param, CallableParam) for param in self.params
        ):
            raise ValueError("CallableMeta.params must be a tuple of CallableParam")
        if not isinstance(self.accepts_native, bool) or not isinstance(
            self.runtime_semantics, bool
        ):
            raise ValueError("CallableMeta.accepts_native/runtime_semantics must be bools")
        if not isinstance(self.body, CallableBody):
            raise ValueError("CallableMeta.body must be a CallableBody")
        seen: set[str] = set()
        for param in self.params:
            if param.name in seen:
                raise ValueError(
                    f"CallableMeta {self.qualname!r} has duplicate parameter {param.name!r}"
                )
            seen.add(param.name)
        if self.return_type is not None and (
            not isinstance(self.return_type, str) or not self.return_type
        ):
            raise ValueError("CallableMeta.return_type must be a non-empty string or None")
        if self.native_symbol is not None:
            if not isinstance(self.native_symbol, str) or not self.native_symbol:
                raise ValueError("CallableMeta.native_symbol must be a non-empty string or None")
            # A native symbol only exists for an actually-generated accepted
            # native helper; carrying one without accepts_native is a
            # contradictory payload that would make a cache key ambiguous.
            if not self.accepts_native:
                raise ValueError(
                    f"CallableMeta {self.qualname!r} carries native_symbol "
                    f"{self.native_symbol!r} but is not accepts_native"
                )

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this callable metadata.

        ``keyword`` is emitted only for a keyword callable, so a positional
        callable keeps its exact pre-keyword serialization shape.
        """
        data: dict[str, object] = {
            "arg_index": self.arg_index,
            "qualname": self.qualname,
            "params": [param.to_dict() for param in self.params],
            "return_type": self.return_type,
            "accepts_native": self.accepts_native,
            "runtime_semantics": self.runtime_semantics,
            "native_symbol": self.native_symbol,
            "body": self.body.to_dict(),
        }
        if self.keyword:
            data["keyword"] = self.keyword
        return data


@dataclass(frozen=True)
class ClaimSite:
    """One candidate construct offered to a plugin's ``claim`` or ``lower``.

    ``kind`` is ``call`` (dotted call target in ``target``), ``binop``
    (operator token in ``target``), or API-1.5 ``compare`` (one non-chained
    comparison operator token in ``target``). ``operand_types`` are the
    resolved operand or argument types in positional order (plugin type keys
    or core type names, ``None`` when unresolved).

    At ``claim()`` time ``rule_id``/``result_type`` are ``None`` (the claim
    has not happened yet). At ``lower()`` time core fills them with the
    plugin's own claimed values, so a plugin with several same-shape rules
    can dispatch its lowering deterministically by ``rule_id`` (council
    round 7 — previously lower() had to re-infer the rule from
    target/operands).

    Plugin API 1.2 additions (all optional / defaulted for 1.1 compatibility):

    * ``operand_literals`` — per-positional :class:`ClaimLiteral` metadata
      aligned with ``operand_types``.
    * ``keywords`` — ordered keyword arguments (calls only; empty for binops).
    * ``expression`` — structured :class:`ClaimExpr` tree for the site, when
      core can represent the nested eligible call/binop structure safely.
    """

    kind: str
    target: str
    operand_types: tuple[str | None, ...]
    file_path: str
    line: int
    column: int
    rule_id: str | None = None
    result_type: str | None = None
    operand_literals: tuple[ClaimLiteral, ...] = ()
    keywords: tuple[KeywordArg, ...] = ()
    expression: ClaimExpr | None = None
    # Plugin API 1.3 static metadata (defaults keep the 1.1/1.2 site shape):
    #   * ``receiver`` — method-call receiver metadata (None for plain calls
    #     and binops).
    #   * ``callables`` — ordered :class:`CallableMeta` for callable arguments
    #     that resolve to project functions (empty when the site has none).
    receiver: ReceiverMeta | None = None
    callables: tuple[CallableMeta, ...] = ()

    def __post_init__(self) -> None:
        """Reject duplicate callable arg indexes so the site's cache key is unambiguous."""
        seen: set[int] = set()
        for callable_meta in self.callables:
            if callable_meta.arg_index in seen:
                raise ValueError(
                    f"ClaimSite carries multiple callables at arg_index {callable_meta.arg_index}"
                )
            seen.add(callable_meta.arg_index)

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this site.

        Plugin API 1.2/1.3 keys are omitted when empty/None so a site built
        with only legacy 1.1 fields keeps the exact pre-1.2 dict shape.
        """
        data: dict[str, object] = {
            "kind": self.kind,
            "target": self.target,
            "operand_types": list(self.operand_types),
            "file_path": self.file_path,
            "line": self.line,
            "column": self.column,
        }
        if self.rule_id is not None:
            data["rule_id"] = self.rule_id
        if self.result_type is not None:
            data["result_type"] = self.result_type
        if self.operand_literals:
            data["operand_literals"] = [lit.to_dict() for lit in self.operand_literals]
        if self.keywords:
            data["keywords"] = [keyword.to_dict() for keyword in self.keywords]
        if self.expression is not None:
            data["expression"] = self.expression.to_dict()
        if self.receiver is not None:
            data["receiver"] = self.receiver.to_dict()
        if self.callables:
            data["callables"] = [callable_meta.to_dict() for callable_meta in self.callables]
        return data


# Closed set for Claimed.operand_mode (plugin API 1.2).
OPERAND_MODES = frozenset({"direct", "leaves"})


@dataclass(frozen=True)
class Claimed:
    """The plugin will lower this site under the given rule.

    ``result_type`` is the expression type the claimed site produces. It must
    be a non-``None`` known core type name or a registered plugin type key so
    the analyzer can type the enclosing expression. Analysis **rejects**
    ``None`` and unknown types with :class:`~rextio.plugins.loader.PluginError`.
    See docs/specs/plugin-lowering.md section 2.

    Plugin API 1.2: ``operand_mode`` selects how codegen feeds
    :class:`LoweringContext`:

    * ``"direct"`` (default, 1.1-compatible) — render classic direct child
      operands into ``ctx.operands``; ``ctx.leaf_operands`` is empty.
    * ``"leaves"`` — render only non-literal leaves of ``ClaimSite.expression``
      into ``ctx.leaf_operands`` (by ``leaf_index``); ``ctx.operands`` is empty.
      Requires ``api_version >= 1.2`` and a leaves-safe expression tree
      (name leaves / literals / binops only; no opaque leaves). Invalid
      leaves claims fail closed with PluginError.
    """

    rule_id: str
    # REQUIRED for expression claims (the engine raises PluginError on None);
    # no default so the omission fails at construction (council round 7).
    result_type: str | None
    operand_mode: str = "direct"

    def __post_init__(self) -> None:
        """Validate operand_mode against the closed set."""
        if self.operand_mode not in OPERAND_MODES:
            options = ", ".join(sorted(OPERAND_MODES))
            raise ValueError(
                f"unsupported Claimed.operand_mode: {self.operand_mode!r}. Use {options}."
            )


@dataclass(frozen=True)
class NotCovered:
    """The site is not this plugin's business; core proceeds as usual."""


@dataclass(frozen=True)
class Rejected:
    """The site is covered but not lowerable; the diagnostic explains why."""

    diagnostic: Diagnostic


ClaimResult = Union[Claimed, NotCovered, Rejected]


@dataclass(frozen=True)
class LoweredExpr:
    """A plugin-lowered expression: one Rust expression plus its support items.

    ``rust`` is a single expression with no trailing semicolon; core owns
    statements, control flow, and temporaries. ``uses`` are deduplicated
    ``use`` lines; ``helpers`` are module-level items deduplicated by exact
    text.
    """

    rust: str
    uses: tuple[str, ...] = ()
    helpers: tuple[str, ...] = ()


# Closed backend identifiers for plugin API 1.4 LoweringContext.backend.
# Host-extension PyO3 builds use ``pyo3``; boundary-free rust-crate and
# host-executable builds use ``standalone-rust``.
LOWERING_BACKEND_PYO3 = "pyo3"
LOWERING_BACKEND_STANDALONE_RUST = "standalone-rust"
LOWERING_BACKENDS = frozenset({LOWERING_BACKEND_PYO3, LOWERING_BACKEND_STANDALONE_RUST})


@dataclass(frozen=True)
class LoweringContext:
    """The codegen-side context handed to a plugin's ``lower()``.

    ``operands`` are the rendered Rust sub-expressions of the claimed site's
    operands/arguments in positional order (already lowered by core or by
    prior plugin claims); ``target_language`` names the active codegen language
    (``"rust"``); ``fresh_name`` allocates a fresh temporary identifier in the
    enclosing function's namespace from a given prefix.

    Plugin API 1.2 addition (defaulted for 1.1 compatibility):

    * ``leaf_operands`` — rendered Rust sub-expressions for non-literal
      leaves of :attr:`ClaimSite.expression`, in left-to-right
      ``leaf_index`` order. Empty when the site has no structured expression
      or only literal leaves. Fusion-aware providers use these to emit one
      helper call without intermediate plugin array results; 1.1 providers
      keep using ``operands`` unchanged.
    """

    operands: tuple[str, ...]
    target_language: str
    fresh_name: Callable[[str], str]
    leaf_operands: tuple[str, ...] = ()
    # Plugin API 1.3 addition (defaulted for 1.1/1.2 compatibility): the
    # rendered Rust sub-expression for a method claim site's receiver, already
    # evaluated by core exactly once in Python evaluation order (a bare
    # reference when the receiver is safe, otherwise a bound single-use
    # temporary). None for plain calls and binops.
    receiver: str | None = None
    # Plugin API 1.4 addition (defaulted for 1.1–1.3 host-extension
    # compatibility). ``backend`` is a closed identifier distinguishing the
    # PyO3 host-extension path from boundary-free standalone Rust emission.
    # ``artifact_profile`` is the exact resolved ArtifactProfile used for
    # authorization on standalone lowers; None for host-extension builds.
    # Old construction that omits both fields remains valid (pyo3 / None).
    backend: str = LOWERING_BACKEND_PYO3
    artifact_profile: ArtifactProfile | None = None

    def __post_init__(self) -> None:
        """Validate the closed backend set for API 1.4 fields."""
        if self.backend not in LOWERING_BACKENDS:
            options = ", ".join(sorted(LOWERING_BACKENDS))
            raise ValueError(
                f"unsupported LoweringContext.backend: {self.backend!r}. Use {options}."
            )
        if self.backend == LOWERING_BACKEND_STANDALONE_RUST and self.artifact_profile is None:
            raise ValueError(
                "LoweringContext.artifact_profile is required when backend is "
                f"{LOWERING_BACKEND_STANDALONE_RUST!r}"
            )


@dataclass(frozen=True)
class CrateDependency:
    """A crate a plugin's generated code depends on, with a mandatory exact pin."""

    name: str
    version: str
    features: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Validate the crate name, exact version pin (``=X.Y.Z``), and features."""
        if CRATE_NAME_PATTERN.match(self.name) is None:
            raise ValueError(
                f"crate dependency name {self.name!r} is not a valid Cargo crate "
                "name (ASCII letters, digits, '-' and '_' only)"
            )
        if CRATE_PIN_PATTERN.match(self.version) is None:
            raise ValueError(
                f"crate dependency {self.name!r} must carry an exact version pin "
                f"(=X.Y.Z), got {self.version!r}"
            )
        for feature in self.features:
            if CRATE_FEATURE_PATTERN.match(feature) is None:
                raise ValueError(
                    f"crate dependency {self.name!r} declares an invalid feature name {feature!r}"
                )

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this dependency."""
        return {
            "name": self.name,
            "version": self.version,
            "features": list(self.features),
        }


@dataclass(frozen=True)
class PluginArtifactTypeSupport:
    """Profile-specific native module support for one exact plugin type key.

    Declared only through
    :meth:`RextioArtifactCapabilityPlugin.artifact_capability` (plugin API
    1.4). Never inferred from :class:`PluginType` conversion, resident status,
    host-extension ``uses``/``helpers``, or ``crate_dependencies()``.
    """

    type_key: str
    uses: tuple[str, ...] = ()
    helpers: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Validate the type key and support item shapes."""
        if not isinstance(self.type_key, str) or not self.type_key:
            raise ValueError("PluginArtifactTypeSupport.type_key must be a non-empty string")
        for label, support in (("uses", self.uses), ("helpers", self.helpers)):
            if not isinstance(support, tuple):
                raise ValueError(f"PluginArtifactTypeSupport.{label} must be a tuple of strings")
            for item in support:
                if not isinstance(item, str) or not item:
                    raise ValueError(
                        f"PluginArtifactTypeSupport.{label} must contain only non-empty strings"
                    )

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable form of this type support."""
        data: dict[str, object] = {"type_key": self.type_key}
        if self.uses:
            data["uses"] = list(self.uses)
        if self.helpers:
            data["helpers"] = list(self.helpers)
        return data


@dataclass(frozen=True)
class PluginArtifactCapability:
    """Explicit fail-closed standalone support for one exact :class:`ArtifactProfile`.

    Returned from ``artifact_capability(profile)``. ``None`` (or a missing hook)
    means the plugin does **not** support that standalone profile. Coverage is
    exact: claim rule ids and type keys used by a function must all appear
    here, and only the declared crate dependencies / uses / helpers may be
    injected for that profile.
    """

    rule_ids: tuple[str, ...] = ()
    types: tuple[PluginArtifactTypeSupport, ...] = ()
    crate_dependencies: tuple[CrateDependency, ...] = ()

    def __post_init__(self) -> None:
        """Validate container shapes; namespace ownership is checked by the resolver."""
        if not isinstance(self.rule_ids, tuple) or not all(
            isinstance(rule_id, str) and rule_id for rule_id in self.rule_ids
        ):
            raise ValueError("PluginArtifactCapability.rule_ids must be a tuple of non-empty strings")
        if not isinstance(self.types, tuple) or not all(
            isinstance(item, PluginArtifactTypeSupport) for item in self.types
        ):
            raise ValueError(
                "PluginArtifactCapability.types must be a tuple of PluginArtifactTypeSupport"
            )
        if not isinstance(self.crate_dependencies, tuple) or not all(
            isinstance(item, CrateDependency) for item in self.crate_dependencies
        ):
            raise ValueError(
                "PluginArtifactCapability.crate_dependencies must be a tuple of CrateDependency"
            )

    def type_keys(self) -> frozenset[str]:
        """Return the set of exact type keys covered by this capability."""
        return frozenset(item.type_key for item in self.types)

    def allowed_uses(self) -> frozenset[str]:
        """Return the union of all profile-declared ``use`` lines."""
        return frozenset(use for item in self.types for use in item.uses)

    def allowed_helpers(self) -> frozenset[str]:
        """Return the union of all profile-declared helper items."""
        return frozenset(helper for item in self.types for helper in item.helpers)

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable form of this capability."""
        return {
            "rule_ids": list(self.rule_ids),
            "types": [item.to_dict() for item in self.types],
            "crate_dependencies": [dep.to_dict() for dep in self.crate_dependencies],
        }


class RextioPluginV2(Protocol):
    """The self-describing plugin protocol (tooling contract, protocol v2).

    A v2 plugin entry point returns an object that provides the v1 metadata
    (a ``to_rextio_plugin()`` method returning :class:`RextioPlugin`, or an
    equivalent metadata mapping) **plus** the members below. The loader
    recognizes v2 by the presence of a callable ``describe``. Metadata-only
    (v1) plugins keep loading unchanged and simply provide no rules.

    Rule records are declarative descriptions; the lowering hooks live on the
    :class:`RextioLoweringPlugin` extension (plugin API 1.1). The analyzer
    remains the authority on which sites are offered and accepted.
    """

    plugin_id: str
    api_version: str

    def covers(self) -> CoverageDecl:
        """Return the coverage declaration for this plugin."""
        ...

    def describe(self, config: RextioConfig) -> tuple[RuleRecord, ...]:
        """Return this plugin's rule records for the resolved configuration."""
        ...


class RextioLoweringPlugin(RextioPluginV2, Protocol):
    """A protocol-v2 plugin that also lowers code (plugin API 1.1).

    All four members below arrive together: the loader rejects a plugin that
    implements ``claim`` without ``lower`` or vice versa, and lowering
    requires the v2 base (``describe``/``covers``). The claim decision MUST
    be deterministic — identical (site, config) inputs always produce the
    identical result; core may cache it across analysis and codegen
    (docs/specs/plugin-lowering.md section 2).
    """

    def type_vocabulary(self) -> tuple[PluginType, ...]:
        """Return the annotation vocabulary this plugin adds to the analyzer."""
        ...

    def claim(self, site: ClaimSite, config: RextioConfig) -> ClaimResult:
        """Decide, at analysis time, whether this plugin lowers the site."""
        ...

    def lower(self, claimed: ClaimSite, ctx: object) -> LoweredExpr:
        """Emit the Rust expression for a previously claimed site.

        ``ctx`` is the codegen-side :class:`LoweringContext`: rendered operand
        sub-expressions in positional order, the target language, and
        fresh-name allocation. (Typed ``object`` here so 1.1 providers with
        looser annotations keep matching the protocol structurally.)
        """
        ...

    def crate_dependencies(self) -> tuple[CrateDependency, ...]:
        """Return the pinned crates this plugin's generated code depends on."""
        ...


class RextioArtifactCapabilityPlugin(Protocol):
    """Optional plugin API 1.4 extension for standalone artifact capability.

    Deliberately **separate** from :class:`RextioLoweringPlugin` so a concrete
    class that inherits the legacy lowering Protocol does not inherit a
    callable ``artifact_capability`` stub. Presence is detected by a concrete
    (non-Protocol) implementation on the provider; the hook is not part of the
    all-or-none lowering set.
    """

    def artifact_capability(
        self, profile: ArtifactProfile
    ) -> PluginArtifactCapability | None:
        """Declare standalone (boundary-free) support for an exact artifact profile.

        Plugin API **1.4** optional hook. Presence requires ``api_version >= 1.4``
        and a lowering-capable provider; absence is valid and means standalone
        artifacts are unsupported.

        Support is never inferred from :class:`PluginType` conversion, resident
        status, host-extension ``uses``/``helpers``, or
        :meth:`RextioLoweringPlugin.crate_dependencies`. Return ``None`` when
        the profile is not supported; return an immutable
        :class:`PluginArtifactCapability` when it is. Core validates namespace
        ownership, rule/type vocabulary membership, duplicates, and crate pins
        and fails closed with :class:`~rextio.plugins.loader.PluginError` on
        invalid declarations or hook exceptions.
        """
        ...
