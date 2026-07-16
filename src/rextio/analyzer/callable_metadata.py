"""Static callable- and schema-metadata extraction for plugin API 1.3 (WP-4).

The claim engine offers a method claim site (``obj.method(func, ...)``) a
:class:`~rextio.plugins.api.CallableMeta` for every callable argument that
statically resolves — through the module's imports/aliases — to a *project
function*, plus the declared :class:`~rextio.plugins.api.SchemaMeta` associated
with a schema-annotated receiver/parameter. Everything here is derived from a
static AST index built once per analysis (so cross-module resolution is
order-independent) and never executes user code.

Two things are deliberately closed and fail-closed:

* the callable *body* is representable only in the closed scalar/simple-row
  grammar of :class:`~rextio.plugins.api.CallableBodyExpr`; any shape outside it
  makes the body :class:`~rextio.plugins.api.CallableBody`-unavailable; and
* the callable *signature* is native-acceptable only when every parameter and
  the return resolve to a core scalar type — a row UDF (an unannotated first
  parameter bound to the receiver's schema) is representable (available body)
  but not ``accepts_native``.
"""

from __future__ import annotations

import ast
import math
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from rextio.analyzer.common_calls import (
    IMPORT_QUALIFIED_STDLIB_TARGETS,
    MATH_FLOAT_BINARY_TARGETS,
    MATH_FLOAT_TO_BOOL_TARGETS,
    MATH_FLOAT_TO_INT_TARGETS,
    MATH_FLOAT_UNARY_TARGETS,
    RUNTIME_FIDELITY_TARGETS,
    canonical_call_target,
    resolve_import_target,
    stdlib_receiver_is_proven_import,
)
from rextio.analyzer.final_bindings import (
    BindingKind,
    ModuleBindings,
    ProjectBindings,
    ProjectMutations,
    build_module_bindings,
    head_binding_blocks,
    marker_decorator_is_proven,
)
from rextio.analyzer.native_marker import dotted_name, parse_native_marker_shape
from rextio.capabilities import NUMERIC_TYPES, SCALAR_TYPES
from rextio.codegen.native_names import RESERVED_NATIVE_PREFIX, native_function_name
from rextio.codegen.rust.keywords import RUST_RAW_INCOMPATIBLE
from rextio.plugins.api import (
    CallableBody,
    CallableBodyExpr,
    CallableMeta,
    CallableParam,
    ScalarLiteral,
    SchemaField,
    SchemaMeta,
)

# Python ``int`` lowers to Rust ``i64``; a literal outside this range cannot be
# emitted as an ``i64`` literal (it fails to compile), so — exactly as core's own
# analysis does (:mod:`rextio.analyzer.unsupported_patterns`) — a body literal
# outside it makes the body unavailable rather than silently truncating.
_I64_MIN = -(2**63)
_I64_MAX = 2**63 - 1

# A resolved annotation type callback: ``(annotation_node, imports) -> type``.
# Returns a core type name (e.g. ``"float"``) or a registered plugin type key,
# or ``None`` when the annotation resolves to neither.
ResolveType = Callable[[ast.expr, "dict[str, str]"], "str | None"]

# The AST binary/unary/compare/bool operator vocabularies the closed body
# grammar accepts, mapped to the record's operator tokens. Anything absent makes
# the body unavailable (fail closed) rather than guessing an operator.
_BINOP_TOKENS: dict[type[ast.operator], str] = {
    ast.Add: "+",
    ast.Sub: "-",
    ast.Mult: "*",
    ast.Div: "/",
    ast.Mod: "%",
    ast.FloorDiv: "//",
    ast.Pow: "**",
    ast.MatMult: "@",
    ast.BitAnd: "&",
    ast.BitOr: "|",
    ast.BitXor: "^",
    ast.LShift: "<<",
    ast.RShift: ">>",
}
_UNARY_TOKENS: dict[type[ast.unaryop], str] = {
    ast.USub: "-",
    ast.UAdd: "+",
    ast.Invert: "~",
    ast.Not: "not",
}
_BOOLOP_TOKENS: dict[type[ast.boolop], str] = {ast.And: "and", ast.Or: "or"}
_COMPARE_TOKENS: dict[type[ast.cmpop], str] = {
    ast.Eq: "==",
    ast.NotEq: "!=",
    ast.Lt: "<",
    ast.LtE: "<=",
    ast.Gt: ">",
    ast.GtE: ">=",
    ast.Is: "is",
    ast.IsNot: "is not",
    ast.In: "in",
    ast.NotIn: "not in",
}

# The only calls the closed body grammar admits are the pure, side-effect-free
# scalar builtins/math that core's own call-return inference
# (:func:`rextio.analyzer.unsupported_patterns._infer_call_type`) types natively
# with an EXACT scalar result — and each admitted call is typed here by exactly
# core's rule (``abs`` preserves its numeric arg type; ``min``/``max`` require
# two operands of one numeric type; the ``math.*`` families require ``float``
# operands and return ``float``/``int``/``bool``). A call outside this set (or one
# whose operands do not match core's contract) leaves the body unavailable (fail
# closed), so a body never claims ``accepts_native`` for a call core would not
# actually lower — e.g. ``math.fabs``/``math.pow`` (which core does not lower at
# all) or a ``float()``/``int()`` conversion (which core does not type here).


@dataclass(frozen=True)
class IndexedSymbol:
    """A statically indexed project function or class definition.

    ``imports`` is the declaring module's resolved import map, so annotations and
    nested call targets inside the definition resolve the same way the module's
    own analysis resolves them.
    """

    qualname: str
    name: str
    node: ast.AST
    module_name: str
    imports: dict[str, str]
    # The declaring module's source-order final binding kinds (visible name ->
    # FINAL_BINDING_* ). A closed-body call whose head is bound at module scope to
    # a project def/class/assignment/``del`` (or a conditional binder) is NOT the
    # pure builtin/import the spelling suggests, so the body extractor fails closed
    # on it instead of lowering a stale builtin/math target (plugin API 1.3, WP-4).
    final_bindings: dict[str, str] = field(default_factory=dict)
    # The declaring module's shared final-binding authority. Unlike the coarse
    # ``final_bindings`` dict (which only carries EXPLICITLY bound names), this
    # models wildcard-import state, so the closed-body extractor fails closed on a
    # bare builtin spelling (``abs``/``min``/``max``) that a ``from x import *``
    # may have shadowed even though it is never explicitly rebound (plugin API 1.3,
    # WP-4).
    module_bindings: ModuleBindings | None = None
    # The same project-wide qualified-mutation authority used by ordinary
    # function analysis.  A callable whose definition or a statically lowered
    # target was rebound during module load must never be advertised as native.
    project_mutations: ProjectMutations = field(
        default_factory=lambda: ProjectMutations({}, frozenset())
    )
    # Project-owned module/package names. Required to distinguish genuine stdlib
    # imports from same-named project modules while extracting a closed body.
    project_modules: frozenset[str] = frozenset()


# Module-level *final binding* kinds for a visible name, computed in source
# order (see :func:`collect_module_final_bindings`). A name resolves to its
# indexed definition ONLY when its final module-level binder is the matching
# ``def``/``class``/import; an ordinary assignment/``del``/other value
# (``other``), or a name a control-flow branch may or may not rebind
# (``ambiguous``), fails closed — the shared final-binding fact for both
# callable and schema resolution.
FINAL_BINDING_FUNCTION = "function"
FINAL_BINDING_CLASS = "class"
FINAL_BINDING_IMPORT = "import"
FINAL_BINDING_OTHER = "other"
FINAL_BINDING_AMBIGUOUS = "ambiguous"


@dataclass
class ProjectSymbolIndex:
    """A project-wide static index of function and class definitions.

    Built once, before the claim pass, from every project source file, so a
    callable/schema reference resolves the same regardless of the order modules
    are analyzed in (cross-module resolution is order-independent).
    """

    functions: dict[str, IndexedSymbol] = field(default_factory=dict)
    classes: dict[str, IndexedSymbol] = field(default_factory=dict)
    # module name -> {visible name -> FINAL_BINDING_* kind}. The conservative,
    # source-order module final-binding model: whether each module-level name's
    # last binder is a specific indexed project function/class, an import/alias,
    # definitely another value/deleted, or ambiguous (a branch may bind it). A
    # later ``def``/``class``/import overrides an earlier binder; a later
    # assignment or ``del`` invalidates the symbol; a later indexed definition
    # restores it. Used by both callable and schema resolution so the cheap
    # probe and the metadata builder never diverge.
    final_bindings: dict[str, dict[str, str]] = field(default_factory=dict)
    # module name -> the shared final-binding authority (wildcard-aware, exact
    # origin). Used by the closed-body extractor so a bare builtin spelling a
    # wildcard import may have shadowed fails closed even without an explicit
    # rebinding entry in ``final_bindings`` (plugin API 1.3, WP-4).
    module_bindings: dict[str, ModuleBindings] = field(default_factory=dict)
    project_mutations: ProjectMutations = field(
        default_factory=lambda: ProjectMutations({}, frozenset())
    )


class SchemaGrammarError(ValueError):
    """A declared-schema class violates the static schema annotation grammar.

    Raised by :func:`build_declared_schema` for any unsupported shape so the
    analysis-time caller can fail closed (produce no schema) rather than guess.
    """


def index_project_symbols(
    files: list[Path],
    project_root: Path,
    module_name_for_path: Callable[[Path, Path], str],
    collect_imports: Callable[[ast.Module, str, bool, ModuleBindings], dict[str, str]],
    *,
    project_bindings: ProjectBindings,
    project_mutations: ProjectMutations,
    project_modules: Collection[str],
) -> ProjectSymbolIndex:
    """Build the project-wide function/class index from the source files.

    ``module_name_for_path`` and ``collect_imports`` are injected (they live in
    the module parser) to avoid an import cycle and to reuse the exact same
    module-name / import resolution the per-module analysis uses. The per-module
    final-binding model (:func:`collect_module_final_bindings`) is AST-only and
    built here directly.
    """
    index = ProjectSymbolIndex(project_mutations=project_mutations)
    for path in files:
        module_name = module_name_for_path(path, project_root)
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (SyntaxError, OSError, UnicodeDecodeError):
            continue
        # Never derive a second authority here.  The project scanner built the
        # binding/effect table before constructing the claim engine; callable
        # and schema metadata consume that exact shared instance.
        module_bindings = project_bindings.for_module(module_name)
        imports = collect_imports(
            tree,
            module_name,
            path.name == "__init__.py",
            module_bindings,
        )
        module_final = project_final_binding_kinds(module_bindings)
        index.final_bindings[module_name] = module_final
        index.module_bindings[module_name] = module_bindings
        prefix = f"{module_name}." if module_name else ""
        for item in tree.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qualname = f"{prefix}{item.name}"
                index.functions[qualname] = IndexedSymbol(
                    qualname=qualname,
                    name=item.name,
                    node=item,
                    module_name=module_name,
                    imports=imports,
                    final_bindings=module_final,
                    module_bindings=module_bindings,
                    project_mutations=project_mutations,
                    project_modules=frozenset(project_modules),
                )
            elif isinstance(item, ast.ClassDef):
                qualname = f"{prefix}{item.name}"
                index.classes[qualname] = IndexedSymbol(
                    qualname=qualname,
                    name=item.name,
                    node=item,
                    module_name=module_name,
                    imports=imports,
                    final_bindings=module_final,
                    module_bindings=module_bindings,
                    project_mutations=project_mutations,
                    project_modules=frozenset(project_modules),
                )
    return index


def collect_module_final_bindings(tree: ast.Module) -> dict[str, str]:
    """Return each module-level name's FINAL binding kind, in source order.

    A backward-compatible projection of the shared final-binding authority
    (:func:`rextio.analyzer.final_bindings.build_module_bindings`) onto the legacy
    ``{name -> FINAL_BINDING_*}`` map this module's callable/schema resolution
    consumes. Deriving both from one walk avoids split-brain: the authority is the
    single source of truth, and this projection only collapses its richer
    :class:`~rextio.analyzer.final_bindings.FinalBinding` (kind + exact origin +
    order + wildcard state) into the coarse kind string. A name shadowed by a
    later wildcard import projects to ``ambiguous`` (its effective
    :meth:`~rextio.analyzer.final_bindings.ModuleBindings.lookup` kind).
    """
    bindings = build_module_bindings(tree)
    return project_final_binding_kinds(bindings)


def project_final_binding_kinds(bindings: ModuleBindings) -> dict[str, str]:
    """Project the already-built shared authority onto the legacy kind map."""
    projected: dict[str, str] = {}
    for name in bindings.entries:
        projected[name] = _FINAL_BINDING_KIND_STR[bindings.lookup(name).kind]
    return projected


# Projection of the shared authority's :class:`BindingKind` onto the legacy
# coarse kind strings the callable/schema resolver consumes.
_FINAL_BINDING_KIND_STR: dict[BindingKind, str] = {
    BindingKind.FUNCTION: FINAL_BINDING_FUNCTION,
    BindingKind.CLASS: FINAL_BINDING_CLASS,
    BindingKind.IMPORT: FINAL_BINDING_IMPORT,
    BindingKind.VALUE: FINAL_BINDING_OTHER,
    BindingKind.DELETED: FINAL_BINDING_OTHER,
    BindingKind.AMBIGUOUS: FINAL_BINDING_AMBIGUOUS,
    BindingKind.UNKNOWN_STAR: FINAL_BINDING_AMBIGUOUS,
    BindingKind.UNBOUND: FINAL_BINDING_OTHER,
}


def resolve_symbol_qualname(
    dotted: str,
    imports: Mapping[str, str],
    module_name: str,
    known: dict[str, IndexedSymbol],
    *,
    kind: str,
    final_bindings: Mapping[str, Mapping[str, str]],
    local_names: Collection[str] = (),
    project_mutations: ProjectMutations | None = None,
) -> str | None:
    """Resolve a dotted reference to an indexed symbol qualname, scope-aware.

    Resolution is conservative and site-aware — it fails closed (returns
    ``None``) whenever the reference is not provably the indexed definition. It
    is driven by the shared module final-binding model
    (:func:`collect_module_final_bindings`), so the callable probe, the callable
    metadata builder, and schema resolution never diverge:

    * ``local_names`` — names bound as locals in the *referencing* function
      scope (parameters, assignments, loop/comprehension/walrus targets, …). A
      reference whose head name is a function local is shadowed and never reaches
      the module/import symbol (this also covers a read-before-local-assignment,
      which Python treats as a local for the whole scope — ``UnboundLocalError``).
    * The *referencing* module's final binding of the head name selects how it
      resolves: an ``import`` head resolves through the module's import/alias map
      (so a ``def`` overwritten by a later import resolves the final import
      target); a matching ``function``/``class`` head resolves the same-module
      definition; and an ``other``/``ambiguous`` (or unbound) head fails closed.
    * The *defining* module must still bind the resolved symbol's own name to the
      matching kind — a ``def``/``class`` overwritten by a later assignment,
      ``del``, import, or conditional binder in its own module is stale, so the
      cross-module reference fails closed too.

    ``kind`` is ``FINAL_BINDING_FUNCTION`` when ``known`` is the function index and
    ``FINAL_BINDING_CLASS`` when it is the class index.
    """
    head, separator, tail = dotted.partition(".")
    if project_mutations is None:
        return None
    if head in local_names:
        return None
    head_kind = final_bindings.get(module_name, {}).get(head)
    if head_kind == FINAL_BINDING_IMPORT:
        target = imports.get(head)
        if target is None:
            return None
        candidate = f"{target}.{tail}" if separator else target
    elif head_kind == kind and not separator:
        candidate = f"{module_name}.{head}" if module_name else head
    else:
        return None
    if candidate not in known:
        return None
    if project_mutations.target_is_mutated(candidate):
        return None
    symbol = known[candidate]
    if final_bindings.get(symbol.module_name, {}).get(symbol.name) != kind:
        return None
    return candidate


# ---------------------------------------------------------------------------
# Declared-schema resolution from a schema class node.
# ---------------------------------------------------------------------------


def _annotation_is_dynamic(node: ast.AST) -> bool:
    """Whether an annotation node contains a call (an executed expression)."""
    return any(isinstance(child, ast.Call) for child in ast.walk(node))


def build_declared_schema(
    identity: str,
    class_node: ast.ClassDef,
    resolve_type: Callable[[ast.expr], str | None],
    *,
    plugin_type_keys: Collection[str] = (),
) -> SchemaMeta:
    """Build a :class:`SchemaMeta` from an annotated class per the static grammar.

    The single, canonical declared-schema grammar (plugin API 1.3), shared by the
    documented public builder and the project-index path
    (:func:`build_schema_from_class`): a schema class carries NO bases, keyword
    class arguments, or decorators, and its body contains ONLY simple field
    annotations ``name: <type>`` (an optional leading string docstring and bare
    ``pass`` are allowed). Each annotation must resolve, through ``resolve_type``,
    to a core scalar type name or a registered plugin type key. The schema is
    never inferred from a runtime object and the annotation is never executed.

    Fails closed with :class:`SchemaGrammarError` on any unsupported shape:

    * a based (``class Row(Base)``), keyworded, or decorated class;
    * a non-annotation statement or class-level metadata (methods, nested
      classes, assignments, ``pass`` with a value, …);
    * a field carrying a default/value (``name: int = ...``);
    * a non-``Name`` annotation target;
    * a dynamic annotation expression (one containing a call);
    * an annotation that does not resolve to a known scalar/plugin type;
    * a duplicate field name.
    """
    if class_node.bases or class_node.keywords or class_node.decorator_list:
        raise SchemaGrammarError(
            f"schema {identity!r} must have no base classes, keyword class arguments, "
            "or decorators; only a plain 'name: type' field class is allowed"
        )
    fields: list[SchemaField] = []
    seen: set[str] = set()
    for index, statement in enumerate(class_node.body):
        if (
            index == 0
            and isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str)
        ):
            continue  # a leading docstring is permitted
        if isinstance(statement, ast.Pass):
            continue
        if not isinstance(statement, ast.AnnAssign):
            raise SchemaGrammarError(
                f"schema {identity!r} contains unsupported metadata: only simple "
                f"'name: type' field annotations are allowed (got {type(statement).__name__})"
            )
        if statement.value is not None:
            raise SchemaGrammarError(
                f"schema {identity!r} field carries a default value; schema fields "
                "must be bare 'name: type' annotations"
            )
        if not isinstance(statement.target, ast.Name):
            raise SchemaGrammarError(
                f"schema {identity!r} has a non-name field target; only 'name: type' is allowed"
            )
        name = statement.target.id
        if _annotation_is_dynamic(statement.annotation):
            raise SchemaGrammarError(
                f"schema {identity!r} field {name!r} uses a dynamic annotation "
                "expression (contains a call); schema annotations must be static"
            )
        resolved = resolve_type(statement.annotation)
        if resolved is None:
            raise SchemaGrammarError(
                f"schema {identity!r} field {name!r} annotation does not resolve to a "
                "known scalar or plugin type"
            )
        # The declared-schema field vocabulary is EXACTLY a core scalar type or an
        # active registered plugin type key. A general type resolver can also name
        # a container/optional/union (``list[int]``, ``dict[str, float]``,
        # ``Optional[int]``, ``int | None``, ``tuple[int, float]``); core cannot
        # lower those as a schema field type, so narrow to the public contract and
        # fail closed rather than silently broadening it.
        if resolved not in SCALAR_TYPES and resolved not in plugin_type_keys:
            raise SchemaGrammarError(
                f"schema {identity!r} field {name!r} type {resolved!r} is not a core "
                "scalar type or a registered plugin type; schema fields must be a "
                "scalar or plugin type (no collection/optional/union types)"
            )
        if name in seen:
            raise SchemaGrammarError(f"schema {identity!r} declares duplicate field {name!r}")
        seen.add(name)
        fields.append(SchemaField(name=name, field_type=resolved))
    # SchemaMeta.__post_init__ re-checks duplicate names as a construction-time
    # invariant; the grammar above rejects them first with a clearer message.
    return SchemaMeta(identity=identity, fields=tuple(fields))


def build_schema_from_class(
    identity: str,
    indexed: IndexedSymbol,
    resolve_type: ResolveType,
    *,
    plugin_type_keys: Collection[str] = (),
) -> SchemaMeta | None:
    """Build a :class:`SchemaMeta` from an indexed schema class, or None.

    The project-index path: applies the single canonical grammar of
    :func:`build_declared_schema`, resolving field annotation types through the
    schema module's own import map. Returns ``None`` (fail closed) on any grammar
    violation, so a malformed schema simply yields no schema association rather
    than a wrong one.
    """
    node = indexed.node
    if not isinstance(node, ast.ClassDef):
        return None
    try:
        return build_declared_schema(
            identity,
            node,
            lambda annotation: resolve_type(annotation, indexed.imports),
            plugin_type_keys=plugin_type_keys,
        )
    except SchemaGrammarError:
        return None


# ---------------------------------------------------------------------------
# Callable metadata extraction.
# ---------------------------------------------------------------------------


def extract_callable_meta(
    arg_index: int,
    indexed: IndexedSymbol,
    resolve_type: ResolveType,
    *,
    receiver_schema: SchemaMeta | None,
    keyword: str = "",
) -> CallableMeta | None:
    """Build a :class:`CallableMeta` for a resolved project-function argument.

    ``receiver_schema`` is the declared schema of the method receiver, if any;
    it is bound to the callable's first *unannotated* positional parameter (the
    row-UDF convention), so ``row["price"]``/``row.price`` reads inside the body
    resolve against it. ``keyword`` names the argument when the callable was
    passed as a keyword (``obj.method(func=udf)``), empty for a positional one.
    Returns ``None`` only when the resolved definition is not an ordinary
    function node.
    """
    node = indexed.node
    if not isinstance(node, ast.FunctionDef):
        # Async defs are never callable-native; expose them as an explicit
        # unavailable body rather than dropping the callable entirely.
        if isinstance(node, ast.AsyncFunctionDef):
            return CallableMeta(
                arg_index=arg_index,
                qualname=indexed.qualname,
                body=CallableBody(available=False, unavailable_reason="async function"),
                keyword=keyword,
            )
        return None

    params, param_types, schema_by_index = _resolve_params(
        node, indexed.imports, resolve_type, receiver_schema
    )
    return_type = resolve_type(node.returns, indexed.imports) if node.returns is not None else None

    # ``runtime_semantics`` reflects the documented actual shim subset: a function
    # whose body calls a runtime-fidelity target (json/statistics/base64.b64decode)
    # rides the RXT080 runtime shim. Determined over the WHOLE body (resolving the
    # target through the module's imports), so it stays truthful even when the body
    # shape is otherwise unavailable — never a misleading ``False``.
    runtime_semantics = _uses_runtime_fidelity(
        node,
        indexed.imports,
        indexed.project_modules,
    )

    disqualifier = _signature_disqualifier(node, indexed)
    if disqualifier is not None:
        body = CallableBody(available=False, unavailable_reason=disqualifier)
        return CallableMeta(
            arg_index=arg_index,
            qualname=indexed.qualname,
            params=tuple(params),
            return_type=return_type,
            runtime_semantics=runtime_semantics,
            body=body,
            keyword=keyword,
        )

    body = _extract_body(
        node,
        param_types,
        schema_by_index,
        indexed.imports,
        indexed.final_bindings,
        indexed.module_bindings,
        indexed.project_mutations,
        indexed.project_modules,
    )
    # accepts_native: a PROVEN scalar native UDF — every parameter and the return
    # resolve to a core scalar, the body is representable with every node carrying a
    # resolved type, it carries no runtime-shim semantics, and the body's own result
    # type is compatible with the declared return. Any missing proof fails closed. A
    # row UDF (schema-bound param) is representable but not scalar-native.
    all_scalar_params = bool(param_types) and all(pt in SCALAR_TYPES for pt in param_types)
    root_type = body.expression.result_type if body.available and body.expression else None
    # ``accepts_native`` also implies an actually-generatable native helper: the
    # function name and every parameter name must lower to a representable Rust
    # identifier. A signature core's own identifier validation (RXT011) would
    # reject — e.g. a parameter named ``crate`` (a Rust keyword a raw identifier
    # cannot carry) — has no native symbol, so claiming it native would fail later
    # with RXT050. This mirrors ``_validate_identifiers``/``_validate_function_name``
    # exactly, so the metadata never promises a helper core will not emit.
    names_representable = _native_function_name_representable(indexed.qualname, node.name) and all(
        _native_identifier_representable(param.name) for param in params
    )
    accepts_native = (
        body.available
        and body.expression is not None
        and _is_core_native_shape(body.expression)
        and not runtime_semantics
        and all_scalar_params
        and return_type in SCALAR_TYPES
        and root_type is not None
        and _return_compatible(root_type, return_type)
        and names_representable
    )
    return CallableMeta(
        arg_index=arg_index,
        qualname=indexed.qualname,
        params=tuple(params),
        return_type=return_type,
        accepts_native=accepts_native,
        runtime_semantics=runtime_semantics,
        native_symbol=None,  # filled at lower time for a generated native helper
        body=body,
        keyword=keyword,
    )


# Body node kinds core lowers as a DIRECTLY native scalar helper. The closed
# grammar also admits ``cond`` (an ``ast.IfExp``) and the row-UDF ``field``/
# ``subscript`` reads, but core's own FunctionAnalysis rejects ``ast.IfExp`` for a
# native helper and a field/subscript read implies a non-scalar schema parameter,
# so those shapes are representable for a plugin body yet are NOT ``accepts_native``.
_CORE_NATIVE_BODY_KINDS = frozenset(
    {"param", "literal", "unary", "binop", "boolop", "compare", "call"}
)


def _contains_call(expr: CallableBodyExpr) -> bool:
    """Whether a body sub-tree contains a call node (used for chained-compare shape)."""
    if expr.kind == "call":
        return True
    return any(_contains_call(child) for child in expr.children)


def _is_core_native_shape(expr: CallableBodyExpr) -> bool:
    """Whether the body tree is a shape core lowers as a direct native helper.

    ``accepts_native`` promises a function core itself accepts as a scalar native
    UDF, so the body must contain only shapes core lowers directly. A conditional
    (``cond``) is representable for a plugin to lower but core rejects it for a
    native helper, so any ``cond`` (or a non-scalar field/subscript read) makes the
    body non-native even though it stays available.
    """
    if expr.kind not in _CORE_NATIVE_BODY_KINDS:
        return False
    return all(_is_core_native_shape(child) for child in expr.children)


def _return_compatible(body_type: str, return_type: str | None) -> bool:
    """Whether a body's result type matches the declared return type.

    Core requires an EXACT match for native acceptance — it does not implicitly
    widen an ``int`` body result to a declared ``float`` return (that function is
    rejected), so anything but exact equality fails closed here too.
    """
    return return_type is not None and body_type == return_type


def _native_identifier_representable(name: str) -> bool:
    """Whether a parameter/local name lowers to a valid Rust identifier.

    Mirrors :func:`rextio.analyzer.unsupported_patterns._validate_identifiers`
    (RXT011): a Rust keyword a raw identifier cannot carry (``crate``/``self``/
    ``Self``/``super``), a name using the reserved generated-temporary prefix, a
    non-ASCII name, and the discard ``_`` cannot be emitted, so a signature using
    one has no native helper.
    """
    if name == "_":
        return False
    if name in RUST_RAW_INCOMPATIBLE:
        return False
    if name.startswith(RESERVED_NATIVE_PREFIX):
        return False
    return name.isascii() and name.isidentifier()


def _native_function_name_representable(qualname: str, name: str) -> bool:
    """Whether a function's name lowers to a valid Rust ``fn`` identifier.

    Mirrors :func:`rextio.analyzer.unsupported_patterns._validate_function_name`:
    a non-ASCII name, an all-underscore name (sanitizes to empty), the reserved
    prefix, and a name that lowers to a non-raw-able Rust keyword all fail.
    """
    if not name.isascii() or not name.strip("_") or name.startswith(RESERVED_NATIVE_PREFIX):
        return False
    try:
        emitted = native_function_name(qualname)
    except ValueError:
        return False
    return emitted not in RUST_RAW_INCOMPATIBLE


def _resolve_params(
    node: ast.FunctionDef,
    imports: dict[str, str],
    resolve_type: ResolveType,
    receiver_schema: SchemaMeta | None,
) -> tuple[list[CallableParam], list[str | None], dict[int, SchemaMeta]]:
    """Resolve the ordered positional parameters and their types/schemas."""
    positional = [*node.args.posonlyargs, *node.args.args]
    params: list[CallableParam] = []
    param_types: list[str | None] = []
    schema_by_index: dict[int, SchemaMeta] = {}
    for index, arg in enumerate(positional):
        param_type: str | None = None
        if arg.annotation is not None:
            param_type = resolve_type(arg.annotation, imports)
        elif index == 0 and receiver_schema is not None:
            # An unannotated first parameter of a method UDF is the row bound to
            # the receiver's declared schema (the row-UDF convention).
            schema_by_index[index] = receiver_schema
            param_type = receiver_schema.identity
        params.append(CallableParam(name=arg.arg, param_type=param_type))
        param_types.append(param_type)
    return params, param_types, schema_by_index


def _signature_disqualifier(node: ast.FunctionDef, indexed: IndexedSymbol) -> str | None:
    """Return why this signature cannot carry a closed native body, or None."""
    if node.args.vararg is not None:
        return "uses *args"
    if node.args.kwarg is not None:
        return "uses **kwargs"
    if node.args.kwonlyargs:
        return "declares keyword-only parameters"
    if any(default is not None for default in node.args.defaults):
        return "declares default argument values"
    if any(default is not None for default in node.args.kw_defaults):
        return "declares default argument values"
    for decorator in node.decorator_list:
        # A well-formed Rextio native marker (``@rextio.native`` /
        # ``@native`` / ``@rextio.native(target="rust")``) does NOT change the
        # function's native contract — an accepted scalar UDF stays accepted — so
        # it must not disqualify the body. Any other decorator (an accelerator,
        # a wrapper, or a malformed native marker with an unsupported target)
        # can change semantics, so it fails closed.
        bindings = indexed.module_bindings
        if bindings is None or not marker_decorator_is_proven(decorator, bindings, "native"):
            return "carries an unsupported decorator"
        marker = parse_native_marker_shape(decorator)
        if not marker.valid:
            return "carries an unsupported decorator"
    return None


def _body_local_names(node: ast.FunctionDef) -> frozenset[str]:
    """Return every name bound as a local in the UDF's own scope (params + Store).

    Conservative and function-scoped: parameters plus every Store-context name and
    walrus target anywhere in the body. A call head that is one of these is a
    local/parameter, not the builtin/import/math the spelling suggests, so the body
    fails closed rather than lower a different target than Python would call.
    """
    names: set[str] = {
        arg.arg for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
    }
    if node.args.vararg is not None:
        names.add(node.args.vararg.arg)
    if node.args.kwarg is not None:
        names.add(node.args.kwarg.arg)
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
            names.add(child.id)
    return frozenset(names)


def _extract_body(
    node: ast.FunctionDef,
    param_types: list[str | None],
    schema_by_index: dict[int, SchemaMeta],
    imports: dict[str, str],
    module_final_bindings: Mapping[str, str],
    module_bindings: ModuleBindings | None = None,
    project_mutations: ProjectMutations | None = None,
    project_modules: Collection[str] = (),
) -> CallableBody:
    """Extract the closed body of a single-``return`` function (fail closed).

    Every node of an available body carries a resolved (non-``None``) type — the
    extractor raises :class:`_BodyUnavailable` the moment a node cannot be typed
    exactly, so an ``available`` body is a complete, exactly-typed tree rather
    than one with unresolved holes.
    """
    statements = list(node.body)
    if statements and _is_docstring(statements[0]):
        statements = statements[1:]
    if len(statements) != 1:
        return CallableBody(available=False, unavailable_reason="body is not a single return")
    only = statements[0]
    if not isinstance(only, ast.Return) or only.value is None:
        return CallableBody(available=False, unavailable_reason="body is not a single return")
    if _uses_runtime_fidelity(node, imports, project_modules):
        return CallableBody(available=False, unavailable_reason="calls a runtime-fidelity target")
    if project_mutations is None:
        return CallableBody(
            available=False,
            unavailable_reason="project mutation authority is unavailable",
        )
    env = _BodyEnv(
        names=_names(node),
        param_types=param_types,
        schema_by_index=schema_by_index,
        imports=imports,
        local_names=_body_local_names(node),
        module_final_bindings=module_final_bindings,
        module_bindings=module_bindings,
        project_mutations=project_mutations,
        project_modules=frozenset(project_modules),
    )
    try:
        expression = _extract_expr(only.value, env)
    except _BodyUnavailable as exc:
        return CallableBody(available=False, unavailable_reason=str(exc))
    except ValueError as exc:
        # A record-construction invariant (a non-finite float literal, an
        # out-of-range value, an irrelevant-payload guard, …) is a fail-closed
        # signal, not an analysis abort: translate it into an unavailable body at
        # this safe extractor boundary rather than leaking the ValueError up
        # through the claim pass.
        return CallableBody(available=False, unavailable_reason=f"unrepresentable body: {exc}")
    return CallableBody(available=True, expression=expression)


def _names(node: ast.FunctionDef) -> list[str]:
    return [arg.arg for arg in (*node.args.posonlyargs, *node.args.args)]


def _is_docstring(statement: ast.stmt) -> bool:
    return (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and isinstance(statement.value.value, str)
    )


def _uses_runtime_fidelity(
    node: ast.FunctionDef,
    imports: dict[str, str],
    project_modules: Collection[str] = (),
) -> bool:
    """Whether any call in the function body targets a runtime-fidelity shim.

    Scans the whole body (not just a single return) and resolves each call target
    through the module's import map, so ``from statistics import mean; mean(xs)``
    is recognized exactly as ``statistics.mean(xs)`` is — the documented RXT080
    shim subset, order-independent of the body shape.
    """
    resolved_imports = dict(imports)
    for statement in node.body:
        for child in ast.walk(statement):
            if isinstance(child, ast.Call):
                dotted = dotted_name(child.func)
                if dotted is None:
                    continue
                target = resolve_import_target(dotted, resolved_imports)
                if target in RUNTIME_FIDELITY_TARGETS and stdlib_receiver_is_proven_import(
                    child.func,
                    resolved_imports,
                    project_modules=project_modules,
                ):
                    return True
    return False


class _BodyUnavailable(Exception):
    """Internal: the body expression is outside the closed grammar."""


@dataclass
class _BodyEnv:
    names: list[str]
    param_types: list[str | None]
    schema_by_index: dict[int, SchemaMeta]
    imports: dict[str, str]
    # Every name bound as a local in the UDF's own scope (parameters plus walrus /
    # Store targets in the body). A call whose head is a UDF local/param does not
    # reach the builtin/import/math the spelling suggests, so it fails closed.
    local_names: frozenset[str] = field(default_factory=frozenset)
    # The declaring module's source-order final binding kinds. A call head bound at
    # module scope to a def/class/assignment/``del``/conditional binder is not the
    # pure builtin/import spelling and fails closed.
    module_final_bindings: Mapping[str, str] = field(default_factory=dict)
    # The declaring module's shared final-binding authority (wildcard-aware). Lets
    # the call gate fail closed on a bare builtin spelling a ``from x import *``
    # may have shadowed even without an explicit rebinding entry above.
    module_bindings: ModuleBindings | None = None
    project_mutations: ProjectMutations = field(
        default_factory=lambda: ProjectMutations({}, frozenset())
    )
    project_modules: frozenset[str] = frozenset()

    def param_index(self, name: str) -> int | None:
        try:
            return self.names.index(name)
        except ValueError:
            return None


def _extract_expr(node: ast.expr, env: _BodyEnv) -> CallableBodyExpr:
    """Extract one closed body node, raising :class:`_BodyUnavailable` otherwise."""
    if isinstance(node, ast.Name):
        index = env.param_index(node.id)
        if index is None:
            raise _BodyUnavailable("reads a non-parameter name (global/closure/unbound)")
        param_type = env.param_types[index]
        if param_type is None:
            raise _BodyUnavailable("reads a parameter with no resolved type")
        return CallableBodyExpr(
            kind="param",
            param_index=index,
            name=node.id,
            result_type=param_type,
        )
    if isinstance(node, ast.Constant):
        return _extract_literal(node)
    if isinstance(node, ast.Subscript):
        return _extract_field_or_subscript(node, env, subscript=True)
    if isinstance(node, ast.Attribute):
        return _extract_field_or_subscript(node, env, subscript=False)
    if (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, ast.USub)
        and isinstance(node.operand, ast.Constant)
        and isinstance(node.operand.value, int)
        and not isinstance(node.operand.value, bool)
    ):
        # Python parses ``-9223372036854775808`` (i64::MIN) as unary minus over the
        # constant 2**63, which alone exceeds i64::MAX. Range-check the *negated*
        # value so the exact lower bound stays available while ``-(2**63 + 1)`` is
        # still unavailable — exactly as core types this constant form.
        negated = -node.operand.value
        if not (_I64_MIN <= negated <= _I64_MAX):
            raise _BodyUnavailable("integer literal is outside the supported i64 range")
        return CallableBodyExpr(
            kind="literal", literal=ScalarLiteral("int", negated), result_type="int"
        )
    if isinstance(node, ast.UnaryOp):
        token = _UNARY_TOKENS.get(type(node.op))
        if token is None:
            raise _BodyUnavailable("unsupported unary operator")
        child = _extract_expr(node.operand, env)
        result = _unary_result_type(token, child.result_type)
        if result is None:
            raise _BodyUnavailable(f"unary {token!r} has no exact result type for its operand")
        return CallableBodyExpr(kind="unary", op=token, children=(child,), result_type=result)
    if isinstance(node, ast.BinOp):
        token = _BINOP_TOKENS.get(type(node.op))
        if token is None:
            raise _BodyUnavailable("unsupported binary operator")
        left = _extract_expr(node.left, env)
        right = _extract_expr(node.right, env)
        result = _binop_result_type(token, left.result_type, right.result_type)
        if result is None:
            raise _BodyUnavailable(f"binary {token!r} has no exact result type for its operands")
        return CallableBodyExpr(
            kind="binop",
            op=token,
            children=(left, right),
            result_type=result,
        )
    if isinstance(node, ast.BoolOp):
        token = _BOOLOP_TOKENS.get(type(node.op))
        if token is None:  # pragma: no cover - only And/Or exist
            raise _BodyUnavailable("unsupported boolean operator")
        children = tuple(_extract_expr(value, env) for value in node.values)
        # Python ``and``/``or`` return an OPERAND, not a bool; core only lowers
        # them for boolean operands (where the operand and a bool coincide). Any
        # non-bool operand (numeric ``a and b``) is outside the native subset and
        # fails closed rather than being mislabeled ``bool``.
        if any(child.result_type != "bool" for child in children):
            raise _BodyUnavailable("boolean operator requires boolean operands")
        return CallableBodyExpr(kind="boolop", op=token, children=children, result_type="bool")
    if isinstance(node, ast.Compare):
        ops: list[str] = []
        for op in node.ops:
            token = _COMPARE_TOKENS.get(type(op))
            if token is None:  # pragma: no cover - closed set
                raise _BodyUnavailable("unsupported comparison operator")
            ops.append(token)
        children = (
            _extract_expr(node.left, env),
            *(_extract_expr(comparator, env) for comparator in node.comparators),
        )
        # Mirror core's chained-comparison shape rule exactly
        # (:func:`rextio.analyzer.unsupported_patterns._validate_compare_types`):
        # a chained comparison ``a < b < c`` double-evaluates every middle operand,
        # so core rejects one whose middle operand contains a call (possible
        # non-determinism / side effect). A call-valued middle would otherwise be
        # a false positive here, so fail closed too.
        if len(ops) >= 2 and any(_contains_call(middle) for middle in children[1:-1]):
            raise _BodyUnavailable(
                "chained comparison with a call-valued middle operand is not native"
            )
        _check_compare(ops, [child.result_type for child in children])
        return CallableBodyExpr(
            kind="compare", ops=tuple(ops), children=children, result_type="bool"
        )
    if isinstance(node, ast.IfExp):
        test = _extract_expr(node.test, env)
        body = _extract_expr(node.body, env)
        orelse = _extract_expr(node.orelse, env)
        # A conditional is exactly typed only when the test is boolean and both
        # branches carry the same resolved type; otherwise the result type is
        # ambiguous and the body fails closed.
        if test.result_type != "bool":
            raise _BodyUnavailable("conditional test is not boolean")
        if body.result_type is None or body.result_type != orelse.result_type:
            raise _BodyUnavailable("conditional branches have incompatible types")
        return CallableBodyExpr(
            kind="cond", children=(test, body, orelse), result_type=body.result_type
        )
    if isinstance(node, ast.Call):
        return _extract_call(node, env)
    raise _BodyUnavailable(f"unsupported expression: {type(node).__name__}")


def _extract_literal(node: ast.Constant) -> CallableBodyExpr:
    value = node.value
    if value is None:
        return CallableBodyExpr(kind="literal", literal=ScalarLiteral("none"), result_type="None")
    if isinstance(value, bool):
        return CallableBodyExpr(
            kind="literal", literal=ScalarLiteral("bool", value), result_type="bool"
        )
    if isinstance(value, int):
        if not (_I64_MIN <= value <= _I64_MAX):
            # An integer literal above i64::MAX (e.g. 9223372036854775808) cannot
            # be emitted as an i64 literal — fail closed exactly as core does.
            raise _BodyUnavailable("integer literal is outside the supported i64 range")
        return CallableBodyExpr(
            kind="literal", literal=ScalarLiteral("int", value), result_type="int"
        )
    if isinstance(value, float):
        if not math.isfinite(value):
            # ``1e400`` parses to ``inf``; a non-finite float has no JSON-safe /
            # cache-stable literal, so the body is unavailable (never a raised
            # ValueError that would abort the claim pass).
            raise _BodyUnavailable("non-finite float literal is not representable")
        return CallableBodyExpr(
            kind="literal", literal=ScalarLiteral("float", value), result_type="float"
        )
    if isinstance(value, str):
        return CallableBodyExpr(
            kind="literal", literal=ScalarLiteral("str", value), result_type="str"
        )
    raise _BodyUnavailable("unsupported literal (only int/float/bool/str/None)")


def _extract_field_or_subscript(
    node: ast.Subscript | ast.Attribute, env: _BodyEnv, *, subscript: bool
) -> CallableBodyExpr:
    base = node.value
    if not isinstance(base, ast.Name):
        raise _BodyUnavailable("field/subscript base is not a schema-bound parameter")
    index = env.param_index(base.id)
    if index is None or index not in env.schema_by_index:
        raise _BodyUnavailable("field/subscript on a non-schema value")
    schema = env.schema_by_index[index]
    if subscript:
        key_node = node.slice  # type: ignore[union-attr]
        if not (isinstance(key_node, ast.Constant) and isinstance(key_node.value, str)):
            raise _BodyUnavailable("subscript key is not a string literal")
        key = key_node.value
        kind = "subscript"
    else:
        key = node.attr  # type: ignore[union-attr]
        kind = "field"
    field_type = schema.field_type(key)
    if field_type is None:
        raise _BodyUnavailable(f"field {key!r} is not in the receiver schema")
    base_node = CallableBodyExpr(
        kind="param", param_index=index, name=base.id, result_type=schema.identity
    )
    return CallableBodyExpr(kind=kind, name=key, children=(base_node,), result_type=field_type)


def _extract_call(node: ast.Call, env: _BodyEnv) -> CallableBodyExpr:
    if node.keywords:
        raise _BodyUnavailable("call uses keyword arguments")
    # The closed body admits only pure builtin/math calls. A call whose HEAD is a
    # UDF local/parameter (``def udf(x, abs): return abs(x)``) or a module-level
    # binding that shadows the spelling (``def sin``/``sin = …``/``del sin`` before
    # the UDF) does NOT reach the builtin/import the spelling suggests, so it must
    # fail closed rather than lower a stale builtin/math target that diverges from
    # what Python actually calls (plugin API 1.3, WP-4).
    head = dotted_name(node.func)
    head_name = head.split(".", 1)[0] if head else None
    if head_name is not None:
        if head_name in env.local_names:
            raise _BodyUnavailable("call head is shadowed by a UDF parameter/local")
        head_binding = env.module_final_bindings.get(head_name)
        # An ``import`` head is resolved through the (final-binding-aware) import map
        # below; a ``function``/``class``/``other``/``ambiguous`` head is a module
        # binding that shadows the builtin/import spelling and fails closed. A head
        # with no module binding (``None``) is a genuine builtin (``abs``) or an
        # unresolved name the result-type check rejects.
        if head_binding in (
            FINAL_BINDING_FUNCTION,
            FINAL_BINDING_CLASS,
            FINAL_BINDING_OTHER,
            FINAL_BINDING_AMBIGUOUS,
        ):
            raise _BodyUnavailable("call head is shadowed by a module-level binding")
        # The coarse dict above only carries EXPLICITLY bound names; a bare builtin
        # spelling (``abs``/``min``/``max``) a ``from x import *`` may have shadowed
        # has no entry, so consult the wildcard-aware authority too and fail closed
        # when the head's effective final binding blocks it (plugin API 1.3, WP-4).
        if head_binding is None and head_binding_blocks(env.module_bindings, head_name):
            raise _BodyUnavailable("call head is shadowed by a wildcard import")
    # Resolve the target exactly as core does (import map applied), so a
    # ``from math import sqrt; sqrt(x)`` body admits the same call the attribute
    # form ``math.sqrt(x)`` does.
    target = canonical_call_target(node, dict(env.imports))
    if target is None:
        target = dotted_name(node.func)
    if target is None:
        raise _BodyUnavailable("call target is not statically resolvable")
    if env.project_mutations.target_is_mutated(target):
        raise _BodyUnavailable("call target was mutated during module execution")
    if target in IMPORT_QUALIFIED_STDLIB_TARGETS and not stdlib_receiver_is_proven_import(
        node.func,
        env.imports,
        env.local_names,
        env.project_modules,
    ):
        # A module-qualified stdlib target (`math.sin`, `hashlib.sha256(...)`) is a
        # native call only when its receiver is a proven final import: a
        # never-imported spelling raises `NameError` in CPython, so the body must
        # fail closed rather than mark it available/native (plugin API 1.3, WP-4).
        raise _BodyUnavailable("stdlib call receiver is not a proven import")
    children = tuple(_extract_expr(arg, env) for arg in node.args)
    result_type = _call_result_type(target, [child.result_type for child in children])
    if result_type is None:
        raise _BodyUnavailable("call is not an exactly-typed pure scalar call")
    return CallableBodyExpr(kind="call", target=target, children=children, result_type=result_type)


def _call_result_type(target: str, arg_types: list[str | None]) -> str | None:
    """Return the EXACT result type of an admitted pure scalar call, or None.

    Mirrors core's own call-return inference for the admitted subset — the same
    arity and operand-type contract, so a body never labels a call ``accepts_
    native`` unless core would type and lower it identically:

    * ``abs`` — one numeric operand, result is that operand's type.
    * ``min``/``max`` — two operands of one numeric type, result is that type.
    * ``math.log`` — one or two ``float`` operands, result ``float``.
    * the ``math`` float-unary/binary families — ``float`` operand(s) -> ``float``.
    * the ``math`` float->int / float->bool families — a ``float`` operand ->
      ``int`` / ``bool``.
    """
    if target == "abs":
        if len(arg_types) == 1 and arg_types[0] in NUMERIC_TYPES:
            return arg_types[0]
        return None
    if target in {"min", "max"}:
        if len(arg_types) == 2 and arg_types[0] in NUMERIC_TYPES and arg_types[0] == arg_types[1]:
            return arg_types[0]
        return None
    if target == "math.log":
        if len(arg_types) in {1, 2} and all(arg_type == "float" for arg_type in arg_types):
            return "float"
        return None
    if target in MATH_FLOAT_UNARY_TARGETS:
        if len(arg_types) == 1 and arg_types[0] == "float":
            return "float"
        return None
    if target in MATH_FLOAT_BINARY_TARGETS:
        if len(arg_types) == 2 and all(arg_type == "float" for arg_type in arg_types):
            return "float"
        return None
    if target in MATH_FLOAT_TO_INT_TARGETS:
        if len(arg_types) == 1 and arg_types[0] == "float":
            return "int"
        return None
    if target in MATH_FLOAT_TO_BOOL_TARGETS:
        if len(arg_types) == 1 and arg_types[0] == "float":
            return "bool"
        return None
    return None


def _unary_result_type(op: str, operand: str | None) -> str | None:
    """Return the exact result type of a unary op, or None (fail closed).

    Mirrors core's native subset exactly (``_infer_unary_type`` +
    ``UNSUPPORTED_SYNTAX``): only boolean ``not`` and unary minus on a numeric
    operand lower. Unary plus (``ast.UAdd``) and bitwise invert (``ast.Invert``)
    are rejected by core outright, so they never carry a result type here.
    """
    if op == "not":
        return "bool" if operand == "bool" else None
    if op == "-":
        return operand if operand in NUMERIC_TYPES else None
    # ``+`` (UAdd) and ``~`` (Invert) are not in core's native subset.
    return None


def _binop_result_type(op: str, left: str | None, right: str | None) -> str | None:
    """Return the exact result type of a binary op, or None (fail closed).

    Mirrors core's native operator subset exactly
    (:func:`rextio.analyzer.unsupported_patterns._infer_binop_type` +
    ``UNSUPPORTED_SYNTAX``): only ``+``/``-``/``*``/``/``/``%`` lower, only for
    two operands of the SAME numeric (``int``/``float``) type — and ``int/int``
    true division is rejected, so ``/`` is native only for ``float/float``.
    Everything else (floor division, ``**``, ``@``, bit ops, shifts, string
    concatenation, mixed ``int``/``float`` arithmetic, ``bool`` arithmetic) is
    left untyped so the body fails closed rather than inventing a type core would
    not accept.
    """
    if left is None or right is None:
        return None
    if left != right or left not in NUMERIC_TYPES:
        # Mixed numeric, string concatenation, bool arithmetic, and any
        # non-numeric operand are all outside core's same-type numeric subset.
        return None
    if op == "/":
        # ``int/int`` true division is rejected by core; only ``float/float``.
        return "float" if left == "float" else None
    if op in {"+", "-", "*", "%"}:
        return left
    # Floor division, ``**``, ``@``, and every bit/shift operator are unsupported.
    return None


# The core scalar types a native comparison lowers for. A schema field or param
# resolving to anything outside this set (a plugin type key, an unresolved type)
# is not a value core compares natively, so a comparison over it fails closed.
_COMPARABLE_SCALAR_TYPES = frozenset({"int", "float", "bool", "str", "bytes"})


def _check_compare(ops: list[str], operand_types: list[str | None]) -> None:
    """Validate a comparison against core's exact native subset (fail closed).

    Mirrors :func:`rextio.analyzer.unsupported_patterns._validate_compare_types`
    over the closed scalar body: membership (``in``/``not in``) has no native
    container semantics and is rejected; ``is``/``is not`` lower faithfully only
    against ``None``; and ordering/equality require two operands of the same core
    scalar type (a mixed or non-scalar comparison, or ``None <op> None``, is
    rejected). Chained comparisons are checked pairwise.
    """
    left = operand_types[0]
    for op, right in zip(ops, operand_types[1:], strict=True):
        if op in {"in", "not in"}:
            raise _BodyUnavailable("membership comparison is not modeled in the native subset")
        if op in {"is", "is not"}:
            # The closed scalar grammar does not model core's ``Optional[T]``, and
            # real core FunctionAnalysis falls back on EVERY ``is``/``is not`` form
            # — including ``x is None`` and ``None is None`` — so reject identity
            # comparisons outright rather than claim a native contract core does
            # not honor (fail closed; P2/P3 consumers do not need identity forms).
            raise _BodyUnavailable("'is'/'is not' identity comparison is not in the native subset")
        else:
            if left == "None" and right == "None":
                raise _BodyUnavailable("comparing None against None is not native")
            if (
                left != right
                or left not in _COMPARABLE_SCALAR_TYPES
                or right not in _COMPARABLE_SCALAR_TYPES
            ):
                raise _BodyUnavailable(
                    f"comparison operands are not a matched core scalar pair: {left} and {right}"
                )
        left = right
