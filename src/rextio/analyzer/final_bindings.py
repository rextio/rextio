"""One source-order module *final-binding* authority (plugin API 1.3, WP-4).

Every call decision in the analyzer, IR lowering, callable metadata, and the
build plans must agree on a single fact: for a module-level *visible name*, what
is the last thing source order binds it to, and where exactly is that binder?
A ``dict[name, kind]`` cannot answer this soundly — matching only a kind (or a
qualname) admits a *stale duplicate* definition, and it has no way to model
``from x import *`` as a wildcard that can shadow any later-unbound spelling.

This module provides the immutable model the director's addendum specifies:

* :class:`FinalBinding` — a name's last binder, carrying its ``kind`` **and its
  exact origin** (``line``/``column`` of the binding node) plus a source ``order``
  index and, for functions/classes/imports, the resolved ``target``.
* :class:`ModuleBindings` — a module's ``{name -> FinalBinding}`` table plus
  ``last_unknown_star_order`` (the source order of the most recent
  ``from ... import *``). :meth:`ModuleBindings.lookup` returns an
  ``UNKNOWN_STAR`` result for any name with no explicit binder *later* than that
  wildcard, and an ``UNBOUND`` result for a name never bound (so — and only then —
  a caller may consult the builtin allowlist).

The object is built once project-wide (:class:`ProjectBindings`) even when no
plugin is active, and shared, so the resolver, analyzer, metadata, IR, and build
plans never re-derive a divergent copy (no split-brain).

Semantics (see :func:`build_module_bindings`):

* a straight-line ``def``/``class``/import binds ``FUNCTION``/``CLASS``/``IMPORT``
  with exact origin; a straight-line assignment / ``AugAssign`` / valued
  ``AnnAssign`` / walrus / ``for``/``with`` target / ``except … as`` / match
  capture binds ``VALUE``; a straight-line ``del`` binds ``DELETED``;
* ANY binder inside ``if``/``for``/``while``/``with``/``try``/``match`` (a branch
  that may or may not run) binds ``AMBIGUOUS`` — even a ``def``/``class``/import,
  which then cannot be trusted as *the* final binding;
* ``from ... import *`` records ``last_unknown_star_order`` and adds no name entry;
* a later straight-line binder for an exact name overrides an earlier one (an
  earlier bad assignment followed by a final ``def`` restores ``FUNCTION``; a
  later class/assignment/``del``/conditional invalidates an earlier function).
"""

from __future__ import annotations

import ast
import operator
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass, field
from enum import Enum

from rextio.analyzer.native_marker import (
    decorator_resolves_to_accelerator,
    dotted_name,
)


class BindingKind(str, Enum):
    """The kind of a module-level name's final binder."""

    FUNCTION = "function"
    CLASS = "class"
    IMPORT = "import"
    VALUE = "value"  # assignment / for / with / except-as / match capture
    DELETED = "deleted"  # `del name`
    AMBIGUOUS = "ambiguous"  # a conditional branch may or may not bind it
    UNKNOWN_STAR = "unknown_star"  # shadowed by a later `import *` (synthesized)
    UNBOUND = "unbound"  # never bound at module scope (synthesized)


# Kinds a bare/attribute call head can safely resolve *through* (a proven local
# function, or an import whose target we can expand). Every other kind blocks
# native resolution and must fail closed.
RESOLVABLE_KINDS = frozenset({BindingKind.FUNCTION, BindingKind.IMPORT})

# Kinds whose final binder means a bare/attribute call head does NOT resolve to
# the callable its spelling suggests (a sibling function, an import, or a
# builtin/stdlib target). Calling it would lower to the wrong target, so a native
# candidate that does must fail closed. ``UNBOUND`` is deliberately excluded — a
# never-bound name is a clean builtin/stdlib spelling — as are ``FUNCTION`` and
# ``IMPORT`` (which resolve to a real sibling/import target).
_BLOCKING_HEAD_KINDS = frozenset(
    {
        BindingKind.CLASS,
        BindingKind.VALUE,
        BindingKind.DELETED,
        BindingKind.AMBIGUOUS,
        BindingKind.UNKNOWN_STAR,
    }
)


def definition_is_final(
    bindings: ModuleBindings | None,
    name: str,
    kind: BindingKind,
    line: int | None,
    column: int | None,
) -> bool:
    """Whether ``name``'s final module binding is EXACTLY this definition.

    The definition/build-output gate (director addendum): a native function (or a
    native method's enclosing class) may be emitted only when the defining
    module's final binding for its visible name is precisely *this* def/class —
    matched by kind AND exact origin (line/column), so a stale duplicate
    definition, or one overwritten by a later class/assignment/``del``/conditional
    binder or shadowed by a later wildcard import, is excluded. With no authority
    available (defensive), the definition is not trusted.
    """
    if bindings is None:
        return False
    entry = bindings.lookup(name)
    return entry.kind is kind and entry.line == line and entry.column == column


def head_binding_blocks(bindings: ModuleBindings | None, name: str) -> bool:
    """Whether ``name``'s final module binding blocks resolving it as a callable.

    The single call-head gate shared by core call typing, the boundary resolver,
    IR lowering, and callable metadata: a name whose last binder is a class, a
    value/assignment, a ``del``, a conditional/ambiguous branch, or a later
    wildcard import is NOT the sibling/import/builtin its spelling suggests, so a
    call to it must not lower to that stale target.
    """
    if bindings is None:
        return True
    return bindings.lookup(name).kind in _BLOCKING_HEAD_KINDS


@dataclass(frozen=True, slots=True)
class FinalBinding:
    """A module-level name's last binder, with its exact definition origin.

    ``target`` is the resolved dotted target for an ``IMPORT`` (e.g. ``pkg.sub``
    for ``import pkg.sub as alias``; ``None`` for a relative import whose target
    is resolved by the module's import map) and the module-qualified definition
    name for a ``FUNCTION``/``CLASS`` (so a cross-module reference can require the
    *exact* origin, not merely a matching qualname). ``line``/``column`` pin the
    binder node so a stale duplicate definition can never be mistaken for the
    final one. ``order`` is the source-order index of the binding event.
    """

    kind: BindingKind
    target: str | None
    line: int | None
    column: int | None
    order: int

    def matches_origin(self, node: ast.AST) -> bool:
        """Whether this binding is exactly ``node`` (same line/column)."""
        return self.line == getattr(node, "lineno", None) and self.column == getattr(
            node, "col_offset", None
        )


# A never-bound name (no entry, no covering wildcard). A distinct singleton so
# callers can tell "clean unbound" (consult builtins) from "deleted" (blocked).
_UNBOUND = FinalBinding(BindingKind.UNBOUND, None, None, None, -1)


@dataclass(frozen=True, slots=True)
class ModuleBindings:
    """A module's final-binding table plus its wildcard-import state.

    ``last_unknown_star_order`` is the COMBINED "some later binder is unmodelable"
    order — the most recent of a ``from x import *`` OR an unproven module-execution
    effect (``exec``/``globals``/an unproven decorator/a local mutator call). It
    drives the conservative call-head/definition fail-close. ``wildcard_star_order``
    is the narrower "a later wildcard import could shadow this spelling" order (only
    ``import *``); the marker proof uses it so an unrelated conservative *effect*
    poison never defeats a genuinely-imported ``@rextio.native`` head (director
    follow-up 8, P0-5).
    """

    module_name: str
    entries: Mapping[str, FinalBinding]
    last_unknown_star_order: int | None = None
    wildcard_star_order: int | None = None
    proven_marker_sites: frozenset[tuple[int, int, str]] = frozenset()
    unstable_class_sites: frozenset[tuple[int, int]] = frozenset()
    # Exact dotted annotations declared by active plugin type vocabularies.
    # Subscription of one of these targets is trusted only while evaluating a
    # function annotation; arbitrary module-load subscriptions remain effects.
    trusted_annotation_targets: frozenset[str] = frozenset()

    def lookup(self, name: str) -> FinalBinding:
        """Return ``name``'s effective final binding, wildcard-aware.

        A name with no explicit binder *later* than the most recent wildcard
        import resolves to ``UNKNOWN_STAR`` (the star may have introduced it);
        a name never bound and not covered by a wildcard resolves to ``UNBOUND``.
        """
        entry = self.entries.get(name)
        star = self.last_unknown_star_order
        if entry is None:
            if star is not None:
                return FinalBinding(BindingKind.UNKNOWN_STAR, None, None, None, star)
            return _UNBOUND
        if star is not None and star > entry.order:
            return FinalBinding(BindingKind.UNKNOWN_STAR, None, None, None, star)
        return entry


def marker_decorator_is_proven(
    decorator: ast.expr,
    bindings: ModuleBindings,
    kind: str,
) -> bool:
    """Whether a marker decorator had the exact real binding at execution time.

    ``kind`` is ``"native"`` or ``"exempt"``.  The execution scanner records a
    site only when the spelling resolved through the source-order scope to the
    real Rextio package.  The final lookup is checked too, so a marker imported
    only after use, shadowed by a wildcard/effect, or overwritten later cannot
    masquerade as the real decorator.
    """
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    name = dotted_name(target)
    if name is None:
        return False
    head, separator, tail = name.partition(".")
    final = bindings.entries.get(head)
    if final is None or final.kind is not BindingKind.IMPORT or final.target is None:
        return False
    wildcard = bindings.wildcard_star_order
    if wildcard is not None and wildcard > final.order:
        return False
    resolved = f"{final.target}.{tail}" if separator else final.target
    final_ok = resolved == f"rextio.{kind}"
    site = (getattr(decorator, "lineno", -1), getattr(decorator, "col_offset", -1), kind)
    return final_ok and site in bindings.proven_marker_sites


@dataclass(frozen=True)
class ProjectBindings:
    """Every project module's :class:`ModuleBindings`, built once and shared."""

    by_module: Mapping[str, ModuleBindings]

    def for_module(self, module_name: str) -> ModuleBindings:
        """Return ``module_name``'s bindings, failing closed when unknown."""
        existing = self.by_module.get(module_name)
        if existing is not None:
            return existing
        # An absent module is not proof that every spelling is cleanly unbound.
        # Synthesize an unknown-effect barrier so every lookup is UNKNOWN_STAR;
        # callers may not reinterpret missing authority as permission.
        return ModuleBindings(module_name, {}, 0)


@dataclass(frozen=True, slots=True)
class ProjectCallable:
    """One exact plain project function callable during module execution.

    The module-mutation prepass cannot execute Python, but it must still replay
    an imported function body when source calls that exact function at import
    time. ``global_aliases`` is the defining module's source-order import
    history (visible name -> qualified roots). ``final_global_aliases`` is used
    for ordinary calls, while ``cycle_global_aliases`` records environments at
    import edges that can suspend the owner inside its strongly connected
    component. ``global_functions`` links exact same-module functions so
    summaries can call one another. Anything absent or ambiguous is
    deliberately not represented and therefore poisons the mutation authority
    if executed.
    """

    target: str
    module_name: str
    is_package_module: bool
    node: ast.FunctionDef
    global_aliases: Mapping[str, frozenset[str]]
    final_global_aliases: Mapping[str, frozenset[str]]
    cycle_global_aliases: Mapping[str, frozenset[str]]
    cycle_snapshot_available: bool
    cycle_modules: frozenset[str]
    global_functions: Mapping[str, str]


@dataclass(frozen=True)
class ProjectMutations:
    """Project-wide record of qualified attributes mutated during module load.

    A module-load ``import pkg.helper as h; h.good = ...`` (or ``setattr``/``del``)
    rebinds ``pkg.helper.good`` for the WHOLE program, so any direct-native
    call / import / re-export that reaches that target would lower the stale
    compiled function and silently diverge from CPython. This authority is built
    once across every project module (from the aggregate of each module's
    module-load attribute mutations) and shared by the call gate, the resolver,
    and the definition/build gate (director follow-up 7, P0-4).

    ``by_module`` remains a compact storage projection (qualified receiver ->
    relative attribute paths), but queries are segment-prefix aware.  Thus a
    mutation of ``pkg.helper`` invalidates ``pkg.helper.good`` without the
    substring bug that would make ``pkg.help`` invalidate ``pkg.helper``.
    ``unknown_modules`` contains receiver paths whose attribute subtree was
    mutated dynamically (for example ``setattr(mod, dynamic_name, value)`` or
    ``vars(mod).update(...)``).
    """

    by_module: Mapping[str, frozenset[str]]
    unknown_modules: frozenset[str]

    @staticmethod
    def _is_segment_prefix(prefix: str, target: str) -> bool:
        return target == prefix or target.startswith(f"{prefix}.")

    def is_mutated(self, module: str, attr: str) -> bool:
        """Whether ``module``'s attribute ``attr`` is a proven module-load mutation."""
        return self.target_is_mutated(f"{module}.{attr}")

    def target_is_mutated(self, qualname: str) -> bool:
        """Whether ``qualname`` overlaps a source-mutated qualified path.

        Parent mutation invalidates descendants (``pkg.helper = fake`` makes
        ``pkg.helper.good`` stale), and descendant executable-state mutation
        invalidates its owner (``rextio.native.__code__ = ...`` changes the
        callable identity of ``rextio.native``).  Bare builtin lowerings are
        queried as ``len``/``sorted``; also compare their runtime owner spelling
        under ``builtins`` so an explicit ``builtins.len = ...`` cannot bypass
        the shared authority.
        """
        targets = {qualname}
        if "." not in qualname:
            targets.add(f"builtins.{qualname}")

        def overlaps(mutation: str) -> bool:
            return any(
                self._is_segment_prefix(mutation, target)
                or self._is_segment_prefix(target, mutation)
                or _logger_cache_groups_may_alias(mutation, target)
                for target in targets
            )

        if any(overlaps(prefix) for prefix in self.unknown_modules):
            return True
        return any(
            overlaps(f"{receiver}.{relative}")
            for receiver, relatives in self.by_module.items()
            for relative in relatives
        )


_EMPTY_MUTATIONS = ProjectMutations({}, frozenset())


def logger_object_target(module_name: str, name: str) -> str:
    """Return the qualified mutation-authority key for a module logger object."""
    return f"{module_name}.{name}" if module_name else name


_LOGGER_CACHE_ROOT = "logging.__rextio_process_logger_cache__"
_LOGGER_UNKNOWN_GROUP = f"{_LOGGER_CACHE_ROOT}.unknown"


def logger_group_target(logger_name: str | None) -> str:
    """Return the process-global cache identity for an exact logger name.

    ``logging.getLogger`` is process-global, not module-local.  Equal names in
    different source modules return the same mutable object, while distinct
    exact names remain independent.  ``None``, ``""`` and the no-argument form
    all identify the root logger.  UTF-8 hex keeps arbitrary names in one dotted
    mutation-authority segment (a logger name containing ``.`` is still one
    cache key, not a qualified Python path).
    """
    if logger_name is None or logger_name == "":
        return f"{_LOGGER_CACHE_ROOT}.root"
    return f"{_LOGGER_CACHE_ROOT}.name_{logger_name.encode('utf-8').hex()}"


def logger_unknown_group_target() -> str:
    """Return the shared identity for a dynamically named logger."""
    return _LOGGER_UNKNOWN_GROUP


def _logger_cache_group(path: str) -> str | None:
    prefix = f"{_LOGGER_CACHE_ROOT}."
    if not path.startswith(prefix):
        return None
    return path[len(prefix) :].split(".", 1)[0]


def _logger_cache_groups_may_alias(left: str, right: str) -> bool:
    """Model an unknown logger name as possibly aliasing every exact cache key."""
    left_group = _logger_cache_group(left)
    right_group = _logger_cache_group(right)
    if left_group is None or right_group is None:
        return False
    return left_group == "unknown" or right_group == "unknown"


LoggerNameValues = frozenset[str | None] | None


def static_logger_name_values(
    node: ast.expr,
    constants: Mapping[str, LoggerNameValues],
) -> LoggerNameValues:
    """Evaluate the small immutable subset useful as ``getLogger`` names.

    ``None`` means unknown (as opposed to ``frozenset({None})``, the exact root
    logger value).  The evaluator intentionally accepts only expressions whose
    result identity is closed over exact strings/``None``; all calls and other
    dynamic computation stay conservative.
    """
    if isinstance(node, ast.Constant) and (isinstance(node.value, str) or node.value is None):
        return frozenset({node.value})
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    if isinstance(node, ast.NamedExpr):
        return static_logger_name_values(node.value, constants)
    if isinstance(node, ast.IfExp):
        left = static_logger_name_values(node.body, constants)
        right = static_logger_name_values(node.orelse, constants)
        return None if left is None or right is None else left | right
    if isinstance(node, ast.BoolOp):
        values = [static_logger_name_values(value, constants) for value in node.values]
        if any(value is None for value in values):
            return None
        return frozenset().union(*(value for value in values if value is not None))
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = static_logger_name_values(node.left, constants)
        right = static_logger_name_values(node.right, constants)
        if left is None or right is None:
            return None
        combined: set[str | None] = set()
        for left_value in left:
            for right_value in right:
                if isinstance(left_value, str) and isinstance(right_value, str):
                    combined.add(left_value + right_value)
                else:
                    return None
        return frozenset(combined)
    return None


def logger_call_group_targets(
    call: ast.Call,
    module_name: str,
    constants: Mapping[str, LoggerNameValues] | None = None,
) -> tuple[str, ...]:
    """Return exact/unknown process-global groups for one proven factory call."""
    constants = {"__name__": frozenset({module_name}), **(constants or {})}
    if not call.args and not call.keywords:
        values: LoggerNameValues = frozenset({None})
    elif len(call.args) == 1 and not call.keywords and not isinstance(call.args[0], ast.Starred):
        values = static_logger_name_values(call.args[0], constants)
    elif not call.args and len(call.keywords) == 1 and call.keywords[0].arg == "name":
        values = static_logger_name_values(call.keywords[0].value, constants)
    else:
        values = None
    if values is None:
        return (logger_unknown_group_target(),)
    return tuple(sorted({logger_group_target(value) for value in values}))


def _assignment_target_value_pairs(
    target: ast.expr,
    value: ast.expr,
) -> tuple[list[tuple[ast.expr, ast.expr | None]], bool]:
    """Pair an assignment target with a statically exact unpacked value shape.

    Only tuple/list displays with equal, non-starred recursive structure are
    treated as identity-preserving destructuring.  Every unsupported shape
    returns all target leaves paired with ``None`` and ``False`` so callers can
    discard aliases and, where execution authority is involved, fail closed.
    """

    def leaves(node: ast.expr) -> list[ast.expr]:
        if isinstance(node, ast.Starred):
            return leaves(node.value)
        if isinstance(node, (ast.Tuple, ast.List)):
            return [leaf for element in node.elts for leaf in leaves(element)]
        return [node]

    if isinstance(target, ast.Starred):
        return [(leaf, None) for leaf in leaves(target)], False
    if not isinstance(target, (ast.Tuple, ast.List)):
        return [(target, value)], True
    if (
        not isinstance(value, (ast.Tuple, ast.List))
        or len(target.elts) != len(value.elts)
        or any(isinstance(element, ast.Starred) for element in target.elts)
    ):
        return [(leaf, None) for leaf in leaves(target)], False

    pairs: list[tuple[ast.expr, ast.expr | None]] = []
    exact = True
    for target_element, value_element in zip(target.elts, value.elts, strict=True):
        nested_pairs, nested_exact = _assignment_target_value_pairs(target_element, value_element)
        pairs.extend(nested_pairs)
        exact = exact and nested_exact
    if not exact:
        return [(leaf, None) for leaf in leaves(target)], False
    return pairs, True


def _definition_header_exprs(
    node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef,
    *,
    evaluate_annotations: bool = True,
) -> list[ast.expr]:
    """Return expressions evaluated while binding a def/class statement."""
    header: list[ast.expr] = list(node.decorator_list)
    if isinstance(node, ast.ClassDef):
        header.extend(node.bases)
        header.extend(keyword.value for keyword in node.keywords)
        return header
    header.extend(node.args.defaults)
    header.extend(default for default in node.args.kw_defaults if default is not None)
    if not evaluate_annotations:
        return header
    for argument in (
        *node.args.posonlyargs,
        *node.args.args,
        *node.args.kwonlyargs,
        *((node.args.vararg,) if node.args.vararg else ()),
        *((node.args.kwarg,) if node.args.kwarg else ()),
    ):
        if argument.annotation is not None:
            header.append(argument.annotation)
    if node.returns is not None:
        header.append(node.returns)
    return header


def collect_module_mutations(
    tree: ast.Module,
    imports: Mapping[str, str],
    project_modules: Collection[str],
    *,
    module_name: str = "",
    watched_modules: Collection[str] = (),
    is_package_module: bool = False,
    project_callables: Mapping[str, ProjectCallable] | None = None,
    known_mutations: ProjectMutations = _EMPTY_MUTATIONS,
) -> tuple[dict[str, set[str]], set[str]]:
    """Replay source order and collect mutations of proven module/class roots.

    Detects ``recv.attr = …`` / ``+=`` / ``: T = …`` / ``del recv.attr`` and
    ``setattr(recv, "attr", …)`` / ``delattr(recv, "attr")`` where ``recv``
    resolves at that exact source position to a project module, a supported
    externally-lowered module, or a module-local class. Returns
    ``(module -> specific mutated attrs, modules mutated dynamically/all)``. A
    non-literal ``setattr`` attribute name marks the whole module unknown. Scans
    module top level, def/class headers, control-flow bodies, and class bodies
    (which execute immediately), but never an ordinary function body merely
    because it is defined.  The ``imports`` argument is retained for API
    compatibility; mutation resolution deliberately does not use its final-only
    view.
    """
    specific: dict[str, set[str]] = {}
    unknown: set[str] = set()
    del imports
    future_annotations = any(
        isinstance(node, ast.ImportFrom)
        and node.module == "__future__"
        and not node.level
        and any(alias.name == "annotations" for alias in node.names)
        for node in tree.body
    )
    roots = frozenset({*project_modules, *watched_modules})
    callable_stack: set[int] = set()
    generator_stack: set[int] = set()
    callable_registry = project_callables or {}
    execution_context: list[tuple[str, bool]] = [(module_name, is_package_module)]
    fail_closed_callable_depth = 0

    @dataclass(frozen=True, slots=True)
    class Root:
        path: str
        is_class: bool = False
        tracked_object: bool = False

    CallableNode = ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda

    @dataclass(frozen=True, slots=True)
    class CallableBinding:
        node: CallableNode
        defaults: Mapping[
            str,
            tuple[
                frozenset[Root],
                CallableBinding | None,
                bool,
                StructuralValue | None,
            ],
        ]

    @dataclass(frozen=True, slots=True)
    class StructuralValue:
        """One closed local value summary used only for identity replay.

        Container members stay nested instead of being flattened into the
        aggregate root set.  ``alternatives`` represents source-visible
        control-flow choices.  ``escaped`` deliberately has no member shape:
        after a mutable value is aliased, shared, or returned it retains only
        the complete set of project roots that mutation could expose.  This
        intentionally small algebra is not a Python value interpreter;
        unsupported/dynamic expressions have no structural value and fail
        closed on later use.
        """

        kind: str
        aliases: frozenset[Root] = frozenset()
        items: tuple[StructuralValue, ...] = ()
        entries: tuple[tuple[object, StructuralValue], ...] = ()
        alternatives: tuple[StructuralValue, ...] = ()
        mutable: bool = False

    @dataclass(frozen=True, slots=True)
    class CallResult:
        """Narrow identity summary for one executed source callable.

        ``known`` means every statically visible return is closed over exact
        roots, immutable scalar values, or a shape-widened mutable value with
        complete project exposure.  An empty alias set is therefore a useful
        closed result (for example ``return 1``), distinct from an opaque
        return whose receiver must fail closed.
        """

        known: bool
        aliases: frozenset[Root] = frozenset()
        closed_scalar: bool = True
        structure: StructuralValue | None = None

    @dataclass(slots=True)
    class Env:
        # Mutation authority is a MAY analysis.  Collapsing two branch aliases
        # to ``None`` loses the exact root that either branch can still mutate.
        aliases: dict[str, frozenset[Root]]
        structures: dict[str, StructuralValue | None]
        functions: dict[str, CallableBinding | None]
        generators: dict[str, ast.GeneratorExp | None]
        logger_constants: dict[str, LoggerNameValues]
        unknown_aliases: set[str]
        closed_scalars: set[str]
        scope_kind: str

        def clone(self) -> Env:
            return Env(
                dict(self.aliases),
                dict(self.structures),
                dict(self.functions),
                dict(self.generators),
                dict(self.logger_constants),
                set(self.unknown_aliases),
                set(self.closed_scalars),
                self.scope_kind,
            )

    def active_module_name() -> str:
        return execution_context[-1][0]

    def active_is_package_module() -> bool:
        return execution_context[-1][1]

    call_results: dict[int, CallResult] = {}
    modeled_mutating_calls: dict[int, CallResult] = {}
    active_return_summaries: list[list[CallResult]] = []

    def remember_call_result(call: ast.Call, result: CallResult) -> None:
        previous = call_results.get(id(call))
        if previous is None:
            call_results[id(call)] = result
            return
        call_results[id(call)] = CallResult(
            previous.known and result.known,
            previous.aliases | result.aliases,
            previous.closed_scalar and result.closed_scalar,
            merge_structures((previous.structure, result.structure)),
        )

    source_classes: dict[str, ast.ClassDef] = {}

    _ALIASED_BUILTINS = frozenset({"id", "len", "range"})
    _MAX_STRUCTURE_NODES = 64

    def bounded_structure(value: StructuralValue) -> StructuralValue | None:
        remaining = _MAX_STRUCTURE_NODES
        pending = [value]
        while pending:
            remaining -= 1
            if remaining < 0:
                return None
            candidate = pending.pop()
            pending.extend(candidate.items)
            pending.extend(member for _key, member in candidate.entries)
            pending.extend(candidate.alternatives)
        return value

    def merge_structures(
        structures: Collection[StructuralValue | None],
    ) -> StructuralValue | None:
        values = list(structures)
        if not values or any(value is None for value in values):
            return None
        if any(value is not None and value.kind == "escaped" for value in values):
            return StructuralValue(
                "escaped",
                frozenset().union(
                    *(structure_aliases(value) for value in values if value is not None)
                ),
            )
        alternatives: list[StructuralValue] = []
        for value in values:
            if value is None:
                return None
            candidates = value.alternatives if value.kind == "union" else (value,)
            for candidate in candidates:
                if candidate not in alternatives:
                    alternatives.append(candidate)
        if len(alternatives) == 1:
            return alternatives[0]
        return bounded_structure(StructuralValue("union", alternatives=tuple(alternatives)))

    def structure_aliases(value: StructuralValue) -> frozenset[Root]:
        nested = [*value.items, *(member for _key, member in value.entries), *value.alternatives]
        return value.aliases | frozenset().union(*(structure_aliases(member) for member in nested))

    def structure_contains_mutable(value: StructuralValue) -> bool:
        """Whether a structural summary contains an aliasable Python container."""
        if value.mutable or value.kind == "escaped":
            return True
        nested = [*value.items, *(member for _key, member in value.entries), *value.alternatives]
        return any(structure_contains_mutable(member) for member in nested)

    def escaped_structure(value: StructuralValue) -> StructuralValue:
        """Discard mutable shape while retaining every exposed project identity."""
        if value.kind == "escaped":
            return value
        return StructuralValue("escaped", structure_aliases(value))

    def structure_direct_aliases(value: StructuralValue) -> frozenset[Root]:
        """Roots that are the value itself, excluding contained exposure."""
        if value.kind in {"root", "escaped"}:
            return value.aliases
        if value.kind == "union":
            return frozenset().union(
                *(structure_direct_aliases(member) for member in value.alternatives)
            )
        return frozenset()

    def literal_structure_key(node: ast.expr) -> tuple[bool, object | None]:
        """Return one hashable literal key, distinct from an unsupported key."""
        try:
            value = ast.literal_eval(node)
            hash(value)
        except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
            return False, None
        return True, value

    def select_structure(
        value: StructuralValue,
        key: object,
    ) -> tuple[StructuralValue | None, bool]:
        """Select a literal member and report whether every branch is exact."""
        if value.kind == "union":
            selected: list[StructuralValue | None] = []
            exact = True
            for alternative in value.alternatives:
                member, branch_exact = select_structure(alternative, key)
                selected.append(member)
                exact = exact and branch_exact
            return merge_structures(selected), exact
        if value.kind == "sequence" and type(key) is int:
            if -len(value.items) <= key < len(value.items):
                return value.items[key], True
            return None, False
        if value.kind == "mapping":
            for candidate, member in reversed(value.entries):
                if candidate == key:
                    return member, True
            return None, False
        return None, False

    def attribute_structure(
        value: StructuralValue,
        attribute: str,
    ) -> tuple[StructuralValue | None, bool]:
        if value.kind == "union":
            selected: list[StructuralValue | None] = []
            exact = True
            for alternative in value.alternatives:
                member, branch_exact = attribute_structure(alternative, attribute)
                selected.append(member)
                exact = exact and branch_exact
            return merge_structures(selected), exact
        if value.kind != "root" or not value.aliases:
            return None, False
        return (
            StructuralValue(
                "root",
                frozenset(
                    Root(
                        f"{root.path}.{attribute}",
                        root.is_class,
                        root.tracked_object,
                    )
                    for root in value.aliases
                ),
            ),
            True,
        )

    def bare_builtin_aliases(name: str, env: Env) -> frozenset[Root]:
        if name in _ALIASED_BUILTINS and name not in env.aliases and name not in env.functions:
            # The runtime name still denotes the builtins namespace slot even
            # after monkey-patching.  Preserve that authority; purity checks
            # separately require the slot to be untouched.
            return frozenset({Root(f"builtins.{name}", tracked_object=True)})
        return frozenset()

    def poison_all() -> None:
        """Fail closed when an executed callable cannot be summarized exactly."""
        unknown.update(roots)

    def poison_project_roots() -> None:
        """Invalidate project state without inventing an external-module write."""
        unknown.update(project_modules)

    def target_is_mutated(path: str) -> bool:
        """Consult both prior project passes and mutations seen in this replay.

        Module import order is not a stable identity boundary.  A builtin or
        stdlib factory changed by any project module must therefore revoke a
        purity shortcut in every module, including one scanned earlier.  The
        project scanner feeds this replay to a monotone fixed point; consulting
        the in-progress facts also preserves exact source-order failures in a
        standalone scan.
        """
        if known_mutations.target_is_mutated(path):
            return True
        current = ProjectMutations(
            {receiver: frozenset(paths) for receiver, paths in specific.items()},
            frozenset(unknown),
        )
        return current.target_is_mutated(path)

    def root_is_watched(path: str) -> bool:
        return any(path == root or path.startswith(f"{root}.") for root in roots)

    def resolve_root_objects(recv: ast.expr, env: Env) -> frozenset[Root]:
        resolved: set[Root] = set()
        for root in assignment_aliases(recv, env):
            if root.is_class or root.tracked_object or root_is_watched(root.path):
                resolved.add(root)
        return frozenset(resolved)

    def resolve_roots(recv: ast.expr, env: Env) -> frozenset[str]:
        return frozenset(root.path for root in resolve_root_objects(recv, env))

    def record(path: str | None, *, subtree: bool = False) -> None:
        if path is None:
            return
        if subtree:
            unknown.add(path)
            return
        receiver, separator, relative = path.rpartition(".")
        if separator:
            specific.setdefault(receiver, set()).add(relative)

    def restore(path: str) -> None:
        """Forget mutations of an older object replaced by an exact new class."""
        for receiver, relatives in list(specific.items()):
            kept = {
                relative
                for relative in relatives
                if not ProjectMutations._is_segment_prefix(path, f"{receiver}.{relative}")
            }
            if kept:
                specific[receiver] = kept
            else:
                specific.pop(receiver, None)
        restored_unknown = {
            prefix for prefix in unknown if ProjectMutations._is_segment_prefix(path, prefix)
        }
        unknown.difference_update(restored_unknown)

    def join_envs(environments: Collection[Env]) -> Env:
        envs = list(environments)
        if not envs:
            return Env({}, {}, {}, {}, {}, set(), set(), "module")

        # Mutation provenance is a MAY fact: a root present on any reachable
        # branch remains a possible receiver after the join.  Function/generator
        # executable identity is a MUST fact and therefore keeps the old exact
        # equality join below.
        alias_keys = set().union(*(env.aliases.keys() for env in envs))
        aliases = {
            name: frozenset().union(*(env.aliases.get(name, frozenset()) for env in envs))
            for name in alias_keys
        }

        def join_mapping(name: str) -> dict[str, object | None]:
            mappings = [getattr(env, name) for env in envs]
            keys = set().union(*(mapping.keys() for mapping in mappings))
            joined: dict[str, object | None] = {}
            for key in keys:
                values = [mapping.get(key) for mapping in mappings]
                first = values[0]
                joined[key] = (
                    first if all(value is first or value == first for value in values) else None
                )
            return joined

        functions = join_mapping("functions")
        generators = join_mapping("generators")
        structure_keys = set().union(*(env.structures.keys() for env in envs))
        structures = {
            name: merge_structures(tuple(env.structures.get(name) for env in envs))
            for name in structure_keys
        }
        constant_keys = set().union(*(env.logger_constants.keys() for env in envs))
        logger_constants: dict[str, LoggerNameValues] = {}
        for name in constant_keys:
            candidates = [env.logger_constants.get(name) for env in envs]
            if any(candidate is None for candidate in candidates):
                logger_constants[name] = None
            else:
                logger_constants[name] = frozenset().union(
                    *(candidate for candidate in candidates if candidate is not None)
                )
        return Env(
            aliases,
            structures,
            {
                name: value if isinstance(value, CallableBinding) else None
                for name, value in functions.items()
            },
            {
                name: value if isinstance(value, ast.GeneratorExp) else None
                for name, value in generators.items()
            },
            logger_constants,
            set().union(*(env.unknown_aliases for env in envs)),
            set.intersection(*(set(env.closed_scalars) for env in envs)),
            envs[0].scope_kind,
        )

    def replace_env(destination: Env, source: Env) -> None:
        destination.aliases.clear()
        destination.aliases.update(source.aliases)
        destination.structures.clear()
        destination.structures.update(source.structures)
        destination.functions.clear()
        destination.functions.update(source.functions)
        destination.generators.clear()
        destination.generators.update(source.generators)
        destination.logger_constants.clear()
        destination.logger_constants.update(source.logger_constants)
        destination.unknown_aliases.clear()
        destination.unknown_aliases.update(source.unknown_aliases)
        destination.closed_scalars.clear()
        destination.closed_scalars.update(source.closed_scalars)

    def exact_builtin_call(expr: ast.expr, name: str, env: Env) -> bool:
        return (
            isinstance(expr, ast.Call)
            and isinstance(expr.func, ast.Name)
            and expr.func.id == name
            and name not in env.aliases
            and name not in env.functions
            and not target_is_mutated(name)
        )

    def exact_builtin_name(name: str, env: Env) -> bool:
        return name not in env.aliases and name not in env.functions and not target_is_mutated(name)

    def module_namespace_expr(expr: ast.expr, env: Env) -> bool:
        if isinstance(expr, ast.Call) and exact_builtin_call(expr, "globals", env):
            return not expr.args and not expr.keywords
        if (
            isinstance(expr, ast.Call)
            and env.scope_kind == "module"
            and exact_builtin_call(expr, "vars", env)
        ):
            return not expr.args and not expr.keywords
        return False

    def builtins_container_expr(expr: ast.expr, env: Env) -> bool:
        """Recognize CPython's implicit ``__builtins__`` module/dict views."""
        if isinstance(expr, ast.Name) and expr.id == "__builtins__":
            return any(root.path == "builtins" for root in env.aliases.get(expr.id, ()))
        if isinstance(expr, ast.NamedExpr):
            return builtins_container_expr(expr.value, env)
        if isinstance(expr, ast.Attribute):
            if expr.attr == "__dict__" and builtins_container_expr(expr.value, env):
                return True
            if expr.attr == "__builtins__" and (
                module_namespace_expr(expr.value, env) or bool(resolve_roots(expr.value, env))
            ):
                return True
        if isinstance(expr, ast.Subscript):
            return literal_subscript_key(expr.slice) == "__builtins__" and (
                module_namespace_expr(expr.value, env) or bool(module_dict_roots(expr.value, env))
            )
        if isinstance(expr, ast.Call):
            if exact_builtin_call(expr, "vars", env) and len(expr.args) == 1:
                return not expr.keywords and builtins_container_expr(expr.args[0], env)
            if (
                exact_builtin_call(expr, "getattr", env)
                and len(expr.args) in {2, 3}
                and not expr.keywords
                and isinstance(expr.args[1], ast.Constant)
                and isinstance(expr.args[1].value, str)
            ):
                attr = expr.args[1].value
                if attr == "__dict__" and builtins_container_expr(expr.args[0], env):
                    return True
                if attr == "__builtins__" and (
                    module_namespace_expr(expr.args[0], env)
                    or bool(module_dict_roots(expr.args[0], env))
                ):
                    return True
        return False

    def module_dict_roots(expr: ast.expr, env: Env) -> frozenset[str]:
        if builtins_container_expr(expr, env):
            return frozenset({"builtins"})
        if module_namespace_expr(expr, env):
            return frozenset({active_module_name()}) if active_module_name() else frozenset()
        if isinstance(expr, ast.Attribute) and expr.attr == "__dict__":
            return resolve_roots(expr.value, env)
        if (
            isinstance(expr, ast.Call)
            and exact_builtin_call(expr, "vars", env)
            and len(expr.args) == 1
            and not expr.keywords
        ):
            return resolve_roots(expr.args[0], env)
        return frozenset()

    def literal_subscript_key(node: ast.expr) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    def record_attr_target(target: ast.expr, env: Env) -> None:
        nonlocal fail_closed_callable_depth
        if isinstance(target, ast.Attribute):
            escaped_exposure = escaped_structure_exposure(target.value, env)
            if escaped_exposure is not None:
                _record_exposed_roots(escaped_exposure)
                return
            receivers = resolve_roots(target.value, env)
            result = (
                call_results.get(id(target.value)) if isinstance(target.value, ast.Call) else None
            )
            if expression_alias_is_unknown(target.value, env):
                poison_all()
            elif not receivers and (
                fail_closed_callable_depth or (result is not None and not result.known)
            ):
                poison_all()
            for receiver in receivers:
                record(
                    receiver if target.attr == "__dict__" else f"{receiver}.{target.attr}",
                    subtree=target.attr == "__dict__",
                )
        elif isinstance(target, ast.Subscript):
            escaped_exposure = escaped_structure_exposure(target.value, env)
            if escaped_exposure is not None:
                _record_exposed_roots(escaped_exposure)
                return
            dictionary_receivers = module_dict_roots(target.value, env)
            direct_receivers = resolve_roots(target.value, env)
            receivers = dictionary_receivers | direct_receivers
            if expression_alias_is_unknown(target.value, env):
                poison_all()
            if not receivers and fail_closed_callable_depth:
                poison_all()
            key = literal_subscript_key(target.slice)
            for receiver in receivers:
                if key is None or receiver in dictionary_receivers:
                    # ``module.__dict__[key]`` and ``vars(module)[key]`` share
                    # the module namespace.  Preserve an exact string key when
                    # available; dynamic keys poison the complete subtree.
                    record(
                        f"{receiver}.{key}" if key is not None else receiver,
                        subtree=key is None,
                    )
                    if key is None and receiver == active_module_name():
                        # The dynamic module-dict key may be ``__builtins__``;
                        # its value is the process builtin module/dict authority.
                        record("builtins", subtree=True)
                else:
                    # In particular, CPython injects ``__builtins__`` as either
                    # the module or its dict.  Both forms mutate the same builtin
                    # authority for static analysis.
                    record(f"{receiver}.{key}")
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                record_attr_target(element, env)
        elif isinstance(target, ast.Starred):
            record_attr_target(target.value, env)

    def scan_store_evaluation(target: ast.expr, env: Env) -> None:
        """Replay expressions evaluated while resolving an assignment target."""
        if isinstance(target, ast.Attribute):
            scan_expr(target.value, env)
        elif isinstance(target, ast.Subscript):
            scan_expr(target.value, env)
            scan_expr(target.slice, env)
        elif isinstance(target, ast.Starred):
            scan_store_evaluation(target.value, env)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                scan_store_evaluation(element, env)

    def assignment_aliases(value: ast.expr, env: Env) -> frozenset[Root]:
        """Return every watched mutable root that ``value`` may evaluate to."""
        if isinstance(value, ast.Starred):
            return assignment_aliases(value.value, env)
        if builtins_container_expr(value, env):
            return frozenset({Root("builtins", tracked_object=True)})
        if isinstance(value, ast.Name):
            structure = env.structures.get(value.id)
            if structure is not None:
                return structure_direct_aliases(structure)
            return env.aliases.get(value.id, frozenset()) or bare_builtin_aliases(value.id, env)
        if isinstance(value, ast.NamedExpr):
            return assignment_aliases(value.value, env)
        if isinstance(value, ast.IfExp):
            return assignment_aliases(value.body, env) | assignment_aliases(value.orelse, env)
        if isinstance(value, ast.BoolOp):
            return frozenset().union(
                *(assignment_aliases(element, env) for element in value.values)
            )
        if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
            return frozenset().union(
                *(
                    assignment_aliases(
                        element.value if isinstance(element, ast.Starred) else element,
                        env,
                    )
                    for element in value.elts
                )
            )
        if isinstance(value, ast.Dict):
            dict_items = [
                *[key for key in value.keys if key is not None],
                *value.values,
            ]
            return frozenset().union(
                *(assignment_aliases(candidate, env) for candidate in dict_items)
            )
        if isinstance(value, ast.Subscript):
            structure = expression_structure(value.value, env)
            key_known, key = literal_structure_key(value.slice)
            if structure is not None and key_known:
                selected, exact = select_structure(structure, key)
                if exact and selected is not None:
                    return structure_aliases(selected)
                # Keep exposure attached to the real members, never to a
                # synthetic ``root.<subscript-key>`` path.  The matching
                # unknown predicate widens if this value is subsequently used.
                return structure_aliases(structure)
        if isinstance(value, ast.Subscript) and isinstance(value.value, (ast.List, ast.Tuple)):
            elements = value.value.elts
            if (
                isinstance(value.slice, ast.Constant)
                and type(value.slice.value) is int
                and -len(elements) <= value.slice.value < len(elements)
            ):
                return assignment_aliases(elements[value.slice.value], env)
            return frozenset().union(
                *(
                    assignment_aliases(
                        element.value if isinstance(element, ast.Starred) else element,
                        env,
                    )
                    for element in elements
                )
            )
        if isinstance(value, ast.Subscript) and isinstance(value.value, ast.Dict):
            candidates: list[ast.expr] = []
            if isinstance(value.slice, ast.Constant):
                for key, candidate in zip(value.value.keys, value.value.values, strict=True):
                    if (
                        isinstance(key, ast.Constant)
                        and type(key.value) is type(value.slice.value)
                        and key.value == value.slice.value
                    ):
                        candidates.append(candidate)
            if not candidates:
                candidates.extend(value.value.values)
            return frozenset().union(
                *(assignment_aliases(candidate, env) for candidate in candidates)
            )
        if isinstance(value, ast.Subscript):
            base = assignment_aliases(value.value, env)
            if expression_alias_is_unknown(value.value, env):
                # The value's structural shape is not closed.  Preserve its
                # rooted owner for widening, but never manufacture a dotted
                # child from a key whose relationship to that root is unknown.
                return base
            subscript_key = literal_subscript_key(value.slice)
            if subscript_key is None:
                if module_namespace_expr(value.value, env) or bool(
                    module_dict_roots(value.value, env)
                ):
                    base |= frozenset({Root("builtins", tracked_object=True)})
                return base
            return frozenset(
                Root(
                    f"{root.path}.{subscript_key}",
                    root.is_class,
                    root.tracked_object,
                )
                for root in base
            )
        if isinstance(value, ast.Call):
            factory = logging_factory_roots(value, env)
            if factory is not None:
                return factory
            result = call_results.get(id(value))
            if result is not None:
                return (
                    structure_direct_aliases(result.structure)
                    if result.structure is not None
                    else result.aliases
                )
            if (
                exact_builtin_call(value, "getattr", env)
                and len(value.args) in {2, 3}
                and not value.keywords
                and isinstance(value.args[1], ast.Constant)
                and isinstance(value.args[1].value, str)
            ):
                return frozenset(
                    Root(
                        f"{root.path}.{value.args[1].value}",
                        root.is_class,
                        root.tracked_object,
                    )
                    for root in assignment_aliases(value.args[0], env)
                )
            if module_namespace_expr(value, env):
                context = active_module_name()
                return frozenset({Root(context, tracked_object=True)}) if context else frozenset()
            return frozenset()
        if isinstance(value, ast.Attribute):
            structure = expression_structure(value.value, env)
            if structure is not None:
                selected, _exact = attribute_structure(structure, value.attr)
                return structure_aliases(selected) if selected is not None else frozenset()
            return frozenset(
                Root(f"{root.path}.{value.attr}", root.is_class, root.tracked_object)
                for root in assignment_aliases(value.value, env)
            )
        dotted = dotted_name(value)
        if dotted is None:
            return frozenset()
        head, separator, tail = dotted.partition(".")
        return frozenset(
            Root(
                f"{root.path}.{tail}" if separator else root.path,
                root.is_class,
                root.tracked_object,
            )
            for root in env.aliases.get(head, frozenset())
        )

    def logging_factory_roots(value: ast.expr, env: Env) -> frozenset[Root] | None:
        if not isinstance(value, ast.Call):
            return None
        raw = dotted_name(value.func)
        if raw is None:
            return None
        head, separator, tail = raw.partition(".")
        if not (
            any(
                (f"{root.path}.{tail}" if separator else root.path) == "logging.getLogger"
                for root in env.aliases.get(head, frozenset())
            )
            and "logging" not in project_modules
            and not target_is_mutated("logging.getLogger")
        ):
            return None
        return frozenset(
            Root(target, tracked_object=True)
            for target in logger_call_group_targets(
                value,
                active_module_name(),
                env.logger_constants,
            )
        )

    def expression_structure(value: ast.expr, env: Env) -> StructuralValue | None:
        """Return a closed shape/exposure summary without evaluating Python."""
        if isinstance(value, ast.Starred):
            return None
        if isinstance(value, ast.Constant):
            return StructuralValue("scalar")
        if isinstance(value, ast.Name):
            if value.id in env.structures:
                return env.structures[value.id]
            aliases = bare_builtin_aliases(value.id, env)
            return StructuralValue("root", aliases) if aliases else None
        if isinstance(value, ast.NamedExpr):
            return expression_structure(value.value, env)
        if isinstance(value, ast.IfExp):
            return merge_structures(
                (
                    expression_structure(value.body, env),
                    expression_structure(value.orelse, env),
                )
            )
        if isinstance(value, ast.BoolOp):
            return merge_structures(
                tuple(expression_structure(candidate, env) for candidate in value.values)
            )
        if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
            if any(isinstance(element, ast.Starred) for element in value.elts):
                return None
            items = tuple(expression_structure(element, env) for element in value.elts)
            if any(item is None for item in items):
                return None
            return bounded_structure(
                StructuralValue(
                    "collection" if isinstance(value, ast.Set) else "sequence",
                    items=tuple(item for item in items if item is not None),
                    mutable=not isinstance(value, ast.Tuple),
                )
            )
        if isinstance(value, ast.Dict):
            entries: list[tuple[object, StructuralValue]] = []
            for key_node, member_node in zip(value.keys, value.values, strict=True):
                if key_node is None:
                    return None
                key_known, key = literal_structure_key(key_node)
                member = expression_structure(member_node, env)
                if not key_known or member is None:
                    return None
                # Dict displays keep only the last value for an equal key.
                entries = [(old_key, old) for old_key, old in entries if old_key != key]
                entries.append((key, member))
            return bounded_structure(
                StructuralValue("mapping", entries=tuple(entries), mutable=True)
            )
        if isinstance(value, ast.Subscript):
            base = expression_structure(value.value, env)
            key_known, key = literal_structure_key(value.slice)
            if base is None or not key_known:
                return None
            selected, exact = select_structure(base, key)
            return selected if exact else None
        if isinstance(value, ast.Attribute):
            base = expression_structure(value.value, env)
            if base is None:
                return None
            selected, exact = attribute_structure(base, value.attr)
            return selected if exact else None
        if isinstance(value, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            aliases, known = comprehension_exposure(value, env)
            if not known:
                return None
            member = StructuralValue("root", aliases) if aliases else StructuralValue("scalar")
            return bounded_structure(
                StructuralValue(
                    "collection",
                    items=(member,),
                    mutable=not isinstance(value, ast.GeneratorExp),
                )
            )
        if isinstance(value, ast.Call):
            result = call_results.get(id(value))
            if result is None or not result.known:
                return None
            if result.structure is not None:
                return result.structure
            if result.aliases:
                return StructuralValue("root", result.aliases)
            if result.closed_scalar:
                return StructuralValue("scalar")
            return None
        if isinstance(value, ast.UnaryOp):
            operand = expression_structure(value.operand, env)
            if operand is not None and not structure_aliases(operand):
                return StructuralValue("scalar")
            return None
        if isinstance(value, ast.BinOp):
            operands = (
                expression_structure(value.left, env),
                expression_structure(value.right, env),
            )
            if all(item is not None and not structure_aliases(item) for item in operands):
                return StructuralValue("scalar")
            return None
        if isinstance(value, ast.Compare):
            compared_expressions = [value.left, *value.comparators]
            structures = [
                expression_structure(candidate, env) for candidate in compared_expressions
            ]
            if all(item is not None and not structure_aliases(item) for item in structures):
                return StructuralValue("scalar")
        return None

    def expression_alias_is_unknown(value: ast.expr, env: Env) -> bool:
        """Whether ``value`` may produce an unenumerated mutable identity."""
        if isinstance(value, ast.Starred):
            return expression_alias_is_unknown(value.value, env)
        if isinstance(value, ast.Name):
            return value.id in env.unknown_aliases
        if isinstance(value, ast.NamedExpr):
            return expression_alias_is_unknown(value.value, env)
        if isinstance(value, (ast.IfExp, ast.BoolOp)):
            candidates = (
                [value.body, value.orelse] if isinstance(value, ast.IfExp) else list(value.values)
            )
            return any(expression_alias_is_unknown(candidate, env) for candidate in candidates)
        if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
            return any(
                expression_alias_is_unknown(
                    element.value if isinstance(element, ast.Starred) else element,
                    env,
                )
                for element in value.elts
            )
        if isinstance(value, ast.Dict):
            return any(
                expression_alias_is_unknown(candidate, env)
                for candidate in [
                    *[key for key in value.keys if key is not None],
                    *value.values,
                ]
            )
        if isinstance(value, ast.Subscript):
            structure = expression_structure(value.value, env)
            if structure is not None:
                key_known, key = literal_structure_key(value.slice)
                if not key_known:
                    return True
                selected, exact = select_structure(structure, key)
                if structure.kind == "escaped":
                    return False
                return not exact or selected is None
            return expression_alias_is_unknown(value.value, env)
        if isinstance(value, ast.Attribute):
            structure = expression_structure(value.value, env)
            if structure is not None:
                selected, exact = attribute_structure(structure, value.attr)
                if structure.kind == "escaped":
                    return False
                return not exact or selected is None
            return expression_alias_is_unknown(value.value, env)
        if isinstance(value, ast.Call):
            result = call_results.get(id(value))
            return result is None or not result.known
        if isinstance(value, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            _aliases, known = comprehension_exposure(value, env)
            return not known
        return False

    def closed_scalar_expression(value: ast.expr, env: Env) -> bool:
        """Whether ``value`` is an exact non-root immutable/scalar identity."""
        structure = expression_structure(value, env)
        if (
            structure is not None
            and not structure_aliases(structure)
            and not structure_contains_mutable(structure)
        ):
            return True
        if isinstance(value, ast.Constant):
            return isinstance(value.value, (bool, int, float, complex, str, bytes, type(None)))
        if isinstance(value, ast.Name):
            return value.id in env.closed_scalars
        if isinstance(value, ast.NamedExpr):
            return closed_scalar_expression(value.value, env)
        if isinstance(value, ast.IfExp):
            return closed_scalar_expression(value.body, env) and closed_scalar_expression(
                value.orelse, env
            )
        if isinstance(value, ast.BoolOp):
            return all(closed_scalar_expression(candidate, env) for candidate in value.values)
        if isinstance(value, ast.UnaryOp):
            return closed_scalar_expression(value.operand, env)
        if isinstance(value, ast.BinOp):
            return closed_scalar_expression(value.left, env) and closed_scalar_expression(
                value.right, env
            )
        if isinstance(value, ast.Compare):
            return closed_scalar_expression(value.left, env) and all(
                closed_scalar_expression(candidate, env) for candidate in value.comparators
            )
        if isinstance(value, ast.Tuple):
            return all(
                closed_scalar_expression(
                    element.value if isinstance(element, ast.Starred) else element,
                    env,
                )
                for element in value.elts
            )
        if isinstance(value, ast.Call):
            result = call_results.get(id(value))
            return (
                result is not None and result.known and result.closed_scalar and not result.aliases
            )
        return False

    def capture_callable(node: CallableNode, env: Env) -> CallableBinding:
        positional = [*node.args.posonlyargs, *node.args.args]
        default_names = [
            parameter.arg for parameter in positional[len(positional) - len(node.args.defaults) :]
        ]
        defaults: dict[
            str,
            tuple[
                frozenset[Root],
                CallableBinding | None,
                bool,
                StructuralValue | None,
            ],
        ] = {}

        def capture_default(
            value: ast.expr,
        ) -> tuple[
            frozenset[Root],
            CallableBinding | None,
            bool,
            StructuralValue | None,
        ]:
            aliases = assignment_aliases(value, env)
            function = assignment_function(value, env)
            structure = expression_structure(value, env)

            def statically_closed(node: ast.expr) -> bool:
                if isinstance(node, ast.Constant):
                    return True
                if isinstance(node, ast.Name):
                    return bool(
                        env.aliases.get(node.id)
                        or env.functions.get(node.id)
                        or env.logger_constants.get(node.id) is not None
                    )
                if isinstance(node, ast.Lambda):
                    return True
                if isinstance(node, ast.NamedExpr):
                    return statically_closed(node.value)
                if isinstance(node, ast.IfExp):
                    return statically_closed(node.body) and statically_closed(node.orelse)
                if isinstance(node, ast.BoolOp):
                    return all(statically_closed(element) for element in node.values)
                if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
                    return all(
                        statically_closed(
                            element.value if isinstance(element, ast.Starred) else element
                        )
                        for element in node.elts
                    )
                if isinstance(node, ast.Dict):
                    return all(
                        key is not None and statically_closed(key) and statically_closed(item)
                        for key, item in zip(node.keys, node.values, strict=True)
                    )
                if isinstance(node, ast.Subscript) and isinstance(
                    node.value, (ast.List, ast.Tuple, ast.Dict)
                ):
                    return statically_closed(node.value) and isinstance(node.slice, ast.Constant)
                if isinstance(node, ast.Attribute):
                    return bool(assignment_aliases(node, env))
                return False

            closed = statically_closed(value) or structure is not None
            if structure is not None and structure_contains_mutable(structure):
                aliases |= structure_aliases(structure)
                escape_mutable_sources(value, env)
                structure = escaped_structure(structure)
            return aliases, function, closed, structure

        for name, value in zip(default_names, node.args.defaults, strict=True):
            defaults[name] = capture_default(value)
        for parameter, default_value in zip(
            node.args.kwonlyargs,
            node.args.kw_defaults,
            strict=True,
        ):
            if default_value is not None:
                defaults[parameter.arg] = capture_default(default_value)
        return CallableBinding(node=node, defaults=defaults)

    def assignment_function(value: ast.expr, env: Env) -> CallableBinding | None:
        if isinstance(value, ast.Lambda):
            return capture_callable(value, env)
        if isinstance(value, ast.Name):
            return env.functions.get(value.id)
        return None

    def assignment_generator(value: ast.expr, env: Env) -> ast.GeneratorExp | None:
        if isinstance(value, ast.GeneratorExp):
            return value
        if isinstance(value, ast.Name):
            return env.generators.get(value.id)
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
            function = env.functions.get(value.func.id)
            if function is not None and isinstance(function.node, ast.FunctionDef):
                executable = [
                    statement
                    for statement in function.node.body
                    if not (
                        isinstance(statement, ast.Expr)
                        and isinstance(statement.value, ast.Constant)
                        and isinstance(statement.value.value, str)
                    )
                    and not isinstance(statement, ast.Pass)
                ]
                if (
                    len(executable) == 1
                    and isinstance(executable[0], ast.Return)
                    and isinstance(executable[0].value, ast.GeneratorExp)
                ):
                    return executable[0].value
        return None

    def iteration_aliases(value: ast.expr, env: Env) -> frozenset[Root]:
        """Return every root possibly yielded by a closed literal iterable."""
        if not isinstance(value, (ast.List, ast.Tuple, ast.Set)) or not value.elts:
            return frozenset()
        return frozenset().union(*(assignment_aliases(element, env) for element in value.elts))

    def iteration_structure(value: ast.expr, env: Env) -> StructuralValue | None:
        structure = expression_structure(value, env)
        if structure is not None:
            if structure.kind == "escaped":
                return structure
            if structure.kind in {"sequence", "collection"}:
                if not structure.items:
                    return StructuralValue("scalar")
                return merge_structures(structure.items)
            if structure.kind == "union":
                members = [iteration_structure_from_value(item) for item in structure.alternatives]
                return merge_structures(members)
        if (
            isinstance(value, ast.Call)
            and exact_builtin_callable_name(value.func, env) == "range"
            and proven_pure_builtin_call(value, env)
        ):
            return StructuralValue("scalar")
        return None

    def iteration_structure_from_value(
        structure: StructuralValue,
    ) -> StructuralValue | None:
        if structure.kind in {"sequence", "collection"}:
            if not structure.items:
                return StructuralValue("scalar")
            return merge_structures(structure.items)
        return None

    def comprehension_exposure(
        value: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp,
        env: Env,
    ) -> tuple[frozenset[Root], bool]:
        """Summarize identities an opaque consumer can observe from a comp."""
        local = env.clone()
        local.scope_kind = "function"
        exposed: frozenset[Root] = frozenset()
        known = True
        for clause in value.generators:
            member = iteration_structure(clause.iter, local)
            if member is None:
                known = False
                bind_target(
                    clause.target,
                    local,
                    iteration_aliases(clause.iter, local),
                    unknown_alias=True,
                )
            else:
                member_aliases = structure_aliases(member)
                bind_target(
                    clause.target,
                    local,
                    member_aliases,
                    unknown_alias=False,
                    closed_scalar=not member_aliases,
                    structure=member,
                )
            for condition in clause.ifs:
                # Calls/effects were already replayed by scan_comprehension;
                # only walrus bindings can affect the yielded identity here.
                # A walrus nested under a bool/compare may be skipped, so join
                # its possible value with the pre-condition binding.
                for candidate in ast.walk(condition):
                    if not isinstance(candidate, ast.NamedExpr):
                        continue
                    assigned_aliases = assignment_aliases(candidate.value, local)
                    assigned_structure = expression_structure(candidate.value, local)
                    old_aliases = (
                        local.aliases.get(candidate.target.id, frozenset())
                        if isinstance(candidate.target, ast.Name)
                        else frozenset()
                    )
                    old_structure = (
                        local.structures.get(candidate.target.id)
                        if isinstance(candidate.target, ast.Name)
                        else None
                    )
                    bind_target(
                        candidate.target,
                        local,
                        old_aliases | assigned_aliases,
                        unknown_alias=(
                            expression_alias_is_unknown(candidate.value, local)
                            or (
                                isinstance(candidate.target, ast.Name)
                                and candidate.target.id in local.unknown_aliases
                            )
                        ),
                        closed_scalar=(
                            closed_scalar_expression(candidate.value, local) and not old_aliases
                        ),
                        structure=merge_structures((old_structure, assigned_structure)),
                    )
        yielded = (value.key, value.value) if isinstance(value, ast.DictComp) else (value.elt,)
        for yielded_expression in yielded:
            exposed |= external_exposed_aliases(yielded_expression, local, replay_deferred=False)
            if (
                expression_alias_is_unknown(yielded_expression, local)
                or expression_structure(yielded_expression, local) is None
            ):
                known = False
        return exposed, known

    def external_exposed_aliases(
        value: ast.expr,
        env: Env,
        *,
        replay_deferred: bool = True,
    ) -> frozenset[Root]:
        """Roots an opaque callee can observe, including deferred iterables."""
        aliases = assignment_aliases(value, env)
        if isinstance(value, ast.Name):
            structure = env.structures.get(value.id)
            if structure is not None:
                aliases |= structure_aliases(structure)
        if isinstance(value, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            comprehension_aliases, _known = comprehension_exposure(value, env)
            if isinstance(value, ast.GeneratorExp) and replay_deferred:
                scan_generator_iteration(value, env)
            return aliases | comprehension_aliases
        if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
            return aliases | frozenset().union(
                *(
                    external_exposed_aliases(
                        element.value if isinstance(element, ast.Starred) else element,
                        env,
                    )
                    for element in value.elts
                )
            )
        if isinstance(value, ast.Dict):
            members = [*[key for key in value.keys if key is not None], *value.values]
            return aliases | frozenset().union(
                *(external_exposed_aliases(member, env) for member in members)
            )
        if isinstance(value, ast.IfExp):
            return (
                aliases
                | external_exposed_aliases(value.body, env)
                | external_exposed_aliases(value.orelse, env)
            )
        if isinstance(value, ast.BoolOp):
            return aliases | frozenset().union(
                *(external_exposed_aliases(member, env) for member in value.values)
            )
        generator: ast.GeneratorExp | None = None
        if isinstance(value, ast.GeneratorExp):
            generator = value
        elif isinstance(value, ast.Name):
            generator = env.generators.get(value.id)
        if generator is None:
            return aliases
        # An opaque callee may consume the iterable immediately.  Replay the
        # deferred body even when the generator was nested inside another
        # container rather than supplied as the direct call argument.
        if replay_deferred:
            scan_generator_iteration(generator, env)
        local = env.clone()
        local.scope_kind = "function"
        for index, clause in enumerate(generator.generators):
            if index:
                aliases |= external_exposed_aliases(clause.iter, local)
            bind_target(clause.target, local, iteration_aliases(clause.iter, local))
            for condition in clause.ifs:
                aliases |= assignment_aliases(condition, local)
        return aliases | external_exposed_aliases(generator.elt, local)

    def bind_name(
        env: Env,
        name: str,
        aliases: frozenset[Root] = frozenset(),
        function: CallableBinding | None = None,
        generator: ast.GeneratorExp | None = None,
        logger_constant: LoggerNameValues = None,
        unknown_alias: bool = False,
        closed_scalar: bool = False,
        structure: StructuralValue | None = None,
    ) -> None:
        env.aliases[name] = aliases
        if structure is not None:
            env.structures[name] = (
                StructuralValue("root", structure.aliases | aliases)
                if structure.kind == "root"
                else structure
            )
        elif aliases and not unknown_alias:
            env.structures[name] = StructuralValue("root", aliases)
        elif closed_scalar:
            env.structures[name] = StructuralValue("scalar")
        else:
            env.structures[name] = None
        env.functions[name] = function
        env.generators[name] = generator
        env.logger_constants[name] = logger_constant
        if unknown_alias:
            env.unknown_aliases.add(name)
        else:
            env.unknown_aliases.discard(name)
        if closed_scalar:
            env.closed_scalars.add(name)
        else:
            env.closed_scalars.discard(name)

    def bind_target(
        target: ast.expr,
        env: Env,
        aliases: frozenset[Root] = frozenset(),
        function: CallableBinding | None = None,
        generator: ast.GeneratorExp | None = None,
        logger_constant: LoggerNameValues = None,
        unknown_alias: bool = False,
        closed_scalar: bool = False,
        structure: StructuralValue | None = None,
    ) -> None:
        if isinstance(target, ast.Name):
            bind_name(
                env,
                target.id,
                aliases,
                function,
                generator,
                logger_constant,
                unknown_alias,
                closed_scalar,
                structure,
            )
        elif isinstance(target, ast.Starred):
            bind_target(
                target.value,
                env,
                aliases,
                unknown_alias=unknown_alias,
                closed_scalar=closed_scalar,
                structure=structure,
            )
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                bind_target(
                    element,
                    env,
                    aliases,
                    unknown_alias=unknown_alias,
                    closed_scalar=closed_scalar,
                    structure=structure,
                )

    def _record_exposed_roots(aliases: frozenset[Root]) -> None:
        for root in aliases:
            if root_is_watched(root.path):
                record(root.path, subtree=True)

    def escape_mutable_sources(value: ast.expr, env: Env) -> None:
        """Widen exact containers referenced by a new shared/escaping binding."""
        seen: set[str] = set()
        for candidate in ast.walk(value):
            if not isinstance(candidate, ast.Name) or candidate.id in seen:
                continue
            structure = env.structures.get(candidate.id)
            if structure is None or not structure_contains_mutable(structure):
                continue
            seen.add(candidate.id)
            invalidate_structural_name(candidate.id, env)

    def escaped_structure_exposure(
        value: ast.expr,
        env: Env,
    ) -> frozenset[Root] | None:
        """Return closed project exposure for a shape-widened container path."""
        structure = expression_structure(value, env)
        if structure is not None and structure.kind == "escaped":
            return structure_aliases(structure)
        if isinstance(value, ast.NamedExpr):
            return escaped_structure_exposure(value.value, env)
        if isinstance(value, (ast.Attribute, ast.Subscript)):
            return escaped_structure_exposure(value.value, env)
        if isinstance(value, ast.IfExp):
            branches = [
                escaped_structure_exposure(value.body, env),
                escaped_structure_exposure(value.orelse, env),
            ]
            if any(branch is not None for branch in branches):
                return frozenset().union(*(branch for branch in branches if branch is not None))
        if isinstance(value, ast.BoolOp):
            branches = [escaped_structure_exposure(member, env) for member in value.values]
            if any(branch is not None for branch in branches):
                return frozenset().union(*(branch for branch in branches if branch is not None))
        return None

    def invalidate_structural_name(
        name: str,
        env: Env,
        additional_aliases: frozenset[Root] = frozenset(),
        *,
        mutation: bool = False,
    ) -> None:
        structure = env.structures.get(name)
        if structure is None or structure.kind in {"root", "scalar"}:
            return
        aliases = (
            env.aliases.get(name, frozenset()) | structure_aliases(structure) | additional_aliases
        )
        env.aliases[name] = aliases
        env.structures[name] = StructuralValue("escaped", aliases)
        # The mutable shape is unknown, but its possible project exposure is
        # complete.  Keep this separate from a truly opaque dynamic identity.
        env.unknown_aliases.discard(name)
        env.closed_scalars.discard(name)
        if mutation:
            _record_exposed_roots(aliases)

    def invalidate_structural_target(
        target: ast.expr,
        env: Env,
        additional_aliases: frozenset[Root] = frozenset(),
        *,
        mutation: bool = False,
    ) -> None:
        receiver = target
        while isinstance(receiver, (ast.Attribute, ast.Subscript)):
            receiver = receiver.value
        if isinstance(receiver, ast.Name):
            invalidate_structural_name(
                receiver.id,
                env,
                additional_aliases,
                mutation=mutation,
            )

    def invalidate_exposed_structures(value: ast.expr, env: Env) -> None:
        if isinstance(value, ast.Name):
            invalidate_structural_name(value.id, env)
            return
        if isinstance(value, ast.Starred):
            invalidate_exposed_structures(value.value, env)
            return
        if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
            for member in value.elts:
                invalidate_exposed_structures(
                    member.value if isinstance(member, ast.Starred) else member,
                    env,
                )
            return
        if isinstance(value, ast.Dict):
            for member in [*[key for key in value.keys if key is not None], *value.values]:
                invalidate_exposed_structures(member, env)
            return
        if isinstance(value, ast.IfExp):
            invalidate_exposed_structures(value.body, env)
            invalidate_exposed_structures(value.orelse, env)
            return
        if isinstance(value, ast.BoolOp):
            for member in value.values:
                invalidate_exposed_structures(member, env)

    def bind_assignment_target(
        target: ast.expr,
        value: ast.expr,
        env: Env,
        *,
        shared_logger_roots: frozenset[Root] | None = None,
        shared_binding: bool = False,
    ) -> bool:
        pairs, exact = _assignment_target_value_pairs(target, value)
        # Python evaluates the complete RHS before binding *any* target, then
        # stores left-to-right.  Resolve every metadata channel from one frozen
        # post-RHS/pre-store snapshot so swaps and duplicate targets cannot read
        # values just written by an earlier pair.
        snapshot = env.clone()
        possible = assignment_aliases(value, snapshot)
        resolved: list[
            tuple[
                ast.expr,
                frozenset[Root],
                CallableBinding | None,
                ast.GeneratorExp | None,
                LoggerNameValues,
                bool,
                bool,
                StructuralValue | None,
            ]
        ] = []
        for leaf, source in pairs:
            aliases = assignment_aliases(source, snapshot) if source is not None else possible
            structure = expression_structure(source, snapshot) if source is not None else None
            mutable_sources = (
                [
                    candidate
                    for candidate in ast.walk(source)
                    if isinstance(candidate, ast.Name)
                    and (candidate_structure := snapshot.structures.get(candidate.id)) is not None
                    and structure_contains_mutable(candidate_structure)
                ]
                if source is not None
                else []
            )
            escapes = (
                structure is not None
                and structure_contains_mutable(structure)
                and (
                    shared_binding
                    or not isinstance(leaf, ast.Name)
                    or structure.kind == "escaped"
                    or bool(mutable_sources)
                    or isinstance(source, ast.Call)
                )
            )
            if escapes and structure is not None:
                aliases |= structure_aliases(structure)
                structure = escaped_structure(structure)
            if source is not None and isinstance(leaf, ast.Name):
                logger_roots = (
                    shared_logger_roots
                    or logging_factory_roots(source, env)
                    or frozenset(
                        root for root in aliases if _logger_cache_group(root.path) is not None
                    )
                )
                if logger_roots:
                    aliases = (
                        logger_roots
                        | aliases
                        | frozenset(
                            {
                                Root(
                                    logger_object_target(active_module_name(), leaf.id),
                                    tracked_object=True,
                                )
                            }
                        )
                    )
            if not exact and isinstance(leaf, ast.Name):
                # A failed/mismatched unpack can leave the old binding intact;
                # a dynamic iterable can also yield any watched RHS candidate.
                aliases |= snapshot.aliases.get(leaf.id, frozenset())
            resolved.append(
                (
                    leaf,
                    aliases,
                    assignment_function(source, snapshot) if source is not None else None,
                    assignment_generator(source, snapshot) if source is not None else None,
                    (
                        static_logger_name_values(source, snapshot.logger_constants)
                        if source is not None
                        else None
                    ),
                    (expression_alias_is_unknown(source, snapshot) if source is not None else True)
                    or (
                        not exact
                        and isinstance(leaf, ast.Name)
                        and leaf.id in snapshot.unknown_aliases
                    ),
                    (
                        closed_scalar_expression(source, snapshot)
                        if source is not None and not escapes
                        else False
                    ),
                    structure,
                )
            )
            if escapes and source is not None:
                escape_mutable_sources(source, env)
        for leaf, source in pairs:
            invalidate_structural_target(
                leaf,
                env,
                assignment_aliases(source, snapshot) if source is not None else possible,
                mutation=not isinstance(leaf, ast.Name),
            )
        for (
            leaf,
            aliases,
            function,
            generator,
            logger_constant,
            unknown_alias,
            closed_scalar,
            structure,
        ) in resolved:
            bind_target(
                leaf,
                env,
                aliases,
                function,
                generator,
                logger_constant,
                unknown_alias,
                closed_scalar,
                structure,
            )
        return exact

    def resolve_import_from_base(node: ast.ImportFrom) -> str | None:
        if not node.level:
            return node.module
        context_module = active_module_name()
        package = context_module.split(".") if context_module else []
        if not active_is_package_module() and package:
            package.pop()
        ascend = node.level - 1
        if ascend > len(package):
            return None
        if ascend:
            package = package[:-ascend]
        if node.module:
            package.extend(node.module.split("."))
        return ".".join(package)

    def pattern_names(pattern: ast.pattern) -> set[str]:
        names: set[str] = set()
        name = getattr(pattern, "name", None)
        if isinstance(name, str):
            names.add(name)
        rest = getattr(pattern, "rest", None)
        if isinstance(rest, str):
            names.add(rest)
        for child in ast.iter_child_nodes(pattern):
            if isinstance(child, ast.pattern):
                names.update(pattern_names(child))
        return names

    def scope_declarations(statements: list[ast.stmt]) -> tuple[set[str], set[str]]:
        globals_: set[str] = set()
        locals_: set[str] = set()

        def target_names(target: ast.expr) -> None:
            if isinstance(target, ast.Name):
                locals_.add(target.id)
            elif isinstance(target, ast.Starred):
                target_names(target.value)
            elif isinstance(target, (ast.Tuple, ast.List)):
                for element in target.elts:
                    target_names(element)

        def visit(items: list[ast.stmt]) -> None:
            for statement in items:
                if isinstance(statement, ast.Global):
                    globals_.update(statement.names)
                    continue
                if isinstance(statement, ast.Nonlocal):
                    continue
                if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    locals_.add(statement.name)
                    continue
                if isinstance(statement, ast.Assign):
                    for target in statement.targets:
                        target_names(target)
                elif isinstance(statement, (ast.AnnAssign, ast.AugAssign)):
                    target_names(statement.target)
                elif isinstance(statement, ast.Delete):
                    for target in statement.targets:
                        target_names(target)
                elif isinstance(statement, (ast.For, ast.AsyncFor)):
                    target_names(statement.target)
                    visit(statement.body)
                    visit(statement.orelse)
                elif isinstance(statement, (ast.With, ast.AsyncWith)):
                    for item in statement.items:
                        if item.optional_vars is not None:
                            target_names(item.optional_vars)
                    visit(statement.body)
                elif isinstance(statement, (ast.If, ast.While)):
                    visit(statement.body)
                    visit(statement.orelse)
                elif isinstance(statement, (ast.Try, ast.TryStar)):
                    visit(statement.body)
                    visit(statement.orelse)
                    visit(statement.finalbody)
                    for handler in statement.handlers:
                        if handler.name is not None:
                            locals_.add(handler.name)
                        visit(handler.body)
                elif isinstance(statement, ast.Match):
                    for case in statement.cases:
                        locals_.update(pattern_names(case.pattern))
                        visit(case.body)
                elif isinstance(statement, ast.Import):
                    locals_.update(
                        alias.asname or alias.name.split(".", 1)[0] for alias in statement.names
                    )
                elif isinstance(statement, ast.ImportFrom):
                    locals_.update(
                        alias.asname or alias.name for alias in statement.names if alias.name != "*"
                    )

        visit(statements)
        return globals_, locals_ - globals_

    def scan_call(call: ast.Call, env: Env) -> None:
        if (
            isinstance(call.func, ast.Name)
            and call.func.id in {"setattr", "delattr"}
            and exact_builtin_name(call.func.id, env)
        ):
            if not call.args:
                return
            receivers = resolve_roots(call.args[0], env)
            if not receivers:
                invalidate_structural_target(
                    call.args[0],
                    env,
                    frozenset().union(
                        *(assignment_aliases(argument, env) for argument in call.args[2:])
                    ),
                )
                if expression_alias_is_unknown(call.args[0], env) or fail_closed_callable_depth:
                    poison_all()
                return
            if len(call.args) < 2:
                for receiver in receivers:
                    record(receiver, subtree=True)
                return
            name_arg = call.args[1]
            if isinstance(name_arg, ast.Constant) and isinstance(name_arg.value, str):
                for receiver in receivers:
                    record(f"{receiver}.{name_arg.value}")
            else:
                for receiver in receivers:
                    record(receiver, subtree=True)
            return
        if isinstance(call.func, ast.Attribute):
            container_mutating_methods = {
                # dict
                "update",
                "clear",
                "pop",
                "popitem",
                "setdefault",
                "__setitem__",
                "__delitem__",
                "__ior__",
                # list
                "append",
                "extend",
                "insert",
                "remove",
                "reverse",
                "sort",
                "__iadd__",
                "__imul__",
                # set
                "add",
                "discard",
                "difference_update",
                "intersection_update",
                "symmetric_difference_update",
                "union_update",
                "__iand__",
                "__isub__",
                "__ixor__",
            }
            structure = expression_structure(call.func.value, env)
            escaped_exposure = escaped_structure_exposure(call.func.value, env)
            if call.func.attr in container_mutating_methods and (
                escaped_exposure is not None
                or (structure is not None and structure_contains_mutable(structure))
            ):
                argument_exposure = frozenset().union(
                    *(
                        external_exposed_aliases(argument, env, replay_deferred=False)
                        for argument in [
                            *call.args,
                            *(keyword.value for keyword in call.keywords),
                        ]
                    )
                )
                exposure = (
                    escaped_exposure
                    if escaped_exposure is not None
                    else structure_aliases(structure)
                    if structure is not None
                    else frozenset()
                ) | argument_exposure
                _record_exposed_roots(exposure)
                invalidate_structural_target(
                    call.func.value,
                    env,
                    argument_exposure,
                    mutation=True,
                )
                modeled_mutating_calls[id(call)] = CallResult(
                    True,
                    exposure,
                    closed_scalar=False,
                    structure=StructuralValue("escaped", exposure),
                )
                return
            dictionary_receivers = module_dict_roots(call.func.value, env)
            direct_receivers = resolve_roots(call.func.value, env)
            receivers = dictionary_receivers | direct_receivers
            mutating_methods = {
                "update",
                "clear",
                "pop",
                "popitem",
                "setdefault",
                "__setitem__",
                "__delitem__",
            }
            if call.func.attr not in mutating_methods:
                return
            if not receivers:
                invalidate_structural_target(
                    call.func.value,
                    env,
                    frozenset().union(
                        *(
                            assignment_aliases(argument, env)
                            for argument in [
                                *call.args,
                                *(keyword.value for keyword in call.keywords),
                            ]
                        )
                    ),
                )
                if expression_alias_is_unknown(call.func.value, env) or fail_closed_callable_depth:
                    poison_all()
                return
            if call.func.attr == "update" and len(call.args) <= 1:
                exact_keys: set[str] = {
                    keyword.arg for keyword in call.keywords if keyword.arg is not None
                }
                exact = all(keyword.arg is not None for keyword in call.keywords)
                if call.args:
                    mapping = call.args[0]
                    if isinstance(mapping, ast.Dict):
                        for mapping_key in mapping.keys:
                            if isinstance(mapping_key, ast.Constant) and isinstance(
                                mapping_key.value, str
                            ):
                                exact_keys.add(mapping_key.value)
                            else:
                                exact = False
                    else:
                        exact = False
                if exact:
                    for receiver in receivers:
                        for exact_key in exact_keys:
                            record(f"{receiver}.{exact_key}")
                    return
            if call.func.attr in {"pop", "setdefault", "__setitem__", "__delitem__"} and call.args:
                method_key = literal_subscript_key(call.args[0])
                if method_key is not None:
                    for receiver in receivers:
                        record(f"{receiver}.{method_key}")
                    return
            for receiver in receivers:
                record(receiver, subtree=True)

    def bind_call_parameters(
        binding: CallableBinding,
        call: ast.Call,
        target_env: Env,
        source_env: Env,
    ) -> bool:
        arguments = binding.node.args
        positional = [*arguments.posonlyargs, *arguments.args]
        if (
            arguments.vararg is not None
            or arguments.kwarg is not None
            or any(isinstance(value, ast.Starred) for value in call.args)
            or any(keyword.arg is None for keyword in call.keywords)
            or len(call.args) > len(positional)
        ):
            poison_all()
            return False
        values: dict[str, ast.expr] = {}
        for parameter, value in zip(positional, call.args, strict=False):
            values[parameter.arg] = value
        positional_only = {parameter.arg for parameter in arguments.posonlyargs}
        known_names = {parameter.arg for parameter in [*positional, *arguments.kwonlyargs]}
        for keyword in call.keywords:
            name = keyword.arg
            if name is None or name in positional_only or name not in known_names or name in values:
                poison_all()
                return False
            values[name] = keyword.value
        for parameter in [*positional, *arguments.kwonlyargs]:
            supplied_value = values.get(parameter.arg)
            if supplied_value is not None:
                aliases = assignment_aliases(supplied_value, source_env)
                structure = expression_structure(supplied_value, source_env)
                escaped = structure is not None and structure_contains_mutable(structure)
                if escaped and structure is not None:
                    aliases |= structure_aliases(structure)
                    escape_mutable_sources(supplied_value, source_env)
                    structure = escaped_structure(structure)
                bind_name(
                    target_env,
                    parameter.arg,
                    aliases,
                    assignment_function(supplied_value, source_env),
                    assignment_generator(supplied_value, source_env),
                    static_logger_name_values(supplied_value, source_env.logger_constants),
                    expression_alias_is_unknown(supplied_value, source_env),
                    closed_scalar_expression(supplied_value, source_env) if not escaped else False,
                    structure,
                )
                continue
            default = binding.defaults.get(parameter.arg)
            if default is None:
                poison_all()
                return False
            aliases, function, statically_closed, structure = default
            if not statically_closed:
                poison_all()
                return False
            bind_name(
                target_env,
                parameter.arg,
                aliases,
                function,
                closed_scalar=statically_closed and not aliases and function is None,
                structure=structure,
            )
        return True

    def _closed_scalar_return(node: ast.expr, env: Env) -> bool:
        if isinstance(node, ast.Constant):
            return isinstance(node.value, (bool, int, float, complex, str, bytes, type(None)))
        if isinstance(node, ast.Name):
            return node.id in env.closed_scalars or env.logger_constants.get(node.id) is not None
        if isinstance(node, ast.NamedExpr):
            return _closed_scalar_return(node.value, env)
        if isinstance(node, ast.IfExp):
            return _closed_scalar_return(node.body, env) and _closed_scalar_return(node.orelse, env)
        if isinstance(node, ast.BoolOp):
            return all(_closed_scalar_return(value, env) for value in node.values)
        if isinstance(node, ast.Tuple):
            return all(
                _closed_scalar_return(
                    element.value if isinstance(element, ast.Starred) else element,
                    env,
                )
                for element in node.elts
            )
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Tuple):
            return _closed_scalar_return(node.value, env) and isinstance(node.slice, ast.Constant)
        if isinstance(node, ast.Call):
            result = call_results.get(id(node))
            return (
                result is not None and result.known and result.closed_scalar and not result.aliases
            )
        return False

    def expression_return_summary(node: ast.expr | None, env: Env) -> CallResult:
        if node is None:
            return CallResult(True, structure=StructuralValue("scalar"))
        aliases = assignment_aliases(node, env)
        closed_scalar = _closed_scalar_return(node, env)
        structure = expression_structure(node, env)
        if structure is not None and structure_contains_mutable(structure):
            # Returning a mutable container creates a shared identity between
            # the callee and caller.  Never copy its exact member layout into
            # the caller; retain only the complete project-root exposure.
            aliases |= structure_aliases(structure)
            escape_mutable_sources(node, env)
            structure = escaped_structure(structure)
            closed_scalar = False
        if structure is not None:
            aliases |= structure_aliases(structure)
        if (
            structure is not None
            and not structure_aliases(structure)
            and not structure_contains_mutable(structure)
        ):
            closed_scalar = True
        return CallResult(
            (bool(aliases) or closed_scalar or structure is not None)
            and not expression_alias_is_unknown(node, env),
            aliases,
            closed_scalar,
            structure,
        )

    def callable_return_summary(
        node: CallableNode,
        env: Env,
        returns: Collection[CallResult],
    ) -> CallResult:
        if isinstance(node, ast.Lambda):
            return expression_return_summary(node.body, env)
        if not returns:
            return CallResult(True, structure=StructuralValue("scalar"))
        return CallResult(
            all(returned.known for returned in returns),
            frozenset().union(*(returned.aliases for returned in returns)),
            all(returned.closed_scalar for returned in returns),
            merge_structures(tuple(returned.structure for returned in returns)),
        )

    def execute_callable(
        binding: CallableBinding,
        call: ast.Call,
        caller: Env,
        *,
        base_env: Env | None = None,
        propagate_globals: bool = True,
    ) -> CallResult:
        nonlocal fail_closed_callable_depth
        node = binding.node
        if isinstance(node, ast.AsyncFunctionDef):
            poison_all()
            return CallResult(False)

        def contains_nonlocal(statements: list[ast.stmt]) -> bool:
            for statement in statements:
                if isinstance(statement, ast.Nonlocal):
                    return True
                if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                for child in ast.iter_child_nodes(statement):
                    if isinstance(child, ast.stmt) and contains_nonlocal([child]):
                        return True
            return False

        if isinstance(node, ast.FunctionDef) and contains_nonlocal(node.body):
            # A nonlocal cell is mutable executable state outside this replay's
            # environment.  Do not emulate closure cells with ordinary name
            # aliases: one executed callable with ``nonlocal`` invalidates the
            # project/global mutation proof.
            poison_project_roots()
            return CallResult(False)
        if id(node) in callable_stack:
            poison_all()
            return CallResult(False)
        callable_stack.add(id(node))
        # Every executed named source function is an exact project callable,
        # including one called locally by its defining module.  Unknown
        # receivers/external effects inside either form must fail closed; using
        # only ``base_env is not None`` missed the local-call spelling.
        fail_closed_unresolved = isinstance(node, ast.FunctionDef)
        if fail_closed_unresolved:
            fail_closed_callable_depth += 1
        try:
            local = (base_env or caller).clone()
            local.scope_kind = "function"
            return_summaries: list[CallResult] = []
            active_return_summaries.append(return_summaries)
            if isinstance(node, ast.FunctionDef):
                globals_, locals_ = scope_declarations(node.body)
                if globals_ and not propagate_globals:
                    poison_all()
                locals_.update(
                    argument.arg
                    for argument in (
                        *node.args.posonlyargs,
                        *node.args.args,
                        *node.args.kwonlyargs,
                        *((node.args.vararg,) if node.args.vararg else ()),
                        *((node.args.kwarg,) if node.args.kwarg else ()),
                    )
                )
                for name in locals_:
                    bind_name(local, name)
                if not bind_call_parameters(binding, call, local, caller):
                    return CallResult(False)
                scan(node.body, local, namespace="function")
                if propagate_globals:
                    for name in globals_:
                        if name in local.aliases:
                            caller.aliases[name] = local.aliases[name]
                        if name in local.structures:
                            caller.structures[name] = local.structures[name]
                        if name in local.functions:
                            caller.functions[name] = local.functions[name]
                        if name in local.generators:
                            caller.generators[name] = local.generators[name]
                        if name in local.logger_constants:
                            caller.logger_constants[name] = local.logger_constants[name]
                        if name in local.unknown_aliases:
                            caller.unknown_aliases.add(name)
                        else:
                            caller.unknown_aliases.discard(name)
                        if name in local.closed_scalars:
                            caller.closed_scalars.add(name)
                        else:
                            caller.closed_scalars.discard(name)
            else:
                if not bind_call_parameters(binding, call, local, caller):
                    return CallResult(False)
                scan_expr(node.body, local)
            return callable_return_summary(node, local, return_summaries)
        finally:
            if active_return_summaries:
                active_return_summaries.pop()
            if fail_closed_unresolved:
                fail_closed_callable_depth -= 1
            callable_stack.remove(id(node))

    def project_callable_env(record: ProjectCallable) -> Env:
        caller_module = active_module_name()
        if caller_module in record.cycle_modules and record.cycle_snapshot_available:
            # An empty snapshot is meaningful: all earlier import aliases may
            # have been rebound before the suspending edge.  Falling back to
            # their historical union would resurrect stale receivers.
            alias_authority = record.cycle_global_aliases
        else:
            alias_authority = record.final_global_aliases
        aliases = {
            name: frozenset(Root(path) for path in paths) for name, paths in alias_authority.items()
        }
        aliases["__builtins__"] = frozenset({Root("builtins", tracked_object=True)})
        env = Env(
            aliases,
            {
                name: StructuralValue("root", value) if value else None
                for name, value in aliases.items()
            },
            {name: None for name in record.global_functions},
            {},
            {"__name__": frozenset({record.module_name})},
            set(),
            {"__name__"},
            "module",
        )
        for name, target in record.global_functions.items():
            candidate = callable_registry.get(target)
            if candidate is not None:
                env.functions[name] = capture_callable(candidate.node, env)
                env.aliases[name] = frozenset({Root(target, tracked_object=True)})
                env.structures[name] = StructuralValue("root", env.aliases[name])
        return env

    def execute_project_callable(
        record: ProjectCallable,
        call: ast.Call,
        caller: Env,
    ) -> CallResult:
        base = project_callable_env(record)
        binding = capture_callable(record.node, base)
        execution_context.append((record.module_name, record.is_package_module))
        try:
            return execute_callable(
                binding,
                call,
                caller,
                base_env=base,
                propagate_globals=False,
            )
        finally:
            execution_context.pop()

    def maybe_execute_project_call(call: ast.Call, env: Env) -> CallResult | None:
        candidates = {root.path for root in assignment_aliases(call.func, env) if not root.is_class}
        project_targets = {
            target
            for target in candidates
            if any(
                target == project_module or target.startswith(f"{project_module}.")
                for project_module in project_modules
            )
        }
        if not project_targets:
            return None
        resolved_records = [callable_registry.get(target) for target in project_targets]
        if any(record is None for record in resolved_records):
            poison_project_roots()
            return CallResult(False)
        records_by_target = {
            record.target: record for record in resolved_records if record is not None
        }
        if len(records_by_target) != 1:
            poison_project_roots()
            return CallResult(False)
        record = next(iter(records_by_target.values()))
        return execute_project_callable(record, call, env)

    def scan_comprehension(node: ast.AST, env: Env) -> None:
        local = env.clone()
        local.scope_kind = "function"
        generators = node.generators  # type: ignore[attr-defined]
        for generator in generators:
            scan_expr(generator.iter, local)
            scan_deferred_iterable(generator.iter, local)
            member = iteration_structure(generator.iter, local)
            member_aliases = (
                structure_aliases(member)
                if member is not None
                else iteration_aliases(generator.iter, local)
            )
            bind_target(
                generator.target,
                local,
                member_aliases,
                unknown_alias=member is None,
                closed_scalar=member is not None and not member_aliases,
                structure=member,
            )
            for condition in generator.ifs:
                scan_expr(condition, local)
        if isinstance(node, ast.DictComp):
            scan_expr(node.key, local)
            scan_expr(node.value, local)
        else:
            scan_expr(node.elt, local)  # type: ignore[attr-defined]
        # Assignment expressions in comprehensions bind the containing scope
        # (PEP 572), while iteration targets remain local to the comprehension.
        # The comprehension may be empty, so mutation provenance joins the old
        # and possible new aliases instead of replacing them.
        for child in ast.walk(node):
            if not isinstance(child, ast.NamedExpr) or not isinstance(child.target, ast.Name):
                continue
            name = child.target.id
            env.aliases[name] = env.aliases.get(name, frozenset()) | local.aliases.get(
                name, frozenset()
            )
            env.structures[name] = merge_structures(
                (env.structures.get(name), local.structures.get(name))
            )
            old_function = env.functions.get(name)
            new_function = local.functions.get(name)
            env.functions[name] = old_function if old_function is new_function else None
            old_generator = env.generators.get(name)
            new_generator = local.generators.get(name)
            env.generators[name] = old_generator if old_generator is new_generator else None
            old_constant = env.logger_constants.get(name)
            new_constant = local.logger_constants.get(name)
            if old_constant is None or new_constant is None:
                env.logger_constants[name] = None
            else:
                env.logger_constants[name] = old_constant | new_constant
            if name in env.unknown_aliases or name in local.unknown_aliases:
                env.unknown_aliases.add(name)
            else:
                env.unknown_aliases.discard(name)
            if name in env.closed_scalars and name in local.closed_scalars:
                env.closed_scalars.add(name)
            else:
                env.closed_scalars.discard(name)

    def scan_generator_iteration(node: ast.GeneratorExp, env: Env) -> None:
        """Scan work performed when an already-created generator is consumed."""
        identity = id(node)
        if identity in generator_stack:
            return
        generator_stack.add(identity)
        try:
            local = env.clone()
            local.scope_kind = "function"
            for index, generator in enumerate(node.generators):
                # Generator construction already evaluated the outermost iterable.
                # Nested iterables remain deferred until iteration reaches them.
                if index:
                    scan_expr(generator.iter, local)
                    scan_deferred_iterable(generator.iter, local)
                member = iteration_structure(generator.iter, local)
                member_aliases = (
                    structure_aliases(member)
                    if member is not None
                    else iteration_aliases(generator.iter, local)
                )
                bind_target(
                    generator.target,
                    local,
                    member_aliases,
                    unknown_alias=member is None,
                    closed_scalar=member is not None and not member_aliases,
                    structure=member,
                )
                for condition in generator.ifs:
                    scan_expr(condition, local)
            scan_expr(node.elt, local)
        finally:
            generator_stack.remove(identity)

    def scan_deferred_iterable(node: ast.expr, env: Env) -> None:
        generator: ast.GeneratorExp | None = None
        if isinstance(node, ast.GeneratorExp):
            generator = node
        elif isinstance(node, ast.Name):
            generator = env.generators.get(node.id)
        if generator is not None:
            scan_generator_iteration(generator, env)

    _PROVEN_PURE_BUILTINS = frozenset(
        {
            "abs",
            "all",
            "any",
            "bool",
            "bytes",
            "float",
            "hash",
            "id",
            "int",
            "isinstance",
            "issubclass",
            "len",
            "max",
            "min",
            "ord",
            "range",
            "repr",
            "round",
            "str",
            "sum",
            "tuple",
            "type",
        }
    )

    def exact_builtin_callable_name(value: ast.expr, env: Env) -> str | None:
        if (
            isinstance(value, ast.Name)
            and value.id in _PROVEN_PURE_BUILTINS
            and exact_builtin_name(value.id, env)
        ):
            return value.id
        roots = assignment_aliases(value, env)
        if len(roots) != 1:
            return None
        root = next(iter(roots))
        prefix = "builtins."
        if not root.path.startswith(prefix):
            return None
        name = root.path[len(prefix) :]
        if "." in name or name not in _PROVEN_PURE_BUILTINS or target_is_mutated(root.path):
            return None
        return name

    def proven_pure_builtin_call(call: ast.Call, env: Env) -> bool:
        builtin_name = exact_builtin_callable_name(call.func, env)
        if builtin_name is None:
            return False
        arguments = [*call.args, *(keyword.value for keyword in call.keywords)]
        if builtin_name == "id":
            # ``id`` neither exposes the object to user Python nor dispatches a
            # protocol hook.  Other builtins below are effect-free only for
            # closed scalar/immutable operands: ``len``/``repr``/``hash``/etc.
            # can otherwise execute arbitrary user dunders.
            return len(arguments) == 1
        return all(closed_scalar_expression(argument, env) for argument in arguments)

    def unknown_external_call_effect(call: ast.Call, env: Env) -> None:
        """Invalidate project roots exposed to an unmodeled external callee."""
        if proven_pure_builtin_call(call, env):
            return
        arguments = [*call.args, *(keyword.value for keyword in call.keywords)]
        exposed_values = list(arguments)
        if isinstance(call.func, ast.Attribute):
            # Calling an unmodeled bound method exposes its receiver just as
            # surely as passing that object as an explicit first argument.  A
            # direct attribute call on an imported module is different: Python
            # module attributes do not descriptor-bind the module as ``self``.
            receiver_roots = assignment_aliases(call.func.value, env)
            direct_module_receiver = (
                isinstance(call.func.value, ast.Name)
                and bool(receiver_roots)
                and all(not root.is_class and not root.tracked_object for root in receiver_roots)
            )
            if not direct_module_receiver:
                exposed_values.append(call.func.value)
        exposed: frozenset[Root] = frozenset().union(
            *(
                external_exposed_aliases(argument, env, replay_deferred=False)
                for argument in exposed_values
            )
        )
        for root in exposed:
            if root_is_watched(root.path):
                record(root.path, subtree=True)
        protocol_builtin_without_closed_operands = exact_builtin_callable_name(
            call.func, env
        ) is not None or (
            isinstance(call.func, ast.Name)
            and call.func.id in _PROVEN_PURE_BUILTINS
            and call.func.id not in env.aliases
            and call.func.id not in env.functions
        )
        mutated_callable_identity = any(
            target_is_mutated(root.path) for root in assignment_aliases(call.func, env)
        )
        unknown_exposure = any(
            expression_alias_is_unknown(argument, env) or module_namespace_expr(argument, env)
            for argument in exposed_values
        )
        if (
            unknown_exposure
            or expression_alias_is_unknown(call.func, env)
            or protocol_builtin_without_closed_operands
            or mutated_callable_identity
        ):
            poison_project_roots()
        for exposed_value in exposed_values:
            invalidate_exposed_structures(exposed_value, env)

    def source_class_has_plain_construction(path: str, node: ast.ClassDef) -> bool:
        """Whether source construction cannot dispatch user Python hooks."""
        if node.decorator_list or node.bases or node.keywords or target_is_mutated(path):
            return False
        class_bindings = build_module_bindings(
            ast.Module(body=node.body, type_ignores=[]),
            active_module_name(),
            project_modules=project_modules,
        )
        return all(
            class_bindings.lookup(name).kind is BindingKind.UNBOUND
            for name in {"__new__", "__init__"}
        )

    def source_class_instance_is_hook_free(node: ast.ClassDef) -> bool:
        """Whether later operations on an instance have no source dispatch.

        Do not grow a miniature descriptor/method interpreter here.  Only an
        inert namespace (pass/docstring/annotations and scalar constants) is
        proven hook-free.  A method, ``__slots__``, descriptor factory, mutable
        class value, or any control flow makes the fresh instance unknown until
        a future structural model can prove that operation exactly.
        """

        def inert_target(target: ast.expr) -> bool:
            return isinstance(target, ast.Name) and target.id != "__slots__"

        for statement in node.body:
            if isinstance(statement, ast.Pass):
                continue
            if (
                isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Constant)
                and isinstance(statement.value.value, str)
            ):
                continue
            if isinstance(statement, ast.AnnAssign):
                if not inert_target(statement.target):
                    return False
                if statement.value is None or isinstance(statement.value, ast.Constant):
                    continue
                return False
            if isinstance(statement, ast.Assign):
                if all(inert_target(target) for target in statement.targets) and isinstance(
                    statement.value, ast.Constant
                ):
                    continue
                return False
            return False
        return True

    def modeled_identity_call(call: ast.Call, env: Env) -> CallResult | None:
        """Return summaries for exact builtin/class identity operations."""
        if (
            exact_builtin_call(call, "vars", env)
            and not call.args
            and not call.keywords
            and env.scope_kind == "function"
        ):
            # A function's zero-argument vars() is its local namespace, never
            # the module globals.  The empty tracked path keeps local mutations
            # exact without publishing a synthetic project mutation target.
            return CallResult(
                True,
                frozenset({Root("", tracked_object=True)}),
                closed_scalar=False,
            )
        if exact_builtin_call(call, "vars", env) and len(call.args) == 1 and not call.keywords:
            return CallResult(True, assignment_aliases(call.args[0], env))
        if (
            exact_builtin_call(call, "getattr", env)
            and len(call.args) in {2, 3}
            and not call.keywords
            and isinstance(call.args[1], ast.Constant)
            and isinstance(call.args[1].value, str)
        ):
            return CallResult(True, assignment_aliases(call, env))
        if (
            isinstance(call.func, ast.Name)
            and call.func.id in {"setattr", "delattr"}
            and exact_builtin_name(call.func.id, env)
            and call.args
            and assignment_aliases(call.args[0], env)
        ):
            return CallResult(True)
        if isinstance(call.func, ast.Attribute) and call.func.attr in {
            "update",
            "clear",
            "pop",
            "popitem",
            "setdefault",
            "__setitem__",
            "__delitem__",
        }:
            receiver = call.func.value
            if module_dict_roots(receiver, env) or resolve_roots(receiver, env):
                # The side effect itself was recorded by ``scan_call``.  Return
                # identity varies by method, so keep it unknown if later used.
                return CallResult(False)
        callable_roots = assignment_aliases(call.func, env)
        if callable_roots and all(root.is_class for root in callable_roots):
            definitions = [(root.path, source_classes.get(root.path)) for root in callable_roots]
            if all(
                definition is not None and source_class_has_plain_construction(path, definition)
                for path, definition in definitions
            ):
                # This exact source class creates a fresh, non-root object.  It
                # is not a closed scalar.  If its body declares a protocol hook,
                # retain the construction but mark the resulting identity
                # unknown so the first later store/call/iteration widens.
                hook_free = all(
                    definition is not None and source_class_instance_is_hook_free(definition)
                    for _path, definition in definitions
                )
                return CallResult(hook_free, closed_scalar=False)
            # Otherwise metaclass/__new__/__init__ Python is unmodeled.
            poison_project_roots()
            return CallResult(False)
        return None

    def scan_expr(node: ast.AST, env: Env) -> None:
        if isinstance(node, ast.Lambda):
            for default in (*node.args.defaults, *node.args.kw_defaults):
                if default is not None:
                    scan_expr(default, env)
            return
        if isinstance(node, ast.GeneratorExp):
            # Generator creation evaluates only the outermost iterable.  Its
            # target, filters, nested iterables and element remain deferred.
            if node.generators:
                scan_expr(node.generators[0].iter, env)
            return
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp)):
            scan_comprehension(node, env)
            return
        if isinstance(node, ast.NamedExpr):
            scan_expr(node.value, env)
            aliases = assignment_aliases(node.value, env)
            structure = expression_structure(node.value, env)
            escapes = (
                structure is not None
                and structure_contains_mutable(structure)
                and (
                    structure.kind == "escaped"
                    or isinstance(node.value, ast.Call)
                    or any(
                        isinstance(candidate, ast.Name)
                        and (candidate_structure := env.structures.get(candidate.id)) is not None
                        and structure_contains_mutable(candidate_structure)
                        for candidate in ast.walk(node.value)
                    )
                )
            )
            if escapes and structure is not None:
                aliases |= structure_aliases(structure)
                escape_mutable_sources(node.value, env)
                structure = escaped_structure(structure)
            bind_target(
                node.target,
                env,
                aliases,
                assignment_function(node.value, env),
                assignment_generator(node.value, env),
                static_logger_name_values(node.value, env.logger_constants),
                expression_alias_is_unknown(node.value, env),
                closed_scalar_expression(node.value, env) if not escapes else False,
                structure,
            )
            return
        if isinstance(node, ast.Call):
            scan_expr(node.func, env)
            for argument in node.args:
                scan_expr(argument, env)
            for keyword in node.keywords:
                scan_expr(keyword.value, env)
            # A generator body is deferred at construction but an executed call
            # may consume a directly supplied (or simply aliased) generator.  We
            # cannot prove an arbitrary callee lazy, so conservatively replay the
            # generator body here.  Merely assigning/returning a generator remains
            # effect-free until such a consumption site.
            for argument in [*node.args, *(keyword.value for keyword in node.keywords)]:
                scan_deferred_iterable(argument, env)
            scan_call(node, env)
            called: CallableBinding | None = None
            if isinstance(node.func, ast.Lambda):
                called = capture_callable(node.func, env)
            elif isinstance(node.func, ast.Name):
                called = env.functions.get(node.func.id)
            result: CallResult | None = None
            if called is not None:
                result = execute_callable(called, node, env)
            else:
                result = modeled_mutating_calls.get(id(node))
                if result is None:
                    result = modeled_identity_call(node, env)
                if result is None:
                    result = maybe_execute_project_call(node, env)
            if result is None:
                logger_roots = logging_factory_roots(node, env)
                if logger_roots is not None:
                    result = CallResult(True, logger_roots)
                elif module_namespace_expr(node, env):
                    context = active_module_name()
                    result = CallResult(
                        True,
                        (
                            frozenset({Root(context, tracked_object=True)})
                            if context
                            else frozenset()
                        ),
                    )
                elif proven_pure_builtin_call(node, env):
                    result = CallResult(True)
                else:
                    unknown_external_call_effect(node, env)
                    result = CallResult(False)
            remember_call_result(node, result)
            return
        for child in ast.iter_child_nodes(node):
            scan_expr(child, env)

    def scan_headers(node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef, env: Env) -> None:
        for expression in _definition_header_exprs(
            node, evaluate_annotations=not future_annotations
        ):
            scan_expr(expression, env)

    def env_equal(left: Env, right: Env) -> bool:
        return (
            left.aliases == right.aliases
            and left.structures == right.structures
            and left.functions == right.functions
            and left.generators == right.generators
            and left.logger_constants == right.logger_constants
            and left.unknown_aliases == right.unknown_aliases
            and left.closed_scalars == right.closed_scalars
        )

    def module_main_guard_truth(node: ast.expr, env: Env) -> bool | None:
        """Resolve the conventional ``__name__ == '__main__'`` import guard."""
        if (
            not isinstance(node, ast.Compare)
            or len(node.ops) != 1
            or len(node.comparators) != 1
            or not isinstance(node.ops[0], (ast.Eq, ast.NotEq))
        ):
            return None
        left = static_logger_name_values(node.left, env.logger_constants)
        right = static_logger_name_values(node.comparators[0], env.logger_constants)
        if left is None or right is None or len(left) != 1 or len(right) != 1:
            return None
        left_value = next(iter(left))
        right_value = next(iter(right))
        if not (
            (left_value == "__main__" and isinstance(right_value, str))
            or (right_value == "__main__" and isinstance(left_value, str))
        ):
            return None
        equal = left_value == right_value
        return equal if isinstance(node.ops[0], ast.Eq) else not equal

    def widen_loop(environments: Collection[Env]) -> None:
        """Conservatively widen a loop whose finite abstraction did not settle."""
        for candidate in environments:
            for aliases in candidate.aliases.values():
                for root in aliases:
                    # A growing qualified path (``alias = alias.child``) has no
                    # finite height.  Invalidating the root subtree is sound and
                    # avoids treating an arbitrary iteration count as proof.
                    base = next(
                        (
                            watched
                            for watched in sorted(roots, key=len, reverse=True)
                            if root.path == watched or root.path.startswith(f"{watched}.")
                        ),
                        root.path,
                    )
                    record(base, subtree=True)

    def loop_fixed_point(entry: Env, transfer: Callable[[Env], None]) -> Env:
        """Compute the MAY loop-head state, widening if paths grow without bound."""
        head = entry.clone()
        # Alias roots, scalar logger names, and callable identities are finite
        # for ordinary loops.  The cap is only for synthetically growing dotted
        # paths; those are widened to their watched root below.
        limit = max(8, min(64, 4 * (len(head.aliases) + len(head.functions) + 1)))
        observed = [head.clone()]
        for _ in range(limit):
            body = head.clone()
            transfer(body)
            next_head = join_envs([entry, body])
            observed.append(next_head.clone())
            if env_equal(next_head, head):
                return next_head
            head = next_head
        widen_loop(observed)
        widened = join_envs(observed)
        for name in set().union(*(candidate.logger_constants.keys() for candidate in observed)):
            values = [candidate.logger_constants.get(name) for candidate in observed]
            if any(value != values[0] for value in values[1:]):
                widened.logger_constants[name] = None
        # Replay once through the widened scalar state.  In particular, a
        # logger name that grows/oscillates without convergence now produces
        # the global unknown cache group rather than a finite sample of names.
        widened_body = widened.clone()
        transfer(widened_body)
        return join_envs([widened, widened_body])

    def scan(
        statements: list[ast.stmt],
        env: Env,
        *,
        namespace: str = "module",
        may_skip: bool = False,
    ) -> None:
        for node in statements:
            if isinstance(node, ast.Return):
                if node.value is not None:
                    scan_expr(node.value, env)
                if active_return_summaries:
                    active_return_summaries[-1].append(expression_return_summary(node.value, env))
                continue
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                scan_headers(node, env)
                # A decorator may replace the function object; only a plain local
                # definition is safe to execute by static identity later.
                function = capture_callable(node, env) if not node.decorator_list else None
                if namespace == "module":
                    context_module = active_module_name()
                    target = f"{context_module}.{node.name}" if context_module else node.name
                    if not may_skip:
                        restore(target)
                bind_name(env, node.name, function=function)
                continue
            if isinstance(node, ast.ClassDef):
                scan_headers(node, env)
                class_env = env.clone()
                class_env.scope_kind = "class"
                global_names, _ = scope_declarations(node.body)
                scan(node.body, class_env, namespace="class", may_skip=may_skip)
                for name in global_names:
                    if name in class_env.aliases:
                        env.aliases[name] = class_env.aliases[name]
                    if name in class_env.structures:
                        env.structures[name] = class_env.structures[name]
                    if name in class_env.functions:
                        env.functions[name] = class_env.functions[name]
                    if name in class_env.generators:
                        env.generators[name] = class_env.generators[name]
                    if name in class_env.logger_constants:
                        env.logger_constants[name] = class_env.logger_constants[name]
                    if name in class_env.unknown_aliases:
                        env.unknown_aliases.add(name)
                    else:
                        env.unknown_aliases.discard(name)
                    if name in class_env.closed_scalars:
                        env.closed_scalars.add(name)
                    else:
                        env.closed_scalars.discard(name)
                if namespace == "module":
                    context_module = active_module_name()
                    class_path = f"{context_module}.{node.name}" if context_module else node.name
                    source_classes[class_path] = node
                    if not may_skip:
                        restore(class_path)
                    bind_name(env, node.name, frozenset({Root(class_path, True)}))
                else:
                    bind_name(env, node.name)
                continue
            if isinstance(node, ast.Expr):
                scan_expr(node.value, env)
                continue
            if isinstance(node, ast.Assign):
                scan_expr(node.value, env)
                for assignment_target in node.targets:
                    scan_store_evaluation(assignment_target, env)
                    record_attr_target(assignment_target, env)
                shared_logger_roots = logging_factory_roots(node.value, env)
                for assignment_target in node.targets:
                    bind_assignment_target(
                        assignment_target,
                        node.value,
                        env,
                        shared_logger_roots=shared_logger_roots,
                        shared_binding=len(node.targets) > 1,
                    )
                continue
            if isinstance(node, ast.AnnAssign):
                if not future_annotations:
                    scan_expr(node.annotation, env)
                if node.value is not None:
                    scan_expr(node.value, env)
                    scan_store_evaluation(node.target, env)
                    record_attr_target(node.target, env)
                    bind_assignment_target(
                        node.target,
                        node.value,
                        env,
                        shared_logger_roots=logging_factory_roots(node.value, env),
                    )
                continue
            if isinstance(node, ast.AugAssign):
                scan_expr(node.target, env)
                scan_expr(node.value, env)
                record_attr_target(node.target, env)
                invalidate_structural_target(
                    node.target,
                    env,
                    assignment_aliases(node.value, env),
                    mutation=True,
                )
                bind_target(node.target, env)
                continue
            if isinstance(node, ast.Delete):
                for deleted_target in node.targets:
                    scan_store_evaluation(deleted_target, env)
                    record_attr_target(deleted_target, env)
                    invalidate_structural_target(
                        deleted_target,
                        env,
                        mutation=not isinstance(deleted_target, ast.Name),
                    )
                    bind_target(deleted_target, env)
                continue
            if isinstance(node, ast.Import):
                for imported in node.names:
                    visible = imported.asname or imported.name.split(".", 1)[0]
                    import_target = imported.name if imported.asname else visible
                    bind_name(
                        env,
                        visible,
                        (
                            frozenset({Root(import_target)})
                            if root_is_watched(import_target)
                            else frozenset()
                        ),
                    )
                continue
            if isinstance(node, ast.ImportFrom):
                if node.module == "__future__" and not node.level:
                    continue
                base = resolve_import_from_base(node)
                for imported in node.names:
                    if imported.name == "*":
                        for name in list(env.aliases):
                            bind_name(env, name)
                        continue
                    import_target = f"{base}.{imported.name}" if base else imported.name
                    bind_name(
                        env,
                        imported.asname or imported.name,
                        (
                            frozenset({Root(import_target)})
                            if root_is_watched(import_target)
                            else frozenset()
                        ),
                    )
                continue
            if isinstance(node, ast.If):
                scan_expr(node.test, env)
                guard_truth = module_main_guard_truth(node.test, env)
                if guard_truth is not None:
                    scan(
                        node.body if guard_truth else node.orelse,
                        env,
                        namespace=namespace,
                        may_skip=may_skip,
                    )
                    continue
                entry = env.clone()
                body = entry.clone()
                scan(node.body, body, namespace=namespace, may_skip=True)
                alternative = entry.clone()
                scan(node.orelse, alternative, namespace=namespace, may_skip=True)
                replace_env(env, join_envs([body, alternative]))
                continue
            if isinstance(node, (ast.For, ast.AsyncFor)):
                scan_expr(node.iter, env)
                scan_deferred_iterable(node.iter, env)
                entry = env.clone()
                member_structure = iteration_structure(node.iter, entry)
                if member_structure is not None and structure_contains_mutable(member_structure):
                    escape_mutable_sources(node.iter, entry)
                    member_structure = escaped_structure(member_structure)
                iteration_roots = (
                    structure_aliases(member_structure)
                    if member_structure is not None
                    else iteration_aliases(node.iter, entry)
                )

                def transfer_for(body: Env) -> None:
                    bind_target(
                        node.target,
                        body,
                        iteration_roots,
                        closed_scalar=(
                            member_structure is not None
                            and not iteration_roots
                            and not structure_contains_mutable(member_structure)
                        ),
                        structure=member_structure,
                    )
                    scan(node.body, body, namespace=namespace, may_skip=True)

                loop_exit = loop_fixed_point(entry, transfer_for)
                alternative = loop_exit.clone()
                scan(node.orelse, alternative, namespace=namespace, may_skip=True)
                replace_env(env, join_envs([loop_exit, alternative]))
                continue
            if isinstance(node, ast.While):
                scan_expr(node.test, env)
                entry = env.clone()

                def transfer_while(body: Env) -> None:
                    scan(node.body, body, namespace=namespace, may_skip=True)
                    # The test is evaluated again after every non-breaking
                    # iteration and may itself rebind aliases via walrus/calls.
                    scan_expr(node.test, body)

                loop_exit = loop_fixed_point(entry, transfer_while)
                alternative = loop_exit.clone()
                scan(node.orelse, alternative, namespace=namespace, may_skip=True)
                replace_env(env, join_envs([loop_exit, alternative]))
                continue
            if isinstance(node, (ast.With, ast.AsyncWith)):
                entry = env.clone()
                body = entry.clone()
                for item in node.items:
                    scan_expr(item.context_expr, body)
                    if item.optional_vars is not None:
                        bind_target(item.optional_vars, body)
                scan(node.body, body, namespace=namespace, may_skip=True)
                replace_env(env, join_envs([entry, body]))
                continue
            if isinstance(node, (ast.Try, ast.TryStar)):
                entry = env.clone()
                body = entry.clone()
                scan(node.body, body, namespace=namespace, may_skip=True)
                normal = body.clone()
                scan(node.orelse, normal, namespace=namespace, may_skip=True)
                exits = [normal]
                for handler in node.handlers:
                    handled = entry.clone()
                    if handler.type is not None:
                        scan_expr(handler.type, handled)
                    if handler.name is not None:
                        bind_name(handled, handler.name)
                    scan(handler.body, handled, namespace=namespace, may_skip=True)
                    exits.append(handled)
                if node.finalbody:
                    final_exits: list[Env] = []
                    for possible in exits:
                        final = possible.clone()
                        scan(node.finalbody, final, namespace=namespace, may_skip=may_skip)
                        final_exits.append(final)
                    exits = final_exits
                replace_env(env, join_envs(exits))
                continue
            if isinstance(node, ast.Match):
                scan_expr(node.subject, env)
                entry = env.clone()
                exits = [entry]
                subject_aliases = assignment_aliases(node.subject, env)
                for case in node.cases:
                    branch = entry.clone()
                    for name in pattern_names(case.pattern):
                        bind_name(branch, name)
                    if (
                        isinstance(case.pattern, ast.MatchAs)
                        and case.pattern.pattern is None
                        and case.pattern.name is not None
                    ):
                        bind_name(branch, case.pattern.name, subject_aliases)
                    if case.guard is not None:
                        scan_expr(case.guard, branch)
                    scan(case.body, branch, namespace=namespace, may_skip=True)
                    exits.append(branch)
                replace_env(env, join_envs(exits))
                continue
            if isinstance(node, (ast.Global, ast.Nonlocal, ast.Pass, ast.Break, ast.Continue)):
                continue
            for expression in _statement_load_exprs(node):
                scan_expr(expression, env)

    initial = Env(
        {"__builtins__": frozenset({Root("builtins", tracked_object=True)})},
        {
            "__builtins__": StructuralValue(
                "root", frozenset({Root("builtins", tracked_object=True)})
            )
        },
        {},
        {},
        {"__name__": frozenset({module_name})},
        set(),
        {"__name__"},
        "module",
    )
    scan(tree.body, initial)
    return specific, unknown


def _statement_load_exprs(node: ast.stmt) -> list[ast.expr]:
    """Return the expressions a simple statement evaluates at module load.

    The direct expression children (an assignment RHS, a bare call, a test/iter,
    an annotation), plus ``with`` context expressions — but not nested statement
    bodies (walk recurses those) and not def/class headers (handled separately).
    """
    exprs = [child for child in ast.iter_child_nodes(node) if isinstance(child, ast.expr)]
    if isinstance(node, (ast.With, ast.AsyncWith)):
        exprs.extend(item.context_expr for item in node.items)
    return exprs


@dataclass
class _ExecutionScope:
    """Source-order names relevant to marker/effect proof in one executing scope."""

    aliases: dict[str, str | None]
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef | None]
    pending_markers: list[tuple[tuple[int, int, str], str, str]]
    scalars: dict[str, frozenset[_ScalarAtom]] = field(default_factory=dict)
    unknown_all_names: bool = False
    restored_names: set[str] = field(default_factory=set)
    walrus_parent: _ExecutionScope | None = None
    safe_classes: set[str] = field(default_factory=set)
    module_objects: set[str] = field(default_factory=set)

    def clone(self, *, walrus_parent: _ExecutionScope | None = None) -> _ExecutionScope:
        return _ExecutionScope(
            dict(self.aliases),
            dict(self.functions),
            list(self.pending_markers),
            dict(self.scalars),
            self.unknown_all_names,
            set(self.restored_names),
            walrus_parent,
            set(self.safe_classes),
            set(self.module_objects),
        )


@dataclass(frozen=True, slots=True)
class _ScalarAtom:
    """One exact immutable builtin scalar value proven from source."""

    runtime_type: type[object]
    value: object


_SCALAR_RUNTIME_TYPES = frozenset({bool, int, float, complex, str, bytes, type(None)})
_MAX_SCALAR_FACTS = 32


class _ModuleExecutionScanner:
    """Conservatively summarize module-load effects and exact marker sites."""

    def __init__(
        self,
        tree: ast.Module,
        project_mutations: ProjectMutations,
        project_modules: Collection[str],
        module_name: str = "",
        trusted_marker_sites: Collection[tuple[int, int, str]] = (),
        trusted_annotation_targets: Collection[str] = (),
        trusted_function_bindings: Mapping[str, ast.FunctionDef | ast.AsyncFunctionDef]
        | None = None,
    ) -> None:
        self.tree = tree
        self.module_name = module_name
        self.project_mutations = project_mutations
        self.project_modules = frozenset(project_modules)
        # A class-namespace binding replay is built from a synthetic module that
        # contains only the class body.  Its decorators still execute in the
        # enclosing module scope, so it cannot rediscover the enclosing import
        # aliases on its own.  The enclosing module authority may therefore pass
        # only marker sites it already proved at their real execution point.
        self.trusted_marker_sites = frozenset(trusted_marker_sites)
        self.trusted_annotation_targets = frozenset(trusted_annotation_targets)
        self.trusted_function_bindings = dict(trusted_function_bindings or {})
        self.effect_nodes: set[int] = set()
        self.proven_markers: set[tuple[int, int, str]] = set()
        self.future_annotations = any(
            isinstance(node, ast.ImportFrom)
            and node.module == "__future__"
            and not node.level
            and any(alias.name == "annotations" for alias in node.names)
            for node in tree.body
        )
        self._active_functions: set[int] = set()
        self._specific_effect_names: set[str] = set()
        self._unknown_effect_seen = False
        # An opaque module-load call can mutate builtins or imported module
        # attributes through ``vars(__import__(...))`` without leaving an AST
        # qualified-write trail.  A later import restores only the local name,
        # never the external object identity, so this poison is intentionally
        # irreversible for the module execution replay.
        self._external_identity_poisoned = False

    def scan(self) -> tuple[frozenset[int], frozenset[tuple[int, int, str]]]:
        scope = _ExecutionScope({}, dict(self.trusted_function_bindings), [])
        self._scan_statements(self.tree.body, scope, conditional=False)
        self._finalize_markers(scope)
        return frozenset(self.effect_nodes), frozenset(self.proven_markers)

    def _finalize_markers(self, scope: _ExecutionScope) -> None:
        for site, visible, expected in scope.pending_markers:
            if scope.aliases.get(visible) == expected:
                self.proven_markers.add(site)

    def _clear_unproven_names(
        self, scope: _ExecutionScope, *, external_identity: bool = True
    ) -> None:
        for name in list(scope.aliases):
            scope.aliases[name] = None
        for name in list(scope.functions):
            scope.functions[name] = None
        scope.scalars.clear()
        scope.safe_classes.clear()
        scope.module_objects.clear()
        scope.unknown_all_names = True
        scope.restored_names.clear()
        if external_identity:
            self._external_identity_poisoned = True

    @staticmethod
    def _name_is_unknown(scope: _ExecutionScope, name: str) -> bool:
        return scope.unknown_all_names and name not in scope.restored_names

    def _builtin_is_exact(self, scope: _ExecutionScope, name: str) -> bool:
        """Whether a bare spelling is the exact untouched builtin object."""
        return (
            name not in scope.aliases
            and name not in scope.functions
            and name not in scope.scalars
            and not self._name_is_unknown(scope, name)
            and not self._external_identity_poisoned
            and not self.project_mutations.target_is_mutated(f"builtins.{name}")
        )

    def _target_is_project_owned(self, target: str) -> bool:
        return any(
            target == module or target.startswith(f"{module}.") for module in self.project_modules
        )

    @staticmethod
    def _scalar_atom(value: object) -> _ScalarAtom | None:
        runtime_type = type(value)
        if runtime_type not in _SCALAR_RUNTIME_TYPES:
            return None
        if runtime_type is int and isinstance(value, int) and value.bit_length() > 256:
            return None
        if isinstance(value, (str, bytes)) and len(value) > 4096:
            return None
        return _ScalarAtom(runtime_type, value)

    @staticmethod
    def _bounded_scalar_facts(values: Collection[_ScalarAtom]) -> frozenset[_ScalarAtom]:
        facts = frozenset(values)
        return facts if len(facts) <= _MAX_SCALAR_FACTS else frozenset()

    def _scalar_facts(
        self,
        node: ast.expr,
        scope: _ExecutionScope,
    ) -> frozenset[_ScalarAtom]:
        """Return exact builtin-scalar results for a deliberately closed grammar."""
        if isinstance(node, ast.Constant):
            atom = self._scalar_atom(node.value)
            return frozenset({atom}) if atom is not None else frozenset()
        if isinstance(node, ast.Name):
            if node.id == "__name__" and (
                node.id not in scope.aliases
                and node.id not in scope.functions
                and node.id not in scope.scalars
                and not self._name_is_unknown(scope, node.id)
            ):
                # The exact module name varies by import context, but its runtime
                # type is an exact builtin str.  An empty spelling is sufficient
                # for type/protocol proof; do not use it for index selection.
                return frozenset({_ScalarAtom(str, self.module_name or "__main__")})
            return scope.scalars.get(node.id, frozenset())
        if isinstance(node, ast.UnaryOp):
            operand = self._scalar_facts(node.operand, scope)
            unary_operations: dict[type[ast.unaryop], Callable[..., object]] = {
                ast.UAdd: operator.pos,
                ast.USub: operator.neg,
                ast.Invert: operator.invert,
                ast.Not: operator.not_,
            }
            operation = unary_operations.get(type(node.op))
            if not operand or operation is None:
                return frozenset()
            unary_results: list[_ScalarAtom] = []
            for atom in operand:
                try:
                    result = operation(atom.value)
                except (ArithmeticError, TypeError, ValueError):
                    return frozenset()
                converted = self._scalar_atom(result)
                if converted is None:
                    return frozenset()
                unary_results.append(converted)
            return self._bounded_scalar_facts(unary_results)
        if isinstance(node, ast.BinOp):
            left = self._scalar_facts(node.left, scope)
            right = self._scalar_facts(node.right, scope)
            operation = {
                ast.Add: operator.add,
                ast.Sub: operator.sub,
                ast.Mult: operator.mul,
                ast.Div: operator.truediv,
                ast.FloorDiv: operator.floordiv,
                ast.Mod: operator.mod,
                ast.Pow: operator.pow,
                ast.LShift: operator.lshift,
                ast.RShift: operator.rshift,
                ast.BitOr: operator.or_,
                ast.BitXor: operator.xor,
                ast.BitAnd: operator.and_,
            }.get(type(node.op))
            if not left or not right or operation is None:
                return frozenset()
            binary_results: list[_ScalarAtom] = []
            for left_atom in left:
                for right_atom in right:
                    if isinstance(node.op, ast.Pow) and isinstance(right_atom.value, int):
                        if abs(right_atom.value) > 64:
                            return frozenset()
                    if isinstance(node.op, (ast.LShift, ast.RShift)) and isinstance(
                        right_atom.value, int
                    ):
                        if not 0 <= right_atom.value <= 256:
                            return frozenset()
                    if isinstance(node.op, ast.Mult):
                        string_value: str | bytes | None = None
                        repeat: int | None = None
                        if isinstance(left_atom.value, (str, bytes)) and isinstance(
                            right_atom.value, int
                        ):
                            string_value, repeat = left_atom.value, right_atom.value
                        elif isinstance(right_atom.value, (str, bytes)) and isinstance(
                            left_atom.value, int
                        ):
                            string_value, repeat = right_atom.value, left_atom.value
                        if (
                            string_value is not None
                            and repeat is not None
                            and len(string_value) * max(repeat, 0) > 4096
                        ):
                            return frozenset()
                    try:
                        result = operation(left_atom.value, right_atom.value)
                    except (ArithmeticError, TypeError, ValueError):
                        return frozenset()
                    converted = self._scalar_atom(result)
                    if converted is None:
                        return frozenset()
                    binary_results.append(converted)
            return self._bounded_scalar_facts(binary_results)
        if isinstance(node, ast.IfExp):
            tests = self._scalar_facts(node.test, scope)
            if not tests:
                return frozenset()
            outcomes = {bool(atom.value) for atom in tests}
            values: set[_ScalarAtom] = set()
            if True in outcomes:
                values.update(self._scalar_facts(node.body, scope))
            if False in outcomes:
                values.update(self._scalar_facts(node.orelse, scope))
            return self._bounded_scalar_facts(values)
        if isinstance(node, ast.Subscript):
            indexes = self._scalar_facts(node.slice, scope)
            if not indexes:
                return frozenset()
            selected: list[ast.expr] = []
            if isinstance(node.value, (ast.List, ast.Tuple)):
                elements = node.value.elts
                for index in indexes:
                    if index.runtime_type is not int:
                        return frozenset()
                    position = index.value
                    if not isinstance(position, int):
                        return frozenset()
                    if not -len(elements) <= position < len(elements):
                        return frozenset()
                    element = elements[position]
                    if isinstance(element, ast.Starred):
                        return frozenset()
                    selected.append(element)
            elif isinstance(node.value, ast.Dict):
                for index in indexes:
                    match: ast.expr | None = None
                    for key, value in zip(node.value.keys, node.value.values, strict=True):
                        if not isinstance(key, ast.Constant):
                            continue
                        if type(key.value) is index.runtime_type and key.value == index.value:
                            match = value
                    if match is None:
                        return frozenset()
                    selected.append(match)
            elif isinstance(node.value, ast.Constant):
                container = node.value.value
                if not isinstance(container, (str, bytes)):
                    return frozenset()
                scalar_results: list[_ScalarAtom] = []
                for index in indexes:
                    if index.runtime_type is not int or not isinstance(index.value, int):
                        return frozenset()
                    try:
                        selected_value = container[index.value]
                    except (IndexError, TypeError):
                        return frozenset()
                    atom = self._scalar_atom(selected_value)
                    if atom is None:
                        return frozenset()
                    scalar_results.append(atom)
                return self._bounded_scalar_facts(scalar_results)
            else:
                return frozenset()
            facts: set[_ScalarAtom] = set()
            for element in selected:
                element_facts = self._scalar_facts(element, scope)
                if not element_facts:
                    return frozenset()
                facts.update(element_facts)
            return self._bounded_scalar_facts(facts)
        return frozenset()

    def _bind_execution_name(
        self,
        scope: _ExecutionScope,
        name: str,
        alias: str | None,
        function: ast.FunctionDef | ast.AsyncFunctionDef | None,
        scalars: frozenset[_ScalarAtom] = frozenset(),
        *,
        conditional: bool,
    ) -> None:
        scope.aliases[name] = None if conditional else alias
        scope.functions[name] = None if conditional else function
        scope.safe_classes.discard(name)
        scope.module_objects.discard(name)
        if conditional or not scalars:
            scope.scalars.pop(name, None)
        else:
            scope.scalars[name] = scalars
        if not conditional:
            scope.restored_names.add(name)

    def _marker_identity(
        self, decorator: ast.expr, scope: _ExecutionScope
    ) -> tuple[str, str, str] | None:
        if self._external_identity_poisoned:
            return None
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = dotted_name(target)
        if name is None:
            return None
        visible, separator, tail = name.partition(".")
        expected = scope.aliases.get(visible)
        if expected is None:
            return None
        resolved = f"{expected}.{tail}" if separator else expected
        if resolved not in {"rextio.native", "rextio.exempt"}:
            return None
        kind = resolved.rsplit(".", 1)[1]
        if "rextio" in self.project_modules:
            return None
        if self.project_mutations.target_is_mutated(f"rextio.{kind}"):
            return None
        return kind, visible, expected

    def _expressions_have_effect(
        self, expressions: Collection[ast.AST], scope: _ExecutionScope
    ) -> bool:
        """Scan every evaluated expression, without state-losing short circuit."""
        effect = False
        for expression in expressions:
            if self._expr_has_effect(expression, scope):
                effect = True
        return effect

    def _decorator_is_pure(self, decorator: ast.expr, scope: _ExecutionScope) -> bool:
        for kind in ("native", "exempt"):
            site = (
                getattr(decorator, "lineno", -1),
                getattr(decorator, "col_offset", -1),
                kind,
            )
            if site not in self.trusted_marker_sites:
                continue
            if isinstance(decorator, ast.Call):
                if self._expressions_have_effect(
                    [*decorator.args, *(keyword.value for keyword in decorator.keywords)],
                    scope,
                ):
                    return False
            self.proven_markers.add(site)
            return True
        identity = self._marker_identity(decorator, scope)
        if identity is not None:
            kind, visible, expected = identity
            # Decorator-call arguments are evaluated before the decorator is
            # applied.  A valid marker uses literals, but scan them defensively so
            # malformed ``@native(target=mutate())`` cannot hide an effect.
            if isinstance(decorator, ast.Call):
                if self._expressions_have_effect(
                    [*decorator.args, *(keyword.value for keyword in decorator.keywords)],
                    scope,
                ):
                    return False
            site = (
                getattr(decorator, "lineno", -1),
                getattr(decorator, "col_offset", -1),
                kind,
            )
            # Execution-time identity is irreversible: once the real decorator
            # has been applied, a later unknown effect cannot turn that already
            # decorated function into an undecorated one.  The final explicit
            # import/binder check remains in ``marker_decorator_is_proven``.
            self.proven_markers.add(site)
            scope.pending_markers.append((site, visible, expected))
            return True
        imports = {name: target for name, target in scope.aliases.items() if target is not None}
        if decorator_resolves_to_accelerator(decorator, imports):
            raw_accelerator = dotted_name(
                decorator.func if isinstance(decorator, ast.Call) else decorator
            )
            if raw_accelerator is None or self._external_identity_poisoned:
                return False
            head, separator, tail = raw_accelerator.partition(".")
            imported = imports.get(head)
            accelerator_target = (
                f"{imported}.{tail}" if imported is not None and separator else imported
            )
            if (
                accelerator_target is None
                or self._target_is_project_owned(accelerator_target)
                or self.project_mutations.target_is_mutated(accelerator_target)
            ):
                return False
            if isinstance(decorator, ast.Call):
                return not self._expressions_have_effect(
                    [
                        *decorator.args,
                        *(keyword.value for keyword in decorator.keywords),
                    ],
                    scope,
                )
            return True
        decorator_target = decorator.func if isinstance(decorator, ast.Call) else decorator
        raw = dotted_name(decorator_target)
        if raw is not None:
            head, separator, tail = raw.partition(".")
            bound = scope.aliases.get(head)
            if bound is not None:
                resolved = f"{bound}.{tail}" if separator else bound
            elif self._builtin_is_exact(scope, head):
                resolved = f"builtins.{raw}"
            else:
                resolved = ""
            if resolved in {
                "builtins.staticmethod",
                "builtins.classmethod",
                "builtins.property",
                "functools.cached_property",
            }:
                if resolved.startswith("builtins."):
                    if not self._builtin_is_exact(scope, resolved.rsplit(".", 1)[1]):
                        return False
                elif (
                    self._external_identity_poisoned
                    or self._target_is_project_owned(resolved)
                    or self.project_mutations.target_is_mutated(resolved)
                ):
                    return False
                if isinstance(decorator, ast.Call):
                    return not self._expressions_have_effect(
                        [
                            *decorator.args,
                            *(keyword.value for keyword in decorator.keywords),
                        ],
                        scope,
                    )
                return True
        return False

    @staticmethod
    def _literal_exec_names(source: object) -> set[str] | None:
        if not isinstance(source, str):
            return None
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return None
        names: set[str] = set()

        def safe_expr(node: ast.expr) -> bool:
            if isinstance(node, ast.Constant):
                return True
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                return True
            if isinstance(node, ast.Lambda):
                return all(
                    default is None or safe_expr(default)
                    for default in (*node.args.defaults, *node.args.kw_defaults)
                )
            if isinstance(node, (ast.Tuple, ast.List)):
                return all(
                    not isinstance(element, ast.Starred) and safe_expr(element)
                    for element in node.elts
                )
            if isinstance(node, ast.Set):
                return all(isinstance(element, ast.Constant) for element in node.elts)
            if isinstance(node, ast.Dict):
                return all(
                    isinstance(key, ast.Constant) and safe_expr(value)
                    for key, value in zip(node.keys, node.values, strict=True)
                )
            return False

        for statement in tree.body:
            if isinstance(statement, ast.Pass):
                continue
            if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant):
                continue
            if isinstance(statement, ast.Assign):
                if not safe_expr(statement.value) or not all(
                    isinstance(target, ast.Name) for target in statement.targets
                ):
                    return None
                names.update(
                    target.id for target in statement.targets if isinstance(target, ast.Name)
                )
                continue
            return None
        return names

    def _operator_operand_is_proven_safe(
        self,
        node: ast.expr,
        scope: _ExecutionScope,
    ) -> bool:
        """Whether an operator operand has a closed builtin scalar runtime type."""
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, ast.Name):
            if self._scalar_facts(node, scope):
                return True
            imported = scope.aliases.get(node.id)
            if (
                imported is not None
                and imported.startswith("typing.")
                and not self._external_identity_poisoned
                and not self._target_is_project_owned(imported)
                and not self.project_mutations.target_is_mutated(imported)
            ):
                return True
            return node.id in {
                "bool",
                "bytes",
                "complex",
                "dict",
                "float",
                "frozenset",
                "int",
                "list",
                "object",
                "set",
                "str",
                "tuple",
                "type",
            } and self._builtin_is_exact(scope, node.id)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return all(
                not isinstance(element, ast.Starred)
                and self._operator_operand_is_proven_safe(element, scope)
                for element in node.elts
            )
        if isinstance(node, ast.Subscript):
            # Safe ``__getitem__`` dispatch does not establish the selected
            # value's runtime type.  Only an exact scalar selected from a closed
            # literal/value shape is safe for a later operator/format/hash call.
            # The one non-scalar exception is an exact PEP 585 builtin generic
            # alias: ``list[int]`` has the fixed ``types.GenericAlias`` runtime
            # type, so a later PEP 604 ``list[int] | None`` cannot dispatch to
            # user code. Do not generalize this to arbitrary safe subscriptions.
            return bool(self._scalar_facts(node, scope)) or (
                isinstance(node.value, ast.Name)
                and node.value.id in {"dict", "frozenset", "list", "set", "tuple", "type"}
                and self._builtin_is_exact(scope, node.value.id)
            )
        if isinstance(node, ast.UnaryOp):
            return bool(self._scalar_facts(node, scope))
        if isinstance(node, ast.BinOp):
            return bool(self._scalar_facts(node, scope))
        if isinstance(node, ast.IfExp):
            return bool(self._scalar_facts(node, scope))
        if isinstance(node, ast.JoinedStr):
            return all(
                isinstance(value, ast.Constant)
                or (
                    isinstance(value, ast.FormattedValue)
                    and self._operator_operand_is_proven_safe(value.value, scope)
                )
                for value in node.values
            )
        return False

    def _subscript_protocol_is_proven_safe(
        self,
        node: ast.Subscript,
        scope: _ExecutionScope,
    ) -> bool:
        """Whether subscription cannot invoke user ``__getitem__``/``__index__``."""
        if (
            isinstance(node.value, ast.Name)
            and node.value.id in {"dict", "frozenset", "list", "set", "tuple", "type"}
            and self._builtin_is_exact(scope, node.value.id)
        ):
            # PEP 585 subscriptions on exact builtin generic classes dispatch to
            # their fixed ``__class_getitem__`` and pass the slice object through;
            # they do not invoke ``__index__`` or another hook on that object.
            # Child evaluation was scanned before this proof, so nested forms such
            # as ``list[list[int]]`` remain clean while a call/effect in the slice
            # is still observed normally.
            return True

        def safe_slice(value: ast.expr) -> bool:
            if isinstance(value, ast.Slice):
                return all(
                    part is None or self._operator_operand_is_proven_safe(part, scope)
                    for part in (value.lower, value.upper, value.step)
                )
            return self._operator_operand_is_proven_safe(value, scope)

        if not safe_slice(node.slice):
            return False
        if isinstance(node.value, ast.Constant):
            return True
        if isinstance(node.value, (ast.List, ast.Tuple)):
            return not any(isinstance(element, ast.Starred) for element in node.value.elts)
        if isinstance(node.value, ast.Dict):
            return all(key is not None for key in node.value.keys)
        if isinstance(node.value, ast.JoinedStr):
            return True
        if isinstance(node.value, ast.Name):
            return self._operator_operand_is_proven_safe(node.value, scope)
        return False

    def _range_call_is_proven_safe(
        self,
        node: ast.Call,
        scope: _ExecutionScope,
    ) -> bool:
        if (
            not isinstance(node.func, ast.Name)
            or node.func.id != "range"
            or not self._builtin_is_exact(scope, "range")
            or node.keywords
            or not 1 <= len(node.args) <= 3
        ):
            return False
        for argument in node.args:
            if isinstance(argument, ast.Starred):
                return False
            facts = self._scalar_facts(argument, scope)
            if not facts or any(atom.runtime_type not in {int, bool} for atom in facts):
                # ``range`` otherwise invokes arbitrary ``__index__`` hooks.
                return False
        return True

    def _trusted_annotation_subscript_has_effect(
        self,
        node: ast.expr,
        scope: _ExecutionScope,
    ) -> bool | None:
        """Return the effect of a registered plugin annotation subscription.

        ``None`` means the expression is not the exact subscription of an
        active plugin type-vocabulary target. Plugin providers are already a
        trusted build input; their declared annotation constructors form the
        narrow purity contract needed for API 1.3 ``Frame[Schema]``. The slice
        is still scanned normally, so ``Frame[mutate()]`` remains effectful.
        This exemption is called only for evaluated function annotations, never
        for an arbitrary module-level ``Frame[...]`` expression.
        """
        if not isinstance(node, ast.Subscript):
            return None
        raw = dotted_name(node.value)
        if raw is None:
            return None
        head, separator, tail = raw.partition(".")
        imported = scope.aliases.get(head)
        if imported is None:
            return None
        resolved = f"{imported}.{tail}" if separator else imported
        if (
            resolved not in self.trusted_annotation_targets
            or self._external_identity_poisoned
            or any(
                resolved == project_module or resolved.startswith(f"{project_module}.")
                for project_module in self.project_modules
            )
            or self.project_mutations.target_is_mutated(resolved)
        ):
            return None
        return self._expr_has_effect(node.slice, scope)

    def _annotation_has_effect(
        self,
        node: ast.expr,
        scope: _ExecutionScope,
    ) -> bool:
        trusted = self._trusted_annotation_subscript_has_effect(node, scope)
        if trusted is not None:
            return trusted
        return self._expr_has_effect(node, scope)

    def _comprehension_has_effect(
        self,
        node: ast.ListComp | ast.SetComp | ast.DictComp,
        scope: _ExecutionScope,
    ) -> bool:
        effect = False
        local = scope.clone(walrus_parent=scope.walrus_parent or scope)
        for generator in node.generators:
            if self._expr_has_effect(generator.iter, local):
                effect = True
            if not self._iterable_protocol_is_proven_safe(generator.iter, local):
                self._unknown_effect_seen = True
                effect = True
            if not isinstance(generator.target, ast.Name):
                self._unknown_effect_seen = True
                effect = True
            else:
                scalar_values: set[_ScalarAtom] = set()
                if isinstance(generator.iter, (ast.List, ast.Tuple, ast.Set)):
                    for element in generator.iter.elts:
                        value = element.value if isinstance(element, ast.Starred) else element
                        facts = self._scalar_facts(value, local)
                        if not facts:
                            scalar_values.clear()
                            break
                        scalar_values.update(facts)
                self._bind_execution_name(
                    local,
                    generator.target.id,
                    None,
                    None,
                    self._bounded_scalar_facts(scalar_values),
                    conditional=False,
                )
            for condition in generator.ifs:
                if self._expr_has_effect(condition, local):
                    effect = True
                if not self._truth_protocol_is_proven_safe(condition, local):
                    self._unknown_effect_seen = True
                    effect = True
        outputs: list[ast.expr]
        if isinstance(node, ast.DictComp):
            outputs = [node.key, node.value]
        else:
            outputs = [node.elt]
        if self._expressions_have_effect(outputs, local):
            effect = True
        insertion_key: ast.expr | None = None
        if isinstance(node, ast.SetComp):
            insertion_key = node.elt
        elif isinstance(node, ast.DictComp):
            insertion_key = node.key
        if insertion_key is not None and not self._operator_operand_is_proven_safe(
            insertion_key, local
        ):
            # Set/dict insertion can execute both ``__hash__`` and ``__eq__``.
            self._unknown_effect_seen = True
            effect = True
        return effect

    def _expr_has_effect(self, node: ast.AST, scope: _ExecutionScope) -> bool:
        if isinstance(node, ast.Lambda):
            return self._expressions_have_effect(
                [
                    default
                    for default in (*node.args.defaults, *node.args.kw_defaults)
                    if default is not None
                ],
                scope,
            )
        if isinstance(node, ast.GeneratorExp):
            # Creating a generator evaluates only the outermost iterable; its
            # element, filters, and nested iterables are deferred until iteration,
            # but obtaining that outer iterator already dispatches ``__iter__``.
            if not node.generators:
                return False
            outer = node.generators[0].iter
            effect = self._expr_has_effect(outer, scope)
            if not self._iterable_protocol_is_proven_safe(outer, scope):
                self._unknown_effect_seen = True
                return True
            return effect
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp)):
            return self._comprehension_has_effect(node, scope)
        if isinstance(node, ast.NamedExpr):
            effect = self._expr_has_effect(node.value, scope)
            destination = scope.walrus_parent or scope
            alias, function = self._assignment_value_binding(node.value, scope)
            self._bind_target(
                node.target,
                destination,
                alias,
                function,
                self._scalar_facts(node.value, scope),
                conditional=False,
            )
            return effect
        if isinstance(node, (ast.List, ast.Tuple)):
            effect = False
            for element in node.elts:
                value = element.value if isinstance(element, ast.Starred) else element
                if self._expr_has_effect(value, scope):
                    effect = True
                if isinstance(element, ast.Starred) and not self._iterable_protocol_is_proven_safe(
                    value, scope
                ):
                    self._unknown_effect_seen = True
                    effect = True
            return effect
        if isinstance(node, ast.Set):
            effect = self._expressions_have_effect(node.elts, scope)
            if any(
                not self._operator_operand_is_proven_safe(element, scope) for element in node.elts
            ):
                self._unknown_effect_seen = True
                return True
            return effect
        if isinstance(node, ast.Dict):
            effect = self._expressions_have_effect(
                [*node.values, *(key for key in node.keys if key is not None)], scope
            )
            for key, value in zip(node.keys, node.values, strict=True):
                if key is None:
                    if not isinstance(value, ast.Dict):
                        self._unknown_effect_seen = True
                        effect = True
                elif not self._operator_operand_is_proven_safe(key, scope):
                    self._unknown_effect_seen = True
                    effect = True
            return effect
        if isinstance(node, ast.BinOp):
            effect = self._expressions_have_effect([node.left, node.right], scope)
            if not all(
                self._operator_operand_is_proven_safe(operand, scope)
                for operand in (node.left, node.right)
            ):
                self._unknown_effect_seen = True
                return True
            return effect
        if isinstance(node, ast.UnaryOp):
            effect = self._expr_has_effect(node.operand, scope)
            safe = (
                self._truth_protocol_is_proven_safe(node.operand, scope)
                if isinstance(node.op, ast.Not)
                else self._operator_operand_is_proven_safe(node.operand, scope)
            )
            if not safe:
                self._unknown_effect_seen = True
                return True
            return effect
        if isinstance(node, ast.BoolOp):
            effect = self._expressions_have_effect(node.values, scope)
            if any(
                not self._truth_protocol_is_proven_safe(value, scope) for value in node.values[:-1]
            ):
                self._unknown_effect_seen = True
                return True
            return effect
        if isinstance(node, ast.IfExp):
            effect = self._expressions_have_effect([node.test, node.body, node.orelse], scope)
            if not self._truth_protocol_is_proven_safe(node.test, scope):
                self._unknown_effect_seen = True
                return True
            return effect
        if isinstance(node, ast.Compare):
            operands = [node.left, *node.comparators]
            effect = self._expressions_have_effect(operands, scope)
            identity_only = all(isinstance(operator, (ast.Is, ast.IsNot)) for operator in node.ops)
            if not identity_only and not all(
                self._operator_operand_is_proven_safe(operand, scope) for operand in operands
            ):
                self._unknown_effect_seen = True
                return True
            return effect
        if isinstance(node, ast.FormattedValue):
            expressions = [node.value]
            if node.format_spec is not None:
                expressions.append(node.format_spec)
            effect = self._expressions_have_effect(expressions, scope)
            if not self._operator_operand_is_proven_safe(node.value, scope):
                self._unknown_effect_seen = True
                return True
            return effect
        if isinstance(node, ast.JoinedStr):
            return self._expressions_have_effect(node.values, scope)
        if isinstance(node, ast.Attribute):
            child_effect = self._expr_has_effect(node.value, scope)
            if not isinstance(node.ctx, ast.Load):
                raw_receiver = dotted_name(node.value)
                if raw_receiver is not None:
                    head = raw_receiver.split(".", 1)[0]
                    if head in scope.safe_classes or scope.aliases.get(head) is not None:
                        # Exact plain classes use ``type.__setattr__`` and exact
                        # imported modules use ``ModuleType.__setattr__``.  The
                        # qualified mutation pass records the actual target.
                        return child_effect
                # STORE_ATTR/DELETE_ATTR invoke arbitrary
                # ``__setattr__``/``__delattr__`` hooks on unknown receivers.
                # Qualified module/class writes are also summarized by the
                # mutation authority, but that does not prove the protocol hook
                # itself effect-free.
                self._unknown_effect_seen = True
                return True
            raw = dotted_name(node)
            if raw is not None:
                head, separator, tail = raw.partition(".")
                imported = scope.aliases.get(head)
                if imported is not None:
                    target = f"{imported}.{tail}" if separator else imported
                    if (
                        not self._external_identity_poisoned
                        and not self._target_is_project_owned(target)
                        and not self.project_mutations.target_is_mutated(target)
                    ):
                        return child_effect
            # Attribute lookup on a local/unknown object can execute arbitrary
            # ``__getattribute__``/descriptor/``__getattr__`` code.
            self._unknown_effect_seen = True
            return True
        if isinstance(node, ast.Subscript):
            child_effect = self._expressions_have_effect([node.value, node.slice], scope)
            if self._subscript_protocol_is_proven_safe(node, scope):
                return child_effect
            self._unknown_effect_seen = True
            return True
        if isinstance(node, ast.Call):
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr in {"__setitem__", "__delitem__"}
                and isinstance(node.func.value, ast.Call)
                and isinstance(node.func.value.func, ast.Name)
                and node.func.value.func.id == "globals"
                and self._builtin_is_exact(scope, "globals")
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                self._expressions_have_effect(
                    [*node.args[1:], *(keyword.value for keyword in node.keywords)],
                    scope,
                )
                self._specific_effect_names.add(node.args[0].value)
                return True
            child_effect = self._expr_has_effect(node.func, scope)
            if self._expressions_have_effect(
                [*node.args, *(keyword.value for keyword in node.keywords)], scope
            ):
                child_effect = True
            for argument in node.args:
                if isinstance(argument, ast.Starred) and not self._iterable_protocol_is_proven_safe(
                    argument.value, scope
                ):
                    self._unknown_effect_seen = True
                    child_effect = True
            for keyword in node.keywords:
                if keyword.arg is None and not isinstance(keyword.value, ast.Dict):
                    self._unknown_effect_seen = True
                    child_effect = True
            if (
                isinstance(node.func, ast.Name)
                and node.func.id == "exec"
                and node.args
                and self._builtin_is_exact(scope, "exec")
            ):
                source = node.args[0]
                names = (
                    self._literal_exec_names(source.value)
                    if isinstance(source, ast.Constant)
                    else None
                )
                if names is not None:
                    self._specific_effect_names.update(names)
                    return child_effect or bool(names)
                self._unknown_effect_seen = True
                return True
            if (
                isinstance(node.func, ast.Name)
                and node.func.id in {"setattr", "delattr"}
                and self._builtin_is_exact(scope, node.func.id)
            ):
                receiver = node.args[0] if node.args else None
                receiver_name = dotted_name(receiver) if receiver is not None else None
                if receiver_name is not None:
                    head = receiver_name.split(".", 1)[0]
                    if head in scope.safe_classes or scope.aliases.get(head) is not None:
                        return child_effect
                self._unknown_effect_seen = True
                return True
            if self._range_call_is_proven_safe(node, scope):
                return child_effect
            descriptor_target: str | None = None
            if isinstance(node.func, ast.Name):
                if node.func.id in {"staticmethod", "classmethod", "property"} and (
                    self._builtin_is_exact(scope, node.func.id)
                ):
                    descriptor_target = f"builtins.{node.func.id}"
                elif scope.aliases.get(node.func.id) in {
                    "builtins.staticmethod",
                    "builtins.classmethod",
                    "builtins.property",
                }:
                    descriptor_target = scope.aliases[node.func.id]
            if (
                descriptor_target is not None
                and not self._external_identity_poisoned
                and not self.project_mutations.target_is_mutated(descriptor_target)
                and len(node.args) == 1
                and not node.keywords
                and isinstance(node.args[0], ast.Name)
                and scope.functions.get(node.args[0].id) is not None
            ):
                # Descriptor constructors are safe only for an exact, freshly
                # created function object.  Arbitrary objects can run metadata
                # hooks (notably ``property`` reading ``__doc__``).
                return child_effect
            if (
                isinstance(node.func, ast.Name)
                and node.func.id in scope.safe_classes
                and not node.args
                and not node.keywords
            ):
                return child_effect
            raw_call = dotted_name(node.func)
            if raw_call is not None:
                head, separator, tail = raw_call.partition(".")
                imported = scope.aliases.get(head)
                resolved = f"{imported}.{tail}" if imported is not None and separator else imported
                if (
                    resolved == "logging.getLogger"
                    and "logging" not in self.project_modules
                    and not self._external_identity_poisoned
                    and not self.project_mutations.target_is_mutated(resolved)
                ):
                    return child_effect
            if isinstance(node.func, ast.Lambda):
                lambda_scope = scope.clone()
                parameters = [
                    *node.func.args.posonlyargs,
                    *node.func.args.args,
                    *node.func.args.kwonlyargs,
                    *((node.func.args.vararg,) if node.func.args.vararg else ()),
                    *((node.func.args.kwarg,) if node.func.args.kwarg else ()),
                ]
                for parameter in parameters:
                    self._bind_execution_name(
                        lambda_scope, parameter.arg, None, None, conditional=False
                    )
                return self._expr_has_effect(node.func.body, lambda_scope) or child_effect
            if isinstance(node.func, ast.Name):
                called_function = scope.functions.get(node.func.id)
                if called_function is not None:
                    summary = self._called_function_global_effects(called_function, scope)
                    if summary is not None:
                        self._specific_effect_names.update(summary)
                        return child_effect or bool(summary)
                    self._unknown_effect_seen = True
                    # ``None`` is explicitly the fail-closed summary.  Do not
                    # let a second, narrower boolean walker turn the already
                    # unknown call back into an effect-free statement.
                    self._called_function_has_effect(called_function, scope)
                    return True
            # Every other executed call is unproven.  This deliberately includes
            # imported calls and builtin spellings: user arguments/protocol hooks
            # can run arbitrary code, so purity requires a closed proof.
            self._unknown_effect_seen = True
            return True
        effect = False
        for child in ast.iter_child_nodes(node):
            if self._expr_has_effect(child, scope):
                effect = True
        return effect

    def _called_function_global_effects(
        self,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
        module_scope: _ExecutionScope,
    ) -> set[str] | None:
        """Return exact global names rebound by a proven local call, or unknown.

        This intentionally recognizes only a closed, auditable subset.  It is
        enough to keep an unrelated exact Rextio import proven for a local
        ``globals()['good'] = ...`` mutator while every opaque call remains an
        unknown-all effect.
        """
        identity = id(function)
        if identity in self._active_functions:
            return None
        self._active_functions.add(identity)
        try:
            global_names: set[str] = set()
            for statement in function.body:
                if isinstance(statement, ast.Global):
                    global_names.update(statement.names)

            analysis_scope = module_scope.clone()
            local_names = {
                argument.arg
                for argument in (
                    *function.args.posonlyargs,
                    *function.args.args,
                    *function.args.kwonlyargs,
                    *((function.args.vararg,) if function.args.vararg else ()),
                    *((function.args.kwarg,) if function.args.kwarg else ()),
                )
            }
            local_names.update(
                child.id
                for statement in function.body
                for child in ast.walk(statement)
                if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store)
            )
            for name in local_names - global_names:
                self._bind_execution_name(analysis_scope, name, None, None, conditional=False)

            def expr_summary(node: ast.AST) -> set[str] | None:
                if isinstance(node, ast.GeneratorExp):
                    # Constructing a generator evaluates only its outermost
                    # iterable.  The element, filters, targets and nested
                    # iterables remain deferred until somebody iterates it.
                    if not node.generators:
                        return set()
                    return expr_summary(node.generators[0].iter)
                if isinstance(node, ast.Lambda):
                    lambda_effects: set[str] = set()
                    for default in (*node.args.defaults, *node.args.kw_defaults):
                        if default is None:
                            continue
                        part = expr_summary(default)
                        if part is None:
                            return None
                        lambda_effects.update(part)
                    return lambda_effects
                if isinstance(node, ast.Call):
                    if (
                        isinstance(node.func, ast.Name)
                        and node.func.id in {"object", "vars"}
                        and not node.args
                        and not node.keywords
                        and self._builtin_is_exact(analysis_scope, node.func.id)
                    ):
                        # ``object()`` is an exact hook-free constructor, and
                        # zero-argument ``vars()`` here denotes this function's
                        # locals rather than the defining module namespace.
                        return set()
                    if (
                        isinstance(node.func, ast.Attribute)
                        and node.func.attr in {"__setitem__", "__delitem__"}
                        and isinstance(node.func.value, ast.Call)
                        and isinstance(node.func.value.func, ast.Name)
                        and node.func.value.func.id == "globals"
                        and node.args
                        and isinstance(node.args[0], ast.Constant)
                        and isinstance(node.args[0].value, str)
                    ):
                        namespace_effects = {node.args[0].value}
                        for argument in [
                            *node.args[1:],
                            *(keyword.value for keyword in node.keywords),
                        ]:
                            part = expr_summary(argument)
                            if part is None:
                                return None
                            namespace_effects.update(part)
                        return namespace_effects
                    if isinstance(node.func, ast.Name):
                        local = module_scope.functions.get(node.func.id)
                        if local is not None:
                            local_effects: set[str] = set()
                            for argument in [
                                *node.args,
                                *(keyword.value for keyword in node.keywords),
                            ]:
                                part = expr_summary(argument)
                                if part is None:
                                    return None
                                local_effects.update(part)
                            nested = self._called_function_global_effects(local, module_scope)
                            if nested is None:
                                return None
                            local_effects.update(nested)
                            return local_effects
                    return None
                if isinstance(
                    node,
                    (
                        ast.Attribute,
                        ast.Subscript,
                        ast.BinOp,
                        ast.UnaryOp,
                        ast.BoolOp,
                        ast.IfExp,
                        ast.Compare,
                        ast.FormattedValue,
                        ast.JoinedStr,
                        ast.Set,
                        ast.Dict,
                        ast.ListComp,
                        ast.SetComp,
                        ast.DictComp,
                        ast.NamedExpr,
                    ),
                ) and self._expr_has_effect(node, analysis_scope):
                    return None
                child_effects: set[str] = set()
                for child in ast.iter_child_nodes(node):
                    part = expr_summary(child)
                    if part is None:
                        return None
                    child_effects.update(part)
                return child_effects

            def target_summary(target: ast.expr) -> set[str] | None:
                if isinstance(target, ast.Name):
                    return {target.id} if target.id in global_names else set()
                if isinstance(target, ast.Subscript):
                    value = target.value
                    if (
                        isinstance(value, ast.Call)
                        and isinstance(value.func, ast.Name)
                        and value.func.id == "vars"
                        and not value.args
                        and not value.keywords
                        and self._builtin_is_exact(analysis_scope, "vars")
                    ):
                        return set()
                    if (
                        isinstance(value, ast.Call)
                        and isinstance(value.func, ast.Name)
                        and value.func.id == "globals"
                    ):
                        if isinstance(target.slice, ast.Constant) and isinstance(
                            target.slice.value, str
                        ):
                            return {target.slice.value}
                        return None
                    return expr_summary(target)
                if isinstance(target, ast.Starred):
                    return target_summary(target.value)
                if isinstance(target, (ast.Tuple, ast.List)):
                    combined: set[str] = set()
                    for item in target.elts:
                        part = target_summary(item)
                        if part is None:
                            return None
                        combined.update(part)
                    return combined
                return expr_summary(target)

            def scan(statements: list[ast.stmt]) -> set[str] | None:
                combined: set[str] = set()
                for statement in statements:
                    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        for expr in _definition_header_exprs(
                            statement, evaluate_annotations=not self.future_annotations
                        ):
                            part = expr_summary(expr)
                            if part is None:
                                return None
                            combined.update(part)
                        continue
                    targets: list[ast.expr] = []
                    if isinstance(statement, ast.Assign):
                        targets.extend(statement.targets)
                    elif isinstance(statement, (ast.AnnAssign, ast.AugAssign)):
                        targets.append(statement.target)
                    elif isinstance(statement, ast.Delete):
                        targets.extend(statement.targets)
                    for target in targets:
                        part = target_summary(target)
                        if part is None:
                            return None
                        combined.update(part)
                    for expr in _statement_load_exprs(statement):
                        if expr in targets:
                            continue
                        part = expr_summary(expr)
                        if part is None:
                            return None
                        combined.update(part)
                    bodies: list[list[ast.stmt]] = []
                    if isinstance(statement, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                        bodies.extend((statement.body, statement.orelse))
                    elif isinstance(statement, (ast.With, ast.AsyncWith)):
                        bodies.append(statement.body)
                    elif isinstance(statement, (ast.Try, ast.TryStar)):
                        bodies.extend((statement.body, statement.orelse, statement.finalbody))
                        bodies.extend(handler.body for handler in statement.handlers)
                    elif isinstance(statement, ast.Match):
                        bodies.extend(case.body for case in statement.cases)
                    for body in bodies:
                        part = scan(body)
                        if part is None:
                            return None
                        combined.update(part)
                return combined

            return scan(function.body)
        finally:
            self._active_functions.remove(identity)

    def _called_function_has_effect(
        self,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
        module_scope: _ExecutionScope,
    ) -> bool:
        identity = id(function)
        if identity in self._active_functions:
            return True
        self._active_functions.add(identity)
        try:
            global_names: set[str] = set()
            for statement in function.body:
                if isinstance(statement, ast.Global):
                    global_names.update(statement.names)

            def target_writes_global(target: ast.expr) -> bool:
                if isinstance(target, ast.Name):
                    return target.id in global_names
                if isinstance(target, ast.Starred):
                    return target_writes_global(target.value)
                if isinstance(target, (ast.Tuple, ast.List)):
                    return any(target_writes_global(item) for item in target.elts)
                return False

            def scan(statements: list[ast.stmt]) -> bool:
                for statement in statements:
                    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        if any(
                            self._expr_has_effect(expr, module_scope)
                            for expr in _definition_header_exprs(
                                statement,
                                evaluate_annotations=not self.future_annotations,
                            )
                        ):
                            return True
                        continue
                    if isinstance(statement, ast.Assign) and any(
                        target_writes_global(target) for target in statement.targets
                    ):
                        return True
                    if isinstance(
                        statement, (ast.AnnAssign, ast.AugAssign)
                    ) and target_writes_global(statement.target):
                        return True
                    if isinstance(statement, ast.Delete) and any(
                        target_writes_global(target) for target in statement.targets
                    ):
                        return True
                    if any(
                        self._expr_has_effect(expr, module_scope)
                        for expr in _statement_load_exprs(statement)
                    ):
                        return True
                    bodies: list[list[ast.stmt]] = []
                    if isinstance(statement, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                        bodies.extend((statement.body, statement.orelse))
                    elif isinstance(statement, (ast.With, ast.AsyncWith)):
                        bodies.append(statement.body)
                    elif isinstance(statement, (ast.Try, ast.TryStar)):
                        bodies.extend((statement.body, statement.orelse, statement.finalbody))
                        bodies.extend(handler.body for handler in statement.handlers)
                    elif isinstance(statement, ast.Match):
                        for case in statement.cases:
                            if case.guard is not None and self._expr_has_effect(
                                case.guard, module_scope
                            ):
                                return True
                            bodies.append(case.body)
                    if any(scan(body) for body in bodies):
                        return True
                return False

            return scan(function.body)
        finally:
            self._active_functions.remove(identity)

    def _header_has_effect(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef,
        scope: _ExecutionScope,
    ) -> bool:
        processed_decorators: set[int] = set()
        effect = False
        for decorator in node.decorator_list:
            processed_decorators.add(id(decorator))
            prior_specific = set(self._specific_effect_names)
            prior_unknown = self._unknown_effect_seen
            if self._decorator_is_pure(decorator, scope):
                pass
            else:
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                if isinstance(target, ast.Name):
                    local = scope.functions.get(target.id)
                    if local is not None:
                        summary = self._called_function_global_effects(local, scope)
                        if summary is not None:
                            self._specific_effect_names.update(summary)
                            effect = effect or bool(summary)
                        else:
                            self._unknown_effect_seen = True
                            effect = True
                    else:
                        self._unknown_effect_seen = True
                        effect = True
                else:
                    self._unknown_effect_seen = True
                    effect = True

            # Decorator expressions are evaluated in order.  Apply each newly
            # discovered effect before proving the next decorator; otherwise an
            # earlier mutator can leave a later marker spuriously trusted.
            if self._unknown_effect_seen and not prior_unknown:
                self._clear_unproven_names(scope)
            elif not self._unknown_effect_seen:
                for name in self._specific_effect_names - prior_specific:
                    scope.aliases[name] = None
                    scope.functions[name] = None
                    scope.scalars.pop(name, None)
                    scope.safe_classes.discard(name)
                    scope.restored_names.discard(name)
        annotation_ids: set[int] = set()
        if not self.future_annotations and not isinstance(node, ast.ClassDef):
            for argument in (
                *node.args.posonlyargs,
                *node.args.args,
                *node.args.kwonlyargs,
                *((node.args.vararg,) if node.args.vararg else ()),
                *((node.args.kwarg,) if node.args.kwarg else ()),
            ):
                if argument.annotation is not None:
                    annotation_ids.add(id(argument.annotation))
            if node.returns is not None:
                annotation_ids.add(id(node.returns))
        header = _definition_header_exprs(node, evaluate_annotations=not self.future_annotations)
        for expr in header:
            if id(expr) in processed_decorators:
                continue
            has_effect = (
                self._annotation_has_effect(expr, scope)
                if id(expr) in annotation_ids
                else self._expr_has_effect(expr, scope)
            )
            if has_effect:
                effect = True
        if isinstance(node, ast.ClassDef):
            if not self._builtin_is_exact(scope, "__build_class__"):
                self._unknown_effect_seen = True
                effect = True
            # Even a call-free custom base/metaclass can execute
            # ``__init_subclass__``/metaclass hooks while the class is built.
            if node.keywords:
                self._unknown_effect_seen = True
                effect = True
            if any(
                not (
                    isinstance(base, ast.Name)
                    and base.id in {"object", "type"}
                    and self._builtin_is_exact(scope, base.id)
                )
                for base in node.bases
            ):
                self._unknown_effect_seen = True
                effect = True
        return effect

    def _plain_class_instantiation_is_safe(
        self,
        node: ast.ClassDef,
        scope: _ExecutionScope,
    ) -> bool:
        """Whether ``node()`` uses only exact object/type construction hooks."""
        class_target = f"{self.module_name}.{node.name}" if self.module_name else node.name
        if (
            node.decorator_list
            or node.keywords
            or self.project_mutations.target_is_mutated(class_target)
        ):
            return False
        if any(
            not (
                isinstance(base, ast.Name)
                and base.id in {"object", "type"}
                and self._builtin_is_exact(scope, base.id)
            )
            for base in node.bases
        ):
            return False
        return not any(
            isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
            and statement.name in {"__new__", "__init__"}
            for statement in node.body
        )

    def _iterable_protocol_is_proven_safe(
        self,
        node: ast.expr,
        scope: _ExecutionScope,
    ) -> bool:
        """Whether module-load iteration cannot dispatch to user protocol code."""
        if isinstance(
            node,
            (
                ast.Constant,
                ast.List,
                ast.Tuple,
                ast.Set,
                ast.Dict,
                ast.ListComp,
                ast.SetComp,
                ast.DictComp,
            ),
        ):
            return True
        return isinstance(node, ast.Call) and self._range_call_is_proven_safe(node, scope)

    def _statement_has_unproven_protocol_effect(
        self,
        node: ast.stmt,
        scope: _ExecutionScope,
    ) -> bool:
        """Whether executing a statement invokes an implicit user hook."""
        if isinstance(node, ast.AsyncFor):
            return True
        if isinstance(node, ast.For):
            if not self._iterable_protocol_is_proven_safe(node.iter, scope):
                return True
            if not isinstance(node.target, ast.Name):
                if not isinstance(node.iter, (ast.List, ast.Tuple, ast.Set)):
                    return True
                return any(
                    not _assignment_target_value_pairs(node.target, element)[1]
                    for element in node.iter.elts
                )
            return False
        # Evaluating a context expression is only the first step: entering and
        # exiting dispatch through arbitrary ``__enter__``/``__exit__`` (or async
        # counterparts), which may rebind module state.
        if isinstance(node, (ast.With, ast.AsyncWith, ast.Match, ast.AugAssign)):
            return True
        if isinstance(node, (ast.If, ast.While, ast.Assert)):
            return not self._truth_protocol_is_proven_safe(node.test, scope)
        if isinstance(node, ast.Assign) and any(
            isinstance(target, (ast.Tuple, ast.List)) for target in node.targets
        ):
            if not self._iterable_protocol_is_proven_safe(node.value, scope):
                return True
            return any(
                not _assignment_target_value_pairs(target, node.value)[1]
                for target in node.targets
                if isinstance(target, (ast.Tuple, ast.List))
            )
        return False

    def _truth_protocol_is_proven_safe(
        self,
        node: ast.expr,
        scope: _ExecutionScope,
    ) -> bool:
        """Whether truth testing cannot dispatch to an arbitrary ``__bool__``."""
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, ast.Name):
            if self._scalar_facts(node, scope):
                return True
            if node.id in scope.module_objects and not self._external_identity_poisoned:
                # A genuine untouched stdlib module has fixed truth behavior.
                # Project modules are not trusted here: PEP 562 permits changing
                # ``module.__class__`` to a ModuleType subclass whose ``__bool__``
                # executes arbitrary code. Imported-member aliases are never
                # entered in ``module_objects``.
                imported_module = scope.aliases.get(node.id)
                return (
                    imported_module is not None
                    and not self._target_is_project_owned(imported_module)
                    and not self.project_mutations.target_is_mutated(imported_module)
                )
            imported = scope.aliases.get(node.id)
            return (
                imported == "typing.TYPE_CHECKING"
                and not self._external_identity_poisoned
                and not self._target_is_project_owned(imported)
                and not self.project_mutations.target_is_mutated(imported)
            )
        if isinstance(node, ast.Attribute):
            raw = dotted_name(node)
            if raw is not None:
                head, separator, tail = raw.partition(".")
                imported = scope.aliases.get(head)
                resolved = f"{imported}.{tail}" if imported is not None and separator else imported
                return (
                    resolved in {"os.environ", "typing.TYPE_CHECKING"}
                    and not self._external_identity_poisoned
                    and not self._target_is_project_owned(resolved)
                    and not self.project_mutations.target_is_mutated(resolved)
                )
            return False
        if isinstance(node, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
            return True
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return self._truth_protocol_is_proven_safe(node.operand, scope)
        if isinstance(node, ast.BoolOp):
            return all(self._truth_protocol_is_proven_safe(value, scope) for value in node.values)
        if isinstance(node, ast.Compare):
            operands = [node.left, *node.comparators]
            return all(
                self._operator_operand_is_proven_safe(operand, scope) for operand in operands
            )
        return False

    @staticmethod
    def _class_global_writes(statements: list[ast.stmt]) -> set[str]:
        """Return module globals explicitly rebound by an executing class body."""
        declared: set[str] = set()
        written: set[str] = set()

        def nested_bodies(statement: ast.stmt) -> list[list[ast.stmt]]:
            if isinstance(statement, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                return [statement.body, statement.orelse]
            if isinstance(statement, (ast.With, ast.AsyncWith)):
                return [statement.body]
            if isinstance(statement, (ast.Try, ast.TryStar)):
                return [
                    statement.body,
                    *(handler.body for handler in statement.handlers),
                    statement.orelse,
                    statement.finalbody,
                ]
            if isinstance(statement, ast.Match):
                return [case.body for case in statement.cases]
            return []

        def collect_globals(items: list[ast.stmt]) -> None:
            for statement in items:
                if isinstance(statement, ast.Global):
                    declared.update(statement.names)
                elif not isinstance(
                    statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                ):
                    for body in nested_bodies(statement):
                        collect_globals(body)

        def record_target(target: ast.expr) -> None:
            if isinstance(target, ast.Name):
                written.add(target.id)
            elif isinstance(target, ast.Starred):
                record_target(target.value)
            elif isinstance(target, (ast.Tuple, ast.List)):
                for element in target.elts:
                    record_target(element)

        def record_class_scope_walruses(node: ast.AST) -> None:
            """Collect ``NamedExpr`` targets evaluated under class-body ``global``.

            Class-body assignment expressions honor ``global`` (PEP 572), so a
            walrus like ``local = (trusted := 1)`` rebinds the module global when
            ``global trusted`` is declared. Nested function / lambda / class
            *bodies* bind elsewhere and must not be treated as class-scope
            writes; only their evaluated headers (decorators, bases, defaults,
            annotations) run while the enclosing class body executes.

            Comprehensions are skipped because an assignment expression inside a
            comprehension nested directly in a class body is a SyntaxError, so it
            never contributes a runtime class-body write. Do not read that skip as
            "PEP 572 comprehension walruses only bind inside the implicit
            comprehension function": outside class scope they normally bind the
            containing function/module scope.
            """
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                header: list[ast.AST] = list(getattr(node, "decorator_list", []))
                if isinstance(node, ast.ClassDef):
                    header.extend(node.bases)
                    header.extend(keyword.value for keyword in node.keywords)
                else:
                    arguments = node.args
                    header.extend(arguments.defaults)
                    header.extend(
                        default for default in arguments.kw_defaults if default is not None
                    )
                    if not isinstance(node, ast.Lambda):
                        for argument in (
                            *arguments.posonlyargs,
                            *arguments.args,
                            *arguments.kwonlyargs,
                            *((arguments.vararg,) if arguments.vararg else ()),
                            *((arguments.kwarg,) if arguments.kwarg else ()),
                        ):
                            if argument.annotation is not None:
                                header.append(argument.annotation)
                        if node.returns is not None:
                            header.append(node.returns)
                for expr in header:
                    record_class_scope_walruses(expr)
                return
            if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                return
            if isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
                written.add(node.target.id)
            for child in ast.iter_child_nodes(node):
                record_class_scope_walruses(child)

        def collect_writes(items: list[ast.stmt]) -> None:
            for statement in items:
                if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    written.add(statement.name)
                    record_class_scope_walruses(statement)
                    continue
                if isinstance(statement, ast.Assign):
                    for target in statement.targets:
                        record_target(target)
                elif isinstance(statement, ast.AnnAssign):
                    if statement.value is not None:
                        record_target(statement.target)
                elif isinstance(statement, ast.AugAssign):
                    record_target(statement.target)
                elif isinstance(statement, ast.Delete):
                    for target in statement.targets:
                        record_target(target)
                elif isinstance(statement, (ast.For, ast.AsyncFor)):
                    record_target(statement.target)
                elif isinstance(statement, (ast.With, ast.AsyncWith)):
                    for item in statement.items:
                        if item.optional_vars is not None:
                            record_target(item.optional_vars)
                elif isinstance(statement, ast.Import):
                    written.update(
                        alias.asname or alias.name.split(".", 1)[0] for alias in statement.names
                    )
                elif isinstance(statement, ast.ImportFrom):
                    written.update(
                        alias.asname or alias.name for alias in statement.names if alias.name != "*"
                    )
                elif isinstance(statement, (ast.Try, ast.TryStar)):
                    written.update(
                        handler.name for handler in statement.handlers if handler.name is not None
                    )
                elif isinstance(statement, ast.Match):
                    for case in statement.cases:
                        for pattern in ast.walk(case.pattern):
                            name = getattr(pattern, "name", None)
                            if isinstance(name, str):
                                written.add(name)
                            rest = getattr(pattern, "rest", None)
                            if isinstance(rest, str):
                                written.add(rest)
                # Assignment-expression writes are not statement targets; walk
                # expressions the class body evaluates (including nested control
                # flow). Nested def/class/lambda *bodies* are skipped above so
                # their local walruses do not become false module writes; headers
                # are still walked. Class-body comprehensions with walruses are
                # SyntaxError, so skipping them is safe rather than a binding rule.
                record_class_scope_walruses(statement)
                for body in nested_bodies(statement):
                    collect_writes(body)

        collect_globals(statements)
        collect_writes(statements)
        return declared & written

    def _bind_target(
        self,
        target: ast.expr,
        scope: _ExecutionScope,
        alias: str | None,
        function: ast.FunctionDef | ast.AsyncFunctionDef | None,
        scalars: frozenset[_ScalarAtom] = frozenset(),
        *,
        conditional: bool,
    ) -> None:
        if isinstance(target, ast.Name):
            self._bind_execution_name(
                scope,
                target.id,
                alias,
                function,
                scalars,
                conditional=conditional,
            )
        elif isinstance(target, ast.Starred):
            self._bind_target(target.value, scope, None, None, conditional=conditional)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self._bind_target(item, scope, None, None, conditional=conditional)

    def _assignment_value_binding(
        self,
        value: ast.expr,
        scope: _ExecutionScope,
    ) -> tuple[str | None, ast.FunctionDef | ast.AsyncFunctionDef | None]:
        if isinstance(value, ast.NamedExpr):
            return self._assignment_value_binding(value.value, scope)
        if isinstance(value, ast.IfExp):
            body = self._assignment_value_binding(value.body, scope)
            alternative = self._assignment_value_binding(value.orelse, scope)
            return body if body == alternative else (None, None)
        if isinstance(value, ast.Subscript) and isinstance(value.value, (ast.List, ast.Tuple)):
            indexes = self._scalar_facts(value.slice, scope)
            if len(indexes) != 1:
                return None, None
            index = next(iter(indexes))
            if index.runtime_type is not int or not isinstance(index.value, int):
                return None, None
            elements = value.value.elts
            if not -len(elements) <= index.value < len(elements):
                return None, None
            selected = elements[index.value]
            if isinstance(selected, ast.Starred):
                return None, None
            return self._assignment_value_binding(selected, scope)
        if not isinstance(value, ast.Name):
            return None, None
        alias = scope.aliases.get(value.id)
        function = scope.functions.get(value.id)
        if (
            alias is None
            and function is None
            and value.id in {"staticmethod", "classmethod", "property"}
            and self._builtin_is_exact(scope, value.id)
        ):
            alias = f"builtins.{value.id}"
        return alias, function

    def _bind_assignment_target(
        self,
        target: ast.expr,
        value: ast.expr,
        scope: _ExecutionScope,
        *,
        conditional: bool,
        source_scope: _ExecutionScope | None = None,
    ) -> bool:
        pairs, exact = _assignment_target_value_pairs(target, value)
        snapshot = source_scope or scope.clone()
        resolved: list[
            tuple[
                ast.expr,
                str | None,
                ast.FunctionDef | ast.AsyncFunctionDef | None,
                frozenset[_ScalarAtom],
            ]
        ] = []
        for leaf, source in pairs:
            alias: str | None = None
            function: ast.FunctionDef | ast.AsyncFunctionDef | None = None
            scalars: frozenset[_ScalarAtom] = frozenset()
            if source is not None:
                alias, function = self._assignment_value_binding(source, snapshot)
                scalars = self._scalar_facts(source, snapshot)
            resolved.append((leaf, alias, function, scalars))
        for leaf, alias, function, scalars in resolved:
            self._bind_target(
                leaf,
                scope,
                alias,
                function,
                scalars,
                conditional=conditional,
            )
        return exact

    def _update_bindings(
        self, node: ast.stmt, scope: _ExecutionScope, *, conditional: bool
    ) -> None:
        if isinstance(node, ast.Import):
            for imported in node.names:
                visible = imported.asname or imported.name.split(".", 1)[0]
                import_target = imported.name if imported.asname else visible
                self._bind_execution_name(
                    scope, visible, import_target, None, conditional=conditional
                )
                if not conditional:
                    scope.module_objects.add(visible)
        elif isinstance(node, ast.ImportFrom):
            if node.module == "__future__" and not node.level:
                return
            if node.module and not node.level:
                for imported in node.names:
                    if imported.name == "*":
                        self._clear_unproven_names(scope, external_identity=False)
                        continue
                    visible = imported.asname or imported.name
                    self._bind_execution_name(
                        scope,
                        visible,
                        f"{node.module}.{imported.name}",
                        None,
                        conditional=conditional,
                    )
            else:
                for imported in node.names:
                    if imported.name != "*":
                        self._bind_execution_name(
                            scope,
                            imported.asname or imported.name,
                            None,
                            None,
                            conditional=conditional,
                        )
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Decorators may replace the just-created function object.  Its raw
            # ``FunctionDef`` body is therefore not an executable-identity proof;
            # a later module-load call must be treated as an unknown effect rather
            # than summarized as though Python necessarily called this body.
            marker_only = bool(node.decorator_list) and all(
                any(
                    (
                        getattr(decorator, "lineno", -1),
                        getattr(decorator, "col_offset", -1),
                        kind,
                    )
                    in self.proven_markers
                    for kind in ("native", "exempt")
                )
                for decorator in node.decorator_list
            )
            self._bind_execution_name(
                scope,
                node.name,
                None,
                node if not node.decorator_list or marker_only else None,
                conditional=conditional,
            )
        elif isinstance(node, ast.ClassDef):
            self._bind_execution_name(scope, node.name, None, None, conditional=conditional)
            if not conditional and self._plain_class_instantiation_is_safe(node, scope):
                scope.safe_classes.add(node.name)
        elif isinstance(node, ast.Assign):
            snapshot = scope.clone()
            for assignment_target in node.targets:
                self._bind_assignment_target(
                    assignment_target,
                    node.value,
                    scope,
                    conditional=conditional,
                    source_scope=snapshot,
                )
        elif isinstance(node, ast.AnnAssign):
            if node.value is None:
                self._bind_target(node.target, scope, None, None, conditional=conditional)
            else:
                self._bind_assignment_target(
                    node.target,
                    node.value,
                    scope,
                    conditional=conditional,
                    source_scope=scope.clone(),
                )
        elif isinstance(node, ast.AugAssign):
            self._bind_target(node.target, scope, None, None, conditional=conditional)
        elif isinstance(node, ast.Delete):
            for assignment_target in node.targets:
                self._bind_target(assignment_target, scope, None, None, conditional=conditional)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            self._bind_target(node.target, scope, None, None, conditional=True)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    self._bind_target(item.optional_vars, scope, None, None, conditional=True)

    def _scan_statements(
        self,
        statements: list[ast.stmt],
        scope: _ExecutionScope,
        *,
        conditional: bool,
    ) -> tuple[set[str], bool]:
        observed_specific: set[str] = set()
        observed_unknown = False

        def observe(summary: tuple[set[str], bool]) -> None:
            nonlocal observed_unknown
            names, unknown = summary
            observed_specific.update(names)
            observed_unknown = observed_unknown or unknown

        for node in statements:
            self._specific_effect_names = set()
            self._unknown_effect_seen = False
            effect = False
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                effect = self._header_has_effect(node, scope)
            elif isinstance(node, ast.ClassDef):
                effect = self._header_has_effect(node, scope)
                header_specific = set(self._specific_effect_names)
                header_unknown = self._unknown_effect_seen
                child_scope = scope.clone()
                child_scope.pending_markers = []
                child_specific, child_unknown = self._scan_statements(
                    node.body, child_scope, conditional=False
                )
                child_specific.update(self._class_global_writes(node.body))
                self._finalize_markers(child_scope)
                if child_specific or child_unknown:
                    effect = True
                self._specific_effect_names = header_specific | child_specific
                self._unknown_effect_seen = header_unknown or child_unknown
            else:
                effect = self._expressions_have_effect(_statement_load_exprs(node), scope)
            if self._statement_has_unproven_protocol_effect(node, scope):
                self._unknown_effect_seen = True
                effect = True
            if isinstance(node, ast.Match):
                guards = [case.guard for case in node.cases if case.guard is not None]
                effect = self._expressions_have_effect(guards, scope) or effect
            if effect:
                self.effect_nodes.add(id(node))
                if self._unknown_effect_seen:
                    observed_unknown = True
                    self._clear_unproven_names(scope)
                else:
                    observed_specific.update(self._specific_effect_names)
                    for name in self._specific_effect_names:
                        scope.aliases[name] = None
                        scope.functions[name] = None
                        scope.scalars.pop(name, None)
                        scope.safe_classes.discard(name)
                        scope.module_objects.discard(name)
                        scope.restored_names.discard(name)
            self._update_bindings(node, scope, conditional=conditional)

            if isinstance(node, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                observe(self._scan_statements(node.body, scope, conditional=True))
                observe(self._scan_statements(node.orelse, scope, conditional=True))
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                observe(self._scan_statements(node.body, scope, conditional=True))
            elif isinstance(node, (ast.Try, ast.TryStar)):
                observe(self._scan_statements(node.body, scope, conditional=True))
                for handler in node.handlers:
                    observe(self._scan_statements(handler.body, scope, conditional=True))
                observe(self._scan_statements(node.orelse, scope, conditional=True))
                observe(self._scan_statements(node.finalbody, scope, conditional=True))
            elif isinstance(node, ast.Match):
                for case in node.cases:
                    observe(self._scan_statements(case.body, scope, conditional=True))
        return observed_specific, observed_unknown


def build_module_bindings(
    tree: ast.Module,
    module_name: str = "",
    *,
    project_mutations: ProjectMutations = _EMPTY_MUTATIONS,
    project_modules: Collection[str] = (),
    trusted_marker_sites: Collection[tuple[int, int, str]] = (),
    trusted_annotation_targets: Collection[str] = (),
    trusted_function_bindings: Mapping[str, ast.FunctionDef | ast.AsyncFunctionDef] | None = None,
) -> ModuleBindings:
    """Build the source-order final-binding table for a module AST.

    Walks the module body in source order — descending into control-flow bodies
    (whose binders are ``AMBIGUOUS``) but never into nested function/class
    *bodies* (which bind in their own scope) — recording each visible name's last
    binder with exact origin. See the module docstring for the full semantics.
    """
    entries: dict[str, FinalBinding] = {}
    order = 0
    star_order: int | None = None
    wildcard_order: int | None = None
    effect_nodes, proven_marker_sites = _ModuleExecutionScanner(
        tree,
        project_mutations,
        project_modules,
        module_name,
        trusted_marker_sites,
        trusted_annotation_targets,
        trusted_function_bindings,
    ).scan()
    unstable_class_sites = frozenset(
        (node.lineno, node.col_offset)
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef) and id(node) in effect_nodes
    )

    def next_order() -> int:
        nonlocal order
        order += 1
        return order

    def bind(name: str, kind: BindingKind, node: ast.AST, *, conditional: bool) -> None:
        effective = BindingKind.AMBIGUOUS if conditional else kind
        entries[name] = FinalBinding(
            kind=effective,
            target=None if conditional else _target_for(name, kind, node),
            line=getattr(node, "lineno", None),
            column=getattr(node, "col_offset", None),
            order=next_order(),
        )

    def _target_for(name: str, kind: BindingKind, node: ast.AST) -> str | None:
        if kind in (BindingKind.FUNCTION, BindingKind.CLASS):
            return f"{module_name}.{name}" if module_name else name
        return None

    def bind_value_target(target: ast.expr, *, conditional: bool) -> None:
        if isinstance(target, ast.Name):
            bind(target.id, BindingKind.VALUE, target, conditional=conditional)
        elif isinstance(target, ast.Starred):
            bind_value_target(target.value, conditional=conditional)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                bind_value_target(element, conditional=conditional)

    def bind_walrus(node: ast.AST, *, conditional: bool) -> None:
        # A module-level walrus binds a value at module scope (PEP 572 also leaks
        # a module-level comprehension's target to the containing scope). Recurse
        # WITHOUT entering nested function/class BODIES (their walruses bind in
        # their own scope) but DO enter a def/class HEADER (decorators, bases,
        # defaults, annotations), which is evaluated at module scope.
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            header: list[ast.AST] = list(getattr(node, "decorator_list", []))
            if isinstance(node, ast.ClassDef):
                header.extend(node.bases)
                header.extend(keyword.value for keyword in node.keywords)
            else:
                arguments = node.args
                header.extend(arguments.defaults)
                header.extend(default for default in arguments.kw_defaults if default is not None)
                if not isinstance(node, ast.Lambda):
                    for argument in (
                        *arguments.posonlyargs,
                        *arguments.args,
                        *arguments.kwonlyargs,
                        *((arguments.vararg,) if arguments.vararg else ()),
                        *((arguments.kwarg,) if arguments.kwarg else ()),
                    ):
                        if argument.annotation is not None:
                            header.append(argument.annotation)
                    if node.returns is not None:
                        header.append(node.returns)
            for expr in header:
                bind_walrus(expr, conditional=conditional)
            return
        if isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
            bind(node.target.id, BindingKind.VALUE, node.target, conditional=conditional)
        for child in ast.iter_child_nodes(node):
            bind_walrus(child, conditional=conditional)

    def bind_match_captures(pattern: ast.AST, *, conditional: bool) -> None:
        name = getattr(pattern, "name", None)
        if isinstance(name, str):
            bind(name, BindingKind.VALUE, pattern, conditional=conditional)
        rest = getattr(pattern, "rest", None)
        if isinstance(rest, str):
            bind(rest, BindingKind.VALUE, pattern, conditional=conditional)
        for child in ast.iter_child_nodes(pattern):
            bind_match_captures(child, conditional=conditional)

    def walk(statements: list[ast.stmt], *, conditional: bool) -> None:
        nonlocal star_order, wildcard_order
        for node in statements:
            bind_walrus(node, conditional=conditional)
            if id(node) in effect_nodes:
                # An unproven module-execution effect (an `exec`/`globals` mutation,
                # or an unproven decorator/default) can rebind any earlier global we
                # cannot model, so treat it exactly like a wildcard import at this
                # exact source order: every name with no explicit binder LATER than
                # this point becomes unknown, while a later explicit binding for a
                # name restores it (director follow-up 7, P0-3). Set the star BEFORE
                # this node's own binding so the node's def/class name is restored.
                star_order = next_order()
            if isinstance(node, ast.ImportFrom):
                if node.module == "__future__" and not node.level:
                    # `from __future__ import annotations` (and any other future
                    # feature) creates NO runtime-visible binding for the name, so it
                    # must not register `annotations` as an import (director follow-up
                    # 7, P1-3). Skip it entirely.
                    continue
                for alias in node.names:
                    if alias.name == "*":
                        # A wildcard import: record its order and add no name
                        # entry (it may shadow any later-unbound spelling).
                        wildcard_order = next_order()
                        star_order = wildcard_order
                    else:
                        import_target = _import_from_target(node, alias)
                        entries[alias.asname or alias.name] = FinalBinding(
                            kind=(BindingKind.AMBIGUOUS if conditional else BindingKind.IMPORT),
                            target=None if conditional else import_target,
                            line=node.lineno,
                            column=node.col_offset,
                            order=next_order(),
                        )
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        visible, import_target = alias.asname, alias.name
                    else:
                        # `import pkg.sub` binds the top package `pkg -> pkg`.
                        visible = alias.name.split(".", 1)[0]
                        import_target = visible
                    entries[visible] = FinalBinding(
                        kind=BindingKind.AMBIGUOUS if conditional else BindingKind.IMPORT,
                        target=None if conditional else import_target,
                        line=node.lineno,
                        column=node.col_offset,
                        order=next_order(),
                    )
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                bind(node.name, BindingKind.FUNCTION, node, conditional=conditional)
            elif isinstance(node, ast.ClassDef):
                bind(node.name, BindingKind.CLASS, node, conditional=conditional)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    bind_value_target(target, conditional=conditional)
            elif isinstance(node, ast.AnnAssign):
                if node.value is not None:
                    bind_value_target(node.target, conditional=conditional)
            elif isinstance(node, ast.AugAssign):
                bind_value_target(node.target, conditional=conditional)
            elif isinstance(node, ast.Delete):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        bind(target.id, BindingKind.DELETED, target, conditional=conditional)
                    else:
                        bind_value_target(target, conditional=conditional)
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                bind_value_target(node.target, conditional=True)
                walk(node.body, conditional=True)
                walk(node.orelse, conditional=True)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars is not None:
                        bind_value_target(item.optional_vars, conditional=True)
                walk(node.body, conditional=True)
            elif isinstance(node, (ast.If, ast.While)):
                walk(node.body, conditional=True)
                walk(node.orelse, conditional=True)
            elif isinstance(node, (ast.Try, ast.TryStar)):
                walk(node.body, conditional=True)
                for handler in node.handlers:
                    if handler.name is not None:
                        bind(handler.name, BindingKind.VALUE, handler, conditional=True)
                    walk(handler.body, conditional=True)
                walk(node.orelse, conditional=True)
                walk(node.finalbody, conditional=True)
            elif isinstance(node, ast.Match):
                for case in node.cases:
                    bind_match_captures(case.pattern, conditional=True)
                    walk(case.body, conditional=True)

    walk(tree.body, conditional=False)
    return ModuleBindings(
        module_name,
        entries,
        star_order,
        wildcard_order,
        proven_marker_sites,
        unstable_class_sites,
        frozenset(trusted_annotation_targets),
    )


def _import_from_target(node: ast.ImportFrom, alias: ast.alias) -> str | None:
    """Return the dotted target of ``from module import name`` (``None`` if relative).

    A relative import (``level > 0``) is resolved by the module's own import map
    (which knows the package), so we leave the target ``None`` here and let the
    resolver expand it through that map; only absolute targets are stored.
    """
    if node.level and node.level > 0:
        return None
    if not node.module:
        return None
    return f"{node.module}.{alias.name}"
