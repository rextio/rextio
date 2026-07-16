"""Analyzer result models.

The dataclasses the analyzer produces — per-function, per-top-level, per-module, and
whole-project — plus the diagnostic-accumulation helpers and the derived views
(accepted/rejected candidates, embedding candidates, aggregated diagnostics) the CLI and
lowering consume. Every model serializes to a plain dict via ``to_dict`` for the
``rextio check`` JSON report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from rextio.analyzer.diagnostics import Diagnostic
from rextio.analyzer.final_bindings import (
    ModuleBindings,
    ProjectBindings,
    ProjectMutations,
    _EMPTY_MUTATIONS,
)
from rextio.contract import TOOLING_CONTRACT_VERSION

if TYPE_CHECKING:
    from rextio.analyzer.plugin_claims import ClaimEngine
    from rextio.plugins.api import (
        CallableMeta,
        ClaimExpr,
        ClaimLiteral,
        KeywordArg,
        ReceiverMeta,
        SchemaMeta,
    )


@dataclass(frozen=True)
class PluginClaim:
    """A site inside a function that an active plugin claimed for lowering."""

    plugin_id: str
    rule_id: str
    kind: str
    target: str
    line: int
    column: int
    result_type: str | None
    # The resolved operand/argument types of the claimed site in positional
    # order (plugin type keys or core type names, None when unresolved),
    # carried through to codegen so lower() sees the same site claim() saw.
    operand_types: tuple[str | None, ...] = ()
    # End of the claimed node's source span. (line, column) alone is ambiguous:
    # a BinOp starts at the same offset as its leftmost operand, so an
    # expression like `np.dot(a, b) * factor` has the call AND the enclosing
    # binop at one (line, column). IR lowering matches claims on the full
    # (start, end, kind) signature to re-identify the exact node.
    end_line: int | None = None
    end_column: int | None = None
    # Plugin API 1.2 claim metadata (defaults keep 1.1 report shape additive).
    operand_literals: tuple[ClaimLiteral, ...] = ()
    keywords: tuple[KeywordArg, ...] = ()
    expression: ClaimExpr | None = None
    # How codegen feeds lower(): "direct" (default) or "leaves" (fusion).
    operand_mode: str = "direct"
    # Plugin API 1.3 static metadata (defaults keep the 1.1/1.2 report shape).
    receiver: ReceiverMeta | None = None
    callables: tuple[CallableMeta, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this claim."""
        data: dict[str, object] = {
            "plugin_id": self.plugin_id,
            "rule_id": self.rule_id,
            "kind": self.kind,
            "target": self.target,
            "line": self.line,
            "column": self.column,
            "end_line": self.end_line,
            "end_column": self.end_column,
            "result_type": self.result_type,
            "operand_types": list(self.operand_types),
        }
        # Serialize 1.2 metadata when present so check.json is stable/cache-safe.
        if self.operand_literals:
            data["operand_literals"] = [lit.to_dict() for lit in self.operand_literals]
        if self.keywords:
            data["keywords"] = [keyword.to_dict() for keyword in self.keywords]
        if self.expression is not None:
            data["expression"] = self.expression.to_dict()
        if self.operand_mode != "direct":
            data["operand_mode"] = self.operand_mode
        # Serialize 1.3 metadata when present so check.json stays additive.
        if self.receiver is not None:
            data["receiver"] = self.receiver.to_dict()
        if self.callables:
            data["callables"] = [callable_meta.to_dict() for callable_meta in self.callables]
        return data


@dataclass(frozen=True)
class PluginClaimRejection:
    """A plugin claim rejection pending boundary-pass delivery, with its site kind.

    The kind matters for delivery: a call-site rejection replaces RXT030 in
    the boundary pass's call loop, while a binop rejection has no CallSite and
    must be attached unconditionally — including when it shares a start
    position with a (claimed) call, e.g. ``np.dot(a, b) + c``.

    ``end_line``/``end_column`` complete the source span so keyword-call RXT010
    suppression can match Claimed and Rejected plugin-managed sites by the
    same full (kind, start, end) signature as claims (plugin API 1.2).
    """

    kind: str
    diagnostic: Diagnostic
    end_line: int | None = None
    end_column: int | None = None


@dataclass(frozen=True)
class CallSite:
    """A recorded call to another function, with its source location."""

    target: str
    line: int
    column: int
    in_loop: bool = False
    # The scalar type of each positional argument that is a literal constant
    # (int/float/bool/str/bytes/None), positionally; None for any argument whose
    # type is not a directly-readable literal. Used by the boundary pass to reject
    # native→native calls whose literal argument type differs from the callee's
    # scalar parameter type, which would otherwise emit Rust that fails to compile.
    arg_types: tuple[str | None, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this call site."""
        return {
            "target": self.target,
            "line": self.line,
            "column": self.column,
            "in_loop": self.in_loop,
            "arg_types": list(self.arg_types),
        }


@dataclass(frozen=True)
class ImportPolicyDecision:
    """The resolved import policy for one imported name (how the boundary treats it)."""

    visible_name: str
    target: str
    package: str
    origin: str
    policy: str
    plugin: str | None = None
    max_depth: int = 0
    reason: str = ""

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this decision."""
        return {
            "visible_name": self.visible_name,
            "target": self.target,
            "package": self.package,
            "origin": self.origin,
            "policy": self.policy,
            "plugin": self.plugin,
            "max_depth": self.max_depth,
            "reason": self.reason,
        }


@dataclass
class FunctionAnalysis:
    """The analysis of a single candidate function: acceptance, types, and diagnostics."""

    name: str
    qualname: str
    module_name: str
    file_path: str
    line: int
    column: int
    is_native_candidate: bool = False
    accepted: bool = False
    # True only when the function carries an explicit `@rextio.native` marker.
    # Auto-discovered (undecorated) functions are False. Used to keep the
    # Python runtime-semantics shim (RXT080) opt-in (see boundary checks).
    explicitly_marked: bool = False
    # Semantic AST identity captured during analysis.  IR/wrapper generation
    # re-reads source and requires an exact match so a same-line edit cannot reuse
    # stale inferred types, plugin claims, or lowering decisions.
    source_ast_fingerprint: str | None = None
    calls: list[CallSite] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    inferred_arg_types: dict[str, str] = field(default_factory=dict)
    # The complete resolved parameter types in positional order (annotated params
    # plus inferred ones), name->type. Unlike inferred_arg_types this includes
    # explicitly annotated parameters, so the boundary pass can compare a caller's
    # literal argument types against the callee's declared scalar parameters.
    signature_arg_types: dict[str, str] = field(default_factory=dict)
    # Inferred positional argument types for each call this function makes, keyed by
    # the call's (line, column). Unlike CallSite.arg_types (literal constants only,
    # captured without an environment) this is filled during type inference, so it
    # also covers non-literal arguments (known locals/params, sub-expressions). The
    # boundary pass prefers it over the literal-only types when validating calls.
    call_arg_types: dict[tuple[int, int], tuple[str | None, ...]] = field(default_factory=dict)
    # For each call (keyed by its (line, column)), the call target of any argument
    # that is itself a call, positionally; None for non-call arguments. Lets the
    # boundary pass resolve a nested call argument's return type through the project
    # resolver (covering cross-module / imported callees the per-module inference
    # registry cannot reach) when the locally-inferred type is unknown.
    call_arg_targets: dict[tuple[int, int], tuple[str | None, ...]] = field(default_factory=dict)
    # The number of positional parameters (positional-only + normal), or None when
    # the signature was never captured (e.g. runtime-shim methods). The boundary
    # pass uses this — not the truthiness/length of signature_arg_types — to check
    # call arity, so a genuine zero-parameter callee (count 0, not None) is still
    # validated against over-arity calls.
    # The resolved return type (annotated, else inferred), used by the boundary pass
    # to resolve this function's return type when it appears as a nested call
    # argument — including across modules, via the project resolver.
    signature_return_type: str | None = None
    positional_param_count: int | None = None
    # True when the callee declares any keyword-only parameters. Such a function
    # cannot be faithfully called through the native calling convention (keyword
    # call arguments are unsupported, and a keyword-only parameter supplied
    # positionally diverges from CPython), so native callers are kept on fallback.
    has_keyword_only_params: bool = False
    inferred_return_type: str | None = None
    # The function's annotated return type name (``annotation_name(node.returns)``)
    # captured for *every* function, including fallback/exempt ones the native
    # analysis does not otherwise type. Used by the executable delegate mode to
    # type a delegated call's result.
    annotated_return_type: str | None = None
    native_target_language: str | None = None
    native_runtime_semantics: bool = False
    is_embedding_candidate: bool = False
    embedding_reason: str | None = None
    # Set when a recognized external accelerator decorator (e.g. numba.njit) keeps
    # this function on the Python fallback intentionally: it is compiled by that
    # tool under THAT tool's semantics, outside Rextio's native contract.
    external_accelerator: str | None = None
    # Resolved import map for the function's module (visible name ->
    # dotted target), used by decorator/call resolution.
    imports: dict[str, str] = field(default_factory=dict)
    logger_names: tuple[str, ...] = ()
    # All names bound anywhere in the function body (params, assignments, loop
    # targets, ...), captured during validation. A value-position name read that
    # is absent from both the local type environment and this set is unbound in
    # the function (a module global, closure, or genuinely undefined name) and
    # cannot be lowered as a Rust local, so it is rejected to the fallback.
    # Module-level names bound by an assignment (e.g. `len = 5` or `helper = ...`
    # at module scope). Such a binding shadows a builtin / import / sibling
    # function of the same name for every function in the module, so a bare call
    # to that name would lower to the wrong callable. Used by the shadow checker.
    module_assigned_names: frozenset[str] = frozenset()
    # Every same-module top-level function name (any def, regardless of whether it
    # is the *final* binding of that name). Lets the standalone body validator's
    # shadow check tell "this bare name would resolve to a sibling function" so it
    # can fail closed when the shared final-binding authority proves that sibling
    # is not the name's final binder (e.g. `def good` then `class good`).
    module_function_names: frozenset[str] = frozenset()
    # The module's source-order FINAL binding kind per visible name (the shared
    # plugin-API-1.3 authority, ``collect_module_final_bindings``). Lets call
    # resolution treat a same-module ``def abs``/``def min`` sibling as the sibling
    # function — never the pure builtin — and fail closed on a spelling whose final
    # binder is an assignment/``del``/conditional rebind, so core never silently
    # types/lowers a stale builtin/math target Python does not call.
    module_final_bindings: dict[str, str] = field(default_factory=dict)
    # The shared, immutable source-order final-binding authority for this
    # function's defining module (``build_module_bindings``). Unlike the coarse
    # ``module_final_bindings`` kind map, it carries each name's exact binder
    # origin (line/column/order) and wildcard-import state, so a call head or a
    # definition is validated against the *exact* final binder — never a stale
    # duplicate — and a ``from x import *`` correctly shadows later-unbound
    # spellings. Shared across every function in the module (one object).
    module_bindings: ModuleBindings | None = None
    # For a native METHOD, its enclosing class's visible name and EXACT origin
    # (line/column of the ``class`` statement). A native method may be built only
    # when this class is the module's exact final CLASS binding AND this method def
    # is the class namespace's final binding for its name; otherwise Python resolves
    # a different class/attribute and the wrapper would install a stale (or missing)
    # method (plugin API 1.3, WP-4, director follow-up 7 P0-2). ``None`` for a
    # module-level function.
    enclosing_class_name: str | None = None
    enclosing_class_line: int | None = None
    enclosing_class_column: int | None = None
    # The shared project-wide record of module attributes mutated during module
    # load (``import pkg.helper as h; h.good = …``). A direct-native call/import
    # that reaches a mutated target would lower a stale compiled function and
    # diverge from CPython, so the call gate and definition gate fail closed on it
    # (plugin API 1.3, WP-4, director follow-up 7 P0-4). Shared across the project.
    project_mutations: ProjectMutations = _EMPTY_MUTATIONS
    # Every project-owned module/package name. A source import whose resolved
    # target is in this set is project code even when its spelling collides with
    # stdlib (for example a project ``math.py`` or ``logging.py``), so static
    # stdlib lowering must fail closed.
    project_modules: frozenset[str] = frozenset()
    # Every name bound as a local in this function's own scope (parameters plus
    # every Store-context target anywhere in the body, including loop and
    # comprehension targets). A callable-argument reference whose name is a local
    # here is shadowed and does NOT resolve to a same-name project function, so
    # scope-aware callable/schema resolution fails closed on it (plugin API 1.3,
    # WP-4). Captured before signature inference and the body pass so claims made
    # during either see it.
    local_binding_names: frozenset[str] = frozenset()
    # Site-scoped comprehension shadowing (plugin API 1.3, WP-4): maps an AST node
    # id to the comprehension ``for`` target names in scope AT that node. A
    # comprehension target shadows a same-name project callable only inside the
    # comprehension's own expression scope (Python 3 comprehension scoping), never
    # across the whole function, so a callable reference is looked up with
    # ``local_binding_names`` UNION this node's entry. Empty for nodes outside any
    # comprehension. Transient analysis state, keyed by node identity.
    comprehension_scope_names: dict[int, frozenset[str]] = field(
        default_factory=dict, repr=False, compare=False
    )
    # Qualnames of project functions this (direct-native) function calls that live
    # on the Python fallback and are delegated to the external CPython dispatcher
    # instead of rejected. Only populated in the Rust-executable "delegate" mode
    # (see boundary.apply_boundary_checks); empty in every normal build, where a
    # native->fallback call is rejected (RXT070) as before.
    delegated_call_targets: set[str] = field(default_factory=set)
    # Fallback functions this native function calls in-process through the
    # scalar boundary-call path (explicitly marked callers only).
    boundary_call_targets: set[str] = field(default_factory=set)
    # User-call return types visible while validating this function body. Keys are
    # the same call targets produced by `canonical_call_target`/`dotted_name`
    # (bare same-module names and fully-qualified imported project functions).
    # This lets operator/assignment checks type a user-defined call result before
    # codegen, so invalid expressions are rejected instead of emitting Rust that
    # fails to compile. INVARIANT: this map is a local-validator HINT only - the
    # boundary check remains the authoritative gate for whether a call is legal
    # (RXT070/RXT072/delegation), so typing a callee here can only ADD rejections,
    # never admit a call the boundary would refuse.
    call_return_types: dict[str, str] = field(default_factory=dict)
    # Sites an active lowering plugin claimed (docs/specs/plugin-lowering.md);
    # a claimed call is legal for the boundary pass and drives the
    # native-plugin:<id> route.
    plugin_claims: list[PluginClaim] = field(default_factory=list)
    # Claim rejections recorded at inference time but attached by the boundary
    # pass (mirroring RXT030): parse-time errors would divert explicitly marked
    # functions onto the RXT080 shim and hide the plugin's guidance.
    plugin_claim_rejections: list[PluginClaimRejection] = field(default_factory=list)
    # Plugin type keys resolved in this function's SIGNATURE (parameters or
    # return). A function can need a plugin's boundary conversions and crates
    # without any claimed body site (e.g. an identity function), so the
    # native-plugin route derives from claims OR these keys.
    plugin_type_keys: list[str] = field(default_factory=list)
    # The ordered positional parameter names (positional-only + normal), so the
    # boundary pass can reconstruct the callee's full positional type list —
    # including resident plugin-typed parameters, which are absent from
    # ``signature_arg_types`` (that map holds only core-typed params).
    positional_param_names: tuple[str, ...] = ()
    # Parameter name -> resolved plugin type key, for parameters annotated with
    # a plugin type. Lets native-to-native signature compatibility match a
    # resident argument against a resident parameter by exact key (plugin API
    # 1.3), preserving the existing arity/keyword/scalar/container checks.
    signature_plugin_keys: dict[str, str] = field(default_factory=dict)
    # True when the signature (parameter or return) carries a RESIDENT plugin
    # type key (opaque, no Python boundary): such a function is a native-only
    # helper, never PyO3-exported (a resident value cannot cross the boundary).
    has_resident_signature: bool = False
    # True when the signature carries a MATERIALIZED plugin type key (a plugin
    # type with a Python boundary conversion): a Python-facing entry point that
    # native callers may not call native-to-native (RXT092), as before.
    has_materialized_plugin_type: bool = False
    # Parameter (or annotated local) name -> declared schema resolved from a
    # schema-parameterized plugin annotation (``df: Frame[Row]``), plugin API
    # 1.3. Drives the method receiver's ``ReceiverMeta.schema`` and the row-UDF
    # callable body's schema-bound field/subscript reads. Empty when no schema
    # annotation appears; never executes the annotation.
    declared_schemas: dict[str, SchemaMeta] = field(default_factory=dict)
    # Transient analysis state: the claim engine for active lowering plugins
    # (None when no lowering plugin is active). Never serialized or compared.
    claim_engine: ClaimEngine | None = field(default=None, repr=False, compare=False)

    @property
    def native_status(self) -> str:
        """The promotion verdict: ``accepted`` | ``rejected`` | ``not-candidate``.

        Part of the tooling contract (docs/specs/tooling-contract.md). Orthogonal
        to :attr:`route`: a rejected candidate still *executes* on the fallback,
        so its route is ``fallback-python`` while its status is ``rejected``.
        """
        if self.is_native_candidate:
            return "accepted" if self.accepted else "rejected"
        return "not-candidate"

    @property
    def rejection_codes(self) -> list[str]:
        """The sorted error-diagnostic codes explaining a rejection (else empty).

        Part of the tooling contract. Only rejected candidates carry codes, so
        consumers can key remediation guidance directly off this list.
        """
        if self.native_status != "rejected":
            return []
        return sorted({diagnostic.code for diagnostic in self.error_diagnostics})

    @property
    def route(self) -> str:
        """The execution-route label defined by the tooling contract.

        One of ``native-direct``, ``native-shim``, ``native-plugin:<id>``,
        ``fallback-accelerated:<tool>``, or ``fallback-python``. A function
        with at least one plugin-claimed site routes as plugin-lowered; in the
        (rare) case of sites claimed by several plugins the ids are joined
        with ``+`` in sorted order.
        """
        if self.is_native_candidate and self.accepted:
            if self.native_runtime_semantics:
                return "native-shim"
            plugin_ids = sorted(
                {claim.plugin_id for claim in self.plugin_claims}
                | {key.split("/")[0] for key in self.plugin_type_keys}
            )
            if plugin_ids:
                return f"native-plugin:{'+'.join(plugin_ids)}"
            return "native-direct"
        if self.external_accelerator is not None:
            return f"fallback-accelerated:{self.external_accelerator}"
        return "fallback-python"

    @property
    def error_diagnostics(self) -> list[Diagnostic]:
        """The error-severity diagnostics attached to this function."""
        return [diagnostic for diagnostic in self.diagnostics if diagnostic.severity == "error"]

    @property
    def warning_diagnostics(self) -> list[Diagnostic]:
        """The warning-severity diagnostics attached to this function."""
        return [diagnostic for diagnostic in self.diagnostics if diagnostic.severity == "warning"]

    def has_diagnostic(self, code: str, line: int | None = None, column: int | None = None) -> bool:
        """Report whether a diagnostic with the given code (and optional location) exists."""
        for diagnostic in self.diagnostics:
            if diagnostic.code != code:
                continue
            if line is not None and diagnostic.line != line:
                continue
            if column is not None and diagnostic.column != column:
                continue
            return True
        return False

    def add_diagnostic(self, diagnostic: Diagnostic) -> None:
        """Append a diagnostic, de-duplicating on (code, line, column)."""
        if self.has_diagnostic(diagnostic.code, diagnostic.line, diagnostic.column):
            return
        self.diagnostics.append(diagnostic)

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this function analysis."""
        data: dict[str, object] = {
            "name": self.name,
            "qualname": self.qualname,
            "module_name": self.module_name,
            "file_path": self.file_path,
            "line": self.line,
            "column": self.column,
            "is_native_candidate": self.is_native_candidate,
            "accepted": self.accepted,
            "route": self.route,
            "native_status": self.native_status,
            "rejection_codes": self.rejection_codes,
            "explicitly_marked": self.explicitly_marked,
            "native_target_language": self.native_target_language,
            "native_runtime_semantics": self.native_runtime_semantics,
            "is_embedding_candidate": self.is_embedding_candidate,
            "boundary_call_targets": sorted(self.boundary_call_targets),
            "embedding_reason": self.embedding_reason,
            "external_accelerator": self.external_accelerator,
            "inferred_arg_types": dict(sorted(self.inferred_arg_types.items())),
            "inferred_return_type": self.inferred_return_type,
            "calls": [call.to_dict() for call in self.calls],
            "plugin_claims": [
                claim.to_dict()
                for claim in sorted(self.plugin_claims, key=lambda c: (c.line, c.column))
            ],
            "plugin_type_keys": sorted(self.plugin_type_keys),
            "diagnostics": [diagnostic.to_dict() for diagnostic in self.diagnostics],
        }
        # Only present for functions kept off embedding for overflow safety, so the
        # common case keeps a stable report shape.
        return data


@dataclass
class TopLevelAnalysis:
    """The analysis of a module's top-level native-initialization candidate."""

    name: str
    qualname: str
    module_name: str
    file_path: str
    line: int | None = None
    column: int | None = None
    is_native_candidate: bool = False
    accepted: bool = False
    assigned_types: dict[str, str] = field(default_factory=dict)
    export_value_type: str | None = None
    diagnostics: list[Diagnostic] = field(default_factory=list)

    @property
    def error_diagnostics(self) -> list[Diagnostic]:
        """The error-severity diagnostics attached to this top level."""
        return [diagnostic for diagnostic in self.diagnostics if diagnostic.severity == "error"]

    def has_diagnostic(self, code: str, line: int | None = None, column: int | None = None) -> bool:
        """Report whether a diagnostic with the given code (and optional location) exists."""
        for diagnostic in self.diagnostics:
            if diagnostic.code != code:
                continue
            if line is not None and diagnostic.line != line:
                continue
            if column is not None and diagnostic.column != column:
                continue
            return True
        return False

    def add_diagnostic(self, diagnostic: Diagnostic) -> None:
        """Append a diagnostic, de-duplicating on (code, line, column)."""
        if self.has_diagnostic(diagnostic.code, diagnostic.line, diagnostic.column):
            return
        self.diagnostics.append(diagnostic)

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this top-level analysis."""
        return {
            "name": self.name,
            "qualname": self.qualname,
            "module_name": self.module_name,
            "file_path": self.file_path,
            "line": self.line,
            "column": self.column,
            "is_native_candidate": self.is_native_candidate,
            "accepted": self.accepted,
            "assigned_types": dict(sorted(self.assigned_types.items())),
            "export_value_type": self.export_value_type,
            "diagnostics": [diagnostic.to_dict() for diagnostic in self.diagnostics],
        }


@dataclass
class ModuleAnalysis:
    """The analysis of one module file: its functions, imports, and top level."""

    module_name: str
    file_path: str
    functions: list[FunctionAnalysis] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    imports: dict[str, str] = field(default_factory=dict)
    logger_names: tuple[str, ...] = ()
    # Process-global ``logging.getLogger`` cache groups proven for each accepted
    # receiver.  Equal exact names share a group across source modules; dynamic
    # names use the global unknown group and may alias every exact group.
    logger_group_targets: dict[str, tuple[str, ...]] = field(default_factory=dict)
    import_policies: tuple[ImportPolicyDecision, ...] = ()
    top_level: TopLevelAnalysis | None = None
    # The module's shared final-binding authority (see FunctionAnalysis).
    module_bindings: ModuleBindings | None = None
    # The same immutable project-wide qualified-mutation authority attached to
    # each function.  IR/wrapper generation consumes it as a defensive gate so
    # a malformed accepted list cannot lower a source-mutated target.
    project_mutations: ProjectMutations = _EMPTY_MUTATIONS
    # Project-owned module/package names used by analyzer and defensive IR gates
    # to distinguish a genuine stdlib import from a same-named local module.
    project_modules: frozenset[str] = frozenset()

    @property
    def functions_by_name(self) -> dict[str, FunctionAnalysis]:
        """Map each function's local name to its analysis."""
        return {function.name: function for function in self.functions}

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this module analysis."""
        return {
            "module_name": self.module_name,
            "file_path": self.file_path,
            "imports": dict(sorted(self.imports.items())),
            "import_policies": [decision.to_dict() for decision in self.import_policies],
            "logger_names": list(self.logger_names),
            "logger_group_targets": {
                name: list(targets) for name, targets in sorted(self.logger_group_targets.items())
            },
            "functions": [function.to_dict() for function in self.functions],
            "top_level": self.top_level.to_dict() if self.top_level is not None else None,
            "diagnostics": [diagnostic.to_dict() for diagnostic in self.diagnostics],
        }


@dataclass
class ProjectAnalysis:
    """The analysis of a whole project: its modules and the derived candidate views."""

    project_root: Path
    modules: list[ModuleAnalysis] = field(default_factory=list)
    # The single project-wide final-binding authority (one ``ModuleBindings`` per
    # module), built once and shared by module parsing, callable indexing, the
    # resolver, and the build gate — even when no plugin is active — so no path
    # re-derives a divergent copy (plugin API 1.3, WP-4, director follow-up 7 P1-4).
    project_bindings: ProjectBindings = field(default_factory=lambda: ProjectBindings({}))
    # The shared project-wide module-load mutation authority (see
    # ``FunctionAnalysis.project_mutations``), used by the boundary resolver and
    # the definition/build gate.
    project_mutations: ProjectMutations = _EMPTY_MUTATIONS

    @property
    def native_candidates(self) -> list[FunctionAnalysis]:
        """All native-candidate functions across modules, sorted by qualname."""
        return sorted(
            [
                function
                for module in self.modules
                for function in module.functions
                if function.is_native_candidate
            ],
            key=lambda function: function.qualname,
        )

    @property
    def accepted_native_functions(self) -> list[FunctionAnalysis]:
        """The native candidates that were accepted for direct-Rust lowering."""
        return sorted(
            [function for function in self.native_candidates if function.accepted],
            key=lambda function: function.qualname,
        )

    @property
    def rejected_native_functions(self) -> list[FunctionAnalysis]:
        """The native candidates that were rejected (kept on Python fallback)."""
        return sorted(
            [function for function in self.native_candidates if not function.accepted],
            key=lambda function: function.qualname,
        )

    @property
    def embedding_candidates(self) -> list[FunctionAnalysis]:
        """The functions eligible for the experimental scalar-helper embedding."""
        return sorted(
            [
                function
                for module in self.modules
                for function in module.functions
                if function.is_embedding_candidate
            ],
            key=lambda function: function.qualname,
        )

    @property
    def native_top_levels(self) -> list[TopLevelAnalysis]:
        """All top-level native candidates across modules, sorted by qualname."""
        return sorted(
            [
                module.top_level
                for module in self.modules
                if module.top_level is not None and module.top_level.is_native_candidate
            ],
            key=lambda top_level: top_level.qualname,
        )

    @property
    def accepted_native_top_levels(self) -> list[TopLevelAnalysis]:
        """The top-level native candidates that were accepted."""
        return sorted(
            [top_level for top_level in self.native_top_levels if top_level.accepted],
            key=lambda top_level: top_level.qualname,
        )

    def requires_native_build(self) -> bool:
        """Whether building this project produces a native artifact (needs cargo).

        Single source of truth for "does this build need the Rust toolchain". It
        mirrors the build plan's ``has_native_artifacts``: only an *accepted*
        native function or top level produces a native module. embedding candidates are
        deliberately excluded — an embedding helper is compiled into the native module
        only when an accepted native function already exists (so it is covered),
        and a project with embedding candidates but no accepted native produces no
        native artifact and must still build its pure-Python fallback.
        """
        return bool(self.accepted_native_functions or self.accepted_native_top_levels)

    @property
    def rejected_native_top_levels(self) -> list[TopLevelAnalysis]:
        """The top-level native candidates that were rejected."""
        return sorted(
            [top_level for top_level in self.native_top_levels if not top_level.accepted],
            key=lambda top_level: top_level.qualname,
        )

    @property
    def diagnostics(self) -> list[Diagnostic]:
        """Every diagnostic across the project, ordered by source location and code."""
        diagnostics: list[Diagnostic] = []
        for module in self.modules:
            diagnostics.extend(module.diagnostics)
            for function in module.functions:
                diagnostics.extend(function.diagnostics)
            if module.top_level is not None:
                diagnostics.extend(module.top_level.diagnostics)
        return sorted(
            diagnostics,
            key=lambda diagnostic: (
                diagnostic.file_path,
                diagnostic.line or 0,
                diagnostic.column or 0,
                diagnostic.code,
            ),
        )

    @property
    def boundary_warnings(self) -> list[Diagnostic]:
        """The native/fallback boundary warnings (RXT073)."""
        return [
            diagnostic
            for diagnostic in self.diagnostics
            if diagnostic.code == "RXT073" and diagnostic.severity == "warning"
        ]

    @property
    def has_error_diagnostics(self) -> bool:
        """Report whether any diagnostic in the project is an error."""
        return any(diagnostic.severity == "error" for diagnostic in self.diagnostics)

    @property
    def has_parse_errors(self) -> bool:
        """Report whether any candidate module failed to parse (RXT000).

        A parse error means a candidate could not even be analyzed, which is a
        genuine failure. A subset *rejection* (RXT010, boundary codes, ...) is an
        expected outcome — the function simply stays on the Python fallback — so
        it is not treated as a failure by ``rextio check``.
        """
        return any(diagnostic.code == "RXT000" for diagnostic in self.diagnostics)

    def module_for_function(self, function: FunctionAnalysis) -> ModuleAnalysis | None:
        """Return the module owning the given function, or None."""
        for module in self.modules:
            if module.module_name == function.module_name:
                return module
        return None

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of the whole project analysis."""
        return {
            "contract_version": TOOLING_CONTRACT_VERSION,
            "project_root": str(self.project_root),
            "modules": [module.to_dict() for module in self.modules],
            "native_candidates": [function.qualname for function in self.native_candidates],
            "accepted_native": [function.qualname for function in self.accepted_native_functions],
            "rejected_native": [function.qualname for function in self.rejected_native_functions],
            "embedding_candidates": [function.qualname for function in self.embedding_candidates],
            "native_top_levels": [top_level.qualname for top_level in self.native_top_levels],
            "accepted_native_top_levels": [
                top_level.qualname for top_level in self.accepted_native_top_levels
            ],
            "rejected_native_top_levels": [
                top_level.qualname for top_level in self.rejected_native_top_levels
            ],
            "diagnostics": [diagnostic.to_dict() for diagnostic in self.diagnostics],
        }
