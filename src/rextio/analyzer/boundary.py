"""Native/fallback boundary checks (RXT07x): which native↔fallback crossings are allowed or warned."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rextio.analyzer.common_calls import COMMON_DIRECT_RUST_CALLS
from rextio.analyzer.call_resolution import FunctionResolver
from rextio.analyzer.diagnostics import Diagnostic
from rextio.analyzer.final_bindings import BindingKind, definition_is_final
from rextio.analyzer.import_policy import decision_for_target
from rextio.analyzer.models import CallSite, FunctionAnalysis, ModuleAnalysis, ProjectAnalysis
from rextio.ir.types import normalize_type_name

if TYPE_CHECKING:
    from rextio.source.external_linkage import ExternalNativeRegistry

SUPPORTED_INTERNAL_CALLS = {
    "abs",
    "len",
    "max",
    "min",
    "range",
    "sum",
    "enumerate",
    "zip",
    "math.cos",
    "math.floor",
    "math.sin",
    "math.sqrt",
    *COMMON_DIRECT_RUST_CALLS,
}

BOUNDARY_DIAGNOSTIC_MESSAGES = {
    "RXT070": "Native function calls fallback-only function.",
    "RXT072": "Native dependency rejected, so caller must fall back.",
    "RXT073": "Native function call inside Python loop may erase speedup.",
    "RXT074": "Undecorated function depends on a runtime-shim native; mark it @rextio.native to opt in.",
    "RXT075": "Native function performs a scalar boundary call to the Python fallback.",
    "RXT076": "Scalar boundary call inside a native loop keeps the caller on fallback.",
}


def apply_boundary_checks(
    analysis: ProjectAnalysis,
    boundary_warnings: bool = True,
    embedding_enabled: bool = False,
    delegate_fallback: bool = False,
    external_native_registry: ExternalNativeRegistry | None = None,
) -> None:
    """Apply the native/fallback boundary policy, attaching RXT07x diagnostics."""
    resolver = FunctionResolver(analysis)
    for function in analysis.native_candidates:
        function.accepted = not function.error_diagnostics

    # Definition/build-output gate (plugin API 1.3, WP-4): a native function may
    # be built and installed in the generated wrapper ONLY when its defining
    # module's final binding for its own visible name is EXACTLY this def (matched
    # by exact origin, not merely a qualname). A function overwritten by a later
    # class/assignment/`del`/conditional binder — or shadowed by a later wildcard
    # import — is stale: Python resolves the name to the overwriting object, so
    # installing the native function would replace it and silently diverge (e.g.
    # `def good` then `class good`: CPython's `good(x)` runs the class, native
    # would run the stale function). Duplicate defs keep only the last. Fail closed
    # to the Python fallback, which resolves the name correctly.
    for function in analysis.native_candidates:
        if not function.accepted:
            continue
        if function.enclosing_class_name is not None:
            # A native method is gated against its enclosing class + method final
            # binding at collection time (its `name` is a class attribute, not a
            # module binding), so the module-level function gate does not apply.
            continue
        if not definition_is_final(
            function.module_bindings,
            function.name,
            BindingKind.FUNCTION,
            function.line,
            function.column,
        ):
            function.accepted = False
            function.add_diagnostic(
                Diagnostic(
                    code="RXT010",
                    severity="error",
                    message=(
                        "native function is not its module's final binding for "
                        f"{function.name!r}; a later class/assignment/del/conditional "
                        "binder or wildcard import overrides it, so installing the "
                        "native function would diverge from CPython"
                    ),
                    file_path=function.file_path,
                    line=function.line,
                    column=function.column,
                    function_name=function.qualname,
                    suggestion=(
                        "Remove the overriding binding, or leave this function on the "
                        "Python fallback so the module-final object is used."
                    ),
                )
            )

    # Mutation gate (plugin API 1.3, WP-4, P0-4): a native function whose own
    # qualname is a project module attribute rebound at module load
    # (`import pkg.helper as h; h.good = …` in another module) must not be installed
    # in the generated wrapper — Python resolves the module attribute to the rebound
    # object, so a compiled sibling/re-export reaching it would use the stale native
    # target. Fail closed to the Python fallback (the module attribute is honored).
    for function in analysis.native_candidates:
        if function.accepted and analysis.project_mutations.target_is_mutated(function.qualname):
            function.accepted = False
            function.add_diagnostic(
                Diagnostic(
                    code="RXT010",
                    severity="error",
                    message=(
                        f"native function {function.qualname} is a module attribute "
                        "rebound at module load (setattr/attribute assignment in a "
                        "project module), so installing the native target would diverge "
                        "from the rebound object CPython resolves"
                    ),
                    file_path=function.file_path,
                    line=function.line,
                    column=function.column,
                    function_name=function.qualname,
                    suggestion=(
                        "Remove the module-load attribute mutation, or leave this "
                        "function on the Python fallback so the rebound object is used."
                    ),
                )
            )

    # Method definition gate (plugin API 1.3, WP-4, P0-2): defensively re-verify
    # that an accepted native method's enclosing class is still the module's exact
    # final CLASS binding (the collection pass also checks the method's class-body
    # final binding). A malformed accepted list cannot install a method onto a stale
    # or duplicate class — Python resolves the final class, whose namespace would not
    # carry this method.
    for function in analysis.native_candidates:
        if not function.accepted or function.enclosing_class_name is None:
            continue
        if not definition_is_final(
            function.module_bindings,
            function.enclosing_class_name,
            BindingKind.CLASS,
            function.enclosing_class_line,
            function.enclosing_class_column,
        ):
            function.accepted = False
            function.add_diagnostic(
                Diagnostic(
                    code="RXT010",
                    severity="error",
                    message=(
                        f"native method {function.qualname} belongs to a class that is not "
                        "the module's final CLASS binding, so installing it would target a "
                        "stale or duplicate class"
                    ),
                    file_path=function.file_path,
                    line=function.line,
                    column=function.column,
                    function_name=function.qualname,
                    suggestion=(
                        "Remove the duplicate/overwriting class binding, or leave the "
                        "method on the Python fallback."
                    ),
                )
            )

    # Resident values (opaque, native-only — plugin API 1.3) must never cross an
    # exported PyO3 boundary. An auto-discovered resident-signature function is
    # kept as a non-exported native-only helper (codegen omits its #[pyfunction]
    # and Python-dispatch wrapper). But an EXPLICITLY marked @rextio.native
    # function is a request for a Python-callable native export, which a resident
    # parameter/return cannot honor — fail closed with RXT092 rather than emit a
    # boundary that silently leaks or cannot compile.
    for function in analysis.native_candidates:
        if function.accepted and function.explicitly_marked and function.has_resident_signature:
            function.accepted = False
            function.add_diagnostic(
                Diagnostic(
                    code="RXT092",
                    severity="error",
                    message=(
                        "explicitly marked native function has a resident plugin type "
                        f"in its signature: {function.qualname}; a resident (opaque, "
                        "native-only) value has no Python boundary conversion and "
                        "cannot cross an exported PyO3 parameter or return"
                    ),
                    file_path=function.file_path,
                    line=function.line,
                    column=function.column,
                    function_name=function.qualname,
                    suggestion=(
                        "Remove the @rextio.native marker so it can serve as an "
                        "internal native-to-native helper, or use a materialized "
                        "plugin type (with a boundary conversion) for the boundary."
                    ),
                )
            )

    changed = True
    while changed:
        changed = False
        for module in analysis.modules:
            for function in sorted(module.functions, key=lambda item: item.qualname):
                if not function.is_native_candidate or not function.accepted:
                    continue
                runtime_dependency = _first_runtime_dependency(module, function, resolver)
                if runtime_dependency is not None:
                    call, dependency = runtime_dependency
                    if function.explicitly_marked:
                        # An explicitly opted-in function inherits the runtime
                        # semantics shim required by its native dependency.
                        function.native_runtime_semantics = True
                        function.add_diagnostic(
                            _runtime_shim_propagation_diagnostic(function, dependency, call)
                        )
                    else:
                        # Auto-discovered functions are not silently promoted to
                        # the RXT080 shim through the call graph (P0-4); they fall
                        # back to Python unless explicitly marked @rextio.native.
                        function.accepted = False
                        function.add_diagnostic(
                            _runtime_shim_requires_marker_diagnostic(function, dependency, call)
                        )
                    changed = True
                    continue
                boundary_errors = _boundary_errors(
                    module,
                    function,
                    resolver,
                    embedding_enabled=embedding_enabled,
                    delegate_fallback=delegate_fallback,
                    external_native_registry=external_native_registry,
                )
                if boundary_errors:
                    for diagnostic in boundary_errors:
                        function.add_diagnostic(diagnostic)
                    function.accepted = False
                    changed = True

    if boundary_warnings:
        _add_python_loop_boundary_warnings(analysis, resolver)


# Types a delegated call can serialize across the JSON wire protocol and type on
# the Rust side. Only immutable scalars: a mutable container crosses the wire by
# value (a JSON copy), which severs the aliasing CPython would preserve, so it
# cannot be delegated as an argument *or* a return without a silent divergence.
# bytes/tuple/dict/list/set need a tagged, reference-preserving encoding and are a
# follow-up. Capitalized/`typing.`-qualified aliases are normalized first.
_DELEGATABLE_SCALARS = frozenset({"int", "float", "bool", "str", "None"})


def _is_delegatable_return_type(type_name: str | None) -> bool:
    # A mutable-container *return* (list/dict/set) is not delegatable either: the
    # returned value may alias persistent Python state, so if the native caller
    # mutates its by-value copy the divergence from CPython is silent (the analyzer
    # cannot prove the callee returned an unaliased fresh container). Scalars only.
    return normalize_type_name(type_name) in _DELEGATABLE_SCALARS


def _is_delegatable_arg_type(type_name: str | None) -> bool:
    # A mutable-container argument (list/dict/set) cannot be delegated: the callee
    # is a black box that may mutate it in place, but arguments cross the wire by
    # value (a JSON copy), so any in-place mutation would be silently lost. Only
    # immutable scalars are safe to pass as delegated-call arguments.
    return normalize_type_name(type_name) in _DELEGATABLE_SCALARS


def _is_delegatable(
    dependency: FunctionAnalysis,
    function: FunctionAnalysis,
    call: CallSite,
) -> bool:
    """Whether a fallback call can faithfully cross an interpreter-mediated boundary.

    Gates BOTH crossing mechanisms: dispatcher delegation over the IPC wire
    protocol (values cross as a JSON copy) and in-process scalar boundary
    calls (RXT075; values re-enter the interpreter from the native caller's
    extracted copies). Requires the callee's return type *and* every argument
    type to be an immutable scalar. A mutable container crosses either
    boundary by value, which severs the aliasing CPython preserves: a callee
    mutating a container argument, or the native caller mutating a returned
    container that aliased Python state, would diverge silently. When a type
    is unknown the call does *not* cross (it stays a rejection, keeping the
    caller on the Python fallback), so neither mechanism guesses and neither
    silently drops a mutation.
    """
    return_type = (
        dependency.signature_return_type
        or dependency.inferred_return_type
        or dependency.annotated_return_type
    )
    if not _is_delegatable_return_type(return_type):
        return False
    arg_types = function.call_arg_types.get((call.line, call.column), call.arg_types)
    return all(_is_delegatable_arg_type(arg_type) for arg_type in arg_types)


def _boundary_errors(
    module: ModuleAnalysis,
    function: FunctionAnalysis,
    resolver: FunctionResolver,
    embedding_enabled: bool = False,
    delegate_fallback: bool = False,
    external_native_registry: ExternalNativeRegistry | None = None,
) -> list[Diagnostic]:
    if function.native_runtime_semantics:
        return []
    diagnostics: list[Diagnostic] = []
    for call in function.calls:
        target = call.target
        # A covering plugin's Rejected verdict wins over every other branch of
        # this loop — checked FIRST so no early `continue` (internal-call
        # allowlist, `.append`, dependency handling) can swallow it. Council
        # round 4: a rejected `numpy.append` (matching the `.append` list
        # special case) was recorded but never delivered, leaving the function
        # accepted with an un-lowerable call. Claimed sites never carry a
        # rejection (the engine records one only when no plugin claims), so
        # this cannot misfire on legal claimed calls.
        claim_rejection = next(
            (
                rejection.diagnostic
                for rejection in function.plugin_claim_rejections
                if rejection.kind == "call"
                and rejection.diagnostic.line == call.line
                and rejection.diagnostic.column == call.column
            ),
            None,
        )
        if claim_rejection is not None:
            diagnostics.append(claim_rejection)
            continue
        resolved = resolver.resolve(module, target)
        if target in SUPPORTED_INTERNAL_CALLS or target.endswith(".append"):
            continue
        if (
            external_native_registry is not None
            and external_native_registry.resolve_for(module, function, call) is not None
        ):
            continue
        dependency = resolved.function
        if embedding_enabled and dependency is not None and dependency.is_embedding_candidate:
            # embedding candidates are lowered to a typed native inner function just like
            # accepted native siblings, so the same call-compatibility check applies.
            diagnostics.extend(
                _native_arg_type_errors(module, function, call, dependency, resolver)
            )
            continue
        if (
            delegate_fallback
            and dependency is not None
            and (not dependency.is_native_candidate or not dependency.accepted)
            and _is_delegatable(dependency, function, call)
        ):
            # Rust-executable delegate mode: a project function that lives on the
            # Python fallback (unsupported subset, RXT070) or was rejected from
            # native (RXT072) is not an error here — the generated binary calls it
            # in the external CPython dispatcher instead. It runs real CPython, so
            # the result is CPython-equivalent (not a silent miscompile).
            function.delegated_call_targets.add(dependency.qualname)
            continue
        if (
            not delegate_fallback
            and function.explicitly_marked
            and dependency is not None
            and (not dependency.is_native_candidate or not dependency.accepted)
            and _is_delegatable(dependency, function, call)
        ):
            # In-process scalar boundary call: the callee stays on the Python
            # fallback and the generated native code calls it through the
            # interpreter at run time. Real CPython executes the callee, so the
            # result is CPython-equivalent; only immutable scalars may cross
            # (the same rule as dispatcher delegation - containers would sever
            # aliasing). Explicitly marked callers only: an auto-discovered
            # candidate never silently acquires interpreter calls (the same
            # conservatism as the RXT080 marker rule).
            if call.in_loop:
                # Frequency is not statically boundable, but position is: a
                # per-iteration interpreter round-trip predictably erases the
                # native speedup, so a loop-positioned boundary call keeps the
                # caller on the Python fallback instead.
                diagnostics.append(
                    Diagnostic(
                        code="RXT076",
                        severity="error",
                        message=(
                            f"scalar boundary call inside a native loop: {resolved.resolved_target}"
                        ),
                        file_path=function.file_path,
                        line=call.line,
                        column=call.column,
                        function_name=function.qualname,
                        suggestion=(
                            "Hoist the call out of the loop, mark the callee "
                            "@rextio.native if it fits the supported subset, or "
                            "enable [embedding] if the callee is an eligible "
                            "unmarked scalar helper (@rextio.exempt callees "
                            "never embed)."
                        ),
                    )
                )
                continue
            function.boundary_call_targets.add(dependency.qualname)
            function.add_diagnostic(
                Diagnostic(
                    code="RXT075",
                    severity="info",
                    message=(
                        "native function performs a scalar boundary call to the "
                        f"Python fallback: {resolved.resolved_target}"
                    ),
                    file_path=function.file_path,
                    line=call.line,
                    column=call.column,
                    function_name=function.qualname,
                    suggestion=(
                        "Each call crosses the native/Python boundary at run time "
                        "and counts toward the boundary-fallback threshold. Scalars "
                        "cross by value: the callee observes equal values, not the "
                        "caller's original objects, so identity checks (`is`) on "
                        "arguments are not preserved (None/bool singletons are)."
                    ),
                )
            )
            continue
        if dependency is not None and not dependency.is_native_candidate:
            diagnostics.append(
                Diagnostic(
                    code="RXT070",
                    severity="error",
                    message=f"native function calls fallback-only function: {resolved.resolved_target}",
                    file_path=function.file_path,
                    line=call.line,
                    column=call.column,
                    function_name=function.qualname,
                    suggestion=(
                        "Mark the dependency as @rextio.native if it belongs to the supported subset, "
                        "or remove the call from the native function."
                    ),
                )
            )
            continue
        if dependency is not None and not dependency.accepted:
            diagnostics.append(
                Diagnostic(
                    code="RXT072",
                    severity="error",
                    message=f"native dependency rejected, so caller must fall back: {resolved.resolved_target}",
                    file_path=function.file_path,
                    line=call.line,
                    column=call.column,
                    function_name=function.qualname,
                    suggestion="Fix the rejected native dependency or keep this caller on fallback.",
                )
            )
            continue
        if dependency is not None and dependency.has_materialized_plugin_type:
            # NOTE: a REJECTED plugin-typed callee is reported as RXT072
            # (dependency rejected) by the earlier branch — deliberate:
            # RXT092 marks calls into otherwise-healthy plugin-typed
            # functions; tooling keying on RXT092 should also handle RXT072.
            # A MATERIALIZED plugin-typed function compiles as a PyO3 boundary
            # entry point (interpreter token + conversion parameter types); a
            # native call into it would emit Rust with the wrong arity and
            # types. Such functions stay Python-facing only in this release.
            #
            # A RESIDENT-only callee (opaque, no boundary conversion — plugin
            # API 1.3) is exempt: it is a native-only helper, so the call falls
            # through to the native-to-native signature check below, which
            # understands resident plugin type keys.
            diagnostics.append(
                Diagnostic(
                    code="RXT092",
                    severity="error",
                    message=(
                        "native function calls a plugin-typed function: "
                        f"{resolved.resolved_target}; materialized plugin-typed "
                        "functions are Python-facing entry points in this release"
                    ),
                    file_path=function.file_path,
                    line=call.line,
                    column=call.column,
                    function_name=function.qualname,
                    suggestion=(
                        "Call the plugin-typed function from Python fallback code, "
                        "or inline the covered operations into this function."
                    ),
                )
            )
            continue
        if dependency is not None:
            diagnostics.extend(
                _native_arg_type_errors(module, function, call, dependency, resolver)
            )
            continue

        if any(
            claim.kind == "call" and claim.line == call.line and claim.column == call.column
            for claim in function.plugin_claims
        ):
            # An active lowering plugin claimed this call at analysis time
            # (docs/specs/plugin-lowering.md): it is legal, the plugin emits it.
            continue
        decision = decision_for_target(module, resolved.resolved_target)
        message, suggestion = _external_call_diagnostic_text(
            resolved.resolved_target, call.in_loop, decision
        )
        diagnostics.append(
            Diagnostic(
                code="RXT030",
                severity="error",
                message=message,
                file_path=function.file_path,
                line=call.line,
                column=call.column,
                function_name=function.qualname,
                suggestion=suggestion,
            )
        )
    # Claim rejections recorded at sites that are not calls (binops and
    # comparisons have no CallSite) never match the loop above; attach them
    # here so a plugin's
    # Rejected verdict always rejects the function with its own guidance.
    # Matching is KIND-aware: a rejected binop can share its start position
    # with a claimed call (`np.dot(a, b) + c`), so position alone must not
    # suppress delivery.
    call_positions = {(call.line, call.column) for call in function.calls}
    for rejection in function.plugin_claim_rejections:
        if (
            rejection.kind == "call"
            and (
                rejection.diagnostic.line,
                rejection.diagnostic.column,
            )
            in call_positions
        ):
            continue
        diagnostics.append(rejection.diagnostic)
    return diagnostics


_SCALAR_PARAM_TYPES = {"int", "float", "bool", "str", "bytes"}
# Parameter types lowered to a concrete fixed Rust type (Vec/HashMap/tuple/HashSet)
# that requires an exactly-matching argument — no coercion from a scalar or a
# differently-parameterised container. `Optional[...]` / `... | None` are excluded:
# they admit the inner type or None, so exact-string equality is not the right test.
_CONTAINER_PARAM_PREFIXES = ("list[", "tuple[", "dict[", "set[", "frozenset[")


def _positional_param_types(dependency: FunctionAnalysis) -> list[str | None]:
    """Return the callee's positional parameter types, in order, with plugin keys.

    ``signature_arg_types`` holds only core-typed parameters (resident
    plugin-typed parameters are absent), so a positional list built from it
    alone would be misaligned once a plugin-typed parameter appears. This walks
    the recorded positional parameter names and resolves each to its core type,
    its resident plugin type key, or ``None`` (undetermined).
    """
    if not dependency.positional_param_names:
        # Signature was never captured positionally (e.g. runtime-shim methods);
        # preserve the legacy core-only view.
        return list(dependency.signature_arg_types.values())
    types: list[str | None] = []
    for name in dependency.positional_param_names:
        if name in dependency.signature_arg_types:
            types.append(dependency.signature_arg_types[name])
        elif name in dependency.signature_plugin_keys:
            types.append(dependency.signature_plugin_keys[name])
        else:
            types.append(None)
    return types


def _native_arg_type_errors(
    module: ModuleAnalysis,
    function: FunctionAnalysis,
    call: CallSite,
    dependency: FunctionAnalysis,
    resolver: FunctionResolver,
) -> list[Diagnostic]:
    """Reject native→native calls that are not compatible with the callee signature.

    The lowered Rust inner function has a fixed positional arity and exact scalar
    parameter types with no implicit coercion and no default arguments, so a call
    that CPython accepts can still emit Rust that fails ``cargo build`` (or, for
    keyword-only parameters, silently diverge from CPython):

    - a callee with keyword-only parameters cannot be called faithfully through the
      native convention (keyword call arguments are unsupported, and a keyword-only
      parameter supplied positionally diverges from CPython's ``TypeError``);
    - too few or too many positional arguments vs the callee's positional arity
      (including a genuine zero-parameter callee) -> E0061;
    - a scalar argument of a different type than the parameter (``g(1.2)`` where
      ``g(x: int)``, or ``g(1)`` where ``g(x: float)``) -> E0308, or a scalar
      argument whose type cannot be proven to match.

    The contract requires keeping such a caller on the Python fallback (RXT010)
    rather than silently building broken or divergent native code.

    Argument types come from the caller's inferred ``call_arg_types`` (which covers
    non-literal arguments such as known locals and resolved nested calls) when
    available, falling back to the literal-only ``CallSite.arg_types``. Arity is
    checked against ``positional_param_count`` (``None`` only for callees whose
    signature was never captured, e.g. runtime-shim methods).
    """
    diagnostics: list[Diagnostic] = []

    if dependency.has_keyword_only_params:
        diagnostics.append(
            Diagnostic(
                code="RXT010",
                severity="error",
                message=(
                    f"native call to {dependency.qualname} targets a function with "
                    "keyword-only parameters, which cannot be supplied through the native "
                    "calling convention (keyword arguments are unsupported, and a "
                    "positional argument for a keyword-only parameter diverges from CPython)"
                ),
                file_path=function.file_path,
                line=call.line,
                column=call.column,
                function_name=function.qualname,
                suggestion=(
                    "Remove the keyword-only parameters from the native callee, or keep "
                    "this caller on the Python fallback."
                ),
            )
        )
        return diagnostics

    param_types = _positional_param_types(dependency)
    # Positions whose parameter is a plugin type key (resident, plugin API 1.3):
    # native-to-native compatibility requires the caller's argument to carry the
    # exact same key. A materialized-typed callee never reaches here (RXT092).
    plugin_param_keys = {
        index: dependency.signature_plugin_keys[name]
        for index, name in enumerate(dependency.positional_param_names)
        if name in dependency.signature_plugin_keys
    }
    arg_types = list(function.call_arg_types.get((call.line, call.column), call.arg_types))
    arg_targets = function.call_arg_targets.get((call.line, call.column), ())

    # Resolve every nested call argument's type through the project resolver, which
    # spans modules and is the authoritative source of acceptance. Only trust a
    # resolved callee's return type when that callee is actually lowered to typed
    # native code (accepted, and not a runtime-semantics shim); a rejected,
    # fallback-only, or shim callee leaves the argument type unknown so the
    # conservative backstop keeps the caller on the Python fallback. (The locally
    # inferred type, when present, already agrees for accepted same-module callees.)
    for index in range(len(arg_types)):
        if index >= len(arg_targets):
            break
        target = arg_targets[index]
        if target is None:
            continue
        resolved = resolver.resolve(module, target).function
        if resolved is None:
            # Not a project function (a supported builtin / standard-library call,
            # or unresolved): trust the locally-inferred argument type rather than
            # discarding it, which would falsely reject e.g. take_int(len(xs)).
            continue
        if resolved.accepted and not resolved.native_runtime_semantics:
            # `accepted` (no error diagnostics) covers a valid embedding candidate too; a
            # rejected one is not accepted and must not be trusted.
            arg_types[index] = resolved.signature_return_type
        else:
            # A rejected, fallback-only, or runtime-shim project function is not
            # lowered to typed native code, so its result type cannot be trusted to
            # keep the caller native.
            arg_types[index] = None

    if (
        dependency.positional_param_count is not None
        and len(arg_types) != dependency.positional_param_count
    ):
        diagnostics.append(
            Diagnostic(
                code="RXT010",
                severity="error",
                message=(
                    f"native call to {dependency.qualname} passes {len(arg_types)} "
                    f"argument(s) but the native function takes "
                    f"{dependency.positional_param_count}; the lowered Rust function has a "
                    "fixed arity with no default arguments, so this would emit native code "
                    "that fails to compile"
                ),
                file_path=function.file_path,
                line=call.line,
                column=call.column,
                function_name=function.qualname,
                suggestion=(
                    "Pass exactly one argument per native parameter (defaults are not "
                    "lowered), or keep this caller on the Python fallback."
                ),
            )
        )
        return diagnostics

    for index, arg_type in enumerate(arg_types):
        expected_key = plugin_param_keys.get(index)
        if expected_key is not None:
            # A resident plugin-typed parameter: the argument must carry the
            # exact same registered plugin type key (no coercion). Anything else
            # — a core value, a different plugin type, or an undetermined type —
            # keeps the caller on the Python fallback.
            if arg_type == expected_key:
                continue
            actual = arg_type if arg_type is not None else "an undetermined type"
            diagnostics.append(
                Diagnostic(
                    code="RXT010",
                    severity="error",
                    message=(
                        f"native call argument {index + 1} to {dependency.qualname} has "
                        f"{actual} but the parameter is the plugin type {expected_key!r}; "
                        "a resident plugin value must match the registered type key "
                        "exactly, so this would emit native code that fails to compile"
                    ),
                    file_path=function.file_path,
                    line=call.line,
                    column=call.column,
                    function_name=function.qualname,
                    suggestion=(
                        "Pass a value of the exact plugin type, or keep this caller "
                        "on the Python fallback."
                    ),
                )
            )
            continue
        if index >= len(param_types):
            continue
        param_type = param_types[index]
        if param_type is None:
            continue
        if arg_type == param_type:
            continue
        is_optional = param_type.startswith("Optional[") or (
            "|" in param_type and "None" in param_type
        )
        if is_optional and arg_type == "None":
            # A bare `None` literal lowers to `Option::None`, valid for any
            # `Optional[...]` / `... | None` parameter.
            continue
        is_scalar = param_type in _SCALAR_PARAM_TYPES
        is_container = param_type.startswith(_CONTAINER_PARAM_PREFIXES)
        if not (is_scalar or is_container or is_optional):
            # Any other looser parameter type: leave to the existing passes rather
            # than over-rejecting on string inequality.
            continue
        if arg_type is None and not is_scalar:
            # An argument whose type could not be inferred against a container or
            # optional parameter: do not reject (would over-reject valid args); the
            # conservative undetermined-type backstop applies to scalars only.
            continue
        actual = arg_type if arg_type is not None else "an undetermined type"
        diagnostics.append(
            Diagnostic(
                code="RXT010",
                severity="error",
                message=(
                    f"native call argument {index + 1} to {dependency.qualname} has "
                    f"{actual} but the parameter is {param_type}; the lowered Rust type "
                    "must match exactly (no scalar/container coercion), so this would "
                    "emit native code that fails to compile"
                ),
                file_path=function.file_path,
                line=call.line,
                column=call.column,
                function_name=function.qualname,
                suggestion=(
                    "Pass an argument whose type matches the native parameter exactly "
                    "(no int/float/bool mixing), or keep this caller on the Python fallback."
                ),
            )
        )
    return diagnostics


def _external_call_diagnostic_text(target: str, in_loop: bool, decision) -> tuple[str, str]:
    if decision is None:
        return (
            f"unsupported unresolved call in native function: {target}",
            "Native functions may call only accepted native functions and supported builtins.",
        )
    if decision.origin == "stdlib":
        return (
            f"unsupported standard-library call in native function: {target}",
            "Use a supported Rextio standard-library subset call or keep this function on fallback.",
        )
    if decision.policy == "plugin":
        plugin = decision.plugin or "<unconfigured>"
        return (
            f"plugin-managed external package call is not lowered by this build: {target}",
            (
                f"Ensure plugin {plugin!r} is active and provides a direct lowering rule for this "
                "call form (keyword-argument calls are never claimed - use positional arguments), "
                "or keep the function on fallback."
            ),
        )
    if decision.policy == "try-native":
        return (
            f"external package call requires experimental dependency lowering and remains fallback: {target}",
            _external_package_suggestion(
                in_loop, "dependency lowering is opt-in and not available for this call"
            ),
        )
    if decision.policy == "analyze":
        return (
            f"external package call is analyze-only and remains fallback: {target}",
            _external_package_suggestion(
                in_loop, "switch this package to try-native only if it is pure Python and safe"
            ),
        )
    return (
        f"external package call uses fallback import policy: {target}",
        _external_package_suggestion(
            in_loop, "add a Rextio plugin or explicit try-native package policy if needed"
        ),
    )


def _external_package_suggestion(in_loop: bool, action: str) -> str:
    base = (
        f"{action}; otherwise keep this function on CPython/Nuitka fallback so Rextio does not "
        "silently transform third-party package code."
    )
    if not in_loop:
        return base
    return (
        f"{base} This call is inside a loop, so prefer function-level fallback, a package plugin, "
        "or a batch API refactor to avoid repeated Python/Rust boundary crossings."
    )


def _first_runtime_dependency(
    module: ModuleAnalysis,
    function: FunctionAnalysis,
    resolver: FunctionResolver,
) -> tuple[CallSite, FunctionAnalysis] | None:
    if function.native_runtime_semantics:
        return None
    for call in function.calls:
        dependency = resolver.resolve(module, call.target).function
        if dependency is None or not dependency.accepted or not dependency.native_runtime_semantics:
            continue
        return call, dependency
    return None


def _runtime_shim_propagation_diagnostic(
    function: FunctionAnalysis,
    dependency: FunctionAnalysis,
    call: CallSite,
) -> Diagnostic:
    return Diagnostic(
        code="RXT080",
        severity="warning",
        message=(
            "native function uses Python runtime semantics shim because it calls "
            f"runtime-backed native function: {dependency.qualname}"
        ),
        file_path=function.file_path,
        line=call.line,
        column=call.column,
        function_name=function.qualname,
        suggestion=(
            "Rextio will route this function through the Python runtime semantics "
            "shim so the native dependency can preserve Python object behavior."
        ),
    )


def _runtime_shim_requires_marker_diagnostic(
    function: FunctionAnalysis,
    dependency: FunctionAnalysis,
    call: CallSite,
) -> Diagnostic:
    return Diagnostic(
        code="RXT074",
        severity="error",
        message=(
            "auto-discovered function calls runtime-backed native function "
            f"{dependency.qualname}; it would require the Python runtime semantics "
            "shim, which is only applied to explicitly marked functions"
        ),
        file_path=function.file_path,
        line=call.line,
        column=call.column,
        function_name=function.qualname,
        suggestion=(
            "Add @rextio.native to this function to opt into the runtime semantics "
            "shim, or leave it on the Python fallback path."
        ),
    )


def _add_python_loop_boundary_warnings(
    analysis: ProjectAnalysis,
    resolver: FunctionResolver,
) -> None:
    for module in analysis.modules:
        for function in module.functions:
            if function.is_native_candidate and function.accepted:
                continue
            for call in function.calls:
                resolved = resolver.resolve(module, call.target)
                dependency = resolved.function
                if (
                    dependency is None
                    or not dependency.is_native_candidate
                    or not dependency.accepted
                    or not call.in_loop
                ):
                    continue
                if function.has_diagnostic("RXT073", call.line, call.column):
                    continue
                function.add_diagnostic(
                    Diagnostic(
                        code="RXT073",
                        severity="warning",
                        message=(
                            f"native function call inside Python loop may erase speedup: "
                            f"{call.target}"
                        ),
                        file_path=function.file_path,
                        line=call.line,
                        column=call.column,
                        function_name=function.qualname,
                        suggestion=(
                            "Move the loop into a native batch function. Supported batch loops include "
                            "for x in xs, for i, x in enumerate(xs), and for x, y in zip(xs, ys)."
                        ),
                    )
                )
