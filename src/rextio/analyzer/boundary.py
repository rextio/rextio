"""Native/fallback boundary checks (RXT07x): which native↔fallback crossings are allowed or warned."""

from __future__ import annotations

from rextio.analyzer.common_calls import COMMON_DIRECT_RUST_CALLS
from rextio.analyzer.call_resolution import FunctionResolver
from rextio.analyzer.diagnostics import Diagnostic
from rextio.analyzer.import_policy import decision_for_target
from rextio.analyzer.models import CallSite, FunctionAnalysis, ModuleAnalysis, ProjectAnalysis
from rextio.ir.types import normalize_type_name

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
}


def apply_boundary_checks(
    analysis: ProjectAnalysis,
    boundary_warnings: bool = True,
    native_jit_enabled: bool = False,
    delegate_fallback: bool = False,
) -> None:
    """Apply the native/fallback boundary policy, attaching RXT07x diagnostics."""
    resolver = FunctionResolver(analysis)
    for function in analysis.native_candidates:
        function.accepted = not function.error_diagnostics

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
                    native_jit_enabled=native_jit_enabled,
                    delegate_fallback=delegate_fallback,
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
# bytes/tuple/dict/list need a tagged, reference-preserving encoding and are a
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
    """Whether a fallback call can be faithfully delegated over the wire protocol.

    Requires the callee's return type to be a JSON-wire type the result can be
    typed from, and every argument type to be an immutable scalar (mutable
    containers cross the wire by value, so a callee's in-place mutation would be
    silently lost). When a type is unknown the call is *not* delegated (it stays a
    rejection, keeping the caller on the Python fallback), so delegation never
    guesses and never silently drops a mutation.
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
    native_jit_enabled: bool = False,
    delegate_fallback: bool = False,
) -> list[Diagnostic]:
    if function.native_runtime_semantics:
        return []
    diagnostics: list[Diagnostic] = []
    for call in function.calls:
        target = call.target
        resolved = resolver.resolve(module, target)
        if target in SUPPORTED_INTERNAL_CALLS or target.endswith(".append"):
            continue
        dependency = resolved.function
        if native_jit_enabled and dependency is not None and dependency.is_jit_candidate:
            # JIT candidates are lowered to a typed native inner function just like
            # accepted native siblings, so the same call-compatibility check applies.
            diagnostics.extend(_native_arg_type_errors(module, function, call, dependency, resolver))
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
        if dependency is not None:
            diagnostics.extend(_native_arg_type_errors(module, function, call, dependency, resolver))
            continue

        decision = decision_for_target(module, resolved.resolved_target)
        message, suggestion = _external_call_diagnostic_text(resolved.resolved_target, call.in_loop, decision)
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
    return diagnostics


_SCALAR_PARAM_TYPES = {"int", "float", "bool", "str", "bytes"}
# Parameter types lowered to a concrete fixed Rust type (Vec/HashMap/tuple/HashSet)
# that requires an exactly-matching argument — no coercion from a scalar or a
# differently-parameterised container. `Optional[...]` / `... | None` are excluded:
# they admit the inner type or None, so exact-string equality is not the right test.
_CONTAINER_PARAM_PREFIXES = ("list[", "tuple[", "dict[", "set[", "frozenset[")


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

    param_types = list(dependency.signature_arg_types.values())
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
            # `accepted` (no error diagnostics) covers a valid JIT candidate too; a
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
        if index >= len(param_types):
            continue
        param_type = param_types[index]
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
                f"Ensure plugin {plugin!r} is active and provides a direct lowering rule for this call, "
                "or keep the function on fallback."
            ),
        )
    if decision.policy == "try-native":
        return (
            f"external package call requires experimental dependency lowering and remains fallback: {target}",
            _external_package_suggestion(in_loop, "dependency lowering is opt-in and not available for this call"),
        )
    if decision.policy == "analyze":
        return (
            f"external package call is analyze-only and remains fallback: {target}",
            _external_package_suggestion(in_loop, "switch this package to try-native only if it is pure Python and safe"),
        )
    return (
        f"external package call uses fallback import policy: {target}",
        _external_package_suggestion(in_loop, "add a Rextio plugin or explicit try-native package policy if needed"),
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
