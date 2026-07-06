"""Core rule records for the machine-readable tooling contract.

The declarative L2 descriptions of the core analyzer's promotion rules,
emitted by ``rextio capabilities``. Each record maps a rule to the diagnostic
code it fires as, states the constraint, and carries the remediation guidance
external tooling (agent skills, LSP servers) shows to developers.

These records describe the analyzer; they do not drive it. The companion test
``tests/analyzer/test_rule_records.py`` keeps them honest: every referenced
diagnostic code must exist in the registry.
"""

from __future__ import annotations

from rextio.plugins.api import RuleRecord, RuleScope


def core_rule_records() -> tuple[RuleRecord, ...]:
    """Return the core analyzer's rule records, ordered by rule id."""
    return _CORE_RULES


_CORE_RULES: tuple[RuleRecord, ...] = tuple(
    sorted(
        (
            RuleRecord(
                id="core/argument-annotation-required",
                provider="core",
                scope=RuleScope(kind="type", pattern="function parameter without a type annotation"),
                constraint="Native lowering needs every parameter type resolved; an unannotated parameter cannot be typed in Rust.",
                outcome="fallback",
                diagnostic_code="RXT001",
                guidance="Annotate every parameter of a hot function end to end with supported types (int, float, bool, str, bytes, list[T], fixed tuple/dict, Optional).",
            ),
            RuleRecord(
                id="core/unsupported-argument-type",
                provider="core",
                scope=RuleScope(kind="type", pattern="parameter annotated with a type outside the supported subset"),
                constraint="Only the supported type subset lowers to Rust; anything else keeps the function on the Python fallback.",
                outcome="fallback",
                diagnostic_code="RXT002",
                guidance="Use supported types on hot-path signatures, or split the function so the typed hot core stands alone.",
            ),
            RuleRecord(
                id="core/set-float-item-type",
                provider="core",
                scope=RuleScope(kind="type", pattern="set[float]"),
                constraint="set[float] has no faithful Rust lowering: CPython's NaN-identity deduplication cannot be reproduced.",
                outcome="fallback",
                diagnostic_code="RXT002",
                guidance="Use list[float] and deduplicate explicitly, or keep the function on the Python fallback.",
            ),
            RuleRecord(
                id="core/return-annotation-required",
                provider="core",
                scope=RuleScope(kind="type", pattern="missing or unsupported return type annotation"),
                constraint="The return type must be annotated and inside the supported subset for native lowering.",
                outcome="fallback",
                diagnostic_code="RXT003",
                guidance="Annotate the return type with a supported type; -> None is supported for procedures.",
            ),
            RuleRecord(
                id="core/unsupported-syntax",
                provider="core",
                scope=RuleScope(kind="syntax", pattern="statement or expression outside the supported subset, or an invalid @rextio.native marker"),
                constraint="Only the documented syntax subset lowers directly (assignment, arithmetic, if/while/for, comprehensions, restricted try/except).",
                outcome="fallback",
                diagnostic_code="RXT010",
                guidance="Rewrite the hot path inside the supported subset (see docs/unsupported-features.md), or accept fallback and mark with @rextio.exempt to silence candidacy.",
            ),
            RuleRecord(
                id="core/rust-identifier",
                provider="core",
                scope=RuleScope(kind="syntax", pattern="identifier not representable in generated Rust"),
                constraint="Identifiers must be expressible in Rust (raw-identifier escaping covers most keywords, but not all names).",
                outcome="fallback",
                diagnostic_code="RXT011",
                guidance="Rename the identifier to an ASCII name that is not a non-raw-able Rust keyword.",
            ),
            RuleRecord(
                id="core/dynamic-feature",
                provider="core",
                scope=RuleScope(kind="syntax", pattern="dynamic Python feature (dynamic attributes, exec/eval, reflection)"),
                constraint="Dynamic features have no static Rust equivalent; explicitly marked functions may ride the runtime shim instead.",
                outcome="fallback",
                diagnostic_code="RXT020",
                guidance="Move the dynamic behavior out of the hot path, or keep the function on the fallback (@rextio.exempt documents the intent).",
            ),
            RuleRecord(
                id="core/unsupported-external-call",
                provider="core",
                scope=RuleScope(kind="call", pattern="call to an unsupported builtin, stdlib, or external function"),
                constraint="A direct-native function may call only accepted native functions, supported builtins, and supported stdlib functions.",
                outcome="fallback",
                diagnostic_code="RXT030",
                guidance="Replace the call with a supported equivalent, hoist it out of the native function, or mark the callee @rextio.native when it fits the subset.",
            ),
            RuleRecord(
                id="core/native-calls-fallback",
                provider="core",
                scope=RuleScope(kind="call", pattern="native candidate calls a fallback-only project function"),
                constraint="Native-to-fallback calls are rejected, except the explicit scalar boundary-call path (see core/scalar-boundary-call).",
                outcome="reject",
                diagnostic_code="RXT070",
                guidance="Mark the callee @rextio.native if it fits the subset, split the caller so the native core calls only native helpers, or rely on a scalar boundary call for explicitly marked callers.",
            ),
            RuleRecord(
                id="core/native-dependency-rejected",
                provider="core",
                scope=RuleScope(kind="call", pattern="native candidate depends on a rejected candidate"),
                constraint="If a callee is rejected, its native callers cannot stay native either.",
                outcome="fallback",
                diagnostic_code="RXT072",
                guidance="Fix the callee's rejection first; acceptance propagates back up the call graph.",
            ),
            RuleRecord(
                id="core/python-loop-calls-native",
                provider="core",
                scope=RuleScope(kind="call", pattern="Python loop repeatedly calling a native function"),
                constraint="Each iteration crosses the Python/native boundary; crossings count toward the per-function demotion threshold.",
                outcome="boundary",
                diagnostic_code="RXT073",
                guidance="Move the loop into the native function so the boundary is crossed once per call instead of once per iteration.",
            ),
            RuleRecord(
                id="core/auto-candidate-shim-dependency",
                provider="core",
                scope=RuleScope(kind="call", pattern="auto-discovered candidate depends on a runtime-shim native"),
                constraint="Auto-discovered candidates must not silently depend on the shim path; only explicit markers opt into shim semantics.",
                outcome="fallback",
                diagnostic_code="RXT074",
                guidance="Mark the function @rextio.native explicitly if the shim dependency is intended.",
            ),
            RuleRecord(
                id="core/scalar-boundary-call",
                provider="core",
                scope=RuleScope(kind="call", pattern="explicitly marked native calls a fallback-only function with an all-scalar signature"),
                constraint="The call runs in-process on the interpreter: values and exceptions are CPython-exact, containers never cross, and each crossing counts toward the demotion threshold.",
                outcome="boundary",
                diagnostic_code="RXT075",
                guidance="Keep boundary-call signatures to immutable scalars (int/float/bool/str/None) and batch enough work per call to amortize the crossing.",
            ),
            RuleRecord(
                id="core/boundary-call-in-loop",
                provider="core",
                scope=RuleScope(kind="call", pattern="scalar boundary call inside a native loop, comprehension body, or while-loop test"),
                constraint="A per-iteration interpreter round-trip would erase the native speedup, so the caller stays on the fallback.",
                outcome="fallback",
                diagnostic_code="RXT076",
                guidance="Hoist the boundary call out of the loop, or mark the callee @rextio.native when it fits the subset.",
            ),
            RuleRecord(
                id="core/runtime-semantics-shim",
                provider="core",
                scope=RuleScope(kind="syntax", pattern="explicitly marked function using classes, exceptions, context managers, async, generators, or dynamic attributes"),
                constraint="The function compiles to a PyO3 shim that calls the generated Python fallback: behavior-preserving, not a speedup.",
                outcome="shim",
                diagnostic_code="RXT080",
                guidance="Treat the shim as a compatibility path; extract the typed hot core into its own function for a real native speedup.",
                stability="experimental",
            ),
            RuleRecord(
                id="core/documented-divergence-note",
                provider="core",
                scope=RuleScope(kind="call", pattern="direct-native function relying on a documented, statically attributable divergence (e.g. bytes.decode error type)"),
                constraint="The function stays native; the note marks a known, documented deviation from CPython behavior.",
                outcome="native",
                diagnostic_code="RXT090",
                guidance="Review the documented divergence (docs/unsupported-features.md) and confirm it is acceptable for this function.",
                stability="experimental",
            ),
            RuleRecord(
                id="core/external-accelerator-decorator",
                provider="core",
                scope=RuleScope(kind="decorator", pattern="@numba.jit / @numba.njit / @numba.vectorize / @numba.guvectorize"),
                constraint="A recognized external-accelerator decorator is the user's explicit opt-in to that tool's semantics; the function is excluded from native discovery and stays on the fallback route without a diagnostic.",
                outcome="fallback",
                diagnostic_code=None,
                guidance="Keep Numba for NumPy/array kernels and @rextio.native for typed scalar code; combining both decorators on one function is rejected.",
                stability="experimental",
            ),
        ),
        key=lambda record: record.id,
    )
)
