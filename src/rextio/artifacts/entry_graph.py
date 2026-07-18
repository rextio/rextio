"""Build executable native-closure reports from project analysis."""

from __future__ import annotations

from rextio.analyzer.call_resolution import FunctionResolver
from rextio.analyzer.models import FunctionAnalysis, ProjectAnalysis
from rextio.artifacts.closure import (
    ClosureBlocker,
    ClosureNode,
    FallbackClosureEdge,
    NativeClosureEdge,
    NativeClosureReport,
    calculate_native_closure,
)
from rextio.artifacts.models import ArtifactProfile, FallbackStrategy
from rextio.artifacts.profiles import host_executable_profile, required_host_target_triple
from rextio.ir.types import normalize_type_name
from rextio.source.planning import select_executable_module_initializers


def executable_entry_graph(
    analysis: ProjectAnalysis,
    entrypoint: str,
    strategy: FallbackStrategy = FallbackStrategy.PYTHON_SUBPROCESS,
    *,
    profile: ArtifactProfile | None = None,
) -> NativeClosureReport:
    """Return the single deterministic authority for a Rust executable graph."""
    by_qualname = {
        function.qualname: function for module in analysis.modules for function in module.functions
    }
    entry = by_qualname.get(entrypoint)
    entrypoint_reason = _entrypoint_reason(entry)
    nodes: list[ClosureNode] = []
    native_edges: list[NativeClosureEdge] = []
    fallback_edges: list[FallbackClosureEdge] = []
    blockers: list[ClosureBlocker] = []
    resolver = FunctionResolver(analysis)
    initializer_selection = select_executable_module_initializers(analysis, entrypoint)
    blockers.extend(
        ClosureBlocker(
            source=entrypoint,
            callee=blocker.qualname,
            reason=f"module initializer is unavailable: {blocker.reason}",
        )
        for blocker in initializer_selection.blockers
    )

    for module in analysis.modules:
        for function in module.functions:
            if _is_direct_native(function):
                nodes.append(ClosureNode(function.qualname))
            elif function.is_embedding_candidate:
                nodes.append(ClosureNode(function.qualname, "embedded-helper"))
            if not _is_direct_native(function):
                continue
            for call in function.calls:
                resolved = resolver.resolve(module, call.target).function
                if resolved is None:
                    continue
                if resolved.qualname in function.delegated_call_targets:
                    fallback_edges.append(
                        FallbackClosureEdge(
                            source=function.qualname,
                            callee=resolved.qualname,
                            reason=_fallback_reason(resolved),
                            return_type=_normalized_return_type(resolved),
                        )
                    )
                elif resolved.is_embedding_candidate or _is_direct_native(resolved):
                    native_edges.append(NativeClosureEdge(function.qualname, resolved.qualname))
                elif resolved.route.startswith("native-plugin:"):
                    blockers.append(
                        ClosureBlocker(
                            source=function.qualname,
                            callee=resolved.qualname,
                            reason=(
                                "plugin-lowered callee has no declared standalone Rust "
                                "executable capability"
                            ),
                        )
                    )
                else:
                    blockers.append(
                        ClosureBlocker(
                            source=function.qualname,
                            callee=resolved.qualname,
                            reason="project callee is not represented by the executable closure",
                        )
                    )

    selected_profile = profile or host_executable_profile(
        required_host_target_triple(), fallback=strategy
    )
    return calculate_native_closure(
        entrypoint,
        nodes,
        native_edges,
        fallback_edges,
        strategy=strategy,
        profile=selected_profile,
        entrypoint_reason=entrypoint_reason,
        blockers=blockers,
        module_initializers=(
            initializer.qualname for initializer in initializer_selection.initializers
        ),
    )


def _is_direct_native(function: FunctionAnalysis) -> bool:
    return function.route == "native-direct" and not function.is_embedding_candidate


def _entrypoint_reason(function: FunctionAnalysis | None) -> str | None:
    if function is None:
        return "entrypoint function was not found"
    if function.native_runtime_semantics:
        return "entrypoint requires Python runtime semantics"
    if function.is_embedding_candidate:
        return "entrypoint is an internal embedded helper"
    if function.route.startswith("native-plugin:"):
        return (
            "entrypoint is plugin-lowered but the plugin declares no standalone "
            "Rust executable capability"
        )
    if not function.accepted:
        codes = ", ".join(function.rejection_codes)
        return f"entrypoint was rejected from native lowering{f' ({codes})' if codes else ''}"
    return None


def _fallback_reason(function: FunctionAnalysis) -> str:
    if function.marker_kind == "exempt":
        return "callee is explicitly exempt from native compilation"
    if function.external_accelerator is not None:
        return f"callee uses external accelerator {function.external_accelerator}"
    if function.native_runtime_semantics:
        return "callee requires Python runtime semantics"
    if not function.is_native_candidate:
        return "callee is a fallback-only project function"
    codes = ", ".join(function.rejection_codes)
    if codes:
        return f"callee was rejected from native lowering ({codes})"
    return "callee was rejected from native lowering"


def _normalized_return_type(function: FunctionAnalysis) -> str | None:
    return_type = (
        function.signature_return_type
        or function.inferred_return_type
        or function.annotated_return_type
    )
    return normalize_type_name(return_type)
