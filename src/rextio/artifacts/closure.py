"""Deterministic native-closure records shared by artifact planners."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from rextio.artifacts.models import ArtifactProfile, FallbackStrategy


class ClosureStatus(str, Enum):
    """Whether an entrypoint's reachable native graph is self-contained."""

    CLOSED = "closed"
    OPEN = "open"
    UNAVAILABLE = "unavailable"


_LEGACY_FALLBACKS = {
    "source": FallbackStrategy.PYTHON_SUBPROCESS,
    "nuitka": FallbackStrategy.NUITKA_SIDECAR,
}


def resolve_executable_fallback(
    fallback: FallbackStrategy | str | None = None,
    hybrid_runtime: str | None = None,
) -> FallbackStrategy:
    """Resolve the canonical strategy and its legacy compatibility alias.

    ``None`` means unspecified.  This distinction lets callers reject two
    explicit, conflicting settings while retaining the historical source
    dispatcher as the compatibility default.
    """
    if fallback is not None and not isinstance(fallback, (str, FallbackStrategy)):
        raise ValueError("executable fallback must be a string when set")
    if hybrid_runtime is not None and not isinstance(hybrid_runtime, str):
        raise ValueError("legacy executable hybrid_runtime must be a string when set")
    canonical: FallbackStrategy | None = None
    if fallback is not None:
        try:
            canonical = FallbackStrategy(fallback)
        except ValueError as exc:
            choices = ", ".join(strategy.value for strategy in FallbackStrategy)
            raise ValueError(
                f"unsupported executable fallback {fallback!r}; use {choices}"
            ) from exc

    legacy: FallbackStrategy | None = None
    if hybrid_runtime is not None:
        legacy = _LEGACY_FALLBACKS.get(hybrid_runtime)
        if legacy is None:
            raise ValueError(
                "unsupported legacy executable hybrid_runtime "
                f"{hybrid_runtime!r}; use 'source' or 'nuitka'"
            )

    if canonical is not None and legacy is not None and canonical is not legacy:
        raise ValueError(
            "conflicting executable fallback settings: "
            f"fallback={canonical.value!r} conflicts with "
            f"hybrid_runtime={hybrid_runtime!r} (which maps to {legacy.value!r}); "
            "remove one setting or make them agree"
        )
    return canonical or legacy or FallbackStrategy.PYTHON_SUBPROCESS


def strategy_from_compatibility_value(
    value: FallbackStrategy | str | None,
) -> FallbackStrategy:
    """Accept one canonical value or one legacy ``source|nuitka`` value."""
    if isinstance(value, str) and value in _LEGACY_FALLBACKS:
        return resolve_executable_fallback(hybrid_runtime=value)
    return resolve_executable_fallback(fallback=value)


@dataclass(frozen=True, order=True)
class ClosureNode:
    """One function represented in an executable entry graph."""

    qualname: str
    kind: str = "native"

    def __post_init__(self) -> None:
        if not self.qualname.strip():
            raise ValueError("closure node qualname must not be empty")
        if self.kind not in {"native", "embedded-helper"}:
            raise ValueError("closure node kind must be 'native' or 'embedded-helper'")
        object.__setattr__(self, "qualname", self.qualname.strip())

    def to_dict(self) -> dict[str, str]:
        """Return the deterministic JSON-serializable node record."""
        return {"qualname": self.qualname, "kind": self.kind}


@dataclass(frozen=True, order=True)
class NativeClosureEdge:
    """A direct native-to-native call edge."""

    source: str
    callee: str

    def __post_init__(self) -> None:
        if not self.source.strip() or not self.callee.strip():
            raise ValueError("closure edge source and callee must not be empty")
        object.__setattr__(self, "source", self.source.strip())
        object.__setattr__(self, "callee", self.callee.strip())

    def to_dict(self) -> dict[str, str]:
        """Return the deterministic JSON-serializable native edge."""
        return {"source": self.source, "callee": self.callee}


@dataclass(frozen=True, order=True)
class FallbackClosureEdge:
    """A reachable native-to-Python fallback call edge."""

    source: str
    callee: str
    reason: str
    return_type: str | None = None

    def __post_init__(self) -> None:
        if not self.source.strip() or not self.callee.strip():
            raise ValueError("fallback edge source and callee must not be empty")
        if not self.reason.strip():
            raise ValueError("fallback edge reason must not be empty")
        object.__setattr__(self, "source", self.source.strip())
        object.__setattr__(self, "callee", self.callee.strip())
        object.__setattr__(self, "reason", self.reason.strip())

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable fallback edge."""
        return {
            "source": self.source,
            "callee": self.callee,
            "reason": self.reason,
            "return_type": self.return_type,
        }


@dataclass(frozen=True, order=True)
class ClosureBlocker:
    """A reachable edge or entry condition with no standalone Rust form."""

    source: str
    callee: str | None
    reason: str

    def __post_init__(self) -> None:
        if not self.source.strip() or not self.reason.strip():
            raise ValueError("closure blocker source and reason must not be empty")
        if self.callee is not None and not self.callee.strip():
            raise ValueError("closure blocker callee must not be empty when set")
        object.__setattr__(self, "source", self.source.strip())
        object.__setattr__(self, "reason", self.reason.strip())
        if self.callee is not None:
            object.__setattr__(self, "callee", self.callee.strip())

    def to_dict(self) -> dict[str, str | None]:
        """Return the deterministic JSON-serializable blocker record."""
        return {"source": self.source, "callee": self.callee, "reason": self.reason}


@dataclass(frozen=True)
class NativeClosureReport:
    """The deterministic reachable closure for one executable entrypoint."""

    entrypoint: str
    nodes: tuple[ClosureNode, ...]
    native_edges: tuple[NativeClosureEdge, ...]
    fallback_edges: tuple[FallbackClosureEdge, ...]
    status: ClosureStatus
    strategy: FallbackStrategy
    profile: ArtifactProfile
    entrypoint_reason: str | None = None
    blockers: tuple[ClosureBlocker, ...] = ()
    module_initializers: tuple[str, ...] = ()

    @property
    def reachable_native_functions(self) -> tuple[str, ...]:
        """Return reachable native qualnames in canonical order."""
        return tuple(node.qualname for node in self.nodes)

    @property
    def delegated_return_types(self) -> dict[str, str]:
        """Return the scalar dispatcher return types keyed by callee."""
        return {
            edge.callee: edge.return_type
            for edge in self.fallback_edges
            if edge.return_type is not None
        }

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable closure report."""
        return {
            "entrypoint": self.entrypoint,
            "reachable_native_functions": list(self.reachable_native_functions),
            "nodes": [node.to_dict() for node in self.nodes],
            "native_edges": [edge.to_dict() for edge in self.native_edges],
            "fallback_edges": [edge.to_dict() for edge in self.fallback_edges],
            "status": self.status.value,
            "strategy": self.strategy.value,
            "entrypoint_reason": self.entrypoint_reason,
            "blockers": [blocker.to_dict() for blocker in self.blockers],
            "module_initializers": list(self.module_initializers),
            "profile": self.profile.to_dict(),
        }


def closure_requires_prebuild_failure(report: NativeClosureReport) -> bool:
    """Return whether no external build work may begin for this report."""
    return report.status is ClosureStatus.UNAVAILABLE or (
        report.status is ClosureStatus.OPEN and report.strategy is FallbackStrategy.ERROR
    )


def calculate_native_closure(
    entrypoint: str,
    nodes: Iterable[ClosureNode],
    native_edges: Iterable[NativeClosureEdge],
    fallback_edges: Iterable[FallbackClosureEdge],
    *,
    strategy: FallbackStrategy,
    profile: ArtifactProfile,
    entrypoint_reason: str | None = None,
    blockers: Iterable[ClosureBlocker] = (),
    module_initializers: Iterable[str] = (),
) -> NativeClosureReport:
    """Calculate and canonicalize the graph reachable from ``entrypoint``."""
    canonical_nodes: dict[str, ClosureNode] = {}
    for node in sorted(set(nodes)):
        previous = canonical_nodes.get(node.qualname)
        if previous is not None and previous != node:
            raise ValueError(f"conflicting closure node records for {node.qualname!r}")
        canonical_nodes[node.qualname] = node
    if profile.fallback is not strategy:
        raise ValueError("closure strategy must match the artifact profile fallback")
    canonical_native_edges = tuple(sorted(set(native_edges)))
    canonical_fallback_edges = tuple(sorted(set(fallback_edges)))
    canonical_blockers = tuple(sorted(set(blockers)))
    canonical_initializers = _canonical_module_initializers(module_initializers)
    if entrypoint not in canonical_nodes:
        return NativeClosureReport(
            entrypoint=entrypoint,
            nodes=(),
            native_edges=(),
            fallback_edges=(),
            status=ClosureStatus.UNAVAILABLE,
            strategy=strategy,
            profile=profile,
            entrypoint_reason=entrypoint_reason or "entrypoint is not direct-native",
            blockers=tuple(
                blocker for blocker in canonical_blockers if blocker.source == entrypoint
            ),
            module_initializers=canonical_initializers,
        )

    outgoing: dict[str, list[str]] = {}
    for edge in canonical_native_edges:
        outgoing.setdefault(edge.source, []).append(edge.callee)
    reachable = {entrypoint}
    pending = [entrypoint]
    while pending:
        source = pending.pop()
        for callee in reversed(sorted(outgoing.get(source, ()))):
            if callee in canonical_nodes and callee not in reachable:
                reachable.add(callee)
                pending.append(callee)

    selected_nodes = tuple(sorted((canonical_nodes[name] for name in reachable)))
    selected_native_edges = tuple(
        edge
        for edge in canonical_native_edges
        if edge.source in reachable and edge.callee in reachable
    )
    selected_fallback_edges = tuple(
        edge for edge in canonical_fallback_edges if edge.source in reachable
    )
    selected_blockers = {blocker for blocker in canonical_blockers if blocker.source in reachable}
    selected_blockers.update(
        ClosureBlocker(
            source=edge.source,
            callee=edge.callee,
            reason="native call target has no standalone Rust closure node",
        )
        for edge in canonical_native_edges
        if edge.source in reachable and edge.callee not in canonical_nodes
    )
    status = (
        ClosureStatus.UNAVAILABLE
        if selected_blockers
        else ClosureStatus.OPEN
        if selected_fallback_edges
        else ClosureStatus.CLOSED
    )
    return NativeClosureReport(
        entrypoint=entrypoint,
        nodes=selected_nodes,
        native_edges=selected_native_edges,
        fallback_edges=selected_fallback_edges,
        status=status,
        strategy=strategy,
        profile=profile,
        blockers=tuple(sorted(selected_blockers)),
        module_initializers=canonical_initializers,
    )


def _canonical_module_initializers(initializers: Iterable[str]) -> tuple[str, ...]:
    """Validate an already planned deterministic initializer order."""
    ordered: list[str] = []
    seen: set[str] = set()
    for initializer in initializers:
        qualname = initializer.strip()
        if not qualname:
            raise ValueError("module initializer qualname must not be empty")
        if qualname in seen:
            raise ValueError(f"duplicate module initializer qualname: {qualname!r}")
        seen.add(qualname)
        ordered.append(qualname)
    return tuple(ordered)
