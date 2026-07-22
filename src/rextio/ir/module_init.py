"""Behavior-neutral intermediate representation for module initialization plans."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import PurePosixPath, PureWindowsPath

from rextio.analyzer.models import SourceRange
from rextio.artifacts import ArtifactProvenance


class ModuleInitSegmentKind(str, Enum):
    """Source-order statement classifications used by the initial planner."""

    NATIVE = "native"
    DEFINITION_PUBLICATION = "definition-publication"
    IMPORT = "import"
    FALLBACK_BARRIER = "fallback-barrier"


class ModuleInitDisposition(str, Enum):
    """Whether a segment is a native candidate or remains Python-preserved."""

    NATIVE_CANDIDATE = "native-candidate"
    PYTHON_PRESERVED = "python-preserved"


class ModuleInitAvailability(str, Enum):
    """Whether exact statement order was available to the planner."""

    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"


def _sorted_unique(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted(set(values)))


@dataclass(frozen=True)
class ModuleInitSegment:
    """One contiguous, non-reordered source region in a module-init plan."""

    ordinal: int
    kind: ModuleInitSegmentKind
    disposition: ModuleInitDisposition
    source_range: SourceRange
    statement_indexes: tuple[int, ...]
    bindings: tuple[str, ...] = ()
    exports: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    must_bindings: tuple[str, ...] | None = None
    may_bindings: tuple[str, ...] | None = None
    deleted_bindings: tuple[str, ...] = ()
    must_exports: tuple[str, ...] | None = None
    may_exports: tuple[str, ...] | None = None
    must_deletions: tuple[str, ...] = ()
    may_deletions: tuple[str, ...] | None = None
    namespace_unknown: bool = False
    barrier_reason: str | None = None

    def __post_init__(self) -> None:
        """Canonicalize value sets while preserving statement source order."""
        object.__setattr__(self, "kind", ModuleInitSegmentKind(self.kind))
        object.__setattr__(self, "disposition", ModuleInitDisposition(self.disposition))
        object.__setattr__(self, "statement_indexes", tuple(self.statement_indexes))
        bindings = _sorted_unique(self.bindings)
        may_bindings = bindings if self.may_bindings is None else _sorted_unique(self.may_bindings)
        must_bindings = (
            bindings if self.must_bindings is None else _sorted_unique(self.must_bindings)
        )
        object.__setattr__(self, "bindings", bindings)
        object.__setattr__(self, "exports", _sorted_unique(self.exports))
        object.__setattr__(self, "dependencies", _sorted_unique(self.dependencies))
        object.__setattr__(self, "must_bindings", must_bindings)
        object.__setattr__(self, "may_bindings", may_bindings)
        deleted_bindings = _sorted_unique(self.deleted_bindings)
        must_exports = (
            tuple(name for name in must_bindings if not name.startswith("_"))
            if self.must_exports is None
            else _sorted_unique(self.must_exports)
        )
        may_exports = self.exports if self.may_exports is None else _sorted_unique(self.may_exports)
        may_deletions = (
            deleted_bindings if self.may_deletions is None else _sorted_unique(self.may_deletions)
        )
        object.__setattr__(self, "deleted_bindings", deleted_bindings)
        object.__setattr__(self, "must_exports", must_exports)
        object.__setattr__(self, "may_exports", may_exports)
        object.__setattr__(self, "must_deletions", _sorted_unique(self.must_deletions))
        object.__setattr__(self, "may_deletions", may_deletions)
        if self.ordinal < 0:
            raise ValueError("module-init segment ordinal must be non-negative")
        if not self.statement_indexes:
            raise ValueError("module-init segment must contain at least one statement")
        if tuple(sorted(set(self.statement_indexes))) != self.statement_indexes:
            raise ValueError("module-init statement indexes must be unique and source ordered")
        if any(index < 0 for index in self.statement_indexes):
            raise ValueError("module-init statement indexes must be non-negative")
        if bindings != may_bindings:
            raise ValueError("module-init bindings must equal conservative may-bindings")
        if not set(must_bindings).issubset(may_bindings):
            raise ValueError("module-init must-bindings must be a subset of may-bindings")
        if not set(self.exports).issubset(may_bindings):
            raise ValueError("module-init exports must also be segment bindings")
        if not set(must_exports).issubset(must_bindings):
            raise ValueError("module-init must-exports must be must-bindings")
        if not set(may_exports).issubset(may_bindings):
            raise ValueError("module-init may-exports must be may-bindings")
        if not set(self.must_deletions).issubset(may_deletions):
            raise ValueError("module-init must-deletions must be may-deletions")
        if deleted_bindings != may_deletions:
            raise ValueError("module-init deleted-bindings must equal may-deletions")
        if self.kind is ModuleInitSegmentKind.NATIVE:
            if self.disposition is not ModuleInitDisposition.NATIVE_CANDIDATE:
                raise ValueError("native module-init segments require native-candidate disposition")
            if self.barrier_reason is not None:
                raise ValueError("native module-init segments cannot carry a barrier reason")
        elif self.disposition is not ModuleInitDisposition.PYTHON_PRESERVED:
            raise ValueError("non-native module-init segments must remain Python-preserved")
        if self.kind is ModuleInitSegmentKind.FALLBACK_BARRIER and not self.barrier_reason:
            raise ValueError("fallback-barrier segments require a reason")

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable representation."""
        return {
            "ordinal": self.ordinal,
            "kind": self.kind.value,
            "disposition": self.disposition.value,
            "source_range": self.source_range.to_dict(),
            "statement_indexes": list(self.statement_indexes),
            "bindings": list(self.bindings),
            "exports": list(self.exports),
            "dependencies": list(self.dependencies),
            "must_bindings": list(self.must_bindings or ()),
            "may_bindings": list(self.may_bindings or ()),
            "deleted_bindings": list(self.deleted_bindings),
            "must_exports": list(self.must_exports or ()),
            "may_exports": list(self.may_exports or ()),
            "must_deletions": list(self.must_deletions),
            "may_deletions": list(self.may_deletions or ()),
            "namespace_unknown": self.namespace_unknown,
            "barrier_reason": self.barrier_reason,
        }


@dataclass(frozen=True)
class ModuleInitIR:
    """Exact source-order planning data for one Python module.

    This IR is descriptive only. It neither opts into the existing
    ``native_top_level`` path nor authorizes code generation or execution.
    """

    module_name: str
    path: str
    source_sha256: str
    availability: ModuleInitAvailability
    segments: tuple[ModuleInitSegment, ...] = ()
    metadata_ranges: tuple[SourceRange, ...] = ()
    unavailable_reason: str | None = None
    provenance: ArtifactProvenance = field(default_factory=ArtifactProvenance)

    def __post_init__(self) -> None:
        """Validate availability and strict non-overlapping source order."""
        object.__setattr__(self, "availability", ModuleInitAvailability(self.availability))
        object.__setattr__(self, "segments", tuple(self.segments))
        object.__setattr__(self, "metadata_ranges", tuple(self.metadata_ranges))
        posix = PurePosixPath(self.path)
        windows = PureWindowsPath(self.path)
        if (
            not self.path.strip()
            or posix.is_absolute()
            or windows.is_absolute()
            or ".." in posix.parts
            or ".." in windows.parts
        ):
            raise ValueError("module-init path must be relative to the project")
        if len(self.source_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.source_sha256
        ):
            raise ValueError("module-init source SHA-256 must be lowercase hexadecimal")
        if self.availability is ModuleInitAvailability.AVAILABLE:
            if self.unavailable_reason is not None:
                raise ValueError("available module-init plans cannot carry an unavailable reason")
        else:
            if not self.unavailable_reason:
                raise ValueError("unavailable module-init plans require a reason")
            if self.segments:
                raise ValueError("unavailable module-init plans cannot approximate segments")
        expected_ordinals = tuple(range(len(self.segments)))
        if tuple(segment.ordinal for segment in self.segments) != expected_ordinals:
            raise ValueError("module-init segments must have contiguous source-order ordinals")
        for previous, current in zip(self.segments, self.segments[1:]):
            previous_end = (
                previous.source_range.end.line,
                previous.source_range.end.column,
            )
            current_start = (
                current.source_range.start.line,
                current.source_range.start.column,
            )
            if current_start < previous_end:
                raise ValueError("module-init segments must be ordered and non-overlapping")

    @property
    def relative_path(self) -> str:
        """Return the project-relative source path."""
        return self.path

    @property
    def available(self) -> bool:
        """Return whether exact source-order segmentation succeeded."""
        return self.availability is ModuleInitAvailability.AVAILABLE

    @property
    def native_segments(self) -> tuple[ModuleInitSegment, ...]:
        """Return native-candidate segments in their original source order."""
        return tuple(
            segment for segment in self.segments if segment.kind is ModuleInitSegmentKind.NATIVE
        )

    @property
    def has_fallback_barrier(self) -> bool:
        """Return whether any source statement requires preserved Python execution."""
        return any(
            segment.kind is ModuleInitSegmentKind.FALLBACK_BARRIER for segment in self.segments
        )

    @property
    def bounded_candidate(self) -> bool:
        """Return the plan-local half of the initial bounded eligibility gate."""
        return (
            self.available
            and any(segment.bindings for segment in self.native_segments)
            and not self.has_fallback_barrier
            and not any(segment.kind is ModuleInitSegmentKind.IMPORT for segment in self.segments)
        )

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable representation."""
        return {
            "module_name": self.module_name,
            "path": self.path,
            "source_sha256": self.source_sha256,
            "availability": self.availability.value,
            "segments": [segment.to_dict() for segment in self.segments],
            "metadata_ranges": [source_range.to_dict() for source_range in self.metadata_ranges],
            "unavailable_reason": self.unavailable_reason,
            "provenance": self.provenance.to_dict(),
        }
