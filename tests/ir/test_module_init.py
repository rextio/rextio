from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from rextio.artifacts import ArtifactProvenance
from rextio.analyzer.models import SourcePosition, SourceRange
from rextio.ir.module_init import (
    ModuleInitAvailability,
    ModuleInitDisposition,
    ModuleInitIR,
    ModuleInitSegment,
    ModuleInitSegmentKind,
)


def _range(line: int, end_line: int | None = None) -> SourceRange:
    return SourceRange(
        start=SourcePosition(line, 0),
        end=SourcePosition(end_line or line, 5),
    )


def _segment(
    ordinal: int,
    line: int,
    *,
    bindings: tuple[str, ...] = (),
    dependencies: tuple[str, ...] = (),
) -> ModuleInitSegment:
    return ModuleInitSegment(
        ordinal=ordinal,
        kind=ModuleInitSegmentKind.NATIVE,
        disposition=ModuleInitDisposition.NATIVE_CANDIDATE,
        source_range=_range(line),
        statement_indexes=(ordinal,),
        bindings=bindings,
        exports=bindings,
        dependencies=dependencies,
    )


def test_module_init_dictionary_is_deterministic() -> None:
    digest = "a" * 64
    plan = ModuleInitIR(
        module_name="pkg.mod",
        path="src/pkg/mod.py",
        source_sha256=digest,
        availability=ModuleInitAvailability.AVAILABLE,
        segments=(_segment(0, 2, bindings=("z", "a", "a"), dependencies=("right", "left")),),
        metadata_ranges=(SourceRange(start=SourcePosition(1, 0), end=SourcePosition(1, 10)),),
        provenance=ArtifactProvenance(
            source_references=("src/pkg/mod.py",),
            evidence=(f"sha256:{digest}",),
        ),
    )

    assert plan.to_dict() == {
        "module_name": "pkg.mod",
        "path": "src/pkg/mod.py",
        "source_sha256": digest,
        "availability": "available",
        "segments": [
            {
                "ordinal": 0,
                "kind": "native",
                "disposition": "native-candidate",
                "source_range": {
                    "start": {"line": 2, "column": 0},
                    "end": {"line": 2, "column": 5},
                },
                "statement_indexes": [0],
                "bindings": ["a", "z"],
                "exports": ["a", "z"],
                "dependencies": ["left", "right"],
                "must_bindings": ["a", "z"],
                "may_bindings": ["a", "z"],
                "deleted_bindings": [],
                "must_exports": ["a", "z"],
                "may_exports": ["a", "z"],
                "must_deletions": [],
                "may_deletions": [],
                "namespace_unknown": False,
                "barrier_reason": None,
            }
        ],
        "metadata_ranges": [
            {
                "start": {"line": 1, "column": 0},
                "end": {"line": 1, "column": 10},
            }
        ],
        "unavailable_reason": None,
        "provenance": {
            "producer": "rextio",
            "source_references": ["src/pkg/mod.py"],
            "evidence": [f"sha256:{digest}"],
        },
    }
    assert plan.bounded_candidate


def test_unavailable_plan_cannot_contain_approximate_segments() -> None:
    with pytest.raises(ValueError, match="cannot approximate"):
        ModuleInitIR(
            module_name="broken",
            path="broken.py",
            source_sha256="0" * 64,
            availability=ModuleInitAvailability.UNAVAILABLE,
            segments=(_segment(0, 1),),
            unavailable_reason="syntax-error",
        )


def test_segments_must_be_non_overlapping_and_exports_must_be_bound() -> None:
    with pytest.raises(ValueError, match="exports must also"):
        ModuleInitSegment(
            ordinal=0,
            kind=ModuleInitSegmentKind.IMPORT,
            disposition=ModuleInitDisposition.PYTHON_PRESERVED,
            source_range=_range(1),
            statement_indexes=(0,),
            exports=("missing",),
        )

    first = ModuleInitSegment(
        ordinal=0,
        kind=ModuleInitSegmentKind.IMPORT,
        disposition=ModuleInitDisposition.PYTHON_PRESERVED,
        source_range=_range(1, 2),
        statement_indexes=(0,),
    )
    second = _segment(1, 2)
    with pytest.raises(ValueError, match="non-overlapping"):
        ModuleInitIR(
            module_name="app",
            path="app.py",
            source_sha256="f" * 64,
            availability=ModuleInitAvailability.AVAILABLE,
            segments=(first, second),
        )


def test_module_init_records_are_frozen() -> None:
    segment = _segment(0, 1)
    with pytest.raises(FrozenInstanceError):
        setattr(segment, "ordinal", 2)
