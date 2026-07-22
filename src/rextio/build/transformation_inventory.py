"""Bounded C6.6 source-transformation observation construction.

This collector is deliberately total for the build path: unsupported or
internally inconsistent analyzer/plan state yields ``None``.  The surrounding
C6.2 evidence and C6.3 required-evidence transaction therefore retain their
independent outcome, while C6.5-C6.9 readiness evaluation fails closed.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import TYPE_CHECKING

from rextio.analyzer.models import FunctionAnalysis
from rextio.artifacts.evidence import (
    MAX_EVIDENCE_STRING_CHARS,
    MAX_SOURCE_TRANSFORMATION_PLUGIN_IDS,
    MAX_SOURCE_TRANSFORMATION_PLUGIN_REFERENCES,
    MAX_SOURCE_TRANSFORMATIONS,
    SOURCE_TRANSFORMATION_GENERATOR_BACKENDS,
    EvidenceFileRef,
    SourceTransformationInventory,
    SourceTransformationRange,
    SourceTransformationRecord,
    project_relative_logical_path,
)
from rextio.partition.build_plan import BuildPlan
from rextio.source.models import SourceModule, SourceOrigin

if TYPE_CHECKING:
    from rextio.build.supply_chain import EvidenceInputSnapshot

_FunctionBinding = tuple[str, str, str, int, int, int, int, str]


def collect_source_transformation_inventory(
    *,
    project_root: Path,
    plan: BuildPlan,
    input_snapshot: EvidenceInputSnapshot,
) -> SourceTransformationInventory | None:
    """Return the canonical accepted-function inventory, or ``None``.

    No source bytes are read here.  The collector binds analyzer identities to
    the already verified ``SourceModule`` graph and the exact generated
    ``src/lib.rs`` :class:`EvidenceFileRef` captured before Cargo ran.
    """
    try:
        if input_snapshot.unavailable_reason is not None:
            return None
        graph = plan.host_source_plan.graph
        if graph is None:
            return None
        native_functions = tuple(plan.native.accepted_functions)
        if len(native_functions) > MAX_SOURCE_TRANSFORMATIONS:
            return None
        analysis_functions = tuple(plan.analysis.accepted_native_functions)
        if len(analysis_functions) > MAX_SOURCE_TRANSFORMATIONS:
            return None
        if not _coverage_matches_codegen_authority(
            project_root=project_root,
            native_functions=native_functions,
            analysis_functions=analysis_functions,
        ):
            return None

        generated = tuple(
            item
            for item in input_snapshot.generated_rust
            if item.role == "generated-rust-input"
            and Path(item.logical_path).as_posix().endswith("/src/lib.rs")
        )
        if len(generated) != 1:
            return None
        generated_rust = generated[0]

        modules_by_name: dict[str, list[SourceModule]] = {}
        for module in graph.modules:
            modules_by_name.setdefault(module.module_name, []).append(module)
        project_inputs_by_path: dict[str, list[EvidenceFileRef]] = {}
        for item in input_snapshot.project_inputs:
            if item.role == "project-python-source":
                project_inputs_by_path.setdefault(item.logical_path, []).append(item)

        records: list[SourceTransformationRecord] = []
        # Code generation consumes ProjectAnalysis.accepted_native_functions.
        # Use that same authority after proving the NativePlan is an exact,
        # ordered value-level copy; object identity is deliberately irrelevant.
        for function in analysis_functions:
            modules = modules_by_name.get(function.module_name, [])
            if len(modules) != 1:
                return None
            module = modules[0]
            if module.source_origin is not SourceOrigin.PROJECT:
                return None

            source_path = Path(function.file_path)
            if not source_path.is_absolute():
                source_path = project_root / source_path
            logical_path = project_relative_logical_path(project_root, source_path)
            if logical_path != module.path:
                return None
            source_inputs = project_inputs_by_path.get(module.path, [])
            if len(source_inputs) != 1:
                return None
            source_input = source_inputs[0]
            if source_input.sha256 != module.sha256:
                return None

            source_range = function.source_range
            fingerprint = function.source_ast_fingerprint
            if source_range is None or fingerprint is None:
                return None
            plugin_ids = _bounded_plugin_ids(function)
            if plugin_ids is None:
                return None
            records.append(
                SourceTransformationRecord(
                    source_path=module.path,
                    source_sha256=module.sha256,
                    function_module=function.module_name,
                    function_qualname=function.qualname,
                    source_range=SourceTransformationRange(
                        start_line=source_range.start.line,
                        start_column=source_range.start.column,
                        end_line=source_range.end.line,
                        end_column=source_range.end.column,
                    ),
                    semantic_ast_sha256=hashlib.sha256(
                        fingerprint.encode("utf-8")
                    ).hexdigest(),
                    generated_rust=generated_rust,
                    generator_backend=next(
                        iter(SOURCE_TRANSFORMATION_GENERATOR_BACKENDS)
                    ),
                    plugin_ids=plugin_ids,
                )
            )

        # The immutable model constructor also enforces the conservative total
        # deterministic-JSON character budget. An excess raises here and the
        # total collector degrades to None before provenance construction.
        return SourceTransformationInventory(
            records=tuple(sorted(records, key=lambda record: record.canonical_key))
        )
    except Exception:
        # Exception text and attacker-controlled values never enter evidence.
        return None


def _coverage_matches_codegen_authority(
    *,
    project_root: Path,
    native_functions: tuple[FunctionAnalysis, ...],
    analysis_functions: tuple[FunctionAnalysis, ...],
) -> bool:
    """Require exact canonical NativePlan coverage of codegen's authority."""
    native_bindings = _function_bindings(project_root, native_functions)
    analysis_bindings = _function_bindings(project_root, analysis_functions)
    if native_bindings is None or analysis_bindings is None:
        return False
    return native_bindings == analysis_bindings


def _function_bindings(
    project_root: Path,
    functions: tuple[FunctionAnalysis, ...],
) -> tuple[_FunctionBinding, ...] | None:
    bindings: list[_FunctionBinding] = []
    identities: set[tuple[str, str]] = set()
    for function in functions:
        binding = _function_binding(project_root, function)
        if binding is None:
            return None
        identity = (binding[0], binding[1])
        if identity in identities:
            return None
        identities.add(identity)
        bindings.append(binding)
    result = tuple(bindings)
    if result != tuple(sorted(result, key=lambda item: (item[0], item[1]))):
        return None
    return result


def _function_binding(
    project_root: Path,
    function: FunctionAnalysis,
) -> _FunctionBinding | None:
    if function.accepted is not True:
        return None
    if type(function.module_name) is not str or type(function.qualname) is not str:
        return None
    if type(function.file_path) is not str:
        return None
    source_path = Path(function.file_path)
    if not source_path.is_absolute():
        source_path = project_root / source_path
    logical_path = project_relative_logical_path(project_root, source_path)
    source_range = function.source_range
    fingerprint = function.source_ast_fingerprint
    if source_range is None or type(fingerprint) is not str or not fingerprint:
        return None
    # Reuse the closed range model so both coverage comparison and emitted
    # records agree on what constitutes a reliable bounded range.
    bounded_range = SourceTransformationRange(
        start_line=source_range.start.line,
        start_column=source_range.start.column,
        end_line=source_range.end.line,
        end_column=source_range.end.column,
    )
    return (
        function.module_name,
        function.qualname,
        logical_path,
        bounded_range.start_line,
        bounded_range.start_column,
        bounded_range.end_line,
        bounded_range.end_column,
        fingerprint,
    )


def _bounded_plugin_ids(function: FunctionAnalysis) -> tuple[str, ...] | None:
    """Collect unique plugin ids without allowing the working set to grow."""
    claims = function.plugin_claims
    type_keys = function.plugin_type_keys
    if (
        len(claims) > MAX_SOURCE_TRANSFORMATION_PLUGIN_REFERENCES
        or len(type_keys) > MAX_SOURCE_TRANSFORMATION_PLUGIN_REFERENCES
        or len(claims) + len(type_keys)
        > MAX_SOURCE_TRANSFORMATION_PLUGIN_REFERENCES
    ):
        return None
    plugin_ids: set[str] = set()
    for claim in claims:
        plugin_id = claim.plugin_id
        if (
            type(plugin_id) is not str
            or not plugin_id
            or len(plugin_id) > MAX_EVIDENCE_STRING_CHARS
        ):
            return None
        if plugin_id not in plugin_ids:
            if len(plugin_ids) >= MAX_SOURCE_TRANSFORMATION_PLUGIN_IDS:
                return None
            plugin_ids.add(plugin_id)
    for key in type_keys:
        if (
            type(key) is not str
            or not key
            or len(key) > MAX_EVIDENCE_STRING_CHARS
        ):
            return None
        plugin_id = key.split("/", 1)[0]
        if plugin_id and plugin_id not in plugin_ids:
            if len(plugin_ids) >= MAX_SOURCE_TRANSFORMATION_PLUGIN_IDS:
                return None
            plugin_ids.add(plugin_id)
    return tuple(sorted(plugin_ids))


__all__ = ["collect_source_transformation_inventory"]
