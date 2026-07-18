"""Fail-closed assembly of source graph and module-initialization plans."""

from __future__ import annotations

import ast
import hashlib
import symtable
from dataclasses import dataclass
from pathlib import Path

from rextio.analyzer.models import ProjectAnalysis, TopLevelAnalysis
from rextio.analyzer.module_init import build_project_module_init_irs
from rextio.ir.module_init import ModuleInitIR, ModuleInitSegmentKind
from rextio.source.graph import SourceGraphError, build_source_module_graph_from_analysis
from rextio.source.models import SourceModuleGraph


@dataclass(frozen=True)
class HostSourcePlan:
    """Behavior-neutral host source plan attached to reports and build plans."""

    graph: SourceModuleGraph | None
    module_initializers: tuple[ModuleInitIR, ...]
    unavailable_reason: str | None = None

    @property
    def available(self) -> bool:
        """Return whether graph and initializer records share one exact snapshot."""
        return (
            self.graph is not None
            and self.unavailable_reason is None
            and all(plan.available for plan in self.module_initializers)
        )

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable planning record."""
        return {
            "availability": "available" if self.available else "unavailable",
            "execution_authority": "descriptive-only",
            "graph": self.graph.to_dict() if self.graph is not None else None,
            "module_initializers": [plan.to_dict() for plan in self.module_initializers],
            "unavailable_reason": self.unavailable_reason,
        }


@dataclass(frozen=True)
class ExecutableModuleInitializer:
    """One exact module-initialization snapshot authorized for a Rust executable.

    This is deliberately narrower than the ordinary ``native_top_level`` path.
    The first executable slice runs local scalar-literal assignments for ordering
    only; it does not publish their values as Rust globals.
    """

    qualname: str
    plan: ModuleInitIR


@dataclass(frozen=True)
class ExecutableInitializerBlocker:
    """One reason a requested native top level cannot run in the Rust process."""

    qualname: str
    reason: str


@dataclass(frozen=True)
class ExecutableInitializerSelection:
    """Fail-closed executable initializer selection for one entrypoint."""

    initializers: tuple[ExecutableModuleInitializer, ...] = ()
    blockers: tuple[ExecutableInitializerBlocker, ...] = ()


def build_host_source_plan(analysis: ProjectAnalysis) -> HostSourcePlan:
    """Build planning data without importing or executing project modules."""
    try:
        module_initializers = build_project_module_init_irs(analysis)
    except (OSError, ValueError):
        # A scanner result can reference a symlink whose resolved target is no
        # longer project-contained.  Source planning is report data, so keep the
        # command alive and avoid copying an exception (and a possible external
        # path) into the machine-readable report.
        return HostSourcePlan(
            graph=None,
            module_initializers=(),
            unavailable_reason="module-init-plan-unavailable",
        )
    try:
        graph = build_source_module_graph_from_analysis(analysis)
    except SourceGraphError as error:
        return HostSourcePlan(
            graph=None,
            module_initializers=module_initializers,
            unavailable_reason=str(error),
        )
    coherence_error = _source_plan_coherence_error(graph, module_initializers)
    return HostSourcePlan(
        graph=graph,
        module_initializers=module_initializers,
        unavailable_reason=coherence_error,
    )


def ensure_host_source_plan(analysis: ProjectAnalysis) -> HostSourcePlan:
    """Return and cache one immutable source snapshot on a project analysis."""
    if analysis.host_source_plan is None:
        analysis.host_source_plan = build_host_source_plan(analysis)
    return analysis.host_source_plan


def select_executable_module_initializers(
    analysis: ProjectAnalysis,
    entrypoint: str,
) -> ExecutableInitializerSelection:
    """Authorize the deliberately tiny initializer-before-main vertical slice.

    No top-level candidate means the feature was disabled (or there was no
    executable module work), so the existing Rust-main path remains unchanged.
    Once ``native_top_level`` produced a candidate, however, omission would
    silently change module-load semantics. Any uncertainty therefore becomes a
    closure blocker for every executable fallback strategy.
    """
    top_levels = tuple(analysis.native_top_levels)
    if not top_levels:
        return ExecutableInitializerSelection()

    source_plan = ensure_host_source_plan(analysis)
    if not source_plan.available or source_plan.graph is None:
        unavailable_reason = source_plan.unavailable_reason or "host source plan is unavailable"
        return _blocked_initializers(top_levels, unavailable_reason)

    graph = source_plan.graph
    if len(graph.modules) != 1:
        return _blocked_initializers(
            top_levels,
            "the initial executable module-init slice requires exactly one source module",
        )
    if graph.cycles:
        return _blocked_initializers(top_levels, "the source module graph contains a load cycle")
    if any(not edge.deferred for edge in graph.local_edges):
        return _blocked_initializers(
            top_levels,
            "module-load project imports are outside the initial executable slice",
        )
    if any(not reference.deferred for reference in graph.external_references):
        return _blocked_initializers(
            top_levels,
            "module-load standard-library or external imports are outside the initial executable slice",
        )

    entry_module = entrypoint.rpartition(".")[0]
    plans = {plan.module_name: plan for plan in source_plan.module_initializers}
    selected: list[ExecutableModuleInitializer] = []
    blockers: list[ExecutableInitializerBlocker] = []
    for top_level in top_levels:
        reason = _top_level_execution_blocker(
            analysis,
            top_level,
            plans.get(top_level.module_name),
            entry_module=entry_module,
        )
        if reason is not None:
            blockers.append(ExecutableInitializerBlocker(top_level.qualname, reason))
            continue
        plan = plans[top_level.module_name]
        selected.append(ExecutableModuleInitializer(top_level.qualname, plan))

    return ExecutableInitializerSelection(
        initializers=tuple(sorted(selected, key=lambda item: item.qualname)),
        blockers=tuple(sorted(blockers, key=lambda item: (item.qualname, item.reason))),
    )


def _source_plan_coherence_error(
    graph: SourceModuleGraph,
    module_initializers: tuple[ModuleInitIR, ...],
) -> str | None:
    """Return a stable reason when graph and initializer snapshots diverge."""
    unavailable = sorted(plan.module_name for plan in module_initializers if not plan.available)
    if unavailable:
        return f"module-init-unavailable:{','.join(unavailable)}"

    graph_modules = graph.modules_by_name
    init_modules = {plan.module_name: plan for plan in module_initializers}
    if set(graph_modules) != set(init_modules):
        return "source-module-set-mismatch"
    for module_name in sorted(graph_modules):
        module = graph_modules[module_name]
        plan = init_modules[module_name]
        if module.path != plan.path or module.sha256 != plan.source_sha256:
            return f"source-snapshot-mismatch:{module_name}"
    return None


def _blocked_initializers(
    top_levels: tuple[TopLevelAnalysis, ...],
    reason: str,
) -> ExecutableInitializerSelection:
    return ExecutableInitializerSelection(
        blockers=tuple(
            ExecutableInitializerBlocker(top_level.qualname, reason)
            for top_level in sorted(top_levels, key=lambda item: item.qualname)
        )
    )


def _top_level_execution_blocker(
    analysis: ProjectAnalysis,
    top_level: TopLevelAnalysis,
    plan: ModuleInitIR | None,
    *,
    entry_module: str,
) -> str | None:
    if not top_level.accepted:
        codes = sorted({diagnostic.code for diagnostic in top_level.error_diagnostics})
        suffix = f" ({', '.join(codes)})" if codes else ""
        return f"native top-level analysis was rejected{suffix}"
    if top_level.module_name != entry_module:
        return "the initial executable slice requires the initializer and entrypoint in one module"
    if plan is None or not plan.available:
        return "the exact module-init plan is unavailable"
    if not plan.bounded_candidate:
        return "imports or fallback barriers prevent bounded module initialization"
    if any(
        segment.namespace_unknown
        or segment.deleted_bindings
        or segment.must_bindings != segment.may_bindings
        for segment in plan.segments
    ):
        return "module initialization has conditional, deleted, or unknown namespace bindings"

    source_path = Path(top_level.file_path)
    try:
        source_bytes = source_path.read_bytes()
    except OSError:
        return "module source became unavailable after analysis"
    if hashlib.sha256(source_bytes).hexdigest() != plan.source_sha256:
        return "module source changed after the host source plan was created"
    try:
        tree = ast.parse(source_bytes.decode("utf-8"), filename=plan.path)
    except (UnicodeDecodeError, SyntaxError):
        return "module source can no longer be parsed as the planned UTF-8 snapshot"

    native_indexes = tuple(
        statement_index
        for segment in plan.segments
        if segment.kind is ModuleInitSegmentKind.NATIVE
        for statement_index in segment.statement_indexes
    )
    if not native_indexes:
        return "the module-init plan contains no native statements"
    if any(index >= len(tree.body) for index in native_indexes):
        return "module-init statement indexes do not match the source snapshot"
    if any(
        not _is_executable_scalar_literal_assignment(tree.body[index]) for index in native_indexes
    ):
        return "the initial executable slice accepts only plain scalar-literal assignments"

    assigned_names = set(top_level.assigned_types)
    if _native_function_reads_initializer_binding(
        analysis,
        source_bytes.decode("utf-8"),
        assigned_names,
    ):
        return (
            "native functions cannot read initializer-local values until Rust globals are modeled"
        )
    return None


def _is_executable_scalar_literal_assignment(statement: ast.stmt) -> bool:
    if not (
        isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Name)
        and isinstance(statement.value, ast.Constant)
    ):
        return False
    # Exact types avoid accepting arbitrary Constant payloads or bool-as-int by
    # subclassing. AnnAssign is intentionally excluded because module annotation
    # evaluation and __annotations__ publication are not modeled by Rust main.
    return type(statement.value.value) in {bool, float, int, str}


def _native_function_reads_initializer_binding(
    analysis: ProjectAnalysis,
    source: str,
    assigned_names: set[str],
) -> bool:
    """Conservatively prevent discarded initializer locals from looking global."""
    if not assigned_names:
        return False
    accepted_sites = {
        (function.name, function.line) for function in analysis.accepted_native_functions
    }
    table = symtable.symtable(source, "<rextio-module-init>", "exec")
    for child in table.get_children():
        if child.get_type() != "function":
            continue
        if (child.get_name(), child.get_lineno()) not in accepted_sites:
            continue
        identifiers = set(child.get_identifiers())
        for name in assigned_names & identifiers:
            symbol = child.lookup(name)
            if symbol.is_referenced() and symbol.is_global():
                return True
    return False
