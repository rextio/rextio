"""Pure source/provenance graph construction without importing application code."""

from __future__ import annotations

import ast
import hashlib
import sys
from collections import deque
from collections.abc import Iterable, Mapping, Set
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING

from rextio.analyzer.models import SourcePosition
from rextio.artifacts import ArtifactProvenance
from rextio.source.models import (
    DistributionMetadata,
    ExternalImportReference,
    ImportAlias,
    ImportKind,
    ImportOwnership,
    ImportRecord,
    LocalImportEdge,
    SourceModule,
    SourceModuleGraph,
    SourceOrigin,
    SourceRange,
    StronglyConnectedComponent,
)

if TYPE_CHECKING:
    from rextio.analyzer.models import ProjectAnalysis


class SourceGraphError(ValueError):
    """A source graph could not be built exactly from the supplied files."""


OwnerMapping = Mapping[str, DistributionMetadata]


@dataclass(frozen=True)
class _SourceEntry:
    """A normalized, project-contained source file input."""

    module_name: str
    path: Path
    relative_path: str


class _ImportCollector(ast.NodeVisitor):
    """Collect every import statement and mark imports in deferred function bodies."""

    def __init__(self, module_name: str, is_package_init: bool) -> None:
        self._module_name = module_name
        self._is_package_init = is_package_init
        self._deferred_depth = 0
        self._records: list[ImportRecord] = []

    @property
    def records(self) -> tuple[ImportRecord, ...]:
        """Return records sorted by exact source position."""
        ordered = sorted(
            self._records,
            key=lambda record: (
                record.source_range.start.line,
                record.source_range.start.column,
                record.ordinal,
            ),
        )
        return tuple(replace(record, ordinal=index) for index, record in enumerate(ordered))

    def visit_Import(self, node: ast.Import) -> None:
        """Record a plain import statement without resolving or loading it."""
        names = tuple(ImportAlias(alias.name, alias.asname) for alias in node.names)
        self._records.append(
            ImportRecord(
                ordinal=len(self._records),
                kind=ImportKind.IMPORT,
                module=None,
                relative_level=0,
                names=names,
                source_range=_source_range(node),
                resolved_targets=tuple(alias.name for alias in node.names),
                deferred=bool(self._deferred_depth),
            )
        )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Record a from-import, retaining its raw module and relative level."""
        names = tuple(ImportAlias(alias.name, alias.asname) for alias in node.names)
        base = resolve_import_from_base(
            self._module_name,
            node.module,
            node.level,
            self._is_package_init,
        )
        if base is None:
            raw_base = f"{'.' * node.level}{node.module or ''}"
            resolved = tuple(
                f"{raw_base}.{alias.name}" if raw_base else alias.name for alias in node.names
            )
        else:
            resolved = tuple(
                base if alias.name == "*" else f"{base}.{alias.name}" if base else alias.name
                for alias in node.names
            )
        self._records.append(
            ImportRecord(
                ordinal=len(self._records),
                kind=ImportKind.FROM_IMPORT,
                module=node.module,
                relative_level=node.level,
                names=names,
                source_range=_source_range(node),
                resolved_targets=resolved,
                deferred=bool(self._deferred_depth),
            )
        )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Mark imports in a synchronous function body as deferred."""
        self._visit_function_body(node.body)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Mark imports in an asynchronous function body as deferred."""
        self._visit_function_body(node.body)

    def _visit_function_body(self, body: list[ast.stmt]) -> None:
        """Visit a function body under a deferred-execution marker."""
        self._deferred_depth += 1
        try:
            for statement in body:
                self.visit(statement)
        finally:
            self._deferred_depth -= 1


def resolve_import_from_base(
    module_name: str,
    imported_module: str | None,
    relative_level: int,
    is_package_init: bool,
) -> str | None:
    """Resolve a from-import base statically, returning ``None`` if it escapes."""
    if relative_level == 0:
        return imported_module
    package_parts = module_name.split(".") if module_name else []
    if not is_package_init and package_parts:
        package_parts.pop()
    if not package_parts:
        return None
    ascend = relative_level - 1
    if ascend >= len(package_parts):
        return None
    if ascend:
        package_parts = package_parts[:-ascend]
    if imported_module:
        package_parts.extend(imported_module.split("."))
    return ".".join(package_parts)


def build_source_module_graph(
    project_root: Path | str,
    files: Iterable[Path | str],
    *,
    owner_mapping: OwnerMapping | None = None,
    stdlib_modules: Set[str] | None = None,
) -> SourceModuleGraph:
    """Build a deterministic graph for explicit project files.

    The builder reads and parses source, but never imports it. Distribution
    ownership is supplied as data rather than discovered implicitly, keeping
    tests and serialized plans independent of the machine's installed wheels.
    """
    root = Path(project_root).resolve()
    entries = tuple(
        _entry_for_explicit_path(root, Path(path))
        for path in sorted(files, key=lambda item: Path(item).as_posix())
    )
    return _build_graph(
        entries,
        owner_mapping=owner_mapping or {},
        stdlib_modules=stdlib_modules if stdlib_modules is not None else sys.stdlib_module_names,
    )


def build_source_module_graph_from_analysis(
    analysis: ProjectAnalysis,
    *,
    owner_mapping: OwnerMapping | None = None,
    stdlib_modules: Set[str] | None = None,
) -> SourceModuleGraph:
    """Build a source graph for exactly the files already in ``ProjectAnalysis``."""
    root = analysis.project_root.resolve()
    entries = tuple(
        _entry_for_analysis_module(root, module.module_name, Path(module.file_path))
        for module in sorted(analysis.modules, key=lambda item: item.module_name)
    )
    return _build_graph(
        entries,
        owner_mapping=owner_mapping or {},
        stdlib_modules=stdlib_modules if stdlib_modules is not None else sys.stdlib_module_names,
    )


def source_module_graph_from_analysis(
    analysis: ProjectAnalysis,
    *,
    owner_mapping: OwnerMapping | None = None,
    stdlib_modules: Set[str] | None = None,
) -> SourceModuleGraph:
    """Compatibility spelling for :func:`build_source_module_graph_from_analysis`."""
    return build_source_module_graph_from_analysis(
        analysis,
        owner_mapping=owner_mapping,
        stdlib_modules=stdlib_modules,
    )


def _entry_for_explicit_path(root: Path, path: Path) -> _SourceEntry:
    candidate = path if path.is_absolute() else root / path
    normalized, relative = _project_relative_path(root, candidate)
    return _SourceEntry(
        module_name=_module_name_for_relative_path(relative),
        path=normalized,
        relative_path=relative.as_posix(),
    )


def _entry_for_analysis_module(root: Path, module_name: str, path: Path) -> _SourceEntry:
    candidate = path if path.is_absolute() else root / path
    normalized, relative = _project_relative_path(root, candidate)
    return _SourceEntry(
        module_name=module_name,
        path=normalized,
        relative_path=relative.as_posix(),
    )


def _project_relative_path(root: Path, path: Path) -> tuple[Path, Path]:
    try:
        normalized = path.resolve(strict=True)
    except OSError as error:
        raise SourceGraphError(f"source file is unavailable: {path.name}") from error
    try:
        relative = normalized.relative_to(root)
    except ValueError as error:
        raise SourceGraphError("source files must remain inside the project root") from error
    if normalized.suffix != ".py":
        raise SourceGraphError(f"source graph only accepts Python files: {relative.as_posix()}")
    return normalized, relative


def _module_name_for_relative_path(relative: Path) -> str:
    parts = list(relative.with_suffix("").parts)
    if parts and parts[0] == "src":
        parts = parts[1:]
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _build_graph(
    entries: tuple[_SourceEntry, ...],
    *,
    owner_mapping: OwnerMapping,
    stdlib_modules: Set[str],
) -> SourceModuleGraph:
    module_names = {entry.module_name for entry in entries}
    if len(module_names) != len(entries):
        raise SourceGraphError("source files must resolve to unique module names")

    modules: list[SourceModule] = []
    for entry in entries:
        try:
            source_bytes = entry.path.read_bytes()
            source = source_bytes.decode("utf-8")
            tree = ast.parse(source, filename=entry.relative_path)
        except (OSError, UnicodeDecodeError) as error:
            raise SourceGraphError(f"source file is unavailable: {entry.relative_path}") from error
        except SyntaxError as error:
            line = error.lineno or 0
            raise SourceGraphError(
                f"source parse failed closed: {entry.relative_path}:{line}: {error.msg}"
            ) from error
        collector = _ImportCollector(
            entry.module_name,
            entry.path.name == "__init__.py",
        )
        collector.visit(tree)
        digest = hashlib.sha256(source_bytes).hexdigest()
        modules.append(
            SourceModule(
                module_name=entry.module_name,
                path=entry.relative_path,
                is_package_init=entry.path.name == "__init__.py",
                source_origin=SourceOrigin.PROJECT,
                sha256=digest,
                dependency_depth=0,
                imports=collector.records,
                provenance=ArtifactProvenance(
                    source_references=(entry.relative_path,),
                    evidence=(f"sha256:{digest}",),
                ),
            )
        )

    local_edges, external_references = _classify_references(
        modules,
        owner_mapping=owner_mapping,
        stdlib_modules=stdlib_modules,
    )
    init_edges = tuple(edge for edge in local_edges if not edge.deferred)
    components = _strongly_connected_components(module_names, init_edges)
    depths = _dependency_depths(module_names, init_edges, components)
    depth_modules = tuple(
        replace(module, dependency_depth=depths[module.module_name]) for module in modules
    )
    return SourceModuleGraph(
        modules=depth_modules,
        local_edges=local_edges,
        external_references=external_references,
        strongly_connected_components=components,
    )


def _classify_references(
    modules: list[SourceModule],
    *,
    owner_mapping: OwnerMapping,
    stdlib_modules: Set[str],
) -> tuple[tuple[LocalImportEdge, ...], tuple[ExternalImportReference, ...]]:
    modules_by_name = {module.module_name: module for module in modules}
    module_names = set(modules_by_name)
    edges: list[LocalImportEdge] = []
    references: list[ExternalImportReference] = []
    for module in modules:
        for record in module.imports:
            requested, unresolved = _requested_modules(
                module,
                record,
                module_names,
            )
            local_targets: dict[str, bool] = {}
            reference_targets: dict[str, tuple[ImportOwnership, str | None]] = {}
            for target, require_local in requested:
                exact = target in module_names
                parents = _package_init_prefixes(target, modules_by_name)
                for parent in parents:
                    local_targets.setdefault(parent, parent != target)
                if exact:
                    local_targets[target] = False
                elif require_local or parents:
                    unresolved.add(target)
                else:
                    root = target.split(".", 1)[0]
                    ownership = (
                        ImportOwnership.STDLIB
                        if root in stdlib_modules
                        else ImportOwnership.EXTERNAL
                    )
                    reference_targets[target] = (ownership, None)
            for target in unresolved:
                reference_targets[target] = (
                    ImportOwnership.UNRESOLVED,
                    "project import target could not be resolved exactly",
                )
            for target, implicit_package_init in sorted(local_targets.items()):
                if module.is_package_init and target == module.module_name:
                    # The package currently being initialized is already present in
                    # sys.modules; importing one of its children does not re-run it.
                    continue
                edges.append(
                    LocalImportEdge(
                        importer=module.module_name,
                        imported=target,
                        import_ordinal=record.ordinal,
                        source_range=record.source_range,
                        deferred=record.deferred,
                        implicit_package_init=implicit_package_init,
                    )
                )
            for target, (ownership, resolution_error) in sorted(reference_targets.items()):
                owner = (
                    _distribution_owner(target, owner_mapping)
                    if ownership is ImportOwnership.EXTERNAL
                    else None
                )
                references.append(
                    ExternalImportReference(
                        importer=module.module_name,
                        imported=target,
                        ownership=ownership,
                        import_ordinal=record.ordinal,
                        source_range=record.source_range,
                        distribution=owner.distribution if owner is not None else None,
                        version=owner.version if owner is not None else None,
                        license=owner.license if owner is not None else None,
                        deferred=record.deferred,
                        resolution_error=resolution_error,
                    )
                )
    return tuple(edges), tuple(references)


def _requested_modules(
    module: SourceModule,
    record: ImportRecord,
    module_names: set[str],
) -> tuple[list[tuple[str, bool]], set[str]]:
    """Return exact module requests and targets that failed static resolution."""
    if record.kind is ImportKind.IMPORT:
        return [(alias.name, False) for alias in record.names], set()

    base = resolve_import_from_base(
        module.module_name,
        record.module,
        record.relative_level,
        module.is_package_init,
    )
    if base is None or not base:
        spelling = f"{'.' * record.relative_level}{record.module or ''}"
        unresolved_targets = {
            f"{spelling}.{alias.name}" if spelling else alias.name for alias in record.names
        }
        return [], unresolved_targets

    requested: list[tuple[str, bool]] = [(base, bool(record.relative_level))]
    unresolved: set[str] = set()
    for alias in record.names:
        if alias.name == "*":
            continue
        candidate = f"{base}.{alias.name}"
        if candidate in module_names:
            requested.append((candidate, True))
        elif record.relative_level and record.module is None:
            unresolved.add(candidate)
    return requested, unresolved


def _package_init_prefixes(
    target: str,
    modules_by_name: Mapping[str, SourceModule],
) -> tuple[str, ...]:
    """Return included package initializers executed while importing target."""
    parts = target.split(".")
    prefixes = []
    for index in range(1, len(parts) + 1):
        prefix = ".".join(parts[:index])
        module = modules_by_name.get(prefix)
        if module is not None and module.is_package_init:
            prefixes.append(prefix)
    return tuple(prefixes)


def _distribution_owner(
    target: str,
    owner_mapping: OwnerMapping,
) -> DistributionMetadata | None:
    candidates = [
        package
        for package in owner_mapping
        if target == package or target.startswith(f"{package}.")
    ]
    if not candidates:
        return None
    package = max(candidates, key=lambda candidate: (candidate.count("."), candidate))
    return owner_mapping[package]


def _strongly_connected_components(
    module_names: set[str],
    edges: tuple[LocalImportEdge, ...],
) -> tuple[StronglyConnectedComponent, ...]:
    adjacency = _adjacency(module_names, edges)
    index = 0
    indexes: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    raw_components: list[tuple[str, ...]] = []

    def visit(module_name: str) -> None:
        nonlocal index
        indexes[module_name] = index
        lowlinks[module_name] = index
        index += 1
        stack.append(module_name)
        on_stack.add(module_name)
        for dependency in adjacency[module_name]:
            if dependency not in indexes:
                visit(dependency)
                lowlinks[module_name] = min(lowlinks[module_name], lowlinks[dependency])
            elif dependency in on_stack:
                lowlinks[module_name] = min(lowlinks[module_name], indexes[dependency])
        if lowlinks[module_name] != indexes[module_name]:
            return
        members: list[str] = []
        while stack:
            member = stack.pop()
            on_stack.remove(member)
            members.append(member)
            if member == module_name:
                break
        raw_components.append(tuple(sorted(members)))

    for module_name in sorted(module_names):
        if module_name not in indexes:
            visit(module_name)
    return tuple(
        sorted(
            (
                StronglyConnectedComponent(
                    members=members,
                    cyclic=len(members) > 1 or members[0] in adjacency[members[0]],
                )
                for members in raw_components
            ),
            key=lambda component: component.members,
        )
    )


def _adjacency(
    module_names: set[str],
    edges: tuple[LocalImportEdge, ...],
) -> dict[str, tuple[str, ...]]:
    mutable = {module_name: set[str]() for module_name in module_names}
    for edge in edges:
        mutable[edge.importer].add(edge.imported)
    return {
        module_name: tuple(sorted(dependencies)) for module_name, dependencies in mutable.items()
    }


def _dependency_depths(
    module_names: set[str],
    edges: tuple[LocalImportEdge, ...],
    components: tuple[StronglyConnectedComponent, ...],
) -> dict[str, int]:
    component_for = {
        member: index for index, component in enumerate(components) for member in component.members
    }
    dependencies = {index: set[int]() for index in range(len(components))}
    incoming = {index: set[int]() for index in range(len(components))}
    for edge in edges:
        source = component_for[edge.importer]
        target = component_for[edge.imported]
        if source == target:
            continue
        dependencies[source].add(target)
        incoming[target].add(source)
    depths: dict[int, int] = {}
    pending: deque[tuple[int, int]] = deque(
        (index, 0) for index in sorted(incoming) if not incoming[index]
    )
    while pending:
        component, depth = pending.popleft()
        previous = depths.get(component)
        if previous is not None and previous <= depth:
            continue
        depths[component] = depth
        for dependency in sorted(dependencies[component]):
            pending.append((dependency, depth + 1))
    return {module_name: depths.get(component_for[module_name], 0) for module_name in module_names}


def _source_range(node: ast.AST) -> SourceRange:
    line = getattr(node, "lineno", None)
    column = getattr(node, "col_offset", None)
    end_line = getattr(node, "end_lineno", None)
    end_column = getattr(node, "end_col_offset", None)
    if line is None or column is None or end_line is None or end_column is None:
        raise SourceGraphError("parsed import statement has no reliable source range")
    return SourceRange(
        start=SourcePosition(line=line, column=column),
        end=SourcePosition(line=end_line, column=end_column),
    )
