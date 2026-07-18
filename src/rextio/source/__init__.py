"""Deterministic project source graph contracts and builders."""

from rextio.source.graph import (
    OwnerMapping,
    SourceGraphError,
    build_source_module_graph,
    build_source_module_graph_from_analysis,
    resolve_import_from_base,
    source_module_graph_from_analysis,
)
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
    SourcePosition,
    SourceRange,
    StronglyConnectedComponent,
)

__all__ = [
    "DistributionMetadata",
    "ExternalImportReference",
    "ImportAlias",
    "ImportKind",
    "ImportOwnership",
    "ImportRecord",
    "LocalImportEdge",
    "OwnerMapping",
    "SourceGraphError",
    "SourceModule",
    "SourceModuleGraph",
    "SourceOrigin",
    "SourcePosition",
    "SourceRange",
    "StronglyConnectedComponent",
    "build_source_module_graph",
    "build_source_module_graph_from_analysis",
    "resolve_import_from_base",
    "source_module_graph_from_analysis",
]
