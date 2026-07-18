"""Immutable source graph records with deterministic serialization."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import PurePosixPath, PureWindowsPath

from rextio.analyzer.models import SourcePosition as SourcePosition
from rextio.analyzer.models import SourceRange
from rextio.artifacts import ArtifactProvenance


class SourceOrigin(str, Enum):
    """The provenance class for source text represented by a graph module."""

    PROJECT = "project"
    DISTRIBUTION = "distribution"
    STDLIB = "stdlib"
    UNKNOWN = "unknown"


class ImportKind(str, Enum):
    """The two Python import statement forms."""

    IMPORT = "import"
    FROM_IMPORT = "from-import"


class ImportOwnership(str, Enum):
    """Static ownership of a resolved import reference."""

    LOCAL = "local"
    STDLIB = "stdlib"
    EXTERNAL = "external"
    UNRESOLVED = "unresolved"


def _range_start(source_range: SourceRange) -> tuple[int, int]:
    return source_range.start.line, source_range.start.column


@dataclass(frozen=True)
class DistributionMetadata:
    """Optional installed-distribution ownership for an import root."""

    distribution: str
    version: str | None = None
    license: str | None = None

    def __post_init__(self) -> None:
        """Require a stable non-empty distribution identifier."""
        if not self.distribution.strip():
            raise ValueError("distribution name must not be empty")

    def to_dict(self) -> dict[str, str | None]:
        """Return the deterministic JSON-serializable representation."""
        return {
            "distribution": self.distribution,
            "version": self.version,
            "license": self.license,
        }


@dataclass(frozen=True)
class ImportAlias:
    """One name, and optional visible alias, in an import statement."""

    name: str
    asname: str | None = None

    def __post_init__(self) -> None:
        """Reject malformed empty import names."""
        if not self.name.strip():
            raise ValueError("import name must not be empty")
        if self.asname is not None and not self.asname.strip():
            raise ValueError("import alias must not be empty")

    def to_dict(self) -> dict[str, str | None]:
        """Return the deterministic JSON-serializable representation."""
        return {"name": self.name, "asname": self.asname}


@dataclass(frozen=True)
class ImportRecord:
    """One Python import statement retained in exact source order."""

    ordinal: int
    kind: ImportKind
    module: str | None
    relative_level: int
    names: tuple[ImportAlias, ...]
    source_range: SourceRange
    resolved_targets: tuple[str, ...]
    deferred: bool = False

    def __post_init__(self) -> None:
        """Normalize enums and validate the statement-level record."""
        object.__setattr__(self, "kind", ImportKind(self.kind))
        object.__setattr__(self, "names", tuple(self.names))
        object.__setattr__(self, "resolved_targets", tuple(self.resolved_targets))
        if self.ordinal < 0:
            raise ValueError("import ordinal must be non-negative")
        if self.relative_level < 0:
            raise ValueError("relative import level must be non-negative")
        if not self.names:
            raise ValueError("import record must contain at least one imported name")
        if len(self.names) != len(self.resolved_targets):
            raise ValueError("each imported name must have one resolved target")
        if self.kind is ImportKind.IMPORT and self.relative_level:
            raise ValueError("plain import statements cannot have a relative level")

    @property
    def level(self) -> int:
        """Return the relative level using the spelling used by :mod:`ast`."""
        return self.relative_level

    @property
    def line(self) -> int:
        """Return the statement's first source line."""
        return self.source_range.start.line

    @property
    def column(self) -> int:
        """Return the statement's first UTF-8 byte column."""
        return self.source_range.start.column

    @property
    def end_line(self) -> int:
        """Return the statement's final source line."""
        return self.source_range.end.line

    @property
    def end_column(self) -> int:
        """Return the statement's final UTF-8 byte column."""
        return self.source_range.end.column

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable representation."""
        return {
            "ordinal": self.ordinal,
            "kind": self.kind.value,
            "module": self.module,
            "relative_level": self.relative_level,
            "names": [name.to_dict() for name in self.names],
            "source_range": self.source_range.to_dict(),
            "resolved_targets": list(self.resolved_targets),
            "deferred": self.deferred,
        }


def _validate_relative_path(path: str) -> None:
    """Reject serialized paths that can disclose a machine-private root."""
    if not path.strip():
        raise ValueError("source module path must not be empty")
    posix = PurePosixPath(path)
    windows = PureWindowsPath(path)
    if posix.is_absolute() or windows.is_absolute() or ".." in posix.parts or ".." in windows.parts:
        raise ValueError("source module path must be relative to the project")


@dataclass(frozen=True)
class SourceModule:
    """One source file and its stable provenance/import metadata."""

    module_name: str
    path: str
    is_package_init: bool
    source_origin: SourceOrigin
    sha256: str
    dependency_depth: int
    imports: tuple[ImportRecord, ...] = ()
    distribution: str | None = None
    version: str | None = None
    license: str | None = None
    provenance: ArtifactProvenance = field(default_factory=ArtifactProvenance)

    def __post_init__(self) -> None:
        """Canonicalize import order and validate serializable provenance."""
        object.__setattr__(self, "source_origin", SourceOrigin(self.source_origin))
        ordered_imports = tuple(
            sorted(
                self.imports,
                key=lambda record: (
                    *_range_start(record.source_range),
                    record.ordinal,
                ),
            )
        )
        object.__setattr__(self, "imports", ordered_imports)
        _validate_relative_path(self.path)
        if len(self.sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.sha256
        ):
            raise ValueError("source SHA-256 must be 64 lowercase hexadecimal characters")
        if self.dependency_depth < 0:
            raise ValueError("source dependency depth must be non-negative")
        if self.distribution is not None and not self.distribution.strip():
            raise ValueError("source distribution name must not be empty")

    @property
    def relative_path(self) -> str:
        """Return the path relative to the project root."""
        return self.path

    @property
    def origin(self) -> SourceOrigin:
        """Return the source origin using a concise compatibility spelling."""
        return self.source_origin

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable representation."""
        return {
            "module_name": self.module_name,
            "path": self.path,
            "is_package_init": self.is_package_init,
            "source_origin": self.source_origin.value,
            "sha256": self.sha256,
            "distribution": self.distribution,
            "version": self.version,
            "license": self.license,
            "dependency_depth": self.dependency_depth,
            "imports": [record.to_dict() for record in self.imports],
            "provenance": self.provenance.to_dict(),
        }


@dataclass(frozen=True)
class LocalImportEdge:
    """One source import statement edge between included project modules."""

    importer: str
    imported: str
    import_ordinal: int
    source_range: SourceRange
    deferred: bool = False
    implicit_package_init: bool = False

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable representation."""
        return {
            "importer": self.importer,
            "imported": self.imported,
            "import_ordinal": self.import_ordinal,
            "source_range": self.source_range.to_dict(),
            "deferred": self.deferred,
            "implicit_package_init": self.implicit_package_init,
        }


@dataclass(frozen=True)
class ExternalImportReference:
    """One non-project import statement reference and its static owner."""

    importer: str
    imported: str
    ownership: ImportOwnership
    import_ordinal: int
    source_range: SourceRange
    distribution: str | None = None
    version: str | None = None
    license: str | None = None
    deferred: bool = False
    resolution_error: str | None = None

    def __post_init__(self) -> None:
        """Normalize ownership and reject local references in this record."""
        object.__setattr__(self, "ownership", ImportOwnership(self.ownership))
        if self.ownership is ImportOwnership.LOCAL:
            raise ValueError("external import reference cannot have local ownership")
        if self.ownership is ImportOwnership.UNRESOLVED and not self.resolution_error:
            raise ValueError("unresolved import references require a resolution error")
        if self.ownership is not ImportOwnership.UNRESOLVED and self.resolution_error is not None:
            raise ValueError("resolved import references cannot carry a resolution error")

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable representation."""
        return {
            "importer": self.importer,
            "imported": self.imported,
            "ownership": self.ownership.value,
            "import_ordinal": self.import_ordinal,
            "source_range": self.source_range.to_dict(),
            "distribution": self.distribution,
            "version": self.version,
            "license": self.license,
            "deferred": self.deferred,
            "resolution_error": self.resolution_error,
        }


@dataclass(frozen=True)
class StronglyConnectedComponent:
    """Deterministic strongly connected component and cycle status."""

    members: tuple[str, ...]
    cyclic: bool

    def __post_init__(self) -> None:
        """Canonicalize and validate component membership."""
        canonical = tuple(sorted(set(self.members)))
        if not canonical:
            raise ValueError("strongly connected component must not be empty")
        object.__setattr__(self, "members", canonical)

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable representation."""
        return {"members": list(self.members), "cyclic": self.cyclic}


@dataclass(frozen=True)
class SourceModuleGraph:
    """A canonical project source graph assembled without importing modules."""

    modules: tuple[SourceModule, ...]
    local_edges: tuple[LocalImportEdge, ...] = ()
    external_references: tuple[ExternalImportReference, ...] = ()
    strongly_connected_components: tuple[StronglyConnectedComponent, ...] = ()

    def __post_init__(self) -> None:
        """Canonicalize all unordered graph collections and validate endpoints."""
        modules = tuple(sorted(self.modules, key=lambda module: module.module_name))
        module_names = tuple(module.module_name for module in modules)
        if len(set(module_names)) != len(module_names):
            raise ValueError("source graph module names must be unique")
        object.__setattr__(self, "modules", modules)
        edges = tuple(
            sorted(
                self.local_edges,
                key=lambda edge: (
                    edge.importer,
                    edge.imported,
                    *_range_start(edge.source_range),
                    edge.import_ordinal,
                    edge.deferred,
                    edge.implicit_package_init,
                ),
            )
        )
        object.__setattr__(self, "local_edges", edges)
        references = tuple(
            sorted(
                self.external_references,
                key=lambda reference: (
                    reference.importer,
                    reference.imported,
                    *_range_start(reference.source_range),
                    reference.import_ordinal,
                    reference.ownership.value,
                ),
            )
        )
        object.__setattr__(self, "external_references", references)
        components = tuple(
            sorted(self.strongly_connected_components, key=lambda component: component.members)
        )
        object.__setattr__(self, "strongly_connected_components", components)

        known = set(module_names)
        if any(edge.importer not in known or edge.imported not in known for edge in edges):
            raise ValueError("local import edge endpoints must be source graph modules")
        if any(reference.importer not in known for reference in references):
            raise ValueError("external import reference importer must be a source graph module")
        component_members = [member for component in components for member in component.members]
        if components and sorted(component_members) != sorted(module_names):
            raise ValueError("strongly connected components must partition source graph modules")

    @property
    def modules_by_name(self) -> dict[str, SourceModule]:
        """Return modules keyed in deterministic module-name order."""
        return {module.module_name: module for module in self.modules}

    @property
    def cycles(self) -> tuple[tuple[str, ...], ...]:
        """Return only cyclic SCC memberships in deterministic order."""
        return tuple(
            component.members
            for component in self.strongly_connected_components
            if component.cyclic
        )

    @property
    def scc_membership(self) -> dict[str, tuple[str, ...]]:
        """Map every module to its deterministic SCC membership tuple."""
        return {
            member: component.members
            for component in self.strongly_connected_components
            for member in component.members
        }

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable representation."""
        return {
            "modules": [module.to_dict() for module in self.modules],
            "local_edges": [edge.to_dict() for edge in self.local_edges],
            "external_references": [reference.to_dict() for reference in self.external_references],
            "strongly_connected_components": [
                component.to_dict() for component in self.strongly_connected_components
            ],
            "cycles": [list(cycle) for cycle in self.cycles],
            "scc_membership": {
                module: list(members) for module, members in self.scc_membership.items()
            },
        }
