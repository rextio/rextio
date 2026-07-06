"""Plugin metadata models: ``RextioPlugin`` and the discovered/active registry."""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from rextio.plugins.api import CoverageDecl, RuleRecord
from rextio.targets.models import TargetSpec


@dataclass(frozen=True)
class PluginCoverage:
    """An active plugin's coverage declaration, tagged with its plugin id."""

    plugin_id: str
    coverage: CoverageDecl

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this object."""
        return {"plugin_id": self.plugin_id, "coverage": self.coverage.to_dict()}


@dataclass(frozen=True)
class RextioPlugin:
    """A Rextio plugin's resolved metadata.

    A plugin declares (a) target compatibility — source/target language, target
    versions, and target build options, used by :meth:`matches` — and (b) the
    external Python packages it covers (``packages``), which the analyzer uses to
    resolve those packages to the ``plugin`` import policy. A protocol-v2 plugin
    additionally *self-describes* declarative rule records through ``describe()``
    (``rules_provided`` is True; see ``rextio.plugins.api``). No plugin injects
    codegen rules or otherwise alters lowering; the analyzer remains the
    authority on what lowers.
    """

    id: str
    name: str
    source_language: str = "python"
    target_language: str = "rust"
    target_versions: tuple[str, ...] = ()
    target_build_options: dict[str, str] = field(default_factory=dict)
    packages: tuple[str, ...] = ()
    source: str = "entry-point"
    package: str | None = None
    entry_point: str | None = None
    # Protocol v2: True when the plugin self-describes rule records through
    # ``describe()``; the declared plugin-API version travels with it.
    rules_provided: bool = False
    api_version: str | None = None

    def matches(self, target: TargetSpec) -> bool:
        """Report whether this plugin applies to the given target spec."""
        if self.source_language != "python":
            return False
        if self.target_language != target.language:
            return False
        if self.target_versions and "*" not in self.target_versions:
            if target.version is None or target.version not in self.target_versions:
                return False
        for key, value in self.target_build_options.items():
            if target.build_options.get(key) != value:
                return False
        return True

    def with_source_metadata(
        self,
        *,
        source: str,
        package: str | None = None,
        entry_point: str | None = None,
    ) -> RextioPlugin:
        """Return a copy of this plugin annotated with its discovery source."""
        return replace(
            self,
            source=source,
            package=package,
            entry_point=entry_point,
        )

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this object."""
        return {
            "id": self.id,
            "name": self.name,
            "source_language": self.source_language,
            "target_language": self.target_language,
            "target_versions": list(self.target_versions),
            "target_build_options": dict(sorted(self.target_build_options.items())),
            "packages": list(self.packages),
            "source": self.source,
            "package": self.package,
            "entry_point": self.entry_point,
            "rules_provided": self.rules_provided,
            "api_version": self.api_version,
        }


@dataclass(frozen=True)
class PluginRegistry:
    """The set of discovered and active plugins, plus their v2 self-descriptions."""

    enabled: tuple[str, ...] = ()
    discovered: tuple[RextioPlugin, ...] = ()
    active: tuple[RextioPlugin, ...] = ()
    # Rule records described by active v2 plugins (provider = plugin id),
    # already validated by the loader. Empty when only v1 plugins are active.
    rule_records: tuple[RuleRecord, ...] = ()
    coverages: tuple[PluginCoverage, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this object.

        The v2 fields are emitted only when present, so reports for
        metadata-only plugin sets keep their existing shape.
        """
        data: dict[str, object] = {
            "enabled": list(self.enabled),
            "discovered": [plugin.to_dict() for plugin in self.discovered],
            "active": [plugin.to_dict() for plugin in self.active],
        }
        if self.rule_records:
            data["rule_records"] = [record.to_dict() for record in self.rule_records]
        if self.coverages:
            data["coverages"] = [coverage.to_dict() for coverage in self.coverages]
        return data
