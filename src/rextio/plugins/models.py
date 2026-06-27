from __future__ import annotations

from dataclasses import dataclass, field, replace

from rextio.targets.models import TargetSpec


@dataclass(frozen=True)
class RextioPlugin:
    id: str
    name: str
    source_language: str = "python"
    target_language: str = "rust"
    target_versions: tuple[str, ...] = ()
    target_build_options: dict[str, str] = field(default_factory=dict)
    rules: tuple[str, ...] = ()
    packages: tuple[str, ...] = ()
    source: str = "entry-point"
    package: str | None = None
    entry_point: str | None = None

    def matches(self, target: TargetSpec) -> bool:
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
        return replace(
            self,
            source=source,
            package=package,
            entry_point=entry_point,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "name": self.name,
            "source_language": self.source_language,
            "target_language": self.target_language,
            "target_versions": list(self.target_versions),
            "target_build_options": dict(sorted(self.target_build_options.items())),
            "rules": list(self.rules),
            "packages": list(self.packages),
            "source": self.source,
            "package": self.package,
            "entry_point": self.entry_point,
        }


@dataclass(frozen=True)
class PluginRegistry:
    enabled: tuple[str, ...] = ()
    discovered: tuple[RextioPlugin, ...] = ()
    active: tuple[RextioPlugin, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "enabled": list(self.enabled),
            "discovered": [plugin.to_dict() for plugin in self.discovered],
            "active": [plugin.to_dict() for plugin in self.active],
        }
