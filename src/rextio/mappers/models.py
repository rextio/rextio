from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from rextio.targets.models import TargetSpec


@dataclass(frozen=True)
class MapperPlugin:
    id: str
    name: str
    path: Path
    source_language: str = "python"
    target_language: str = "rust"
    target_versions: tuple[str, ...] = ()
    target_build_options: dict[str, str] = field(default_factory=dict)
    rules: tuple[str, ...] = ()

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

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "name": self.name,
            "path": str(self.path),
            "source_language": self.source_language,
            "target_language": self.target_language,
            "target_versions": list(self.target_versions),
            "target_build_options": dict(sorted(self.target_build_options.items())),
            "rules": list(self.rules),
        }


@dataclass(frozen=True)
class MapperRegistry:
    discovered: tuple[MapperPlugin, ...] = ()
    active: tuple[MapperPlugin, ...] = ()
    repository: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "repository": self.repository,
            "discovered": [mapper.to_dict() for mapper in self.discovered],
            "active": [mapper.to_dict() for mapper in self.active],
        }

