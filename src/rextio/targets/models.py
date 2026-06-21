from __future__ import annotations

from dataclasses import dataclass, field


SUPPORTED_TARGET_LANGUAGES = {"rust", "mojo", "julia"}
IMPLEMENTED_TARGET_LANGUAGES = {"rust"}


@dataclass(frozen=True)
class TargetSpec:
    language: str = "rust"
    version: str | None = None
    build_options: dict[str, str] = field(default_factory=dict)

    @property
    def implemented(self) -> bool:
        return self.language in IMPLEMENTED_TARGET_LANGUAGES

    def to_dict(self) -> dict[str, object]:
        return {
            "language": self.language,
            "version": self.version,
            "build_options": dict(sorted(self.build_options.items())),
            "implemented": self.implemented,
        }


def normalize_target_language(value: str) -> str:
    return value.strip().lower()

