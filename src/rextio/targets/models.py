"""Target specification model and language constants."""

from __future__ import annotations

from dataclasses import dataclass, field


SUPPORTED_TARGET_LANGUAGES = {"rust"}
IMPLEMENTED_TARGET_LANGUAGES = {"rust"}


@dataclass(frozen=True)
class TargetSpec:
    """A resolved native target: language, version, and build options."""

    language: str = "rust"
    version: str | None = None
    build_options: dict[str, str] = field(default_factory=dict)

    @property
    def implemented(self) -> bool:
        """Report whether the target language has an implemented codegen backend."""
        return self.language in IMPLEMENTED_TARGET_LANGUAGES

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this spec."""
        return {
            "language": self.language,
            "version": self.version,
            "build_options": dict(sorted(self.build_options.items())),
            "implemented": self.implemented,
        }


def normalize_target_language(value: str) -> str:
    """Normalize a target language string (strip + lowercase)."""
    return value.strip().lower()

