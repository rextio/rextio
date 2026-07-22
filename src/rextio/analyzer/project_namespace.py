"""Shared built-in project namespace exclusions.

These exclusions are compiler policy, not caller-provided authority.  Strict
Full C6 and ordinary analysis share the same fixed set; only ordinary analysis
adds patterns from ``.rextioignore``.
"""

from __future__ import annotations

from pathlib import Path


BUILTIN_IGNORED_PARTS = frozenset(
    {
        ".git",
        ".hg",
        ".mypy_cache",
        ".pytest_cache",
        ".rextio",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "venv",
    }
)


def has_builtin_ignored_part(relative: Path) -> bool:
    """Return whether a relative project path is excluded by compiler policy."""
    return any(part in BUILTIN_IGNORED_PARTS for part in relative.parts)


__all__ = ["BUILTIN_IGNORED_PARTS", "has_builtin_ignored_part"]
