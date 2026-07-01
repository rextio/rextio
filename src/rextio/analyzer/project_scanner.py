"""Project file discovery and the analyze_project entry point."""

from __future__ import annotations

from collections.abc import Iterable
from fnmatch import fnmatch
from pathlib import Path

from rextio.analyzer.boundary import apply_boundary_checks
from rextio.analyzer.models import ProjectAnalysis
from rextio.analyzer.module_parser import module_name_for_path, parse_module
from rextio.config.schema import ImportsConfig
from rextio.plugins.models import RextioPlugin
from rextio.targets.models import normalize_target_language

IGNORED_PARTS = {
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


def scan_python_files(project_root: Path) -> list[Path]:
    """Return the project's Python files, honoring .rextioignore."""
    root = project_root.resolve()
    ignore_patterns = load_rextioignore(root)
    files: list[Path] = []
    for path in root.rglob("*.py"):
        relative = path.relative_to(root)
        if _is_ignored(relative, ignore_patterns):
            continue
        files.append(path)
    return sorted(files)


def load_rextioignore(project_root: Path) -> list[str]:
    """Load the .rextioignore patterns for the project, if present."""
    path = project_root / ".rextioignore"
    if not path.exists():
        return []
    patterns: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        patterns.append(line)
    return patterns


def _is_ignored(relative: Path, ignore_patterns: list[str]) -> bool:
    parts = relative.parts
    if any(part in IGNORED_PARTS for part in parts):
        return True
    relative_text = relative.as_posix()
    for pattern in ignore_patterns:
        normalized = pattern.strip("/")
        if not normalized:
            continue
        if pattern.endswith("/"):
            if normalized in parts or relative_text.startswith(f"{normalized}/"):
                return True
            continue
        if fnmatch(relative_text, normalized) or fnmatch(relative.name, normalized):
            return True
        if relative_text == normalized or relative_text.startswith(f"{normalized}/"):
            return True
    return False


def analyze_project(
    project_root: Path | str,
    boundary_warnings: bool = True,
    native_marker: str = "auto",
    target_language: str = "rust",
    native_top_level: bool = False,
    imports_config: ImportsConfig | None = None,
    active_plugins: Iterable[RextioPlugin] = (),
    native_jit_enabled: bool = False,
    jit_hot_threshold: int = 25,
    delegate_fallback: bool = False,
) -> ProjectAnalysis:
    """Analyze a project directory and return its ProjectAnalysis.

    When ``delegate_fallback`` is set (the Rust-executable delegate mode), a
    direct-native function that calls a project function living on the Python
    fallback records it as a delegated call instead of being rejected, so the
    generated binary can invoke it through the external CPython dispatcher.
    """
    root = Path(project_root).resolve()
    target_language = normalize_target_language(target_language)
    analysis = ProjectAnalysis(project_root=root)
    files = scan_python_files(root)
    project_modules = _project_module_names(files, root)
    analysis.modules = [
        parse_module(
            path,
            root,
            native_marker=native_marker,
            target_language=target_language,
            native_top_level=native_top_level,
            project_modules=project_modules,
            imports_config=imports_config,
            active_plugins=active_plugins,
            native_jit_enabled=native_jit_enabled,
            jit_hot_threshold=jit_hot_threshold,
        )
        for path in files
    ]
    apply_boundary_checks(
        analysis,
        boundary_warnings=boundary_warnings,
        native_jit_enabled=native_jit_enabled,
        delegate_fallback=delegate_fallback,
    )
    return analysis


def _project_module_names(files: list[Path], project_root: Path) -> set[str]:
    names: set[str] = set()
    for path in files:
        module_name = module_name_for_path(path, project_root)
        if not module_name:
            continue
        parts = module_name.split(".")
        for index in range(1, len(parts) + 1):
            names.add(".".join(parts[:index]))
    return names
