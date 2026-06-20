from __future__ import annotations

from fnmatch import fnmatch
from pathlib import Path

from rextio.analyzer.boundary import apply_boundary_checks
from rextio.analyzer.models import ProjectAnalysis
from rextio.analyzer.module_parser import parse_module

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


def analyze_project(project_root: Path | str) -> ProjectAnalysis:
    root = Path(project_root).resolve()
    analysis = ProjectAnalysis(project_root=root)
    analysis.modules = [parse_module(path, root) for path in scan_python_files(root)]
    apply_boundary_checks(analysis)
    return analysis
