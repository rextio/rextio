from __future__ import annotations

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
    files: list[Path] = []
    for path in root.rglob("*.py"):
        relative_parts = path.relative_to(root).parts
        if any(part in IGNORED_PARTS for part in relative_parts):
            continue
        files.append(path)
    return sorted(files)


def analyze_project(project_root: Path | str) -> ProjectAnalysis:
    root = Path(project_root).resolve()
    analysis = ProjectAnalysis(project_root=root)
    analysis.modules = [parse_module(path, root) for path in scan_python_files(root)]
    apply_boundary_checks(analysis)
    return analysis
