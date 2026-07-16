"""Copying and naming of fallback module files."""

from __future__ import annotations

import ast
import shutil
from pathlib import Path

from rextio.analyzer.models import ModuleAnalysis
from rextio.analyzer.top_level import collect_native_top_level_statements
from rextio.fallback.fallback_marker import GENERATED_PYTHON_HEADER


def generated_module_path(python_root: Path, module: ModuleAnalysis) -> Path:
    """Return the path of a module within the generated Python tree."""
    source_path = Path(module.file_path)
    if module.module_name:
        parts = module.module_name.split(".")
    else:
        parts = [source_path.stem]
    if source_path.name == "__init__.py":
        return python_root.joinpath(*parts, "__init__.py")
    return python_root.joinpath(*parts).with_suffix(".py")


def fallback_module_name(module: ModuleAnalysis) -> str:
    """Return the fallback module name for a module."""
    return f"_fallback_{Path(module.file_path).stem}"


def native_top_level_fallback_module_name(module: ModuleAnalysis) -> str:
    """Return the native-top-level fallback module name for a module."""
    return f"_native_top_level_fallback_{Path(module.file_path).stem}"


def fallback_module_path(python_root: Path, module: ModuleAnalysis) -> Path:
    """Return the fallback module file path for a module."""
    generated_path = generated_module_path(python_root, module)
    return generated_path.with_name(f"{fallback_module_name(module)}.py")


def native_top_level_fallback_module_path(python_root: Path, module: ModuleAnalysis) -> Path:
    """Return the native-top-level fallback module file path for a module."""
    generated_path = generated_module_path(python_root, module)
    return generated_path.with_name(f"{native_top_level_fallback_module_name(module)}.py")


def copy_module_to_fallback(module: ModuleAnalysis, fallback_path: Path) -> None:
    """Copy a module's source to its fallback location."""
    fallback_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(module.file_path, fallback_path)


def write_native_top_level_fallback_module(module: ModuleAnalysis, python_root: Path) -> Path:
    """Write the native-top-level fallback module and return its path."""
    path = native_top_level_fallback_module_path(python_root, module)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_native_top_level_fallback_module(module), encoding="utf-8")
    return path


def render_native_top_level_fallback_module(module: ModuleAnalysis) -> str:
    """Render an elided fallback while preserving source definition lines.

    Method identity guards compare ``co_firstlineno`` with the analyzed source.
    Re-unparsing the residual AST renumbered every function/class after an
    elided initializer.  Replace each converted statement span with a harmless
    statement of the same byte/line footprint instead, and put the generated
    marker at EOF so every surviving definition keeps its original line.
    """
    source = Path(module.file_path).read_text(encoding="utf-8")
    tree = ast.parse(source, filename=module.file_path)
    lines = [bytearray(line.encode("utf-8")) for line in source.splitlines(keepends=True)]
    for statement in collect_native_top_level_statements(tree):
        start_line = statement.lineno - 1
        end_line = (statement.end_lineno or statement.lineno) - 1
        start_column = statement.col_offset
        end_column = statement.end_col_offset or 0
        for line_number in range(start_line, end_line + 1):
            line = lines[line_number]
            content_end = len(line.rstrip(b"\r\n"))
            lower = start_column if line_number == start_line else 0
            upper = end_column if line_number == end_line else content_end
            line[lower:upper] = b" " * max(upper - lower, 0)
        first_line = lines[start_line]
        first_content_end = len(first_line.rstrip(b"\r\n"))
        first_upper = end_column if start_line == end_line else first_content_end
        width = max(first_upper - start_column, 0)
        replacement = b"pass" if width >= 4 else b"0"
        first_line[start_column : start_column + len(replacement)] = replacement
    body = b"".join(lines).decode("utf-8")
    separator = "\n" if body.endswith(("\n", "\r")) else "\n\n"
    return f"{body}{separator}{GENERATED_PYTHON_HEADER}\n"


def copy_plain_module(module: ModuleAnalysis, python_root: Path) -> Path:
    """Copy a module unchanged into the fallback tree and return its path."""
    destination = generated_module_path(python_root, module)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(module.file_path, destination)
    return destination
