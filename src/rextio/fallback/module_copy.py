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
    """Render the source of a native-top-level fallback module."""
    source = Path(module.file_path).read_text(encoding="utf-8")
    tree = ast.parse(source, filename=module.file_path)
    converted = set(collect_native_top_level_statements(tree))
    tree.body = [statement for statement in tree.body if statement not in converted]
    ast.fix_missing_locations(tree)
    body = ast.unparse(tree) if tree.body else ""
    return f"{GENERATED_PYTHON_HEADER}\n\n{body}\n"


def copy_plain_module(module: ModuleAnalysis, python_root: Path) -> Path:
    """Copy a module unchanged into the fallback tree and return its path."""
    destination = generated_module_path(python_root, module)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(module.file_path, destination)
    return destination
