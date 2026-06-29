"""Writing the CPython fallback modules."""

from __future__ import annotations

from pathlib import Path

from rextio.analyzer.models import ModuleAnalysis
from rextio.fallback.module_copy import (
    copy_module_to_fallback,
    copy_plain_module,
    fallback_module_path,
    generated_module_path,
    write_native_top_level_fallback_module,
)


def write_cpython_fallback(module: ModuleAnalysis, python_root: Path) -> Path:
    """Write the CPython fallback for a module and return its path."""
    path = fallback_module_path(python_root, module)
    copy_module_to_fallback(module, path)
    return path


def write_cpython_native_top_level_fallback(module: ModuleAnalysis, python_root: Path) -> Path:
    """Write the CPython fallback for a module's native top level and return its path."""
    return write_native_top_level_fallback_module(module, python_root)


def write_plain_cpython_module(module: ModuleAnalysis, python_root: Path) -> Path:
    """Write a module unchanged into the fallback tree and return its path."""
    return copy_plain_module(module, python_root)


def generated_path_for_module(module: ModuleAnalysis, python_root: Path) -> Path:
    """Return the generated fallback path for a module."""
    return generated_module_path(python_root, module)
