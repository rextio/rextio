from __future__ import annotations

from pathlib import Path

from rextio.analyzer.models import ModuleAnalysis
from rextio.fallback.module_copy import (
    copy_module_to_fallback,
    copy_plain_module,
    fallback_module_path,
    generated_module_path,
)


def write_cpython_fallback(module: ModuleAnalysis, python_root: Path) -> Path:
    path = fallback_module_path(python_root, module)
    copy_module_to_fallback(module, path)
    return path


def write_plain_cpython_module(module: ModuleAnalysis, python_root: Path) -> Path:
    return copy_plain_module(module, python_root)


def generated_path_for_module(module: ModuleAnalysis, python_root: Path) -> Path:
    return generated_module_path(python_root, module)
