from __future__ import annotations

import shutil
from pathlib import Path

from rextio.analyzer.models import ModuleAnalysis


def generated_module_path(python_root: Path, module: ModuleAnalysis) -> Path:
    source_path = Path(module.file_path)
    if module.module_name:
        parts = module.module_name.split(".")
    else:
        parts = [source_path.stem]
    if source_path.name == "__init__.py":
        return python_root.joinpath(*parts, "__init__.py")
    return python_root.joinpath(*parts).with_suffix(".py")


def fallback_module_name(module: ModuleAnalysis) -> str:
    return f"_fallback_{Path(module.file_path).stem}"


def fallback_module_path(python_root: Path, module: ModuleAnalysis) -> Path:
    generated_path = generated_module_path(python_root, module)
    return generated_path.with_name(f"{fallback_module_name(module)}.py")


def copy_module_to_fallback(module: ModuleAnalysis, fallback_path: Path) -> None:
    fallback_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(module.file_path, fallback_path)


def copy_plain_module(module: ModuleAnalysis, python_root: Path) -> Path:
    destination = generated_module_path(python_root, module)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(module.file_path, destination)
    return destination
