from __future__ import annotations

from importlib import import_module
from types import ModuleType
from typing import Any


def load_native_module(module_name: str) -> ModuleType | None:
    try:
        return import_module(module_name)
    except Exception:
        return None


def load_native_function(module_name: str, function_name: str) -> Any | None:
    module = load_native_module(module_name)
    if module is None:
        return None
    return getattr(module, function_name, None)
