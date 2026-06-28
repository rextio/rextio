from __future__ import annotations

import os
import warnings
from importlib import import_module
from types import ModuleType
from typing import Any

def _debug_native() -> bool:
    return os.environ.get("REXTIO_DEBUG_NATIVE") == "1"


def _surface_broken_native(module_name: str, exc: Exception) -> None:
    """Re-raise (debug) or warn that an existing native module failed to load."""
    if _debug_native():
        raise exc
    warnings.warn(
        f"Rextio native module {module_name!r} failed to load and will fall back "
        f"to Python: {exc!r}. Set REXTIO_DEBUG_NATIVE=1 to see the full traceback.",
        RuntimeWarning,
        stacklevel=3,
    )


def load_native_module(module_name: str) -> ModuleType | None:
    """Import a generated native module, distinguishing "absent" from "broken".

    A module that was never built is an expected condition and yields ``None`` so
    the wrapper can use the Python fallback. An import-time failure of a module that
    *does* exist (ABI mismatch, init panic, a missing dependency of the native
    module) is a real fault and is never swallowed silently: it is re-raised under
    ``REXTIO_DEBUG_NATIVE=1`` and otherwise surfaced as a ``RuntimeWarning``.

    The two are told apart by the failed import's target: a ``ModuleNotFoundError``
    whose ``name`` is the native module itself means "absent"; a ``ModuleNotFoundError``
    for some *other* module means the native module loaded far enough to import a
    dependency that is missing — that is "broken", not "absent".
    """
    try:
        return import_module(module_name)
    except ModuleNotFoundError as exc:
        if exc.name == module_name:
            return None
        _surface_broken_native(module_name, exc)
        return None
    except Exception as exc:  # noqa: BLE001 - intentionally broad; re-raised or warned below
        _surface_broken_native(module_name, exc)
        return None


def load_native_function(module_name: str, function_name: str) -> Any | None:
    module = load_native_module(module_name)
    if module is None:
        return None
    return getattr(module, function_name, None)
