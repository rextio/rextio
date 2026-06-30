"""Loading compiled native functions at runtime."""

from __future__ import annotations

import importlib.util
import os
import sys
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

    Absence is decided up front with ``importlib.util.find_spec``: if the module
    is not importable at all (never built), return ``None`` so the wrapper uses the
    Python fallback. If a spec exists but the import then fails (ABI mismatch, init
    panic, a missing dependency of the native module), that is a real fault and is
    never swallowed silently — it is re-raised under ``REXTIO_DEBUG_NATIVE=1`` and
    otherwise surfaced as a ``RuntimeWarning``.

    Using ``find_spec`` instead of inspecting ``ModuleNotFoundError`` keeps the
    absent/broken split correct regardless of how the import fails (relative vs
    top-level import, ``exc.name`` being ``None``, custom importers, etc.).
    """
    try:
        spec = importlib.util.find_spec(module_name)
    except Exception:  # noqa: BLE001 - exotic meta-path finders can raise anything
        spec = None
    # An already-imported module (including test injections) counts as present.
    if spec is None and module_name not in sys.modules:
        return None
    try:
        return import_module(module_name)
    except Exception as exc:  # noqa: BLE001 - intentionally broad; re-raised or warned above
        _surface_broken_native(module_name, exc)
        return None


def load_native_function(module_name: str, function_name: str) -> Any | None:
    """Load a compiled native function, or None if unavailable.

    A missing *module* is normal absence (fall back silently). A module that
    loaded but is missing the requested *function* is a codegen/wrapper naming
    mismatch — a real fault — so surface it (re-raised under
    ``REXTIO_DEBUG_NATIVE=1``, otherwise a ``RuntimeWarning``) instead of
    silently falling back.
    """
    module = load_native_module(module_name)
    if module is None:
        return None
    function = getattr(module, function_name, None)
    if function is None:
        _surface_missing_function(module_name, function_name)
    return function


def _surface_missing_function(module_name: str, function_name: str) -> None:
    """Re-raise (debug) or warn that a loaded native module lacks a function."""
    if _debug_native():
        raise AttributeError(
            f"Rextio native module {module_name!r} has no function {function_name!r}"
        )
    warnings.warn(
        f"Rextio native module {module_name!r} loaded but has no function "
        f"{function_name!r} (codegen/wrapper name mismatch); falling back to Python. "
        f"Set REXTIO_DEBUG_NATIVE=1 to raise instead.",
        RuntimeWarning,
        stacklevel=3,
    )
