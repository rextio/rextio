from __future__ import annotations

import os
import warnings
from importlib import import_module
from types import ModuleType
from typing import Any

def _debug_native() -> bool:
    return os.environ.get("REXTIO_DEBUG_NATIVE") == "1"


def load_native_module(module_name: str) -> ModuleType | None:
    """Import a generated native module, distinguishing "absent" from "broken".

    A missing module (never built) is an expected condition and yields ``None`` so
    the wrapper can use the Python fallback. An import-time failure of a module that
    *does* exist (ABI mismatch, init panic, missing dependency) is a real fault: it
    is never swallowed silently — it is re-raised under ``REXTIO_DEBUG_NATIVE=1``
    for a full traceback, and otherwise surfaced as a ``RuntimeWarning`` so the
    fallback path stays usable while the cause remains visible. (In native-required
    mode the wrapper still raises a clear error when the binding is unavailable.)
    """
    try:
        return import_module(module_name)
    except ModuleNotFoundError:
        return None
    except Exception as exc:  # noqa: BLE001 - intentionally broad; re-raised or warned below
        if _debug_native():
            raise
        warnings.warn(
            f"Rextio native module {module_name!r} failed to load and will fall back "
            f"to Python: {exc!r}. Set REXTIO_DEBUG_NATIVE=1 to see the full traceback.",
            RuntimeWarning,
            stacklevel=2,
        )
        return None


def load_native_function(module_name: str, function_name: str) -> Any | None:
    module = load_native_module(module_name)
    if module is None:
        return None
    return getattr(module, function_name, None)
