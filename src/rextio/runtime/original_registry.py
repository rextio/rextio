"""Isolated storage for exact Python originals used by RXT080 shims.

Generated wrappers must not add synthetic attributes to either the copied
fallback module or the user's public wrapper namespace: a user may legitimately
export every ``_rextio_*`` spelling.  Wrappers therefore capture originals in
their private bootstrap frame and publish one ordinal mapping here.  Generated
Rust resolves an ordinal only when the corresponding shim is invoked.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from threading import RLock
from typing import Any


_LOCK = RLock()
_ORIGINALS: dict[str, dict[int, Callable[..., Any]]] = {}


def register_runtime_originals(
    module_name: str,
    originals: Mapping[int, Callable[..., Any]],
) -> None:
    """Atomically replace ``module_name``'s exact ordinal-to-callable mapping."""
    captured = dict(originals)
    if any(type(ordinal) is not int or ordinal < 0 for ordinal in captured):
        raise ValueError("runtime-original ordinals must be non-negative integers")
    if any(not callable(original) for original in captured.values()):
        raise TypeError("runtime originals must be callable")
    with _LOCK:
        _ORIGINALS[module_name] = captured


def resolve_runtime_original(module_name: str, ordinal: int) -> Callable[..., Any]:
    """Return one registered exact original, failing loudly on stale metadata."""
    with _LOCK:
        try:
            return _ORIGINALS[module_name][ordinal]
        except KeyError:
            raise RuntimeError(
                f"runtime original is unavailable: {module_name!r} ordinal {ordinal}"
            ) from None
