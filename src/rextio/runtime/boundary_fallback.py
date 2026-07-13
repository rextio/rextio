"""Runtime boundary-fallback threshold tracking."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from threading import Lock

from rextio.runtime.flags import env_truthy

DEFAULT_BOUNDARY_FALLBACK_THRESHOLD = 1000
THRESHOLD_ENV = "REXTIO_BOUNDARY_FALLBACK_THRESHOLD"
DISABLE_ENV = "REXTIO_DISABLE_BOUNDARY_FALLBACK"


@dataclass
class _BoundaryFallbackState:
    lock: Lock = field(default_factory=Lock)
    counts: dict[str, int] = field(default_factory=dict)
    fallback_functions: set[str] = field(default_factory=set)


_STATE = _BoundaryFallbackState()


def boundary_fallback_threshold(
    default_threshold: int = DEFAULT_BOUNDARY_FALLBACK_THRESHOLD,
) -> int:
    """Return the effective boundary-fallback threshold."""
    raw_value = os.environ.get(THRESHOLD_ENV)
    if raw_value is None or raw_value == "":
        return _valid_default_threshold(default_threshold)
    try:
        value = int(raw_value)
    except ValueError:
        return _valid_default_threshold(default_threshold)
    if value < 0:
        return _valid_default_threshold(default_threshold)
    return value


def boundary_fallback_disabled(
    default_threshold: int = DEFAULT_BOUNDARY_FALLBACK_THRESHOLD,
) -> bool:
    """Report whether boundary fallback is disabled."""
    return env_truthy(DISABLE_ENV) or boundary_fallback_threshold(default_threshold) == 0


def boundary_fallback_required(
    function_name: str,
    default_threshold: int = DEFAULT_BOUNDARY_FALLBACK_THRESHOLD,
) -> bool:
    """Report whether a function has crossed the boundary-fallback threshold."""
    threshold = boundary_fallback_threshold(default_threshold)
    if threshold == 0 or env_truthy(DISABLE_ENV):
        return False

    # Fast path: once a function has crossed the threshold it stays on fallback
    # permanently, so the steady state — every call after the threshold — needs
    # no lock at all. The set membership read is atomic under the GIL; a race
    # with a concurrent insert only costs one extra slow-path check, never a
    # wrong answer. This removes the per-call global-lock contention that would
    # otherwise persist for the hot functions that fell back.
    if function_name in _STATE.fallback_functions:
        return True

    with _STATE.lock:
        if function_name in _STATE.fallback_functions:
            return True

        count = _STATE.counts.get(function_name, 0) + 1
        _STATE.counts[function_name] = count
        if count > threshold:
            _STATE.fallback_functions.add(function_name)
            return True
        return False


def boundary_fallback_count(function_name: str) -> int:
    """Return the recorded boundary-crossing count for a function."""
    with _STATE.lock:
        return _STATE.counts.get(function_name, 0)


def reset_boundary_fallback_state() -> None:
    """Reset the in-process boundary-fallback counters (test helper)."""
    with _STATE.lock:
        _STATE.counts.clear()
        _STATE.fallback_functions.clear()


def _valid_default_threshold(default_threshold: int) -> int:
    if default_threshold < 0:
        return DEFAULT_BOUNDARY_FALLBACK_THRESHOLD
    return default_threshold
