from __future__ import annotations

import os
from dataclasses import dataclass, field
from threading import Lock

DEFAULT_BOUNDARY_FALLBACK_THRESHOLD = 1000
THRESHOLD_ENV = "REXTIO_BOUNDARY_FALLBACK_THRESHOLD"
DISABLE_ENV = "REXTIO_DISABLE_BOUNDARY_FALLBACK"


@dataclass
class _BoundaryFallbackState:
    lock: Lock = field(default_factory=Lock)
    counts: dict[str, int] = field(default_factory=dict)
    fallback_functions: set[str] = field(default_factory=set)


_STATE = _BoundaryFallbackState()


def boundary_fallback_threshold() -> int:
    raw_value = os.environ.get(THRESHOLD_ENV)
    if raw_value in {None, ""}:
        return DEFAULT_BOUNDARY_FALLBACK_THRESHOLD
    try:
        value = int(raw_value)
    except ValueError:
        return DEFAULT_BOUNDARY_FALLBACK_THRESHOLD
    if value < 0:
        return DEFAULT_BOUNDARY_FALLBACK_THRESHOLD
    return value


def boundary_fallback_disabled() -> bool:
    return os.environ.get(DISABLE_ENV) == "1" or boundary_fallback_threshold() == 0


def boundary_fallback_required(function_name: str) -> bool:
    threshold = boundary_fallback_threshold()
    if threshold == 0 or os.environ.get(DISABLE_ENV) == "1":
        return False

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
    with _STATE.lock:
        return _STATE.counts.get(function_name, 0)


def reset_boundary_fallback_state() -> None:
    with _STATE.lock:
        _STATE.counts.clear()
        _STATE.fallback_functions.clear()
