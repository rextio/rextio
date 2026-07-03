"""Runtime environment flags controlling native execution."""

from __future__ import annotations

import os
import warnings

_TRUTHY = {"1", "true", "yes", "on"}
_VALID_MODES = {"auto", "native", "fallback"}
_warned_modes: set[str] = set()


def env_truthy(name: str) -> bool:
    """Report whether an environment variable holds a truthy value.

    Accepts ``1``/``true``/``yes``/``on`` (case-insensitive) so boolean flags
    are not a footgun for users who write ``=true``.
    """
    value = os.environ.get(name)
    return value is not None and value.strip().lower() in _TRUTHY


def native_disabled() -> bool:
    """Report whether native execution is disabled via the environment."""
    return native_mode() == "fallback"


def native_required() -> bool:
    """Report whether native execution is required via the environment."""
    return native_mode() == "native"


def native_mode() -> str:
    """Return the configured native execution mode.

    Warns once per distinct invalid value before coercing to ``auto`` so a typo
    in ``REXTIO_NATIVE_MODE`` is not silently ignored.
    """
    raw = os.environ.get("REXTIO_NATIVE_MODE")
    if raw is None:
        return "auto"
    mode = raw.strip().lower()
    if mode in _VALID_MODES:
        return mode
    if raw not in _warned_modes:
        _warned_modes.add(raw)
        warnings.warn(
            f"REXTIO_NATIVE_MODE={raw!r} is not one of auto/native/fallback; using 'auto'.",
            RuntimeWarning,
            stacklevel=2,
        )
    return "auto"
