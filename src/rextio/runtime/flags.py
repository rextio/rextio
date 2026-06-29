"""Runtime environment flags controlling native execution."""

from __future__ import annotations

import os


def native_disabled() -> bool:
    """Report whether native execution is disabled via the environment."""
    return os.environ.get("REXTIO_DISABLE_NATIVE") == "1" or os.environ.get(
        "REXTIO_NATIVE_MODE"
    ) == "fallback"


def native_required() -> bool:
    """Report whether native execution is required via the environment."""
    return os.environ.get("REXTIO_DISABLE_NATIVE") != "1" and native_mode() == "native"


def native_mode() -> str:
    """Return the configured native execution mode."""
    mode = os.environ.get("REXTIO_NATIVE_MODE", "auto")
    if mode not in {"auto", "native", "fallback"}:
        return "auto"
    return mode
