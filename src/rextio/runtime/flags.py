from __future__ import annotations

import os


def native_disabled() -> bool:
    return os.environ.get("REXTIO_DISABLE_NATIVE") == "1" or os.environ.get(
        "REXTIO_NATIVE_MODE"
    ) == "fallback"


def native_mode() -> str:
    mode = os.environ.get("REXTIO_NATIVE_MODE", "auto")
    if mode not in {"auto", "native", "fallback"}:
        return "auto"
    return mode
