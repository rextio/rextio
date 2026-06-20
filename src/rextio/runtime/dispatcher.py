from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from rextio.runtime.flags import native_disabled, native_required

T = TypeVar("T")


def dispatch(native_func: Callable[..., T] | None, fallback_func: Callable[..., T], *args: object) -> T:
    if native_disabled():
        return fallback_func(*args)
    if native_func is None:
        if native_required():
            raise RuntimeError("native mode requires generated native function, but it is unavailable")
        return fallback_func(*args)
    return native_func(*args)
