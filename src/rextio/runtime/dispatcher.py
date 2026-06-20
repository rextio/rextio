from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from rextio.runtime.flags import native_disabled

T = TypeVar("T")


def dispatch(native_func: Callable[..., T] | None, fallback_func: Callable[..., T], *args: object) -> T:
    if native_disabled() or native_func is None:
        return fallback_func(*args)
    return native_func(*args)
