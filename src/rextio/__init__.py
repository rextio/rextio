from __future__ import annotations

from collections.abc import Callable
from typing import overload, TypeVar

from rextio.__about__ import __version__

F = TypeVar("F", bound=Callable[..., object])


@overload
def native(func: F) -> F: ...


@overload
def native(*, target: str | None = None) -> Callable[[F], F]: ...


def native(func: F | None = None, *, target: str | None = None) -> F | Callable[[F], F]:
    """Mark a function as a Rextio native compilation candidate."""
    if func is None:
        return lambda wrapped: native(wrapped, target=target)
    if not callable(func):
        raise TypeError("@rextio.native can only decorate callables")
    setattr(func, "__rextio_native__", True)
    if target is not None:
        setattr(func, "__rextio_native_target__", target.strip().lower())
    return func


def exempt(func: F) -> F:
    """Mark a function as excluded from Rextio native compilation."""
    setattr(func, "__rextio_exempt__", True)
    return func


__all__ = ["__version__", "exempt", "native"]
