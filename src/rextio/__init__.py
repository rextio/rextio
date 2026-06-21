from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

__version__ = "0.1.0"

F = TypeVar("F", bound=Callable[..., object])


def native(func: F) -> F:
    """Mark a function as a Rextio native compilation candidate."""
    setattr(func, "__rextio_native__", True)
    return func


def exempt(func: F) -> F:
    """Mark a function as excluded from Rextio native compilation."""
    setattr(func, "__rextio_exempt__", True)
    return func


__all__ = ["__version__", "exempt", "native"]
