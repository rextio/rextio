"""Rextio's public package surface: the ``native`` and ``exempt`` marker decorators."""

from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import overload, TypeVar

from rextio.__about__ import __version__

F = TypeVar("F", bound=Callable[..., object])


@overload
def native(func: F) -> F: ...


@overload
def native(*, target: str | None = None) -> Callable[[F], F]: ...


def native(func: F | None = None, *, target: str | None = None) -> F | Callable[[F], F]:
    """Mark a function as a Rextio native compilation candidate.

    ``target`` optionally pins the native target language; it must be one of
    the supported target languages (currently only ``rust``). The decorator applies
    to functions and methods, not classes.
    """
    normalized_target = _normalize_target(target)

    def apply(wrapped: F) -> F:
        _require_decoratable(wrapped, "native")
        setattr(wrapped, "__rextio_native__", True)
        if normalized_target is not None:
            setattr(wrapped, "__rextio_native_target__", normalized_target)
        return wrapped

    if func is None:
        return apply
    return apply(func)


def exempt(func: F) -> F:
    """Mark a function as excluded from Rextio native compilation."""
    _require_decoratable(func, "exempt")
    setattr(func, "__rextio_exempt__", True)
    return func


def _require_decoratable(func: object, decorator: str) -> None:
    if isinstance(func, type):
        raise TypeError(f"@rextio.{decorator} can only decorate functions, not classes")
    if not callable(func):
        raise TypeError(f"@rextio.{decorator} can only decorate callables")
    # The marker is read off a plain function object. A `staticmethod`/`classmethod`
    # descriptor or a callable instance is callable but is not a function, so the
    # `setattr` below would land on the wrapper and the analyzer would never see it —
    # reject those rather than silently misfire. Apply `@rextio.native` directly to
    # the function, beneath `@staticmethod`/`@classmethod`.
    if not inspect.isfunction(func):
        raise TypeError(
            f"@rextio.{decorator} can only decorate functions and methods, "
            f"not {type(func).__name__} objects; apply @rextio.{decorator} directly to "
            f"the function (e.g. as the innermost decorator, below "
            f"@staticmethod/@classmethod)"
        )


def _normalize_target(target: str | None) -> str | None:
    if target is None:
        return None
    if not isinstance(target, str):
        raise TypeError("@rextio.native target must be a string")
    # Imported lazily so a bare ``import rextio`` stays lightweight.
    from rextio.targets.models import SUPPORTED_TARGET_LANGUAGES

    normalized = target.strip().lower()
    if normalized not in SUPPORTED_TARGET_LANGUAGES:
        supported = ", ".join(sorted(SUPPORTED_TARGET_LANGUAGES))
        raise ValueError(
            f"@rextio.native target {target!r} is not supported; choose one of: {supported}"
        )
    return normalized


__all__ = ["__version__", "exempt", "native"]
