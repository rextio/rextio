"""Helpers that turn CLI override flags into config-override values."""

from __future__ import annotations


def key_value_overrides(values: list[tuple[str, str]] | None) -> dict[str, str] | None:
    """Convert repeated KEY=VALUE flags into an override mapping, or None."""
    if values is None:
        return None
    return dict(values)


def package_policy_overrides(values: list[tuple[str, str]] | None) -> dict[str, dict[str, object]] | None:
    """Convert repeated PACKAGE=POLICY flags into a per-package override mapping, or None."""
    if values is None:
        return None
    return {package: {"policy": policy} for package, policy in values}


def tuple_overrides(values: list[str] | None) -> tuple[str, ...] | None:
    """Convert a list of flag values into a tuple override, or None."""
    if values is None:
        return None
    return tuple(values)
