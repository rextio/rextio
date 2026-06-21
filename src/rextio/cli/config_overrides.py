from __future__ import annotations


def key_value_overrides(values: list[tuple[str, str]] | None) -> dict[str, str] | None:
    if values is None:
        return None
    return dict(values)


def tuple_overrides(values: list[str] | None) -> tuple[str, ...] | None:
    if values is None:
        return None
    return tuple(values)

