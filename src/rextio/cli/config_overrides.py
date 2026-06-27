from __future__ import annotations


def key_value_overrides(values: list[tuple[str, str]] | None) -> dict[str, str] | None:
    if values is None:
        return None
    return dict(values)


def package_policy_overrides(values: list[tuple[str, str]] | None) -> dict[str, dict[str, object]] | None:
    if values is None:
        return None
    return {package: {"policy": policy} for package, policy in values}


def tuple_overrides(values: list[str] | None) -> tuple[str, ...] | None:
    if values is None:
        return None
    return tuple(values)
