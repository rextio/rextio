"""Selected-only Device Provider API 1 entry-point loading."""

from __future__ import annotations

from collections.abc import Iterable
from importlib import metadata
from typing import Any

from rextio.devices.api import (
    DEVICE_PROVIDER_ENTRY_POINT,
    DeviceProvider,
    DeviceProviderError,
    DeviceProviderSelection,
    DeviceProviderSource,
)


def _entry_points(entry_points: Iterable[Any] | None) -> tuple[Any, ...]:
    """Return device-provider entry points without importing their payloads."""
    if entry_points is not None:
        return tuple(
            entry_point
            for entry_point in entry_points
            if getattr(entry_point, "group", None) == DEVICE_PROVIDER_ENTRY_POINT
        )
    discovered = metadata.entry_points()
    if hasattr(discovered, "select"):
        return tuple(discovered.select(group=DEVICE_PROVIDER_ENTRY_POINT))
    return tuple(discovered.get(DEVICE_PROVIDER_ENTRY_POINT, ()))


def load_selected_device_provider(
    selection: DeviceProviderSelection,
    *,
    entry_points: Iterable[Any] | None = None,
) -> tuple[DeviceProvider, DeviceProviderSource]:
    """Load exactly the selected provider; never import unselected payloads."""
    if not isinstance(selection, DeviceProviderSelection):
        raise DeviceProviderError("selection must be a DeviceProviderSelection")
    matches = tuple(
        entry_point
        for entry_point in _entry_points(entry_points)
        if getattr(entry_point, "name", None) == selection.provider_id
    )
    if not matches:
        raise DeviceProviderError(
            f"selected device provider {selection.provider_id!r} was not discovered "
            f"in entry-point group {DEVICE_PROVIDER_ENTRY_POINT!r}"
        )
    if len(matches) != 1:
        raise DeviceProviderError(
            f"selected device provider {selection.provider_id!r} has multiple entry points"
        )
    entry_point = matches[0]
    entry_point_value = getattr(entry_point, "value", None)
    distribution = getattr(entry_point, "dist", None)
    distribution_name = getattr(distribution, "name", None)
    distribution_version = getattr(distribution, "version", None)
    try:
        if not isinstance(entry_point_value, str):
            raise ValueError("entry-point value is unavailable")
        if not isinstance(distribution_name, str):
            raise ValueError("entry-point distribution name is unavailable")
        if not isinstance(distribution_version, str):
            raise ValueError("entry-point distribution version is unavailable")
        source = DeviceProviderSource(
            entry_point_group=DEVICE_PROVIDER_ENTRY_POINT,
            entry_point_name=selection.provider_id,
            entry_point_value=entry_point_value,
            distribution_name=distribution_name,
            distribution_version=distribution_version,
        )
    except ValueError as exc:
        raise DeviceProviderError(
            f"selected device provider {selection.provider_id!r} has invalid "
            "entry-point provenance"
        ) from exc
    try:
        payload = entry_point.load()
    except Exception as exc:
        raise DeviceProviderError(
            f"selected device provider {selection.provider_id!r} entry-point load failed"
        ) from exc
    if isinstance(payload, type) or not isinstance(payload, DeviceProvider):
        if not callable(payload):
            raise DeviceProviderError(
                f"selected entry point {selection.provider_id!r} does not implement "
                "Device Provider API 1 or a zero-argument provider factory"
            )
        try:
            payload = payload()
        except Exception as exc:
            raise DeviceProviderError(
                f"selected device provider {selection.provider_id!r} factory stage failed"
            ) from exc
    if not isinstance(payload, DeviceProvider):
        raise DeviceProviderError(
            f"selected entry point {selection.provider_id!r} does not implement "
            "Device Provider API 1"
        )
    return payload, source
