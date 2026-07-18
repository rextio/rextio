"""Experimental device-provider contracts.

This package is deliberately separate from :mod:`rextio.plugins`.  The draft
surface describes hardware/runtime preflight only; core does not discover,
select, or invoke providers during builds yet.
"""

from rextio.devices.api import (
    DEVICE_PROVIDER_API_VERSION,
    DevicePreflightRequest,
    DevicePreflightResult,
    DevicePreflightStatus,
    DeviceProvider,
    DeviceProviderManifest,
)

__all__ = [
    "DEVICE_PROVIDER_API_VERSION",
    "DevicePreflightRequest",
    "DevicePreflightResult",
    "DevicePreflightStatus",
    "DeviceProvider",
    "DeviceProviderManifest",
]
