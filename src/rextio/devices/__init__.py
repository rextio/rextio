"""Device Provider API 1 contracts.

This package is deliberately separate from :mod:`rextio.plugins`. Domain
plugins own Python semantics; explicitly selected device providers own
hardware/runtime compatibility and declarative build inputs.
"""

from rextio.devices.api import (
    DEVICE_PROVIDER_ENTRY_POINT,
    DEVICE_PROVIDER_API_VERSION,
    CanonicalDeviceId,
    DeviceBuildContribution,
    DevicePreflightRequest,
    DevicePreflightResult,
    DevicePreflightStatus,
    DeviceProvider,
    DeviceProviderError,
    DeviceProviderLock,
    DeviceProviderManifest,
    DeviceProviderOptions,
    DeviceProviderReport,
    DeviceProviderSelection,
    DeviceProviderSource,
    DeviceResourceAccess,
    DeviceResourceContract,
    DeviceResourceOwner,
    DeviceValueMetadata,
    ResolvedDevicePlan,
    normalize_device_id,
    resolve_device_plan,
)
from rextio.devices.loader import load_selected_device_provider

__all__ = [
    "DEVICE_PROVIDER_ENTRY_POINT",
    "DEVICE_PROVIDER_API_VERSION",
    "CanonicalDeviceId",
    "DeviceBuildContribution",
    "DevicePreflightRequest",
    "DevicePreflightResult",
    "DevicePreflightStatus",
    "DeviceProvider",
    "DeviceProviderError",
    "DeviceProviderLock",
    "DeviceProviderManifest",
    "DeviceProviderOptions",
    "DeviceProviderReport",
    "DeviceProviderSelection",
    "DeviceProviderSource",
    "DeviceResourceAccess",
    "DeviceResourceContract",
    "DeviceResourceOwner",
    "DeviceValueMetadata",
    "ResolvedDevicePlan",
    "normalize_device_id",
    "load_selected_device_provider",
    "resolve_device_plan",
]
