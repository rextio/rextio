"""Bounded C6.7 observation of reachable Cargo license metadata strings."""

from __future__ import annotations

from collections.abc import Sequence

from rextio.artifacts.evidence import (
    ComponentLicenseInventory,
    ComponentLicenseRecord,
    CargoPackageRef,
)


def collect_component_license_inventory(
    packages: Sequence[CargoPackageRef],
) -> ComponentLicenseInventory | None:
    """Return an exact observation-only inventory, or ``None`` if inadmissible.

    Cargo package collection remains owned by C6.2. C6.7 only copies the
    already bounded reachable package identity and raw metadata ``license``
    value. It deliberately performs no SPDX parsing, normalization, legal
    classification, license-file reading, or allow/deny decision.
    """
    try:
        if not all(type(package) is CargoPackageRef for package in packages):
            return None
        records = tuple(
            ComponentLicenseRecord(
                bom_ref=package.bom_ref(),
                name=package.name,
                version=package.version,
                kind=package.kind,
                license_observed=package.license,
                license_observation=(
                    "declared-unvalidated" if package.license is not None else "missing"
                ),
            )
            for package in sorted(packages, key=lambda package: package.bom_ref())
        )
        return ComponentLicenseInventory(records=records)
    except Exception:
        # C6.7 is additive observation metadata. Its inability to bind must not
        # change C6.2 evidence or the independent C6.3 required-evidence gate.
        return None


__all__ = ["collect_component_license_inventory"]
