"""Focused C6.7 component-license observation model tests."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError, replace

import pytest

import rextio.artifacts.evidence as evidence_mod
from rextio.artifacts.evidence import (
    CargoPackageRef,
)
from rextio.build.license_inventory import collect_component_license_inventory


def _packages(*, root_license: str | None = None) -> tuple[CargoPackageRef, ...]:
    return (
        CargoPackageRef(
            name="rextio-generated-native",
            version="0.1.0",
            source=None,
            checksum=None,
            kind="path-root",
            license=root_license,
        ),
        CargoPackageRef(
            name="pyo3",
            version="0.23.5",
            source="registry+https://github.com/rust-lang/crates.io-index",
            checksum="7" * 64,
            kind="registry",
            license=" MIT OR Apache-2.0 ",
        ),
    )


def test_inventory_is_exact_canonical_immutable_and_json_roundtrips() -> None:
    packages = _packages()
    inventory = collect_component_license_inventory(packages)
    assert inventory is not None

    assert tuple(record.bom_ref for record in inventory.records) == tuple(
        sorted(package.bom_ref() for package in packages)
    )
    assert {record.kind for record in inventory.records} == {"path-root", "registry"}
    observed = next(record for record in inventory.records if record.name == "pyo3")
    assert observed.license_observed == " MIT OR Apache-2.0 "
    assert observed.license_observation == "declared-unvalidated"
    missing = next(record for record in inventory.records if record.kind == "path-root")
    assert missing.license_observed is None
    assert missing.license_observation == "missing"
    payload = inventory.to_dict()
    assert json.loads(json.dumps(payload, sort_keys=True)) == payload
    assert payload["record_count"] == len(packages)
    assert payload["complete"] is False
    with pytest.raises(FrozenInstanceError):
        inventory.complete = True  # type: ignore[misc]


@pytest.mark.parametrize(
    "license_value",
    ["UNKNOWN", "NOASSERTION", "MIT/Apache-2.0", "LicenseRef-Proprietary", " GPL-3.0-only "],
)
def test_nonblank_license_strings_remain_verbatim_and_unvalidated(
    license_value: str,
) -> None:
    package = _packages(root_license=license_value)[0]
    inventory = collect_component_license_inventory((package,))
    assert inventory is not None
    record = inventory.records[0]
    assert record.license_observed == license_value
    assert record.license_observation == "declared-unvalidated"


@pytest.mark.parametrize("license_value", ["", " ", "\t", "\n", "\u00a0"])
def test_blank_license_strings_are_missing(license_value: str) -> None:
    package = _packages(root_license=license_value)[0]
    assert package.license is None
    inventory = collect_component_license_inventory((package,))
    assert inventory is not None
    assert inventory.records[0].license_observed is None
    assert inventory.records[0].license_observation == "missing"


@pytest.mark.parametrize("license_value", ["MIT\x00hidden", "MIT\nApache-2.0", "MIT\t"])
def test_license_control_characters_are_rejected(license_value: str) -> None:
    with pytest.raises(ValueError, match="control characters"):
        _packages(root_license=license_value)


def test_record_and_inventory_reject_inconsistent_or_noncanonical_shapes(
) -> None:
    inventory = collect_component_license_inventory(_packages())
    assert inventory is not None
    declared = next(record for record in inventory.records if record.license_observed)

    with pytest.raises(ValueError, match="inconsistent"):
        replace(declared, license_observation="missing")
    with pytest.raises(ValueError, match="blank"):
        replace(declared, license_observed="  ")
    with pytest.raises(ValueError, match="canonical bom_ref order"):
        replace(inventory, records=tuple(reversed(inventory.records)))
    with pytest.raises(ValueError, match="unique"):
        replace(inventory, records=(inventory.records[0], inventory.records[0]))
    with pytest.raises(ValueError, match="path root"):
        replace(inventory, records=())


def test_per_string_count_and_serialized_size_bounds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inventory = collect_component_license_inventory(_packages())
    assert inventory is not None
    declared = next(record for record in inventory.records if record.license_observed)
    with pytest.raises(ValueError, match="character bound"):
        replace(
            declared,
            license_observed="x" * (evidence_mod.MAX_COMPONENT_LICENSE_OBSERVED_CHARS + 1),
        )

    monkeypatch.setattr(evidence_mod, "MAX_COMPONENT_LICENSE_RECORDS", 1)
    with pytest.raises(ValueError, match="record count"):
        replace(inventory)

    monkeypatch.setattr(evidence_mod, "MAX_COMPONENT_LICENSE_RECORDS", 512)
    monkeypatch.setattr(evidence_mod, "MAX_COMPONENT_LICENSE_INVENTORY_CHARS", 1)
    with pytest.raises(ValueError, match="character bound"):
        replace(inventory)
