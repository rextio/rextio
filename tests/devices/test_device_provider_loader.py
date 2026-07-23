"""Selected-only device-provider entry-point loader tests."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from rextio.artifacts.models import (
    ArtifactKind,
    CertificationTier,
    TargetCapability,
)
from rextio.devices import (
    DEVICE_PROVIDER_ENTRY_POINT,
    DeviceBuildContribution,
    DevicePreflightRequest,
    DevicePreflightResult,
    DeviceProviderError,
    DeviceProviderManifest,
    DeviceProviderSelection,
    load_selected_device_provider,
)


class _Provider:
    def manifest(self) -> DeviceProviderManifest:
        return DeviceProviderManifest(
            provider_id="example-device",
            display_name="Example",
            provider_version="1.0.0",
            backend="cuda",
            capabilities=(
                TargetCapability(
                    id="cuda-linux",
                    target_triples=("x86_64-unknown-linux-gnu",),
                    artifact_kinds=(ArtifactKind.HOST_EXTENSION,),
                    accelerator_backends=("cuda",),
                    certification_tier=CertificationTier.BUILD_ONLY,
                    evidence_references=("tests/device-evidence.json",),
                ),
            ),
        )

    def preflight(self, request: DevicePreflightRequest) -> DevicePreflightResult:
        del request
        return DevicePreflightResult(provider_id="example-device", status="ready")

    def build_contribution(
        self, request: DevicePreflightRequest
    ) -> DeviceBuildContribution:
        del request
        return DeviceBuildContribution()


@dataclass
class _Dist:
    name: str = "rextio-device-example"
    version: str = "1.0.0"


class _EntryPoint:
    def __init__(
        self,
        name: str,
        payload: object,
        *,
        group: str = DEVICE_PROVIDER_ENTRY_POINT,
    ) -> None:
        self.name = name
        self.group = group
        self.value = "rextio_device_example:provider"
        self.dist = _Dist()
        self._payload = payload
        self.load_count = 0

    def load(self) -> object:
        self.load_count += 1
        if isinstance(self._payload, BaseException):
            raise self._payload
        return self._payload


def _selection() -> DeviceProviderSelection:
    return DeviceProviderSelection("example-device", "cuda-linux")


def test_loader_imports_only_the_explicitly_selected_entry_point() -> None:
    selected = _EntryPoint("example-device", _Provider())
    ignored = _EntryPoint("ignored-device", AssertionError("must not load"))

    provider, source = load_selected_device_provider(
        _selection(),
        entry_points=(ignored, selected),
    )

    assert isinstance(provider, _Provider)
    assert selected.load_count == 1
    assert ignored.load_count == 0
    assert source.to_dict() == {
        "entry_point_group": DEVICE_PROVIDER_ENTRY_POINT,
        "entry_point_name": "example-device",
        "entry_point_value": "rextio_device_example:provider",
        "distribution_name": "rextio-device-example",
        "distribution_version": "1.0.0",
    }


def test_duplicate_selected_entry_points_fail_before_import() -> None:
    first = _EntryPoint("example-device", _Provider())
    second = _EntryPoint("example-device", _Provider())

    with pytest.raises(DeviceProviderError, match="multiple entry points"):
        load_selected_device_provider(
            _selection(),
            entry_points=(first, second),
        )

    assert first.load_count == second.load_count == 0


def test_foreign_group_and_unselected_failures_are_not_loaded() -> None:
    foreign = _EntryPoint(
        "example-device",
        AssertionError("must not load"),
        group="rextio.plugins",
    )
    with pytest.raises(DeviceProviderError, match="was not discovered"):
        load_selected_device_provider(_selection(), entry_points=(foreign,))
    assert foreign.load_count == 0


@pytest.mark.parametrize("payload", [_Provider, lambda: _Provider()])
def test_provider_class_and_zero_argument_factory_are_instantiated(
    payload: object,
) -> None:
    entry_point = _EntryPoint("example-device", payload)

    provider, _source = load_selected_device_provider(
        _selection(),
        entry_points=(entry_point,),
    )

    assert isinstance(provider, _Provider)
    assert entry_point.load_count == 1


def test_loader_errors_do_not_echo_provider_exception_text() -> None:
    secret = "/private/toolkit/locator"
    entry_point = _EntryPoint("example-device", RuntimeError(secret))

    with pytest.raises(DeviceProviderError) as raised:
        load_selected_device_provider(_selection(), entry_points=(entry_point,))

    assert "entry-point load failed" in str(raised.value)
    assert secret not in str(raised.value)
    assert isinstance(raised.value.__cause__, RuntimeError)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("value", "/private/provider.py"),
        ("dist", None),
        ("dist", _Dist(name="../private-provider")),
        ("dist", _Dist(version="..\\private-version")),
    ],
)
def test_loader_requires_stable_non_filesystem_entry_point_provenance(
    field: str,
    value: object,
) -> None:
    entry_point = _EntryPoint("example-device", _Provider())
    setattr(entry_point, field, value)

    with pytest.raises(DeviceProviderError, match="invalid entry-point provenance"):
        load_selected_device_provider(_selection(), entry_points=(entry_point,))

    assert entry_point.load_count == 0
