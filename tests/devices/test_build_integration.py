"""Bounded selected-provider integration tests for generate/build."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest

import rextio.build.orchestrator as orchestrator
from rextio.analyzer.project_scanner import analyze_project
from rextio.artifacts.models import (
    ArtifactKind,
    CertificationTier,
    DeviceRequirement,
    TargetCapability,
)
from rextio.artifacts.profiles import host_extension_profile
from rextio.build.artifact_layout import ArtifactLayout
from rextio.build.supply_chain import (
    EvidenceInputSnapshot,
    capture_generated_rust_inputs,
)
from rextio.devices import (
    DEVICE_PROVIDER_ENTRY_POINT,
    DeviceBuildContribution,
    DevicePreflightRequest,
    DevicePreflightResult,
    DeviceProviderError,
    DeviceProviderManifest,
    DeviceProviderOptions,
    DeviceProviderSelection,
)


@dataclass
class _Dist:
    name: str = "rextio-device-test"
    version: str = "0.1.0"


class _EntryPoint:
    group = DEVICE_PROVIDER_ENTRY_POINT
    name = "test-device"
    value = "rextio_device_test:provider"
    dist = _Dist()

    def __init__(self, provider: object) -> None:
        self.provider = provider
        self.load_count = 0

    def load(self) -> object:
        self.load_count += 1
        return self.provider


class _Provider:
    def __init__(
        self,
        target_triple: str,
        *,
        contribution: DeviceBuildContribution | None = None,
        fail_preflight: bool = False,
    ) -> None:
        self.target_triple = target_triple
        self.contribution = contribution or DeviceBuildContribution(
            native_libraries=("rxtnative",)
        )
        self.fail_preflight = fail_preflight

    def manifest(self) -> DeviceProviderManifest:
        return DeviceProviderManifest(
            provider_id="test-device",
            display_name="Test device integration",
            provider_version="0.1.0",
            backend=None,
            capabilities=(
                TargetCapability(
                    id="host-link",
                    target_triples=(self.target_triple,),
                    artifact_kinds=(ArtifactKind.HOST_EXTENSION,),
                    certification_tier=CertificationTier.BUILD_ONLY,
                    evidence_references=("tests/provider-build-only.json",),
                ),
            ),
        )

    def preflight(self, request: DevicePreflightRequest) -> DevicePreflightResult:
        if self.fail_preflight:
            raise RuntimeError("/private/provider-option")
        assert request.options.get("toolkit_root") == "/private/provider-option"
        return DevicePreflightResult(
            provider_id="test-device",
            status="ready",
            observations=(("probe", "synthetic-build-only"),),
        )

    def build_contribution(
        self,
        request: DevicePreflightRequest,
    ) -> DeviceBuildContribution:
        del request
        return self.contribution


def _analysis(project: Path):
    (project / "app.py").write_text(
        "def add(left: int, right: int) -> int:\n    return left + right\n",
        encoding="utf-8",
    )
    return analyze_project(project)


def _selection() -> DeviceProviderSelection:
    return DeviceProviderSelection("test-device", "host-link")


def _options() -> DeviceProviderOptions:
    return DeviceProviderOptions((("toolkit_root", "/private/provider-option"),))


def test_generate_materializes_native_link_lock_report_and_evidence(
    tmp_path: Path,
) -> None:
    analysis = _analysis(tmp_path)
    target_triple = orchestrator._required_host_target_triple()
    entry_point = _EntryPoint(_Provider(target_triple))

    result = orchestrator.generate_source_artifact(
        tmp_path,
        analysis,
        "cpython",
        device_selection=_selection(),
        device_options=_options(),
        device_entry_points=(entry_point,),
    )

    layout = ArtifactLayout(tmp_path)
    build_rs = (layout.rust_dir / "build.rs").read_text(encoding="utf-8")
    lock_text = (layout.rust_dir / "device-provider.lock.json").read_text(
        encoding="utf-8"
    )
    lock = json.loads(lock_text)
    report = result.to_dict()
    assert entry_point.load_count == 1
    assert 'cargo:rustc-link-lib=dylib=rxtnative' in build_rs
    assert "[features]" not in (layout.rust_dir / "Cargo.toml").read_text(
        encoding="utf-8"
    )
    assert lock["device_provider"]["source"] == {
        "entry_point_group": DEVICE_PROVIDER_ENTRY_POINT,
        "entry_point_name": "test-device",
        "entry_point_value": "rextio_device_test:provider",
        "distribution_name": "rextio-device-test",
        "distribution_version": "0.1.0",
    }
    assert report["device_provider_plans"][0]["lock"] == lock["device_provider"]["lock"]
    serialized = json.dumps(report, sort_keys=True) + lock_text
    assert "/private/provider-option" not in serialized
    assert report["device_provider_plans"][0]["options"]["option_keys"] == [
        "toolkit_root"
    ]

    snapshot = capture_generated_rust_inputs(
        EvidenceInputSnapshot((), (), ()),
        project_root=tmp_path,
        layout=layout,
    )
    assert snapshot.unavailable_reason is None
    by_name = {Path(item.logical_path).name: item for item in snapshot.generated_rust}
    assert by_name["build.rs"].role == "generated-rust-input"
    assert by_name["device-provider.lock.json"].role == "device-provider-lock"


@pytest.mark.parametrize("command", ["generate", "build"])
def test_provider_preflight_fails_before_generated_output_mutation(
    tmp_path: Path,
    command: str,
) -> None:
    analysis = _analysis(tmp_path)
    layout = ArtifactLayout(tmp_path)
    stale = layout.rust_dir / "stale.txt"
    stale.parent.mkdir(parents=True)
    stale.write_text("keep", encoding="utf-8")
    target_triple = orchestrator._required_host_target_triple()
    entry_point = _EntryPoint(_Provider(target_triple, fail_preflight=True))

    with pytest.raises(DeviceProviderError) as raised:
        if command == "generate":
            orchestrator.generate_source_artifact(
                tmp_path,
                analysis,
                "cpython",
                device_selection=_selection(),
                device_options=_options(),
                device_entry_points=(entry_point,),
            )
        else:
            orchestrator.build_hybrid_artifact(
                tmp_path,
                analysis,
                "cpython",
                device_selection=_selection(),
                device_options=_options(),
                device_entry_points=(entry_point,),
            )

    assert "preflight stage failed" in str(raised.value)
    assert "/private/provider-option" not in str(raised.value)
    assert stale.read_text(encoding="utf-8") == "keep"


@pytest.mark.parametrize(
    "contribution",
    [
        DeviceBuildContribution(cargo_features=("cuda-runtime",)),
        DeviceBuildContribution(package_references=("packages/cuda.json",)),
        DeviceBuildContribution(generated_helper_ids=("cuda-helper",)),
        DeviceBuildContribution(runtime_check_ids=("cuda-runtime-check",)),
    ],
)
def test_unmaterializable_contributions_fail_before_generated_output_writes(
    tmp_path: Path,
    contribution: DeviceBuildContribution,
) -> None:
    analysis = _analysis(tmp_path)
    layout = ArtifactLayout(tmp_path)
    stale = layout.rust_dir / "stale.txt"
    stale.parent.mkdir(parents=True)
    stale.write_text("keep", encoding="utf-8")
    target_triple = orchestrator._required_host_target_triple()
    entry_point = _EntryPoint(
        _Provider(target_triple, contribution=contribution)
    )

    with pytest.raises(DeviceProviderError, match="cannot be represented"):
        orchestrator.generate_source_artifact(
            tmp_path,
            analysis,
            "cpython",
            device_selection=_selection(),
            device_options=_options(),
            device_entry_points=(entry_point,),
        )

    assert stale.read_text(encoding="utf-8") == "keep"


def test_no_selection_preserves_legacy_report_and_generated_file_shape(
    tmp_path: Path,
) -> None:
    analysis = _analysis(tmp_path)
    layout = ArtifactLayout(tmp_path)
    layout.rust_dir.mkdir(parents=True)
    (layout.rust_dir / "build.rs").write_text("stale", encoding="utf-8")
    (layout.rust_dir / "device-provider.lock.json").write_text(
        "stale",
        encoding="utf-8",
    )

    result = orchestrator.generate_source_artifact(tmp_path, analysis, "cpython")

    assert "device_provider_plans" not in result.to_dict()
    assert not (layout.rust_dir / "build.rs").exists()
    assert not (layout.rust_dir / "device-provider.lock.json").exists()


def test_no_selection_checks_every_profile_for_accelerator_requirements() -> None:
    target_triple = orchestrator._required_host_target_triple()
    profiles = (
        host_extension_profile(target_triple),
        host_extension_profile(
            target_triple,
            packaging_backend="secondary-wheel",
            device_requirements=(
                DeviceRequirement(logical_device="cuda:0", backend="cuda"),
            ),
        ),
    )

    with pytest.raises(
        DeviceProviderError,
        match="requires an explicit device provider selection",
    ):
        orchestrator._resolve_build_device_plans(
            profiles,
            selection=None,
            options=DeviceProviderOptions(),
            # No-selection validation must not discover/import this object.
            entry_points=(object(),),
        )
