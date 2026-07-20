"""Bounded C6.14 artifact-policy coverage derivation.

The collector is intentionally total for the optional evidence path: a missing
or malformed C6.9-C6.13 prerequisite returns ``None`` and cannot affect the
ordinary build or C6.3 required-evidence result.
"""

from __future__ import annotations

from collections.abc import Sequence

from rextio.artifacts.evidence import (
    AnalysisInputVerification,
    ArtifactPolicyCoverageInventory,
    CargoPackageRef,
    ComponentLicenseInventory,
    ComponentLicensePolicyVerification,
    EvidenceFileRef,
    NativeRuntimeInventory,
    NativeRuntimePathResolutionInventory,
    NativeRuntimeTransitiveClosureInventory,
    ProjectSourceLicensePolicyVerification,
    SourceTransformationInventory,
    SourceTransformationVerification,
    WheelEntryRef,
    derive_artifact_policy_coverage_inventory,
)


def collect_artifact_policy_coverage_inventory(
    *,
    target_triple: str,
    subject: EvidenceFileRef,
    inputs: Sequence[EvidenceFileRef],
    wheel_entries: Sequence[WheelEntryRef],
    cargo_packages: Sequence[CargoPackageRef],
    native_runtime_inventory: NativeRuntimeInventory | None,
    native_runtime_path_resolution: NativeRuntimePathResolutionInventory | None,
    native_runtime_transitive_closure: (NativeRuntimeTransitiveClosureInventory | None),
    source_transformation_inventory: SourceTransformationInventory | None,
    source_transformation_verification: SourceTransformationVerification | None,
    analysis_input_verification: AnalysisInputVerification | None,
    component_license_inventory: ComponentLicenseInventory | None,
    component_license_policy_verification: (ComponentLicensePolicyVerification | None),
    project_source_license_policy_verification: (ProjectSourceLicensePolicyVerification | None),
) -> ArtifactPolicyCoverageInventory | None:
    """Return the exact C6.14 inventory, or omit it on any unsafe gap."""
    if (
        native_runtime_inventory is None
        or native_runtime_path_resolution is None
        or native_runtime_transitive_closure is None
        or source_transformation_inventory is None
        or source_transformation_verification is None
        or analysis_input_verification is None
        or component_license_inventory is None
        or component_license_policy_verification is None
        or project_source_license_policy_verification is None
    ):
        return None
    try:
        return derive_artifact_policy_coverage_inventory(
            target_triple=target_triple,
            subject=subject,
            inputs=inputs,
            wheel_entries=wheel_entries,
            cargo_packages=cargo_packages,
            native_runtime_inventory=native_runtime_inventory,
            native_runtime_path_resolution=native_runtime_path_resolution,
            native_runtime_transitive_closure=native_runtime_transitive_closure,
            source_transformation_inventory=source_transformation_inventory,
            source_transformation_verification=source_transformation_verification,
            analysis_input_verification=analysis_input_verification,
            component_license_inventory=component_license_inventory,
            component_license_policy_verification=(component_license_policy_verification),
            project_source_license_policy_verification=(project_source_license_policy_verification),
        )
    except Exception:
        return None


__all__ = ["collect_artifact_policy_coverage_inventory"]
