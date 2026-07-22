"""Adversarial tests for the offline Full C6 owner-policy handoff."""

from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import runpy
import stat
from typing import Literal, cast

import pytest

from rextio.artifacts.evidence import canonical_json_bytes, sha256_hex
from rextio.build.full_c6_policy import (
    FullC6OwnerDeclaration,
    FullC6PolicyFileIdentity,
    full_c6_license_detector_payload_digest,
)
from rextio.build.full_c6_policy_completion import (
    FullC6OwnerLicenseDecision,
    FullC6OwnerPolicyCompletion,
    FullC6PolicyCompletionError,
    finalize_full_c6_policy_files,
    finalize_full_c6_policy_manifest,
    parse_full_c6_owner_policy_completion,
)
from rextio.build.full_c6_policy_bootstrap import FullC6PolicyBootstrapRequest
from rextio.build.full_c6_policy_manifest import parse_full_c6_policy_manifest
from rextio.build.full_c6_policy_template import (
    FullC6ExternalLicenseObservation,
    FullC6InternalLicenseObservation,
)


_BOOTSTRAP = runpy.run_path(
    str(Path(__file__).with_name("test_full_c6_policy_bootstrap.py"))
)


def _bootstrap(tmp_path: Path):
    return _BOOTSTRAP["_request"](tmp_path)


def _completion(
    bootstrap: FullC6PolicyBootstrapRequest,
) -> FullC6OwnerPolicyCompletion:
    template = bootstrap.technical_template
    decisions: list[FullC6OwnerLicenseDecision] = []
    for row in template.rows:
        if row.required_license_disposition != "owner-approved-allow":
            continue
        observation: (
            FullC6ExternalLicenseObservation | FullC6InternalLicenseObservation
        )
        if row.license_evidence_origin == "production-external-observation":
            observation = template.external_license_observation
        else:
            observation = next(
                item
                for item in template.internal_license_observations
                if item.observation_sha256 == row.license_observation_sha256
            )
        decisions.append(
            FullC6OwnerLicenseDecision(
                authority_identity=row.authority_identity,
                declared_spdx="MIT",
                detected_spdx=observation.detected_spdx,
                source_detector_receipt_sha256=(
                    observation.source_detector_receipt_sha256
                ),
                detector_payload_sha256=observation.detector_payload_sha256,
                license_files=observation.license_files,
                evidence_origin=cast(
                    Literal[
                        "owner-project-observation",
                        "production-external-observation",
                    ],
                    row.license_evidence_origin,
                ),
            )
        )
    return FullC6OwnerPolicyCompletion(
        bootstrap_request_sha256=bootstrap.request_sha256,
        transformation_set_sha256=template.transformation_set_sha256,
        owner_declaration=FullC6OwnerDeclaration(
            owner_identity=template.observed_owner_identity,
            owner_role="organization-owner",
            trusted_public_key_sha256=(
                bootstrap.trusted_owner_public_key_sha256
            ),
        ),
        license_decisions=tuple(
            sorted(decisions, key=lambda item: item.authority_identity)
        ),
    )


def _write_input(path: Path, payload: bytes) -> None:
    path.write_bytes(payload)
    path.chmod(0o600)


def test_completion_round_trip_finalizes_exact_non_authorizing_manifest(
    tmp_path: Path,
) -> None:
    bootstrap = _bootstrap(tmp_path)
    completion = _completion(bootstrap)

    parsed = parse_full_c6_owner_policy_completion(completion.to_bytes())
    manifest = finalize_full_c6_policy_manifest(
        bootstrap=bootstrap,
        completion=parsed,
    )
    receipt = parse_full_c6_policy_manifest(
        manifest,
        expected_sha256=sha256_hex(manifest),
    )

    assert parsed == completion
    assert receipt.bootstrap_request_sha256 == bootstrap.request_sha256
    assert receipt.artifact_coverage == bootstrap.technical_template.artifact_coverage
    assert receipt.external_authority == bootstrap.technical_template.external_authority
    assert receipt.transformations == bootstrap.technical_template.transformations
    assert receipt.distribution_authorized is False
    assert all(
        row.license_evidence is not None
        for row in receipt.rows
        if row.license_disposition == "owner-approved-allow"
    )


def test_completion_rejects_wrong_bootstrap_and_transformation_set(
    tmp_path: Path,
) -> None:
    bootstrap = _bootstrap(tmp_path)
    completion = _completion(bootstrap)

    with pytest.raises(FullC6PolicyCompletionError, match="another bootstrap"):
        finalize_full_c6_policy_manifest(
            bootstrap=bootstrap,
            completion=replace(completion, bootstrap_request_sha256="8" * 64),
        )
    with pytest.raises(FullC6PolicyCompletionError, match="another transformation"):
        finalize_full_c6_policy_manifest(
            bootstrap=bootstrap,
            completion=replace(completion, transformation_set_sha256="8" * 64),
        )


def test_completion_requires_every_explicit_unique_allow_decision(
    tmp_path: Path,
) -> None:
    bootstrap = _bootstrap(tmp_path)
    completion = _completion(bootstrap)

    with pytest.raises(FullC6PolicyCompletionError, match="every license-applicable"):
        finalize_full_c6_policy_manifest(
            bootstrap=bootstrap,
            completion=replace(
                completion,
                license_decisions=completion.license_decisions[:-1],
            ),
        )
    with pytest.raises(FullC6PolicyCompletionError, match="duplicated"):
        replace(
            completion,
            license_decisions=(
                completion.license_decisions[0],
                completion.license_decisions[0],
            ),
        )

    document = completion.to_dict()
    decisions = document["license_decisions"]
    assert isinstance(decisions, list)
    assert isinstance(decisions[0], dict)
    decisions[0].pop("decision")
    with pytest.raises(FullC6PolicyCompletionError, match="schema is invalid"):
        parse_full_c6_owner_policy_completion(canonical_json_bytes(document))

    document = completion.to_dict()
    decisions = document["license_decisions"]
    assert isinstance(decisions, list)
    assert isinstance(decisions[0], dict)
    decisions[0]["decision"] = "deny"
    with pytest.raises(FullC6PolicyCompletionError, match="explicit allow"):
        parse_full_c6_owner_policy_completion(canonical_json_bytes(document))


@pytest.mark.parametrize("field", ["owner_identity", "trusted_public_key_sha256"])
def test_completion_requires_observed_owner_and_bootstrap_key(
    tmp_path: Path,
    field: str,
) -> None:
    bootstrap = _bootstrap(tmp_path)
    completion = _completion(bootstrap)
    owner = completion.owner_declaration
    replacement = FullC6OwnerDeclaration(
        owner_identity=(
            "Another Owner" if field == "owner_identity" else owner.owner_identity
        ),
        owner_role=owner.owner_role,
        trusted_public_key_sha256=(
            "8" * 64
            if field == "trusted_public_key_sha256"
            else owner.trusted_public_key_sha256
        ),
    )

    with pytest.raises(FullC6PolicyCompletionError, match="owner identity|owner key"):
        finalize_full_c6_policy_manifest(
            bootstrap=bootstrap,
            completion=replace(completion, owner_declaration=replacement),
        )


def test_completion_rejects_external_observation_changes_and_origin_confusion(
    tmp_path: Path,
) -> None:
    bootstrap = _bootstrap(tmp_path)
    completion = _completion(bootstrap)
    decisions = list(completion.license_decisions)
    external_index = next(
        index
        for index, item in enumerate(decisions)
        if item.evidence_origin == "production-external-observation"
    )
    external = decisions[external_index]
    decisions[external_index] = replace(external, declared_spdx="Apache-2.0")
    with pytest.raises(FullC6PolicyCompletionError, match="independent wheel"):
        finalize_full_c6_policy_manifest(
            bootstrap=bootstrap,
            completion=replace(completion, license_decisions=tuple(decisions)),
        )

    decisions = list(completion.license_decisions)
    external = decisions[external_index]
    changed_detected = "Apache-2.0"
    decisions[external_index] = replace(
        external,
        detected_spdx=changed_detected,
        detector_payload_sha256=full_c6_license_detector_payload_digest(
            changed_detected,
            external.license_files,
            source_detector_receipt_sha256=(
                external.source_detector_receipt_sha256
            ),
        ),
    )
    with pytest.raises(FullC6PolicyCompletionError, match="independent wheel"):
        finalize_full_c6_policy_manifest(
            bootstrap=bootstrap,
            completion=replace(completion, license_decisions=tuple(decisions)),
        )

    decisions = list(completion.license_decisions)
    project_index = next(
        index
        for index, item in enumerate(decisions)
        if item.evidence_origin == "owner-project-observation"
    )
    project = decisions[project_index]
    decisions[project_index] = replace(project, declared_spdx="Apache-2.0")
    with pytest.raises(
        FullC6PolicyCompletionError,
        match="production license-material observation",
    ):
        finalize_full_c6_policy_manifest(
            bootstrap=bootstrap,
            completion=replace(completion, license_decisions=tuple(decisions)),
        )

    decisions = list(completion.license_decisions)
    project = decisions[project_index]
    fabricated = (
        FullC6PolicyFileIdentity(
            logical_path="licenses/FABRICATED-LICENSE",
            sha256="9" * 64,
            size=101,
            role="license-file",
        ),
    )
    decisions[project_index] = replace(
        project,
        license_files=fabricated,
        detector_payload_sha256=full_c6_license_detector_payload_digest(
            project.detected_spdx,
            fabricated,
            source_detector_receipt_sha256=(
                project.source_detector_receipt_sha256
            ),
        ),
    )
    with pytest.raises(
        FullC6PolicyCompletionError,
        match="production license-material observation",
    ):
        finalize_full_c6_policy_manifest(
            bootstrap=bootstrap,
            completion=replace(completion, license_decisions=tuple(decisions)),
        )

    decisions = list(completion.license_decisions)
    project_index = next(
        index
        for index, item in enumerate(decisions)
        if item.evidence_origin == "owner-project-observation"
    )
    decisions[project_index] = replace(
        decisions[project_index],
        evidence_origin="production-external-observation",
    )
    with pytest.raises(FullC6PolicyCompletionError, match="explicit license decision"):
        finalize_full_c6_policy_manifest(
            bootstrap=bootstrap,
            completion=replace(completion, license_decisions=tuple(decisions)),
        )


def test_completion_parser_rejects_json_scalar_type_aliases(tmp_path: Path) -> None:
    bootstrap = _bootstrap(tmp_path)
    completion = _completion(bootstrap)
    document = completion.to_dict()
    document["schema_version"] = True
    with pytest.raises(FullC6PolicyCompletionError, match="invalid authority"):
        parse_full_c6_owner_policy_completion(canonical_json_bytes(document))

    document = completion.to_dict()
    document["private_key_present"] = 0
    with pytest.raises(FullC6PolicyCompletionError, match="invalid authority"):
        parse_full_c6_owner_policy_completion(canonical_json_bytes(document))


def test_finalize_files_creates_once_and_exactly_reuses(tmp_path: Path) -> None:
    bootstrap = _bootstrap(tmp_path)
    completion = _completion(bootstrap)
    inputs = tmp_path / "policy-inputs"
    output = tmp_path / "policy-output"
    inputs.mkdir(mode=0o700)
    output.mkdir(mode=0o700)
    bootstrap_path = inputs / "bootstrap.json"
    completion_path = inputs / "completion.json"
    output_path = output / "manifest.json"
    _write_input(bootstrap_path, bootstrap.to_bytes())
    _write_input(completion_path, completion.to_bytes())

    created = finalize_full_c6_policy_files(
        bootstrap_path=bootstrap_path,
        completion_path=completion_path,
        output_path=output_path,
    )
    reused = finalize_full_c6_policy_files(
        bootstrap_path=bootstrap_path,
        completion_path=completion_path,
        output_path=output_path,
    )

    observed = output_path.stat()
    assert created.created is True
    assert reused.created is False
    assert created.manifest_sha256 == reused.manifest_sha256
    assert created.size == output_path.stat().st_size
    assert stat.S_IMODE(observed.st_mode) == 0o600
    assert observed.st_nlink == 1


def test_finalize_files_rejects_changed_symlink_and_hardlink_outputs(
    tmp_path: Path,
) -> None:
    bootstrap = _bootstrap(tmp_path)
    completion = _completion(bootstrap)
    inputs = tmp_path / "inputs"
    inputs.mkdir(mode=0o700)
    bootstrap_path = inputs / "bootstrap.json"
    completion_path = inputs / "completion.json"
    _write_input(bootstrap_path, bootstrap.to_bytes())
    _write_input(completion_path, completion.to_bytes())

    changed_dir = tmp_path / "changed"
    changed_dir.mkdir(mode=0o700)
    changed = changed_dir / "manifest.json"
    _write_input(changed, canonical_json_bytes({"different": True}))
    with pytest.raises(FullC6PolicyCompletionError, match="bytes differ"):
        finalize_full_c6_policy_files(
            bootstrap_path=bootstrap_path,
            completion_path=completion_path,
            output_path=changed,
        )

    symlink_dir = tmp_path / "symlink"
    symlink_dir.mkdir(mode=0o700)
    target = symlink_dir / "target.json"
    _write_input(target, canonical_json_bytes({"target": True}))
    symlink = symlink_dir / "manifest.json"
    symlink.symlink_to(target)
    with pytest.raises(FullC6PolicyCompletionError, match="output transaction"):
        finalize_full_c6_policy_files(
            bootstrap_path=bootstrap_path,
            completion_path=completion_path,
            output_path=symlink,
        )

    hardlink_dir = tmp_path / "hardlink"
    hardlink_dir.mkdir(mode=0o700)
    original = hardlink_dir / "original.json"
    _write_input(
        original,
        finalize_full_c6_policy_manifest(
            bootstrap=bootstrap,
            completion=completion,
        ),
    )
    hardlink = hardlink_dir / "manifest.json"
    os.link(original, hardlink)
    with pytest.raises(FullC6PolicyCompletionError, match="output transaction"):
        finalize_full_c6_policy_files(
            bootstrap_path=bootstrap_path,
            completion_path=completion_path,
            output_path=hardlink,
        )


def test_finalize_files_rejects_aliased_or_noncanonical_paths(tmp_path: Path) -> None:
    bootstrap = _bootstrap(tmp_path)
    completion = _completion(bootstrap)
    inputs = tmp_path / "inputs"
    real_output = tmp_path / "real-output"
    inputs.mkdir(mode=0o700)
    real_output.mkdir(mode=0o700)
    bootstrap_path = inputs / "bootstrap.json"
    completion_path = inputs / "completion.json"
    _write_input(bootstrap_path, bootstrap.to_bytes())
    _write_input(completion_path, completion.to_bytes())

    alias = tmp_path / "output-alias"
    alias.symlink_to(real_output, target_is_directory=True)
    with pytest.raises(FullC6PolicyCompletionError, match="output transaction"):
        finalize_full_c6_policy_files(
            bootstrap_path=bootstrap_path,
            completion_path=completion_path,
            output_path=alias / "manifest.json",
        )

    noncanonical = real_output / ".." / real_output.name / "manifest.json"
    with pytest.raises(FullC6PolicyCompletionError, match="output path is invalid"):
        finalize_full_c6_policy_files(
            bootstrap_path=bootstrap_path,
            completion_path=completion_path,
            output_path=noncanonical,
        )
