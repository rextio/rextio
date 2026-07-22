from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat

import pytest

import rextio.build.full_c6_policy_bootstrap as bootstrap_module
from rextio.artifacts.evidence import (
    ARTIFACT_POLICY_COVERAGE_CLASS_IDS,
    artifact_policy_coverage_inventory_digest,
    canonical_json_bytes,
)
from rextio.build.full_c6_policy import (
    FULL_C6_EXTERNAL_POLICY_CLASS_IDS,
    full_c6_license_detector_payload_digest,
)
from rextio.build.full_c6_policy_bootstrap import (
    FULL_C6_POLICY_BOOTSTRAP_FILENAME,
    FullC6PolicyBootstrapError,
    FullC6PolicyBootstrapInputs,
    create_configured_full_c6_policy_bootstrap_request,
    materialize_configured_full_c6_policy_bootstrap,
    materialize_full_c6_policy_bootstrap_request,
    parse_full_c6_policy_bootstrap_request,
    resolve_full_c6_policy_lifecycle,
)
from rextio.build.full_c6_policy_template import (
    FullC6ExternalLicenseObservation,
    FullC6InternalLicenseObservation,
    FullC6PolicyTemplateError,
    FullC6TechnicalPolicyRow,
    FullC6TechnicalPolicyTemplate,
    parse_full_c6_technical_policy_template,
)
from rextio.config.loader import load_config


_SHA_A = "a" * 64
_SHA_B = "b" * 64
_SHA_C = "c" * 64
_SHA_D = "d" * 64
_SHA_E = "e" * 64
_SHA_F = "f" * 64
_SHA_1 = "1" * 64
_SHA_2 = "2" * 64
_SHA_3 = "3" * 64

_POLICY = runpy.run_path(str(Path(__file__).with_name("test_full_c6_policy.py")))


def _config_text(*, policy_sha256: bool, final_signature: bool = False) -> str:
    digest = (
        f'artifact_policy_manifest_sha256 = "{_SHA_B}"\n'
        if policy_sha256
        else ""
    )
    signature = (
        'artifact_final_signature = "signatures/final-authorization.sig.json"\n'
        if final_signature
        else ""
    )
    return f"""
[build]
artifact_evidence_policy = "required"
artifact_distribution_policy = "strict-evidence"
artifact_source_lock_manifest = "locks/source-lock.v2.json"
artifact_source_lock_signature = "locks/source-lock.v2.sig.json"
artifact_policy_manifest = "locks/rextio.full-c6-policy.json"
{digest}artifact_cargo_vendor = "vendor/cargo"
artifact_cargo_vendor_sha256 = "{_SHA_A}"
artifact_cargo_lock = "locks/Cargo.lock"
artifact_cargo_lock_sha256 = "{_SHA_B}"
artifact_toolchain_support_lock = "locks/toolchain-support.lock.json"
artifact_toolchain_support_lock_sha256 = "{_SHA_C}"
artifact_trusted_public_key = "keys/release.pub"
artifact_trusted_public_key_sha256 = "{_SHA_A}"
artifact_signing_request_output = "state/rextio.full-c6-final-authorization-request.json"
{signature}artifact_repeat_builds = 2

[imports]
default_external_policy = "fallback"

[imports.packages.demo_math]
policy = "try-native"
max_depth = 1
distribution = "demo-math"
version = "1.2.3"
source_archive = "vendor/demo_math-1.2.3-py3-none-any.whl"
source_archive_sha256 = "{_SHA_B}"
""".strip() + "\n"


def _config(
    tmp_path: Path,
    *,
    policy_sha256: bool,
    final_signature: bool = False,
):
    (tmp_path / "rextio.toml").write_text(
        _config_text(
            policy_sha256=policy_sha256,
            final_signature=final_signature,
        ),
        encoding="utf-8",
    )
    return load_config(tmp_path)


def _inputs(**replacements: object) -> FullC6PolicyBootstrapInputs:
    values: dict[str, object] = {
        "analysis_ir_transaction_sha256": _SHA_A,
        "artifact_coverage_inventory_sha256": _SHA_B,
        "artifact_authority_partition_sha256": _SHA_C,
        "build_input_closure_sha256": _SHA_D,
        "cargo_workspace_sha256": _SHA_E,
        "combined_authority_partition_sha256": _SHA_F,
        "external_authority_partition_sha256": _SHA_1,
        "license_materials_transaction_sha256": _SHA_2,
        "source_lock_verification_sha256": _SHA_3,
        "artifact_class_observed_counts": (1,) * len(
            ARTIFACT_POLICY_COVERAGE_CLASS_IDS
        ),
        "external_class_observed_counts": (1,) * len(
            FULL_C6_EXTERNAL_POLICY_CLASS_IDS
        ),
        "artifact_observed_component_count": len(
            ARTIFACT_POLICY_COVERAGE_CLASS_IDS
        ),
        "external_observed_component_count": len(
            FULL_C6_EXTERNAL_POLICY_CLASS_IDS
        ),
        "required_transformation_count": 3,
        "target_triple": "aarch64-apple-darwin",
        "build_profile": "release",
    }
    values.update(replacements)
    return FullC6PolicyBootstrapInputs(**values)  # type: ignore[arg-type]


def _request(tmp_path: Path):
    template = _technical_template()
    return create_configured_full_c6_policy_bootstrap_request(
        config=_config(tmp_path, policy_sha256=False),
        inputs=_coherent_inputs(template),
        technical_template=template,
    )


def _technical_template() -> FullC6TechnicalPolicyTemplate:
    receipt = _POLICY["_receipt"]()
    external_file = _POLICY["_file"](
        "external/pkg-1.0.dist-info/licenses/LICENSE"
    )
    external_receipt = "c" * 64
    external_observation = FullC6ExternalLicenseObservation(
        declared_spdx="MIT",
        detected_spdx="MIT",
        source_detector_receipt_sha256=external_receipt,
        detector_payload_sha256=full_c6_license_detector_payload_digest(
            "MIT",
            (external_file,),
            source_detector_receipt_sha256=external_receipt,
        ),
        license_files=(external_file,),
    )
    project_file = _POLICY["_file"]("licenses/PROJECT-LICENSE")
    project_receipt = "7" * 64
    project_observation = FullC6InternalLicenseObservation(
        subject_kind="project",
        subject_canonical_identity="project:demo@0.1.0",
        declared_spdx="MIT",
        detected_spdx="MIT",
        source_detector_receipt_sha256=project_receipt,
        detector_payload_sha256=full_c6_license_detector_payload_digest(
            "MIT",
            (project_file,),
            source_detector_receipt_sha256=project_receipt,
        ),
        license_files=(project_file,),
    )
    cargo_identity = next(
        row.canonical_identity
        for row in receipt.rows
        if row.class_id == "cargo-component:registry-package"
    )
    cargo_file = _POLICY["_file"]("licenses/CARGO-LICENSE")
    cargo_receipt = "8" * 64
    cargo_observation = FullC6InternalLicenseObservation(
        subject_kind="cargo-registry-package",
        subject_canonical_identity=cargo_identity,
        declared_spdx="MIT",
        detected_spdx="MIT",
        source_detector_receipt_sha256=cargo_receipt,
        detector_payload_sha256=full_c6_license_detector_payload_digest(
            "MIT",
            (cargo_file,),
            source_detector_receipt_sha256=cargo_receipt,
        ),
        license_files=(cargo_file,),
    )
    internal_observations = tuple(
        sorted(
            (project_observation, cargo_observation),
            key=lambda item: (
                item.subject_kind,
                item.subject_canonical_identity.casefold(),
                item.observation_sha256,
            ),
        )
    )
    rows = tuple(
        FullC6TechnicalPolicyRow(
            class_id=row.class_id,
            canonical_identity=row.canonical_identity,
            authority_identity=row.authority_identity,
            identity_mode=row.identity_mode,
            sha256=row.sha256,
            size=row.size,
            required_license_disposition=row.license_disposition,
            transformation_disposition=row.transformation_disposition,
            license_evidence_origin=(
                "not-applicable"
                if row.license_disposition != "owner-approved-allow"
                else (
                    "production-external-observation"
                    if row.class_id in FULL_C6_EXTERNAL_POLICY_CLASS_IDS
                    else "owner-project-observation"
                )
            ),
            license_observation_sha256=(
                None
                if row.license_disposition != "owner-approved-allow"
                else (
                    external_observation.observation_sha256
                    if row.class_id in FULL_C6_EXTERNAL_POLICY_CLASS_IDS
                    else (
                        cargo_observation.observation_sha256
                        if row.class_id == "cargo-component:registry-package"
                        else project_observation.observation_sha256
                    )
                )
            ),
        )
        for row in receipt.rows
    )
    return FullC6TechnicalPolicyTemplate(
        artifact_coverage=receipt.artifact_coverage,
        external_authority=receipt.external_authority,
        rows=rows,
        transformations=receipt.transformations,
        internal_license_observations=internal_observations,
        external_license_observation=external_observation,
        observed_owner_identity=receipt.owner_declaration.owner_identity,
    )


def _coherent_inputs(
    template: FullC6TechnicalPolicyTemplate,
) -> FullC6PolicyBootstrapInputs:
    return _inputs(
        artifact_coverage_inventory_sha256=(
            artifact_policy_coverage_inventory_digest(template.artifact_coverage)
        ),
        artifact_authority_partition_sha256=(
            template.artifact_coverage.canonical_partition_sha256
        ),
        combined_authority_partition_sha256=template.authority_partition_sha256,
        external_authority_partition_sha256=(
            template.external_authority.canonical_partition_sha256
        ),
        artifact_class_observed_counts=tuple(
            item.observed_count for item in template.artifact_coverage.classes
        ),
        external_class_observed_counts=tuple(
            item.observed_count for item in template.external_authority.classes
        ),
        artifact_observed_component_count=(
            template.artifact_coverage.observed_component_count
        ),
        external_observed_component_count=(
            template.external_authority.observed_component_count
        ),
        required_transformation_count=len(template.transformations),
    )


def _private_state(tmp_path: Path) -> Path:
    state = tmp_path / "state"
    state.mkdir(mode=0o700, parents=True)
    state.chmod(0o700)
    return state


def test_policy_lifecycle_distinguishes_bootstrap_signing_and_publication(
    tmp_path: Path,
) -> None:
    bootstrap = resolve_full_c6_policy_lifecycle(
        _config(tmp_path, policy_sha256=False)
    )
    assert bootstrap.status == "bootstrap-required"
    assert bootstrap.bootstrap_allowed is True
    assert bootstrap.signing_request_allowed is False
    assert bootstrap.publication_attempt_allowed is False
    assert bootstrap.published is False

    signing = resolve_full_c6_policy_lifecycle(
        _config(tmp_path, policy_sha256=True)
    )
    assert signing.status == "signing-required"
    assert signing.owner_policy_pinned is True
    assert signing.signing_request_allowed is True
    assert signing.publication_attempt_allowed is False
    assert signing.published is False

    publication = resolve_full_c6_policy_lifecycle(
        _config(tmp_path, policy_sha256=True, final_signature=True)
    )
    assert publication.status == "publication-required"
    assert publication.publication_attempt_allowed is True
    assert publication.published is False


def test_policy_lifecycle_is_disabled_for_ordinary_config(tmp_path: Path) -> None:
    lifecycle = resolve_full_c6_policy_lifecycle(load_config(tmp_path))

    assert lifecycle.status == "disabled"
    assert lifecycle.bootstrap_allowed is False
    assert lifecycle.owner_policy_pinned is False
    assert lifecycle.signing_request_allowed is False
    assert lifecycle.publication_attempt_allowed is False
    assert lifecycle.published is False


def test_bootstrap_request_is_deterministic_exact_and_non_authorizing(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)
    repeated = _request(tmp_path)
    document = request.to_dict()
    payload = request.to_bytes()

    assert repeated.to_bytes() == payload
    assert payload == canonical_json_bytes(document)
    assert request.request_sha256 == hashlib.sha256(
        canonical_json_bytes(
            {key: value for key, value in document.items() if key != "request_sha256"}
        )
    ).hexdigest()
    assert document["authority"] == "non-authorizing-observation"
    assert document["distribution_authorized"] is False
    assert document["owner_completion_required"] is True
    assert document["trusted_owner_public_key_sha256"] == _SHA_A
    assert document["technical_template"] == request.technical_template.to_dict()
    assert document["technical_template_sha256"] == (
        request.technical_template.template_sha256
    )
    assert document["target"] == {
        "build_profile": "release",
        "target_triple": "aarch64-apple-darwin",
    }
    completion = document["completion_requirements"]
    assert isinstance(completion, dict)
    assert completion["policy_rows"] == {
        "closed_license_disposition_required": True,
        "closed_transformation_disposition_required": True,
        "exact_authority_partition_required": True,
        "required_count": len(ARTIFACT_POLICY_COVERAGE_CLASS_IDS)
        + len(FULL_C6_EXTERNAL_POLICY_CLASS_IDS),
    }
    external = completion["external_authority"]
    assert isinstance(external, dict)
    assert external["classes"] == [
        {"class_id": class_id, "observed_count": 1}
        for class_id in FULL_C6_EXTERNAL_POLICY_CLASS_IDS
    ]
    text = payload.decode("ascii")
    assert str(tmp_path) not in text
    assert "locks/rextio.full-c6-policy.json" not in text
    assert "source bytes" not in text
    assert "private" not in text
    assert "signature" not in text
    assert "absolute" not in text


@pytest.mark.parametrize(
    ("replacement", "match"),
    [
        ({"analysis_ir_transaction_sha256": "BAD"}, "lowercase SHA-256"),
        ({"artifact_observed_component_count": -1}, "bounded profile"),
        ({"external_observed_component_count": -1}, "bounded profile"),
        ({"required_transformation_count": 0}, "bounded profile"),
        ({"artifact_class_observed_counts": (9,)}, "not exact"),
        ({"external_class_observed_counts": (0, 0, 0, 0)}, "not exact"),
        ({"target_triple": "x86_64-pc-windows-msvc"}, "unsupported"),
        ({"build_profile": "debug"}, "release build profile"),
    ],
)
def test_bootstrap_inputs_fail_closed(
    replacement: dict[str, object],
    match: str,
) -> None:
    with pytest.raises(FullC6PolicyBootstrapError, match=match):
        _inputs(**replacement)


def test_bootstrap_factory_refuses_a_pinned_owner_policy(tmp_path: Path) -> None:
    template = _technical_template()
    with pytest.raises(FullC6PolicyBootstrapError, match="not required"):
        create_configured_full_c6_policy_bootstrap_request(
            config=_config(tmp_path, policy_sha256=True),
            inputs=_coherent_inputs(template),
            technical_template=template,
        )


def test_materialization_creates_exact_private_file_and_reuses_exact_bytes(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)
    state = _private_state(tmp_path)

    created = materialize_full_c6_policy_bootstrap_request(
        state_directory=state,
        request=request,
    )
    path = state / FULL_C6_POLICY_BOOTSTRAP_FILENAME
    observed = path.stat()
    assert created.created is True
    assert created.request_sha256 == request.request_sha256
    assert created.size == len(request.to_bytes())
    assert created.distribution_authorized is False
    assert path.read_bytes() == request.to_bytes()
    assert stat.S_IMODE(observed.st_mode) == 0o600
    assert observed.st_uid == os.getuid()
    assert observed.st_nlink == 1

    reused = materialize_full_c6_policy_bootstrap_request(
        state_directory=state,
        request=request,
    )
    assert reused.created is False
    assert reused.request_sha256 == created.request_sha256
    assert path.read_bytes() == request.to_bytes()


def test_configured_materialization_uses_only_bootstrap_lifecycle(
    tmp_path: Path,
) -> None:
    state = _private_state(tmp_path)
    template = _technical_template()

    result = materialize_configured_full_c6_policy_bootstrap(
        state_directory=state,
        config=_config(tmp_path, policy_sha256=False),
        inputs=_coherent_inputs(template),
        technical_template=template,
    )

    assert result.created is True
    assert result.status == "bootstrap-required"
    assert result.to_dict()["filename"] == FULL_C6_POLICY_BOOTSTRAP_FILENAME


def test_materialization_rejects_different_existing_bytes(tmp_path: Path) -> None:
    request = _request(tmp_path)
    state = _private_state(tmp_path)
    path = state / FULL_C6_POLICY_BOOTSTRAP_FILENAME
    path.write_bytes(b"different")
    path.chmod(0o600)

    with pytest.raises(FullC6PolicyBootstrapError, match="bytes differ"):
        materialize_full_c6_policy_bootstrap_request(
            state_directory=state,
            request=request,
        )


def test_materialization_rejects_unsafe_existing_mode(tmp_path: Path) -> None:
    request = _request(tmp_path)
    state = _private_state(tmp_path)
    path = state / FULL_C6_POLICY_BOOTSTRAP_FILENAME
    path.write_bytes(request.to_bytes())
    path.chmod(0o644)

    with pytest.raises(FullC6PolicyBootstrapError, match="mode 0600"):
        materialize_full_c6_policy_bootstrap_request(
            state_directory=state,
            request=request,
        )


def test_materialization_rejects_symlink_and_hardlink_aliases(tmp_path: Path) -> None:
    request = _request(tmp_path)

    symlink_state = _private_state(tmp_path / "symlink-case")
    target = symlink_state / "target"
    target.write_bytes(request.to_bytes())
    target.chmod(0o600)
    (symlink_state / FULL_C6_POLICY_BOOTSTRAP_FILENAME).symlink_to(target)
    with pytest.raises(FullC6PolicyBootstrapError, match="unsafe"):
        materialize_full_c6_policy_bootstrap_request(
            state_directory=symlink_state,
            request=request,
        )

    hardlink_state = _private_state(tmp_path / "hardlink-case")
    original = hardlink_state / "original"
    original.write_bytes(request.to_bytes())
    original.chmod(0o600)
    os.link(original, hardlink_state / FULL_C6_POLICY_BOOTSTRAP_FILENAME)
    with pytest.raises(FullC6PolicyBootstrapError, match="single-link"):
        materialize_full_c6_policy_bootstrap_request(
            state_directory=hardlink_state,
            request=request,
        )


def test_materialization_rejects_unsafe_or_aliased_state_directory(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)
    unsafe = tmp_path / "unsafe-state"
    unsafe.mkdir(mode=0o755)
    unsafe.chmod(0o755)
    with pytest.raises(FullC6PolicyBootstrapError, match="0700"):
        materialize_full_c6_policy_bootstrap_request(
            state_directory=unsafe,
            request=request,
        )

    real = _private_state(tmp_path / "real-case")
    alias = tmp_path / "state-alias"
    alias.symlink_to(real, target_is_directory=True)
    with pytest.raises(FullC6PolicyBootstrapError, match="symlink-free"):
        materialize_full_c6_policy_bootstrap_request(
            state_directory=alias,
            request=request,
        )


def test_materialization_requires_absolute_lexical_nfc_state_path(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)
    state = _private_state(tmp_path)
    invalid = (
        "state",
        f"{state.parent}/./{state.name}",
        f"{state.parent}/{state.name}/../{state.name}",
        f"{state.parent}//{state.name}",
        f"{state}/",
        str(tmp_path / "state-e\u0301"),
    )

    for candidate in invalid:
        with pytest.raises(
            FullC6PolicyBootstrapError,
            match="absolute|lexically canonical|NFC-normalized",
        ):
            materialize_full_c6_policy_bootstrap_request(
                state_directory=candidate,
                request=request,
            )


def test_materialization_rejects_a_symlink_in_any_state_path_ancestor(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir(mode=0o700)
    state = _private_state(real_parent)
    alias_parent = tmp_path / "alias-parent"
    alias_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(FullC6PolicyBootstrapError, match="symlink-free"):
        materialize_full_c6_policy_bootstrap_request(
            state_directory=alias_parent / state.name,
            request=request,
        )


@pytest.mark.parametrize(
    "alias_name",
    (
        FULL_C6_POLICY_BOOTSTRAP_FILENAME.upper(),
        FULL_C6_POLICY_BOOTSTRAP_FILENAME.replace("s", "ſ", 1),
    ),
)
def test_materialization_rejects_casefold_or_nfc_filename_alias(
    tmp_path: Path,
    alias_name: str,
) -> None:
    request = _request(tmp_path)
    state = _private_state(tmp_path)
    alias = state / alias_name
    alias.write_bytes(request.to_bytes())
    alias.chmod(0o600)

    with pytest.raises(FullC6PolicyBootstrapError, match="casefold/NFC alias"):
        materialize_full_c6_policy_bootstrap_request(
            state_directory=state,
            request=request,
        )


def test_materialization_detects_same_byte_inode_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _request(tmp_path)
    state = _private_state(tmp_path)
    path = state / FULL_C6_POLICY_BOOTSTRAP_FILENAME
    original_reader = bootstrap_module._read_private_file
    replaced = False

    def replace_before_reopen(root_fd: int):
        nonlocal replaced
        if not replaced:
            replaced = True
            payload = path.read_bytes()
            path.unlink()
            path.write_bytes(payload)
            path.chmod(0o600)
        return original_reader(root_fd)

    monkeypatch.setattr(
        bootstrap_module,
        "_read_private_file",
        replace_before_reopen,
    )

    with pytest.raises(FullC6PolicyBootstrapError, match="final bytes changed"):
        materialize_full_c6_policy_bootstrap_request(
            state_directory=state,
            request=request,
        )


def test_request_input_aggregate_set_digest_is_exact(tmp_path: Path) -> None:
    document = _request(tmp_path).to_dict()
    aggregates = document["input_aggregates"]

    assert document["input_aggregate_set_sha256"] == hashlib.sha256(
        canonical_json_bytes(
            {
                "domain": "rextio.full-c6-policy-bootstrap-input-set.v1",
                "input_aggregates": aggregates,
            }
        )
    ).hexdigest()
    assert isinstance(aggregates, dict)
    assert len(aggregates) == 9
    assert all(
        isinstance(value, str) and len(value) == 64
        for value in aggregates.values()
    )


def test_request_bytes_are_canonical_json_without_duplicate_keys(tmp_path: Path) -> None:
    payload = _request(tmp_path).to_bytes()
    parsed = json.loads(payload)

    assert canonical_json_bytes(parsed) == payload


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", 2.0),
        ("owner_completion_required", 1),
        ("distribution_authorized", 0),
    ],
)
def test_bootstrap_parser_rejects_json_scalar_type_aliases(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    document = _request(tmp_path).to_dict()
    document[field] = value

    with pytest.raises(FullC6PolicyBootstrapError, match="invalid authority"):
        parse_full_c6_policy_bootstrap_request(canonical_json_bytes(document))


def test_template_parser_rejects_boolean_schema_alias(tmp_path: Path) -> None:
    document = _request(tmp_path).technical_template.to_dict()
    document["schema_version"] = True

    with pytest.raises(FullC6PolicyTemplateError, match="invalid authority"):
        parse_full_c6_technical_policy_template(document)


def test_bootstrap_rejects_semantically_different_coverage_digest(
    tmp_path: Path,
) -> None:
    template = _technical_template()
    inputs = replace(
        _coherent_inputs(template),
        artifact_coverage_inventory_sha256="0" * 64,
    )

    with pytest.raises(FullC6PolicyBootstrapError, match="differs from bootstrap"):
        create_configured_full_c6_policy_bootstrap_request(
            config=_config(tmp_path, policy_sha256=False),
            inputs=inputs,
            technical_template=template,
        )
