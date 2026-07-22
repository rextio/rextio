"""Focused contracts for the path-safe resolved Full C6 config identity."""

from __future__ import annotations

from dataclasses import replace
import math
from pathlib import Path
import runpy

import pytest

from rextio.build.full_c6_config_identity import (
    FULL_C6_EFFECTIVE_CONFIG_AGGREGATE_ID,
    FullC6ConfigIdentityError,
    MAX_FULL_C6_EFFECTIVE_CONFIG_CONTAINER_ITEMS,
    MAX_FULL_C6_EFFECTIVE_CONFIG_STRING_BYTES,
    capture_effective_full_c6_config_identity,
)
from rextio.build.full_c6_policy_bootstrap import (
    create_full_c6_policy_bootstrap_request,
)
from rextio.build.input_closure import (
    BuildInputClosure,
    ExactFileIdentity,
    bind_build_input_aggregate,
)
from rextio.config.schema import (
    BuildConfig,
    ImportPackagePolicy,
    ImportsConfig,
    RextioConfig,
    TargetConfig,
    ToolchainConfig,
)


_BOOTSTRAP = runpy.run_path(str(Path(__file__).with_name("test_full_c6_policy_bootstrap.py")))


def _config() -> RextioConfig:
    return RextioConfig(
        build=BuildConfig(
            fallback_threshold=17,
            build_timeout_seconds=23.5,
            artifact_evidence_policy="required",
            artifact_distribution_policy="full-c6-required",
            artifact_source_lock_manifest="locks/source.json",
            artifact_source_lock_signature="locks/source.sig",
            artifact_policy_manifest="locks/policy.json",
            artifact_policy_manifest_sha256="1" * 64,
            artifact_cargo_vendor="vendor",
            artifact_cargo_vendor_sha256="2" * 64,
            artifact_cargo_lock="Cargo.lock",
            artifact_cargo_lock_sha256="3" * 64,
            artifact_toolchain_support_lock="locks/toolchain-support.json",
            artifact_toolchain_support_lock_sha256="6" * 64,
            artifact_trusted_public_key="keys/owner.pub",
            artifact_trusted_public_key_sha256="4" * 64,
            artifact_signing_request_output="state/request.json",
        ),
        target=TargetConfig(
            version="stable",
            build_options={"lto": "thin", "profile": "release"},
        ),
        imports=ImportsConfig(
            packages={
                "demo_pkg": ImportPackagePolicy(
                    policy="try-native",
                    max_depth=1,
                    distribution="demo-pkg",
                    version="1.0.0",
                    source_archive="vendor/demo_pkg.whl",
                    source_archive_sha256="5" * 64,
                )
            }
        ),
        toolchain=ToolchainConfig(
            cargo="tools/cargo",
            python="tools/python",
            rust_toolchain="1.93.1",
            cargo_version="==1.93.1",
            python_version="==3.11.15",
        ),
    )


def _closure(config: RextioConfig) -> BuildInputClosure:
    base = BuildInputClosure(
        files=(
            ExactFileIdentity(
                logical_name="project/app.py",
                role="project-python-source",
                sha256="a" * 64,
                size=1,
                executable=False,
            ),
        )
    )
    return bind_build_input_aggregate(
        base,
        capture_effective_full_c6_config_identity(config).to_build_input_aggregate(),
    )


def _request_digest(config: RextioConfig) -> str:
    template = _BOOTSTRAP["_technical_template"]()
    inputs = _BOOTSTRAP["_coherent_inputs"](template)
    inputs = replace(
        inputs,
        build_input_closure_sha256=_closure(config).digest,
    )
    return create_full_c6_policy_bootstrap_request(
        inputs=inputs,
        trusted_owner_public_key_sha256="4" * 64,
        technical_template=template,
    ).request_sha256


def test_equivalent_typed_configs_have_one_canonical_private_identity() -> None:
    first = _config()
    second = replace(
        first,
        target=replace(
            first.target,
            build_options={"profile": "release", "lto": "thin"},
        ),
        imports=replace(
            first.imports,
            packages=dict(reversed(tuple(first.imports.packages.items()))),
        ),
    )

    first_identity = capture_effective_full_c6_config_identity(first)
    second_identity = capture_effective_full_c6_config_identity(second)

    assert first_identity == second_identity
    assert tuple(first_identity.to_dict()) == ("domain", "digest", "member_count")
    assert "tools/cargo" not in repr(first_identity.to_dict())
    assert "keys/owner.pub" not in repr(first_identity.to_dict())
    assert _closure(first).digest == _closure(second).digest
    assert _request_digest(first) == _request_digest(second)


@pytest.mark.parametrize(
    "change",
    (
        lambda value: replace(
            value,
            build=replace(value.build, fallback_threshold=18),
        ),
        lambda value: replace(
            value,
            build=replace(value.build, build_timeout_seconds=24.0),
        ),
        lambda value: replace(
            value,
            build=replace(value.build, artifact_policy_manifest="locks/other.json"),
        ),
        lambda value: replace(
            value,
            policy=replace(value.policy, native_marker="decorator"),
        ),
        lambda value: replace(
            value,
            policy=replace(value.policy, boundary_warnings=False),
        ),
        lambda value: replace(
            value,
            target=replace(
                value.target,
                build_options={**value.target.build_options, "codegen-units": "1"},
            ),
        ),
        lambda value: replace(
            value,
            imports=replace(
                value.imports,
                packages={
                    "demo_pkg": replace(
                        value.imports.packages["demo_pkg"],
                        version="1.0.1",
                    )
                },
            ),
        ),
        lambda value: replace(
            value,
            toolchain=replace(value.toolchain, cargo_version="==1.94.0"),
        ),
        lambda value: replace(
            value,
            build=replace(
                value.build,
                artifact_toolchain_support_lock_sha256="7" * 64,
            ),
        ),
    ),
    ids=(
        "fallback-threshold",
        "timeout",
        "policy-manifest-path",
        "native-marker",
        "boundary-warnings",
        "target-build-options",
        "import-package-pin",
        "toolchain-pin",
        "toolchain-support-lock",
    ),
)
def test_every_resolved_semantic_change_rebinds_closure_and_request(change) -> None:
    original = _config()
    changed = change(original)

    assert capture_effective_full_c6_config_identity(
        changed
    ) != capture_effective_full_c6_config_identity(original)
    assert _closure(changed).digest != _closure(original).digest
    assert _request_digest(changed) != _request_digest(original)


def test_three_stage_lifecycle_uses_only_two_separately_bound_markers() -> None:
    signing = _config()
    bootstrap = replace(
        signing,
        build=replace(
            signing.build,
            artifact_policy_manifest_sha256=None,
        ),
    )
    publication = replace(
        signing,
        build=replace(
            signing.build,
            artifact_final_signature="state/final-signature.json",
        ),
    )

    identities = {
        capture_effective_full_c6_config_identity(config)
        for config in (bootstrap, signing, publication)
    }
    closures = {_closure(config).digest for config in (bootstrap, signing, publication)}
    requests = {
        _request_digest(config) for config in (bootstrap, signing, publication)
    }
    assert len(identities) == 1
    assert len(closures) == 1
    assert len(requests) == 1


def test_nonfinite_and_noncanonical_nested_values_fail_closed() -> None:
    nonfinite = replace(
        _config(),
        build=replace(_config().build, build_timeout_seconds=math.inf),
    )
    with pytest.raises(FullC6ConfigIdentityError, match="canonicalized"):
        capture_effective_full_c6_config_identity(nonfinite)

    invalid = _config()
    invalid.target.build_options["profile"] = 1  # type: ignore[assignment]
    with pytest.raises(FullC6ConfigIdentityError, match="build options"):
        capture_effective_full_c6_config_identity(invalid)


def test_oversized_mapping_and_string_fail_before_public_identity() -> None:
    oversized_mapping = _config()
    oversized_mapping.target.build_options.update(
        {
            f"option-{index}": "value"
            for index in range(MAX_FULL_C6_EFFECTIVE_CONFIG_CONTAINER_ITEMS + 1)
        }
    )
    with pytest.raises(FullC6ConfigIdentityError, match="canonicalized"):
        capture_effective_full_c6_config_identity(oversized_mapping)

    oversized_string = replace(
        _config(),
        build=replace(
            _config().build,
            artifact_signing_request_output=(
                "x" * (MAX_FULL_C6_EFFECTIVE_CONFIG_STRING_BYTES + 1)
            ),
        ),
    )
    with pytest.raises(FullC6ConfigIdentityError, match="canonicalized"):
        capture_effective_full_c6_config_identity(oversized_string)


@pytest.mark.parametrize("invalid_text", ("bad\npath", "cafe\N{COMBINING ACUTE ACCENT}"))
def test_control_and_non_nfc_config_text_fail_closed(invalid_text: str) -> None:
    config = replace(
        _config(),
        build=replace(_config().build, artifact_signing_request_output=invalid_text),
    )
    with pytest.raises(FullC6ConfigIdentityError, match="canonicalized"):
        capture_effective_full_c6_config_identity(config)


def test_config_aggregate_uses_one_generic_non_cargo_row() -> None:
    closure = _closure(_config())
    assert len(closure.aggregates) == 1
    assert closure.aggregates[0].aggregate_id == FULL_C6_EFFECTIVE_CONFIG_AGGREGATE_ID
    assert closure.aggregates[0].kind == "effective-config"
