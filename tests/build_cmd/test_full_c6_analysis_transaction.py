"""Focused generated-path bindings for the Full C6 analysis transaction."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import runpy

from rextio.build.full_c6_analysis_transaction import (
    create_full_c6_analysis_ir_transaction,
)
from rextio.build.full_c6_input_identity import (
    canonical_full_c6_build_input_name,
)
from rextio.build.input_closure import BuildInputClosure
from rextio.build.transformation_verification import (
    SourceTransformationReplayAuthority,
    _replay_authority_payload,
    _replay_authority_seal,
)
from rextio.source.source_lock_v2 import SourceLockV2Verification


_GATE = runpy.run_path(
    str(Path(__file__).with_name("test_full_c6_gate.py"))
)


def _captured_generated_replay(policy: object) -> SourceTransformationReplayAuthority:
    replay = _GATE["_project_replay_authority"](policy)
    verification = replace(
        replay.verification,
        generated_rust=replace(
            replay.verification.generated_rust,
            logical_path=f".rextio/{replay.verification.generated_rust.logical_path}",
        ),
    )
    generated_python = tuple(
        replace(item, logical_path=f".rextio/{item.logical_path}")
        for item in replay.generated_python
    )
    generated_cargo_toml = replace(
        replay.generated_cargo_toml,
        logical_path=f".rextio/{replay.generated_cargo_toml.logical_path}",
    )
    payload = _replay_authority_payload(
        verification=verification,
        generated_python=generated_python,
        generated_cargo_toml=generated_cargo_toml,
    )
    return SourceTransformationReplayAuthority(
        verification=verification,
        generated_python=generated_python,
        generated_cargo_toml=generated_cargo_toml,
        _authority_seal=_replay_authority_seal(payload),
    )


def test_analysis_transaction_binds_captured_generated_paths_to_policy_names(
    tmp_path: Path,
) -> None:
    arguments = _GATE["_fixture"](tmp_path)
    build_inputs = arguments["build_inputs"]
    verification = arguments["source_verification"]
    assert isinstance(build_inputs, BuildInputClosure)
    assert isinstance(verification, SourceLockV2Verification)

    transaction = create_full_c6_analysis_ir_transaction(
        project_replay_authority=_captured_generated_replay(arguments["policy"]),
        source_verification=verification,
        build_inputs=build_inputs,
    )

    assert transaction.build_input_closure_sha256 == build_inputs.digest


def test_generated_path_mapping_is_exactly_role_and_prefix_scoped() -> None:
    captured = ".rextio/generated/python/wrapper.py"
    assert canonical_full_c6_build_input_name(
        captured,
        "generated-python-input",
    ) == "generated/python/wrapper.py"
    assert canonical_full_c6_build_input_name(
        ".rextio/generated/rust/src/lib.rs",
        "generated-rust-input",
    ) == "generated/rust/src/lib.rs"
    assert (
        canonical_full_c6_build_input_name(captured, "project-python-source")
        == captured
    )
    outside = ".rextio/cache/generated/python/wrapper.py"
    assert (
        canonical_full_c6_build_input_name(outside, "generated-python-input")
        == outside
    )
