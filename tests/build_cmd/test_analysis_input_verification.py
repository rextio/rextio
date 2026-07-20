"""Focused C6.13 analysis-input verification tests."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from rextio.analyzer.project_scanner import analyze_project
import rextio.analyzer.stub_inputs as stub_inputs
from rextio.analyzer.stub_inputs import StubInputLimits, StubInputRecord
from rextio.artifacts.evidence import (
    MAX_EVIDENCE_FILE_BYTES,
    MAX_INPUT_FILES,
    AnalysisInputVerification,
    AnalysisInputRecord,
    EvidenceFileRef,
    SourceTransformationVerification,
    canonical_json_bytes,
)
from rextio.artifacts.evidence import _reconstruct_analysis_input_verification
import rextio.build.analysis_input_verification as analysis_input_verification
from rextio.build.analysis_input_verification import collect_scoped_analysis_input_verification
from rextio.partition.build_plan import create_build_plan


def _receipt(tmp_path: Path, *, present: bool = True, stub_text: str | None = None):
    source = tmp_path / "pkg" / "module.py"
    source.parent.mkdir(exist_ok=True)
    source.write_text("value = 1\n", encoding="utf-8")
    stub = source.with_suffix(".pyi")
    if present:
        stub.write_text(
            stub_text or "def score(value: int) -> int: ...\n",
            encoding="utf-8",
        )
    analysis = analyze_project(tmp_path)
    plan = create_build_plan(analysis, "cpython")
    source_ref = EvidenceFileRef(
        logical_path="pkg/module.py",
        sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        size=source.stat().st_size,
        role="project-python-source",
    )
    generated = EvidenceFileRef("generated/src/lib.rs", "a" * 64, 1, "generated-rust-input")
    verification = SourceTransformationVerification(
        source_transformation_inventory_sha256="b" * 64,
        source_input_set_sha256=hashlib.sha256(
            canonical_json_bytes([source_ref.to_dict()])
        ).hexdigest(),
        module_ir_sha256="c" * 64,
        function_qualnames=("pkg.module.score",),
        source_inputs=(source_ref,),
        generated_rust=generated,
        regenerated_rust_sha256=generated.sha256,
        regenerated_rust_size=generated.size,
        generator_backend="rextio-core-rust-pyo3-v1",
    )
    return plan, verification


def test_collects_present_and_absent_inputs_and_binds_c610(tmp_path: Path) -> None:
    plan, verification = _receipt(tmp_path)
    evidence = collect_scoped_analysis_input_verification(
        project_root=tmp_path, plan=plan, source_transformation_verification=verification
    )
    assert isinstance(evidence, AnalysisInputVerification)
    assert evidence.records[0].state == "present"
    assert evidence.records[0].stub is not None
    assert evidence.records[0].stub.role == "project-python-stub"
    assert evidence.records[0].stub.logical_path == "pkg/module.pyi"
    expected = hashlib.sha256(canonical_json_bytes(verification.to_dict())).hexdigest()
    assert evidence.source_transformation_verification_sha256 == expected
    assert evidence.source_input_set_sha256 == verification.source_input_set_sha256
    assert evidence.source_paths == ("pkg/module.py",)

    (tmp_path / "pkg" / "module.pyi").unlink()
    absent_plan, absent_verification = _receipt(tmp_path, present=False)
    absent = collect_scoped_analysis_input_verification(
        project_root=tmp_path,
        plan=absent_plan,
        source_transformation_verification=absent_verification,
    )
    assert absent is not None
    assert absent.records[0].state == "absent"
    assert absent.records[0].stub is None


def test_compatibility_absent_stub_is_not_c613_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(stub_inputs, "_secure_api_available", lambda: False)
    plan, verification = _receipt(tmp_path, present=False)

    assert plan.analysis._stub_inputs.records[0].state.value == "absent-unverified"
    assert collect_scoped_analysis_input_verification(
        project_root=tmp_path,
        plan=plan,
        source_transformation_verification=verification,
    ) is None


@pytest.mark.parametrize("mutation", ["present-to-absent", "absent-to-present", "bytes", "projection"])
def test_snapshot_mutations_return_none(tmp_path: Path, mutation: str) -> None:
    plan, verification = _receipt(tmp_path, present=mutation != "absent-to-present")
    if mutation == "present-to-absent":
        (tmp_path / "pkg" / "module.pyi").unlink()
    elif mutation == "absent-to-present":
        (tmp_path / "pkg" / "module.pyi").write_text(
            "def changed(value: str) -> str: ...\n", encoding="utf-8"
        )
    elif mutation == "bytes":
        (tmp_path / "pkg" / "module.pyi").write_text(
            "def changed(value: str) -> str: ...\n", encoding="utf-8"
        )
    else:
        plan.analysis._stub_inputs = replace(
            plan.analysis._stub_inputs,
            records=(replace(plan.analysis._stub_inputs.records[0], projection_sha256="d" * 64),),
        )
    assert collect_scoped_analysis_input_verification(
        project_root=tmp_path, plan=plan, source_transformation_verification=verification
    ) is None


def test_unsafe_present_input_and_forged_records_fail_closed(tmp_path: Path) -> None:
    plan, verification = _receipt(tmp_path)
    stub = tmp_path / "pkg" / "module.pyi"
    target = tmp_path / "target.pyi"
    target.write_bytes(stub.read_bytes())
    stub.unlink()
    stub.symlink_to(target)
    assert collect_scoped_analysis_input_verification(
        project_root=tmp_path, plan=plan, source_transformation_verification=verification
    ) is None

    with pytest.raises(ValueError):
        AnalysisInputRecord("module.py", "module.pyi", "absent", stub=verification.generated_rust)


def test_model_ordering_and_serialization_have_no_raw_or_absolute_paths(tmp_path: Path) -> None:
    plan, verification = _receipt(tmp_path)
    evidence = collect_scoped_analysis_input_verification(
        project_root=tmp_path, plan=plan, source_transformation_verification=verification
    )
    assert evidence is not None
    rendered = json.dumps(evidence.to_dict(), sort_keys=True)
    assert str(tmp_path.resolve()) not in rendered
    assert "def score" not in rendered
    assert "bytes" not in rendered
    assert tuple(record.source_path for record in evidence.records) == ("pkg/module.py",)


def test_present_records_require_fixed_projection_and_safety_versions(tmp_path: Path) -> None:
    plan, verification = _receipt(tmp_path)
    evidence = collect_scoped_analysis_input_verification(
        project_root=tmp_path, plan=plan, source_transformation_verification=verification
    )
    assert evidence is not None
    with pytest.raises(ValueError):
        replace(evidence.records[0], supported_signature_projection_sha256=None)
    with pytest.raises((TypeError, ValueError)):
        replace(evidence.records[0], supported_signature_projection_version=True)
    with pytest.raises(ValueError):
        replace(evidence.records[0], supported_signature_projection_version=2)
    with pytest.raises((TypeError, ValueError)):
        replace(evidence, analysis_input_set_version=True)
    with pytest.raises((TypeError, ValueError)):
        replace(evidence, supported_signature_projection_set_version=True)
    with pytest.raises(ValueError):
        replace(evidence, supported_signature_projection_set_version=2)


def test_model_rejects_noncanonical_coverage_and_bounded_counts(tmp_path: Path) -> None:
    plan, verification = _receipt(tmp_path)
    evidence = collect_scoped_analysis_input_verification(
        project_root=tmp_path, plan=plan, source_transformation_verification=verification
    )
    assert evidence is not None
    with pytest.raises(ValueError):
        replace(evidence, source_paths=("z.py", "a.py"))
    with pytest.raises(ValueError):
        replace(evidence, source_paths=tuple(f"{index}.py" for index in range(MAX_INPUT_FILES + 1)))


def test_reconstruction_rejects_forged_oversized_tuples_before_copying() -> None:
    record = AnalysisInputRecord("module.py", "module.pyi", "absent")
    evidence = object.__new__(AnalysisInputVerification)
    object.__setattr__(evidence, "source_paths", ("module.py",) * (MAX_INPUT_FILES + 1))
    object.__setattr__(evidence, "records", (record,))
    with pytest.raises(ValueError, match="record count exceeds the bound"):
        _reconstruct_analysis_input_verification(evidence)


def test_valid_ascii_stub_over_quarter_limit_remains_c613_eligible(tmp_path: Path) -> None:
    stub_text = "def score(value: int) -> int: ...\n" + "#" * (300 * 1024)
    plan, verification = _receipt(tmp_path, stub_text=stub_text)

    evidence = collect_scoped_analysis_input_verification(
        project_root=tmp_path,
        plan=plan,
        source_transformation_verification=verification,
    )

    assert evidence is not None
    assert evidence.records[0].state == "present"


def test_low_level_nested_snapshot_mutation_and_c610_binding_fail_closed(tmp_path: Path) -> None:
    plan, verification = _receipt(tmp_path)
    snapshot = plan.analysis._stub_inputs
    assert snapshot is not None and snapshot.records[0].exact_bytes is not None
    object.__setattr__(snapshot.records[0], "exact_bytes", b"forged")
    assert collect_scoped_analysis_input_verification(
        project_root=tmp_path, plan=plan, source_transformation_verification=verification
    ) is None


@pytest.mark.parametrize("mutation", ["bytes", "text", "declared", "aggregate"])
def test_snapshot_content_bounds_reject_before_record_reconstruction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    plan, verification = _receipt(tmp_path)
    snapshot = plan.analysis._stub_inputs
    assert snapshot is not None
    record = snapshot.records[0]
    limits = StubInputLimits()
    if mutation == "bytes":
        object.__setattr__(record, "exact_bytes", b"x" * (limits.max_file_bytes + 1))
    elif mutation == "text":
        object.__setattr__(record, "text", "😀" * (limits.max_file_bytes // 4 + 1))
    elif mutation == "declared":
        object.__setattr__(record, "size", limits.max_file_bytes + 1)
    else:
        monkeypatch.setattr(
            analysis_input_verification,
            "StubInputLimits",
            lambda: StubInputLimits(max_total_bytes=(record.size or 1) - 1),
        )

    def unexpected_constructor_call(self: StubInputRecord) -> None:
        raise AssertionError("oversized snapshot content reached record reconstruction")

    monkeypatch.setattr(StubInputRecord, "__post_init__", unexpected_constructor_call)
    assert collect_scoped_analysis_input_verification(
        project_root=tmp_path,
        plan=plan,
        source_transformation_verification=verification,
    ) is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("state", "present-valid"),
        ("sha256", "not-a-digest"),
        ("size", True),
        ("text", "forged"),
    ],
)
def test_low_level_nested_stub_record_metadata_mutations_fail_closed(
    tmp_path: Path, field: str, value: object
) -> None:
    plan, verification = _receipt(tmp_path)
    record = plan.analysis._stub_inputs.records[0]
    object.__setattr__(record, field, value)
    assert collect_scoped_analysis_input_verification(
        project_root=tmp_path, plan=plan, source_transformation_verification=verification
    ) is None


@pytest.mark.parametrize(
    "field,value",
    [("size", True), ("sha256", b"x"), ("logical_path", Path("module.pyi")), ("role", b"project-python-stub")],
)
def test_analysis_input_record_rejects_mutated_nested_stub_reference(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    plan, verification = _receipt(tmp_path)
    evidence = collect_scoped_analysis_input_verification(
        project_root=tmp_path, plan=plan, source_transformation_verification=verification
    )
    assert evidence is not None and evidence.records[0].stub is not None
    object.__setattr__(evidence.records[0].stub, field, value)
    with pytest.raises((TypeError, ValueError)):
        AnalysisInputRecord(
            source_path=evidence.records[0].source_path,
            stub_path=evidence.records[0].stub_path,
            state="present",
            stub=evidence.records[0].stub,
            supported_signature_projection_version=1,
            supported_signature_projection_sha256="a" * 64,
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("sha256", "A" * 64),
        ("size", -1),
        ("size", MAX_EVIDENCE_FILE_BYTES + 1),
        ("logical_path", "../module.pyi"),
        ("role", " "),
        ("role", "wrong-role"),
    ],
)
def test_analysis_input_record_revalidates_mutated_nested_stub_semantics(
    tmp_path: Path, field: str, value: object
) -> None:
    plan, verification = _receipt(tmp_path)
    evidence = collect_scoped_analysis_input_verification(
        project_root=tmp_path, plan=plan, source_transformation_verification=verification
    )
    assert evidence is not None and evidence.records[0].stub is not None
    object.__setattr__(evidence.records[0].stub, field, value)
    with pytest.raises((TypeError, ValueError)):
        AnalysisInputRecord(
            source_path=evidence.records[0].source_path,
            stub_path=evidence.records[0].stub_path,
            state="present",
            stub=evidence.records[0].stub,
            supported_signature_projection_version=1,
            supported_signature_projection_sha256="a" * 64,
        )


def test_projection_algorithm_and_set_versions_are_checked_independently(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    plan, verification = _receipt(tmp_path)
    monkeypatch.setattr(analysis_input_verification, "STUB_SIGNATURE_PROJECTION_VERSION", 2)
    assert collect_scoped_analysis_input_verification(
        project_root=tmp_path, plan=plan, source_transformation_verification=verification
    ) is None

    plan, verification = _receipt(tmp_path)
    object.__setattr__(verification, "source_input_set_sha256", "d" * 64)
    assert collect_scoped_analysis_input_verification(
        project_root=tmp_path, plan=plan, source_transformation_verification=verification
    ) is None
