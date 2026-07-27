"""Focused C6.13 artifact-evidence and provenance integration tests."""

from __future__ import annotations

from dataclasses import replace

import pytest

from rextio.artifacts.evidence import (
    AnalysisInputRecord,
    AnalysisInputVerification,
    ArtifactEvidence,
    EvidenceFileRef,
    NativeRuntimeInventory,
    SourceTransformationInventory,
    SourceTransformationRange,
    SourceTransformationRecord,
    SourceTransformationVerification,
    SidecarArtifact,
    WheelEntryRef,
    analysis_input_projections_digest,
    analysis_input_records_digest,
    build_intoto_provenance_document,
    canonical_json_bytes,
    sha256_hex,
)


def _fixture(*, stub_present: bool) -> dict[str, object]:
    source = EvidenceFileRef("pkg/mod.py", "1" * 64, 10, "project-python-source")
    generated = EvidenceFileRef(
        ".rextio/generated/rust/src/lib.rs", "2" * 64, 20, "generated-rust-input"
    )
    inventory = SourceTransformationInventory(
        records=(
            SourceTransformationRecord(
                source_path=source.logical_path,
                source_sha256=source.sha256,
                function_module="pkg.mod",
                function_qualname="pkg.mod.f",
                source_range=SourceTransformationRange(1, 0, 1, 10),
                semantic_ast_sha256="3" * 64,
                generated_rust=generated,
                generator_backend="rextio-core-rust-pyo3-v1",
            ),
        )
    )
    transformation = SourceTransformationVerification(
        source_transformation_inventory_sha256=sha256_hex(
            canonical_json_bytes(inventory.to_dict())
        ),
        source_input_set_sha256=sha256_hex(
            canonical_json_bytes([source.to_dict()])
        ),
        module_ir_sha256="4" * 64,
        function_qualnames=("pkg.mod.f",),
        source_inputs=(source,),
        generated_rust=generated,
        regenerated_rust_sha256=generated.sha256,
        regenerated_rust_size=generated.size,
        generator_backend="rextio-core-rust-pyo3-v1",
    )
    stub = (
        EvidenceFileRef("pkg/mod.pyi", "5" * 64, 30, "project-python-stub")
        if stub_present
        else None
    )
    record = AnalysisInputRecord(
        source_path=source.logical_path,
        stub_path="pkg/mod.pyi",
        state="present" if stub_present else "absent",
        stub=stub,
        supported_signature_projection_version=1 if stub_present else None,
        supported_signature_projection_sha256="6" * 64 if stub_present else None,
    )
    analysis = AnalysisInputVerification(
        source_transformation_verification_sha256=sha256_hex(
            canonical_json_bytes(transformation.to_dict())
        ),
        source_input_set_sha256=transformation.source_input_set_sha256,
        source_paths=(source.logical_path,),
        records=(record,),
        analysis_input_set_sha256=analysis_input_records_digest((record,), 1),
        supported_signature_projection_set_sha256=analysis_input_projections_digest(
            (record,), 1
        ),
    )
    return {
        "source": source,
        "generated": generated,
        "inventory": inventory,
        "transformation": transformation,
        "analysis": analysis,
    }


def _provenance(
    fixture: dict[str, object],
    *,
    analysis: AnalysisInputVerification | None,
    transformation: SourceTransformationVerification | None = None,
):
    source = fixture["source"]
    if transformation is None:
        transformation = fixture["transformation"]
    return build_intoto_provenance_document(
        subject=EvidenceFileRef("dist/demo.whl", "7" * 64, 1, "host-extension-wheel"),
        sbom=EvidenceFileRef("dist/demo.cdx.json", "8" * 64, 1, "cyclonedx-sbom"),
        inputs=(source,),
        cargo_packages=(),
        target_triple="x86_64-unknown-linux-gnu",
        source_transformation_verification=transformation,
        analysis_input_verification=analysis,
    )


@pytest.mark.parametrize("stub_present", [True, False])
def test_artifact_evidence_accepts_c613_and_serializes_additively(
    stub_present: bool,
) -> None:
    fixture = _fixture(stub_present=stub_present)
    native = WheelEntryRef("_rextio_native.so", "9" * 64, 1, 1)
    evidence = ArtifactEvidence(
        kind="host-extension-wheel",
        status="preview-ready",
        target_triple="x86_64-unknown-linux-gnu",
        subject=EvidenceFileRef("dist/demo.whl", "a" * 64, 1, "wheel"),
        sbom=SidecarArtifact("CycloneDX", "dist/demo.cdx.json", "b" * 64, 1),
        provenance=SidecarArtifact(
            "in-toto-Statement", "dist/demo.intoto.json", "c" * 64, 1
        ),
        inputs=(fixture["source"], fixture["generated"]),
        wheel_entries=(native,),
        native_runtime_inventory=NativeRuntimeInventory(
            format="elf",
            architecture="x86_64",
            inspector="readelf",
            subject_basename=native.name,
            subject_sha256=native.sha256,
            subject_size=1,
            wheel_member=native.name,
            wheel_member_sha256=native.sha256,
            wheel_member_size=1,
        ),
        source_transformation_inventory=fixture["inventory"],
        source_transformation_verification=fixture["transformation"],
        analysis_input_verification=fixture["analysis"],
    )
    serialized = evidence.to_dict()
    assert serialized["analysis_input_verification"] == fixture["analysis"].to_dict()
    assert ".pyi" in serialized["analysis_input_verification"]["records"][0]["stub_path"]


def test_c613_provenance_adds_only_present_stub_materials_and_is_deterministic() -> None:
    present = _fixture(stub_present=True)
    absent = _fixture(stub_present=False)
    present_document = _provenance(present, analysis=present["analysis"])
    absent_document = _provenance(absent, analysis=absent["analysis"])
    present_materials = present_document["predicate"]["buildDefinition"][
        "resolvedDependencies"
    ]
    absent_materials = absent_document["predicate"]["buildDefinition"][
        "resolvedDependencies"
    ]
    assert [item["annotations"]["rextio:role"] for item in present_materials] == [
        "project-python-source",
        "project-python-stub",
    ]
    assert len(absent_materials) == 1
    assert all(item["annotations"]["rextio:role"] != "project-python-stub" for item in absent_materials)
    internal = present_document["predicate"]["buildDefinition"]["internalParameters"]
    metadata = present_document["predicate"]["runDetails"]["metadata"]
    assert internal["scoped_analysis_inputs_verified"] is True
    assert internal["build_input_closure_complete"] is False
    assert metadata["rextio:analysis_input_verification_observed"] is True
    assert metadata["rextio:analysis_input_verification"] == present["analysis"].to_dict()
    absent_metadata = absent_document["predicate"]["runDetails"]["metadata"]
    assert absent_document["predicate"]["buildDefinition"]["internalParameters"][
        "scoped_analysis_inputs_verified"
    ] is True
    assert absent_metadata["rextio:analysis_input_verification_observed"] is True
    assert absent_metadata["rextio:analysis_input_verification"] == absent["analysis"].to_dict()
    assert all(
        item["annotations"]["rextio:role"] != "project-python-stub"
        for item in absent_materials
    )
    assert _provenance(present, analysis=present["analysis"]) == present_document


def test_c613_rejects_missing_c610_digest_and_nested_mutation() -> None:
    fixture = _fixture(stub_present=True)
    analysis = fixture["analysis"]
    with pytest.raises(
        ValueError,
        match="requires artifact-evidence verification",
    ):
        build_intoto_provenance_document(
            subject=EvidenceFileRef("dist/demo.whl", "7" * 64, 1, "host-extension-wheel"),
            sbom=EvidenceFileRef("dist/demo.cdx.json", "8" * 64, 1, "cyclonedx-sbom"),
            inputs=(fixture["source"],),
            cargo_packages=(),
            target_triple="x86_64-unknown-linux-gnu",
            analysis_input_verification=analysis,
        )
    with pytest.raises(ValueError, match="artifact-evidence digest"):
        _provenance(
            fixture,
            analysis=replace(analysis, source_transformation_verification_sha256="0" * 64),
        )
    object.__setattr__(analysis.records[0].stub, "size", True)
    with pytest.raises((TypeError, ValueError)):
        _provenance(fixture, analysis=analysis)


def test_c613_model_rejects_casefold_and_nfc_source_aliases() -> None:
    fixture = _fixture(stub_present=False)
    record = fixture["analysis"].records[0]
    alias_record = AnalysisInputRecord("PKG/MOD.py", "PKG/MOD.pyi", "absent")
    with pytest.raises(ValueError, match="aliases"):
        AnalysisInputVerification(
            source_transformation_verification_sha256=fixture["analysis"].source_transformation_verification_sha256,
            source_input_set_sha256=fixture["analysis"].source_input_set_sha256,
            source_paths=(record.source_path, "PKG/MOD.py"),
            records=(record, alias_record),
            analysis_input_set_sha256=analysis_input_records_digest(
                (record, alias_record), 1
            ),
            supported_signature_projection_set_sha256=analysis_input_projections_digest(
                (record, alias_record), 1
            ),
        )


def test_c613_builder_rejects_forged_stub_path_aliases() -> None:
    fixture = _fixture(stub_present=False)
    analysis = fixture["analysis"]
    object.__setattr__(analysis.records[0], "stub_path", "PKG/MOD.pyi")
    with pytest.raises(ValueError, match="aliases|derived"):
        _provenance(fixture, analysis=analysis)
