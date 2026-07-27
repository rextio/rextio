"""Optional verification of the exact inputs used for source transformation."""

from __future__ import annotations

import unicodedata
from pathlib import Path

from rextio.analyzer.models import ProjectAnalysis
from rextio.analyzer.stub_inputs import (
    STUB_SIGNATURE_PROJECTION_VERSION,
    StubInputRecord,
    StubInputSnapshot,
    StubInputState,
    StubInputLimits,
    capture_sibling_stub_inputs,
)
from rextio.artifacts.evidence import (
    ANALYSIS_INPUT_SET_VERSION,
    AnalysisInputRecord,
    AnalysisInputVerification,
    EvidenceFileRef,
    MAX_INPUT_FILES,
    SOURCE_TRANSFORMATION_VERIFICATION_SCOPE,
    SourceTransformationVerification,
    SUPPORTED_SIGNATURE_PROJECTION_VERSION,
    SUPPORTED_SIGNATURE_PROJECTION_SET_VERSION,
    analysis_input_projections_digest,
    analysis_input_records_digest,
    canonical_json_bytes,
    sha256_hex,
)
from rextio.partition.build_plan import BuildPlan


def collect_scoped_analysis_input_verification(
    *,
    project_root: Path,
    plan: BuildPlan,
    source_transformation_verification: SourceTransformationVerification,
) -> AnalysisInputVerification | None:
    """Capture scoped analysis inputs, returning ``None`` on every failure."""
    try:
        return _collect_scoped_analysis_input_verification(
            project_root=project_root,
            plan=plan,
            source_transformation_verification=source_transformation_verification,
        )
    except Exception:
        return None


def _collect_scoped_analysis_input_verification(
    *,
    project_root: Path,
    plan: BuildPlan,
    source_transformation_verification: SourceTransformationVerification,
) -> AnalysisInputVerification:
    if type(plan) is not BuildPlan or type(source_transformation_verification) is not SourceTransformationVerification:
        raise TypeError("analysis input verification inputs are invalid")
    if source_transformation_verification.scope != SOURCE_TRANSFORMATION_VERIFICATION_SCOPE:
        raise ValueError("analysis input verification requires the exact transformation scope")
    if STUB_SIGNATURE_PROJECTION_VERSION != SUPPORTED_SIGNATURE_PROJECTION_VERSION:
        raise ValueError("analyzer and evidence projection versions differ")
    verification = _reconstruct_verification(source_transformation_verification)
    root = _canonical_root(project_root)
    analysis = plan.analysis
    if type(analysis) is not ProjectAnalysis:
        raise TypeError("analysis input verification analysis is invalid")
    if not isinstance(analysis.project_root, Path) or Path(analysis.project_root).resolve(strict=True) != root:
        raise ValueError("analysis input verification project roots differ")
    snapshot_value = analysis._stub_inputs
    snapshot = _reconstruct_stub_snapshot(snapshot_value)
    if snapshot.root != root:
        raise ValueError("analysis input verification stub snapshot root differs")

    source_inputs = verification.source_inputs
    if len(source_inputs) > MAX_INPUT_FILES:
        raise ValueError("analysis input verification source count exceeds the bound")
    source_paths = tuple(item.logical_path for item in source_inputs)
    if source_paths != tuple(sorted(source_paths)) or not source_paths:
        raise ValueError("analysis input verification source coverage is noncanonical")
    if len(snapshot.records) > MAX_INPUT_FILES or tuple(record.source_path for record in snapshot.records) != source_paths:
        raise ValueError("analysis input verification snapshot scope differs from transformation")
    _reject_path_aliases(source_paths, "source")
    _reject_path_aliases(tuple(record.stub_path for record in snapshot.records), "stub")

    sources = tuple(root / path for path in source_paths)
    recaptured = capture_sibling_stub_inputs(root, sources)
    if recaptured != snapshot:
        raise ValueError("analysis input verification stub snapshot changed")

    records: list[AnalysisInputRecord] = []
    for snapshot_record, source_ref in zip(recaptured.records, source_inputs, strict=True):
        if snapshot_record.source_path != source_ref.logical_path:
            raise ValueError("analysis input verification source binding differs")
        if snapshot_record.state is StubInputState.ABSENT:
            records.append(AnalysisInputRecord(snapshot_record.source_path, snapshot_record.stub_path, "absent"))
            continue
        if snapshot_record.state is not StubInputState.PRESENT_VALID:
            raise ValueError("analysis input verification contains an unsafe or uncapturable stub")
        if snapshot_record.sha256 is None or snapshot_record.size is None or snapshot_record.projection_sha256 is None:
            raise ValueError("analysis input verification present stub metadata is incomplete")
        records.append(
            AnalysisInputRecord(
                source_path=snapshot_record.source_path,
                stub_path=snapshot_record.stub_path,
                state="present",
                stub=EvidenceFileRef(snapshot_record.stub_path, snapshot_record.sha256, snapshot_record.size, "project-python-stub"),
                supported_signature_projection_version=SUPPORTED_SIGNATURE_PROJECTION_VERSION,
                supported_signature_projection_sha256=snapshot_record.projection_sha256,
            )
        )

    immutable_records = tuple(records)
    return AnalysisInputVerification(
        source_transformation_verification_sha256=sha256_hex(canonical_json_bytes(verification.to_dict())),
        source_input_set_sha256=verification.source_input_set_sha256,
        source_paths=source_paths,
        records=immutable_records,
        analysis_input_set_sha256=analysis_input_records_digest(immutable_records, ANALYSIS_INPUT_SET_VERSION),
        supported_signature_projection_set_sha256=analysis_input_projections_digest(immutable_records, SUPPORTED_SIGNATURE_PROJECTION_SET_VERSION),
    )


def _reconstruct_stub_snapshot(value: StubInputSnapshot | None) -> StubInputSnapshot:
    if (
        type(value) is not StubInputSnapshot
        or not isinstance(value.root, Path)
        or type(value.records) is not tuple
        or len(value.records) > MAX_INPUT_FILES
    ):
        raise TypeError("analysis input verification stub snapshot is invalid")
    limits = StubInputLimits()
    total_bytes = 0
    rebuilt_records: list[StubInputRecord] = []
    for record in value.records:
        if type(record) is not StubInputRecord:
            raise TypeError("analysis input verification stub record is invalid")
        if any(
            type(field) is not expected
            for field, expected in (
                (record.source_path, str),
                (record.stub_path, str),
                (record.eligible, bool),
            )
        ) or type(record.state) is not StubInputState:
            raise TypeError("analysis input verification stub record fields are invalid")
        if record.reason is not None and type(record.reason) is not str:
            raise TypeError("analysis input verification stub reason is invalid")
        if record.sha256 is not None and type(record.sha256) is not str:
            raise TypeError("analysis input verification stub digest is invalid")
        if record.size is not None and type(record.size) is not int:
            raise TypeError("analysis input verification stub size is invalid")
        if record.projection_sha256 is not None and type(record.projection_sha256) is not str:
            raise TypeError("analysis input verification projection digest is invalid")
        if record.exact_bytes is not None and type(record.exact_bytes) is not bytes:
            raise TypeError("analysis input verification stub bytes are invalid")
        if record.text is not None and type(record.text) is not str:
            raise TypeError("analysis input verification stub text is invalid")
        declared_size = record.size
        if declared_size is not None and declared_size > limits.max_file_bytes:
            raise ValueError("analysis input verification stub file exceeds the bound")
        exact_size = len(record.exact_bytes) if record.exact_bytes is not None else None
        if exact_size is not None and exact_size > limits.max_file_bytes:
            raise ValueError("analysis input verification stub file exceeds the bound")
        if exact_size is not None and declared_size is not None and exact_size != declared_size:
            raise ValueError("analysis input verification stub size does not match bytes")
        text_size = None
        if record.text is not None:
            if (
                record.exact_bytes is None
                or record.sha256 is None
                or declared_size is None
            ):
                raise ValueError("analysis input verification stub text metadata is incomplete")
            # A Python str can require up to four UTF-8 bytes per code point.
            # Bound the character count before attempting the encoding, then
            # enforce the analyzer's actual byte limit on the encoded text.
            if len(record.text) > limits.max_file_bytes:
                raise ValueError("analysis input verification stub text exceeds the bound")
            text_size = len(record.text.encode("utf-8"))
            if text_size > limits.max_file_bytes:
                raise ValueError("analysis input verification stub text exceeds the bound")
            if declared_size < len(record.text):
                raise ValueError("analysis input verification stub size does not match text")
        record_size = exact_size
        if record_size is None:
            record_size = text_size if text_size is not None else declared_size or 0
        if record_size > limits.max_file_bytes:
            raise ValueError("analysis input verification stub file exceeds the bound")
        if total_bytes + record_size > limits.max_total_bytes:
            raise ValueError("analysis input verification stub aggregate exceeds the bound")
        total_bytes += record_size
        rebuilt_records.append(
            StubInputRecord(
                source_path=record.source_path,
                stub_path=record.stub_path,
                state=record.state,
                eligible=record.eligible,
                reason=record.reason,
                sha256=record.sha256,
                size=record.size,
                projection_sha256=record.projection_sha256,
                exact_bytes=record.exact_bytes,
                text=record.text,
            )
        )
    rebuilt = StubInputSnapshot(root=value.root, records=tuple(rebuilt_records))
    if rebuilt != value:
        raise ValueError("analysis input verification stub snapshot is not immutable")
    return rebuilt


def _reconstruct_verification(value: SourceTransformationVerification) -> SourceTransformationVerification:
    if type(value.source_inputs) is not tuple or len(value.source_inputs) > MAX_INPUT_FILES:
        raise TypeError("analysis input verification source inputs are invalid")
    if type(value.function_qualnames) is not tuple:
        raise TypeError("analysis input verification function names are invalid")
    if any(type(item) is not EvidenceFileRef for item in value.source_inputs):
        raise TypeError("analysis input verification source references are invalid")
    if type(value.generated_rust) is not EvidenceFileRef:
        raise TypeError("analysis input verification generated reference is invalid")
    source_inputs = tuple(_reconstruct_file_ref(item) for item in value.source_inputs)
    generated_rust = _reconstruct_file_ref(value.generated_rust)
    rebuilt = SourceTransformationVerification(
        source_transformation_inventory_sha256=value.source_transformation_inventory_sha256,
        source_input_set_sha256=value.source_input_set_sha256,
        module_ir_sha256=value.module_ir_sha256,
        function_qualnames=value.function_qualnames,
        source_inputs=source_inputs,
        generated_rust=generated_rust,
        regenerated_rust_sha256=value.regenerated_rust_sha256,
        regenerated_rust_size=value.regenerated_rust_size,
        generator_backend=value.generator_backend,
        kind=value.kind,
        schema_version=value.schema_version,
        scope=value.scope,
        complete_for_scope=value.complete_for_scope,
        global_provenance_complete=value.global_provenance_complete,
        complete=value.complete,
        authority=value.authority,
    )
    if rebuilt != value:
        raise ValueError("analysis input verification receipt is not immutable")
    return rebuilt


def _reconstruct_file_ref(value: EvidenceFileRef) -> EvidenceFileRef:
    if type(value) is not EvidenceFileRef:
        raise TypeError("analysis input evidence file reference is invalid")
    return EvidenceFileRef(value.logical_path, value.sha256, value.size, value.role)


def _canonical_root(value: Path) -> Path:
    root = Path(value).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("analysis input verification project root is not canonical")
    return root


def _reject_path_aliases(paths: tuple[str, ...], label: str) -> None:
    aliases: set[str] = set()
    for path in paths:
        if type(path) is not str:
            raise TypeError(f"analysis input {label} path is not a string")
        key = unicodedata.normalize("NFC", path).casefold()
        if key in aliases:
            raise ValueError(f"analysis input {label} paths contain aliases")
        aliases.add(key)


__all__ = ["collect_scoped_analysis_input_verification"]
