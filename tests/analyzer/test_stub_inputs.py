from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path

import pytest

import rextio.analyzer.stub_inputs as stub_inputs
from rextio.analyzer.stub_inputs import (
    StubInputLimits,
    StubInputRecord,
    StubInputSnapshot,
    StubInputState,
    capture_sibling_stub_inputs,
)


def _write_source(root: Path, relative: str, text: str = "pass\n") -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _capture(root: Path, *sources: Path, limits: StubInputLimits | None = None):
    return capture_sibling_stub_inputs(
        root.resolve(),
        tuple(sorted((source.resolve() for source in sources), key=lambda path: path.as_posix())),
        limits=limits,
    )


def test_snapshot_has_canonical_present_and_absent_records(tmp_path: Path) -> None:
    present_source = _write_source(tmp_path, "pkg/present.py")
    absent_source = _write_source(tmp_path, "pkg/absent.py")
    stub_bytes = b"def score(value: int) -> int: ...\n"
    present_source.with_suffix(".pyi").write_bytes(stub_bytes)

    snapshot = _capture(tmp_path, absent_source, present_source)

    present = snapshot.for_source(present_source)
    assert present.state is StubInputState.PRESENT_VALID
    assert present.eligible is True
    assert present.source_path == "pkg/present.py"
    assert present.stub_path == "pkg/present.pyi"
    assert present.sha256 == hashlib.sha256(stub_bytes).hexdigest()
    assert present.size == len(stub_bytes)
    assert present.projection_sha256 is not None
    assert present.exact_bytes == stub_bytes
    assert present.text == stub_bytes.decode("utf-8")

    absent = snapshot.for_source(absent_source)
    assert absent.state is StubInputState.ABSENT
    assert absent.eligible is False
    assert absent.stub_path == "pkg/absent.pyi"
    assert absent.sha256 is None
    assert absent.exact_bytes is None
    assert len(snapshot.records) == 2


def test_snapshot_bytes_do_not_change_after_stub_mutation(tmp_path: Path) -> None:
    source = _write_source(tmp_path, "module.py")
    stub = source.with_suffix(".pyi")
    original = b"def before(value: int) -> int: ...\n"
    stub.write_bytes(original)
    snapshot = _capture(tmp_path, source)

    stub.write_bytes(b"def after(value: str) -> str: ...\n")

    record = snapshot.for_source(source)
    assert record.exact_bytes == original
    assert record.text == original.decode("utf-8")
    assert record.sha256 == hashlib.sha256(original).hexdigest()


@pytest.mark.parametrize(
    ("payload", "reason"),
    [
        (b"def bad(\xff): ...\n", "invalid-utf8"),
        (b"def broken(: ...\n", "invalid-syntax"),
    ],
)
def test_invalid_stub_is_present_and_never_collapsed_to_absence(
    tmp_path: Path,
    payload: bytes,
    reason: str,
) -> None:
    source = _write_source(tmp_path, "module.py")
    source.with_suffix(".pyi").write_bytes(payload)

    record = _capture(tmp_path, source).for_source(source)

    assert record.state is StubInputState.PRESENT_INVALID
    assert record.eligible is False
    assert record.reason == reason
    assert record.sha256 == hashlib.sha256(payload).hexdigest()
    assert record.exact_bytes == payload
    if reason == "invalid-utf8":
        assert record.text is None
    else:
        assert record.text is not None


def test_symlink_and_hardlink_stubs_are_rejected_without_becoming_absent(tmp_path: Path) -> None:
    target = tmp_path / "target.pyi"
    target.write_text("def target() -> int: ...\n", encoding="utf-8")
    symlink_source = _write_source(tmp_path, "symlinked.py")
    symlink_source.with_suffix(".pyi").symlink_to(target)

    hardlink_source = _write_source(tmp_path, "hardlinked.py")
    os.link(target, hardlink_source.with_suffix(".pyi"))

    snapshot = _capture(tmp_path, hardlink_source, symlink_source)

    for source in (symlink_source, hardlink_source):
        record = snapshot.for_source(source)
        assert record.state is StubInputState.PRESENT_INVALID
        assert record.reason in {"unsafe-symlink", "unsafe-link-count"}
        assert record.exact_bytes is None


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires POSIX FIFO support")
def test_fifo_stub_is_rejected_without_opening_it(tmp_path: Path) -> None:
    source = _write_source(tmp_path, "module.py")
    os.mkfifo(source.with_suffix(".pyi"))

    record = _capture(tmp_path, source).for_source(source)

    assert record.state is StubInputState.PRESENT_INVALID
    assert record.reason == "unsafe-file-type"
    assert record.exact_bytes is None


def test_projection_metadata_is_deterministic_and_content_digest_is_exact(tmp_path: Path) -> None:
    left_source = _write_source(tmp_path, "left.py")
    right_source = _write_source(tmp_path, "right.py")
    left = b"def score(value: int = ...) -> int: ...\n"
    right = b"# formatting differs\ndef score( value: int=... )->int: ...\n"
    left_source.with_suffix(".pyi").write_bytes(left)
    right_source.with_suffix(".pyi").write_bytes(right)

    first = _capture(tmp_path, left_source, right_source)
    second = _capture(tmp_path, left_source, right_source)
    left_record = first.for_source(left_source)
    right_record = first.for_source(right_source)

    assert left_record.projection_sha256 == right_record.projection_sha256
    assert left_record.sha256 != right_record.sha256
    assert first.to_dict() == second.to_dict()
    assert tuple(record.source_path for record in first.records) == ("left.py", "right.py")


@pytest.mark.parametrize(
    ("stub_text", "reason"),
    [
        (
            "def duplicate(value: int) -> int: ...\n"
            "def duplicate(value: str) -> str: ...\n",
            "duplicate-function",
        ),
        (
            "from typing import overload\n"
            "@overload\n"
            "def convert(value: int) -> int: ...\n",
            "overload-decorator",
        ),
        ("value = compute()\n", "unsupported-top-level"),
    ],
)
def test_complex_stub_is_ineligible_but_safe_snapshot_data_is_preserved(
    tmp_path: Path,
    stub_text: str,
    reason: str,
) -> None:
    source = _write_source(tmp_path, "module.py")
    source.with_suffix(".pyi").write_text(stub_text, encoding="utf-8")

    record = _capture(tmp_path, source).for_source(source)

    assert record.state is StubInputState.PRESENT_INVALID
    assert record.reason == reason
    assert record.exact_bytes == stub_text.encode("utf-8")
    assert record.text == stub_text
    assert record.projection_sha256 is None


def test_casefold_logical_path_aliases_are_rejected_deterministically(tmp_path: Path) -> None:
    upper = _write_source(tmp_path, "Upper.py")
    lower = _write_source(tmp_path, "upper.py")
    upper.with_suffix(".pyi").write_text("def upper() -> int: ...\n", encoding="utf-8")
    lower.with_suffix(".pyi").write_text("def lower() -> int: ...\n", encoding="utf-8")

    snapshot = _capture(tmp_path, upper, lower)

    assert [record.reason for record in snapshot.records] == [
        "logical-path-alias",
        "logical-path-alias",
    ]
    assert all(record.state is StubInputState.PRESENT_INVALID for record in snapshot.records)
    assert all(record.exact_bytes is None for record in snapshot.records)


def test_per_file_and_signature_limits_are_explicit_ineligible_records(tmp_path: Path) -> None:
    large_source = _write_source(tmp_path, "large.py")
    signature_source = _write_source(tmp_path, "signatures.py")
    large_source.with_suffix(".pyi").write_bytes(b"def large() -> int: ...\n")
    signature_text = "def one() -> int: ...\ndef two() -> int: ...\n"
    signature_source.with_suffix(".pyi").write_text(signature_text, encoding="utf-8")

    large = _capture(
        tmp_path,
        large_source,
        limits=StubInputLimits(max_file_bytes=8),
    ).for_source(large_source)
    signatures = _capture(
        tmp_path,
        signature_source,
        limits=StubInputLimits(max_signatures_per_file=1),
    ).for_source(signature_source)

    assert (large.state, large.reason, large.exact_bytes) == (
        StubInputState.PRESENT_INVALID,
        "file-bytes-limit",
        None,
    )
    assert signatures.state is StubInputState.PRESENT_INVALID
    assert signatures.reason == "signature-count-limit"
    assert signatures.exact_bytes == signature_text.encode("utf-8")


def test_serialized_metadata_and_repr_never_leak_bytes_or_absolute_paths(tmp_path: Path) -> None:
    source = _write_source(tmp_path, "pkg/module.py")
    secret_marker = "NEVER_SERIALIZE_RAW_STUB_MARKER"
    source.with_suffix(".pyi").write_text(
        f"def marker(value: str = {secret_marker!r}) -> str: ...\n",
        encoding="utf-8",
    )

    snapshot = _capture(tmp_path, source)
    rendered = json.dumps(snapshot.to_dict(), sort_keys=True)
    record_repr = repr(snapshot.for_source(source))

    assert secret_marker not in rendered
    assert secret_marker not in record_repr
    assert str(tmp_path.resolve()) not in rendered
    assert str(tmp_path.resolve()) not in record_repr
    assert "exact_bytes" not in rendered
    assert "text" not in rendered


def test_lookup_rejects_paths_outside_the_captured_project(tmp_path: Path) -> None:
    source = _write_source(tmp_path, "module.py")
    snapshot = _capture(tmp_path, source)

    with pytest.raises(KeyError):
        snapshot.for_source(tmp_path.parent / "outside.py")


def test_outside_root_stub_symlink_is_present_invalid(tmp_path: Path) -> None:
    source = _write_source(tmp_path, "module.py")
    outside = tmp_path.parent / "outside.pyi"
    outside.write_text("def outside() -> int: ...\n", encoding="utf-8")
    source.with_suffix(".pyi").symlink_to(outside)

    record = _capture(tmp_path, source).for_source(source)

    assert record.state is StubInputState.PRESENT_INVALID
    assert record.reason == "unsafe-symlink"
    assert record.exact_bytes is None


def test_replacement_between_read_and_identity_check_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = _write_source(tmp_path, "module.py")
    stub = source.with_suffix(".pyi")
    stub.write_text("def before() -> int: ...\n", encoding="utf-8")

    def replace_stub() -> None:
        replacement = tmp_path / "replacement.pyi"
        replacement.write_text("def after() -> int: ...\n", encoding="utf-8")
        os.replace(replacement, stub)

    monkeypatch.setattr(stub_inputs, "_READ_INTERLOCK", replace_stub)
    record = _capture(tmp_path, source).for_source(source)

    assert record.state is StubInputState.PRESENT_INVALID
    assert record.reason == "secure-read-race"


def test_source_total_ast_and_depth_limits_are_explicit(tmp_path: Path) -> None:
    first = _write_source(tmp_path, "first.py")
    second = _write_source(tmp_path, "second.py")
    first.with_suffix(".pyi").write_text("def first() -> int: ...\n", encoding="utf-8")
    second.with_suffix(".pyi").write_text("def second() -> int: ...\n", encoding="utf-8")

    source_limited = _capture(tmp_path, first, second, limits=StubInputLimits(max_source_records=1))
    assert source_limited.records[1].reason == "source-record-limit"

    total_limited = _capture(tmp_path, first, second, limits=StubInputLimits(max_total_bytes=1))
    assert all(record.reason == "total-bytes-limit" for record in total_limited.records)

    ast_limited = _capture(tmp_path, first, limits=StubInputLimits(max_ast_nodes=1))
    assert ast_limited.records[0].reason == "ast-node-limit"

    depth_limited = _capture(tmp_path, first, limits=StubInputLimits(max_ast_depth=1_000))
    assert depth_limited.records[0].state is StubInputState.PRESENT_VALID
    depth_limited = _capture(tmp_path, first, limits=StubInputLimits(max_ast_depth=2))
    assert depth_limited.records[0].reason == "ast-depth-limit"


def test_default_source_record_bound_is_analyzer_owned_and_above_evidence_cap(tmp_path: Path) -> None:
    sources = tuple(_write_source(tmp_path, f"module_{index}.py") for index in range(257))
    snapshot = _capture(tmp_path, *sources)
    assert len(snapshot.records) == 257
    assert all(record.state is StubInputState.ABSENT for record in snapshot.records)
    assert StubInputLimits().max_source_records > 256
    assert StubInputLimits().max_source_records == 10_000


@pytest.mark.parametrize("field", [
    "max_file_bytes",
    "max_signatures_per_file",
    "max_source_records",
    "max_total_bytes",
    "max_ast_nodes",
    "max_ast_depth",
    "max_identifiers_per_file",
])
def test_limits_require_exact_positive_ints(field: str) -> None:
    with pytest.raises(ValueError):
        StubInputLimits(**{field: 0})
    with pytest.raises(ValueError):
        StubInputLimits(**{field: True})


def test_compatibility_reader_rejects_path_replacement_race(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = _write_source(tmp_path, "module.py")
    stub = source.with_suffix(".pyi")
    stub.write_text("def score(value: int) -> int: ...\n", encoding="utf-8")
    replacement = tmp_path / "replacement.pyi"
    replacement.write_bytes(stub.read_bytes())

    monkeypatch.setattr(stub_inputs, "_secure_api_available", lambda: False)

    def replace_stub() -> None:
        stub.unlink()
        stub.symlink_to(replacement)

    monkeypatch.setattr(stub_inputs, "_READ_INTERLOCK", replace_stub)
    record = _capture(tmp_path, source).for_source(source)
    assert record.state is StubInputState.PRESENT_INVALID
    assert record.reason == "compatibility-read-race"


def test_forged_state_combinations_fail_closed() -> None:
    with pytest.raises(ValueError):
        StubInputRecord("module.py", "module.pyi", StubInputState.ABSENT, False, reason="forged")
    with pytest.raises(ValueError):
        StubInputRecord("module.py", "module.pyi", StubInputState.PRESENT_VALID, True)
    with pytest.raises(ValueError):
        StubInputRecord("module.py", "module.pyi", StubInputState.PRESENT_INVALID, True, reason="forged")


def test_nfc_casefold_aliases_and_snapshot_repr_are_private(tmp_path: Path) -> None:
    composed = _write_source(tmp_path, "\u00e9.py")
    decomposed = _write_source(tmp_path, "e\u0301.py")
    composed.with_suffix(".pyi").write_text("def composed() -> int: ...\n", encoding="utf-8")
    decomposed.with_suffix(".pyi").write_text("def decomposed() -> int: ...\n", encoding="utf-8")

    snapshot = _capture(tmp_path, composed, decomposed)
    assert all(record.reason == "logical-path-alias" for record in snapshot.records)
    assert str(tmp_path.resolve()) not in repr(snapshot)
    assert "root=" not in repr(snapshot)


def test_alias_group_is_fail_closed_without_invalidating_unrelated_records(tmp_path: Path) -> None:
    alias_a = _write_source(tmp_path, "Alias.py")
    alias_b = _write_source(tmp_path, "alias.py")
    normal = _write_source(tmp_path, "normal.py")
    alias_a.with_suffix(".pyi").write_text("def a() -> int: ...\n", encoding="utf-8")
    alias_b.with_suffix(".pyi").write_text("def b() -> int: ...\n", encoding="utf-8")
    normal.with_suffix(".pyi").write_text("def normal() -> int: ...\n", encoding="utf-8")

    snapshot = _capture(tmp_path, normal, alias_b, alias_a)

    assert [record.reason for record in snapshot.records] == [
        "logical-path-alias",
        "logical-path-alias",
        None,
    ]
    assert snapshot.for_source(normal).state is StubInputState.PRESENT_VALID


def test_exact_duplicate_caller_input_has_explicit_fail_closed_result(tmp_path: Path) -> None:
    source = _write_source(tmp_path, "module.py")
    source.with_suffix(".pyi").write_text("def value() -> int: ...\n", encoding="utf-8")

    snapshot = _capture(tmp_path, source, source)

    assert len(snapshot.records) == 2
    assert all(record.reason == "logical-path-alias" for record in snapshot.records)
    assert all(record.state is StubInputState.PRESENT_INVALID for record in snapshot.records)


def test_forged_alias_group_cannot_hide_a_non_alias_member(tmp_path: Path) -> None:
    first = StubInputRecord("Alias.py", "Alias.pyi", StubInputState.PRESENT_INVALID, False, "logical-path-alias")
    second = StubInputRecord("alias.py", "alias.pyi", StubInputState.ABSENT, False)

    with pytest.raises(ValueError):
        StubInputSnapshot(tmp_path.resolve(), (first, second))


@pytest.mark.parametrize("failure", ["root-fstat", "child-fstat", "child-stat"])
def test_open_directory_chain_closes_partially_opened_descriptors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    (tmp_path / "pkg").mkdir()
    original_open = stub_inputs.os.open
    original_close = stub_inputs.os.close
    original_fstat = stub_inputs.os.fstat
    original_stat = stub_inputs.os.stat
    opened: list[int] = []
    closed: list[int] = []

    def tracked_open(*args, **kwargs):
        fd = original_open(*args, **kwargs)
        opened.append(fd)
        return fd

    def failing_fstat(fd: int):
        if failure == "root-fstat" and len(opened) == 1:
            raise OSError("root fstat failure")
        if failure == "child-fstat" and len(opened) == 2:
            raise OSError("child fstat failure")
        return original_fstat(fd)

    def failing_stat(*args, **kwargs):
        if failure == "child-stat" and len(opened) == 2:
            raise OSError("child stat failure")
        return original_stat(*args, **kwargs)

    def tracked_close(fd: int) -> None:
        closed.append(fd)
        original_close(fd)

    monkeypatch.setattr(stub_inputs.os, "open", tracked_open)
    monkeypatch.setattr(stub_inputs.os, "fstat", failing_fstat)
    monkeypatch.setattr(stub_inputs.os, "stat", failing_stat)
    monkeypatch.setattr(stub_inputs.os, "close", tracked_close)

    with pytest.raises(OSError):
        stub_inputs._open_directory_chain(tmp_path, ["pkg"])

    assert opened
    assert set(opened) <= set(closed)


def test_directory_cleanup_continues_after_close_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "pkg").mkdir()
    original_close = stub_inputs.os.close
    closed: list[int] = []
    failed = False

    def close_with_one_failure(fd: int) -> None:
        nonlocal failed
        closed.append(fd)
        if not failed:
            failed = True
            raise OSError("injected close failure")
        original_close(fd)

    monkeypatch.setattr(stub_inputs.os, "close", close_with_one_failure)
    with pytest.raises(OSError):
        stub_inputs._open_directory_chain(tmp_path, ["pkg", "missing"])

    assert len(closed) >= 2


def test_read_cleanup_continues_after_close_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "module.pyi").write_text(
        "def score() -> int: ...\n", encoding="utf-8"
    )
    original_close = stub_inputs.os.close
    closed: list[int] = []
    failed = False

    def close_with_one_failure(fd: int) -> None:
        nonlocal failed
        closed.append(fd)
        if not failed:
            failed = True
            raise OSError("injected close failure")
        original_close(fd)

    monkeypatch.setattr(stub_inputs.os, "close", close_with_one_failure)
    result = stub_inputs._read_secure_stub(tmp_path, "pkg/module.pyi", 1_048_576)

    assert result == ("ok", b"def score() -> int: ...\n")
    assert len(closed) >= 2


def test_capture_sorts_sources_without_caller_order(tmp_path: Path) -> None:
    first = _write_source(tmp_path, "a.py")
    second = _write_source(tmp_path, "b.py")
    snapshot = capture_sibling_stub_inputs(tmp_path, (second, first))
    assert tuple(record.source_path for record in snapshot.records) == ("a.py", "b.py")


def test_record_rejects_forged_metadata_and_snapshot_order(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        StubInputRecord("module.py", "module.pyi", StubInputState.ABSENT, False, sha256="0" * 64)
    with pytest.raises(ValueError):
        StubInputRecord("module.py", "other.pyi", StubInputState.ABSENT, False)
    source = StubInputRecord("b.py", "b.pyi", StubInputState.ABSENT, False)
    other = StubInputRecord("a.py", "a.pyi", StubInputState.ABSENT, False)
    with pytest.raises(ValueError):
        StubInputSnapshot(tmp_path.resolve(), (source, other))


def test_projection_ignores_decorators_aliases_and_non_signature_text(tmp_path: Path) -> None:
    source = _write_source(tmp_path, "module.py")
    stub = source.with_suffix(".pyi")
    stub.write_text("# comment\ndef score(value: int = 1) -> int: ...\n", encoding="utf-8")
    record = _capture(tmp_path, source).for_source(source)
    stub.write_text("# other\ndef score(value:int=999) -> int: ...\n", encoding="utf-8")
    changed = _capture(tmp_path, source).for_source(source)
    assert changed.projection_sha256 == record.projection_sha256
    stub.write_text("@typing.overload\ndef score(value: int) -> int: ...\n", encoding="utf-8")
    assert _capture(tmp_path, source).for_source(source).reason == "overload-decorator"


def test_projection_does_not_unparse_unsupported_annotations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _write_source(tmp_path, "module.py")
    source.with_suffix(".pyi").write_text(
        "def score(value: VendorType) -> VendorResult: ...\n", encoding="utf-8"
    )

    def fail_unparse(node: ast.AST) -> str:
        raise AssertionError("unparse called")

    monkeypatch.setattr(stub_inputs.ast, "unparse", fail_unparse)
    record = _capture(tmp_path, source).for_source(source)

    assert record.state is StubInputState.PRESENT_VALID
    assert record.projection_sha256 is not None


def test_parser_recursion_is_a_deterministic_invalid_reason(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = _write_source(tmp_path, "module.py")
    source.with_suffix(".pyi").write_text("def score(value: int) -> int: ...\n", encoding="utf-8")

    def recurse(*args, **kwargs):
        raise RecursionError

    monkeypatch.setattr(stub_inputs.ast, "parse", recurse)
    assert _capture(tmp_path, source).for_source(source).reason == "parser-recursion"


def test_secure_read_unavailable_keeps_analyzer_consumable_unverified_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _write_source(tmp_path, "module.py")
    source.with_suffix(".pyi").write_text("def score(value: int) -> int: ...\n", encoding="utf-8")
    monkeypatch.setattr(stub_inputs, "_secure_api_available", lambda: False)
    record = _capture(tmp_path, source).for_source(source)
    assert record.state is StubInputState.PRESENT_UNVERIFIED
    assert record.eligible is False
    assert record.analyzer_consumable is True
    assert record.exact_bytes == b"def score(value: int) -> int: ...\n"
    assert record.projection_sha256 is not None


def test_secure_read_unavailable_marks_absent_stub_unverified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _write_source(tmp_path, "module.py")
    monkeypatch.setattr(stub_inputs, "_secure_api_available", lambda: False)

    snapshot = _capture(tmp_path, source)
    record = snapshot.for_source(source)

    assert record.state is StubInputState.ABSENT_UNVERIFIED
    assert record.eligible is False
    assert record.analyzer_consumable is False
    assert record.to_dict()["state"] == "absent-unverified"
    assert snapshot == StubInputSnapshot(tmp_path.resolve(), snapshot.records)
