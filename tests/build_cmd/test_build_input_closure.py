"""Focused Full-C6 tests for immutable build-input capture."""

from __future__ import annotations

from pathlib import Path
import os

import pytest


def test_exact_file_receipt_detects_content_mutation(tmp_path: Path) -> None:
    try:
        from rextio.build.input_closure import (
            BuildInputIdentityError,
            capture_exact_file,
            verify_exact_file,
        )
    except ImportError:
        pytest.fail("the immutable build-input closure module is missing")

    source = tmp_path / "app.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    receipt = capture_exact_file(
        source,
        logical_name="project/app.py",
        role="project-python-source",
    )

    assert receipt.logical_name == "project/app.py"
    assert receipt.role == "project-python-source"
    assert receipt.size == len(b"VALUE = 1\n")
    assert receipt.sha256

    source.write_text("VALUE = 2\n", encoding="utf-8")
    with pytest.raises(BuildInputIdentityError, match="changed"):
        verify_exact_file(source, receipt)


def test_exact_file_capture_rejects_missing_and_symlink_inputs(tmp_path: Path) -> None:
    from rextio.build.input_closure import BuildInputIdentityError, capture_exact_file

    with pytest.raises(BuildInputIdentityError, match="missing"):
        capture_exact_file(
            tmp_path / "missing",
            logical_name="input/missing",
            role="generated-rust-input",
        )

    target = tmp_path / "target"
    target.write_bytes(b"trusted")
    link = tmp_path / "link"
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable on this platform")
    with pytest.raises(BuildInputIdentityError, match="symlink"):
        capture_exact_file(
            link,
            logical_name="input/link",
            role="generated-rust-input",
        )


def test_build_input_closure_is_canonical_and_reverifiable(tmp_path: Path) -> None:
    from rextio.build.input_closure import (
        BuildInputIdentityError,
        InputFileSpec,
        capture_build_input_closure,
        verify_build_input_closure,
    )

    first = tmp_path / "app.py"
    second = tmp_path / "Cargo.lock"
    first.write_bytes(b"def answer() -> int:\n    return 42\n")
    second.write_bytes(b"version = 4\n")
    specs = (
        InputFileSpec(first, "project/app.py", "project-python-source"),
        InputFileSpec(second, "generated/Cargo.lock", "generated-cargo-lock"),
    )

    forward = capture_build_input_closure(specs)
    reverse = capture_build_input_closure(tuple(reversed(specs)))
    from rextio.artifacts.full_authorization import FULL_C6_SCOPE

    assert forward == reverse
    assert forward.scope == FULL_C6_SCOPE
    assert forward.digest == reverse.digest
    assert forward.complete_for_scope is True
    serialized = forward.to_dict()
    assert serialized["files"][0]["role"] == "generated-cargo-lock"
    assert str(tmp_path) not in repr(serialized)

    verify_build_input_closure(specs, forward)
    second.write_bytes(b"version = 3\n")
    with pytest.raises(BuildInputIdentityError, match="closure changed"):
        verify_build_input_closure(specs, forward)


def test_build_input_closure_rejects_casefold_path_aliases(tmp_path: Path) -> None:
    from rextio.build.input_closure import (
        BuildInputIdentityError,
        InputFileSpec,
        capture_build_input_closure,
    )

    first = tmp_path / "one"
    second = tmp_path / "two"
    first.write_bytes(os.urandom(4))
    second.write_bytes(os.urandom(4))
    with pytest.raises(BuildInputIdentityError, match="alias"):
        capture_build_input_closure(
            (
                InputFileSpec(first, "Project/App.py", "project-python-source"),
                InputFileSpec(second, "project/app.py", "project-python-source"),
            )
        )
