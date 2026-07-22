"""Adversarial tests for the bounded Full-C6 reproducibility gate."""

from __future__ import annotations

import os
from pathlib import Path

import pytest


def _outputs(root: Path, *, wheel: bytes = b"wheel-v1"):
    from rextio.build.reproducibility import ReproducibilityBuildOutputs

    wheel_path = root / "artifact.whl"
    sbom_path = root / "sbom.json"
    provenance_path = root / "provenance-input.json"
    wheel_path.write_bytes(wheel)
    sbom_path.write_text('{"packages":[{"version":"1","name":"demo"}]}', encoding="utf-8")
    provenance_path.write_text('{"source":"abc","parameters":{"strict":true}}', encoding="utf-8")
    return ReproducibilityBuildOutputs(
        unsigned_wheel=wheel_path,
        sbom_json=sbom_path,
        provenance_input_json=provenance_path,
    )


def test_two_isolated_builds_produce_one_non_authorizing_receipt(tmp_path: Path) -> None:
    try:
        from rextio.build.reproducibility import verify_two_build_reproducibility
    except ImportError:
        pytest.fail("the Full-C6 reproducibility module is missing")

    roots = (tmp_path / "one", tmp_path / "two")
    for root in roots:
        root.mkdir()
    calls: list[Path] = []

    def build(root: Path):
        calls.append(root)
        outputs = _outputs(root)
        if root == roots[1]:
            outputs.sbom_json.write_text(
                '{\n  "packages": [{"name": "demo", "version": "1"}]\n}\n',
                encoding="utf-8",
            )
            outputs.provenance_input_json.write_text(
                '{"parameters":{"strict":true},"source":"abc"}',
                encoding="utf-8",
            )
        return outputs

    receipt = verify_two_build_reproducibility(*roots, build=build)

    assert calls == list(roots)
    assert len(receipt.builds) == 2
    assert receipt.builds[0].ordinal == 1
    assert receipt.builds[1].ordinal == 2
    assert receipt.wheel_sha256 == receipt.builds[0].unsigned_wheel.sha256
    assert receipt.sbom_canonical_sha256 == receipt.builds[0].sbom_canonical_sha256
    assert (
        receipt.provenance_input_canonical_sha256
        == receipt.builds[0].provenance_input_canonical_sha256
    )
    assert receipt.reproducible is True
    assert receipt.authorizes_distribution is False
    assert receipt.complete_for_scope is True
    assert receipt.scope == (
        "host-extension-wheel-cpython-external-source-depth1-plugin-free-v1"
    )
    assert str(tmp_path) not in repr(receipt.to_dict())


@pytest.mark.parametrize(
    ("kind", "message"),
    (("wheel", "wheel"), ("sbom", "SBOM"), ("provenance", "provenance")),
)
def test_reproducibility_rejects_any_semantic_mismatch(
    tmp_path: Path,
    kind: str,
    message: str,
) -> None:
    from rextio.build.reproducibility import (
        ReproducibilityError,
        verify_two_build_reproducibility,
    )

    roots = (tmp_path / "one", tmp_path / "two")
    for root in roots:
        root.mkdir()

    def build(root: Path):
        outputs = _outputs(
            root, wheel=b"wheel-v2" if root == roots[1] and kind == "wheel" else b"wheel-v1"
        )
        if root == roots[1] and kind == "sbom":
            outputs.sbom_json.write_text('{"packages":[]}', encoding="utf-8")
        if root == roots[1] and kind == "provenance":
            outputs.provenance_input_json.write_text(
                '{"source":"different","parameters":{"strict":true}}',
                encoding="utf-8",
            )
        return outputs

    with pytest.raises(ReproducibilityError, match=message):
        verify_two_build_reproducibility(*roots, build=build)


@pytest.mark.parametrize(
    "invalid_json",
    (
        '{"duplicate":1,"duplicate":2}',
        '{"nonfinite":NaN}',
        '{"nonfinite":Infinity}',
        "[" * 70 + "0" + "]" * 70,
    ),
)
def test_reproducibility_rejects_noncanonical_json_inputs(
    tmp_path: Path,
    invalid_json: str,
) -> None:
    from rextio.build.reproducibility import (
        ReproducibilityError,
        verify_two_build_reproducibility,
    )

    roots = (tmp_path / "one", tmp_path / "two")
    for root in roots:
        root.mkdir()

    def build(root: Path):
        outputs = _outputs(root)
        outputs.sbom_json.write_text(invalid_json, encoding="utf-8")
        return outputs

    with pytest.raises(ReproducibilityError, match="JSON"):
        verify_two_build_reproducibility(*roots, build=build)


def test_reproducibility_requires_distinct_empty_nonnested_real_roots(tmp_path: Path) -> None:
    from rextio.build.reproducibility import (
        ReproducibilityError,
        verify_two_build_reproducibility,
    )

    first = tmp_path / "first"
    first.mkdir()
    second = first / "nested"
    second.mkdir()
    with pytest.raises(ReproducibilityError, match="nested"):
        verify_two_build_reproducibility(first, second, build=_outputs)

    second.rmdir()
    second = tmp_path / "second"
    second.mkdir()
    (first / "preexisting").write_text("not isolated", encoding="utf-8")
    with pytest.raises(ReproducibilityError, match="empty"):
        verify_two_build_reproducibility(first, second, build=_outputs)

    symlink = tmp_path / "root-link"
    try:
        symlink.symlink_to(second, target_is_directory=True)
    except (NotImplementedError, OSError):
        return
    first.joinpath("preexisting").unlink()
    with pytest.raises(ReproducibilityError, match="symlink"):
        verify_two_build_reproducibility(first, symlink, build=_outputs)


def test_reproducibility_rejects_outputs_outside_root_or_aliasing_each_other(
    tmp_path: Path,
) -> None:
    from rextio.build.reproducibility import (
        ReproducibilityBuildOutputs,
        ReproducibilityError,
        verify_two_build_reproducibility,
    )

    roots = (tmp_path / "one", tmp_path / "two")
    for root in roots:
        root.mkdir()
    escaped = tmp_path / "escaped.whl"
    escaped.write_bytes(b"wheel-v1")

    def escape(root: Path):
        outputs = _outputs(root)
        if root == roots[0]:
            return ReproducibilityBuildOutputs(
                unsigned_wheel=escaped,
                sbom_json=outputs.sbom_json,
                provenance_input_json=outputs.provenance_input_json,
            )
        return outputs

    with pytest.raises(ReproducibilityError, match="escape"):
        verify_two_build_reproducibility(*roots, build=escape)

    for root in roots:
        for path in root.iterdir():
            path.unlink()

    def duplicate(root: Path):
        outputs = _outputs(root)
        return ReproducibilityBuildOutputs(
            unsigned_wheel=outputs.unsigned_wheel,
            sbom_json=outputs.unsigned_wheel,
            provenance_input_json=outputs.provenance_input_json,
        )

    with pytest.raises(ReproducibilityError, match="duplicate"):
        verify_two_build_reproducibility(*roots, build=duplicate)


def test_reproducibility_rejects_shared_hardlinks_and_post_capture_mutation(
    tmp_path: Path,
) -> None:
    from rextio.build.reproducibility import (
        ReproducibilityError,
        verify_two_build_reproducibility,
    )

    roots = (tmp_path / "one", tmp_path / "two")
    for root in roots:
        root.mkdir()
    first_outputs = None

    def hardlinked(root: Path):
        nonlocal first_outputs
        outputs = _outputs(root)
        if first_outputs is None:
            first_outputs = outputs
        else:
            outputs.unsigned_wheel.unlink()
            os.link(first_outputs.unsigned_wheel, outputs.unsigned_wheel)
        return outputs

    with pytest.raises(ReproducibilityError, match="shared"):
        verify_two_build_reproducibility(*roots, build=hardlinked)

    for root in roots:
        for path in root.iterdir():
            path.unlink()
    first_outputs = None

    def mutating(root: Path):
        nonlocal first_outputs
        outputs = _outputs(root)
        if first_outputs is None:
            first_outputs = outputs
        else:
            first_outputs.unsigned_wheel.write_bytes(b"changed-after-capture")
        return outputs

    with pytest.raises(ReproducibilityError, match="changed"):
        verify_two_build_reproducibility(*roots, build=mutating)
