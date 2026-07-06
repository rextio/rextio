from __future__ import annotations

from pathlib import Path

import pytest

from rextio.plugins.api import RuleRecord, RuleScope
from rextio.plugins.testing import (
    CertificationError,
    CertifiedProject,
    build_certification_project,
    default_equals,
)


def test_default_equals_scalars() -> None:
    assert default_equals(1, 1)
    assert not default_equals(1, 2)
    assert default_equals("x", "x")
    assert not default_equals(1, 1.0)  # type-strict
    assert not default_equals(True, 1)


def test_default_equals_float_nan_and_signed_zero() -> None:
    assert default_equals(float("nan"), float("nan"))
    assert default_equals(1.5, 1.5)
    assert not default_equals(0.0, -0.0)
    assert not default_equals(float("inf"), float("-inf"))


def test_default_equals_rejects_ambiguous_comparisons() -> None:
    class Weird:
        def __eq__(self, other: object) -> object:  # returns non-bool
            return [True]

    with pytest.raises(CertificationError, match="pass a custom equals"):
        default_equals(Weird(), Weird())


def test_equivalence_checker_requires_qualified_name(tmp_path: Path) -> None:
    project = CertifiedProject(project_root=tmp_path)
    with pytest.raises(ValueError, match="package-qualified"):
        project.equivalence_checker("dot")


def test_build_certification_project_requires_native_module(tmp_path: Path) -> None:
    # A fallback-only project builds fine but certifies nothing: the kit must
    # refuse instead of vacuously passing every equivalence check.
    source = tmp_path / "src" / "plain_app" / "mod.py"
    source.parent.mkdir(parents=True)
    (source.parent / "__init__.py").write_text("", encoding="utf-8")
    source.write_text(
        """
def untyped(value):
    return value
""",
        encoding="utf-8",
    )
    with pytest.raises(CertificationError, match="requires a built native module"):
        build_certification_project(tmp_path)


def test_rule_record_verified_field_is_optional() -> None:
    base = dict(
        id="rextio-numpy/dot-float64",
        provider="rextio-numpy",
        scope=RuleScope(kind="call", pattern="numpy.dot"),
        constraint="c",
        outcome="native",
        diagnostic_code="RXTP-NUMPY-002",
        guidance="g",
        stability="experimental",
    )
    unset = RuleRecord(**base)
    assert "verified" not in unset.to_dict()
    verified = RuleRecord(**base, verified=True)
    assert verified.to_dict()["verified"] is True
