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


def _write_check_report(tmp_path: Path, qualname: str, route: str, status: str) -> None:
    module_name, _, name = qualname.rpartition(".")
    report = {
        "modules": [
            {
                "module_name": module_name,
                "functions": [
                    {"qualname": qualname, "route": route, "native_status": status}
                ],
            }
        ]
    }
    reports = tmp_path / ".rextio" / "reports"
    reports.mkdir(parents=True)
    import json

    (reports / "check.json").write_text(json.dumps(report), encoding="utf-8")


def test_equivalence_checker_refuses_fallback_only_functions(tmp_path: Path) -> None:
    # Council M16: certifying a fallback-only symbol compares the fallback
    # against itself and passes vacuously.
    _write_check_report(tmp_path, "app.mod.f", "fallback-python", "rejected")
    project = CertifiedProject(project_root=tmp_path)
    with pytest.raises(CertificationError, match="not natively served"):
        project.equivalence_checker("app.mod.f")


def test_equivalence_checker_refuses_shim_functions(tmp_path: Path) -> None:
    _write_check_report(tmp_path, "app.mod.f", "native-shim", "accepted")
    project = CertifiedProject(project_root=tmp_path)
    with pytest.raises(CertificationError, match="not natively served"):
        project.equivalence_checker("app.mod.f")


def test_equivalence_checker_accepts_native_routes(tmp_path: Path) -> None:
    _write_check_report(tmp_path, "app.mod.f", "native-plugin:rextio-numpy", "accepted")
    project = CertifiedProject(project_root=tmp_path)
    checker = project.equivalence_checker("app.mod.f")
    assert checker.function_name == "f"


def test_equivalence_checker_requires_known_function(tmp_path: Path) -> None:
    _write_check_report(tmp_path, "app.mod.f", "native-direct", "accepted")
    project = CertifiedProject(project_root=tmp_path)
    with pytest.raises(CertificationError, match="was not found"):
        project.equivalence_checker("app.mod.other")


def test_args_equals_catches_in_place_mutation_divergence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Council T12 (round 3): a fallback that mutates an argument in place
    # while the native leg leaves its copy untouched returns identical
    # values — only the arguments' post-call state shows the divergence.
    import os

    from rextio.plugins.testing import EquivalenceChecker

    _write_check_report(tmp_path, "app.mod.f", "native-direct", "accepted")
    project = CertifiedProject(project_root=tmp_path)

    def constant_but_mutating(items: list[int]) -> int:
        if os.environ.get("REXTIO_NATIVE_MODE") == "fallback":
            items.append(99)
        return 0

    checker = EquivalenceChecker(
        project=project,
        module_name="app.mod",
        function_name="f",
        equals=default_equals,
        args_equals=lambda left, right: left == right,
    )
    monkeypatch.setattr(checker, "_load_function", lambda: constant_but_mutating)
    with pytest.raises(CertificationError, match="argument 0 diverged after the call"):
        checker([1, 2, 3])

    # Without args_equals the same divergence passes silently (return values
    # agree) — documenting that the opt-in is what adds the coverage.
    plain = EquivalenceChecker(
        project=project,
        module_name="app.mod",
        function_name="f",
        equals=default_equals,
    )
    monkeypatch.setattr(plain, "_load_function", lambda: constant_but_mutating)
    assert plain([1, 2, 3]) == 0
