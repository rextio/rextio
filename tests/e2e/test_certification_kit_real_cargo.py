from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from rextio.plugins.testing import build_certification_project


@pytest.fixture(scope="module")
def certified_project(tmp_path_factory: pytest.TempPathFactory):
    root = tmp_path_factory.mktemp("certkit")
    (root / "rextio.toml").write_text('[rust]\nbuild_tool = "cargo"\n', encoding="utf-8")
    source = root / "src" / "cert_app" / "mathy.py"
    source.parent.mkdir(parents=True)
    (source.parent / "__init__.py").write_text("", encoding="utf-8")
    source.write_text(
        """
import rextio

@rextio.native
def add(a: int, b: int) -> int:
    return a + b

@rextio.native
def divide(a: float, b: float) -> float:
    return a / b
""",
        encoding="utf-8",
    )
    return build_certification_project(root)


def test_kit_certifies_matching_results(certified_project) -> None:
    add = certified_project.equivalence_checker("cert_app.mathy.add")
    assert add(2, 3) == 5
    assert add(-7, 7) == 0


def test_kit_surfaces_equivalent_exceptions(certified_project) -> None:
    divide = certified_project.equivalence_checker("cert_app.mathy.divide")
    assert divide(1.0, 2.0) == 0.5
    with pytest.raises(ZeroDivisionError):
        divide(1.0, 0.0)


@settings(max_examples=25, deadline=None)
@given(
    a=st.floats(allow_nan=False, allow_infinity=False, width=64),
    b=st.floats(allow_nan=False, allow_infinity=False, width=64),
)
def test_kit_composes_with_hypothesis(certified_project, a: float, b: float) -> None:
    # The composition pattern plugin certification suites use: hypothesis
    # drives inputs, the checker asserts leg equivalence per example (including
    # equivalent ZeroDivisionError raises for b == 0.0).
    divide = certified_project.equivalence_checker("cert_app.mathy.divide")
    try:
        divide(a, b)
    except ZeroDivisionError:
        pass
