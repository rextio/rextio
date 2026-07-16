"""Soundness regressions for WP-4 follow-up 15."""

from __future__ import annotations

from pathlib import Path

import pytest

from rextio.analyzer.project_scanner import analyze_project


def _analyze(root: Path, boot: str):
    sources = {
        "pkg/__init__.py": "",
        "pkg/helper.py": (
            "import rextio\n\n@rextio.native\ndef good(x: int) -> int:\n    return x + 1\n"
        ),
        "pkg/other.py": (
            "import rextio\n\n@rextio.native\ndef good(x: int) -> int:\n    return x + 2\n"
        ),
        "pkg/boot.py": boot,
    }
    for relative, source in sources.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    return analyze_project(root, native_marker="decorator")


def _route(analysis, qualname: str) -> str:
    return next(
        function.route
        for module in analysis.modules
        for function in module.functions
        if function.qualname == qualname
    )


def _assert_both_project_roots_invalidated(analysis) -> None:
    assert analysis.project_mutations.target_is_mutated("pkg.helper.good")
    assert analysis.project_mutations.target_is_mutated("pkg.other.good")
    assert _route(analysis, "pkg.helper.good") != "native-direct"
    assert _route(analysis, "pkg.other.good") != "native-direct"


def test_alias_before_return_cannot_leave_stale_container_shape(tmp_path: Path) -> None:
    analysis = _analyze(
        tmp_path,
        "from . import helper, other\n"
        "result = {'slot': helper}\n"
        "alias = result\n"
        "alias['slot'] = other\n"
        "def choose():\n"
        "    return result\n"
        "selected = choose()\n"
        "selected['slot'].good = lambda x: x + 10\n",
    )
    _assert_both_project_roots_invalidated(analysis)


@pytest.mark.parametrize(
    "body",
    [
        (
            "result = {'slot': helper}\n"
            "def choose():\n"
            "    return result\n"
            "selected = choose()\n"
            "alias = selected\n"
            "alias['slot'] = other\n"
        ),
        ("result = [{'slot': helper}]\nalias = result\nalias.append(other)\n"),
        ("result = {helper}\nalias = result\nalias.add(other)\n"),
        ("result = ({'slot': helper},)\nalias = result\nalias[0]['slot'] = other\n"),
        (
            "result = {'outer': ([{'slot': helper}],)}\n"
            "first = result\n"
            "second = first\n"
            "second['outer'][0][0]['slot'] = other\n"
        ),
    ],
)
def test_mutable_container_alias_variants_invalidate_all_exposed_roots(
    tmp_path: Path, body: str
) -> None:
    analysis = _analyze(tmp_path, f"from . import helper, other\n{body}")
    _assert_both_project_roots_invalidated(analysis)


def test_direct_mutable_return_is_widened_before_caller_binding(tmp_path: Path) -> None:
    analysis = _analyze(
        tmp_path,
        "from . import helper, other\n"
        "def choose():\n"
        "    return {'slot': helper}\n"
        "selected = choose()\n"
        "selected['slot'] = other\n",
    )
    _assert_both_project_roots_invalidated(analysis)


@pytest.mark.parametrize(
    "body",
    [
        (
            "result = {'slot': helper}\n"
            "def mutate(alias):\n"
            "    alias['slot'] = other\n"
            "mutate(result)\n"
        ),
        (
            "result = {'slot': helper}\n"
            "def mutate(alias=result):\n"
            "    alias['slot'] = other\n"
            "mutate()\n"
        ),
        "left = right = {'slot': helper}\nright['slot'] = other\n",
        ("result = [{'slot': helper}]\nfor alias in result:\n    alias['slot'] = other\n"),
    ],
)
def test_parameter_default_shared_and_iteration_aliases_widen(tmp_path: Path, body: str) -> None:
    analysis = _analyze(tmp_path, f"from . import helper, other\n{body}")
    _assert_both_project_roots_invalidated(analysis)


def test_delete_through_alias_invalidates_preexisting_exposure(tmp_path: Path) -> None:
    analysis = _analyze(
        tmp_path,
        "from . import helper\nresult = {'slot': helper}\nalias = result\ndel alias['slot']\n",
    )
    assert analysis.project_mutations.target_is_mutated("pkg.helper.good")
    assert not analysis.project_mutations.target_is_mutated("pkg.other.good")


def test_aliased_scalar_only_container_does_not_poison_project(tmp_path: Path) -> None:
    analysis = _analyze(
        tmp_path,
        "result = {'slot': [1]}\nalias = result\nalias['slot'].append(2)\n",
    )
    assert _route(analysis, "pkg.helper.good") == "native-direct"
    assert _route(analysis, "pkg.other.good") == "native-direct"


def test_immutable_tuple_alias_retains_precise_root_selection(tmp_path: Path) -> None:
    analysis = _analyze(
        tmp_path,
        "from . import helper\n"
        "result = (helper,)\n"
        "alias = result\n"
        "alias[0].good = lambda x: x + 10\n",
    )
    assert analysis.project_mutations.target_is_mutated("pkg.helper.good")
    assert not analysis.project_mutations.target_is_mutated("pkg.other.good")


def test_fresh_literal_direct_selection_stays_precise(tmp_path: Path) -> None:
    analysis = _analyze(
        tmp_path,
        "from . import helper\n{'slot': helper}['slot'].good = lambda x: x + 10\n",
    )
    assert analysis.project_mutations.target_is_mutated("pkg.helper.good")
    assert not analysis.project_mutations.target_is_mutated("pkg.other.good")
