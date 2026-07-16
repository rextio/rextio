"""Soundness regressions for WP-4 follow-up 14."""

from __future__ import annotations

from pathlib import Path

import pytest

from rextio.analyzer.project_scanner import analyze_project


def _analyze(root: Path, files: dict[str, str]):
    for relative, source in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    return analyze_project(root, native_marker="decorator")


def _project() -> dict[str, str]:
    return {
        "pkg/__init__.py": "",
        "pkg/helper.py": (
            "import rextio\n\n@rextio.native\ndef good(x: int) -> int:\n    return x + 1\n"
        ),
        "pkg/other.py": (
            "import rextio\n\n@rextio.native\ndef good(x: int) -> int:\n    return x + 2\n"
            "def hidden(x):\n    return x\n"
        ),
    }


def _route(analysis, qualname: str) -> str:
    return next(
        function.route
        for module in analysis.modules
        for function in module.functions
        if function.qualname == qualname
    )


@pytest.mark.parametrize(
    "body, mutation",
    [
        (
            "    result = {'slot': helper}\n    return result\n",
            "selected = choose()\nselected['slot'].good = lambda x: x + 10\n",
        ),
        (
            "    result = {'outer': [({'slot': helper},)]}\n    return result\n",
            "choose()['outer'][0][0]['slot'].good = lambda x: x + 10\n",
        ),
        (
            "    result = ({'slot': helper},)\n    return result\n",
            "selected = choose()\nselected[0]['slot'].good = lambda x: x + 10\n",
        ),
    ],
)
def test_mutable_local_structured_returns_preserve_exposure_after_widening(
    tmp_path: Path, body: str, mutation: str
) -> None:
    files = _project()
    files["pkg/boot.py"] = f"from . import helper\ndef choose():\n{body}{mutation}"
    analysis = _analyze(tmp_path, files)
    assert analysis.project_mutations.target_is_mutated("pkg.helper.good")
    assert analysis.project_mutations.target_is_mutated("pkg.helper.slot.good")
    assert _route(analysis, "pkg.helper.good") != "native-direct"


def test_conditional_mutable_return_preserves_each_exposed_branch(tmp_path: Path) -> None:
    files = _project()
    files["pkg/boot.py"] = (
        "from . import helper, other\n"
        "def choose():\n"
        "    result = {'slot': helper} if FLAG else {'slot': other}\n"
        "    return result\n"
        "selected = choose()\n"
        "selected['slot'].good = lambda x: x + 10\n"
    )
    analysis = _analyze(tmp_path, files)
    assert analysis.project_mutations.target_is_mutated("pkg.helper.good")
    assert analysis.project_mutations.target_is_mutated("pkg.other.good")
    assert analysis.project_mutations.target_is_mutated("pkg.helper.slot.good")


def test_partially_unknown_local_structure_retains_exposure_and_widens(
    tmp_path: Path,
) -> None:
    files = _project()
    files["pkg/boot.py"] = (
        "from . import helper\n"
        "def choose():\n"
        "    result = {'slot': helper, 'unknown': dynamic()}\n"
        "    return result\n"
        "selected = choose()\n"
        "selected['slot'].good = lambda x: x + 10\n"
    )
    analysis = _analyze(tmp_path, files)
    assert analysis.project_mutations.target_is_mutated("pkg.helper")
    assert analysis.project_mutations.target_is_mutated("pkg.other.hidden")


def test_mutated_local_structure_becomes_unknown_with_original_and_new_exposure(
    tmp_path: Path,
) -> None:
    files = _project()
    files["pkg/boot.py"] = (
        "from . import helper, other\n"
        "def choose():\n"
        "    result = {'slot': helper}\n"
        "    result['slot'] = other\n"
        "    return result\n"
        "selected = choose()\n"
        "selected['slot'].good = lambda x: x + 10\n"
    )
    analysis = _analyze(tmp_path, files)
    assert analysis.project_mutations.target_is_mutated("pkg.helper")
    assert analysis.project_mutations.target_is_mutated("pkg.other")


@pytest.mark.parametrize("assigned", [False, True])
def test_clean_scalar_structured_return_stays_closed(tmp_path: Path, assigned: bool) -> None:
    files = _project()
    use = "selected = choose()\nlen(selected[0])\n" if assigned else "len(choose()[0])\n"
    files["pkg/boot.py"] = f"def choose():\n    result = ((1, (2, 3)),)\n    return result\n{use}"
    analysis = _analyze(tmp_path, files)
    assert _route(analysis, "pkg.helper.good") == "native-direct"


@pytest.mark.parametrize(
    "builtin, argument",
    [("id", "helper"), ("len", "(1, 2)"), ("range", "3")],
)
@pytest.mark.parametrize("binding", ["alias = {builtin}", "first = {builtin}\nalias, = (first,)"])
def test_mutated_bare_builtin_alias_revokes_identity_and_purity(
    tmp_path: Path, builtin: str, argument: str, binding: str
) -> None:
    files = _project()
    files["pkg/boot.py"] = (
        "from . import helper\n"
        "import builtins\n"
        f"builtins.{builtin} = lambda *args: 0\n"
        f"{binding.format(builtin=builtin)}\n"
        f"alias({argument})\n"
    )
    analysis = _analyze(tmp_path, files)
    assert analysis.project_mutations.target_is_mutated(f"builtins.{builtin}")
    assert _route(analysis, "pkg.helper.good") != "native-direct"


@pytest.mark.parametrize(
    "setup, call",
    [
        ("alias = id", "alias(helper)"),
        ("first = len\nalias, = (first,)", "alias((1, 2))"),
        ("first = range\nalias = first", "tuple(alias(3))"),
        ("def len(value):\n    return 1\nalias = len", "alias((1, 2))"),
    ],
)
def test_clean_or_shadowed_builtin_alias_controls_stay_closed(
    tmp_path: Path, setup: str, call: str
) -> None:
    files = _project()
    files["pkg/boot.py"] = f"from . import helper\n{setup}\n{call}\n"
    analysis = _analyze(tmp_path, files)
    assert _route(analysis, "pkg.helper.good") == "native-direct"


@pytest.mark.parametrize(
    "argument",
    [
        "[helper for _ in (0,)]",
        "{helper for _ in (0,)}",
        "{'slot': helper for _ in (0,)}",
        "(helper for _ in (0,))",
        "[{'nested': (helper if FLAG else other)} for _ in (0,)]",
        "[[helper for _ in (0,)] for _ in (0,)]",
        "[chosen for _ in (0,) if ((chosen := helper) or True)]",
    ],
)
def test_opaque_exposure_recurses_through_all_comprehensions(tmp_path: Path, argument: str) -> None:
    files = _project()
    files["pkg/boot.py"] = (
        f"from . import helper, other\nfrom external_package import touch\ntouch({argument})\n"
    )
    analysis = _analyze(tmp_path, files)
    assert _route(analysis, "pkg.helper.good") != "native-direct"


def test_opaque_exposure_of_unknown_comprehension_widens_project(tmp_path: Path) -> None:
    files = _project()
    files["pkg/boot.py"] = (
        "from external_package import values, touch\ntouch([value for value in values])\n"
    )
    analysis = _analyze(tmp_path, files)
    assert analysis.project_mutations.target_is_mutated("pkg.helper.good")
    assert analysis.project_mutations.target_is_mutated("pkg.other.hidden")


@pytest.mark.parametrize(
    "argument",
    [
        "[value + 1 for value in (1, 2)]",
        "{value for value in (1, 2)}",
        "{value: value + 1 for value in (1, 2)}",
        "(value + 1 for value in (1, 2))",
    ],
)
def test_clean_scalar_comprehensions_do_not_poison(tmp_path: Path, argument: str) -> None:
    files = _project()
    files["pkg/boot.py"] = f"from external_package import touch\ntouch({argument})\n"
    analysis = _analyze(tmp_path, files)
    assert _route(analysis, "pkg.helper.good") == "native-direct"


def test_project_root_used_only_as_closed_comprehension_input_is_not_exposed(
    tmp_path: Path,
) -> None:
    files = _project()
    files["pkg/boot.py"] = (
        "from . import helper\nfrom external_package import touch\ntouch([1 for _ in (helper,)])\n"
    )
    analysis = _analyze(tmp_path, files)
    assert _route(analysis, "pkg.helper.good") == "native-direct"
