"""Independent merge-gate regressions for WP-4 follow-up 11."""

from __future__ import annotations

from pathlib import Path

import pytest

from rextio.analyzer.final_bindings import (
    logger_group_target,
    logger_unknown_group_target,
)
from rextio.analyzer.project_scanner import analyze_project


def _analyze(root: Path, files: dict[str, str]):
    for relative, source in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    return analyze_project(root, native_marker="decorator")


def _functions(analysis):
    return {
        function.qualname: function for module in analysis.modules for function in module.functions
    }


@pytest.mark.parametrize(
    "loop",
    [
        (
            "alias = left\n"
            "for _item in (0, 1):\n"
            "    alias.good = lambda x: x + 100\n"
            "    alias = right\n"
        ),
        (
            "alias = left\n"
            "count = 0\n"
            "while count < 2:\n"
            "    alias.good = lambda x: x + 100\n"
            "    alias = right\n"
            "    count += 1\n"
        ),
    ],
)
def test_loop_mutation_replay_reaches_a_sound_fixed_point(tmp_path: Path, loop: str) -> None:
    analysis = _analyze(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/left.py": "def good(x):\n    return x + 1\n",
            "pkg/right.py": "def good(x):\n    return x + 2\n",
            "pkg/mutator.py": (f"import pkg.left as left\nimport pkg.right as right\n{loop}"),
        },
    )
    assert analysis.project_mutations.target_is_mutated("pkg.left.good")
    assert analysis.project_mutations.target_is_mutated("pkg.right.good")


def test_loop_swap_break_continue_and_else_retain_every_possible_root(
    tmp_path: Path,
) -> None:
    analysis = _analyze(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/left.py": "def good(x):\n    return x + 1\n",
            "pkg/right.py": "def good(x):\n    return x + 2\n",
            "pkg/mutator.py": (
                "import pkg.left as left\n"
                "import pkg.right as right\n"
                "for _item in (0, 1):\n"
                "    left, right = right, left\n"
                "    left.good = lambda x: x + 100\n"
                "    if _item:\n"
                "        break\n"
                "    continue\n"
                "else:\n"
                "    right.good = lambda x: x + 200\n"
            ),
        },
    )
    assert analysis.project_mutations.target_is_mutated("pkg.left.good")
    assert analysis.project_mutations.target_is_mutated("pkg.right.good")


def test_clean_simple_loops_do_not_poison_native_candidates(tmp_path: Path) -> None:
    analysis = _analyze(
        tmp_path,
        {
            "loops.py": (
                "total = 0\n"
                "for value in (1, 2, 3):\n"
                "    total += value\n"
                "while total < 4:\n"
                "    total += 1\n"
            ),
            "ops.py": (
                "import rextio\n\n@rextio.native\ndef good(x: int) -> int:\n    return x + 1\n"
            ),
        },
    )
    assert _functions(analysis)["ops.good"].route == "native-direct"


def _logger_project(
    mutation_factory: str,
    consumer_factory: str,
    *,
    mutation_alias: str = "logger",
) -> dict[str, str]:
    return {
        "pkg/__init__.py": "",
        "pkg/mutator.py": (
            "import logging\n"
            f"logger = {mutation_factory}\n"
            f"alias = {mutation_alias}\n"
            "alias.info = lambda *args: None\n"
        ),
        "pkg/consumer.py": (
            "import logging\n"
            "import rextio\n"
            f"logger = {consumer_factory}\n\n"
            "@rextio.native\n"
            "def use(x: int) -> int:\n"
            "    logger.info('x=%s', x)\n"
            "    return x + 1\n"
        ),
    }


def test_same_named_loggers_share_process_global_identity(tmp_path: Path) -> None:
    analysis = _analyze(
        tmp_path,
        _logger_project(
            "logging.getLogger('shared')",
            "logging.getLogger('shared')",
        ),
    )
    assert analysis.project_mutations.target_is_mutated(logger_group_target("shared"))
    assert _functions(analysis)["pkg.consumer.use"].route != "native-direct"


def test_provably_different_logger_names_remain_independent(tmp_path: Path) -> None:
    analysis = _analyze(
        tmp_path,
        _logger_project(
            "logging.getLogger('mutated')",
            "logging.getLogger('clean')",
        ),
    )
    assert analysis.project_mutations.target_is_mutated(logger_group_target("mutated"))
    assert not analysis.project_mutations.target_is_mutated(logger_group_target("clean"))
    assert _functions(analysis)["pkg.consumer.use"].route == "native-direct"


@pytest.mark.parametrize(
    ("mutation_factory", "consumer_factory"),
    [
        ("logging.getLogger()", "logging.getLogger(None)"),
        ("logging.getLogger(None)", "logging.getLogger('')"),
    ],
)
def test_root_logger_spellings_share_process_global_identity(
    tmp_path: Path,
    mutation_factory: str,
    consumer_factory: str,
) -> None:
    analysis = _analyze(
        tmp_path,
        _logger_project(mutation_factory, consumer_factory),
    )
    assert analysis.project_mutations.target_is_mutated(logger_group_target(None))
    assert _functions(analysis)["pkg.consumer.use"].route != "native-direct"


def test_dynamic_logger_mutation_invalidates_every_possible_named_logger(
    tmp_path: Path,
) -> None:
    files = _logger_project(
        "logging.getLogger(NAME)",
        "logging.getLogger('shared')",
    )
    files["pkg/mutator.py"] = (
        "import logging\n"
        "NAME = ''.join(('sha', 'red'))\n"
        "logger = logging.getLogger(NAME)\n"
        "alias = logger\n"
        "alias.info = lambda *args: None\n"
    )
    analysis = _analyze(tmp_path, files)
    assert analysis.project_mutations.target_is_mutated(logger_unknown_group_target())
    assert analysis.project_mutations.target_is_mutated(logger_group_target("shared"))
    assert _functions(analysis)["pkg.consumer.use"].route != "native-direct"


def test_exact_logger_name_constants_are_shared_across_modules(tmp_path: Path) -> None:
    files = _logger_project(
        "logging.getLogger(NAME)",
        "logging.getLogger(ALIAS)",
    )
    files["pkg/mutator.py"] = (
        "import logging\n"
        "NAME = 'shared'\n"
        "logger = logging.getLogger(NAME)\n"
        "alias = logger\n"
        "alias.info = lambda *args: None\n"
    )
    files["pkg/consumer.py"] = (
        "import logging\n"
        "import rextio\n"
        "NAME = 'shared'\n"
        "ALIAS = NAME\n"
        "logger = logging.getLogger(ALIAS)\n\n"
        "@rextio.native\n"
        "def use(x: int) -> int:\n"
        "    logger.info('x=%s', x)\n"
        "    return x + 1\n"
    )
    analysis = _analyze(tmp_path, files)
    assert analysis.project_mutations.target_is_mutated(logger_group_target("shared"))
    assert _functions(analysis)["pkg.consumer.use"].route != "native-direct"


def test_conditionally_rebound_logger_name_does_not_retain_stale_constant(
    tmp_path: Path,
) -> None:
    files = _logger_project(
        "logging.getLogger('mutated')",
        "logging.getLogger(NAME)",
    )
    files["pkg/consumer.py"] = (
        "import logging\n"
        "import rextio\n"
        "NAME = 'clean'\n"
        "if FLAG:\n"
        "    NAME = 'mutated'\n"
        "logger = logging.getLogger(NAME)\n\n"
        "@rextio.native\n"
        "def use(x: int) -> int:\n"
        "    logger.info('x=%s', x)\n"
        "    return x + 1\n"
    )
    analysis = _analyze(tmp_path, files)
    assert analysis.project_mutations.target_is_mutated(logger_group_target("mutated"))
    assert _functions(analysis)["pkg.consumer.use"].route != "native-direct"


def test_nonconverging_loop_logger_name_widens_to_unknown_group(tmp_path: Path) -> None:
    analysis = _analyze(
        tmp_path,
        {
            "mutator.py": (
                "import logging\n"
                "name = 'x'\n"
                "for _item in values:\n"
                "    logger = logging.getLogger(name)\n"
                "    logger.info = lambda *args: None\n"
                "    name = name + 'x'\n"
            )
        },
    )
    assert analysis.project_mutations.target_is_mutated(logger_unknown_group_target())


@pytest.mark.parametrize(
    "mutation",
    [
        "__builtins__['ValueError'] = KeyError",
        "__builtins__.ValueError = KeyError",
        "del __builtins__['ValueError']",
        "__builtins__.update({'ValueError': KeyError})",
        "__builtins__.__dict__.update({'ValueError': KeyError})",
    ],
)
def test_implicit_builtins_mutation_blocks_cross_module_exception_identity(
    tmp_path: Path,
    mutation: str,
) -> None:
    analysis = _analyze(
        tmp_path,
        {
            "mutator.py": f"{mutation}\n",
            "ops.py": (
                "import rextio\n\n"
                "@rextio.native\n"
                "def guarded(xs: list[int]) -> int:\n"
                "    out = 0\n"
                "    try:\n"
                "        out = xs[0]\n"
                "    except ValueError:\n"
                "        out = -1\n"
                "    return out\n"
            ),
        },
    )
    assert analysis.project_mutations.target_is_mutated("builtins.ValueError")
    assert _functions(analysis)["ops.guarded"].route != "native-direct"


def test_unrelated_implicit_builtin_mutation_does_not_block_value_error(
    tmp_path: Path,
) -> None:
    analysis = _analyze(
        tmp_path,
        {
            "mutator.py": "__builtins__['RuntimeError'] = Exception\n",
            "ops.py": (
                "import rextio\n\n"
                "@rextio.native\n"
                "def guarded(xs: list[int]) -> int:\n"
                "    out = 0\n"
                "    try:\n"
                "        out = xs[0]\n"
                "    except ValueError:\n"
                "        out = -1\n"
                "    return out\n"
            ),
        },
    )
    assert analysis.project_mutations.target_is_mutated("builtins.RuntimeError")
    assert not analysis.project_mutations.target_is_mutated("builtins.ValueError")
    assert _functions(analysis)["ops.guarded"].route == "native-direct"


def _imported_mutator_project(boot: str, mutator: str) -> dict[str, str]:
    return {
        "pkg/__init__.py": "",
        "pkg/helper.py": (
            "import rextio\n\n@rextio.native\ndef good(x: int) -> int:\n    return x + 1\n"
        ),
        "pkg/mutator.py": mutator,
        "pkg/boot.py": boot,
        "pkg/consumer.py": (
            "import rextio\n"
            "from . import helper\n\n"
            "@rextio.native\n"
            "def caller(x: int) -> int:\n"
            "    return helper.good(x)\n"
        ),
    }


def test_executed_exact_relative_imported_mutator_body_is_replayed(
    tmp_path: Path,
) -> None:
    analysis = _analyze(
        tmp_path,
        _imported_mutator_project(
            "from .mutator import mutate\nmutate()\n",
            ("from . import helper\n\ndef mutate():\n    helper.good = lambda x: x + 100\n"),
        ),
    )
    functions = _functions(analysis)
    assert "pkg.helper" not in analysis.project_mutations.unknown_modules
    assert "good" in analysis.project_mutations.by_module["pkg.helper"]
    assert analysis.project_mutations.target_is_mutated("pkg.helper.good")
    assert functions["pkg.helper.good"].accepted is False
    assert functions["pkg.consumer.caller"].route != "native-direct"


def test_clean_exact_imported_callable_does_not_poison_project(tmp_path: Path) -> None:
    analysis = _analyze(
        tmp_path,
        _imported_mutator_project(
            "from .mutator import inspect\ninspect(1)\n",
            "def inspect(value):\n    return value + 1\n",
        ),
    )
    assert _functions(analysis)["pkg.helper.good"].route == "native-direct"
    assert _functions(analysis)["pkg.consumer.caller"].route == "native-direct"


def test_unknown_imported_callable_and_import_cycle_fail_closed(
    tmp_path: Path,
) -> None:
    analysis = _analyze(
        tmp_path,
        {
            **_imported_mutator_project(
                "from .mutator import first\nfirst()\n",
                ("from .other import second\n\ndef first():\n    second()\n"),
            ),
            "pkg/other.py": ("from .mutator import first\n\ndef second():\n    first()\n"),
        },
    )
    assert analysis.project_mutations.target_is_mutated("pkg.helper.good")
    assert _functions(analysis)["pkg.helper.good"].route != "native-direct"


def test_conditional_imported_callable_expression_fails_closed(tmp_path: Path) -> None:
    analysis = _analyze(
        tmp_path,
        _imported_mutator_project(
            (
                "from .mutator import inspect, mutate\n"
                "FLAG = object()\n"
                "(mutate if FLAG else inspect)()\n"
            ),
            (
                "from . import helper\n\n"
                "def inspect():\n"
                "    return None\n\n"
                "def mutate():\n"
                "    helper.good = lambda x: x + 100\n"
            ),
        ),
    )
    assert analysis.project_mutations.target_is_mutated("pkg.helper.good")
    assert _functions(analysis)["pkg.helper.good"].route != "native-direct"


def test_source_mutated_imported_callable_is_not_replayed_as_stale_source(
    tmp_path: Path,
) -> None:
    analysis = _analyze(
        tmp_path,
        _imported_mutator_project(
            (
                "from . import helper, mutator\n\n"
                "def replacement():\n"
                "    helper.good = lambda x: x + 100\n\n"
                "mutator.mutate = replacement\n"
                "from .mutator import mutate\n"
                "mutate()\n"
            ),
            "def mutate():\n    return None\n",
        ),
    )
    assert analysis.project_mutations.target_is_mutated("pkg.mutator.mutate")
    assert analysis.project_mutations.target_is_mutated("pkg.helper.good")
    assert _functions(analysis)["pkg.helper.good"].route != "native-direct"


def test_import_main_guard_does_not_execute_mutator_body(tmp_path: Path) -> None:
    analysis = _analyze(
        tmp_path,
        _imported_mutator_project(
            (
                "from . import helper\n"
                "if __name__ == '__main__':\n"
                "    helper.good = lambda x: x + 100\n"
            ),
            "",
        ),
    )
    assert not analysis.project_mutations.target_is_mutated("pkg.helper.good")
    assert _functions(analysis)["pkg.helper.good"].route == "native-direct"


def test_local_callable_default_binds_at_definition_time(tmp_path: Path) -> None:
    analysis = _analyze(
        tmp_path,
        _imported_mutator_project(
            (
                "from . import helper\n\n"
                "def mutate(target=helper):\n"
                "    target.good = lambda x: x + 100\n\n"
                "helper = object()\n"
                "mutate()\n"
            ),
            "",
        ),
    )
    assert analysis.project_mutations.target_is_mutated("pkg.helper.good")


def test_local_callable_keyword_override_wins_over_default(tmp_path: Path) -> None:
    files = _imported_mutator_project(
        (
            "from . import helper, other\n\n"
            "def mutate(target=other):\n"
            "    target.good = lambda x: x + 100\n\n"
            "mutate(target=helper)\n"
        ),
        "",
    )
    files["pkg/other.py"] = "def good(x):\n    return x + 2\n"
    analysis = _analyze(tmp_path, files)
    assert analysis.project_mutations.target_is_mutated("pkg.helper.good")
    assert not analysis.project_mutations.target_is_mutated("pkg.other.good")


@pytest.mark.parametrize(
    "boot",
    [
        (
            "from . import helper\n\n"
            "def choose():\n"
            "    return helper\n\n"
            "def mutate(target=choose()):\n"
            "    target.good = lambda x: x + 100\n\n"
            "mutate()\n"
        ),
        (
            "from . import helper\n\n"
            "def mutate(*targets):\n"
            "    targets[0].good = lambda x: x + 100\n\n"
            "mutate(helper)\n"
        ),
        (
            "from . import helper\n\n"
            "def choose():\n"
            "    return helper\n\n"
            "def mutate(target=[choose()][0]):\n"
            "    target.good = lambda x: x + 100\n\n"
            "mutate()\n"
        ),
    ],
)
def test_hostile_dynamic_defaults_and_complex_argument_binding_fail_closed(
    tmp_path: Path,
    boot: str,
) -> None:
    analysis = _analyze(
        tmp_path,
        _imported_mutator_project(boot, ""),
    )
    assert analysis.project_mutations.target_is_mutated("pkg.helper.good")
    assert _functions(analysis)["pkg.helper.good"].route != "native-direct"
