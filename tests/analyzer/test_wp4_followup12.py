"""Merge-gate regressions for WP-4 follow-up 12."""

from __future__ import annotations

from pathlib import Path

import pytest

from rextio.analyzer.final_bindings import logger_group_target
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


def _helper_project() -> dict[str, str]:
    return {
        "pkg/__init__.py": "",
        "pkg/helper.py": (
            "import rextio\n\n@rextio.native\ndef good(x: int) -> int:\n    return x + 1\n"
        ),
        "pkg/consumer.py": (
            "import rextio\n"
            "from . import helper\n\n"
            "@rextio.native\n"
            "def call(x: int) -> int:\n"
            "    return helper.good(x)\n"
        ),
    }


def test_two_module_circular_early_call_uses_historical_callable_globals(
    tmp_path: Path,
) -> None:
    files = _helper_project()
    files.update(
        {
            "pkg/left.py": (
                "from . import helper as target\n"
                "def mutate():\n"
                "    target.good = lambda x: x + 100\n"
                "from . import right\n"
                "from . import clean as target\n"
            ),
            "pkg/right.py": "from .left import mutate\nmutate()\n",
            "pkg/clean.py": "def good(x):\n    return x\n",
        }
    )
    analysis = _analyze(tmp_path, files)
    assert analysis.project_mutations.target_is_mutated("pkg.helper.good")
    assert _functions(analysis)["pkg.helper.good"].route != "native-direct"


def test_three_module_circular_early_call_uses_historical_callable_globals(
    tmp_path: Path,
) -> None:
    files = _helper_project()
    files.update(
        {
            "pkg/left.py": (
                "from . import helper as target\n"
                "def mutate():\n"
                "    target.good = lambda x: x + 100\n"
                "from . import middle\n"
                "from . import clean as target\n"
            ),
            "pkg/middle.py": "from . import right\n",
            "pkg/right.py": "from .left import mutate\nmutate()\n",
            "pkg/clean.py": "def good(x):\n    return x\n",
        }
    )
    analysis = _analyze(tmp_path, files)
    assert analysis.project_mutations.target_is_mutated("pkg.helper.good")


def test_clean_circular_imports_do_not_poison_unrelated_native_function(
    tmp_path: Path,
) -> None:
    files = _helper_project()
    files.update(
        {
            "pkg/left.py": "from . import right\ndef inspect():\n    return 1\n",
            "pkg/right.py": "from . import left\nleft.inspect()\n",
        }
    )
    analysis = _analyze(tmp_path, files)
    assert _functions(analysis)["pkg.helper.good"].route == "native-direct"


def test_non_cyclic_late_call_uses_final_not_stale_definition_alias(tmp_path: Path) -> None:
    files = _helper_project()
    files.update(
        {
            "pkg/clean.py": "def good(x):\n    return x\n",
            "pkg/mutator.py": (
                "from . import helper as target\n"
                "def mutate():\n"
                "    target.good = lambda x: x + 100\n"
                "from . import clean as target\n"
            ),
            "pkg/boot.py": "from .mutator import mutate\nmutate()\n",
        }
    )
    analysis = _analyze(tmp_path, files)
    assert not analysis.project_mutations.target_is_mutated("pkg.helper.good")
    assert analysis.project_mutations.target_is_mutated("pkg.clean.good")
    assert _functions(analysis)["pkg.helper.good"].route == "native-direct"


@pytest.mark.parametrize(
    "factory",
    [
        "choose().good = lambda x: x + 100",
        "alias = choose()\nalias.good = lambda x: x + 100",
    ],
)
def test_project_callable_return_alias_is_a_mutation_receiver(tmp_path: Path, factory: str) -> None:
    files = _helper_project()
    files["pkg/chooser.py"] = "from . import helper\ndef choose():\n    return helper\n"
    files["pkg/boot.py"] = f"from .chooser import choose\n{factory}\n"
    analysis = _analyze(tmp_path, files)
    assert analysis.project_mutations.target_is_mutated("pkg.helper.good")


def test_local_callable_default_and_conditional_return_aliases_are_tracked(
    tmp_path: Path,
) -> None:
    files = _helper_project()
    files["pkg/other.py"] = "def good(x):\n    return x\n"
    files["pkg/boot.py"] = (
        "from . import helper, other\n"
        "def choose(flag=True, target=helper):\n"
        "    return target if flag else other\n"
        "choose().good = lambda x: x + 100\n"
    )
    analysis = _analyze(tmp_path, files)
    assert analysis.project_mutations.target_is_mutated("pkg.helper.good")
    assert analysis.project_mutations.target_is_mutated("pkg.other.good")


@pytest.mark.parametrize("imported", [False, True])
def test_exact_scalar_default_return_does_not_poison_project(
    tmp_path: Path, imported: bool
) -> None:
    files = _helper_project()
    files["pkg/scalar.py"] = "def choose(value=1):\n    return value\n"
    if imported:
        files["pkg/boot.py"] = (
            "from .scalar import choose\n"
            "try:\n    choose().good = 1\nexcept AttributeError:\n    pass\n"
        )
    else:
        files["pkg/scalar.py"] += "try:\n    choose().good = 1\nexcept AttributeError:\n    pass\n"
    analysis = _analyze(tmp_path, files)
    assert _functions(analysis)["pkg.helper.good"].route == "native-direct"


def test_unknown_callable_return_used_as_receiver_fails_closed(tmp_path: Path) -> None:
    files = _helper_project()
    files["pkg/boot.py"] = (
        "from . import helper\n"
        "def choose():\n"
        "    return dynamic()\n"
        "choose().good = lambda x: x + 100\n"
    )
    analysis = _analyze(tmp_path, files)
    assert analysis.project_mutations.target_is_mutated("pkg.helper.good")


@pytest.mark.parametrize(
    "mutation",
    [
        "choose().good = lambda x: x + 100",
        "alias = choose()\nalias.good = lambda x: x + 100",
    ],
)
def test_partially_unknown_conditional_return_poison_is_not_dropped(
    tmp_path: Path, mutation: str
) -> None:
    files = _helper_project()
    files["pkg/other.py"] = "def good(x):\n    return x\ndef hidden(x):\n    return x\n"
    files["pkg/boot.py"] = (
        "from . import helper\n"
        "def choose():\n"
        "    return helper if FLAG else dynamic()\n"
        f"{mutation}\n"
    )
    analysis = _analyze(tmp_path, files)
    assert analysis.project_mutations.target_is_mutated("pkg.other.hidden")


@pytest.mark.parametrize(
    "receiver",
    [
        "logging.getLogger('shared')",
        "(logging.getLogger('shared') if FLAG else logging.getLogger('other'))",
        "[logging.getLogger('shared')][0]",
        "{'logger': logging.getLogger('shared')}['logger']",
        "(logger := logging.getLogger('shared'))",
        "make_logger()",
    ],
)
def test_logger_factory_expression_shapes_share_process_global_identity(
    tmp_path: Path, receiver: str
) -> None:
    make_logger = (
        "def make_logger():\n    return logging.getLogger('shared')\n"
        if "make_logger" in receiver
        else ""
    )
    analysis = _analyze(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/mutator.py": (
                f"import logging\n{make_logger}{receiver}.info = lambda *args: None\n"
            ),
            "pkg/consumer.py": (
                "import logging\nimport rextio\n"
                "logger = logging.getLogger('shared')\n\n"
                "@rextio.native\n"
                "def use(x: int) -> int:\n"
                "    logger.info('x=%s', x)\n"
                "    return x + 1\n"
            ),
        },
    )
    assert analysis.project_mutations.target_is_mutated(logger_group_target("shared"))
    assert _functions(analysis)["pkg.consumer.use"].route != "native-direct"


def test_different_direct_logger_factory_name_remains_clean(tmp_path: Path) -> None:
    analysis = _analyze(
        tmp_path,
        {
            "mutator.py": (
                "import logging\nlogging.getLogger('changed').info = lambda *args: None\n"
            ),
            "consumer.py": (
                "import logging\nimport rextio\n"
                "logger = logging.getLogger('clean')\n\n"
                "@rextio.native\n"
                "def use(x: int) -> int:\n"
                "    logger.info('x=%s', x)\n"
                "    return x + 1\n"
            ),
        },
    )
    assert not analysis.project_mutations.target_is_mutated(logger_group_target("clean"))
    assert _functions(analysis)["consumer.use"].route == "native-direct"


@pytest.mark.parametrize(
    "mutation",
    [
        "globals()['__builtins__']['ValueError'] = KeyError",
        "vars()['__builtins__']['ValueError'] = KeyError",
        "globals()['__builtins__'].ValueError = KeyError",
        "getattr(globals()['__builtins__'], '__dict__').update({'ValueError': KeyError})",
        "del vars()['__builtins__']['ValueError']",
    ],
)
def test_implicit_builtins_via_module_namespace_are_global_mutations(
    tmp_path: Path, mutation: str
) -> None:
    files = _helper_project()
    files["pkg/mutator.py"] = f"{mutation}\n"
    analysis = _analyze(tmp_path, files)
    assert analysis.project_mutations.target_is_mutated("builtins.ValueError")


@pytest.mark.parametrize("imported", [False, True])
def test_external_call_receiving_project_root_fails_closed(tmp_path: Path, imported: bool) -> None:
    files = _helper_project()
    files["pkg/external.py"] = "def touch(value):\n    return None\n"
    files["pkg/mutator.py"] = (
        "from . import helper\nfrom external_package import touch\ndef run():\n    touch(helper)\n"
    )
    if imported:
        files["pkg/boot.py"] = "from .mutator import run\nrun()\n"
    else:
        files["pkg/mutator.py"] += "run()\n"
    analysis = _analyze(tmp_path, files)
    assert analysis.project_mutations.target_is_mutated("pkg.helper.good")


def test_proven_pure_builtin_in_project_callable_does_not_poison(tmp_path: Path) -> None:
    files = _helper_project()
    files["pkg/inspect.py"] = "def run():\n    return len((1, 2, 3))\n"
    files["pkg/boot.py"] = "from .inspect import run\nrun()\n"
    analysis = _analyze(tmp_path, files)
    assert _functions(analysis)["pkg.helper.good"].route == "native-direct"


def test_circular_import_callback_uses_pre_store_name_alias(tmp_path: Path) -> None:
    files = _helper_project()
    files.update(
        {
            "pkg/left.py": (
                "from . import helper as target\n"
                "def mutate():\n"
                "    target.good = lambda x: x + 100\n"
                "from . import right as target\n"
            ),
            "pkg/right.py": "from .left import mutate\nmutate()\n",
        }
    )
    analysis = _analyze(tmp_path, files)
    assert analysis.project_mutations.target_is_mutated("pkg.helper.good")
    assert not analysis.project_mutations.target_is_mutated("pkg.right.good")


@pytest.mark.parametrize(
    "rebind",
    [
        "(target := other)",
        "if True:\n    target = other",
    ],
)
def test_circular_import_widens_non_simple_pre_edge_rebinding(tmp_path: Path, rebind: str) -> None:
    files = _helper_project()
    files.update(
        {
            "pkg/other.py": "def good(x):\n    return x\n",
            "pkg/left.py": (
                "from . import helper as target\n"
                "from . import other\n"
                "def mutate():\n"
                "    target.good = lambda x: x + 100\n"
                f"{rebind}\n"
                "from . import right\n"
            ),
            "pkg/right.py": "from .left import mutate\nmutate()\n",
        }
    )
    analysis = _analyze(tmp_path, files)
    assert analysis.project_mutations.target_is_mutated("pkg.other.good")


def test_global_dynamic_rebind_propagates_unknown_and_clears_scalar(
    tmp_path: Path,
) -> None:
    files = _helper_project()
    files["pkg/mutator.py"] = (
        "from external_package import dynamic\n"
        "x = 1\n"
        "def reset():\n"
        "    global x\n"
        "    x = dynamic()\n"
        "reset()\n"
        "x.good = lambda value: value\n"
    )
    analysis = _analyze(tmp_path, files)
    assert analysis.project_mutations.target_is_mutated("pkg.helper.good")


def test_source_constructor_effects_fail_closed(tmp_path: Path) -> None:
    files = _helper_project()
    files["pkg/mutator.py"] = (
        "from . import helper\n"
        "class Evil:\n"
        "    def __init__(self):\n"
        "        helper.good = lambda x: x + 100\n"
        "def run():\n"
        "    Evil()\n"
        "run()\n"
    )
    analysis = _analyze(tmp_path, files)
    assert analysis.project_mutations.target_is_mutated("pkg.helper.good")


def test_builtin_protocol_hook_operand_is_not_assumed_pure(tmp_path: Path) -> None:
    files = _helper_project()
    files["pkg/mutator.py"] = (
        "from . import helper\n"
        "class Evil:\n"
        "    def __len__(self):\n"
        "        helper.good = lambda x: x + 100\n"
        "        return 0\n"
        "evil = Evil()\n"
        "def run():\n"
        "    return len(evil)\n"
        "run()\n"
    )
    analysis = _analyze(tmp_path, files)
    assert analysis.project_mutations.target_is_mutated("pkg.helper.good")


@pytest.mark.parametrize(
    "argument_setup, argument",
    [
        ("", "{'target': helper}"),
        ("    value = dynamic()\n", "value"),
    ],
)
def test_external_callee_exposure_recurses_and_rejects_unknown_aliases(
    tmp_path: Path, argument_setup: str, argument: str
) -> None:
    files = _helper_project()
    files["pkg/mutator.py"] = (
        "from . import helper\n"
        "from external_package import dynamic, touch\n"
        "def run():\n"
        f"{argument_setup}"
        f"    touch({argument})\n"
        "run()\n"
    )
    analysis = _analyze(tmp_path, files)
    assert analysis.project_mutations.target_is_mutated("pkg.helper.good")


@pytest.mark.parametrize(
    "mutation",
    [
        "setattr(dynamic(), 'good', lambda x: x)",
        "delattr(dynamic(), 'good')",
        "dynamic().update({'good': lambda x: x})",
    ],
)
def test_unknown_return_mutation_syntaxes_fail_closed_at_module_scope(
    tmp_path: Path, mutation: str
) -> None:
    files = _helper_project()
    files["pkg/mutator.py"] = f"from external_package import dynamic\n{mutation}\n"
    analysis = _analyze(tmp_path, files)
    assert analysis.project_mutations.target_is_mutated("pkg.helper.good")


def test_zero_argument_vars_inside_function_is_not_module_namespace(
    tmp_path: Path,
) -> None:
    analysis = _analyze(
        tmp_path,
        {
            "mod.py": (
                "import rextio\n\n"
                "@rextio.native\n"
                "def good(x: int) -> int:\n"
                "    return x + 1\n\n"
                "def inspect():\n"
                "    vars()['good'] = object()\n\n"
                "inspect()\n"
            )
        },
    )
    assert _functions(analysis)["mod.good"].route == "native-direct"
