"""Independent-review regressions for WP-4 follow-up 10."""

from __future__ import annotations

from pathlib import Path

import pytest

from rextio.analyzer.final_bindings import (
    ProjectMutations,
    logger_group_target,
    logger_object_target,
)
from rextio.analyzer.project_scanner import analyze_project
from rextio.ir.lowering import LoweringError, lower_project


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


def _stale_binding_source(effect: str, *, prelude: str = "") -> str:
    return (
        f"{prelude}"
        "import rextio\n\n"
        "@rextio.native\n"
        "def good(x: int) -> int:\n"
        "    return x + 100\n\n"
        f"{effect}\n\n"
        "import rextio\n\n"
        "@rextio.native\n"
        "def caller(x: int) -> int:\n"
        "    return good(x)\n"
    )


def _assert_stale_binding_rejected(analysis) -> None:
    functions = _functions(analysis)
    assert functions["ops.good"].accepted is False
    assert functions["ops.caller"].route != "native-direct"


def test_destructuring_uses_one_pre_assignment_snapshot(tmp_path: Path) -> None:
    analysis = _analyze(
        tmp_path,
        {
            "ops.py": (
                "import logging\n"
                "import rextio\n\n"
                "@rextio.native\n"
                "def good(x: int) -> int:\n"
                "    return x + 1\n\n"
                "def mutate(fn):\n"
                "    globals()['good'] = lambda x: x + 200\n"
                "    return fn\n\n"
                "logging.native = mutate\n"
                "a = rextio\n"
                "b = logging\n"
                "b, a = a, b\n\n"
                "@a.native\n"
                "def decoy(x: int) -> int:\n"
                "    return x\n\n"
                "import rextio\n\n"
                "@rextio.native\n"
                "def caller(x: int) -> int:\n"
                "    return good(x)\n"
            )
        },
    )
    _assert_stale_binding_rejected(analysis)


@pytest.mark.parametrize(
    ("assignment", "expected"),
    [
        ("left, right = right, left", "pkg.right.good"),
        ("left, left = right, left", "pkg.left.good"),
    ],
)
def test_mutation_collector_snapshots_swaps_and_duplicate_targets(
    tmp_path: Path,
    assignment: str,
    expected: str,
) -> None:
    analysis = _analyze(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/left.py": "def good(x): return x + 1\n",
            "pkg/right.py": "def good(x): return x + 2\n",
            "pkg/mutator.py": (
                "import pkg.left as left\n"
                "import pkg.right as right\n"
                f"{assignment}\n"
                "left.good = lambda x: x + 200\n"
            ),
        },
    )
    assert analysis.project_mutations.target_is_mutated(expected)


@pytest.mark.parametrize(
    ("method", "expression"),
    [
        ("__add__", "[trigger][0] + 1"),
        ("__neg__", "-[trigger][0]"),
        ("__eq__", "[trigger][0] == 1"),
        ("__format__", "f'{[trigger][0]}'"),
        ("__hash__", "{[trigger][0]}"),
        ("__hash__", "{[trigger][0]: 1}"),
    ],
)
def test_safe_subscription_dispatch_does_not_imply_safe_result(
    tmp_path: Path,
    method: str,
    expression: str,
) -> None:
    if method == "__format__":
        signature = "def __format__(self, spec):"
    elif method in {"__neg__", "__hash__"}:
        signature = f"def {method}(self):"
    else:
        signature = f"def {method}(self, other):"
    analysis = _analyze(
        tmp_path,
        {
            "ops.py": _stale_binding_source(
                f"_result = {expression}",
                prelude=(
                    "class Trigger:\n"
                    f"    {signature}\n"
                    "        globals()['good'] = lambda x: x + 200\n"
                    "        return 0\n\n"
                    "trigger = Trigger()\n"
                ),
            )
        },
    )
    _assert_stale_binding_rejected(analysis)


@pytest.mark.parametrize(
    "expression",
    [
        "{item for item in [trigger]}",
        "{item: 0 for item in [trigger]}",
    ],
)
def test_set_and_dict_comprehensions_account_for_hash_effects(
    tmp_path: Path,
    expression: str,
) -> None:
    analysis = _analyze(
        tmp_path,
        {
            "ops.py": _stale_binding_source(
                f"_result = {expression}",
                prelude=(
                    "class Trigger:\n"
                    "    def __hash__(self):\n"
                    "        globals()['good'] = lambda x: x + 200\n"
                    "        return 0\n\n"
                    "trigger = Trigger()\n"
                ),
            )
        },
    )
    _assert_stale_binding_rejected(analysis)


def test_closed_comprehensions_and_exact_scalar_propagation_stay_clean(
    tmp_path: Path,
) -> None:
    analysis = _analyze(
        tmp_path,
        {
            "ops.py": (
                "import rextio\n\n"
                "@rextio.native\n"
                "def good(x: int) -> int:\n"
                "    return x + 1\n\n"
                "CONST = 1\n"
                "VALUE = CONST + 2\n"
                "INDEX = 0\n"
                "SELECTED = [VALUE, 9][INDEX] + 1\n"
                "S = {item for item in [1, 2]}\n"
                "D = {item: item + 1 for item in [1, 2]}\n"
            )
        },
    )
    assert _functions(analysis)["ops.good"].route == "native-direct"


@pytest.mark.parametrize(
    "assignment",
    [
        "(r, *rest) = (rextio,)",
        "(r, extra) = (rextio,)",
        "(r,) = dynamic",
    ],
)
def test_unproven_unpack_preserves_possible_rextio_mutation_across_reimport(
    tmp_path: Path,
    assignment: str,
) -> None:
    dynamic = "dynamic = (rextio,)\n" if assignment.endswith("dynamic") else ""
    analysis = _analyze(
        tmp_path,
        {
            "ops.py": (
                "import rextio\n"
                f"{dynamic}"
                f"{assignment}\n"
                "r.native = lambda fn: (lambda x: x + 200)\n"
                "import rextio\n\n"
                "@rextio.native\n"
                "def f(x: int) -> int:\n"
                "    return x + 1\n"
            )
        },
    )
    assert analysis.project_mutations.target_is_mutated("rextio.native")
    assert _functions(analysis)["ops.f"].accepted is False


@pytest.mark.parametrize(
    "alias_statement",
    [
        "alias = [helper][0]",
        "alias = (helper,)[0]",
        "alias = helper if True else None",
        "alias = (tmp := helper)",
    ],
)
def test_closed_expression_aliases_preserve_project_mutation_authority(
    tmp_path: Path,
    alias_statement: str,
) -> None:
    analysis = _analyze(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/helper.py": (
                "import rextio\n\n@rextio.native\ndef good(x: int) -> int:\n    return x + 1\n"
            ),
            "pkg/mutator.py": (
                f"from . import helper\n{alias_statement}\nalias.good = lambda x: x + 200\n"
            ),
            "pkg/consumer.py": (
                "import rextio\n"
                "from . import helper\n\n"
                "@rextio.native\n"
                "def caller(x: int) -> int:\n"
                "    return helper.good(x)\n"
            ),
        },
    )
    functions = _functions(analysis)
    assert analysis.project_mutations.target_is_mutated("pkg.helper.good")
    assert functions["pkg.helper.good"].accepted is False
    assert functions["pkg.consumer.caller"].route != "native-direct"


@pytest.mark.parametrize(
    "alias_statement",
    [
        "logger = alias = logging.getLogger(__name__)",
        "logger = logging.getLogger(__name__)\nalias = [logger][0]",
        "logger = logging.getLogger(__name__)\nalias = logger if True else None",
        (
            "logger = logging.getLogger(__name__)\n"
            "if True:\n"
            "    alias = logger\n"
            "else:\n"
            "    alias = None"
        ),
        "logger = logging.getLogger(__name__)\nfor alias in [logger]:\n    pass",
        (
            "logger = logging.getLogger(__name__)\n"
            "other = logging.getLogger(__name__)\n"
            "alias = other"
        ),
    ],
)
def test_all_provably_shared_logger_aliases_invalidate_receiver(
    tmp_path: Path,
    alias_statement: str,
) -> None:
    analysis = _analyze(
        tmp_path,
        {
            "ops.py": (
                "import logging\n"
                "import rextio\n\n"
                f"{alias_statement}\n"
                "alias.info = lambda *args: None\n\n"
                "@rextio.native\n"
                "def f(x: int) -> int:\n"
                "    logger.info('x=%s', x)\n"
                "    return x + 1\n"
            )
        },
    )
    assert analysis.modules[0].logger_names == ()
    assert _functions(analysis)["ops.f"].route != "native-direct"


@pytest.mark.parametrize(
    "effect",
    [
        "_result = range(trigger)",
        "for _item in range(trigger):\n    pass",
        "setattr(trigger, 'value', 1)",
        "trigger.value = 1",
        "fire()",
    ],
)
def test_builtin_and_local_call_fast_paths_account_for_protocol_hooks(
    tmp_path: Path,
    effect: str,
) -> None:
    prelude = (
        "class Trigger:\n"
        "    def _mutate(self, *args):\n"
        "        globals()['good'] = lambda x: x + 200\n"
        "        return 0\n"
        "    __index__ = _mutate\n"
        "    __setattr__ = _mutate\n"
        "    def __add__(self, other):\n"
        "        return self._mutate()\n\n"
        "trigger = Trigger()\n"
        "def fire():\n"
        "    trigger + 1\n"
    )
    analysis = _analyze(
        tmp_path,
        {"ops.py": _stale_binding_source(effect, prelude=prelude)},
    )
    _assert_stale_binding_rejected(analysis)


def test_mutated_builtin_range_is_never_treated_as_exact_builtin(tmp_path: Path) -> None:
    analysis = _analyze(
        tmp_path,
        {
            "ops.py": (
                "import builtins\n"
                "import rextio\n\n"
                "def evil(*args):\n"
                "    globals()['good'] = lambda x: x + 200\n"
                "    return ()\n\n"
                "builtins.range = evil\n\n"
                "@rextio.native\n"
                "def good(x: int) -> int:\n"
                "    return x + 1\n\n"
                "for _item in range(1):\n"
                "    pass\n\n"
                "import rextio\n\n"
                "@rextio.native\n"
                "def caller(x: int) -> int:\n"
                "    return good(x)\n"
            )
        },
    )
    _assert_stale_binding_rejected(analysis)


def test_unknown_effect_poison_applies_to_later_absent_builtin_name(tmp_path: Path) -> None:
    analysis = _analyze(
        tmp_path,
        {
            "ops.py": (
                "import rextio\n\n"
                "def evil(*args):\n"
                "    globals()['good'] = lambda x: x + 200\n"
                "    return ()\n\n"
                "def install():\n"
                "    globals().update(range=evil)\n\n"
                "install()\n\n"
                "@rextio.native\n"
                "def good(x: int) -> int:\n"
                "    return x + 1\n\n"
                "_result = range(1)\n\n"
                "import rextio\n\n"
                "@rextio.native\n"
                "def caller(x: int) -> int:\n"
                "    return good(x)\n"
            )
        },
    )
    _assert_stale_binding_rejected(analysis)


def test_walrus_binding_is_replayed_before_later_decorator(tmp_path: Path) -> None:
    analysis = _analyze(
        tmp_path,
        {
            "ops.py": (
                "import logging\n"
                "import rextio\n\n"
                "@rextio.native\n"
                "def good(x: int) -> int:\n"
                "    return x + 1\n\n"
                "def mutate(fn):\n"
                "    globals()['good'] = lambda x: x + 200\n"
                "    return fn\n\n"
                "logging.native = mutate\n"
                "a = rextio\n"
                "_dummy = (a := logging)\n\n"
                "@a.native\n"
                "def decoy(x: int) -> int:\n"
                "    return x\n\n"
                "import rextio\n\n"
                "@rextio.native\n"
                "def caller(x: int) -> int:\n"
                "    return good(x)\n"
            )
        },
    )
    _assert_stale_binding_rejected(analysis)


@pytest.mark.parametrize(
    "expression",
    [
        "exec('trigger + 1')",
        "exec('trigger.value')",
    ],
)
def test_literal_exec_scans_protocol_effects_conservatively(
    tmp_path: Path,
    expression: str,
) -> None:
    prelude = (
        "class Trigger:\n"
        "    def __add__(self, other):\n"
        "        globals()['good'] = lambda x: x + 200\n"
        "        return 0\n"
        "    @property\n"
        "    def value(self):\n"
        "        globals()['good'] = lambda x: x + 200\n"
        "        return 0\n\n"
        "trigger = Trigger()\n"
    )
    analysis = _analyze(
        tmp_path,
        {"ops.py": _stale_binding_source(expression, prelude=prelude)},
    )
    _assert_stale_binding_rejected(analysis)


def test_project_module_attribute_read_is_not_assumed_pure(tmp_path: Path) -> None:
    analysis = _analyze(
        tmp_path,
        {
            "helper.py": (
                "def __getattr__(name):\n"
                "    import consumer\n"
                "    consumer.good = lambda x: x + 200\n"
                "    return 0\n"
            ),
            "consumer.py": (
                "import helper\n"
                "import rextio\n\n"
                "@rextio.native\n"
                "def good(x: int) -> int:\n"
                "    return x + 1\n\n"
                "_result = helper.missing\n\n"
                "import rextio\n\n"
                "@rextio.native\n"
                "def caller(x: int) -> int:\n"
                "    return good(x)\n"
            ),
        },
    )
    functions = _functions(analysis)
    assert functions["consumer.good"].accepted is False
    assert functions["consumer.caller"].route != "native-direct"


def test_project_module_truth_can_dispatch_custom_module_bool(tmp_path: Path) -> None:
    analysis = _analyze(
        tmp_path,
        {
            "helper.py": (
                "import sys\n"
                "import types\n\n"
                "class TruthModule(types.ModuleType):\n"
                "    def __bool__(self):\n"
                "        import consumer\n"
                "        consumer.good = lambda x: x + 200\n"
                "        return True\n\n"
                "sys.modules[__name__].__class__ = TruthModule\n"
            ),
            "consumer.py": (
                "import helper\n"
                "import rextio\n\n"
                "@rextio.native\n"
                "def good(x: int) -> int:\n"
                "    return x + 1\n\n"
                "if helper:\n"
                "    pass\n\n"
                "import rextio\n\n"
                "@rextio.native\n"
                "def caller(x: int) -> int:\n"
                "    return good(x)\n"
            ),
        },
    )
    functions = _functions(analysis)
    assert functions["consumer.good"].accepted is False
    assert functions["consumer.caller"].route != "native-direct"


def test_project_local_stdlib_names_never_receive_static_stdlib_lowering(
    tmp_path: Path,
) -> None:
    analysis = _analyze(
        tmp_path,
        {
            "math.py": "def sin(x):\n    return x + 100.0\n",
            "logging.py": (
                "class Logger:\n"
                "    def info(self, *args):\n"
                "        return None\n\n"
                "def getLogger(name):\n"
                "    return Logger()\n"
            ),
            "ops.py": (
                "import logging\n"
                "import math\n"
                "import rextio\n\n"
                "logger = logging.getLogger(__name__)\n\n"
                "@rextio.native\n"
                "def use_math(x: float) -> float:\n"
                "    return math.sin(x)\n\n"
                "@rextio.native\n"
                "def use_logger(x: int) -> int:\n"
                "    logger.info('x=%s', x)\n"
                "    return x + 1\n"
            ),
        },
    )
    functions = _functions(analysis)
    ops = next(module for module in analysis.modules if module.module_name == "ops")
    assert ops.logger_names == ()
    assert functions["ops.use_math"].route != "native-direct"
    assert functions["ops.use_logger"].route != "native-direct"


def test_project_local_from_import_math_is_not_static_stdlib_lowering(
    tmp_path: Path,
) -> None:
    analysis = _analyze(
        tmp_path,
        {
            "math.py": "def sin(x):\n    return x + 100.0\n",
            "ops.py": (
                "from math import sin\n"
                "import rextio\n\n"
                "@rextio.native\n"
                "def use_math(x: float) -> float:\n"
                "    return sin(x)\n"
            ),
        },
    )
    assert _functions(analysis)["ops.use_math"].route != "native-direct"


@pytest.mark.parametrize(
    "logging_import,call",
    [
        ("import logging", "logging.info('x=%s', x)"),
        ("from logging import info", "info('x=%s', x)"),
    ],
)
def test_ir_rejects_stale_project_local_logging_receiver(
    tmp_path: Path,
    logging_import: str,
    call: str,
) -> None:
    analysis = _analyze(
        tmp_path,
        {
            "logging.py": "def info(*args):\n    return None\n",
            "ops.py": (
                f"{logging_import}\n"
                "import rextio\n\n"
                "@rextio.native\n"
                "def f(x: int) -> int:\n"
                f"    {call}\n"
                "    return x + 1\n"
            ),
        },
    )
    function = _functions(analysis)["ops.f"]
    assert function.route != "native-direct"
    module = analysis.module_for_function(function)
    assert module is not None
    assert "logging" in module.project_modules

    # Simulate a stale/malformed accepted record handed directly to lowering.
    # The defensive IR gate must independently retain the project-module
    # collision instead of erasing the Python receiver into Rust logging.
    function.is_native_candidate = True
    function.accepted = True
    function.native_runtime_semantics = False
    with pytest.raises(
        LoweringError,
        match="logging call receiver is not a proven stdlib import",
    ):
        lower_project(analysis)


@pytest.mark.parametrize(
    "prelude,call",
    [
        ("import logging", "logging.info('x=%s', x)"),
        ("from logging import info", "info('x=%s', x)"),
        (
            "import logging\nlogger = logging.getLogger(__name__)",
            "logger.info('x=%s', x)",
        ),
    ],
)
def test_ir_accepts_clean_stdlib_logging_provenance(
    tmp_path: Path,
    prelude: str,
    call: str,
) -> None:
    analysis = _analyze(
        tmp_path,
        {
            "ops.py": (
                f"{prelude}\n"
                "import rextio\n\n"
                "@rextio.native\n"
                "def f(x: int) -> int:\n"
                f"    {call}\n"
                "    return x + 1\n"
            )
        },
    )
    function = _functions(analysis)["ops.f"]
    assert function.route == "native-direct"
    assert [item.qualname for item in lower_project(analysis).functions] == ["ops.f"]


@pytest.mark.parametrize(
    "mutation_target",
    [
        "logging.getLogger",
        logger_group_target("ops"),
        logger_object_target("ops", "logger"),
    ],
)
def test_ir_rechecks_logger_instance_mutation_authority(
    tmp_path: Path,
    mutation_target: str,
) -> None:
    analysis = _analyze(
        tmp_path,
        {
            "ops.py": (
                "import logging\n"
                "import rextio\n\n"
                "logger = logging.getLogger(__name__)\n\n"
                "@rextio.native\n"
                "def f(x: int) -> int:\n"
                "    logger.info('x=%s', x)\n"
                "    return x + 1\n"
            )
        },
    )
    function = _functions(analysis)["ops.f"]
    module = analysis.module_for_function(function)
    assert module is not None
    assert module.logger_names == ("logger",)
    assert function.route == "native-direct"

    # Simulate mutation authority that became newer than the accepted record.
    # IR must recheck all three identities erased by native logging lowering.
    module.project_mutations = ProjectMutations({}, frozenset({mutation_target}))
    with pytest.raises(
        LoweringError,
        match="logger receiver provenance was invalidated by module execution",
    ):
        lower_project(analysis)


def test_genuine_stdlib_math_and_logging_stay_native(tmp_path: Path) -> None:
    analysis = _analyze(
        tmp_path,
        {
            "ops.py": (
                "import logging\n"
                "import math\n"
                "import rextio\n\n"
                "logger = logging.getLogger(__name__)\n\n"
                "@rextio.native\n"
                "def use_math(x: float) -> float:\n"
                "    return math.sin(x)\n\n"
                "@rextio.native\n"
                "def use_logger(x: int) -> int:\n"
                "    logger.info('x=%s', x)\n"
                "    return x + 1\n"
            )
        },
    )
    functions = _functions(analysis)
    assert analysis.modules[0].logger_names == ("logger",)
    assert functions["ops.use_math"].route == "native-direct"
    assert functions["ops.use_logger"].route == "native-direct"


@pytest.mark.parametrize(
    "prelude",
    [
        "ValueError = KeyError\n",
        "import builtins\nbuiltins.ValueError = KeyError\n",
    ],
)
def test_exception_handler_requires_exact_untouched_builtin_identity(
    tmp_path: Path,
    prelude: str,
) -> None:
    analysis = _analyze(
        tmp_path,
        {
            "ops.py": (
                "import rextio\n"
                f"{prelude}\n"
                "@rextio.native\n"
                "def guarded(xs: list[int]) -> int:\n"
                "    out = 0\n"
                "    try:\n"
                "        out = xs[0]\n"
                "    except ValueError:\n"
                "        out = -1\n"
                "    return out\n"
            )
        },
    )
    assert _functions(analysis)["ops.guarded"].route != "native-direct"


def test_cross_module_builtin_exception_mutation_blocks_native_handler(
    tmp_path: Path,
) -> None:
    analysis = _analyze(
        tmp_path,
        {
            "mutator.py": "import builtins\nbuiltins.ValueError = KeyError\n",
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
    assert _functions(analysis)["ops.guarded"].route != "native-direct"


def test_clean_builtin_exception_handler_stays_native(tmp_path: Path) -> None:
    analysis = _analyze(
        tmp_path,
        {
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
            )
        },
    )
    assert _functions(analysis)["ops.guarded"].route == "native-direct"
