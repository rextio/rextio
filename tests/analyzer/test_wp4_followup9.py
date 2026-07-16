"""Independent review regressions for WP-4 follow-up 9."""

from __future__ import annotations

from pathlib import Path

import pytest

from rextio.analyzer.project_scanner import analyze_project


def _write(root: Path, relative: str, source: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")


def _analyze(root: Path, files: dict[str, str]):
    for relative, source in files.items():
        _write(root, relative, source)
    return analyze_project(root, native_marker="decorator")


def _functions(analysis):
    return {
        function.qualname: function for module in analysis.modules for function in module.functions
    }


def test_destructured_rextio_alias_cannot_hide_marker_mutation(tmp_path: Path) -> None:
    analysis = _analyze(
        tmp_path,
        {
            "ops.py": (
                "import rextio\n"
                "(r,) = (rextio,)\n"
                "r.native = lambda fn: (lambda x: x + 200)\n\n"
                "@rextio.native\n"
                "def f(x: int) -> int:\n"
                "    return x + 100\n"
            )
        },
    )
    function = _functions(analysis)["ops.f"]

    assert function.is_native_candidate is False
    assert function not in analysis.accepted_native_functions
    assert analysis.project_mutations.target_is_mutated("rextio.native")


def test_destructured_relative_module_alias_cannot_hide_project_mutation(
    tmp_path: Path,
) -> None:
    analysis = _analyze(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/helper.py": (
                "import rextio\n\n@rextio.native\ndef good(x: int) -> int:\n    return x + 100\n"
            ),
            "pkg/mutator.py": (
                "from . import helper\n(h,) = (helper,)\nh.good = lambda x: x + 200\n"
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

    assert functions["pkg.helper.good"].accepted is False
    assert functions["pkg.consumer.caller"].route != "native-direct"
    assert analysis.project_mutations.target_is_mutated("pkg.helper.good")


@pytest.mark.parametrize(
    "assignment",
    [
        "(r, *rest) = (rextio,)",
        "(r, extra) = (rextio,)",
        "(r,) = dynamic",
    ],
)
def test_unproven_destructuring_fails_closed(
    tmp_path: Path,
    assignment: str,
) -> None:
    prelude = (
        "class Dynamic:\n    def __iter__(self):\n        return iter(())\n\ndynamic = Dynamic()\n"
        if assignment.endswith("dynamic")
        else ""
    )
    analysis = _analyze(
        tmp_path,
        {
            "ops.py": (
                f"{prelude}"
                "import rextio\n"
                f"{assignment}\n"
                "r.native = lambda fn: (lambda x: x + 200)\n\n"
                "@rextio.native\n"
                "def f(x: int) -> int:\n"
                "    return x + 100\n"
            )
        },
    )

    assert _functions(analysis)["ops.f"].is_native_candidate is False
    assert analysis.accepted_native_functions == []


def test_mutated_logger_receiver_is_not_erased_by_native_logging(
    tmp_path: Path,
) -> None:
    analysis = _analyze(
        tmp_path,
        {
            "ops.py": (
                "import logging\n"
                "import rextio\n\n"
                "logger = logging.getLogger(__name__)\n"
                "alias = logger\n"
                "alias.info = lambda *args: (_ for _ in ()).throw(\n"
                "    RuntimeError('mutated logger receiver')\n"
                ")\n\n"
                "@rextio.native\n"
                "def f(x: int) -> int:\n"
                "    logger.info('x=%s', x)\n"
                "    return x + 1\n"
            )
        },
    )
    function = _functions(analysis)["ops.f"]

    assert analysis.modules[0].logger_names == ()
    assert function.route != "native-direct"
    assert function not in analysis.accepted_native_functions
    assert analysis.project_mutations.target_is_mutated("ops.logger")


def test_cross_module_logger_alias_mutation_invalidates_receiver(
    tmp_path: Path,
) -> None:
    analysis = _analyze(
        tmp_path,
        {
            "logger_mod.py": (
                "import logging\n"
                "import rextio\n\n"
                "logger = logging.getLogger(__name__)\n\n"
                "@rextio.native\n"
                "def f(x: int) -> int:\n"
                "    logger.info('x=%s', x)\n"
                "    return x + 1\n"
            ),
            "mutator.py": (
                "from logger_mod import logger as receiver\nreceiver.info = lambda *args: None\n"
            ),
        },
    )
    module = next(module for module in analysis.modules if module.module_name == "logger_mod")

    assert module.logger_names == ()
    assert _functions(analysis)["logger_mod.f"].accepted is False


def test_mutated_build_class_rejects_native_method(tmp_path: Path) -> None:
    analysis = _analyze(
        tmp_path,
        {
            "ops.py": (
                "import builtins\n"
                "import rextio\n\n"
                "builtins.__build_class__ = lambda *args, **kwargs: type('Fake', (), {})\n\n"
                "class A:\n"
                "    @rextio.native\n"
                "    def m(self, x: int) -> int:\n"
                "        return x + 1\n"
            )
        },
    )
    method = _functions(analysis)["ops.A.m"]

    assert analysis.project_mutations.target_is_mutated("builtins.__build_class__")
    assert method.accepted is False
    assert method not in analysis.accepted_native_functions


def test_clean_plain_class_remains_native(tmp_path: Path) -> None:
    analysis = _analyze(
        tmp_path,
        {
            "ops.py": (
                "import rextio\n\n"
                "class A:\n"
                "    @rextio.native\n"
                "    def m(self, x: int) -> int:\n"
                "        return x + 1\n"
            )
        },
    )

    assert _functions(analysis)["ops.A.m"].route == "native-shim"


@pytest.mark.parametrize(
    "method,expression",
    [
        ("def __add__(self, other):", "trigger + 1"),
        ("def __neg__(self):", "-trigger"),
        ("def __eq__(self, other):", "trigger == 1"),
        ("def __getitem__(self, key):", "trigger[0]"),
        ("@property\n    def value(self):", "trigger.value"),
        ("def __format__(self, spec):", "f'{trigger}'"),
        (
            "def __iter__(self):\n"
            "        globals()['good'] = lambda x: x + 200\n"
            "        return iter(())\n\n"
            "    def harmless(self):",
            "[item for item in trigger]",
        ),
    ],
)
def test_module_operator_protocol_effect_invalidates_stale_native_binding(
    tmp_path: Path,
    method: str,
    expression: str,
) -> None:
    if "__iter__" in method:
        method_body = f"    {method}\n        return None\n"
    else:
        method_body = (
            f"    {method}\n        globals()['good'] = lambda x: x + 200\n        return 0\n"
        )
    analysis = _analyze(
        tmp_path,
        {
            "ops.py": (
                "class Trigger:\n"
                f"{method_body}\n"
                "trigger = Trigger()\n"
                "import rextio\n\n"
                "@rextio.native\n"
                "def good(x: int) -> int:\n"
                "    return x + 100\n\n"
                f"_result = {expression}\n"
                "import rextio\n\n"
                "@rextio.native\n"
                "def caller(x: int) -> int:\n"
                "    return good(x)\n"
            )
        },
    )
    functions = _functions(analysis)

    assert functions["ops.good"].accepted is False
    assert functions["ops.caller"].route != "native-direct"


def test_closed_builtin_operator_and_container_expressions_remain_clean(
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
                "A = 1 + 2\n"
                "B = -1\n"
                "C = 1 < 2\n"
                "D = [1, 2][0]\n"
                "E = f'{1}'\n"
                "F = [item for item in [1, 2]]\n"
                "G = {'a': 1, 'b': 2}\n"
            )
        },
    )

    assert _functions(analysis)["ops.good"].route == "native-direct"


def test_clean_relative_reexport_chain_resolves_to_native_function(
    tmp_path: Path,
) -> None:
    analysis = _analyze(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/c.py": (
                "import rextio\n\n@rextio.native\ndef good(x: int) -> int:\n    return x + 1\n"
            ),
            "pkg/b.py": "from .c import good\n",
            "pkg/a.py": (
                "import rextio\n"
                "from . import b\n\n"
                "@rextio.native\n"
                "def caller(x: int) -> int:\n"
                "    return b.good(x)\n"
            ),
        },
    )

    assert _functions(analysis)["pkg.a.caller"].route == "native-direct"


def test_mutated_relative_reexport_chain_fails_closed(tmp_path: Path) -> None:
    analysis = _analyze(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/c.py": (
                "import rextio\n\n@rextio.native\ndef good(x: int) -> int:\n    return x + 1\n"
            ),
            "pkg/b.py": "from .c import good\n",
            "pkg/mutator.py": ("from . import b\nb.good = lambda x: x + 200\n"),
            "pkg/a.py": (
                "import rextio\n"
                "from . import b\n\n"
                "@rextio.native\n"
                "def caller(x: int) -> int:\n"
                "    return b.good(x)\n"
            ),
        },
    )

    assert _functions(analysis)["pkg.a.caller"].route != "native-direct"


def test_cyclic_relative_reexport_chain_fails_closed(tmp_path: Path) -> None:
    analysis = _analyze(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/b.py": "from .c import good\n",
            "pkg/c.py": "from .b import good\n",
            "pkg/a.py": (
                "import rextio\n"
                "from . import b\n\n"
                "@rextio.native\n"
                "def caller(x: int) -> int:\n"
                "    return b.good(x)\n"
            ),
        },
    )

    assert _functions(analysis)["pkg.a.caller"].route != "native-direct"
