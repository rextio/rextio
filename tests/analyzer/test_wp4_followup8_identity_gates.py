from __future__ import annotations

import ast
from pathlib import Path

import pytest

from rextio.analyzer.final_bindings import build_module_bindings
from rextio.analyzer.models import FunctionAnalysis
from rextio.analyzer.project_scanner import analyze_project
from rextio.analyzer.unsupported_patterns import _validate_decorators
from rextio.codegen.python_wrapper.wrapper_gen import render_wrapper_module
from rextio.ir.lowering import LoweringError, lower_project


def _write(tmp_path: Path, source: str) -> Path:
    path = tmp_path / "ops.py"
    path.write_text(source, encoding="utf-8")
    return path


def _function(tmp_path: Path, source: str, qualname: str = "ops.f"):
    _write(tmp_path, source)
    analysis = analyze_project(tmp_path, native_marker="decorator")
    function = next(
        function
        for module in analysis.modules
        for function in module.functions
        if function.qualname == qualname
    )
    return analysis, function


def test_mixed_fake_and_real_native_decorators_are_rejected(tmp_path: Path) -> None:
    analysis, function = _function(
        tmp_path,
        "from fake import native\n"
        "import rextio\n\n"
        "@native\n"
        "@rextio.native\n"
        "def f(x: int) -> int:\n    return x + 1\n",
    )

    assert function.is_native_candidate is False
    assert function.accepted is False
    assert analysis.accepted_native_functions == []


def test_exact_native_alias_is_the_only_decorator_and_remains_native(tmp_path: Path) -> None:
    analysis, function = _function(
        tmp_path,
        "from rextio import native as n\n\n@n\ndef f(x: int) -> int:\n    return x + 1\n",
    )

    assert function.accepted is True
    assert function.route == "native-direct"
    assert analysis.accepted_native_functions == [function]


def test_raw_native_spelling_is_not_accepted_by_standalone_validator() -> None:
    tree = ast.parse("import rextio\n\n@rextio.native\ndef f(x: int) -> int:\n    return x + 1\n")
    node = tree.body[-1]
    assert isinstance(node, ast.FunctionDef)
    bindings = build_module_bindings(tree, "ops")
    # Simulate a malformed accepted AST carrying an additional raw marker-shaped
    # decorator that the authority never proved.
    fake = ast.copy_location(ast.Name(id="native", ctx=ast.Load()), node.decorator_list[0])
    node.decorator_list.insert(0, fake)
    function = FunctionAnalysis(
        name="f",
        qualname="ops.f",
        module_name="ops",
        file_path="ops.py",
        line=node.lineno,
        column=node.col_offset,
        is_native_candidate=True,
        module_bindings=bindings,
    )

    _validate_decorators(node, function)

    assert any(d.code == "RXT010" for d in function.error_diagnostics)


def test_exact_native_aliases_work_on_plain_instance_methods(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "import rextio as rx\n"
        "from rextio import native as n\n\n"
        "class A:\n"
        "    @n\n"
        "    def m(self, x: int) -> int:\n        return x + 1\n\n"
        "class B:\n"
        "    @rx.native\n"
        "    def m(self, x: int) -> int:\n        return x + 2\n",
    )
    analysis = analyze_project(tmp_path, native_marker="decorator")
    by_name = {
        function.qualname: function for module in analysis.modules for function in module.functions
    }

    assert by_name["ops.A.m"].route == "native-shim"
    assert by_name["ops.B.m"].route == "native-shim"


def test_unshadowed_explicit_object_base_remains_a_stable_method(tmp_path: Path) -> None:
    analysis, function = _function(
        tmp_path,
        "import rextio\n\n"
        "class A(object):\n"
        "    @rextio.native\n"
        "    def m(self, x: int) -> int:\n        return x + 1\n",
        "ops.A.m",
    )

    assert function.accepted is True
    assert function.route == "native-shim"
    assert analysis.accepted_native_functions == [function]


def test_descriptor_set_name_cannot_replace_an_accepted_native_method(
    tmp_path: Path,
) -> None:
    analysis, function = _function(
        tmp_path,
        "class Descriptor:\n"
        "    def __set_name__(self, owner, name):\n"
        "        owner.m = lambda self, x: x + 200\n\n"
        "descriptor = Descriptor()\n"
        "import rextio\n\n"
        "class A:\n"
        "    trigger = descriptor\n"
        "    @rextio.native\n"
        "    def m(self, x: int) -> int:\n"
        "        return x + 100\n",
        "ops.A.m",
    )

    assert function.accepted is False
    assert function.route != "native-shim"
    assert function not in analysis.accepted_native_functions


@pytest.mark.parametrize(
    "class_binding",
    [
        "for trigger in [descriptor]:\n        pass",
        "from holder import descriptor as trigger",
    ],
)
def test_all_class_namespace_binders_are_descriptor_guarded(
    tmp_path: Path,
    class_binding: str,
) -> None:
    holder = tmp_path / "holder.py"
    holder.write_text(
        "class Descriptor:\n"
        "    def __set_name__(self, owner, name):\n"
        "        del owner.m\n\n"
        "descriptor = Descriptor()\n",
        encoding="utf-8",
    )
    analysis, function = _function(
        tmp_path,
        "from holder import descriptor\n"
        "import rextio\n\n"
        "class A:\n"
        f"    {class_binding}\n"
        "    @rextio.native\n"
        "    def m(self, x: int) -> int:\n"
        "        return x + 100\n",
        "ops.A.m",
    )

    assert function.accepted is False
    assert function not in analysis.accepted_native_functions


def test_exact_exempt_aliases_suppress_native_candidates(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "import rextio as rx\n"
        "from rextio import exempt as x, native\n\n"
        "@x\n"
        "@native\n"
        "def a(v: int) -> int:\n    return v + 1\n\n"
        "@rx.exempt\n"
        "@native\n"
        "def b(v: int) -> int:\n    return v + 2\n",
    )
    analysis = analyze_project(tmp_path, native_marker="decorator")
    by_name = {
        function.qualname: function for module in analysis.modules for function in module.functions
    }

    assert by_name["ops.a"].is_native_candidate is False
    assert by_name["ops.b"].is_native_candidate is False
    assert analysis.accepted_native_functions == []


@pytest.mark.parametrize(
    "prefix",
    [
        "logger = logging.getLogger(__name__)\nimport rextio\n",
        (
            "import logging\nimport rextio\n\n"
            "logging.getLogger = lambda name: object()\n"
            "logger = logging.getLogger(__name__)\n"
        ),
        (
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "logger = object()\n"
            "import rextio\n"
        ),
    ],
)
def test_logging_receiver_requires_clean_proven_getlogger_import(
    tmp_path: Path, prefix: str
) -> None:
    analysis, function = _function(
        tmp_path,
        prefix + "\n@rextio.native\n"
        "def f(x: int) -> int:\n"
        '    logger.info("x=%s", x)\n'
        "    return x\n",
    )

    assert function.route != "native-direct"
    assert function not in [
        candidate
        for candidate in analysis.accepted_native_functions
        if candidate.route == "native-direct"
    ]
    assert analysis.modules[0].logger_names == ()


def test_clean_logging_alias_receiver_remains_native(tmp_path: Path) -> None:
    analysis, function = _function(
        tmp_path,
        "import logging as log\nimport rextio\n\n"
        "logger = log.getLogger(__name__)\n\n"
        "@rextio.native\n"
        "def f(x: int) -> int:\n"
        '    logger.info("x=%s", x)\n'
        "    return x\n",
    )

    assert function.accepted is True
    assert analysis.accepted_native_functions == [function]
    assert analysis.modules[0].logger_names == ("logger",)


def test_ir_and_wrapper_recheck_current_marker_identity(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "import rextio\n\n@rextio.native\ndef f(x: int) -> int:\n    return x + 1\n",
    )
    analysis = analyze_project(tmp_path, native_marker="decorator")
    module = analysis.modules[0]
    assert analysis.accepted_native_functions

    # Keep every relevant source location unchanged while replacing the import
    # authority.  A build gate that trusts the earlier analysis table would accept
    # the now-fake marker solely because the decorator still has the same position.
    path.write_text(
        "import fake as rextio\n\n@rextio.native\ndef f(x: int) -> int:\n    return x + 1\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="native marker identity"):
        render_wrapper_module(module)
    with pytest.raises(LoweringError, match="native marker identity"):
        lower_project(analysis)


def test_ir_and_wrapper_reject_same_position_source_edits(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "import rextio\n\n@rextio.native\ndef f(x: int) -> int:\n    return x + 1\n",
    )
    analysis = analyze_project(tmp_path, native_marker="decorator")
    module = analysis.modules[0]
    assert analysis.accepted_native_functions

    # Preserve every line/column while changing the analyzed body.  Reusing the
    # old inferred types/claims for this new AST would compile stale semantics.
    path.write_text(
        "import rextio\n\n@rextio.native\ndef f(x: int) -> int:\n    return x + 2\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="source AST changed"):
        render_wrapper_module(module)
    with pytest.raises(LoweringError, match="source AST changed"):
        lower_project(analysis)


@pytest.mark.parametrize(
    "source,qualname",
    [
        (
            "import rextio\n\n"
            "def replace(cls):\n    return type('A', (), {})\n\n"
            "@replace\n"
            "class A:\n"
            "    @rextio.native\n"
            "    def m(self, x: int) -> int:\n        return x + 1\n",
            "ops.A.m",
        ),
        (
            "import rextio\n\n"
            "class Base:\n    pass\n\n"
            "object = Base\n\n"
            "class A(object):\n"
            "    @rextio.native\n"
            "    def m(self, x: int) -> int:\n        return x + 1\n",
            "ops.A.m",
        ),
    ],
)
def test_malformed_accepted_method_cannot_bypass_class_stability_gate(
    tmp_path: Path, source: str, qualname: str
) -> None:
    analysis, function = _function(tmp_path, source, qualname)

    # Simulate a malformed/stale accepted list handed directly to the build
    # pipeline.  IR and wrapper planning must independently fail closed.
    function.is_native_candidate = True
    function.accepted = True

    with pytest.raises(
        ValueError,
        match="class construction|native marker identity|source AST changed",
    ):
        render_wrapper_module(analysis.module_for_function(function))  # type: ignore[arg-type]
    with pytest.raises(
        LoweringError,
        match="class construction|native marker identity|source AST changed",
    ):
        lower_project(analysis)
