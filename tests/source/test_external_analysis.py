from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from rextio.analyzer.models import SourcePosition, SourceRange
from rextio.source.external_analysis import (
    ExternalFunctionBinding,
    ExternalScalarParameter,
    ExternalSourceAnalysisError,
    ExternalSourceNativePlan,
    ExternalSourceSnapshot,
    analyze_external_source_snapshot,
)
from rextio.source.models import (
    ImportAlias,
    ImportKind,
    ImportRecord,
    SourceModule,
    SourceOrigin,
)


MODULE_NAME = "rextio_c5_poc_math"
DIST_NAME = "rextio-c5-poc-math"
SOURCE_PATH = (
    "distributions/rextio-c5-poc-math/"
    "rextio_c5_poc_math/__init__.py"
)
VALID_SOURCE = b"""\
\"\"\"Deterministic MIT-licensed C5.2 fixture.\"\"\"

def affine(x: int, scale: int, bias: int) -> int:
    product: int = x * scale
    return product + bias
"""


def _module(
    source: bytes,
    *,
    origin: SourceOrigin = SourceOrigin.DISTRIBUTION,
    depth: int = 1,
    module_name: str = MODULE_NAME,
    imports: tuple[ImportRecord, ...] = (),
) -> SourceModule:
    return SourceModule(
        module_name=module_name,
        path=SOURCE_PATH,
        is_package_init=True,
        source_origin=origin,
        sha256=hashlib.sha256(source).hexdigest(),
        dependency_depth=depth,
        imports=imports,
        distribution=DIST_NAME,
        version="1.0.0",
        license="MIT",
    )


def _snapshot(source: bytes = VALID_SOURCE) -> ExternalSourceSnapshot:
    return ExternalSourceSnapshot(_module(source), source)


def _rejects(source: str, reason: str) -> None:
    data = source.encode("utf-8")
    with pytest.raises(ExternalSourceAnalysisError) as raised:
        analyze_external_source_snapshot(_snapshot(data))
    assert raised.value.reason == reason


def test_exact_byte_snapshot_produces_deterministic_sanitized_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = _snapshot()

    def unexpected_read(*_args: object, **_kwargs: object) -> bytes:
        pytest.fail("external analysis must not reread an ambient path")

    monkeypatch.setattr(Path, "read_bytes", unexpected_read)
    first = analyze_external_source_snapshot(snapshot)
    second = analyze_external_source_snapshot(snapshot)

    assert first == second
    assert len(first.semantic_sha256) == 64
    assert first.module_init.available
    assert first.module_init.source_sha256 == snapshot.module.sha256
    assert tuple(binding.qualname for binding in first.functions) == (
        f"{MODULE_NAME}.affine",
    )
    binding = first.functions[0]
    assert binding.parameters == (
        ExternalScalarParameter("x", "int"),
        ExternalScalarParameter("scale", "int"),
        ExternalScalarParameter("bias", "int"),
    )
    assert binding.return_type == "int"
    assert len(binding.semantic_ast_sha256) == 64
    assert len(binding.lowered_ir_sha256) == 64
    payload = first.to_dict()
    rendered = repr(payload)
    assert VALID_SOURCE.decode("utf-8") not in rendered
    assert "site-packages" not in rendered
    assert payload["authority"] == "analysis-only"
    assert payload["module"]["size"] == len(VALID_SOURCE)


def test_snapshot_requires_exact_immutable_authority() -> None:
    module = _module(VALID_SOURCE)
    with pytest.raises(ExternalSourceAnalysisError, match="immutable"):
        ExternalSourceSnapshot(module, bytearray(VALID_SOURCE))  # type: ignore[arg-type]
    with pytest.raises(ExternalSourceAnalysisError, match="sha256"):
        ExternalSourceSnapshot(module, VALID_SOURCE + b"# drift\n")
    with pytest.raises(ExternalSourceAnalysisError, match="out-of-scope"):
        ExternalSourceSnapshot(
            _module(VALID_SOURCE, origin=SourceOrigin.PROJECT), VALID_SOURCE
        )
    with pytest.raises(ExternalSourceAnalysisError, match="out-of-scope"):
        ExternalSourceSnapshot(_module(VALID_SOURCE, depth=2), VALID_SOURCE)


def test_snapshot_rejects_predeclared_imports_and_unsafe_module_identity() -> None:
    imported = ImportRecord(
        ordinal=0,
        kind=ImportKind.IMPORT,
        module=None,
        relative_level=0,
        names=(ImportAlias("math"),),
        source_range=SourceRange(
            SourcePosition(1, 0),
            SourcePosition(1, 11),
        ),
        resolved_targets=("math",),
    )
    with pytest.raises(ExternalSourceAnalysisError, match="out-of-scope"):
        ExternalSourceSnapshot(
            _module(VALID_SOURCE, imports=(imported,)), VALID_SOURCE
        )
    with pytest.raises(ExternalSourceAnalysisError, match="module-name-invalid"):
        ExternalSourceSnapshot(
            _module(VALID_SOURCE, module_name="bad-module"), VALID_SOURCE
        )
    wrong_path = replace(_module(VALID_SOURCE), path="other/location.py")
    with pytest.raises(ExternalSourceAnalysisError, match="source-path-invalid"):
        ExternalSourceSnapshot(wrong_path, VALID_SOURCE)


@pytest.mark.parametrize(
    ("source", "reason"),
    (
        ("import math\n\ndef f(x: int) -> int:\n    return x\n", "source-import-not-supported"),
        ("VALUE = 1\n\ndef f(x: int) -> int:\n    return x\n", "source-top-level-effect-not-supported"),
        ("class C:\n    pass\n", "source-class-not-supported"),
        ("async def f(x: int) -> int:\n    return x\n", "source-async-function-not-supported"),
        ("def f(x: int) -> int:\n    return x\n\ndef f(x: int) -> int:\n    return x + 1\n", "source-function-binding-not-final"),
        ("def int(x: int) -> int:\n    return x\n", "source-scalar-annotation-shadowed"),
    ),
)
def test_module_surface_rejects_imports_effects_and_nonfinal_bindings(
    source: str,
    reason: str,
) -> None:
    _rejects(source, reason)


def test_invalid_utf8_and_syntax_are_sanitized() -> None:
    invalid_utf8 = b"\xff\xfe"
    with pytest.raises(ExternalSourceAnalysisError) as utf8:
        analyze_external_source_snapshot(_snapshot(invalid_utf8))
    assert utf8.value.reason == "source-not-utf8"

    invalid_syntax = b"def broken(:\n"
    with pytest.raises(ExternalSourceAnalysisError) as syntax:
        analyze_external_source_snapshot(_snapshot(invalid_syntax))
    assert syntax.value.reason == "source-not-parseable"


@pytest.mark.parametrize(
    ("source", "reason"),
    (
        ("def f(x: int = 1) -> int:\n    return x\n", "function-signature-not-fixed-positional"),
        ("def f(*, x: int) -> int:\n    return x\n", "function-signature-not-fixed-positional"),
        ("def f(*xs: int) -> int:\n    return 1\n", "function-signature-not-fixed-positional"),
        ("@staticmethod\ndef f(x: int) -> int:\n    return x\n", "function-decorator-not-supported"),
        ("def f(x) -> int:\n    return 1\n", "function-parameter-not-scalar-annotated"),
        ("def f(x: int):\n    return x\n", "function-return-not-scalar-annotated"),
        ("def f(x: int) -> int:\n    global state\n    return x\n", "function-global-state-not-supported"),
        ("def f(x: int) -> int:\n    yield x\n", "function-nested-or-generator-not-supported"),
        ("def f(x: int) -> int:\n    def inner() -> int:\n        return x\n    return x\n", "function-nested-or-generator-not-supported"),
        ("def f(x: int) -> int:\n    return abs(x)\n", "function-call-not-leaf"),
    ),
)
def test_function_surface_is_fixed_scalar_and_leaf(source: str, reason: str) -> None:
    _rejects(source, reason)


@pytest.mark.parametrize(
    ("source", "reason"),
    (
        ("def f(x: int) -> int:\n    \"\"\"doc\"\"\"\n    return x\n", "function-body-not-straight-line"),
        ("def f(x: int) -> int:\n    if x > 0:\n        return x\n    return -x\n", "function-body-not-straight-line"),
        ("def f(x: int) -> int:\n    return missing + x\n", "function-free-name-not-supported"),
        ("def f(x: int) -> int:\n    return x.bit_length\n", "function-expression-not-supported"),
        ("def f() -> int:\n    return 9223372036854775808\n", "function-integer-literal-out-of-range"),
        ("def f() -> float:\n    return 1e999\n", "function-float-literal-not-finite"),
    ),
)
def test_body_gate_rejects_control_globals_and_unemittable_literals(
    source: str,
    reason: str,
) -> None:
    _rejects(source, reason)


def test_core_validator_rejects_type_inconsistent_straight_line_body() -> None:
    _rejects(
        "def f(x: int) -> int:\n    return \"wrong\"\n",
        "function-not-core-lowerable",
    )


def test_function_and_plan_hashes_bind_semantic_body() -> None:
    first = analyze_external_source_snapshot(
        _snapshot(b"def affine(x: int) -> int:\n    return x + 1\n")
    )
    second = analyze_external_source_snapshot(
        _snapshot(b"def affine(x: int) -> int:\n    return x + 2\n")
    )
    assert first.functions[0].semantic_ast_sha256 != second.functions[0].semantic_ast_sha256
    assert first.functions[0].lowered_ir_sha256 != second.functions[0].lowered_ir_sha256
    assert first.semantic_sha256 != second.semantic_sha256


def test_native_plan_rejects_digest_or_binding_tampering() -> None:
    plan = analyze_external_source_snapshot(_snapshot())
    with pytest.raises(ValueError, match="digest"):
        replace(plan, semantic_sha256="0" * 64)

    binding = plan.functions[0]
    changed_binding = ExternalFunctionBinding(
        name=binding.name,
        qualname=binding.qualname,
        module_name=binding.module_name,
        source_path=binding.source_path,
        source_sha256=binding.source_sha256,
        source_range=binding.source_range,
        parameters=binding.parameters,
        return_type=binding.return_type,
        semantic_ast_sha256="0" * 64,
        lowered_ir_sha256=binding.lowered_ir_sha256,
    )
    with pytest.raises(ValueError, match="digest"):
        ExternalSourceNativePlan(
            snapshot=plan.snapshot,
            module_init=plan.module_init,
            functions=(changed_binding,),
            semantic_sha256=plan.semantic_sha256,
        )
