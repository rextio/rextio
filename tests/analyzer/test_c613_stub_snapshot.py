from __future__ import annotations

from pathlib import Path

import rextio.analyzer.project_scanner as project_scanner
from rextio.analyzer.module_parser import parse_module
from rextio.analyzer.models import ModuleAnalysis, ProjectAnalysis
from rextio.analyzer.stub_inputs import capture_sibling_stub_inputs
from rextio.analyzer.stub_inputs import StubInputLimits


def _write(root: Path, relative: str, text: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_project_analysis_preserves_positional_constructor_contract(tmp_path: Path) -> None:
    modules = [ModuleAnalysis(module_name="ops", file_path=str(tmp_path / "ops.py"))]

    analysis = ProjectAnalysis(tmp_path, modules)
    keyword_analysis = ProjectAnalysis(project_root=tmp_path, modules=modules)
    assert analysis._stub_inputs is None
    analysis._stub_inputs = object()  # type: ignore[assignment]

    assert analysis.modules is modules
    assert keyword_analysis.modules is modules
    assert keyword_analysis._stub_inputs is None
    assert analysis == keyword_analysis
    assert "_stub_inputs" not in repr(analysis)


def test_analysis_captures_once_and_consumers_use_the_same_frozen_stub(
    tmp_path: Path, monkeypatch
) -> None:
    _write(tmp_path, "pkg/ops.py", "def score(value):\n    return value + 1\n")
    _write(tmp_path, "pkg/other.py", "def other(value: int) -> int:\n    return value\n")
    stub = _write(tmp_path, "pkg/ops.pyi", "def score(value: int) -> int: ...\n")
    calls: list[tuple[Path, ...]] = []
    original_capture = project_scanner.capture_sibling_stub_inputs

    def capture(root: Path, sources: tuple[Path, ...]):
        calls.append(sources)
        snapshot = original_capture(root, sources)
        stub.write_text("def score(value: str) -> str: ...\n", encoding="utf-8")
        return snapshot

    monkeypatch.setattr(project_scanner, "capture_sibling_stub_inputs", capture)
    original_read_text = Path.read_text

    def reject_stub_reread(path: Path, *args, **kwargs):
        if path.suffix == ".pyi":
            raise AssertionError("analysis reread a sibling .pyi")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", reject_stub_reread)
    analysis = project_scanner.analyze_project(tmp_path)

    assert len(calls) == 1
    assert calls[0] == tuple(sorted(calls[0], key=lambda path: path.as_posix()))
    function = next(function for module in analysis.modules for function in module.functions if function.name == "score")
    assert function.inferred_arg_types == {"value": "int"}
    assert function.inferred_return_type == "int"
    assert "_stub_inputs" not in analysis.to_dict()


def test_complex_safe_stub_text_keeps_ordinary_inference(tmp_path: Path) -> None:
    source = _write(tmp_path, "ops.py", "def score(value):\n    return value + 1\n")
    stub = _write(
        tmp_path,
        "ops.pyi",
        "from typing import overload\n@overload\ndef score(value: int) -> int: ...\n",
    )
    snapshot = capture_sibling_stub_inputs(tmp_path, (source,))
    record = snapshot.for_source(source)
    assert record.eligible is False
    assert record.text is not None

    module = parse_module(source, tmp_path, stub_inputs=snapshot)
    function = module.functions[0]
    assert function.inferred_arg_types == {"value": "int"}
    assert function.inferred_return_type == "int"
    assert stub.exists()


def test_standalone_parse_module_still_reads_a_live_stub(tmp_path: Path) -> None:
    source = _write(tmp_path, "ops.py", "def score(value):\n    return value + 1\n")
    _write(tmp_path, "ops.pyi", "def score(value: int) -> int: ...\n")

    module = parse_module(source, tmp_path)

    function = module.functions[0]
    assert function.inferred_arg_types == {"value": "int"}
    assert function.inferred_return_type == "int"


def test_resource_rejected_stub_is_not_reparsed_by_module_parser(
    tmp_path: Path, monkeypatch
) -> None:
    source = _write(tmp_path, "ops.py", "def score(value):\n    return value + 1\n")
    _write(tmp_path, "ops.pyi", "def score(value: int) -> int: ...\n")
    snapshot = capture_sibling_stub_inputs(
        tmp_path, (source,), limits=StubInputLimits(max_ast_nodes=1)
    )
    record = snapshot.for_source(source)
    assert record.reason == "ast-node-limit"
    assert record.analyzer_consumable is False

    import rextio.analyzer.module_parser as module_parser

    original_parse = module_parser.ast.parse
    def reject_stub_parse(source_text, *args, **kwargs):
        filename = kwargs.get("filename")
        if filename == "ops.pyi":
            raise AssertionError("resource-rejected stub was reparsed")
        return original_parse(source_text, *args, **kwargs)

    monkeypatch.setattr(module_parser.ast, "parse", reject_stub_parse)
    module = parse_module(source, tmp_path, stub_inputs=snapshot)

    assert module.functions
