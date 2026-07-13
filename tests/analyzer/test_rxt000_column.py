"""RXT000 column contract: 0-based UTF-8 byte offsets (not SyntaxError.offset)."""

from __future__ import annotations

import json
from pathlib import Path

from rextio.analyzer.module_parser import _syntax_error_column, parse_module
from rextio.analyzer.project_scanner import analyze_project
from rextio.cli.check_cmd import write_check_report


def write_module(root: Path, name: str, contents: str) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")
    return path


def test_rxt000_ascii_column_is_zero_based_utf8_byte_offset(tmp_path: Path) -> None:
    # `(` is the 15th code point (1-based SyntaxError.offset=15); 0-based
    # UTF-8 byte column of the prefix before `(` is 14 (all ASCII).
    source = 'x = "hello" + (\n'
    path = write_module(tmp_path, "broken_ascii.py", source)

    module = parse_module(path, tmp_path)

    assert len(module.diagnostics) == 1
    diagnostic = module.diagnostics[0]
    assert diagnostic.code == "RXT000"
    assert diagnostic.severity == "error"
    assert diagnostic.line == 1
    assert diagnostic.column == 14
    assert diagnostic.column == len('x = "hello" + '.encode("utf-8"))


def test_rxt000_non_ascii_column_uses_utf8_bytes_not_codepoints(tmp_path: Path) -> None:
    # Korean BMP (3 bytes each) + non-BMP emoji (4 bytes) before the error site.
    # CPython SyntaxError.offset is 13 (1-based code points); RXT000.column must
    # be 19 (0-based UTF-8 byte length of the prefix before `(`).
    source = 'x = "한글😀" + (\n'
    path = write_module(tmp_path, "broken_unicode.py", source)

    module = parse_module(path, tmp_path)

    assert len(module.diagnostics) == 1
    diagnostic = module.diagnostics[0]
    assert diagnostic.code == "RXT000"
    assert diagnostic.severity == "error"
    assert diagnostic.line == 1
    assert diagnostic.column == 19
    assert diagnostic.column == len('x = "한글😀" + '.encode("utf-8"))
    # Prove the old bug (storing SyntaxError.offset=13 verbatim) is fixed.
    assert diagnostic.column != 13


def test_rxt000_column_in_check_json_report(tmp_path: Path) -> None:
    write_module(tmp_path, "broken.py", 'x = "한글😀" + (\n')

    analysis = analyze_project(tmp_path)
    report_path = write_check_report(tmp_path, analysis)
    report = json.loads(report_path.read_text(encoding="utf-8"))

    rxt000 = [d for d in report["diagnostics"] if d["code"] == "RXT000"]
    assert len(rxt000) == 1
    assert rxt000[0]["line"] == 1
    assert rxt000[0]["column"] == 19
    assert rxt000[0]["severity"] == "error"


def test_syntax_error_column_preserves_none_without_offset() -> None:
    # Runtime may supply a bare SyntaxError with no location details.
    exc = SyntaxError("invalid syntax")
    assert exc.offset is None
    assert exc.lineno is None
    assert _syntax_error_column(exc, "x = 1\n") is None


def test_syntax_error_column_falls_back_to_source_line() -> None:
    # Prefer SyntaxError.text when present; fall back to source/lineno.
    line = 'x = "한글😀" + (\n'
    exc = SyntaxError("unclosed", ("broken.py", 1, 13, None))
    assert exc.text is None
    assert _syntax_error_column(exc, line) == 19
