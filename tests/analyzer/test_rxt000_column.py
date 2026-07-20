"""RXT000 column contract: 0-based UTF-8 byte offsets (not SyntaxError.offset).

Contract 2.x (position semantics from 2.0.0; current producer 2.19.0) standardizes
every diagnostic column (including RXT000) as a 0-based UTF-8 byte offset.
Adversarial cases deliberately make Python code points, UTF-8 bytes, and UTF-16
code units diverge so a regression to either legacy 1-based code-point storage
or accidental UTF-16 indexing fails loudly.
"""

from __future__ import annotations

import json
from pathlib import Path

from rextio.analyzer.module_parser import _syntax_error_column, parse_module
from rextio.analyzer.project_scanner import analyze_project
from rextio.cli.check_cmd import write_check_report
from rextio.contract import TOOLING_CONTRACT_VERSION


def write_module(root: Path, name: str, contents: str) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")
    return path


def _utf16_len(text: str) -> int:
    return sum(2 if ord(ch) > 0xFFFF else 1 for ch in text)


def test_tooling_contract_version_is_major_2() -> None:
    # Protocol discriminator for the RXT000 column semantic break (major 2);
    # 2.19.0 adds C6.14 artifact-policy coverage inventory.
    assert TOOLING_CONTRACT_VERSION == "2.19.0"
    assert TOOLING_CONTRACT_VERSION.split(".", 1)[0] == "2"


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


def test_rxt000_adversarial_codepoints_utf8_utf16_diverge(tmp_path: Path) -> None:
    """Lock the three encodings apart so any wrong unit system fails.

    Line (no trailing newline for the math): ``x = "한글😀" + (``

    Indices of the error site ``(`` (0-based unless noted):

    - Python code points (0-based): 12  →  SyntaxError.offset = 13 (1-based)
    - UTF-8 bytes: 19
    - UTF-16 code units: 13  (😀 is a surrogate pair)

    Contract 2.x must emit the UTF-8 byte column (19), not 13 and not a
    UTF-16 unit index.
    """
    source = 'x = "한글😀" + (\n'
    path = write_module(tmp_path, "broken_adversarial.py", source)
    prefix = 'x = "한글😀" + '
    assert len(prefix) == 12  # code points
    assert len(prefix.encode("utf-8")) == 19  # UTF-8 bytes
    assert _utf16_len(prefix) == 13  # UTF-16 units
    # All three numbers are distinct so a wrong unit cannot pass by coincidence.
    assert len({12, 19, 13}) == 3

    try:
        compile(source, str(path), "exec")
    except SyntaxError as exc:
        err = exc
    else:
        raise AssertionError("expected SyntaxError")
    assert err.offset == 13  # 1-based code points (legacy contract 1.x value)

    module = parse_module(path, tmp_path)
    (diagnostic,) = module.diagnostics
    assert diagnostic.code == "RXT000"
    assert diagnostic.column == 19
    assert diagnostic.column != err.offset  # not 1-based code points
    assert diagnostic.column != len(prefix)  # not 0-based code points
    assert diagnostic.column != _utf16_len(prefix)  # not UTF-16 units


def test_rxt000_astral_only_prefix_uses_utf8_bytes(tmp_path: Path) -> None:
    # Non-BMP MATHEMATICAL BOLD CAPITAL A (U+1D400): 1 code point, 4 UTF-8
    # bytes, 2 UTF-16 units. Column must be the UTF-8 length of the prefix.
    source = "𝐀 = (\n"
    path = write_module(tmp_path, "broken_astral.py", source)
    prefix = "𝐀 = "
    assert len(prefix) == 4
    assert len(prefix.encode("utf-8")) == 7
    assert _utf16_len(prefix) == 5

    module = parse_module(path, tmp_path)
    (diagnostic,) = module.diagnostics
    assert diagnostic.code == "RXT000"
    assert diagnostic.column == 7
    assert diagnostic.column == len(prefix.encode("utf-8"))
    assert diagnostic.column != len(prefix)
    assert diagnostic.column != _utf16_len(prefix)


def test_rxt000_column_in_check_json_report(tmp_path: Path) -> None:
    write_module(tmp_path, "broken.py", 'x = "한글😀" + (\n')

    analysis = analyze_project(tmp_path)
    report_path = write_check_report(tmp_path, analysis)
    report = json.loads(report_path.read_text(encoding="utf-8"))

    assert report["contract_version"] == TOOLING_CONTRACT_VERSION
    assert report["contract_version"] == "2.19.0"

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
