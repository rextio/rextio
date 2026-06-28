"""Rust string-literal escaping for user-provided string constants (P1-6).

Generated code must (1) never let a user string literal break out of the Rust
string (injection safety) and (2) always be valid Rust, including for non-ASCII
characters (`json.dumps` emits `\\uXXXX`/surrogate escapes Rust rejects).
"""

from __future__ import annotations

import pytest

from rextio.codegen.rust.rust_format import render_literal, rust_string_literal


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("ready", '"ready"'),
        ("", '""'),
        ('quote"', '"quote\\""'),
        ("back\\slash", '"back\\\\slash"'),
        ("tab\tnew\nret\r", '"tab\\tnew\\nret\\r"'),
        ("nul\0byte", '"nul\\0byte"'),
        ("ctrl\x01\x1f", '"ctrl\\u{1}\\u{1f}"'),
        ("\x7f", '"\\u{7f}"'),
        # Non-ASCII is emitted literally (Rust source is UTF-8) — valid Rust.
        ("café", '"café"'),
        ("emoji 🦀", '"emoji 🦀"'),
        # An attempt to break out of the string / inject code stays a literal.
        ('"; std::process::exit(1); //', '"\\"; std::process::exit(1); //"'),
        ("*/ end comment", '"*/ end comment"'),
    ],
)
def test_rust_string_literal_is_valid_and_escaped(value: str, expected: str) -> None:
    assert rust_string_literal(value) == expected


def test_render_literal_wraps_string_in_string_from() -> None:
    assert render_literal("café") == 'String::from("café")'


def test_no_raw_json_unicode_escapes_leak() -> None:
    # Regression: `json.dumps` would have produced `é` (invalid Rust); the
    # literal must contain the raw character, not a `\uXXXX` escape.
    rendered = rust_string_literal("café")
    assert "\\u00e9" not in rendered
    assert "é" in rendered
