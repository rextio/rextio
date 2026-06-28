"""Pure Rust-source formatting helpers for the code generator.

These are stateless helpers (literal rendering, paren stripping, default values,
indentation, Python-`%` format conversion) extracted from ``generator.py`` so the
generator module is concerned with rendering logic rather than string plumbing.
No behavior change — ``generator`` re-imports these names.
"""

from __future__ import annotations

from rextio.codegen.rust.errors import RustCodegenError
from rextio.ir.nodes import BlockIR, ExprIR, ReturnIR, TupleIR

# Characters that have a short Rust escape; everything else printable is emitted
# as-is (Rust source is UTF-8), and remaining control characters use `\u{..}`.
_RUST_STRING_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
    "\0": "\\0",
}


def rust_string_literal(value: str) -> str:
    """Render a Python ``str`` as a Rust string literal that is always valid.

    Unlike ``json.dumps`` (which emits ``\\uXXXX`` / surrogate-pair escapes that
    Rust does not accept), this escapes only the characters that must be escaped
    in a Rust string — ``"``, ``\\``, and control characters (via ``\\u{..}``) —
    and emits every other character, including non-ASCII, literally. This keeps
    user string literals from producing uncompilable Rust and leaves no way for a
    literal to break out of the string (injection-safe).
    """
    out = ['"']
    for char in value:
        codepoint = ord(char)
        escape = _RUST_STRING_ESCAPES.get(char)
        if escape is not None:
            out.append(escape)
        elif codepoint < 0x20 or codepoint == 0x7F:
            out.append(f"\\u{{{codepoint:x}}}")
        elif 0xD800 <= codepoint <= 0xDFFF:
            # Lone surrogates are valid in a Python ``str`` (e.g. ``"\ud83e"``) but
            # are not Unicode scalar values: Rust rejects both ``\u{d83e}`` and a
            # raw surrogate, and encoding the .rs file as UTF-8 would itself raise
            # ``UnicodeEncodeError``. There is no representable Rust string for
            # them, so fail with a clear diagnostic rather than emitting garbage.
            raise RustCodegenError(
                f"cannot encode lone surrogate U+{codepoint:04X} in a Rust string "
                "literal (not a valid Unicode scalar value)"
            )
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def render_literal(value: object) -> str:
    if value is None:
        return "None"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return f"String::from({rust_string_literal(value)})"
    if isinstance(value, bytes):
        return f"vec![{', '.join(str(item) for item in value)}]"
    return repr(value)


def python_logging_format_to_rust(value: str) -> tuple[str, int] | None:
    output: list[str] = []
    placeholders = 0
    index = 0
    while index < len(value):
        char = value[index]
        if char == "%":
            if index + 1 >= len(value):
                return None
            specifier = value[index + 1]
            if specifier == "%":
                output.append("%")
                index += 2
                continue
            if specifier in {"s", "d", "i", "f"}:
                output.append("{}")
                placeholders += 1
                index += 2
                continue
            if specifier == "r":
                output.append("{:?}")
                placeholders += 1
                index += 2
                continue
            return None
        if char == "{":
            output.append("{{")
        elif char == "}":
            output.append("}}")
        else:
            output.append(char)
        index += 1
    return "".join(output), placeholders


def strip_wrapping_parens(value: str) -> str:
    if not value.startswith("(") or not value.endswith(")"):
        return value
    depth = 0
    for index, char in enumerate(value):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0 and index != len(value) - 1:
                return value
    if depth == 0:
        return value[1:-1]
    return value


def strip_expr_if_safe(expr: ExprIR, value: str) -> str:
    if isinstance(expr, TupleIR):
        return value
    return strip_wrapping_parens(value)


def default_return(return_type: str) -> str:
    if return_type == "()":
        return "()"
    if return_type == "bool":
        return "false"
    if return_type == "String":
        return "String::new()"
    if return_type.startswith("Vec<"):
        return "Vec::new()"
    if return_type.startswith("HashMap<"):
        return "HashMap::new()"
    if return_type.startswith("HashSet<"):
        return "HashSet::new()"
    if return_type.startswith("Option<"):
        return "None"
    if return_type == "i64":
        return "0"
    if return_type == "f64":
        return "0.0"
    return "Default::default()"


def block_always_returns(block: BlockIR) -> bool:
    return bool(block.statements) and isinstance(block.statements[-1], ReturnIR)


def indent(level: int) -> str:
    return "    " * level
