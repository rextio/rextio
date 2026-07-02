"""Parsing of printf-style logging format strings.

Shared by the analyzer (which validates each ``%`` conversion against the
argument's inferred type, rejecting combinations with no CPython-exact native
lowering) and the Rust code generator (which renders the accepted
combinations). Living in the analyzer package keeps the dependency direction
codegen -> analyzer.
"""

from __future__ import annotations


def python_logging_format_segments(value: str) -> tuple[list[str], list[str]] | None:
    """Split a printf-style logging format into literal segments + specifiers.

    Returns ``(segments, specifiers)`` where ``segments`` has exactly one more
    element than ``specifiers`` and the original string is
    ``segments[0] + %spec[0] + segments[1] + ...``. Segment text is already
    escaped for use inside a Rust format string (`{`/`}` doubled). Returns
    ``None`` for conversions outside the supported ``%s %d %i %f %r`` set, so
    the caller can reject (analyzer) or fall back (legacy paths).
    """
    segments: list[str] = []
    specifiers: list[str] = []
    current: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "%":
            if index + 1 >= len(value):
                return None
            specifier = value[index + 1]
            if specifier == "%":
                current.append("%")
                index += 2
                continue
            if specifier in {"s", "d", "i", "f", "r"}:
                segments.append("".join(current))
                current = []
                specifiers.append(specifier)
                index += 2
                continue
            return None
        if char == "{":
            current.append("{{")
        elif char == "}":
            current.append("}}")
        else:
            current.append(char)
        index += 1
    segments.append("".join(current))
    return segments, specifiers
