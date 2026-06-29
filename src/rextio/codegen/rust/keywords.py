"""Rust 2021 keyword data shared by the analyzer and the code generator.

The analyzer (RXT011 identifier validation) uses it to decide which Python
identifiers cannot be lowered at all, and the code generator uses it to escape the
rest as raw identifiers (``r#name``). Keeping the data in one leaf module prevents
the two from drifting.
"""

from __future__ import annotations

# Rust 2021 strict + reserved keywords.
RUST_KEYWORDS: frozenset[str] = frozenset(
    {
        # Strict keywords.
        "as", "break", "const", "continue", "crate", "dyn", "else", "enum",
        "extern", "false", "fn", "for", "if", "impl", "in", "let", "loop",
        "match", "mod", "move", "mut", "pub", "ref", "return", "self", "Self",
        "static", "struct", "super", "trait", "true", "type", "unsafe", "use",
        "where", "while", "async", "await",
        # Reserved for future use.
        "abstract", "become", "box", "do", "final", "macro", "override", "priv",
        "typeof", "unsized", "virtual", "yield", "try",
    }
)

# A raw identifier (`r#name`) can express any keyword EXCEPT these, so a parameter
# or local with one of these names cannot be lowered to Rust at all.
RUST_RAW_INCOMPATIBLE: frozenset[str] = frozenset({"crate", "self", "Self", "super"})

# Keywords that CAN be carried as raw identifiers, so codegen escapes them and the
# analyzer leaves them on the native path.
RUST_RAWABLE_KEYWORDS: frozenset[str] = RUST_KEYWORDS - RUST_RAW_INCOMPATIBLE
