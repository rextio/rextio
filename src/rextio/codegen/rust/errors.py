"""Shared error type for the Rust code generator.

Lives in its own module so submodules can raise it without
importing ``generator`` and creating an import cycle. ``generator`` re-exports
``RustCodegenError`` for backward compatibility.
"""

from __future__ import annotations


class RustCodegenError(RuntimeError):
    """Raised when Rust source cannot be generated from the IR."""

    pass
