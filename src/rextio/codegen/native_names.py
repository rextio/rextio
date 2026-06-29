"""Sanitization of Python qualnames into valid native (Rust) identifiers."""

from __future__ import annotations

import re


def native_function_name(qualname: str) -> str:
    """Return the sanitized native (Rust) identifier for a qualname; raises ValueError if empty."""
    name = re.sub(r"[^0-9a-zA-Z_]+", "__", qualname).strip("_")
    if not name:
        raise ValueError("native function qualname produced an empty name")
    if name[0].isdigit():
        return f"_{name}"
    return name


def runtime_original_name(qualname: str) -> str:
    """Return the runtime-dispatch name preserving the original Python qualname."""
    return f"_rextio_original_{native_function_name(qualname)}"
