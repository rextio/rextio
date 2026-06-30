"""Sanitization of Python qualnames into valid native (Rust) identifiers."""

from __future__ import annotations

import re

# The code generator emits every internal temporary and helper with this prefix
# (e.g. ``__rextio_min_a_1``, ``__rextio_checked_add``, ``__rextio_top_level__``).
# The analyzer rejects user identifiers sharing it so a generated ``let`` binding
# can never silently shadow a user name. Kept here, next to the other native
# naming rules, so the analyzer and code generator cannot drift apart.
RESERVED_NATIVE_PREFIX = "__rextio"


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
