"""Mapping of Rextio types to their Rust representations."""

from __future__ import annotations

from rextio.ir.types import (
    RxtBool,
    RxtBytes,
    RxtDict,
    RxtFloat,
    RxtInt,
    RxtList,
    RxtNone,
    RxtOptional,
    RxtPyObject,
    RxtSet,
    RxtStr,
    RxtTuple,
    RxtType,
)


def rust_type(rxt_type: RxtType) -> str:
    """Return the Rust type string for a Rextio type."""
    if isinstance(rxt_type, RxtInt):
        return "i64"
    if isinstance(rxt_type, RxtFloat):
        return "f64"
    if isinstance(rxt_type, RxtBool):
        return "bool"
    if isinstance(rxt_type, RxtStr):
        return "String"
    if isinstance(rxt_type, RxtBytes):
        return "Vec<u8>"
    if isinstance(rxt_type, RxtNone):
        return "()"
    if isinstance(rxt_type, RxtPyObject):
        return "Py<PyAny>"
    if isinstance(rxt_type, RxtList):
        return f"Vec<{rust_type(rxt_type.item_type)}>"
    if isinstance(rxt_type, RxtSet):
        if isinstance(rxt_type.item_type, RxtFloat):
            # `set[float]` has no faithful native lowering: no Rust
            # representation reproduces CPython's identity-based NaN dedup,
            # so the analyzer keeps it on the Python
            # fallback (`float` is not in `SET_ITEM_TYPES`). Fail loudly here so a
            # future relaxation of that gate surfaces as a build error instead of
            # silently re-introducing the divergent lowering.
            raise TypeError(
                "set[float] has no native Rust representation; it must stay on the "
                "Python fallback (float is excluded from SET_ITEM_TYPES)"
            )
        return f"HashSet<{rust_type(rxt_type.item_type)}>"
    if isinstance(rxt_type, RxtTuple):
        if len(rxt_type.item_types) == 1:
            return f"({rust_type(rxt_type.item_types[0])},)"
        return f"({', '.join(rust_type(item_type) for item_type in rxt_type.item_types)})"
    if isinstance(rxt_type, RxtDict):
        return f"HashMap<{rust_type(rxt_type.key_type)}, {rust_type(rxt_type.value_type)}>"
    if isinstance(rxt_type, RxtOptional):
        return f"Option<{rust_type(rxt_type.item_type)}>"
    raise TypeError(f"unsupported Rextio type for Rust: {type(rxt_type).__name__}")
