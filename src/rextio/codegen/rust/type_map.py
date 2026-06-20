from __future__ import annotations

from rextio.ir.types import RxtBool, RxtFloat, RxtInt, RxtList, RxtNone, RxtStr, RxtType


def rust_type(rxt_type: RxtType) -> str:
    if isinstance(rxt_type, RxtInt):
        return "i64"
    if isinstance(rxt_type, RxtFloat):
        return "f64"
    if isinstance(rxt_type, RxtBool):
        return "bool"
    if isinstance(rxt_type, RxtStr):
        return "String"
    if isinstance(rxt_type, RxtNone):
        return "()"
    if isinstance(rxt_type, RxtList):
        return f"Vec<{rust_type(rxt_type.item_type)}>"
    raise TypeError(f"unsupported Rextio type for Rust: {type(rxt_type).__name__}")
