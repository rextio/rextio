from __future__ import annotations

import pytest

from rextio.codegen.rust.type_map import rust_type
from rextio.ir.types import RxtFloat, RxtInt, RxtSet, RxtStr


def test_rust_type_maps_hashable_sets() -> None:
    assert rust_type(RxtSet(RxtInt())) == "HashSet<i64>"
    assert rust_type(RxtSet(RxtStr())) == "HashSet<String>"


def test_rust_type_rejects_float_set_loudly() -> None:
    # set[float] has no faithful native lowering (f64 has no object identity, so a
    # native set cannot reproduce CPython's identity-based NaN dedup). The analyzer
    # keeps it on the Python fallback; this is the backstop so a future gate
    # relaxation fails loudly instead of silently re-emitting the divergent
    # `Vec<f64>` lowering.
    with pytest.raises(TypeError, match="set\\[float\\] has no native Rust representation"):
        rust_type(RxtSet(RxtFloat()))
