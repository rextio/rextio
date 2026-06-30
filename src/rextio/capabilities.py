"""Single source of truth for the Rextio native subset's supported types.

The analyzer (which decides whether a function is accepted into the native
subset) and the code generator (which must emit Rust for every accepted
construct) have to agree on exactly which Python types are supported. When these
sets are duplicated across modules they drift, producing the worst failure mode
for a compiler: *analysis accepts, codegen fails* (mod-proposal P2-5).

Defining the type-capability matrix here once — and importing it everywhere —
keeps the analyzer and backend in lockstep. ``tests/capabilities/`` asserts the
backend's type mapping covers every type named here.

These are ``frozenset`` so a caller cannot accidentally mutate the shared
capability matrix.
"""

from __future__ import annotations

# Scalar Python types accepted as parameter / return / local value types.
SCALAR_TYPES: frozenset[str] = frozenset({"int", "float", "bool", "str", "bytes"})

# Numeric scalars (the arithmetic-capable subset of ``SCALAR_TYPES``).
NUMERIC_TYPES: frozenset[str] = frozenset({"int", "float"})

# Item types allowed inside ``list[...]``.
LIST_ITEM_TYPES: frozenset[str] = frozenset({"int", "float", "bool", "str"})

# Key types allowed inside ``dict[K, V]``.
DICT_KEY_TYPES: frozenset[str] = frozenset({"int", "bool", "str"})

# Item types allowed inside ``set[...]``. `float` is excluded: a Rust set of
# f64 (lowered as Vec + `contains`) cannot reproduce CPython's set semantics for
# NaN -- CPython dedups the *same* NaN object by identity (`{n, n}` has length 1)
# while f64 has no object identity, so the native set would keep both. There is
# no faithful native lowering, so `set[float]` stays on the Python fallback
# (same call as `dict[float, ...]` keys, which are excluded for the same reason).
SET_ITEM_TYPES: frozenset[str] = frozenset({"int", "bool", "str"})

# Value types that may appear in a value lowered to/from JSON.
JSON_VALUE_TYPES: frozenset[str] = frozenset({"int", "float", "bool", "str", "bytes"})
