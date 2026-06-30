"""The built-in Python exceptions Rextio can catch natively.

Native ``try``/``except`` support is restricted to this fixed set of built-in
exception types so the analyzer and the PyO3 code generator cannot drift: the
analyzer rejects handlers for anything outside these names (keeping the function
on the Python fallback), and the generator maps each name to its PyO3 type for
``PyErr::is_instance_of`` matching.

Ordered most-derived first only matters for documentation; Python's own
top-to-bottom handler order is what the generator preserves.
"""

from __future__ import annotations

# Built-in exception name -> PyO3 exception type path.
BUILTIN_EXCEPTION_TO_PYO3: dict[str, str] = {
    "ZeroDivisionError": "pyo3::exceptions::PyZeroDivisionError",
    "OverflowError": "pyo3::exceptions::PyOverflowError",
    "IndexError": "pyo3::exceptions::PyIndexError",
    "KeyError": "pyo3::exceptions::PyKeyError",
    "ValueError": "pyo3::exceptions::PyValueError",
    "TypeError": "pyo3::exceptions::PyTypeError",
    "ArithmeticError": "pyo3::exceptions::PyArithmeticError",
    "RuntimeError": "pyo3::exceptions::PyRuntimeError",
    "Exception": "pyo3::exceptions::PyException",
}


def is_supported_builtin_exception(name: str) -> bool:
    """Report whether a name is a natively-catchable built-in exception."""
    return name in BUILTIN_EXCEPTION_TO_PYO3
