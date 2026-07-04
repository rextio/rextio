"""Numba-accelerated module that the Nuitka backend must keep as plain Python.

Numba JIT-compiles from Python bytecode; a Nuitka-compiled module exposes
none, so Rextio's ``--fallback=nuitka`` backend detects the accelerator
decorator and keeps this module as importable ``.py`` source while the rest
of the fallback tree is Nuitka-compiled.
"""

import numpy as np
from numba import njit


@njit(cache=True)
def clipped_cumsum(values: np.ndarray, limit: float) -> np.ndarray:
    out = np.empty_like(values)
    acc = 0.0
    for i in range(values.shape[0]):
        acc += values[i]
        if acc > limit:
            acc = limit
        out[i] = acc
    return out
