"""NumPy array kernel accelerated by Numba on the Python fallback.

Rextio recognizes the ``numba.njit`` decorator as an external accelerator:
the function is excluded from native discovery and stays on the Python
fallback, where Numba JIT-compiles it under NUMBA'S semantics (for example,
nopython-mode integer arithmetic wraps on overflow). That trade is the
user's explicit opt-in, outside Rextio's native contract.
"""

import numpy as np
from numba import njit


@njit(cache=True)
def rolling_mean(values: np.ndarray, window: int) -> np.ndarray:
    out = np.empty(values.shape[0] - window + 1, dtype=np.float64)
    acc = 0.0
    for i in range(window):
        acc += values[i]
    out[0] = acc / window
    for i in range(window, values.shape[0]):
        acc += values[i] - values[i - window]
        out[i - window + 1] = acc / window
    return out
