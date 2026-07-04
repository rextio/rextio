"""Timing demo: Rextio-native scalar path vs. Numba-JIT array path."""

import time

import numpy as np

from numba_accelerator.array_ops import rolling_mean
from numba_accelerator.scalar_ops import polynomial_sum


def main() -> None:
    started = time.perf_counter()
    total = polynomial_sum(2_000_000)
    scalar_seconds = time.perf_counter() - started
    print(f"polynomial_sum: {total} in {scalar_seconds:.4f}s")

    values = np.arange(2_000_000, dtype=np.float64)
    rolling_mean(values[:16], 4)  # warm up the Numba JIT before timing
    started = time.perf_counter()
    means = rolling_mean(values, 32)
    array_seconds = time.perf_counter() - started
    print(f"rolling_mean: {means.shape[0]} points in {array_seconds:.4f}s")


if __name__ == "__main__":
    main()
