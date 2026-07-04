"""Typed functions exported both to Python and to Rust callers."""


def mean_abs_delta(values: list[float]) -> float:
    n = len(values)
    if n < 2:
        return 0.0
    total = 0.0
    denom = 0.0
    i = 1
    while i < n:
        delta = values[i] - values[i - 1]
        if delta < 0.0:
            delta = -delta
        total += delta
        denom += 1.0
        i += 1
    return total / denom


def scaled_sum(values: list[int], factor: int) -> int:
    total = 0
    for value in values:
        total += value * factor
    return total
