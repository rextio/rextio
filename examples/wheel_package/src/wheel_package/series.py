"""Typed hot paths shipped as native Rust inside the wheel."""


def harmonic_like(n: int) -> float:
    total = 0.0
    value = 1.0
    i = 0
    while i < n:
        total += 1.0 / value
        value += 1.0
        i += 1
    return total


def window_max(values: list[int]) -> int:
    best = values[0]
    for value in values:
        if value > best:
            best = value
    return best
