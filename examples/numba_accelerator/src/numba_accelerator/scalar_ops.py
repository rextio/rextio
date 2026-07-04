"""Typed scalar hot path that Rextio lowers to native Rust."""


def polynomial_sum(n: int) -> int:
    total = 0
    for i in range(n):
        total += i * i + 3 * i + 1
    return total
