"""Typed hot paths that Rextio lowers to native Rust."""


def sum_squares(xs: list[int]) -> int:
    total = 0
    for x in xs:
        total += x * x
    return total


def weighted_sum(xs: list[float], factor: float) -> float:
    total = 0.0
    for x in xs:
        total += x * factor
    return total
