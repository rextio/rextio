"""Typed hot path that Rextio lowers to native Rust."""


def mix_series(n: int, seed: int) -> int:
    total = 0
    acc = seed
    for i in range(1, n):
        acc = (acc * 31 + i) % 1000000007
        total += acc
    return total
