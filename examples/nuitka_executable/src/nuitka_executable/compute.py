"""Typed hot path that Rextio lowers to native Rust."""


def triangle_mod(n: int) -> int:
    total = 0
    for i in range(n):
        total = (total + i) % 998244353
    return total
