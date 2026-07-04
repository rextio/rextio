"""Typed hot path that Rextio lowers to native Rust."""


def checksum(values: list[int]) -> int:
    total = 0
    for value in values:
        total = (total * 131 + value) % 1000000007
    return total
