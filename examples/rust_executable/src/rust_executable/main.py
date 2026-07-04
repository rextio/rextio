"""Entrypoint compiled into a native Rust binary.

The whole call graph is direct-native, so the produced binary is standalone:
no Python interpreter is needed on the target machine. If the entrypoint
called a fallback-only project function instead, Rextio would ship a
`dist/<name>.runtime/` directory and delegate that call to an external
CPython subprocess (hybrid mode).
"""


def count_primes(limit: int) -> int:
    count = 0
    for n in range(2, limit):
        is_prime = True
        d = 2
        while d * d <= n:
            if n % d == 0:
                is_prime = False
                break
            d += 1
        if is_prime:
            count += 1
    return count


def main(argv: list[str]) -> int:
    # String-to-int parsing is outside the direct-native subset, so the
    # limit scales with the number of extra arguments instead: each extra
    # argument adds 50000 to the default limit of 50000.
    limit = 50000 * len(argv)
    print(count_primes(limit))
    return 0
