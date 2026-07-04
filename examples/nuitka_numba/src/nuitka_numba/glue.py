"""Dynamic glue code that the Nuitka backend compiles."""

from nuitka_numba.hot_path import mix_series


def summary(n: int, seed: int) -> str:
    result = mix_series(n, seed)
    return f"mix_series(n={n}, seed={seed}) -> {result}"
