"""Dynamic formatting code that stays on the (Nuitka-compiled) fallback."""

from nuitka_fallback.kernels import sum_squares, weighted_sum


def describe(xs: list[int], factor: float) -> str:
    # f-strings and dict formatting keep this function outside the direct
    # Rust subset - it runs on the fallback, which the Nuitka backend
    # compiles into a C extension module.
    stats = {
        "sum_squares": sum_squares(xs),
        "weighted": weighted_sum([float(x) for x in xs], factor),
    }
    return ", ".join(f"{key}={value}" for key, value in stats.items())
