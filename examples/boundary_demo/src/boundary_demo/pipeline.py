import rextio


@rextio.native
def square(x: float) -> float:
    return x * x


@rextio.native
def sum_squares(xs: list[float]) -> float:
    total = 0.0
    for x in xs:
        total += square(x)
    return total


def fallback_helper(x: float) -> float:
    return x + 10.0


@rextio.native
def compute_rejected(x: float) -> float:
    return fallback_helper(x)


def process_all(xs: list[float]) -> list[float]:
    out = []
    for x in xs:
        out.append(square(x))
    return out
