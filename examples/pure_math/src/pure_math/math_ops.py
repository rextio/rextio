import rextio


@rextio.native
def sum_squares(xs: list[float]) -> float:
    total = 0.0
    for x in xs:
        total += x * x
    return total


@rextio.native
def dot_simple(left: list[float], right: list[float]) -> float:
    total = 0.0
    for i in range(len(left)):
        total += left[i] * right[i]
    return total


@rextio.native
def count_positive(xs: list[int]) -> int:
    count = 0
    for x in xs:
        if x > 0:
            count += 1
    return count
