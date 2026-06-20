import rextio


@rextio.native
def compute_score(values: list[float]) -> float:
    total = 0.0
    for value in values:
        total += value * value
    return total
