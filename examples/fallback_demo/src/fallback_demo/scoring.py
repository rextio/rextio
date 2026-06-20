import rextio


@rextio.native
def score_one(value: float) -> float:
    return value * 2.0 + 1.0


def score_python_batch(values: list[float]) -> list[float]:
    out = []
    for value in values:
        out.append(score_one(value))
    return out
