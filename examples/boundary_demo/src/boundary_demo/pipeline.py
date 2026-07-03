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


@rextio.exempt
def fallback_helper(x: float) -> float:
    return x + 10.0


@rextio.native
def compute_boundary(x: float) -> float:
    # A marked native calling a scalar-signature fallback function survives:
    # this is an in-process scalar boundary call (RXT075). The helper keeps
    # running in the interpreter, and each call counts toward the
    # boundary-fallback threshold.
    return fallback_helper(x)


@rextio.exempt
def batch_helper(xs: list[float]) -> float:
    return sum(xs) / len(xs)


@rextio.native
def compute_rejected(xs: list[float]) -> float:
    # A container-signature fallback callee cannot cross the boundary
    # (aliasing would sever), so this caller is rejected to the Python
    # fallback (RXT070).
    return batch_helper(xs)


def process_all(xs: list[float]) -> list[float]:
    out = []
    for x in xs:
        out.append(square(x))
    return out
