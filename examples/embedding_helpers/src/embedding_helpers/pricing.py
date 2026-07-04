"""A marked native hot path calling a tiny unmarked scalar helper.

Without embedding, each helper call is an in-process scalar boundary call
(RXT075): it crosses into the interpreter and counts toward the demotion
threshold. With ``[embedding] enabled`` (or ``--embed-helpers``) the helper
compiles INTO the native artifact as an internal function, removing the
per-call round-trip.
"""

import rextio


def margin(price: float) -> float:
    return price * 0.2 + 1.5


@rextio.native
def total_margin(base: float) -> float:
    total = 0.0
    total += margin(base)
    total += margin(base + 1.0)
    total += margin(base + 2.0)
    return total
