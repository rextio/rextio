from __future__ import annotations

import rextio


def test_exempt_decorator_marks_function_without_wrapping() -> None:
    def helper() -> int:
        return 1

    marked = rextio.exempt(helper)

    assert marked is helper
    assert marked() == 1
    assert getattr(marked, "__rextio_exempt__") is True
