from __future__ import annotations

import rextio


def test_exempt_decorator_marks_function_without_wrapping() -> None:
    def helper() -> int:
        return 1

    marked = rextio.exempt(helper)

    assert marked is helper
    assert marked() == 1
    assert getattr(marked, "__rextio_exempt__") is True


def test_native_decorator_accepts_target_keyword() -> None:
    @rextio.native(target="Rust")
    def helper() -> int:
        return 1

    assert helper() == 1
    assert getattr(helper, "__rextio_native__") is True
    assert getattr(helper, "__rextio_native_target__") == "rust"


def test_native_decorator_keeps_bare_form() -> None:
    def helper() -> int:
        return 1

    marked = rextio.native(helper)

    assert marked is helper
    assert marked() == 1
    assert getattr(marked, "__rextio_native__") is True
    assert not hasattr(marked, "__rextio_native_target__")
