from __future__ import annotations

import pytest

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


@pytest.mark.parametrize("target", ["mojo", "Julia", " RUST "])
def test_native_decorator_accepts_supported_targets(target: str) -> None:
    @rextio.native(target=target)
    def helper() -> int:
        return 1

    assert getattr(helper, "__rextio_native_target__") == target.strip().lower()


@pytest.mark.parametrize("target", ["cpp", "", "   ", "rsut"])
def test_native_decorator_rejects_unsupported_target(target: str) -> None:
    with pytest.raises(ValueError, match="not supported"):
        rextio.native(target=target)


def test_native_decorator_rejects_non_string_target() -> None:
    with pytest.raises(TypeError, match="must be a string"):
        rextio.native(target=123)  # type: ignore[arg-type]


def test_native_decorator_rejects_classes() -> None:
    with pytest.raises(TypeError, match="functions, not classes"):

        @rextio.native
        class Service:  # pragma: no cover - decoration raises
            pass


def test_native_decorator_rejects_non_callable() -> None:
    with pytest.raises(TypeError, match="callables"):
        rextio.native(42)  # type: ignore[arg-type]


def test_exempt_decorator_rejects_classes() -> None:
    with pytest.raises(TypeError, match="functions, not classes"):

        @rextio.exempt
        class Service:  # pragma: no cover - decoration raises
            pass


def test_exempt_decorator_rejects_non_callable() -> None:
    with pytest.raises(TypeError, match="callables"):
        rextio.exempt(42)  # type: ignore[arg-type]
