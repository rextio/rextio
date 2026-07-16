from __future__ import annotations

import types

import pytest

from rextio.codegen.python_wrapper.wrapper_gen import (
    _render_builtin_captures,
    _render_method_identity_helpers,
)


def _guard_namespace(source: str) -> dict[str, object]:
    fallback = types.ModuleType("_fallback_ops")
    exec(source, fallback.__dict__)
    namespace: dict[str, object] = {
        "_rextio_fallback_module": fallback,
        "_rextio_types": types,
    }
    exec("\n".join([*_render_builtin_captures(), *_render_method_identity_helpers()]), namespace)
    return namespace


def test_runtime_method_guard_accepts_exact_plain_native_method() -> None:
    namespace = _guard_namespace(
        "import rextio\nclass A:\n    @rextio.native\n    def m(self, x):\n        return x + 1\n"
    )

    require = namespace["_rextio_require_fallback_method"]
    owner, candidate = require(("A",), "m", "A.m", 3)  # type: ignore[operator]
    assert owner is namespace["_rextio_fallback_module"].A  # type: ignore[union-attr]
    assert candidate.__rextio_native__ is True


def test_runtime_method_guard_rejects_missing_native_marker() -> None:
    namespace = _guard_namespace("class A:\n    def m(self, x):\n        return x + 1\n")

    require = namespace["_rextio_require_fallback_method"]
    with pytest.raises(RuntimeError, match="identity mismatch"):
        require(("A",), "m", "A.m", 2)  # type: ignore[operator]


def test_runtime_method_guard_rejects_custom_metaclass_owner() -> None:
    namespace = _guard_namespace(
        "import rextio\n"
        "class Meta(type):\n"
        "    pass\n"
        "class A(metaclass=Meta):\n"
        "    @rextio.native\n"
        "    def m(self, x):\n"
        "        return x + 1\n"
    )

    require = namespace["_rextio_require_fallback_method"]
    with pytest.raises(RuntimeError, match="owner identity mismatch"):
        require(("A",), "m", "A.m", 5)  # type: ignore[operator]
