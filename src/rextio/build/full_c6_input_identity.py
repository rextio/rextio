"""Shared canonical build-input names for the bounded Full C6 transaction."""

from __future__ import annotations


_GENERATED_EVIDENCE_PREFIX = ".rextio/generated/"
_GENERATED_BUILD_INPUT_PREFIX = "generated/"
_GENERATED_INPUT_ROLES = frozenset(
    {
        "generated-python-input",
        "generated-rust-input",
    }
)


def canonical_full_c6_build_input_name(logical_path: str, role: str) -> str:
    """Return the one closure name for an exact Full C6 evidence reference.

    Generated evidence is captured beneath Rextio's private ``.rextio`` build
    directory, while the path-safe Full C6 owner-policy namespace deliberately
    names the same bytes beneath ``generated``.  No other dot-prefixed path or
    evidence role is rewritten.
    """
    if type(logical_path) is not str or type(role) is not str:
        raise TypeError("Full C6 build-input identity fields must be strings")
    if role in _GENERATED_INPUT_ROLES and logical_path.startswith(
        _GENERATED_EVIDENCE_PREFIX
    ):
        suffix = logical_path[len(_GENERATED_EVIDENCE_PREFIX) :]
        if not suffix:
            raise ValueError("Full C6 generated build-input identity is incomplete")
        return f"{_GENERATED_BUILD_INPUT_PREFIX}{suffix}"
    return logical_path


__all__: list[str] = []
