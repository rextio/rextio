from __future__ import annotations


def nuitka_unavailable_message() -> str:
    return (
        "Nuitka fallback was requested, but Nuitka is not installed.\n"
        "Install Nuitka or run: rextio build --fallback=cpython"
    )
