from __future__ import annotations


def nuitka_unavailable_message() -> str:
    return (
        "Nuitka fallback was requested, but Nuitka is not installed.\n"
        "Install Nuitka or run: rextio build --fallback=cpython"
    )


def nuitka_not_implemented_message() -> str:
    return (
        "Nuitka fallback is experimental and is not implemented in this Public 1 build slice.\n"
        "Run: rextio build --fallback=cpython"
    )
