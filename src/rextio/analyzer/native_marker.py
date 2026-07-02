"""Recognition of the @rextio.native / @rextio.exempt decorators on functions."""

from __future__ import annotations

import ast
from dataclasses import dataclass

from rextio.targets.models import SUPPORTED_TARGET_LANGUAGES, normalize_target_language


@dataclass(frozen=True)
class NativeMarker:
    """The result of recognizing a native/exempt marker: its kind and optional target."""

    target_language: str | None = None
    error: str | None = None

    @property
    def valid(self) -> bool:
        """Report whether the marker is well-formed."""
        return self.error is None


def dotted_name(node: ast.AST) -> str | None:
    """Return the dotted name of a Name/Attribute node, or None."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = dotted_name(node.value)
        if parent is None:
            return None
        return f"{parent}.{node.attr}"
    return None


def parse_native_marker(node: ast.AST) -> NativeMarker | None:
    """Parse a decorator AST node into a NativeMarker, or None if it is not one."""
    if isinstance(node, ast.Call):
        name = dotted_name(node.func)
    else:
        name = dotted_name(node)
    if name not in {"rextio.native", "native"}:
        return None
    if not isinstance(node, ast.Call):
        return NativeMarker()
    if node.args:
        return NativeMarker(error="@rextio.native only accepts keyword arguments")
    target_language: str | None = None
    for keyword in node.keywords:
        if keyword.arg != "target":
            return NativeMarker(
                error=f"unsupported @rextio.native keyword: {keyword.arg or '**kwargs'}"
            )
        if target_language is not None:
            return NativeMarker(error="duplicate @rextio.native target keyword")
        if not isinstance(keyword.value, ast.Constant) or not isinstance(keyword.value.value, str):
            return NativeMarker(error="@rextio.native target must be a string literal")
        target_language = normalize_target_language(keyword.value.value)
        if target_language not in SUPPORTED_TARGET_LANGUAGES:
            options = ", ".join(sorted(SUPPORTED_TARGET_LANGUAGES))
            return NativeMarker(
                target_language=target_language,
                error=(
                    f"unsupported @rextio.native target: {target_language!r}. "
                    f"Use one of: {options}."
                ),
            )
    return NativeMarker(target_language=target_language)


def native_marker_for_function(node: ast.FunctionDef | ast.AsyncFunctionDef) -> NativeMarker | None:
    """Return the native marker applied to a function, or None."""
    for decorator in node.decorator_list:
        marker = parse_native_marker(decorator)
        if marker is not None:
            return marker
    return None


def is_native_decorator(node: ast.AST) -> bool:
    """Report whether the node is the @rextio.native decorator."""
    return parse_native_marker(node) is not None


def is_exempt_decorator(node: ast.AST) -> bool:
    """Report whether the node is the @rextio.exempt decorator."""
    name = dotted_name(node)
    return name in {"rextio.exempt", "exempt"}


def has_native_marker(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Report whether the function carries an @rextio.native marker."""
    return native_marker_for_function(node) is not None


def has_exempt_marker(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Report whether the function carries an @rextio.exempt marker."""
    return any(is_exempt_decorator(decorator) for decorator in node.decorator_list)


# Decorators from external accelerator packages Rextio recognizes as "this
# function intentionally stays on the Python fallback and is compiled by an
# external tool". Keys are fully-resolved dotted names (module import map
# applied), values name the tool for report labeling. The function's semantics
# are then the TOOL's contract (e.g. Numba nopython int arithmetic wraps on
# overflow), not Rextio's CPython-exact native contract - the same opt-out
# philosophy as @rextio.exempt.
_EXTERNAL_ACCELERATOR_QUALNAMES = {
    "numba.jit": "numba",
    "numba.njit": "numba",
    "numba.vectorize": "numba",
    "numba.guvectorize": "numba",
}


def external_accelerator_for_function(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    imports: dict[str, str],
) -> str | None:
    """Return the external accelerator a decorator applies, or None.

    Resolves the decorator through the module's import map so ``@numba.njit``,
    ``from numba import njit`` + ``@njit``, aliases, and the call forms
    (``@njit(cache=True)``) are all recognized precisely - a user-defined
    decorator that merely shares a bare name is not.
    """
    for decorator in node.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = dotted_name(target)
        if name is None:
            continue
        head, _, rest = name.partition(".")
        resolved_head = imports.get(head)
        if resolved_head is None:
            continue
        resolved = f"{resolved_head}.{rest}" if rest else resolved_head
        tool = _EXTERNAL_ACCELERATOR_QUALNAMES.get(resolved)
        if tool is not None:
            return tool
    return None
