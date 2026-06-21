from __future__ import annotations

import ast
from dataclasses import dataclass

from rextio.targets.models import SUPPORTED_TARGET_LANGUAGES, normalize_target_language


@dataclass(frozen=True)
class NativeMarker:
    target_language: str | None = None
    error: str | None = None

    @property
    def valid(self) -> bool:
        return self.error is None


def dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = dotted_name(node.value)
        if parent is None:
            return None
        return f"{parent}.{node.attr}"
    return None


def parse_native_marker(node: ast.AST) -> NativeMarker | None:
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
    for decorator in node.decorator_list:
        marker = parse_native_marker(decorator)
        if marker is not None:
            return marker
    return None


def is_native_decorator(node: ast.AST) -> bool:
    return parse_native_marker(node) is not None


def is_exempt_decorator(node: ast.AST) -> bool:
    name = dotted_name(node)
    return name in {"rextio.exempt", "exempt"}


def has_native_marker(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return native_marker_for_function(node) is not None


def has_exempt_marker(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(is_exempt_decorator(decorator) for decorator in node.decorator_list)
