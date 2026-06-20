from __future__ import annotations

import ast


def dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = dotted_name(node.value)
        if parent is None:
            return None
        return f"{parent}.{node.attr}"
    return None


def is_native_decorator(node: ast.AST) -> bool:
    name = dotted_name(node)
    return name in {"rextio.native", "native"}


def has_native_marker(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(is_native_decorator(decorator) for decorator in node.decorator_list)
