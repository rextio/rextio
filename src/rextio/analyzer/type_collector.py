from __future__ import annotations

import ast

SUPPORTED_SCALARS = {"int", "float", "bool", "str"}
SUPPORTED_LIST_ITEMS = {"int", "float", "bool", "str"}


def annotation_name(node: ast.AST | None) -> str:
    if node is None:
        return "<missing>"
    return ast.unparse(node)


def is_supported_type(node: ast.AST | None) -> bool:
    if node is None:
        return False
    if isinstance(node, ast.Name):
        return node.id in SUPPORTED_SCALARS or node.id == "None"
    if isinstance(node, ast.Constant) and node.value is None:
        return True
    if isinstance(node, ast.Subscript):
        if not isinstance(node.value, ast.Name) or node.value.id != "list":
            return False
        return _is_supported_list_item(node.slice)
    return False


def _is_supported_list_item(node: ast.AST) -> bool:
    return isinstance(node, ast.Name) and node.id in SUPPORTED_LIST_ITEMS
