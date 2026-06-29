"""Helpers for reading and validating type annotations."""

from __future__ import annotations

import ast

from rextio.capabilities import (
    DICT_KEY_TYPES,
    LIST_ITEM_TYPES,
    SCALAR_TYPES,
    SET_ITEM_TYPES,
)

# Aliases onto the shared capability matrix (see rextio.capabilities). Kept under
# the existing names so call sites are unchanged while the values have one source.
SUPPORTED_SCALARS = SCALAR_TYPES
SUPPORTED_LIST_ITEMS = LIST_ITEM_TYPES
SUPPORTED_DICT_KEYS = DICT_KEY_TYPES
SUPPORTED_SET_ITEMS = SET_ITEM_TYPES


def annotation_name(node: ast.AST | None) -> str:
    """Return the display name of a type annotation node."""
    if node is None:
        return "<missing>"
    display = _display_type(node)
    if display is not None:
        return display
    return ast.unparse(node)


def is_supported_type(node: ast.AST | None) -> bool:
    """Report whether an annotation denotes a supported native type."""
    return _display_type(node) is not None


def _display_type(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    if isinstance(node, ast.Name):
        if node.id in SUPPORTED_SCALARS or node.id == "None":
            return node.id
        return None
    if isinstance(node, ast.Constant) and node.value is None:
        return "None"
    optional_inner = _optional_inner(node)
    if optional_inner is not None:
        inner_display = _display_type(optional_inner)
        if inner_display is not None and inner_display != "None" and not _is_optional_display(inner_display):
            return f"Optional[{inner_display}]"
        return None
    if isinstance(node, ast.Subscript):
        value_name = _annotation_dotted_name(node.value)
        if value_name == "list" and _is_supported_list_item(node.slice):
            return f"list[{_display_type(node.slice)}]"
        if value_name == "set" and _is_supported_set_item(node.slice):
            return f"set[{_display_type(node.slice)}]"
        if value_name == "tuple":
            tuple_items = _tuple_slice_items(node.slice)
            if tuple_items and all(_is_supported_tuple_item(item) for item in tuple_items):
                return f"tuple[{', '.join(_display_type(item) or ast.unparse(item) for item in tuple_items)}]"
        if value_name == "dict":
            dict_items = _tuple_slice_items(node.slice)
            if (
                len(dict_items) == 2
                and _is_supported_dict_key(dict_items[0])
                and _is_supported_dict_value(dict_items[1])
            ):
                return f"dict[{_display_type(dict_items[0])}, {_display_type(dict_items[1])}]"
    return None


def _is_supported_list_item(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return node.id in SUPPORTED_LIST_ITEMS
    if isinstance(node, ast.Subscript) and _annotation_dotted_name(node.value) == "list":
        return _is_supported_list_item(node.slice)
    return False


def _is_supported_set_item(node: ast.AST) -> bool:
    return isinstance(node, ast.Name) and node.id in SUPPORTED_SET_ITEMS


def _is_supported_dict_key(node: ast.AST) -> bool:
    return isinstance(node, ast.Name) and node.id in SUPPORTED_DICT_KEYS


def _is_supported_dict_value(node: ast.AST) -> bool:
    display = _display_type(node)
    return display is not None and display != "None" and not display.startswith("set[")


def _is_supported_tuple_item(node: ast.AST) -> bool:
    return isinstance(node, ast.Name) and node.id in SUPPORTED_SCALARS


def _optional_inner(node: ast.AST) -> ast.AST | None:
    if isinstance(node, ast.Subscript) and _annotation_dotted_name(node.value) in {"Optional", "typing.Optional"}:
        return node.slice
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left_is_none = _is_none_annotation(node.left)
        right_is_none = _is_none_annotation(node.right)
        if left_is_none and not right_is_none:
            return node.right
        if right_is_none and not left_is_none:
            return node.left
    return None


def _is_none_annotation(node: ast.AST) -> bool:
    return (
        (isinstance(node, ast.Name) and node.id == "None")
        or (isinstance(node, ast.Constant) and node.value is None)
    )


def _annotation_dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _annotation_dotted_name(node.value)
        if prefix is None:
            return None
        return f"{prefix}.{node.attr}"
    return None


def _tuple_slice_items(node: ast.AST) -> list[ast.AST]:
    if isinstance(node, ast.Tuple):
        return list(node.elts)
    return [node]


def _is_optional_display(value: str) -> bool:
    return value.startswith("Optional[") and value.endswith("]")
