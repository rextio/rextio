"""Pure type-string and AST-shape predicates for the native subset checker.

Stateless classification helpers (is-this-a-list/dict/set/tuple/optional type,
item-type extraction, assignability/comparability, small AST-shape checks)
extracted from ``unsupported_patterns.py``. They depend only on the capability
matrix and ``ast``, so both the validation and inference layers can share them
without an import cycle. Pure move, no behavior change.
"""

from __future__ import annotations

import ast

from rextio.analyzer.native_marker import dotted_name
from rextio.capabilities import DICT_KEY_TYPES, JSON_VALUE_TYPES, SET_ITEM_TYPES

def _is_list_type(value: str | None) -> bool:
    return value is not None and value.startswith("list[") and value.endswith("]")


def _list_item_type(value: str | None) -> str | None:
    if value is not None and _is_list_type(value):
        return value[5:-1]
    return None


def _is_supported_list_item_type(value: str) -> bool:
    if value in {"int", "float", "bool", "str", "bytes"}:
        return True
    item_type = _list_item_type(value)
    return item_type is not None and _is_supported_list_item_type(item_type)


def _is_supported_dict_value_type(value: str) -> bool:
    if value in {"int", "float", "bool", "str", "bytes"}:
        return True
    if value is not None and _is_list_type(value):
        item_type = _list_item_type(value)
        return item_type is not None and _is_supported_list_item_type(item_type)
    if value is not None and _is_tuple_type(value):
        return all(item_type in {"int", "float", "bool", "str", "bytes"} for item_type in _tuple_item_types(value))
    if value is not None and _is_dict_type(value):
        key_type, value_type = _dict_item_types(value)
        return (
            key_type in DICT_KEY_TYPES
            and value_type is not None
            and _is_supported_dict_value_type(value_type)
        )
    optional_item = _optional_item_type(value)
    if optional_item is not None:
        return _is_supported_dict_value_type(optional_item)
    return False


def _is_supported_signature_type(value: str) -> bool:
    if value in {"int", "float", "bool", "str", "bytes", "None"}:
        return True
    if value is not None and _is_list_type(value):
        item_type = _list_item_type(value)
        return item_type is not None and _is_supported_list_item_type(item_type)
    if value is not None and _is_tuple_type(value):
        return all(item_type in {"int", "float", "bool", "str", "bytes"} for item_type in _tuple_item_types(value))
    if value is not None and _is_dict_type(value):
        key_type, value_type = _dict_item_types(value)
        return (
            key_type in DICT_KEY_TYPES
            and value_type is not None
            and _is_supported_dict_value_type(value_type)
        )
    if value is not None and _is_set_type(value):
        return _set_item_type(value) in SET_ITEM_TYPES
    optional_item = _optional_item_type(value)
    if optional_item is not None:
        return _is_supported_signature_type(optional_item)
    return False


def _is_tuple_type(value: str | None) -> bool:
    return value is not None and value.startswith("tuple[") and value.endswith("]")


def _tuple_item_types(value: str | None) -> list[str]:
    if value is None or not _is_tuple_type(value):
        return []
    return _split_type_args(value[6:-1])


def _is_dict_type(value: str | None) -> bool:
    return value is not None and value.startswith("dict[") and value.endswith("]")


def _dict_item_types(value: str | None) -> tuple[str | None, str | None]:
    if value is None or not _is_dict_type(value):
        return None, None
    items = _split_type_args(value[5:-1])
    if len(items) != 2:
        return None, None
    return items[0], items[1]


def _is_set_type(value: str | None) -> bool:
    return value is not None and value.startswith("set[") and value.endswith("]")


def _set_item_type(value: str | None) -> str | None:
    if value is not None and _is_set_type(value):
        return value[4:-1]
    return None


def _is_mutable_collection_type(value: str | None) -> bool:
    return _is_list_type(value) or _is_dict_type(value) or _is_set_type(value)


def _is_optional_type(value: str | None) -> bool:
    return value is not None and value.startswith("Optional[") and value.endswith("]")


def _optional_item_type(value: str | None) -> str | None:
    if value is not None and _is_optional_type(value):
        return value[9:-1]
    return None


def _types_assignable(actual: str, expected: str) -> bool:
    if actual == expected:
        return True
    expected_item = _optional_item_type(expected)
    if expected_item is not None:
        return actual == "None" or actual == expected_item
    return False


def _types_comparable(left: str, right: str) -> bool:
    if left == right:
        return True
    left_item = _optional_item_type(left)
    right_item = _optional_item_type(right)
    if left_item is not None:
        return right == "None" or right == left_item
    if right_item is not None:
        return left == "None" or left == right_item
    return False


def _split_type_args(value: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    start = 0
    for index, char in enumerate(value):
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(value[start:index].strip())
            start = index + 1
    parts.append(value[start:].strip())
    return [part for part in parts if part]


def _constant_int(node: ast.AST) -> int | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return node.value
    return None


def _mutated_collection_names(node: ast.FunctionDef) -> set[str]:
    names: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Call) and _is_append_call(child) and isinstance(child.func, ast.Attribute):
            receiver = child.func.value
            if isinstance(receiver, ast.Name):
                names.add(receiver.id)
        if isinstance(child, ast.Assign):
            for target in child.targets:
                if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
                    names.add(target.value.id)
        if isinstance(child, ast.AnnAssign):
            target = child.target
            if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
                names.add(target.value.id)
    return names


def _mutable_collection_names_captured_by_container(
    node: ast.AST,
    env: dict[str, str],
) -> set[str]:
    names: set[str] = set()

    def visit(value: ast.AST, inside_container: bool) -> None:
        if isinstance(value, ast.Name):
            if inside_container and _is_mutable_collection_type(env.get(value.id)):
                names.add(value.id)
            return
        if isinstance(value, ast.List):
            for item in value.elts:
                visit(item, True)
            return
        if isinstance(value, ast.Tuple):
            for item in value.elts:
                visit(item, True)
            return
        if isinstance(value, ast.Dict):
            for key in value.keys:
                if key is not None:
                    visit(key, True)
            for item in value.values:
                visit(item, True)
            return
        if isinstance(value, ast.Set):
            for item in value.elts:
                visit(item, True)
            return
        for child in ast.iter_child_nodes(value):
            visit(child, inside_container)

    visit(node, False)
    return names


def _is_append_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "append"
        and len(node.args) == 1
        and not node.keywords
    )


def _is_enumerate_call(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and dotted_name(node.func) == "enumerate"


def _is_zip_call(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and dotted_name(node.func) == "zip"


def _call_receiver(node: ast.Call) -> ast.AST | None:
    if isinstance(node.func, ast.Attribute):
        return node.func.value
    return None


def _chained_call_args(node: ast.Call) -> list[ast.AST]:
    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Call):
        return list(node.func.value.args)
    return []


def _is_json_supported_type(value: str | None) -> bool:
    if value in JSON_VALUE_TYPES:
        return True
    if value is not None and _is_list_type(value):
        item_type = _list_item_type(value)
        return item_type is not None and _is_json_supported_type(item_type)
    if value is not None and _is_tuple_type(value):
        return all(_is_json_supported_type(item_type) for item_type in _tuple_item_types(value))
    if value is not None and _is_dict_type(value):
        key_type, value_type = _dict_item_types(value)
        return key_type == "str" and _is_json_supported_type(value_type)
    optional_item = _optional_item_type(value)
    if optional_item is not None:
        return _is_json_supported_type(optional_item)
    return False
