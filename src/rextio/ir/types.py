from __future__ import annotations

import ast
from dataclasses import dataclass


class RxtType:
    def display_name(self) -> str:
        raise NotImplementedError

    def to_dict(self) -> dict[str, object]:
        return {"kind": self.display_name()}


@dataclass(frozen=True)
class RxtInt(RxtType):
    def display_name(self) -> str:
        return "int"


@dataclass(frozen=True)
class RxtFloat(RxtType):
    def display_name(self) -> str:
        return "float"


@dataclass(frozen=True)
class RxtBool(RxtType):
    def display_name(self) -> str:
        return "bool"


@dataclass(frozen=True)
class RxtStr(RxtType):
    def display_name(self) -> str:
        return "str"


@dataclass(frozen=True)
class RxtBytes(RxtType):
    def display_name(self) -> str:
        return "bytes"


@dataclass(frozen=True)
class RxtNone(RxtType):
    def display_name(self) -> str:
        return "None"


@dataclass(frozen=True)
class RxtPyObject(RxtType):
    def display_name(self) -> str:
        return "object"


@dataclass(frozen=True)
class RxtList(RxtType):
    item_type: RxtType

    def display_name(self) -> str:
        return f"list[{self.item_type.display_name()}]"

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "list",
            "item_type": self.item_type.to_dict(),
        }


@dataclass(frozen=True)
class RxtSet(RxtType):
    item_type: RxtType

    def display_name(self) -> str:
        return f"set[{self.item_type.display_name()}]"

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "set",
            "item_type": self.item_type.to_dict(),
        }


@dataclass(frozen=True)
class RxtTuple(RxtType):
    item_types: tuple[RxtType, ...]

    def display_name(self) -> str:
        return f"tuple[{', '.join(item.display_name() for item in self.item_types)}]"

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "tuple",
            "item_types": [item.to_dict() for item in self.item_types],
        }


@dataclass(frozen=True)
class RxtDict(RxtType):
    key_type: RxtType
    value_type: RxtType

    def display_name(self) -> str:
        return f"dict[{self.key_type.display_name()}, {self.value_type.display_name()}]"

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "dict",
            "key_type": self.key_type.to_dict(),
            "value_type": self.value_type.to_dict(),
        }


@dataclass(frozen=True)
class RxtOptional(RxtType):
    item_type: RxtType

    def display_name(self) -> str:
        return f"Optional[{self.item_type.display_name()}]"

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "optional",
            "item_type": self.item_type.to_dict(),
        }


def type_from_annotation(node: ast.AST | None) -> RxtType:
    if node is None:
        raise ValueError("missing type annotation")
    if isinstance(node, ast.Name):
        if node.id == "int":
            return RxtInt()
        if node.id == "float":
            return RxtFloat()
        if node.id == "bool":
            return RxtBool()
        if node.id == "str":
            return RxtStr()
        if node.id == "bytes":
            return RxtBytes()
        if node.id == "None":
            return RxtNone()
    if isinstance(node, ast.Constant) and node.value is None:
        return RxtNone()
    optional_inner = _optional_inner(node)
    if optional_inner is not None:
        return RxtOptional(type_from_annotation(optional_inner))
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
        if node.value.id == "list":
            return RxtList(type_from_annotation(node.slice))
        if node.value.id == "set":
            return RxtSet(type_from_annotation(node.slice))
        if node.value.id == "tuple":
            return RxtTuple(tuple(type_from_annotation(item) for item in _tuple_slice_items(node.slice)))
        if node.value.id == "dict":
            items = _tuple_slice_items(node.slice)
            if len(items) == 2:
                return RxtDict(type_from_annotation(items[0]), type_from_annotation(items[1]))
    raise ValueError(f"unsupported type annotation: {ast.unparse(node)}")


def type_from_string(value: str) -> RxtType:
    node = ast.parse(value, mode="eval").body
    return type_from_annotation(node)


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
