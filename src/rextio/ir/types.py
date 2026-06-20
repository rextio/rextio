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
class RxtNone(RxtType):
    def display_name(self) -> str:
        return "None"


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
        if node.id == "None":
            return RxtNone()
    if isinstance(node, ast.Constant) and node.value is None:
        return RxtNone()
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
        if node.value.id == "list":
            return RxtList(type_from_annotation(node.slice))
    raise ValueError(f"unsupported type annotation: {ast.unparse(node)}")
