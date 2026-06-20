from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rextio.ir.types import RxtType


class IRNode:
    def to_dict(self) -> dict[str, object]:
        raise NotImplementedError


class StatementIR(IRNode):
    pass


class ExprIR(IRNode):
    pass


@dataclass(frozen=True)
class ModuleIR(IRNode):
    functions: list["FunctionIR"]

    def to_dict(self) -> dict[str, object]:
        return {"functions": [function.to_dict() for function in self.functions]}


@dataclass(frozen=True)
class FunctionIR(IRNode):
    name: str
    qualname: str
    module_name: str
    params: list["ParamIR"]
    return_type: RxtType
    body: "BlockIR"

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "qualname": self.qualname,
            "module_name": self.module_name,
            "params": [param.to_dict() for param in self.params],
            "return_type": self.return_type.to_dict(),
            "body": self.body.to_dict(),
        }


@dataclass(frozen=True)
class ParamIR(IRNode):
    name: str
    type: RxtType

    def to_dict(self) -> dict[str, object]:
        return {"name": self.name, "type": self.type.to_dict()}


@dataclass(frozen=True)
class BlockIR(IRNode):
    statements: list[StatementIR]

    def to_dict(self) -> dict[str, object]:
        return {"statements": [statement.to_dict() for statement in self.statements]}


@dataclass(frozen=True)
class AssignIR(StatementIR):
    target: "NameIR"
    value: ExprIR

    def to_dict(self) -> dict[str, object]:
        return {"kind": "assign", "target": self.target.to_dict(), "value": self.value.to_dict()}


@dataclass(frozen=True)
class ReturnIR(StatementIR):
    value: ExprIR | None

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "return",
            "value": self.value.to_dict() if self.value is not None else None,
        }


@dataclass(frozen=True)
class IfIR(StatementIR):
    condition: ExprIR
    body: BlockIR
    orelse: BlockIR

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "if",
            "condition": self.condition.to_dict(),
            "body": self.body.to_dict(),
            "orelse": self.orelse.to_dict(),
        }


@dataclass(frozen=True)
class ForIR(StatementIR):
    target: "NameIR"
    iterable: ExprIR
    body: BlockIR
    orelse: BlockIR

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "for",
            "target": self.target.to_dict(),
            "iterable": self.iterable.to_dict(),
            "body": self.body.to_dict(),
            "orelse": self.orelse.to_dict(),
        }


@dataclass(frozen=True)
class WhileIR(StatementIR):
    condition: ExprIR
    body: BlockIR
    orelse: BlockIR

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "while",
            "condition": self.condition.to_dict(),
            "body": self.body.to_dict(),
            "orelse": self.orelse.to_dict(),
        }


@dataclass(frozen=True)
class BinaryOpIR(ExprIR):
    left: ExprIR
    op: str
    right: ExprIR

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "binary",
            "left": self.left.to_dict(),
            "op": self.op,
            "right": self.right.to_dict(),
        }


@dataclass(frozen=True)
class UnaryOpIR(ExprIR):
    op: str
    value: ExprIR

    def to_dict(self) -> dict[str, object]:
        return {"kind": "unary", "op": self.op, "value": self.value.to_dict()}


@dataclass(frozen=True)
class CompareIR(ExprIR):
    left: ExprIR
    ops: list[str]
    comparators: list[ExprIR]

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "compare",
            "left": self.left.to_dict(),
            "ops": list(self.ops),
            "comparators": [comparator.to_dict() for comparator in self.comparators],
        }


@dataclass(frozen=True)
class CallIR(ExprIR):
    function: str
    args: list[ExprIR]

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "call",
            "function": self.function,
            "args": [arg.to_dict() for arg in self.args],
        }


@dataclass(frozen=True)
class NameIR(ExprIR):
    id: str

    def to_dict(self) -> dict[str, object]:
        return {"kind": "name", "id": self.id}


@dataclass(frozen=True)
class LiteralIR(ExprIR):
    value: Any

    def to_dict(self) -> dict[str, object]:
        return {"kind": "literal", "value": self.value}


@dataclass(frozen=True)
class IndexIR(ExprIR):
    value: ExprIR
    index: ExprIR

    def to_dict(self) -> dict[str, object]:
        return {"kind": "index", "value": self.value.to_dict(), "index": self.index.to_dict()}
