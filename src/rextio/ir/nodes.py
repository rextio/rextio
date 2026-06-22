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


class TargetIR(IRNode):
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
    native_runtime_semantics: bool = False
    runtime_fallback_module: str | None = None
    runtime_attr_path: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        data = {
            "name": self.name,
            "qualname": self.qualname,
            "module_name": self.module_name,
            "params": [param.to_dict() for param in self.params],
            "return_type": self.return_type.to_dict(),
            "body": self.body.to_dict(),
        }
        if self.native_runtime_semantics:
            data["native_runtime_semantics"] = True
            data["runtime_fallback_module"] = self.runtime_fallback_module
            data["runtime_attr_path"] = list(self.runtime_attr_path)
        return data


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
    target_type: RxtType | None = None

    def to_dict(self) -> dict[str, object]:
        data = {"kind": "assign", "target": self.target.to_dict(), "value": self.value.to_dict()}
        if self.target_type is not None:
            data["target_type"] = self.target_type.to_dict()
        return data


@dataclass(frozen=True)
class DictSetIR(StatementIR):
    target: "NameIR"
    key: ExprIR
    value: ExprIR

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "dict_set",
            "target": self.target.to_dict(),
            "key": self.key.to_dict(),
            "value": self.value.to_dict(),
        }


@dataclass(frozen=True)
class AppendIR(StatementIR):
    target: "NameIR"
    value: ExprIR

    def to_dict(self) -> dict[str, object]:
        return {"kind": "append", "target": self.target.to_dict(), "value": self.value.to_dict()}


@dataclass(frozen=True)
class BreakIR(StatementIR):
    def to_dict(self) -> dict[str, object]:
        return {"kind": "break"}


@dataclass(frozen=True)
class ContinueIR(StatementIR):
    def to_dict(self) -> dict[str, object]:
        return {"kind": "continue"}


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
    target: TargetIR
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
class NameIR(ExprIR, TargetIR):
    id: str

    def to_dict(self) -> dict[str, object]:
        return {"kind": "name", "id": self.id}


@dataclass(frozen=True)
class TupleTargetIR(TargetIR):
    items: list[NameIR]

    def to_dict(self) -> dict[str, object]:
        return {"kind": "tuple_target", "items": [item.to_dict() for item in self.items]}


@dataclass(frozen=True)
class LiteralIR(ExprIR):
    value: Any

    def to_dict(self) -> dict[str, object]:
        return {"kind": "literal", "value": self.value}


@dataclass(frozen=True)
class ListIR(ExprIR):
    items: list[ExprIR]

    def to_dict(self) -> dict[str, object]:
        return {"kind": "list", "items": [item.to_dict() for item in self.items]}


@dataclass(frozen=True)
class TupleIR(ExprIR):
    items: list[ExprIR]

    def to_dict(self) -> dict[str, object]:
        return {"kind": "tuple", "items": [item.to_dict() for item in self.items]}


@dataclass(frozen=True)
class DictIR(ExprIR):
    items: list[tuple[ExprIR, ExprIR]]

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "dict",
            "items": [
                {"key": key.to_dict(), "value": value.to_dict()} for key, value in self.items
            ],
        }


@dataclass(frozen=True)
class SetIR(ExprIR):
    items: list[ExprIR]

    def to_dict(self) -> dict[str, object]:
        return {"kind": "set", "items": [item.to_dict() for item in self.items]}


@dataclass(frozen=True)
class ComprehensionGeneratorIR(IRNode):
    target: TargetIR
    iterable: ExprIR
    conditions: list[ExprIR]

    def to_dict(self) -> dict[str, object]:
        return {
            "target": self.target.to_dict(),
            "iterable": self.iterable.to_dict(),
            "conditions": [condition.to_dict() for condition in self.conditions],
        }


@dataclass(frozen=True)
class ListComprehensionIR(ExprIR):
    item: ExprIR
    generators: list[ComprehensionGeneratorIR]

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "list_comprehension",
            "item": self.item.to_dict(),
            "generators": [generator.to_dict() for generator in self.generators],
        }


@dataclass(frozen=True)
class DictComprehensionIR(ExprIR):
    key: ExprIR
    value: ExprIR
    generators: list[ComprehensionGeneratorIR]

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "dict_comprehension",
            "key": self.key.to_dict(),
            "value": self.value.to_dict(),
            "generators": [generator.to_dict() for generator in self.generators],
        }


@dataclass(frozen=True)
class SetComprehensionIR(ExprIR):
    item: ExprIR
    generators: list[ComprehensionGeneratorIR]

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "set_comprehension",
            "item": self.item.to_dict(),
            "generators": [generator.to_dict() for generator in self.generators],
        }


@dataclass(frozen=True)
class NamedExprIR(ExprIR):
    target: "NameIR"
    value: ExprIR

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "named_expr",
            "target": self.target.to_dict(),
            "value": self.value.to_dict(),
        }


@dataclass(frozen=True)
class IndexIR(ExprIR):
    value: ExprIR
    index: ExprIR

    def to_dict(self) -> dict[str, object]:
        return {"kind": "index", "value": self.value.to_dict(), "index": self.index.to_dict()}
