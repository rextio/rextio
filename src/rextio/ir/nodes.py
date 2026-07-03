"""Rextio IR node types.

A small, explicit tree of frozen dataclasses representing the lowered form of an
accepted native function. Every node serializes to a plain dict via ``to_dict`` so
the IR can be snapshot-tested and inspected; the codegen backends consume the tree
directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rextio.ir.types import RxtType


class IRNode:
    """Base class for every IR node."""

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this node."""
        raise NotImplementedError


class StatementIR(IRNode):
    """Base class for IR statements (executed for effect)."""


class ExprIR(IRNode):
    """Base class for IR expressions (evaluate to a value)."""


class TargetIR(IRNode):
    """Base class for assignment targets."""


@dataclass(frozen=True)
class ModuleIR(IRNode):
    """A lowered module: the set of native functions it contributes."""

    functions: list["FunctionIR"]

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this node."""
        return {"functions": [function.to_dict() for function in self.functions]}


@dataclass(frozen=True)
class FunctionIR(IRNode):
    """A lowered native function: signature, body, and native-lowering flags."""

    name: str
    qualname: str
    module_name: str
    params: list["ParamIR"]
    return_type: RxtType
    body: "BlockIR"
    native_runtime_semantics: bool = False
    embedded: bool = False
    # Whether the body performs in-process scalar boundary calls to the
    # Python fallback (RXT075); such a function has no pure-Rust crate form.
    has_boundary_calls: bool = False
    runtime_fallback_module: str | None = None
    runtime_attr_path: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this node."""
        data: dict[str, object] = {
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
        if self.embedded:
            data["embedded"] = True
        return data


@dataclass(frozen=True)
class ParamIR(IRNode):
    """A function parameter: its name and resolved type."""

    name: str
    type: RxtType

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this node."""
        return {"name": self.name, "type": self.type.to_dict()}


@dataclass(frozen=True)
class BlockIR(IRNode):
    """An ordered sequence of statements."""

    statements: list[StatementIR]

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this node."""
        return {"statements": [statement.to_dict() for statement in self.statements]}


@dataclass(frozen=True)
class AssignIR(StatementIR):
    """Assignment of a value to a name, optionally with a declared target type."""

    target: "NameIR"
    value: ExprIR
    target_type: RxtType | None = None

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this node."""
        data: dict[str, object] = {
            "kind": "assign",
            "target": self.target.to_dict(),
            "value": self.value.to_dict(),
        }
        if self.target_type is not None:
            data["target_type"] = self.target_type.to_dict()
        return data


@dataclass(frozen=True)
class DictSetIR(StatementIR):
    """Item assignment into a dict: ``target[key] = value``."""

    target: "NameIR"
    key: ExprIR
    value: ExprIR

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this node."""
        return {
            "kind": "dict_set",
            "target": self.target.to_dict(),
            "key": self.key.to_dict(),
            "value": self.value.to_dict(),
        }


@dataclass(frozen=True)
class AppendIR(StatementIR):
    """An ``target.append(value)`` call lowered to a dedicated statement."""

    target: "NameIR"
    value: ExprIR

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this node."""
        return {"kind": "append", "target": self.target.to_dict(), "value": self.value.to_dict()}


@dataclass(frozen=True)
class EffectCallIR(StatementIR):
    """A call evaluated only for its side effect (its result is discarded)."""

    call: "CallIR"

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this node."""
        return {"kind": "effect_call", "call": self.call.to_dict()}


@dataclass(frozen=True)
class BreakIR(StatementIR):
    """A ``break`` statement."""

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this node."""
        return {"kind": "break"}


@dataclass(frozen=True)
class ContinueIR(StatementIR):
    """A ``continue`` statement."""

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this node."""
        return {"kind": "continue"}


@dataclass(frozen=True)
class ReturnIR(StatementIR):
    """A ``return`` statement, with an optional value."""

    value: ExprIR | None

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this node."""
        return {
            "kind": "return",
            "value": self.value.to_dict() if self.value is not None else None,
        }


@dataclass(frozen=True)
class IfIR(StatementIR):
    """An ``if`` statement with its body and ``else`` block."""

    condition: ExprIR
    body: BlockIR
    orelse: BlockIR

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this node."""
        return {
            "kind": "if",
            "condition": self.condition.to_dict(),
            "body": self.body.to_dict(),
            "orelse": self.orelse.to_dict(),
        }


@dataclass(frozen=True)
class ForIR(StatementIR):
    """A ``for`` loop over an iterable, with body and ``else`` block."""

    target: TargetIR
    iterable: ExprIR
    body: BlockIR
    orelse: BlockIR

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this node."""
        return {
            "kind": "for",
            "target": self.target.to_dict(),
            "iterable": self.iterable.to_dict(),
            "body": self.body.to_dict(),
            "orelse": self.orelse.to_dict(),
        }


@dataclass(frozen=True)
class WhileIR(StatementIR):
    """A ``while`` loop, with body and ``else`` block."""

    condition: ExprIR
    body: BlockIR
    orelse: BlockIR

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this node."""
        return {
            "kind": "while",
            "condition": self.condition.to_dict(),
            "body": self.body.to_dict(),
            "orelse": self.orelse.to_dict(),
        }


@dataclass(frozen=True)
class ExceptHandlerIR(IRNode):
    """A single ``except <BuiltinException>:`` handler and its body."""

    exception: str
    body: BlockIR

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this node."""
        return {
            "exception": self.exception,
            "body": self.body.to_dict(),
        }


@dataclass(frozen=True)
class TryIR(StatementIR):
    """A ``try`` statement with built-in ``except`` handlers and ``finally``."""

    body: BlockIR
    handlers: tuple[ExceptHandlerIR, ...]
    finalbody: BlockIR

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this node."""
        return {
            "kind": "try",
            "body": self.body.to_dict(),
            "handlers": [handler.to_dict() for handler in self.handlers],
            "finalbody": self.finalbody.to_dict(),
        }


@dataclass(frozen=True)
class BinaryOpIR(ExprIR):
    """A binary operation (``left op right``)."""

    left: ExprIR
    op: str
    right: ExprIR

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this node."""
        return {
            "kind": "binary",
            "left": self.left.to_dict(),
            "op": self.op,
            "right": self.right.to_dict(),
        }


@dataclass(frozen=True)
class UnaryOpIR(ExprIR):
    """A unary operation (``op value``)."""

    op: str
    value: ExprIR

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this node."""
        return {"kind": "unary", "op": self.op, "value": self.value.to_dict()}


@dataclass(frozen=True)
class CompareIR(ExprIR):
    """A (possibly chained) comparison: ``left ops[0] comparators[0] ...``."""

    left: ExprIR
    ops: list[str]
    comparators: list[ExprIR]

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this node."""
        return {
            "kind": "compare",
            "left": self.left.to_dict(),
            "ops": list(self.ops),
            "comparators": [comparator.to_dict() for comparator in self.comparators],
        }


@dataclass(frozen=True)
class CallIR(ExprIR):
    """A call to a named function with positional arguments."""

    function: str
    args: list[ExprIR]

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this node."""
        return {
            "kind": "call",
            "function": self.function,
            "args": [arg.to_dict() for arg in self.args],
        }


@dataclass(frozen=True)
class NameIR(ExprIR, TargetIR):
    """A name reference, usable as both an expression and an assignment target."""

    id: str

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this node."""
        return {"kind": "name", "id": self.id}


@dataclass(frozen=True)
class TupleTargetIR(TargetIR):
    """A tuple-unpacking assignment target (``a, b = ...``)."""

    items: list[NameIR]

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this node."""
        return {"kind": "tuple_target", "items": [item.to_dict() for item in self.items]}


@dataclass(frozen=True)
class LiteralIR(ExprIR):
    """A literal constant value."""

    value: Any

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this node."""
        return {"kind": "literal", "value": self.value}


@dataclass(frozen=True)
class ListIR(ExprIR):
    """A list display (``[...]``)."""

    items: list[ExprIR]

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this node."""
        return {"kind": "list", "items": [item.to_dict() for item in self.items]}


@dataclass(frozen=True)
class TupleIR(ExprIR):
    """A tuple display (``(...)``)."""

    items: list[ExprIR]

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this node."""
        return {"kind": "tuple", "items": [item.to_dict() for item in self.items]}


@dataclass(frozen=True)
class DictIR(ExprIR):
    """A dict display (``{key: value, ...}``)."""

    items: list[tuple[ExprIR, ExprIR]]

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this node."""
        return {
            "kind": "dict",
            "items": [
                {"key": key.to_dict(), "value": value.to_dict()} for key, value in self.items
            ],
        }


@dataclass(frozen=True)
class SetIR(ExprIR):
    """A set display (``{...}``)."""

    items: list[ExprIR]

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this node."""
        return {"kind": "set", "items": [item.to_dict() for item in self.items]}


@dataclass(frozen=True)
class ComprehensionGeneratorIR(IRNode):
    """One ``for`` clause of a comprehension, with its target, iterable, and filters."""

    target: TargetIR
    iterable: ExprIR
    conditions: list[ExprIR]

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this node."""
        return {
            "target": self.target.to_dict(),
            "iterable": self.iterable.to_dict(),
            "conditions": [condition.to_dict() for condition in self.conditions],
        }


@dataclass(frozen=True)
class ListComprehensionIR(ExprIR):
    """A list comprehension."""

    item: ExprIR
    generators: list[ComprehensionGeneratorIR]

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this node."""
        return {
            "kind": "list_comprehension",
            "item": self.item.to_dict(),
            "generators": [generator.to_dict() for generator in self.generators],
        }


@dataclass(frozen=True)
class DictComprehensionIR(ExprIR):
    """A dict comprehension."""

    key: ExprIR
    value: ExprIR
    generators: list[ComprehensionGeneratorIR]

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this node."""
        return {
            "kind": "dict_comprehension",
            "key": self.key.to_dict(),
            "value": self.value.to_dict(),
            "generators": [generator.to_dict() for generator in self.generators],
        }


@dataclass(frozen=True)
class SetComprehensionIR(ExprIR):
    """A set comprehension."""

    item: ExprIR
    generators: list[ComprehensionGeneratorIR]

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this node."""
        return {
            "kind": "set_comprehension",
            "item": self.item.to_dict(),
            "generators": [generator.to_dict() for generator in self.generators],
        }


@dataclass(frozen=True)
class NamedExprIR(ExprIR):
    """A named (walrus) expression: ``target := value``."""

    target: "NameIR"
    value: ExprIR

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this node."""
        return {
            "kind": "named_expr",
            "target": self.target.to_dict(),
            "value": self.value.to_dict(),
        }


@dataclass(frozen=True)
class IndexIR(ExprIR):
    """A subscript expression: ``value[index]``."""

    value: ExprIR
    index: ExprIR

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-serializable dict form of this node."""
        return {"kind": "index", "value": self.value.to_dict(), "index": self.index.to_dict()}
