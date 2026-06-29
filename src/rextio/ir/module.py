"""Assembly of an ``ModuleIR`` from lowered functions in dependency order."""

from __future__ import annotations

from rextio.ir.nodes import (
    AppendIR,
    AssignIR,
    BinaryOpIR,
    BlockIR,
    CallIR,
    DictComprehensionIR,
    CompareIR,
    DictIR,
    DictSetIR,
    ExprIR,
    ForIR,
    FunctionIR,
    IfIR,
    IndexIR,
    ListComprehensionIR,
    ListIR,
    ModuleIR,
    NamedExprIR,
    ReturnIR,
    SetComprehensionIR,
    SetIR,
    StatementIR,
    TupleIR,
    UnaryOpIR,
    WhileIR,
)


def empty_module() -> ModuleIR:
    """Return a module IR with no functions."""
    return ModuleIR(functions=[])


def module_from_functions(functions: list[FunctionIR]) -> ModuleIR:
    """Build a module IR, ordering functions so callees precede their callers."""
    return ModuleIR(functions=_dependency_ordered_functions(functions))


def _dependency_ordered_functions(functions: list[FunctionIR]) -> list[FunctionIR]:
    by_qualname = {function.qualname: function for function in functions}
    ordered: list[FunctionIR] = []
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(function: FunctionIR) -> None:
        if function.qualname in visited:
            return
        if function.qualname in visiting:
            return
        visiting.add(function.qualname)
        for dependency in sorted(_called_native_qualnames(function.body, by_qualname)):
            visit(by_qualname[dependency])
        visiting.remove(function.qualname)
        visited.add(function.qualname)
        ordered.append(function)

    for function in sorted(functions, key=lambda item: item.qualname):
        visit(function)
    return ordered


def _called_native_qualnames(block: BlockIR, functions: dict[str, FunctionIR]) -> set[str]:
    calls: set[str] = set()
    for statement in block.statements:
        calls.update(_statement_calls(statement, functions))
    return calls


def _statement_calls(statement: StatementIR, functions: dict[str, FunctionIR]) -> set[str]:
    if isinstance(statement, AssignIR):
        return _expr_calls(statement.value, functions)
    if isinstance(statement, AppendIR):
        return _expr_calls(statement.value, functions)
    if isinstance(statement, DictSetIR):
        return (
            _expr_calls(statement.key, functions)
            | _expr_calls(statement.value, functions)
        )
    if isinstance(statement, ReturnIR):
        return _expr_calls(statement.value, functions) if statement.value is not None else set()
    if isinstance(statement, IfIR):
        return (
            _expr_calls(statement.condition, functions)
            | _called_native_qualnames(statement.body, functions)
            | _called_native_qualnames(statement.orelse, functions)
        )
    if isinstance(statement, ForIR):
        return (
            _expr_calls(statement.iterable, functions)
            | _called_native_qualnames(statement.body, functions)
            | _called_native_qualnames(statement.orelse, functions)
        )
    if isinstance(statement, WhileIR):
        return (
            _expr_calls(statement.condition, functions)
            | _called_native_qualnames(statement.body, functions)
            | _called_native_qualnames(statement.orelse, functions)
        )
    return set()


def _expr_calls(expr: ExprIR, functions: dict[str, FunctionIR]) -> set[str]:
    if isinstance(expr, CallIR):
        calls = {expr.function} if expr.function in functions else set()
        for arg in expr.args:
            calls.update(_expr_calls(arg, functions))
        return calls
    if isinstance(expr, BinaryOpIR):
        return _expr_calls(expr.left, functions) | _expr_calls(expr.right, functions)
    if isinstance(expr, UnaryOpIR):
        return _expr_calls(expr.value, functions)
    if isinstance(expr, CompareIR):
        calls = _expr_calls(expr.left, functions)
        for comparator in expr.comparators:
            calls.update(_expr_calls(comparator, functions))
        return calls
    if isinstance(expr, IndexIR):
        return _expr_calls(expr.value, functions) | _expr_calls(expr.index, functions)
    if isinstance(expr, ListIR):
        calls: set[str] = set()
        for item in expr.items:
            calls.update(_expr_calls(item, functions))
        return calls
    if isinstance(expr, ListComprehensionIR):
        calls = _expr_calls(expr.item, functions)
        for generator in expr.generators:
            calls.update(_expr_calls(generator.iterable, functions))
            for condition in generator.conditions:
                calls.update(_expr_calls(condition, functions))
        return calls
    if isinstance(expr, TupleIR):
        calls: set[str] = set()
        for item in expr.items:
            calls.update(_expr_calls(item, functions))
        return calls
    if isinstance(expr, DictIR):
        calls: set[str] = set()
        for key, value in expr.items:
            calls.update(_expr_calls(key, functions))
            calls.update(_expr_calls(value, functions))
        return calls
    if isinstance(expr, DictComprehensionIR):
        calls = _expr_calls(expr.key, functions) | _expr_calls(expr.value, functions)
        for generator in expr.generators:
            calls.update(_expr_calls(generator.iterable, functions))
            for condition in generator.conditions:
                calls.update(_expr_calls(condition, functions))
        return calls
    if isinstance(expr, SetIR):
        calls: set[str] = set()
        for item in expr.items:
            calls.update(_expr_calls(item, functions))
        return calls
    if isinstance(expr, SetComprehensionIR):
        calls = _expr_calls(expr.item, functions)
        for generator in expr.generators:
            calls.update(_expr_calls(generator.iterable, functions))
            for condition in generator.conditions:
                calls.update(_expr_calls(condition, functions))
        return calls
    if isinstance(expr, NamedExprIR):
        return _expr_calls(expr.value, functions)
    return set()
