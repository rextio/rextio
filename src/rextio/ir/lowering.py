from __future__ import annotations

import ast
from pathlib import Path

from rextio.analyzer.call_resolution import FunctionResolver
from rextio.analyzer.models import FunctionAnalysis, ModuleAnalysis, ProjectAnalysis
from rextio.analyzer.native_marker import dotted_name
from rextio.ir.module import module_from_functions
from rextio.ir.nodes import (
    AssignIR,
    BinaryOpIR,
    BlockIR,
    CallIR,
    CompareIR,
    ExprIR,
    ForIR,
    FunctionIR,
    IfIR,
    IndexIR,
    LiteralIR,
    ModuleIR,
    NameIR,
    ParamIR,
    ReturnIR,
    StatementIR,
    UnaryOpIR,
    WhileIR,
)
from rextio.ir.types import type_from_annotation


class LoweringError(RuntimeError):
    pass


def lower_project(analysis: ProjectAnalysis) -> ModuleIR:
    functions: list[FunctionIR] = []
    nodes_by_file: dict[str, dict[str, ast.FunctionDef]] = {}
    resolver = FunctionResolver(analysis)
    for function in analysis.accepted_native_functions:
        nodes = nodes_by_file.setdefault(function.file_path, _function_nodes(Path(function.file_path)))
        node = nodes.get(function.name)
        if node is None:
            raise LoweringError(f"accepted native function was not found: {function.qualname}")
        module = analysis.module_for_function(function)
        if module is None:
            raise LoweringError(f"module was not found for accepted function: {function.qualname}")
        functions.append(lower_function(function, node, module, resolver))
    return module_from_functions(functions)


def lower_function(
    function: FunctionAnalysis,
    node: ast.FunctionDef,
    module: ModuleAnalysis,
    resolver: FunctionResolver,
) -> FunctionIR:
    args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
    params = [ParamIR(name=arg.arg, type=type_from_annotation(arg.annotation)) for arg in args]
    return FunctionIR(
        name=function.name,
        qualname=function.qualname,
        module_name=function.module_name,
        params=params,
        return_type=type_from_annotation(node.returns),
        body=lower_block(node.body, module, resolver),
    )


def lower_block(
    statements: list[ast.stmt],
    module: ModuleAnalysis,
    resolver: FunctionResolver,
) -> BlockIR:
    return BlockIR(
        statements=[lower_statement(statement, module, resolver) for statement in statements]
    )


def lower_statement(
    node: ast.stmt,
    module: ModuleAnalysis,
    resolver: FunctionResolver,
) -> StatementIR:
    if isinstance(node, ast.Assign):
        if len(node.targets) != 1:
            raise LoweringError("multiple assignment targets are not supported")
        return AssignIR(
            target=lower_name_target(node.targets[0]),
            value=lower_expr(node.value, module, resolver),
        )
    if isinstance(node, ast.AnnAssign):
        return AssignIR(
            target=lower_name_target(node.target),
            value=lower_expr(node.value, module, resolver),
        )
    if isinstance(node, ast.AugAssign):
        target = lower_name_target(node.target)
        return AssignIR(
            target=target,
            value=BinaryOpIR(
                left=target,
                op=lower_binary_op(node.op),
                right=lower_expr(node.value, module, resolver),
            ),
        )
    if isinstance(node, ast.Return):
        return ReturnIR(
            value=lower_expr(node.value, module, resolver) if node.value is not None else None
        )
    if isinstance(node, ast.If):
        return IfIR(
            condition=lower_expr(node.test, module, resolver),
            body=lower_block(node.body, module, resolver),
            orelse=lower_block(node.orelse, module, resolver),
        )
    if isinstance(node, ast.For):
        return ForIR(
            target=lower_name_target(node.target),
            iterable=lower_expr(node.iter, module, resolver),
            body=lower_block(node.body, module, resolver),
            orelse=lower_block(node.orelse, module, resolver),
        )
    if isinstance(node, ast.While):
        return WhileIR(
            condition=lower_expr(node.test, module, resolver),
            body=lower_block(node.body, module, resolver),
            orelse=lower_block(node.orelse, module, resolver),
        )
    raise LoweringError(f"unsupported statement during IR lowering: {type(node).__name__}")


def lower_expr(
    node: ast.AST | None,
    module: ModuleAnalysis,
    resolver: FunctionResolver,
) -> ExprIR:
    if node is None:
        return LiteralIR(None)
    if isinstance(node, ast.Constant):
        return LiteralIR(node.value)
    if isinstance(node, ast.Name):
        return NameIR(node.id)
    if isinstance(node, ast.BinOp):
        return BinaryOpIR(
            left=lower_expr(node.left, module, resolver),
            op=lower_binary_op(node.op),
            right=lower_expr(node.right, module, resolver),
        )
    if isinstance(node, ast.BoolOp):
        return _lower_bool_op(node, module, resolver)
    if isinstance(node, ast.UnaryOp):
        return UnaryOpIR(
            op=lower_unary_op(node.op),
            value=lower_expr(node.operand, module, resolver),
        )
    if isinstance(node, ast.Compare):
        return CompareIR(
            left=lower_expr(node.left, module, resolver),
            ops=[lower_compare_op(op) for op in node.ops],
            comparators=[lower_expr(comparator, module, resolver) for comparator in node.comparators],
        )
    if isinstance(node, ast.Call):
        target = dotted_name(node.func)
        if target is None:
            raise LoweringError("dynamic calls cannot be lowered to Rextio IR")
        return CallIR(
            function=_lower_call_target(target, module, resolver),
            args=[lower_expr(arg, module, resolver) for arg in node.args],
        )
    if isinstance(node, ast.Subscript):
        return IndexIR(
            value=lower_expr(node.value, module, resolver),
            index=lower_expr(node.slice, module, resolver),
        )
    raise LoweringError(f"unsupported expression during IR lowering: {type(node).__name__}")


def lower_name_target(node: ast.AST) -> NameIR:
    if not isinstance(node, ast.Name):
        raise LoweringError(f"unsupported assignment target: {type(node).__name__}")
    return NameIR(node.id)


def lower_binary_op(node: ast.operator) -> str:
    if isinstance(node, ast.Add):
        return "+"
    if isinstance(node, ast.Sub):
        return "-"
    if isinstance(node, ast.Mult):
        return "*"
    if isinstance(node, ast.Div):
        return "/"
    if isinstance(node, ast.Mod):
        return "%"
    raise LoweringError(f"unsupported binary operator: {type(node).__name__}")


def lower_unary_op(node: ast.unaryop) -> str:
    if isinstance(node, ast.USub):
        return "-"
    if isinstance(node, ast.Not):
        return "not"
    raise LoweringError(f"unsupported unary operator: {type(node).__name__}")


def lower_compare_op(node: ast.cmpop) -> str:
    if isinstance(node, ast.Eq):
        return "=="
    if isinstance(node, ast.NotEq):
        return "!="
    if isinstance(node, ast.Lt):
        return "<"
    if isinstance(node, ast.LtE):
        return "<="
    if isinstance(node, ast.Gt):
        return ">"
    if isinstance(node, ast.GtE):
        return ">="
    raise LoweringError(f"unsupported comparison operator: {type(node).__name__}")


def _lower_call_target(
    target: str,
    module: ModuleAnalysis,
    resolver: FunctionResolver,
) -> str:
    if target in {"len", "range"}:
        return target
    resolved = resolver.resolve(module, target)
    if resolved.function is None:
        return resolved.resolved_target
    return resolved.function.qualname


def _lower_bool_op(
    node: ast.BoolOp,
    module: ModuleAnalysis,
    resolver: FunctionResolver,
) -> ExprIR:
    if not node.values:
        raise LoweringError("empty boolean operation cannot be lowered")
    op = "and" if isinstance(node.op, ast.And) else "or"
    current = lower_expr(node.values[0], module, resolver)
    for value in node.values[1:]:
        current = BinaryOpIR(left=current, op=op, right=lower_expr(value, module, resolver))
    return current


def _function_nodes(path: Path) -> dict[str, ast.FunctionDef]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
