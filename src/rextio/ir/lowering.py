from __future__ import annotations

import ast
from pathlib import Path

from rextio.analyzer.call_resolution import FunctionResolver
from rextio.analyzer.models import (
    FunctionAnalysis,
    ModuleAnalysis,
    ProjectAnalysis,
    TopLevelAnalysis,
)
from rextio.analyzer.native_marker import dotted_name
from rextio.analyzer.top_level import collect_native_top_level_statements
from rextio.ir.module import module_from_functions
from rextio.ir.nodes import (
    AppendIR,
    AssignIR,
    BinaryOpIR,
    BlockIR,
    BreakIR,
    CallIR,
    ComprehensionGeneratorIR,
    CompareIR,
    ContinueIR,
    DictComprehensionIR,
    DictIR,
    DictSetIR,
    ExprIR,
    ForIR,
    FunctionIR,
    IfIR,
    IndexIR,
    ListComprehensionIR,
    ListIR,
    LiteralIR,
    ModuleIR,
    NameIR,
    NamedExprIR,
    ParamIR,
    ReturnIR,
    SetComprehensionIR,
    SetIR,
    StatementIR,
    TargetIR,
    TupleIR,
    TupleTargetIR,
    UnaryOpIR,
    WhileIR,
)
from rextio.ir.types import type_from_annotation, type_from_string
from rextio.ir.types import RxtDict, RxtStr


class LoweringError(RuntimeError):
    pass


def lower_project(analysis: ProjectAnalysis) -> ModuleIR:
    functions: list[FunctionIR] = []
    nodes_by_file: dict[str, dict[str, ast.FunctionDef]] = {}
    module_trees_by_file: dict[str, ast.Module] = {}
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
    for top_level in analysis.accepted_native_top_levels:
        tree = module_trees_by_file.setdefault(
            top_level.file_path,
            _module_tree(Path(top_level.file_path)),
        )
        module = _module_for_top_level(analysis, top_level)
        if module is None:
            raise LoweringError(f"module was not found for accepted top level: {top_level.qualname}")
        functions.append(lower_top_level(top_level, tree, module, resolver))
    return module_from_functions(functions)


def lower_function(
    function: FunctionAnalysis,
    node: ast.FunctionDef,
    module: ModuleAnalysis,
    resolver: FunctionResolver,
) -> FunctionIR:
    args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
    params = [
        ParamIR(name=arg.arg, type=_argument_type(function, arg))
        for arg in args
    ]
    return FunctionIR(
        name=function.name,
        qualname=function.qualname,
        module_name=function.module_name,
        params=params,
        return_type=_return_type(function, node),
        body=lower_block(node.body, module, resolver),
    )


def lower_top_level(
    top_level: TopLevelAnalysis,
    tree: ast.Module,
    module: ModuleAnalysis,
    resolver: FunctionResolver,
) -> FunctionIR:
    if top_level.export_value_type is None:
        raise LoweringError(f"missing export value type for top-level native init: {top_level.qualname}")
    statements = lower_block(collect_native_top_level_statements(tree), module, resolver).statements
    statements.append(
        ReturnIR(
            DictIR(
                items=[
                    (LiteralIR(name), NameIR(name))
                    for name in sorted(top_level.assigned_types)
                ]
            )
        )
    )
    return FunctionIR(
        name=top_level.name,
        qualname=top_level.qualname,
        module_name=top_level.module_name,
        params=[],
        return_type=RxtDict(RxtStr(), type_from_string(top_level.export_value_type)),
        body=BlockIR(statements=statements),
    )


def _argument_type(function: FunctionAnalysis, arg: ast.arg):
    if arg.annotation is not None:
        return type_from_annotation(arg.annotation)
    inferred = function.inferred_arg_types.get(arg.arg)
    if inferred is None:
        raise LoweringError(f"missing inferred type for argument: {function.qualname}.{arg.arg}")
    return type_from_string(inferred)


def _return_type(function: FunctionAnalysis, node: ast.FunctionDef):
    if node.returns is not None:
        return type_from_annotation(node.returns)
    if function.inferred_return_type is None:
        raise LoweringError(f"missing inferred return type for function: {function.qualname}")
    return type_from_string(function.inferred_return_type)


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
        if isinstance(node.targets[0], ast.Subscript):
            target = node.targets[0]
            return DictSetIR(
                target=lower_name_target(target.value),
                key=lower_expr(target.slice, module, resolver),
                value=lower_expr(node.value, module, resolver),
            )
        return AssignIR(
            target=lower_name_target(node.targets[0]),
            value=lower_expr(node.value, module, resolver),
        )
    if isinstance(node, ast.AnnAssign):
        return AssignIR(
            target=lower_name_target(node.target),
            value=lower_expr(node.value, module, resolver),
            target_type=type_from_annotation(node.annotation),
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
    if isinstance(node, ast.Expr):
        if isinstance(node.value, ast.Call) and _is_append_call(node.value):
            call = node.value
            if not isinstance(call.func, ast.Attribute):
                raise LoweringError("append call target cannot be lowered")
            return AppendIR(
                target=lower_name_target(call.func.value),
                value=lower_expr(call.args[0], module, resolver),
            )
        raise LoweringError(f"unsupported expression statement during IR lowering: {type(node.value).__name__}")
    if isinstance(node, ast.Break):
        return BreakIR()
    if isinstance(node, ast.Continue):
        return ContinueIR()
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
            target=lower_loop_target(node.target),
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
    if isinstance(node, ast.List):
        return ListIR(items=[lower_expr(item, module, resolver) for item in node.elts])
    if isinstance(node, ast.ListComp):
        return ListComprehensionIR(
            item=lower_expr(node.elt, module, resolver),
            generators=lower_comprehension_generators(node.generators, module, resolver),
        )
    if isinstance(node, ast.Tuple):
        return TupleIR(items=[lower_expr(item, module, resolver) for item in node.elts])
    if isinstance(node, ast.Dict):
        if any(key is None for key in node.keys):
            raise LoweringError("dictionary unpacking cannot be lowered")
        return DictIR(
            items=[
                (lower_expr(key, module, resolver), lower_expr(value, module, resolver))
                for key, value in zip(node.keys, node.values, strict=True)
                if key is not None
            ]
        )
    if isinstance(node, ast.DictComp):
        return DictComprehensionIR(
            key=lower_expr(node.key, module, resolver),
            value=lower_expr(node.value, module, resolver),
            generators=lower_comprehension_generators(node.generators, module, resolver),
        )
    if isinstance(node, ast.Set):
        return SetIR(items=[lower_expr(item, module, resolver) for item in node.elts])
    if isinstance(node, ast.SetComp):
        return SetComprehensionIR(
            item=lower_expr(node.elt, module, resolver),
            generators=lower_comprehension_generators(node.generators, module, resolver),
        )
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
    if isinstance(node, ast.NamedExpr):
        return NamedExprIR(
            target=lower_name_target(node.target),
            value=lower_expr(node.value, module, resolver),
        )
    raise LoweringError(f"unsupported expression during IR lowering: {type(node).__name__}")


def lower_name_target(node: ast.AST) -> NameIR:
    if not isinstance(node, ast.Name):
        raise LoweringError(f"unsupported assignment target: {type(node).__name__}")
    return NameIR(node.id)


def lower_loop_target(node: ast.AST) -> TargetIR:
    if isinstance(node, ast.Name):
        return NameIR(node.id)
    if isinstance(node, ast.Tuple):
        items = [lower_name_target(item) for item in node.elts]
        return TupleTargetIR(items=items)
    raise LoweringError(f"unsupported for-loop target: {type(node).__name__}")


def lower_comprehension_generators(
    generators: list[ast.comprehension],
    module: ModuleAnalysis,
    resolver: FunctionResolver,
) -> list[ComprehensionGeneratorIR]:
    lowered: list[ComprehensionGeneratorIR] = []
    for generator in generators:
        if generator.is_async:
            raise LoweringError("async comprehensions cannot be lowered")
        lowered.append(
            ComprehensionGeneratorIR(
                target=lower_loop_target(generator.target),
                iterable=lower_expr(generator.iter, module, resolver),
                conditions=[lower_expr(condition, module, resolver) for condition in generator.ifs],
            )
        )
    return lowered


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
    if isinstance(node, ast.Is):
        return "=="
    if isinstance(node, ast.IsNot):
        return "!="
    raise LoweringError(f"unsupported comparison operator: {type(node).__name__}")


def _lower_call_target(
    target: str,
    module: ModuleAnalysis,
    resolver: FunctionResolver,
) -> str:
    if target in {
        "abs",
        "len",
        "max",
        "min",
        "range",
        "sum",
        "enumerate",
        "zip",
        "math.floor",
        "math.cos",
        "math.sin",
        "math.sqrt",
    }:
        return target
    resolved = resolver.resolve(module, target)
    if resolved.function is None:
        return resolved.resolved_target
    return resolved.function.qualname


def _is_append_call(node: ast.Call) -> bool:
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "append"
        and isinstance(node.func.value, ast.Name)
        and len(node.args) == 1
        and not node.keywords
    )


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


def _module_tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _module_for_top_level(
    analysis: ProjectAnalysis,
    top_level: TopLevelAnalysis,
) -> ModuleAnalysis | None:
    for module in analysis.modules:
        if module.module_name == top_level.module_name:
            return module
    return None
