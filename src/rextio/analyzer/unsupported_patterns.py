from __future__ import annotations

import ast

from rextio.analyzer.diagnostics import Diagnostic
from rextio.analyzer.models import FunctionAnalysis
from rextio.analyzer.native_marker import dotted_name, is_native_decorator
from rextio.analyzer.type_collector import annotation_name, is_supported_type

DYNAMIC_FEATURES = {"getattr", "setattr", "hasattr", "globals", "locals", "eval", "exec", "__import__"}
NUMERIC_TYPES = {"int", "float"}

UNSUPPORTED_SYNTAX: tuple[type[ast.AST], ...] = (
    ast.AsyncFunctionDef,
    ast.ClassDef,
    ast.Lambda,
    ast.ListComp,
    ast.DictComp,
    ast.SetComp,
    ast.GeneratorExp,
    ast.Tuple,
    ast.Dict,
    ast.Set,
    ast.Await,
    ast.Yield,
    ast.YieldFrom,
    ast.Pass,
    ast.Assert,
    ast.Raise,
    ast.Delete,
    ast.NamedExpr,
    ast.IfExp,
    ast.JoinedStr,
    ast.Starred,
    ast.Slice,
    ast.Global,
    ast.Nonlocal,
    ast.Match,
    ast.FloorDiv,
    ast.Pow,
    ast.MatMult,
    ast.BitAnd,
    ast.BitOr,
    ast.BitXor,
    ast.LShift,
    ast.RShift,
    ast.UAdd,
    ast.Invert,
    ast.Is,
    ast.IsNot,
    ast.In,
    ast.NotIn,
    ast.Try,
    ast.With,
    ast.AsyncWith,
    ast.Import,
    ast.ImportFrom,
)


def validate_native_function(node: ast.FunctionDef, function: FunctionAnalysis) -> None:
    _validate_decorators(node, function)
    _validate_signature(node, function)
    _validate_body(node, function)
    function.accepted = not function.error_diagnostics


def _validate_decorators(node: ast.FunctionDef, function: FunctionAnalysis) -> None:
    for decorator in node.decorator_list:
        if is_native_decorator(decorator):
            continue
        function.add_diagnostic(
            Diagnostic(
                code="RXT010",
                severity="error",
                message="unsupported decorator on native function",
                file_path=function.file_path,
                line=getattr(decorator, "lineno", node.lineno),
                column=getattr(decorator, "col_offset", node.col_offset),
                function_name=function.qualname,
                suggestion="Use only @rextio.native on Public 1 native candidates.",
            )
        )


def _validate_signature(node: ast.FunctionDef, function: FunctionAnalysis) -> None:
    if node.args.vararg is not None:
        _add_unsupported_syntax(function, node.args.vararg, "arbitrary *args are not supported")
    if node.args.kwarg is not None:
        _add_unsupported_syntax(function, node.args.kwarg, "arbitrary **kwargs are not supported")

    args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
    for arg in args:
        if arg.annotation is None:
            function.add_diagnostic(
                Diagnostic(
                    code="RXT001",
                    severity="error",
                    message=f"missing type annotation for argument: {arg.arg}",
                    file_path=function.file_path,
                    line=arg.lineno,
                    column=arg.col_offset,
                    function_name=function.qualname,
                    suggestion="Add a supported Public 1 type annotation.",
                )
            )
        elif not is_supported_type(arg.annotation):
            function.add_diagnostic(
                Diagnostic(
                    code="RXT002",
                    severity="error",
                    message=f"unsupported argument type for {arg.arg}: {annotation_name(arg.annotation)}",
                    file_path=function.file_path,
                    line=arg.lineno,
                    column=arg.col_offset,
                    function_name=function.qualname,
                    suggestion="Use int, float, bool, str, None, or list[...] with a supported scalar item.",
                )
            )

    if node.returns is None:
        function.add_diagnostic(
            Diagnostic(
                code="RXT001",
                severity="error",
                message="missing return type annotation",
                file_path=function.file_path,
                line=node.lineno,
                column=node.col_offset,
                function_name=function.qualname,
                suggestion="Add a supported Public 1 return type annotation.",
            )
        )
    elif not is_supported_type(node.returns):
        function.add_diagnostic(
            Diagnostic(
                code="RXT003",
                severity="error",
                message=f"unsupported return type: {annotation_name(node.returns)}",
                file_path=function.file_path,
                line=node.lineno,
                column=node.col_offset,
                function_name=function.qualname,
                suggestion="Use int, float, bool, str, None, or list[...] with a supported scalar item.",
            )
        )


def _validate_body(node: ast.FunctionDef, function: FunctionAnalysis) -> None:
    type_env = _initial_type_env(node)
    return_type = annotation_name(node.returns) if node.returns is not None and is_supported_type(node.returns) else None
    for statement in node.body:
        _validate_statement_types(statement, function, type_env, return_type)
        for child in ast.walk(statement):
            if isinstance(child, ast.FunctionDef):
                _add_unsupported_syntax(function, child, "nested functions are not supported")
                continue
            if isinstance(child, UNSUPPORTED_SYNTAX):
                _add_unsupported_syntax(function, child, _unsupported_message(child))
                continue
            if isinstance(child, ast.Call):
                _validate_call(function, child)


def _initial_type_env(node: ast.FunctionDef) -> dict[str, str]:
    env: dict[str, str] = {}
    args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
    for arg in args:
        if arg.annotation is not None and is_supported_type(arg.annotation):
            env[arg.arg] = annotation_name(arg.annotation)
    return env


def _validate_statement_types(
    node: ast.stmt,
    function: FunctionAnalysis,
    env: dict[str, str],
    return_type: str | None,
) -> None:
    if isinstance(node, ast.Assign):
        value_type = _infer_expr_type(node.value, function, env)
        for target in node.targets:
            if isinstance(target, ast.Name) and value_type is not None:
                env[target.id] = value_type
        return
    if isinstance(node, ast.AnnAssign):
        annotated_type = (
            annotation_name(node.annotation)
            if node.annotation is not None and is_supported_type(node.annotation)
            else None
        )
        if annotated_type is None:
            _add_unsupported_syntax(
                function,
                node,
                f"unsupported local annotation type: {annotation_name(node.annotation)}",
            )
            return
        if node.value is None:
            _add_unsupported_syntax(
                function,
                node,
                "annotated local variables must include an initializer",
            )
            return
        value_type = _infer_expr_type(node.value, function, env, expected_type=annotated_type)
        if value_type is not None and annotated_type is not None:
            _validate_type_match(value_type, annotated_type, function, node)
        if isinstance(node.target, ast.Name) and annotated_type is not None:
            env[node.target.id] = annotated_type
        return
    if isinstance(node, ast.AugAssign):
        target_type = _infer_expr_type(node.target, function, env)
        value_type = _infer_expr_type(node.value, function, env)
        result_type = _infer_binop_type(node.op, target_type, value_type, function, node)
        if isinstance(node.target, ast.Name) and result_type is not None:
            env[node.target.id] = result_type
        return
    if isinstance(node, ast.Expr):
        _infer_expr_type(node.value, function, env)
        if not _is_append_call(node.value):
            _add_unsupported_syntax(
                function,
                node,
                "expression statements are supported only for list.append in native functions",
            )
        return
    if isinstance(node, (ast.Break, ast.Continue)):
        return
    if isinstance(node, ast.Return):
        value_type = "None"
        if node.value is not None:
            value_type = _infer_expr_type(node.value, function, env)
        if value_type is not None and return_type is not None:
            _validate_type_match(value_type, return_type, function, node)
        return
    if isinstance(node, ast.If):
        _infer_expr_type(node.test, function, env)
        _validate_statement_list_types(node.body, function, dict(env), return_type)
        _validate_statement_list_types(node.orelse, function, dict(env), return_type)
        return
    if isinstance(node, ast.For):
        iterable_type = _infer_expr_type(node.iter, function, env)
        body_env = dict(env)
        if isinstance(node.target, ast.Name):
            item_type = _iter_item_type(node.iter, iterable_type)
            if item_type is not None:
                body_env[node.target.id] = item_type
        _validate_statement_list_types(node.body, function, body_env, return_type)
        _validate_statement_list_types(node.orelse, function, dict(env), return_type)
        return
    if isinstance(node, ast.While):
        _infer_expr_type(node.test, function, env)
        _validate_statement_list_types(node.body, function, dict(env), return_type)
        _validate_statement_list_types(node.orelse, function, dict(env), return_type)


def _validate_statement_list_types(
    statements: list[ast.stmt],
    function: FunctionAnalysis,
    env: dict[str, str],
    return_type: str | None,
) -> None:
    for statement in statements:
        _validate_statement_types(statement, function, env, return_type)


def _validate_type_match(
    actual: str,
    expected: str,
    function: FunctionAnalysis,
    node: ast.AST,
) -> None:
    if actual == expected:
        return
    _add_unsupported_syntax(
        function,
        node,
        f"inferred type {actual} does not match expected type {expected}",
    )


def _infer_expr_type(
    node: ast.AST | None,
    function: FunctionAnalysis,
    env: dict[str, str],
    expected_type: str | None = None,
) -> str | None:
    if node is None:
        return "None"
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool):
            return "bool"
        if isinstance(node.value, int):
            return "int"
        if isinstance(node.value, float):
            return "float"
        if isinstance(node.value, str):
            return "str"
        if node.value is None:
            return "None"
        return None
    if isinstance(node, ast.Name):
        return env.get(node.id)
    if isinstance(node, ast.List):
        return _infer_list_type(node, function, env, expected_type)
    if isinstance(node, ast.BinOp):
        left = _infer_expr_type(node.left, function, env)
        right = _infer_expr_type(node.right, function, env)
        return _infer_binop_type(node.op, left, right, function, node)
    if isinstance(node, ast.UnaryOp):
        value_type = _infer_expr_type(node.operand, function, env)
        return _infer_unary_type(node.op, value_type, function, node)
    if isinstance(node, ast.BoolOp):
        for value in node.values:
            value_type = _infer_expr_type(value, function, env)
            if value_type is not None and value_type != "bool":
                _add_unsupported_syntax(
                    function,
                    value,
                    f"boolean operations require bool operands in Public 1, got {value_type}",
                )
        return "bool"
    if isinstance(node, ast.Compare):
        _validate_compare_types(node, function, env)
        return "bool"
    if isinstance(node, ast.Call):
        return _infer_call_type(node, function, env)
    if isinstance(node, ast.Subscript):
        value_type = _infer_expr_type(node.value, function, env)
        _infer_expr_type(node.slice, function, env)
        if value_type is not None and value_type.startswith("list[") and value_type.endswith("]"):
            return value_type[5:-1]
        return None
    return None


def _infer_list_type(
    node: ast.List,
    function: FunctionAnalysis,
    env: dict[str, str],
    expected_type: str | None,
) -> str | None:
    if not node.elts:
        if expected_type is not None and _is_list_type(expected_type):
            return expected_type
        _add_unsupported_syntax(
            function,
            node,
            "empty list literals require a supported list[...] annotation",
        )
        return None

    item_types = [_infer_expr_type(item, function, env) for item in node.elts]
    if any(item_type is None for item_type in item_types):
        return None
    unique_item_types = set(item_types)
    if len(unique_item_types) != 1:
        _add_unsupported_syntax(
            function,
            node,
            "list literals must contain a single supported item type",
        )
        return None
    item_type = item_types[0]
    if item_type not in {"int", "float", "bool", "str"}:
        _add_unsupported_syntax(
            function,
            node,
            f"list literal item type is not supported: {item_type}",
        )
        return None
    return f"list[{item_type}]"


def _infer_call_type(
    node: ast.Call,
    function: FunctionAnalysis,
    env: dict[str, str],
) -> str | None:
    for arg in node.args:
        _infer_expr_type(arg, function, env)

    target = dotted_name(node.func)
    if target == "len":
        if not _require_arg_count("len", node, function, {1}):
            return None
        return "int"
    if target == "range":
        _validate_range_call(node, function, env)
        return None
    if target == "abs":
        if not _require_arg_count("abs", node, function, {1}):
            return None
        arg_type = _infer_expr_type(node.args[0], function, env)
        if arg_type in NUMERIC_TYPES:
            return arg_type
        _add_unsupported_syntax(function, node, f"abs requires int or float, got {arg_type}")
        return None
    if target in {"min", "max"}:
        if not _require_arg_count(target, node, function, {2}):
            return None
        arg_types = [_infer_expr_type(arg, function, env) for arg in node.args]
        if arg_types[0] in NUMERIC_TYPES and arg_types[0] == arg_types[1]:
            return arg_types[0]
        _add_unsupported_syntax(
            function,
            node,
            f"{target} requires two operands with the same numeric type",
        )
        return None
    if target == "sum":
        if not _require_arg_count("sum", node, function, {1}):
            return None
        arg_type = _infer_expr_type(node.args[0], function, env)
        item_type = _list_item_type(arg_type)
        if item_type in NUMERIC_TYPES:
            return item_type
        _add_unsupported_syntax(function, node, f"sum requires list[int] or list[float], got {arg_type}")
        return None
    if target in {"math.sqrt", "math.sin", "math.cos"}:
        if not _require_arg_count(target, node, function, {1}):
            return None
        arg_type = _infer_expr_type(node.args[0], function, env)
        if arg_type == "float":
            return "float"
        _add_unsupported_syntax(function, node, f"{target} requires a float argument")
        return None
    if target == "math.floor":
        if not _require_arg_count("math.floor", node, function, {1}):
            return None
        arg_type = _infer_expr_type(node.args[0], function, env)
        if arg_type == "float":
            return "int"
        _add_unsupported_syntax(function, node, "math.floor requires a float argument")
        return None
    if _is_append_call(node):
        return _infer_append_call_type(node, function, env)
    return None


def _infer_append_call_type(
    node: ast.Call,
    function: FunctionAnalysis,
    env: dict[str, str],
) -> str | None:
    assert isinstance(node.func, ast.Attribute)
    receiver_type = _infer_expr_type(node.func.value, function, env)
    item_type = _list_item_type(receiver_type)
    value_type = _infer_expr_type(node.args[0], function, env)
    if item_type is None:
        _add_unsupported_syntax(function, node, f"append receiver must be list[...], got {receiver_type}")
        return None
    if value_type is not None and value_type != item_type:
        _add_unsupported_syntax(
            function,
            node,
            f"append value type {value_type} does not match list item type {item_type}",
        )
        return None
    return "None"


def _infer_binop_type(
    op: ast.operator,
    left: str | None,
    right: str | None,
    function: FunctionAnalysis,
    node: ast.AST,
) -> str | None:
    if not isinstance(op, (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod)):
        return None
    if left is None or right is None:
        return None
    if isinstance(op, ast.Div) and left == "int" and right == "int":
        _add_unsupported_syntax(
            function,
            node,
            "int division is not supported in Public 1 native functions",
        )
        return None
    if left not in NUMERIC_TYPES or right not in NUMERIC_TYPES:
        _add_unsupported_syntax(
            function,
            node,
            f"operator is not supported for inferred operand types: {left} and {right}",
        )
        return None
    if left != right:
        _add_unsupported_syntax(
            function,
            node,
            f"mixed numeric operand types are not supported: {left} and {right}",
        )
        return None
    return left


def _infer_unary_type(
    op: ast.unaryop,
    value_type: str | None,
    function: FunctionAnalysis,
    node: ast.AST,
) -> str | None:
    if isinstance(op, ast.Not):
        if value_type is not None and value_type != "bool":
            _add_unsupported_syntax(
                function,
                node,
                f"not operator requires bool in Public 1 native functions, got {value_type}",
            )
        return "bool"
    if isinstance(op, ast.USub):
        if value_type in NUMERIC_TYPES:
            return value_type
        if value_type is not None:
            _add_unsupported_syntax(
                function,
                node,
                f"unary minus is not supported for inferred operand type: {value_type}",
            )
    return None


def _validate_compare_types(
    node: ast.Compare,
    function: FunctionAnalysis,
    env: dict[str, str],
) -> None:
    left_type = _infer_expr_type(node.left, function, env)
    for op, comparator in zip(node.ops, node.comparators, strict=True):
        right_type = _infer_expr_type(comparator, function, env)
        if left_type is not None and right_type is not None and left_type != right_type:
            _add_unsupported_syntax(
                function,
                node,
                f"mixed comparison operand types are not supported: {left_type} and {right_type}",
            )
        left_type = right_type


def _iter_item_type(node: ast.AST, iterable_type: str | None) -> str | None:
    if iterable_type is not None and iterable_type.startswith("list[") and iterable_type.endswith("]"):
        return iterable_type[5:-1]
    if isinstance(node, ast.Call) and dotted_name(node.func) == "range":
        return "int"
    return None


def _validate_range_call(
    node: ast.Call,
    function: FunctionAnalysis,
    env: dict[str, str],
) -> None:
    if not _require_arg_count("range", node, function, {1, 2, 3}):
        return
    for arg in node.args:
        arg_type = _infer_expr_type(arg, function, env)
        if arg_type is not None and arg_type != "int":
            _add_unsupported_syntax(function, arg, f"range arguments must be int, got {arg_type}")
    if len(node.args) == 3:
        step = node.args[2]
        if not (
            isinstance(step, ast.Constant)
            and isinstance(step.value, int)
            and not isinstance(step.value, bool)
            and step.value > 0
        ):
            _add_unsupported_syntax(
                function,
                step,
                "range step must be a positive int literal in Public 1 native functions",
            )


def _require_arg_count(
    target: str,
    node: ast.Call,
    function: FunctionAnalysis,
    expected_counts: set[int],
) -> bool:
    if len(node.args) in expected_counts:
        return True
    expected = ", ".join(str(count) for count in sorted(expected_counts))
    _add_unsupported_syntax(
        function,
        node,
        f"{target} expects {expected} positional argument(s), got {len(node.args)}",
    )
    return False


def _is_list_type(value: str | None) -> bool:
    return value is not None and value.startswith("list[") and value.endswith("]")


def _list_item_type(value: str | None) -> str | None:
    if _is_list_type(value):
        return value[5:-1]
    return None


def _is_append_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "append"
        and len(node.args) == 1
        and not node.keywords
    )


def _validate_call(function: FunctionAnalysis, node: ast.Call) -> None:
    if node.keywords:
        _add_unsupported_syntax(function, node, "keyword call arguments are not supported")

    target = dotted_name(node.func)
    if target in DYNAMIC_FEATURES:
        function.add_diagnostic(
            Diagnostic(
                code="RXT020",
                severity="error",
                message=f"dynamic Python feature is not supported: {target}",
                file_path=function.file_path,
                line=node.lineno,
                column=node.col_offset,
                function_name=function.qualname,
                suggestion="Remove the dynamic call from the native candidate or let it run as fallback.",
            )
        )


def _unsupported_message(node: ast.AST) -> str:
    if isinstance(node, (ast.ListComp, ast.DictComp, ast.SetComp, ast.GeneratorExp)):
        return "comprehensions are not supported in Public 1 native functions"
    if isinstance(node, (ast.Tuple, ast.Dict, ast.Set)):
        return "container literals are not supported in Public 1 native functions"
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return "imports inside native functions are not supported"
    if isinstance(node, (ast.With, ast.AsyncWith)):
        return "context managers are not supported in native functions"
    if isinstance(node, ast.Try):
        return "exception handling is not supported in native functions"
    if isinstance(node, ast.Pass):
        return "pass statements are not supported in native functions"
    if isinstance(node, (ast.Assert, ast.Raise)):
        return "explicit exception flow is not supported in native functions"
    if isinstance(node, ast.Delete):
        return "delete statements are not supported in native functions"
    if isinstance(node, ast.NamedExpr):
        return "assignment expressions are not supported in native functions"
    if isinstance(node, ast.IfExp):
        return "conditional expressions are not supported in native functions"
    if isinstance(node, ast.JoinedStr):
        return "f-strings are not supported in native functions"
    if isinstance(node, ast.Starred):
        return "starred expressions are not supported in native functions"
    if isinstance(node, ast.Slice):
        return "slice expressions are not supported in native functions"
    if isinstance(node, (ast.Global, ast.Nonlocal)):
        return "global and nonlocal statements are not supported in native functions"
    if isinstance(node, ast.Match):
        return "match statements are not supported in native functions"
    if isinstance(
        node,
        (
            ast.FloorDiv,
            ast.Pow,
            ast.MatMult,
            ast.BitAnd,
            ast.BitOr,
            ast.BitXor,
            ast.LShift,
            ast.RShift,
        ),
    ):
        return "this binary operator is not supported in native functions"
    if isinstance(node, (ast.UAdd, ast.Invert)):
        return "this unary operator is not supported in native functions"
    if isinstance(node, (ast.Is, ast.IsNot, ast.In, ast.NotIn)):
        return "identity and membership comparisons are not supported in native functions"
    return f"unsupported syntax in native function: {type(node).__name__}"


def _add_unsupported_syntax(function: FunctionAnalysis, node: ast.AST, message: str) -> None:
    function.add_diagnostic(
        Diagnostic(
            code="RXT010",
            severity="error",
            message=message,
            file_path=function.file_path,
            line=getattr(node, "lineno", function.line),
            column=getattr(node, "col_offset", function.column),
            function_name=function.qualname,
            suggestion="Keep native candidates inside the supported Public 1 subset.",
        )
    )
