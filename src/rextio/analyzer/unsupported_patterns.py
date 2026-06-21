from __future__ import annotations

import ast

from rextio.analyzer.diagnostics import Diagnostic
from rextio.analyzer.models import FunctionAnalysis
from rextio.analyzer.native_marker import dotted_name, is_native_decorator
from rextio.analyzer.type_collector import annotation_name, is_supported_type

DYNAMIC_FEATURES = {"getattr", "setattr", "hasattr", "globals", "locals", "eval", "exec", "__import__"}
NUMERIC_TYPES = {"int", "float"}
DICT_KEY_TYPES = {"int", "bool", "str"}
SET_ITEM_TYPES = {"int", "float", "bool", "str"}

UNSUPPORTED_SYNTAX: tuple[type[ast.AST], ...] = (
    ast.AsyncFunctionDef,
    ast.ClassDef,
    ast.Lambda,
    ast.GeneratorExp,
    ast.Set,
    ast.Await,
    ast.Yield,
    ast.YieldFrom,
    ast.Pass,
    ast.Assert,
    ast.Raise,
    ast.Delete,
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
    ast.BitXor,
    ast.LShift,
    ast.RShift,
    ast.UAdd,
    ast.Invert,
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
                    suggestion="Use a supported Public 1 scalar or collection type.",
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
                suggestion="Use a supported Public 1 scalar or collection type.",
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
            if isinstance(target, ast.Subscript):
                _validate_dict_set(target, node.value, function, env)
                continue
            if not isinstance(target, ast.Name):
                _add_unsupported_syntax(function, target, "assignment targets must be local names")
                continue
            if value_type is not None:
                env[target.id] = value_type
        return
    if isinstance(node, ast.AnnAssign):
        if not isinstance(node.target, ast.Name):
            _add_unsupported_syntax(function, node.target, "annotated assignment targets must be local names")
            return
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
        if annotated_type is not None:
            env[node.target.id] = annotated_type
        return
    if isinstance(node, ast.AugAssign):
        if not isinstance(node.target, ast.Name):
            _add_unsupported_syntax(function, node.target, "augmented assignment targets must be local names")
            return
        target_type = _infer_expr_type(node.target, function, env)
        value_type = _infer_expr_type(node.value, function, env)
        result_type = _infer_binop_type(node.op, target_type, value_type, function, node)
        if result_type is not None:
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
        body_env = dict(env)
        if _is_enumerate_call(node.iter) or _is_zip_call(node.iter):
            item_types = _iter_unpack_types(node.iter, function, env)
            _bind_loop_target_types(node.target, item_types, function, body_env)
        else:
            iterable_type = _infer_expr_type(node.iter, function, env)
            item_type = _iter_item_type(node.iter, iterable_type)
            _bind_loop_target_types(
                node.target,
                [item_type] if item_type is not None else [],
                function,
                body_env,
            )
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
    if _types_assignable(actual, expected):
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
    *,
    allow_named_expr: bool = False,
    named_expr_binding_env: dict[str, str] | None = None,
    active_comprehension_targets: set[str] | None = None,
) -> str | None:
    binding_env = named_expr_binding_env if named_expr_binding_env is not None else env
    active_targets = active_comprehension_targets or set()

    def infer_child(
        child: ast.AST | None,
        child_env: dict[str, str] | None = None,
        child_expected_type: str | None = None,
    ) -> str | None:
        return _infer_expr_type(
            child,
            function,
            child_env if child_env is not None else env,
            child_expected_type,
            allow_named_expr=allow_named_expr,
            named_expr_binding_env=binding_env,
            active_comprehension_targets=active_targets,
        )

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
    if isinstance(node, ast.Attribute):
        _add_unsupported_syntax(
            function,
            node,
            "dynamic attribute access is not supported in native functions",
        )
        return None
    if isinstance(node, ast.List):
        return _infer_list_type(node, function, env, expected_type)
    if isinstance(node, ast.ListComp):
        return _infer_list_comprehension_type(
            node,
            function,
            env,
            binding_env,
            active_targets,
        )
    if isinstance(node, ast.Tuple):
        return _infer_tuple_type(node, function, env, expected_type)
    if isinstance(node, ast.Dict):
        return _infer_dict_type(node, function, env, expected_type)
    if isinstance(node, ast.DictComp):
        return _infer_dict_comprehension_type(
            node,
            function,
            env,
            binding_env,
            active_targets,
        )
    if isinstance(node, ast.SetComp):
        return _infer_set_comprehension_type(
            node,
            function,
            env,
            binding_env,
            active_targets,
        )
    if isinstance(node, ast.NamedExpr):
        return _infer_named_expr_type(
            node,
            function,
            env,
            binding_env,
            allow_named_expr,
            active_targets,
        )
    if isinstance(node, ast.BinOp):
        left = infer_child(node.left)
        right = infer_child(node.right)
        return _infer_binop_type(node.op, left, right, function, node)
    if isinstance(node, ast.UnaryOp):
        value_type = infer_child(node.operand)
        return _infer_unary_type(node.op, value_type, function, node)
    if isinstance(node, ast.BoolOp):
        for value in node.values:
            value_type = infer_child(value)
            if value_type is not None and value_type != "bool":
                _add_unsupported_syntax(
                    function,
                    value,
                    f"boolean operations require bool operands in Public 1, got {value_type}",
                )
        return "bool"
    if isinstance(node, ast.Compare):
        _validate_compare_types(
            node,
            function,
            env,
            allow_named_expr=allow_named_expr,
            named_expr_binding_env=binding_env,
            active_comprehension_targets=active_targets,
        )
        return "bool"
    if isinstance(node, ast.Call):
        return _infer_call_type(
            node,
            function,
            env,
            allow_named_expr=allow_named_expr,
            named_expr_binding_env=binding_env,
            active_comprehension_targets=active_targets,
        )
    if isinstance(node, ast.Subscript):
        value_type = infer_child(node.value)
        infer_child(node.slice)
        if _is_list_type(value_type):
            return _list_item_type(value_type)
        if _is_tuple_type(value_type):
            item_types = _tuple_item_types(value_type)
            index = _constant_int(node.slice)
            if index is None or index < 0 or index >= len(item_types):
                _add_unsupported_syntax(
                    function,
                    node,
                    "tuple indexes must be in-range int literals",
                )
                return None
            return item_types[index]
        if _is_dict_type(value_type):
            key_type, value_item_type = _dict_item_types(value_type)
            slice_type = infer_child(node.slice)
            if slice_type != key_type:
                _add_unsupported_syntax(function, node.slice, f"dict keys must be {key_type}, got {slice_type}")
                return None
            return value_item_type
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
    if item_type is None or not _is_supported_list_item_type(item_type):
        _add_unsupported_syntax(
            function,
            node,
            f"list literal item type is not supported: {item_type}",
        )
        return None
    return f"list[{item_type}]"


def _infer_tuple_type(
    node: ast.Tuple,
    function: FunctionAnalysis,
    env: dict[str, str],
    expected_type: str | None,
) -> str | None:
    if not node.elts:
        _add_unsupported_syntax(function, node, "empty tuple literals are not supported")
        return None

    item_types = [_infer_expr_type(item, function, env) for item in node.elts]
    if any(item_type is None for item_type in item_types):
        return None
    tuple_type = f"tuple[{', '.join(item_types)}]"
    if expected_type is not None and _is_tuple_type(expected_type):
        _validate_type_match(tuple_type, expected_type, function, node)
    return tuple_type


def _infer_dict_type(
    node: ast.Dict,
    function: FunctionAnalysis,
    env: dict[str, str],
    expected_type: str | None,
) -> str | None:
    if any(key is None for key in node.keys):
        _add_unsupported_syntax(function, node, "dictionary unpacking is not supported")
        return None

    if not node.keys:
        if expected_type is not None and _is_dict_type(expected_type):
            return expected_type
        _add_unsupported_syntax(
            function,
            node,
            "empty dict literals require a supported dict[...] annotation",
        )
        return None

    key_types = [_infer_expr_type(key, function, env) for key in node.keys if key is not None]
    value_types = [_infer_expr_type(value, function, env) for value in node.values]
    if any(key_type is None for key_type in key_types) or any(value_type is None for value_type in value_types):
        return None
    unique_key_types = set(key_types)
    if len(unique_key_types) != 1:
        _add_unsupported_syntax(function, node, "dict literal keys must have one supported type")
        return None
    key_type = key_types[0]
    if key_type not in DICT_KEY_TYPES:
        _add_unsupported_syntax(function, node, f"dict keys must be int, bool, or str, got {key_type}")
        return None
    unique_value_types = set(value_types)
    if len(unique_value_types) != 1:
        _add_unsupported_syntax(function, node, "dict literal values must have one supported type")
        return None
    value_type = value_types[0]
    if value_type is None or not _is_supported_dict_value_type(value_type):
        _add_unsupported_syntax(function, node, f"dict value type is not supported: {value_type}")
        return None
    dict_type = f"dict[{key_type}, {value_type}]"
    if expected_type is not None and _is_dict_type(expected_type):
        _validate_type_match(dict_type, expected_type, function, node)
    return dict_type


def _infer_list_comprehension_type(
    node: ast.ListComp,
    function: FunctionAnalysis,
    env: dict[str, str],
    binding_env: dict[str, str],
    active_targets: set[str],
) -> str | None:
    comp_env = _bind_comprehension_generators(node.generators, function, env, binding_env, active_targets)
    if comp_env is None:
        return None
    item_type = _infer_expr_type(
        node.elt,
        function,
        comp_env,
        allow_named_expr=True,
        named_expr_binding_env=binding_env,
        active_comprehension_targets=active_targets | _comprehension_target_names(node.generators),
    )
    if item_type is None:
        return None
    if not _is_supported_list_item_type(item_type):
        _add_unsupported_syntax(
            function,
            node,
            f"list comprehension item type is not supported: {item_type}",
        )
        return None
    return f"list[{item_type}]"


def _infer_dict_comprehension_type(
    node: ast.DictComp,
    function: FunctionAnalysis,
    env: dict[str, str],
    binding_env: dict[str, str],
    active_targets: set[str],
) -> str | None:
    comp_env = _bind_comprehension_generators(node.generators, function, env, binding_env, active_targets)
    if comp_env is None:
        return None
    comprehension_targets = active_targets | _comprehension_target_names(node.generators)
    key_type = _infer_expr_type(
        node.key,
        function,
        comp_env,
        allow_named_expr=True,
        named_expr_binding_env=binding_env,
        active_comprehension_targets=comprehension_targets,
    )
    value_type = _infer_expr_type(
        node.value,
        function,
        comp_env,
        allow_named_expr=True,
        named_expr_binding_env=binding_env,
        active_comprehension_targets=comprehension_targets,
    )
    if key_type not in DICT_KEY_TYPES:
        _add_unsupported_syntax(function, node.key, f"dict comprehension keys must be int, bool, or str, got {key_type}")
        return None
    if value_type is None or not _is_supported_dict_value_type(value_type):
        _add_unsupported_syntax(
            function,
            node.value,
            f"dict comprehension value type is not supported: {value_type}",
        )
        return None
    return f"dict[{key_type}, {value_type}]"


def _infer_set_comprehension_type(
    node: ast.SetComp,
    function: FunctionAnalysis,
    env: dict[str, str],
    binding_env: dict[str, str],
    active_targets: set[str],
) -> str | None:
    comp_env = _bind_comprehension_generators(node.generators, function, env, binding_env, active_targets)
    if comp_env is None:
        return None
    item_type = _infer_expr_type(
        node.elt,
        function,
        comp_env,
        allow_named_expr=True,
        named_expr_binding_env=binding_env,
        active_comprehension_targets=active_targets | _comprehension_target_names(node.generators),
    )
    if item_type not in SET_ITEM_TYPES:
        _add_unsupported_syntax(
            function,
            node.elt,
            f"set comprehension item type must be int, float, bool, or str, got {item_type}",
        )
        return None
    return f"set[{item_type}]"


def _bind_comprehension_generators(
    generators: list[ast.comprehension],
    function: FunctionAnalysis,
    env: dict[str, str],
    binding_env: dict[str, str],
    active_targets: set[str],
) -> dict[str, str] | None:
    if not generators:
        _add_unsupported_syntax(function, function, "comprehensions require at least one generator")
        return None
    comp_env = dict(env)
    comprehension_targets = active_targets | _comprehension_target_names(generators)
    for generator in generators:
        if generator.is_async:
            _add_unsupported_syntax(function, generator, "async comprehensions are not supported")
            return None
        item_types = _comprehension_iter_item_types(generator.iter, function, comp_env)
        _bind_loop_target_types(generator.target, item_types, function, comp_env)
        for condition in generator.ifs:
            condition_type = _infer_expr_type(
                condition,
                function,
                comp_env,
                allow_named_expr=True,
                named_expr_binding_env=binding_env,
                active_comprehension_targets=comprehension_targets,
            )
            if condition_type is not None and condition_type != "bool":
                _add_unsupported_syntax(
                    function,
                    condition,
                    f"comprehension if clauses must be bool, got {condition_type}",
                )
    return comp_env


def _comprehension_iter_item_types(
    node: ast.AST,
    function: FunctionAnalysis,
    env: dict[str, str],
) -> list[str]:
    if isinstance(node, ast.Call) and (_is_enumerate_call(node) or _is_zip_call(node)):
        return _iter_unpack_types(node, function, env)
    iterable_type = _infer_expr_type(node, function, env)
    item_type = _iter_item_type(node, iterable_type)
    return [item_type] if item_type is not None else []


def _infer_named_expr_type(
    node: ast.NamedExpr,
    function: FunctionAnalysis,
    env: dict[str, str],
    binding_env: dict[str, str],
    allow_named_expr: bool,
    active_targets: set[str],
) -> str | None:
    if not allow_named_expr:
        _add_unsupported_syntax(
            function,
            node,
            "assignment expressions are supported only inside comprehensions",
        )
        return None
    if not isinstance(node.target, ast.Name):
        _add_unsupported_syntax(function, node.target, "assignment expression targets must be local names")
        return None
    if node.target.id in active_targets:
        _add_unsupported_syntax(
            function,
            node.target,
            "assignment expressions cannot rebind comprehension iteration variables",
        )
        return None
    value_type = _infer_expr_type(
        node.value,
        function,
        env,
        allow_named_expr=True,
        named_expr_binding_env=binding_env,
        active_comprehension_targets=active_targets,
    )
    if value_type is not None:
        env[node.target.id] = value_type
        binding_env[node.target.id] = value_type
    return value_type


def _comprehension_target_names(generators: list[ast.comprehension]) -> set[str]:
    names: set[str] = set()
    for generator in generators:
        names.update(_target_names(generator.target))
    return names


def _target_names(target: ast.AST) -> set[str]:
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, ast.Tuple):
        names: set[str] = set()
        for item in target.elts:
            names.update(_target_names(item))
        return names
    return set()


def _infer_call_type(
    node: ast.Call,
    function: FunctionAnalysis,
    env: dict[str, str],
    *,
    allow_named_expr: bool = False,
    named_expr_binding_env: dict[str, str] | None = None,
    active_comprehension_targets: set[str] | None = None,
) -> str | None:
    binding_env = named_expr_binding_env if named_expr_binding_env is not None else env
    active_targets = active_comprehension_targets or set()

    def infer_arg(arg: ast.AST) -> str | None:
        return _infer_expr_type(
            arg,
            function,
            env,
            allow_named_expr=allow_named_expr,
            named_expr_binding_env=binding_env,
            active_comprehension_targets=active_targets,
        )

    for arg in node.args:
        infer_arg(arg)

    target = dotted_name(node.func)
    if target == "len":
        if not _require_arg_count("len", node, function, {1}):
            return None
        return "int"
    if target == "range":
        _validate_range_call(node, function, env)
        return None
    if target == "enumerate":
        _add_unsupported_syntax(
            function,
            node,
            "enumerate is supported only as a for-loop iterable",
        )
        return None
    if target == "zip":
        _add_unsupported_syntax(function, node, "zip is supported only as a for-loop iterable")
        return None
    if target == "abs":
        if not _require_arg_count("abs", node, function, {1}):
            return None
        arg_type = infer_arg(node.args[0])
        if arg_type in NUMERIC_TYPES:
            return arg_type
        _add_unsupported_syntax(function, node, f"abs requires int or float, got {arg_type}")
        return None
    if target in {"min", "max"}:
        if not _require_arg_count(target, node, function, {2}):
            return None
        arg_types = [infer_arg(arg) for arg in node.args]
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
        arg_type = infer_arg(node.args[0])
        item_type = _list_item_type(arg_type)
        if item_type in NUMERIC_TYPES:
            return item_type
        _add_unsupported_syntax(function, node, f"sum requires list[int] or list[float], got {arg_type}")
        return None
    if target in {"math.sqrt", "math.sin", "math.cos"}:
        if not _require_arg_count(target, node, function, {1}):
            return None
        arg_type = infer_arg(node.args[0])
        if arg_type == "float":
            return "float"
        _add_unsupported_syntax(function, node, f"{target} requires a float argument")
        return None
    if target == "math.floor":
        if not _require_arg_count("math.floor", node, function, {1}):
            return None
        arg_type = infer_arg(node.args[0])
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
        _add_unsupported_syntax(
            function,
            node,
            "this binary operator is not supported in native functions",
        )
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
    *,
    allow_named_expr: bool = False,
    named_expr_binding_env: dict[str, str] | None = None,
    active_comprehension_targets: set[str] | None = None,
) -> None:
    binding_env = named_expr_binding_env if named_expr_binding_env is not None else env
    active_targets = active_comprehension_targets or set()

    def infer_side(side: ast.AST) -> str | None:
        return _infer_expr_type(
            side,
            function,
            env,
            allow_named_expr=allow_named_expr,
            named_expr_binding_env=binding_env,
            active_comprehension_targets=active_targets,
        )

    left_type = infer_side(node.left)
    for op, comparator in zip(node.ops, node.comparators, strict=True):
        right_type = infer_side(comparator)
        if (
            left_type is not None
            and right_type is not None
            and not _types_comparable(left_type, right_type)
        ):
            _add_unsupported_syntax(
                function,
                node,
                f"mixed comparison operand types are not supported: {left_type} and {right_type}",
            )
        left_type = right_type


def _iter_item_type(node: ast.AST, iterable_type: str | None) -> str | None:
    if _is_list_type(iterable_type):
        return _list_item_type(iterable_type)
    if _is_set_type(iterable_type):
        return _set_item_type(iterable_type)
    if isinstance(node, ast.Call) and dotted_name(node.func) == "range":
        return "int"
    return None


def _iter_unpack_types(
    node: ast.AST,
    function: FunctionAnalysis,
    env: dict[str, str],
) -> list[str]:
    if isinstance(node, ast.Call) and _is_enumerate_call(node):
        _validate_enumerate_call(node, function, env)
        item_type = _list_item_type(_infer_expr_type(node.args[0], function, env))
        return ["int", item_type] if item_type is not None else []
    if isinstance(node, ast.Call) and _is_zip_call(node):
        item_types = _validate_zip_call(node, function, env)
        return item_types
    return []


def _bind_loop_target_types(
    target: ast.AST,
    item_types: list[str],
    function: FunctionAnalysis,
    env: dict[str, str],
) -> None:
    if isinstance(target, ast.Name):
        if len(item_types) == 1:
            env[target.id] = item_types[0]
            return
        if len(item_types) == 0:
            _add_unsupported_syntax(
                function,
                target,
                "for-loop iterable must be a supported list, range, enumerate, or zip",
            )
            return
        _add_unsupported_syntax(
            function,
            target,
            "enumerate and zip loop targets must unpack into local names",
        )
        return

    if isinstance(target, ast.Tuple):
        names = [item for item in target.elts if isinstance(item, ast.Name)]
        if len(names) != len(target.elts):
            _add_unsupported_syntax(function, target, "for-loop unpack targets must be local names")
            return
        if len(item_types) == 0:
            _add_unsupported_syntax(
                function,
                target,
                "for-loop iterable must be a supported enumerate or zip call",
            )
            return
        if len(names) != len(item_types):
            _add_unsupported_syntax(
                function,
                target,
                f"for-loop unpack target count {len(names)} does not match iterable item count {len(item_types)}",
            )
            return
        for name, item_type in zip(names, item_types, strict=True):
            env[name.id] = item_type
        return

    _add_unsupported_syntax(function, target, "for-loop targets must be local names")


def _validate_enumerate_call(
    node: ast.Call,
    function: FunctionAnalysis,
    env: dict[str, str],
) -> None:
    if not _require_arg_count("enumerate", node, function, {1}):
        return
    if not isinstance(node.args[0], ast.Name):
        _add_unsupported_syntax(
            function,
            node.args[0],
            "enumerate currently supports list variables only",
        )
        return
    item_type = _list_item_type(_infer_expr_type(node.args[0], function, env))
    if item_type is None:
        _add_unsupported_syntax(
            function,
            node.args[0],
            "enumerate currently supports supported list[...] variables only",
        )


def _validate_zip_call(
    node: ast.Call,
    function: FunctionAnalysis,
    env: dict[str, str],
) -> list[str]:
    if not _require_arg_count("zip", node, function, {2}):
        return []
    item_types: list[str] = []
    for arg in node.args:
        if not isinstance(arg, ast.Name):
            _add_unsupported_syntax(function, arg, "zip currently supports list variables only")
            continue
        item_type = _list_item_type(_infer_expr_type(arg, function, env))
        if item_type is None:
            _add_unsupported_syntax(
                function,
                arg,
                "zip currently supports supported list[...] variables only",
            )
            continue
        item_types.append(item_type)
    return item_types if len(item_types) == 2 else []


def _validate_dict_set(
    target: ast.Subscript,
    value: ast.AST,
    function: FunctionAnalysis,
    env: dict[str, str],
) -> None:
    if not isinstance(target.value, ast.Name):
        _add_unsupported_syntax(function, target, "dict assignment targets must be local names")
        return
    target_type = _infer_expr_type(target.value, function, env)
    if not _is_dict_type(target_type):
        _add_unsupported_syntax(function, target, f"subscript assignment requires a supported dict, got {target_type}")
        return
    key_type, value_type = _dict_item_types(target_type)
    slice_type = _infer_expr_type(target.slice, function, env)
    assigned_type = _infer_expr_type(value, function, env)
    if slice_type != key_type:
        _add_unsupported_syntax(function, target.slice, f"dict assignment key must be {key_type}, got {slice_type}")
    if assigned_type is not None and not _types_assignable(assigned_type, value_type):
        _add_unsupported_syntax(
            function,
            value,
            f"dict assignment value type {assigned_type} does not match {value_type}",
        )


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


def _is_supported_list_item_type(value: str) -> bool:
    if value in {"int", "float", "bool", "str"}:
        return True
    item_type = _list_item_type(value)
    return item_type is not None and _is_supported_list_item_type(item_type)


def _is_supported_dict_value_type(value: str) -> bool:
    if value in {"int", "float", "bool", "str"}:
        return True
    if _is_list_type(value):
        item_type = _list_item_type(value)
        return item_type is not None and _is_supported_list_item_type(item_type)
    if _is_tuple_type(value):
        return all(item_type in {"int", "float", "bool", "str"} for item_type in _tuple_item_types(value))
    if _is_dict_type(value):
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


def _is_tuple_type(value: str | None) -> bool:
    return value is not None and value.startswith("tuple[") and value.endswith("]")


def _tuple_item_types(value: str | None) -> list[str]:
    if not _is_tuple_type(value):
        return []
    return _split_type_args(value[6:-1])


def _is_dict_type(value: str | None) -> bool:
    return value is not None and value.startswith("dict[") and value.endswith("]")


def _dict_item_types(value: str | None) -> tuple[str | None, str | None]:
    if not _is_dict_type(value):
        return None, None
    items = _split_type_args(value[5:-1])
    if len(items) != 2:
        return None, None
    return items[0], items[1]


def _is_set_type(value: str | None) -> bool:
    return value is not None and value.startswith("set[") and value.endswith("]")


def _set_item_type(value: str | None) -> str | None:
    if _is_set_type(value):
        return value[4:-1]
    return None


def _is_optional_type(value: str | None) -> bool:
    return value is not None and value.startswith("Optional[") and value.endswith("]")


def _optional_item_type(value: str | None) -> str | None:
    if _is_optional_type(value):
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
    if isinstance(node, ast.Set):
        return "set literals are not supported in Public 1 native functions"
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
            ast.BitXor,
            ast.LShift,
            ast.RShift,
        ),
    ):
        return "this binary operator is not supported in native functions"
    if isinstance(node, (ast.UAdd, ast.Invert)):
        return "this unary operator is not supported in native functions"
    if isinstance(node, (ast.In, ast.NotIn)):
        return "membership comparisons are not supported in native functions"
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
