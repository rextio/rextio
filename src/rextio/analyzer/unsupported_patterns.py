"""Validation of a function body against the supported subset."""

from __future__ import annotations

import ast

from rextio.analyzer.common_calls import (
    BASE64_TARGETS,
    BYTES_METHOD_TARGETS,
    DATETIME_ISOFORMAT_TARGETS,
    DATETIME_TIMESTAMP_TARGETS,
    HASHLIB_CHAIN_TARGETS,
    JSON_TARGETS,
    LIST_METHOD_TARGETS,
    LOGGING_CANONICAL_TARGETS,
    MATH_CONSTANT_TARGETS,
    MATH_FLOAT_BINARY_TARGETS,
    MATH_FLOAT_TO_BOOL_TARGETS,
    MATH_FLOAT_TO_INT_TARGETS,
    MATH_FLOAT_UNARY_TARGETS,
    STATISTICS_TARGETS,
    STR_METHOD_TARGETS,
    TIME_TARGETS,
    canonical_attribute_target,
    canonical_call_target,
    is_supported_effect_call,
)
from rextio.analyzer.diagnostics import Diagnostic
from rextio.analyzer.models import FunctionAnalysis
from rextio.analyzer.native_marker import dotted_name, is_native_decorator
from rextio.analyzer.type_collector import annotation_name, is_supported_type
from rextio.codegen.native_names import native_function_name
from rextio.codegen.rust.keywords import RUST_RAW_INCOMPATIBLE

# Shared, stateless type/AST predicates (see rextio.analyzer.type_predicates).
from rextio.analyzer.type_predicates import (
    _call_receiver,
    _chained_call_args,
    _constant_int,
    _dict_item_types,
    _is_append_call,
    _is_dict_type,
    _is_enumerate_call,
    _is_json_supported_type,
    _is_list_type,
    _is_mutable_collection_type,
    _is_set_type,
    _is_supported_dict_value_type,
    _is_supported_list_item_type,
    _is_supported_signature_type,
    _is_tuple_type,
    _is_zip_call,
    _list_item_type,
    _mutable_collection_names_captured_by_container,
    _mutated_collection_names,
    _set_item_type,
    _tuple_item_types,
    _types_assignable,
    _types_comparable,
)

# Type-capability sets come from the shared registry (see rextio.capabilities)
# so the analyzer and code generator cannot drift apart.
from rextio.capabilities import (
    DICT_KEY_TYPES,
    NUMERIC_TYPES,
    SET_ITEM_TYPES,
)
from rextio.exceptions import is_supported_builtin_exception

DYNAMIC_FEATURES = {"getattr", "setattr", "hasattr", "globals", "locals", "eval", "exec", "__import__"}

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
    ast.TryStar,
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
    ast.With,
    ast.AsyncWith,
    ast.Import,
    ast.ImportFrom,
)


def validate_native_function(node: ast.FunctionDef, function: FunctionAnalysis) -> None:
    """Validate a function body against the supported subset, attaching diagnostics."""
    _validate_decorators(node, function)
    _infer_missing_signature_from_context(node, function)
    _validate_signature(node, function)
    _validate_body(node, function)
    _validate_identifiers(node, function)
    function.accepted = not function.error_diagnostics


def _validate_identifiers(node: ast.FunctionDef, function: FunctionAnalysis) -> None:
    """Reject identifiers that cannot be lowered to a valid Rust identifier.

    The function name, parameters, and locals are emitted as Rust identifiers.
    Codegen carries a name that collides with a Rust keyword as a raw identifier
    (`match` -> `r#match`), so those stay native. What still cannot be represented
    is kept on the Python fallback path with a clear diagnostic: keywords `r#`
    cannot express (`crate`/`self`/`Self`/`super`), non-ASCII names (Rextio does
    not transliterate them), and `_` used as anything other than a throwaway
    loop/comprehension target (Rust `_` is a discard pattern, not a value).
    """
    _validate_function_name(node, function)

    # `_` is special; emit its diagnostic once, independent of the candidate loop
    # (it can be misused as a read with no Store occurrence to iterate over).
    misused_underscore = _misused_underscore_node(node)
    if misused_underscore is not None:
        _add_identifier_diagnostic(
            function,
            misused_underscore,
            "'_' is a Rust discard pattern and cannot be assigned to or read",
            "Use a named variable instead of '_', or keep '_' only as an unused loop variable.",
        )

    args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
    if node.args.vararg is not None:
        args.append(node.args.vararg)
    if node.args.kwarg is not None:
        args.append(node.args.kwarg)
    # Parameters plus every binding (Store-context) name — assignment targets,
    # for-loop targets, and walrus targets are all `ast.Name` with `ctx=Store`,
    # which also covers every load site (a load only follows a binding).
    candidates: list[tuple[str, ast.AST]] = [(arg.arg, arg) for arg in args]
    candidates.extend(
        (child.id, child)
        for child in ast.walk(node)
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store)
    )
    seen: set[str] = set()
    for name, where in candidates:
        if name in seen:
            continue
        seen.add(name)
        if name == "_":
            continue  # handled by `_misused_underscore_node` above
        if name in RUST_RAW_INCOMPATIBLE:
            message = (
                f"identifier '{name}' is a Rust keyword that cannot be carried as a "
                "raw identifier"
            )
            suggestion = (
                f"Rename '{name}' (a Rust keyword `r#` cannot escape) or keep this "
                "function on Python fallback."
            )
        elif not (name.isascii() and name.isidentifier()):
            message = f"identifier '{name}' uses non-ASCII characters not supported in generated Rust"
            suggestion = (
                f"Use an ASCII name for '{name}' or keep this function on Python fallback."
            )
        else:
            continue
        _add_identifier_diagnostic(function, where, message, suggestion)


def _validate_function_name(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    function: FunctionAnalysis,
) -> None:
    """Reject a function whose *name* cannot be lowered to a Rust `fn` identifier.

    Checked on the raw name first, before `native_function_name` (which raises on a
    name that sanitizes to empty): a non-ASCII name would be silently mangled (and
    can collide), an all-underscore name sanitizes to empty/`fn _` (invalid), and an
    emitted name that is a non-raw-able keyword (`crate`/`self`/…) cannot be escaped.
    """
    name = node.name
    if not name.isascii():
        _add_identifier_diagnostic(
            function,
            node,
            f"function name '{name}' uses non-ASCII characters not supported in generated Rust",
            f"Rename '{name}' to an ASCII name or keep this function on Python fallback.",
        )
        return
    if not name.strip("_"):
        _add_identifier_diagnostic(
            function,
            node,
            f"function name '{name}' has no usable characters for a Rust identifier",
            f"Rename '{name}' or keep this function on Python fallback.",
        )
        return
    emitted = native_function_name(function.qualname)
    if emitted in RUST_RAW_INCOMPATIBLE:
        _add_identifier_diagnostic(
            function,
            node,
            f"function name '{name}' lowers to the Rust keyword '{emitted}', "
            "which a raw identifier cannot carry",
            f"Rename '{name}' or keep this function on Python fallback.",
        )


def _misused_underscore_node(node: ast.AST) -> ast.AST | None:
    """Return the first `_` used as a value, or None.

    Rust accepts `_` only as a discard pattern (`for _ in …`); as an assignment or
    walrus target it would emit `let mut _` and as a read a bare `_`, both invalid.
    Returns the offending `ast.Name` so the diagnostic can point at it.
    """
    discard_targets: set[int] = set()
    for child in ast.walk(node):
        target = child.target if isinstance(child, (ast.For, ast.comprehension)) else None
        if target is not None:
            for inner in ast.walk(target):
                if isinstance(inner, ast.Name) and inner.id == "_":
                    discard_targets.add(id(inner))
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id == "_" and id(child) not in discard_targets:
            return child
    return None


def _add_identifier_diagnostic(
    function: FunctionAnalysis,
    where: ast.AST,
    message: str,
    suggestion: str,
) -> None:
    function.add_diagnostic(
        Diagnostic(
            code="RXT011",
            severity="error",
            message=message,
            file_path=function.file_path,
            line=getattr(where, "lineno", function.line),
            column=getattr(where, "col_offset", function.column),
            function_name=function.qualname,
            suggestion=suggestion,
        )
    )


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
                suggestion="Use only @rextio.native on 0.1.0 alpha native candidates.",
            )
        )


def _validate_signature(node: ast.FunctionDef, function: FunctionAnalysis) -> None:
    if node.args.vararg is not None:
        _add_unsupported_syntax(function, node.args.vararg, "arbitrary *args are not supported")
    if node.args.kwarg is not None:
        _add_unsupported_syntax(function, node.args.kwarg, "arbitrary **kwargs are not supported")

    args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
    for arg in args:
        if arg.annotation is None and arg.arg not in function.inferred_arg_types:
            function.add_diagnostic(
                Diagnostic(
                    code="RXT001",
                    severity="error",
                    message=f"missing type annotation for argument: {arg.arg}",
                    file_path=function.file_path,
                    line=arg.lineno,
                    column=arg.col_offset,
                    function_name=function.qualname,
                    suggestion="Add a supported 0.1.0 alpha type annotation.",
                )
            )
        elif arg.annotation is not None and not is_supported_type(arg.annotation):
            function.add_diagnostic(
                Diagnostic(
                    code="RXT002",
                    severity="error",
                    message=f"unsupported argument type for {arg.arg}: {annotation_name(arg.annotation)}",
                    file_path=function.file_path,
                    line=arg.lineno,
                    column=arg.col_offset,
                    function_name=function.qualname,
                    suggestion="Use a supported 0.1.0 alpha scalar or collection type.",
                )
            )

    if node.returns is None and function.inferred_return_type is None:
        function.add_diagnostic(
            Diagnostic(
                code="RXT001",
                severity="error",
                message="missing return type annotation",
                file_path=function.file_path,
                line=node.lineno,
                column=node.col_offset,
                function_name=function.qualname,
                suggestion="Add a supported 0.1.0 alpha return type annotation.",
            )
        )
    elif node.returns is not None and not is_supported_type(node.returns):
        function.add_diagnostic(
            Diagnostic(
                code="RXT003",
                severity="error",
                message=f"unsupported return type: {annotation_name(node.returns)}",
                file_path=function.file_path,
                line=node.lineno,
                column=node.col_offset,
                function_name=function.qualname,
                suggestion="Use a supported 0.1.0 alpha scalar or collection type.",
            )
        )


def _validate_body(node: ast.FunctionDef, function: FunctionAnalysis) -> None:
    type_env = _initial_type_env(node, function)
    return_type = _return_type_name(node, function)
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
    _validate_mutable_ownership_patterns(node, function)
    _validate_return_paths(node, function, return_type)


def _validate_return_paths(
    node: ast.FunctionDef,
    function: FunctionAnalysis,
    return_type: str | None,
) -> None:
    """Reject a value-returning function whose body can fall off the end.

    Python returns ``None`` when control reaches the end of a function, but the
    Rust generator appends a synthesized default return (``0``/``false``/empty
    string/``None``) for the declared type, so a fall-through path would silently
    return a fabricated value instead of ``None``. Keep such functions on the
    Python fallback path with a diagnostic rather than mis-compile them.
    """
    if return_type is None or return_type == "None":
        return
    if not _block_always_returns(node.body):
        _add_unsupported_syntax(
            function,
            node,
            "not all control-flow paths return a value; "
            f"a fall-through path would not return the declared {return_type}",
        )


def _block_always_returns(statements: list[ast.stmt]) -> bool:
    """Report whether a statement list guarantees a return/raise on every path."""
    for statement in statements:
        if isinstance(statement, (ast.Return, ast.Raise)):
            return True
        if (
            isinstance(statement, ast.If)
            and statement.orelse
            and _block_always_returns(statement.body)
            and _block_always_returns(statement.orelse)
        ):
            return True
    return False


def _initial_type_env(node: ast.FunctionDef, function: FunctionAnalysis) -> dict[str, str]:
    env: dict[str, str] = {}
    args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
    for arg in args:
        if arg.annotation is not None and is_supported_type(arg.annotation):
            env[arg.arg] = annotation_name(arg.annotation)
        elif arg.arg in function.inferred_arg_types:
            env[arg.arg] = function.inferred_arg_types[arg.arg]
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
        if not _is_append_call(node.value) and not is_supported_effect_call(
            node.value,
            function.imports,
            function.logger_names,
        ):
            _add_unsupported_syntax(
                function,
                node,
                "expression statements are supported only for list.append, print, and logging calls in native functions",
            )
        return
    if isinstance(node, (ast.Break, ast.Continue)):
        return
    if isinstance(node, ast.Return):
        value_type = "None"
        if node.value is not None:
            value_type = _infer_expr_type(node.value, function, env, expected_type=return_type)
        if value_type is not None and return_type is not None:
            _validate_type_match(value_type, return_type, function, node)
        return
    if isinstance(node, ast.If):
        _infer_expr_type(node.test, function, env)
        _validate_statement_list_types(node.body, function, dict(env), return_type)
        _validate_statement_list_types(node.orelse, function, dict(env), return_type)
        return
    if isinstance(node, ast.For):
        if node.orelse:
            _add_unsupported_syntax(
                function,
                node,
                "for ... else is not supported in native functions",
            )
            return
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
        if node.orelse:
            _add_unsupported_syntax(
                function,
                node,
                "while ... else is not supported in native functions",
            )
            return
        _infer_expr_type(node.test, function, env)
        _validate_statement_list_types(node.body, function, dict(env), return_type)
        return
    if isinstance(node, ast.Try):
        _validate_try(node, function, env, return_type)


def _validate_statement_list_types(
    statements: list[ast.stmt],
    function: FunctionAnalysis,
    env: dict[str, str],
    return_type: str | None,
) -> None:
    for statement in statements:
        _validate_statement_types(statement, function, env, return_type)


def _validate_try(
    node: ast.Try,
    function: FunctionAnalysis,
    env: dict[str, str],
    return_type: str | None,
) -> None:
    """Validate the restricted native ``try``/``except``/``finally`` subset.

    Native lowering uses immediately-invoked closures, so the supported subset is
    deliberately narrow: built-in exception handlers only, no ``try ... else``,
    no ``return``/``break``/``continue`` inside any block, no ``as`` binding, and
    no variable first-bound inside a block (it would be closure-scoped). Anything
    outside the subset is rejected with RXT010 so the function stays on the
    Python fallback (or the RXT080 runtime shim when explicitly ``@rextio.native``).
    """
    if node.orelse:
        _add_unsupported_syntax(
            function, node, "try ... else is not supported in native functions"
        )
        return
    if not node.handlers and not node.finalbody:
        _add_unsupported_syntax(
            function, node, "try without except or finally is not supported in native functions"
        )
        return
    for handler in node.handlers:
        if handler.name is not None:
            _add_unsupported_syntax(
                function, handler, "'except ... as name' is not supported in native functions"
            )
            return
        if not isinstance(handler.type, ast.Name) or not is_supported_builtin_exception(
            handler.type.id
        ):
            _add_unsupported_syntax(
                function,
                handler,
                "only single built-in exception handlers are supported in native functions",
            )
            return
    blocks = [node.body, node.finalbody, *(handler.body for handler in node.handlers)]
    for block in blocks:
        for statement in block:
            for child in ast.walk(statement):
                if isinstance(child, ast.Return):
                    # The try body is lowered into an immediately-invoked closure,
                    # so a `return` would return from the closure, not the function.
                    _add_unsupported_syntax(
                        function,
                        node,
                        "return inside try/except/finally is not supported in native functions",
                    )
                    return
        if any(_has_free_break_continue(statement) for statement in block):
            # break/continue bound to a loop *inside* the block is fine; one that
            # targets a loop enclosing the try cannot cross the closure boundary.
            _add_unsupported_syntax(
                function,
                node,
                "break/continue targeting a loop outside try/except/finally is not "
                "supported in native functions",
            )
            return
    bound_before = set(env)
    new_bindings = sorted(_block_bound_names(blocks) - bound_before)
    if new_bindings:
        _add_unsupported_syntax(
            function,
            node,
            "variables first assigned inside try/except/finally are not supported "
            f"in native functions: {', '.join(new_bindings)}",
        )
        return
    _validate_statement_list_types(node.body, function, env, return_type)
    for handler in node.handlers:
        _validate_statement_list_types(handler.body, function, env, return_type)
    _validate_statement_list_types(node.finalbody, function, env, return_type)


def _has_free_break_continue(node: ast.AST) -> bool:
    """Report whether a node has a ``break``/``continue`` not bound to a loop it contains.

    A loop (or nested scope) binds any ``break``/``continue`` inside it, so only a
    ``break``/``continue`` that would target an *enclosing* loop is "free".
    """
    if isinstance(node, (ast.Break, ast.Continue)):
        return True
    if isinstance(node, (ast.For, ast.While, ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        return False
    return any(_has_free_break_continue(child) for child in ast.iter_child_nodes(node))


def _assignment_target_names(target: ast.AST) -> set[str]:
    """Return the Store-context names in an assignment/loop target (handles tuples)."""
    return {
        node.id
        for node in ast.walk(target)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
    }


def _block_bound_names(blocks: list[list[ast.stmt]]) -> set[str]:
    """Return the names a block first binds and that could escape its closure.

    Collects assignment / annotated-assignment / augmented-assignment / for-loop /
    walrus targets. Comprehension targets are intentionally excluded: they are
    scoped to the comprehension in both Python and Rust and never leak, so they
    are not new function-scope bindings. (Loop targets stay included — a Python
    loop variable leaks past its loop where a Rust one does not.)
    """
    names: set[str] = set()
    for block in blocks:
        for statement in block:
            for child in ast.walk(statement):
                if isinstance(child, ast.Assign):
                    for target in child.targets:
                        names |= _assignment_target_names(target)
                elif isinstance(child, (ast.AnnAssign, ast.AugAssign, ast.For, ast.NamedExpr)):
                    names |= _assignment_target_names(child.target)
    return names


def _validate_mutable_ownership_patterns(node: ast.FunctionDef, function: FunctionAnalysis) -> None:
    mutation_names = _mutated_collection_names(node)
    if not mutation_names:
        return
    env = _initial_type_env(node, function)
    _validate_mutable_ownership_in_statements(node.body, function, env, mutation_names)


def _validate_mutable_ownership_in_statements(
    statements: list[ast.stmt],
    function: FunctionAnalysis,
    env: dict[str, str],
    mutation_names: set[str],
) -> None:
    for statement in statements:
        if isinstance(statement, ast.Assign):
            value_type = _infer_expr_type(statement.value, function, env)
            _validate_mutated_container_captures(statement.value, function, env, mutation_names)
            for target in statement.targets:
                if isinstance(target, ast.Name):
                    _validate_mutable_alias_assignment(target, statement.value, function, env, mutation_names)
                    if value_type is not None:
                        env[target.id] = value_type
            continue
        if isinstance(statement, ast.AnnAssign):
            annotated_type = (
                annotation_name(statement.annotation)
                if statement.annotation is not None and is_supported_type(statement.annotation)
                else None
            )
            if statement.value is not None:
                _infer_expr_type(statement.value, function, env, expected_type=annotated_type)
                _validate_mutated_container_captures(statement.value, function, env, mutation_names)
                if isinstance(statement.target, ast.Name):
                    _validate_mutable_alias_assignment(
                        statement.target,
                        statement.value,
                        function,
                        env,
                        mutation_names,
                    )
            if annotated_type is not None and isinstance(statement.target, ast.Name):
                env[statement.target.id] = annotated_type
            continue
        if isinstance(statement, ast.AugAssign):
            _infer_expr_type(statement.target, function, env)
            _infer_expr_type(statement.value, function, env)
            _validate_mutated_container_captures(statement.value, function, env, mutation_names)
            continue
        if isinstance(statement, ast.Expr):
            _infer_expr_type(statement.value, function, env)
            _validate_mutated_container_captures(statement.value, function, env, mutation_names)
            continue
        if isinstance(statement, ast.Return):
            if statement.value is not None:
                _infer_expr_type(statement.value, function, env)
                _validate_mutated_container_captures(statement.value, function, env, mutation_names)
            continue
        if isinstance(statement, ast.If):
            _infer_expr_type(statement.test, function, env)
            _validate_mutable_ownership_in_statements(statement.body, function, dict(env), mutation_names)
            _validate_mutable_ownership_in_statements(statement.orelse, function, dict(env), mutation_names)
            continue
        if isinstance(statement, ast.For):
            body_env = dict(env)
            if _is_enumerate_call(statement.iter) or _is_zip_call(statement.iter):
                item_types = _iter_unpack_types(statement.iter, function, env)
                _bind_loop_target_types(statement.target, item_types, function, body_env)
            else:
                iterable_type = _infer_expr_type(statement.iter, function, env)
                item_type = _iter_item_type(statement.iter, iterable_type)
                _bind_loop_target_types(
                    statement.target,
                    [item_type] if item_type is not None else [],
                    function,
                    body_env,
                )
            _validate_mutated_container_captures(statement.iter, function, env, mutation_names)
            _validate_mutable_ownership_in_statements(statement.body, function, body_env, mutation_names)
            _validate_mutable_ownership_in_statements(statement.orelse, function, dict(env), mutation_names)
            continue
        if isinstance(statement, ast.While):
            _infer_expr_type(statement.test, function, env)
            _validate_mutated_container_captures(statement.test, function, env, mutation_names)
            _validate_mutable_ownership_in_statements(statement.body, function, dict(env), mutation_names)
            _validate_mutable_ownership_in_statements(statement.orelse, function, dict(env), mutation_names)


def _validate_mutable_alias_assignment(
    target: ast.Name,
    value: ast.AST,
    function: FunctionAnalysis,
    env: dict[str, str],
    mutation_names: set[str],
) -> None:
    if not isinstance(value, ast.Name) or target.id == value.id:
        return
    value_type = env.get(value.id)
    if not _is_mutable_collection_type(value_type):
        return
    if target.id not in mutation_names and value.id not in mutation_names:
        return
    _add_unsupported_syntax(
        function,
        value,
        (
            "mutable collection aliases are not supported in direct Rust native functions "
            "when either alias is mutated"
        ),
        suggestion=(
            "Use an explicit .copy() before mutation, move the mutation into one owned "
            "variable, or keep this function on Python fallback."
        ),
    )


def _validate_mutated_container_captures(
    value: ast.AST,
    function: FunctionAnalysis,
    env: dict[str, str],
    mutation_names: set[str],
) -> None:
    captured = _mutable_collection_names_captured_by_container(value, env)
    unsafe = sorted(name for name in captured if name in mutation_names)
    if not unsafe:
        return
    _add_unsupported_syntax(
        function,
        value,
        (
            "mutable collection values captured inside a container literal cannot be "
            "directly lowered when those values are later mutated"
        ),
        suggestion=(
            "Use .copy() explicitly for container items, avoid mutating the captured "
            "collection, or keep this function on Python fallback."
        ),
    )


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


def _return_type_name(node: ast.FunctionDef, function: FunctionAnalysis) -> str | None:
    if node.returns is not None and is_supported_type(node.returns):
        return annotation_name(node.returns)
    return function.inferred_return_type


def _infer_missing_signature_from_context(
    node: ast.FunctionDef,
    function: FunctionAnalysis,
) -> None:
    inferencer = _SignatureInferencer(node, function)
    inferencer.infer()


class _SignatureInferencer:
    def __init__(self, node: ast.FunctionDef, function: FunctionAnalysis) -> None:
        self.node = node
        self.function = function
        self.args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        self.arg_names = {arg.arg for arg in self.args}
        self.known: dict[str, str] = {}
        self.return_types: list[str] = []
        self.changed = False
        for arg in self.args:
            if arg.annotation is not None and is_supported_type(arg.annotation):
                self.known[arg.arg] = annotation_name(arg.annotation)
            elif arg.arg in function.inferred_arg_types:
                self.known[arg.arg] = function.inferred_arg_types[arg.arg]
        if function.inferred_return_type is not None:
            self.return_types.append(function.inferred_return_type)

    def infer(self) -> None:
        for _ in range(8):
            self.changed = False
            self.visit_statements(self.node.body)
            if not self.changed:
                break
        for arg in self.args:
            if (
                arg.annotation is None
                and arg.arg in self.known
                and _is_supported_signature_type(self.known[arg.arg])
            ):
                self.function.inferred_arg_types[arg.arg] = self.known[arg.arg]
        if self.node.returns is None and self.return_types:
            unique = set(self.return_types)
            if len(unique) == 1:
                return_type = self.return_types[0]
                if _is_supported_signature_type(return_type):
                    self.function.inferred_return_type = return_type

    def visit_statements(self, statements: list[ast.stmt]) -> None:
        for statement in statements:
            self.visit_statement(statement)

    def visit_statement(self, node: ast.stmt) -> None:
        if isinstance(node, ast.Assign):
            value_type = self.infer_expr(node.value)
            for target in node.targets:
                self.bind_target(target, value_type)
            return
        if isinstance(node, ast.AnnAssign):
            annotated = annotation_name(node.annotation) if is_supported_type(node.annotation) else None
            self.bind_target(node.target, annotated)
            if node.value is not None:
                self.infer_expr(node.value, annotated)
            return
        if isinstance(node, ast.AugAssign):
            target_type = self.infer_expr(node.target)
            value_type = self.infer_expr(node.value, target_type)
            if target_type is None:
                target_type = value_type
            self.bind_target(node.target, target_type)
            return
        if isinstance(node, ast.Expr):
            self.infer_expr(node.value)
            return
        if isinstance(node, ast.Return):
            value_type = "None" if node.value is None else self.infer_expr(node.value)
            if value_type is not None:
                self.return_types.append(value_type)
            return
        if isinstance(node, ast.If):
            self.infer_expr(node.test, "bool")
            self.visit_statements(node.body)
            self.visit_statements(node.orelse)
            return
        if isinstance(node, ast.While):
            self.infer_expr(node.test, "bool")
            self.visit_statements(node.body)
            self.visit_statements(node.orelse)
            return
        if isinstance(node, ast.For):
            iterable_type = self.infer_expr(node.iter)
            item_types = self.iterable_item_types(node.iter, iterable_type)
            self.bind_loop_target(node.target, item_types)
            before = dict(self.known)
            self.visit_statements(node.body)
            if isinstance(node.iter, ast.Name) and node.iter.id not in before:
                inferred_items = self.target_types(node.target)
                if len(inferred_items) == 1 and inferred_items[0] is not None:
                    self.add_type(node.iter.id, f"list[{inferred_items[0]}]")
            self.visit_statements(node.orelse)

    def infer_expr(self, node: ast.AST | None, expected: str | None = None) -> str | None:
        if node is None:
            return "None"
        if isinstance(node, ast.Constant):
            return self.constant_type(node)
        if isinstance(node, ast.Name):
            known = self.known.get(node.id)
            if known is None and expected is not None:
                self.add_type(node.id, expected)
                known = expected
            return known
        if isinstance(node, ast.List):
            item_types = [self.infer_expr(item) for item in node.elts]
            return self.homogeneous_collection_type("list", item_types, expected)
        if isinstance(node, ast.Set):
            item_types = [self.infer_expr(item) for item in node.elts]
            return self.homogeneous_collection_type("set", item_types, expected)
        if isinstance(node, ast.Tuple):
            item_types = [self.infer_expr(item) for item in node.elts]
            if all(item_type is not None for item_type in item_types):
                return f"tuple[{', '.join(item for item in item_types if item is not None)}]"
            return None
        if isinstance(node, ast.Dict):
            key_types = [self.infer_expr(key) for key in node.keys if key is not None]
            value_types = [self.infer_expr(value) for value in node.values]
            if not key_types and expected is not None and _is_dict_type(expected):
                return expected
            if len(set(key_types)) == 1 and len(set(value_types)) == 1:
                key_type = key_types[0]
                value_type = value_types[0]
                if key_type is not None and value_type is not None:
                    return f"dict[{key_type}, {value_type}]"
            return None
        if isinstance(node, ast.ListComp):
            return self.infer_list_comprehension(node)
        if isinstance(node, ast.DictComp):
            return self.infer_dict_comprehension(node)
        if isinstance(node, ast.SetComp):
            return self.infer_set_comprehension(node)
        if isinstance(node, ast.NamedExpr):
            value_type = self.infer_expr(node.value, expected)
            self.bind_target(node.target, value_type)
            return value_type
        if isinstance(node, ast.BinOp):
            return self.infer_binop(node, expected)
        if isinstance(node, ast.BoolOp):
            for value in node.values:
                self.infer_expr(value, "bool")
            return "bool"
        if isinstance(node, ast.UnaryOp):
            if isinstance(node.op, ast.Not):
                self.infer_expr(node.operand, "bool")
                return "bool"
            if isinstance(node.op, ast.USub):
                return self.infer_expr(node.operand, expected if expected in NUMERIC_TYPES else None)
            return None
        if isinstance(node, ast.Compare):
            self.infer_compare(node)
            return "bool"
        if isinstance(node, ast.Call):
            return self.infer_call(node, expected)
        if isinstance(node, ast.Subscript):
            return self.infer_subscript(node, expected)
        return None

    def infer_binop(self, node: ast.BinOp, expected: str | None) -> str | None:
        expected_numeric = expected if expected in NUMERIC_TYPES else None
        left = self.infer_expr(node.left, expected_numeric)
        right = self.infer_expr(node.right, expected_numeric or left)
        if left is None and right in NUMERIC_TYPES:
            left = self.infer_expr(node.left, right)
        if right is None and left in NUMERIC_TYPES:
            right = self.infer_expr(node.right, left)
        if left in NUMERIC_TYPES and left == right:
            return left
        return left if left in NUMERIC_TYPES and right is None else None

    def infer_compare(self, node: ast.Compare) -> None:
        left_type = self.infer_expr(node.left)
        for comparator in node.comparators:
            right_type = self.infer_expr(comparator, left_type)
            if left_type is None and right_type is not None:
                left_type = self.infer_expr(node.left, right_type)
            left_type = right_type or left_type

    def infer_call(self, node: ast.Call, expected: str | None) -> str | None:
        target = canonical_call_target(node, self.function.imports, self.function.logger_names)
        if target is None:
            target = dotted_name(node.func)
        if target == "print" or target in LOGGING_CANONICAL_TARGETS.values():
            for arg in node.args:
                self.infer_expr(arg)
            return "None"
        if target in DATETIME_ISOFORMAT_TARGETS:
            return "str"
        if target in DATETIME_TIMESTAMP_TARGETS or target in TIME_TARGETS:
            return "float"
        if target == "len":
            for arg in node.args:
                self.infer_expr(arg)
            return "int"
        if target in {"all", "any"} and node.args:
            self.infer_expr(node.args[0], "list[bool]")
            return "bool"
        if target == "sorted" and node.args:
            arg_type = self.infer_expr(node.args[0])
            return arg_type if _is_list_type(arg_type) else None
        if target == "reversed" and node.args:
            arg_type = self.infer_expr(node.args[0])
            return arg_type if _is_list_type(arg_type) else None
        if target == "range":
            for arg in node.args:
                self.infer_expr(arg, "int")
            return None
        if target in {"abs", "min", "max"}:
            seed = expected if expected in NUMERIC_TYPES else None
            arg_types = [self.infer_expr(arg, seed) for arg in node.args]
            known = next((arg_type for arg_type in arg_types if arg_type in NUMERIC_TYPES), None)
            if known is not None:
                for arg in node.args:
                    self.infer_expr(arg, known)
            return known
        if target == "sum" and node.args:
            item_type = expected if expected in NUMERIC_TYPES else None
            arg_type = self.infer_expr(node.args[0], f"list[{item_type}]" if item_type else None)
            return _list_item_type(arg_type)
        if target in {"math.sqrt", "math.sin", "math.cos"}:
            for arg in node.args:
                self.infer_expr(arg, "float")
            return "float"
        if target in MATH_FLOAT_UNARY_TARGETS:
            for arg in node.args:
                self.infer_expr(arg, "float")
            return "float"
        if target in MATH_FLOAT_BINARY_TARGETS:
            for arg in node.args:
                self.infer_expr(arg, "float")
            return "float"
        if target in MATH_FLOAT_TO_INT_TARGETS:
            for arg in node.args:
                self.infer_expr(arg, "float")
            return "int"
        if target in MATH_FLOAT_TO_BOOL_TARGETS:
            for arg in node.args:
                self.infer_expr(arg, "float")
            return "bool"
        if target in MATH_CONSTANT_TARGETS:
            return "float"
        if target in STR_METHOD_TARGETS:
            return self.infer_string_method(node, expected, target)
        if target in BYTES_METHOD_TARGETS:
            return self.infer_bytes_method(node, expected, target)
        if target in LIST_METHOD_TARGETS:
            return self.infer_list_method(node, expected, target)
        if target in STATISTICS_TARGETS and node.args:
            self.infer_expr(node.args[0])
            return "float"
        if target in HASHLIB_CHAIN_TARGETS:
            for chain_arg in _chained_call_args(node):
                self.infer_expr(chain_arg, "bytes")
            return "str"
        if target in BASE64_TARGETS and node.args:
            self.infer_expr(node.args[0], "bytes" if target.endswith("b64encode") else None)
            return "bytes"
        if target == "json.dumps" and node.args:
            self.infer_expr(node.args[0])
            return "str"
        if target == "json.loads" and node.args:
            self.infer_expr(node.args[0], "str")
            return expected if expected is not None and _is_json_supported_type(expected) else None
        for arg in node.args:
            self.infer_expr(arg)
        return None

    def infer_string_method(self, node: ast.Call, expected: str | None, target: str) -> str | None:
        receiver = _call_receiver(node)
        if receiver is not None:
            self.infer_expr(receiver, "str")
        if target in {"str.lower", "str.upper", "str.strip"}:
            return "str"
        if target == "str.encode":
            return "bytes"
        if target in {"str.startswith", "str.endswith"}:
            for arg in node.args:
                self.infer_expr(arg, "str")
            return "bool"
        if target == "str.replace":
            for arg in node.args:
                self.infer_expr(arg, "str")
            return "str"
        return None

    def infer_bytes_method(self, node: ast.Call, expected: str | None, target: str) -> str | None:
        receiver = _call_receiver(node)
        if receiver is not None:
            self.infer_expr(receiver, "bytes")
        if target == "bytes.decode":
            return "str"
        return None

    def infer_list_method(self, node: ast.Call, expected: str | None, target: str) -> str | None:
        receiver = _call_receiver(node)
        receiver_type = self.infer_expr(receiver) if receiver is not None else None
        item_type = _list_item_type(receiver_type)
        if target == "list.copy":
            return receiver_type
        if item_type is None:
            return None
        for arg in node.args:
            self.infer_expr(arg, item_type)
        if target == "list.count":
            return "int"
        if target == "list.index":
            return "int"
        return None

    def infer_subscript(self, node: ast.Subscript, expected: str | None) -> str | None:
        self.infer_expr(node.slice, "int")
        value_type = self.infer_expr(node.value)
        if value_type is None and expected is not None and isinstance(node.value, ast.Name):
            self.add_type(node.value.id, f"list[{expected}]")
            value_type = f"list[{expected}]"
        if _is_list_type(value_type):
            return _list_item_type(value_type)
        if _is_dict_type(value_type):
            return _dict_item_types(value_type)[1]
        return None

    def infer_list_comprehension(self, node: ast.ListComp) -> str | None:
        item_type = self.with_comprehension_generators(node.generators, lambda: self.infer_expr(node.elt))
        return f"list[{item_type}]" if item_type is not None else None

    def infer_dict_comprehension(self, node: ast.DictComp) -> str | None:
        def infer_items() -> tuple[str | None, str | None]:
            return self.infer_expr(node.key), self.infer_expr(node.value)

        key_type, value_type = self.with_comprehension_generators(node.generators, infer_items) or (None, None)
        if key_type is not None and value_type is not None:
            return f"dict[{key_type}, {value_type}]"
        return None

    def infer_set_comprehension(self, node: ast.SetComp) -> str | None:
        item_type = self.with_comprehension_generators(node.generators, lambda: self.infer_expr(node.elt))
        return f"set[{item_type}]" if item_type is not None else None

    def with_comprehension_generators(self, generators: list[ast.comprehension], callback):
        saved = dict(self.known)
        for generator in generators:
            iterable_type = self.infer_expr(generator.iter)
            item_types = self.iterable_item_types(generator.iter, iterable_type)
            self.bind_loop_target(generator.target, item_types)
            for condition in generator.ifs:
                self.infer_expr(condition, "bool")
        value = callback()
        for generator in reversed(generators):
            if isinstance(generator.iter, ast.Name) and generator.iter.id not in saved:
                inferred_items = self.target_types(generator.target)
                if len(inferred_items) == 1 and inferred_items[0] is not None:
                    self.add_type(generator.iter.id, f"list[{inferred_items[0]}]")
        return value

    def iterable_item_types(self, node: ast.AST, iterable_type: str | None) -> list[str]:
        if _is_list_type(iterable_type):
            item_type = _list_item_type(iterable_type)
            return [item_type] if item_type is not None else []
        if _is_set_type(iterable_type):
            item_type = _set_item_type(iterable_type)
            return [item_type] if item_type is not None else []
        if isinstance(node, ast.Call) and dotted_name(node.func) == "range":
            return ["int"]
        if isinstance(node, ast.Call) and dotted_name(node.func) == "enumerate" and node.args:
            item_type = _list_item_type(self.infer_expr(node.args[0]))
            return ["int", item_type] if item_type is not None else []
        if isinstance(node, ast.Call) and dotted_name(node.func) == "zip":
            item_types = [_list_item_type(self.infer_expr(arg)) for arg in node.args]
            return [item_type for item_type in item_types if item_type is not None]
        return []

    def target_types(self, target: ast.AST) -> list[str | None]:
        if isinstance(target, ast.Name):
            return [self.known.get(target.id)]
        if isinstance(target, ast.Tuple):
            return [self.known.get(item.id) if isinstance(item, ast.Name) else None for item in target.elts]
        return []

    def bind_loop_target(self, target: ast.AST, item_types: list[str]) -> None:
        if isinstance(target, ast.Name) and len(item_types) == 1:
            self.add_type(target.id, item_types[0])
        elif isinstance(target, ast.Tuple) and len(target.elts) == len(item_types):
            for item, item_type in zip(target.elts, item_types, strict=True):
                if isinstance(item, ast.Name):
                    self.add_type(item.id, item_type)

    def bind_target(self, target: ast.AST, value_type: str | None) -> None:
        if value_type is not None and isinstance(target, ast.Name):
            self.add_type(target.id, value_type)

    def add_type(self, name: str, value_type: str) -> None:
        if not _is_supported_signature_type(value_type):
            return
        current = self.known.get(name)
        if current is None:
            self.known[name] = value_type
            self.changed = True
        elif current == value_type:
            return

    def homogeneous_collection_type(
        self,
        kind: str,
        item_types: list[str | None],
        expected: str | None,
    ) -> str | None:
        if not item_types:
            if expected is not None and expected.startswith(f"{kind}["):
                return expected
            return None
        unique = set(item_types)
        if len(unique) == 1:
            item_type = item_types[0]
            return f"{kind}[{item_type}]" if item_type is not None else None
        return None

    @staticmethod
    def constant_type(node: ast.Constant) -> str | None:
        if isinstance(node.value, bool):
            return "bool"
        if isinstance(node.value, int):
            return "int"
        if isinstance(node.value, float):
            return "float"
        if isinstance(node.value, str):
            return "str"
        if isinstance(node.value, bytes):
            return "bytes"
        if node.value is None:
            return "None"
        return None


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
        if isinstance(node.value, bytes):
            return "bytes"
        if node.value is None:
            return "None"
        return None
    if isinstance(node, ast.Name):
        return env.get(node.id)
    if isinstance(node, ast.Attribute):
        target = canonical_attribute_target(node, function.imports)
        if target in MATH_CONSTANT_TARGETS:
            return "float"
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
                    f"boolean operations require bool operands in 0.1.0 alpha, got {value_type}",
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
            expected_type=expected_type,
            allow_named_expr=allow_named_expr,
            named_expr_binding_env=binding_env,
            active_comprehension_targets=active_targets,
        )
    if isinstance(node, ast.Subscript):
        value_type = infer_child(node.value)
        slice_type = infer_child(node.slice)
        if _is_list_type(value_type):
            # Python requires integer list indices; a float/str index is a
            # TypeError, not a silently truncated lookup.
            if (
                not isinstance(node.slice, ast.Slice)
                and slice_type is not None
                and slice_type not in {"int", "bool"}
            ):
                _add_unsupported_syntax(
                    function,
                    node,
                    f"list indexes must be int, got {slice_type}",
                )
                return None
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
    tuple_type = f"tuple[{', '.join(item for item in item_types if item is not None)}]"
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
    expected_type: str | None = None,
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

    target = canonical_call_target(node, function.imports, function.logger_names)
    if target is None:
        target = dotted_name(node.func)
    if target == "print":
        return _infer_effect_call_type("print", node, function, env)
    if target is not None and target in LOGGING_CANONICAL_TARGETS.values():
        return _infer_effect_call_type(target, node, function, env)
    if target in DATETIME_ISOFORMAT_TARGETS:
        if not _require_arg_count(target, node, function, {0}):
            return None
        return "str"
    if target in DATETIME_TIMESTAMP_TARGETS:
        if not _require_arg_count(target, node, function, {0}):
            return None
        return "float"
    if target in TIME_TARGETS:
        if not _require_arg_count(target, node, function, {0}):
            return None
        return "float"
    if target == "len":
        if not _require_arg_count("len", node, function, {1}):
            return None
        arg_type = infer_arg(node.args[0])
        if arg_type is not None and not _is_sized_type(arg_type):
            # `len(x)` on a scalar lowers to `x.len()`, which is not valid Rust
            # for i64/f64/bool and would fail the cargo build instead of falling
            # back. Reject so the function stays on the Python fallback path.
            _add_unsupported_syntax(
                function,
                node,
                f"len() requires a sized type (list/set/dict/tuple/str/bytes), got {arg_type}",
            )
            return None
        return "int"
    if target in {"all", "any"}:
        if not _require_arg_count(target, node, function, {1}):
            return None
        arg_type = infer_arg(node.args[0])
        if arg_type == "list[bool]":
            return "bool"
        _add_unsupported_syntax(function, node, f"{target} requires list[bool], got {arg_type}")
        return None
    if target == "sorted":
        if not _require_arg_count("sorted", node, function, {1}):
            return None
        arg_type = infer_arg(node.args[0])
        item_type = _list_item_type(arg_type)
        if item_type in {"int", "float", "bool", "str"}:
            return arg_type
        _add_unsupported_syntax(function, node, f"sorted requires list[int|float|bool|str], got {arg_type}")
        return None
    if target == "reversed":
        if not _require_arg_count("reversed", node, function, {1}):
            return None
        arg_type = infer_arg(node.args[0])
        if _list_item_type(arg_type) is not None:
            return arg_type
        _add_unsupported_syntax(function, node, f"reversed requires a supported list, got {arg_type}")
        return None
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
    if target == "math.log":
        if not _require_arg_count(target, node, function, {1, 2}):
            return None
        arg_types = [infer_arg(arg) for arg in node.args]
        if all(arg_type == "float" for arg_type in arg_types):
            return "float"
        _add_unsupported_syntax(function, node, "math.log requires float argument(s)")
        return None
    if target in MATH_FLOAT_UNARY_TARGETS:
        if not _require_arg_count(target, node, function, {1}):
            return None
        arg_type = infer_arg(node.args[0])
        if arg_type == "float":
            return "float"
        _add_unsupported_syntax(function, node, f"{target} requires a float argument")
        return None
    if target in MATH_FLOAT_BINARY_TARGETS:
        if not _require_arg_count(target, node, function, {2}):
            return None
        arg_types = [infer_arg(arg) for arg in node.args]
        if arg_types == ["float", "float"]:
            return "float"
        _add_unsupported_syntax(function, node, f"{target} requires two float arguments")
        return None
    if target in MATH_FLOAT_TO_INT_TARGETS:
        if not _require_arg_count(target, node, function, {1}):
            return None
        arg_type = infer_arg(node.args[0])
        if arg_type == "float":
            return "int"
        _add_unsupported_syntax(function, node, f"{target} requires a float argument")
        return None
    if target in MATH_FLOAT_TO_BOOL_TARGETS:
        if not _require_arg_count(target, node, function, {1}):
            return None
        arg_type = infer_arg(node.args[0])
        if arg_type == "float":
            return "bool"
        _add_unsupported_syntax(function, node, f"{target} requires a float argument")
        return None
    if target in MATH_CONSTANT_TARGETS:
        return "float"
    if target in STR_METHOD_TARGETS:
        return _infer_str_method_type(target, node, function, env)
    if target in BYTES_METHOD_TARGETS:
        return _infer_bytes_method_type(target, node, function, env)
    if target in LIST_METHOD_TARGETS:
        return _infer_list_method_type(target, node, function, env)
    if target in STATISTICS_TARGETS:
        if not _require_arg_count(target, node, function, {1}):
            return None
        arg_type = infer_arg(node.args[0])
        item_type = _list_item_type(arg_type)
        if item_type in NUMERIC_TYPES:
            return "float"
        _add_unsupported_syntax(function, node, f"{target} requires list[int] or list[float], got {arg_type}")
        return None
    if target in HASHLIB_CHAIN_TARGETS:
        inner_args = _chained_call_args(node)
        if len(inner_args) != 1:
            _add_unsupported_syntax(function, node, f"{target} requires exactly one bytes argument")
            return None
        arg_type = _infer_expr_type(inner_args[0], function, env)
        if arg_type == "bytes":
            return "str"
        _add_unsupported_syntax(function, node, f"{target} requires bytes, got {arg_type}")
        return None
    if target in BASE64_TARGETS:
        if not _require_arg_count(target, node, function, {1}):
            return None
        arg_type = infer_arg(node.args[0])
        if target == "base64.b64encode" and arg_type == "bytes":
            return "bytes"
        if target == "base64.b64decode" and arg_type in {"bytes", "str"}:
            return "bytes"
        _add_unsupported_syntax(function, node, f"{target} requires bytes input" if target.endswith("b64encode") else f"{target} requires bytes or str input")
        return None
    if target in JSON_TARGETS:
        if not _require_arg_count(target, node, function, {1}):
            return None
        if target == "json.dumps":
            arg_type = infer_arg(node.args[0])
            if _is_json_supported_type(arg_type):
                return "str"
            _add_unsupported_syntax(function, node, f"json.dumps argument type is not supported: {arg_type}")
            return None
        arg_type = infer_arg(node.args[0])
        if arg_type != "str":
            _add_unsupported_syntax(function, node, f"json.loads requires str input, got {arg_type}")
            return None
        if expected_type is not None and _is_json_supported_type(expected_type):
            return expected_type
        _add_unsupported_syntax(function, node, "json.loads requires an expected supported target type")
        return None
    if _is_append_call(node):
        return _infer_append_call_type(node, function, env)
    return None


def _infer_effect_call_type(
    target: str,
    node: ast.Call,
    function: FunctionAnalysis,
    env: dict[str, str],
) -> str | None:
    if node.keywords:
        return None
    if target != "print" and len(node.args) < 1:
        _add_unsupported_syntax(function, node, f"{target} requires at least one positional argument")
        return None
    for arg in node.args:
        _infer_expr_type(arg, function, env)
    return "None"


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


def _infer_str_method_type(
    target: str,
    node: ast.Call,
    function: FunctionAnalysis,
    env: dict[str, str],
) -> str | None:
    receiver = _call_receiver(node)
    receiver_type = _infer_expr_type(receiver, function, env) if receiver is not None else None
    if receiver_type != "str":
        _add_unsupported_syntax(function, node, f"{target} receiver must be str, got {receiver_type}")
        return None
    if target in {"str.lower", "str.upper", "str.strip", "str.encode"}:
        if not _require_arg_count(target, node, function, {0}):
            return None
        return "bytes" if target == "str.encode" else "str"
    if target in {"str.startswith", "str.endswith"}:
        if not _require_arg_count(target, node, function, {1}):
            return None
        arg_type = _infer_expr_type(node.args[0], function, env)
        if arg_type == "str":
            return "bool"
        _add_unsupported_syntax(function, node.args[0], f"{target} requires a str prefix/suffix")
        return None
    if target == "str.replace":
        if not _require_arg_count(target, node, function, {2}):
            return None
        arg_types = [_infer_expr_type(arg, function, env) for arg in node.args]
        if arg_types == ["str", "str"]:
            return "str"
        _add_unsupported_syntax(function, node, "str.replace requires two str arguments")
    return None


def _infer_bytes_method_type(
    target: str,
    node: ast.Call,
    function: FunctionAnalysis,
    env: dict[str, str],
) -> str | None:
    receiver = _call_receiver(node)
    receiver_type = _infer_expr_type(receiver, function, env) if receiver is not None else None
    if receiver_type != "bytes":
        _add_unsupported_syntax(function, node, f"{target} receiver must be bytes, got {receiver_type}")
        return None
    if target == "bytes.decode":
        if not _require_arg_count(target, node, function, {0}):
            return None
        return "str"
    return None


def _infer_list_method_type(
    target: str,
    node: ast.Call,
    function: FunctionAnalysis,
    env: dict[str, str],
) -> str | None:
    receiver = _call_receiver(node)
    receiver_type = _infer_expr_type(receiver, function, env) if receiver is not None else None
    item_type = _list_item_type(receiver_type)
    if item_type is None:
        _add_unsupported_syntax(function, node, f"{target} receiver must be a supported list, got {receiver_type}")
        return None
    if target == "list.copy":
        if not _require_arg_count(target, node, function, {0}):
            return None
        return receiver_type
    if target in {"list.count", "list.index"}:
        if not _require_arg_count(target, node, function, {1}):
            return None
        arg_type = _infer_expr_type(node.args[0], function, env)
        if arg_type == item_type:
            return "int"
        _add_unsupported_syntax(function, node.args[0], f"{target} argument must be {item_type}, got {arg_type}")
        return None
    return None


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
            "int division is not supported in 0.1.0 alpha native functions",
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
                f"not operator requires bool in 0.1.0 alpha native functions, got {value_type}",
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


def _is_sized_type(type_name: str) -> bool:
    """Report whether a type supports ``len()`` (maps to Rust ``.len()``)."""
    return type_name in {"str", "bytes"} or type_name.startswith(
        ("list[", "set[", "dict[", "tuple[")
    )


def _is_none_literal(node: ast.AST) -> bool:
    """Report whether an expression node is the ``None`` literal."""
    return (isinstance(node, ast.Constant) and node.value is None) or (
        isinstance(node, ast.Name) and node.id == "None"
    )


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
    left_node = node.left
    for op, comparator in zip(node.ops, node.comparators, strict=True):
        right_type = infer_side(comparator)
        if isinstance(op, (ast.Is, ast.IsNot)) and not (
            _is_none_literal(left_node) or _is_none_literal(comparator)
        ):
            # `is`/`is not` lower to Rust `==`/`!=`, which is only faithful to
            # Python identity semantics when one side is `None`. For arbitrary
            # values (e.g. `a is b` on two strings) `==` is value equality, so
            # reject and keep the function on the Python fallback path.
            _add_unsupported_syntax(
                function,
                node,
                "'is'/'is not' is supported only against None in native functions",
            )
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
        left_node = comparator


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
    if assigned_type is not None and value_type is not None and not _types_assignable(assigned_type, value_type):
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
                "range step must be a positive int literal in 0.1.0 alpha native functions",
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


def _validate_call(function: FunctionAnalysis, node: ast.Call) -> None:
    if node.keywords:
        _add_unsupported_syntax(function, node, "keyword call arguments are not supported")

    target = canonical_call_target(node, function.imports, function.logger_names)
    if target is None:
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
        return "comprehensions are not supported in 0.1.0 alpha native functions"
    if isinstance(node, ast.Set):
        return "set literals are not supported in 0.1.0 alpha native functions"
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return "imports inside native functions are not supported"
    if isinstance(node, (ast.With, ast.AsyncWith)):
        return "context managers are not supported in native functions"
    if isinstance(node, ast.TryStar):
        return "except* (exception groups) is not supported in native functions"
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


def _add_unsupported_syntax(
    function: FunctionAnalysis,
    node: ast.AST | FunctionAnalysis,
    message: str,
    suggestion: str = "Keep native candidates inside the supported 0.1.0 alpha subset.",
) -> None:
    function.add_diagnostic(
        Diagnostic(
            code="RXT010",
            severity="error",
            message=message,
            file_path=function.file_path,
            line=getattr(node, "lineno", function.line),
            column=getattr(node, "col_offset", function.column),
            function_name=function.qualname,
            suggestion=suggestion,
        )
    )
