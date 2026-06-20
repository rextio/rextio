from __future__ import annotations

import ast

from rextio.analyzer.diagnostics import Diagnostic
from rextio.analyzer.models import FunctionAnalysis
from rextio.analyzer.native_marker import dotted_name, is_native_decorator
from rextio.analyzer.type_collector import annotation_name, is_supported_type

DYNAMIC_FEATURES = {"getattr", "setattr", "hasattr", "globals", "locals", "eval", "exec", "__import__"}

UNSUPPORTED_SYNTAX: tuple[type[ast.AST], ...] = (
    ast.AsyncFunctionDef,
    ast.ClassDef,
    ast.Lambda,
    ast.ListComp,
    ast.DictComp,
    ast.SetComp,
    ast.GeneratorExp,
    ast.Await,
    ast.Yield,
    ast.YieldFrom,
    ast.Break,
    ast.Continue,
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
    for child in ast.walk(node):
        if child is node:
            continue
        if isinstance(child, ast.FunctionDef):
            _add_unsupported_syntax(function, child, "nested functions are not supported")
            continue
        if isinstance(child, UNSUPPORTED_SYNTAX):
            _add_unsupported_syntax(function, child, _unsupported_message(child))
            continue
        if isinstance(child, ast.Call):
            target = dotted_name(child.func)
            if target in DYNAMIC_FEATURES:
                function.add_diagnostic(
                    Diagnostic(
                        code="RXT020",
                        severity="error",
                        message=f"dynamic Python feature is not supported: {target}",
                        file_path=function.file_path,
                        line=child.lineno,
                        column=child.col_offset,
                        function_name=function.qualname,
                        suggestion="Remove the dynamic call from the native candidate or let it run as fallback.",
                    )
                )


def _unsupported_message(node: ast.AST) -> str:
    if isinstance(node, (ast.ListComp, ast.DictComp, ast.SetComp, ast.GeneratorExp)):
        return "comprehensions are not supported in Public 1 native functions"
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return "imports inside native functions are not supported"
    if isinstance(node, (ast.With, ast.AsyncWith)):
        return "context managers are not supported in native functions"
    if isinstance(node, ast.Try):
        return "exception handling is not supported in native functions"
    if isinstance(node, (ast.Break, ast.Continue)):
        return "break and continue are not supported in Public 1 native functions"
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
