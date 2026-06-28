from __future__ import annotations

import ast

from rextio.analyzer.models import FunctionAnalysis
from rextio.analyzer.type_collector import annotation_name

JIT_SCALAR_TYPES = {"int", "float"}


def is_cranelift_jit_candidate(
    node: ast.FunctionDef,
    function: FunctionAnalysis,
) -> tuple[bool, str]:
    if function.error_diagnostics:
        return False, "native subset validation failed"
    signature_types = _signature_types(node, function)
    if signature_types is None:
        return False, "JIT candidates require resolved scalar annotations"
    arg_types, return_type = signature_types
    if return_type not in JIT_SCALAR_TYPES:
        return False, "JIT candidates currently require int or float return types"
    if any(arg_type not in JIT_SCALAR_TYPES for arg_type in arg_types.values()):
        return False, "JIT candidates currently require int or float arguments"
    if any(arg_type != return_type for arg_type in arg_types.values()):
        return False, "JIT candidates currently require arguments to match the return type"
    if len(node.body) != 1 or not isinstance(node.body[0], ast.Return) or node.body[0].value is None:
        return False, "JIT candidates currently require a single return expression"
    if not _is_supported_expr(node.body[0].value, set(arg_types), return_type):
        return False, "JIT candidates currently support only scalar arithmetic expressions"
    if return_type == "int" and _has_overflow_prone_int_arithmetic(node.body[0].value):
        # The Cranelift path lowers i64 `+`/`-`/`*` to wrapping `iadd`/`isub`/`imul`
        # and cannot raise `OverflowError`, so it would silently wrap where the
        # regular native path now raises (Python ints are arbitrary precision).
        # Keep such functions on the checked native path instead of JIT-compiling.
        return False, (
            "integer JIT disabled for overflow-prone arithmetic: the Cranelift "
            "path cannot raise OverflowError, so the helper stays on the checked "
            "native path"
        )
    return True, "typed scalar helper can be compiled by the experimental Cranelift JIT"


def _has_overflow_prone_int_arithmetic(node: ast.AST) -> bool:
    """True if the expression contains i64 arithmetic that can overflow.

    Addition, subtraction, multiplication and unary negation on a fixed-width
    i64 can overflow; the experimental Cranelift JIT lowers them to wrapping
    instructions, so any such node disqualifies an ``int`` helper from JIT.
    """
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub, ast.Mult)):
        return True
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        return True
    return any(_has_overflow_prone_int_arithmetic(child) for child in ast.iter_child_nodes(node))


def _signature_types(
    node: ast.FunctionDef,
    function: FunctionAnalysis,
) -> tuple[dict[str, str], str] | None:
    arg_types: dict[str, str] = {}
    args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
    for arg in args:
        if arg.annotation is not None:
            arg_types[arg.arg] = annotation_name(arg.annotation)
        elif arg.arg in function.inferred_arg_types:
            arg_types[arg.arg] = function.inferred_arg_types[arg.arg]
        else:
            return None
    if node.returns is not None:
        return_type = annotation_name(node.returns)
    else:
        return_type = function.inferred_return_type
    if return_type is None:
        return None
    return arg_types, return_type


def _is_supported_expr(node: ast.AST, names: set[str], return_type: str) -> bool:
    if isinstance(node, ast.Name):
        return node.id in names
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool):
            return False
        if return_type == "int":
            return isinstance(node.value, int)
        if return_type == "float":
            return isinstance(node.value, (int, float))
        return False
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        return _is_supported_expr(node.operand, names, return_type)
    if isinstance(node, ast.BinOp):
        if return_type == "int" and not isinstance(node.op, (ast.Add, ast.Sub, ast.Mult)):
            return False
        if return_type == "float" and not isinstance(node.op, (ast.Add, ast.Sub, ast.Mult, ast.Div)):
            return False
        return (
            _is_supported_expr(node.left, names, return_type)
            and _is_supported_expr(node.right, names, return_type)
        )
    return False
