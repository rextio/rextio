"""Eligibility check for the experimental scalar-helper native embedding.

With `[embedding] enabled`, an unmarked typed scalar helper is embedded as an
ordinary internal native function, compiled ahead of time. Embedded int
arithmetic goes through the normal checked lowering, so overflow raises
OverflowError like any other native function.
"""

from __future__ import annotations

import ast

from rextio.analyzer.models import FunctionAnalysis
from rextio.analyzer.type_collector import annotation_name
from rextio.capabilities import NUMERIC_TYPES

# The experimental scalar embedding currently supports exactly the numeric scalars.
EMBEDDING_SCALAR_TYPES = NUMERIC_TYPES


def is_embedding_candidate(
    node: ast.FunctionDef,
    function: FunctionAnalysis,
) -> tuple[bool, str]:
    """Report whether a typed scalar function is eligible for native embedding, with a reason."""
    if function.error_diagnostics:
        return False, "native subset validation failed"
    signature_types = _signature_types(node, function)
    if signature_types is None:
        return False, "embedding candidates require resolved scalar annotations"
    arg_types, return_type = signature_types
    if return_type not in EMBEDDING_SCALAR_TYPES:
        return False, "embedding candidates currently require int or float return types"
    if any(arg_type not in EMBEDDING_SCALAR_TYPES for arg_type in arg_types.values()):
        return False, "embedding candidates currently require int or float arguments"
    if any(arg_type != return_type for arg_type in arg_types.values()):
        return False, "embedding candidates currently require arguments to match the return type"
    if (
        len(node.body) != 1
        or not isinstance(node.body[0], ast.Return)
        or node.body[0].value is None
    ):
        return False, "embedding candidates currently require a single return expression"
    if not _is_supported_expr(node.body[0].value, set(arg_types), return_type):
        return False, "embedding candidates currently support only scalar arithmetic expressions"
    # This exact wording is asserted by tests and surfaces in reports as
    # embedding_reason - change it deliberately, not in passing.
    return True, "typed scalar helper can be embedded as an internal native function"


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
    return_type: str | None
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
        # Embedded helpers lower through the ordinary checked native path, so the
        # full checked operator set is safe: int overflow raises OverflowError,
        # `%` handles floored semantics and division-by-zero, and float `/`
        # raises ZeroDivisionError.
        if return_type == "int" and not isinstance(node.op, (ast.Add, ast.Sub, ast.Mult, ast.Mod)):
            return False
        if return_type == "float" and not isinstance(
            node.op, (ast.Add, ast.Sub, ast.Mult, ast.Div)
        ):
            return False
        return _is_supported_expr(node.left, names, return_type) and _is_supported_expr(
            node.right, names, return_type
        )
    return False
