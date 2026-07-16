"""Shared defensive proof for executable native definitions.

The analyzer normally establishes these facts before a function reaches IR or
wrapper planning.  Those later stages still consume mutable analysis records and
re-read source files, however, so they must fail closed when handed a malformed
accepted list or when the source changed after analysis.  This module deliberately
uses the same :class:`ModuleBindings` authority as analysis instead of trusting raw
decorator spelling or deriving a second import table.
"""

from __future__ import annotations

import ast

from rextio.analyzer.final_bindings import (
    BindingKind,
    ModuleBindings,
    ProjectMutations,
    marker_decorator_is_proven,
)
from rextio.analyzer.native_marker import parse_native_marker_shape


def executable_ast_fingerprint(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> str:
    """Return a deterministic semantic identity for an analyzed function AST."""
    return ast.dump(node, annotate_fields=True, include_attributes=False)


def native_marker_identity_reason(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    bindings: ModuleBindings,
    *,
    explicitly_marked: bool,
) -> str | None:
    """Return why ``node`` cannot be trusted as the accepted native definition.

    Every decorator on an explicitly marked accepted function must be the exact
    real ``rextio.native`` binding at its execution site.  This rejects a real
    marker mixed with a fake/native-looking wrapper; the wrapper can change the
    runtime function even though one decorator in the list is genuine.  An
    auto-discovered accepted function must be undecorated for the same reason.
    """
    if not node.decorator_list:
        return None if not explicitly_marked else "the explicit native marker is missing"

    if not explicitly_marked:
        return "an auto-discovered accepted function carries a decorator"

    for decorator in node.decorator_list:
        if not marker_decorator_is_proven(decorator, bindings, "native"):
            return "a decorator does not have proven native marker identity"
        marker = parse_native_marker_shape(decorator)
        if not marker.valid:
            return marker.error or "the native marker shape is invalid"
    return None


def class_construction_stability_reason(
    node: ast.ClassDef,
    bindings: ModuleBindings,
    *,
    project_mutations: ProjectMutations,
) -> str | None:
    """Return why the runtime class/member identity is not statically proven.

    The supported native-method surface is intentionally limited to a plain class
    with no construction hooks.  An explicit ``object`` base is accepted only when
    ``object`` is the unshadowed builtin, not merely because its source spelling is
    ``object``.
    """
    if project_mutations.target_is_mutated("builtins.__build_class__"):
        return "the builtin class-construction hook was mutated during module execution"
    if node.decorator_list:
        return "the enclosing class has a class decorator"
    for base in node.bases:
        if not isinstance(base, ast.Name) or base.id != "object":
            return "the enclosing class has an unproven base class"
        if bindings.lookup("object").kind is not BindingKind.UNBOUND:
            return "the explicit object base is not the proven builtin"
    if node.keywords:
        return "the enclosing class has a metaclass or class keyword"
    if _has_unproven_descriptor_binding(node.body):
        return "the class body contains a value with unproven __set_name__ behavior"
    if (node.lineno, node.col_offset) in bindings.unstable_class_sites:
        return "the class body or construction has an unproven effect or descriptor hook"
    return None


def _has_unproven_descriptor_binding(statements: list[ast.stmt]) -> bool:
    """Whether class construction may invoke an arbitrary ``__set_name__`` hook.

    CPython calls ``value.__set_name__(owner, name)`` for every descriptor left
    in the completed class namespace.  A bare name/attribute/subscript/lambda or
    container assembled from such values may therefore replace/delete a native
    method *after* its syntactic definition.  Accept only class assignments whose
    values are closed immutable literals; calls and control-flow effects are
    already rejected by the execution scanner, but this structural gate covers
    call-free descriptor aliases such as ``trigger = descriptor``.
    """
    for statement in statements:
        if _has_unproven_class_walrus(statement):
            return True
        if isinstance(statement, ast.Assign):
            if not _is_descriptor_safe_value(statement.value):
                return True
        elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
            if not _is_descriptor_safe_value(statement.value):
                return True
        elif isinstance(statement, ast.AugAssign):
            return True
        elif isinstance(statement, ast.ImportFrom):
            # A from-import may bind an arbitrary exported object directly.
            return True
        elif isinstance(statement, ast.Import):
            continue
        elif isinstance(statement, (ast.For, ast.AsyncFor)):
            if not _iteration_value_is_descriptor_safe(statement.iter):
                return True
            if _has_unproven_descriptor_binding(statement.body) or _has_unproven_descriptor_binding(
                statement.orelse
            ):
                return True
        elif isinstance(statement, (ast.With, ast.AsyncWith)):
            if any(item.optional_vars is not None for item in statement.items):
                return True
            if _has_unproven_descriptor_binding(statement.body):
                return True
        elif isinstance(statement, (ast.If, ast.While)):
            if _has_unproven_descriptor_binding(statement.body) or _has_unproven_descriptor_binding(
                statement.orelse
            ):
                return True
        elif isinstance(statement, (ast.Try, ast.TryStar)):
            bodies = [
                statement.body,
                statement.orelse,
                statement.finalbody,
                *(handler.body for handler in statement.handlers),
            ]
            if any(_has_unproven_descriptor_binding(body) for body in bodies):
                return True
        elif isinstance(statement, ast.Match):
            if any(
                isinstance(name, str)
                for case in statement.cases
                for pattern in ast.walk(case.pattern)
                for name in (getattr(pattern, "name", None), getattr(pattern, "rest", None))
            ):
                return True
            if any(_has_unproven_descriptor_binding(case.body) for case in statement.cases):
                return True
    return False


def _has_unproven_class_walrus(node: ast.AST) -> bool:
    """Find class-scope walrus binders without descending into deferred bodies."""
    if isinstance(node, ast.NamedExpr):
        return not _is_descriptor_safe_value(node.value)
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        expressions: list[ast.AST] = [*node.decorator_list, *node.args.defaults]
        expressions.extend(default for default in node.args.kw_defaults if default is not None)
        expressions.extend(
            argument.annotation
            for argument in (
                *node.args.posonlyargs,
                *node.args.args,
                *node.args.kwonlyargs,
                *((node.args.vararg,) if node.args.vararg else ()),
                *((node.args.kwarg,) if node.args.kwarg else ()),
            )
            if argument.annotation is not None
        )
        if node.returns is not None:
            expressions.append(node.returns)
        return any(_has_unproven_class_walrus(expression) for expression in expressions)
    if isinstance(node, ast.ClassDef):
        expressions = [*node.decorator_list, *node.bases]
        expressions.extend(keyword.value for keyword in node.keywords)
        return any(_has_unproven_class_walrus(expression) for expression in expressions)
    if isinstance(node, ast.Lambda):
        return any(
            _has_unproven_class_walrus(default)
            for default in (*node.args.defaults, *node.args.kw_defaults)
            if default is not None
        )
    return any(_has_unproven_class_walrus(child) for child in ast.iter_child_nodes(node))


def _is_descriptor_safe_value(node: ast.expr) -> bool:
    """Whether a class namespace value has a proven-safe runtime type."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        # The namespace value is the builtin container itself; its elements are
        # not individually offered to the class ``__set_name__`` loop.
        return True
    if isinstance(node, ast.Dict):
        return True
    if isinstance(
        node,
        (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp),
    ):
        return True
    if isinstance(node, ast.Call):
        target = _dotted_name(node.func)
        return target in {
            "staticmethod",
            "classmethod",
            "property",
            "functools.cached_property",
        }
    return False


def _iteration_value_is_descriptor_safe(node: ast.expr) -> bool:
    if isinstance(node, ast.Call) and _dotted_name(node.func) == "range":
        return True
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(_is_descriptor_safe_value(element) for element in node.elts)
    if isinstance(node, ast.Dict):
        return all(key is not None and _is_descriptor_safe_value(key) for key in node.keys)
    return False


def _dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base is not None else None
    return None
