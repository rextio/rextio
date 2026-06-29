from __future__ import annotations

import ast

from rextio.analyzer.boundary import SUPPORTED_INTERNAL_CALLS, _external_call_diagnostic_text
from rextio.analyzer.common_calls import canonical_call_target
from rextio.analyzer.diagnostics import Diagnostic
from rextio.analyzer.import_policy import decision_for_target
from rextio.analyzer.models import FunctionAnalysis, ModuleAnalysis, TopLevelAnalysis
from rextio.analyzer.native_marker import dotted_name
from rextio.analyzer.unsupported_patterns import (
    UNSUPPORTED_SYNTAX,
    _add_identifier_diagnostic,
    _add_unsupported_syntax,
    _is_append_call,
    _is_supported_signature_type,
    _misused_underscore_node,
    _unsupported_message,
    _validate_call,
    _validate_statement_types,
)
from rextio.codegen.rust.keywords import RUST_RAW_INCOMPATIBLE

TOP_LEVEL_NATIVE_NAME = "__rextio_top_level__"


def top_level_qualname(module_name: str) -> str:
    if module_name:
        return f"{module_name}.{TOP_LEVEL_NATIVE_NAME}"
    return TOP_LEVEL_NATIVE_NAME


def collect_native_top_level_statements(tree: ast.Module) -> list[ast.stmt]:
    statements: list[ast.stmt] = []
    for index, statement in enumerate(tree.body):
        if _is_module_metadata_statement(index, statement):
            continue
        if isinstance(
            statement,
            (
                ast.Import,
                ast.ImportFrom,
                ast.FunctionDef,
                ast.AsyncFunctionDef,
                ast.ClassDef,
            ),
        ):
            continue
        statements.append(statement)
    return statements


def analyze_native_top_level(tree: ast.Module, module: ModuleAnalysis) -> TopLevelAnalysis | None:
    statements = collect_native_top_level_statements(tree)
    if not statements:
        return None

    first = statements[0]
    top_level = TopLevelAnalysis(
        name=TOP_LEVEL_NATIVE_NAME,
        qualname=top_level_qualname(module.module_name),
        module_name=module.module_name,
        file_path=module.file_path,
        line=getattr(first, "lineno", None),
        column=getattr(first, "col_offset", None),
        is_native_candidate=True,
    )
    validator = FunctionAnalysis(
        name=TOP_LEVEL_NATIVE_NAME,
        qualname=top_level.qualname,
        module_name=module.module_name,
        file_path=module.file_path,
        line=top_level.line or 1,
        column=top_level.column or 0,
        is_native_candidate=True,
        imports=dict(module.imports),
        logger_names=module.logger_names,
    )
    validator_module = ModuleAnalysis(
        module_name=module.module_name,
        file_path=module.file_path,
        imports=dict(module.imports),
        import_policies=module.import_policies,
    )
    env: dict[str, str] = {}
    assigned_names: set[str] = set()
    for statement in statements:
        _validate_top_level_statement(statement, validator, validator_module, env, assigned_names)
    _validate_top_level_identifiers(statements, validator)

    for diagnostic in validator.diagnostics:
        top_level.add_diagnostic(diagnostic)

    top_level.assigned_types = {
        name: env[name]
        for name in sorted(assigned_names)
        if name in env and _is_supported_signature_type(env[name])
    }
    _validate_exports(top_level, assigned_names)
    top_level.accepted = not top_level.error_diagnostics
    return top_level


def _validate_top_level_statement(
    statement: ast.stmt,
    validator: FunctionAnalysis,
    module: ModuleAnalysis,
    env: dict[str, str],
    assigned_names: set[str],
) -> None:
    if isinstance(statement, ast.For):
        _add_top_level_error(
            validator,
            statement,
            "top-level for loops are not supported for native module initialization",
            "Move the loop into a native function or use a supported comprehension assignment.",
        )
        return

    if isinstance(statement, (ast.If, ast.While)):
        new_names = _new_assignment_names(statement, set(env))
        if new_names:
            _add_top_level_error(
                validator,
                statement,
                (
                    "top-level control-flow blocks may only update variables "
                    f"assigned before the block: {', '.join(sorted(new_names))}"
                ),
                "Assign an initial value before the if/while block or keep this module top level on fallback.",
            )
            return

    before = dict(env)
    _validate_statement_types(statement, validator, env, return_type=None)
    assigned_names.update(_assigned_name_targets(statement))
    _validate_top_level_ast(statement, validator)
    _reject_unsupported_top_level_calls(statement, validator, module)
    if isinstance(statement, (ast.If, ast.While)):
        env.update({name: before[name] for name in before if name not in env})


def _validate_top_level_identifiers(
    statements: list[ast.stmt],
    validator: FunctionAnalysis,
) -> None:
    """Reject top-level module names that cannot be lowered to a Rust identifier.

    Top-level assignments are emitted through the same renderer (which escapes
    raw-able keywords as `r#name`), so the unrepresentable cases mirror those of a
    function body: non-raw-able keywords, non-ASCII names, and a value-used `_`.
    """
    module_node = ast.Module(body=list(statements), type_ignores=[])
    misused_underscore = _misused_underscore_node(module_node)
    if misused_underscore is not None:
        _add_identifier_diagnostic(
            validator,
            misused_underscore,
            "'_' is a Rust discard pattern and cannot be assigned to or read",
            "Use a named module variable instead of '_'.",
        )
    seen: set[str] = set()
    for child in ast.walk(module_node):
        if not (isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store)):
            continue
        name = child.id
        if name in seen:
            continue
        seen.add(name)
        if name == "_":
            continue
        if name in RUST_RAW_INCOMPATIBLE:
            _add_identifier_diagnostic(
                validator,
                child,
                f"identifier '{name}' is a Rust keyword that cannot be carried as a raw identifier",
                f"Rename the module variable '{name}' or keep this module top level on Python fallback.",
            )
        elif not (name.isascii() and name.isidentifier()):
            _add_identifier_diagnostic(
                validator,
                child,
                f"identifier '{name}' uses non-ASCII characters not supported in generated Rust",
                f"Use an ASCII name for '{name}' or keep this module top level on Python fallback.",
            )


def _validate_top_level_ast(statement: ast.stmt, validator: FunctionAnalysis) -> None:
    for child in ast.walk(statement):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _add_unsupported_syntax(validator, child, "nested functions are not supported")
            continue
        if isinstance(child, UNSUPPORTED_SYNTAX):
            _add_unsupported_syntax(validator, child, _unsupported_message(child))
            continue
        if isinstance(child, ast.Call):
            _validate_call(validator, child)


def _reject_unsupported_top_level_calls(
    statement: ast.stmt,
    validator: FunctionAnalysis,
    module: ModuleAnalysis,
) -> None:
    for node in ast.walk(statement):
        if not isinstance(node, ast.Call):
            continue
        target = canonical_call_target(node, validator.imports, validator.logger_names)
        if target is None:
            target = dotted_name(node.func)
        if target in SUPPORTED_INTERNAL_CALLS or _is_append_call(node):
            continue
        decision = decision_for_target(module, target or "")
        message, suggestion = _external_call_diagnostic_text(target or "<dynamic>", False, decision)
        _add_top_level_error(
            validator,
            node,
            f"top-level native initialization cannot lower call: {message}",
            suggestion,
            code="RXT030",
        )


def _validate_exports(top_level: TopLevelAnalysis, assigned_names: set[str]) -> None:
    if not assigned_names:
        _add_top_level_analysis_error(
            top_level,
            "top-level native initialization requires at least one assigned module variable",
        )
        return
    missing = sorted(name for name in assigned_names if name not in top_level.assigned_types)
    if missing:
        _add_top_level_analysis_error(
            top_level,
            f"top-level assigned variables have unresolved or unsupported types: {', '.join(missing)}",
        )
        return
    value_types = set(top_level.assigned_types.values())
    if len(value_types) != 1:
        _add_top_level_analysis_error(
            top_level,
            (
                "top-level native initialization currently requires assigned "
                "module variables to share one supported value type"
            ),
        )
        return
    top_level.export_value_type = next(iter(value_types))


def _assigned_name_targets(statement: ast.stmt) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(statement):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                names.update(_target_names(target))
        elif isinstance(node, ast.AnnAssign):
            names.update(_target_names(node.target))
        elif isinstance(node, ast.AugAssign):
            names.update(_target_names(node.target))
        elif isinstance(node, ast.NamedExpr):
            names.update(_target_names(node.target))
    return names


def _new_assignment_names(statement: ast.stmt, known_names: set[str]) -> set[str]:
    return _assigned_name_targets(statement) - known_names


def _target_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, ast.Tuple):
        names: set[str] = set()
        for item in node.elts:
            names.update(_target_names(item))
        return names
    return set()


def _is_module_metadata_statement(index: int, statement: ast.stmt) -> bool:
    return (
        index == 0
        and isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and isinstance(statement.value.value, str)
    )


def _add_top_level_error(
    validator: FunctionAnalysis,
    node: ast.AST,
    message: str,
    suggestion: str,
    code: str = "RXT010",
) -> None:
    validator.add_diagnostic(
        Diagnostic(
            code=code,
            severity="error",
            message=message,
            file_path=validator.file_path,
            line=getattr(node, "lineno", validator.line),
            column=getattr(node, "col_offset", validator.column),
            function_name=validator.qualname,
            suggestion=suggestion,
        )
    )


def _add_top_level_analysis_error(
    top_level: TopLevelAnalysis,
    message: str,
    code: str = "RXT010",
) -> None:
    top_level.add_diagnostic(
        Diagnostic(
            code=code,
            severity="error",
            message=message,
            file_path=top_level.file_path,
            line=top_level.line,
            column=top_level.column,
            function_name=top_level.qualname,
            suggestion="Keep this module top level on Python fallback or simplify it to the supported subset.",
        )
    )
