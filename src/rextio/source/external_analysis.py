"""Exact-byte C5.2 analysis foundation for external pure-Python source.

This module deliberately stops before project call linkage, code generation, or
build authorization.  It accepts an immutable byte snapshot that has already
been tied to a :class:`~rextio.source.models.SourceModule`, parses only those
bytes, and proves a very small scalar leaf-function surface against the same
core validator and IR lowerer used by project functions.

No function in this module imports the represented package, resolves an
installed distribution, follows a filesystem path, or rereads ambient source.
Absolute installation paths and source bytes are also excluded from every
serialized record.
"""

from __future__ import annotations

import ast
import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path

from rextio.analyzer.call_resolution import FunctionResolver
from rextio.analyzer.executable_identity import executable_ast_fingerprint
from rextio.analyzer.final_bindings import (
    ProjectBindings,
    build_module_bindings,
)
from rextio.analyzer.models import (
    FunctionAnalysis,
    ModuleAnalysis,
    ProjectAnalysis,
    SourcePosition,
    SourceRange,
)
from rextio.analyzer.unsupported_patterns import validate_native_function
from rextio.ir.lowering import LoweringError, lower_function
from rextio.ir.module_init import ModuleInitIR
from rextio.source.external import MAX_FILE_BYTES, MAX_MODULE_NAME_LEN
from rextio.source.models import SourceModule, SourceOrigin


EXTERNAL_SOURCE_ANALYSIS_DOMAIN = "rextio.external-source-analysis.v1"
EXTERNAL_FUNCTION_SEMANTIC_DOMAIN = "rextio.external-source-function.v1"
EXTERNAL_FUNCTION_IR_DOMAIN = "rextio.external-source-function-ir.v1"
SCALAR_TYPE_NAMES = frozenset({"bool", "float", "int", "str"})

_SAFE_DOTTED_NAME = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*"
)
_ALLOWED_BINARY_OPERATORS = (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod)
_ALLOWED_UNARY_OPERATORS = (ast.USub, ast.Not)
_ALLOWED_BOOLEAN_OPERATORS = (ast.And, ast.Or)
_ALLOWED_COMPARISON_OPERATORS = (
    ast.Eq,
    ast.NotEq,
    ast.Lt,
    ast.LtE,
    ast.Gt,
    ast.GtE,
)
_NESTED_OR_GENERATOR_NODES = (
    ast.AsyncFunctionDef,
    ast.ClassDef,
    ast.DictComp,
    ast.GeneratorExp,
    ast.Lambda,
    ast.ListComp,
    ast.SetComp,
    ast.Yield,
    ast.YieldFrom,
)


class ExternalSourceAnalysisError(ValueError):
    """A stable fail-closed rejection from exact external-source analysis."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class ExternalSourceSnapshot:
    """One immutable distribution-source snapshot supplied by a prior verifier.

    ``source_bytes`` intentionally participates in equality but not repr or
    serialization.  Requiring exact ``bytes`` (rather than accepting mutable
    bytes-like objects) prevents a caller from changing the analysis input
    after construction.
    """

    module: SourceModule
    source_bytes: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.module) is not SourceModule:
            raise ExternalSourceAnalysisError("snapshot-module-invalid")
        if type(self.source_bytes) is not bytes:
            raise ExternalSourceAnalysisError("snapshot-bytes-must-be-immutable")
        if not self.source_bytes or len(self.source_bytes) > MAX_FILE_BYTES:
            raise ExternalSourceAnalysisError("snapshot-size-out-of-bounds")
        module = self.module
        if (
            module.source_origin is not SourceOrigin.DISTRIBUTION
            or module.dependency_depth != 1
            or module.distribution is None
            or module.version is None
            or module.license is None
            or not module.distribution.strip()
            or not module.version.strip()
            or not module.license.strip()
            or module.imports
        ):
            raise ExternalSourceAnalysisError("snapshot-authority-out-of-scope")
        if (
            len(module.module_name) > MAX_MODULE_NAME_LEN
            or _SAFE_DOTTED_NAME.fullmatch(module.module_name) is None
        ):
            raise ExternalSourceAnalysisError("snapshot-module-name-invalid")
        if not _source_path_matches_module(module):
            raise ExternalSourceAnalysisError("snapshot-source-path-invalid")
        if hashlib.sha256(self.source_bytes).hexdigest() != module.sha256:
            raise ExternalSourceAnalysisError("snapshot-sha256-mismatch")

    @property
    def size(self) -> int:
        """Return the exact immutable source size."""
        return len(self.source_bytes)

    def to_dict(self) -> dict[str, object]:
        """Return sanitized identity material without source bytes or host paths."""
        return {
            "module": self.module.to_dict(),
            "size": self.size,
        }


@dataclass(frozen=True, slots=True)
class ExternalScalarParameter:
    """One fixed positional scalar parameter on an external leaf function."""

    name: str
    type_name: str

    def __post_init__(self) -> None:
        if (
            not self.name.isascii()
            or not self.name.isidentifier()
            or self.type_name not in SCALAR_TYPE_NAMES
        ):
            raise ValueError("external scalar parameter is invalid")

    def to_dict(self) -> dict[str, str]:
        """Return the deterministic scalar-parameter record."""
        return {"name": self.name, "type": self.type_name}


@dataclass(frozen=True, slots=True)
class ExternalFunctionBinding:
    """A fully checked, exact-source scalar leaf function."""

    name: str
    qualname: str
    module_name: str
    source_path: str
    source_sha256: str
    source_range: SourceRange
    parameters: tuple[ExternalScalarParameter, ...]
    return_type: str
    semantic_ast_sha256: str
    lowered_ir_sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "parameters", tuple(self.parameters))
        if (
            self.qualname != f"{self.module_name}.{self.name}"
            or self.return_type not in SCALAR_TYPE_NAMES
            or len(self.source_sha256) != 64
            or len(self.semantic_ast_sha256) != 64
            or len(self.lowered_ir_sha256) != 64
        ):
            raise ValueError("external function binding is invalid")
        if len({parameter.name for parameter in self.parameters}) != len(self.parameters):
            raise ValueError("external function parameters are duplicated")

    def to_dict(self) -> dict[str, object]:
        """Return exact source and lowering identity without source bytes."""
        return {
            "name": self.name,
            "qualname": self.qualname,
            "module_name": self.module_name,
            "source_path": self.source_path,
            "source_sha256": self.source_sha256,
            "source_range": self.source_range.to_dict(),
            "parameters": [parameter.to_dict() for parameter in self.parameters],
            "return_type": self.return_type,
            "semantic_ast_sha256": self.semantic_ast_sha256,
            "lowered_ir_sha256": self.lowered_ir_sha256,
        }


@dataclass(frozen=True, slots=True)
class ExternalSourceNativePlan:
    """One deterministic, analysis-only depth-1 external native plan."""

    snapshot: ExternalSourceSnapshot = field(repr=False)
    module_init: ModuleInitIR
    functions: tuple[ExternalFunctionBinding, ...]
    semantic_sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "functions", tuple(self.functions))
        module = self.snapshot.module
        if (
            not self.functions
            or tuple(binding.qualname for binding in self.functions)
            != tuple(sorted(binding.qualname for binding in self.functions))
            or len({binding.qualname for binding in self.functions})
            != len(self.functions)
            or any(
                binding.module_name != module.module_name
                or binding.source_path != module.path
                or binding.source_sha256 != module.sha256
                for binding in self.functions
            )
            or self.module_init.module_name != module.module_name
            or self.module_init.path != module.path
            or self.module_init.source_sha256 != module.sha256
            or not self.module_init.available
            or len(self.semantic_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.semantic_sha256
            )
        ):
            raise ValueError("external source native plan is inconsistent")
        expected = _plan_semantic_sha256(
            snapshot=self.snapshot,
            module_init=self.module_init,
            functions=self.functions,
        )
        if self.semantic_sha256 != expected:
            raise ValueError("external source native plan digest is inconsistent")

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic analysis-only plan record."""
        return {
            "authority": "analysis-only",
            "domain": EXTERNAL_SOURCE_ANALYSIS_DOMAIN,
            "module": self.snapshot.to_dict(),
            "module_init": self.module_init.to_dict(),
            "functions": [binding.to_dict() for binding in self.functions],
            "semantic_sha256": self.semantic_sha256,
        }


def analyze_external_source_snapshot(
    snapshot: ExternalSourceSnapshot,
) -> ExternalSourceNativePlan:
    """Analyze exactly ``snapshot.source_bytes`` as one strict scalar-leaf module.

    The function raises :class:`ExternalSourceAnalysisError` with a fixed,
    sanitized reason.  It never degrades uncertainty into a partial plan.
    """
    if type(snapshot) is not ExternalSourceSnapshot:
        raise ExternalSourceAnalysisError("snapshot-invalid")
    try:
        return _analyze_external_source_snapshot(snapshot)
    except ExternalSourceAnalysisError:
        raise
    except Exception as error:
        raise ExternalSourceAnalysisError("analysis-internal-invariant") from error


def _analyze_external_source_snapshot(
    snapshot: ExternalSourceSnapshot,
) -> ExternalSourceNativePlan:
    try:
        source = snapshot.source_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise ExternalSourceAnalysisError("source-not-utf8") from None
    try:
        tree = ast.parse(
            source,
            filename=snapshot.module.path,
            mode="exec",
            type_comments=True,
        )
    except SyntaxError:
        raise ExternalSourceAnalysisError("source-not-parseable") from None
    if tree.type_ignores:
        raise ExternalSourceAnalysisError("source-type-ignore-not-supported")
    if any(isinstance(node, (ast.Import, ast.ImportFrom)) for node in ast.walk(tree)):
        raise ExternalSourceAnalysisError("source-import-not-supported")

    statements = list(tree.body)
    if statements and _is_docstring_statement(statements[0]):
        statements = statements[1:]
    if not statements:
        raise ExternalSourceAnalysisError("source-has-no-functions")
    functions: list[ast.FunctionDef] = []
    for statement in statements:
        if isinstance(statement, ast.AsyncFunctionDef):
            raise ExternalSourceAnalysisError("source-async-function-not-supported")
        if isinstance(statement, ast.ClassDef):
            raise ExternalSourceAnalysisError("source-class-not-supported")
        if not isinstance(statement, ast.FunctionDef):
            raise ExternalSourceAnalysisError("source-top-level-effect-not-supported")
        functions.append(statement)
    if len({function.name for function in functions}) != len(functions):
        raise ExternalSourceAnalysisError("source-function-binding-not-final")
    if any(function.name in SCALAR_TYPE_NAMES for function in functions):
        # Without ``from __future__ import annotations`` (imports are outside
        # this slice), a same-module definition can replace a scalar annotation
        # name during module execution. Never reinterpret that dynamic binding
        # as the builtin scalar type.
        raise ExternalSourceAnalysisError("source-scalar-annotation-shadowed")

    bindings = build_module_bindings(tree, snapshot.module.module_name)
    module = ModuleAnalysis(
        module_name=snapshot.module.module_name,
        file_path=snapshot.module.path,
        module_bindings=bindings,
        project_modules=frozenset({snapshot.module.module_name}),
    )
    analysis = ProjectAnalysis(
        project_root=Path("."),
        modules=[module],
        project_bindings=ProjectBindings({snapshot.module.module_name: bindings}),
    )
    resolver = FunctionResolver(analysis)
    function_names = {function.name for function in functions}
    return_types = {
        function.name: _scalar_annotation(function.returns)
        for function in functions
        if _scalar_annotation(function.returns) is not None
    }

    analyzed: list[tuple[ast.FunctionDef, FunctionAnalysis]] = []
    for node in functions:
        _require_external_function_shape(node)
        source_range = _node_range(node)
        fingerprint = executable_ast_fingerprint(node)
        function = FunctionAnalysis(
            name=node.name,
            qualname=f"{snapshot.module.module_name}.{node.name}",
            module_name=snapshot.module.module_name,
            file_path=snapshot.module.path,
            line=node.lineno,
            column=node.col_offset,
            source_range=source_range,
            marker_kind="none",
            is_native_candidate=True,
            explicitly_marked=False,
            source_ast_fingerprint=fingerprint,
            annotated_return_type=_scalar_annotation(node.returns),
            native_target_language="rust",
            imports={},
            module_function_names=frozenset(function_names),
            module_bindings=bindings,
            project_modules=frozenset({snapshot.module.module_name}),
        )
        validate_native_function(
            node,
            function,
            return_types={name: value for name, value in return_types.items() if value is not None},
            module_function_names=function_names,
        )
        if not function.accepted:
            raise ExternalSourceAnalysisError("function-not-core-lowerable")
        analyzed.append((node, function))

    module.functions = [function for _, function in analyzed]
    result: list[ExternalFunctionBinding] = []
    for node, function in analyzed:
        try:
            function_ir = lower_function(function, node, module, resolver)
        except LoweringError:
            raise ExternalSourceAnalysisError("function-not-core-lowerable") from None
        ast_digest = _domain_hash(
            EXTERNAL_FUNCTION_SEMANTIC_DOMAIN,
            executable_ast_fingerprint(node).encode("utf-8"),
        )
        ir_payload = json.dumps(
            function_ir.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        parameters = tuple(
            ExternalScalarParameter(argument.arg, _required_scalar_annotation(argument.annotation))
            for argument in (*node.args.posonlyargs, *node.args.args)
        )
        result.append(
            ExternalFunctionBinding(
                name=node.name,
                qualname=function.qualname,
                module_name=snapshot.module.module_name,
                source_path=snapshot.module.path,
                source_sha256=snapshot.module.sha256,
                source_range=_node_range(node),
                parameters=parameters,
                return_type=_required_scalar_annotation(node.returns),
                semantic_ast_sha256=ast_digest,
                lowered_ir_sha256=_domain_hash(EXTERNAL_FUNCTION_IR_DOMAIN, ir_payload),
            )
        )

    # Keep this import local.  ``rextio.analyzer.module_init`` depends on the
    # source graph package, whose public ``rextio.source`` facade eagerly
    # exposes this analysis module.  Importing the planner here, after both
    # modules are initialized, prevents that facade from creating an
    # import-order-dependent analyzer/source cycle.
    from rextio.analyzer.module_init import build_module_init_ir

    module_init = build_module_init_ir(
        snapshot.source_bytes,
        module_name=snapshot.module.module_name,
        path=snapshot.module.path,
        is_package_init=snapshot.module.is_package_init,
    )
    if not module_init.available:
        raise ExternalSourceAnalysisError("module-init-plan-unavailable")
    ordered = tuple(sorted(result, key=lambda binding: binding.qualname))
    digest = _plan_semantic_sha256(
        snapshot=snapshot,
        module_init=module_init,
        functions=ordered,
    )
    return ExternalSourceNativePlan(
        snapshot=snapshot,
        module_init=module_init,
        functions=ordered,
        semantic_sha256=digest,
    )


def _require_external_function_shape(node: ast.FunctionDef) -> None:
    if node.decorator_list:
        raise ExternalSourceAnalysisError("function-decorator-not-supported")
    if getattr(node, "type_params", ()):
        raise ExternalSourceAnalysisError("function-type-parameter-not-supported")
    if node.type_comment is not None:
        raise ExternalSourceAnalysisError("function-type-comment-not-supported")
    if (
        node.args.vararg is not None
        or node.args.kwarg is not None
        or node.args.kwonlyargs
        or node.args.defaults
        or any(default is not None for default in node.args.kw_defaults)
    ):
        raise ExternalSourceAnalysisError("function-signature-not-fixed-positional")
    arguments = (*node.args.posonlyargs, *node.args.args)
    if any(_scalar_annotation(argument.annotation) is None for argument in arguments):
        raise ExternalSourceAnalysisError("function-parameter-not-scalar-annotated")
    if _scalar_annotation(node.returns) is None:
        raise ExternalSourceAnalysisError("function-return-not-scalar-annotated")
    if any(isinstance(child, (ast.Global, ast.Nonlocal)) for child in ast.walk(node)):
        raise ExternalSourceAnalysisError("function-global-state-not-supported")
    if any(
        isinstance(child, (ast.FunctionDef, *_NESTED_OR_GENERATOR_NODES))
        for child in ast.walk(node)
        if child is not node
    ):
        raise ExternalSourceAnalysisError("function-nested-or-generator-not-supported")
    if any(isinstance(child, ast.Call) for child in ast.walk(node)):
        raise ExternalSourceAnalysisError("function-call-not-leaf")
    _require_straight_line_body(node)


def _require_straight_line_body(node: ast.FunctionDef) -> None:
    if not node.body or _is_docstring_statement(node.body[0]):
        raise ExternalSourceAnalysisError("function-body-not-straight-line")
    if not isinstance(node.body[-1], ast.Return) or node.body[-1].value is None:
        raise ExternalSourceAnalysisError("function-body-not-straight-line")
    bound = {argument.arg for argument in (*node.args.posonlyargs, *node.args.args)}
    for statement in node.body[:-1]:
        if isinstance(statement, ast.Assign):
            if (
                statement.type_comment is not None
                or len(statement.targets) != 1
                or not isinstance(statement.targets[0], ast.Name)
            ):
                raise ExternalSourceAnalysisError("function-body-not-straight-line")
            _require_scalar_expression(statement.value, bound)
            bound.add(statement.targets[0].id)
            continue
        if isinstance(statement, ast.AnnAssign):
            if (
                not isinstance(statement.target, ast.Name)
                or statement.value is None
                or _scalar_annotation(statement.annotation) is None
            ):
                raise ExternalSourceAnalysisError("function-body-not-straight-line")
            _require_scalar_expression(statement.value, bound)
            bound.add(statement.target.id)
            continue
        raise ExternalSourceAnalysisError("function-body-not-straight-line")
    final = node.body[-1]
    assert isinstance(final, ast.Return) and final.value is not None
    _require_scalar_expression(final.value, bound)


def _require_scalar_expression(node: ast.expr, bound: set[str]) -> None:
    if isinstance(node, ast.Name):
        if not isinstance(node.ctx, ast.Load) or node.id not in bound:
            raise ExternalSourceAnalysisError("function-free-name-not-supported")
        return
    if isinstance(node, ast.Constant):
        literal_value = node.value
        if type(literal_value) not in {bool, float, int, str}:
            raise ExternalSourceAnalysisError("function-literal-not-scalar")
        if type(literal_value) is int and not (
            -(2**63) <= literal_value <= 2**63 - 1
        ):
            raise ExternalSourceAnalysisError("function-integer-literal-out-of-range")
        if type(literal_value) is float and not math.isfinite(literal_value):
            raise ExternalSourceAnalysisError("function-float-literal-not-finite")
        return
    if isinstance(node, ast.BinOp) and isinstance(node.op, _ALLOWED_BINARY_OPERATORS):
        _require_scalar_expression(node.left, bound)
        _require_scalar_expression(node.right, bound)
        return
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, _ALLOWED_UNARY_OPERATORS):
        _require_scalar_expression(node.operand, bound)
        return
    if isinstance(node, ast.BoolOp) and isinstance(node.op, _ALLOWED_BOOLEAN_OPERATORS):
        for bool_value in node.values:
            _require_scalar_expression(bool_value, bound)
        return
    if isinstance(node, ast.Compare) and all(
        isinstance(operator, _ALLOWED_COMPARISON_OPERATORS) for operator in node.ops
    ):
        _require_scalar_expression(node.left, bound)
        for comparator in node.comparators:
            _require_scalar_expression(comparator, bound)
        return
    raise ExternalSourceAnalysisError("function-expression-not-supported")


def _scalar_annotation(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Name) and node.id in SCALAR_TYPE_NAMES:
        return node.id
    return None


def _required_scalar_annotation(node: ast.expr | None) -> str:
    result = _scalar_annotation(node)
    if result is None:  # pragma: no cover - guarded by strict shape validation
        raise ExternalSourceAnalysisError("function-scalar-annotation-missing")
    return result


def _is_docstring_statement(node: ast.stmt) -> bool:
    return (
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and type(node.value.value) is str
    )


def _source_path_matches_module(module: SourceModule) -> bool:
    distribution = re.sub(r"[-_.]+", "-", module.distribution or "").lower()
    prefix = f"distributions/{distribution}/"
    if not module.path.startswith(prefix) or not module.path.endswith(".py"):
        return False
    relative = module.path.removeprefix(prefix)
    module_parts = module.module_name.split(".")
    expected = (
        "/".join((*module_parts, "__init__.py"))
        if module.is_package_init
        else "/".join((*module_parts[:-1], f"{module_parts[-1]}.py"))
    )
    return relative == expected


def _node_range(node: ast.AST) -> SourceRange:
    start_line = getattr(node, "lineno", None)
    start_column = getattr(node, "col_offset", None)
    end_line = getattr(node, "end_lineno", None)
    end_column = getattr(node, "end_col_offset", None)
    if (
        start_line is None
        or start_column is None
        or end_line is None
        or end_column is None
    ):
        raise ExternalSourceAnalysisError("function-source-range-unavailable")
    return SourceRange(
        start=SourcePosition(line=start_line, column=start_column),
        end=SourcePosition(line=end_line, column=end_column),
    )


def _domain_hash(domain: str, payload: bytes) -> str:
    return hashlib.sha256(domain.encode("ascii") + b"\0" + payload).hexdigest()


def _plan_semantic_sha256(
    *,
    snapshot: ExternalSourceSnapshot,
    module_init: ModuleInitIR,
    functions: tuple[ExternalFunctionBinding, ...],
) -> str:
    payload = {
        "domain": EXTERNAL_SOURCE_ANALYSIS_DOMAIN,
        "module": snapshot.to_dict(),
        "module_init": module_init.to_dict(),
        "functions": [binding.to_dict() for binding in functions],
    }
    return hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


__all__ = [
    "EXTERNAL_FUNCTION_IR_DOMAIN",
    "EXTERNAL_FUNCTION_SEMANTIC_DOMAIN",
    "EXTERNAL_SOURCE_ANALYSIS_DOMAIN",
    "SCALAR_TYPE_NAMES",
    "ExternalFunctionBinding",
    "ExternalScalarParameter",
    "ExternalSourceAnalysisError",
    "ExternalSourceNativePlan",
    "ExternalSourceSnapshot",
    "analyze_external_source_snapshot",
]
