"""Source-order module initialization segmentation with no runtime integration."""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING

from rextio.analyzer.models import SourcePosition, SourceRange
from rextio.artifacts import ArtifactProvenance
from rextio.ir.module_init import (
    ModuleInitAvailability,
    ModuleInitDisposition,
    ModuleInitIR,
    ModuleInitSegment,
    ModuleInitSegmentKind,
)
from rextio.source.graph import resolve_import_from_base
from rextio.source.models import SourceModuleGraph

if TYPE_CHECKING:
    from rextio.analyzer.models import ProjectAnalysis


# Runtime annotations are evaluated while a function definition executes
# unless ``from __future__ import annotations`` is active.  The first module
# initializer slice can prove these builtins only while no earlier statement
# may have rebound them.  Names from typing modules or user classes remain a
# preserved-Python boundary because resolving them would require executing
# prior source.
_SAFE_RUNTIME_ANNOTATION_BUILTINS = frozenset(
    {
        "bool",
        "bytes",
        "complex",
        "dict",
        "float",
        "frozenset",
        "int",
        "list",
        "memoryview",
        "object",
        "set",
        "str",
        "tuple",
        "type",
    }
)


def build_module_init_ir(
    source: str | bytes,
    *,
    module_name: str,
    path: str | None = None,
    is_package_init: bool | None = None,
) -> ModuleInitIR:
    """Plan exact top-level statement segments without executing source.

    A leading module docstring is deterministically excluded and retained in
    ``metadata_ranges``. Every other top-level statement belongs to one ordered
    segment. Syntax errors produce an unavailable plan with no approximated
    segments.
    """
    relative_path = path or _default_module_path(module_name)
    package_init = (
        relative_path.endswith("/__init__.py") or relative_path == "__init__.py"
        if is_package_init is None
        else is_package_init
    )
    source_bytes = source if isinstance(source, bytes) else source.encode("utf-8")
    digest = hashlib.sha256(source_bytes).hexdigest()
    provenance = ArtifactProvenance(
        source_references=(relative_path,),
        evidence=(f"sha256:{digest}",),
    )
    try:
        source_text = source_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return ModuleInitIR(
            module_name=module_name,
            path=relative_path,
            source_sha256=digest,
            availability=ModuleInitAvailability.UNAVAILABLE,
            unavailable_reason="source-decode-error:utf-8",
            provenance=provenance,
        )
    try:
        tree = ast.parse(source_text, filename=relative_path)
    except SyntaxError as error:
        line = error.lineno or 0
        column = error.offset or 0
        return ModuleInitIR(
            module_name=module_name,
            path=relative_path,
            source_sha256=digest,
            availability=ModuleInitAvailability.UNAVAILABLE,
            unavailable_reason=f"syntax-error:{line}:{column}:{error.msg}",
            provenance=provenance,
        )

    segments: list[ModuleInitSegment] = []
    metadata_ranges: list[SourceRange] = []
    future_annotations = False
    runtime_shadowed_names: set[str] = set()
    runtime_namespace_unknown = False
    for statement_index, statement in enumerate(tree.body):
        if statement_index == 0 and _is_module_docstring(statement):
            metadata_ranges.append(_source_range(statement))
            continue
        if isinstance(statement, ast.ImportFrom) and _is_future_import(statement):
            metadata_ranges.append(_source_range(statement))
            if any(alias.name == "annotations" for alias in statement.names):
                future_annotations = True
            continue
        segment = _segment_for_statement(
            statement_index,
            statement,
            module_name=module_name,
            is_package_init=package_init,
            future_annotations=future_annotations,
            runtime_shadowed_names=frozenset(runtime_shadowed_names),
            runtime_namespace_unknown=runtime_namespace_unknown,
        )
        if segments and _can_merge(segments[-1], segment):
            segments[-1] = _merge_segments(segments[-1], segment)
        else:
            segments.append(segment)
        facts = _binding_facts(statement)
        # A definite deletion exposes the builtin again; a conditional deletion
        # does not.  Every possible binding is retained conservatively so a
        # source-order annotation lookup can never be silently changed.
        runtime_shadowed_names.difference_update(facts.must_deleted)
        runtime_shadowed_names.update(facts.may)
        runtime_namespace_unknown = runtime_namespace_unknown or facts.namespace_unknown

    ordered = tuple(replace(segment, ordinal=index) for index, segment in enumerate(segments))
    return ModuleInitIR(
        module_name=module_name,
        path=relative_path,
        source_sha256=digest,
        availability=ModuleInitAvailability.AVAILABLE,
        segments=ordered,
        metadata_ranges=tuple(metadata_ranges),
        provenance=provenance,
    )


def plan_module_init(
    source: str,
    *,
    module_name: str,
    path: str | None = None,
    is_package_init: bool | None = None,
) -> ModuleInitIR:
    """Compatibility spelling for :func:`build_module_init_ir`."""
    return build_module_init_ir(
        source,
        module_name=module_name,
        path=path,
        is_package_init=is_package_init,
    )


def build_module_init_ir_from_path(
    project_root: Path | str,
    source_path: Path | str,
    *,
    module_name: str,
) -> ModuleInitIR:
    """Read one project-contained file and build its behavior-neutral plan."""
    root = Path(project_root).resolve()
    path = Path(source_path)
    normalized = (path if path.is_absolute() else root / path).resolve()
    try:
        relative = normalized.relative_to(root).as_posix()
    except ValueError as error:
        raise ValueError("module-init source must remain inside the project root") from error
    try:
        source = normalized.read_bytes()
    except OSError:
        digest = hashlib.sha256(b"").hexdigest()
        return ModuleInitIR(
            module_name=module_name,
            path=relative,
            source_sha256=digest,
            availability=ModuleInitAvailability.UNAVAILABLE,
            unavailable_reason="source-unavailable",
            provenance=ArtifactProvenance(source_references=(relative,)),
        )
    return build_module_init_ir(
        source,
        module_name=module_name,
        path=relative,
        is_package_init=normalized.name == "__init__.py",
    )


def build_project_module_init_irs(analysis: ProjectAnalysis) -> tuple[ModuleInitIR, ...]:
    """Build plans for exactly the modules already present in an analysis."""
    return tuple(
        build_module_init_ir_from_path(
            analysis.project_root,
            module.file_path,
            module_name=module.module_name,
        )
        for module in sorted(analysis.modules, key=lambda item: item.module_name)
    )


def is_initial_module_init_eligible(
    plan: ModuleInitIR,
    graph: SourceModuleGraph,
) -> bool:
    """Apply the deliberately bounded first-slice eligibility predicate.

    The initial slice accepts only an exact, hash-matched plan for a graph with
    one module, no self-cycle, at least one native candidate, and no fallback
    barrier. Imports and definition-publication segments remain Python-preserved
    boundaries; this predicate does not execute or lower any segment.
    """
    if not plan.bounded_candidate or len(graph.modules) != 1 or graph.cycles:
        return False
    module = graph.modules[0]
    return module.module_name == plan.module_name and module.sha256 == plan.source_sha256


def initial_module_init_eligible(plan: ModuleInitIR, graph: SourceModuleGraph) -> bool:
    """Compatibility spelling for :func:`is_initial_module_init_eligible`."""
    return is_initial_module_init_eligible(plan, graph)


def _segment_for_statement(
    statement_index: int,
    statement: ast.stmt,
    *,
    module_name: str,
    is_package_init: bool,
    future_annotations: bool,
    runtime_shadowed_names: frozenset[str],
    runtime_namespace_unknown: bool,
) -> ModuleInitSegment:
    facts = _binding_facts(statement)
    bindings = tuple(sorted(facts.may))
    exports = tuple(name for name in bindings if not name.startswith("_"))
    dependencies = tuple(sorted(_statement_dependencies(statement)))
    if isinstance(statement, (ast.Import, ast.ImportFrom)):
        dependencies = _import_dependencies(statement, module_name, is_package_init)
        kind = ModuleInitSegmentKind.IMPORT
        disposition = ModuleInitDisposition.PYTHON_PRESERVED
        barrier_reason = None
    elif isinstance(
        statement, (ast.FunctionDef, ast.AsyncFunctionDef)
    ) and not _definition_header_effectful(
        statement,
        future_annotations=future_annotations,
        runtime_shadowed_names=runtime_shadowed_names,
        runtime_namespace_unknown=runtime_namespace_unknown,
    ):
        kind = ModuleInitSegmentKind.DEFINITION_PUBLICATION
        disposition = ModuleInitDisposition.PYTHON_PRESERVED
        barrier_reason = None
    elif _is_bounded_native_statement(statement):
        kind = ModuleInitSegmentKind.NATIVE
        disposition = ModuleInitDisposition.NATIVE_CANDIDATE
        barrier_reason = None
    else:
        kind = ModuleInitSegmentKind.FALLBACK_BARRIER
        disposition = ModuleInitDisposition.PYTHON_PRESERVED
        barrier_reason = _barrier_reason(
            statement,
            future_annotations=future_annotations,
            runtime_shadowed_names=runtime_shadowed_names,
            runtime_namespace_unknown=runtime_namespace_unknown,
        )
    return ModuleInitSegment(
        ordinal=statement_index,
        kind=kind,
        disposition=disposition,
        source_range=_source_range(statement),
        statement_indexes=(statement_index,),
        bindings=bindings,
        exports=exports,
        dependencies=dependencies,
        must_bindings=tuple(sorted(facts.must)),
        may_bindings=bindings,
        deleted_bindings=tuple(sorted(facts.may_deleted)),
        must_exports=tuple(sorted(name for name in facts.must if not name.startswith("_"))),
        may_exports=exports,
        must_deletions=tuple(sorted(facts.must_deleted)),
        may_deletions=tuple(sorted(facts.may_deleted)),
        namespace_unknown=facts.namespace_unknown,
        barrier_reason=barrier_reason,
    )


def _is_module_docstring(statement: ast.stmt) -> bool:
    return (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and isinstance(statement.value.value, str)
    )


def _is_future_import(statement: ast.stmt) -> bool:
    return isinstance(statement, ast.ImportFrom) and statement.module == "__future__"


def _definition_header_effectful(
    statement: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    future_annotations: bool,
    runtime_shadowed_names: frozenset[str],
    runtime_namespace_unknown: bool,
) -> bool:
    if statement.decorator_list or statement.args.defaults:
        return True
    if any(default is not None for default in statement.args.kw_defaults):
        return True
    if future_annotations:
        return False
    return _definition_annotations_require_preserved_runtime(
        statement,
        runtime_shadowed_names=runtime_shadowed_names,
        runtime_namespace_unknown=runtime_namespace_unknown,
    )


def _definition_annotations(
    statement: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[ast.expr, ...]:
    annotations: list[ast.expr] = []
    if statement.returns is not None:
        annotations.append(statement.returns)
    for argument in (*statement.args.posonlyargs, *statement.args.args, *statement.args.kwonlyargs):
        if argument.annotation is not None:
            annotations.append(argument.annotation)
    if statement.args.vararg is not None and statement.args.vararg.annotation is not None:
        annotations.append(statement.args.vararg.annotation)
    if statement.args.kwarg is not None and statement.args.kwarg.annotation is not None:
        annotations.append(statement.args.kwarg.annotation)
    return tuple(annotations)


def _definition_annotations_require_preserved_runtime(
    statement: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    runtime_shadowed_names: frozenset[str],
    runtime_namespace_unknown: bool,
) -> bool:
    return any(
        not _is_runtime_safe_annotation(
            annotation,
            runtime_shadowed_names=runtime_shadowed_names,
            runtime_namespace_unknown=runtime_namespace_unknown,
        )
        for annotation in _definition_annotations(statement)
    )


def _is_runtime_safe_annotation(
    annotation: ast.expr,
    *,
    runtime_shadowed_names: frozenset[str],
    runtime_namespace_unknown: bool,
) -> bool:
    """Prove that evaluating one eager annotation cannot run project code."""
    if isinstance(annotation, ast.Constant):
        return True
    if isinstance(annotation, ast.Name):
        return (
            not runtime_namespace_unknown
            and annotation.id in _SAFE_RUNTIME_ANNOTATION_BUILTINS
            and annotation.id not in runtime_shadowed_names
        )
    if isinstance(annotation, ast.Subscript):
        return _is_runtime_safe_annotation(
            annotation.value,
            runtime_shadowed_names=runtime_shadowed_names,
            runtime_namespace_unknown=runtime_namespace_unknown,
        ) and _is_runtime_safe_annotation(
            annotation.slice,
            runtime_shadowed_names=runtime_shadowed_names,
            runtime_namespace_unknown=runtime_namespace_unknown,
        )
    if isinstance(annotation, (ast.Tuple, ast.List)):
        return all(
            _is_runtime_safe_annotation(
                item,
                runtime_shadowed_names=runtime_shadowed_names,
                runtime_namespace_unknown=runtime_namespace_unknown,
            )
            for item in annotation.elts
        )
    if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
        return _is_runtime_safe_annotation(
            annotation.left,
            runtime_shadowed_names=runtime_shadowed_names,
            runtime_namespace_unknown=runtime_namespace_unknown,
        ) and _is_runtime_safe_annotation(
            annotation.right,
            runtime_shadowed_names=runtime_shadowed_names,
            runtime_namespace_unknown=runtime_namespace_unknown,
        )
    return False


def _is_bounded_native_statement(statement: ast.stmt) -> bool:
    if isinstance(statement, ast.Assign):
        return (
            len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
            and _is_bounded_native_expression(statement.value)
        )
    if isinstance(statement, ast.AnnAssign):
        return (
            isinstance(statement.target, ast.Name)
            and statement.value is not None
            and _is_bounded_native_expression(statement.value)
        )
    return isinstance(statement, ast.Pass)


def _is_bounded_native_expression(expression: ast.expr) -> bool:
    """Accept only the initial side-effect-free scalar/container expression slice."""
    if isinstance(expression, ast.Constant):
        return True
    if isinstance(expression, ast.BinOp):
        return _is_bounded_native_expression(expression.left) and _is_bounded_native_expression(
            expression.right
        )
    if isinstance(expression, ast.UnaryOp):
        return _is_bounded_native_expression(expression.operand)
    if isinstance(expression, ast.BoolOp):
        return all(_is_bounded_native_expression(value) for value in expression.values)
    if isinstance(expression, ast.Compare):
        return _is_bounded_native_expression(expression.left) and all(
            _is_bounded_native_expression(comparator) for comparator in expression.comparators
        )
    if isinstance(expression, ast.IfExp):
        return all(
            _is_bounded_native_expression(value)
            for value in (expression.test, expression.body, expression.orelse)
        )
    if isinstance(expression, (ast.List, ast.Tuple)):
        return all(_is_bounded_native_expression(item) for item in expression.elts)
    if isinstance(expression, ast.Dict):
        return all(
            key is not None
            and _is_bounded_native_expression(key)
            and _is_bounded_native_expression(value)
            for key, value in zip(expression.keys, expression.values)
        )
    return False


def _barrier_reason(
    statement: ast.stmt,
    *,
    future_annotations: bool,
    runtime_shadowed_names: frozenset[str],
    runtime_namespace_unknown: bool,
) -> str:
    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
        if not future_annotations and _definition_annotations_require_preserved_runtime(
            statement,
            runtime_shadowed_names=runtime_shadowed_names,
            runtime_namespace_unknown=runtime_namespace_unknown,
        ):
            return "function definition annotations require preserved Python source-order evaluation"
        return "function definition header requires preserved Python execution"
    if any(isinstance(node, ast.Call) for node in ast.walk(statement)):
        return "top-level call requires preserved Python execution"
    if isinstance(statement, ast.Expr):
        return "standalone top-level expression requires preserved Python execution"
    return f"top-level {statement.__class__.__name__} is outside the bounded native slice"


def _can_merge(previous: ModuleInitSegment, current: ModuleInitSegment) -> bool:
    return (
        previous.kind is ModuleInitSegmentKind.NATIVE
        and current.kind is ModuleInitSegmentKind.NATIVE
        and previous.statement_indexes[-1] + 1 == current.statement_indexes[0]
    )


def _merge_segments(
    previous: ModuleInitSegment,
    current: ModuleInitSegment,
) -> ModuleInitSegment:
    return ModuleInitSegment(
        ordinal=previous.ordinal,
        kind=previous.kind,
        disposition=previous.disposition,
        source_range=_span_source_ranges(previous.source_range, current.source_range),
        statement_indexes=previous.statement_indexes + current.statement_indexes,
        bindings=previous.bindings + current.bindings,
        exports=previous.exports + current.exports,
        dependencies=previous.dependencies
        + tuple(
            dependency for dependency in current.dependencies if dependency not in previous.bindings
        ),
        must_bindings=tuple(
            (set(previous.must_bindings or ()) - set(current.deleted_bindings))
            | set(current.must_bindings or ())
        ),
        may_bindings=tuple(set(previous.may_bindings or ()) | set(current.may_bindings or ())),
        deleted_bindings=tuple(
            set(previous.may_deletions or ()) | set(current.may_deletions or ())
        ),
        must_exports=tuple(
            (set(previous.must_exports or ()) - set(current.may_deletions or ()))
            | set(current.must_exports or ())
        ),
        may_exports=tuple(set(previous.may_exports or ()) | set(current.may_exports or ())),
        must_deletions=tuple(set(previous.must_deletions) | set(current.must_deletions)),
        may_deletions=tuple(set(previous.may_deletions or ()) | set(current.may_deletions or ())),
        namespace_unknown=previous.namespace_unknown or current.namespace_unknown,
    )


def _span_source_ranges(first: SourceRange, last: SourceRange) -> SourceRange:
    if (last.start.line, last.start.column) < (first.start.line, first.start.column):
        raise ValueError("source ranges must be supplied in source order")
    return SourceRange(start=first.start, end=last.end)


@dataclass(frozen=True)
class _BindingFacts:
    must: frozenset[str] = frozenset()
    may: frozenset[str] = frozenset()
    must_deleted: frozenset[str] = frozenset()
    may_deleted: frozenset[str] = frozenset()
    namespace_unknown: bool = False


def _suite_binding_facts(statements: list[ast.stmt]) -> _BindingFacts:
    must: set[str] = set()
    may: set[str] = set()
    must_deleted: set[str] = set()
    may_deleted: set[str] = set()
    namespace_unknown = False
    for statement in statements:
        facts = _binding_facts(statement)
        must.difference_update(facts.may_deleted)
        must.update(facts.must)
        may.update(facts.may)
        must_deleted.update(facts.must_deleted)
        may_deleted.update(facts.may_deleted)
        namespace_unknown = namespace_unknown or facts.namespace_unknown
    return _BindingFacts(
        must=frozenset(must),
        may=frozenset(may),
        must_deleted=frozenset(must_deleted),
        may_deleted=frozenset(may_deleted),
        namespace_unknown=namespace_unknown,
    )


def _binding_facts(statement: ast.stmt) -> _BindingFacts:
    if isinstance(statement, ast.If):
        body = _suite_binding_facts(statement.body)
        otherwise = _suite_binding_facts(statement.orelse)
        must = body.must & otherwise.must if statement.orelse else frozenset()
        return _BindingFacts(
            must=must,
            may=body.may | otherwise.may,
            must_deleted=(
                body.must_deleted & otherwise.must_deleted if statement.orelse else frozenset()
            ),
            may_deleted=body.may_deleted | otherwise.may_deleted,
            namespace_unknown=body.namespace_unknown or otherwise.namespace_unknown,
        )

    collector = _ModuleBindingCollector()
    collector.visit(statement)
    may = frozenset(collector.names)
    conditional = isinstance(
        statement,
        (ast.For, ast.AsyncFor, ast.While, ast.Try, ast.Match, ast.With, ast.AsyncWith),
    )
    return _BindingFacts(
        must=frozenset() if conditional else may,
        may=may,
        must_deleted=(frozenset() if conditional else frozenset(collector.deleted)),
        may_deleted=frozenset(collector.deleted),
        namespace_unknown=collector.namespace_unknown,
    )


class _ModuleBindingCollector(ast.NodeVisitor):
    """Collect names bound in module scope by one top-level statement."""

    def __init__(self) -> None:
        self.names: set[str] = set()
        self.deleted: set[str] = set()
        self.namespace_unknown = False

    def visit_Name(self, node: ast.Name) -> None:
        """Record ordinary store-context names."""
        if isinstance(node.ctx, ast.Store):
            self.names.add(node.id)

    def visit_Import(self, node: ast.Import) -> None:
        """Record names published by a plain import."""
        for alias in node.names:
            self.names.add(alias.asname or alias.name.split(".", 1)[0])

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Record statically known names published by a from-import."""
        for alias in node.names:
            if alias.name == "*":
                self.namespace_unknown = True
            else:
                self.names.add(alias.asname or alias.name)

    def visit_Delete(self, node: ast.Delete) -> None:
        """Record names that may be removed from the module namespace."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.deleted.add(target.id)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Record only the published function name, not deferred body locals."""
        self.names.add(node.name)
        self._visit_definition_header(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Record only the published async-function name."""
        self.names.add(node.name)
        self._visit_definition_header(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Record the class publication without treating class locals as globals."""
        self.names.add(node.name)
        for expression in (*node.decorator_list, *node.bases):
            self.visit(expression)
        for keyword in node.keywords:
            self.visit(keyword.value)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        """Do not treat lambda-local stores as module bindings."""
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self.visit(default)

    def visit_comprehension(self, node: ast.comprehension) -> None:
        """Exclude comprehension iteration variables from module bindings."""
        self.visit(node.iter)
        for condition in node.ifs:
            self.visit(condition)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        """Record an except-as name and visit its executed body."""
        if node.name:
            self.names.add(node.name)
        if node.type is not None:
            self.visit(node.type)
        for statement in node.body:
            self.visit(statement)

    def _visit_definition_header(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        for expression in node.decorator_list:
            self.visit(expression)
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self.visit(default)


class _ExecutedLoadCollector(ast.NodeVisitor):
    """Collect names read while a top-level statement itself executes."""

    def __init__(self) -> None:
        self.names: set[str] = set()

    def visit_Name(self, node: ast.Name) -> None:
        """Record load-context names."""
        if isinstance(node.ctx, ast.Load):
            self.names.add(node.id)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit definition-time expressions but skip the deferred body."""
        self._visit_definition_header(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Visit async definition-time expressions but skip its body."""
        self._visit_definition_header(node)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        """Visit lambda defaults but skip its deferred body."""
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self.visit(default)

    def _visit_definition_header(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        for expression in node.decorator_list:
            self.visit(expression)
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self.visit(default)
        if node.returns is not None:
            self.visit(node.returns)
        for argument in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
            if argument.annotation is not None:
                self.visit(argument.annotation)
        if node.args.vararg is not None and node.args.vararg.annotation is not None:
            self.visit(node.args.vararg.annotation)
        if node.args.kwarg is not None and node.args.kwarg.annotation is not None:
            self.visit(node.args.kwarg.annotation)


def _statement_dependencies(statement: ast.stmt) -> set[str]:
    collector = _ExecutedLoadCollector()
    collector.visit(statement)
    if isinstance(statement, ast.AugAssign) and isinstance(statement.target, ast.Name):
        collector.names.add(statement.target.id)
    return collector.names


def _import_dependencies(
    statement: ast.Import | ast.ImportFrom,
    module_name: str,
    is_package_init: bool,
) -> tuple[str, ...]:
    if isinstance(statement, ast.Import):
        return tuple(sorted({alias.name for alias in statement.names}))
    base = resolve_import_from_base(
        module_name,
        statement.module,
        statement.level,
        is_package_init,
    )
    if base is None or not base:
        return (f"unresolved:{'.' * statement.level}{statement.module or ''}",)
    if statement.module is None:
        return tuple(
            sorted(
                base if alias.name == "*" else f"{base}.{alias.name}" for alias in statement.names
            )
        )
    return (base,)


def _default_module_path(module_name: str) -> str:
    return f"{module_name.replace('.', '/')}.py" if module_name else "__init__.py"


def _source_range(node: ast.AST) -> SourceRange:
    line = getattr(node, "lineno", None)
    column = getattr(node, "col_offset", None)
    end_line = getattr(node, "end_lineno", None)
    end_column = getattr(node, "end_col_offset", None)
    if line is None or column is None or end_line is None or end_column is None:
        raise ValueError("parsed module statement has no reliable source range")
    return SourceRange(
        start=SourcePosition(line=line, column=column),
        end=SourcePosition(line=end_line, column=end_column),
    )
