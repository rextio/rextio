"""Lowering of accepted analyzer results into Rextio IR.

Walks the AST of each accepted native function (and supported top-level module code)
and produces the ``ModuleIR`` the codegen backends consume. Anything the lowering
cannot represent raises ``LoweringError`` — by this stage the analyzer has already
accepted the input, so a failure here is an internal invariant violation, not user error.
"""

from __future__ import annotations

import ast
import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from rextio.analyzer.call_resolution import FunctionResolver
from rextio.analyzer.executable_identity import (
    class_construction_stability_reason,
    executable_ast_fingerprint,
    native_marker_identity_reason,
)
from rextio.analyzer.final_bindings import (
    BindingKind,
    ModuleBindings,
    build_module_bindings,
    definition_is_final,
    logger_group_target,
    logger_object_target,
)
from rextio.analyzer.common_calls import (
    COMMON_DIRECT_RUST_CALLS,
    HASHLIB_CHAIN_TARGETS,
    IMPORT_QUALIFIED_STDLIB_TARGETS,
    LIST_METHOD_TARGETS,
    LOGGING_CANONICAL_TARGETS,
    MATH_CONSTANT_TARGETS,
    STR_METHOD_TARGETS,
    BYTES_METHOD_TARGETS,
    canonical_attribute_target,
    canonical_call_target,
    is_supported_effect_call,
    stdlib_receiver_is_proven_import,
)
from rextio.analyzer.models import (
    FunctionAnalysis,
    ModuleAnalysis,
    PluginClaim,
    ProjectAnalysis,
    TopLevelAnalysis,
)
from rextio.analyzer.native_marker import dotted_name
from rextio.analyzer.top_level import collect_native_top_level_statements
from rextio.ir.module import module_from_functions
from rextio.ir.module_init import ModuleInitIR, ModuleInitSegmentKind
from rextio.ir.nodes import (
    AppendIR,
    AssignIR,
    BinaryOpIR,
    BlockIR,
    BreakIR,
    CallIR,
    ComprehensionGeneratorIR,
    CompareIR,
    ContinueIR,
    DictComprehensionIR,
    DictIR,
    DictSetIR,
    EffectCallIR,
    ExceptHandlerIR,
    ExprIR,
    ForIR,
    FunctionIR,
    IfIR,
    IndexIR,
    ListComprehensionIR,
    ListIR,
    LiteralIR,
    ModuleIR,
    NameIR,
    NamedExprIR,
    ParamIR,
    PluginClaimIR,
    ReturnIR,
    SetComprehensionIR,
    SetIR,
    StatementIR,
    TargetIR,
    TupleIR,
    TryIR,
    TupleTargetIR,
    UnaryOpIR,
    WhileIR,
)
from rextio.ir.types import type_from_annotation, type_from_string
from rextio.ir.types import RxtDict, RxtNone, RxtPluginType, RxtPyObject, RxtStr, RxtType

if TYPE_CHECKING:
    from rextio.source.external_linkage import ExternalNativeRegistry


class LoweringError(RuntimeError):
    """Raised when an accepted analysis result cannot be lowered to IR."""


@dataclass(frozen=True)
class PluginTypeMaps:
    """Plugin type lookups for lowering: by stable key and by annotation spelling."""

    by_key: dict[str, RxtPluginType]
    by_spelling: dict[str, RxtPluginType]


@dataclass
class _PluginLoweringState:
    """Per-function plugin state consulted while lowering one function."""

    # (line, column) of the claimed AST node -> the analyzer claim.
    claims: dict[tuple[str, int, int, int | None, int | None], PluginClaim] = field(
        default_factory=dict
    )
    type_maps: PluginTypeMaps | None = None
    # The function's resolved import map (visible name -> dotted target),
    # used to resolve plugin annotation spellings like the claim engine does.
    imports: dict[str, str] = field(default_factory=dict)
    external_native_registry: ExternalNativeRegistry | None = None
    caller_qualname: str | None = None


# Module-level plugin state, set/cleared (try/finally) around each
# ``lower_function`` call. ``lower_expr`` and the signature-type helpers
# recurse deeply and are called from many statement paths; a module global
# avoids threading a rarely-used parameter through that whole recursion for
# the plugin-free common case. Lowering is single-threaded per process, and
# the try/finally keeps the state strictly scoped to one function.
_PLUGIN_STATE: _PluginLoweringState | None = None


def lower_project(
    analysis: ProjectAnalysis,
    include_embedding: bool = False,
    plugin_types: PluginTypeMaps | None = None,
    *,
    executable_module_initializers: Mapping[str, ModuleInitIR] | None = None,
    external_native_registry: ExternalNativeRegistry | None = None,
) -> ModuleIR:
    """Lower accepted native functions and the explicitly selected top levels.

    ``None`` preserves the existing PyO3 top-level lowering. A mapping is the
    standalone executable path: only listed, snapshot-authorized initializers
    are lowered, and they return unit rather than publishing Python globals.
    """
    if external_native_registry is not None:
        external_native_registry.require_fresh_analysis(analysis)
    functions: list[FunctionIR] = []
    nodes_by_file: dict[str, _FunctionSource] = {}
    module_trees_by_file: dict[str, ast.Module] = {}
    resolver = FunctionResolver(analysis)
    for function in analysis.accepted_native_functions:
        functions.append(
            _lower_analysis_function(
                function,
                analysis,
                nodes_by_file,
                resolver,
                plugin_types=plugin_types,
                external_native_registry=external_native_registry,
            )
        )
    if include_embedding:
        for function in analysis.embedding_candidates:
            functions.append(
                _lower_analysis_function(
                    function,
                    analysis,
                    nodes_by_file,
                    resolver,
                    embedded=True,
                    plugin_types=plugin_types,
                    external_native_registry=external_native_registry,
                )
            )
    for top_level in analysis.accepted_native_top_levels:
        if executable_module_initializers is not None:
            init_plan = executable_module_initializers.get(top_level.qualname)
            if init_plan is None:
                continue
            module = _module_for_top_level(analysis, top_level)
            if module is None:
                raise LoweringError(
                    f"module was not found for accepted top level: {top_level.qualname}"
                )
            functions.append(
                lower_executable_module_initializer(top_level, init_plan, module, resolver)
            )
            continue
        tree = module_trees_by_file.setdefault(
            top_level.file_path,
            _module_tree(Path(top_level.file_path)),
        )
        module = _module_for_top_level(analysis, top_level)
        if module is None:
            raise LoweringError(
                f"module was not found for accepted top level: {top_level.qualname}"
            )
        functions.append(lower_top_level(top_level, tree, module, resolver))
    if external_native_registry is not None:
        functions.extend(external_native_registry.private_functions)
    return module_from_functions(functions)


def _lower_analysis_function(
    function: FunctionAnalysis,
    analysis: ProjectAnalysis,
    nodes_by_file: dict[str, _FunctionSource],
    resolver: FunctionResolver,
    *,
    embedded: bool = False,
    plugin_types: PluginTypeMaps | None = None,
    external_native_registry: ExternalNativeRegistry | None = None,
) -> FunctionIR:
    source = nodes_by_file.setdefault(
        function.file_path,
        _function_nodes(
            Path(function.file_path),
            function.module_name,
            analysis,
        ),
    )
    origin = source.origins.get(_function_node_key(function))
    if origin is None:
        kind = "embedding candidate" if embedded else "accepted native function"
        raise LoweringError(f"{kind} was not found: {function.qualname}")
    node = origin.node
    _require_exact_function_origin(function, origin, analysis, source.bindings)
    module = analysis.module_for_function(function)
    if module is None:
        raise LoweringError(f"module was not found for function: {function.qualname}")
    return lower_function(
        function,
        node,
        module,
        resolver,
        embedded=embedded,
        plugin_types=plugin_types,
        external_native_registry=external_native_registry,
    )


def lower_function(
    function: FunctionAnalysis,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    module: ModuleAnalysis,
    resolver: FunctionResolver,
    *,
    embedded: bool = False,
    plugin_types: PluginTypeMaps | None = None,
    external_native_registry: ExternalNativeRegistry | None = None,
) -> FunctionIR:
    """Lower a single analyzed native function (signature + body) to a ``FunctionIR``."""
    global _PLUGIN_STATE
    if function.native_runtime_semantics:
        runtime_functions = sorted(
            (
                candidate
                for candidate in module.functions
                if candidate.is_native_candidate
                and candidate.accepted
                and candidate.native_runtime_semantics
                and not candidate.has_resident_signature
            ),
            key=lambda candidate: candidate.qualname,
        )
        try:
            runtime_ordinal = next(
                index
                for index, candidate in enumerate(runtime_functions)
                if candidate.qualname == function.qualname
            )
        except StopIteration:
            raise LoweringError(
                f"runtime-semantics function has no bootstrap ordinal: {function.qualname}"
            ) from None
        return FunctionIR(
            name=function.name,
            qualname=function.qualname,
            module_name=function.module_name,
            params=[],
            return_type=RxtPyObject(),
            body=BlockIR(statements=[]),
            native_runtime_semantics=True,
            embedded=embedded,
            runtime_fallback_module=module.module_name,
            runtime_attr_path=(str(runtime_ordinal),),
        )
    if _PLUGIN_STATE is not None:
        # The module-global claim state is single-threaded and non-reentrant.
        # A plugin lower() hook that re-triggered lowering would clobber the
        # outer state on its inner finally; fail loudly rather than silently
        # mis-resolve claims/plugin types (council round 8).
        raise LoweringError(
            "re-entrant plugin lowering detected: lower_function was called "
            "while another lowering was in progress"
        )
    _PLUGIN_STATE = _PluginLoweringState(
        claims={
            (claim.kind, claim.line, claim.column, claim.end_line, claim.end_column): claim
            for claim in function.plugin_claims
        },
        type_maps=plugin_types,
        imports=function.imports,
        external_native_registry=external_native_registry,
        caller_qualname=function.qualname,
    )
    try:
        args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        params = [ParamIR(name=arg.arg, type=_argument_type(function, arg)) for arg in args]
        return_type = _return_type(function, node)
        plugin_lowered = (
            bool(function.plugin_claims)
            or any(isinstance(param.type, RxtPluginType) for param in params)
            or isinstance(return_type, RxtPluginType)
        )
        return FunctionIR(
            name=function.name,
            qualname=function.qualname,
            module_name=function.module_name,
            params=params,
            return_type=return_type,
            body=lower_block(node.body, module, resolver),
            embedded=embedded,
            has_boundary_calls=bool(function.boundary_call_targets),
            plugin_lowered=plugin_lowered,
        )
    finally:
        _PLUGIN_STATE = None


def lower_top_level(
    top_level: TopLevelAnalysis,
    tree: ast.Module,
    module: ModuleAnalysis,
    resolver: FunctionResolver,
) -> FunctionIR:
    """Lower supported module top-level initialization into a synthetic ``FunctionIR``."""
    if top_level.export_value_type is None:
        raise LoweringError(
            f"missing export value type for top-level native init: {top_level.qualname}"
        )
    statements = lower_block(collect_native_top_level_statements(tree), module, resolver).statements
    statements.append(
        ReturnIR(
            DictIR(
                items=[(LiteralIR(name), NameIR(name)) for name in sorted(top_level.assigned_types)]
            )
        )
    )
    return FunctionIR(
        name=top_level.name,
        qualname=top_level.qualname,
        module_name=top_level.module_name,
        params=[],
        return_type=RxtDict(RxtStr(), type_from_string(top_level.export_value_type)),
        body=BlockIR(statements=statements),
    )


def lower_executable_module_initializer(
    top_level: TopLevelAnalysis,
    plan: ModuleInitIR,
    module: ModuleAnalysis,
    resolver: FunctionResolver,
) -> FunctionIR:
    """Lower one exact, pre-authorized initializer snapshot to ``Result<(), _>``.

    This does not reuse ``collect_native_top_level_statements``. It re-hashes
    and re-plans the same bytes, then consumes only the exact native statement
    indexes carried by ``ModuleInitIR``. That keeps report authorization and
    executable codegen on one source snapshot.
    """
    if plan.module_name != top_level.module_name:
        raise LoweringError(
            f"module-init plan does not match accepted top level: {top_level.qualname}"
        )
    source_path = Path(top_level.file_path)
    try:
        source_bytes = source_path.read_bytes()
    except OSError as error:
        raise LoweringError(
            f"module source is unavailable for executable initializer: {top_level.qualname}"
        ) from error
    if hashlib.sha256(source_bytes).hexdigest() != plan.source_sha256:
        raise LoweringError(
            f"module source changed after executable initializer planning: {top_level.qualname}"
        )

    # Reconstruct the plan from the exact bytes to defend against a malformed or
    # stale programmatic caller supplying valid source hash with different indexes.
    from rextio.analyzer.module_init import build_module_init_ir

    rebuilt = build_module_init_ir(
        source_bytes,
        module_name=plan.module_name,
        path=plan.path,
        is_package_init=plan.path == "__init__.py" or plan.path.endswith("/__init__.py"),
    )
    if rebuilt != plan:
        raise LoweringError(
            f"module-init plan does not match the executable source snapshot: {top_level.qualname}"
        )
    try:
        tree = ast.parse(source_bytes.decode("utf-8"), filename=plan.path)
    except (UnicodeDecodeError, SyntaxError) as error:
        raise LoweringError(
            f"module source cannot be parsed for executable initializer: {top_level.qualname}"
        ) from error

    indexes = tuple(
        statement_index
        for segment in plan.segments
        if segment.kind is ModuleInitSegmentKind.NATIVE
        for statement_index in segment.statement_indexes
    )
    if not indexes or any(index >= len(tree.body) for index in indexes):
        raise LoweringError(f"module-init statement indexes are unavailable: {top_level.qualname}")
    statements = [tree.body[index] for index in indexes]
    if any(
        not (
            isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
            and isinstance(statement.value, ast.Constant)
            and type(statement.value.value) in {bool, float, int, str}
        )
        for statement in statements
    ):
        raise LoweringError(
            "executable module initializer exceeded the scalar-literal assignment slice: "
            f"{top_level.qualname}"
        )

    lowered = lower_block(statements, module, resolver).statements
    lowered.append(ReturnIR(value=None))
    return FunctionIR(
        name=top_level.name,
        qualname=top_level.qualname,
        module_name=top_level.module_name,
        params=[],
        return_type=RxtNone(),
        body=BlockIR(statements=lowered),
    )


def _argument_type(function: FunctionAnalysis, arg: ast.arg) -> RxtType:
    if arg.annotation is not None:
        plugin_type = _plugin_annotation_type(arg.annotation)
        if plugin_type is not None:
            return plugin_type
        return type_from_annotation(arg.annotation)
    inferred = function.inferred_arg_types.get(arg.arg)
    if inferred is None:
        raise LoweringError(f"missing inferred type for argument: {function.qualname}.{arg.arg}")
    return type_from_string(inferred)


def _return_type(
    function: FunctionAnalysis, node: ast.FunctionDef | ast.AsyncFunctionDef
) -> RxtType:
    if node.returns is not None:
        plugin_type = _plugin_annotation_type(node.returns)
        if plugin_type is not None:
            return plugin_type
        return type_from_annotation(node.returns)
    if function.inferred_return_type is None:
        raise LoweringError(f"missing inferred return type for function: {function.qualname}")
    return type_from_string(function.inferred_return_type)


def _plugin_annotation_type(node: ast.AST) -> RxtPluginType | None:
    """Resolve an annotation node to a plugin type through the active state, or None.

    Tried BEFORE ``type_from_annotation`` (no exception juggling): only a
    Name/Attribute dotted chain can spell a plugin type, and the core table
    never claims a dotted plugin spelling, so plugin-first resolution cannot
    shadow a supported core annotation. The dotted spelling is resolved
    through the function's import map (head partition, like
    ``_resolve_import_alias`` in ``analyzer/call_resolution.py``), so both
    ``from rextio_numpy.types import F64Arr1`` and
    ``import rextio_numpy.types as t; t.F64Arr1`` reach the vocabulary entry.
    """
    state = _PLUGIN_STATE
    if state is None or state.type_maps is None:
        return None
    # A schema-parameterized plugin annotation ``Frame[Row]`` (plugin API 1.3)
    # resolves to the SAME plugin type as bare ``Frame``: the ``[Row]`` subscript
    # only carries the declared-schema association and never changes the type.
    if isinstance(node, ast.Subscript):
        node = node.value
    dotted = dotted_name(node)
    if dotted is None:
        return None
    head, separator, tail = dotted.partition(".")
    imported = state.imports.get(head)
    resolved = dotted if imported is None else (f"{imported}.{tail}" if separator else imported)
    return state.type_maps.by_spelling.get(resolved)


def _plugin_claim_ir(node: ast.AST, kind: str) -> PluginClaimIR | None:
    """Return the claim IR matching an AST node's kind and source span, or None.

    Claims are matched on (kind, start, end): the start position alone is
    ambiguous because a BinOp shares its (line, column) with its leftmost
    operand (`np.dot(a, b) * factor` puts the call and the enclosing binop at
    one start offset). The same matching also carries API-1.5 comparison claims.
    """
    state = _PLUGIN_STATE
    if state is None or not state.claims:
        return None
    lineno = getattr(node, "lineno", None)
    col_offset = getattr(node, "col_offset", None)
    if lineno is None or col_offset is None:
        return None
    claim = state.claims.get(
        (
            kind,
            lineno,
            col_offset,
            getattr(node, "end_lineno", None),
            getattr(node, "end_col_offset", None),
        )
    )
    if claim is None:
        return None
    return PluginClaimIR(
        plugin_id=claim.plugin_id,
        rule_id=claim.rule_id,
        kind=claim.kind,
        target=claim.target,
        operand_types=claim.operand_types,
        result_type=claim.result_type,
        operand_literals=claim.operand_literals,
        keywords=claim.keywords,
        expression=claim.expression,
        operand_mode=claim.operand_mode,
        receiver=claim.receiver,
        callables=claim.callables,
    )


def _function_node_key(function: FunctionAnalysis) -> str:
    if function.module_name and function.qualname.startswith(f"{function.module_name}."):
        return function.qualname[len(function.module_name) + 1 :]
    return function.qualname


def lower_block(
    statements: list[ast.stmt],
    module: ModuleAnalysis,
    resolver: FunctionResolver,
) -> BlockIR:
    """Lower a list of statements into a ``BlockIR``."""
    return BlockIR(
        statements=[lower_statement(statement, module, resolver) for statement in statements]
    )


def lower_statement(
    node: ast.stmt,
    module: ModuleAnalysis,
    resolver: FunctionResolver,
) -> StatementIR:
    """Lower a single statement AST node into a ``StatementIR``."""
    if isinstance(node, ast.Assign):
        if len(node.targets) != 1:
            raise LoweringError("multiple assignment targets are not supported")
        if isinstance(node.targets[0], ast.Subscript):
            subscript_target = node.targets[0]
            return DictSetIR(
                target=lower_name_target(subscript_target.value),
                key=lower_expr(subscript_target.slice, module, resolver),
                value=lower_expr(node.value, module, resolver),
            )
        return AssignIR(
            target=lower_name_target(node.targets[0]),
            value=lower_expr(node.value, module, resolver),
        )
    if isinstance(node, ast.AnnAssign):
        return AssignIR(
            target=lower_name_target(node.target),
            value=lower_expr(node.value, module, resolver),
            target_type=type_from_annotation(node.annotation),
        )
    if isinstance(node, ast.AugAssign):
        target = lower_name_target(node.target)
        return AssignIR(
            target=target,
            value=BinaryOpIR(
                left=target,
                op=lower_binary_op(node.op),
                right=lower_expr(node.value, module, resolver),
            ),
        )
    if isinstance(node, ast.Expr):
        if isinstance(node.value, ast.Call) and _is_append_call(node.value):
            append_call = node.value
            if not isinstance(append_call.func, ast.Attribute):
                raise LoweringError("append call target cannot be lowered")
            return AppendIR(
                target=lower_name_target(append_call.func.value),
                value=lower_expr(append_call.args[0], module, resolver),
            )
        if is_supported_effect_call(node.value, module.imports, module.logger_names):
            call = lower_expr(node.value, module, resolver)
            if not isinstance(call, CallIR):
                raise LoweringError("effect call did not lower to a call expression")
            return EffectCallIR(call=call)
        raise LoweringError(
            f"unsupported expression statement during IR lowering: {type(node.value).__name__}"
        )
    if isinstance(node, ast.Break):
        return BreakIR()
    if isinstance(node, ast.Continue):
        return ContinueIR()
    if isinstance(node, ast.Return):
        return ReturnIR(
            value=lower_expr(node.value, module, resolver) if node.value is not None else None
        )
    if isinstance(node, ast.If):
        return IfIR(
            condition=lower_expr(node.test, module, resolver),
            body=lower_block(node.body, module, resolver),
            orelse=lower_block(node.orelse, module, resolver),
        )
    if isinstance(node, ast.For):
        return ForIR(
            target=lower_loop_target(node.target),
            iterable=lower_expr(node.iter, module, resolver),
            body=lower_block(node.body, module, resolver),
            orelse=lower_block(node.orelse, module, resolver),
        )
    if isinstance(node, ast.While):
        return WhileIR(
            condition=lower_expr(node.test, module, resolver),
            body=lower_block(node.body, module, resolver),
            orelse=lower_block(node.orelse, module, resolver),
        )
    if isinstance(node, ast.Try):
        return TryIR(
            body=lower_block(node.body, module, resolver),
            handlers=tuple(
                ExceptHandlerIR(
                    exception=_handler_exception_name(handler),
                    body=lower_block(handler.body, module, resolver),
                )
                for handler in node.handlers
            ),
            finalbody=lower_block(node.finalbody, module, resolver),
        )
    raise LoweringError(f"unsupported statement during IR lowering: {type(node).__name__}")


def _handler_exception_name(handler: ast.ExceptHandler) -> str:
    """Return the built-in exception name an ``except`` clause catches.

    The analyzer has already restricted handlers to a single built-in exception
    ``ast.Name`` with no ``as`` binding, so this lowering is total for accepted
    functions.
    """
    if not isinstance(handler.type, ast.Name):
        raise LoweringError("except handler type must be a built-in exception name")
    return handler.type.id


def lower_expr(
    node: ast.AST | None,
    module: ModuleAnalysis,
    resolver: FunctionResolver,
) -> ExprIR:
    """Lower an expression AST node into an ``ExprIR`` (``None`` becomes a ``None`` literal)."""
    if node is None:
        return LiteralIR(None)
    if isinstance(node, ast.Constant):
        return LiteralIR(node.value)
    if isinstance(node, ast.Name):
        return NameIR(node.id)
    if isinstance(node, ast.Attribute):
        target = canonical_attribute_target(node, module.imports)
        if target in MATH_CONSTANT_TARGETS:
            if module.project_mutations.target_is_mutated(target):
                raise LoweringError(
                    f"stdlib constant target was mutated during module execution: {target}"
                )
            if not stdlib_receiver_is_proven_import(
                node,
                module.imports,
                project_modules=module.project_modules,
            ):
                # Defensive: the analyzer fails closed on a never-imported / shadowed
                # stdlib constant, so reaching here with an unproven receiver is a
                # bug — raise loudly rather than emit a stale `std::f64::consts::*`.
                raise LoweringError(
                    f"stdlib constant receiver is not a proven import: {ast.unparse(node)}"
                )
            return CallIR(function=target, args=[])
        raise LoweringError(f"unsupported attribute during IR lowering: {ast.unparse(node)}")
    if isinstance(node, ast.List):
        return ListIR(items=[lower_expr(item, module, resolver) for item in node.elts])
    if isinstance(node, ast.ListComp):
        return ListComprehensionIR(
            item=lower_expr(node.elt, module, resolver),
            generators=lower_comprehension_generators(node.generators, module, resolver),
        )
    if isinstance(node, ast.Tuple):
        return TupleIR(items=[lower_expr(item, module, resolver) for item in node.elts])
    if isinstance(node, ast.Dict):
        if any(key is None for key in node.keys):
            raise LoweringError("dictionary unpacking cannot be lowered")
        return DictIR(
            items=[
                (lower_expr(key, module, resolver), lower_expr(value, module, resolver))
                for key, value in zip(node.keys, node.values, strict=True)
                if key is not None
            ]
        )
    if isinstance(node, ast.DictComp):
        return DictComprehensionIR(
            key=lower_expr(node.key, module, resolver),
            value=lower_expr(node.value, module, resolver),
            generators=lower_comprehension_generators(node.generators, module, resolver),
        )
    if isinstance(node, ast.Set):
        return SetIR(items=[lower_expr(item, module, resolver) for item in node.elts])
    if isinstance(node, ast.SetComp):
        return SetComprehensionIR(
            item=lower_expr(node.elt, module, resolver),
            generators=lower_comprehension_generators(node.generators, module, resolver),
        )
    if isinstance(node, ast.BinOp):
        claim = _plugin_claim_ir(node, "binop")
        if claim is not None:
            # A plugin-claimed binop skips core operator validation; codegen
            # hands the whole site to the claiming plugin's lower(). The op
            # label comes from the CLAIM, not lower_binary_op: a claimed
            # operator (e.g. `@`) need not be in core's operator map, and
            # calling the core lowering here failed generate for a site check
            # had already accepted (council round 7).
            return BinaryOpIR(
                left=lower_expr(node.left, module, resolver),
                op=claim.target,
                right=lower_expr(node.right, module, resolver),
                claim=claim,
            )
        return BinaryOpIR(
            left=lower_expr(node.left, module, resolver),
            op=lower_binary_op(node.op),
            right=lower_expr(node.right, module, resolver),
        )
    if isinstance(node, ast.BoolOp):
        return _lower_bool_op(node, module, resolver)
    if isinstance(node, ast.UnaryOp):
        return UnaryOpIR(
            op=lower_unary_op(node.op),
            value=lower_expr(node.operand, module, resolver),
        )
    if isinstance(node, ast.Compare):
        claim = _plugin_claim_ir(node, "compare")
        return CompareIR(
            left=lower_expr(node.left, module, resolver),
            ops=[lower_compare_op(op) for op in node.ops],
            comparators=[
                lower_expr(comparator, module, resolver) for comparator in node.comparators
            ],
            claim=claim,
        )
    if isinstance(node, ast.Call):
        claim = _plugin_claim_ir(node, "call")
        if claim is not None:
            # A plugin-claimed call skips the normal target resolution: the
            # claim carries the dotted target, and keyword arguments are
            # never claimed, so the positional args are the whole site. For a
            # method claim (``obj.method(...)``) the receiver value is lowered
            # separately onto ``CallIR.receiver`` — it is NOT a positional arg —
            # so codegen can evaluate it exactly once, in Python order, before
            # the operands (plugin API 1.3).
            receiver_expr: ExprIR | None = None
            if claim.receiver is not None and isinstance(node.func, ast.Attribute):
                receiver_expr = lower_expr(node.func.value, module, resolver)
            return CallIR(
                function=claim.target,
                args=[lower_expr(arg, module, resolver) for arg in node.args],
                claim=claim,
                receiver=receiver_expr,
            )
        target = canonical_call_target(node, module.imports, module.logger_names)
        if target is None:
            target = dotted_name(node.func)
        if target is None:
            raise LoweringError("dynamic calls cannot be lowered to Rextio IR")
        if target in LOGGING_CANONICAL_TARGETS.values():
            _require_logging_call_provenance(node, module)
        if target in IMPORT_QUALIFIED_STDLIB_TARGETS and not stdlib_receiver_is_proven_import(
            node.func,
            module.imports,
            project_modules=module.project_modules,
        ):
            # Defensive: the analyzer fails closed on a never-imported / shadowed
            # stdlib call, so reaching here with an unproven receiver is a bug —
            # raise loudly rather than emit a stale static stdlib call.
            raise LoweringError(f"stdlib call receiver is not a proven import: {ast.unparse(node)}")
        if module.project_mutations.target_is_mutated(target):
            raise LoweringError(
                f"statically lowered call target was mutated during module execution: {target}"
            )
        args = _lower_call_args(node, target, module, resolver)
        external_target: str | None = None
        if (
            _PLUGIN_STATE is not None
            and _PLUGIN_STATE.external_native_registry is not None
            and _PLUGIN_STATE.caller_qualname is not None
        ):
            external_target = _PLUGIN_STATE.external_native_registry.resolve(
                _PLUGIN_STATE.caller_qualname,
                node.lineno,
                node.col_offset,
            )
        return CallIR(
            function=(
                external_target
                if external_target is not None
                else _lower_call_target(target, module, resolver)
            ),
            args=args,
        )
    if isinstance(node, ast.Subscript):
        return IndexIR(
            value=lower_expr(node.value, module, resolver),
            index=lower_expr(node.slice, module, resolver),
        )
    if isinstance(node, ast.NamedExpr):
        return NamedExprIR(
            target=lower_name_target(node.target),
            value=lower_expr(node.value, module, resolver),
        )
    raise LoweringError(f"unsupported expression during IR lowering: {type(node).__name__}")


def _require_logging_call_provenance(node: ast.Call, module: ModuleAnalysis) -> None:
    """Defensively prove the receiver erased by native logging lowering.

    Both ``logging.info(...)`` and ``from logging import info; info(...)`` must
    resolve through the module's final import map to the genuine stdlib module.
    ``logger.info(...)`` is the one exception: the receiver must be an exact
    logger name collected from a clean ``logging.getLogger`` assignment, and
    neither that object nor its process-global, name-keyed logger cache group
    may have been mutated during module execution.

    The analyzer enforces the same rules before accepting a function.  Keeping
    the checks here is intentional defense in depth: a stale or malformed
    accepted record must fail loudly instead of erasing a project-local
    ``logging`` receiver and emitting Rust logging calls.
    """
    func = node.func
    if (
        isinstance(func, ast.Attribute)
        and isinstance(func.value, ast.Name)
        and func.value.id in module.logger_names
    ):
        receiver = func.value.id
        guarded_targets = (
            "logging.getLogger",
            *module.logger_group_targets.get(
                receiver,
                (logger_group_target(module.module_name),),
            ),
            logger_object_target(module.module_name, receiver),
        )
        mutated = next(
            (
                candidate
                for candidate in guarded_targets
                if module.project_mutations.target_is_mutated(candidate)
            ),
            None,
        )
        if mutated is not None:
            raise LoweringError(
                f"logger receiver provenance was invalidated by module execution: {mutated}"
            )
        return

    if not stdlib_receiver_is_proven_import(
        func,
        module.imports,
        project_modules=module.project_modules,
    ):
        raise LoweringError(
            f"logging call receiver is not a proven stdlib import: {ast.unparse(node)}"
        )


def lower_name_target(node: ast.AST) -> NameIR:
    """Lower an assignment target that must be a bare name into a ``NameIR``."""
    if not isinstance(node, ast.Name):
        raise LoweringError(f"unsupported assignment target: {type(node).__name__}")
    return NameIR(node.id)


def lower_loop_target(node: ast.AST) -> TargetIR:
    """Lower a ``for``-loop target (a name or a tuple of names) into a ``TargetIR``."""
    if isinstance(node, ast.Name):
        return NameIR(node.id)
    if isinstance(node, ast.Tuple):
        items = [lower_name_target(item) for item in node.elts]
        return TupleTargetIR(items=items)
    raise LoweringError(f"unsupported for-loop target: {type(node).__name__}")


def lower_comprehension_generators(
    generators: list[ast.comprehension],
    module: ModuleAnalysis,
    resolver: FunctionResolver,
) -> list[ComprehensionGeneratorIR]:
    """Lower the ``for``/``if`` clauses of a comprehension into ``ComprehensionGeneratorIR``."""
    lowered: list[ComprehensionGeneratorIR] = []
    for generator in generators:
        if generator.is_async:
            raise LoweringError("async comprehensions cannot be lowered")
        lowered.append(
            ComprehensionGeneratorIR(
                target=lower_loop_target(generator.target),
                iterable=lower_expr(generator.iter, module, resolver),
                conditions=[lower_expr(condition, module, resolver) for condition in generator.ifs],
            )
        )
    return lowered


def lower_binary_op(node: ast.operator) -> str:
    """Return the Rust operator string for a binary AST operator."""
    if isinstance(node, ast.Add):
        return "+"
    if isinstance(node, ast.Sub):
        return "-"
    if isinstance(node, ast.Mult):
        return "*"
    if isinstance(node, ast.Div):
        return "/"
    if isinstance(node, ast.Mod):
        return "%"
    raise LoweringError(f"unsupported binary operator: {type(node).__name__}")


def lower_unary_op(node: ast.unaryop) -> str:
    """Return the Rust operator string for a unary AST operator."""
    if isinstance(node, ast.USub):
        return "-"
    if isinstance(node, ast.Not):
        return "not"
    raise LoweringError(f"unsupported unary operator: {type(node).__name__}")


def lower_compare_op(node: ast.cmpop) -> str:
    """Return the Rust operator string for a comparison AST operator."""
    if isinstance(node, ast.Eq):
        return "=="
    if isinstance(node, ast.NotEq):
        return "!="
    if isinstance(node, ast.Lt):
        return "<"
    if isinstance(node, ast.LtE):
        return "<="
    if isinstance(node, ast.Gt):
        return ">"
    if isinstance(node, ast.GtE):
        return ">="
    if isinstance(node, ast.Is):
        return "=="
    if isinstance(node, ast.IsNot):
        return "!="
    raise LoweringError(f"unsupported comparison operator: {type(node).__name__}")


def _lower_call_target(
    target: str,
    module: ModuleAnalysis,
    resolver: FunctionResolver,
) -> str:
    # A same-module project function shadows a builtin/stdlib spelling of the same
    # name (``def abs`` -> a bare ``abs(x)`` calls the sibling, not the builtin), so
    # resolve the project function FIRST and only fall back to the builtin
    # short-circuit when no project function is reached — otherwise codegen would
    # emit the checked builtin instead of the sibling native symbol that analysis
    # typed and that Python actually calls.
    resolved = resolver.resolve(module, target)
    if resolved.function is not None:
        return resolved.function.qualname
    if target in {
        "abs",
        "len",
        "max",
        "min",
        "range",
        "sum",
        "enumerate",
        "zip",
        "math.floor",
        "math.cos",
        "math.sin",
        "math.sqrt",
        *COMMON_DIRECT_RUST_CALLS,
    }:
        return target
    return resolved.resolved_target


def _lower_call_args(
    node: ast.Call,
    target: str,
    module: ModuleAnalysis,
    resolver: FunctionResolver,
) -> list[ExprIR]:
    if (
        target in STR_METHOD_TARGETS
        or target in LIST_METHOD_TARGETS
        or target in BYTES_METHOD_TARGETS
    ):
        if not isinstance(node.func, ast.Attribute):
            raise LoweringError(f"{target} receiver cannot be lowered")
        return [
            lower_expr(node.func.value, module, resolver),
            *[lower_expr(arg, module, resolver) for arg in node.args],
        ]
    if target in HASHLIB_CHAIN_TARGETS:
        if not isinstance(node.func, ast.Attribute) or not isinstance(node.func.value, ast.Call):
            raise LoweringError(f"{target} inner call cannot be lowered")
        return [lower_expr(arg, module, resolver) for arg in node.func.value.args]
    return [lower_expr(arg, module, resolver) for arg in node.args]


def _is_append_call(node: ast.Call) -> bool:
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "append"
        and isinstance(node.func.value, ast.Name)
        and len(node.args) == 1
        and not node.keywords
    )


def _lower_bool_op(
    node: ast.BoolOp,
    module: ModuleAnalysis,
    resolver: FunctionResolver,
) -> ExprIR:
    if not node.values:
        raise LoweringError("empty boolean operation cannot be lowered")
    op = "and" if isinstance(node.op, ast.And) else "or"
    current = lower_expr(node.values[0], module, resolver)
    for value in node.values[1:]:
        current = BinaryOpIR(left=current, op=op, right=lower_expr(value, module, resolver))
    return current


@dataclass(frozen=True)
class _FunctionNodeOrigin:
    node: ast.FunctionDef | ast.AsyncFunctionDef
    enclosing_class: ast.ClassDef | None = None


@dataclass(frozen=True)
class _FunctionSource:
    origins: dict[str, _FunctionNodeOrigin]
    bindings: ModuleBindings


def _require_exact_function_origin(
    function: FunctionAnalysis,
    origin: _FunctionNodeOrigin,
    analysis: ProjectAnalysis,
    current_bindings: ModuleBindings,
) -> None:
    """Defensively prove an accepted record still names its exact source def."""
    node = origin.node
    if (node.lineno, node.col_offset) != (function.line, function.column):
        raise LoweringError(
            f"accepted function origin does not match the source AST: {function.qualname}"
        )
    if (
        function.source_ast_fingerprint is None
        or executable_ast_fingerprint(node) != function.source_ast_fingerprint
    ):
        raise LoweringError(
            f"accepted function source AST changed after analysis: {function.qualname}"
        )
    if analysis.project_mutations.target_is_mutated(function.qualname):
        raise LoweringError(
            f"accepted function target was mutated during module execution: {function.qualname}"
        )
    analyzed_bindings = analysis.project_bindings.for_module(function.module_name)
    marker_reason = native_marker_identity_reason(
        node, current_bindings, explicitly_marked=function.explicitly_marked
    ) or native_marker_identity_reason(
        node, analyzed_bindings, explicitly_marked=function.explicitly_marked
    )
    if marker_reason is not None:
        raise LoweringError(
            f"accepted function native marker identity is unproven: "
            f"{function.qualname}: {marker_reason}"
        )
    if function.enclosing_class_name is None:
        if origin.enclosing_class is not None or not definition_is_final(
            current_bindings,
            function.name,
            BindingKind.FUNCTION,
            function.line,
            function.column,
        ):
            raise LoweringError(
                f"accepted function is not its module's exact final binding: {function.qualname}"
            )
        return
    class_node = origin.enclosing_class
    if (
        class_node is None
        or class_node.name != function.enclosing_class_name
        or (class_node.lineno, class_node.col_offset)
        != (function.enclosing_class_line, function.enclosing_class_column)
        or not definition_is_final(
            current_bindings,
            class_node.name,
            BindingKind.CLASS,
            class_node.lineno,
            class_node.col_offset,
        )
    ):
        raise LoweringError(
            f"accepted method does not belong to the exact final class: {function.qualname}"
        )
    class_reason = class_construction_stability_reason(
        class_node,
        current_bindings,
        project_mutations=analysis.project_mutations,
    ) or class_construction_stability_reason(
        class_node,
        analyzed_bindings,
        project_mutations=analysis.project_mutations,
    )
    if class_reason is not None:
        raise LoweringError(
            f"accepted method class construction is unproven: {function.qualname}: {class_reason}"
        )
    outer_tree = ast.parse(
        Path(function.file_path).read_text(encoding="utf-8"), filename=function.file_path
    )
    class_bindings = build_module_bindings(
        ast.Module(body=class_node.body, type_ignores=[]),
        function.module_name,
        trusted_marker_sites=current_bindings.proven_marker_sites,
        trusted_annotation_targets=current_bindings.trusted_annotation_targets,
        trusted_function_bindings={
            statement.name: statement
            for statement in outer_tree.body
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
            and not statement.decorator_list
            and definition_is_final(
                current_bindings,
                statement.name,
                BindingKind.FUNCTION,
                statement.lineno,
                statement.col_offset,
            )
        },
    )
    if not definition_is_final(
        class_bindings,
        function.name,
        BindingKind.FUNCTION,
        function.line,
        function.column,
    ):
        raise LoweringError(
            f"accepted method is not the class body's exact final binding: {function.qualname}"
        )


def _function_nodes(
    path: Path,
    module_name: str,
    analysis: ProjectAnalysis,
) -> _FunctionSource:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    nodes: dict[str, _FunctionNodeOrigin] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            nodes[node.name] = _FunctionNodeOrigin(node)
        elif isinstance(node, ast.ClassDef):
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    nodes[f"{node.name}.{child.name}"] = _FunctionNodeOrigin(child, node)
    project_modules = {name.split(".", 1)[0] for name in analysis.project_bindings.by_module}
    return _FunctionSource(
        nodes,
        build_module_bindings(
            tree,
            module_name,
            project_mutations=analysis.project_mutations,
            project_modules=project_modules,
            trusted_annotation_targets=analysis.project_bindings.for_module(
                module_name
            ).trusted_annotation_targets,
        ),
    )


def _module_tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _module_for_top_level(
    analysis: ProjectAnalysis,
    top_level: TopLevelAnalysis,
) -> ModuleAnalysis | None:
    for module in analysis.modules:
        if module.module_name == top_level.module_name:
            return module
    return None
