"""Lowering of accepted analyzer results into Rextio IR.

Walks the AST of each accepted native function (and supported top-level module code)
and produces the ``ModuleIR`` the codegen backends consume. Anything the lowering
cannot represent raises ``LoweringError`` — by this stage the analyzer has already
accepted the input, so a failure here is an internal invariant violation, not user error.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from rextio.analyzer.call_resolution import FunctionResolver
from rextio.analyzer.common_calls import (
    COMMON_DIRECT_RUST_CALLS,
    HASHLIB_CHAIN_TARGETS,
    LIST_METHOD_TARGETS,
    MATH_CONSTANT_TARGETS,
    STR_METHOD_TARGETS,
    BYTES_METHOD_TARGETS,
    canonical_attribute_target,
    canonical_call_target,
    is_supported_effect_call,
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
from rextio.codegen.native_names import runtime_original_name
from rextio.fallback.module_copy import fallback_module_name
from rextio.ir.module import module_from_functions
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
from rextio.ir.types import RxtDict, RxtPluginType, RxtPyObject, RxtStr, RxtType


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
    claims: dict[tuple[str, int, int, int | None, int | None], PluginClaim] = field(default_factory=dict)
    type_maps: PluginTypeMaps | None = None
    # The function's resolved import map (visible name -> dotted target),
    # used to resolve plugin annotation spellings like the claim engine does.
    imports: dict[str, str] = field(default_factory=dict)


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
) -> ModuleIR:
    """Lower every accepted native function (and embedding candidate, if included) to a module IR."""
    functions: list[FunctionIR] = []
    nodes_by_file: dict[str, dict[str, ast.FunctionDef | ast.AsyncFunctionDef]] = {}
    module_trees_by_file: dict[str, ast.Module] = {}
    resolver = FunctionResolver(analysis)
    for function in analysis.accepted_native_functions:
        functions.append(
            _lower_analysis_function(
                function, analysis, nodes_by_file, resolver, plugin_types=plugin_types
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
                )
            )
    for top_level in analysis.accepted_native_top_levels:
        tree = module_trees_by_file.setdefault(
            top_level.file_path,
            _module_tree(Path(top_level.file_path)),
        )
        module = _module_for_top_level(analysis, top_level)
        if module is None:
            raise LoweringError(f"module was not found for accepted top level: {top_level.qualname}")
        functions.append(lower_top_level(top_level, tree, module, resolver))
    return module_from_functions(functions)


def _lower_analysis_function(
    function: FunctionAnalysis,
    analysis: ProjectAnalysis,
    nodes_by_file: dict[str, dict[str, ast.FunctionDef | ast.AsyncFunctionDef]],
    resolver: FunctionResolver,
    *,
    embedded: bool = False,
    plugin_types: PluginTypeMaps | None = None,
) -> FunctionIR:
    nodes = nodes_by_file.setdefault(function.file_path, _function_nodes(Path(function.file_path)))
    node = nodes.get(_function_node_key(function))
    if node is None:
        kind = "embedding candidate" if embedded else "accepted native function"
        raise LoweringError(f"{kind} was not found: {function.qualname}")
    module = analysis.module_for_function(function)
    if module is None:
        raise LoweringError(f"module was not found for function: {function.qualname}")
    return lower_function(
        function, node, module, resolver, embedded=embedded, plugin_types=plugin_types
    )


def lower_function(
    function: FunctionAnalysis,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    module: ModuleAnalysis,
    resolver: FunctionResolver,
    *,
    embedded: bool = False,
    plugin_types: PluginTypeMaps | None = None,
) -> FunctionIR:
    """Lower a single analyzed native function (signature + body) to a ``FunctionIR``."""
    global _PLUGIN_STATE
    if function.native_runtime_semantics:
        return FunctionIR(
            name=function.name,
            qualname=function.qualname,
            module_name=function.module_name,
            params=[],
            return_type=RxtPyObject(),
            body=BlockIR(statements=[]),
            native_runtime_semantics=True,
            embedded=embedded,
            runtime_fallback_module=_runtime_fallback_module(module),
            runtime_attr_path=(runtime_original_name(function.qualname),),
        )
    _PLUGIN_STATE = _PluginLoweringState(
        claims={
            (claim.kind, claim.line, claim.column, claim.end_line, claim.end_column): claim
            for claim in function.plugin_claims
        },
        type_maps=plugin_types,
        imports=function.imports,
    )
    try:
        args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        params = [
            ParamIR(name=arg.arg, type=_argument_type(function, arg))
            for arg in args
        ]
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
        raise LoweringError(f"missing export value type for top-level native init: {top_level.qualname}")
    statements = lower_block(collect_native_top_level_statements(tree), module, resolver).statements
    statements.append(
        ReturnIR(
            DictIR(
                items=[
                    (LiteralIR(name), NameIR(name))
                    for name in sorted(top_level.assigned_types)
                ]
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


def _return_type(function: FunctionAnalysis, node: ast.FunctionDef | ast.AsyncFunctionDef) -> RxtType:
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
    one start offset).
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
    )


def _runtime_fallback_module(module: ModuleAnalysis) -> str:
    name = fallback_module_name(module)
    if not module.module_name:
        return name
    if Path(module.file_path).name == "__init__.py":
        return f"{module.module_name}.{name}"
    parent, separator, _leaf = module.module_name.rpartition(".")
    if separator:
        return f"{parent}.{name}"
    return name


def _function_node_key(function: FunctionAnalysis) -> str:
    if function.module_name and function.qualname.startswith(f"{function.module_name}."):
        return function.qualname[len(function.module_name) + 1:]
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
        raise LoweringError(f"unsupported expression statement during IR lowering: {type(node.value).__name__}")
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
        return CompareIR(
            left=lower_expr(node.left, module, resolver),
            ops=[lower_compare_op(op) for op in node.ops],
            comparators=[lower_expr(comparator, module, resolver) for comparator in node.comparators],
        )
    if isinstance(node, ast.Call):
        claim = _plugin_claim_ir(node, "call")
        if claim is not None:
            # A plugin-claimed call skips the normal target resolution: the
            # claim carries the dotted target, and keyword arguments are
            # never claimed, so the positional args are the whole site.
            return CallIR(
                function=claim.target,
                args=[lower_expr(arg, module, resolver) for arg in node.args],
                claim=claim,
            )
        target = canonical_call_target(node, module.imports, module.logger_names)
        if target is None:
            target = dotted_name(node.func)
        if target is None:
            raise LoweringError("dynamic calls cannot be lowered to Rextio IR")
        args = _lower_call_args(node, target, module, resolver)
        return CallIR(
            function=_lower_call_target(target, module, resolver),
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
    resolved = resolver.resolve(module, target)
    if resolved.function is None:
        return resolved.resolved_target
    return resolved.function.qualname


def _lower_call_args(
    node: ast.Call,
    target: str,
    module: ModuleAnalysis,
    resolver: FunctionResolver,
) -> list[ExprIR]:
    if target in STR_METHOD_TARGETS or target in LIST_METHOD_TARGETS or target in BYTES_METHOD_TARGETS:
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


def _function_nodes(path: Path) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    nodes: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            nodes[node.name] = node
        elif isinstance(node, ast.ClassDef):
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    nodes[f"{node.name}.{child.name}"] = child
    return nodes


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
