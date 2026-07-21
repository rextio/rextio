"""Strict C5.2 linkage for signed, exact external scalar source.

The registry is deliberately separate from :class:`ProjectAnalysis`: external
modules never become project modules or Python exports.  It proves direct,
final import call sites and re-lowers only the reached exact-byte helpers as
private Rust functions.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath

from rextio.analyzer.call_resolution import FunctionResolver
from rextio.analyzer.executable_identity import executable_ast_fingerprint
from rextio.analyzer.final_bindings import (
    BindingKind,
    ProjectBindings,
    build_module_bindings,
)
from rextio.analyzer.models import (
    CallSite,
    FunctionAnalysis,
    ModuleAnalysis,
    ProjectAnalysis,
)
from rextio.analyzer.unsupported_patterns import validate_native_function
from rextio.ir.lowering import LoweringError, lower_function
from rextio.ir.nodes import FunctionIR
from rextio.ir.types import normalize_type_name
from rextio.source.external import MAX_FILE_BYTES
from rextio.source.external_analysis import (
    EXTERNAL_FUNCTION_IR_DOMAIN,
    ExternalFunctionBinding,
    ExternalSourceNativePlan,
    analyze_external_source_snapshot,
)


class ExternalLinkageError(ValueError):
    """One external call or exact-byte helper failed the strict linkage gate."""


_SAFE_DOTTED_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")
_SAFE_DISTRIBUTION = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")
_SAFE_VERSION = re.compile(r"[A-Za-z0-9]+(?:[._+-][A-Za-z0-9]+)*")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_SCALAR_TYPES = frozenset({"bool", "float", "int", "str"})


@dataclass(frozen=True, slots=True)
class ExternalLinkedCall:
    """One project call site proven to target one exact external helper."""

    caller_qualname: str
    line: int
    column: int
    target: str
    import_head: str
    import_target: str
    import_line: int
    import_column: int
    import_order: int
    caller_ast_fingerprint: str
    argument_types: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            type(self.caller_qualname) is not str
            or _SAFE_DOTTED_NAME.fullmatch(self.caller_qualname) is None
            or type(self.target) is not str
            or _SAFE_DOTTED_NAME.fullmatch(self.target) is None
            or type(self.import_head) is not str
            or not self.import_head.isascii()
            or not self.import_head.isidentifier()
            or type(self.import_target) is not str
            or _SAFE_DOTTED_NAME.fullmatch(self.import_target) is None
            or type(self.line) is not int
            or self.line < 1
            or type(self.column) is not int
            or self.column < 0
            or type(self.import_line) is not int
            or self.import_line < 1
            or type(self.import_column) is not int
            or self.import_column < 0
            or type(self.import_order) is not int
            or self.import_order < 0
            or type(self.caller_ast_fingerprint) is not str
            or not self.caller_ast_fingerprint
            or len(self.caller_ast_fingerprint) > 1_048_576
            or "\x00" in self.caller_ast_fingerprint
            or type(self.argument_types) is not tuple
            or any(value not in _SCALAR_TYPES for value in self.argument_types)
        ):
            raise ValueError("external linked call identity is invalid")


@dataclass(frozen=True, slots=True)
class ExternalNativeRegistry:
    """Closed call-site registry plus reachable private external Rust IR."""

    package: str
    distribution: str
    version: str
    linked_calls: tuple[ExternalLinkedCall, ...]
    private_functions: tuple[FunctionIR, ...]

    def __post_init__(self) -> None:
        calls = tuple(self.linked_calls)
        functions = tuple(self.private_functions)
        if (
            type(self.package) is not str
            or _SAFE_DOTTED_NAME.fullmatch(self.package) is None
            or type(self.distribution) is not str
            or _SAFE_DISTRIBUTION.fullmatch(self.distribution) is None
            or type(self.version) is not str
            or _SAFE_VERSION.fullmatch(self.version) is None
            or type(self.linked_calls) is not tuple
            or type(self.private_functions) is not tuple
            or not all(type(item) is ExternalLinkedCall for item in calls)
            or not all(type(item) is FunctionIR for item in functions)
        ):
            raise ValueError("external native registry identity is invalid")
        if not calls or not functions:
            raise ValueError("external native registry must have reachable linkage")
        if calls != tuple(
            sorted(calls, key=lambda item: (item.caller_qualname, item.line, item.column))
        ):
            raise ValueError("external linked calls are not canonical")
        if len({(item.caller_qualname, item.line, item.column) for item in calls}) != len(calls):
            raise ValueError("external linked call sites are duplicated")
        if functions != tuple(sorted(functions, key=lambda item: item.qualname)):
            raise ValueError("external private functions are not canonical")
        if any(not function.embedded for function in functions):
            raise ValueError("external functions must be private embedded functions")
        targets = {item.target for item in calls}
        function_names = {item.qualname for item in functions}
        if targets != function_names or any(
            not target.startswith(f"{self.package}.") for target in targets
        ):
            raise ValueError("external registry linkage coverage is invalid")

    def resolve(self, caller_qualname: str, line: int, column: int) -> str | None:
        """Resolve one already-proven project call site without spelling guesses."""
        for call in self.linked_calls:
            if (call.caller_qualname, call.line, call.column) == (
                caller_qualname,
                line,
                column,
            ):
                return call.target
        return None

    def resolve_for(
        self,
        module: ModuleAnalysis,
        function: FunctionAnalysis,
        call: CallSite,
    ) -> str | None:
        """Revalidate one call against freshly analyzed source and bindings."""
        linked = next(
            (
                item
                for item in self.linked_calls
                if (item.caller_qualname, item.line, item.column)
                == (function.qualname, call.line, call.column)
            ),
            None,
        )
        if linked is None or module.module_bindings is None:
            return None
        final = module.module_bindings.lookup(linked.import_head)
        current_types = function.call_arg_types.get((call.line, call.column), ())
        normalized_types = tuple(
            normalize_type_name(value) if value is not None else "" for value in current_types
        )
        if (
            function.source_ast_fingerprint != linked.caller_ast_fingerprint
            or call.target != linked.target
            or linked.import_head in function.local_binding_names
            or module.imports.get(linked.import_head) != linked.import_target
            or final.kind is not BindingKind.IMPORT
            or final.target != linked.import_target
            or final.line != linked.import_line
            or final.column != linked.import_column
            or final.order != linked.import_order
            or normalized_types != linked.argument_types
            or analysis_target_is_mutated(module, linked.target)
        ):
            return None
        return linked.target

    def require_fresh_analysis(self, analysis: ProjectAnalysis) -> None:
        """Fail unless every registered site survives one fresh strict analysis."""
        modules = {module.module_name: module for module in analysis.modules}
        functions = {
            function.qualname: (module, function)
            for module in analysis.modules
            for function in module.functions
        }
        for linked in self.linked_calls:
            entry = functions.get(linked.caller_qualname)
            if entry is None:
                raise ExternalLinkageError("external-linkage-project-analysis-stale")
            module, function = entry
            try:
                tree = _read_project_tree(module)
                _require_no_external_value_escape(
                    tree,
                    targets=frozenset(item.target for item in self.linked_calls),
                    imports=module.imports,
                )
            except ExternalLinkageError as error:
                raise ExternalLinkageError("external-linkage-project-analysis-stale") from error
            function_name_count = sum(
                1
                for node in tree.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and f"{module.module_name}.{node.name}" == linked.caller_qualname
            )
            call = next(
                (
                    item
                    for item in function.calls
                    if (item.line, item.column) == (linked.line, linked.column)
                ),
                None,
            )
            if (
                modules.get(module.module_name) is not module
                or function_name_count != 1
                or not function.accepted
                or call is None
                or self.resolve_for(module, function, call) != linked.target
            ):
                raise ExternalLinkageError("external-linkage-project-analysis-stale")


@dataclass(frozen=True, slots=True)
class ExternalRuntimeCallable:
    """Exact callable identity checked when the generated extension imports."""

    name: str
    qualname: str
    first_line: int

    def __post_init__(self) -> None:
        if (
            type(self.name) is not str
            or not self.name.isascii()
            or not self.name.isidentifier()
            or type(self.qualname) is not str
            or _SAFE_DOTTED_NAME.fullmatch(self.qualname) is None
            or type(self.first_line) is not int
            or self.first_line < 1
        ):
            raise ValueError("external runtime callable identity is invalid")


@dataclass(frozen=True, slots=True)
class ExternalRuntimeModule:
    """Exact installed module source and reached callable identities."""

    module_name: str
    source_member: str
    source_sha256: str
    source_size: int
    callables: tuple[ExternalRuntimeCallable, ...]

    def __post_init__(self) -> None:
        path = (
            PurePosixPath(self.source_member)
            if type(self.source_member) is str
            else PurePosixPath(".")
        )
        if (
            type(self.module_name) is not str
            or _SAFE_DOTTED_NAME.fullmatch(self.module_name) is None
            or type(self.source_member) is not str
            or not self.source_member.endswith(".py")
            or path.is_absolute()
            or path.as_posix() != self.source_member
            or any(part in {"", ".", ".."} for part in path.parts)
            or type(self.source_sha256) is not str
            or _SHA256.fullmatch(self.source_sha256) is None
            or type(self.source_size) is not int
            or not 1 <= self.source_size <= MAX_FILE_BYTES
            or type(self.callables) is not tuple
            or not self.callables
            or not all(type(item) is ExternalRuntimeCallable for item in self.callables)
            or self.callables != tuple(sorted(self.callables, key=lambda item: item.qualname))
            or len({item.qualname for item in self.callables}) != len(self.callables)
            or any(item.qualname != f"{self.module_name}.{item.name}" for item in self.callables)
        ):
            raise ValueError("external runtime module identity is invalid")


@dataclass(frozen=True, slots=True)
class ExternalRuntimeGuard:
    """Frozen runtime guard material for one exact external distribution."""

    distribution: str
    version: str
    modules: tuple[ExternalRuntimeModule, ...]

    def __post_init__(self) -> None:
        if (
            type(self.distribution) is not str
            or _SAFE_DISTRIBUTION.fullmatch(self.distribution) is None
            or type(self.version) is not str
            or _SAFE_VERSION.fullmatch(self.version) is None
            or type(self.modules) is not tuple
            or not self.modules
            or not all(type(item) is ExternalRuntimeModule for item in self.modules)
            or self.modules != tuple(sorted(self.modules, key=lambda item: item.module_name))
            or len({item.module_name for item in self.modules}) != len(self.modules)
        ):
            raise ValueError("external runtime guard modules are invalid")


def build_external_native_registry(
    analysis: ProjectAnalysis,
    plans: tuple[ExternalSourceNativePlan, ...],
    *,
    package: str,
    distribution: str,
    version: str,
) -> ExternalNativeRegistry:
    """Prove direct final aliases and lower exactly the reached helpers.

    The input plans must all be fresh results for the same pinned distribution.
    No external module is inserted into ``analysis.modules``.
    """
    if type(analysis) is not ProjectAnalysis or type(plans) is not tuple or not plans:
        raise ExternalLinkageError("external-linkage-input-invalid")
    if not all(type(plan) is ExternalSourceNativePlan for plan in plans):
        raise ExternalLinkageError("external-linkage-plan-invalid")
    if any(
        module.module_name == package or module.module_name.startswith(f"{package}.")
        for module in analysis.modules
    ):
        raise ExternalLinkageError("external-linkage-project-shadow")

    bindings: dict[str, tuple[ExternalSourceNativePlan, ExternalFunctionBinding]] = {}
    for plan in plans:
        snapshot = plan.snapshot.module
        if (
            snapshot.distribution != distribution
            or snapshot.version != version
            or not (
                snapshot.module_name == package or snapshot.module_name.startswith(f"{package}.")
            )
        ):
            raise ExternalLinkageError("external-linkage-identity-mismatch")
        if analyze_external_source_snapshot(plan.snapshot) != plan:
            raise ExternalLinkageError("external-linkage-analysis-stale")
        for binding in plan.functions:
            if binding.qualname in bindings:
                raise ExternalLinkageError("external-linkage-function-duplicate")
            bindings[binding.qualname] = (plan, binding)

    linked: list[ExternalLinkedCall] = []
    caller_definition_counts: dict[str, int] = {}
    for module in analysis.modules:
        tree = _read_project_tree(module)
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qualname = f"{module.module_name}.{node.name}"
                caller_definition_counts[qualname] = caller_definition_counts.get(qualname, 0) + 1
        external_targets = frozenset(bindings)
        for target in external_targets:
            if analysis_target_is_mutated(module, target):
                raise ExternalLinkageError("external-linkage-target-mutated")
        _require_no_external_value_escape(
            tree,
            targets=external_targets,
            imports=module.imports,
        )
        calls_by_position = {
            (node.lineno, node.col_offset): node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
        }
        for function in module.functions:
            for call in function.calls:
                call_node = calls_by_position.get((call.line, call.column))
                if call_node is None:
                    continue
                resolved = _direct_external_target(
                    call_node,
                    module=module,
                    function=function,
                    external_bindings=bindings,
                )
                if resolved is None:
                    continue
                target, import_head = resolved
                _require_call_signature(
                    function,
                    call.line,
                    call.column,
                    call_node,
                    bindings[target][1],
                )
                assert module.module_bindings is not None
                final = module.module_bindings.lookup(import_head)
                argument_types = function.call_arg_types.get((call.line, call.column), ())
                normalized_argument_types: list[str] = []
                for value in argument_types:
                    normalized = normalize_type_name(value) if value is not None else None
                    if normalized is None or normalized not in _SCALAR_TYPES:
                        raise ExternalLinkageError("external-linkage-call-type-unknown")
                    normalized_argument_types.append(normalized)
                if function.source_ast_fingerprint is None:
                    raise ExternalLinkageError("external-linkage-caller-identity-missing")
                linked.append(
                    ExternalLinkedCall(
                        caller_qualname=function.qualname,
                        line=call.line,
                        column=call.column,
                        target=target,
                        import_head=import_head,
                        import_target=module.imports[import_head],
                        import_line=final.line if final.line is not None else -1,
                        import_column=final.column if final.column is not None else -1,
                        import_order=final.order,
                        caller_ast_fingerprint=function.source_ast_fingerprint,
                        argument_types=tuple(normalized_argument_types),
                    )
                )

    linked_tuple = tuple(
        sorted(linked, key=lambda item: (item.caller_qualname, item.line, item.column))
    )
    if any(caller_definition_counts.get(item.caller_qualname) != 1 for item in linked_tuple):
        raise ExternalLinkageError("external-linkage-caller-duplicate")
    linked_positions = [(item.caller_qualname, item.line, item.column) for item in linked_tuple]
    if len(linked_positions) != len(set(linked_positions)):
        raise ExternalLinkageError("external-linkage-call-position-duplicate")
    reachable = {item.target for item in linked_tuple}
    private_functions = tuple(
        sorted(
            (
                _lower_exact_external_function(plan, binding)
                for qualname in reachable
                for plan, binding in (bindings[qualname],)
            ),
            key=lambda item: item.qualname,
        )
    )
    try:
        return ExternalNativeRegistry(
            package=package,
            distribution=distribution,
            version=version,
            linked_calls=linked_tuple,
            private_functions=private_functions,
        )
    except (TypeError, ValueError) as error:
        raise ExternalLinkageError("external-linkage-no-reachable-helper") from error


def build_external_runtime_guard(
    registry: ExternalNativeRegistry,
    plans: tuple[ExternalSourceNativePlan, ...],
) -> ExternalRuntimeGuard:
    """Bind reached helpers to exact installed source and callable identities."""
    if type(registry) is not ExternalNativeRegistry or type(plans) is not tuple:
        raise ExternalLinkageError("external-runtime-guard-input-invalid")
    reachable = {function.qualname for function in registry.private_functions}
    modules: list[ExternalRuntimeModule] = []
    observed: set[str] = set()
    for plan in plans:
        if type(plan) is not ExternalSourceNativePlan:
            raise ExternalLinkageError("external-runtime-guard-plan-invalid")
        if analyze_external_source_snapshot(plan.snapshot) != plan:
            raise ExternalLinkageError("external-runtime-guard-analysis-stale")
        module = plan.snapshot.module
        if module.distribution != registry.distribution or module.version != registry.version:
            raise ExternalLinkageError("external-runtime-guard-identity-mismatch")
        callables = tuple(
            ExternalRuntimeCallable(
                name=binding.name,
                qualname=binding.qualname,
                first_line=binding.source_range.start.line,
            )
            for binding in plan.functions
            if binding.qualname in reachable
        )
        if not callables:
            continue
        prefix = f"distributions/{registry.distribution}/"
        if not module.path.startswith(prefix):
            raise ExternalLinkageError("external-runtime-guard-source-path-invalid")
        source_member = module.path.removeprefix(prefix)
        modules.append(
            ExternalRuntimeModule(
                module_name=module.module_name,
                source_member=source_member,
                source_sha256=module.sha256,
                source_size=len(plan.snapshot.source_bytes),
                callables=callables,
            )
        )
        observed.update(item.qualname for item in callables)
    if observed != reachable:
        raise ExternalLinkageError("external-runtime-guard-coverage-incomplete")
    try:
        return ExternalRuntimeGuard(
            distribution=registry.distribution,
            version=registry.version,
            modules=tuple(sorted(modules, key=lambda item: item.module_name)),
        )
    except ValueError as error:
        raise ExternalLinkageError("external-runtime-guard-invalid") from error


def _read_project_tree(module: ModuleAnalysis) -> ast.Module:
    try:
        source = Path(module.file_path).read_text(encoding="utf-8")
        return ast.parse(source, filename=module.file_path, type_comments=True)
    except (OSError, UnicodeError, SyntaxError) as error:
        raise ExternalLinkageError("external-linkage-project-source-unavailable") from error


def _direct_external_target(
    node: ast.Call,
    *,
    module: ModuleAnalysis,
    function: FunctionAnalysis,
    external_bindings: dict[str, tuple[ExternalSourceNativePlan, ExternalFunctionBinding]],
) -> tuple[str, str] | None:
    head: str
    target: str | None
    if isinstance(node.func, ast.Name):
        head = node.func.id
        target = module.imports.get(head)
    elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
        head = node.func.value.id
        imported = module.imports.get(head)
        target = f"{imported}.{node.func.attr}" if imported is not None else None
    else:
        return None
    if target not in external_bindings:
        return None
    if head in function.local_binding_names or module.module_bindings is None:
        raise ExternalLinkageError("external-linkage-call-head-shadowed")
    final = module.module_bindings.lookup(head)
    if final.kind is not BindingKind.IMPORT or final.target != module.imports.get(head):
        raise ExternalLinkageError("external-linkage-import-not-final")
    if analysis_target_is_mutated(module, target):
        raise ExternalLinkageError("external-linkage-target-mutated")
    return target, head


def analysis_target_is_mutated(module: ModuleAnalysis, target: str) -> bool:
    """Reject project-authority or exact-source mutation of an external target.

    The ordinary project mutation index is intentionally rooted in project and
    known runtime symbols.  A C5.2 package is neither, so a write such as
    ``pkg.external_helper = replacement`` can otherwise fall outside that
    index.  Re-read the exact project module and conservatively collect writes
    through every import alias that resolves to the external target.
    """
    if module.project_mutations.target_is_mutated(target):
        return True
    tree = _read_project_tree(module)
    for node in ast.walk(tree):
        mutation: str | None = None
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete)):
            targets: tuple[ast.expr, ...]
            if isinstance(node, ast.Assign):
                targets = tuple(node.targets)
            elif isinstance(node, ast.Delete):
                targets = tuple(node.targets)
            else:
                targets = (node.target,)
            for candidate in targets:
                mutation = _external_alias_path(candidate, module.imports)
                if mutation is not None and _qualified_paths_overlap(mutation, target):
                    return True
        if (
            isinstance(node, ast.NamedExpr)
            and (mutation := _external_alias_path(node.target, module.imports)) is not None
            and _qualified_paths_overlap(mutation, target)
        ):
            return True
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"setattr", "delattr"}
            and len(node.args) >= 2
        ):
            base = _external_alias_path(node.args[0], module.imports)
            attribute = node.args[1]
            if base is not None:
                mutation = (
                    f"{base}.{attribute.value}"
                    if isinstance(attribute, ast.Constant)
                    and isinstance(attribute.value, str)
                    and attribute.value
                    else base
                )
                if _qualified_paths_overlap(mutation, target):
                    return True
    return False


def _external_alias_path(
    node: ast.expr,
    imports: dict[str, str],
) -> str | None:
    if isinstance(node, ast.Name):
        return imports.get(node.id)
    if isinstance(node, ast.Attribute):
        base = _external_alias_path(node.value, imports)
        return f"{base}.{node.attr}" if base is not None else None
    if isinstance(node, (ast.Subscript, ast.Starred)):
        return _external_alias_path(node.value, imports)
    if isinstance(node, (ast.Tuple, ast.List)):
        paths = {
            path for item in node.elts if (path := _external_alias_path(item, imports)) is not None
        }
        return next(iter(paths)) if len(paths) == 1 else None
    return None


def _qualified_paths_overlap(left: str, right: str) -> bool:
    return left == right or left.startswith(f"{right}.") or right.startswith(f"{left}.")


def _require_no_external_value_escape(
    tree: ast.Module,
    *,
    targets: frozenset[str],
    imports: dict[str, str],
) -> None:
    parents = {
        id(child): parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.expr):
            resolved = _external_alias_path(node, imports)
            if resolved in targets:
                parent = parents.get(id(node))
                if isinstance(parent, ast.Call) and parent.func is node:
                    continue
                raise ExternalLinkageError("external-linkage-target-escaped")
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and node.args
        ):
            base = _external_alias_path(node.args[0], imports)
            if base is None:
                continue
            attribute = node.args[1] if len(node.args) > 1 else None
            if isinstance(attribute, ast.Constant) and isinstance(attribute.value, str):
                resolved = f"{base}.{attribute.value}"
                if resolved in targets:
                    raise ExternalLinkageError("external-linkage-target-escaped")
            elif any(target == base or target.startswith(f"{base}.") for target in targets):
                raise ExternalLinkageError("external-linkage-target-escaped")


def _require_call_signature(
    function: FunctionAnalysis,
    line: int,
    column: int,
    node: ast.Call,
    binding: ExternalFunctionBinding,
) -> None:
    if node.keywords or any(isinstance(argument, ast.Starred) for argument in node.args):
        raise ExternalLinkageError("external-linkage-call-shape-unsupported")
    if len(node.args) != len(binding.parameters):
        raise ExternalLinkageError("external-linkage-call-arity-mismatch")
    argument_types = function.call_arg_types.get((line, column), ())
    if len(argument_types) != len(binding.parameters):
        raise ExternalLinkageError("external-linkage-call-type-unknown")
    for observed, parameter in zip(argument_types, binding.parameters, strict=True):
        if normalize_type_name(observed) != normalize_type_name(parameter.type_name):
            raise ExternalLinkageError("external-linkage-call-type-mismatch")


def _lower_exact_external_function(
    plan: ExternalSourceNativePlan,
    binding: ExternalFunctionBinding,
) -> FunctionIR:
    source = plan.snapshot.source_bytes.decode("utf-8")
    tree = ast.parse(
        source,
        filename=plan.snapshot.module.path,
        mode="exec",
        type_comments=True,
    )
    nodes = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
    node = nodes.get(binding.name)
    if node is None:
        raise ExternalLinkageError("external-linkage-function-missing")
    bindings = build_module_bindings(tree, binding.module_name)
    module = ModuleAnalysis(
        module_name=binding.module_name,
        file_path=binding.source_path,
        module_bindings=bindings,
        project_modules=frozenset({binding.module_name}),
    )
    function_names = frozenset(nodes)
    function = FunctionAnalysis(
        name=binding.name,
        qualname=binding.qualname,
        module_name=binding.module_name,
        file_path=binding.source_path,
        line=node.lineno,
        column=node.col_offset,
        source_range=binding.source_range,
        marker_kind="none",
        is_native_candidate=True,
        explicitly_marked=False,
        source_ast_fingerprint=executable_ast_fingerprint(node),
        annotated_return_type=binding.return_type,
        native_target_language="rust",
        imports={},
        module_function_names=function_names,
        module_bindings=bindings,
        project_modules=frozenset({binding.module_name}),
    )
    return_types = {item.name: item.return_type for item in plan.functions}
    validate_native_function(
        node,
        function,
        return_types=return_types,
        module_function_names=set(function_names),
    )
    if not function.accepted:
        raise ExternalLinkageError("external-linkage-function-no-longer-lowerable")
    module.functions = [function]
    analysis = ProjectAnalysis(
        project_root=Path("."),
        modules=[module],
        project_bindings=ProjectBindings({binding.module_name: bindings}),
    )
    try:
        function_ir = lower_function(
            function,
            node,
            module,
            FunctionResolver(analysis),
        )
    except LoweringError as error:
        raise ExternalLinkageError("external-linkage-function-no-longer-lowerable") from error
    payload = json.dumps(
        function_ir.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    observed_ir_sha256 = hashlib.sha256(
        EXTERNAL_FUNCTION_IR_DOMAIN.encode("ascii") + b"\0" + payload
    ).hexdigest()
    if observed_ir_sha256 != binding.lowered_ir_sha256:
        raise ExternalLinkageError("external-linkage-function-ir-stale")
    return replace(function_ir, embedded=True)


__all__ = [
    "ExternalLinkageError",
    "ExternalLinkedCall",
    "ExternalNativeRegistry",
    "ExternalRuntimeCallable",
    "ExternalRuntimeGuard",
    "ExternalRuntimeModule",
    "build_external_native_registry",
    "build_external_runtime_guard",
]
