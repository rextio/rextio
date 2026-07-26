"""Plugin API 1.7 function-scope RAII guard resolution and validation.

A used API-1.7 plugin may return at most one non-fallible Rust guard expression
plus validated ``use`` lines and helper items. Core owns collision-free binding
names and emits let-bound guards at the start of accepted generated native
functions so Rust ``Drop`` covers normal return, early return, and error paths.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from rextio.artifacts.models import ArtifactProfile
from rextio.codegen.rust.errors import RustCodegenError
from rextio.ir.nodes import (
    BlockIR,
    ExprIR,
    FunctionIR,
    PluginClaimIR,
    StatementIR,
)
from rextio.ir.types import RxtPluginType, RxtType
from rextio.plugins.api import (
    LOWERING_BACKEND_PYO3,
    LOWERING_BACKEND_STANDALONE_RUST,
    PluginFunctionScopeContext,
    PluginFunctionScopeGuard,
)
from rextio.plugins.loader import PluginError

# Statement-like prefixes that must never appear as a "guard expression".
_STATEMENT_PREFIXES = (
    "let ",
    "return ",
    "if ",
    "while ",
    "for ",
    "loop ",
    "match ",
    "break",
    "continue",
    "unsafe ",
    "async ",
    "await ",
    "use ",
    "mod ",
    "fn ",
    "struct ",
    "enum ",
    "impl ",
    "type ",
    "const ",
    "static ",
    "trait ",
    "pub ",
)

_BINDING_SAFE = re.compile(r"[^0-9A-Za-z_]+")


def _version_tuple(version: str) -> tuple[int, int]:
    parts = version.split(".")
    try:
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
    except (ValueError, IndexError):
        return (0, 0)
    return (major, minor)


def _is_protocol_class(cls: type) -> bool:
    return bool(getattr(cls, "_is_protocol", False))


def provider_declares_function_scope_guard(provider: object) -> bool:
    """Return whether the provider has a *concrete* function_scope_guard hook.

    Inheritance of a Protocol that lists ``function_scope_guard`` must not count
    as a declaration: Protocol stubs are callable but are not real
    implementations. Only a non-Protocol class in the provider's MRO that
    defines the method counts.
    """
    for cls in type(provider).__mro__:
        if _is_protocol_class(cls):
            continue
        if "function_scope_guard" not in cls.__dict__:
            continue
        attr = cls.__dict__["function_scope_guard"]
        if isinstance(attr, (staticmethod, classmethod)):
            attr = attr.__func__
        if callable(attr):
            return True
    return False


def validate_function_scope_guard_hook_version(
    plugin_id: str, api_version: str, provider: object
) -> bool:
    """Validate that a present function-scope hook is version-gated.

    Returns True when the hook is present (and legal). Raises PluginError when a
    pre-1.7 provider exposes the hook. Returns False when the hook is absent.
    """
    if not provider_declares_function_scope_guard(provider):
        return False
    if _version_tuple(api_version) < (1, 7):
        raise PluginError(
            f"plugin {plugin_id!r} implements function_scope_guard() but declares "
            f"plugin-API {api_version!r}; function-scope RAII guards require "
            "api_version >= 1.7"
        )
    return True


def core_owned_guard_binding_name(plugin_id: str) -> str:
    """Return Core's collision-free let-binding name for one plugin's guard.

    Uses the reserved ``__rextio`` prefix so user identifiers cannot collide
    (analyzer rejects that prefix) and Rust treats the binding as intentionally
    unused while keeping it alive for ``Drop`` until lexical function end.
    """
    mangled = _BINDING_SAFE.sub("_", plugin_id).strip("_") or "plugin"
    if mangled[0].isdigit():
        mangled = f"p_{mangled}"
    return f"__rextio_plugin_scope_guard_{mangled}"


def _is_plugin_type_key(value: object) -> bool:
    return isinstance(value, str) and "/" in value and bool(value.split("/", 1)[0])


def _walk_expr_claims(expr: ExprIR | None, out: list[PluginClaimIR]) -> None:
    if expr is None:
        return
    claim = getattr(expr, "claim", None)
    if isinstance(claim, PluginClaimIR):
        out.append(claim)
    for value in vars(expr).values():
        if isinstance(value, ExprIR):
            _walk_expr_claims(value, out)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, ExprIR):
                    _walk_expr_claims(item, out)
                elif isinstance(item, BlockIR):
                    _walk_block_claims(item, out)


def _walk_statement_claims(statement: StatementIR, out: list[PluginClaimIR]) -> None:
    for value in vars(statement).values():
        if isinstance(value, ExprIR):
            _walk_expr_claims(value, out)
        elif isinstance(value, BlockIR):
            _walk_block_claims(value, out)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, ExprIR):
                    _walk_expr_claims(item, out)
                elif isinstance(item, BlockIR):
                    _walk_block_claims(item, out)
                elif isinstance(item, StatementIR):
                    _walk_statement_claims(item, out)


def _walk_block_claims(block: BlockIR, out: list[PluginClaimIR]) -> None:
    for statement in block.statements:
        _walk_statement_claims(statement, out)


def collect_function_plugin_usage(
    function: FunctionIR,
) -> dict[str, tuple[tuple[str, ...], tuple[str, ...]]]:
    """Map plugin id → (sorted rule ids, sorted type keys) actually used by ``function``.

    A plugin is used only when the function has a claim owned by it or a
    directly used plugin type key namespaced to it (signature parameter/return
    types plus claim operand/result/receiver types). Unused installed plugins
    are absent from the result.
    """
    rule_ids_by_plugin: dict[str, set[str]] = {}
    type_keys_by_plugin: dict[str, set[str]] = {}

    def add_type_key(type_key: str) -> None:
        if not _is_plugin_type_key(type_key):
            return
        plugin_id = type_key.split("/", 1)[0]
        type_keys_by_plugin.setdefault(plugin_id, set()).add(type_key)

    def add_type(rxt_type: RxtType) -> None:
        if isinstance(rxt_type, RxtPluginType):
            add_type_key(rxt_type.key)

    for param in function.params:
        add_type(param.type)
    add_type(function.return_type)

    claims: list[PluginClaimIR] = []
    _walk_block_claims(function.body, claims)
    for claim in claims:
        rule_ids_by_plugin.setdefault(claim.plugin_id, set()).add(claim.rule_id)
        if claim.result_type is not None:
            add_type_key(claim.result_type)
        for operand in claim.operand_types:
            if operand is not None:
                add_type_key(operand)
        receiver = claim.receiver
        if receiver is not None:
            arg_type = getattr(receiver, "arg_type", None)
            if isinstance(arg_type, str):
                add_type_key(arg_type)

    plugin_ids = sorted(set(rule_ids_by_plugin) | set(type_keys_by_plugin))
    return {
        plugin_id: (
            tuple(sorted(rule_ids_by_plugin.get(plugin_id, ()))),
            tuple(sorted(type_keys_by_plugin.get(plugin_id, ()))),
        )
        for plugin_id in plugin_ids
    }


def _reject_multiline(label: str, value: str, *, plugin_id: str, qualname: str) -> None:
    if "\n" in value or "\r" in value:
        raise RustCodegenError(
            f"plugin {plugin_id!r} function_scope_guard() {label} for {qualname} "
            "must be a single line (no newlines)"
        )


def validate_function_scope_guard(
    plugin_id: str,
    qualname: str,
    guard: PluginFunctionScopeGuard,
) -> PluginFunctionScopeGuard:
    """Validate a guard declaration fail-closed with actionable context."""
    rust = guard.rust.strip()
    if not rust:
        raise RustCodegenError(
            f"plugin {plugin_id!r} function_scope_guard() returned an empty rust "
            f"expression for {qualname}"
        )
    _reject_multiline("rust expression", rust, plugin_id=plugin_id, qualname=qualname)
    if rust.endswith(";"):
        raise RustCodegenError(
            f"plugin {plugin_id!r} function_scope_guard() rust expression for "
            f"{qualname} must not end with a semicolon (Core owns the statement)"
        )
    if ";" in rust:
        raise RustCodegenError(
            f"plugin {plugin_id!r} function_scope_guard() rust expression for "
            f"{qualname} must be a single non-statement expression (found ';')"
        )
    if "?" in rust:
        raise RustCodegenError(
            f"plugin {plugin_id!r} function_scope_guard() rust expression for "
            f"{qualname} must be non-fallible (found '?')"
        )
    lowered = rust.lstrip()
    for prefix in _STATEMENT_PREFIXES:
        if lowered.startswith(prefix) or lowered == prefix.rstrip():
            raise RustCodegenError(
                f"plugin {plugin_id!r} function_scope_guard() rust expression for "
                f"{qualname} looks statement-like ({prefix!r}); emit a pure "
                "expression that constructs an RAII value"
            )
    uses: list[str] = []
    for use in guard.uses:
        item = use.strip()
        if not item:
            raise RustCodegenError(
                f"plugin {plugin_id!r} function_scope_guard() returned an empty use "
                f"line for {qualname}"
            )
        _reject_multiline("use line", item, plugin_id=plugin_id, qualname=qualname)
        if not item.startswith("use "):
            raise RustCodegenError(
                f"plugin {plugin_id!r} function_scope_guard() use line for "
                f"{qualname} must start with 'use ' (got {item!r})"
            )
        uses.append(item)
    helpers: list[str] = []
    for helper in guard.helpers:
        item = helper.strip()
        if not item:
            raise RustCodegenError(
                f"plugin {plugin_id!r} function_scope_guard() returned an empty helper "
                f"item for {qualname}"
            )
        # Helpers are module items; reject control characters other than newline.
        if "\0" in item or "\r" in item:
            raise RustCodegenError(
                f"plugin {plugin_id!r} function_scope_guard() helper item for "
                f"{qualname} contains unsafe control characters"
            )
        helpers.append(item)
    return PluginFunctionScopeGuard(rust=rust, uses=tuple(uses), helpers=tuple(helpers))


def resolve_function_scope_guard(
    plugin_id: str,
    provider: object,
    ctx: PluginFunctionScopeContext,
) -> PluginFunctionScopeGuard | None:
    """Call a concrete function_scope_guard hook and validate the result.

    Missing concrete hook → ``None``. Hook returns ``None`` → ``None``.
    Wrong return type, invalid declaration, or hook exception →
    :class:`RustCodegenError` with actionable context.
    """
    if not provider_declares_function_scope_guard(provider):
        return None
    api_version = str(getattr(provider, "api_version", "") or "")
    if _version_tuple(api_version) < (1, 7):
        # Defense-in-depth: loader should already reject this at load time.
        raise RustCodegenError(
            f"plugin {plugin_id!r} implements function_scope_guard() but declares "
            f"plugin-API {api_version!r}; function-scope RAII guards require "
            "api_version >= 1.7"
        )
    hook = getattr(provider, "function_scope_guard")
    try:
        result = hook(ctx)
    except RustCodegenError:
        raise
    except Exception as exc:
        raise RustCodegenError(
            f"plugin {plugin_id!r} function_scope_guard() failed for {ctx.function_qualname}: {exc}"
        ) from exc
    if result is None:
        return None
    if not isinstance(result, PluginFunctionScopeGuard):
        raise RustCodegenError(
            f"plugin {plugin_id!r} function_scope_guard() must return "
            f"PluginFunctionScopeGuard or None for {ctx.function_qualname}, "
            f"got {type(result).__name__}"
        )
    try:
        return validate_function_scope_guard(plugin_id, ctx.function_qualname, result)
    except ValueError as exc:
        raise RustCodegenError(
            f"plugin {plugin_id!r} function_scope_guard() returned an invalid "
            f"declaration for {ctx.function_qualname}: {exc}"
        ) from exc


def build_function_scope_context(
    *,
    function_qualname: str,
    used_rule_ids: Iterable[str],
    used_type_keys: Iterable[str],
    backend: str,
    artifact_profile: ArtifactProfile | None = None,
) -> PluginFunctionScopeContext:
    """Build a validated context with deterministically sorted usage facts."""
    return PluginFunctionScopeContext(
        function_qualname=function_qualname,
        used_rule_ids=tuple(sorted(used_rule_ids)),
        used_type_keys=tuple(sorted(used_type_keys)),
        backend=backend,
        artifact_profile=artifact_profile,
    )


def lowering_backend_for_mode(mode: str) -> str:
    """Map a codegen mode string to a closed LoweringContext backend id."""
    if mode == "pyo3":
        return LOWERING_BACKEND_PYO3
    return LOWERING_BACKEND_STANDALONE_RUST
