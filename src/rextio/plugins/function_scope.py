"""Plugin API 1.7 function-scope RAII guard resolution and validation.

A used API-1.7 plugin may return at most one non-fallible zero-argument Rust
path-call expression plus validated ``use`` lines and helper items. Core owns
collision-free ordinal bindings and emits let-bound guards at the start of
accepted generated native functions so Rust ``Drop`` covers normal return,
early return, and error paths.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from typing import Any, cast
from dataclasses import fields, is_dataclass

from rextio.artifacts.models import ArtifactProfile
from rextio.codegen.rust.errors import RustCodegenError
from rextio.ir.nodes import FunctionIR, PluginClaimIR
from rextio.ir.types import RxtPluginType, RxtType
from rextio.plugins.api import (
    LOWERING_BACKEND_PYO3,
    LOWERING_BACKEND_STANDALONE_RUST,
    PluginFunctionScopeContext,
    PluginFunctionScopeGuard,
)

# Bounded grammar for ``PluginFunctionScopeGuard.rust`` (plugin API 1.7):
#
#   PATH_CALL ::= IDENT ( "::" IDENT )* "()"
#   IDENT     ::= [A-Za-z_][A-Za-z0-9_]*
#
# Accepted examples: ``tch::no_grad_guard()``, ``AlphaGuard::enter()``, ``enter()``.
# Rejected: arguments, macros (``!``), blocks, operators, method chains (``.``),
# ``?``, statements, bare identifiers, and any parameter reference.
_ZERO_ARG_PATH_CALL = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*\(\)$")
# Final path segments that are semantically fallible / non-RAII even as zero-arg calls.
_REJECTED_FINAL_SEGMENTS = frozenset(
    {
        "unwrap",
        "expect",
        "unwrap_err",
        "unwrap_or",
        "unwrap_or_else",
        "unwrap_or_default",
        "panic",
        "todo",
        "unimplemented",
        "unreachable",
    }
)


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
    # Local import avoids a loader <-> function_scope import cycle at module load.
    from rextio.plugins.loader import PluginError

    if not provider_declares_function_scope_guard(provider):
        return False
    if _version_tuple(api_version) < (1, 7):
        raise PluginError(
            f"plugin {plugin_id!r} implements function_scope_guard() but declares "
            f"plugin-API {api_version!r}; function-scope RAII guards require "
            "api_version >= 1.7"
        )
    return True


def allocate_function_scope_guard_bindings(
    plugin_ids: Sequence[str] | Iterable[str],
) -> dict[str, str]:
    """Allocate Core-owned, collision-free guard bindings for used plugins.

    Bindings are assigned in sorted plugin-id order with a stable ordinal so
    distinct plugin ids (including pairs that sanitize identically, such as
    ``rextio-a-b`` vs ``rextio-a_b``) never share a binding name. Format:
    ``__rextio_plugin_scope_guard_{ordinal}``.
    """
    ordered = sorted(plugin_ids)
    return {
        plugin_id: f"__rextio_plugin_scope_guard_{index}" for index, plugin_id in enumerate(ordered)
    }


def core_owned_guard_binding_name(plugin_id: str, *, ordinal: int) -> str:
    """Return the Core-owned binding for one plugin at a known sorted ordinal.

    Prefer :func:`allocate_function_scope_guard_bindings` when allocating a set
    of names; this helper exists for single-name assertions.
    """
    if ordinal < 0:
        raise ValueError("guard binding ordinal must be non-negative")
    return f"__rextio_plugin_scope_guard_{ordinal}"


def _is_plugin_type_key(value: object) -> bool:
    return isinstance(value, str) and "/" in value and bool(value.split("/", 1)[0])


def _walk_ir_for_claims(node: object, out: list[PluginClaimIR]) -> None:
    """Deterministic generic IR traversal that visits every nested claim.

    Walks dataclasses, lists/tuples (including ``DictIR`` key/value pairs),
    comprehension generators, try handlers, and other IR containers without
    relying on ad hoc type branches that miss nested containers.
    """
    if isinstance(node, PluginClaimIR):
        out.append(node)
        return
    if is_dataclass(node) and not isinstance(node, type):
        for field in fields(cast(Any, node)):
            _walk_ir_for_claims(getattr(node, field.name), out)
        return
    if isinstance(node, (list, tuple)):
        for item in node:
            _walk_ir_for_claims(item, out)
        return
    if isinstance(node, dict):
        for key, value in node.items():
            _walk_ir_for_claims(key, out)
            _walk_ir_for_claims(value, out)


def collect_function_plugin_usage(
    function: FunctionIR,
) -> dict[str, tuple[tuple[str, ...], tuple[str, ...]]]:
    """Map plugin id → (sorted unique rule ids, sorted unique type keys).

    A plugin is used only when the function has a claim owned by it or a
    directly used plugin type key namespaced to it (signature parameter/return
    types plus claim operand/result/receiver types). Unused installed plugins
    are absent from the result. Facts are unique and deterministically sorted.
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
    _walk_ir_for_claims(function.body, claims)
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
    """Validate a guard declaration fail-closed with actionable context.

    ``rust`` must match the zero-argument path-call grammar documented on this
    module (e.g. ``AlphaGuard::enter()`` / ``tch::no_grad_guard()``).
    """
    rust = guard.rust.strip()
    if not rust:
        raise RustCodegenError(
            f"plugin {plugin_id!r} function_scope_guard() returned an empty rust "
            f"expression for {qualname}"
        )
    _reject_multiline("rust expression", rust, plugin_id=plugin_id, qualname=qualname)
    if _ZERO_ARG_PATH_CALL.fullmatch(rust) is None:
        raise RustCodegenError(
            f"plugin {plugin_id!r} function_scope_guard() rust expression for "
            f"{qualname} must be a zero-argument path call such as "
            f"'AlphaGuard::enter()' or 'tch::no_grad_guard()' "
            f"(no arguments, macros, blocks, operators, method chains, '?', "
            f"statements, or parameter references); got {rust!r}"
        )
    final_segment = rust[: -len("()")].rsplit("::", 1)[-1]
    if final_segment in _REJECTED_FINAL_SEGMENTS:
        raise RustCodegenError(
            f"plugin {plugin_id!r} function_scope_guard() rust expression for "
            f"{qualname} must be a zero-argument path call such as "
            f"'AlphaGuard::enter()' or 'tch::no_grad_guard()' "
            f"(rejected fallible/non-RAII path segment {final_segment!r}); got {rust!r}"
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


def _unique_sorted(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted(set(values)))


def build_function_scope_context(
    *,
    function_qualname: str,
    used_rule_ids: Iterable[str],
    used_type_keys: Iterable[str],
    backend: str,
    artifact_profile: ArtifactProfile | None = None,
) -> PluginFunctionScopeContext:
    """Build a validated context with unique, deterministically sorted usage facts."""
    return PluginFunctionScopeContext(
        function_qualname=function_qualname,
        used_rule_ids=_unique_sorted(used_rule_ids),
        used_type_keys=_unique_sorted(used_type_keys),
        backend=backend,
        artifact_profile=artifact_profile,
    )


def lowering_backend_for_mode(mode: str) -> str:
    """Map a codegen mode string to a closed LoweringContext backend id."""
    if mode == "pyo3":
        return LOWERING_BACKEND_PYO3
    return LOWERING_BACKEND_STANDALONE_RUST
