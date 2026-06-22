from __future__ import annotations

import ast

from rextio.analyzer.native_marker import dotted_name

LOGGING_METHODS = {
    "debug",
    "info",
    "warning",
    "warn",
    "error",
    "exception",
    "critical",
}

LOGGING_CANONICAL_TARGETS = {
    "logging.debug": "logging.debug",
    "logging.info": "logging.info",
    "logging.warning": "logging.warning",
    "logging.warn": "logging.warning",
    "logging.error": "logging.error",
    "logging.exception": "logging.error",
    "logging.critical": "logging.error",
}

DATETIME_NOW_TARGETS = {
    "datetime.datetime.now",
    "datetime.datetime.utcnow",
}

DATETIME_ISOFORMAT_TARGETS = {
    "datetime.datetime.now.isoformat",
    "datetime.datetime.utcnow.isoformat",
}

COMMON_DIRECT_RUST_CALLS = {
    "print",
    *LOGGING_CANONICAL_TARGETS.values(),
    *DATETIME_NOW_TARGETS,
    *DATETIME_ISOFORMAT_TARGETS,
}


def canonical_call_target(
    node: ast.Call,
    imports: dict[str, str],
    logger_names: set[str] | tuple[str, ...] = (),
) -> str | None:
    datetime_target = canonical_datetime_isoformat_call(node, imports)
    if datetime_target is not None:
        return datetime_target
    raw_target = dotted_name(node.func)
    if raw_target is None:
        return None
    return canonical_simple_call_target(raw_target, imports, logger_names)


def canonical_simple_call_target(
    target: str,
    imports: dict[str, str],
    logger_names: set[str] | tuple[str, ...] = (),
) -> str:
    if target == "print":
        return target

    resolved = resolve_import_target(target, imports)
    if resolved in LOGGING_CANONICAL_TARGETS:
        return LOGGING_CANONICAL_TARGETS[resolved]

    parts = target.split(".")
    if len(parts) == 2 and parts[0] in set(logger_names) and parts[1] in LOGGING_METHODS:
        return LOGGING_CANONICAL_TARGETS.get(f"logging.{parts[1]}", "logging.error")

    return resolved


def canonical_datetime_isoformat_call(node: ast.Call, imports: dict[str, str]) -> str | None:
    if not isinstance(node.func, ast.Attribute) or node.func.attr != "isoformat":
        return None
    receiver = node.func.value
    if not isinstance(receiver, ast.Call) or receiver.args or receiver.keywords:
        return None
    raw_inner = dotted_name(receiver.func)
    if raw_inner is None:
        return None
    inner = resolve_import_target(raw_inner, imports)
    if inner in DATETIME_NOW_TARGETS:
        return f"{inner}.isoformat"
    return None


def is_logging_get_logger_call(node: ast.AST, imports: dict[str, str]) -> bool:
    if not isinstance(node, ast.Call):
        return False
    raw_target = dotted_name(node.func)
    if raw_target is None:
        return False
    return resolve_import_target(raw_target, imports) == "logging.getLogger"


def is_supported_effect_call(
    node: ast.AST,
    imports: dict[str, str],
    logger_names: set[str] | tuple[str, ...] = (),
) -> bool:
    if not isinstance(node, ast.Call):
        return False
    target = canonical_call_target(node, imports, logger_names)
    return target == "print" or target in LOGGING_CANONICAL_TARGETS.values()


def resolve_import_target(target: str, imports: dict[str, str]) -> str:
    head, separator, tail = target.partition(".")
    imported = imports.get(head)
    if imported is None:
        return target
    if not separator:
        return imported
    return f"{imported}.{tail}"
