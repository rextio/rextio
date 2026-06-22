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

DATETIME_TIMESTAMP_TARGETS = {
    "datetime.datetime.now.timestamp",
    "datetime.datetime.utcnow.timestamp",
}

MATH_FLOAT_UNARY_TARGETS = {
    "math.acos",
    "math.asin",
    "math.atan",
    "math.cos",
    "math.exp",
    "math.log",
    "math.log10",
    "math.log2",
    "math.sin",
    "math.sqrt",
    "math.tan",
}

MATH_FLOAT_BINARY_TARGETS = {
    "math.atan2",
}

MATH_FLOAT_TO_INT_TARGETS = {
    "math.ceil",
    "math.floor",
    "math.trunc",
}

MATH_FLOAT_TO_BOOL_TARGETS = {
    "math.isfinite",
    "math.isinf",
    "math.isnan",
}

MATH_CONSTANT_TARGETS = {
    "math.e",
    "math.pi",
}

STR_METHOD_TARGETS = {
    "str.encode",
    "str.endswith",
    "str.lower",
    "str.replace",
    "str.startswith",
    "str.strip",
    "str.upper",
}

BYTES_METHOD_TARGETS = {
    "bytes.decode",
}

LIST_METHOD_TARGETS = {
    "list.copy",
    "list.count",
    "list.index",
}

HASHLIB_CHAIN_TARGETS = {
    "hashlib.sha256.hexdigest",
}

HASHLIB_INTERNAL_TARGETS = {
    "hashlib.sha256",
}

BASE64_TARGETS = {
    "base64.b64decode",
    "base64.b64encode",
}

JSON_TARGETS = {
    "json.dumps",
    "json.loads",
}

STATISTICS_TARGETS = {
    "statistics.fmean",
    "statistics.mean",
}

TIME_TARGETS = {
    "time.time",
}

COMMON_DIRECT_RUST_CALLS = {
    "all",
    "any",
    "reversed",
    "sorted",
    "print",
    *BASE64_TARGETS,
    *BYTES_METHOD_TARGETS,
    *DATETIME_TIMESTAMP_TARGETS,
    *LOGGING_CANONICAL_TARGETS.values(),
    *HASHLIB_CHAIN_TARGETS,
    *HASHLIB_INTERNAL_TARGETS,
    *JSON_TARGETS,
    *LIST_METHOD_TARGETS,
    *MATH_CONSTANT_TARGETS,
    *MATH_FLOAT_BINARY_TARGETS,
    *MATH_FLOAT_TO_BOOL_TARGETS,
    *MATH_FLOAT_TO_INT_TARGETS,
    *MATH_FLOAT_UNARY_TARGETS,
    *STATISTICS_TARGETS,
    *STR_METHOD_TARGETS,
    *TIME_TARGETS,
    *DATETIME_NOW_TARGETS,
    *DATETIME_ISOFORMAT_TARGETS,
}


def canonical_call_target(
    node: ast.Call,
    imports: dict[str, str],
    logger_names: set[str] | tuple[str, ...] = (),
) -> str | None:
    chained_target = canonical_chained_call(node, imports)
    if chained_target is not None:
        return chained_target
    method_target = canonical_method_call(node, imports)
    if method_target is not None:
        return method_target
    datetime_target = canonical_datetime_terminal_call(node, imports)
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


def canonical_attribute_target(node: ast.Attribute, imports: dict[str, str]) -> str | None:
    raw_target = dotted_name(node)
    if raw_target is None:
        return None
    return resolve_import_target(raw_target, imports)


def canonical_chained_call(node: ast.Call, imports: dict[str, str]) -> str | None:
    if not isinstance(node.func, ast.Attribute):
        return None
    receiver = node.func.value
    if not isinstance(receiver, ast.Call):
        return None
    raw_inner = dotted_name(receiver.func)
    if raw_inner is None:
        return None
    inner = resolve_import_target(raw_inner, imports)
    target = f"{inner}.{node.func.attr}"
    if target in HASHLIB_CHAIN_TARGETS:
        return target
    return None


def canonical_datetime_terminal_call(node: ast.Call, imports: dict[str, str]) -> str | None:
    if not isinstance(node.func, ast.Attribute) or node.func.attr not in {"isoformat", "timestamp"}:
        return None
    receiver = node.func.value
    if not isinstance(receiver, ast.Call) or receiver.args or receiver.keywords:
        return None
    raw_inner = dotted_name(receiver.func)
    if raw_inner is None:
        return None
    inner = resolve_import_target(raw_inner, imports)
    if inner in DATETIME_NOW_TARGETS:
        return f"{inner}.{node.func.attr}"
    return None


def canonical_method_call(node: ast.Call, imports: dict[str, str]) -> str | None:
    if not isinstance(node.func, ast.Attribute):
        return None
    attr = node.func.attr
    if attr in {target.rsplit(".", 1)[1] for target in STR_METHOD_TARGETS}:
        return f"str.{attr}"
    if attr in {target.rsplit(".", 1)[1] for target in BYTES_METHOD_TARGETS}:
        return f"bytes.{attr}"
    if attr in {target.rsplit(".", 1)[1] for target in LIST_METHOD_TARGETS}:
        return f"list.{attr}"
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
