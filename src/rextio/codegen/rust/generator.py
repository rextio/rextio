"""Rust/PyO3 source generation from the Rextio IR."""

from __future__ import annotations

import re
from collections.abc import Callable

from rextio.codegen.native_names import native_function_name
from rextio.exceptions import BUILTIN_EXCEPTION_TO_PYO3
from rextio.codegen.rust.checked_arith import (
    checked_arith_helpers as _checked_arith_helpers,
)
from rextio.codegen.rust.errors import RustCodegenError
from rextio.codegen.rust.keywords import RUST_RAWABLE_KEYWORDS
from rextio.codegen.rust.jit_codegen import jit_prelude as _jit_prelude
from rextio.codegen.rust.jit_codegen import jit_pointer_type as _jit_pointer_type
from rextio.codegen.rust.jit_codegen import render_cranelift_expr as _render_cranelift_expr
from rextio.codegen.rust.pyo3 import render_pyo3_module
from rextio.codegen.rust.rust_format import (
    block_always_returns as _block_always_returns,
)
from rextio.codegen.rust.rust_format import (
    default_return,
    python_logging_format_to_rust,
    render_literal,
    rust_string_literal,
    strip_expr_if_safe,
    strip_wrapping_parens,
)
from rextio.codegen.rust.rust_format import (
    indent as _indent,
)
from rextio.codegen.rust.type_map import rust_type
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
    ReturnIR,
    SetComprehensionIR,
    SetIR,
    StatementIR,
    TargetIR,
    TryIR,
    TupleIR,
    TupleTargetIR,
    UnaryOpIR,
    WhileIR,
)
from rextio.ir.types import (
    RxtBool,
    RxtBytes,
    RxtDict,
    RxtFloat,
    RxtInt,
    RxtList,
    RxtNone,
    RxtOptional,
    RxtSet,
    RxtStr,
    RxtTuple,
    RxtType,
)


# `RustCodegenError` is imported from .errors above and re-exported here for
# backward compatibility (tests import `rextio.codegen.rust.generator`). No
# `__all__` is declared so this pure refactor leaves the module's wildcard-export
# surface exactly as it was before the split.



def generate_rust_module(module_ir: ModuleIR) -> str:
    """Generate the PyO3 extension-module Rust source for a lowered module."""
    names_by_qualname = {
        function.qualname: rust_identifier(native_function_name(function.qualname))
        for function in module_ir.functions
    }
    names_by_module_and_name = {
        (function.module_name, function.name): names_by_qualname[function.qualname]
        for function in module_ir.functions
    }
    return_types_by_qualname = {
        function.qualname: function.return_type for function in module_ir.functions
    }
    used_helpers: set[str] = set()
    rendered = [
        (
            names_by_qualname[function.qualname],
            (
                _render_jit_function(
                    function,
                    names_by_qualname[function.qualname],
                    names_by_qualname,
                    names_by_module_and_name,
                    return_types_by_qualname,
                )
                if function.native_jit
                else
                _render_runtime_semantics_function(function)
                if function.native_runtime_semantics
                else _render_function(
                    function,
                    names_by_qualname,
                    names_by_module_and_name,
                    return_types_by_qualname,
                    mode="pyo3",
                    used_helpers=used_helpers,
                )
            ),
        )
        for function in module_ir.functions
    ]
    exported = [
        names_by_qualname[function.qualname]
        for function in module_ir.functions
        if not function.native_jit
    ]
    prelude: list[str] = []
    if any(function.native_jit for function in module_ir.functions):
        prelude.extend(_jit_prelude())
    prelude.extend(_checked_arith_helpers(used_helpers, "pyo3"))
    return render_pyo3_module(
        rendered,
        exported_functions=exported,
        extra_prelude=prelude or None,
    )


def generate_rust_crate_module(module_ir: ModuleIR) -> str:
    """Generate the Rust-importable crate source for a lowered module."""
    direct_functions = [
        function
        for function in module_ir.functions
        if not function.native_runtime_semantics and not function.native_jit
    ]
    if not direct_functions:
        raise RustCodegenError("no direct Rust native functions are available for a Rust-importable crate")
    names_by_qualname = {
        function.qualname: rust_identifier(native_function_name(function.qualname))
        for function in direct_functions
    }
    names_by_module_and_name = {
        (function.module_name, function.name): names_by_qualname[function.qualname]
        for function in direct_functions
    }
    return_types_by_qualname = {
        function.qualname: function.return_type for function in direct_functions
    }
    used_helpers: set[str] = set()
    rendered = [
        _render_function(
            function,
            names_by_qualname,
            names_by_module_and_name,
            return_types_by_qualname,
            mode="crate",
            used_helpers=used_helpers,
        )
        for function in direct_functions
    ]
    return _render_importable_crate_module(rendered, used_helpers)


def rust_identifier(value: str) -> str:
    """Return a valid Rust identifier for a name, escaping keywords as raw identifiers."""
    identifier = re.sub(r"[^0-9a-zA-Z_]", "_", value)
    if not identifier:
        raise RustCodegenError("empty Rust identifier")
    if identifier[0].isdigit():
        identifier = f"_{identifier}"
    # Carry a name that collides with a Rust keyword as a raw identifier so it
    # stays valid Rust (e.g. a Python local `match` -> `r#match`). The handful of
    # keywords `r#` cannot express (`crate`/`self`/`Self`/`super`) are rejected
    # upstream by the analyzer (RXT011), so they never reach here.
    if identifier in RUST_RAWABLE_KEYWORDS:
        return f"r#{identifier}"
    return identifier


def _render_runtime_semantics_function(function: FunctionIR) -> str:
    if function.runtime_fallback_module is None or not function.runtime_attr_path:
        raise RustCodegenError(f"missing runtime fallback metadata for {function.qualname}")
    rust_name = rust_identifier(native_function_name(function.qualname))
    attr_path = ", ".join(rust_string_literal(item) for item in function.runtime_attr_path)
    return "\n".join(
        [
            "#[pyfunction(signature = (*args, **kwargs))]",
            f"fn {rust_name}(",
            "    py: Python<'_>,",
            "    args: &Bound<'_, PyTuple>,",
            "    kwargs: Option<&Bound<'_, PyDict>>,",
            ") -> PyResult<PyObject> {",
            "    rextio_call_python_runtime(",
            "        py,",
            f"        {rust_string_literal(function.runtime_fallback_module)},",
            f"        &[{attr_path}],",
            "        args,",
            "        kwargs,",
            "    )",
            "}",
        ]
    )


def _render_jit_function(
    function: FunctionIR,
    rust_name: str,
    native_names_by_qualname: dict[str, str],
    native_names_by_module_and_name: dict[tuple[str, str], str],
    native_return_types: dict[str, RxtType],
) -> str:
    if len(function.body.statements) != 1 or not isinstance(function.body.statements[0], ReturnIR):
        raise RustCodegenError(f"JIT function must contain a single return statement: {function.qualname}")
    return_statement = function.body.statements[0]
    if return_statement.value is None:
        raise RustCodegenError(f"JIT function must return a value: {function.qualname}")
    return_type = rust_type(function.return_type)
    if return_type not in {"i64", "f64"}:
        raise RustCodegenError(f"JIT function return type is not supported: {function.qualname}")
    param_types = [rust_type(param.type) for param in function.params]
    if any(param_type != return_type for param_type in param_types):
        raise RustCodegenError(
            f"JIT function parameters must match the return type in 0.1.0 alpha: {function.qualname}"
        )
    threshold = function.jit_hot_threshold if function.jit_hot_threshold is not None else 25
    pointer_type = _jit_pointer_type(return_type, len(function.params))
    interpreter = _FunctionRenderer(
        function,
        native_names_by_qualname,
        native_names_by_module_and_name,
        native_return_types,
        mode="pyo3",
    )
    interpreter_expr = strip_expr_if_safe(
        return_statement.value,
        interpreter.render_expr_with_expected(return_statement.value, function.return_type),
    )
    # ``rust_name`` may be a raw identifier (``r#fn``) for a keyword function name.
    # That is valid as the standalone ``fn`` name, but the derived type/static/helper
    # identifiers are *compound* and a raw-identifier prefix cannot appear
    # mid-identifier, so build those from the unescaped base. They are also namespaced
    # under ``__rextio_jit_`` so they can never collide with a user function that
    # happens to be named like one of the helpers (e.g. a real ``compile_foo``).
    base = rust_name.removeprefix("r#")
    helper = f"__rextio_jit_{base}"
    compile_name = f"{helper}_compile"
    signature_params = ", ".join(
        f"{rust_identifier(param.name)}: {rust_type(param.type)}" for param in function.params
    )
    pointer_args = ", ".join(rust_identifier(param.name) for param in function.params)
    cranelift_type = "types::I64" if return_type == "i64" else "types::F64"
    jit_lines, jit_value = _render_cranelift_expr(
        return_statement.value,
        {param.name: index for index, param in enumerate(function.params)},
        return_type,
    )
    name_literal = rust_string_literal(base)
    return "\n".join(
        [
            f"type {helper}_JitFn = {pointer_type};",
            "",
            f"static {helper}_HOT_COUNT: AtomicUsize = AtomicUsize::new(0);",
            f"static {helper}_COMPILED: OnceLock<Result<{helper}_JitFn, String>> = OnceLock::new();",
            "",
            f"fn {rust_name}({signature_params}) -> PyResult<{return_type}> {{",
            f"    let calls = {helper}_HOT_COUNT.fetch_add(1, Ordering::Relaxed) + 1;",
            f"    if calls >= {threshold} {{",
            f"        if let Ok(compiled) = {helper}_COMPILED.get_or_init({compile_name}) {{",
            f"            return Ok(unsafe {{ compiled({pointer_args}) }});",
            "        }",
            "    }",
            f"    Ok({interpreter_expr})",
            "}",
            "",
            f"fn {compile_name}() -> Result<{helper}_JitFn, String> {{",
            "    let jit_builder = JITBuilder::new(cranelift_module::default_libcall_names())",
            "        .map_err(|err| err.to_string())?;",
            "    let mut module = JITModule::new(jit_builder);",
            "    let mut ctx = module.make_context();",
            *[
                f"    ctx.func.signature.params.push(AbiParam::new({cranelift_type}));"
                for _param in function.params
            ],
            f"    ctx.func.signature.returns.push(AbiParam::new({cranelift_type}));",
            "    let mut builder_context = FunctionBuilderContext::new();",
            "    let mut builder = FunctionBuilder::new(&mut ctx.func, &mut builder_context);",
            "    let block = builder.create_block();",
            "    builder.append_block_params_for_function_params(block);",
            "    builder.switch_to_block(block);",
            "    builder.seal_block(block);",
            *[f"    {line}" for line in jit_lines],
            f"    builder.ins().return_(&[{jit_value}]);",
            "    builder.finalize();",
            f"    let id = module.declare_function({name_literal}, Linkage::Export, &ctx.func.signature)",
            "        .map_err(|err| err.to_string())?;",
            "    module.define_function(id, &mut ctx).map_err(|err| err.to_string())?;",
            "    module.clear_context(&mut ctx);",
            "    module.finalize_definitions().map_err(|err| err.to_string())?;",
            "    let module = Box::leak(Box::new(module));",
            "    let code = module.get_finalized_function(id);",
            f"    Ok(unsafe {{ std::mem::transmute::<*const u8, {helper}_JitFn>(code) }})",
            "}",
        ]
    )


# Map the renderer's internal error ``kind`` to the CPython exception type name a
# crate-mode ``RextioError`` carries (so a consumer can print a Python-style
# ``TypeName: message``). pyo3 mode uses the ``Py*`` exception types directly.
_CRATE_EXCEPTION_NAMES = {
    "key": "KeyError",
    "runtime": "RuntimeError",
    "unbound": "UnboundLocalError",
    "value": "ValueError",
}


def _crate_exception_name(kind: str) -> str:
    """Return the CPython exception type name for a renderer error ``kind``."""
    return _CRATE_EXCEPTION_NAMES.get(kind, "ValueError")


def _render_importable_crate_module(function_sources: list[str], used_helpers: set[str]) -> str:
    lines = [
        "// Generated by Rextio. Do not edit manually.",
        "",
        # Generated function names are snake_case-violating (e.g. `app__f`) and a
        # given crate may not use every prelude import; silence those lints so a
        # clean build does not bury the success line in warnings.
        "#![allow(non_snake_case, unused_imports)]",
        "",
        "use base64::Engine;",
        "use sha2::Digest;",
        "use std::collections::HashMap;",
        "use std::collections::HashSet;",
        "",
        "#[derive(Debug, Clone, PartialEq, Eq)]",
        "pub struct RextioError {",
        "    // The CPython exception type name this error corresponds to (e.g.",
        "    // \"OverflowError\"), so a consumer can render a Python-style message.",
        "    kind: String,",
        "    message: String,",
        "}",
        "",
        "impl RextioError {",
        "    pub fn new(kind: impl Into<String>, message: impl Into<String>) -> Self {",
        "        Self { kind: kind.into(), message: message.into() }",
        "    }",
        "",
        "    pub fn kind(&self) -> &str {",
        "        &self.kind",
        "    }",
        "",
        "    pub fn message(&self) -> &str {",
        "        &self.message",
        "    }",
        "}",
        "",
        "impl std::fmt::Display for RextioError {",
        "    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {",
        "        // CPython-style `TypeName: message`.",
        "        write!(f, \"{}: {}\", self.kind, self.message)",
        "    }",
        "}",
        "",
        "impl std::error::Error for RextioError {}",
        "",
    ]
    lines.extend(_checked_arith_helpers(used_helpers, "crate"))
    for function_source in function_sources:
        lines.append(function_source)
        lines.append("")
    return "\n".join(lines)


class _FunctionRenderer:
    def __init__(
        self,
        function: FunctionIR,
        native_names_by_qualname: dict[str, str],
        native_names: dict[tuple[str, str], str],
        native_return_types: dict[str, RxtType],
        mode: str,
        used_helpers: set[str] | None = None,
    ) -> None:
        self.function = function
        self.native_names_by_qualname = native_names_by_qualname
        self.native_names = native_names
        self.native_return_types = native_return_types
        self.mode = mode
        self.declared = {param.name for param in function.params}
        self.variable_types = {param.name: param.type for param in function.params}
        self.maybe_bound_types: dict[str, RxtType] = {}
        self.temp_index = 0
        # Checked-arithmetic helper names (e.g. "add", "neg") used by this
        # function, recorded structurally so the module assembler emits exactly
        # the helpers that are referenced rather than scanning the rendered text.
        self.used_helpers = used_helpers if used_helpers is not None else set()

    def render(self) -> str:
        assigned_names = _assigned_names(self.function.body)
        params = ", ".join(
            f"{'mut ' if param.name in assigned_names else ''}"
            f"{rust_identifier(param.name)}: {rust_type(param.type)}"
            for param in self.function.params
        )
        return_type = rust_type(self.function.return_type)
        rust_name = rust_identifier(native_function_name(self.function.qualname))
        if self.mode == "pyo3":
            lines = [
                "#[pyfunction]",
                f"fn {rust_name}({params}) -> PyResult<{return_type}> {{",
            ]
        else:
            lines = [
                f"pub fn {rust_name}({params}) -> Result<{return_type}, RextioError> {{",
            ]
        lines.extend(self.render_block(self.function.body, indent=1))
        if not _block_always_returns(self.function.body):
            lines.append(f"{_indent(1)}Ok({default_return(return_type)})")
        lines.append("}")
        return "\n".join(lines)

    def render_block(self, block: BlockIR, indent: int) -> list[str]:
        lines: list[str] = []
        for statement in block.statements:
            lines.extend(self.render_statement(statement, indent))
        return lines

    def render_statement(self, statement: StatementIR, indent: int) -> list[str]:
        prefix = _indent(indent)
        if isinstance(statement, AssignIR):
            lines = self.named_expr_prelude(statement.value, indent)
            target = statement.target.id  # original name for bookkeeping
            emit = rust_identifier(target)  # escaped name for emission
            target_type = statement.target_type or self.infer_expr_type(statement.value)
            value = strip_expr_if_safe(
                statement.value,
                self.render_assignment_value(statement.value, target_type),
            )
            if target_type is not None:
                self.variable_types[target] = target_type
            if target in self.maybe_bound_types:
                return [*lines, f"{prefix}{emit} = Some({value});"]
            if target in self.declared:
                return [*lines, f"{prefix}{emit} = {value};"]
            self.declared.add(target)
            if statement.target_type is not None and _needs_local_type_annotation(statement.value, statement.target_type):
                return [*lines, f"{prefix}let mut {emit}: {rust_type(statement.target_type)} = {value};"]
            return [*lines, f"{prefix}let mut {emit} = {value};"]
        if isinstance(statement, DictSetIR):
            # Python evaluates the RHS value before the subscript key for
            # `d[k] = v`; bind the value first to preserve that order.
            value_tmp = self.next_temp("__rextio_value")
            lines = [
                *self.named_expr_prelude(statement.value, indent),
                f"{prefix}let {value_tmp} = "
                f"{strip_wrapping_parens(self.render_call_arg(statement.value))};",
                *self.named_expr_prelude(statement.key, indent),
            ]
            self.declared.add(statement.target.id)
            return [
                *lines,
                f"{prefix}{rust_identifier(statement.target.id)}.insert("
                f"{strip_wrapping_parens(self.render_call_arg(statement.key))}, {value_tmp});"
            ]
        if isinstance(statement, AppendIR):
            lines = self.named_expr_prelude(statement.value, indent)
            return [
                *lines,
                f"{prefix}{rust_identifier(statement.target.id)}.push("
                f"{strip_wrapping_parens(self.render_call_arg(statement.value))});"
            ]
        if isinstance(statement, EffectCallIR):
            lines = self.named_expr_prelude(statement.call, indent)
            return [*lines, f"{prefix}{self.render_call(statement.call)};"]
        if isinstance(statement, BreakIR):
            return [f"{prefix}break;"]
        if isinstance(statement, ContinueIR):
            return [f"{prefix}continue;"]
        if isinstance(statement, ReturnIR):
            if statement.value is None:
                # A bare `return` is Python `return None`. In an `Optional[T]`
                # function that is `Ok(None)` (the `Option` is `None`), not
                # `Ok(())` which would be a unit value and fail to compile against
                # the `Option<T>` return type.
                if isinstance(self.function.return_type, RxtOptional):
                    return [f"{prefix}return Ok(None);"]
                return [f"{prefix}return Ok(());"]
            lines = self.named_expr_prelude(statement.value, indent)
            value = strip_expr_if_safe(
                statement.value,
                self.render_expr_with_expected(statement.value, self.function.return_type),
            )
            return [*lines, f"{prefix}return Ok({value});"]
        if isinstance(statement, IfIR):
            lines = self.named_expr_prelude(statement.condition, indent)
            condition = strip_wrapping_parens(self.render_expr(statement.condition))
            lines.append(f"{prefix}if {condition} {{")
            lines.extend(self.render_block(statement.body, indent + 1))
            if statement.orelse.statements:
                lines.append(f"{prefix}}} else {{")
                lines.extend(self.render_block(statement.orelse, indent + 1))
            lines.append(f"{prefix}}}")
            return lines
        if isinstance(statement, ForIR):
            lines = self.named_expr_prelude(statement.iterable, indent)
            iterable = self.render_iterable(statement.iterable)
            lines = [
                *lines,
                f"{prefix}for {self.render_loop_target(statement.target)} "
                f"in {iterable} {{"
            ]
            self.declared.update(target_names(statement.target))
            # Bind the loop variable's type for the body so type-directed
            # rendering (e.g. checked integer arithmetic on `acc += x`) sees the
            # element type, mirroring the comprehension-generator path.
            self.bind_target_types(
                statement.target, self.iterable_target_types(statement.iterable)
            )
            lines.extend(self.render_block(statement.body, indent + 1))
            lines.append(f"{prefix}}}")
            return lines
        if isinstance(statement, WhileIR):
            lines = self.named_expr_prelude(statement.condition, indent)
            condition = strip_wrapping_parens(self.render_expr(statement.condition))
            lines.append(f"{prefix}while {condition} {{")
            lines.extend(self.render_block(statement.body, indent + 1))
            lines.append(f"{prefix}}}")
            return lines
        if isinstance(statement, TryIR):
            return self.render_try(statement, indent)
        raise RustCodegenError(f"unsupported statement IR: {type(statement).__name__}")

    def render_try(self, statement: TryIR, indent: int) -> list[str]:
        """Render a ``try``/``except``/``finally`` statement.

        Python ``try`` semantics are modelled with immediately-invoked closures:
        the inner closure runs the ``try`` body (``?`` turns a Python exception
        into an ``Err``); a ``match`` dispatches to the first ``except`` handler
        whose built-in type matches (preserving Python's top-to-bottom order),
        re-raising otherwise. The whole try/except is itself a closure, so the
        ``finally`` body runs on every path before any pending error is
        propagated with ``?`` — matching Python's "finally always runs, then the
        exception continues" rule. The analyzer guarantees the restricted subset
        this relies on (built-in handlers only, no ``return`` and no
        ``break``/``continue`` targeting a loop outside the block, and no
        non-comprehension variable first-bound inside a block).
        """
        if self.mode != "pyo3":
            raise RustCodegenError(
                "native try/except is only supported in the pyo3 backend, "
                "not the importable Rust crate"
            )
        prefix = _indent(indent)
        outcome = self.next_temp("__rextio_try")
        err = f"{outcome}_err"
        inner = f"{outcome}_body"
        lines = [f"{prefix}let {outcome}: PyResult<()> = (|| -> PyResult<()> {{"]
        lines.append(f"{_indent(indent + 1)}let {inner}: PyResult<()> = (|| -> PyResult<()> {{")
        lines.extend(self.render_block(statement.body, indent + 2))
        lines.append(f"{_indent(indent + 2)}Ok(())")
        lines.append(f"{_indent(indent + 1)}}})();")
        lines.append(f"{_indent(indent + 1)}match {inner} {{")
        lines.append(f"{_indent(indent + 2)}Ok(()) => Ok(()),")
        lines.append(f"{_indent(indent + 2)}Err({err}) => {{")
        if statement.handlers:
            for position, handler in enumerate(statement.handlers):
                pyo3_exception = BUILTIN_EXCEPTION_TO_PYO3[handler.exception]
                guard = (
                    f"Python::with_gil(|py| {err}.is_instance_of::<{pyo3_exception}>(py))"
                )
                keyword = "if" if position == 0 else "} else if"
                lines.append(f"{_indent(indent + 3)}{keyword} {guard} {{")
                lines.extend(self.render_block(handler.body, indent + 4))
                lines.append(f"{_indent(indent + 4)}Ok(())")
            lines.append(f"{_indent(indent + 3)}}} else {{")
            lines.append(f"{_indent(indent + 4)}Err({err})")
            lines.append(f"{_indent(indent + 3)}}}")
        else:
            lines.append(f"{_indent(indent + 3)}Err({err})")
        lines.append(f"{_indent(indent + 2)}}}")
        lines.append(f"{_indent(indent + 1)}}}")
        lines.append(f"{prefix}}})();")
        lines.extend(self.render_block(statement.finalbody, indent))
        lines.append(f"{prefix}{outcome}?;")
        return lines

    def render_iterable(self, expr: ExprIR) -> str:
        if isinstance(expr, NameIR):
            return f"{rust_identifier(expr.id)}.iter().cloned()"
        if isinstance(expr, CallIR) and expr.function == "enumerate" and len(expr.args) == 1:
            return (
                f"{self.render_expr(expr.args[0])}.iter().cloned().enumerate()"
                ".map(|(i, value)| (i as i64, value))"
            )
        if isinstance(expr, CallIR) and expr.function == "zip" and len(expr.args) == 2:
            return (
                f"{self.render_expr(expr.args[0])}.iter().cloned()"
                f".zip({self.render_expr(expr.args[1])}.iter().cloned())"
            )
        if isinstance(expr, CallIR) and expr.function == "reversed" and len(expr.args) == 1:
            return f"{self.render_expr(expr.args[0])}.iter().rev().cloned()"
        if (
            isinstance(expr, CallIR)
            and expr.function == "range"
            and len(expr.args) == 1
            and isinstance(expr.args[0], CallIR)
            and expr.args[0].function == "len"
            and len(expr.args[0].args) == 1
        ):
            # `range(len(x))` lowers the bound inline; mirror the value-position
            # `len` rule so a `str` counts code points (`.chars().count()`), not
            # the UTF-8 byte length `String::len` returns.
            inner = expr.args[0].args[0]
            if isinstance(self.infer_expr_type(inner), RxtStr):
                return f"0..({self.render_expr(inner)}.chars().count() as i64)"
            return f"0..({self.render_expr(inner)}.len() as i64)"
        if isinstance(expr, CallIR) and expr.function == "range" and len(expr.args) == 1:
            return f"0..{self.render_expr(expr.args[0])}"
        if isinstance(expr, CallIR) and expr.function == "range" and len(expr.args) == 2:
            return f"{self.render_expr(expr.args[0])}..{self.render_expr(expr.args[1])}"
        if isinstance(expr, CallIR) and expr.function == "range" and len(expr.args) == 3:
            return (
                f"({self.render_expr(expr.args[0])}..{self.render_expr(expr.args[1])})"
                f".step_by({strip_wrapping_parens(self.render_expr(expr.args[2]))} as usize)"
            )
        raise RustCodegenError("unsupported for-loop iterable")

    def render_loop_target(self, target: TargetIR) -> str:
        if isinstance(target, NameIR):
            return rust_identifier(target.id)
        if isinstance(target, TupleTargetIR):
            return f"({', '.join(rust_identifier(item.id) for item in target.items)})"
        raise RustCodegenError(f"unsupported loop target IR: {type(target).__name__}")

    def render_expr(self, expr: ExprIR) -> str:
        if isinstance(expr, LiteralIR):
            return render_literal(expr.value)
        if isinstance(expr, NameIR):
            if expr.id in self.maybe_bound_types:
                return self.render_maybe_bound_name(expr.id)
            return rust_identifier(expr.id)
        if isinstance(expr, ListIR):
            return f"vec![{', '.join(self.render_owned_expr(item) for item in expr.items)}]"
        if isinstance(expr, ListComprehensionIR):
            return self.render_list_comprehension(expr)
        if isinstance(expr, TupleIR):
            if len(expr.items) == 1:
                return f"({self.render_owned_expr(expr.items[0])},)"
            return f"({', '.join(self.render_owned_expr(item) for item in expr.items)})"
        if isinstance(expr, DictIR):
            if not expr.items:
                return "HashMap::new()"
            lines = ["{"]
            lines.append("    let mut map = HashMap::new();")
            for key, value in expr.items:
                lines.append(
                    f"    map.insert({strip_wrapping_parens(self.render_call_arg(key))}, "
                    f"{strip_wrapping_parens(self.render_owned_expr(value))});"
                )
            lines.append("    map")
            lines.append("}")
            return "\n".join(lines)
        if isinstance(expr, DictComprehensionIR):
            return self.render_dict_comprehension(expr)
        if isinstance(expr, SetIR):
            if not expr.items:
                return "HashSet::new()"
            lines = ["{"]
            lines.append("    let mut set = HashSet::new();")
            for item in expr.items:
                lines.append(f"    set.insert({strip_wrapping_parens(self.render_call_arg(item))});")
            lines.append("    set")
            lines.append("}")
            return "\n".join(lines)
        if isinstance(expr, SetComprehensionIR):
            return self.render_set_comprehension(expr)
        if isinstance(expr, BinaryOpIR):
            checked = self.render_checked_int_binop(expr)
            if checked is None:
                checked = self.render_checked_float_binop(expr)
            if checked is not None:
                return checked
            op = {"and": "&&", "or": "||"}.get(expr.op, expr.op)
            return f"({self.render_expr(expr.left)} {op} {self.render_expr(expr.right)})"
        if isinstance(expr, UnaryOpIR):
            checked = self.render_checked_int_neg(expr)
            if checked is not None:
                return checked
            op = "!" if expr.op == "not" else expr.op
            return f"({op}{self.render_expr(expr.value)})"
        if isinstance(expr, CompareIR):
            return self.render_compare(expr)
        if isinstance(expr, CallIR):
            return self.render_call(expr)
        if isinstance(expr, IndexIR):
            return self.render_index_expr(expr)
        if isinstance(expr, NamedExprIR):
            return self.render_named_expr(expr)
        raise RustCodegenError(f"unsupported expression IR: {type(expr).__name__}")

    def render_list_comprehension(self, expr: ListComprehensionIR) -> str:
        target = self.next_temp("__rextio_list")
        lines = ["{"]
        lines.append(f"    let mut {target} = Vec::new();")
        lines.extend(
            self.render_comprehension_generators(
                expr.generators,
                1,
                lambda indent: [
                    f"{_indent(indent)}{target}.push("
                    f"{strip_wrapping_parens(self.render_call_arg(expr.item))});"
                ],
            )
        )
        lines.append(f"    {target}")
        lines.append("}")
        return "\n".join(lines)

    def render_dict_comprehension(self, expr: DictComprehensionIR) -> str:
        target = self.next_temp("__rextio_dict")
        lines = ["{"]
        lines.append(f"    let mut {target} = HashMap::new();")
        lines.extend(
            self.render_comprehension_generators(
                expr.generators,
                1,
                lambda indent: [
                    f"{_indent(indent)}{target}.insert("
                    f"{strip_wrapping_parens(self.render_call_arg(expr.key))}, "
                    f"{strip_wrapping_parens(self.render_call_arg(expr.value))});"
                ],
            )
        )
        lines.append(f"    {target}")
        lines.append("}")
        return "\n".join(lines)

    def render_set_comprehension(self, expr: SetComprehensionIR) -> str:
        target = self.next_temp("__rextio_set")
        lines = ["{"]
        lines.append(f"    let mut {target} = HashSet::new();")
        lines.extend(
            self.render_comprehension_generators(
                expr.generators,
                1,
                lambda indent: [
                    f"{_indent(indent)}{target}.insert("
                    f"{strip_wrapping_parens(self.render_call_arg(expr.item))});"
                ],
            )
        )
        lines.append(f"    {target}")
        lines.append("}")
        return "\n".join(lines)

    def render_comprehension_generators(
        self,
        generators: list[ComprehensionGeneratorIR],
        index: int,
        render_leaf: Callable[[int], list[str]],
    ) -> list[str]:
        if index > len(generators):
            return render_leaf(index)
        generator = generators[index - 1]
        prefix = _indent(index)
        iterable = self.render_iterable(generator.iterable)
        lines = [
            f"{prefix}for {self.render_loop_target(generator.target)} in {iterable} {{"
        ]
        saved_types = dict(self.variable_types)
        self.bind_target_types(generator.target, self.iterable_target_types(generator.iterable))
        if generator.conditions:
            condition = " && ".join(
                strip_wrapping_parens(self.render_expr(condition))
                for condition in generator.conditions
            )
            lines.append(f"{_indent(index + 1)}if {condition} {{")
            lines.extend(self.render_comprehension_generators(generators, index + 1, render_leaf))
            lines.append(f"{_indent(index + 1)}}}")
        else:
            lines.extend(self.render_comprehension_generators(generators, index + 1, render_leaf))
        self.variable_types = saved_types
        lines.append(f"{prefix}}}")
        return lines

    def iterable_target_types(self, expr: ExprIR) -> list[RxtType]:
        if isinstance(expr, CallIR) and expr.function == "enumerate" and len(expr.args) == 1:
            item_type = self.iterable_item_type(expr.args[0])
            return [RxtInt(), item_type] if item_type is not None else []
        if isinstance(expr, CallIR) and expr.function == "zip" and len(expr.args) == 2:
            item_types = [self.iterable_item_type(arg) for arg in expr.args]
            return [item for item in item_types if item is not None]
        if isinstance(expr, CallIR) and expr.function == "range":
            return [RxtInt()]
        item_type = self.iterable_item_type(expr)
        return [item_type] if item_type is not None else []

    def iterable_item_type(self, expr: ExprIR) -> RxtType | None:
        value_type = self.infer_expr_type(expr)
        if isinstance(value_type, (RxtList, RxtSet)):
            return value_type.item_type
        return None

    def bind_target_types(self, target: TargetIR, item_types: list[RxtType]) -> None:
        if isinstance(target, NameIR) and len(item_types) == 1:
            self.variable_types[target.id] = item_types[0]
            return
        if isinstance(target, TupleTargetIR) and len(target.items) == len(item_types):
            for item, item_type in zip(target.items, item_types, strict=True):
                self.variable_types[item.id] = item_type

    def render_named_expr(self, expr: NamedExprIR) -> str:
        target = expr.target.id  # original name for bookkeeping
        emit = rust_identifier(target)  # escaped name for emission
        value = strip_expr_if_safe(
            expr.value,
            self.render_call_arg(expr.value),
        )
        if target in self.maybe_bound_types:
            return (
                f"{{ {emit} = Some({value}); "
                f"{self.render_maybe_bound_name(target)} }}"
            )
        return f"{{ {emit} = {value}; {emit}.clone() }}"

    def render_maybe_bound_name(self, name: str) -> str:
        # The diagnostic message keeps the original Python name; the emitted Rust
        # identifier is escaped (e.g. a keyword name -> `r#name`).
        message = rust_string_literal(f"local variable '{name}' referenced before assignment")
        return (
            f"{rust_identifier(name)}.clone().ok_or_else(|| "
            f"{self.error_new(message, kind='unbound')})?"
        )

    def error_new(self, message: str, *, kind: str = "value") -> str:
        if self.mode == "pyo3":
            exception = {
                "key": "PyKeyError",
                "runtime": "PyRuntimeError",
                "unbound": "PyUnboundLocalError",
                "value": "PyValueError",
            }.get(kind, "PyValueError")
            return f"pyo3::exceptions::{exception}::new_err({message})"
        return f'RextioError::new("{_crate_exception_name(kind)}", {message})'

    def error_from_to_string(self, value: str, *, kind: str = "value") -> str:
        return self.error_new(f"{value}.to_string()", kind=kind)

    def map_err_to_error(self, *, kind: str = "value") -> str:
        if self.mode == "pyo3":
            exception = {
                "runtime": "PyRuntimeError",
                "value": "PyValueError",
            }.get(kind, "PyValueError")
            return f".map_err(|err| pyo3::exceptions::{exception}::new_err(err.to_string()))?"
        return (
            f'.map_err(|err| RextioError::new("{_crate_exception_name(kind)}", err.to_string()))?'
        )

    def next_temp(self, prefix: str) -> str:
        self.temp_index += 1
        return f"{prefix}_{self.temp_index}"

    def named_expr_prelude(self, expr: ExprIR, indent: int) -> list[str]:
        bindings = self.collect_named_expr_bindings(expr)
        lines: list[str] = []
        for name, binding_type in bindings.items():
            if name in self.declared:
                self.variable_types[name] = self.variable_types.get(name, binding_type)
                continue
            self.declared.add(name)
            self.variable_types[name] = binding_type
            self.maybe_bound_types[name] = binding_type
            lines.append(
                f"{_indent(indent)}let mut {rust_identifier(name)}: Option<{rust_type(binding_type)}> = None;"
            )
        return lines

    def collect_named_expr_bindings(self, expr: ExprIR) -> dict[str, RxtType]:
        bindings: dict[str, RxtType] = {}
        scope = dict(self.variable_types)
        self.collect_named_expr_bindings_in_expr(expr, scope, scope, bindings)
        return bindings

    def collect_named_expr_bindings_in_expr(
        self,
        expr: ExprIR,
        scope: dict[str, RxtType],
        binding_scope: dict[str, RxtType],
        bindings: dict[str, RxtType],
    ) -> None:
        if isinstance(expr, NamedExprIR):
            self.collect_named_expr_bindings_in_expr(expr.value, scope, binding_scope, bindings)
            value_type = self.infer_expr_type_in_scope(expr.value, scope)
            if value_type is None:
                raise RustCodegenError("cannot infer assignment expression type")
            bindings.setdefault(expr.target.id, value_type)
            scope[expr.target.id] = value_type
            binding_scope[expr.target.id] = value_type
            return
        if isinstance(expr, BinaryOpIR):
            self.collect_named_expr_bindings_in_expr(expr.left, scope, binding_scope, bindings)
            self.collect_named_expr_bindings_in_expr(expr.right, scope, binding_scope, bindings)
            return
        if isinstance(expr, UnaryOpIR):
            self.collect_named_expr_bindings_in_expr(expr.value, scope, binding_scope, bindings)
            return
        if isinstance(expr, CompareIR):
            self.collect_named_expr_bindings_in_expr(expr.left, scope, binding_scope, bindings)
            for comparator in expr.comparators:
                self.collect_named_expr_bindings_in_expr(comparator, scope, binding_scope, bindings)
            return
        if isinstance(expr, CallIR):
            for arg in expr.args:
                self.collect_named_expr_bindings_in_expr(arg, scope, binding_scope, bindings)
            return
        if isinstance(expr, IndexIR):
            self.collect_named_expr_bindings_in_expr(expr.value, scope, binding_scope, bindings)
            self.collect_named_expr_bindings_in_expr(expr.index, scope, binding_scope, bindings)
            return
        if isinstance(expr, ListIR):
            for item in expr.items:
                self.collect_named_expr_bindings_in_expr(item, scope, binding_scope, bindings)
            return
        if isinstance(expr, TupleIR):
            for item in expr.items:
                self.collect_named_expr_bindings_in_expr(item, scope, binding_scope, bindings)
            return
        if isinstance(expr, DictIR):
            for key, value in expr.items:
                self.collect_named_expr_bindings_in_expr(key, scope, binding_scope, bindings)
                self.collect_named_expr_bindings_in_expr(value, scope, binding_scope, bindings)
            return
        if isinstance(expr, SetIR):
            for item in expr.items:
                self.collect_named_expr_bindings_in_expr(item, scope, binding_scope, bindings)
            return
        if isinstance(expr, ListComprehensionIR):
            self.collect_named_expr_bindings_in_comprehension(
                expr.generators,
                [expr.item],
                scope,
                binding_scope,
                bindings,
            )
            return
        if isinstance(expr, DictComprehensionIR):
            self.collect_named_expr_bindings_in_comprehension(
                expr.generators,
                [expr.key, expr.value],
                scope,
                binding_scope,
                bindings,
            )
            return
        if isinstance(expr, SetComprehensionIR):
            self.collect_named_expr_bindings_in_comprehension(
                expr.generators,
                [expr.item],
                scope,
                binding_scope,
                bindings,
            )

    def collect_named_expr_bindings_in_comprehension(
        self,
        generators: list[ComprehensionGeneratorIR],
        result_exprs: list[ExprIR],
        scope: dict[str, RxtType],
        binding_scope: dict[str, RxtType],
        bindings: dict[str, RxtType],
    ) -> None:
        comp_scope = dict(scope)
        for generator in generators:
            self.collect_named_expr_bindings_in_expr(
                generator.iterable,
                comp_scope,
                binding_scope,
                bindings,
            )
            item_types = self.iterable_target_types_in_scope(generator.iterable, comp_scope)
            self.bind_target_types_to_scope(generator.target, item_types, comp_scope)
            for condition in generator.conditions:
                self.collect_named_expr_bindings_in_expr(
                    condition,
                    comp_scope,
                    binding_scope,
                    bindings,
                )
        for result_expr in result_exprs:
            self.collect_named_expr_bindings_in_expr(
                result_expr,
                comp_scope,
                binding_scope,
                bindings,
            )

    def infer_expr_type_in_scope(
        self,
        expr: ExprIR,
        scope: dict[str, RxtType],
    ) -> RxtType | None:
        saved_types = self.variable_types
        self.variable_types = scope
        try:
            return self.infer_expr_type(expr)
        finally:
            self.variable_types = saved_types

    def iterable_target_types_in_scope(
        self,
        expr: ExprIR,
        scope: dict[str, RxtType],
    ) -> list[RxtType]:
        saved_types = self.variable_types
        self.variable_types = scope
        try:
            return self.iterable_target_types(expr)
        finally:
            self.variable_types = saved_types

    def bind_target_types_to_scope(
        self,
        target: TargetIR,
        item_types: list[RxtType],
        scope: dict[str, RxtType],
    ) -> None:
        if isinstance(target, NameIR) and len(item_types) == 1:
            scope[target.id] = item_types[0]
            return
        if isinstance(target, TupleTargetIR) and len(target.items) == len(item_types):
            for item, item_type in zip(target.items, item_types, strict=True):
                scope[item.id] = item_type

    def _index_error_expr(self) -> str:
        """Mode-aware constructor expression for a Python ``IndexError``."""
        if self.mode == "pyo3":
            return 'pyo3::exceptions::PyIndexError::new_err("list index out of range")'
        return 'RextioError::new("IndexError", "list index out of range")'

    def _key_error_expr(self, key: str) -> str:
        """Mode-aware constructor expression for a Python ``KeyError``."""
        if self.mode == "pyo3":
            return f"pyo3::exceptions::PyKeyError::new_err({key}.clone())"
        return f'RextioError::new("KeyError", format!("key not found: {{:?}}", {key}))'

    def render_checked_int_binop(self, expr: BinaryOpIR) -> str | None:
        """Render an i64 ``+``/``-``/``*``/``%`` as checked arithmetic, or ``None``.

        Returns ``None`` when the operator is not overflow-prone integer
        arithmetic (the caller then falls back to the plain rendering). When both
        operands are ``int``, the operation is lowered to a ``__rextio_checked_*``
        helper that raises ``OverflowError`` / ``ZeroDivisionError`` (PyO3) or
        returns ``RextioError`` (crate) instead of wrapping or panicking. Python
        ``int`` is arbitrary precision, so an i64 op that would wrap/overflow is an
        ``OverflowError`` (catchable via ``except Exception``) rather than the
        previous ``overflow-checks`` panic, which PyO3 surfaces as an uncatchable
        ``PanicException`` (a ``BaseException``); ``a % 0`` is a ``ZeroDivisionError``.
        The helper is a plain function call, so an operand sub-expression
        containing ``?`` propagates in function scope with no closure to leak into.
        """
        name = {"+": "add", "-": "sub", "*": "mul", "%": "rem"}.get(expr.op)
        if name is None:
            return None
        left_type = self.infer_expr_type(expr.left)
        right_type = self.infer_expr_type(expr.right)
        if not (isinstance(left_type, RxtInt) and isinstance(right_type, RxtInt)):
            return None
        left = strip_wrapping_parens(self.render_expr(expr.left))
        right = strip_wrapping_parens(self.render_expr(expr.right))
        self.used_helpers.add(name)
        return f"__rextio_checked_{name}({left}, {right})?"

    def render_checked_int_neg(self, expr: UnaryOpIR) -> str | None:
        """Render an i64 unary ``-`` as checked negation, or ``None``.

        ``-i64::MIN`` overflows (Python ``int`` is arbitrary precision, so
        ``-(-2**63) == 2**63``); route int negation through ``__rextio_checked_neg``
        so it raises ``OverflowError`` instead of an uncatchable panic.
        """
        if expr.op != "-":
            return None
        if not isinstance(self.infer_expr_type(expr.value), RxtInt):
            return None
        value = strip_wrapping_parens(self.render_expr(expr.value))
        self.used_helpers.add("neg")
        return f"__rextio_checked_neg({value})?"

    def render_checked_float_binop(self, expr: BinaryOpIR) -> str | None:
        """Render an f64 ``/`` or ``%`` with Python semantics, or ``None``.

        Python raises ``ZeroDivisionError`` for float division/modulo by zero
        (Rust returns inf/NaN), and float ``%`` is floored like the integer case
        (Rust ``%`` is truncated). Route both through helpers so the divide-by-zero
        is catchable and the modulo sign matches Python.
        """
        name = {"/": "fdiv", "%": "frem"}.get(expr.op)
        if name is None:
            return None
        left_type = self.infer_expr_type(expr.left)
        right_type = self.infer_expr_type(expr.right)
        if not (isinstance(left_type, RxtFloat) and isinstance(right_type, RxtFloat)):
            return None
        left = strip_wrapping_parens(self.render_expr(expr.left))
        right = strip_wrapping_parens(self.render_expr(expr.right))
        self.used_helpers.add(name)
        return f"__rextio_checked_{name}({left}, {right})?"

    def render_index_expr(self, expr: IndexIR) -> str:
        value_type = self.infer_expr_type(expr.value)
        if isinstance(value_type, RxtTuple):
            tuple_index = literal_int(expr.index)
            if tuple_index is None or tuple_index < 0 or tuple_index >= len(value_type.item_types):
                raise RustCodegenError("tuple index must be an in-range literal")
            return f"{self.render_expr(expr.value)}.{tuple_index}.clone()"
        if isinstance(value_type, RxtDict):
            mapping = self.next_temp("__rextio_map")
            key_tmp = self.next_temp("__rextio_key")
            key = strip_wrapping_parens(self.render_expr(expr.index))
            # Bind value and key to temporaries before the error closure. The key
            # expression may itself contain `?` (e.g. `m[xs[i]]`); evaluating it in
            # a let-binding keeps the `?` in function scope instead of leaking into
            # the `ok_or_else` closure body, which would not compile.
            return (
                f"{{ let {mapping} = &{self.render_expr(expr.value)}; "
                f"let {key_tmp} = {key}; "
                f"{mapping}.get(&{key_tmp}).cloned()"
                f".ok_or_else(|| {self._key_error_expr(key_tmp)})? }}"
            )
        # Sequence indexing preserves Python semantics:
        #   * a negative index counts from the end (`xs[-1]` is the last item),
        #   * an out-of-range index (after normalization) raises IndexError
        #     instead of panicking via an unchecked `[]`.
        # The sequence and index are bound to temporaries so neither sub-expression
        # is evaluated twice. The index is cast to i64 (absorbing any integer
        # operand type); negative normalization uses checked_add (cannot overflow
        # by construction, but this avoids any debug-build overflow panic and makes
        # it explicit). Bounds are checked in the i64 domain, so the final
        # `as usize` only runs for an in-range index — correct on every target
        # width (no reliance on usize truncation). `len() as i64` is exact because a
        # sequence length never exceeds `isize::MAX <= i64::MAX`.
        seq = self.next_temp("__rextio_seq")
        index = self.next_temp("__rextio_index")
        length = self.next_temp("__rextio_len")
        bound = self.next_temp("__rextio_bound")
        return (
            f"{{ let {seq} = &{self.render_expr(expr.value)}; "
            f"let {length} = {seq}.len() as i64; "
            f"let {index} = ({strip_wrapping_parens(self.render_expr(expr.index))}) as i64; "
            f"let {index} = if {index} < 0 {{ {index}.checked_add({length}) }} "
            f"else {{ Some({index}) }}; "
            f"(match {index} {{ "
            f"Some({bound}) if {bound} >= 0 && {bound} < {length} => "
            f"{seq}.get({bound} as usize).cloned(), "
            f"_ => None }})"
            f".ok_or_else(|| {self._index_error_expr()})? }}"
        )

    def render_compare(self, expr: CompareIR) -> str:
        if len(expr.ops) != len(expr.comparators):
            raise RustCodegenError("invalid comparison IR")
        left = expr.left
        parts: list[str] = []
        for op, comparator in zip(expr.ops, expr.comparators, strict=True):
            parts.append(f"({self.render_expr(left)} {op} {self.render_expr(comparator)})")
            left = comparator
        # A chained comparison `a < b < c` lowers to `(a < b) && (b < c)`, which
        # renders the shared middle operand `b` twice and so evaluates it twice
        # when the first comparison is true (CPython evaluates it once). Rust `&&`
        # preserves CPython's left-to-right short-circuit exactly, so for a pure,
        # deterministic operand the second evaluation yields the same value and
        # the only cost is redundant computation. The analyzer rejects any chained
        # comparison whose middle operand contains a call (see
        # `_validate_compare_types`), which is the only way a non-deterministic or
        # side-effecting operand could reach here, so the doubled evaluation is
        # always divergence-free by construction.
        return " && ".join(parts)

    def render_call(self, expr: CallIR) -> str:
        if expr.function == "len" and len(expr.args) == 1:
            # CPython `len(str)` counts Unicode code points; Rust `String::len`
            # returns the UTF-8 byte length, so a `str` argument must use
            # `.chars().count()` to match (e.g. `len("é") == 1`, not 2). Other
            # sized types (bytes/list/set/dict) use `.len()` faithfully.
            if isinstance(self.infer_expr_type(expr.args[0]), RxtStr):
                return f"({self.render_expr(expr.args[0])}.chars().count() as i64)"
            return f"({self.render_expr(expr.args[0])}.len() as i64)"
        if expr.function == "abs" and len(expr.args) == 1:
            if isinstance(self.infer_expr_type(expr.args[0]), RxtInt):
                self.used_helpers.add("abs")
                return f"__rextio_checked_abs({strip_wrapping_parens(self.render_expr(expr.args[0]))})?"
            return f"({self.render_expr(expr.args[0])}).abs()"
        if expr.function in {"min", "max"} and len(expr.args) == 2:
            # Rust's f64::min/max are NOT CPython-equivalent on NaN: f64::min
            # returns the non-NaN operand, but CPython's min/max keep the first
            # operand whenever the comparison is False (which it always is when
            # either operand is NaN). So `min(nan, 1.0)` is `nan` in CPython but
            # `1.0` via f64::min -> a silent wrong value. Emit CPython's own
            # `b < a ? b : a` (min) / `b > a ? b : a` (max) form instead, binding
            # both operands to locals first so each is evaluated exactly once,
            # left-to-right, matching CPython argument evaluation. Integers have
            # no NaN, but the comparison form is equally correct, so use it for
            # both numeric types.
            cmp = "<" if expr.function == "min" else ">"
            a_tmp = self.next_temp(f"__rextio_{expr.function}_a")
            b_tmp = self.next_temp(f"__rextio_{expr.function}_b")
            return (
                f"{{ let {a_tmp} = {self.render_expr(expr.args[0])}; "
                f"let {b_tmp} = {self.render_expr(expr.args[1])}; "
                f"if {b_tmp} {cmp} {a_tmp} {{ {b_tmp} }} else {{ {a_tmp} }} }}"
            )
        if expr.function == "sum" and len(expr.args) == 1:
            arg_type = self.infer_expr_type(expr.args[0])
            if isinstance(arg_type, RxtList) and isinstance(arg_type.item_type, RxtInt):
                self.used_helpers.add("sum")
                return f"__rextio_checked_sum(&{self.render_expr(expr.args[0])})?"
            return f"({self.render_expr(expr.args[0])}).iter().cloned().sum()"
        if expr.function == "all" and len(expr.args) == 1:
            return f"({self.render_expr(expr.args[0])}).iter().copied().all(|value| value)"
        if expr.function == "any" and len(expr.args) == 1:
            return f"({self.render_expr(expr.args[0])}).iter().copied().any(|value| value)"
        if expr.function == "sorted" and len(expr.args) == 1:
            return self.render_sorted(expr.args[0])
        if expr.function == "reversed" and len(expr.args) == 1:
            return self.render_reversed(expr.args[0])
        if expr.function == "math.pi" and not expr.args:
            return "std::f64::consts::PI"
        if expr.function == "math.e" and not expr.args:
            return "std::f64::consts::E"
        if expr.function in {
            "math.atan",
            "math.cos",
            "math.exp",
            "math.sin",
            "math.tan",
        } and len(expr.args) == 1:
            method = expr.function.rsplit(".", 1)[1]
            return f"({self.render_expr(expr.args[0])}).{method}()"
        # Domain-error-prone math functions: CPython raises ValueError only for
        # an out-of-domain *input* (a nan/inf input returns nan/inf, not an
        # error), so validate the input before applying the operation rather
        # than checking the result for finiteness.
        if expr.function == "math.sqrt" and len(expr.args) == 1:
            self.used_helpers.add("mnonneg")
            return f"__rextio_checked_mnonneg({self.render_expr(expr.args[0])})?.sqrt()"
        if expr.function in {"math.acos", "math.asin"} and len(expr.args) == 1:
            method = expr.function.rsplit(".", 1)[1]
            self.used_helpers.add("munit")
            return f"__rextio_checked_munit({self.render_expr(expr.args[0])})?.{method}()"
        if expr.function in {"math.log10", "math.log2"} and len(expr.args) == 1:
            method = expr.function.rsplit(".", 1)[1]
            self.used_helpers.add("mpositive")
            return f"__rextio_checked_mpositive({self.render_expr(expr.args[0])})?.{method}()"
        if expr.function == "math.log":
            self.used_helpers.add("mpositive")
            if len(expr.args) == 1:
                return f"__rextio_checked_mpositive({self.render_expr(expr.args[0])})?.ln()"
            if len(expr.args) == 2:
                # `math.log(x, base)` also constrains the base: CPython raises
                # ValueError for base <= 0 and ZeroDivisionError for base == 1
                # (log(base) is 0). CPython evaluates BOTH argument expressions
                # left-to-right before any domain check, so bind both to locals
                # first — otherwise `mpositive(x)?` as the receiver would
                # short-circuit before `base` is even evaluated, dropping a
                # raising base's exception (e.g. `log(-1.0, a / 0.0)` would raise
                # ValueError natively where CPython raises ZeroDivisionError).
                # x's domain is then checked before the base's, matching CPython.
                self.used_helpers.add("mlogbase")
                x_tmp = self.next_temp("__rextio_log_x")
                base_tmp = self.next_temp("__rextio_log_base")
                return (
                    f"{{ let {x_tmp} = {self.render_expr(expr.args[0])}; "
                    f"let {base_tmp} = {self.render_expr(expr.args[1])}; "
                    f"__rextio_checked_mpositive({x_tmp})?"
                    f".log(__rextio_checked_mlogbase({base_tmp})?) }}"
                )
        if expr.function == "math.atan2" and len(expr.args) == 2:
            return f"({self.render_expr(expr.args[0])}).atan2({self.render_expr(expr.args[1])})"
        if expr.function in {"math.ceil", "math.floor", "math.trunc"} and len(expr.args) == 1:
            method = expr.function.rsplit(".", 1)[1]
            self.used_helpers.add("f2i")
            return f"__rextio_checked_f2i(({self.render_expr(expr.args[0])}).{method}())?"
        if expr.function in {"math.isfinite", "math.isinf", "math.isnan"} and len(expr.args) == 1:
            method = {
                "math.isfinite": "is_finite",
                "math.isinf": "is_infinite",
                "math.isnan": "is_nan",
            }[expr.function]
            return f"({self.render_expr(expr.args[0])}).{method}()"
        if expr.function.startswith("str.") or expr.function.startswith("bytes."):
            return self.render_string_or_bytes_method(expr)
        if expr.function.startswith("list."):
            return self.render_list_method(expr)
        if expr.function == "print":
            return self.render_format_macro("println!", expr.args, allow_empty=True)
        if expr.function in {"logging.debug", "logging.info", "logging.warning", "logging.error"}:
            macro = {
                "logging.debug": "log::debug!",
                "logging.info": "log::info!",
                "logging.warning": "log::warn!",
                "logging.error": "log::error!",
            }[expr.function]
            return self.render_logging_macro(macro, expr.args)
        if expr.function == "datetime.datetime.now.isoformat" and not expr.args:
            return self.render_naive_isoformat("chrono::Local::now().naive_local()")
        if expr.function == "datetime.datetime.utcnow.isoformat" and not expr.args:
            return self.render_naive_isoformat("chrono::Utc::now().naive_utc()")
        if expr.function == "datetime.datetime.now.timestamp" and not expr.args:
            return self.render_chrono_timestamp("chrono::Local::now()")
        if expr.function == "time.time" and not expr.args:
            return (
                "std::time::SystemTime::now()"
                ".duration_since(std::time::UNIX_EPOCH)"
                f"{self.map_err_to_error(kind='runtime')}"
                ".as_secs_f64()"
            )
        if expr.function == "hashlib.sha256.hexdigest" and len(expr.args) == 1:
            return f"format!(\"{{:x}}\", sha2::Sha256::digest(&{strip_wrapping_parens(self.render_call_arg(expr.args[0]))}))"
        if expr.function == "base64.b64encode" and len(expr.args) == 1:
            return (
                "base64::engine::general_purpose::STANDARD"
                f".encode({strip_wrapping_parens(self.render_call_arg(expr.args[0]))}).into_bytes()"
            )
        rust_name = self.native_names_by_qualname.get(expr.function)
        if rust_name is None:
            rust_name = self.native_names.get((self.function.module_name, expr.function))
        if rust_name is not None:
            args = ", ".join(self.render_call_arg(arg) for arg in expr.args)
            return f"{rust_name}({args})?"
        raise RustCodegenError(f"unsupported call during Rust codegen: {expr.function}")

    def render_sorted(self, expr: ExprIR) -> str:
        # `sorted` is only admitted for totally-ordered item types (int/bool/str);
        # `list[float]` is rejected to the Python fallback by the analyzer because
        # NaN ordering cannot match CPython, so `.sort()` (which requires `Ord`)
        # is always valid here.
        source = strip_wrapping_parens(self.render_call_arg(expr))
        return "\n".join(
            [
                "{",
                f"    let mut values = {source};",
                "    values.sort();",
                "    values",
                "}",
            ]
        )

    def render_reversed(self, expr: ExprIR) -> str:
        source = strip_wrapping_parens(self.render_call_arg(expr))
        return "\n".join(
            [
                "{",
                f"    let mut values = {source};",
                "    values.reverse();",
                "    values",
                "}",
            ]
        )

    def render_string_or_bytes_method(self, expr: CallIR) -> str:
        receiver = strip_wrapping_parens(self.render_call_arg(expr.args[0]))
        if expr.function == "str.lower" and len(expr.args) == 1:
            return f"{receiver}.to_lowercase()"
        if expr.function == "str.upper" and len(expr.args) == 1:
            return f"{receiver}.to_uppercase()"
        if expr.function == "str.encode" and len(expr.args) == 1:
            return f"{receiver}.as_bytes().to_vec()"
        if expr.function == "bytes.decode" and len(expr.args) == 1:
            # KNOWN LIMITATION (documented in docs/unsupported-features.md,
            # "Accepted Native Semantic Divergences"): on invalid UTF-8 this raises
            # ValueError, whereas CPython raises UnicodeDecodeError. UnicodeDecodeError
            # is a subclass of ValueError (so `except ValueError` still catches it).
            # A faithful UnicodeDecodeError is feasible but DEFERRED for alpha: the
            # inner native fn has no `py` token and `RextioError` only carries a
            # message, so it would require threading the decode-position data
            # (`str::from_utf8(...).valid_up_to()`) through to the wrapper boundary
            # where `py` is available. Valid UTF-8 decodes identically.
            return (
                f"String::from_utf8({receiver})"
                f"{self.map_err_to_error()}"
            )
        if expr.function in {"str.startswith", "str.endswith"} and len(expr.args) == 2:
            method = "starts_with" if expr.function == "str.startswith" else "ends_with"
            value = strip_wrapping_parens(self.render_call_arg(expr.args[1]))
            return f"{receiver}.{method}(&{value})"
        if expr.function == "str.replace" and len(expr.args) == 3:
            old = strip_wrapping_parens(self.render_call_arg(expr.args[1]))
            new = strip_wrapping_parens(self.render_call_arg(expr.args[2]))
            return f"{receiver}.replace(&{old}, &{new})"
        raise RustCodegenError(f"unsupported string/bytes method during Rust codegen: {expr.function}")

    def render_list_method(self, expr: CallIR) -> str:
        receiver = strip_wrapping_parens(self.render_call_arg(expr.args[0]))
        if expr.function == "list.copy" and len(expr.args) == 1:
            return receiver
        if expr.function == "list.count" and len(expr.args) == 2:
            recv_tmp = self.next_temp("__rextio_recv")
            needle = strip_wrapping_parens(self.render_call_arg(expr.args[1]))
            needle_tmp = self.next_temp("__rextio_needle")
            # Bind the receiver before the argument to preserve Python's
            # left-to-right evaluation order, and hoist the needle out of the
            # predicate closure (it may contain `?`, e.g. `xs.count(ys[i])`).
            # `filter` passes `&Item`, so `*item` is `&T` and matches `&needle`.
            return (
                f"{{ let {recv_tmp} = &{receiver}; "
                f"let {needle_tmp} = {needle}; "
                f"{recv_tmp}.iter().filter(|item| *item == &{needle_tmp}).count() as i64 }}"
            )
        if expr.function == "list.index" and len(expr.args) == 2:
            recv_tmp = self.next_temp("__rextio_recv")
            needle = strip_wrapping_parens(self.render_call_arg(expr.args[1]))
            needle_tmp = self.next_temp("__rextio_needle")
            # `position` passes `Item` (`&T`), so the predicate compares `item`
            # (not `*item`) against `&needle`.
            return (
                f"{{ let {recv_tmp} = &{receiver}; "
                f"let {needle_tmp} = {needle}; "
                f"{recv_tmp}.iter().position(|item| item == &{needle_tmp})"
                ".map(|index| index as i64)"
                f".ok_or_else(|| {self.error_new(rust_string_literal('list.index(x): x not in list'))})? }}"
            )
        raise RustCodegenError(f"unsupported list method during Rust codegen: {expr.function}")

    def render_naive_isoformat(self, naive_expr: str) -> str:
        # CPython's datetime.now()/utcnow() are *naive*, so .isoformat() has NO
        # timezone offset (unlike chrono's to_rfc3339, which always appends one)
        # and emits the fractional part only when the microsecond is non-zero,
        # always as exactly 6 digits otherwise. Truncate the nanosecond clock to
        # microseconds (matching CPython's microsecond resolution) and format the
        # value explicitly rather than relying on chrono's offset-aware/variable
        # precision formatter.
        dt = self.next_temp("__rextio_dt")
        micros = self.next_temp("__rextio_us")
        base = self.next_temp("__rextio_iso")
        return "\n".join(
            [
                "{",
                f"    let {dt} = {naive_expr};",
                f"    let {micros} = chrono::Timelike::nanosecond(&{dt}) / 1000;",
                f'    let {base} = {dt}.format("%Y-%m-%dT%H:%M:%S").to_string();',
                f'    if {micros} == 0 {{ {base} }} else {{ format!("{{}}.{{:06}}", {base}, {micros}) }}',
                "}",
            ]
        )

    def render_chrono_timestamp(self, now_expr: str) -> str:
        # CPython datetime.now().timestamp() has microsecond resolution; truncate
        # the nanosecond clock to microseconds so the f64 matches CPython rather
        # than carrying extra sub-microsecond precision.
        return "\n".join(
            [
                "{",
                f"    let value = {now_expr};",
                "    value.timestamp() as f64 + value.timestamp_subsec_micros() as f64 / 1_000_000.0",
                "}",
            ]
        )

    def render_call_arg(self, expr: ExprIR) -> str:
        if isinstance(expr, NameIR):
            if expr.id in self.maybe_bound_types:
                return self.render_expr(expr)
            return f"{rust_identifier(expr.id)}.clone()"
        return self.render_expr(expr)

    def render_owned_expr(self, expr: ExprIR) -> str:
        if isinstance(expr, NameIR) and not self.is_copy_expr(expr):
            return self.render_call_arg(expr)
        return self.render_expr(expr)

    def render_assignment_value(self, expr: ExprIR, expected_type: RxtType | None) -> str:
        if isinstance(expr, NameIR) and not self.is_copy_expr(expr):
            return self.render_call_arg(expr)
        return self.render_expr_with_expected(expr, expected_type)

    def is_copy_expr(self, expr: ExprIR) -> bool:
        return is_copy_rust_type(self.infer_expr_type(expr))

    def render_expr_with_expected(self, expr: ExprIR, expected_type: RxtType | None) -> str:
        if isinstance(expected_type, RxtOptional):
            if isinstance(expr, LiteralIR) and expr.value is None:
                return "None"
            actual_type = self.infer_expr_type(expr)
            rendered = strip_expr_if_safe(expr, self.render_expr(expr))
            if same_type(actual_type, expected_type):
                return rendered
            if same_type(actual_type, expected_type.item_type):
                return f"Some({strip_expr_if_safe(expr, rendered)})"
            return rendered
        if isinstance(expected_type, RxtNone) and isinstance(expr, LiteralIR) and expr.value is None:
            return "()"
        return self.render_expr(expr)

    def infer_expr_type(self, expr: ExprIR) -> RxtType | None:
        if isinstance(expr, LiteralIR):
            if isinstance(expr.value, bool):
                return RxtBool()
            if isinstance(expr.value, int):
                return RxtInt()
            if isinstance(expr.value, float):
                return RxtFloat()
            if isinstance(expr.value, str):
                return RxtStr()
            if isinstance(expr.value, bytes):
                return RxtBytes()
            if expr.value is None:
                return RxtNone()
            return None
        if isinstance(expr, NameIR):
            return self.variable_types.get(expr.id)
        if isinstance(expr, ListIR):
            if not expr.items:
                return None
            item_type = self.infer_expr_type(expr.items[0])
            if item_type is None:
                return None
            return RxtList(item_type)
        if isinstance(expr, ListComprehensionIR):
            saved_types = dict(self.variable_types)
            self.bind_comprehension_generator_types(expr.generators)
            item_type = self.infer_expr_type(expr.item)
            self.variable_types = saved_types
            if item_type is None:
                return None
            return RxtList(item_type)
        if isinstance(expr, TupleIR):
            item_types: list[RxtType] = []
            for item in expr.items:
                item_type = self.infer_expr_type(item)
                if item_type is None:
                    return None
                item_types.append(item_type)
            return RxtTuple(tuple(item_types))
        if isinstance(expr, DictIR):
            if not expr.items:
                return None
            first_key, first_value = expr.items[0]
            key_type = self.infer_expr_type(first_key)
            value_type = self.infer_expr_type(first_value)
            if key_type is None or value_type is None:
                return None
            return RxtDict(key_type, value_type)
        if isinstance(expr, DictComprehensionIR):
            saved_types = dict(self.variable_types)
            self.bind_comprehension_generator_types(expr.generators)
            key_type = self.infer_expr_type(expr.key)
            value_type = self.infer_expr_type(expr.value)
            self.variable_types = saved_types
            if key_type is None or value_type is None:
                return None
            return RxtDict(key_type, value_type)
        if isinstance(expr, SetIR):
            if not expr.items:
                return None
            item_type = self.infer_expr_type(expr.items[0])
            if item_type is None:
                return None
            return RxtSet(item_type)
        if isinstance(expr, SetComprehensionIR):
            saved_types = dict(self.variable_types)
            self.bind_comprehension_generator_types(expr.generators)
            item_type = self.infer_expr_type(expr.item)
            self.variable_types = saved_types
            if item_type is None:
                return None
            return RxtSet(item_type)
        if isinstance(expr, BinaryOpIR):
            return self.infer_expr_type(expr.left)
        if isinstance(expr, UnaryOpIR):
            if expr.op == "not":
                return RxtBool()
            return self.infer_expr_type(expr.value)
        if isinstance(expr, CompareIR):
            return RxtBool()
        if isinstance(expr, IndexIR):
            value_type = self.infer_expr_type(expr.value)
            if isinstance(value_type, RxtList):
                return value_type.item_type
            if isinstance(value_type, RxtTuple):
                index = literal_int(expr.index)
                if index is not None and 0 <= index < len(value_type.item_types):
                    return value_type.item_types[index]
            if isinstance(value_type, RxtDict):
                return value_type.value_type
        if isinstance(expr, CallIR):
            return self.call_return_type(expr)
        if isinstance(expr, NamedExprIR):
            value_type = self.infer_expr_type(expr.value)
            if value_type is not None:
                self.variable_types[expr.target.id] = value_type
            return value_type
        return None

    def bind_comprehension_generator_types(
        self,
        generators: list[ComprehensionGeneratorIR],
    ) -> None:
        for generator in generators:
            self.bind_target_types(generator.target, self.iterable_target_types(generator.iterable))
            for condition in generator.conditions:
                self.infer_expr_type(condition)

    def call_return_type(self, expr: CallIR) -> RxtType | None:
        if expr.function == "len":
            return RxtInt()
        if expr.function in {"all", "any"}:
            return RxtBool()
        if expr.function in {"sorted", "reversed"} and expr.args:
            return self.infer_expr_type(expr.args[0])
        if expr.function in {"abs", "min", "max"} and expr.args:
            return self.infer_expr_type(expr.args[0])
        if expr.function == "sum" and expr.args:
            arg_type = self.infer_expr_type(expr.args[0])
            if isinstance(arg_type, RxtList):
                return arg_type.item_type
            return None
        if expr.function in {
            "math.acos",
            "math.asin",
            "math.atan",
            "math.atan2",
            "math.cos",
            "math.exp",
            "math.log",
            "math.log10",
            "math.log2",
            "math.sin",
            "math.sqrt",
            "math.tan",
            "math.e",
            "math.pi",
        }:
            return RxtFloat()
        if expr.function in {"math.ceil", "math.floor", "math.trunc"}:
            return RxtInt()
        if expr.function in {"math.isfinite", "math.isinf", "math.isnan"}:
            return RxtBool()
        if expr.function in {"str.lower", "str.upper", "str.replace"}:
            return RxtStr()
        if expr.function in {"str.startswith", "str.endswith"}:
            return RxtBool()
        if expr.function == "str.encode":
            return RxtBytes()
        if expr.function == "bytes.decode":
            return RxtStr()
        if expr.function in {"list.copy"} and expr.args:
            return self.infer_expr_type(expr.args[0])
        if expr.function in {"list.count", "list.index"}:
            return RxtInt()
        if expr.function == "print" or expr.function.startswith("logging."):
            return RxtNone()
        if expr.function in {
            "datetime.datetime.now.isoformat",
            "datetime.datetime.utcnow.isoformat",
        }:
            return RxtStr()
        if expr.function in {
            "datetime.datetime.now.timestamp",
            "datetime.datetime.utcnow.timestamp",
            "time.time",
        }:
            return RxtFloat()
        if expr.function == "hashlib.sha256.hexdigest":
            return RxtStr()
        if expr.function == "base64.b64encode":
            return RxtBytes()
        return self.native_return_types.get(expr.function)

    def render_format_macro(
        self,
        macro: str,
        args: list[ExprIR],
        *,
        allow_empty: bool,
    ) -> str:
        if not args:
            if allow_empty:
                return f"{macro}()"
            return f"{macro}(\"\")"
        placeholders = " ".join(self.format_placeholder(arg) for arg in args)
        rendered_args = ", ".join(
            strip_wrapping_parens(self.render_call_arg(arg))
            for arg in args
        )
        return f"{macro}({rust_string_literal(placeholders)}, {rendered_args})"

    def render_logging_macro(self, macro: str, args: list[ExprIR]) -> str:
        if (
            len(args) > 1
            and isinstance(args[0], LiteralIR)
            and isinstance(args[0].value, str)
        ):
            converted = python_logging_format_to_rust(args[0].value)
            if converted is not None:
                format_string, placeholder_count = converted
                if placeholder_count == len(args) - 1:
                    rendered_args = ", ".join(
                        strip_wrapping_parens(self.render_call_arg(arg))
                        for arg in args[1:]
                    )
                    return f"{macro}({rust_string_literal(format_string)}, {rendered_args})"
        return self.render_format_macro(macro, args, allow_empty=False)

    def format_placeholder(self, expr: ExprIR) -> str:
        expr_type = self.infer_expr_type(expr)
        # KNOWN LIMITATION (documented in docs/unsupported-features.md, "Accepted
        # Native Semantic Divergences"): the textual print/log form of some scalars
        # differs from CPython. A float uses Rust Debug (`{:?}`), which matches
        # CPython's float repr for the common cases (`1.0` -> "1.0", scientific
        # notation for large/small magnitudes) but still differs on NaN casing
        # ("NaN" vs "nan") and the exponent format ("1e16"/"1e-5" vs the CPython
        # "1e+16"/"1e-05"). A bool prints lowercase ("true"/"false") where CPython
        # prints "True"/"False". int and str format identically to CPython.
        if isinstance(expr_type, RxtFloat):
            return "{:?}"
        if isinstance(expr_type, (RxtInt, RxtBool, RxtStr)):
            return "{}"
        return "{:?}"


def _render_function(
    function: FunctionIR,
    native_names_by_qualname: dict[str, str],
    native_names: dict[tuple[str, str], str],
    native_return_types: dict[str, RxtType],
    mode: str,
    used_helpers: set[str] | None = None,
) -> str:
    return _FunctionRenderer(
        function,
        native_names_by_qualname,
        native_names,
        native_return_types,
        mode,
        used_helpers=used_helpers,
    ).render()


def _assigned_names(block: BlockIR) -> set[str]:
    names: set[str] = set()
    for statement in block.statements:
        if isinstance(statement, AssignIR):
            names.add(statement.target.id)
            names.update(_expr_assigned_names(statement.value))
        elif isinstance(statement, DictSetIR):
            names.add(statement.target.id)
            names.update(_expr_assigned_names(statement.key))
            names.update(_expr_assigned_names(statement.value))
        elif isinstance(statement, AppendIR):
            names.add(statement.target.id)
            names.update(_expr_assigned_names(statement.value))
        elif isinstance(statement, EffectCallIR):
            names.update(_expr_assigned_names(statement.call))
        elif isinstance(statement, ReturnIR):
            if statement.value is not None:
                names.update(_expr_assigned_names(statement.value))
        elif isinstance(statement, IfIR):
            names.update(_expr_assigned_names(statement.condition))
            names.update(_assigned_names(statement.body))
            names.update(_assigned_names(statement.orelse))
        elif isinstance(statement, ForIR):
            names.update(target_names(statement.target))
            names.update(_expr_assigned_names(statement.iterable))
            names.update(_assigned_names(statement.body))
            names.update(_assigned_names(statement.orelse))
        elif isinstance(statement, WhileIR):
            names.update(_expr_assigned_names(statement.condition))
            names.update(_assigned_names(statement.body))
            names.update(_assigned_names(statement.orelse))
        elif isinstance(statement, TryIR):
            names.update(_assigned_names(statement.body))
            names.update(_assigned_names(statement.finalbody))
            for handler in statement.handlers:
                names.update(_assigned_names(handler.body))
    return names


def _expr_assigned_names(expr: ExprIR) -> set[str]:
    if isinstance(expr, NamedExprIR):
        return {expr.target.id} | _expr_assigned_names(expr.value)
    if isinstance(expr, BinaryOpIR):
        return _expr_assigned_names(expr.left) | _expr_assigned_names(expr.right)
    if isinstance(expr, UnaryOpIR):
        return _expr_assigned_names(expr.value)
    if isinstance(expr, CompareIR):
        names = _expr_assigned_names(expr.left)
        for comparator in expr.comparators:
            names.update(_expr_assigned_names(comparator))
        return names
    if isinstance(expr, CallIR):
        names = set[str]()
        for arg in expr.args:
            names.update(_expr_assigned_names(arg))
        return names
    if isinstance(expr, IndexIR):
        return _expr_assigned_names(expr.value) | _expr_assigned_names(expr.index)
    if isinstance(expr, ListIR):
        names = set[str]()
        for item in expr.items:
            names.update(_expr_assigned_names(item))
        return names
    if isinstance(expr, TupleIR):
        names = set[str]()
        for item in expr.items:
            names.update(_expr_assigned_names(item))
        return names
    if isinstance(expr, DictIR):
        names = set[str]()
        for key, value in expr.items:
            names.update(_expr_assigned_names(key))
            names.update(_expr_assigned_names(value))
        return names
    if isinstance(expr, SetIR):
        names = set[str]()
        for item in expr.items:
            names.update(_expr_assigned_names(item))
        return names
    if isinstance(expr, ListComprehensionIR):
        return _comprehension_assigned_names(expr.generators, [expr.item])
    if isinstance(expr, DictComprehensionIR):
        return _comprehension_assigned_names(expr.generators, [expr.key, expr.value])
    if isinstance(expr, SetComprehensionIR):
        return _comprehension_assigned_names(expr.generators, [expr.item])
    return set()


def _comprehension_assigned_names(
    generators: list[ComprehensionGeneratorIR],
    result_exprs: list[ExprIR],
) -> set[str]:
    names: set[str] = set()
    for generator in generators:
        names.update(_expr_assigned_names(generator.iterable))
        for condition in generator.conditions:
            names.update(_expr_assigned_names(condition))
    for result_expr in result_exprs:
        names.update(_expr_assigned_names(result_expr))
    return names


def target_names(target: TargetIR) -> set[str]:
    """Return the set of names bound by an assignment target."""
    if isinstance(target, NameIR):
        return {target.id}
    if isinstance(target, TupleTargetIR):
        return {item.id for item in target.items}
    return set()


def literal_int(expr: ExprIR) -> int | None:
    """Return the integer value of an expression if it is an int literal, else None."""
    if isinstance(expr, LiteralIR) and isinstance(expr.value, int) and not isinstance(expr.value, bool):
        return expr.value
    return None


def same_type(left: RxtType | None, right: RxtType | None) -> bool:
    """Report whether two optional Rextio types are equal."""
    if left is None or right is None:
        return False
    return left.to_dict() == right.to_dict()


def is_copy_rust_type(value_type: RxtType | None) -> bool:
    """Report whether a value type lowers to a Copy Rust type."""
    if isinstance(value_type, (RxtBool, RxtFloat, RxtInt, RxtNone)):
        return True
    if isinstance(value_type, RxtOptional):
        return is_copy_rust_type(value_type.item_type)
    if isinstance(value_type, RxtTuple):
        return all(is_copy_rust_type(item_type) for item_type in value_type.item_types)
    return False


def _needs_local_type_annotation(expr: ExprIR, target_type: RxtType) -> bool:
    return (
        (isinstance(expr, (DictIR, ListIR, SetIR)) and not expr.items)
        or (isinstance(expr, LiteralIR) and expr.value is None)
        or isinstance(target_type, RxtOptional)
    )
