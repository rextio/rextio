"""Cranelift JIT lowering helpers for the experimental native-side JIT.

Standalone emission helpers (prelude, function-pointer type, and the
expression->Cranelift IR lowering) extracted from ``generator.py``. The JIT
*function* orchestrator stays in ``generator`` because it drives the full
``_FunctionRenderer``; these lower-level helpers have no such dependency.
"""

from __future__ import annotations

from rextio.codegen.rust.errors import RustCodegenError
from rextio.ir.nodes import BinaryOpIR, ExprIR, LiteralIR, NameIR, UnaryOpIR

def jit_prelude() -> list[str]:
    """Return the Rust prelude lines required by the JIT codegen."""
    return [
        "use cranelift_codegen::ir::{types, AbiParam};",
        "use cranelift_codegen::ir::InstBuilder;",
        "use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext};",
        "use cranelift_jit::{JITBuilder, JITModule};",
        "use cranelift_module::{Linkage, Module};",
        "use std::sync::atomic::{AtomicUsize, Ordering};",
        "use std::sync::OnceLock;",
    ]


def jit_pointer_type(return_type: str, param_count: int) -> str:
    """Return the Rust function-pointer type for a JIT-compiled helper."""
    args = ", ".join(return_type for _index in range(param_count))
    return f"unsafe extern \"C\" fn({args}) -> {return_type}"


def render_cranelift_expr(
    expr: ExprIR,
    params: dict[str, int],
    return_type: str,
) -> tuple[list[str], str]:
    """Render a scalar expression into Cranelift IR-building Rust statements."""
    lines: list[str] = []
    temp_index = 0

    def next_temp() -> str:
        nonlocal temp_index
        temp_index += 1
        return f"jit_value_{temp_index}"

    def lower(item: ExprIR) -> str:
        if isinstance(item, NameIR):
            if item.id not in params:
                raise RustCodegenError(f"JIT expression references unsupported local: {item.id}")
            temp = next_temp()
            lines.append(f"let {temp} = builder.block_params(block)[{params[item.id]}];")
            return temp
        if isinstance(item, LiteralIR):
            temp = next_temp()
            if return_type == "i64" and isinstance(item.value, int) and not isinstance(item.value, bool):
                lines.append(f"let {temp} = builder.ins().iconst(types::I64, {item.value});")
                return temp
            if return_type == "f64" and isinstance(item.value, (int, float)) and not isinstance(item.value, bool):
                lines.append(f"let {temp} = builder.ins().f64const({float(item.value)!r});")
                return temp
            raise RustCodegenError("JIT expression literal is not supported")
        if isinstance(item, UnaryOpIR) and item.op == "-":
            value = lower(item.value)
            temp = next_temp()
            if return_type == "i64":
                lines.append(f"let {temp} = builder.ins().ineg({value});")
            else:
                lines.append(f"let {temp} = builder.ins().fneg({value});")
            return temp
        if isinstance(item, BinaryOpIR):
            left = lower(item.left)
            right = lower(item.right)
            if return_type == "i64":
                op = {"+": "iadd", "-": "isub", "*": "imul"}.get(item.op)
            else:
                op = {"+": "fadd", "-": "fsub", "*": "fmul", "/": "fdiv"}.get(item.op)
            if op is None:
                raise RustCodegenError(f"JIT binary operator is not supported: {item.op}")
            temp = next_temp()
            lines.append(f"let {temp} = builder.ins().{op}({left}, {right});")
            return temp
        raise RustCodegenError(f"unsupported JIT expression IR: {type(item).__name__}")

    return lines, lower(expr)

