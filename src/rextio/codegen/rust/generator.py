from __future__ import annotations

import json
import re

from rextio.codegen.rust.pyo3 import render_pyo3_module
from rextio.codegen.rust.type_map import rust_type
from rextio.ir.nodes import (
    AssignIR,
    BinaryOpIR,
    BlockIR,
    CallIR,
    CompareIR,
    ExprIR,
    ForIR,
    FunctionIR,
    IfIR,
    IndexIR,
    LiteralIR,
    ModuleIR,
    NameIR,
    ReturnIR,
    StatementIR,
    UnaryOpIR,
    WhileIR,
)


class RustCodegenError(RuntimeError):
    pass


def generate_rust_module(module_ir: ModuleIR) -> str:
    names = {function.name: rust_identifier(function.name) for function in module_ir.functions}
    rendered = [
        (names[function.name], _render_function(function, names))
        for function in sorted(module_ir.functions, key=lambda item: item.qualname)
    ]
    return render_pyo3_module(rendered)


def rust_identifier(value: str) -> str:
    identifier = re.sub(r"[^0-9a-zA-Z_]", "_", value)
    if not identifier:
        raise RustCodegenError("empty Rust identifier")
    if identifier[0].isdigit():
        identifier = f"_{identifier}"
    return identifier


class _FunctionRenderer:
    def __init__(self, function: FunctionIR, native_names: dict[str, str]) -> None:
        self.function = function
        self.native_names = native_names
        self.declared = {param.name for param in function.params}

    def render(self) -> str:
        assigned_names = _assigned_names(self.function.body)
        params = ", ".join(
            f"{'mut ' if param.name in assigned_names else ''}{param.name}: {rust_type(param.type)}"
            for param in self.function.params
        )
        return_type = rust_type(self.function.return_type)
        lines = [
            "#[pyfunction]",
            f"fn {rust_identifier(self.function.name)}({params}) -> PyResult<{return_type}> {{",
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
            target = statement.target.id
            value = strip_wrapping_parens(self.render_expr(statement.value))
            if target in self.declared:
                return [f"{prefix}{target} = {value};"]
            self.declared.add(target)
            return [f"{prefix}let mut {target} = {value};"]
        if isinstance(statement, ReturnIR):
            if statement.value is None:
                return [f"{prefix}return Ok(());"]
            return [f"{prefix}return Ok({strip_wrapping_parens(self.render_expr(statement.value))});"]
        if isinstance(statement, IfIR):
            lines = [f"{prefix}if {self.render_expr(statement.condition)} {{"]
            lines.extend(self.render_block(statement.body, indent + 1))
            if statement.orelse.statements:
                lines.append(f"{prefix}}} else {{")
                lines.extend(self.render_block(statement.orelse, indent + 1))
            lines.append(f"{prefix}}}")
            return lines
        if isinstance(statement, ForIR):
            lines = [f"{prefix}for {statement.target.id} in {self.render_iterable(statement.iterable)} {{"]
            self.declared.add(statement.target.id)
            lines.extend(self.render_block(statement.body, indent + 1))
            lines.append(f"{prefix}}}")
            return lines
        if isinstance(statement, WhileIR):
            lines = [f"{prefix}while {self.render_expr(statement.condition)} {{"]
            lines.extend(self.render_block(statement.body, indent + 1))
            lines.append(f"{prefix}}}")
            return lines
        raise RustCodegenError(f"unsupported statement IR: {type(statement).__name__}")

    def render_iterable(self, expr: ExprIR) -> str:
        if isinstance(expr, NameIR):
            return f"{expr.id}.iter().cloned()"
        if (
            isinstance(expr, CallIR)
            and expr.function == "range"
            and len(expr.args) == 1
            and isinstance(expr.args[0], CallIR)
            and expr.args[0].function == "len"
            and len(expr.args[0].args) == 1
        ):
            return f"0..{self.render_expr(expr.args[0].args[0])}.len()"
        if isinstance(expr, CallIR) and expr.function == "range" and len(expr.args) == 1:
            return f"0..{self.render_expr(expr.args[0])}"
        raise RustCodegenError("unsupported for-loop iterable")

    def render_expr(self, expr: ExprIR) -> str:
        if isinstance(expr, LiteralIR):
            return render_literal(expr.value)
        if isinstance(expr, NameIR):
            return expr.id
        if isinstance(expr, BinaryOpIR):
            op = {"and": "&&", "or": "||"}.get(expr.op, expr.op)
            return f"({self.render_expr(expr.left)} {op} {self.render_expr(expr.right)})"
        if isinstance(expr, UnaryOpIR):
            op = "!" if expr.op == "not" else expr.op
            return f"({op}{self.render_expr(expr.value)})"
        if isinstance(expr, CompareIR):
            return self.render_compare(expr)
        if isinstance(expr, CallIR):
            return self.render_call(expr)
        if isinstance(expr, IndexIR):
            return f"{self.render_expr(expr.value)}[{self.render_expr(expr.index)}]"
        raise RustCodegenError(f"unsupported expression IR: {type(expr).__name__}")

    def render_compare(self, expr: CompareIR) -> str:
        if len(expr.ops) != len(expr.comparators):
            raise RustCodegenError("invalid comparison IR")
        left = expr.left
        parts: list[str] = []
        for op, comparator in zip(expr.ops, expr.comparators, strict=True):
            parts.append(f"({self.render_expr(left)} {op} {self.render_expr(comparator)})")
            left = comparator
        return " && ".join(parts)

    def render_call(self, expr: CallIR) -> str:
        if expr.function == "len" and len(expr.args) == 1:
            return f"{self.render_expr(expr.args[0])}.len()"
        rust_name = self.native_names.get(expr.function)
        if rust_name is not None:
            args = ", ".join(self.render_expr(arg) for arg in expr.args)
            return f"{rust_name}({args})?"
        raise RustCodegenError(f"unsupported call during Rust codegen: {expr.function}")


def _render_function(function: FunctionIR, native_names: dict[str, str]) -> str:
    return _FunctionRenderer(function, native_names).render()


def render_literal(value: object) -> str:
    if value is None:
        return "()"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return json.dumps(value)
    return repr(value)


def strip_wrapping_parens(value: str) -> str:
    if value.startswith("(") and value.endswith(")"):
        return value[1:-1]
    return value


def default_return(return_type: str) -> str:
    if return_type == "()":
        return "()"
    if return_type == "bool":
        return "false"
    if return_type == "String":
        return "String::new()"
    if return_type.startswith("Vec<"):
        return "Vec::new()"
    if return_type == "i64":
        return "0"
    if return_type == "f64":
        return "0.0"
    return "Default::default()"


def _block_always_returns(block: BlockIR) -> bool:
    return bool(block.statements) and isinstance(block.statements[-1], ReturnIR)


def _indent(level: int) -> str:
    return "    " * level


def _assigned_names(block: BlockIR) -> set[str]:
    names: set[str] = set()
    for statement in block.statements:
        if isinstance(statement, AssignIR):
            names.add(statement.target.id)
        elif isinstance(statement, IfIR):
            names.update(_assigned_names(statement.body))
            names.update(_assigned_names(statement.orelse))
        elif isinstance(statement, ForIR):
            names.add(statement.target.id)
            names.update(_assigned_names(statement.body))
            names.update(_assigned_names(statement.orelse))
        elif isinstance(statement, WhileIR):
            names.update(_assigned_names(statement.body))
            names.update(_assigned_names(statement.orelse))
    return names
