from __future__ import annotations

from rextio.ir.nodes import FunctionIR, ModuleIR


def empty_module() -> ModuleIR:
    return ModuleIR(functions=[])


def module_from_functions(functions: list[FunctionIR]) -> ModuleIR:
    return ModuleIR(functions=sorted(functions, key=lambda function: function.qualname))
