from __future__ import annotations

import re


def native_function_name(qualname: str) -> str:
    name = re.sub(r"[^0-9a-zA-Z_]+", "__", qualname).strip("_")
    if not name:
        raise ValueError("native function qualname produced an empty name")
    if name[0].isdigit():
        return f"_{name}"
    return name
