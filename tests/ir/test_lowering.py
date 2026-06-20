from __future__ import annotations

from pathlib import Path

from rextio.analyzer.project_scanner import analyze_project
from rextio.ir.lowering import lower_project


def test_lowers_accepted_native_functions_to_ir(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        """
import rextio

@rextio.native
def add(a: int, b: int) -> int:
    total = a + b
    return total
""",
        encoding="utf-8",
    )

    module_ir = lower_project(analyze_project(tmp_path))

    assert module_ir.to_dict() == {
        "functions": [
            {
                "name": "add",
                "qualname": "app.add",
                "module_name": "app",
                "params": [
                    {"name": "a", "type": {"kind": "int"}},
                    {"name": "b", "type": {"kind": "int"}},
                ],
                "return_type": {"kind": "int"},
                "body": {
                    "statements": [
                        {
                            "kind": "assign",
                            "target": {"kind": "name", "id": "total"},
                            "value": {
                                "kind": "binary",
                                "left": {"kind": "name", "id": "a"},
                                "op": "+",
                                "right": {"kind": "name", "id": "b"},
                            },
                        },
                        {
                            "kind": "return",
                            "value": {"kind": "name", "id": "total"},
                        },
                    ]
                },
            }
        ]
    }
