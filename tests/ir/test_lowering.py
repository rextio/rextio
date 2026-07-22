from __future__ import annotations

from pathlib import Path

import pytest

from rextio.analyzer.project_scanner import analyze_project
from rextio.codegen.rust.errors import RustCodegenError
from rextio.codegen.rust.generator import generate_rust_module
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


def test_pyo3_codegen_rejects_distinct_project_qualnames_with_one_native_symbol(
    tmp_path: Path,
) -> None:
    package = tmp_path / "demo"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "pkg.py").write_text(
        "def affine(x: int) -> int:\n    return x + 1\n",
        encoding="utf-8",
    )
    (tmp_path / "demo__pkg.py").write_text(
        "def affine(x: int) -> int:\n    return x + 2\n",
        encoding="utf-8",
    )

    analysis = analyze_project(tmp_path)

    module_ir = lower_project(analysis)

    with pytest.raises(
        RustCodegenError,
        match=(
            "native Rust symbol collision: 'demo.pkg.affine', "
            "'demo__pkg.affine' all lower to 'demo__pkg__affine'"
        ),
    ):
        generate_rust_module(module_ir)


def test_lowers_comprehensions_and_assignment_expressions_to_ir(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        """
import rextio

@rextio.native
def last_positive(xs: list[int]) -> list[int]:
    return [y for x in xs if (y := x) > 0]
""",
        encoding="utf-8",
    )

    module_ir = lower_project(analyze_project(tmp_path))
    body = module_ir.to_dict()["functions"][0]["body"]

    assert body == {
        "statements": [
            {
                "kind": "return",
                "value": {
                    "kind": "list_comprehension",
                    "item": {"kind": "name", "id": "y"},
                    "generators": [
                        {
                            "target": {"kind": "name", "id": "x"},
                            "iterable": {"kind": "name", "id": "xs"},
                            "conditions": [
                                {
                                    "kind": "compare",
                                    "left": {
                                        "kind": "named_expr",
                                        "target": {"kind": "name", "id": "y"},
                                        "value": {"kind": "name", "id": "x"},
                                    },
                                    "ops": [">"],
                                    "comparators": [{"kind": "literal", "value": 0}],
                                }
                            ],
                        }
                    ],
                },
            }
        ]
    }
