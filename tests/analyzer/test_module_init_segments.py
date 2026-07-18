from __future__ import annotations

from pathlib import Path

from rextio.analyzer.module_init import (
    build_module_init_ir,
    build_module_init_ir_from_path,
    is_initial_module_init_eligible,
)
from rextio.ir.module_init import ModuleInitAvailability, ModuleInitSegmentKind
from rextio.source import build_source_module_graph


def test_adjacent_native_statements_merge_without_crossing_boundaries() -> None:
    source = '''"""Module metadata."""
x = 1
y = 3
import os

def publish(value: int) -> int:
    return value

z = 6
print(z)
w = 4
'''

    plan = build_module_init_ir(source, module_name="app", path="app.py")

    assert plan.available
    assert len(plan.metadata_ranges) == 1
    assert [segment.kind for segment in plan.segments] == [
        ModuleInitSegmentKind.NATIVE,
        ModuleInitSegmentKind.IMPORT,
        ModuleInitSegmentKind.DEFINITION_PUBLICATION,
        ModuleInitSegmentKind.NATIVE,
        ModuleInitSegmentKind.FALLBACK_BARRIER,
        ModuleInitSegmentKind.NATIVE,
    ]
    assert plan.segments[0].statement_indexes == (1, 2)
    assert plan.segments[0].bindings == ("x", "y")
    assert plan.segments[0].exports == ("x", "y")
    assert plan.segments[0].dependencies == ()
    assert plan.segments[1].dependencies == ("os",)
    assert plan.segments[2].bindings == ("publish",)
    assert "int" in plan.segments[2].dependencies
    assert plan.segments[4].barrier_reason == ("top-level call requires preserved Python execution")
    assert plan.segments[3].source_range.end.line < plan.segments[4].source_range.start.line


def test_imports_definitions_and_barriers_never_merge() -> None:
    source = (
        "import os\n"
        "import sys\n"
        "def first():\n    return 1\n"
        "def second():\n    return 2\n"
        "touch()\n"
        "notify()\n"
    )

    plan = build_module_init_ir(source, module_name="app", path="app.py")

    assert [segment.statement_indexes for segment in plan.segments] == [
        (0,),
        (1,),
        (2,),
        (3,),
        (4,),
        (5,),
    ]
    assert [segment.kind for segment in plan.segments] == [
        ModuleInitSegmentKind.IMPORT,
        ModuleInitSegmentKind.IMPORT,
        ModuleInitSegmentKind.DEFINITION_PUBLICATION,
        ModuleInitSegmentKind.DEFINITION_PUBLICATION,
        ModuleInitSegmentKind.FALLBACK_BARRIER,
        ModuleInitSegmentKind.FALLBACK_BARRIER,
    ]


def test_relative_import_dependencies_preserve_level_and_source_order() -> None:
    plan = build_module_init_ir(
        "from . import helper\nfrom ..shared import VALUE as current\n",
        module_name="pkg.inner.mod",
        path="pkg/inner/mod.py",
    )

    assert [segment.dependencies for segment in plan.segments] == [
        ("pkg.inner.helper",),
        ("pkg.shared",),
    ]
    assert [segment.source_range.start.line for segment in plan.segments] == [1, 2]


def test_parse_error_is_modeled_as_unavailable_without_approximation() -> None:
    plan = build_module_init_ir(
        "x = 1\nif True\n    y = 2\n",
        module_name="broken",
        path="broken.py",
    )

    assert plan.availability is ModuleInitAvailability.UNAVAILABLE
    assert not plan.available
    assert plan.segments == ()
    assert plan.unavailable_reason is not None
    assert plan.unavailable_reason.startswith("syntax-error:2:")


def test_bounded_eligibility_requires_one_hash_matched_acyclic_module(
    tmp_path: Path,
) -> None:
    source = "value = 1\nother = 2\n"
    path = tmp_path / "app.py"
    path.write_text(source, encoding="utf-8")
    graph = build_source_module_graph(tmp_path, (path,))
    plan = build_module_init_ir(source, module_name="app", path="app.py")

    assert is_initial_module_init_eligible(plan, graph)

    path.write_text("value = 9\n", encoding="utf-8")
    stale_graph = build_source_module_graph(tmp_path, (path,))
    assert not is_initial_module_init_eligible(plan, stale_graph)

    path.write_text("import app\nvalue = 1\n", encoding="utf-8")
    cyclic_graph = build_source_module_graph(tmp_path, (path,))
    cyclic_plan = build_module_init_ir(
        path.read_text(encoding="utf-8"),
        module_name="app",
        path="app.py",
    )
    assert not is_initial_module_init_eligible(cyclic_plan, cyclic_graph)


def test_fallback_barrier_blocks_bounded_eligibility(tmp_path: Path) -> None:
    source = "value = 1\nprint(value)\n"
    path = tmp_path / "app.py"
    path.write_text(source, encoding="utf-8")
    graph = build_source_module_graph(tmp_path, (path,))
    plan = build_module_init_ir(source, module_name="app", path="app.py")

    assert plan.has_fallback_barrier
    assert not plan.bounded_candidate
    assert not is_initial_module_init_eligible(plan, graph)


def test_path_planner_hashes_crlf_source_bytes_exactly(tmp_path: Path) -> None:
    path = tmp_path / "app.py"
    path.write_bytes(b"value = 1\r\n")

    graph = build_source_module_graph(tmp_path, (path,))
    plan = build_module_init_ir_from_path(tmp_path, path, module_name="app")

    assert plan.source_sha256 == graph.modules[0].sha256
    assert is_initial_module_init_eligible(plan, graph)


def test_imports_classes_and_effectful_definitions_block_initial_slice(
    tmp_path: Path,
) -> None:
    sources = {
        "import": "import os\nvalue = 1\n",
        "class": "class Model:\n    pass\nvalue = 1\n",
        "decorated": "@decorate\ndef main():\n    pass\nvalue = 1\n",
        "default": "def main(value=make_value()):\n    pass\nvalue = 1\n",
    }
    for name, source in sources.items():
        path = tmp_path / f"{name}.py"
        path.write_text(source, encoding="utf-8")
        graph = build_source_module_graph(tmp_path, (path,))
        plan = build_module_init_ir(source, module_name=name, path=path.name)
        assert not is_initial_module_init_eligible(plan, graph), name


def test_binding_facts_distinguish_may_must_deletion_and_unknown_namespace() -> None:
    conditional = build_module_init_ir(
        "if condition:\n    left = 1\nelse:\n    right = 2\n",
        module_name="conditional",
    ).segments[0]
    common = build_module_init_ir(
        "if condition:\n    shared = 1\nelse:\n    shared = 2\n",
        module_name="common",
    ).segments[0]
    deleted = build_module_init_ir("del value\n", module_name="deleted").segments[0]
    star = build_module_init_ir("from package import *\n", module_name="star").segments[0]

    assert conditional.may_bindings == ("left", "right")
    assert conditional.must_bindings == ()
    assert common.must_bindings == ("shared",)
    assert deleted.must_deletions == ("value",)
    assert deleted.may_deletions == ("value",)
    assert star.namespace_unknown


def test_future_import_is_metadata_for_the_bounded_initializer(tmp_path: Path) -> None:
    source = "from __future__ import annotations\nvalue = 1\n"
    path = tmp_path / "app.py"
    path.write_text(source, encoding="utf-8")

    graph = build_source_module_graph(tmp_path, (path,))
    plan = build_module_init_ir(source, module_name="app", path="app.py")

    assert len(plan.metadata_ranges) == 1
    assert [segment.kind for segment in plan.segments] == [ModuleInitSegmentKind.NATIVE]
    assert is_initial_module_init_eligible(plan, graph)
