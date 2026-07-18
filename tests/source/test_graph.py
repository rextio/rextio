from __future__ import annotations

from pathlib import Path

from rextio.analyzer.models import ModuleAnalysis, ProjectAnalysis
from rextio.source import (
    DistributionMetadata,
    ImportKind,
    ImportOwnership,
    build_source_module_graph,
    build_source_module_graph_from_analysis,
)


def _write(root: Path, relative: str, source: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return path


def test_hash_change_package_init_and_relative_import(tmp_path: Path) -> None:
    package = _write(tmp_path, "src/pkg/__init__.py", "from . import helper\n")
    helper = _write(tmp_path, "src/pkg/helper.py", "VALUE = 1\n")
    module = _write(tmp_path, "src/pkg/mod.py", "from .helper import VALUE\n")

    first = build_source_module_graph(tmp_path, (module, package, helper))
    package_record = first.modules_by_name["pkg"]
    module_record = first.modules_by_name["pkg.mod"]

    assert package_record.is_package_init
    assert package_record.path == "src/pkg/__init__.py"
    assert module_record.imports[0].kind is ImportKind.FROM_IMPORT
    assert module_record.imports[0].relative_level == 1
    assert module_record.imports[0].resolved_targets == ("pkg.helper.VALUE",)
    assert [(edge.importer, edge.imported) for edge in first.local_edges] == [
        ("pkg", "pkg.helper"),
        ("pkg.mod", "pkg"),
        ("pkg.mod", "pkg.helper"),
    ]
    assert first.local_edges[1].implicit_package_init

    module.write_text("from .helper import VALUE\nRESULT = VALUE\n", encoding="utf-8")
    second = build_source_module_graph(tmp_path, (module, package, helper))

    assert first.modules_by_name["pkg.mod"].sha256 != second.modules_by_name["pkg.mod"].sha256
    assert first.modules_by_name["pkg.helper"].sha256 == second.modules_by_name["pkg.helper"].sha256


def test_repeated_shadowed_imports_are_not_collapsed_and_owner_is_injected(
    tmp_path: Path,
) -> None:
    module = _write(
        tmp_path,
        "app.py",
        (
            "import vendor_pkg as current\n"
            "current = object()\n"
            "import vendor_pkg as current\n"
            "from vendor_pkg.tools import run as current\n"
        ),
    )
    owner = DistributionMetadata("vendor-dist", "2.4", "BSD-3-Clause")

    graph = build_source_module_graph(
        tmp_path,
        (module,),
        owner_mapping={"vendor_pkg": owner},
        stdlib_modules=set(),
    )
    imports = graph.modules[0].imports

    assert [record.line for record in imports] == [1, 3, 4]
    assert [record.names[0].asname for record in imports] == ["current", "current", "current"]
    assert [reference.import_ordinal for reference in graph.external_references] == [0, 1, 2]
    assert all(
        reference.ownership is ImportOwnership.EXTERNAL for reference in graph.external_references
    )
    assert {
        (reference.distribution, reference.version, reference.license)
        for reference in graph.external_references
    } == {("vendor-dist", "2.4", "BSD-3-Clause")}


def test_stdlib_external_ownership_and_deferred_import_record(tmp_path: Path) -> None:
    module = _write(
        tmp_path,
        "app.py",
        "import pathlib\ndef load():\n    import optional_backend\n",
    )

    graph = build_source_module_graph(
        tmp_path,
        (module,),
        stdlib_modules={"pathlib"},
    )

    assert [record.deferred for record in graph.modules[0].imports] == [False, True]
    assert [reference.ownership for reference in graph.external_references] == [
        ImportOwnership.EXTERNAL,
        ImportOwnership.STDLIB,
    ]


def test_deferred_local_imports_do_not_create_module_init_cycles(tmp_path: Path) -> None:
    left = _write(tmp_path, "left.py", "def load():\n    import right\n")
    right = _write(tmp_path, "right.py", "def load():\n    import left\n")

    graph = build_source_module_graph(tmp_path, (left, right))

    assert len(graph.local_edges) == 2
    assert all(edge.deferred for edge in graph.local_edges)
    assert graph.cycles == ()
    assert all(module.dependency_depth == 0 for module in graph.modules)


def test_missing_local_submodule_and_relative_escape_are_unresolved(tmp_path: Path) -> None:
    package = _write(tmp_path, "pkg/__init__.py", "")
    missing = _write(tmp_path, "pkg/mod.py", "import pkg.missing\n")
    escaping = _write(tmp_path, "pkg/escape.py", "from ..outside import VALUE\n")

    graph = build_source_module_graph(tmp_path, (package, missing, escaping))

    unresolved = [
        reference
        for reference in graph.external_references
        if reference.ownership is ImportOwnership.UNRESOLVED
    ]
    assert [reference.imported for reference in unresolved] == [
        "..outside.VALUE",
        "pkg.missing",
    ]
    assert all(reference.resolution_error for reference in unresolved)
    assert ("pkg.mod", "pkg") in {(edge.importer, edge.imported) for edge in graph.local_edges}


def test_self_cycle_and_multi_module_scc_are_deterministic(tmp_path: Path) -> None:
    a = _write(tmp_path, "a.py", "import a\n")
    b = _write(tmp_path, "b.py", "import c\n")
    c = _write(tmp_path, "c.py", "import b\n")
    root = _write(tmp_path, "root.py", "import b\n")

    graph = build_source_module_graph(tmp_path, (root, c, a, b))

    assert graph.cycles == (("a",), ("b", "c"))
    assert graph.scc_membership == {
        "a": ("a",),
        "b": ("b", "c"),
        "c": ("b", "c"),
        "root": ("root",),
    }
    assert graph.modules_by_name["a"].dependency_depth == 0
    assert graph.modules_by_name["root"].dependency_depth == 0
    assert graph.modules_by_name["b"].dependency_depth == 1
    assert graph.modules_by_name["c"].dependency_depth == 1


def test_graph_dictionaries_and_analysis_adapter_are_stable(tmp_path: Path) -> None:
    alpha = _write(tmp_path, "alpha.py", "import os\nimport vendor.pkg\n")
    beta = _write(tmp_path, "beta.py", "import alpha\n")
    owner_mapping = {
        "vendor": DistributionMetadata("broad-owner", "1"),
        "vendor.pkg": DistributionMetadata("specific-owner", "3"),
    }
    direct = build_source_module_graph(
        tmp_path,
        (beta, alpha),
        owner_mapping=owner_mapping,
        stdlib_modules={"os"},
    )
    analysis = ProjectAnalysis(
        project_root=tmp_path,
        modules=[
            ModuleAnalysis(module_name="beta", file_path=str(beta)),
            ModuleAnalysis(module_name="alpha", file_path=str(alpha)),
        ],
    )
    adapted = build_source_module_graph_from_analysis(
        analysis,
        owner_mapping=dict(reversed(tuple(owner_mapping.items()))),
        stdlib_modules={"os"},
    )

    assert direct.to_dict() == adapted.to_dict()
    assert list(direct.modules_by_name) == ["alpha", "beta"]
    assert direct.to_dict()["scc_membership"] == {
        "alpha": ["alpha"],
        "beta": ["beta"],
    }
    serialized = repr(direct.to_dict())
    assert str(tmp_path) not in serialized
    specific = next(
        reference for reference in direct.external_references if reference.imported == "vendor.pkg"
    )
    assert specific.distribution == "specific-owner"
    source_range = direct.to_dict()["modules"][0]["imports"][0]["source_range"]
    assert source_range == {
        "start": {"line": 1, "column": 0},
        "end": {"line": 1, "column": 9},
    }


def test_from_local_package_attribute_does_not_invent_missing_submodule(
    tmp_path: Path,
) -> None:
    package = _write(tmp_path, "pkg/__init__.py", "VALUE = 1\n")
    consumer = _write(tmp_path, "consumer.py", "from pkg import VALUE\n")

    graph = build_source_module_graph(tmp_path, (package, consumer))

    assert [(edge.importer, edge.imported) for edge in graph.local_edges] == [("consumer", "pkg")]
    assert graph.external_references == ()
