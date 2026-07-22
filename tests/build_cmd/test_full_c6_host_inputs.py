"""Focused adversarial tests for strict Full C6 host prerequisites."""

from __future__ import annotations

import base64
import copy
import csv
import hashlib
import importlib.util
import io
import json
import marshal
import os
from pathlib import Path
import platform
import pickle
import stat
import struct
import sys
from types import SimpleNamespace
from typing import cast

import pytest

import rextio.analyzer.project_scanner as project_scanner
from rextio.__about__ import __version__
from rextio.analyzer.project_scanner import analyze_project, scan_python_files
from rextio.build import full_c6_host_inputs as host_inputs
from rextio.build import full_c6_native_output, full_c6_pipeline, full_c6_production
from rextio.build.full_c6_host_inputs import (
    FULL_C6_CARGO_ARGUMENTS,
    FULL_C6_SOURCE_DATE_EPOCH,
    FullC6AnalysisScope,
    FullC6HostInputsError,
    collect_full_c6_analysis_scope,
    collect_full_c6_host_prerequisites,
    require_full_c6_analysis_scope,
)
from rextio.build.full_c6_cargo_workspace import (
    compute_full_c6_cargo_vendor_tree_sha256,
    validate_full_c6_cargo_dependency_workspace_receipt,
)
from rextio.build.toolchain_identity import capture_argv_identity
from rextio.build.input_closure import ExactFileIdentity
from rextio.build.toolchain_identity import ToolIdentity
from rextio.build.toolchain_support_lock import (
    ToolchainSupportLock,
    create_toolchain_support_locator,
    generate_toolchain_support_lock,
)
from rextio.config.schema import BuildConfig, RextioConfig, ToolchainConfig


def _record_hash(data: bytes) -> str:
    encoded = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
    return f"sha256={encoded}"


def _write_record_install(
    tmp_path: Path,
    *,
    rows: list[tuple[str, bytes]] | None = None,
    metadata_data: bytes | None = None,
) -> tuple[Path, Path, Path]:
    root = (tmp_path / "site-packages").resolve()
    package = root / "rextio"
    dist_info = root / f"rextio-{__version__}.dist-info"
    package.mkdir(parents=True)
    dist_info.mkdir()
    members = rows or [
        ("rextio/__init__.py", b"from .__about__ import __version__\n"),
        ("rextio/__about__.py", f'__version__ = "{__version__}"\n'.encode()),
        ("rextio/build.py", b"VALUE = 1\n"),
    ]
    record_rows: list[list[str]] = []
    for logical, data in members:
        path = root.joinpath(*Path(logical).parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        record_rows.append([logical, _record_hash(data), str(len(data))])
    metadata = metadata_data or (
        "Metadata-Version: 2.4\n"
        "Name: rextio\n"
        f"Version: {__version__}\n"
        "\n"
    ).encode()
    metadata_path = dist_info / "METADATA"
    metadata_path.write_bytes(metadata)
    record_rows.append(
        [
            f"{dist_info.name}/METADATA",
            _record_hash(metadata),
            str(len(metadata)),
        ]
    )
    record = dist_info / "RECORD"
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerows(record_rows)
    writer.writerow([f"{dist_info.name}/RECORD", "", ""])
    record.write_text(stream.getvalue(), encoding="utf-8")
    return root, record, package / "__init__.py"


def _capture_fixture(tmp_path: Path):
    root, record, module = _write_record_install(tmp_path)
    return host_inputs._capture_record_backed_rextio_identity(
        distribution_root=root,
        record_path=record,
        module_file=module,
        version=__version__,
    )


def _extend_record(record: Path, rows: list[list[str]]) -> None:
    existing = list(csv.reader(io.StringIO(record.read_text(encoding="utf-8"))))
    assert existing[-1][0].endswith(".dist-info/RECORD")
    existing[-1:-1] = rows
    stream = io.StringIO(newline="")
    csv.writer(stream, lineterminator="\n").writerows(existing)
    record.write_text(stream.getvalue(), encoding="utf-8")


def _add_dist_info_file(record: Path, name: str, data: bytes) -> Path:
    path = record.parent / name
    path.write_bytes(data)
    _extend_record(
        record,
        [[f"{record.parent.name}/{name}", _record_hash(data), str(len(data))]],
    )
    return path


def _select_installed_fixture(
    monkeypatch: pytest.MonkeyPatch, *, module_file: Path
) -> None:
    import rextio

    monkeypatch.setattr(rextio, "__file__", os.fspath(module_file))
    monkeypatch.setattr(host_inputs.sys, "dont_write_bytecode", True)


def test_record_backed_inventory_captures_every_installed_member(tmp_path: Path) -> None:
    identity = _capture_fixture(tmp_path)

    assert identity.version == __version__
    assert tuple(item.logical_name for item in identity.files) == (
        "rextio/__about__.py",
        "rextio/__init__.py",
        "rextio/build.py",
    )


def test_record_inventory_rejects_bytecode_record_rows_when_cache_is_absent(
    tmp_path: Path,
) -> None:
    root, record, module = _write_record_install(tmp_path)
    _extend_record(
        record,
        [["rextio/__pycache__/__init__.cpython-311.pyc", "", ""]],
    )

    with pytest.raises(FullC6HostInputsError, match="RECORD.*bytecode cache row"):
        host_inputs._capture_record_backed_rextio_identity(
            distribution_root=root,
            record_path=record,
            module_file=module,
            version=__version__,
        )


def test_record_inventory_rejects_timestamp_valid_malicious_bytecode(
    tmp_path: Path,
) -> None:
    root, record, module = _write_record_install(tmp_path)
    source = root / "rextio" / "build.py"
    assert source.read_bytes() == b"VALUE = 1\n"
    observed = source.stat()
    malicious = compile(
        b"raise RuntimeError('malicious cache executed')\n",
        str(source),
        "exec",
        dont_inherit=True,
        optimize=0,
    )
    payload = b"".join(
        (
            importlib.util.MAGIC_NUMBER,
            struct.pack(
                "<III",
                0,
                int(observed.st_mtime) & 0xFFFFFFFF,
                observed.st_size & 0xFFFFFFFF,
            ),
            marshal.dumps(malicious),
        )
    )
    logical = f"rextio/__pycache__/build.{sys.implementation.cache_tag}.pyc"
    bytecode = root.joinpath(*logical.split("/"))
    bytecode.parent.mkdir()
    bytecode.write_bytes(payload)

    with pytest.raises(FullC6HostInputsError, match="physical bytecode"):
        host_inputs._capture_record_backed_rextio_identity(
            distribution_root=root,
            record_path=record,
            module_file=module,
            version=__version__,
        )


def test_record_inventory_bounds_unrecorded_entry_flood(tmp_path: Path) -> None:
    root, record, module = _write_record_install(tmp_path)
    (root / "rextio" / "extra-a.py").write_bytes(b"A" * 1024)
    (root / "rextio" / "extra-b.py").write_bytes(b"B" * 1024)

    with pytest.raises(FullC6HostInputsError, match="RECORD bound"):
        host_inputs._capture_record_backed_rextio_identity(
            distribution_root=root,
            record_path=record,
            module_file=module,
            version=__version__,
        )


def test_record_inventory_rejects_declared_aggregate_oversize_before_walk(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, record, module = _write_record_install(tmp_path)
    declared_bytes = sum(
        int(row[2])
        for row in csv.reader(io.StringIO(record.read_text(encoding="utf-8")))
        if row[0].startswith("rextio/")
    )
    monkeypatch.setattr(
        host_inputs, "MAX_FULL_C6_ANALYSIS_SOURCE_BYTES", declared_bytes - 1
    )
    walked = False

    def reject_walk(*args: object, **kwargs: object) -> object:
        nonlocal walked
        walked = True
        raise AssertionError("installed package walk must not start")

    monkeypatch.setattr(host_inputs, "_walk_installed_package", reject_walk)

    with pytest.raises(FullC6HostInputsError, match="RECORD.*cumulative byte bound"):
        host_inputs._capture_record_backed_rextio_identity(
            distribution_root=root,
            record_path=record,
            module_file=module,
            version=__version__,
        )
    assert not walked


def test_record_inventory_rejects_actual_aggregate_oversize_while_walking(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, record, module = _write_record_install(tmp_path)
    rows = tuple(csv.reader(io.StringIO(record.read_text(encoding="utf-8"))))
    declared_bytes = sum(
        int(row[2]) for row in rows if row[0].startswith("rextio/")
    )
    source = root / "rextio" / "build.py"
    source.write_bytes(source.read_bytes() + b"x")
    monkeypatch.setattr(
        host_inputs, "MAX_FULL_C6_ANALYSIS_SOURCE_BYTES", declared_bytes
    )

    with pytest.raises(FullC6HostInputsError, match="package.*cumulative byte bound"):
        host_inputs._capture_record_backed_rextio_identity(
            distribution_root=root,
            record_path=record,
            module_file=module,
            version=__version__,
        )


def test_record_inventory_rejects_aggregate_growth_after_directory_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, record, module = _write_record_install(tmp_path)
    rows = tuple(csv.reader(io.StringIO(record.read_text(encoding="utf-8"))))
    declared_bytes = sum(
        int(row[2]) for row in rows if row[0].startswith("rextio/")
    )
    source = root / "rextio" / "build.py"
    original_read = host_inputs._secure_read_regular
    mutated = False

    def grow_then_read(
        path: Path,
        *,
        label: str,
        max_bytes: int = 64 * 1024 * 1024,
        reject_hardlinks: bool,
    ) -> tuple[bytes, os.stat_result]:
        nonlocal mutated
        if path == source:
            source.write_bytes(source.read_bytes() + b"x")
            mutated = True
        return original_read(
            path,
            label=label,
            max_bytes=max_bytes,
            reject_hardlinks=reject_hardlinks,
        )

    monkeypatch.setattr(
        host_inputs, "MAX_FULL_C6_ANALYSIS_SOURCE_BYTES", declared_bytes
    )
    monkeypatch.setattr(host_inputs, "_secure_read_regular", grow_then_read)

    with pytest.raises(FullC6HostInputsError, match="package.*cumulative byte bound"):
        host_inputs._capture_record_backed_rextio_identity(
            distribution_root=root,
            record_path=record,
            module_file=module,
            version=__version__,
        )
    assert mutated


def test_record_inventory_rejects_cache_created_between_complete_walks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, record, module = _write_record_install(tmp_path)
    original_walk = host_inputs._walk_installed_package
    calls = 0

    def walk_then_inject(*args: object, **kwargs: object):
        nonlocal calls
        calls += 1
        result = original_walk(*args, **kwargs)  # type: ignore[arg-type]
        if calls == 1:
            cache = root / "rextio" / "__pycache__"
            cache.mkdir()
            (cache / "build.cpython-311.pyc").write_bytes(b"late bytecode")
        return result

    monkeypatch.setattr(host_inputs, "_walk_installed_package", walk_then_inject)

    with pytest.raises(FullC6HostInputsError, match="physical bytecode"):
        host_inputs._capture_record_backed_rextio_identity(
            distribution_root=root,
            record_path=record,
            module_file=module,
            version=__version__,
        )
    assert calls == 2


@pytest.mark.parametrize(
    "shape", ("regular", "symlink", "nested-directory", "legacy-pyc")
)
def test_record_inventory_rejects_unsafe_bytecode_cache_shapes(
    tmp_path: Path,
    shape: str,
) -> None:
    root, record, module = _write_record_install(tmp_path)
    cache = root / "rextio" / "__pycache__"
    if shape == "regular":
        cache.write_bytes(b"not a directory")
    elif shape == "symlink":
        outside = tmp_path / "outside-cache"
        outside.mkdir()
        cache.symlink_to(outside, target_is_directory=True)
    elif shape == "nested-directory":
        cache.mkdir()
        (cache / "nested").mkdir()
    else:
        (root / "rextio" / "legacy.pyc").write_bytes(b"legacy bytecode")

    with pytest.raises(FullC6HostInputsError, match="physical bytecode|symlink"):
        host_inputs._capture_record_backed_rextio_identity(
            distribution_root=root,
            record_path=record,
            module_file=module,
            version=__version__,
        )


@pytest.mark.parametrize(
    "rows",
    (
        [["rextio/__pycache__/__init__.cpython-311.pyc", _record_hash(b"pyc"), "3"]],
        [["rextio/__pycache__/__init__.cpython-311.pyc", "", "3"]],
        [
            ["rextio/__pycache__/__init__.cpython-311.pyc", "", ""],
            ["rextio/__pycache__/__INIT__.cpython-311.pyc", "", ""],
        ],
        [["rextio/__pycache__/__init__.cpython-311.py", "", ""]],
        [["rextio/__pycache__/missing.cpython-311.pyc", "", ""]],
        [["rextio/__pycache__/__init__.cpython-311.opt-3.pyc", "", ""]],
        [["rextio/__pycache__/__init__.cpython-312.pyc", "", ""]],
        [["rextio/legacy.pyc", _record_hash(b"legacy"), "6"]],
    ),
    ids=(
        "hashed",
        "sized",
        "case-alias",
        "non-pyc",
        "missing-source",
        "invalid-optimization",
        "foreign-cache-tag",
        "legacy-sourceless",
    ),
)
def test_record_inventory_rejects_noncanonical_or_authoritative_bytecode_rows(
    tmp_path: Path,
    rows: list[list[str]],
) -> None:
    root, record, module = _write_record_install(tmp_path)
    _extend_record(record, rows)

    with pytest.raises(FullC6HostInputsError):
        host_inputs._capture_record_backed_rextio_identity(
            distribution_root=root,
            record_path=record,
            module_file=module,
            version=__version__,
        )


@pytest.mark.parametrize("mutation", ["missing", "unrecorded", "symlink", "hardlink"])
def test_record_inventory_rejects_incomplete_or_aliased_source(
    tmp_path: Path,
    mutation: str,
) -> None:
    root, record, module = _write_record_install(tmp_path)
    source = root / "rextio" / "build.py"
    if mutation == "missing":
        source.unlink()
    elif mutation == "unrecorded":
        (root / "rextio" / "extra.py").write_text("VALUE = 2\n", encoding="utf-8")
    elif mutation == "symlink":
        source.unlink()
        target = tmp_path / "outside.py"
        target.write_text("VALUE = 1\n", encoding="utf-8")
        source.symlink_to(target)
    else:
        alias = tmp_path / "source-alias.py"
        os.link(source, alias)

    with pytest.raises(FullC6HostInputsError):
        host_inputs._capture_record_backed_rextio_identity(
            distribution_root=root,
            record_path=record,
            module_file=module,
            version=__version__,
        )


@pytest.mark.parametrize(
    "row",
    [
        "rextio/../escape.py",
        "rextio/Thing.py",
        "rextio//build.py",
        "rextio/./build.py",
    ],
)
def test_record_inventory_rejects_escape_and_casefold_alias(
    tmp_path: Path,
    row: str,
) -> None:
    root, record, module = _write_record_install(tmp_path)
    existing = (root / "rextio" / "build.py").read_bytes()
    lines = list(csv.reader(io.StringIO(record.read_text(encoding="utf-8"))))
    lines.insert(-1, [row, _record_hash(existing), str(len(existing))])
    if row.endswith("Thing.py"):
        lines.insert(-1, ["rextio/thing.py", _record_hash(existing), str(len(existing))])
    stream = io.StringIO(newline="")
    csv.writer(stream, lineterminator="\n").writerows(lines)
    record.write_text(stream.getvalue(), encoding="utf-8")

    with pytest.raises(FullC6HostInputsError, match="escaped|alias|canonical"):
        host_inputs._capture_record_backed_rextio_identity(
            distribution_root=root,
            record_path=record,
            module_file=module,
            version=__version__,
        )


def test_record_inventory_rejects_running_module_from_elsewhere(tmp_path: Path) -> None:
    root, record, _module = _write_record_install(tmp_path)
    outside = tmp_path / "outside-init.py"
    outside.write_text("", encoding="utf-8")

    with pytest.raises(FullC6HostInputsError, match="running Rextio"):
        host_inputs._capture_record_backed_rextio_identity(
            distribution_root=root,
            record_path=record,
            module_file=outside,
            version=__version__,
        )


def test_installed_inventory_rejects_editable_distribution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _root, record, module = _write_record_install(tmp_path)
    _add_dist_info_file(
        record,
        "direct_url.json",
        json.dumps({"dir_info": {"editable": True}}).encode(),
    )
    _select_installed_fixture(monkeypatch, module_file=module)

    with pytest.raises(FullC6HostInputsError, match="editable"):
        host_inputs._capture_installed_rextio_identity()


def test_installed_inventory_uses_bounded_filesystem_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _root, _record, module = _write_record_install(tmp_path)
    _select_installed_fixture(monkeypatch, module_file=module)

    identity = host_inputs._capture_installed_rextio_identity()

    assert identity.version == __version__
    assert "metadata" not in vars(host_inputs)


@pytest.mark.parametrize(
    "metadata_data",
    (
        (
            "Metadata-Version: 2.4\n"
            "Name: rextio\n"
            "Name: rextio\n"
            f"Version: {__version__}\n\n"
        ).encode(),
        (
            "Metadata-Version: 2.4\n"
            "Name: rextio\n"
            f"Version: {__version__}\n"
            f"Version: {__version__}\n\n"
        ).encode(),
        (
            "Metadata-Version: 2.4\n"
            "Name: Rextio\n"
            f"Version: {__version__}\n\n"
        ).encode(),
        (
            "Metadata-Version: 2.4\n"
            "Name: rextio\n"
            f"Version: {__version__}.1\n\n"
        ).encode(),
    ),
    ids=(
        "duplicate-name",
        "duplicate-version",
        "noncanonical-name",
        "version-mismatch",
    ),
)
def test_installed_inventory_rejects_ambiguous_metadata_fields(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    metadata_data: bytes,
) -> None:
    _root, _record, module = _write_record_install(
        tmp_path, metadata_data=metadata_data
    )
    _select_installed_fixture(monkeypatch, module_file=module)

    with pytest.raises(FullC6HostInputsError, match="METADATA.*ambiguous"):
        host_inputs._capture_installed_rextio_identity()


def test_installed_inventory_bounds_metadata_before_parsing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    metadata_data = (
        "Metadata-Version: 2.4\n"
        "Name: rextio\n"
        f"Version: {__version__}\n\n"
    ).encode()
    _root, _record, module = _write_record_install(
        tmp_path, metadata_data=metadata_data
    )
    _select_installed_fixture(monkeypatch, module_file=module)
    monkeypatch.setattr(host_inputs, "_METADATA_MAX_BYTES", len(metadata_data) - 1)

    with pytest.raises(FullC6HostInputsError, match="METADATA.*regular file"):
        host_inputs._capture_installed_rextio_identity()


def test_installed_inventory_bounds_direct_url_before_parsing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _root, record, module = _write_record_install(tmp_path)
    direct_url_data = json.dumps({"url": "https://example.invalid/rextio"}).encode()
    _add_dist_info_file(record, "direct_url.json", direct_url_data)
    _select_installed_fixture(monkeypatch, module_file=module)
    monkeypatch.setattr(
        host_inputs, "_DIRECT_URL_MAX_BYTES", len(direct_url_data) - 1
    )

    with pytest.raises(FullC6HostInputsError, match="direct_url.*regular file"):
        host_inputs._capture_installed_rextio_identity()


def test_installed_inventory_rejects_ambiguous_dist_info_roots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _record, module = _write_record_install(tmp_path)
    (root / "rextio-999.dist-info").mkdir()
    _select_installed_fixture(monkeypatch, module_file=module)

    with pytest.raises(FullC6HostInputsError, match="dist-info root is ambiguous"):
        host_inputs._capture_installed_rextio_identity()


def test_installed_inventory_rejects_import_root_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _record, _module = _write_record_install(tmp_path)
    wrong_package = root / "other"
    wrong_package.mkdir()
    wrong_module = wrong_package / "__init__.py"
    wrong_module.write_bytes(b"")
    _select_installed_fixture(monkeypatch, module_file=wrong_module)

    with pytest.raises(FullC6HostInputsError, match="module root is not canonical"):
        host_inputs._capture_installed_rextio_identity()


def test_record_row_bound_stops_before_trailing_invalid_csv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(host_inputs, "_RECORD_MAX_ROWS", 2)
    data = b"a,b,c\nd,e,f\ng,h,i\n\"unterminated"

    with pytest.raises(FullC6HostInputsError, match="row count is outside bound"):
        tuple(host_inputs._iter_installed_record_rows(data))


def test_installed_inventory_rejects_record_over_row_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _root, _record, module = _write_record_install(tmp_path)
    _select_installed_fixture(monkeypatch, module_file=module)
    monkeypatch.setattr(host_inputs, "_RECORD_MAX_ROWS", 4)

    with pytest.raises(FullC6HostInputsError, match="row count is outside bound"):
        host_inputs._capture_installed_rextio_identity()


@pytest.mark.parametrize("member", ("METADATA", "direct_url.json"))
def test_installed_inventory_requires_dist_info_record_membership(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    member: str,
) -> None:
    _root, record, module = _write_record_install(tmp_path)
    if member == "direct_url.json":
        (record.parent / member).write_text(
            json.dumps({"url": "https://example.invalid/rextio"}),
            encoding="utf-8",
        )
    rows = list(csv.reader(io.StringIO(record.read_text(encoding="utf-8"))))
    rows = [row for row in rows if not row[0].endswith(f"/{member}")]
    stream = io.StringIO(newline="")
    csv.writer(stream, lineterminator="\n").writerows(rows)
    record.write_text(stream.getvalue(), encoding="utf-8")
    _select_installed_fixture(monkeypatch, module_file=module)

    with pytest.raises(FullC6HostInputsError, match="RECORD membership"):
        host_inputs._capture_installed_rextio_identity()


def test_installed_inventory_requires_cache_free_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(host_inputs.sys, "dont_write_bytecode", False)

    with pytest.raises(FullC6HostInputsError, match="cache-free Python process"):
        host_inputs._capture_installed_rextio_identity()


def test_project_root_requires_raw_absolute_nofollow_path(tmp_path: Path) -> None:
    project = (tmp_path / "project").resolve()
    project.mkdir()
    with pytest.raises(FullC6HostInputsError, match="raw lexical absolute"):
        host_inputs._open_raw_project_root(Path("project"))

    alias = tmp_path / "alias"
    alias.symlink_to(project)
    with pytest.raises(FullC6HostInputsError, match="symlink"):
        host_inputs._open_raw_project_root(alias.resolve(strict=False).parent / alias.name)


def test_inherited_environment_is_reduced_to_two_discovery_values() -> None:
    result = host_inputs._validate_inherited_environment(
        {
            "PATH": "/tools",
            "RUSTUP_HOME": "/rustup",
            "CC": "attacker-cc",
            "RUSTFLAGS": "--cfg attacker",
            "HTTP_PROXY": "http://proxy.invalid",
            "TOKEN": "secret",
        }
    )

    assert result == {"PATH": "/tools", "RUSTUP_HOME": "/rustup"}


def _host_config(**build_overrides: object) -> RextioConfig:
    values: dict[str, object] = {
        "artifact_signing_request_output": (
            "state/rextio.full-c6-final-authorization-request.json"
        ),
        **build_overrides,
    }
    return RextioConfig(build=BuildConfig(**values))  # type: ignore[arg-type]


def _write_cargo_workspace(
    project: Path,
    *,
    extra_files: dict[str, bytes] | None = None,
) -> tuple[Path, Path, str, str]:
    lock = project / "Cargo.lock"
    lock.write_text(
        """\
version = 4

[[package]]
name = "rextio_generated_native"
version = "0.1.0"

[[package]]
name = "demo-dep"
version = "1.2.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
""",
        encoding="utf-8",
    )
    vendor = project / "vendor"
    package = vendor / "demo-dep-1.2.3"
    (package / "src").mkdir(parents=True)
    files = {
        "Cargo.toml": (
            b'[package]\nname = "demo-dep"\nversion = "1.2.3"\n'
            b'license = "MIT"\nlicense-file = "LICENSE"\n'
        ),
        "LICENSE": b"MIT license evidence\n",
        "src/lib.rs": b"pub fn answer() -> u32 { 42 }\n",
        **(extra_files or {}),
    }
    for relative, data in files.items():
        path = package.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o644)
    checksum = {
        "files": {
            name: hashlib.sha256(data).hexdigest()
            for name, data in sorted(files.items())
        },
        "package": "a" * 64,
    }
    (package / ".cargo-checksum.json").write_text(
        json.dumps(checksum, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    return (
        lock,
        vendor,
        hashlib.sha256(lock.read_bytes()).hexdigest(),
        compute_full_c6_cargo_vendor_tree_sha256(vendor),
    )


def _write_toolchain_support_lock(
    project: Path,
    fixture_root: Path,
    *,
    target_triple: str = "aarch64-apple-darwin",
) -> tuple[Path, ToolchainSupportLock, dict[str, str]]:
    support = (fixture_root / "toolchain-support-fixture").resolve()
    manifest = support / "rustlib-manifest.txt"
    sysroot = support / "sysroot"
    sysroot.mkdir(parents=True)
    manifest.write_text("rustc 1.93.1\n", encoding="utf-8")
    (sysroot / "libcore.rlib").write_bytes(b"bounded rustlib fixture")
    lock = generate_toolchain_support_lock(
        target_triple=target_triple,
        manifests=(
            create_toolchain_support_locator(
                logical_role="rustlib-manifest",
                path=manifest,
                kind="file",
            ),
        ),
        roots=(
            create_toolchain_support_locator(
                logical_role="rust-sysroot",
                path=sysroot,
                kind="tree",
            ),
        ),
    )
    lock_path = project / "locks" / "toolchain-support.json"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_bytes(lock.canonical_bytes)
    return (
        lock_path,
        lock,
        {
            "artifact_toolchain_support_lock": lock_path.relative_to(
                project
            ).as_posix(),
            "artifact_toolchain_support_lock_sha256": lock.raw_sha256,
        },
    )


def _mock_support_plan(
    monkeypatch: pytest.MonkeyPatch,
    *,
    target_triple: str = "aarch64-apple-darwin",
) -> SimpleNamespace:
    plan = SimpleNamespace(
        target_triple=target_triple,
        digest="d" * 64,
    )
    monkeypatch.setattr(
        host_inputs,
        "require_full_c6_toolchain_support_plan",
        lambda value: value,
    )
    monkeypatch.setattr(
        host_inputs,
        "verify_full_c6_toolchain_support_lock",
        lambda value, _lock: value is plan,
    )
    return plan


def _analysis_scope_fixture(
    tmp_path: Path,
    *,
    extra_files: dict[str, bytes] | None = None,
    project_files: dict[str, bytes] | None = None,
) -> tuple[Path, RextioConfig, FullC6AnalysisScope, Path, Path]:
    project, config, lock, vendor = _analysis_scope_inputs(
        tmp_path,
        extra_files=extra_files,
        project_files=project_files,
    )
    scope = collect_full_c6_analysis_scope(project, config=config)
    return project, config, scope, lock, vendor


def _analysis_scope_inputs(
    tmp_path: Path,
    *,
    extra_files: dict[str, bytes] | None = None,
    project_files: dict[str, bytes] | None = None,
) -> tuple[Path, RextioConfig, Path, Path]:
    project = (tmp_path / "project").resolve()
    project.mkdir()
    (project / "app.py").write_text("VALUE: int = 1\n", encoding="utf-8")
    for relative, payload in (project_files or {}).items():
        path = project.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    lock, vendor, lock_sha256, vendor_sha256 = _write_cargo_workspace(
        project,
        extra_files=extra_files,
    )
    config = _host_config(
        artifact_distribution_policy="full-c6-required",
        artifact_cargo_lock=lock.relative_to(project).as_posix(),
        artifact_cargo_lock_sha256=lock_sha256,
        artifact_cargo_vendor=vendor.relative_to(project).as_posix(),
        artifact_cargo_vendor_sha256=vendor_sha256,
    )
    return project, config, lock, vendor


def test_analysis_scope_excludes_only_verified_vendor_python(
    tmp_path: Path,
) -> None:
    project, config, scope, _lock, vendor = _analysis_scope_fixture(
        tmp_path,
        extra_files={"etc/libc-util.py": b"async = 1\n"},
        project_files={"cargo-vendor-shadow/helper.py": b"VALUE = 3\n"},
    )
    helper = vendor / "demo-dep-1.2.3" / "etc" / "libc-util.py"
    adjacent = project / "cargo-vendor-shadow" / "helper.py"

    assert helper in scan_python_files(project)
    strict_files = scan_python_files(
        project,
        full_c6_analysis_scope=scope,
        full_c6_config=config,
    )
    assert strict_files == [project / "app.py", adjacent]

    ignored = project / "ignored.py"
    ignored.write_text("VALUE = 2\n", encoding="utf-8")
    (project / ".rextioignore").write_text("ignored.py\n", encoding="utf-8")
    ordinary = scan_python_files(project)
    assert ignored not in ordinary
    assert helper in ordinary


@pytest.mark.parametrize("kind", ("file", "directory", "symlink"))
def test_analysis_scope_rejects_every_present_rextioignore(
    tmp_path: Path,
    kind: str,
) -> None:
    project = (tmp_path / "project").resolve()
    project.mkdir()
    lock, vendor, lock_sha256, vendor_sha256 = _write_cargo_workspace(project)
    config = _host_config(
        artifact_distribution_policy="full-c6-required",
        artifact_cargo_lock=lock.relative_to(project).as_posix(),
        artifact_cargo_lock_sha256=lock_sha256,
        artifact_cargo_vendor=vendor.relative_to(project).as_posix(),
        artifact_cargo_vendor_sha256=vendor_sha256,
    )
    ignore = project / ".rextioignore"
    if kind == "file":
        ignore.write_text("vendor/\n", encoding="utf-8")
    elif kind == "directory":
        ignore.mkdir()
    else:
        ignore.symlink_to("missing-ignore-target")

    with pytest.raises(FullC6HostInputsError, match="forbids"):
        collect_full_c6_analysis_scope(project, config=config)


def test_analysis_scope_is_exact_typed_root_and_config_authority(
    tmp_path: Path,
) -> None:
    project, config, scope, _lock, vendor = _analysis_scope_fixture(tmp_path)

    assert type(scope) is FullC6AnalysisScope
    assert require_full_c6_analysis_scope(
        scope,
        project_root=project,
        config=config,
    ) == vendor
    with pytest.raises(TypeError, match="verified Cargo authority"):
        FullC6AnalysisScope()
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.copy(scope)
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.deepcopy(scope)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(scope)
    with pytest.raises(FullC6HostInputsError, match="invalid"):
        require_full_c6_analysis_scope(vendor, project_root=project, config=config)
    with pytest.raises(FullC6HostInputsError, match="stale or foreign"):
        require_full_c6_analysis_scope(
            scope,
            project_root=project,
            config=RextioConfig(build=config.build),
        )
    other = (tmp_path / "other").resolve()
    other.mkdir()
    with pytest.raises(FullC6HostInputsError, match="stale or foreign"):
        require_full_c6_analysis_scope(scope, project_root=other, config=config)

    object.__setattr__(scope, "_seal", b"forged")
    with pytest.raises(FullC6HostInputsError, match="stale or foreign"):
        require_full_c6_analysis_scope(scope, project_root=project, config=config)


@pytest.mark.parametrize("mutation", ("vendor-bytes", "lock-bytes", "vendor-replace"))
def test_analysis_scope_revalidates_cargo_authority(
    tmp_path: Path,
    mutation: str,
) -> None:
    project, config, scope, lock, vendor = _analysis_scope_fixture(tmp_path)
    if mutation == "vendor-bytes":
        (vendor / "demo-dep-1.2.3" / "src" / "lib.rs").write_text(
            "pub fn answer() -> u32 { 7 }\n",
            encoding="utf-8",
        )
    elif mutation == "lock-bytes":
        lock.write_text(lock.read_text(encoding="utf-8") + "# changed\n", encoding="utf-8")
    else:
        moved = project / "old-vendor"
        vendor.rename(moved)
        vendor.mkdir()

    with pytest.raises(FullC6HostInputsError):
        require_full_c6_analysis_scope(scope, project_root=project, config=config)


@pytest.mark.parametrize("joint_vendor_update", (False, True))
def test_analysis_scope_rejects_changed_config_pin_even_if_vendor_matches(
    tmp_path: Path,
    joint_vendor_update: bool,
) -> None:
    project, config, scope, _lock, vendor = _analysis_scope_fixture(tmp_path)
    new_pin = "0" * 64
    if joint_vendor_update:
        source = vendor / "demo-dep-1.2.3" / "src" / "lib.rs"
        payload = b"pub fn answer() -> u32 { 100 }\n"
        source.write_bytes(payload)
        checksum_path = vendor / "demo-dep-1.2.3" / ".cargo-checksum.json"
        checksum = json.loads(checksum_path.read_text(encoding="utf-8"))
        checksum["files"]["src/lib.rs"] = hashlib.sha256(payload).hexdigest()
        checksum_path.write_text(
            json.dumps(checksum, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        new_pin = compute_full_c6_cargo_vendor_tree_sha256(vendor)
    object.__setattr__(config.build, "artifact_cargo_vendor_sha256", new_pin)

    with pytest.raises(FullC6HostInputsError, match="stale or foreign"):
        require_full_c6_analysis_scope(scope, project_root=project, config=config)


def test_analysis_scan_fails_when_vendor_changes_between_validations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, config, scope, _lock, vendor = _analysis_scope_fixture(tmp_path)
    original = host_inputs.require_full_c6_analysis_files
    calls = 0

    def race(
        value: object, *, project_root: Path, config: RextioConfig
    ) -> tuple[Path, ...]:
        nonlocal calls
        result = original(value, project_root=project_root, config=config)
        calls += 1
        if calls == 1:
            (vendor / "demo-dep-1.2.3" / "src" / "lib.rs").write_text(
                "pub fn answer() -> u32 { 9 }\n",
                encoding="utf-8",
            )
        return result

    monkeypatch.setattr(host_inputs, "require_full_c6_analysis_files", race)
    with pytest.raises(FullC6HostInputsError):
        scan_python_files(
            project,
            full_c6_analysis_scope=scope,
            full_c6_config=config,
        )
    assert calls == 1


def test_analysis_scope_rejects_new_project_python_but_ignores_builtin_output(
    tmp_path: Path,
) -> None:
    project, config, scope, _lock, _vendor = _analysis_scope_fixture(tmp_path)
    generated = project / ".rextio" / "generated" / "helper.py"
    generated.parent.mkdir(parents=True)
    generated.write_text("VALUE = 2\n", encoding="utf-8")

    assert scan_python_files(
        project,
        full_c6_analysis_scope=scope,
        full_c6_config=config,
    ) == [project / "app.py"]

    (project / "new_source.py").write_text("VALUE = 3\n", encoding="utf-8")
    with pytest.raises(FullC6HostInputsError, match="namespace changed"):
        scan_python_files(
            project,
            full_c6_analysis_scope=scope,
            full_c6_config=config,
        )


def test_strict_scanner_uses_sealed_paths_not_caller_rglob(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, config, scope, _lock, _vendor = _analysis_scope_fixture(tmp_path)
    monkeypatch.setattr(
        Path,
        "rglob",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("strict scanner must not rediscover caller paths")
        ),
    )

    assert scan_python_files(
        project,
        full_c6_analysis_scope=scope,
        full_c6_config=config,
    ) == [project / "app.py"]


def test_analysis_end_rejects_transient_project_file_move_into_vendor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, config, scope, _lock, vendor = _analysis_scope_fixture(tmp_path)
    source = project / "app.py"
    hidden = vendor / "demo-dep-1.2.3" / "temporarily-hidden.py"
    original = project_scanner._note_plugin_lowerable_accelerated

    def transient_move(analysis: object, plugins: object) -> None:
        original(analysis, plugins)  # type: ignore[arg-type]
        source.rename(hidden)
        hidden.rename(source)

    monkeypatch.setattr(
        project_scanner,
        "_note_plugin_lowerable_accelerated",
        transient_move,
    )

    with pytest.raises(FullC6HostInputsError, match="Python source changed"):
        analyze_project(
            project,
            plugin_config=config,
            full_c6_analysis_scope=scope,
        )


def test_strict_namespace_rejects_nonignored_symlink_directory(
    tmp_path: Path,
) -> None:
    project, config, scope, _lock, _vendor = _analysis_scope_fixture(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "hidden.py").write_text("VALUE = 4\n", encoding="utf-8")
    (project / "alias").symlink_to(outside, target_is_directory=True)

    with pytest.raises(FullC6HostInputsError, match="path alias"):
        scan_python_files(
            project,
            full_c6_analysis_scope=scope,
            full_c6_config=config,
        )


@pytest.mark.parametrize(
    "attack",
    ("directory-roundtrip", "extra-file-roundtrip", "root-extra-roundtrip"),
)
def test_analysis_end_rejects_transient_source_directory_namespace_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attack: str,
) -> None:
    project, config, scope, _lock, vendor = _analysis_scope_fixture(
        tmp_path,
        project_files={"pkg/module.py": b"VALUE: int = 2\n"},
    )
    package = project / "pkg"
    original = project_scanner._note_plugin_lowerable_accelerated

    def transient_change(analysis: object, plugins: object) -> None:
        original(analysis, plugins)  # type: ignore[arg-type]
        if attack == "directory-roundtrip":
            hidden = vendor / "temporarily-hidden-package"
            package.rename(hidden)
            hidden.rename(package)
        elif attack == "extra-file-roundtrip":
            extra = package / "temporary.py"
            extra.write_text("VALUE = 5\n", encoding="utf-8")
            extra.unlink()
        else:
            extra = project / "temporary.py"
            extra.write_text("VALUE = 6\n", encoding="utf-8")
            extra.unlink()

    monkeypatch.setattr(
        project_scanner,
        "_note_plugin_lowerable_accelerated",
        transient_change,
    )

    with pytest.raises(FullC6HostInputsError, match="directory changed"):
        analyze_project(
            project,
            plugin_config=config,
            full_c6_analysis_scope=scope,
        )


def test_analysis_namespace_public_bounds_are_fixed() -> None:
    assert host_inputs.MAX_FULL_C6_ANALYSIS_PYTHON_FILES == 1024
    assert host_inputs.MAX_FULL_C6_ANALYSIS_DIRECTORIES == 4096
    assert host_inputs.MAX_FULL_C6_ANALYSIS_ENTRIES == 16384
    assert host_inputs.MAX_FULL_C6_ANALYSIS_SOURCE_BYTES == 256 * 1024 * 1024
    assert host_inputs.MAX_FULL_C6_ANALYSIS_RELATIVE_CHARS == 512
    assert host_inputs.MAX_FULL_C6_ANALYSIS_RELATIVE_BYTES == 2048
    assert host_inputs.MAX_FULL_C6_ANALYSIS_DEPTH == 32


@pytest.mark.parametrize(
    ("constant", "limit", "extra_path", "payload"),
    (
        ("MAX_FULL_C6_ANALYSIS_PYTHON_FILES", 1, "extra.py", b"VALUE = 2\n"),
        ("MAX_FULL_C6_ANALYSIS_DIRECTORIES", 1, "wide/marker.txt", b"x"),
        ("MAX_FULL_C6_ANALYSIS_ENTRIES", 1, None, None),
        ("MAX_FULL_C6_ANALYSIS_SOURCE_BYTES", 1, None, None),
        ("MAX_FULL_C6_ANALYSIS_RELATIVE_CHARS", 5, None, None),
        ("MAX_FULL_C6_ANALYSIS_DEPTH", 1, "pkg/deep.py", b"VALUE = 3\n"),
    ),
)
def test_analysis_namespace_bounds_fail_closed_before_analysis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    constant: str,
    limit: int,
    extra_path: str | None,
    payload: bytes | None,
) -> None:
    project, config, _lock, _vendor = _analysis_scope_inputs(tmp_path)
    if extra_path is not None and payload is not None:
        path = project.joinpath(*extra_path.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    monkeypatch.setattr(host_inputs, constant, limit)

    with pytest.raises(FullC6HostInputsError, match="bounded limit"):
        collect_full_c6_analysis_scope(project, config=config)


def test_configured_cargo_workspace_requires_exact_lock_and_vendor_pins(
    tmp_path: Path,
) -> None:
    project = (tmp_path / "project").resolve()
    project.mkdir()
    lock, vendor, lock_sha256, vendor_sha256 = _write_cargo_workspace(project)
    config = _host_config(
        artifact_cargo_lock=lock.relative_to(project).as_posix(),
        artifact_cargo_lock_sha256=lock_sha256,
        artifact_cargo_vendor=vendor.relative_to(project).as_posix(),
        artifact_cargo_vendor_sha256=vendor_sha256,
    )

    workspace = host_inputs._collect_configured_cargo_workspace(project, config)
    assert validate_full_c6_cargo_dependency_workspace_receipt(workspace)
    assert workspace.cargo_sources is not None
    assert workspace.cargo_sources.lock_file.sha256 == lock_sha256
    assert workspace.vendor_tree_sha256 == vendor_sha256

    changed_lock = _host_config(
        artifact_cargo_lock="Cargo.lock",
        artifact_cargo_lock_sha256="0" * 64,
        artifact_cargo_vendor="vendor",
        artifact_cargo_vendor_sha256=vendor_sha256,
    )
    with pytest.raises(FullC6HostInputsError, match="Cargo.lock SHA-256"):
        host_inputs._collect_configured_cargo_workspace(project, changed_lock)

    changed_vendor = _host_config(
        artifact_cargo_lock="Cargo.lock",
        artifact_cargo_lock_sha256=lock_sha256,
        artifact_cargo_vendor="vendor",
        artifact_cargo_vendor_sha256="0" * 64,
    )
    with pytest.raises(FullC6HostInputsError, match="Cargo vendor SHA-256"):
        host_inputs._collect_configured_cargo_workspace(project, changed_vendor)


def test_toolchain_retains_workspace_sources_and_reprobes_exact_tools(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = (tmp_path / "project").resolve()
    project.mkdir()
    lock, vendor, lock_sha256, vendor_sha256 = _write_cargo_workspace(project)
    workspace = host_inputs._collect_configured_cargo_workspace(
        project,
        _host_config(
            artifact_cargo_lock=lock.name,
            artifact_cargo_lock_sha256=lock_sha256,
            artifact_cargo_vendor=vendor.name,
            artifact_cargo_vendor_sha256=vendor_sha256,
        ),
    )
    tools = project / "tools"
    tools.mkdir()
    paths: dict[str, Path] = {}
    for name in ("python", "cargo", "rustc", "linker", "otool"):
        path = tools / name
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(0o755)
        paths[name] = path
    rextio_identity = _capture_fixture(tmp_path / "install")
    probes: list[str] = []

    monkeypatch.setattr(host_inputs, "_resolve_python", lambda _config: paths["python"])
    monkeypatch.setattr(
        host_inputs,
        "_resolve_required_tool",
        lambda _name, _configured: paths["cargo"],
    )
    monkeypatch.setattr(
        host_inputs,
        "_resolve_actual_rust_tools",
        lambda _cargo, **_kwargs: (paths["cargo"], paths["rustc"]),
    )
    monkeypatch.setattr(
        host_inputs,
        "resolve_full_c6_linker_and_inspector",
        lambda **_kwargs: (paths["linker"], paths["otool"]),
    )
    monkeypatch.setattr(
        host_inputs,
        "_minimal_build_environment",
        lambda _cargo: {"PATH": str(tools)},
    )

    def probe(path: Path, **_kwargs: object) -> str:
        name = path.name
        probes.append(name)
        return {
            "python": "Python 3.11.9",
            "cargo": "cargo 1.85.0",
            "rustc": "rustc 1.85.0",
            "linker": "clang 16.0.0",
            "otool": "otool 1000.0.0",
        }[name]

    monkeypatch.setattr(host_inputs, "_probe_version", probe)
    monkeypatch.setattr(
        host_inputs,
        "_probe_rustc_host",
        lambda _path, **_kwargs: "aarch64-apple-darwin",
    )
    monkeypatch.setattr(
        host_inputs,
        "_capture_installed_rextio_identity",
        lambda: rextio_identity,
    )

    def capture(name: str, path: Path, *, reported_version: str) -> ToolIdentity:
        return ToolIdentity(
            name=name,
            executable=ExactFileIdentity(
                logical_name=f"toolchain/{name}",
                role="toolchain-executable",
                sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                size=path.stat().st_size,
                executable=True,
            ),
            reported_version=reported_version,
        )

    monkeypatch.setattr(host_inputs, "capture_tool_identity", capture)
    monkeypatch.setattr(host_inputs, "verify_tool_identity", lambda _path, _identity: None)
    support_plan = SimpleNamespace(
        base_environment={"PATH": str(tools)},
        digest="8" * 64,
    )
    support_lock = cast(
        ToolchainSupportLock,
        SimpleNamespace(
            raw_sha256="9" * 64,
            merkle_sha256="a" * 64,
        ),
    )
    monkeypatch.setattr(
        host_inputs,
        "discover_full_c6_toolchain_support",
        lambda **_kwargs: support_plan,
    )
    monkeypatch.setattr(
        host_inputs,
        "verify_full_c6_toolchain_support_lock",
        lambda plan, lock: plan is support_plan and lock is support_lock,
    )
    monkeypatch.setattr(host_inputs.sys, "executable", str(paths["python"]))
    config = RextioConfig(
        toolchain=ToolchainConfig(python_version="==3.11.9", cargo_version="1.85")
    )

    native_tools, identity, environment, retained_plan = host_inputs._collect_toolchain(
        root=project,
        config=config,
        target_triple="aarch64-apple-darwin",
        inherited={},
        cargo_workspace=workspace,
        support_lock=support_lock,
    )

    assert identity.cargo_sources is workspace.cargo_sources
    assert identity.argv.values == ("cargo", *FULL_C6_CARGO_ARGUMENTS)
    assert identity.support_plan_sha256 == "8" * 64
    assert identity.support_lock_raw_sha256 == "9" * 64
    assert identity.support_lock_merkle_sha256 == "a" * 64
    assert native_tools.cargo == paths["cargo"]
    assert environment == {"PATH": str(tools)}
    assert retained_plan is support_plan
    assert probes == [
        "python",
        "cargo",
        "rustc",
        "linker",
        "otool",
        "python",
        "cargo",
        "rustc",
        "linker",
        "otool",
        "python",
        "cargo",
        "rustc",
        "linker",
        "otool",
    ]


def _write_executable(path: Path) -> Path:
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def _write_rustup_proxy_tree(
    tmp_path: Path,
    *,
    nested_proxy: bool = True,
) -> tuple[Path, Path, Path]:
    tools = (tmp_path / "rustup-tools").resolve()
    tools.mkdir()
    rustup = tools / "rustup"
    cargo_proxy = tools / "cargo"
    if nested_proxy:
        rustup_init = _write_executable(tools / "rustup-init")
        rustup.symlink_to(rustup_init.name)
    else:
        _write_executable(rustup)
    cargo_proxy.symlink_to(rustup.name)
    cargo = _write_executable(tools / "actual-cargo")
    rustc = _write_executable(tools / "actual-rustc")
    return cargo_proxy, cargo, rustc


def test_rustup_proxy_chain_selects_stable_regular_tools_twice(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cargo_proxy, cargo, rustc = _write_rustup_proxy_tree(tmp_path)
    selections = iter((cargo, rustc, cargo, rustc))
    monkeypatch.setattr(
        host_inputs,
        "_rustup_selection_environment",
        lambda **_kwargs: {},
    )
    monkeypatch.setattr(
        host_inputs,
        "_rustup_which",
        lambda *_args, **_kwargs: next(selections),
    )

    assert host_inputs._resolve_actual_rust_tools(
        cargo_proxy,
        root=tmp_path.resolve(),
        config=RextioConfig(),
        inherited={},
    ) == (cargo, rustc)


def test_regular_rustup_proxy_selects_stable_regular_tools_twice(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cargo_proxy, cargo, rustc = _write_rustup_proxy_tree(
        tmp_path,
        nested_proxy=False,
    )
    selections = iter((cargo, rustc, cargo, rustc))
    monkeypatch.setattr(
        host_inputs,
        "_rustup_selection_environment",
        lambda **_kwargs: {},
    )
    monkeypatch.setattr(
        host_inputs,
        "_rustup_which",
        lambda *_args, **_kwargs: next(selections),
    )

    assert host_inputs._resolve_actual_rust_tools(
        cargo_proxy,
        root=tmp_path.resolve(),
        config=RextioConfig(),
        inherited={},
    ) == (cargo, rustc)


def test_non_rustup_cargo_symlink_is_rejected(tmp_path: Path) -> None:
    tools = (tmp_path / "non-rustup-tools").resolve()
    tools.mkdir()
    shim = _write_executable(tools / "cargo-shim")
    cargo_proxy = tools / "cargo"
    cargo_proxy.symlink_to(shim.name)

    with pytest.raises(FullC6HostInputsError, match="non-rustup"):
        host_inputs._resolve_actual_rust_tools(
            cargo_proxy,
            root=tmp_path.resolve(),
            config=RextioConfig(),
            inherited={},
        )


def test_rustup_selection_drift_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cargo_proxy, cargo, rustc = _write_rustup_proxy_tree(tmp_path)
    changed_cargo = _write_executable(cargo.parent / "changed-cargo")
    selections = iter((cargo, rustc, changed_cargo, rustc))
    monkeypatch.setattr(
        host_inputs,
        "_rustup_selection_environment",
        lambda **_kwargs: {},
    )
    monkeypatch.setattr(
        host_inputs,
        "_rustup_which",
        lambda *_args, **_kwargs: next(selections),
    )

    with pytest.raises(FullC6HostInputsError, match="ambiguous"):
        host_inputs._resolve_actual_rust_tools(
            cargo_proxy,
            root=tmp_path.resolve(),
            config=RextioConfig(),
            inherited={},
        )


def test_rustup_which_rejects_multiple_output_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rustup = _write_executable((tmp_path / "rustup").resolve())
    first = _write_executable((tmp_path / "first").resolve())
    second = _write_executable((tmp_path / "second").resolve())
    monkeypatch.setattr(
        host_inputs,
        "run_build_tool",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout=f"{first}\n{second}\n",
            stderr="",
        ),
    )

    with pytest.raises(FullC6HostInputsError, match="failed closed"):
        host_inputs._rustup_which(
            rustup,
            "cargo",
            root=tmp_path.resolve(),
            environment={},
        )


def test_configured_toolchain_support_lock_is_securely_pinned_and_typed(
    tmp_path: Path,
) -> None:
    project = (tmp_path / "project").resolve()
    project.mkdir()
    lock_path, expected, fields = _write_toolchain_support_lock(
        project,
        tmp_path,
    )

    observed, observed_path, binding = (
        host_inputs._collect_configured_toolchain_support_lock(
            project,
            _host_config(**fields),
            target_triple="aarch64-apple-darwin",
        )
    )

    assert type(observed) is ToolchainSupportLock
    assert observed == expected
    assert observed_path == lock_path
    assert binding.sha256 == expected.raw_sha256
    assert binding.links == 1


@pytest.mark.parametrize(
    "attack",
    ("wrong-pin", "noncanonical", "symlink", "hardlink", "wrong-target"),
)
def test_configured_toolchain_support_lock_fails_closed(
    tmp_path: Path,
    attack: str,
) -> None:
    project = (tmp_path / "project").resolve()
    project.mkdir()
    lock_path, lock, fields = _write_toolchain_support_lock(
        project,
        tmp_path,
        target_triple=(
            "x86_64-unknown-linux-gnu"
            if attack == "wrong-target"
            else "aarch64-apple-darwin"
        ),
    )
    if attack == "wrong-pin":
        fields["artifact_toolchain_support_lock_sha256"] = "0" * 64
    elif attack == "noncanonical":
        lock_path.write_bytes(lock.canonical_bytes + b"\n")
        fields["artifact_toolchain_support_lock_sha256"] = hashlib.sha256(
            lock_path.read_bytes()
        ).hexdigest()
    elif attack == "symlink":
        replacement = tmp_path / "replacement-lock.json"
        lock_path.rename(replacement)
        lock_path.symlink_to(replacement)
    elif attack == "hardlink":
        os.link(lock_path, tmp_path / "toolchain-support-alias.json")

    with pytest.raises(FullC6HostInputsError, match="toolchain support lock"):
        host_inputs._collect_configured_toolchain_support_lock(
            project,
            _host_config(**fields),
            target_triple="aarch64-apple-darwin",
        )


@pytest.mark.parametrize(
    "relative",
    (
        "state/toolchain-support.json",
        "dist/toolchain-support.json",
        "vendor/toolchain-support.json",
        "Cargo.lock",
    ),
)
def test_toolchain_support_lock_cannot_overlap_mutable_or_cargo_paths(
    tmp_path: Path,
    relative: str,
) -> None:
    project = tmp_path.resolve()
    config = _host_config(
        artifact_cargo_vendor="vendor",
        artifact_cargo_lock="Cargo.lock",
        artifact_toolchain_support_lock=relative,
    )

    with pytest.raises(FullC6HostInputsError, match="support lock must not overlap"):
        host_inputs._validate_host_layout(project, config)


def test_context_owns_two_fresh_quarantines_and_cleans_them(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = (tmp_path / "project").resolve()
    project.mkdir()
    support_lock_path, expected_support_lock, support_fields = (
        _write_toolchain_support_lock(project, tmp_path)
    )
    cargo_sources = object()
    workspace = SimpleNamespace(cargo_sources=cargo_sources)
    toolchain = SimpleNamespace(cargo_sources=cargo_sources)
    native_tools = object()
    support_plan = _mock_support_plan(monkeypatch)
    monkeypatch.setattr(host_inputs, "_require_supported_host", lambda: "aarch64-apple-darwin")
    monkeypatch.setattr(
        host_inputs,
        "_collect_configured_cargo_workspace",
        lambda _root, _config: workspace,
    )
    monkeypatch.setattr(
        host_inputs,
        "_collect_toolchain",
        lambda **_kwargs: (
            native_tools,
            toolchain,
            {"PATH": "/tools"},
            support_plan,
        ),
    )

    with collect_full_c6_host_prerequisites(
        project,
        config=_host_config(**support_fields),
        inherited_environment={"PATH": "/ignored", "TOKEN": "secret"},
    ) as prerequisites:
        first = prerequisites.first_quarantine_root
        second = prerequisites.second_quarantine_root
        assert first != second
        assert (first.stat().st_dev, first.stat().st_ino) != (
            second.stat().st_dev,
            second.stat().st_ino,
        )
        assert stat.S_IMODE(first.stat().st_mode) == 0o700
        assert prerequisites.source_date_epoch == FULL_C6_SOURCE_DATE_EPOCH
        assert prerequisites.base_environment == {"PATH": "/tools"}
        assert prerequisites.toolchain_support_lock == expected_support_lock
        assert prerequisites.toolchain_support_plan is support_plan
        retained_support_lock = prerequisites.toolchain_support_lock
        assert prerequisites.production_arguments()["cargo_workspace"] is workspace
        assert prerequisites.production_arguments()[
            "toolchain_support_plan"
        ] is support_plan
        assert prerequisites.production_arguments()[
            "toolchain_support_lock"
        ] is retained_support_lock
        assert prerequisites.toolchain.cargo_sources is workspace.cargo_sources
        assert stat.S_IMODE(prerequisites.state_directory.stat().st_mode) == 0o700
        assert prerequisites.state_directory == project / "state"
        assert not (project / "dist").exists()
        (first / "leftover").write_text("safe cleanup", encoding="utf-8")

        object.__setattr__(prerequisites, "_toolchain", object())
        sealed_accessors = (
            lambda: prerequisites.project_root,
            lambda: prerequisites.config,
            lambda: prerequisites.target_triple,
            lambda: prerequisites.source_date_epoch,
            lambda: prerequisites.toolchain,
            lambda: prerequisites.native_tools,
            lambda: prerequisites.toolchain_support_lock,
            lambda: prerequisites.toolchain_support_plan,
            lambda: prerequisites.cargo_workspace,
            lambda: prerequisites.first_quarantine_root,
            lambda: prerequisites.second_quarantine_root,
            lambda: prerequisites.state_directory,
            lambda: prerequisites.base_environment,
            prerequisites.production_arguments,
        )
        for access in sealed_accessors:
            with pytest.raises(FullC6HostInputsError, match="seal is invalid"):
                access()

        object.__setattr__(prerequisites, "_toolchain", toolchain)
        object.__setattr__(
            prerequisites,
            "_toolchain_support_lock",
            expected_support_lock,
        )
        with pytest.raises(FullC6HostInputsError, match="seal is invalid"):
            _ = prerequisites.toolchain_support_lock
        object.__setattr__(
            prerequisites,
            "_toolchain_support_lock",
            retained_support_lock,
        )
        object.__setattr__(prerequisites, "_toolchain_support_plan", object())
        with pytest.raises(FullC6HostInputsError, match="seal is invalid"):
            _ = prerequisites.toolchain_support_plan
        object.__setattr__(
            prerequisites,
            "_toolchain_support_plan",
            support_plan,
        )
        object.__setattr__(prerequisites, "_project_root", object())
        with pytest.raises(FullC6HostInputsError, match="seal is invalid"):
            _ = prerequisites.project_root
        object.__setattr__(prerequisites, "_project_root", project)

        # Direct mutation of the otherwise-private transition state must not
        # bypass real quarantine deletion or make context exit skip cleanup.
        prerequisites._lease.quarantine_cleaned = True
        prerequisites._lease.publication_authority = object()
        with pytest.raises(FullC6HostInputsError, match="seal is invalid"):
            _ = prerequisites.project_root
        prerequisites._lease.quarantine_cleaned = False
        prerequisites._lease.publication_authority = None
        assert prerequisites.project_root == project

        support_lock_path.write_bytes(b"changed after lease collection")
        with pytest.raises(FullC6HostInputsError, match="support lock changed"):
            _ = prerequisites.toolchain_support_lock

    assert not first.parent.exists()
    with pytest.raises(FullC6HostInputsError, match="lease has ended"):
        _ = prerequisites.project_root


def test_fixed_cargo_argv_is_the_only_native_build_shape() -> None:
    identity = capture_argv_identity(("cargo", *FULL_C6_CARGO_ARGUMENTS))

    assert identity.values == (
        "cargo",
        "build",
        "--release",
        "--locked",
        "--offline",
        "--frozen",
    )


def test_publication_plan_requires_valid_final_authority_and_real_wheel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = (tmp_path / "project").resolve()
    project.mkdir()
    (project / "key.bin").write_bytes(b"k" * 32)
    (project / "signature.json").write_text("{}", encoding="utf-8")
    _support_lock_path, _support_lock, support_fields = (
        _write_toolchain_support_lock(project, tmp_path)
    )
    config = _host_config(
        artifact_trusted_public_key="key.bin",
        artifact_final_signature="signature.json",
        **support_fields,
    )
    cargo_sources = object()
    workspace = SimpleNamespace(cargo_sources=cargo_sources)
    toolchain = SimpleNamespace(cargo_sources=cargo_sources)
    support_plan = _mock_support_plan(monkeypatch)
    monkeypatch.setattr(host_inputs, "_require_supported_host", lambda: "aarch64-apple-darwin")
    monkeypatch.setattr(
        host_inputs,
        "_collect_configured_cargo_workspace",
        lambda _root, _config: workspace,
    )
    monkeypatch.setattr(
        host_inputs,
        "_collect_toolchain",
        lambda **_kwargs: (
            object(),
            toolchain,
            {"PATH": "/tools"},
            support_plan,
        ),
    )
    monkeypatch.setattr(
        full_c6_production,
        "validate_full_c6_production_authority",
        lambda _authority: True,
    )
    remove_quarantines = host_inputs._remove_private_quarantine_container
    cleanup_calls = 0

    def tracked_cleanup(
        container: Path,
        binding: host_inputs._DirectoryBinding,
    ) -> None:
        nonlocal cleanup_calls
        cleanup_calls += 1
        remove_quarantines(container, binding)

    monkeypatch.setattr(
        host_inputs,
        "_remove_private_quarantine_container",
        tracked_cleanup,
    )

    with collect_full_c6_host_prerequisites(project, config=config) as prerequisites:
        first_quarantine = prerequisites.first_quarantine_root
        second_quarantine = prerequisites.second_quarantine_root
        wheel = prerequisites.state_directory / "native" / "demo-0.1.0-cp311-macosx.whl"
        wheel.parent.mkdir(mode=0o700)
        wheel.write_bytes(b"wheel")
        transaction = object()
        monkeypatch.setattr(
            full_c6_native_output,
            "full_c6_native_output_wheel_path",
            lambda _transaction: wheel,
        )
        material = SimpleNamespace(
            lifecycle=SimpleNamespace(status="publication-required"),
            project_root=project,
            config=config,
            cargo_workspace=workspace,
            native_output_transaction=transaction,
        )
        authority = object.__new__(full_c6_production.FullC6ProductionAuthority)
        object.__setattr__(authority, "_material", material)
        object.__setattr__(authority, "_transaction_seal", b"test")

        assert not (project / "dist").exists()
        with pytest.raises(FullC6HostInputsError, match="prepublication cleanup"):
            prerequisites.derive_publication_plan(authority)
        prerequisites.complete_prepublication_cleanup(authority)
        prerequisites.complete_prepublication_cleanup(authority)
        assert cleanup_calls == 1
        replaced_authority = object.__new__(
            full_c6_production.FullC6ProductionAuthority
        )
        object.__setattr__(replaced_authority, "_material", material)
        object.__setattr__(replaced_authority, "_transaction_seal", b"replacement")
        with pytest.raises(FullC6HostInputsError, match="authority changed"):
            prerequisites.complete_prepublication_cleanup(replaced_authority)
        assert not first_quarantine.parent.exists()
        assert not second_quarantine.exists()
        with pytest.raises(FullC6HostInputsError, match="cleanup is complete"):
            _ = prerequisites.first_quarantine_root
        plan = prerequisites.derive_publication_plan(authority)
        assert plan.wheel_filename == wheel.name
        assert plan.bundle_name == f"{wheel.name.removesuffix('.whl')}.full-c6"
        assert (project / "dist").is_dir()
        assert str(project) not in repr(plan)
        assert not hasattr(plan, "to_dict")
        adapter = object()

        def adapter_factory(**values: object) -> object:
            assert values["authority"] is authority
            assert values["bundle_name"] == plan.bundle_name
            return adapter

        monkeypatch.setattr(
            full_c6_pipeline,
            "_full_c6_atomic_publication_adapter",
            adapter_factory,
        )
        assert plan.atomic_adapter() is adapter
        with pytest.raises(TypeError):
            pickle.dumps(prerequisites)

        object.__setattr__(plan, "_subject_path", object())
        for access in (lambda: plan.wheel_filename, lambda: plan.bundle_name, plan.atomic_adapter):
            with pytest.raises(FullC6HostInputsError, match="seal is invalid"):
                access()
        object.__setattr__(plan, "_subject_path", wheel)

        material.lifecycle.status = "signing-required"
        with pytest.raises(FullC6HostInputsError, match="publication-required"):
            prerequisites.derive_publication_plan(authority)

    with pytest.raises(FullC6HostInputsError, match="lease has ended"):
        _ = plan.wheel_filename
    assert cleanup_calls == 1
    prerequisites._lease.active = True
    with pytest.raises(FullC6HostInputsError, match="seal is invalid"):
        _ = prerequisites.project_root
    with pytest.raises(FullC6HostInputsError, match="seal is invalid"):
        _ = plan.wheel_filename


def test_publication_plan_rejects_invalid_or_foreign_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = (tmp_path / "project").resolve()
    project.mkdir()
    _support_lock_path, _support_lock, support_fields = (
        _write_toolchain_support_lock(project, tmp_path)
    )
    cargo_sources = object()
    workspace = SimpleNamespace(cargo_sources=cargo_sources)
    toolchain = SimpleNamespace(cargo_sources=cargo_sources)
    support_plan = _mock_support_plan(monkeypatch)
    monkeypatch.setattr(host_inputs, "_require_supported_host", lambda: "aarch64-apple-darwin")
    monkeypatch.setattr(
        host_inputs,
        "_collect_configured_cargo_workspace",
        lambda _root, _config: workspace,
    )
    monkeypatch.setattr(
        host_inputs,
        "_collect_toolchain",
        lambda **_kwargs: (object(), toolchain, {}, support_plan),
    )

    with collect_full_c6_host_prerequisites(
        project,
        config=_host_config(**support_fields),
    ) as prerequisites:
        with pytest.raises(FullC6HostInputsError, match="valid production authority"):
            prerequisites.complete_prepublication_cleanup(object())


def test_post_cleanup_revalidation_failure_is_not_retried_on_context_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = (tmp_path / "project").resolve()
    project.mkdir()
    _support_lock_path, _support_lock, support_fields = (
        _write_toolchain_support_lock(project, tmp_path)
    )
    config = _host_config(**support_fields)
    cargo_sources = object()
    workspace = SimpleNamespace(cargo_sources=cargo_sources)
    toolchain = SimpleNamespace(cargo_sources=cargo_sources)
    support_plan = _mock_support_plan(monkeypatch)
    monkeypatch.setattr(
        host_inputs,
        "_require_supported_host",
        lambda: "aarch64-apple-darwin",
    )
    monkeypatch.setattr(
        host_inputs,
        "_collect_configured_cargo_workspace",
        lambda _root, _config: workspace,
    )
    monkeypatch.setattr(
        host_inputs,
        "_collect_toolchain",
        lambda **_kwargs: (object(), toolchain, {}, support_plan),
    )
    monkeypatch.setattr(
        full_c6_production,
        "validate_full_c6_production_authority",
        lambda _authority: True,
    )
    cleanup_calls = 0
    remove_quarantines = host_inputs._remove_private_quarantine_container

    with collect_full_c6_host_prerequisites(project, config=config) as prerequisites:
        quarantine_container = prerequisites.first_quarantine_root.parent
        state_directory = prerequisites.state_directory
        material = SimpleNamespace(
            lifecycle=SimpleNamespace(status="publication-required"),
            project_root=project,
            config=config,
            cargo_workspace=workspace,
        )
        authority = object.__new__(full_c6_production.FullC6ProductionAuthority)
        object.__setattr__(authority, "_material", material)
        object.__setattr__(authority, "_transaction_seal", b"test")

        def cleanup_then_change_state(
            container: Path,
            binding: host_inputs._DirectoryBinding,
        ) -> None:
            nonlocal cleanup_calls
            cleanup_calls += 1
            remove_quarantines(container, binding)
            state_directory.chmod(0o755)

        monkeypatch.setattr(
            host_inputs,
            "_remove_private_quarantine_container",
            cleanup_then_change_state,
        )
        with pytest.raises(FullC6HostInputsError, match="directory changed"):
            prerequisites.complete_prepublication_cleanup(authority)
        assert cleanup_calls == 1
        assert not quarantine_container.exists()
        assert not (project / "dist").exists()

    assert cleanup_calls == 1


@pytest.mark.skipif(
    platform.python_implementation() != "CPython" or sys.version_info[:2] != (3, 11),
    reason="real host gate is intentionally CPython 3.11-only",
)
def test_real_host_probe_is_availability_gated() -> None:
    """Keep the real OS probe optional; synthetic tests remain host-independent."""
    try:
        target = host_inputs._require_supported_host()
    except FullC6HostInputsError:
        pytest.skip("this runner is outside the supported Full C6 host pair")
    assert target in {"aarch64-apple-darwin", "x86_64-unknown-linux-gnu"}
