"""Adversarial tests for exact C5.2 source-wheel authority."""

from __future__ import annotations

import base64
import csv
from dataclasses import replace
import hashlib
import io
import stat
import zipfile
from pathlib import Path

import pytest

from rextio.artifacts import ArtifactProvenance
from rextio.source.external import AuthorityFile, ExternalSourcePlan
from rextio.source.models import SourceModule, SourceOrigin
from rextio.source.wheel_authority import (
    SourceWheelAuthorityError,
    verify_source_wheel,
    verify_source_wheel_license_detection,
)


PACKAGE = "demo_pkg"
DIST = "demo-pkg"
VERSION = "1.0.0"
DIST_INFO = "demo_pkg-1.0.0.dist-info"
SOURCE_NAME = "demo_pkg/__init__.py"
SOURCE = b"def affine(x: int) -> int:\n    return x + 1\n"
LICENSE = (
    b"MIT License\n\n"
    b"Copyright (c) 2026 Demo\n\n"
    b"Permission is hereby granted, free of charge, to any person obtaining a copy\n"
    b"of this software and associated documentation files (the \"Software\"), to deal\n"
    b"in the Software without restriction, including without limitation the rights\n"
    b"to use, copy, modify, merge, publish, distribute, sublicense, and/or sell\n"
    b"copies of the Software, and to permit persons to whom the Software is\n"
    b"furnished to do so, subject to the following conditions:\n\n"
    b"The above copyright notice and this permission notice shall be included in all\n"
    b"copies or substantial portions of the Software.\n\n"
    b'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\n'
    b"IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n"
    b"FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\n"
    b"AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n"
    b"LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\n"
    b"OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\n"
    b"SOFTWARE.\n"
)
WHEEL = b"Wheel-Version: 1.0\nGenerator: rextio-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
METADATA = (
    b"Metadata-Version: 2.4\n"
    b"Name: demo-pkg\n"
    b"Version: 1.0.0\n"
    b"License-Expression: MIT\n"
    b"License-File: LICENSE\n\n"
)


def _record(entries: dict[str, bytes]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for name, data in sorted(entries.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
        writer.writerow((name, f"sha256={digest}", str(len(data))))
    writer.writerow((f"{DIST_INFO}/RECORD", "", ""))
    return output.getvalue().encode()


def _base_entries(source: bytes = SOURCE) -> dict[str, bytes]:
    entries = {
        SOURCE_NAME: source,
        f"{DIST_INFO}/METADATA": METADATA,
        f"{DIST_INFO}/WHEEL": WHEEL,
        f"{DIST_INFO}/licenses/LICENSE": LICENSE,
    }
    entries[f"{DIST_INFO}/RECORD"] = _record(entries)
    return entries


def _wheel_bytes(
    entries: dict[str, bytes],
    *,
    modes: dict[str, int] | None = None,
    duplicate: str | None = None,
) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = (modes or {}).get(name, stat.S_IFREG | 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
        if duplicate is not None:
            info = zipfile.ZipInfo(duplicate)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, entries[duplicate])
    return output.getvalue()


def _authority_path(name: str) -> str:
    return f"distributions/{DIST}/{name}"


def _plan(entries: dict[str, bytes] | None = None) -> ExternalSourcePlan:
    values = entries or _base_entries()
    source = values[SOURCE_NAME]
    source_path = _authority_path(SOURCE_NAME)
    module = SourceModule(
        module_name=PACKAGE,
        path=source_path,
        is_package_init=True,
        source_origin=SourceOrigin.DISTRIBUTION,
        sha256=hashlib.sha256(source).hexdigest(),
        dependency_depth=1,
        distribution=DIST,
        version=VERSION,
        license="MIT",
        provenance=ArtifactProvenance(source_references=(source_path,)),
    )
    source_files = (
        AuthorityFile(
            path=source_path,
            sha256=module.sha256,
            size=len(source),
            role="source-module",
            module_name=PACKAGE,
        ),
    )
    roles = {
        f"{DIST_INFO}/METADATA": "metadata",
        f"{DIST_INFO}/RECORD": "record",
        f"{DIST_INFO}/WHEEL": "wheel",
    }
    license_path = f"{DIST_INFO}/licenses/LICENSE"
    if license_path in values:
        roles[license_path] = "license-file"
    metadata_files = tuple(
        sorted(
            (
                AuthorityFile(
                    path=_authority_path(name),
                    sha256=hashlib.sha256(values[name]).hexdigest(),
                    size=len(values[name]),
                    role=role,
                )
                for name, role in roles.items()
            ),
            key=lambda item: item.path,
        )
    )
    return ExternalSourcePlan(
        package=PACKAGE,
        distribution=DIST,
        requested_version=VERSION,
        installed_version=VERSION,
        max_depth=1,
        status="preview-ready",
        license="MIT",
        modules=(module,),
        candidate_functions=(f"{PACKAGE}.affine",),
        source_files=source_files,
        metadata_files=metadata_files,
    )


def _write_wheel(path: Path, payload: bytes) -> str:
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _with_installed_record(
    plan: ExternalSourcePlan,
    payload: bytes,
) -> ExternalSourcePlan:
    installed_record = AuthorityFile(
        path=_authority_path(f"{DIST_INFO}/RECORD"),
        sha256=hashlib.sha256(payload).hexdigest(),
        size=len(payload),
        role="record",
    )
    return replace(
        plan,
        metadata_files=tuple(
            installed_record if item.role == "record" else item
            for item in plan.metadata_files
        ),
    )


def _mark_first_entry_encrypted(payload: bytes) -> bytes:
    changed = bytearray(payload)
    for signature, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        index = changed.find(signature)
        assert index >= 0
        flags = int.from_bytes(changed[index + flag_offset : index + flag_offset + 2], "little")
        changed[index + flag_offset : index + flag_offset + 2] = (flags | 1).to_bytes(2, "little")
    return bytes(changed)


def test_exact_pure_wheel_produces_immutable_depth_one_snapshot(tmp_path: Path) -> None:
    entries = _base_entries()
    payload = _wheel_bytes(entries)
    path = tmp_path / "demo_pkg-1.0.0-py3-none-any.whl"
    digest = _write_wheel(path, payload)

    authority = verify_source_wheel(path, expected_sha256=digest, plan=_plan(entries))

    assert authority.archive.sha256 == digest
    assert authority.snapshots[0].source_bytes == SOURCE
    assert authority.snapshots[0].module.module_name == PACKAGE
    assert authority.authorizes_build is False
    assert authority.authorizes_distribution is False
    assert authority.license_detection.status == "detected"
    assert authority.license_detection.detected_spdx == "MIT"
    assert verify_source_wheel_license_detection(
        authority.license_detection,
        authority.license_entry_paths,
        authority.license_payloads,
    )
    serialized = repr(authority.to_dict())
    assert SOURCE.decode().strip() not in serialized
    assert str(tmp_path) not in serialized


@pytest.mark.parametrize(
    "installed_record",
    (
        # Index-resolved pip install: INSTALLER, REQUESTED, and bytecode are
        # installer-owned rows, while direct_url.json is absent.
        b"demo_pkg-1.0.0.dist-info/INSTALLER,sha256=installer,4\n"
        b"demo_pkg-1.0.0.dist-info/REQUESTED,sha256=empty,0\n"
        b"demo_pkg/__pycache__/__init__.cpython-311.pyc,,\n"
        b"demo_pkg-1.0.0.dist-info/RECORD,,\n",
        # Direct local-wheel pip install additionally records PEP 610 origin.
        b"demo_pkg-1.0.0.dist-info/INSTALLER,sha256=installer,4\n"
        b"demo_pkg-1.0.0.dist-info/REQUESTED,sha256=empty,0\n"
        b"demo_pkg-1.0.0.dist-info/direct_url.json,sha256=origin,200\n"
        b"demo_pkg/__pycache__/__init__.cpython-311.pyc,,\n"
        b"demo_pkg-1.0.0.dist-info/RECORD,,\n",
    ),
)
def test_installed_and_archive_record_are_separate_bound_authorities(
    tmp_path: Path,
    installed_record: bytes,
) -> None:
    entries = _base_entries()
    payload = _wheel_bytes(entries)
    path = tmp_path / "demo_pkg-1.0.0-py3-none-any.whl"
    digest = _write_wheel(path, payload)
    plan = _with_installed_record(_plan(entries), installed_record)

    authority = verify_source_wheel(path, expected_sha256=digest, plan=plan)

    plan_record = next(item for item in plan.metadata_files if item.role == "record")
    archive_record = next(
        item for item in authority.entries if item.path == f"{DIST_INFO}/RECORD"
    )
    assert plan_record.sha256 == hashlib.sha256(installed_record).hexdigest()
    assert archive_record.sha256 == hashlib.sha256(entries[f"{DIST_INFO}/RECORD"]).hexdigest()
    assert plan_record.sha256 != archive_record.sha256


def test_installed_record_role_path_and_cardinality_are_fail_closed(
    tmp_path: Path,
) -> None:
    entries = _base_entries()
    payload = _wheel_bytes(entries)
    path = tmp_path / "demo_pkg-1.0.0-py3-none-any.whl"
    digest = _write_wheel(path, payload)
    plan = _plan(entries)
    record = next(item for item in plan.metadata_files if item.role == "record")

    missing = replace(
        plan,
        metadata_files=tuple(
            replace(item, role="metadata") if item is record else item
            for item in plan.metadata_files
        ),
    )
    with pytest.raises(SourceWheelAuthorityError, match="installed-record-plan-invalid"):
        verify_source_wheel(path, expected_sha256=digest, plan=missing)

    substituted = replace(
        plan,
        metadata_files=tuple(
            replace(item, role="record")
            if item.role == "metadata"
            else replace(item, role="metadata")
            if item.role == "record"
            else item
            for item in plan.metadata_files
        ),
    )
    with pytest.raises(SourceWheelAuthorityError, match="installed-record-plan-invalid"):
        verify_source_wheel(path, expected_sha256=digest, plan=substituted)

    wrong_path = replace(
        plan,
        metadata_files=tuple(
            replace(record, path=_authority_path(f"{DIST_INFO}/INSTALLER"))
            if item is record
            else item
            for item in plan.metadata_files
        ),
    )
    with pytest.raises(SourceWheelAuthorityError, match="installed-record-plan-invalid"):
        verify_source_wheel(path, expected_sha256=digest, plan=wrong_path)

    duplicate = replace(
        plan,
        metadata_files=(
            *plan.metadata_files,
            replace(record, path=_authority_path(f"{DIST_INFO}/installed.RECORD")),
        ),
    )
    with pytest.raises(SourceWheelAuthorityError, match="installed-record-plan-invalid"):
        verify_source_wheel(path, expected_sha256=digest, plan=duplicate)

    identical_duplicate = replace(
        plan,
        metadata_files=(*plan.metadata_files, record),
    )
    with pytest.raises(SourceWheelAuthorityError, match="installed-record-plan-invalid"):
        verify_source_wheel(
            path,
            expected_sha256=digest,
            plan=identical_duplicate,
        )

    invalid_sha_record = replace(record)
    object.__setattr__(invalid_sha_record, "sha256", "invalid")

    class AuthorityFileSubtype(AuthorityFile):
        pass

    subtype_record = AuthorityFileSubtype(
        path=record.path,
        sha256=record.sha256,
        size=record.size,
        role=record.role,
    )
    for invalid_record in (
        replace(record, role="Record"),
        replace(record, module_name=PACKAGE),
        replace(record, size=True),
        invalid_sha_record,
        subtype_record,
    ):
        invalid_plan = replace(
            plan,
            metadata_files=tuple(
                invalid_record if item is record else item
                for item in plan.metadata_files
            ),
        )
        with pytest.raises(
            SourceWheelAuthorityError,
            match="installed-record-plan-invalid",
        ):
            verify_source_wheel(
                path,
                expected_sha256=digest,
                plan=invalid_plan,
            )

    with pytest.warns(UserWarning, match="Duplicate name"):
        duplicate_archive_record = _wheel_bytes(
            entries,
            duplicate=f"{DIST_INFO}/RECORD",
        )
    duplicate_digest = _write_wheel(path, duplicate_archive_record)
    with pytest.raises(SourceWheelAuthorityError, match="duplicate"):
        verify_source_wheel(
            path,
            expected_sha256=duplicate_digest,
            plan=plan,
        )


@pytest.mark.parametrize("role", ("metadata", "wheel", "license-file"))
def test_dual_record_exception_does_not_exclude_shared_metadata_drift(
    tmp_path: Path,
    role: str,
) -> None:
    entries = _base_entries()
    payload = _wheel_bytes(entries)
    path = tmp_path / "demo_pkg-1.0.0-py3-none-any.whl"
    digest = _write_wheel(path, payload)
    plan = _with_installed_record(_plan(entries), b"pip-rewritten-record\n")
    drifted = replace(
        plan,
        metadata_files=tuple(
            replace(item, sha256="0" * 64) if item.role == role else item
            for item in plan.metadata_files
        ),
    )

    with pytest.raises(SourceWheelAuthorityError, match="metadata-set-plan-mismatch"):
        verify_source_wheel(path, expected_sha256=digest, plan=drifted)


def test_metadata_license_does_not_masquerade_as_independent_detection(
    tmp_path: Path,
) -> None:
    entries = _base_entries()
    license_path = f"{DIST_INFO}/licenses/LICENSE"
    entries[license_path] = b"MIT License\n"
    entries[f"{DIST_INFO}/RECORD"] = _record(
        {name: data for name, data in entries.items() if name != f"{DIST_INFO}/RECORD"}
    )
    payload = _wheel_bytes(entries)
    path = tmp_path / "demo_pkg-1.0.0-py3-none-any.whl"
    digest = _write_wheel(path, payload)

    authority = verify_source_wheel(path, expected_sha256=digest, plan=_plan(entries))

    assert authority.license_observed == "MIT"
    assert authority.license_detection.status == "unsupported"
    assert authority.license_detection.detected_spdx is None


def test_mit_body_with_trailing_dual_license_terms_fails_closed(tmp_path: Path) -> None:
    entries = _base_entries()
    license_path = f"{DIST_INFO}/licenses/LICENSE"
    entries[license_path] = (
        LICENSE
        + b"\nAdditional terms: this work is alternatively available under Apache-2.0.\n"
    )
    entries[f"{DIST_INFO}/RECORD"] = _record(
        {name: data for name, data in entries.items() if name != f"{DIST_INFO}/RECORD"}
    )
    payload = _wheel_bytes(entries)
    path = tmp_path / "demo_pkg-1.0.0-py3-none-any.whl"
    digest = _write_wheel(path, payload)

    authority = verify_source_wheel(path, expected_sha256=digest, plan=_plan(entries))

    assert authority.license_observed == "MIT"
    assert authority.license_detection.status == "unsupported"
    assert authority.license_detection.detected_spdx is None


def test_license_detector_receipt_tampering_is_rejected(tmp_path: Path) -> None:
    entries = _base_entries()
    payload = _wheel_bytes(entries)
    path = tmp_path / "demo_pkg-1.0.0-py3-none-any.whl"
    digest = _write_wheel(path, payload)
    authority = verify_source_wheel(path, expected_sha256=digest, plan=_plan(entries))

    object.__setattr__(authority.license_detection, "detected_spdx", None)

    assert not verify_source_wheel_license_detection(
        authority.license_detection,
        authority.license_entry_paths,
        authority.license_payloads,
    )


def test_archive_hash_and_symlink_are_fail_closed(tmp_path: Path) -> None:
    entries = _base_entries()
    payload = _wheel_bytes(entries)
    path = tmp_path / "demo_pkg-1.0.0-py3-none-any.whl"
    digest = _write_wheel(path, payload)
    with pytest.raises(SourceWheelAuthorityError, match="sha256"):
        verify_source_wheel(path, expected_sha256="0" * 64, plan=_plan(entries))

    linked = tmp_path / "linked.whl"
    linked.symlink_to(path)
    with pytest.raises(SourceWheelAuthorityError, match="regular"):
        verify_source_wheel(linked, expected_sha256=digest, plan=_plan(entries))


@pytest.mark.parametrize(
    "unsafe_name",
    ("../escape.py", "/absolute.py", "bad\\name.py", "bad\x00name.py", "bad\x1fname.py"),
)
def test_unsafe_member_names_are_rejected(tmp_path: Path, unsafe_name: str) -> None:
    entries = _base_entries()
    entries[unsafe_name] = b"x = 1\n"
    entries[f"{DIST_INFO}/RECORD"] = _record(
        {name: data for name, data in entries.items() if name != f"{DIST_INFO}/RECORD"}
    )
    payload = _wheel_bytes(entries)
    path = tmp_path / "demo_pkg-1.0.0-py3-none-any.whl"
    digest = _write_wheel(path, payload)
    with pytest.raises(SourceWheelAuthorityError, match="unsafe"):
        verify_source_wheel(path, expected_sha256=digest, plan=_plan(_base_entries()))


def test_duplicate_case_alias_and_nonregular_entries_are_rejected(tmp_path: Path) -> None:
    entries = _base_entries()
    with pytest.warns(UserWarning, match="Duplicate name"):
        payload = _wheel_bytes(entries, duplicate=SOURCE_NAME)
    path = tmp_path / "demo_pkg-1.0.0-py3-none-any.whl"
    digest = _write_wheel(path, payload)
    with pytest.raises(SourceWheelAuthorityError, match="duplicate"):
        verify_source_wheel(path, expected_sha256=digest, plan=_plan(entries))

    aliased = _base_entries()
    aliased["DEMO_PKG/__init__.py"] = SOURCE
    aliased[f"{DIST_INFO}/RECORD"] = _record(
        {name: data for name, data in aliased.items() if name != f"{DIST_INFO}/RECORD"}
    )
    payload = _wheel_bytes(aliased)
    digest = _write_wheel(path, payload)
    with pytest.raises(SourceWheelAuthorityError, match="alias"):
        verify_source_wheel(path, expected_sha256=digest, plan=_plan(entries))

    unicode_alias = _base_entries()
    unicode_alias["data/caf\N{LATIN SMALL LETTER E WITH ACUTE}.txt"] = b"first"
    unicode_alias["data/cafe\N{COMBINING ACUTE ACCENT}.txt"] = b"second"
    unicode_alias[f"{DIST_INFO}/RECORD"] = _record(
        {name: data for name, data in unicode_alias.items() if name != f"{DIST_INFO}/RECORD"}
    )
    payload = _wheel_bytes(unicode_alias)
    digest = _write_wheel(path, payload)
    with pytest.raises(SourceWheelAuthorityError, match="unsafe|alias"):
        verify_source_wheel(path, expected_sha256=digest, plan=_plan(entries))

    payload = _wheel_bytes(entries, modes={SOURCE_NAME: stat.S_IFLNK | 0o777})
    digest = _write_wheel(path, payload)
    with pytest.raises(SourceWheelAuthorityError, match="regular"):
        verify_source_wheel(path, expected_sha256=digest, plan=_plan(entries))

    payload = _mark_first_entry_encrypted(_wheel_bytes(entries))
    digest = _write_wheel(path, payload)
    with pytest.raises(SourceWheelAuthorityError, match="encrypted"):
        verify_source_wheel(path, expected_sha256=digest, plan=_plan(entries))


def test_record_coverage_hash_size_and_plan_drift_are_rejected(tmp_path: Path) -> None:
    base = _base_entries()
    path = tmp_path / "demo_pkg-1.0.0-py3-none-any.whl"

    unrecorded = dict(base)
    unrecorded["data.bin"] = b"data"
    payload = _wheel_bytes(unrecorded)
    digest = _write_wheel(path, payload)
    with pytest.raises(SourceWheelAuthorityError, match="coverage"):
        verify_source_wheel(path, expected_sha256=digest, plan=_plan(base))

    bad_record = dict(base)
    record_text = bad_record[f"{DIST_INFO}/RECORD"].decode().replace("sha256=", "sha256=AAAA", 1)
    bad_record[f"{DIST_INFO}/RECORD"] = record_text.encode()
    payload = _wheel_bytes(bad_record)
    digest = _write_wheel(path, payload)
    with pytest.raises(SourceWheelAuthorityError, match="hash"):
        verify_source_wheel(path, expected_sha256=digest, plan=_plan(base))

    changed = _base_entries(b"def affine(x: int) -> int:\n    return x + 2\n")
    payload = _wheel_bytes(changed)
    digest = _write_wheel(path, payload)
    with pytest.raises(SourceWheelAuthorityError, match="plan-mismatch"):
        verify_source_wheel(path, expected_sha256=digest, plan=_plan(base))


def test_platform_tag_foreign_metadata_and_compression_bomb_are_rejected(
    tmp_path: Path,
) -> None:
    entries = _base_entries()
    path = tmp_path / "demo_pkg-1.0.0-py3-none-any.whl"

    bad_tag_path = tmp_path / "demo_pkg-1.0.0-cp311-cp311-macosx_11_0_arm64.whl"
    payload = _wheel_bytes(entries)
    digest = _write_wheel(bad_tag_path, payload)
    with pytest.raises(SourceWheelAuthorityError, match="pure"):
        verify_source_wheel(bad_tag_path, expected_sha256=digest, plan=_plan(entries))

    wrong_name_path = tmp_path / "other_pkg-1.0.0-py3-none-any.whl"
    digest = _write_wheel(wrong_name_path, payload)
    with pytest.raises(SourceWheelAuthorityError, match="identity"):
        verify_source_wheel(wrong_name_path, expected_sha256=digest, plan=_plan(entries))

    wrong_metadata = dict(entries)
    wrong_metadata[f"{DIST_INFO}/METADATA"] = METADATA.replace(b"Name: demo-pkg", b"Name: other")
    wrong_metadata[f"{DIST_INFO}/RECORD"] = _record(
        {name: data for name, data in wrong_metadata.items() if name != f"{DIST_INFO}/RECORD"}
    )
    payload = _wheel_bytes(wrong_metadata)
    digest = _write_wheel(path, payload)
    with pytest.raises(SourceWheelAuthorityError, match="identity"):
        verify_source_wheel(path, expected_sha256=digest, plan=_plan(entries))

    foreign = dict(entries)
    foreign["other-1.0.dist-info/METADATA"] = b"foreign"
    foreign[f"{DIST_INFO}/RECORD"] = _record(
        {name: data for name, data in foreign.items() if name != f"{DIST_INFO}/RECORD"}
    )
    payload = _wheel_bytes(foreign)
    digest = _write_wheel(path, payload)
    with pytest.raises(SourceWheelAuthorityError, match="foreign"):
        verify_source_wheel(path, expected_sha256=digest, plan=_plan(entries))

    case_aliased_foreign = dict(entries)
    case_aliased_foreign["other-1.0.DIST-INFO/METADATA"] = b"foreign"
    case_aliased_foreign[f"{DIST_INFO}/RECORD"] = _record(
        {name: data for name, data in case_aliased_foreign.items() if name != f"{DIST_INFO}/RECORD"}
    )
    payload = _wheel_bytes(case_aliased_foreign)
    digest = _write_wheel(path, payload)
    with pytest.raises(SourceWheelAuthorityError, match="foreign"):
        verify_source_wheel(path, expected_sha256=digest, plan=_plan(entries))

    bomb = dict(entries)
    bomb["data.bin"] = b"A" * 100_000
    bomb[f"{DIST_INFO}/RECORD"] = _record(
        {name: data for name, data in bomb.items() if name != f"{DIST_INFO}/RECORD"}
    )
    payload = _wheel_bytes(bomb)
    digest = _write_wheel(path, payload)
    with pytest.raises(SourceWheelAuthorityError, match="ratio"):
        verify_source_wheel(path, expected_sha256=digest, plan=_plan(entries))


def test_strict_scope_requires_one_exact_license_file(tmp_path: Path) -> None:
    entries = _base_entries()
    entries.pop(f"{DIST_INFO}/licenses/LICENSE")
    entries[f"{DIST_INFO}/METADATA"] = (
        b"Metadata-Version: 2.3\nName: demo-pkg\nVersion: 1.0.0\nLicense: MIT\n\n"
    )
    entries[f"{DIST_INFO}/RECORD"] = _record(
        {name: data for name, data in entries.items() if name != f"{DIST_INFO}/RECORD"}
    )
    payload = _wheel_bytes(entries)
    path = tmp_path / "demo_pkg-1.0.0-py3-none-any.whl"
    digest = _write_wheel(path, payload)

    with pytest.raises(SourceWheelAuthorityError, match="plan-out-of-scope"):
        verify_source_wheel(path, expected_sha256=digest, plan=_plan(entries))
