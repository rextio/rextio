from __future__ import annotations

import base64
import copy
import hashlib
import json
import pickle
import stat
import zipfile
from pathlib import Path

import pytest

from rextio.artifacts.evidence import (
    EvidenceFileRef,
    WheelEntryRef,
    inventory_wheel_zip_bytes,
)
from rextio.build.full_c6_subject_wheel import (
    FullC6SubjectWheelError,
    FullC6SubjectWheelTransaction,
    capture_full_c6_subject_wheel,
    validate_full_c6_subject_wheel_transaction,
)
from rextio.build.full_c6_output_license import (
    OutputWheelLicenseContract,
    OutputWheelLicenseFile,
)
from rextio.build.wheel_builder import (
    ExternalWheelContract,
    ExternalWheelMemberIdentity,
)


NATIVE_NAME = "_rextio_native.cpython-311-test.so"
DIST_INFO = "subject-0.1.0.dist-info"


def _record_hash(data: bytes) -> str:
    encoded = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return f"sha256={encoded.decode('ascii')}"


def _contract() -> ExternalWheelContract:
    source_payloads = {
        "demo_pkg/__init__.py": b"def affine(x): return x + 1\n",
        "demo_pkg-1.0.0.dist-info/METADATA": b"metadata",
        "demo_pkg-1.0.0.dist-info/WHEEL": b"wheel",
        "demo_pkg-1.0.0.dist-info/licenses/LICENSE": b"license",
        "demo_pkg-1.0.0.dist-info/RECORD": b"record",
    }
    return ExternalWheelContract(
        package="demo_pkg",
        distribution="demo-pkg",
        version="1.0.0",
        source_members=("demo_pkg/__init__.py",),
        external_members=tuple(
            ExternalWheelMemberIdentity(
                path=name,
                sha256=hashlib.sha256(data).hexdigest(),
                size=len(data),
            )
            for name, data in sorted(source_payloads.items())
        ),
    )


def _payloads(native: bytes = b"native-extension") -> dict[str, bytes]:
    return {
        NATIVE_NAME: native,
        "app/__init__.py": b"VALUE = 1\n",
        f"{DIST_INFO}/METADATA": (
            b"Metadata-Version: 2.1\nName: subject\nVersion: 0.1.0\n"
            b"Requires-Dist: demo-pkg==1.0.0\n"
        ),
        f"{DIST_INFO}/WHEEL": (
            b"Wheel-Version: 1.0\nGenerator: tests\nRoot-Is-Purelib: false\n"
            b"Tag: cp311-cp311-test\n"
        ),
    }


def _output_license_contract() -> OutputWheelLicenseContract:
    return OutputWheelLicenseContract(
        expression="MIT",
        files=(OutputWheelLicenseFile(path="LICENSE", data=b"license payload\n"),),
    )


def _licensed_payloads(
    *,
    native: bytes = b"native-extension",
    license_payload: bytes = b"license payload\n",
) -> dict[str, bytes]:
    payloads = _payloads(native)
    payloads[f"{DIST_INFO}/METADATA"] = (
        b"Metadata-Version: 2.4\nName: subject\nVersion: 0.1.0\n"
        b"Requires-Dist: demo-pkg==1.0.0\n"
        b"License-Expression: MIT\nLicense-File: LICENSE\n"
    )
    payloads[f"{DIST_INFO}/licenses/LICENSE"] = license_payload
    return payloads


def _write_wheel(
    path: Path,
    payloads: dict[str, bytes],
    *,
    extra_entries: tuple[tuple[str, bytes, int], ...] = (),
    record_override: bytes | None = None,
) -> None:
    entries = list(payloads.items()) + [(name, data) for name, data, _mode in extra_entries]
    record_name = f"{DIST_INFO}/RECORD"
    record = _record_bytes(entries)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        special_modes = {name: mode for name, _data, mode in extra_entries}
        for name, data in entries:
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = special_modes.get(name, stat.S_IFREG | 0o644) << 16
            archive.writestr(info, data)
        info = zipfile.ZipInfo(record_name)
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = (stat.S_IFREG | 0o644) << 16
        archive.writestr(info, record if record_override is None else record_override)


def _record_bytes(entries: list[tuple[str, bytes]]) -> bytes:
    record_name = f"{DIST_INFO}/RECORD"
    return b"\n".join(
        f"{name},{_record_hash(data)},{len(data)}".encode() for name, data in entries
    ) + f"\n{record_name},,\n".encode()


def _subject(path: Path) -> EvidenceFileRef:
    data = path.read_bytes()
    return EvidenceFileRef(
        logical_path=f"dist/{path.name}",
        sha256=hashlib.sha256(data).hexdigest(),
        size=len(data),
        role="host-extension-wheel",
    )


def _expected(path: Path) -> tuple[EvidenceFileRef, tuple[WheelEntryRef, ...]]:
    data = path.read_bytes()
    return _subject(path), inventory_wheel_zip_bytes(data)


def _capture(
    path: Path,
    *,
    native: bytes = b"native-extension",
    output_license_contract: OutputWheelLicenseContract | None = None,
) -> FullC6SubjectWheelTransaction:
    subject, entries = _expected(path)
    return capture_full_c6_subject_wheel(
        path,
        expected_subject=subject,
        expected_wheel_entries=entries,
        external_contract=_contract(),
        native_member_path=NATIVE_NAME,
        expected_native_member_sha256=hashlib.sha256(native).hexdigest(),
        expected_native_member_size=len(native),
        output_license_contract=output_license_contract,
    )


def test_capture_full_c6_subject_wheel_rejects_plain_text_whl(tmp_path: Path) -> None:
    path = tmp_path / "subject-0.1.0-cp311-cp311-test.whl"
    path.write_text("not a zip", encoding="utf-8")
    data = path.read_bytes()
    subject = EvidenceFileRef(
        logical_path=f"dist/{path.name}",
        sha256=hashlib.sha256(data).hexdigest(),
        size=len(data),
        role="host-extension-wheel",
    )
    with pytest.raises(FullC6SubjectWheelError, match="captured exactly"):
        capture_full_c6_subject_wheel(
            path,
            expected_subject=subject,
            expected_wheel_entries=(),
            external_contract=_contract(),
            native_member_path=NATIVE_NAME,
            expected_native_member_sha256=hashlib.sha256(b"native").hexdigest(),
            expected_native_member_size=6,
        )


def test_capture_seals_actual_zip_and_is_path_free_nonserializable(tmp_path: Path) -> None:
    path = tmp_path / "subject-0.1.0-cp311-cp311-test.whl"
    _write_wheel(path, _payloads())

    transaction = _capture(path)

    assert validate_full_c6_subject_wheel_transaction(transaction)
    serialized = json.dumps(transaction.to_dict(), sort_keys=True)
    assert str(tmp_path) not in serialized
    assert NATIVE_NAME not in serialized
    assert DIST_INFO not in serialized
    assert set(transaction.to_dict()) == {
        "domain",
        "subject_sha256",
        "subject_identity_sha256",
        "wheel_inventory_sha256",
        "external_contract_sha256",
        "external_verification_sha256",
        "native_member_sha256",
        "native_member_identity_sha256",
        "record_member_sha256",
        "record_member_identity_sha256",
        "digest",
    }
    with pytest.raises(TypeError):
        copy.copy(transaction)
    with pytest.raises(TypeError):
        copy.deepcopy(transaction)
    with pytest.raises(TypeError):
        pickle.dumps(transaction)
    with pytest.raises(TypeError):
        FullC6SubjectWheelTransaction()


def test_capture_privately_seals_and_revalidates_output_license_bytes(
    tmp_path: Path,
) -> None:
    path = tmp_path / "subject-0.1.0-cp311-cp311-test.whl"
    contract = _output_license_contract()
    _write_wheel(path, _licensed_payloads())

    transaction = _capture(path, output_license_contract=contract)

    assert validate_full_c6_subject_wheel_transaction(transaction)
    payload = transaction.to_dict()
    assert {
        "output_license_expression_sha256",
        "output_license_contract_sha256",
        "output_metadata_sha256",
        "output_license_member_set_sha256",
        "output_license_payload_set_sha256",
        "output_license_verification_sha256",
    }.issubset(payload)
    serialized = json.dumps(payload, sort_keys=True)
    assert "MIT" not in serialized
    assert "LICENSE" not in serialized
    assert "license payload" not in serialized
    assert str(tmp_path) not in serialized

    _write_wheel(path, _licensed_payloads(license_payload=b"tampered license\n"))

    assert not validate_full_c6_subject_wheel_transaction(transaction)


def test_capture_seal_detects_private_metadata_payload_replacement(tmp_path: Path) -> None:
    path = tmp_path / "subject-0.1.0-cp311-cp311-test.whl"
    _write_wheel(path, _licensed_payloads())
    transaction = _capture(path, output_license_contract=_output_license_contract())

    object.__setattr__(transaction, "_output_metadata_payload", b"forged metadata")

    assert not validate_full_c6_subject_wheel_transaction(transaction)


@pytest.mark.parametrize("failure", ("metadata", "missing-license"))
def test_capture_rejects_incomplete_output_license_material(
    tmp_path: Path,
    failure: str,
) -> None:
    path = tmp_path / "subject-0.1.0-cp311-cp311-test.whl"
    payloads = _licensed_payloads()
    if failure == "metadata":
        payloads[f"{DIST_INFO}/METADATA"] = payloads[f"{DIST_INFO}/METADATA"].replace(
            b"License-Expression: MIT\n",
            b"",
        )
    else:
        del payloads[f"{DIST_INFO}/licenses/LICENSE"]
    _write_wheel(path, payloads)
    subject, entries = _expected(path)

    with pytest.raises(FullC6SubjectWheelError, match="captured exactly"):
        capture_full_c6_subject_wheel(
            path,
            expected_subject=subject,
            expected_wheel_entries=entries,
            external_contract=_contract(),
            native_member_path=NATIVE_NAME,
            expected_native_member_sha256=hashlib.sha256(b"native-extension").hexdigest(),
            expected_native_member_size=len(b"native-extension"),
            output_license_contract=_output_license_contract(),
        )


def test_capture_rejects_caller_inventory_mismatch(tmp_path: Path) -> None:
    path = tmp_path / "subject-0.1.0-cp311-cp311-test.whl"
    _write_wheel(path, _payloads())
    subject, entries = _expected(path)
    with pytest.raises(FullC6SubjectWheelError, match="inventory is stale"):
        capture_full_c6_subject_wheel(
            path,
            expected_subject=subject,
            expected_wheel_entries=entries[:-1],
            external_contract=_contract(),
            native_member_path=NATIVE_NAME,
            expected_native_member_sha256=hashlib.sha256(b"native-extension").hexdigest(),
            expected_native_member_size=len(b"native-extension"),
        )


def test_transaction_validation_fails_after_native_wheel_tamper(tmp_path: Path) -> None:
    path = tmp_path / "subject-0.1.0-cp311-cp311-test.whl"
    _write_wheel(path, _payloads())
    transaction = _capture(path)

    _write_wheel(path, _payloads(native=b"tampered-native"))

    assert not validate_full_c6_subject_wheel_transaction(transaction)


def test_capture_rejects_native_member_tamper(tmp_path: Path) -> None:
    path = tmp_path / "subject-0.1.0-cp311-cp311-test.whl"
    _write_wheel(path, _payloads(native=b"tampered-native"))
    subject, entries = _expected(path)

    with pytest.raises(FullC6SubjectWheelError, match="native member identity is stale"):
        capture_full_c6_subject_wheel(
            path,
            expected_subject=subject,
            expected_wheel_entries=entries,
            external_contract=_contract(),
            native_member_path=NATIVE_NAME,
            expected_native_member_sha256=hashlib.sha256(b"native-extension").hexdigest(),
            expected_native_member_size=len(b"native-extension"),
        )


@pytest.mark.parametrize("alias_kind", ("duplicate", "case", "nfc"))
@pytest.mark.filterwarnings("ignore:Duplicate name.*:UserWarning")
def test_capture_rejects_duplicate_case_and_nfc_aliases(
    tmp_path: Path, alias_kind: str
) -> None:
    path = tmp_path / "subject-0.1.0-cp311-cp311-test.whl"
    extras: tuple[tuple[str, bytes, int], ...]
    if alias_kind == "duplicate":
        extras = (("app/__init__.py", b"duplicate", stat.S_IFREG | 0o644),)
    elif alias_kind == "case":
        extras = (("APP/__INIT__.PY", b"case alias", stat.S_IFREG | 0o644),)
    else:
        extras = (
            ("app/caf\N{LATIN SMALL LETTER E WITH ACUTE}.py", b"nfc", stat.S_IFREG | 0o644),
            ("app/cafe\N{COMBINING ACUTE ACCENT}.py", b"nfd", stat.S_IFREG | 0o644),
        )
    _write_wheel(path, _payloads(), extra_entries=extras)

    with pytest.raises(FullC6SubjectWheelError):
        capture_full_c6_subject_wheel(
            path,
            expected_subject=_subject(path),
            expected_wheel_entries=(),
            external_contract=_contract(),
            native_member_path=NATIVE_NAME,
            expected_native_member_sha256=hashlib.sha256(b"native-extension").hexdigest(),
            expected_native_member_size=len(b"native-extension"),
        )


@pytest.mark.parametrize("special_mode", (stat.S_IFLNK | 0o777, stat.S_IFIFO | 0o644))
def test_capture_rejects_symlink_and_special_zip_entries(
    tmp_path: Path, special_mode: int
) -> None:
    path = tmp_path / "subject-0.1.0-cp311-cp311-test.whl"
    _write_wheel(
        path,
        _payloads(),
        extra_entries=(("app/special", b"target", special_mode),),
    )

    with pytest.raises(FullC6SubjectWheelError):
        capture_full_c6_subject_wheel(
            path,
            expected_subject=_subject(path),
            expected_wheel_entries=(),
            external_contract=_contract(),
            native_member_path=NATIVE_NAME,
            expected_native_member_sha256=hashlib.sha256(b"native-extension").hexdigest(),
            expected_native_member_size=len(b"native-extension"),
        )


@pytest.mark.parametrize("failure", ("hash", "size", "coverage"))
def test_capture_rejects_record_hash_size_and_coverage_errors(
    tmp_path: Path, failure: str
) -> None:
    path = tmp_path / "subject-0.1.0-cp311-cp311-test.whl"
    payloads = _payloads()
    record = _record_bytes(list(payloads.items()))
    app_row = (
        f"app/__init__.py,{_record_hash(payloads['app/__init__.py'])},"
        f"{len(payloads['app/__init__.py'])}\n"
    ).encode()
    if failure == "hash":
        replacement = app_row.replace(_record_hash(payloads["app/__init__.py"]).encode(), b"sha256=bad")
    elif failure == "size":
        replacement = app_row.rsplit(b",", 1)[0] + b",999\n"
    else:
        replacement = b""
    _write_wheel(path, payloads, record_override=record.replace(app_row, replacement))
    subject, entries = _expected(path)

    with pytest.raises(FullC6SubjectWheelError):
        capture_full_c6_subject_wheel(
            path,
            expected_subject=subject,
            expected_wheel_entries=entries,
            external_contract=_contract(),
            native_member_path=NATIVE_NAME,
            expected_native_member_sha256=hashlib.sha256(b"native-extension").hexdigest(),
            expected_native_member_size=len(b"native-extension"),
        )


def test_capture_rejects_external_contract_violation(tmp_path: Path) -> None:
    path = tmp_path / "subject-0.1.0-cp311-cp311-test.whl"
    payloads = _payloads()
    payloads[f"{DIST_INFO}/METADATA"] = payloads[f"{DIST_INFO}/METADATA"].replace(
        b"demo-pkg==1.0.0", b"demo-pkg==2.0.0"
    )
    _write_wheel(path, payloads)
    subject, entries = _expected(path)

    with pytest.raises(FullC6SubjectWheelError):
        capture_full_c6_subject_wheel(
            path,
            expected_subject=subject,
            expected_wheel_entries=entries,
            external_contract=_contract(),
            native_member_path=NATIVE_NAME,
            expected_native_member_sha256=hashlib.sha256(b"native-extension").hexdigest(),
            expected_native_member_size=len(b"native-extension"),
        )


def test_capture_rejects_filesystem_symlink(tmp_path: Path) -> None:
    target_dir = tmp_path / "target"
    target_dir.mkdir()
    target = target_dir / "subject-0.1.0-cp311-cp311-test.whl"
    _write_wheel(target, _payloads())
    path = tmp_path / target.name
    path.symlink_to(target)

    with pytest.raises(FullC6SubjectWheelError, match="captured exactly"):
        capture_full_c6_subject_wheel(
            path,
            expected_subject=_subject(path),
            expected_wheel_entries=inventory_wheel_zip_bytes(path.read_bytes()),
            external_contract=_contract(),
            native_member_path=NATIVE_NAME,
            expected_native_member_sha256=hashlib.sha256(b"native-extension").hexdigest(),
            expected_native_member_size=len(b"native-extension"),
        )


@pytest.mark.parametrize(
    "name",
    ("/absolute.py", "../escape.py", "app\\escape.py", "app/control\x01.py"),
)
def test_capture_rejects_noncanonical_zip_paths(tmp_path: Path, name: str) -> None:
    path = tmp_path / "subject-0.1.0-cp311-cp311-test.whl"
    _write_wheel(
        path,
        _payloads(),
        extra_entries=((name, b"bad", stat.S_IFREG | 0o644),),
    )
    with pytest.raises(FullC6SubjectWheelError):
        capture_full_c6_subject_wheel(
            path,
            expected_subject=_subject(path),
            expected_wheel_entries=(),
            external_contract=_contract(),
            native_member_path=NATIVE_NAME,
            expected_native_member_sha256=hashlib.sha256(b"native-extension").hexdigest(),
            expected_native_member_size=len(b"native-extension"),
        )
