"""Signed replay and tamper tests for non-authorizing SourceLock v2."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import pickle
import zipfile
from dataclasses import asdict, dataclass, replace
from pathlib import Path

import pytest

import rextio.source.source_lock_v2 as source_lock_module
from rextio.artifacts import ArtifactProvenance
from rextio.source.authorization import ExternalSourceAuthorization
from rextio.source.external import AuthorityFile, ExternalSourcePlan
from rextio.source.external_analysis import (
    ExternalSourceNativePlan,
    analyze_external_source_snapshot,
)
from rextio.source.models import SourceModule, SourceOrigin
from rextio.source.source_lock_v2 import (
    SOURCE_LOCK_V2_SIGNED_MESSAGE_PREFIX,
    SourceLockV2Manifest,
    SourceLockV2Signature,
    SourceLockV2VerifiedContext,
    build_source_lock_v2_manifest,
    validate_source_lock_v2_verified_context,
    verify_source_lock_v2,
    verify_source_lock_v2_with_context,
)
from rextio.source.wheel_authority import (
    VerifiedSourceWheel,
    verify_source_wheel,
)


_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _recover_x(y: int) -> int:
    value = (y * y - 1) * pow(_D * y * y + 1, _Q - 2, _Q) % _Q
    x = pow(value, (_Q + 3) // 8, _Q)
    if (x * x - value) % _Q != 0:
        x = x * _I % _Q
    return _Q - x if x & 1 else x


_BY = 4 * pow(5, _Q - 2, _Q) % _Q
_B = (_recover_x(_BY), _BY)


def _add(first: tuple[int, int], second: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = first
    x2, y2 = second
    product = _D * x1 * x2 * y1 * y2 % _Q
    return (
        (x1 * y2 + x2 * y1) * pow(1 + product, _Q - 2, _Q) % _Q,
        (y1 * y2 + x1 * x2) * pow(1 - product, _Q - 2, _Q) % _Q,
    )


def _multiply(point: tuple[int, int], scalar: int) -> tuple[int, int]:
    result = (0, 1)
    addend = point
    while scalar:
        if scalar & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        scalar >>= 1
    return result


def _encode(point: tuple[int, int]) -> bytes:
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _sign(seed: bytes, message: bytes) -> tuple[bytes, bytes]:
    expanded = hashlib.sha512(seed).digest()
    scalar_bytes = bytearray(expanded[:32])
    scalar_bytes[0] &= 248
    scalar_bytes[31] &= 63
    scalar_bytes[31] |= 64
    scalar = int.from_bytes(scalar_bytes, "little")
    public_key = _encode(_multiply(_B, scalar))
    nonce = int.from_bytes(hashlib.sha512(expanded[32:] + message).digest(), "little") % _L
    encoded_r = _encode(_multiply(_B, nonce))
    challenge = (
        int.from_bytes(hashlib.sha512(encoded_r + public_key + message).digest(), "little") % _L
    )
    signature = encoded_r + ((nonce + challenge * scalar) % _L).to_bytes(32, "little")
    return public_key, signature


PACKAGE = "demo_pkg"
DIST = "demo-pkg"
VERSION = "1.0.0"
SOURCE_PATH = "distributions/demo-pkg/demo_pkg/__init__.py"
SOURCE = b"def affine(x: int) -> int:\n    return x + 1\n"
DIST_INFO = "demo_pkg-1.0.0.dist-info"
SIGNING_SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc04449c5697b326919703bac031cae7f60")
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
WHEEL_METADATA = (
    b"Wheel-Version: 1.0\nGenerator: rextio-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
)
DIST_METADATA = (
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


def _wheel_bytes(entries: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    return output.getvalue()


def _inputs(
    tmp_path: Path,
) -> tuple[
    ExternalSourcePlan,
    VerifiedSourceWheel,
    tuple[ExternalSourceNativePlan, ...],
    Path,
    str,
]:
    source_sha = hashlib.sha256(SOURCE).hexdigest()
    module = SourceModule(
        module_name=PACKAGE,
        path=SOURCE_PATH,
        is_package_init=True,
        source_origin=SourceOrigin.DISTRIBUTION,
        sha256=source_sha,
        dependency_depth=1,
        distribution=DIST,
        version=VERSION,
        license="MIT",
        provenance=ArtifactProvenance(source_references=(SOURCE_PATH,)),
    )
    source_file = AuthorityFile(
        path=SOURCE_PATH,
        sha256=source_sha,
        size=len(SOURCE),
        role="source-module",
        module_name=PACKAGE,
    )
    entries = {
        "demo_pkg/__init__.py": SOURCE,
        f"{DIST_INFO}/METADATA": DIST_METADATA,
        f"{DIST_INFO}/WHEEL": WHEEL_METADATA,
        f"{DIST_INFO}/licenses/LICENSE": LICENSE,
    }
    entries[f"{DIST_INFO}/RECORD"] = _record(entries)
    metadata_specs = (
        (f"{DIST_INFO}/METADATA", "metadata", DIST_METADATA),
        (f"{DIST_INFO}/RECORD", "record", entries[f"{DIST_INFO}/RECORD"]),
        (f"{DIST_INFO}/WHEEL", "wheel", WHEEL_METADATA),
        (f"{DIST_INFO}/licenses/LICENSE", "license-file", LICENSE),
    )
    metadata_files = tuple(
        sorted(
            (
                AuthorityFile(
                    path=f"distributions/{DIST}/{path}",
                    sha256=hashlib.sha256(data).hexdigest(),
                    size=len(data),
                    role=role,
                )
                for path, role, data in metadata_specs
            ),
            key=lambda item: item.path,
        )
    )
    plan = ExternalSourcePlan(
        package=PACKAGE,
        distribution=DIST,
        requested_version=VERSION,
        installed_version=VERSION,
        max_depth=1,
        status="preview-ready",
        license="MIT",
        modules=(module,),
        candidate_functions=(f"{PACKAGE}.affine",),
        source_files=(source_file,),
        metadata_files=metadata_files,
    )
    wheel_path = tmp_path / "demo_pkg-1.0.0-py3-none-any.whl"
    wheel_payload = _wheel_bytes(entries)
    wheel_path.write_bytes(wheel_payload)
    wheel_sha256 = hashlib.sha256(wheel_payload).hexdigest()
    wheel = verify_source_wheel(
        wheel_path,
        expected_sha256=wheel_sha256,
        plan=plan,
    )
    analyses = tuple(analyze_external_source_snapshot(snapshot) for snapshot in wheel.snapshots)
    return plan, wheel, analyses, wheel_path, wheel_sha256


@dataclass(frozen=True)
class _SignedFixture:
    plan: ExternalSourcePlan
    wheel: VerifiedSourceWheel
    analyses: tuple[ExternalSourceNativePlan, ...]
    wheel_path: Path
    wheel_sha256: str
    key_hash: str
    manifest: SourceLockV2Manifest
    lock_path: Path
    signature_path: Path
    key_path: Path


def _write_signed(tmp_path: Path, *, wrong_prefix: bool = False) -> _SignedFixture:
    tmp_path.mkdir(parents=True, exist_ok=True)
    plan, wheel, analyses, wheel_path, wheel_sha256 = _inputs(tmp_path)
    provisional_key, _ = _sign(SIGNING_SEED, b"provisional")
    key_hash = hashlib.sha256(provisional_key).hexdigest()
    manifest = build_source_lock_v2_manifest(
        plan=plan,
        wheel=wheel,
        analyses=analyses,
        owner="Acme Engineering",
        trusted_public_key_sha256=key_hash,
    )
    prefix = (
        b"REXTIO-FULL-C6-ED25519-V1\0" if wrong_prefix else SOURCE_LOCK_V2_SIGNED_MESSAGE_PREFIX
    )
    public_key, signature = _sign(
        SIGNING_SEED,
        prefix + manifest.canonical_json_bytes,
    )
    assert hashlib.sha256(public_key).hexdigest() == key_hash
    envelope = SourceLockV2Signature.from_signature(
        public_key_sha256=key_hash,
        manifest_sha256=manifest.manifest_sha256,
        signature=signature,
    )
    lock_path = tmp_path / "rextio.external-source.lock.v2.json"
    signature_path = tmp_path / "rextio.external-source.lock.v2.sig.json"
    key_path = tmp_path / "source-lock-owner.ed25519.pub"
    lock_path.write_bytes(manifest.canonical_json_bytes)
    signature_path.write_bytes(envelope.canonical_json_bytes)
    key_path.write_bytes(public_key)
    return _SignedFixture(
        plan=plan,
        wheel=wheel,
        analyses=analyses,
        wheel_path=wheel_path,
        wheel_sha256=wheel_sha256,
        key_hash=key_hash,
        manifest=manifest,
        lock_path=lock_path,
        signature_path=signature_path,
        key_path=key_path,
    )


def _verify(fixture: _SignedFixture):
    return verify_source_lock_v2(
        lock_path=fixture.lock_path,
        signature_path=fixture.signature_path,
        public_key_path=fixture.key_path,
        wheel_path=fixture.wheel_path,
        expected_wheel_sha256=fixture.wheel_sha256,
        expected_public_key_sha256=fixture.key_hash,
        plan=fixture.plan,
    )


def _verify_context(fixture: _SignedFixture):
    return verify_source_lock_v2_with_context(
        lock_path=fixture.lock_path,
        signature_path=fixture.signature_path,
        public_key_path=fixture.key_path,
        wheel_path=fixture.wheel_path,
        expected_wheel_sha256=fixture.wheel_sha256,
        expected_public_key_sha256=fixture.key_hash,
        plan=fixture.plan,
    )


def test_exact_signed_lock_admits_only_prebuild_and_serializes_digests(tmp_path: Path) -> None:
    fixture = _write_signed(tmp_path)
    result = _verify(fixture)

    assert result.status == "admitted"
    assert result.prebuild_admitted is True
    assert result.authorizes_build is False
    assert result.authorizes_distribution is False
    rendered = repr(result.to_dict())
    assert SOURCE.decode().strip() not in rendered
    assert str(tmp_path) not in rendered
    assert "signature" not in result.to_dict()
    manifest_bytes = fixture.manifest.canonical_json_bytes
    assert SOURCE not in manifest_bytes
    assert str(tmp_path).encode() not in manifest_bytes
    assert fixture.key_path.read_bytes() not in manifest_bytes
    assert fixture.signature_path.read_bytes() not in manifest_bytes
    license_document = fixture.manifest.to_dict()["license"]
    assert isinstance(license_document, dict)
    assert license_document["observed"] == "MIT"
    assert license_document["independent_detection"] == ("pending-final-full-c6-detector")
    assert "detected" not in license_document


def test_analyzer_shaped_legacy_authorization_is_validated_then_stripped(
    tmp_path: Path,
) -> None:
    fixture = _write_signed(tmp_path)
    legacy = ExternalSourceAuthorization(
        status="verified",
        snapshot_sha256=fixture.plan.plan_snapshot_sha256(),
        attestor="Acme Engineering",
        attestor_kind="organization",
        license_observed="MIT",
        license_attestation_verified=True,
        source_inventory_verified=True,
        provenance_verified=True,
    )
    analyzer_shaped = replace(fixture, plan=replace(fixture.plan, authorization=legacy))
    verification = _verify_context(analyzer_shaped)

    assert verification.admission.status == "admitted"
    assert verification.context is not None
    assert verification.context.plan.authorization is None
    assert "authorization" not in verification.context.to_dict()

    forged_verified = replace(
        analyzer_shaped,
        plan=replace(
            fixture.plan,
            authorization=ExternalSourceAuthorization(status="verified"),
        ),
    )
    assert _verify_context(forged_verified).admission.status == "rejected"

    inert_failure = replace(
        fixture,
        plan=replace(
            fixture.plan,
            authorization=ExternalSourceAuthorization(
                status="invalid",
                reason="legacy lock was invalid",
                license_attestation_verified=True,
            ),
        ),
    )
    inert_verification = _verify_context(inert_failure)
    assert inert_verification.admission.status == "admitted"
    assert inert_verification.context is not None
    assert inert_verification.context.plan.authorization is None


def test_manifest_tamper_and_replay_against_changed_plan_are_rejected(tmp_path: Path) -> None:
    fixture = _write_signed(tmp_path)
    document = fixture.manifest.to_dict()
    document["plan_snapshot_sha256"] = "0" * 64
    fixture.lock_path.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":")), encoding="utf-8"
    )
    assert _verify(fixture).status == "rejected"

    fresh = _write_signed(tmp_path)
    replay_plan = replace(fresh.plan, candidate_functions=(f"{PACKAGE}.other",))
    replay = verify_source_lock_v2(
        lock_path=fresh.lock_path,
        signature_path=fresh.signature_path,
        public_key_path=fresh.key_path,
        wheel_path=fresh.wheel_path,
        expected_wheel_sha256=fresh.wheel_sha256,
        expected_public_key_sha256=fresh.key_hash,
        plan=replay_plan,
    )
    assert replay.status == "rejected"


def test_signature_key_hash_and_domain_replay_are_rejected(tmp_path: Path) -> None:
    fixture = _write_signed(tmp_path)
    assert (
        verify_source_lock_v2(
            lock_path=fixture.lock_path,
            signature_path=fixture.signature_path,
            public_key_path=fixture.key_path,
            wheel_path=fixture.wheel_path,
            expected_wheel_sha256=fixture.wheel_sha256,
            expected_public_key_sha256="0" * 64,
            plan=fixture.plan,
        ).status
        == "rejected"
    )

    signature_document = json.loads(fixture.signature_path.read_text())
    signature_document["signature"] = "A" + signature_document["signature"][1:]
    fixture.signature_path.write_text(
        json.dumps(signature_document, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    assert _verify(fixture).status == "rejected"

    wrong_domain = _write_signed(tmp_path, wrong_prefix=True)
    assert _verify(wrong_domain).status == "rejected"


def test_noncanonical_duplicate_and_false_owner_decision_are_rejected(tmp_path: Path) -> None:
    fixture = _write_signed(tmp_path)
    document = fixture.manifest.to_dict()
    fixture.lock_path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    assert _verify(fixture).status == "rejected"

    fixture = _write_signed(tmp_path)
    raw = fixture.lock_path.read_text()
    fixture.lock_path.write_text(raw[:-1] + ',"kind":"duplicate"}', encoding="utf-8")
    assert _verify(fixture).status == "rejected"

    fixture = _write_signed(tmp_path)
    document = fixture.manifest.to_dict()
    owner_decision = document["owner_decision"]
    assert isinstance(owner_decision, dict)
    owner_decision["redistribute"] = False
    fixture.lock_path.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":")), encoding="utf-8"
    )
    assert _verify(fixture).status == "rejected"


def test_verifier_freshly_rechecks_wheel_plan_and_analysis(tmp_path: Path) -> None:
    fixture = _write_signed(tmp_path)
    assert _verify(replace(fixture, wheel_sha256="0" * 64)).status == "rejected"

    changed_wheel = _write_signed(tmp_path / "changed-wheel")
    changed_wheel.wheel_path.write_bytes(changed_wheel.wheel_path.read_bytes() + b"changed")
    assert _verify(changed_wheel).status == "rejected"

    changed_plan = _write_signed(tmp_path / "changed-plan")
    object.__setattr__(changed_plan.plan.source_files[0], "size", True)
    assert _verify(changed_plan).status == "rejected"

    forged_analysis = _write_signed(tmp_path / "forged-analysis")
    object.__setattr__(forged_analysis.analyses[0], "semantic_sha256", "0" * 64)
    forged_manifest = build_source_lock_v2_manifest(
        plan=forged_analysis.plan,
        wheel=forged_analysis.wheel,
        analyses=forged_analysis.analyses,
        owner="Acme Engineering",
        trusted_public_key_sha256=forged_analysis.key_hash,
    )
    public_key, signature = _sign(
        SIGNING_SEED,
        SOURCE_LOCK_V2_SIGNED_MESSAGE_PREFIX + forged_manifest.canonical_json_bytes,
    )
    envelope = SourceLockV2Signature.from_signature(
        public_key_sha256=forged_analysis.key_hash,
        manifest_sha256=forged_manifest.manifest_sha256,
        signature=signature,
    )
    forged_analysis.lock_path.write_bytes(forged_manifest.canonical_json_bytes)
    forged_analysis.signature_path.write_bytes(envelope.canonical_json_bytes)
    assert public_key == forged_analysis.key_path.read_bytes()
    assert _verify(forged_analysis).status == "rejected"


def test_verified_context_reuses_exact_objects_and_final_revalidation_catches_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _write_signed(tmp_path / "stable")
    verification = _verify_context(fixture)
    assert verification.admission.status == "admitted"
    assert verification.context is not None
    assert verification.context.manifest == fixture.manifest
    assert verification.context.wheel.archive.sha256 == fixture.wheel_sha256
    assert verification.context.analyses[0].snapshot.source_bytes == SOURCE
    sanitized = repr(verification.to_dict())
    assert SOURCE.decode().strip() not in sanitized
    assert str(tmp_path) not in sanitized
    fixture.wheel_path.write_bytes(b"replaced after admission")
    assert verification.context.analyses[0].snapshot.source_bytes == SOURCE

    raced = _write_signed(tmp_path / "raced")
    original = source_lock_module.verify_source_wheel
    call_count = 0

    def swap_after_first_verification(
        wheel_path: str | Path,
        *,
        expected_sha256: str,
        plan: ExternalSourcePlan,
    ) -> VerifiedSourceWheel:
        nonlocal call_count
        result = original(
            wheel_path,
            expected_sha256=expected_sha256,
            plan=plan,
        )
        call_count += 1
        if call_count == 1:
            raced.wheel_path.write_bytes(raced.wheel_path.read_bytes() + b"swapped")
        return result

    monkeypatch.setattr(
        source_lock_module,
        "verify_source_wheel",
        swap_after_first_verification,
    )
    raced_verification = _verify_context(raced)
    assert raced_verification.admission.status == "rejected"
    assert raced_verification.context is None


def test_verified_context_is_same_transaction_sealed_and_nonserializing(
    tmp_path: Path,
) -> None:
    fixture = _write_signed(tmp_path)
    verification = _verify_context(fixture)
    context = verification.context
    assert context is not None
    assert validate_source_lock_v2_verified_context(context) is True

    with pytest.raises(TypeError, match="verification transaction"):
        SourceLockV2VerifiedContext(
            admission=context.admission,
            plan=context.plan,
            wheel=context.wheel,
            analyses=context.analyses,
            manifest=context.manifest,
        )
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(context)
    with pytest.raises(TypeError, match="cannot be copied"):
        asdict(verification)

    object.__setattr__(context, "manifest", replace(context.manifest, owner="Other Owner"))
    assert validate_source_lock_v2_verified_context(context) is False


def test_symlinked_lock_signature_or_key_is_rejected(tmp_path: Path) -> None:
    for field_name in ("lock_path", "signature_path", "key_path"):
        case = tmp_path / f"case-{field_name}"
        case.mkdir()
        fixture = _write_signed(case)
        original = getattr(fixture, field_name)
        linked = case / f"linked-{original.name}"
        linked.symlink_to(original)
        if field_name == "lock_path":
            changed = replace(fixture, lock_path=linked)
        elif field_name == "signature_path":
            changed = replace(fixture, signature_path=linked)
        else:
            changed = replace(fixture, key_path=linked)
        assert _verify(changed).status == "rejected"
