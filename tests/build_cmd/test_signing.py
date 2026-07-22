"""RFC and adversarial tests for Full-C6 detached authorization signatures."""

from __future__ import annotations

import base64
import hashlib

import pytest


_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _recover_x(y: int) -> int:
    xx = (y * y - 1) * pow(_D * y * y + 1, _Q - 2, _Q) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = x * _I % _Q
    if x & 1:
        x = _Q - x
    return x


_BY = (4 * pow(5, _Q - 2, _Q)) % _Q
_B = (_recover_x(_BY), _BY)


def _add(first: tuple[int, int], second: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = first
    x2, y2 = second
    product = _D * x1 * x2 * y1 * y2 % _Q
    return (
        (x1 * y2 + x2 * y1) * pow(1 + product, _Q - 2, _Q) % _Q,
        (y1 * y2 + x1 * x2) * pow(1 - product, _Q - 2, _Q) % _Q,
    )


def _scalar_mult(point: tuple[int, int], scalar: int) -> tuple[int, int]:
    result = (0, 1)
    addend = point
    while scalar:
        if scalar & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        scalar >>= 1
    return result


def _encode_point(point: tuple[int, int]) -> bytes:
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _test_only_sign(seed: bytes, message: bytes) -> tuple[bytes, bytes]:
    expanded = hashlib.sha512(seed).digest()
    scalar_bytes = bytearray(expanded[:32])
    scalar_bytes[0] &= 248
    scalar_bytes[31] &= 63
    scalar_bytes[31] |= 64
    scalar = int.from_bytes(scalar_bytes, "little")
    public_key = _encode_point(_scalar_mult(_B, scalar))
    nonce = int.from_bytes(hashlib.sha512(expanded[32:] + message).digest(), "little") % _L
    encoded_r = _encode_point(_scalar_mult(_B, nonce))
    challenge = (
        int.from_bytes(
            hashlib.sha512(encoded_r + public_key + message).digest(),
            "little",
        )
        % _L
    )
    signature = encoded_r + ((nonce + challenge * scalar) % _L).to_bytes(32, "little")
    return public_key, signature


def _request(**changes: str):
    from rextio.build.signing import FinalAuthorizationRequest

    values = {
        "target_triple": "aarch64-apple-darwin",
        "project_sha256": "11" * 32,
        "artifact_sha256": "22" * 32,
        "evidence_sha256": "33" * 32,
        "reproducibility_sha256": "44" * 32,
        "policy_sha256": "55" * 32,
    }
    values.update(changes)
    return FinalAuthorizationRequest(**values)


def test_low_level_ed25519_verifier_accepts_rfc8032_vector_one() -> None:
    try:
        from rextio.build.signing import verify_ed25519_signature
    except ImportError:
        pytest.fail("the Full-C6 signing module is missing")

    public_key = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    signature = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a"
        "84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46b"
        "d25bf5f0595bbe24655141438e7a100b"
    )

    assert verify_ed25519_signature(public_key, b"", signature) is True
    assert verify_ed25519_signature(public_key, b"tampered", signature) is False


def test_low_level_ed25519_verifier_rejects_noncanonical_or_small_order_values() -> None:
    from rextio.build.signing import verify_ed25519_signature

    public_key = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    signature = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a"
        "84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46b"
        "d25bf5f0595bbe24655141438e7a100b"
    )
    noncanonical_scalar = signature[:32] + _L.to_bytes(32, "little")

    assert verify_ed25519_signature(public_key, b"", noncanonical_scalar) is False
    assert verify_ed25519_signature(b"\x01" + b"\x00" * 31, b"", signature) is False
    assert verify_ed25519_signature(public_key, b"", b"\x00" * 64) is False
    assert verify_ed25519_signature(public_key[:-1], b"", signature) is False


def test_detached_signature_binds_every_request_field_and_pinned_key() -> None:
    from rextio.build.signing import (
        DetachedSignatureEnvelope,
        SIGNED_MESSAGE_PREFIX,
        verify_detached_authorization_signature,
    )

    request = _request()
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc04449c5697b326919703bac031cae7f60")
    public_key, signature = _test_only_sign(
        seed,
        SIGNED_MESSAGE_PREFIX + request.canonical_manifest_bytes,
    )
    key_hash = hashlib.sha256(public_key).hexdigest()
    envelope = DetachedSignatureEnvelope.from_signature(
        public_key_sha256=key_hash,
        manifest_sha256=request.manifest_sha256,
        signature=signature,
    )

    receipt = verify_detached_authorization_signature(
        request=request,
        envelope=envelope,
        public_key=public_key,
        expected_public_key_sha256=key_hash,
    )

    assert receipt.signature_verified is True
    assert receipt.authorizes_distribution is False
    assert receipt.manifest_sha256 == request.manifest_sha256
    assert receipt.public_key_sha256 == key_hash
    assert receipt.target_triple == request.target_triple
    assert receipt.scope == request.scope


@pytest.mark.parametrize(
    "change",
    (
        "target_triple",
        "project_sha256",
        "artifact_sha256",
        "evidence_sha256",
        "reproducibility_sha256",
        "policy_sha256",
    ),
)
def test_detached_signature_cannot_replay_against_another_request(change: str) -> None:
    from rextio.build.signing import (
        DetachedSignatureEnvelope,
        SIGNED_MESSAGE_PREFIX,
        SignatureVerificationError,
        verify_detached_authorization_signature,
    )

    request = _request()
    seed = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
    public_key, signature = _test_only_sign(
        seed,
        SIGNED_MESSAGE_PREFIX + request.canonical_manifest_bytes,
    )
    key_hash = hashlib.sha256(public_key).hexdigest()
    envelope = DetachedSignatureEnvelope.from_signature(
        public_key_sha256=key_hash,
        manifest_sha256=request.manifest_sha256,
        signature=signature,
    )
    replacement = "x86_64-unknown-linux-gnu" if change == "target_triple" else "aa" * 32

    with pytest.raises(SignatureVerificationError, match="manifest"):
        verify_detached_authorization_signature(
            request=_request(**{change: replacement}),
            envelope=envelope,
            public_key=public_key,
            expected_public_key_sha256=key_hash,
        )


def test_detached_signature_rejects_wrong_or_unpinned_public_key() -> None:
    from rextio.build.signing import (
        DetachedSignatureEnvelope,
        SIGNED_MESSAGE_PREFIX,
        SignatureVerificationError,
        verify_detached_authorization_signature,
    )

    request = _request()
    public_key, signature = _test_only_sign(
        b"\x01" * 32,
        SIGNED_MESSAGE_PREFIX + request.canonical_manifest_bytes,
    )
    other_public_key, _ = _test_only_sign(b"\x02" * 32, b"unused")
    key_hash = hashlib.sha256(public_key).hexdigest()
    envelope = DetachedSignatureEnvelope.from_signature(
        public_key_sha256=key_hash,
        manifest_sha256=request.manifest_sha256,
        signature=signature,
    )

    with pytest.raises(SignatureVerificationError, match="pinned"):
        verify_detached_authorization_signature(
            request=request,
            envelope=envelope,
            public_key=public_key,
            expected_public_key_sha256="99" * 32,
        )
    with pytest.raises(SignatureVerificationError, match="public key"):
        verify_detached_authorization_signature(
            request=request,
            envelope=envelope,
            public_key=other_public_key,
            expected_public_key_sha256=key_hash,
        )


def test_envelope_parser_requires_closed_canonical_strict_json() -> None:
    from rextio.build.signing import (
        DetachedSignatureEnvelope,
        SignatureVerificationError,
        parse_detached_signature_envelope,
    )

    signature = bytes(range(64))
    envelope = DetachedSignatureEnvelope.from_signature(
        public_key_sha256="11" * 32,
        manifest_sha256="22" * 32,
        signature=signature,
    )
    encoded = envelope.canonical_json_bytes
    assert parse_detached_signature_envelope(encoded) == envelope

    with pytest.raises(SignatureVerificationError, match="canonical"):
        parse_detached_signature_envelope(encoded.replace(b'"algorithm"', b' "algorithm"', 1))
    with pytest.raises(SignatureVerificationError, match="fields"):
        parse_detached_signature_envelope(encoded[:-1] + b',"private_key":"forbidden"}')
    duplicate = encoded.replace(
        b'"algorithm":"ed25519"',
        b'"algorithm":"ed25519","algorithm":"ed25519"',
    )
    with pytest.raises(SignatureVerificationError, match="duplicate"):
        parse_detached_signature_envelope(duplicate)
    invalid_base64 = encoded.replace(
        base64.b64encode(signature),
        b"!" * len(base64.b64encode(signature)),
    )
    with pytest.raises(SignatureVerificationError, match="base64"):
        parse_detached_signature_envelope(invalid_base64)
    boolean_schema = encoded.replace(b'"schema_version":1', b'"schema_version":true')
    with pytest.raises(SignatureVerificationError, match="metadata"):
        parse_detached_signature_envelope(boolean_schema)


def test_authorization_request_rejects_expanded_scope_or_invalid_digest() -> None:
    from rextio.build.signing import FinalAuthorizationRequest

    with pytest.raises(ValueError, match="scope"):
        FinalAuthorizationRequest(
            target_triple="aarch64-apple-darwin",
            project_sha256="11" * 32,
            artifact_sha256="22" * 32,
            evidence_sha256="33" * 32,
            reproducibility_sha256="44" * 32,
            policy_sha256="55" * 32,
            scope="all-artifacts-everywhere",
        )
    with pytest.raises(ValueError, match="artifact"):
        _request(artifact_sha256="NOT-A-DIGEST")
