"""Strict, dependency-free Ed25519 verification for bounded Full C6.

This module never accepts, derives, stores, or uses private keys.  It verifies
one canonical final-authorization request against a detached signature and a
separately supplied, SHA-256-pinned raw Ed25519 public key.  The returned
receipt proves only that signature check; policy integration remains a
separate hard gate and the receipt cannot authorize distribution by itself.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import re

from rextio.artifacts.contract_dialects import (
    AUTHORIZATION_REQUEST,
    AUTHORIZATION_SIGNATURE,
    AUTHORIZATION_SIGNED_MESSAGE,
    AUTHORIZATION_VERIFICATION_RECEIPT,
    CURRENT,
    LEGACY_0_1_7,
    ArtifactContractDialect,
    resolve_artifact_contract_dialect,
)

_CURRENT_REQUEST = CURRENT.identity(AUTHORIZATION_REQUEST)
_CURRENT_SIGNATURE = CURRENT.identity(AUTHORIZATION_SIGNATURE)
FINAL_AUTHORIZATION_REQUEST_KIND = _CURRENT_REQUEST.kind
FINAL_AUTHORIZATION_REQUEST_SCHEMA = _CURRENT_REQUEST.schema_version
FINAL_AUTHORIZATION_DOMAIN = _CURRENT_REQUEST.domain
FINAL_AUTHORIZATION_SCOPE = "host-extension-wheel-cpython-external-source-depth1-plugin-free-v1"
DETACHED_SIGNATURE_KIND = _CURRENT_SIGNATURE.kind
DETACHED_SIGNATURE_SCHEMA = _CURRENT_SIGNATURE.schema_version
DETACHED_SIGNATURE_ALGORITHM = "ed25519"
DETACHED_SIGNATURE_DOMAIN = _CURRENT_SIGNATURE.domain
SIGNATURE_RECEIPT_DOMAIN = CURRENT.string_value(AUTHORIZATION_VERIFICATION_RECEIPT)
SIGNED_MESSAGE_PREFIX = CURRENT.byte_value(AUTHORIZATION_SIGNED_MESSAGE)
MAX_SIGNATURE_ENVELOPE_BYTES = 16 * 1024
MAX_AUTHORIZATION_REQUEST_BYTES = 16 * 1024

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TARGET_TRIPLES = frozenset({"aarch64-apple-darwin", "x86_64-unknown-linux-gnu"})
_ENVELOPE_FIELDS = frozenset(
    {
        "kind",
        "schema_version",
        "algorithm",
        "domain",
        "public_key_sha256",
        "manifest_sha256",
        "signature",
    }
)

# RFC 8032 / Ed25519 constants.  Extended Edwards coordinates keep verification
# reasonably small without relying on a native crypto dependency.  This is a
# verifier only; production signing must happen in an external trusted system.
_FIELD_Q = 2**255 - 19
_GROUP_L = 2**252 + 27742317777372353535851937790883648493
_CURVE_D = (-121665 * pow(121666, _FIELD_Q - 2, _FIELD_Q)) % _FIELD_Q
_SQRT_M1 = pow(2, (_FIELD_Q - 1) // 4, _FIELD_Q)
_BASE_Y = (4 * pow(5, _FIELD_Q - 2, _FIELD_Q)) % _FIELD_Q


class SignatureVerificationError(RuntimeError):
    """A detached authorization signature or its envelope is invalid."""


@dataclass(frozen=True, slots=True)
class FinalAuthorizationRequest:
    """Canonical manifest binding every input to one bounded authorization."""

    target_triple: str
    project_sha256: str
    artifact_sha256: str
    evidence_sha256: str
    reproducibility_sha256: str
    policy_sha256: str
    scope: str = FINAL_AUTHORIZATION_SCOPE
    kind: str = field(default=FINAL_AUTHORIZATION_REQUEST_KIND, init=False)
    schema_version: int = field(default=FINAL_AUTHORIZATION_REQUEST_SCHEMA, init=False)
    domain: str = field(default=FINAL_AUTHORIZATION_DOMAIN, init=False)
    _artifact_contract_dialect: str = field(
        default=CURRENT.name,
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if type(self.target_triple) is not str or self.target_triple not in _TARGET_TRIPLES:
            raise ValueError("final authorization target triple is outside the frozen scope")
        if self.scope != FINAL_AUTHORIZATION_SCOPE:
            raise ValueError("final authorization scope is outside the frozen scope")
        for name in (
            "project_sha256",
            "artifact_sha256",
            "evidence_sha256",
            "reproducibility_sha256",
            "policy_sha256",
        ):
            _require_sha256(getattr(self, name), name.removesuffix("_sha256").replace("_", " "))

    def to_dict(self) -> dict[str, object]:
        """Return the fixed closed manifest shape."""
        return {
            "kind": self.kind,
            "schema_version": self.schema_version,
            "domain": self.domain,
            "scope": self.scope,
            "target_triple": self.target_triple,
            "project_sha256": self.project_sha256,
            "artifact_sha256": self.artifact_sha256,
            "evidence_sha256": self.evidence_sha256,
            "reproducibility_sha256": self.reproducibility_sha256,
            "policy_sha256": self.policy_sha256,
        }

    @property
    def canonical_manifest_bytes(self) -> bytes:
        """Return the only byte representation accepted for signing."""
        return _canonical_json(self.to_dict())

    @property
    def manifest_sha256(self) -> str:
        """Return the SHA-256 binding of the canonical manifest bytes."""
        return hashlib.sha256(self.canonical_manifest_bytes).hexdigest()


@dataclass(frozen=True, slots=True)
class DetachedSignatureEnvelope:
    """Closed canonical envelope containing one raw Ed25519 signature."""

    public_key_sha256: str
    manifest_sha256: str
    signature: str
    kind: str = field(default=DETACHED_SIGNATURE_KIND, init=False)
    schema_version: int = field(default=DETACHED_SIGNATURE_SCHEMA, init=False)
    algorithm: str = field(default=DETACHED_SIGNATURE_ALGORITHM, init=False)
    domain: str = field(default=DETACHED_SIGNATURE_DOMAIN, init=False)
    _artifact_contract_dialect: str = field(
        default=CURRENT.name,
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        _require_sha256(self.public_key_sha256, "public key")
        _require_sha256(self.manifest_sha256, "manifest")
        _decode_signature(self.signature)

    @classmethod
    def from_signature(
        cls,
        *,
        public_key_sha256: str,
        manifest_sha256: str,
        signature: bytes,
    ) -> DetachedSignatureEnvelope:
        """Create an envelope from an externally produced raw signature."""
        if type(signature) is not bytes or len(signature) != 64:
            raise ValueError("Ed25519 signature must be exactly 64 raw bytes")
        return cls(
            public_key_sha256=public_key_sha256,
            manifest_sha256=manifest_sha256,
            signature=base64.b64encode(signature).decode("ascii"),
        )

    @property
    def signature_bytes(self) -> bytes:
        """Decode and return the exact 64-byte detached signature."""
        return _decode_signature(self.signature)

    def to_dict(self) -> dict[str, object]:
        """Return the closed signature envelope shape."""
        return {
            "kind": self.kind,
            "schema_version": self.schema_version,
            "algorithm": self.algorithm,
            "domain": self.domain,
            "public_key_sha256": self.public_key_sha256,
            "manifest_sha256": self.manifest_sha256,
            "signature": self.signature,
        }

    @property
    def canonical_json_bytes(self) -> bytes:
        """Return the only accepted serialized envelope representation."""
        return _canonical_json(self.to_dict())


@dataclass(frozen=True, slots=True)
class SignatureVerificationReceipt:
    """Non-authorizing receipt for one successfully verified signature."""

    target_triple: str
    scope: str
    manifest_sha256: str
    public_key_sha256: str
    signature_sha256: str
    domain: str = SIGNATURE_RECEIPT_DOMAIN
    signature_verified: bool = True
    authorizes_distribution: bool = False

    def __post_init__(self) -> None:
        if self.domain not in {
            CURRENT.string_value(AUTHORIZATION_VERIFICATION_RECEIPT),
            LEGACY_0_1_7.string_value(AUTHORIZATION_VERIFICATION_RECEIPT),
        }:
            raise ValueError("signature receipt domain is invalid")
        if self.target_triple not in _TARGET_TRIPLES or self.scope != FINAL_AUTHORIZATION_SCOPE:
            raise ValueError("signature receipt scope is invalid")
        for value, label in (
            (self.manifest_sha256, "manifest"),
            (self.public_key_sha256, "public key"),
            (self.signature_sha256, "signature"),
        ):
            _require_sha256(value, label)
        if self.signature_verified is not True:
            raise ValueError("signature receipt must represent successful verification")
        if self.authorizes_distribution is not False:
            raise ValueError("signature receipt cannot authorize distribution")

    @property
    def digest(self) -> str:
        """Return the semantic digest of this non-authorizing receipt."""
        return hashlib.sha256(_canonical_json(self._payload())).hexdigest()

    def _payload(self) -> dict[str, object]:
        return {
            "domain": self.domain,
            "target_triple": self.target_triple,
            "scope": self.scope,
            "manifest_sha256": self.manifest_sha256,
            "public_key_sha256": self.public_key_sha256,
            "signature_sha256": self.signature_sha256,
            "signature_verified": True,
            "authorizes_distribution": False,
        }

    def to_dict(self) -> dict[str, object]:
        """Return the canonical receipt plus its semantic digest."""
        return {**self._payload(), "digest": self.digest}


def parse_final_authorization_request(
    value: bytes | str,
) -> FinalAuthorizationRequest:
    """Parse an exact current or 0.1.7 authorization request."""
    raw = _bounded_json_bytes(
        value,
        limit=MAX_AUTHORIZATION_REQUEST_BYTES,
        label="authorization request",
    )
    document = _strict_json_document(raw, label="authorization request")
    fields = {
        "kind",
        "schema_version",
        "domain",
        "scope",
        "target_triple",
        "project_sha256",
        "artifact_sha256",
        "evidence_sha256",
        "reproducibility_sha256",
        "policy_sha256",
    }
    if set(document) != fields:
        raise SignatureVerificationError(
            "authorization request fields are not the closed schema"
        )
    try:
        dialect = resolve_artifact_contract_dialect(
            AUTHORIZATION_REQUEST,
            kind=document["kind"],
            schema_version=document["schema_version"],
            domain=document["domain"],
        )
        request = FinalAuthorizationRequest(
            target_triple=_require_string(
                document["target_triple"],
                "target triple",
            ),
            project_sha256=_require_sha256(document["project_sha256"], "project"),
            artifact_sha256=_require_sha256(document["artifact_sha256"], "artifact"),
            evidence_sha256=_require_sha256(document["evidence_sha256"], "evidence"),
            reproducibility_sha256=_require_sha256(
                document["reproducibility_sha256"],
                "reproducibility",
            ),
            policy_sha256=_require_sha256(document["policy_sha256"], "policy"),
            scope=_require_string(document["scope"], "scope"),
        )
    except (TypeError, ValueError) as exc:
        raise SignatureVerificationError(str(exc)) from exc
    _apply_dialect_identity(request, dialect, AUTHORIZATION_REQUEST)
    if not hmac.compare_digest(raw, request.canonical_manifest_bytes):
        raise SignatureVerificationError("authorization request is not canonical JSON")
    return request


def parse_detached_signature_envelope(
    value: bytes | str,
) -> DetachedSignatureEnvelope:
    """Parse only the exact canonical JSON representation of an envelope."""
    raw = _bounded_json_bytes(
        value,
        limit=MAX_SIGNATURE_ENVELOPE_BYTES,
        label="signature envelope",
    )
    document = _strict_json_document(raw, label="signature envelope")
    if type(document) is not dict or set(document) != _ENVELOPE_FIELDS:
        raise SignatureVerificationError("signature envelope fields are not the closed schema")
    if document.get("algorithm") != DETACHED_SIGNATURE_ALGORITHM:
        raise SignatureVerificationError("signature envelope metadata is invalid")
    try:
        dialect = resolve_artifact_contract_dialect(
            AUTHORIZATION_SIGNATURE,
            kind=document["kind"],
            schema_version=document["schema_version"],
            domain=document["domain"],
        )
    except ValueError as exc:
        raise SignatureVerificationError(
            "signature envelope metadata is invalid"
        ) from exc
    try:
        envelope = DetachedSignatureEnvelope(
            public_key_sha256=_require_sha256(
                document["public_key_sha256"],
                "public key",
            ),
            manifest_sha256=_require_sha256(
                document["manifest_sha256"],
                "manifest",
            ),
            signature=_require_string(document["signature"], "signature"),
        )
    except (TypeError, ValueError) as exc:
        raise SignatureVerificationError(str(exc)) from exc
    _apply_dialect_identity(envelope, dialect, AUTHORIZATION_SIGNATURE)
    if not hmac.compare_digest(raw, envelope.canonical_json_bytes):
        raise SignatureVerificationError("signature envelope is not canonical JSON")
    return envelope


def verify_detached_authorization_signature(
    *,
    request: FinalAuthorizationRequest,
    envelope: DetachedSignatureEnvelope,
    public_key: bytes,
    expected_public_key_sha256: str,
) -> SignatureVerificationReceipt:
    """Verify the pinned key, exact manifest binding, and Ed25519 signature."""
    if type(request) is not FinalAuthorizationRequest:
        raise SignatureVerificationError("final authorization request has an invalid type")
    if type(envelope) is not DetachedSignatureEnvelope:
        raise SignatureVerificationError("detached signature envelope has an invalid type")
    try:
        request_dialect = _object_dialect(request, AUTHORIZATION_REQUEST)
        envelope_dialect = _object_dialect(envelope, AUTHORIZATION_SIGNATURE)
    except ValueError as exc:
        raise SignatureVerificationError(str(exc)) from exc
    if request_dialect is not envelope_dialect:
        raise SignatureVerificationError(
            "authorization request and signature use different contract dialects"
        )
    if type(public_key) is not bytes or len(public_key) != 32:
        raise SignatureVerificationError("Ed25519 public key must be exactly 32 raw bytes")
    try:
        _require_sha256(expected_public_key_sha256, "pinned public key")
    except ValueError as exc:
        raise SignatureVerificationError(str(exc)) from exc

    actual_key_hash = hashlib.sha256(public_key).hexdigest()
    if not hmac.compare_digest(actual_key_hash, expected_public_key_sha256):
        raise SignatureVerificationError("public key does not match the pinned digest")
    if not hmac.compare_digest(envelope.public_key_sha256, expected_public_key_sha256):
        raise SignatureVerificationError("signature envelope public key is not the pinned key")
    if not hmac.compare_digest(envelope.manifest_sha256, request.manifest_sha256):
        raise SignatureVerificationError("signature envelope manifest does not match the request")

    signature = envelope.signature_bytes
    message = (
        request_dialect.byte_value(AUTHORIZATION_SIGNED_MESSAGE)
        + request.canonical_manifest_bytes
    )
    if not verify_ed25519_signature(public_key, message, signature):
        raise SignatureVerificationError("Ed25519 signature verification failed")
    return SignatureVerificationReceipt(
        target_triple=request.target_triple,
        scope=request.scope,
        manifest_sha256=request.manifest_sha256,
        public_key_sha256=actual_key_hash,
        signature_sha256=hashlib.sha256(signature).hexdigest(),
        domain=request_dialect.string_value(AUTHORIZATION_VERIFICATION_RECEIPT),
    )


def _bounded_json_bytes(value: bytes | str, *, limit: int, label: str) -> bytes:
    if type(value) is str:
        raw = value.encode("utf-8")
    elif type(value) is bytes:
        raw = value
    else:
        raise SignatureVerificationError(f"{label} must be UTF-8 JSON bytes")
    if not raw or len(raw) > limit:
        raise SignatureVerificationError(f"{label} exceeds the byte bound")
    return raw


def _strict_json_document(raw: bytes, *, label: str) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise SignatureVerificationError(f"{label} contains a duplicate field")
            result[key] = item
        return result

    def reject_constant(_value: str) -> object:
        raise SignatureVerificationError(f"{label} contains invalid JSON")

    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except SignatureVerificationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise SignatureVerificationError(f"{label} is not valid JSON") from exc
    if type(document) is not dict:
        raise SignatureVerificationError(f"{label} root is invalid")
    return document


def _apply_dialect_identity(
    value: FinalAuthorizationRequest | DetachedSignatureEnvelope,
    dialect: ArtifactContractDialect,
    artifact: str,
) -> None:
    identity = dialect.identity(artifact)
    object.__setattr__(value, "kind", identity.kind)
    object.__setattr__(value, "schema_version", identity.schema_version)
    object.__setattr__(value, "domain", identity.domain)
    object.__setattr__(value, "_artifact_contract_dialect", dialect.name)


def _object_dialect(
    value: FinalAuthorizationRequest | DetachedSignatureEnvelope,
    artifact: str,
) -> ArtifactContractDialect:
    dialect = resolve_artifact_contract_dialect(
        artifact,
        kind=value.kind,
        schema_version=value.schema_version,
        domain=value.domain,
    )
    if value._artifact_contract_dialect != dialect.name:
        raise ValueError("artifact contract dialect marker is inconsistent")
    return dialect


Point = tuple[int, int, int, int]


def verify_ed25519_signature(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Return whether ``signature`` is strict RFC-8032 Ed25519 for ``message``.

    Decoded public-key and R points must be canonical members of the prime
    order subgroup, and S must be a canonical scalar.  These checks reject the
    small-order and mixed-order variants that permissive verifiers may accept.
    """
    if type(public_key) is not bytes or type(message) is not bytes or type(signature) is not bytes:
        return False
    if len(public_key) != 32 or len(signature) != 64:
        return False
    encoded_r = signature[:32]
    scalar = int.from_bytes(signature[32:], "little")
    if scalar >= _GROUP_L:
        return False
    public_point = _decode_point(public_key)
    r_point = _decode_point(encoded_r)
    if public_point is None or r_point is None:
        return False
    if not _is_prime_order_nonidentity(public_point) or not _is_prime_order_nonidentity(r_point):
        return False

    challenge = (
        int.from_bytes(
            hashlib.sha512(encoded_r + public_key + message).digest(),
            "little",
        )
        % _GROUP_L
    )
    left = _scalar_multiply(_base_point(), scalar)
    right = _point_add(r_point, _scalar_multiply(public_point, challenge))
    return hmac.compare_digest(_encode_point(left), _encode_point(right))


def _base_point() -> Point:
    x = _recover_x(_BASE_Y, 0)
    if x is None:  # pragma: no cover - fixed RFC constant
        raise RuntimeError("Ed25519 base point is invalid")
    return (x, _BASE_Y, 1, x * _BASE_Y % _FIELD_Q)


def _decode_point(encoded: bytes) -> Point | None:
    if len(encoded) != 32:
        return None
    raw = int.from_bytes(encoded, "little")
    sign = raw >> 255
    y = raw & ((1 << 255) - 1)
    if y >= _FIELD_Q:
        return None
    x = _recover_x(y, sign)
    if x is None or (x == 0 and sign == 1):
        return None
    point = (x, y, 1, x * y % _FIELD_Q)
    if not _is_on_curve(point):
        return None
    return point


def _recover_x(y: int, sign: int) -> int | None:
    y_squared = y * y % _FIELD_Q
    denominator = (_CURVE_D * y_squared + 1) % _FIELD_Q
    if denominator == 0:
        return None
    x_squared = (y_squared - 1) * pow(denominator, _FIELD_Q - 2, _FIELD_Q) % _FIELD_Q
    x = pow(x_squared, (_FIELD_Q + 3) // 8, _FIELD_Q)
    if (x * x - x_squared) % _FIELD_Q != 0:
        x = x * _SQRT_M1 % _FIELD_Q
    if (x * x - x_squared) % _FIELD_Q != 0:
        return None
    if (x & 1) != sign:
        x = _FIELD_Q - x
    return x


def _point_add(first: Point, second: Point) -> Point:
    x1, y1, z1, t1 = first
    x2, y2, z2, t2 = second
    a = (y1 - x1) * (y2 - x2) % _FIELD_Q
    b = (y1 + x1) * (y2 + x2) % _FIELD_Q
    c = 2 * _CURVE_D * t1 * t2 % _FIELD_Q
    d = 2 * z1 * z2 % _FIELD_Q
    e = (b - a) % _FIELD_Q
    f = (d - c) % _FIELD_Q
    g = (d + c) % _FIELD_Q
    h = (b + a) % _FIELD_Q
    return (e * f % _FIELD_Q, g * h % _FIELD_Q, f * g % _FIELD_Q, e * h % _FIELD_Q)


def _point_double(point: Point) -> Point:
    x, y, z, _t = point
    a = x * x % _FIELD_Q
    b = y * y % _FIELD_Q
    c = 2 * z * z % _FIELD_Q
    d = -a % _FIELD_Q
    e = ((x + y) * (x + y) - a - b) % _FIELD_Q
    g = (d + b) % _FIELD_Q
    f = (g - c) % _FIELD_Q
    h = (d - b) % _FIELD_Q
    return (e * f % _FIELD_Q, g * h % _FIELD_Q, f * g % _FIELD_Q, e * h % _FIELD_Q)


def _scalar_multiply(point: Point, scalar: int) -> Point:
    result: Point = (0, 1, 1, 0)
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_double(addend)
        scalar >>= 1
    return result


def _encode_point(point: Point) -> bytes:
    x, y, z, _t = point
    inverse_z = pow(z, _FIELD_Q - 2, _FIELD_Q)
    affine_x = x * inverse_z % _FIELD_Q
    affine_y = y * inverse_z % _FIELD_Q
    return (affine_y | ((affine_x & 1) << 255)).to_bytes(32, "little")


def _is_on_curve(point: Point) -> bool:
    x, y, z, t = point
    if z % _FIELD_Q == 0 or (x * y - z * t) % _FIELD_Q != 0:
        return False
    x2 = x * x % _FIELD_Q
    y2 = y * y % _FIELD_Q
    z2 = z * z % _FIELD_Q
    return (y2 - x2) * z2 % _FIELD_Q == (z2 * z2 + _CURVE_D * x2 * y2) % _FIELD_Q


def _is_identity(point: Point) -> bool:
    x, y, z, _t = point
    return x % _FIELD_Q == 0 and (y - z) % _FIELD_Q == 0


def _is_prime_order_nonidentity(point: Point) -> bool:
    return not _is_identity(point) and _is_identity(_scalar_multiply(point, _GROUP_L))


def _decode_signature(value: object) -> bytes:
    if type(value) is not str or not value:
        raise ValueError("signature must be canonical base64 text")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("signature is not valid base64") from exc
    if len(raw) != 64 or base64.b64encode(raw).decode("ascii") != value:
        raise ValueError("signature is not canonical base64 for 64 bytes")
    return raw


def _require_sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{label} SHA-256 is invalid")
    return value


def _require_string(value: object, label: str) -> str:
    if type(value) is not str:
        raise ValueError(f"{label} must be text")
    return value


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


__all__ = [
    "DETACHED_SIGNATURE_ALGORITHM",
    "DETACHED_SIGNATURE_DOMAIN",
    "DETACHED_SIGNATURE_KIND",
    "DETACHED_SIGNATURE_SCHEMA",
    "DetachedSignatureEnvelope",
    "FINAL_AUTHORIZATION_DOMAIN",
    "FINAL_AUTHORIZATION_REQUEST_KIND",
    "FINAL_AUTHORIZATION_REQUEST_SCHEMA",
    "FINAL_AUTHORIZATION_SCOPE",
    "FinalAuthorizationRequest",
    "MAX_AUTHORIZATION_REQUEST_BYTES",
    "MAX_SIGNATURE_ENVELOPE_BYTES",
    "SIGNED_MESSAGE_PREFIX",
    "SignatureVerificationError",
    "SignatureVerificationReceipt",
    "parse_detached_signature_envelope",
    "parse_final_authorization_request",
    "verify_detached_authorization_signature",
    "verify_ed25519_signature",
]
