"""SD-JWT VC verification core (verifier/RP role).

Implements verification of an SD-JWT VC presentation per the IETF SD-JWT family
(selective disclosure via `_sd` digest arrays, `sha-256` disclosure hashing, KB-JWT
key binding) restricted to what the EUDI HAIP profile mandates for relying parties:

- issuer JWT signed with ES256 (P-256); `none`/HMAC and unknown algs are rejected
- disclosures are matched by digest, recursively (object claims and array elements)
- every supplied disclosure MUST be consumed (dangling disclosures are rejected)
- duplicate digests and claim-name collisions are rejected
- key binding (KB-JWT): `typ=kb+jwt`, holder key from `cnf.jwk`, `aud`/`nonce`
  checked against verifier expectations, `sd_hash` recomputed over the presentation

Trust-anchor resolution (which issuer keys to trust, x5c chains, trusted lists) is a
separate layer above this module: callers pass the issuer JWK they already trust.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import time
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature as _CryptoInvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

__all__ = [
    "SdJwtError",
    "InvalidSignature",
    "UnsupportedAlgorithm",
    "DisclosureError",
    "InvalidKeyBinding",
    "VerifiedCredential",
    "verify_sd_jwt_vc",
]


class SdJwtError(Exception):
    """Base class for every SD-JWT verification failure."""


class InvalidSignature(SdJwtError):
    """A JWS signature did not verify against the expected key."""


class UnsupportedAlgorithm(SdJwtError):
    """The JWT names an algorithm outside the accepted profile (ES256)."""


class DisclosureError(SdJwtError):
    """A disclosure is malformed, dangling, duplicated, or colliding."""


class InvalidKeyBinding(SdJwtError):
    """The KB-JWT is missing, malformed, or fails its checks."""


class ExpiredCredential(SdJwtError):
    """The credential is outside its exp/nbf validity window."""


_SD_KEY = "_sd"
_SD_ALG_KEY = "_sd_alg"
_ARRAY_DIGEST_KEY = "..."
_RESERVED_CLAIMS = frozenset({_SD_KEY, _SD_ALG_KEY})
# SD-JWT VC (draft-ietf-oauth-sd-jwt-vc, "Registered JWT Claims"): these claims MUST NOT
# be selectively disclosable. A credential that carries one in a disclosure is malformed,
# and a verifier that only reads the clear payload would silently skip the check it guards.
_NEVER_DISCLOSABLE = frozenset({"iss", "nbf", "exp", "cnf", "vct", "status"})
# Key Binding JWT freshness (RFC 9901 §7.3, step 5.5: "iat ... within an acceptable window").
DEFAULT_KB_MAX_AGE = 300  # seconds after its iat that a KB-JWT is still accepted
CLOCK_SKEW = 60  # seconds an iat may sit in the future before it is rejected


def _b64url_decode(data: str) -> bytes:
    pad = -len(data) % 4
    try:
        return base64.urlsafe_b64decode(data + "=" * pad)
    except Exception as exc:  # binascii.Error, ValueError
        raise SdJwtError(f"invalid base64url segment: {exc}") from exc


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _sha256_b64url(data: str) -> str:
    return _b64url_encode(hashlib.sha256(data.encode("ascii")).digest())


def _p256_key_from_jwk(jwk: dict[str, Any]) -> ec.EllipticCurvePublicKey:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise UnsupportedAlgorithm("only EC/P-256 keys are accepted (HAIP profile)")
    try:
        x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
        y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
    except KeyError as exc:
        raise SdJwtError(f"JWK missing coordinate: {exc}") from exc
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def _verify_es256(signing_input: bytes, signature: bytes, key: ec.EllipticCurvePublicKey) -> None:
    if len(signature) != 64:
        raise InvalidSignature("ES256 signature must be 64 raw bytes (r||s)")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    try:
        key.verify(encode_dss_signature(r, s), signing_input, ec.ECDSA(hashes.SHA256()))
    except _CryptoInvalidSignature as exc:
        raise InvalidSignature("signature verification failed") from exc


def _sign_es256(signing_input: bytes, key: ec.EllipticCurvePrivateKey) -> bytes:
    """Test-kit helper (also used by testkit.py); raw r||s output."""
    der = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _numeric_date(container: dict[str, Any], name: str, exc: type[SdJwtError]) -> int:
    """Read a NumericDate (RFC 7519 §2) claim; anything that is not a finite number is refused."""
    value = container[name]
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise exc(f"{name} must be a NumericDate")
    return int(value)


def _parse_jws(token: str, key: ec.EllipticCurvePublicKey, expected_typ: str | None = None) -> dict[str, Any]:
    """Parse and verify one compact JWS; returns the payload. ES256 only."""
    parts = token.split(".")
    if len(parts) != 3:
        raise SdJwtError("compact JWS must have exactly three segments")
    header = json.loads(_b64url_decode(parts[0]))
    if not isinstance(header, dict):
        raise SdJwtError("JWS header must be a JSON object")
    if "crit" in header:
        # RFC 7515 §4.1.11: a JWS whose crit lists an extension the verifier does not
        # understand MUST be rejected. This verifier understands no extensions.
        raise SdJwtError("crit header present; no JWS extensions are supported")
    alg = header.get("alg")
    if alg != "ES256":
        raise UnsupportedAlgorithm(f"alg {alg!r} rejected; profile requires ES256")
    if expected_typ is not None and header.get("typ") != expected_typ:
        raise SdJwtError(f"unexpected typ {header.get('typ')!r}; expected {expected_typ!r}")
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    _verify_es256(signing_input, _b64url_decode(parts[2]), key)
    payload = json.loads(_b64url_decode(parts[1]))
    if not isinstance(payload, dict):
        raise SdJwtError("JWS payload must be a JSON object")
    return payload


@dataclass(frozen=True)
class _Disclosure:
    b64: str
    digest: str
    salt: str
    name: str | None  # None for array-element disclosures
    value: Any


def _parse_disclosure(b64: str) -> _Disclosure:
    decoded = json.loads(_b64url_decode(b64))
    if not isinstance(decoded, list) or len(decoded) not in (2, 3):
        raise DisclosureError("disclosure must be a JSON array of 2 or 3 elements")
    if len(decoded) == 3:
        salt, name, value = decoded
        if not isinstance(name, str):
            raise DisclosureError("disclosure claim name must be a string")
    else:
        salt, value = decoded
        name = None
    if not isinstance(salt, str):
        raise DisclosureError("disclosure salt must be a string")
    return _Disclosure(b64=b64, digest=_sha256_b64url(b64), salt=salt, name=name, value=value)


def _resolve(node: Any, by_digest: dict[str, _Disclosure], used: set[str]) -> Any:
    """Recursively replace `_sd` / `...` digests with disclosed values."""
    if isinstance(node, dict):
        out: dict[str, Any] = {}
        for key, value in node.items():
            if key in _RESERVED_CLAIMS:
                continue
            out[key] = _resolve(value, by_digest, used)
        digests = node.get(_SD_KEY, [])
        if not isinstance(digests, list):
            raise DisclosureError("_sd must be an array of digests")
        for digest in digests:
            if not isinstance(digest, str):
                raise DisclosureError("_sd entries must be strings")
            if digest in used:
                raise DisclosureError("duplicate digest in credential structure")
            disc = by_digest.get(digest)
            if disc is None:
                continue  # undisclosed claim — absent from the output, by design
            used.add(digest)
            if disc.name is None:
                raise DisclosureError("array-element disclosure used in object position")
            if disc.name in out or disc.name in _RESERVED_CLAIMS:
                raise DisclosureError(f"claim-name collision for {disc.name!r}")
            out[disc.name] = _resolve(disc.value, by_digest, used)
        return out
    if isinstance(node, list):
        resolved: list[Any] = []
        for item in node:
            if isinstance(item, dict) and set(item.keys()) == {_ARRAY_DIGEST_KEY}:
                digest = item[_ARRAY_DIGEST_KEY]
                if digest in used:
                    raise DisclosureError("duplicate digest in credential structure")
                disc = by_digest.get(digest)
                if disc is None:
                    continue  # undisclosed array element
                used.add(digest)
                if disc.name is not None:
                    raise DisclosureError("object disclosure used in array position")
                resolved.append(_resolve(disc.value, by_digest, used))
            else:
                resolved.append(_resolve(item, by_digest, used))
        return resolved
    return node


@dataclass(frozen=True)
class VerifiedCredential:
    """Outcome of a successful verification — everything an RP may rely on."""

    issuer: str
    vct: str | None
    claims: dict[str, Any]
    key_binding_verified: bool
    disclosed_names: frozenset[str] = field(default_factory=frozenset)


def verify_sd_jwt_vc(
    presentation: str,
    issuer_jwk: dict[str, Any],
    *,
    expected_aud: str | None = None,
    expected_nonce: str | None = None,
    require_key_binding: bool = True,
    require_exp: bool = False,
    kb_max_age: int = DEFAULT_KB_MAX_AGE,
    now: int | None = None,
) -> VerifiedCredential:
    """Verify an SD-JWT VC presentation string and return the disclosed claims.

    `presentation` is `<issuer-jwt>~<disclosure>*~[<kb-jwt>]`. The caller supplies
    the trusted issuer JWK (trust-anchor resolution lives a layer above) and, when
    key binding is required (the RP flow default), the `aud`/`nonce` it challenged
    the wallet with.

    `require_exp` refuses credentials that carry no `exp` in the clear payload (a
    relying-party policy; the profile leaves `exp` optional). `kb_max_age` is the
    window, in seconds after its `iat`, during which a KB-JWT is accepted.
    """
    if "~" not in presentation:
        raise SdJwtError("not an SD-JWT presentation (no '~' separator)")
    segments = presentation.split("~")
    issuer_jwt, disclosure_b64s, kb_jwt = segments[0], segments[1:-1], segments[-1]

    issuer_key = _p256_key_from_jwk(issuer_jwk)
    payload = _parse_jws(issuer_jwt, issuer_key)

    sd_alg = payload.get(_SD_ALG_KEY, "sha-256")
    if sd_alg != "sha-256":
        raise UnsupportedAlgorithm(f"_sd_alg {sd_alg!r} rejected; profile requires sha-256")

    ts = int(time.time()) if now is None else now
    if "exp" in payload and ts >= _numeric_date(payload, "exp", ExpiredCredential):
        raise ExpiredCredential("credential is expired")
    elif "exp" not in payload and require_exp:
        raise ExpiredCredential("credential carries no exp and one is required")
    if "nbf" in payload and ts < _numeric_date(payload, "nbf", ExpiredCredential):
        raise ExpiredCredential("credential is not yet valid")

    disclosures = [_parse_disclosure(b) for b in disclosure_b64s]
    by_digest: dict[str, _Disclosure] = {}
    for disc in disclosures:
        if disc.digest in by_digest:
            raise DisclosureError("duplicate disclosure supplied")
        by_digest[disc.digest] = disc

    used: set[str] = set()
    claims = _resolve(payload, by_digest, used)

    dangling = set(by_digest) - used
    if dangling:
        raise DisclosureError("disclosure(s) supplied that match no digest in the credential")

    # Validity-controlling claims must sit in the clear payload, where they were checked
    # above. One arriving through a disclosure was never checked: reject the credential.
    smuggled = sorted(n for n in _NEVER_DISCLOSABLE if n in claims and n not in payload)
    if smuggled:
        raise DisclosureError(f"claim(s) {smuggled} must not be selectively disclosable")

    key_binding_verified = False
    if kb_jwt:
        cnf = payload.get("cnf", {})
        holder_jwk = cnf.get("jwk")
        if not holder_jwk:
            raise InvalidKeyBinding("KB-JWT supplied but credential carries no cnf.jwk")
        holder_key = _p256_key_from_jwk(holder_jwk)
        kb_payload = _parse_jws(kb_jwt, holder_key, expected_typ="kb+jwt")
        if "iat" not in kb_payload:
            raise InvalidKeyBinding("KB-JWT iat missing")
        kb_iat = _numeric_date(kb_payload, "iat", InvalidKeyBinding)
        if kb_iat > ts + CLOCK_SKEW:
            raise InvalidKeyBinding("KB-JWT iat is in the future")
        if ts - kb_iat > kb_max_age:
            raise InvalidKeyBinding("KB-JWT is older than the accepted window")
        if "exp" in kb_payload and ts >= _numeric_date(kb_payload, "exp", InvalidKeyBinding):
            raise InvalidKeyBinding("KB-JWT is expired")
        if "nbf" in kb_payload and ts < _numeric_date(kb_payload, "nbf", InvalidKeyBinding):
            raise InvalidKeyBinding("KB-JWT is not yet valid")
        if expected_aud is not None and kb_payload.get("aud") != expected_aud:
            raise InvalidKeyBinding("KB-JWT aud mismatch")
        if expected_nonce is not None and kb_payload.get("nonce") != expected_nonce:
            raise InvalidKeyBinding("KB-JWT nonce mismatch")
        prefix = "~".join([issuer_jwt, *disclosure_b64s]) + "~"
        if kb_payload.get("sd_hash") != _sha256_b64url(prefix):
            raise InvalidKeyBinding("KB-JWT sd_hash does not match the presentation")
        key_binding_verified = True
    elif require_key_binding:
        raise InvalidKeyBinding("key binding required but no KB-JWT supplied")

    # strip registered/structural claims from the RP-facing claim set
    disclosed = {
        k: v
        for k, v in claims.items()
        if k not in {"iss", "iat", "exp", "nbf", "cnf", "vct", "aud"}
    }
    return VerifiedCredential(
        issuer=str(payload.get("iss", "")),
        vct=payload.get("vct"),
        claims=disclosed,
        key_binding_verified=key_binding_verified,
        disclosed_names=frozenset(disclosed.keys()),
    )
