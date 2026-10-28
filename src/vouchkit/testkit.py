"""Test kit — a self-contained SD-JWT VC issuer + holder for integration tests.

This is a deliberate product feature, not just test scaffolding: vouchkit's
design bar is "easiest to verify programmatically", so the kit that mints
known-good (and deliberately broken) presentations ships with the library. A
relying party integrating the verifier can prove its own wiring in CI without a
wallet, a trust list, or the network.

Test-only: nothing here may ever run in a production path (it holds private keys).
"""

from __future__ import annotations

import json
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from .sdjwt import _b64url_encode, _sha256_b64url, _sign_es256


def _b64url_json(obj: Any) -> str:
    return _b64url_encode(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


def _jwk_public(key: ec.EllipticCurvePrivateKey) -> dict[str, Any]:
    numbers = key.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url_encode(numbers.x.to_bytes(32, "big")),
        "y": _b64url_encode(numbers.y.to_bytes(32, "big")),
    }


def _sign_jwt(header: dict[str, Any], payload: dict[str, Any], key: ec.EllipticCurvePrivateKey) -> str:
    signing_input = f"{_b64url_json(header)}.{_b64url_json(payload)}"
    signature = _sign_es256(signing_input.encode("ascii"), key)
    return f"{signing_input}.{_b64url_encode(signature)}"


@dataclass
class TestIssuer:
    """Mints SD-JWT VCs with every non-registered claim selectively disclosable."""

    __test__ = False  # public test-kit API, not a pytest collectable

    issuer: str = "https://issuer.test"
    key: ec.EllipticCurvePrivateKey = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.key is None:
            self.key = ec.generate_private_key(ec.SECP256R1())

    @property
    def public_jwk(self) -> dict[str, Any]:
        return _jwk_public(self.key)

    def issue(
        self,
        claims: dict[str, Any],
        *,
        vct: str = "urn:eudi:test:credential:1",
        holder_jwk: dict[str, Any] | None = None,
        lifetime: int = 3600,
        now: int | None = None,
    ) -> tuple[str, dict[str, str]]:
        """Returns (issuer_jwt, {claim_name: disclosure_b64})."""
        ts = int(time.time()) if now is None else now
        disclosures: dict[str, str] = {}
        sd_digests: list[str] = []
        for name, value in claims.items():
            disclosure = _b64url_json([_b64url_encode(secrets.token_bytes(16)), name, value])
            disclosures[name] = disclosure
            sd_digests.append(_sha256_b64url(disclosure))
        payload: dict[str, Any] = {
            "iss": self.issuer,
            "iat": ts,
            "exp": ts + lifetime,
            "vct": vct,
            "_sd": sorted(sd_digests),  # sorted: don't leak claim order
            "_sd_alg": "sha-256",
        }
        if holder_jwk is not None:
            payload["cnf"] = {"jwk": holder_jwk}
        issuer_jwt = _sign_jwt({"alg": "ES256", "typ": "dc+sd-jwt"}, payload, self.key)
        return issuer_jwt, disclosures


@dataclass
class TestHolder:
    """Builds presentations (subset of disclosures + KB-JWT) like a wallet would."""

    __test__ = False  # public test-kit API, not a pytest collectable

    key: ec.EllipticCurvePrivateKey = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.key is None:
            self.key = ec.generate_private_key(ec.SECP256R1())

    @property
    def public_jwk(self) -> dict[str, Any]:
        return _jwk_public(self.key)

    def present(
        self,
        issuer_jwt: str,
        disclosures: dict[str, str],
        reveal: list[str],
        *,
        aud: str | None = None,
        nonce: str | None = None,
        now: int | None = None,
    ) -> str:
        chosen = [disclosures[name] for name in reveal]
        prefix = "~".join([issuer_jwt, *chosen]) + "~"
        if aud is None and nonce is None:
            return prefix  # presentation without key binding
        kb_payload = {
            "iat": int(time.time()) if now is None else now,
            "aud": aud,
            "nonce": nonce,
            "sd_hash": _sha256_b64url(prefix),
        }
        kb_jwt = _sign_jwt({"alg": "ES256", "typ": "kb+jwt"}, kb_payload, self.key)
        return prefix + kb_jwt


@dataclass
class TestWallet:
    """A stand-in wallet for the OpenID4VP flow: consumes a verifier's request
    object and produces the `direct_post` form a real wallet would POST. Lets a
    relying party run the *entire* sign-in round-trip in CI."""

    __test__ = False  # public test-kit API, not a pytest collectable

    holder: TestHolder = None  # type: ignore[assignment]
    clock: Callable[[], float] = time.time  # stamps the KB-JWT iat; align it with the verifier's

    def __post_init__(self) -> None:
        if self.holder is None:
            self.holder = TestHolder()

    @property
    def public_jwk(self) -> dict[str, Any]:
        return self.holder.public_jwk

    def respond(
        self,
        request_object: dict[str, Any],
        issuer_jwt: str,
        disclosures: dict[str, str],
        reveal: list[str],
    ) -> dict[str, str]:
        query_id = request_object["dcql_query"]["credentials"][0]["id"]
        presentation = self.holder.present(
            issuer_jwt,
            disclosures,
            reveal,
            aud=request_object["client_id"],
            nonce=request_object["nonce"],
            now=int(self.clock()),
        )
        return {
            "vp_token": json.dumps({query_id: [presentation]}),
            "state": request_object["state"],
        }
