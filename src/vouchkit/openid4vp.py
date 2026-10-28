"""OpenID4VP verifier-side transport (HAIP-shaped subset).

Implements the relying party's half of "sign in with the EU wallet":

- **authorization requests** — nonce/state minting, a minimal DCQL credential
  query, and an ES256-signed request object (`typ: oauth-authz-req+jwt`), plus
  the `openid4vp://` authorize URL (request by value, or by `request_uri`)
- **response handling** — `response_mode=direct_post`: the wallet POSTs
  `vp_token` + `state`; transactions are one-time-use and TTL-bounded; the
  presentation is verified by the core (`verify_sd_jwt_vc`) with the
  transaction's nonce and this verifier's `client_id` as the key-binding
  audience; DCQL satisfaction is checked against what was actually disclosed.

Scope notes (roadmap): encrypted responses (`direct_post.jwt`), the browser
Digital Credentials API front-end, and cross-device flows are later slices.
Interop against the EUDI reference wallet is the exit criterion of this arc;
`vouchkit.testkit.TestWallet` provides the CI stand-in until then.

Trust anchors and receipts arrive through the backend seam
(`vouchkit.backends`); neither can alter what is accepted or rejected.
"""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

from cryptography.hazmat.primitives.asymmetric import ec

from .backends import (
    NoopReceipts,
    ReceiptSink,
    StaticTrustAnchors,
    TrustAnchorSource,
    VerificationEvent,
)
from .sdjwt import (
    SdJwtError,
    VerifiedCredential,
    _b64url_decode,
    _b64url_encode,
    _sign_es256,
    verify_sd_jwt_vc,
)

__all__ = [
    "CredentialQuery",
    "OpenId4VpError",
    "MalformedResponse",
    "QueryNotSatisfied",
    "StartedTransaction",
    "TransactionExpired",
    "TransactionReplayed",
    "UnknownTransaction",
    "Verifier",
]


class OpenId4VpError(Exception):
    """Base class for transport-layer failures (distinct from SdJwtError)."""


class UnknownTransaction(OpenId4VpError):
    """The response's `state` matches no pending transaction."""


class TransactionReplayed(OpenId4VpError):
    """The transaction was already consumed — one-time use is absolute."""


class TransactionExpired(OpenId4VpError):
    """The transaction outlived its TTL before the wallet responded."""


class MalformedResponse(OpenId4VpError):
    """The direct_post form is structurally invalid."""


class QueryNotSatisfied(OpenId4VpError):
    """The presentation verified, but does not satisfy the DCQL query."""


@dataclass(frozen=True)
class CredentialQuery:
    """Minimal DCQL credential query: one SD-JWT VC type + required claims.

    `vct="*"` accepts any SD-JWT VC type: the DCQL query carries no `meta`
    constraint and the post-verification vct check is skipped. Use for RPs
    that accept multiple credential types (or during interop discovery)."""

    id: str
    vct: str
    claims: tuple[str, ...] = ()

    def to_dcql(self) -> dict[str, Any]:
        query: dict[str, Any] = {
            "id": self.id,
            "format": "dc+sd-jwt",
        }
        if self.vct != "*":
            query["meta"] = {"vct_values": [self.vct]}
        if self.claims:
            query["claims"] = [{"path": [name]} for name in self.claims]
        return query


@dataclass
class _Transaction:
    state: str
    nonce: str
    query: CredentialQuery
    created_at: float
    consumed: bool = False


@dataclass(frozen=True)
class StartedTransaction:
    """Everything the RP needs to send the wallet on its way."""

    state: str
    nonce: str
    request_object: dict[str, Any]
    request_jwt: str | None
    authorize_url: str


def _b64url_json(obj: Any) -> str:
    return _b64url_encode(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


def _peek_unverified_claim(presentation: str, claim: str) -> Any:
    """Read one claim from the issuer JWT *without verification* — used only to
    look up which trust anchor to verify against, never trusted for anything else."""
    try:
        issuer_jwt = presentation.split("~", 1)[0]
        payload = json.loads(_b64url_decode(issuer_jwt.split(".")[1]))
        return payload.get(claim)
    except Exception as exc:  # noqa: BLE001 - any parse failure is the same answer
        raise MalformedResponse(f"vp_token is not parseable: {exc}") from exc


class Verifier:
    """The relying-party instance: start transactions, handle wallet responses."""

    def __init__(
        self,
        client_id: str,
        response_uri: str,
        *,
        trust_anchors: TrustAnchorSource | dict[str, dict[str, Any]],
        receipts: ReceiptSink | None = None,
        signing_key: ec.EllipticCurvePrivateKey | None = None,
        ttl_seconds: int = 300,
        clock=time.time,
        require_exp: bool = False,
        kb_max_age: int = 300,
        kb_clock_skew: int = 60,
    ) -> None:
        self.client_id = client_id
        self.response_uri = response_uri
        self._anchors: TrustAnchorSource = (
            StaticTrustAnchors(trust_anchors) if isinstance(trust_anchors, dict) else trust_anchors
        )
        self._receipts: ReceiptSink = receipts if receipts is not None else NoopReceipts()
        self._signing_key = signing_key
        self._ttl = ttl_seconds
        self._clock = clock
        self._require_exp = require_exp
        self._kb_max_age = kb_max_age
        self._kb_clock_skew = kb_clock_skew
        self._transactions: dict[str, _Transaction] = {}

    # -- request side ---------------------------------------------------------

    def start(self, query: CredentialQuery, *, request_uri: str | None = None) -> StartedTransaction:
        state = _b64url_encode(secrets.token_bytes(16))
        nonce = _b64url_encode(secrets.token_bytes(16))
        now = self._clock()
        self._transactions[state] = _Transaction(state, nonce, query, now)

        request_object: dict[str, Any] = {
            "client_id": self.client_id,
            "response_type": "vp_token",
            "response_mode": "direct_post",
            "response_uri": self.response_uri,
            "nonce": nonce,
            "state": state,
            "dcql_query": {"credentials": [query.to_dcql()]},
            "iat": int(now),
            "exp": int(now) + self._ttl,
        }

        request_jwt = None
        if self._signing_key is not None:
            header = _b64url_json({"alg": "ES256", "typ": "oauth-authz-req+jwt"})
            payload = _b64url_json(request_object)
            signature = _sign_es256(f"{header}.{payload}".encode("ascii"), self._signing_key)
            request_jwt = f"{header}.{payload}.{_b64url_encode(signature)}"

        if request_uri is not None:
            params = {"client_id": self.client_id, "request_uri": request_uri}
        elif request_jwt is not None:
            params = {"client_id": self.client_id, "request": request_jwt}
        else:  # unsigned, by value — dev/test flows only
            params = {"client_id": self.client_id, **{
                k: (json.dumps(v, separators=(",", ":")) if isinstance(v, dict) else str(v))
                for k, v in request_object.items()
            }}
        authorize_url = "openid4vp://?" + urlencode(params)

        return StartedTransaction(state, nonce, request_object, request_jwt, authorize_url)

    # -- response side --------------------------------------------------------

    def handle_response(self, form: dict[str, Any]) -> VerifiedCredential:
        state = form.get("state")
        if not isinstance(state, str) or not state:
            raise MalformedResponse("direct_post form carries no state")

        tx = self._transactions.get(state)
        if tx is None:
            raise UnknownTransaction("state matches no pending transaction")
        if tx.consumed:
            raise TransactionReplayed("transaction already consumed")
        tx.consumed = True  # consume before verifying: a failed attempt burns the state
        if self._clock() - tx.created_at > self._ttl:
            raise TransactionExpired("transaction outlived its TTL")

        presentation = self._extract_presentation(form, tx.query.id)
        issuer = _peek_unverified_claim(presentation, "iss")
        issuer_jwk = self._anchors.resolve(str(issuer))

        try:
            credential = verify_sd_jwt_vc(
                presentation,
                issuer_jwk,
                expected_aud=self.client_id,
                expected_nonce=tx.nonce,
                require_exp=self._require_exp,
                kb_max_age=self._kb_max_age,
                kb_clock_skew=self._kb_clock_skew,
                now=int(self._clock()),
            )
        except SdJwtError as exc:
            self._record(str(issuer), None, frozenset(), outcome=type(exc).__name__)
            raise

        if tx.query.vct != "*" and credential.vct != tx.query.vct:
            self._record(credential.issuer, credential.vct, credential.disclosed_names, "QueryNotSatisfied")
            raise QueryNotSatisfied(f"vct {credential.vct!r} does not match the query")
        missing = set(tx.query.claims) - set(credential.disclosed_names)
        if missing:
            self._record(credential.issuer, credential.vct, credential.disclosed_names, "QueryNotSatisfied")
            raise QueryNotSatisfied(f"required claims not disclosed: {sorted(missing)}")

        self._record(credential.issuer, credential.vct, credential.disclosed_names, "verified")
        return credential

    @staticmethod
    def _extract_presentation(form: dict[str, Any], query_id: str) -> str:
        vp_token = form.get("vp_token")
        if isinstance(vp_token, str):
            try:
                vp_token = json.loads(vp_token)
            except json.JSONDecodeError as exc:
                raise MalformedResponse("vp_token is not valid JSON") from exc
        if not isinstance(vp_token, dict):
            raise MalformedResponse("vp_token must be a JSON object keyed by credential query id")
        presentations = vp_token.get(query_id)
        if not isinstance(presentations, list) or not presentations or not isinstance(presentations[0], str):
            raise MalformedResponse(f"vp_token carries no presentation for query {query_id!r}")
        return presentations[0]

    def _record(self, issuer: str, vct: str | None, names: frozenset[str], outcome: str) -> None:
        try:
            self._receipts.record(
                VerificationEvent(issuer=issuer, vct=vct, claim_names=names, outcome=outcome)
            )
        except Exception:  # noqa: BLE001 - a ReceiptSink must never break verification
            pass
