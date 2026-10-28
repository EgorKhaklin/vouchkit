"""OpenID4VP transport — adversarial-first tests for the verifier role.

The round-trip runs entirely in CI via the test kit's TestWallet; the reference
wallet interop is the arc's separate exit criterion.
"""

import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from vouchkit import InvalidKeyBinding
from vouchkit.backends import UnknownIssuer, VerificationEvent
from vouchkit.openid4vp import (
    CredentialQuery,
    MalformedResponse,
    QueryNotSatisfied,
    TransactionExpired,
    TransactionReplayed,
    UnknownTransaction,
    Verifier,
)
from vouchkit.sdjwt import _b64url_decode
from vouchkit.testkit import TestIssuer, TestWallet

CLIENT_ID = "x509_san_dns:rp.example"
RESPONSE_URI = "https://rp.example/wallet-response"
QUERY = CredentialQuery(id="q1", vct="urn:eudi:test:credential:1", claims=("given_name",))


class RecordingReceipts:
    def __init__(self):
        self.events: list[VerificationEvent] = []

    def record(self, event):
        self.events.append(event)


class ExplodingReceipts:
    def record(self, event):
        raise RuntimeError("sink down")


@pytest.fixture()
def world():
    issuer = TestIssuer()
    receipts = RecordingReceipts()
    clock = {"now": 1_000_000.0}
    wallet = TestWallet(clock=lambda: clock["now"])
    verifier = Verifier(
        CLIENT_ID,
        RESPONSE_URI,
        trust_anchors={issuer.issuer: issuer.public_jwk},
        receipts=receipts,
        ttl_seconds=300,
        clock=lambda: clock["now"],
    )
    issuer_jwt, disclosures = issuer.issue(
        {"given_name": "Ada", "family_name": "Lovelace"},
        holder_jwk=wallet.public_jwk,
        now=1_000_000,
    )
    return issuer, wallet, verifier, receipts, clock, issuer_jwt, disclosures


def test_full_round_trip(world):
    issuer, wallet, verifier, receipts, clock, issuer_jwt, disclosures = world
    tx = verifier.start(QUERY)
    assert tx.authorize_url.startswith("openid4vp://?client_id=")
    form = wallet.respond(tx.request_object, issuer_jwt, disclosures, ["given_name"])
    credential = verifier.handle_response(form)
    assert credential.claims == {"given_name": "Ada"}
    assert credential.key_binding_verified is True
    assert receipts.events[-1].outcome == "verified"
    assert receipts.events[-1].claim_names == frozenset({"given_name"})


def test_receipt_carries_names_never_values(world):
    _, wallet, verifier, receipts, _, issuer_jwt, disclosures = world
    tx = verifier.start(QUERY)
    verifier.handle_response(wallet.respond(tx.request_object, issuer_jwt, disclosures, ["given_name"]))
    dumped = repr(receipts.events[-1])
    assert "Ada" not in dumped and "Lovelace" not in dumped


def test_replayed_state_rejected(world):
    _, wallet, verifier, _, _, issuer_jwt, disclosures = world
    tx = verifier.start(QUERY)
    form = wallet.respond(tx.request_object, issuer_jwt, disclosures, ["given_name"])
    verifier.handle_response(form)
    with pytest.raises(TransactionReplayed):
        verifier.handle_response(form)


def test_unknown_state_rejected(world):
    _, _, verifier, _, _, _, _ = world
    with pytest.raises(UnknownTransaction):
        verifier.handle_response({"state": "never-issued", "vp_token": "{}"})


def test_expired_transaction_rejected(world):
    _, wallet, verifier, _, clock, issuer_jwt, disclosures = world
    tx = verifier.start(QUERY)
    form = wallet.respond(tx.request_object, issuer_jwt, disclosures, ["given_name"])
    clock["now"] += 301
    with pytest.raises(TransactionExpired):
        verifier.handle_response(form)


def test_response_bound_to_its_own_transaction(world):
    """A response minted for transaction A must not satisfy transaction B."""
    _, wallet, verifier, _, _, issuer_jwt, disclosures = world
    tx_a = verifier.start(QUERY)
    tx_b = verifier.start(QUERY)
    form = wallet.respond(tx_a.request_object, issuer_jwt, disclosures, ["given_name"])
    form["state"] = tx_b.state  # splice A's presentation onto B's state
    with pytest.raises(InvalidKeyBinding):  # nonce mismatch: KB-JWT carries A's nonce
        verifier.handle_response(form)


def test_undisclosed_required_claim_rejected(world):
    _, wallet, verifier, receipts, _, issuer_jwt, disclosures = world
    tx = verifier.start(QUERY)
    form = wallet.respond(tx.request_object, issuer_jwt, disclosures, ["family_name"])
    with pytest.raises(QueryNotSatisfied):
        verifier.handle_response(form)
    assert receipts.events[-1].outcome == "QueryNotSatisfied"


def test_vct_mismatch_rejected(world):
    issuer, wallet, verifier, _, _, _, _ = world
    other_jwt, other_disc = issuer.issue(
        {"given_name": "Ada"}, holder_jwk=wallet.public_jwk, vct="urn:other:vct", now=1_000_000
    )
    tx = verifier.start(QUERY)
    form = wallet.respond(tx.request_object, other_jwt, other_disc, ["given_name"])
    with pytest.raises(QueryNotSatisfied):
        verifier.handle_response(form)


def test_unknown_issuer_rejected(world):
    _, wallet, verifier, _, _, _, _ = world
    rogue = TestIssuer(issuer="https://rogue.example")
    rogue_jwt, rogue_disc = rogue.issue(
        {"given_name": "Mallory"}, holder_jwk=wallet.public_jwk, now=1_000_000
    )
    tx = verifier.start(QUERY)
    form = wallet.respond(tx.request_object, rogue_jwt, rogue_disc, ["given_name"])
    with pytest.raises(UnknownIssuer):
        verifier.handle_response(form)


def test_malformed_vp_token_rejected(world):
    _, _, verifier, _, _, _, _ = world
    tx = verifier.start(QUERY)
    with pytest.raises(MalformedResponse):
        verifier.handle_response({"state": tx.state, "vp_token": "not json"})
    tx2 = verifier.start(QUERY)
    with pytest.raises(MalformedResponse):
        verifier.handle_response({"state": tx2.state, "vp_token": json.dumps({"wrong_id": ["x"]})})


def test_signed_request_object(world):
    issuer, _, _, _, clock, _, _ = world
    key = ec.generate_private_key(ec.SECP256R1())
    verifier = Verifier(
        CLIENT_ID,
        RESPONSE_URI,
        trust_anchors={issuer.issuer: issuer.public_jwk},
        signing_key=key,
        clock=lambda: clock["now"],
    )
    tx = verifier.start(QUERY)
    assert tx.request_jwt is not None
    header = json.loads(_b64url_decode(tx.request_jwt.split(".")[0]))
    assert header == {"alg": "ES256", "typ": "oauth-authz-req+jwt"}
    payload = json.loads(_b64url_decode(tx.request_jwt.split(".")[1]))
    assert payload["nonce"] == tx.nonce and payload["response_mode"] == "direct_post"
    assert "request=" in tx.authorize_url


def test_exploding_receipt_sink_never_breaks_verification(world):
    issuer, wallet, _, _, clock, issuer_jwt, disclosures = world
    verifier = Verifier(
        CLIENT_ID,
        RESPONSE_URI,
        trust_anchors={issuer.issuer: issuer.public_jwk},
        receipts=ExplodingReceipts(),
        clock=lambda: clock["now"],
    )
    tx = verifier.start(QUERY)
    credential = verifier.handle_response(
        wallet.respond(tx.request_object, issuer_jwt, disclosures, ["given_name"])
    )
    assert credential.claims == {"given_name": "Ada"}
