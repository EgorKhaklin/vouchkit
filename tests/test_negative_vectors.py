"""Negative test vectors for the 0.0.3 verifier fixes.

Written by an independent checker agent against the fix branch, held back from the builder
until the fix was complete (2026-10-28), then adopted as a CI fixture. Every vector is a
presentation a relying party must refuse, or a conforming edge case it must still accept.
"""
import json
import secrets

import pytest

from vouchkit import SdJwtError, DisclosureError, InvalidKeyBinding, ExpiredCredential, verify_sd_jwt_vc
from vouchkit.sdjwt import _b64url_encode, _sha256_b64url, _sign_es256
from vouchkit.testkit import TestHolder, TestIssuer, _b64url_json, _sign_jwt

AUD, NONCE, NOW = "https://rp.example", "n-123", 1_000_000


def disc(name, value):
    return _b64url_json([_b64url_encode(secrets.token_bytes(16)), name, value])


def make(issuer, holder, clear, disclosed=(), header=None, raw_payload=None):
    """disclosed: list of (name, value) top-level disclosures. Returns (jwt, {name: disc})."""
    ds = {n: disc(n, v) for n, v in disclosed}
    payload = {"cnf": {"jwk": holder.public_jwk}, **clear}
    if ds:
        payload["_sd"] = sorted(_sha256_b64url(d) for d in ds.values())
        payload["_sd_alg"] = "sha-256"
    hdr = header if header is not None else {"alg": "ES256", "typ": "dc+sd-jwt"}
    if raw_payload is not None:
        si = f"{_b64url_json(hdr)}.{_b64url_encode(raw_payload)}"
        return f"{si}.{_b64url_encode(_sign_es256(si.encode('ascii'), issuer.key))}", ds
    return _sign_jwt(hdr, payload, issuer.key), ds


def present(holder, jwt, chosen, kb_claims=None, kb_header=None, kb_raw_payload=None):
    prefix = "~".join([jwt, *chosen]) + "~"
    body = {"iat": NOW, "aud": AUD, "nonce": NONCE, "sd_hash": _sha256_b64url(prefix)}
    if kb_claims is not None:
        body.update(kb_claims)
        body = {k: v for k, v in body.items() if v is not DROP}
    hdr = kb_header if kb_header is not None else {"alg": "ES256", "typ": "kb+jwt"}
    if kb_raw_payload is not None:
        si = f"{_b64url_json(hdr)}.{_b64url_encode(kb_raw_payload)}"
        return prefix + f"{si}.{_b64url_encode(_sign_es256(si.encode('ascii'), holder.key))}"
    return prefix + _sign_jwt(hdr, body, holder.key)


DROP = object()
BASE = lambda iss: {"iss": iss, "iat": NOW - 10, "exp": NOW + 3600, "vct": "urn:t:1"}


def verify(p, issuer, **kw):
    return verify_sd_jwt_vc(p, issuer.public_jwk, expected_aud=AUD, expected_nonce=NONCE, now=NOW, **kw)


@pytest.fixture()
def ih():
    return TestIssuer(), TestHolder()


def assert_sdjwt_error(fn, cls=SdJwtError):
    """Must raise an SdJwtError subclass, never some other exception type."""
    try:
        fn()
    except cls:
        return
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"raised non-{cls.__name__}: {type(e).__name__}: {e}")
    pytest.fail("accepted")


# ---------- finding 1: never-disclosable claims ----------

def test_v01_disclosed_exp_revealed_expired(ih):
    i, h = ih
    clear = BASE(i.issuer); clear.pop("exp")
    jwt, ds = make(i, h, clear, [("exp", NOW - 10), ("a", 1)])
    assert_sdjwt_error(lambda: verify(present(h, jwt, [ds["exp"], ds["a"]]), i), DisclosureError)


def test_v02_disclosed_exp_revealed_not_expired_rejected(ih):
    i, h = ih
    clear = BASE(i.issuer); clear.pop("exp")
    jwt, ds = make(i, h, clear, [("exp", NOW + 10_000), ("a", 1)])
    assert_sdjwt_error(lambda: verify(present(h, jwt, [ds["exp"], ds["a"]]), i), DisclosureError)


def test_v03_disclosed_exp_withheld_default_accepted_require_exp_rejects(ih):
    i, h = ih
    clear = BASE(i.issuer); clear.pop("exp")
    jwt, ds = make(i, h, clear, [("exp", NOW - 10), ("a", 1)])
    p = present(h, jwt, [ds["a"]])
    assert verify(p, i).claims == {"a": 1}  # documented residual
    assert_sdjwt_error(lambda: verify(p, i, require_exp=True), ExpiredCredential)


def test_v04_disclosed_iss_other_issuer(ih):
    i, h = ih
    clear = BASE(i.issuer); clear.pop("iss")
    jwt, ds = make(i, h, clear, [("iss", "https://evil.test")])
    assert_sdjwt_error(lambda: verify(present(h, jwt, [ds["iss"]]), i), DisclosureError)


def test_v05_disclosed_iss_alongside_clear_iss_collides(ih):
    i, h = ih
    jwt, ds = make(i, h, BASE(i.issuer), [("iss", "https://evil.test")])
    assert_sdjwt_error(lambda: verify(present(h, jwt, [ds["iss"]]), i), DisclosureError)


def test_v06_disclosed_status(ih):
    i, h = ih
    jwt, ds = make(i, h, BASE(i.issuer), [("status", {"status_list": {"idx": 1, "uri": "https://x"}})])
    assert_sdjwt_error(lambda: verify(present(h, jwt, [ds["status"]]), i), DisclosureError)


def test_v07_disclosed_cnf_no_kb(ih):
    i, h = ih
    jwt, ds = make(i, h, BASE(i.issuer), [("cnf", {"jwk": h.public_jwk})])
    # make() puts cnf in clear; rebuild without it
    payload_clear = BASE(i.issuer)
    d = disc("cnf", {"jwk": h.public_jwk})
    p = {**payload_clear, "_sd": [_sha256_b64url(d)], "_sd_alg": "sha-256"}
    jwt = _sign_jwt({"alg": "ES256", "typ": "dc+sd-jwt"}, p, i.key)
    pres = "~".join([jwt, d]) + "~"
    assert_sdjwt_error(
        lambda: verify_sd_jwt_vc(pres, i.public_jwk, require_key_binding=False, now=NOW), DisclosureError
    )
    assert_sdjwt_error(lambda: verify(present(h, jwt, [d]), i), DisclosureError)


def test_v08_disclosed_vct_and_nbf(ih):
    i, h = ih
    clear = BASE(i.issuer); clear.pop("vct")
    jwt, ds = make(i, h, clear, [("vct", "urn:x"), ("nbf", NOW + 100)])
    assert_sdjwt_error(lambda: verify(present(h, jwt, [ds["vct"]]), i), DisclosureError)
    assert_sdjwt_error(lambda: verify(present(h, jwt, [ds["nbf"]]), i), DisclosureError)


def test_v09_nested_disclosed_exp_inside_object_accepted(ih):
    i, h = ih
    inner = disc("exp", 5)  # an "exp" key inside a non-top-level object: legitimate
    addr_val = {"_sd": [_sha256_b64url(inner)], "street": "Main"}
    outer = disc("document", addr_val)
    p = {**BASE(i.issuer), "cnf": {"jwk": h.public_jwk}, "_sd": [_sha256_b64url(outer)], "_sd_alg": "sha-256"}
    jwt = _sign_jwt({"alg": "ES256", "typ": "dc+sd-jwt"}, p, i.key)
    r = verify(present(h, jwt, [outer, inner]), i)
    assert r.claims["document"] == {"street": "Main", "exp": 5}


def test_v10_nested_clear_exp_inside_disclosed_object_accepted(ih):
    i, h = ih
    jwt, ds = make(i, h, BASE(i.issuer), [("validity", {"exp": 5, "iss": "x", "status": 1})])
    assert verify(present(h, jwt, [ds["validity"]]), i).claims["validity"]["exp"] == 5


def test_v11_iat_and_sub_disclosed_accepted(ih):
    # SD-JWT VC lets iat and sub be selectively disclosed
    i, h = ih
    clear = BASE(i.issuer); clear.pop("iat")
    jwt, ds = make(i, h, clear, [("iat", NOW - 5), ("sub", "u1")])
    assert verify(present(h, jwt, [ds["iat"], ds["sub"]]), i).claims.get("sub") == "u1"


def test_v12_disclosed_vct_integrity_accepted(ih):
    # draft-ietf-oauth-sd-jwt-vc lists iss, nbf, exp, cnf, vct and status as never-disclosable;
    # vct#integrity is not on that list, and vouchkit never reads it, so it stays accepted.
    i, h = ih
    jwt, ds = make(i, h, BASE(i.issuer), [("vct#integrity", "sha256-abc")])
    verify(present(h, jwt, [ds["vct#integrity"]]), i)


# ---------- finding 2: crit ----------

@pytest.mark.parametrize("crit", [[], ["alg"], "b64", {"b64": 1}, None, ["b64"], ["x-unknown"]])
def test_v13_crit_issuer(ih, crit):
    i, h = ih
    jwt, _ = make(i, h, BASE(i.issuer), header={"alg": "ES256", "typ": "dc+sd-jwt", "crit": crit})
    assert_sdjwt_error(lambda: verify(present(h, jwt, []), i))


@pytest.mark.parametrize("crit", [[], ["alg"], "b64", ["b64"]])
def test_v14_crit_kb(ih, crit):
    i, h = ih
    jwt, _ = make(i, h, BASE(i.issuer))
    p = present(h, jwt, [], kb_header={"alg": "ES256", "typ": "kb+jwt", "crit": crit})
    assert_sdjwt_error(lambda: verify(p, i))


def test_v15_header_json_array(ih):
    i, h = ih
    jwt, _ = make(i, h, BASE(i.issuer))
    _, pl, sig = jwt.split(".")
    header = _b64url_encode(b'["ES256"]')
    bad = f"{header}.{pl}.{sig}"
    assert_sdjwt_error(lambda: verify(present(h, bad, []), i))


def test_v16_payload_json_array(ih):
    i, h = ih
    jwt, _ = make(i, h, BASE(i.issuer), raw_payload=b'["iss","exp"]')
    assert_sdjwt_error(lambda: verify(present(h, jwt, []), i))


def test_v17_kb_header_and_payload_json_array(ih):
    i, h = ih
    jwt, _ = make(i, h, BASE(i.issuer))
    assert_sdjwt_error(lambda: verify(present(h, jwt, [], kb_raw_payload=b"[1,2]"), i))
    good = present(h, jwt, [])
    pre, kb = good.rsplit("~", 1)
    _, kpl, ksig = kb.split(".")
    assert_sdjwt_error(lambda: verify(pre + "~" + _b64url_encode(b"[]") + "." + kpl + "." + ksig, i))


# ---------- finding 3: KB iat/exp ----------

@pytest.mark.parametrize(
    "kb",
    [
        {"iat": float("nan")}, {"iat": "1000000"}, {"iat": True}, {"iat": False}, {"iat": None}, {"iat": [NOW]},
        {"iat": DROP}, {"iat": NOW + 10**7}, {"iat": NOW - 10**7}, {"iat": NOW - 301}, {"iat": NOW + 61},
        {"iat": float("inf")}, {"iat": float("-inf")},
        {"exp": "2000000"}, {"exp": NOW - 1}, {"exp": NOW}, {"exp": True}, {"nbf": NOW + 1}, {"nbf": "0"},
    ],
    ids=lambda kb: repr(kb)[:40],
)
def test_v18_kb_rejected(ih, kb):
    i, h = ih
    jwt, _ = make(i, h, BASE(i.issuer))
    assert_sdjwt_error(lambda: verify(present(h, jwt, [], kb_claims=kb), i), InvalidKeyBinding)


@pytest.mark.parametrize(
    "kb", [{"iat": NOW - 300}, {"iat": NOW + 60}, {"iat": NOW + 0.5}, {"iat": 1_000_000.5 - 10},
           {"exp": NOW + 1}, {"nbf": NOW}, {"exp": 10**12}],
    ids=lambda kb: repr(kb),
)
def test_v19_kb_accepted(ih, kb):
    i, h = ih
    jwt, _ = make(i, h, BASE(i.issuer))
    assert verify(present(h, jwt, [], kb_claims=kb), i).key_binding_verified


def test_v20_kb_iat_huge_int(ih):
    # holder-controlled: must be InvalidKeyBinding, not OverflowError
    i, h = ih
    jwt, _ = make(i, h, BASE(i.issuer))
    assert_sdjwt_error(lambda: verify(present(h, jwt, [], kb_claims={"iat": 10**400}), i), InvalidKeyBinding)


def test_v21_kb_exp_huge_int_accepted_without_crash(ih):
    # a far-future exp is valid; the point is that it must not raise OverflowError
    i, h = ih
    jwt, _ = make(i, h, BASE(i.issuer))
    verify(present(h, jwt, [], kb_claims={"exp": 10**400}), i)


# ---------- issuer exp/nbf ----------

@pytest.mark.parametrize("exp", ["9999999999", None, {}, float("nan")])
def test_v22_issuer_exp_bad_type(ih, exp):
    i, h = ih
    c = BASE(i.issuer); c["exp"] = exp
    jwt, _ = make(i, h, c)
    assert_sdjwt_error(lambda: verify(present(h, jwt, []), i))


def test_v23_exp_equals_now_rejected(ih):
    i, h = ih
    c = BASE(i.issuer); c["exp"] = NOW
    jwt, _ = make(i, h, c)
    assert_sdjwt_error(lambda: verify(present(h, jwt, []), i), ExpiredCredential)


def test_v24_nbf_equals_now_accepted(ih):
    i, h = ih
    c = BASE(i.issuer); c["nbf"] = NOW
    jwt, _ = make(i, h, c)
    assert verify(present(h, jwt, []), i).key_binding_verified


def test_v25_exp_large_int_accepted(ih):
    i, h = ih
    c = BASE(i.issuer); c["exp"] = 2**63  # large but float-representable
    jwt, _ = make(i, h, c)
    assert verify(present(h, jwt, []), i)


def test_v26_exp_huge_int_no_crash(ih):
    i, h = ih
    c = BASE(i.issuer); c["exp"] = 10**400  # > float range
    jwt, _ = make(i, h, c)
    try:
        verify(present(h, jwt, []), i)
    except SdJwtError:
        pass
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"raised {type(e).__name__}: {e}")


def test_v27_exp_fractional_semantics(ih):
    # exp 1000000.5 at now=1000000: credential still valid for half a second
    i, h = ih
    c = BASE(i.issuer); c["exp"] = NOW + 0.5
    jwt, _ = make(i, h, c)
    verify(present(h, jwt, []), i)


def test_v28_require_exp_with_clear_exp_accepted(ih):
    i, h = ih
    jwt, _ = make(i, h, BASE(i.issuer))
    assert verify(present(h, jwt, []), i, require_exp=True)


# ---------- happy path + error message hygiene ----------

def test_v29_happy_path_testkit(ih):
    i, h = ih
    jwt, ds = i.issue({"given_name": "Ada", "age_over_18": True}, holder_jwk=h.public_jwk, now=NOW - 10)
    p = h.present(jwt, ds, ["given_name"], aud=AUD, nonce=NONCE, now=NOW)
    r = verify(p, i)
    assert r.claims == {"given_name": "Ada"} and r.key_binding_verified


def test_v30_no_values_in_new_messages(ih):
    i, h = ih
    secret = "SECRETVALUE-9f1"
    jwt, _ = make(i, h, BASE(i.issuer))
    for kb in ({"iat": secret}, {"exp": secret}, {"nbf": secret}):
        with pytest.raises(SdJwtError) as ei:
            verify(present(h, jwt, [], kb_claims=kb), i)
        assert secret not in str(ei.value)
    clear = BASE(i.issuer); clear.pop("iss")
    jwt2, ds = make(i, h, clear, [("iss", secret)])
    with pytest.raises(SdJwtError) as ei:
        verify(present(h, jwt2, [ds["iss"]]), i)
    assert secret not in str(ei.value)
    jwt3, _ = make(i, h, BASE(i.issuer), header={"alg": "ES256", "crit": [secret]})
    with pytest.raises(SdJwtError) as ei:
        verify(present(h, jwt3, []), i)
    assert secret not in str(ei.value)


# ---------- pre-existing non-SdJwtError paths (not introduced by the diff) ----------

@pytest.mark.parametrize("pres", [
    "e30.e30.AA~",                              # header {} → UnsupportedAlgorithm (ok)
    _b64url_encode(b"not json") + ".e30.AA~",   # unauthenticated: header not JSON
    _b64url_encode(b"\xff\xfe") + ".e30.AA~",   # unauthenticated: header not UTF-8
])
def test_v31_preexisting_garbage_header(ih, pres):
    i, _ = ih
    assert_sdjwt_error(lambda: verify_sd_jwt_vc(pres, i.public_jwk, now=NOW))


def test_v32_preexisting_garbage_disclosure(ih):
    i, h = ih
    jwt, _ = make(i, h, BASE(i.issuer))
    assert_sdjwt_error(lambda: verify(present(h, jwt, [_b64url_encode(b"{not json")]), i))


def test_v33_preexisting_garbage_kb_header(ih):
    i, h = ih
    jwt, _ = make(i, h, BASE(i.issuer))
    assert_sdjwt_error(lambda: verify(jwt + "~" + _b64url_encode(b"nope") + ".e30.AA", i))
