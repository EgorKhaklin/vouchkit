"""The Polaris negative vectors for SD-JWT VC presentations, as a CI fixture.

tests/data/polaris-sd-jwt-vc-vectors.json is lab/interop/negative-vectors/vectors.json from
github.com/EgorKhaklin/polaris-id at commit 03bd91a2715ce8457b62294ff2b251308d847934 (version
0.3.1, Apache-2.0; see NOTICE). Each vector is a presentation under OpenID4VP 1.0 and HAIP 1.0
with its expected verdict, the clauses behind it and a class saying how strongly they require
it; every vector but the controls differs from a control in one thing.

verify_sd_jwt_vc takes the issuer key from its caller, so this runs the vectors at the layers it
decides: the controls, JOSE, SD-JWT, SD-JWT VC and OpenID4VP. The issuer's x5c chain, the
binding of `iss` to the x5c leaf and the Token Status List are decided a layer above it, and
their vectors are not run here. Every vector run is signed by the file's first issuer JWK (an
x5c vector's leaf certifies that key).

To move the pin: copy the file from a newer commit, read what changed, and set COMMIT, SHA256
and RUN to match.
"""
import hashlib
import json
from pathlib import Path

import pytest

from vouchkit import SdJwtError, verify_sd_jwt_vc

FILE = Path(__file__).parent / "data" / "polaris-sd-jwt-vc-vectors.json"
COMMIT = "03bd91a2715ce8457b62294ff2b251308d847934"
SHA256 = "57be7019119665bbc1515559090099df8f34a483b1e2b6da0a96396adf897073"
RUN = 20  # the vectors at the layers below, controls included

# The layers verify_sd_jwt_vc decides, and those decided above it. A layer in neither fails
# the run, so a new layer in the file is noticed.
LAYERS = {"control", "jose", "sd-jwt", "sd-jwt-vc", "openid4vp"}
ABOVE = {"haip-x509", "x5c-issuer", "status-list"}

RAW = FILE.read_bytes()
DATA = json.loads(RAW)
SETTINGS = DATA["settings"]
VECTORS = [v for v in DATA["vectors"] if v["layer"] in LAYERS]


def test_the_file_is_the_pinned_one():
    assert hashlib.sha256(RAW).hexdigest() == SHA256, f"not the file at polaris-id {COMMIT}"
    assert {v["layer"] for v in DATA["vectors"]} <= LAYERS | ABOVE
    assert len(VECTORS) == RUN
    assert sum(v["expected"] == "accept" for v in VECTORS) == 2


@pytest.mark.parametrize("vector", VECTORS, ids=[v["id"] for v in VECTORS])
def test_vector(vector):
    def verify():
        return verify_sd_jwt_vc(
            vector["presentation"],
            SETTINGS["issuer_jwks"][0],
            expected_aud=SETTINGS["audience"],
            expected_nonce=SETTINGS["nonce"],
            now=int(SETTINGS["now"]),
        )

    if vector["expected"] == "accept":
        verify()
        return
    try:
        verify()
    except SdJwtError:
        return
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"raised non-SdJwtError: {type(e).__name__}: {e} ({vector['changed']})")
    pytest.fail(f"accepted: {vector['changed']}")
