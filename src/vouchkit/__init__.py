"""vouchkit — the wallet-relying-party toolkit for personal-data services.

vouchkit lets a service become a **(wallet-)relying party** for the EU Digital
Identity Wallet ecosystem: verify wallet presentations (SD-JWT VC per the
HAIP-mandatory profile) with a small, auditable, pure-Python core.

Current scope (pre-alpha): the cryptographic heart of the verifier role —
SD-JWT VC verification (issuer signature, selective-disclosure digests, KB-JWT
key binding) plus a reusable test kit so integrators can verify their own
wiring in CI without a wallet, and the OpenID4VP verifier-side transport
(`vouchkit.openid4vp`: signed request objects, `direct_post`, a DCQL subset).
The DC API front-end and trust-anchor resolution are the next layers (see the
roadmap in README.md).

Design bar: easiest to integrate, maintain, and verify programmatically —
`cryptography` is the only runtime dependency; failures are precise, typed
exceptions; adversarial tests are the suite's spine.
"""

from .sdjwt import (
    DisclosureError,
    ExpiredCredential,
    InvalidKeyBinding,
    InvalidSignature,
    SdJwtError,
    UnsupportedAlgorithm,
    VerifiedCredential,
    verify_sd_jwt_vc,
)

__version__ = "0.0.3"

__all__ = [
    "DisclosureError",
    "ExpiredCredential",
    "InvalidKeyBinding",
    "InvalidSignature",
    "SdJwtError",
    "UnsupportedAlgorithm",
    "VerifiedCredential",
    "verify_sd_jwt_vc",
    "__version__",
]
