# Changelog

All notable changes to vouchkit are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) (pre-1.0: minor/patch numbers may
carry breaking changes while the API stabilizes).

## [0.0.3] - Unreleased

### Fixed

Three verifier checks that accepted inputs the specifications call on a verifier to refuse,
reported privately against 0.0.2 by an external researcher running public negative test
vectors offline. None is a signature forgery; each needed a non-conforming issuer or wallet.

- **Validity claims hidden in a disclosure.** `exp`, `nbf` and `iss` were read from the clear
  issuer-signed payload before disclosures were resolved, so an issuer that placed one of
  them in a disclosure (which the SD-JWT VC profile forbids) escaped the check entirely: an
  expired credential with a disclosed `exp` was accepted. A credential whose `iss`, `nbf`,
  `exp`, `cnf`, `vct` or `status` arrives through a disclosure is now rejected
  (`DisclosureError`). A disclosed `exp` the holder withholds cannot be told from a credential
  issued without one, so that half stays accepted by default; the new opt-in `require_exp=True`
  (also on `Verifier`) refuses credentials with no `exp` in the clear payload. Relying parties
  whose issuers always set `exp` should turn it on.
- **`crit` header ignored.** RFC 7515 §4.1.11 requires rejecting a JWS whose `crit` names an
  extension the verifier does not understand; vouchkit understands none, so any `crit` on the
  issuer JWT or the KB-JWT is now rejected. A JWS header or payload that is not a JSON object
  is rejected as well.
- **KB-JWT `iat`/`exp` unchecked.** Key-binding freshness rested on the nonce alone. The
  KB-JWT now needs a numeric `iat` within a window (`kb_max_age`, default 300 s, and
  `kb_clock_skew`, default 60 s, both also on `Verifier`), and `exp`/`nbf` are honoured when
  present (RFC 9901 §7.3). `exp`, `nbf` and `iat` in the clear issuer payload and `iat`, `exp`,
  `nbf` on the KB-JWT must be finite numbers; strings, `NaN`, infinities and booleans are
  rejected. Values are compared without truncation.
- **Decode failures surfaced as the wrong exception.** A JWS header, payload or disclosure that
  was not valid base64url JSON raised a bare `ValueError` (present since 0.0.1) instead of an
  `SdJwtError`, so a relying party catching the documented base class could crash on a hostile
  presentation. All three now raise `SdJwtError`/`DisclosureError`.

### Changed

- `TestWallet` takes a `clock` so the KB-JWT it stamps follows the verifier's clock in tests.

## [0.0.2] - 2026-07-11

### Added

- **OpenID4VP verifier-side transport** (`vouchkit.openid4vp`): the relying party's half of
  "sign in with the EU wallet" — nonce/state minting, a DCQL credential-query subset,
  ES256-signed request objects (`typ: oauth-authz-req+jwt`), the `openid4vp://` authorize URL
  (request by value or by `request_uri`), and `response_mode=direct_post` response handling
  with one-time, TTL-bounded transactions. Presentations are verified by the existing core
  (`verify_sd_jwt_vc`); DCQL satisfaction is checked against what was actually disclosed.
- **Backend seam** (`vouchkit.backends`): optional trust-anchor and receipt-sink interfaces,
  each with a local-first default. No backend can alter what is accepted or rejected, and a
  receipt-sink failure never fails or delays verification. Design in `docs/design/backends.md`.
- **`TestWallet`** in the test kit: an in-process wallet stand-in for a full OpenID4VP
  request/response round-trip in CI, no device or network required.
- **Live-interop artifacts** from a manual on-device session against the EUDI reference wallet
  (Android demo build, 2026-07): a runnable demo relying party (`examples/demo_rp.py`),
  wildcard-DCQL and `x509_hash` signed-request support, and a written findings report
  (`docs/interop/eudi-reference-wallet-2026-07.md`). The session validated transport,
  intent delivery, and request-object parsing end to end against a real wallet and a real
  credential; it stopped at the wallet's reader-trust-store check (self-signed verifier cert
  rejected — the eIDAS 2 RP-registration model working as designed). This is a manual
  session, not a CI or automated interop gate.
- **Agent-experience pack**: `PROMPT.md` (paste-in integration prompt for coding agents),
  `llms.txt` / `llms-full.txt` doc maps, and the co-maintainer call (`CO-MAINTAINER.md`).

### Changed

- README status and package docstring now reflect that the OpenID4VP transport ships in this
  release; the DC API front-end and trust-anchor resolution remain the next layers.

## [0.0.1] - 2026-07-07

### Added

- **SD-JWT VC verification core** (`vouchkit.verify_sd_jwt_vc`): issuer-signature verification,
  selective-disclosure digest checking, and KB-JWT holder key-binding validation for the
  HAIP-mandatory profile (ES256, `sha-256` disclosures). Failures are precise, typed
  exceptions that name the rule that failed and never carry claim values.
- **Integrator test kit** (`vouchkit.testkit`): `TestIssuer` / `TestHolder` for minting
  known-good and deliberately broken presentations, so integrators can prove their wiring in
  CI without a wallet, trust list, or network. Adversarial tests are the spine of the suite.

[0.0.2]: https://github.com/vouchkit/vouchkit/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/vouchkit/vouchkit/releases/tag/v0.0.1
