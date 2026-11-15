# ADR 0001 — XEdDSA signing for pairing

Status: **Proposed** (maintainer decision pending)

## Context

Completing the pairing flow requires a `pair-device-sign` response whose
`device-identity` payload carries an XEdDSA signature (prefix `0x06 0x01`) made
with the client's Curve25519 identity key. Verification is implemented and
proven (PF-017), but **signing** is not available in the Go standard library.

Project constraints from the technical specification:

- no hand-rolled cryptographic primitives (§5.2);
- no CGo and no libsignal bindings (§5.2);
- new dependencies need a policy review (§5.3).

## Options

1. **Hand-rolled XEdDSA signer** over `crypto/ed25519` / Edwards arithmetic.
   Rejected unless an external cryptographer reviews it; risk is concentrated
   in the sign-bit handling and nonce derivation.
2. **Vetted pure-Go dependency** that implements Curve25519 signatures.
   Requires the §5.3 checklist (pure Go, permissive license, maintained,
   minimal transitive tree) and known-answer vectors before use.
3. **Defer signing.** Keep pairing read-only (verify identity, store
   credentials) and finish Signal/SDK work first. The QR/pair-success path can
   be exercised against the fake server without emitting a client signature.

## Recommendation

Prefer **option 2** if a dependency passes the policy; otherwise **option 3**.
Do not ship option 1 without independent review. In all cases, land known-answer
vectors (sign → verify, including odd/even Edwards x) before wiring the
payload into a live flow.

## Consequences

- Until decided, the credential manager and pairing verification remain
  usable; the fake-server pairing test cannot complete the final ack.
- The decision blocks Phase 3 exit criteria, not Phase 4/5 work.
