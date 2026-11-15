# ADR 0001 — XEdDSA device signing

Status: **Accepted — blocked on a vetted implementation** · 2026-11-15

## Decision

WhatsCore does **not** implement XEdDSA signing itself. The pairing flow keeps
an injected signer seam and returns `ErrSignerRequired` when none is supplied,
instead of emitting an unsigned credential.

## Why — measured, not assumed

On 2026-11-15 an attempt was made to implement signing with
`filippo.io/edwards25519` (the audited library behind `crypto/ed25519`'s group
operations). It produced signatures that verified against the code that made
them, and that is exactly what made it dangerous. Comparison against an
independent RFC 8032 reference and against libsignal's construction showed
three divergences that would only surface against the real service:

1. **Two different scalars in one signature.** libsignal derives the signing
   scalar as `clamp(SHA-512(privScalar)[:32])` and the nonce prefix as
   `[32:]`, but the public point `A` as `clamp(privScalar)·B`. RFC 8032 uses one
   scalar for both.
2. **Nonce input includes the public key.** curve25519-donna's `crypto_sign`
   hashes `prefix ‖ message ‖ publicKey`, not `prefix ‖ message`.
3. **The sign bit rides in S.** XEdDSA stores the Edwards sign choice in the
   top bit of the final S byte, which standard Ed25519 verification rejects.

Any one of these produces signatures that pass local round-trip tests and fail
a real pairing. That is the worst possible failure mode: a green test suite
hides a broken protocol.

## Consequence

- Pairing stops at `ErrSignerRequired` **after** the server container is
  verified, so no half-formed credential is returned or persisted.
- The message to be signed is fully specified in PF-017, so a future
  implementation is a drop-in: supply a signer and the flow completes.
- Do not scan a pairing QR against this build: the flow cannot answer
  `pair-device-sign`, so the link attempt would fail and may leave a dangling
  device entry on the account.

## What would change this

A vetted implementation (a dependency under §5.3, or a first-party one reviewed
against libsignal's `curve25519-donna` reference), pinned by known-answer
vectors that include odd/even Edwards x **and** a cross-check against libsignal
output. The vectors must come from that reference, not from our own code.
