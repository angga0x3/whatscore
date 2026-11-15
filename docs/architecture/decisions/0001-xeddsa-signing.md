# ADR 0001 — XEdDSA device signing

Status: **Accepted (deferred)** · 2026-11-15

## Decision

WhatsCore does **not** implement XEdDSA signing itself. The pairing flow keeps
an injected `signer` seam and returns `ErrSignerRequired` when no signer is
supplied, instead of emitting an unsigned credential.

## Why

Signing here means converting a clamped X25519 scalar into an Ed25519 signer
(point encoding, sign-bit handling, and nonce derivation). Getting any of that
subtly wrong produces signatures that verify locally and fail in the field —
the worst failure mode: tests pass, pairing silently breaks.

The project rule is older than this ADR: no hand-rolled cryptographic
primitives (§5.2). Verification is different — it is a public-key operation
whose correctness is pinned by the live handshake we already ran — so
`internal/xeddsa` verifies, and only verifies.

## Consequences

- Pairing stops at `ErrSignerRequired`. That is a feature: an unsigned device
  record would be rejected by the server after a full round trip.
- `CredentialResult.DeviceSignature` stays empty, so nothing can persist a
  half-formed credential by accident.
- A future implementation is a **drop-in**: supply `signal.Signer` (or an
  equivalent for the device-identity message) and the flow completes. The exact
  message construction is recorded in PF-017.

## What would change this

Either (a) a vetted pure-Go library under the §5.3 policy, reviewed and pinned
by known-answer vectors including odd/even Edwards x; or (b) a reviewed
first-party implementation with the same vectors. Neither exists today, so
neither is claimed.
