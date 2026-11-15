# ADR 0001 — XEdDSA device signing

Status: **Accepted — implemented against the reference** · 2026-11-15

## Decision

XEdDSA signing is implemented in `internal/xeddsa`, with the curve arithmetic
delegated to `filippo.io/edwards25519` (the audited library behind
`crypto/ed25519`'s group operations). Only the XEdDSA framing is ours.

Pairing signs `0x06,0x01 ‖ details ‖ identityPub ‖ accountSignatureKey` with
this signer (PF-017) and returns the signature in `CredentialResult`.

## How it was validated

An earlier attempt failed, and it failed in the most dangerous way: local
round-trip tests passed while the construction diverged from the reference.
The three differences it exposed are recorded as PF-067.

The second attempt starts from the reference instead of from a guess:

1. **Vectors come from the reference.** Four known-answer vectors were produced
   by calling `ecc.CalculateSignature` in `go.mau.fi/libsignal v0.2.2`, then
   recorded as constants. Nothing in this repository produced them.
2. **The verifier is tested against those vectors** — reference signatures must
   verify here, including the sign-bit handling.
3. **The signer is tested for shape and determinism**, and its output must
   verify under the same code path the live handshake already exercised.

## The construction (PF-067)

```
A  = clamp(privScalar) · B
r  = SHA-512(0xFE,0xFF… ‖ privScalar ‖ msg ‖ random[64])
R  = r · B
S  = r + SHA-512(R ‖ A ‖ msg) · clamp(privScalar)   (mod L)
sig = R ‖ S, with sig[63] |= A[31] & 0x80
```

## Consequences

- `Ed25519Signer` was removed: it only verified when the key's Edwards x
  happened to be even, which is a trap. `XEdDSASigner` is the one path.
- Test helpers now sign the way production does. Three test files were signing
  with `crypto/ed25519` and passed only by luck; they were fixed rather than
  the production code being relaxed.
- Pairing can still fail for other reasons (token table, server rejection), but
  the signature is no longer one of them.

## What would invalidate this

A live pairing run that the server rejects at `pair-device-sign`. That is the
next test, and it requires a real account.
