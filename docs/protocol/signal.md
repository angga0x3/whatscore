# Signal findings

Session establishment for Signal-style end-to-end encryption: X3DH key
agreement over Curve25519. Extracted from read-only reference study of
libsignal-protocol-go (`ratchet/`, `kdf/`, `ecc/`) on 2026-11-15. The full
Double Ratchet and message encryption are not implemented yet.

## PF-050: X3DH master secret and DH order

| Field | Value |
|-------|-------|
| **ID** | PF-050 |
| **Title** | The X3DH master secret is `0xFF×32 ‖ DH1 ‖ DH2 ‖ DH3 [‖ DH4]`, with DH1 = DH(IKa, SPKb), DH2 = DH(EKa, IKb), DH3 = DH(EKa, SPKb), DH4 = DH(EKa, OPKb) |
| **Layer** | signal |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Confirmed |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/signal` (independent vectors for DH1…DH4) |
| **Related findings** | PF-051, PF-053 |
| **Notes** | libsignal-protocol-go `ratchet/Ratchet.go` `CalculateSenderSession`: the master secret starts with 32 `0xFF` discontinuity bytes, then the shared secrets in the order above, appending DH4 only when a one-time prekey exists. The receiver (`CalculateReceiverSession`) computes the mirrored pairs: DH(SPKb, IKa), DH(IKb, EKa), DH(SPKb, EKa), DH(OPKb, EKa) — the same values. |

## PF-051: X3DH key derivation

| Field | Value |
|-------|-------|
| **ID** | PF-051 |
| **Title** | `HKDF-SHA256(ikm=masterSecret, salt=nil, info="WhisperText", L=64)` yields the root key (first 32 bytes) and chain key (last 32) |
| **Layer** | signal |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Confirmed |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/signal` (root/chain vectors generated with Python `cryptography`) |
| **Related findings** | PF-050, PF-052 |
| **Notes** | libsignal `kdf.DeriveSecrets(masterSecret, nil, []byte("WhisperText"), root.DerivedSecretsSize)` with `DerivedSecretsSize = 64`; `session.NewDerivedSecrets` splits the output into the root key and chain key. The salt is absent, which HKDF treats as 32 zero bytes. |

## PF-052: Initial keys and identifiers

| Field | Value |
|-------|-------|
| **ID** | PF-052 |
| **Title** | A new session carries the root key, chain key (index 0), and the prekey identifiers used: registration id, signed-prekey id, and optional one-time-prekey id |
| **Layer** | signal |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Confirmed |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/signal` (agreement tests with and without a one-time prekey) |
| **Related findings** | PF-050, PF-051 |
| **Notes** | `session.NewKeyPair(rootKey, chainKey)` and `chain.NewKey(..., index 0)` in the reference. The initiator's `PreKeySignalMessage` (not implemented here) carries the registration id, prekey ids, identity key, and base key; the responder selects the matching private prekeys. |

## PF-053: Signed-prekey signature

| Field | Value |
|-------|-------|
| **ID** | PF-053 |
| **Title** | The signed prekey is an XEdDSA signature under the identity key over `0x05 ‖ signedPreKeyPublic`; the curve type byte `0x05` is the libsignal Djb key type |
| **Layer** | signal |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Confirmed |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/signal` (positive/negative signature tests), `internal/xeddsa` |
| **Related findings** | PF-050 |
| **Notes** | libsignal `ecc.DjbECPublicKey.serialize()` prepends the type byte `0x05`; `Curve.verifySignature(identityKey, signedPreKey.serialize(), signature)` verifies it. Verification accepts either Edwards sign because a Montgomery u coordinate does not carry the sign bit (see `internal/xeddsa`). Signing is still blocked by ADR 0001. |

---

Status: X3DH initiator/responder agreement and signed-prekey verification are
implemented and proven by independent vectors. The Double Ratchet, message
encryption, prekey generation/rotation, and serialized session state remain.

## PF-054: Root ratchet

| Field | Value |
|-------|-------|
| **ID** | PF-054 |
| **Title** | One DH ratchet step derives `(nextRoot, chain) = HKDF-SHA256(ikm=X25519(ourRatchetPriv, theirRatchetPub), salt=rootKey, info="WhisperRatchet", L=64)` |
| **Layer** | signal |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Confirmed |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/signal` (independent root/chain vectors, mirrored DH agreement) |
| **Related findings** | PF-051, PF-055 |
| **Notes** | libsignal `keys/root/root_key.go` `CreateChain`: `calculateAgreement(theirRatchetKey, ourRatchetKey)` then `DeriveSecrets(secret, rootKey, "WhisperRatchet", 64)`; the first 32 bytes become the next root key and the last 32 the chain key. Both sides compute the same values with mirrored private/public keys. |

## PF-055: Symmetric chain ratchet

| Field | Value |
|-------|-------|
| **ID** | PF-055 |
| **Title** | The message key is `HMAC-SHA256(chainKey, 0x01)`; advancing the chain is `HMAC-SHA256(chainKey, 0x02)` and increments the index |
| **Layer** | signal |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Confirmed |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/signal` (three chained steps with independent vectors) |
| **Related findings** | PF-054, PF-056 |
| **Notes** | libsignal `keys/chain/chain_key.go`: `BaseMaterial(0x01)` for the message key, `BaseMaterial(0x02)` for the next chain key, both HMAC-SHA256; the chain index starts at 0 and increases per message. |

## PF-056: Message keys

| Field | Value |
|-------|-------|
| **ID** | PF-056 |
| **Title** | `HKDF-SHA256(ikm=messageKey, salt=nil, info="WhisperMessageKeys", L=80)` yields the 32-byte cipher key, 32-byte MAC key, and 16-byte IV |
| **Layer** | signal |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Confirmed |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/signal` (cipher/MAC/IV vectors per chain step) |
| **Related findings** | PF-055 |
| **Notes** | libsignal `keys/chain.Key.MessageKeys`: `DeriveSecrets(baseMaterial, nil, "WhisperMessageKeys", 80)`, split as cipher key 32, MAC key 32, IV 16. Message encryption itself (SignalMessage framing, MAC over identities) is not implemented. |

---

Status update: X3DH, the root/chain key schedule, and message-key expansion are
implemented and proven by independent vectors. The ratchet state machine
(header handling, skipped keys, out-of-order), message encryption, prekeys,
and serialized session state remain.

## PF-057: Session initialization

| Field | Value |
|-------|-------|
| **ID** | PF-057 |
| **Title** | The initiator keeps the X3DH chain as its receiver chain for the responder's signed prekey and derives its first sender chain from a fresh ratchet key; the responder starts with the X3DH chain as its sender chain keyed by its signed prekey |
| **Layer** | signal |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/signal` (conversation, responder-first tests) |
| **Related findings** | PF-050, PF-054, PF-058 |
| **Notes** | libsignal `session/Session.go` `ProcessBundle`: `AddReceiverChain(theirRatchetKey = signed prekey, X3DH chain)` then a fresh `sendingRatchetKey` with `rootKey.CreateChain(theirRatchetKey, sendingRatchetKey)` becomes the sender chain and root. `processV3` (responder): `SetSenderChain(ourRatchetKey = signed prekey, X3DH chain)` and the X3DH root. |

## PF-058: Receive ratchet and skipped keys

| Field | Value |
|-------|-------|
| **ID** | PF-058 |
| **Title** | A header with a new ratchet key triggers `receiverChain = root.CreateChain(ourCurrentRatchet, theirNew)` and a fresh sender ratchet `root' = CreateChain(theirNew, newRatchet)`; counters that jump ahead cache skipped message keys (bound 2000), older counters fail |
| **Layer** | signal |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/signal` (multi-round conversation, out-of-order, old counter, future and cache limits) |
| **Related findings** | PF-054, PF-057, PF-059 |
| **Notes** | libsignal `session/SessionCipher.go` `getOrCreateChainKey` performs exactly these two DH steps and sets `previousCounter = max(senderChainIndex-1, 0)`; `getOrCreateMessageKeys` stores keys for `[chainIndex, counter)`, rejects `counter-chainIndex > 2000` (`ErrTooFarIntoFuture`), and uses saved keys when `chainIndex > counter` (`ErrOldCounter`). WhatsCore caps the skipped cache at 1000 (`MaxSkippedKeys`). |

## PF-059: Header fields

| Field | Value |
|-------|-------|
| **ID** | PF-059 |
| **Title** | Each message carries the sender ratchet public key, the previous sending-chain length, and the message counter; the counter starts at 0 per chain |
| **Layer** | signal |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/signal` (header values across ratchet rounds) |
| **Related findings** | PF-058 |
| **Notes** | libsignal `protocol/SignalMessage` serializes version, sender ratchet key, counter, previous counter, ciphertext, MAC. WhatsCore models the header fields but not the wire serialization or SignalMessage MAC yet. |

---

Status update: session initialization, the DH ratchet, skipped keys, and
out-of-order delivery are implemented and tested. SignalMessage
serialization/MAC, payload encryption, prekeys, and durable state remain.
