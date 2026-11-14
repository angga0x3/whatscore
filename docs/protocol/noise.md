# Noise findings

Findings for the WhatsApp transport-encryption handshake ("Noise-mode":
Noise_XX_25519_AESGCM_SHA256-inspired, with WhatsApp-specific deviations
from the standard Noise cipherstate — the handshake key is derived from the
running hash, not from a standard MixKey chain). Extracted from read-only
reference study of two independent, known-working implementations (see
Sources); cross-validated between whatsmeow (2025 rewrite) and Baileys
`noise-handler`.

Algorithm-internal findings (state machine semantics) are Confirmed by
deterministic vector tests (independently generated reference values);
live-server-facing aspects stay Probable until manual interop.

## PF-004: Handshake initialization and hash chain

| Field | Value |
|-------|-------|
| **ID** | PF-004 |
| **Title** | Initial hash `h0` is the raw 32 bytes `"Noise_XX_25519_AESGCM_SHA256\0\0\0\0"`; the chain is `h = SHA256(h ‖ data)` over the conn header, both ephemerals, and every ciphertext |
| **Layer** | noise |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Confirmed |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/noise` vector tests (h-chain values matched against independently generated reference vectors) |
| **Related findings** | PF-005, PF-007 |
| **Notes** | The pattern string is 28 ASCII chars; both references append four NUL bytes to reach 32 and use the result RAW (not hashed again): whatsmeow `NoiseStartPattern = "Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00"` (len==32 → used as-is), Baileys `NOISE_MODE = 'Noise_XX_25519_AESGCM_SHA256\0\0\0\0'` (len==32 → used as-is). This matches the Noise spec rule "h = protocol_name zero-padded to 32 bytes when shorter than 32". Authenticate order observed: `Authenticate(connHeader)`, `Authenticate(clientEphemeral)` before msg1; `Authenticate(serverEphemeral)` before first decrypt; `Authenticate(ciphertext)` after every handshake encrypt/decrypt. |

## PF-005: Handshake AEAD operations

| Field | Value |
|-------|-------|
| **ID** | PF-005 |
| **Title** | Handshake encrypt/decrypt = AES-256-GCM, key = current handshake key (initially `h0`), nonce = 12-byte counter (BE32 counter in bytes 8–11, bytes 0–7 zero), AAD = running hash `h`; counter resets on every key mix |
| **Layer** | noise |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Confirmed |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/noise` vector tests (ciphertexts matched against independently generated reference vectors); `tests/integration` handshake round-trip |
| **Related findings** | PF-004, PF-006 |
| **Notes** | Both references: whatsmeow `Encrypt`/`Decrypt` with `generateIV(counter)` and `nh.hash` as additional data, `counter` incremented per operation and reset in `MixIntoKey`; Baileys `generateIV(counter++)` with `hash` as AAD and identical IV layout (`iv[8..11] = counter BE32`). Decryption failures abort the handshake. |

## PF-006: Key mixing (HKDF)

| Field | Value |
|-------|-------|
| **ID** | PF-006 |
| **Title** | After each DH: `(write, read) = HKDF-SHA256(ikm=X25519(dh_priv, dh_pub), salt=salt, info=∅, L=64)`; then `salt = write`, handshake key = `read`, counter = 0 |
| **Layer** | noise |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Confirmed |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/noise` vector tests (key schedule values matched against independently generated reference vectors) |
| **Related findings** | PF-005, PF-007 |
| **Notes** | DH sequence (client side): `ee` = X25519(eph_priv, server_ephemeral) after msg2's ephemeral is hashed; `es` = X25519(eph_priv, decrypted_server_static); `se` = X25519(noise_priv, server_ephemeral) after encrypting the client static. Both references agree on output order: first 32 bytes = write/salt, second 32 bytes = read/key. |

## PF-007: Handshake message sequence

| Field | Value |
|-------|-------|
| **ID** | PF-007 |
| **Title** | Three protobuf `HandshakeMessage` frames: msg1 `clientHello{ephemeral}` (plaintext), msg2 `serverHello{ephemeral, static, payload}`, msg3 `clientFinish{static = Enc(noisePub), payload = Enc(ClientPayload)}` — the frames themselves are never encrypted, only their inner fields |
| **Layer** | noise |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Confirmed |
| **Status** | Verified-by-test |
| **Proving test** | `tests/integration` fake-server handshake round-trip (full msg1→msg3 sequence over framed transport) |
| **Related findings** | PF-003, PF-004, PF-008 |
| **Notes** | Protobuf shape (field numbers verified against whatsmeow `proto/waWa6/WAWebProtobufsWa6.proto`): `HandshakeMessage{clientHello=2, serverHello=3, clientFinish=4}`, `ClientHello{ephemeral=1}`, `ServerHello{ephemeral=1, static=2, payload=3}`, `ClientFinish{static=1, payload=2}`. The decrypt counter starts at msg2.static; encrypt counter starts at msg3.static. whatsmeow uses a 20s timeout for the msg2 response. The real `ClientPayload` (registration/login data) is Phase 3 territory; Phase 1 sends an empty payload against the fake server. A newer WhatsApp "extended"/PQ handshake mode exists in the proto schema (`pqMode`, `extended*` fields) — WhatsCore implements the classical XX path only, recorded for future drift handling. |

## PF-008: Transport key derivation and post-handshake framing

| Field | Value |
|-------|-------|
| **ID** | PF-008 |
| **Title** | Final keys: `(write, read) = HKDF-SHA256(ikm=∅, salt=salt, info=∅, L=64)`; client writes with `write`, reads with `read`; per-direction counters from 0; AAD empty; frames keep the PF-003 3-byte length prefix with ciphertext payloads |
| **Layer** | noise |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Confirmed |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/noise` vector tests (final keys matched against independently generated reference vectors); `tests/integration` post-handshake encrypted frame exchange |
| **Related findings** | PF-003, PF-006 |
| **Notes** | whatsmeow `Finish` → `extractAndExpand(salt, nil)`; Baileys `finishInit` → `localHKDF(new Uint8Array(0))`. Transport `TransportState` (Baileys) keeps independent read/write counters with the same 12-byte counter IV layout as PF-005 but empty AAD. Server perspective swaps write/read. |

## PF-009: Server certificate chain

| Field | Value |
|-------|-------|
| **ID** | PF-009 |
| **Title** | msg2.payload decrypts to a protobuf `CertChain{leaf=1, intermediate=2}`; each certificate is `{details=1, signature=2}` with `Details{serial=1, issuerSerial=2, key=3, notBefore=4, notAfter=5}`; signatures are 64-byte XEdDSA over the details bytes, chained to a pinned 32-byte root key; leaf.key must equal the decrypted server static |
| **Layer** | noise |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Confirmed |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/noise` cert verification tests (positive path against a synthetic chain signed by a test root; negative paths: tampered signature, wrong root, expired window, static mismatch) |
| **Related findings** | PF-007 |
| **Notes** | Root public key (public constant, from whatsmeow `handshake.go` `WACertPubKey` and Baileys `WA_CERT_DETAILS.PUBLIC_KEY`, identical): `142375574d0a587166aae71ebe516437c4a28b73e3695c6ce1f7f9545da8ee6b`. Validation chain: root verifies intermediate.details; intermediate.key verifies leaf.details; intermediate.issuerSerial == 0; leaf.issuerSerial == intermediate.serial; leaf.key == decrypted server static; `notBefore ≤ now ≤ notAfter`. Signatures are XEdDSA (Curve25519 keys, Ed25519-style 64-byte signatures): verification derives the Edwards y-coordinate `y = (u−1)/(u+1) mod p` from the Montgomery key and verifies with standard Ed25519. Proto schema source: whatsmeow `proto/waCert/WACert.proto`. |

---

Status: recorded 2026-11-15 from reference study (whatsmeow `main`,
Baileys `master`). Vector tests and the fake-server round-trip prove the
state machine; live-server confirmation of PF-002/PF-003 pending manual
interop (Phase 3).
