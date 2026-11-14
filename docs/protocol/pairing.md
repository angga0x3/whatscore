# Pairing findings

Device-pairing payloads of the multi-device flow. Extracted from read-only
reference study of whatsmeow `pair.go` on 2026-11-15; no live pairing run is
recorded yet, so findings stay **Probable**.

## PF-015: QR payload format

| Field | Value |
|-------|-------|
| **ID** | PF-015 |
| **Title** | A pairing QR encodes `https://wa.me/settings/linked_devices#<ref>,<noisePub>,<identityPub>,<advSecret>,<clientType>` with base64 (standard, padded) 32-byte keys |
| **Layer** | pairing |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/pairing` (golden QR, round-trip) |
| **Related findings** | PF-004 (Noise static key), PF-016 (planned) |
| **Notes** | whatsmeow `makeQRData(ref, clientType)`: `fmt.Sprintf("https://wa.me/settings/linked_devices#%s,%s,%s,%s,%s", ref, base64(noisePub), base64(identityPub), base64(advSecret), clientType)`. `ref` is the raw content of a `<ref>` child in the server's `<pair-device>` node (typically ASCII). `clientType` is an opaque enum value; it may be empty when unknown. QR rendering is a caller concern. |

## PF-016: pair-device and pair-success stanzas

| Field | Value |
|-------|-------|
| **ID** | PF-016 |
| **Title** | The server sends `<iq><pair-device><ref>…</ref></pair-device></iq>`; the client acks with an iq result, and pairing completes with `<iq><pair-success>` carrying `device@jid`, `device@lid`, `biz@name`, `platform@name`, `client-props` bytes, and `device-identity` bytes |
| **Layer** | pairing |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/pairing` (stanza table, binary round-trip) |
| **Related findings** | PF-015 |
| **Notes** | whatsmeow `handlePairDevice` acks with `iq{to: from, id, type: result}` and skips non-`ref` children; `handlePairSuccess` reads the iq `id`, the `pair-success` child, and its `device` (`jid`, `lid`), `biz` (`name`), `platform` (`name`), `client-props`, and `device-identity` children. `device-identity` is an `ADVSignedDeviceIdentityHMAC` protobuf: HMAC-SHA256 over `details` with the adv secret, then account/device XEdDSA signatures. WhatsCore currently returns those bytes opaque; verification and credential provisioning are pending. |

---

Status: QR payload construction/parsing and the pair-device/pair-success
stanza parsers are implemented and proven with synthetic keys and nodes. The
device-identity authentication, credential provisioning, and a live pairing
run remain.
