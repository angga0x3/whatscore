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

---

Status: QR payload construction/parsing implemented and proven with synthetic
keys; the `<pair-device>`/`<pair-success>` exchange (PF-016+) is not
implemented yet. No real pairing attempt has been recorded.
