# Compatibility matrix

What is proven, against what, and how to reproduce it. Cells are
`supported` / `broken` / `unknown` / `untested` (spec §7.2). `supported`
requires a green test; anything measured against the live service names the
run.

## Against the live WhatsApp endpoint

| Capability | State | Evidence |
|------------|-------|----------|
| WebSocket dial + headers | **supported** | `cmd/whatscore-probe`, 4/4 runs, 2026-11-15 |
| Intro header + frame reassembly | **supported** | same runs |
| Noise handshake (msg1→msg3) | **supported** | same runs, suite `Noise_XX_25519_AESGCM_SHA256` |
| Server certificate chain | **supported** | same runs (pinned root verified) |
| Auth payload accepted | **supported** | live: `whatscore-probe -payload` builds a real registration payload and the server answers 679 bytes (PF-068) |
| Pairing reply decoded | **supported** | with the nine-token partial table in `deployments/tokendict`, the live stanza decodes to 6 refs and the iq result is accepted (PF-069) |
| Pairing stanza + keepalive | **supported** | pair-device decoded to 6 refs, ack accepted, keepalive pings decoded and answered (PF-069/PF-070) |
| Pairing (QR → success) | **in progress** | scannable QR with rotation works live; one phone attempt was refused, and it exposed three fixed defects (PF-072…PF-074); `pair-success` still unobserved |
| Binary node encoding | **unknown** | no real token table ships (spec §10.2) |
| Message send/receive | **untested** | needs pairing |
| Media upload/download | **untested** | needs pairing + an upload endpoint |
| App-state sync | **untested** | needs pairing |

## Against the fake server (in-repo)

| Capability | State | Evidence |
|------------|-------|----------|
| Handshake round-trip | **supported** | `tests/integration`, `protocol/noise` |
| Encrypted frame exchange | **supported** | `protocol/noise`, `core/messaging` |
| Signal session bootstrap (inbound + outbound) | **supported** | `core/messaging`, `core/client` |
| Pairing stanzas + identity verification | **supported** | `protocol/pairing`, `core/engine` |
| Media envelope (buffered/streaming/range) | **supported** | `protocol/media` |
| App-state patch decode + LTHash | **supported** | `protocol/sync` |
| REST sessions/messages/media/webhooks/SSE | **supported** | `server/api` |

## How to reproduce the live result

```bash
go run ./cmd/whatscore-probe -timeout 25s
# endpoint: wss://web.whatsapp.com/ws/chat
# outcome:  handshake-completed
```

The probe never pairs, never authenticates, never sends a message, and never
persists a key. If it reports `server-rejected`, the first diverging layer is
the one in `detail`.

Its `-pair` mode is the exception and is manual by design: it contacts the
server with fresh keys, renders a QR from the refs the server sends, and — if a
phone scans one — verifies `pair-success`, completes the link, and writes
credentials. It needs a token table and a dedicated number; see
`docs/pairing-manual.md`.

## What this matrix deliberately does not say

It does not say WhatsApp works. The bottom two rows of the live table are the
ones that matter for real use, and they are `untested`. Anyone reading this
should treat a `supported` cell as "proven for this build, on this date, by
this test" — not as a compatibility promise.
