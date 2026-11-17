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
| Pairing reply decoded | **supported** | with the partial table in `deployments/tokendict`, the live stanza decodes to 6 refs and the iq result is accepted (PF-069) |
| Pairing stanza + keepalive | **supported** | pair-device decoded to 6 refs, ack accepted, keepalive pings decoded and answered (PF-069/PF-070) |
| Pairing (QR → success) | **supported** | a phone scan produced a verified `pair-success`, `pair-device-sign` was accepted, and credentials were written (PF-075) |
| Login with paired credentials | **supported** | reconnects with the login payload and the server answers `<success>` (PF-077, PF-078) |
| Binary node encoding | **supported** | with a completed token table the live stanzas decode (PF-069, PF-087) |
| Send a text message | **supported** | the server acknowledges a real message stanza and attaches a timestamp (PF-082, PF-083) |
| Receive a text message | **supported** | live queue drain: pkmsg bootstrap, decrypt, render, delivery receipt, ratchet persisted (PF-087) |
| Receive media | **supported** | a phone-sent sticker decrypted, downloaded from the CDN, passed SHA-256, and landed as a 51 KB WebP (2026-11-16) |
| Send media | **partially proven** | upload accepted live 2026-11-17 (HTTP 200, url + direct_path) and a media-class message was acknowledged; probe and REST both send; phone rendering unproven (PF-092) |
| Own-device copy of a send | **untested live** | implemented in the probe and the REST runtime (PF-090); the copy needs a session with the phone, and no live run has shown it on the phone yet |
| App-state sync | **supported** | 11 key shares, 15 patches, 39/39 mutations verified and decoded live (2026-11-16) |

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

In its default mode the probe never pairs, never authenticates, never sends a
message, and never persists a key. If it reports `server-rejected`, the first
diverging layer is the one in `detail`.

Its `-pair` and `-login` modes are the exceptions and are manual by design.
`-pair` contacts the server with fresh keys, renders a QR from the refs the
server sends, and — if a phone scans one — verifies `pair-success`, completes
the link, and writes credentials. `-login` reconnects with those credentials and
reports the server's verdict. Both need a token table and a dedicated number;
see `docs/pairing-manual.md`.

## What this matrix deliberately does not say

It does not say WhatsApp works. Messaging and media are the rows that matter for
real use, and they are still `untested`: nothing in this project has sent or
received a message. Anyone reading this should treat a `supported` cell as
"proven for this build, on this date, by
this test" — not as a compatibility promise.
