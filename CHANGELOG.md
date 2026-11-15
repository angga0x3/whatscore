# Changelog

All notable changes, newest first. Releases follow Semantic Versioning; the
project is pre-1.0, so breaking changes happen in minor versions.

## [v0.0.1] — 2026-11-15

First tag. A protocol foundation preview: real transport and Noise against the
live service, everything else proven with vectors and a fake server. Full
statement in [docs/releases/v0.0.1.md](docs/releases/v0.0.1.md).

### Proven live

- WebSocket dial, intro header, and 3-byte frame reassembly (PF-002, PF-003)
- Noise XX handshake with certificate verification against the pinned root
  (PF-004…PF-009), reproduced 4/4
- Registration `ClientPayload` accepted by the server, which answers 679 bytes
  (PF-068)
- `pair-device` stanza decoded to 6 refs with a twelve-token partial table, the
  iq result accepted, and the server's keepalive decoded and answered (PF-069,
  PF-070)

### Added

- `protocol/transport`, `protocol/noise`: dialer, framing, handshake, secure conn
- `protocol/binary`: node codec with injected dictionary, synthetic vectors, fuzz
- `protocol/auth`: registration and login payloads, with mutual rejection
- `protocol/pairing`: QR payload, pair-device/pair-success parsing, identity
  verification
- `protocol/messaging`: JIDs, text and `<enc>` envelopes, receipts
- `protocol/media`: envelope, streaming, and range decryption
- `protocol/signal`: X3DH, Double Ratchet, message crypto, prekey bootstrap,
  state persistence
- `protocol/sync`: patch parsing, mutation decode, LTHash, envelope MACs
- `core/*`: events, session actor, engine orchestration, credentials, prekeys,
  per-peer Signal sessions, messaging, media, contacts, groups, SDK facade
- `storage/*`: envelope encryption, credential vault, PostgreSQL and cgo-free
  SQLite backends
- `server/*`: chi router, API-key auth, sessions/messages/media/webhooks REST,
  SSE streams, signed webhook delivery with retries, rate limiting
- `cmd/whatscore-probe`: read-only live transport probe
- `cmd/tokendict`: token-table provenance and shape validator

### Security

- AES-256-GCM credential envelope with record-bound AAD
- XEdDSA signing validated against libsignal-produced vectors (ADR 0001)
- Pairing gate: a session is only `CONNECTED` after the server's verdict
- Redirects refused, size caps enforced, secrets redacted from logs and JSON

### Known limits

- Sessions are in-memory; a restart clears them
- `WHATSAPP_SESSION_LIMIT` is parsed but not enforced
- The REST message route records; it does not deliver
- Pairing cannot complete: three reply token indices are unobserved

[v0.0.1]: https://github.com/angga0x3/whatscore/releases/tag/v0.0.1
