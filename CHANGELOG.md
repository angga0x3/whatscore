# Changelog

All notable changes, newest first. Releases follow Semantic Versioning; the
project is pre-1.0, so breaking changes happen in minor versions.

## [Unreleased]

### Fixed

- The pairing payload now carries a real XEdDSA signed-prekey signature. It
  previously carried 64 zero bytes, which is the correct length and therefore
  passed local validation, but is not a signature the server can verify against
  `eIdent` (PF-072).
- Pairing runs now rotate the six QR codes instead of printing them at once.
  Only one code is valid at a time — 60 s for the first, 20 s for each of the
  rest (PF-074).
- `pair-success` is now confirmed with `pair-device-sign`, without which the
  phone never finishes linking a verified device (PF-073).
- `protocol/auth` round-trips `DeviceProps.historySyncConfig`. The marshaller
  emitted it and the parser discarded it, so building a payload and parsing it
  back silently lost the capability block.
- Undecodable stanzas are written to `undecoded/*.bin`. The raw frame is the
  only record of a stanza that took a phone scan to produce.

### Changed

- A web QR login reports `DeviceProps.platformType = CHROME`, matching the
  client-type field `1` the QR already carried (PF-071).

### Proven live

- A phone scan of a WhatsCore-generated QR produced a real `pair-success`. Its
  account-identity HMAC verified against the adv secret from that QR and its
  account signature against that QR's identity key (PF-075).
- The `pair-success` stanza decodes: nine tokens the `pair-device` set lacked
  were recovered from the saved frame and cross-checked with a second decoder
  (`deployments/tokendict/pairing-minimal.json`).
- An unconfirmed `pair-success` is followed by `<stream:error>` and then
  `<xmlstreamend>` — the mechanism behind the phone's generic refusal (PF-076).
- A paired device can log in: reconnecting with the login ClientPayload earns
  `<success>` from the server (PF-077). This is the step that stops the phone's
  linking spinner, and it was missing entirely.

### Added

- `whatscore-probe -login -creds <file> [-dict <table>]` reconnects with a
  paired device's credentials and reports the server's verdict.

### Known limits

- No message has been sent or received. Pairing and login are proven; the Signal
  session layer on a live connection is not.
- The token table is partial by design: it covers only what the server has
  actually sent to this project, and any other stanza still fails loudly.

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

- A paired device can log in: reconnecting with the login ClientPayload earns
  `<success>` from the server (PF-077). This is the step that stops the phone's
  linking spinner, and it was missing entirely.


### Known limits

- Sessions are in-memory; a restart clears them
- `WHATSAPP_SESSION_LIMIT` is parsed but not enforced
- The REST message route records; it does not deliver
- Pairing cannot complete: three reply token indices are unobserved

[v0.0.1]: https://github.com/angga0x3/whatscore/releases/tag/v0.0.1
