# Changelog

All notable changes, newest first. Releases follow Semantic Versioning; the
project is pre-1.0, so breaking changes happen in minor versions.

## [Unreleased]

### Added

- `whatscore-probe -dump <frame.bin> -dict <table>` decodes one saved
  `undecoded/*.bin` frame. Holes in the table are filled with placeholders that
  name their slot (`¿s153`, `¿d0[56]`), so a frame the table almost covers still
  shows its shape and names the exact entries to record.
- `-listen` traces every stanza before interpretation and asks the server how
  many one-time prekeys it holds. "Nothing arrived" and "something arrived and
  was rejected" are no longer the same observation, and "published" now has a
  server-side answer instead of a key-file assertion.

### Fixed

- `-listen` now answers the server's `<ib><offline_preview/>` announcement with
  `<ib><offline_batch count="100"/>` and treats `<ib><offline/>` as the drain
  marker. The queue stays frozen until the client names a batch size, so a
  listen run that ignored the announcement was a client the server never
  delivered to — the strongest remaining PF-087 candidate. A queue that is
  announced but never drained is now reported as such when the window ends,
  instead of passing as "listen window ended".
- The token table now covers the `<ib><offline_preview/>` announcement:
  `single[153]` (the `message`/`notification` counts) and `dictionary0[56]`
  (`count`). The stanza that announces the PF-087 queue was itself landing in
  `undecoded/` and being dropped silently.

### Proven live

- The PF-087 queue announcement decodes: `count=107 message=26 receipt=37
  notification=26` in the 2026-11-15 run. The server announces its queue in a
  stanza this project could not read when PF-087 was first recorded.
- The server reports holding 11 one-time prekeys for this device. The prekey
  upload was accepted, so "the server cannot encrypt to us" is eliminated as a
  PF-087 cause.

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
- The paired device no longer identifies itself as `whatsmeow`. `DeviceProps.os`
  was a literal copied from the reference, and it is what the phone showed
  inside the parentheses: **"Google Chrome (whatsmeow)"**. It now reads
  `"Google Chrome (whatscore)"` (PF-079). Existing pairings keep the old label,
  because `DeviceProps` is only sent at pairing time (PF-080).

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
- A real text message was accepted by the server, which answered
  `<ack class="message">` with a server timestamp.

### Added

- `whatscore-probe -login -creds <file> [-dict <table>]` reconnects with a
  paired device's credentials and reports the server's verdict.
- `whatscore-probe -send -creds <file> -to <jid> -text <text>` sends one text
  message: fetches the peer's prekey bundle, verifies its signature, builds the
  Signal session, and waits for the server's acknowledgement.
- `whatscore-probe -listen -creds <file>` decrypts inbound messages and answers
  with delivery receipts.
- A persistent key file (`paired.keys.json` by default) holds the private halves
  of published prekeys, because a peer may encrypt to them at any later date.

### Fixed

- Text is sent and read as a protobuf `Message` (`conversation`), not as raw
  bytes in a `<body>` child. The old carrier was accepted and acknowledged by
  the server but rendered nothing on a phone (PF-083).
- The pairing run no longer discards the private half of the signed prekey it
  registers. Losing it made every message sent before the next rotation
  unreadable — the live backlog failed with `bad message MAC` for exactly this
  reason (PF-085).
- A dispatcher now owns the connection's single read loop. Previously each step
  read for itself and silently discarded whatever else arrived, which is how the
  inbound backlog was thrown away during a send.

### Changed

- `-listen` reported a dead connection as "listen window ended". It now fails
  with the transport error, which is how an evicted session (PF-086) stops
  looking like a quiet one.
- The probe's receiver logs at debug level instead of discarding. A dropped
  `bad message MAC` and "no message arrived" were previously the same
  observation, which made the first live receive attempt undiagnosable
  (PF-088).

### Known limits

- Sending is proven: the server acknowledged a real text message and attached a
  timestamp.
- Receiving is proven in test, not live. The inbound messages already queued on
  the server were encrypted to a signed prekey whose private half the pairing
  run discarded, so they cannot be opened. Messages sent to this device **after**
  a run that wrote its key file can be decrypted; that has not yet been shown
  against the live service.
- Live receive has **not** been demonstrated. The server announced a queue of
  24 messages, the socket stayed up for three minutes, and none were delivered
  (PF-087). The cause is not established. The earlier theory — that a repeated
  prekey upload was being refused — was wrong: the upload request was malformed
  (two-byte key ids instead of three), which is now fixed and acknowledged.
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
- A real text message was accepted by the server, which answered
  `<ack class="message">` with a server timestamp.


### Known limits

- Sessions are in-memory; a restart clears them
- `WHATSAPP_SESSION_LIMIT` is parsed but not enforced
- The REST message route records; it does not deliver
- Pairing cannot complete: three reply token indices are unobserved

[v0.0.1]: https://github.com/angga0x3/whatscore/releases/tag/v0.0.1
