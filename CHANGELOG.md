# Changelog

All notable changes, newest first. Releases follow Semantic Versioning; the
project is pre-1.0, so breaking changes happen in minor versions.

## [Unreleased]

### Added

- The REST send path now sends the own-device copy too: `DeliverText` builds
  the `DeviceSentMessage` for the phone after the recipient's copy, under the
  same message id, over the ratchet the phone's messages bootstrapped. The
  copy is best effort — a device that has never heard from the phone has no
  ratchet to ride, and the recipient's copy has already gone out.
- The server persists Signal ratchets across restarts. Every session the
  receiver installs or advances, and every ratchet a send advances, is written
  to the credential vault through `core/signalsession`; `restoreSessions`
  installs them before the first frame is read. Before this, every restart
  re-initiated a prekey session and orphaned the chain the peer was answering
  on — the server-side form of the PF-087 redelivery.
- `core/signalsession.Manager.Peers` and the peer index it reads: the store
  is a key/value vault with no enumeration, and a restore has to know which
  peers exist. The index is written after each record, so an entry without a
  record is skipped on load and a record is never invisible.
- The own-device copy of a 1:1 send. whatsmeow's `marshalMessage` builds two
  plaintexts for every direct message: the recipient's, and a
  `DeviceSentMessage{destinationJID, message}` copy encrypted to the account's
  other devices. `-send` now sends that second copy over the ratchet the
  phone's messages bootstrapped, so a message this device sends appears on the
  phone in the destination chat instead of nowhere. Without a stored session
  with the phone the copy is skipped and reported: a bundle fetch for the own
  account is not served, so there is nothing else to encrypt to. Not yet
  proven live.
- `DeviceSentMessage` in the message protobuf (field 31, `destinationJID` 1,
  `message` 2), `EncodeDeviceSentMessage` to build the copy, and unwrapping on
  the receive side. A decrypted copy is published in the chat its
  `destinationJID` names, as outgoing, with the sending device as its sender —
  the shape the account's other devices see for this device's sends.
- Peer-addressed message stanzas: a device-qualified `to` is now legal when
  the caller means exactly one device (the own-device copy, a retry), carries
  `device_fanout="false"`, and is still refused for ordinary sends where the
  server must fan out to the account's devices (PF-090).
- `-send` restores the stored sessions before encrypting and writes the
  advanced ratchet back after sending. The receiver's session observer covers
  decrypts only, so the send path used to leave the store one step behind: the
  next run encrypted from a chain the peer had already left, and every send
  re-initiated a prekey session against a peer this device was already talking
  to.

### Fixed

- App state sync keys are stored in the credential vault. The runtime wrote
  them to a filesystem path derived from the vault key name
  (`sessions/<id>/appstate.keys.json`), so they either failed to persist — the
  directory does not exist — or, worse, landed in plaintext outside the vault.
  They now travel through the same encrypted store as every other secret and
  are restored at construction.
- Media arriving on an established session is published. The msg carrier —
  every message after the first in a conversation — decoded text only, so an
  image, sticker or voice note that decrypted cleanly was dropped as "no text
  payload". Both carriers now classify through `DecodePayload`.

### Added

- `whatscore-probe -dump <frame.bin> -dict <table>` decodes one saved
  `undecoded/*.bin` frame. Holes in the table are filled with placeholders that
  name their slot (`¿s153`, `¿d0[56]`), so a frame the table almost covers still
  shows its shape and names the exact entries to record.
- `-listen` traces every stanza before interpretation and asks the server how
  many one-time prekeys it holds. "Nothing arrived" and "something arrived and
  was rejected" are no longer the same observation, and "published" now has a
  server-side answer instead of a key-file assertion.

### Added

- Provisioning completes and the phone releases the "keep both apps open"
  banner. The full sequence ran live after a fresh pairing: login → prekey
  top-up (the count query answered) → app state sync request → the phone
  pushed 11 key shares unprompted → 15 patches fetched, 39/39 mutations
  verified and decoded, zero skipped → history chunks ACK'd with hist_sync
  receipts, each confirmed by the server. The offline queue drained with its
  marker on the same run.
- Live media receive, proven end to end: after a fresh pairing, a sticker
  sent from the phone arrived, decrypted, downloaded from the real CDN,
  passed the SHA-256 check, and landed on disk as a valid 51 KB WebP — the
  pipeline's first live artifact. Five note-to-self texts decrypted in the
  same run (the fresh device's keys make the phone's messages bootstrap
  cleanly), and the offline queue drained with its marker.
- Inbound media flows through the server: the session runtime fetches the
  attachment from the CDN (mediaConn hosts, the whatsmeow URL shape, MAC and
  SHA-256 verified), re-encrypts it at rest with a fresh media key — the
  exact shape the upload routes store — and lands it in the API media store.
  GET /sessions/{id}/media lists what arrived; downloads are deduped per
  message id and never block the read loop.
- The server delivers. POST /sessions/{id}/messages/text now sends over the
  session connection — an established ratchet continues it, first contact
  fetches the peer's prekey bundle and initiates — and stores the message
  under the wire id, so receipts and events correlate with the REST entry.
  Inbound messages land in the same store (GET /sessions/{id}/messages now
  reflects what the session actually received), and without a deliverer the
  route keeps its record-only behavior.
- The server pairs over REST. POST /sessions/{id}/connect on an unpaired
  session runs the whole exchange inside one Connect: registration payload →
  QR codes streamed on GET /sessions/{id}/qr → scan → pair-success verified
  and signed (pair-device-sign written, PF-073) → credentials persisted
  (vault-sealed) → a fresh connection logs in (PF-077's two-connection shape)
  → CONNECTED.
- A connected server session finally hears: the factory passes a session
  runtime as the FrameHandler — decoded stanzas, keepalive answers, the
  offline batch answer (PF-087), the receiver fed with the session's key
  material, retry receipts with inline keys on failures, delivery receipts
  after successful decrypts, and the post-connect sequence (active, presence,
  prekey pool top-up). core/session discards frames by design; without this
  handler a connected session heard nothing.
- A message this device cannot open is not a dead end. The receiver exposes
  `SetDecryptFailureHandler`, and the probe answers every failure with the
  retry receipt whatsmeow sends (receipt `type="retry"` + `<retry count id t
  v=1>` + `<registration>`, capped at three per message id) — carrying the
  inline `<keys>` block (a fresh one-time prekey persisted before the wire,
  the signed prekey, the identity key, the paired device identity). The live
  response was immediate: the phone re-encrypted within seconds of the first
  receipts. The inline keys matter because the sender re-encrypts with its
  cached bundle — the very bundle that produced the unreadable message — and
  its re-encryption arrives under a new message id, so waiting for a second
  attempt never fires.
- The probe persists Signal sessions (`<creds>.sessions.json`, 0600). A
  bootstrapped ratchet is a one-way door: the phone continues it with
  msg-carrier messages, and a run that does not restore the state loses every
  one of them. The receiver's `SetSessionObserver` writes installs and ratchet
  advances; startup restores before reading.
- `-listen` marks the device available (`<presence type="available"/>`) after
  login, like whatsmeow. Without it every stanza the probe ever saw was
  offline-queue replay; live fan-out never started.

### Fixed

- Encrypted media stanzas were rejected before decryption: the live service
  stamps `type="media"` on them, and the envelope parser gated on `"text"`.
  Every sticker, image and voice note queued for this device died in the
  parser (PF-089). The gate now accepts both observed transport types and
  leaves the payload kind to DecodePayload.
- The empty one-time prekey store is why senders drift to the signed prekey
  and why every queued message came to name one spent key (108). `-listen`
  now tops the server up with a fresh id batch when the count hits zero,
  private halves written to disk before the upload, and re-tests the "repeat
  upload is refused" reading in PF-082 with the server's own count as the
  verdict — the repeat upload was answered with silence again.
- `-listen` now answers the server's `<ib><offline_preview/>` announcement with
  `<ib><offline_batch count="100"/>` and treats `<ib><offline/>` as the drain
  marker. The queue stays frozen until the client names a batch size, so a
  listen run that ignored the announcement was a client the server never
  delivered to — the strongest remaining PF-087 candidate. A queue that is
  announced but never drained is now reported as such when the window ends,
  instead of passing as "listen window ended".
- The offline announcement also rides on counter values the table has never
  observed (`message=¿d1[158]`, `receipt=¿d2[126]` — the counts grow with the
  queue, so they come as dictionary refs). A strict decode failed the whole
  stanza on one unknown value, and the queue it announced was never answered.
  An `<ib>` that decodes with placeholder holes is now routed by its shape —
  `<ib>` is server-state routing, not user data — with the holes printed so the
  table can be completed. Every other tag keeps the loud failure.
- The inbound peer is the sender, not the recipient: sessions were keyed and
  events published on `to`, which only worked against a fake node that happened
  to be symmetric. The live service omits `to` on inbound stanzas entirely, so
  the envelope parser required the one attribute the wire does not carry.
- The service pads v2 plaintexts with N copies of the byte N (whatsmeow
  `padMessage`/`unpadMessage`); the receive path now strips it before parsing
  and the send path adds it before encrypting. The trailing pad bytes are not
  protobuf — they are how payloads that decrypted cleanly still came back as
  wire-format errors. The msg-carrier send path also carries the protobuf
  payload now; it encrypted the raw string.

### Proven live

- Live receive, end to end, including a third party: with the token table
  completed, two queued text messages from a real contact bootstrapped pkmsg
  sessions, decrypted, rendered their text ("uy", "nng kamar", "ngpo", …) and
  earned delivery receipts; six messages total decrypted in one run, the last
  arriving while the listener was connected. The ratchet state persisted to
  disk mid-run (`paired.keys.sessions.json`).
- The offline queue drains. A 2026-11-15 session answered the announcement and
  the backlog streamed: 21 `message` stanzas with a delivery receipt for each,
  plus notifications, statuses and newsletter plaintexts. The queue count moves
  between sessions (123 → 118 → 121), so deliveries are being counted.
- Signal sessions bootstrap from live `pkmsg` carriers and decrypt: three
  messages from the phone opened cleanly at the crypto layer. Their payloads
  then failed on the padding, which is fixed above; the same messages cannot be
  retried against the live service, because a consumed prekey is gone and a
  probe is stateless — the bootstrap in a later run references a key the
  earlier run spent.
- The server reports holding 0 one-time prekeys where it held 11 earlier the
  same day. That is what one-time prekeys are for: senders consumed them. The
  server can still encrypt to the signed prekey.
- A note-to-self sent from this device (`-send` to the user's own JID) is
  accepted and acknowledged but is not echoed back to the sending device — the
  phone gets it, the linked device does not.


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
