# Protocol Findings — Provenance Policy

Every claim WhatsCore makes about the WhatsApp Web protocol lives in this
folder as a **finding**: a small, dated record stating what was observed,
where the observation came from, how confident the project is about it, and
which test proves it.

## Why this exists

- The WhatsApp Web protocol is **proprietary and unpublished**. There is no
  spec to cite, so the project's credibility rests entirely on verifiable
  documentation: anyone should be able to trace every protocol constant in
  the codebase back to an observation and forward to a green test.
- **The engine may only rely on findings with test evidence.**
  Implementation code depends on Confirmed findings only — folklore, forum
  posts, and unverified observations do not enter the codebase (see
  [CONTRIBUTING.md](../../CONTRIBUTING.md), architecture rule 6).
- **Protocol versions drift.** WhatsApp ships changes without notice and
  without changelogs, so every finding is dated and has a lifecycle (below).
  An old finding is not wrong — but it may describe a protocol that no
  longer exists, which is why findings are reopened and retired rather than
  treated as permanent truth.

Compatibility is proven by tests, never claimed in prose. This folder
documents what we know; the test suite proves it.

## Finding record format

Each finding is one section using the exact record below. Copy
[TEMPLATE.md](TEMPLATE.md) — do not invent field variants.

| Field | Meaning |
|-------|---------|
| **ID** | `PF-NNN` — three digits, sequential, never reused |
| **Title** | One specific line: the protocol behavior this record describes |
| **Layer** | `transport` / `noise` / `binary` / `auth` / `pairing` / `messaging` / `signal` / `sync` / `media` |
| **Source** | One of: `direct observation of own session` · `captured handshake of own device` · `derived from test` · `inferred` |
| **Observed date** | Date of the observation(s) backing the record, `YYYY-MM-DD`; updated when the finding is reopened |
| **Confidence** | **Confirmed** = proven by automated test · **Probable** = consistent repeated observation · **Speculative** = single observation or inference |
| **Status** | **Verified-by-test** · **Observed-only** · **Retired** |
| **Proving test** | Repo path(s) of the test(s) that prove this finding — `—` if none yet |
| **Related findings** | IDs this record depends on, supersedes, or contradicts |
| **Notes** | Context, caveats, drift history, links to fixtures and captures |

Confidence and Status are deliberately separate axes:

- **Confidence** is epistemics — how sure are we that the observation is true?
- **Status** is bookkeeping — where does the record stand right now?
- A **Confirmed** finding must be **Verified-by-test**: its proving test
  exists and is green. Probable and Speculative findings stay
  **Observed-only** until a test lands.

## Lifecycle rules

- **Implementation code may depend on Confirmed findings only.** Speculative
  and Probable findings may inform experiments, prototypes, and discussions —
  never `protocol/*` code. A finding graduates to Confirmed exactly when a
  test proves it; update Confidence and Status in the same PR.
- **Exception — Probable wire/payload work (PF-010…PF-017,
  PF-020…PF-025, PF-030…PF-036, PF-040…PF-048, PF-057…PF-059,
  PF-064, PF-065, PF-066, PF-070…PF-072, PF-074, PF-076).** Framing, binary encoding,
  pairing payloads, auth/messaging stanza shapes, and the media envelope are
  necessarily implemented before a live connection exists. They may be coded
  while **Probable** because our own codec, synthetic vectors, independent
  reference generators, and per-package round-trips prove the implementation
  matches the record. They must not be described as compatible with the live
  service until a manual interop observation is recorded here. This does not
  apply to new cryptographic primitives: Signal's X3DH/ratchet findings must
  reach Confirmed with known-answer vectors before code depends on them.
- **Findings are never deleted.** When an observation or test contradicts a
  finding, mark it **Retired**, keep its index row, and record the reason
  plus the contradicting evidence in Notes. History stays auditable.
- **Drift reopens, it does not replace.** When the protocol changes and a
  finding no longer holds, reopen it: keep the ID, add the new observation
  date, describe what changed, and downgrade Confidence until a fresh test
  confirms the new shape. The superseded observation stays in Notes.
- **Never edit proven material.** Same rule as fixtures
  ([tests/fixtures/README.md](../../tests/fixtures/README.md)): corrections
  add a new observation or a new record linked via Related findings — they
  do not silently rewrite the old one.

## Findings index

| ID | Layer | Title | Confidence | Status | Proving test |
|----|-------|-------|------------|--------|--------------|
| PF-000 | noise | EXAMPLE (synthetic): handshake frame header layout | Speculative | Observed-only | — |
| PF-001 | transport | EXAMPLE (synthetic): WebSocket keepalive ping cadence | Speculative | Observed-only | — |
| PF-002 | transport | WebSocket endpoint and dial headers | Confirmed | Verified-by-test | `cmd/whatscore-probe` (live dial, 4/4) |
| PF-003 | transport | One-time intro header + 3-byte length framing across WS messages | Confirmed | Verified-by-test | `cmd/whatscore-probe` (live), `protocol/transport`, `tests/integration` |
| PF-004 | noise | Handshake initialization and hash chain | Confirmed | Verified-by-test | `protocol/noise` (vectors) |
| PF-005 | noise | Handshake AEAD operations (AES-256-GCM, counter IV, hash AAD) | Confirmed | Verified-by-test | `protocol/noise` (vectors, handshake), `tests/integration` (fake server) |
| PF-006 | noise | Key mixing via HKDF after each X25519 | Confirmed | Verified-by-test | `protocol/noise` (vectors) |
| PF-007 | noise | Handshake message sequence (protobuf frames, msg1–msg3) | Confirmed | Verified-by-test | `protocol/noise` (handshake round-trip), `tests/integration` (fake server) |
| PF-008 | noise | Transport key derivation and post-handshake framing | Confirmed | Verified-by-test | `protocol/noise` (vectors, conn), `tests/integration` (fake server) |
| PF-009 | noise | Server certificate chain and XEdDSA signatures | Confirmed | Verified-by-test | `protocol/noise` (cert tests) |
| PF-010 | binary | Frame flag and zlib compression | Probable | Verified-by-test | `protocol/binary` (compressed frame, vectors) |
| PF-011 | binary | Node layout and list encoding | Probable | Verified-by-test | `protocol/binary` (round-trip, vectors) |
| PF-012 | binary | String and byte encodings | Probable | Verified-by-test | `protocol/binary` (vectors, large values) |
| PF-013 | binary | Packed nibble and hex strings | Probable | Verified-by-test | `protocol/binary` (packed tests, vectors) |
| PF-014 | binary | JID wire forms | Probable | Verified-by-test | `protocol/binary` (JID table) |
| PF-015 | pairing | QR payload format | Probable | Verified-by-test | `protocol/pairing` (golden QR, round-trip) |
| PF-016 | pairing | pair-device and pair-success stanzas | Probable | Verified-by-test | `protocol/pairing` (stanza table, binary round-trip) |
| PF-017 | pairing | Device-identity authentication | Probable | Verified-by-test | `protocol/pairing` (identity table) |
| PF-020 | auth | Registration ClientPayload envelope | Probable | Verified-by-test | `protocol/auth`, `protocol/protobuf` (wire fields) |
| PF-021 | auth | ClientPayload.UserAgent schema | Probable | Verified-by-test | `protocol/auth`, `protocol/protobuf` (wire fields) |
| PF-022 | auth | WebInfo and connection metadata | Probable | Verified-by-test | `protocol/auth` (round-trip, validation) |
| PF-023 | auth | DevicePairingRegistrationData encoding | Probable | Verified-by-test | `protocol/auth` (round-trip, validation) |
| PF-024 | auth | DeviceProps schema | Probable | Verified-by-test | `protocol/auth` (round-trip) |
| PF-025 | auth | Registration versus login payloads | Probable | Verified-by-test | `protocol/auth` (validation table) |
| PF-026 | auth | Login ClientPayload envelope | Probable | Verified-by-test | `protocol/auth` (login round-trip) |
| PF-027 | auth | Registration vs login discrimination | Probable | Verified-by-test | `protocol/auth` (mutual rejection) |
| PF-030 | messaging | JID textual grammar | Probable | Verified-by-test | `protocol/messaging` (JID table) |
| PF-031 | messaging | JID normalization | Probable | Verified-by-test | `protocol/messaging` (normalization table) |
| PF-032 | messaging | JID rendering | Probable | Verified-by-test | `protocol/messaging` (round-trip) |
| PF-033 | messaging | `<message>` envelope | Probable | Verified-by-test | `protocol/messaging` (stanza round-trip) |
| PF-034 | messaging | Text payload carrier | Probable | Verified-by-test | `protocol/messaging` (stanza round-trip) |
| PF-035 | messaging | `<receipt>` stanza | Probable | Verified-by-test | `protocol/messaging` (stanza round-trip) |
| PF-036 | messaging | Encrypted payload envelope | Probable | Verified-by-test | `protocol/messaging` (enc round-trip) |
| PF-040 | media | Media key expansion and key layout | Probable | Verified-by-test | `protocol/media` (independent vectors) |
| PF-041 | media | Media-type HKDF info strings | Probable | Verified-by-test | `protocol/media` (per-type vectors) |
| PF-042 | media | AES-256-CBC with always-on PKCS#7 | Probable | Verified-by-test | `protocol/media` (ciphertext vectors) |
| PF-043 | media | Truncated HMAC-SHA256 over IV and ciphertext | Probable | Verified-by-test | `protocol/media` (MAC vectors) |
| PF-044 | media | Download framing and verification order | Probable | Verified-by-test | `protocol/media` (tamper sweep) |
| PF-045 | media | Media key size, unused expansion tail | Probable | Verified-by-test | `protocol/media` (key vectors) |
| PF-046 | media | Streaming envelope with verify-before-write | Probable | Verified-by-test | `protocol/media` (stream tests) |
| PF-047 | media | Video sidecar hash | Probable | Verified-by-test | `protocol/media` (sidecar vectors) |
| PF-048 | media | Range decryption window and auth contract | Probable | Verified-by-test | `protocol/media` (window sweep, tamper) |
| PF-050 | signal | X3DH master secret and DH order | Confirmed | Verified-by-test | `protocol/signal` (independent vectors) |
| PF-051 | signal | X3DH key derivation | Confirmed | Verified-by-test | `protocol/signal` (root/chain vectors) |
| PF-052 | signal | Initial keys and identifiers | Confirmed | Verified-by-test | `protocol/signal` (agreement tests) |
| PF-053 | signal | Signed-prekey signature | Confirmed | Verified-by-test | `protocol/signal`, `internal/xeddsa` |
| PF-054 | signal | Root ratchet | Confirmed | Verified-by-test | `protocol/signal` (vectors, mirrored DH) |
| PF-055 | signal | Symmetric chain ratchet | Confirmed | Verified-by-test | `protocol/signal` (chained vectors) |
| PF-056 | signal | Message keys | Confirmed | Verified-by-test | `protocol/signal` (key vectors) |
| PF-057 | signal | Session initialization | Probable | Verified-by-test | `protocol/signal` (conversation tests) |
| PF-058 | signal | Receive ratchet and skipped keys | Probable | Verified-by-test | `protocol/signal` (out-of-order tests) |
| PF-059 | signal | Header fields | Probable | Verified-by-test | `protocol/signal` (header tests) |
| PF-060 | signal | SignalMessage framing | Confirmed | Verified-by-test | `protocol/signal` (wire vector), `protocol/protobuf` |
| PF-061 | signal | SignalMessage MAC | Confirmed | Verified-by-test | `protocol/signal` (vector, negatives) |
| PF-062 | signal | SignalMessage payload encryption | Confirmed | Verified-by-test | `protocol/signal` (vector, tamper table) |
| PF-063 | signal | PreKeySignalMessage envelope | Confirmed | Verified-by-test | `protocol/signal` (prekey vector), `protocol/protobuf` |
| PF-064 | signal | Session bootstrap from a prekey message | Probable | Verified-by-test | `protocol/signal` (bootstrap tests) |
| PF-065 | signal | Inbound prekey bootstrap | Probable | Verified-by-test | `core/messaging` (bootstrap + follow-up) |
| PF-066 | signal | Outbound prekey message | Probable | Verified-by-test | `core/messaging` (pkmsg send, responder accept) |
| PF-067 | signal | XEdDSA signing is not Ed25519 signing | Confirmed | Verified-by-test | ADR 0001 investigation (cross-checked against an independent reference) |
| PF-068 | auth | Server answers a complete registration payload | Confirmed | Verified-by-test | `cmd/whatscore-probe -payload` live run |
| PF-069 | pairing | Live pairing exchange decodes with twelve tokens | Confirmed | Verified-by-test | `deployments/tokendict` live run |
| PF-070 | transport | Keepalive, not rejection | Confirmed | Verified-by-test | `deployments/tokendict` live run (pings answered) |
| PF-070 | sync | App-state stanza shape | Probable | Verified-by-test | `protocol/sync` (parse table) |
| PF-071 | sync | SyncdPatch/SyncdMutation schema | Probable | Verified-by-test | `protocol/sync` (wire table) |
| PF-072 | sync | Value blob framing | Probable | Verified-by-test | `protocol/sync` (blob table) |
| PF-073 | sync | Value MAC | Confirmed | Verified-by-test | `protocol/sync` (independent vectors) |
| PF-074 | sync | Snapshot/patch ordering and envelope MACs | Probable | Verified-by-test | `protocol/sync` (ordering) |
| PF-075 | sync | App-state key expansion | Confirmed | Verified-by-test | `protocol/sync` (key expansion) |
| PF-076 | sync | Mutation decode and index MAC | Probable | Verified-by-test | `protocol/sync` (decode round-trip) |
| PF-077 | sync | LTHash accumulator | Confirmed | Verified-by-test | `protocol/sync` (independent expansion vectors) |
| PF-078 | sync | Snapshot/patch envelope MACs | Confirmed | Verified-by-test | `protocol/sync` (MAC vectors) |

> **SYNTHETIC placeholders.** The two rows above exist only so contributors
> can see the intended usage; they describe nothing real. Real findings
> follow them, taking the next unused number.

Rules for this table:

- One row per finding, ordered by ID; Title matches the section title.
- Retired findings keep their row with Status `Retired` — this table is the
  complete history, not a list of current beliefs.

## How to add your first finding

1. Follow the method in
   [../reverse-engineering/README.md](../reverse-engineering/README.md):
   observe your own session, form a hypothesis, build a minimal repro.
2. Extract a synthetic test vector and add a CI test
   ([tests/protocol/README.md](../../tests/protocol/README.md) explains the
   conventions).
3. Copy [TEMPLATE.md](TEMPLATE.md), assign the next free `PF-NNN` ID, fill
   in every field truthfully, and add the matching index row.

No sign-off or permission is needed. A finding is complete when all its
fields are truthful and — if it claims Confirmed — its proving test is green
in CI.

## Data hygiene

- **Never commit real credentials, QR codes, phone numbers, session keys, or
  message content** — not in findings, not in Notes, not in linked captures.
- Evidence lives as **synthetic or anonymous fixtures** under `tests/fixtures/`
  (hex + JSON mirror + provenance), per
  [tests/fixtures/README.md](../../tests/fixtures/README.md).
- Describe real observations in prose with anonymized values. If a finding
  needs byte-exact data, that data must be reconstructable from synthetic
  material alone.

## Cross-links

- [../reverse-engineering/README.md](../reverse-engineering/README.md) — how
  findings are obtained (methodology and ethics rules).
- [../architecture/technical-specification.md](../architecture/technical-specification.md)
  — how findings are consumed by the engine and the version registry.
- [../../tests/fixtures/README.md](../../tests/fixtures/README.md) — where
  the evidence lives.

---

Status: PF-002 and PF-003 were promoted to Confirmed on 2026-11-15 by
`cmd/whatscore-probe`, which completed a live Noise handshake against the real
endpoint (4/4 runs). Everything after the handshake — auth, pairing,
messaging — remains unproven live. Findings recorded from reference study
(whatsmeow + Baileys; see [transport.md](transport.md),
[noise.md](noise.md), [binary.md](binary.md), [pairing.md](pairing.md),
[auth.md](auth.md), [messaging.md](messaging.md),
[media.md](media.md), [signal.md](signal.md), and [sync.md](sync.md)). Algorithm findings are Confirmed by vector tests;
live-server-facing findings (PF-010…PF-017, PF-020…PF-025,
PF-030…PF-035, PF-040…PF-045) stay Probable until manual interop.
`tests/integration` runs the fake-server path end to end (WebSocket dial →
handshake → encrypted frames), which is what the Proving test column cites.
Signal findings PF-050…PF-056 and PF-060…PF-063, and the app-state value MAC
(PF-073) plus key expansion (PF-075), the LTHash accumulator (PF-077), and the envelope
MACs (PF-078), are Confirmed by independent vectors.
The binary token table itself is not reproduced (spec §10.2); the codec takes
an injected dictionary. PF-034 records that the plaintext `<body>` carrier is
a scoped deviation from the references' encrypted `<enc>` payload.
