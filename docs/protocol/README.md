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
| **Layer** | `transport` / `noise` / `binary` / `pairing` / `signal` / `sync` / `media` |
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
- **Exception — transport wiring (PF-002, PF-003).** The endpoint, dial
  headers, intro header, and frame layout are necessarily implemented before
  a live connection exists. They may be coded while **Probable**, behind
  `transport.FrameConn`, because our own codec and the fake-server test prove
  the implementation matches this record. They must not be described as
  compatible with the live service until a manual interop observation is
  recorded here. Algorithm-internal findings (noise, signal) have no such
  exception.
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
| PF-002 | transport | WebSocket endpoint and dial headers | Probable | Observed-only | — |
| PF-003 | transport | One-time intro header + 3-byte length framing across WS messages | Probable | Observed-only | `protocol/transport`, `tests/integration` |
| PF-004 | noise | Handshake initialization and hash chain | Confirmed | Verified-by-test | `protocol/noise` (vectors) |
| PF-005 | noise | Handshake AEAD operations (AES-256-GCM, counter IV, hash AAD) | Confirmed | Verified-by-test | `protocol/noise` (vectors, handshake), `tests/integration` (fake server) |
| PF-006 | noise | Key mixing via HKDF after each X25519 | Confirmed | Verified-by-test | `protocol/noise` (vectors) |
| PF-007 | noise | Handshake message sequence (protobuf frames, msg1–msg3) | Confirmed | Verified-by-test | `protocol/noise` (handshake round-trip), `tests/integration` (fake server) |
| PF-008 | noise | Transport key derivation and post-handshake framing | Confirmed | Verified-by-test | `protocol/noise` (vectors, conn), `tests/integration` (fake server) |
| PF-009 | noise | Server certificate chain and XEdDSA signatures | Confirmed | Verified-by-test | `protocol/noise` (cert tests) |

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

Status: first real findings recorded 2026-11-15 (reference study:
whatsmeow + Baileys; see [transport.md](transport.md) and
[noise.md](noise.md)). Algorithm findings are Confirmed by vector tests;
live-server-facing findings (PF-002, PF-003) stay Probable until manual
interop. `tests/integration` now runs the fake-server path end to end
(WebSocket dial → handshake → encrypted frames), which is what the Proving
test column cites.
