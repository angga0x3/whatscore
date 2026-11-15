# Roadmap — execution plan

Status snapshot: Phase 0–2 complete; Phases 3–5 in progress. This file
turns the phase table in the technical specification into workstreams with
owners, file boundaries, acceptance criteria, and dependencies. It is updated
as workstreams land.

## Current state

| Area | Done | Missing |
|------|------|---------|
| Transport | dial, framing, intro header, backoff/retry | live interop |
| Noise | XX handshake, cert chain, secure conn, fake server | live interop |
| Binary | node codec, vectors, fuzz, dictionary loader | real token table |
| Pairing | QR payload, pair-device/pair-success, identity verification | device signature, manager wiring |
| Auth | registration ClientPayload + DeviceProps | login payload, challenge handling |
| Messaging | JID, text `<message>`, `<receipt>` | encrypted `<enc>` carrier (PF-034) |
| Media | HKDF + CBC/HMAC byte envelope | streaming, sidecar hashes |
| Storage | envelope, credential vault, PostgreSQL backend, `core/credentials` manager | Signal-addressed stores |
| Core | event bus, single-actor session runtime with connector/frame handler, credential manager, SDK facade with plaintext send, inbound text, receipts | contacts/groups/media, SQLite |
| SDK / API | — | everything |

## Execution log

| Date | Workstream | Result |
|------|------------|--------|
| 2026-11-15 | Auth payloads | `protocol/auth` + `auth.proto`, PF-020…025 |
| 2026-11-15 | Messaging | `protocol/messaging`, PF-030…035 (PF-034 deviation documented) |
| 2026-11-15 | Media | `protocol/media`, PF-040…045 |
| 2026-11-15 | Core | `core/events`, `core/session` |
| 2026-11-15 | Credential manager | `core/credentials` + ADR 0001 |
| 2026-11-15 | SDK facade | `core/client` (connect/events; send pending) |
| 2026-11-15 | Session wiring | `Connector` + `FrameHandler` in `core/session` |
| 2026-11-15 | Text send | `Session.WriteFrame`, `core/messaging.Sender`, `client.SendMessage`, noise connector |
| 2026-11-15 | Inbound text | `protocol/messaging.ParseIncomingText`, `core/messaging.Receiver` in the client pipeline |
| 2026-11-15 | Receipts | inbound parse/events + `Sender.SendReceipt` + `client.SendReceipt` |
| 2026-11-15 | Signal X3DH | `protocol/signal` + independent vectors, PF-050…053 |
| 2026-11-15 | Signal key schedule | root/chain/message keys, PF-054…056 |
| 2026-11-15 | Signal ratchet state | initialization, DH ratchet, skipped keys, PF-057…059 |
| 2026-11-15 | Signal message crypto | framing, MAC, AES-CBC payload, PF-060…062 |

Next: device-signature decision, credential manager, Signal/sync, SDK facade.

## Workstreams

### W1 — Phase 3 completion (pairing)

Depends on: pairing stanzas, credential vault.

1. Device-signature generation (`0x06 0x01` prefix) for `pair-device-sign`.
   Blocked on a crypto decision: XEdDSA signing is not in the standard
   library. See
   [decisions/0001-xeddsa-signing.md](decisions/0001-xeddsa-signing.md).
2. Credential manager: persist `DeviceIdentity`, noise key, identity key, adv
   secret through `storage/credentials.Vault`; all-or-nothing write.
3. Fake-server pairing test: pair-device → QR → pair-success → verify →
   store, with synthetic keys.
4. Token table decision (§10.2) and manual interop.

Acceptance: `tests/integration` pairing test green; no plaintext credentials in
the database; findings updated.

### W2 — Phase 4 protocol layers

Independent packages; can run in parallel.

- `protocol/messaging`: JID parse/normalize, text stanza build/parse, receipt
  stanzas. Depends on `protocol/binary`.
- `protocol/media`: media key derivation (HKDF), AES-256-CBC + HMAC-SHA256
  encrypt/decrypt, integrity sidecar. Depends on stdlib only.
- `protocol/signal`: X3DH, the key schedule, the ratchet state machine, and
  SignalMessage framing/MAC/encryption done (PF-050…062); prekeys,
  PreKeySignalMessage, persistence, and sender keys remain.
- `protocol/sync`: app-state patch parsing; depends on signal primitives.

Acceptance per package: round-trip/known-answer tests, adversarial tables,
findings with provenance, no network I/O.

### W3 — Phase 5 core & SDK

- `core/events`: normalized event taxonomy, subscriptions, ordered
  non-blocking fan-out.
- `core/session`: one actor, command channel, lifecycle events, shutdown.
- `core/client`: SDK facade (`NewClient`, `Connect`, `SendMessage`,
  `Subscribe`, `Disconnect`), option plumbing.
- `core/messaging`, `core/contacts`, `core/groups`, `core/media`: orchestration.
- `storage/sqlite`: pure-Go backend implementing `storage.Store`.

Acceptance: behavior tests against the fake server; `-race` clean; examples
compile.

### W4 — Phase 6 REST API

- `/api/v1/sessions`, QR SSE, messaging, webhooks, deliveries.
- API-key auth, idempotency, webhook signing/retries.
- Contract tests against `docs/api/openapi.yaml`.

Depends on W3. Acceptance: OpenAPI paths implemented, integration tests green.

### W5 — Phase 7 release

- Compatibility matrix, changelog, goreleaser/GHCR, docs pass.
- Blocked on W1 interop and W4 acceptance.

## Parallelization map

| Workstream | Package boundary | Shared files |
|------------|------------------|--------------|
| Auth payloads | `protocol/auth`, `protocol/protobuf/auth*.proto` | none |
| Messaging | `protocol/messaging` | none |
| Media | `protocol/media` | none |
| Core events/session | `core/events`, `core/session` | none |

Rule: a workstream owns its package tree and its findings file
(`docs/protocol/<area>.md`). It must not edit `README.md`, the technical
specification, `docs/protocol/README.md`, `go.mod`, `tests/integration`, or
`storage/*`; integration happens in the main session.

Finding ID ranges are reserved per workstream to avoid collisions: auth
PF-020…PF-029, messaging PF-030…PF-039, media PF-040…PF-049, signal
PF-050…PF-059.

## Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| XEdDSA signing is custom crypto | security, review load | decide before coding; no unaudited primitives |
| Token table licensing | cannot decode real traffic | injected dictionary; keep the codec independent |
| Live interop absent | compatibility claims unproven | keep findings Probable; no release claims |
| Protocol drift | wire changes | dated findings, reopen instead of replace |
| Parallel edits collide | broken tree | disjoint package boundaries; main session integrates |

## Order of execution

1. W1 decisions + fake-server pairing.
2. W2 packages in parallel with W3 events/session.
3. W3 SDK facade once events/session land.
4. W4 REST once the SDK is usable.
5. W5 release after interop and API acceptance.
