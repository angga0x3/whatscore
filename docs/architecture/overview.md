# Architecture overview

WhatsCore is an independent WhatsApp Web protocol implementation in pure Go,
organized as **three layers** with one-way dependencies. This page is the
short public overview; the
[technical specification](technical-specification.md) is the detailed source
of truth — where the two disagree, the specification wins.

## The three layers

```
┌───────────────────────────────────────────────────────────────┐
│  Public interfaces                                            │
│  Go SDK · REST API · Webhooks                                 │
└───────────────────────────────┬───────────────────────────────┘
                                ▼
┌───────────────────────────────────────────────────────────────┐
│  Application core                                             │
│  client · session · messaging · events                        │
│  (one session, one actor)                                     │
└───────────────────────────────┬───────────────────────────────┘
                                ▼
┌───────────────────────────────────────────────────────────────┐
│  Protocol engine (pure Go)                                    │
│  transport · noise · binary · pairing · signal · sync          │
└───────────────────────────────────────────────────────────────┘
```

- **Public interfaces** — everything outside code sees. The Go SDK (Phase 5)
  for embedding, the REST API server for self-hosted deployments, and signed
  webhooks for event delivery. All of them are thin surfaces over the same
  application core.
- **Application core** — `core/*`: client lifecycle, session ownership,
  messaging, and event normalization. It knows *what* to do, never *how* the
  wire works.
- **Protocol engine** — `protocol/*`: the owned implementation of the
  WhatsApp Web protocol — WebSocket transport, Noise handshake, binary node
  codec, pairing, Signal-style E2E, and history sync. It knows *how* the wire
  works and nothing about applications.

## Dependency direction

Imports point downward only:

1. `protocol/*` never imports `core/*`, `server/*`, `storage/*`, or
   `config/*`. The engine depends only on the Go standard library.
2. `core/*` imports `protocol` exclusively through documented interfaces.
3. `server/*` is an adapter over the core — it never contains protocol logic.
4. Storage backends implement `storage.Store`; nothing else touches a
   database directly.

## One session, one actor

Every WhatsApp session has exactly **one owner** at any moment. Two
goroutines — and, later, two server instances — must never drive the same
device simultaneously: parallel actors corrupt protocol state and are a
reliable way to trigger server-side account action. Ownership is enforced in
the core's session registry; multi-instance deployments need a distributed
lease mechanism before they will be supported.

## Storage strategy

- The **SDK defaults to SQLite** (pure-Go driver) — zero external processes
  for embedded use.
- The **server uses PostgreSQL** — concurrent access, migrations, and
  operational tooling.
- Both (and any future backend) implement the same `storage.Store` interface;
  callers never see the engine behind it. Schema migrations for the server
  backend are embedded in the binary.

## Crypto separation

Two cryptographic systems, two purposes, **never shared key material**:

- **Noise** secures the *transport* — the handshake and the encrypted channel
  to WhatsApp servers.
- **Signal** secures the *messages* — per-conversation E2E encryption.

Keys never cross the boundary: Noise session keys never encrypt a message,
Signal identity/identity-adjacent keys never protect the channel. Key
material lives in the storage layer and is zeroed on use wherever possible.

## Log hygiene

Never logged, without exception: **QR codes, pairing codes, private keys,
tokens, API keys, session credentials**. Secrets flow through the engine and
core without entering log fields; the request logger carries only structured,
non-sensitive metadata. Tests and issue reports follow the same rule —
synthetic keys only ([tests/fixtures/README.md](../tests/fixtures/README.md)).

## From protocol findings to code

Protocol knowledge enters the codebase through one door:

```
observation → finding in docs/protocol (source, date, confidence, proving tests)
            → status Confirmed
            → only then may implementation depend on it
```

The provenance policy is defined in [docs/protocol/README.md](../protocol/README.md).
Unverified folklore — a blog post, a memory, a captured trace nobody can
reproduce — never reaches the engine.

## Open design questions

Tracked in the [technical specification](technical-specification.md) and the
issue tracker. Examples: multi-instance session ownership leases, retention
policies for events and deliveries, and the exact shape of the SDK's
`storage.Store` contract.
