# WhatsCore — Technical Specification v0.1

**Status:** Proposed v0.1 — awaiting maintainer review · **Date:** 2026-11-15 · **Applies to:** v0.0.1 (protocol foundation preview)

Normative technical specification for WhatsCore: an independent implementation of the WhatsApp Web
protocol in pure Go. The engine is owned by this project — no whatsmeow, no Baileys, no libsignal
binding anywhere. Items marked **decided** are locked (a change requires a new spec version).

Module: `github.com/angga0x3/whatscore` · Go 1.26.x · single Go module · semantic versioning.

## 1. Purpose & scope

WhatsCore lets self-hosters and Go developers talk to WhatsApp on infrastructure they control, with
an auditable end-to-end stack. In scope: the engine (`protocol/*`), application core (`core/*`),
public interfaces (Go SDK, REST adapter), storage contracts. Out of scope: web UI, multi-tenant
orchestration, non-WhatsApp bridges.

### 1.1 v0.0.1 target checklist

v0.0.1 is the **protocol foundation preview**: it proves the bottom two layers of the stack against
a fake server, not the production endpoint. A release is cut only when all five items hold.

| # | Deliverable | Definition of done |
|---|-------------|--------------------|
| 1 | WebSocket transport works | `protocol/transport.Dialer` opens a framed connection, frames flow bidirectionally, `ReconnectPolicy` drives a scripted drop/reconnect in tests |
| 2 | Noise handshake succeeds | `protocol/noise` completes `Noise_XX_25519_AESGCM_SHA256` against the fake server; `SecureConn` round-trips encrypted payloads |
| 3 | Binary node encode/decode | `protocol/binary.Codec` round-trips every golden fixture byte-exactly; `Decode(Encode(n)) == n` holds |
| 4 | Fake-server integration test passes | `tests/integration` runs the full stack — dial → handshake → encoded node exchange — green in CI |
| 5 | Protocol documentation available | `docs/protocol/README.md` documents every constant used, with provenance (source, observation date, confidence, proving tests) |

### 1.2 Phase roadmap

| Phase | Name | Packages | Exit criteria |
|-------|------|----------|---------------|
| 0 | Foundation | repo skeleton, CI, lint, contract skeletons, this spec | `go test ./...` green on Go 1.26.x; import-rule check passes |
| 1 | Transport & Noise | `protocol/transport`, `protocol/noise` | loopback handshake over in-memory `FrameConn` pair; reconnect policy table tests |
| 2 | Binary protocol | `protocol/binary`, `protocol/protobuf` | codec round-trips fixtures; fuzz corpus has no untriaged crashes; protobuf round-trip |
| 3 | Pairing & authentication | `protocol/pairing`, `protocol/auth` | full pairing flow against the fake server; credentials encrypted at rest |
| 4 | Messaging / Signal | `protocol/signal`, `protocol/messaging`, `protocol/sync`, `protocol/media` | X3DH + Double Ratchet proven via test vectors; send/receive loop vs fake server |
| 5 | Public SDK | `core/*`, `storage/*` | SDK example runs end to end vs fake server; SQLite/Postgres stores interchangeable |
| 6 | API server | `server/*` | REST surface matches `docs/api/openapi.yaml`; sessions manageable over HTTP |
| 7 | Release v0.1.0 | docs, versioning, compatibility matrix | compatibility matrix published; tagged release |

Phases are strictly ordered: a phase starts only when the previous exit criteria are green; compatibility claims begin at Phase 3 (§6 hard rule).

## 2. Locked decisions

| # | Decision | Status | Justification |
|---|----------|--------|---------------|
| 1 | Go 1.26.x, single Go module, semantic versioning | **decided** | One module keeps layer boundaries enforceable by import checks; SemVer lets the SDK make stability promises independently of the server |
| 2 | Layers `protocol/*` → `core/*` → public interfaces (`core/client` SDK + `server/*` REST adapter); one-way dependency direction; protocol MUST NOT import core/server/storage/config; core imports protocol only via the interfaces in §4; storage backends implement `storage.Store` interfaces | **decided** | The engine must be reusable and testable without application or persistence concerns; one-way flow enables both the fake server and the SDK |
| 3 | One session, one actor: each WhatsApp session is owned by a single goroutine (actor) that serializes all state mutations; callers interact via context, channels, and an event bus — never shared mutable state | **decided** | Ratchet and connection state are inherently sequential; an actor eliminates data races by construction and gives deterministic replay in tests |
| 4 | Crypto: Go standard library + `golang.org/x/crypto` primitives only, no custom crypto. Transport encryption = `Noise_XX_25519_AESGCM_SHA256` ([Noise spec](https://noiseprotocol.org/noise.html)). E2E message encryption = Signal-style (X3DH + Double Ratchet), Phase 4, proven via test vectors. Noise and Signal layers must never share key material | **decided** | Vetted primitives only; domain separation (distinct HKDF info strings, distinct key stores) prevents cross-layer key reuse |
| 5 | Transport: WebSocket via `gorilla/websocket`, wrapped behind `transport.FrameConn` so tests inject in-memory transports | **decided** | Proven interop with WhatsApp's `wss` endpoint; the interface keeps the engine socket-agnostic |
| 6 | Storage: SQLite (`modernc.org/sqlite`, pure Go, no cgo) default for SDK and development; PostgreSQL (`pgx`) for the REST server deployment | **decided** | Pure Go keeps cgo out of the build; one schema semantic, two drivers |
| 7 | Protobuf: `google.golang.org/protobuf`, generated code committed to the repo, generator version pinned | **decided** | Committed code = reproducible builds without protoc installed; pinned generator = diffs change only intentionally |
| 8 | Binary codec: token-dictionary based node encoding; codec must be symmetric (`Decode(Encode(n)) == n`) and deterministic (same node → same bytes, always) | **decided** | Determinism is required for golden fixtures and fuzzing; symmetry is the invariant that makes round-trip tests meaningful |

## 3. Architecture & dependency rules

```
┌───────────────────────────────────────────────────────────────────┐
│ Public interfaces                                                 │
│   Go SDK (core/client facade)        REST adapter (server/*)      │
├───────────────────────────────────────────────────────────────────┤
│ Application core (core/*)                                         │
│   client · session · messaging · events · contacts · groups ·     │
│   media                                                           │
├───────────────────────────────────────────────────────────────────┤
│ Protocol engine (protocol/*) — owns the wire                      │
│   transport · noise · binary · protobuf · pairing · auth ·        │
│   signal · messaging · sync · media                               │
├───────────────────────────────────────────────────────────────────┤
│ Infrastructure (storage/*, config/*, observability, buildinfo)    │
└───────────────────────────────────────────────────────────────────┘
              all dependencies point downward only
```

### 3.1 Import rules

1. `protocol/*` imports only: stdlib, `golang.org/x/crypto`, `gorilla/websocket`,
   `google.golang.org/protobuf`, and other `protocol/*` packages. **`protocol` MUST NOT import
   `core`, `server`, `storage`, or `config`.**
2. `core/*` imports `protocol/*` **only through the interfaces in §4** (`FrameConn`, `Dialer`,
   `ReconnectPolicy`, `Handshaker`, `Codec`, store interfaces); implementations are injected at
   the composition root (`cmd/whatscore`, or tests).
3. `server/*` adapts `core/*`; handlers never construct protocol types, never see `Node`,
   `SecureConn`, or ratchet state.
4. `storage/*` implements the `storage.Store` interfaces (§4.19); nothing above `storage` knows
   which SQL engine is in use.
5. No import cycles, anywhere, including tests.

### 3.2 Violation policy

Import rules are enforced mechanically by `tests/architecture/imports_test.go` (runs with every
`go test`, parses imports with `go/parser`) and by review: **a PR that imports engine internals from
handlers is rejected.** Reintroducing a forbidden edge requires a spec change, not a workaround; if
the interfaces are insufficient, extend them behind the same boundary.

## 4. Package contract

Each package states responsibility, public surface, allowed dependencies, and test strategy. The
three blocks marked *verbatim* are contract skeletons in the repo; editing them requires a spec change.

### 4.1 `protocol/transport`

**Responsibility.** Frame-oriented transport over WebSocket: dialing, length-prefixed frame
read/write, close, reconnect scheduling. Higher layers never see sockets, TLS details, or HTTP
upgrade headers — only frames and a `context.Context`.

**Public surface** (verbatim contract skeleton, `protocol/transport`):

```go
// FrameConn is a bidirectional stream of opaque binary frames. Higher
// layers (noise, binary) never see sockets, only frames.
type FrameConn interface {
    ReadFrame(ctx context.Context) ([]byte, error)
    WriteFrame(ctx context.Context, frame []byte) error
    Close() error
}

// Dialer opens new transport connections.
type Dialer interface {
    Dial(ctx context.Context, endpoint Endpoint) (FrameConn, error)
}

// ReconnectPolicy decides whether and when a dropped connection is retried.
type ReconnectPolicy interface {
    Next(attempt int) (time.Duration, bool)
    Reset()
}
```

**Allowed deps.** stdlib (`context`, `net`, `time`), `gorilla/websocket`; no crypto, no encoding.
**Tests.** Framing tables (truncated/oversized frames); in-memory `FrameConn` pair for loopback;
scripted drop/reconnect; WebSocket paths against an `httptest` server.

### 4.2 `protocol/noise`

**Responsibility.** The `Noise_XX_25519_AESGCM_SHA256` handshake (client role) and the encrypted
frame connection it produces: handshake state machine, key derivation, symmetric encrypt/decrypt
over `transport.FrameConn`. Handshake payload *content* (client hello, build metadata) lives in
`protocol/auth`; `noise` is payload-agnostic.

**Public surface** (verbatim contract skeleton, `protocol/noise`; `SecureConn` implements
`transport.FrameConn` semantics over the encrypted channel):

```go
// Handshaker performs the client role of the Noise handshake over framed
// transport, returning an encrypted frame connection.
type Handshaker interface {
    Handshake(ctx context.Context, fr transport.FrameConn) (noise.SecureConn, error)
}
```

**Allowed deps.** stdlib `crypto/*` (AES-GCM, SHA-256), `golang.org/x/crypto` (`curve25519`,
`hkdf`), `internal/xeddsa`, `protocol/transport`; never `protocol/signal`. **Tests.** Noise framework XX vectors;
loopback handshake; tampered-ciphertext tests fail closed; key-separation test (§9).

### 4.3 `protocol/binary`

**Responsibility.** The WhatsApp binary protocol: `Node` tree model, token
dictionary, byte-level codec. The codec is the single place wire bytes are interpreted, including the
one-byte frame flag (PF-010).

**Public surface** (`protocol/binary`):

```go
// Node is one element of the WhatsApp binary protocol tree.
type Node struct {
    Tag      string
    Attrs    Attrs
    Children []Node
    Bytes    []byte
}

// Codec converts nodes to and from the wire format. Encode is
// deterministic; Decode consumes exactly one encoded frame.
type Codec interface {
    Encode(n *Node) ([]byte, error)
    Decode(r io.Reader) (*Node, error)
}

// Dictionary maps strings to wire tokens; NewCodec(nil) uses an empty one.
type Dictionary struct{ /* ... */ }
func NewDictionaryFromTokens(single []string, double [][]string) (*Dictionary, error)
func NewCodec(dict *Dictionary) Codec
```

**Invariants.** (a) Symmetry: `Decode(Encode(n)) == n` for every representable node. (b)
Determinism: identical nodes → identical bytes; attributes are emitted in lexicographic key order and
maps are never iterated directly. (c) `Decode` consumes exactly one frame; (d) unknown tokens produce
typed errors, never guesses (§8); (e) decode limits bound depth, node count, list size, and byte
length.

**Dictionary.** The token tables are injected rather than compiled in: the real table's licensing
question is still open (§10.2). `DefaultDictionary()` is empty, so every string encodes raw. Tests and
fixtures use a small synthetic table.

**Status.** Phase 2 implemented: codec, synthetic vectors, fuzz tests, and a JSON dictionary loader
(`LoadDictionary` / `LoadDictionaryFile`). The real token table remains open (§10.2).

**Allowed deps.** stdlib only (`io`, `errors`, `fmt`, `sort`, `compress/zlib`).
**Tests.** Byte-exact golden fixtures (§6); round-trip property tests; native fuzzing on `Decode`;
adversarial-input table (deep nesting, huge lists, invalid tag lengths).

### 4.4 `protocol/protobuf`

**Responsibility.** Wire messages as `.proto` sources; generated Go code **committed to the repo**,
generator version pinned in the package doc; regeneration is a standalone PR touching only generated
files. **Allowed deps.** `google.golang.org/protobuf`, `protocol/binary`. **Tests.** Generated
round-trip per message type; golden wire bytes; unknown-field preservation.
**Status.** Generated messages are covered by round-trip and field-number wire tests (PF-007, PF-009).

### 4.5 `protocol/pairing`

**Responsibility.** Device pairing (Phase 3): QR pairing payload construction/parsing, pairing
handshake over the Noise channel, identity provisioning records; QR rendering is a caller concern.
**Allowed deps.** stdlib, `internal/xeddsa`, `protocol/noise`, `protocol/binary`, `protocol/protobuf`.
**Tests.** Synthetic vectors only (§6 hard rule); payload round-trips; malformed-payload negatives.
**Status.** QR payload (PF-015), pair-device/pair-success parsers (PF-016), and device-identity
authentication (PF-017) are implemented. Device-signature generation and credential provisioning
remain.

### 4.6 `protocol/auth`

**Responsibility.** Post-handshake authentication: client hello payload construction (build
metadata, version strings), server hello validation, challenge handling, version registry (§7).
**Allowed deps.** stdlib, `protocol/noise`, `protocol/binary`, `protocol/protobuf`. **Tests.**
Payload golden fixtures; registry tables; fake-server auth flow in `tests/integration`.
**Status.** Both payload forms are implemented: registration (`BuildClientPayload`/`ParseClientPayload`,
PF-020…025) and paired-device login (`BuildLoginPayload`/`ParseLoginPayload`, PF-026…027), with
mutual rejection. Challenge handling and registration crypto remain.

### 4.7 `protocol/signal`

**Responsibility.** Signal-style E2E encryption: X3DH key agreement, Double Ratchet sessions,
prekey generation/rotation, sender-key distribution for groups; owns all ratchet state
serialization (byte blobs handed to the stores, §4.19). **Decided:** never shares key material with
`protocol/noise` — separate roots, HKDF domains, stores. **Allowed deps.** stdlib `crypto/*`,
`golang.org/x/crypto`, `internal/xeddsa`, `internal/cbc`, `protocol/protobuf`. **Tests.** Known-answer X3DH/Double Ratchet vectors
(Phase 4 exit criterion); out-of-order/replay tables; state-serialization round-trip; no network I/O.
**Status.** X3DH agreement, signed-prekey verification, the key schedule, the Double Ratchet state
machine, SignalMessage framing/MAC/payload encryption, and PreKeySignalMessage bootstrap are
implemented (PF-050…PF-064). Ratchet state also has a versioned, deterministic binary encoding with
chain/skipped-key limits (`MarshalBinary`/`ParseState`). Prekey generation/rotation and signing
(ADR 0001), one-time prekey deletion, store wiring, and WhatsApp `<enc>` wiring remain.

### 4.8 `protocol/messaging`

**Responsibility.** Message stanza construction/parsing: send/receipt nodes, JID parsing and
normalization, wrapping Signal ciphertext in stanzas. Knows stanza shapes; does not ratchet.
**Allowed deps.** stdlib, `protocol/binary`, `protocol/protobuf`, `protocol/signal` (ciphertext
in/out only). **Tests.** Stanza golden fixtures; JID normalization tables; build-parse round-trips.
**Status.** JID parsing/rendering/normalization, the `<message type="text">` envelope, `<receipt>`,
and the `<enc>` ciphertext carrier are implemented (PF-030…036). Choosing the carrier and producing
ciphertext from a stored session belongs to `core/messaging`; plaintext `<body>` remains for
unencrypted runs.

### 4.9 `protocol/sync`

**Responsibility.** Encrypted application-state sync and history sync decoding: patch parsing,
action ordering, blob decryption boundaries (primitives from stdlib only). **Allowed deps.** stdlib,
`protocol/binary`, `protocol/protobuf`, `protocol/signal` (key derivation inputs only). **Tests.**
Synthetic app-state fixtures; truncated/corrupt patch tables; deterministic decode.
**Status.** `protocol/sync` parses the app-state stanza and mutation protobuf with a strict,
limits-bounded wire reader, verifies value MACs, expands the five app-state keys, and decodes
mutations end to end (value MAC → CBC → action envelope → index MAC) per PF-070…PF-076, and verifies
the LTHash accumulator and snapshot/patch envelope MACs (PF-077…PF-078). The enforcement policy
(which mismatch is fatal) stays with the caller.

### 4.10 `protocol/media`

**Responsibility.** Encrypted media upload/download: media path construction, ciphertext framing,
integrity sidecar computation via stdlib `crypto/aes`/`crypto/hmac`/`crypto/sha256`; bytes move over
injected transport interfaces, not a hardcoded HTTP client. **Allowed deps.** stdlib,
`internal/cbc`, `protocol/binary`. **Tests.** Round-trip with synthetic keys; corruption tables; fake media endpoint.
**Status.** Byte envelope implemented (PF-040…048): HKDF-SHA256, AES-256-CBC/PKCS#7, truncated HMAC,
streaming encrypt/decrypt with verify-before-write that requires `io.ReaderAt`, the plaintext sidecar
digest, and range decryption. Range decryption requires the caller to have authenticated the full
blob first (`verified`), because a per-range MAC does not exist.

### 4.11 `core/client`

**Responsibility.** The public SDK facade — the only `core` package third-party code needs.
Composes session, messaging, and events behind a small API; owns option plumbing.

**Public surface — target API, Phase 5** (sketch, not yet implemented; names may shift until the
Phase 5 review, structure will not):

```go
// target API, Phase 5
c := whatscore.NewClient(
    whatscore.WithStore(store),      // storage.Store aggregate (§4.19)
    whatscore.WithLogger(slog.Default()),
)

err := c.Connect(ctx)                // dial, handshake, resume session if stored
id, err := c.SendMessage(ctx, to, whatscore.NewTextMessage("hello"))

sub := c.Subscribe()                 // event subscription (core/events)
for ev := range sub.C {
    // ev is a core/events value; protocol types never leak here
}
err = c.Disconnect(ctx)
```

**Allowed deps.** `core/*`, `protocol/*` via §4 interfaces, `storage` interfaces, stdlib.
**Tests.** Behavior tests vs fake server; option composition tables; examples compiled in CI.
**Status.** `core/client` implements connect/disconnect/state/subscribe/credentials/close with
option validation, `WithConnector`/`WithFrameHandler` pass-through, plaintext `SendMessage`, and
`SendEncrypted`, which loads a peer session, picks `pkmsg` vs `msg`, sends, and persists the advanced
ratchet through an injected `SessionStore`. The SDK also exposes lazy contact/group caches that
publish a group-update event only when a cache reports a real change (duplicate contact pushes stay
silent). Media orchestration through the SDK remains.

### 4.12 `core/session`

**Responsibility.** The actor (§2 decision 3): one goroutine owns one WhatsApp session and all its
state mutations. Receives commands over a command channel, emits lifecycle events on the event bus,
drives reconnection via `transport.ReconnectPolicy`, is the single writer for session-scoped
records. **Allowed deps.** `protocol/*` via interfaces, `core/events`, storage interfaces, stdlib.
**Tests.** `-race` mandatory; deterministic actor tests with fake `FrameConn`; shutdown liveness;
channels and contexts only — no sleeps.
**Status.** Actor runtime implemented: Connect/Disconnect/State/Stop, injected Dialer/ReconnectPolicy/
Bus, lifecycle events, late-dial cleanup, reconnect after drops. An injectable `Connector` wraps the
dialed transport (Noise) and a `FrameHandler` consumes inbound frames; a returned handler error drops
the connection and feeds the reconnect policy.

### 4.13 `core/messaging`

**Responsibility.** Send/receive orchestration: hands plaintext to `protocol/messaging` +
`protocol/signal` for ratcheting, correlates receipts, retries idempotently, normalizes inbound
messages into `core/events` values. **Allowed deps.** `protocol/*` via interfaces, `core/events`,
storage interfaces, stdlib. **Tests.** Fake-server conversation scripts; retry/backoff and dedup
tables.
**Status.** `core/messaging.Sender` builds and writes plaintext and Signal-encrypted text stanzas and
receipts over a `FrameWriter`; `Receiver` decodes inbound plaintext text, encrypted `<enc>` text, and
receipts into `events.Message` / `events.Receipt` values, decrypting on a state clone so a failed
attempt never advances the live ratchet. Inbound `pkmsg` bootstrap resolves prekeys through an
injected `PreKeySource`, installs the new session, and decrypts the carried text. Retries/dedup and
persistence callbacks remain.

### 4.14 `core/events`

**Responsibility.** Normalized event taxonomy (Connected, Disconnected, PairingCode, Message,
Receipt, GroupUpdate, …), subscription handles, in-process bus. Guarantees: ordered per session,
non-blocking fan-out, protocol types never appear in event values. **Allowed deps.** stdlib only.
**Tests.** Ordering and backpressure tables; slow-subscriber behavior.
**Status.** Taxonomy and bus implemented: bounded per-subscriber buffers, drop counters, ordered
non-blocking fan-out, subscription lifecycle. `core/messaging.Receiver` publishes inbound text
messages; other events follow with their layers.

### 4.15 `core/contacts`

**Responsibility.** Contact/profile caching and lookups; pushes changes as events. **Allowed
deps.** `protocol/*` via interfaces, `core/events`, storage interfaces, stdlib. **Tests.** Cache
invalidation tables vs fake server responses.
**Status.** `core/contacts.Cache` implements the cache: JID-keyed, change detection that ignores
duplicate pushes, sorted snapshots, copy semantics, stdlib only. Fetch orchestration and event
publication stay with the caller.

### 4.16 `core/groups`

**Responsibility.** Group metadata and participant management; delegates group message crypto to
`protocol/signal` sender keys. **Allowed deps.** `protocol/*` via interfaces, `core/events`,
storage interfaces, stdlib. **Tests.** Participant change tables; fake-server group flows.
**Status.** `core/groups.Cache` implements metadata caching with normalized participants and
participant change detection. Sender keys remain.

### 4.17 `core/media`

**Responsibility.** Download/decrypt and encrypt/upload orchestration; exposes plain byte streams
to callers while keys stay internal. **Allowed deps.** `protocol/media` via interface, storage
interfaces, stdlib. **Tests.** Round-trip vs fake media endpoint; corruption tables.

### 4.18 `server/*` (REST adapter)

**Responsibility.** HTTP surface (`chi` router, middleware, API-key auth, handlers) adapting
`core/client`/`core/session` to REST. Sessions map to actors; handlers only send commands and read
events. **Allowed deps.** `core/*`, `go-chi/chi/v5`, stdlib; never `protocol/*`. **Tests.**
`httptest` router tests; handler tables; contract checks vs `docs/api/openapi.yaml`.
**Status.** `server/api` implements the session routes behind a `Service` interface with an
in-memory manager; the router mounts it when `Deps.API` is set, and unmounted `/api/v1` paths still
answer 501. `server/webhook` implements signed delivery with retries and delivery records, and
`server/api` also serves webhook CRUD with a write-once secret, messaging routes with idempotency,
the `/events` + `/qr` SSE streams over `core/events`, and multipart image/document uploads with a
bounded attachment store. Rate limiting and real delivery remain contract-only.

### 4.19 `storage` (Store aggregate)

The store layer persists **opaque byte blobs with Signal-addressed keys**. The protocol layer owns
record semantics; a store never interprets a value it persists. The aggregate interface `Store`
composes:

| Interface | Keyed by | Carries |
|-----------|----------|---------|
| `DeviceStore` | device/registration identity | registration + account identity blob |
| `IdentityStore` | remote Signal address (JID + device) | remote identity-key blobs |
| `SessionStore` | remote Signal address | Double Ratchet session state blob |
| `PreKeyStore` | prekey ID | one-time prekey blobs |
| `SignedPreKeyStore` | signed prekey ID | signed prekey blobs |
| `SenderKeyStore` | (group address, sender address) | group sender-key blobs |
| `AppStateStore` | app-state key | sync state blobs |

Backends: `storage/sqlite` (`modernc.org/sqlite`, SDK/development default) and `storage/postgres`
(`pgx/v5`, server deployment) implement the same aggregate; all access is keyed lookups of `[]byte`
— no crypto structures leak into SQL schemas. SQLite is cgo-free, runs WAL with a schema-version
guard, and is verified with `CGO_ENABLED=0` builds (docs/architecture/storage.md).

**Status.** Interfaces and PostgreSQL migrations exist; `storage/envelope` provides the envelope
cipher, `storage/credentials` the encrypting vault plus an in-memory backend,
`storage/postgres.CredentialBackend` the `credentials` table, `core/credentials` the versioned
device-record manager, and `core/signalsession` the per-peer ratchet-state manager. Signal-addressed
stores for the remaining record types land with the core work.

## 5. Dependency policy

### 5.1 Approved

| Dependency | Purpose | Constraints |
|------------|---------|-------------|
| Go stdlib (`crypto/*`, `net`, `encoding`, `log/slog`, `context`) | all core primitives | preferred over any external equivalent |
| `golang.org/x/crypto` | `curve25519`, `hkdf`, adjacent vetted primitives | only packages with no stdlib equivalent |
| `github.com/gorilla/websocket` | wss transport (§2 decision 5) | only behind `transport.FrameConn` |
| `google.golang.org/protobuf` | protobuf runtime + codegen (§2 decision 7) | generated code committed; generator pinned |
| `modernc.org/sqlite` | SQLite driver, pure Go (§2 decision 6) | no cgo alternative accepted |
| `github.com/jackc/pgx/v5` | PostgreSQL driver/pool | server deployment only |
| `github.com/go-chi/chi/v5` | REST router | `server/*` only |
| `github.com/golang-migrate/migrate/v4` | schema migrations | storage backends only |

### 5.2 Rejected

| Dependency | Reason |
|------------|--------|
| whatsmeow or Baileys ports/transplants | the protocol engine must be owned by this project; porting reproduces the dependency this project exists to remove |
| libsignal CGo bindings | CGo banned; foreign runtime is unauditable here and violates decision 4 |
| any CGo dependency | breaks cross-compilation, auditability, and the pure-Go storage decision |
| hand-rolled crypto primitives | only vetted stdlib/x/crypto implementations; novel constructions out of scope permanently |

### 5.3 Process

| Step | Requirement |
|------|-------------|
| Proposal | PR adds the dependency to `go.mod` plus a justification in the PR description |
| Justification criteria | pure Go (no CGo); permissive license (Apache-2.0/MIT/BSD/ISC); maintained (upstream activity within 12 months); minimal transitive dependency tree |
| Review | maintainer approval; the PR states which §5.1 slot it fills or why a new slot is needed |
| Record | new entries are appended to §5.1 in the same PR; the spec is the single source of truth |

## 6. Test strategy

| Tier | Mechanism | Where | Cadence |
|------|-----------|-------|---------|
| Unit | table-driven `go test`, `-race` on actor packages | every package | every PR |
| Golden fixtures | byte-exact hex fixture + JSON mirror + provenance id | `tests/fixtures` | every PR |
| Fake server (tier 1) | in-memory `FrameConn` pair for loopback handshake | package-local `_test.go` | every PR |
| Fake server (tier 2) | full fake WhatsApp server implementing the handshake server-side + minimal stanza behavior | `tests/integration` | every PR |
| Fuzzing | Go native fuzzing on the binary decoder (`FuzzDecode`) | `protocol/binary` | short run per PR; **nightly** long run |
| Interop | manual runs against the real endpoint, recorded as protocol findings | `docs/protocol/README.md` | per release |

- **Golden fixtures.** `tests/fixtures/<area>/<id>.hex` holds exact wire bytes; a parallel `.json`
  holds the decoded mirror plus `provenance` (`source`, `observation_date`, `confidence`,
  `proving_test`). Fixtures are immutable once proven — corrections add a new fixture, never edit one.
- **Fuzzing.** Nightly jobs write crashes into the corpus; every crash becomes a regression fixture
  before the fix merges. The decoder is fuzzed because it consumes untrusted bytes (§9).
- **Interop.** Manual runs, never in CI, always recorded as protocol findings in
  `docs/protocol/README.md`.

> **HARD RULE:** compatibility claims require a green test. No real credentials, no real QR codes,
> and no personal data in fixtures — synthetic keys only. A fixture that cannot be regenerated from
> synthetic material is rejected in review.

## 7. Protocol versioning & compatibility

### 7.1 Version registry

**Planned (Phase 2).** All version-sensitive constants will live in one code-owned registry (single
package, one documented struct). Values change only in a PR that updates the proving fixtures in the
same commit. Until the registry exists, each constant carries its provenance in `docs/protocol/`.

| Field | Owner package | Example content | Documented how |
|-------|---------------|-----------------|----------------|
| Noise cipher suite / handshake constants | `protocol/noise` | `Noise_XX_25519_AESGCM_SHA256`, pattern, framing widths | package doc + `docs/protocol/README.md` |
| WA version string | `protocol/auth` | observed client build string | provenance entry per value |
| Capability flags | `protocol/auth` | advertised feature bits | provenance entry per flag |
| Token dictionary version | `protocol/binary` | dictionary generation id | provenance entry |

### 7.2 Compatibility matrix

Each release publishes a matrix in its release notes: rows are capabilities (handshake, pairing,
messaging, receipts, groups, media, sync), columns are releases, cells are `supported` / `broken` /
`unknown` / `untested`. `supported` requires a green test (§6 hard rule); `unknown` is the default.

### 7.3 Provenance policy

Every protocol constant, stanza shape, and behavioral assumption is recorded in
`docs/protocol/README.md` with **source**, **observation date**, **confidence** (high/medium/low),
and **proving tests**. A constant without provenance may not be referenced by non-test code;
superseded findings are archived, not deleted, keeping behavior history auditable.

## 8. Error taxonomy & observability

### 8.1 Typed sentinel errors per layer

| Layer | Sentinels (wrapped with `%w` + context) |
|-------|------------------------------------------|
| `transport` | `ErrClosed`, `ErrDialFailed`, `ErrBadFrame`, `ErrTimeout` |
| `noise` | `ErrHandshakeFailed`, `ErrDecryptFailed`, `ErrBadPayload` |
| `binary` | `ErrTruncated`, `ErrUnknownToken`, `ErrInvalidNode`, `ErrTooLarge` |
| `signal` | `ErrNoSession`, `ErrInvalidKey`, `ErrDuplicateMessage`, `ErrStalePreKey` |
| `protocol/messaging` | `ErrBadStanza`, `ErrUnsupportedStanza` |
| `core` | `ErrNotConnected`, `ErrSessionClosed`, `ErrAlreadyPaired` |
| `storage` | `ErrNotFound`, `ErrConflict` |

Callers match with `errors.Is`; each sentinel documents when it is returned. Layer-crossing errors
are re-wrapped with the origin layer's sentinel, never stringified.

### 8.2 Logging

`log/slog` throughout; JSON in production, text in development; every line carries `component` and,
where applicable, a `session` correlation id. Levels: `Debug` protocol traces, `Info` lifecycle,
`Warn` retryable failures, `Error` terminal failures.

### 8.3 Redaction rules

| Field class | Rule |
|-------------|------|
| QR content / pairing codes | never logged, at any level |
| Private keys, ratchet state, prekeys | never logged; error values carry key ids only |
| Tokens, credentials, API keys | never logged |
| Message bodies | `Debug` only, behind an explicit opt-in flag; redacted by default |
| JIDs / phone numbers | allowed at `Info` (operational necessity), documented as such |

Redaction happens at log-call construction, not via a scrubbing middleware; `observability` keeps a
middleware as a second line of defense for unexpected fields.

## 9. Security

- **Credentials at rest.** Server: credential blobs and stores are encrypted with a key derived from
  `ENCRYPTION_KEY`. `storage/envelope` implements the AES-256-GCM envelope
  (`version(1) ‖ nonce(12) ‖ ciphertext ‖ tag(16)`, random per-record nonce, associated data binds
  the record key, key parsed from the base64 32-byte secret). `storage/credentials.Vault` seals
  before writing and opens after reading; `storage/postgres.CredentialBackend` persists the
  ciphertext in the `credentials` table. Wiring the engine's credential manager still lands with the
  core/session work. SDK: optional passphrase-derived encryption of the SQLite store, Phase 3.
  Unencrypted stores: development only, never in `server/*`.
- **Key-material separation.** Noise transport keys and Signal E2E keys never share roots, HKDF info
  strings, or stores (§2 decision 4, §4.7); a test asserts no byte overlap across derived key sets.
- **Key zeroing hygiene.** Private key buffers are zeroed after use; keys never appear in `String()`,
  errors, or logs; key structs do not implement `MarshalJSON`. Ratchet state is zeroed in memory
  after its serialized blob is handed to a store.
- **Rate limiting.** `server/middleware.RateLimiter` guards `/api/v1` with a per-process,
  in-memory token bucket. Defaults: 10 tokens/s refill, burst 30, 5-minute idle TTL, at most 4096
  tracked identities. The identity is the API key from the `Authorization` header when present
  (hashed before use as a map key, never logged or echoed), otherwise the client IP from
  `RemoteAddr`; `X-Forwarded-For` is deliberately ignored, matching the router's RealIP omission
  (GHSA-3fxj-6jh8-hvhx). Allowed requests carry `X-RateLimit-Limit` (burst) and
  `X-RateLimit-Remaining`; denials answer `429` with `Retry-After` (whole seconds, minimum 1),
  `X-RateLimit-Reset` (delta seconds until the next token, same value as `Retry-After`), and the
  standard error envelope with code `rate_limited`. Idle buckets are
  swept on access and the map is hard-capped, so a hostile key space cannot grow memory without
  bound. System endpoints (`/health`, `/ready`, `/version`) are never limited, so probes keep
  working while a client is throttled.
  **Limitation (documented, accepted):** the bucket lives in the process, so with N instances
  behind a load balancer the effective limit is N × burst and each instance counts separately.
  Deployments needing a global budget must route `/api/v1` to a single instance or enforce the
  quota in a fronting proxy; a shared store (Redis) was rejected for v0.0.1 because it adds a
  dependency, a request-path failure mode, and a store holding rate-limit identities.
- **Threat model summary.**

| Asset / actor | Threat | Mitigation |
|---------------|--------|------------|
| Self-hosted server | operator misconfiguration exposes API | API-key auth required; `ENCRYPTION_KEY` mandated for production config |
| Local attacker with disk access | reads stored session material | encrypted-at-rest credential blobs; keys not stored beside the store |
| Malicious webhook URLs | SSRF / exfiltration from the server | target validation, no redirect following, HMAC-signed payloads, outbound calls only from the webhook worker |
| Hostile network peer | crafted frames reach decoders | strict binary decoder (typed errors), fuzzed decoder, handshake fails closed |
| Compromised Noise channel | attacker injects post-handshake frames | Signal-layer authentication on every message; transport compromise yields metadata only |
| QR interception | pairing hijack | pairing payloads single-use and short-lived; documented operational guidance |

## 10. Open questions

1. **Protobuf codegen scope.** Full observed schema, or a narrow per-message subset with
   unknown-field passthrough? The pinned generator solves reproducibility; scope decides review
   surface. Target: before Phase 2 exit.
2. **Token dictionary derivation & licensing.** Clean-room reconstruction vs derivation from
   observed tables, and license constraints on extracted tables. Target: before live interop. The
   Phase 2 codec takes an injected dictionary, so codec mechanics are not blocked by this question.
3. **SQLite WAL vs SDK concurrency.** WAL with multiple sessions per process: acceptable contention,
   or does the actor model (§4.12) already serialize enough? Target: Phase 5, with benchmarks.
4. **Legacy vs multi-device protocol paths.** Multi-device flows are current; some operations may
   still need legacy paths. Target: Phase 3, from fake-server and interop findings.

## Definition of done for v0.0.1

v0.0.1 is released when **all** of the following are true, verified by green tests in CI:

- [ ] **WebSocket transport works** — framed dial/read/write/close, reconnect policy proven
- [ ] **Noise handshake succeeds** — `Noise_XX_25519_AESGCM_SHA256` handshake vs fake server; `SecureConn` round-trips payloads
- [ ] **Binary node encode/decode** — codec symmetric + deterministic over all fixtures; fuzzer clean
- [ ] **Fake-server integration test passes** — dial → handshake → node exchange loop in `tests/integration`
- [ ] **Protocol documentation available** — `docs/protocol/README.md` provenance for every constant used

No compatibility claim ships with v0.0.1 beyond what these tests prove (§6 hard rule).
