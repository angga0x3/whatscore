# Architecture

WhatsCore is a **modular monolith**: one Go application, clear module
boundaries, explicit interfaces. This document is the reference for every
contribution — the rules below are enforced in code review.

## System overview

```
External Clients (REST API · SDK · CLI · Dashboard)
        │
HTTP Layer (Chi Router · Middleware · Auth · Validation)
        │
Session Module ── Messaging Module ── Event Module ── Webhook Module
   (Lifecycle/QR)    (Send/Receive)   (Normalization)   (Delivery/Retry)
        │
Engine Abstraction (WhatsAppEngine interface)
        │
whatsmeow adapter ──────────────┐
                                │
Persistence Layer (PostgreSQL · whatsmeow device store · file storage)
```

## Dependency direction

```
HTTP Handler
    ↓
Application Service
    ↓
Domain Interface
    ↓
Infrastructure Adapter
    ↓
External System
```

Imports only ever point downward. Concretely:

- `session` must not import `transport/http`.
- Business logic stays independent of HTTP.
- The transport layer depends on interfaces, wired by `internal/app`
  (composition root).

## Architectural rules

1. **HTTP handlers never call whatsmeow directly.** They call services.
2. **All WhatsApp operations go through application services.**
3. **The engine only handles WhatsApp communication** — no persistence of
   WhatsCore metadata, no HTTP concerns.
4. **Engine events are normalized before processing.** whatsmeow's
   event structs are converted into WhatsCore's internal event types at the
   adapter boundary; nothing downstream knows whatsmeow's types.
5. **Webhooks are asynchronous.** Request handlers never make outbound
   webhook HTTP calls.
6. **Database access goes through repository interfaces.** Handlers and
   services never touch `*pgxpool.Pool` directly (the readiness checker is
   the only structural adapter, defined consumer-side).
7. **Session credentials never appear in REST responses.** They live in the
   whatsmeow device store and are managed by the engine adapter only.

## Package map (Milestone 1)

| Package | Responsibility |
|---------|----------------|
| `cmd/whatscore` | Process entry: flags, signal handling, `app.New` + `app.Run` |
| `internal/config` | Environment variable loading + validation |
| `internal/app` | Composition root, HTTP server lifecycle, graceful shutdown |
| `internal/observability` | slog logger construction (JSON in production) |
| `internal/transport/http` | Chi router, middleware chain, handler wiring |
| `internal/transport/http/handlers` | Endpoint implementations |
| `internal/transport/http/middleware` | Request logging, panic recovery |
| `internal/auth` | API key generation/hashing/verification (used from Milestone 2) |
| `internal/storage/postgres` | pgx pool, embedded-migration runner |
| `internal/buildinfo` | ldflags-injected version information |
| `migrations` | SQL migrations, embedded via `go:embed` |

Planned packages follow the repository layout in the specification:
`internal/session`, `internal/messaging`, `internal/events`, `internal/webhook`,
`internal/media`, `internal/storage`, and `internal/engine` with the
`whatsmeow` adapter.

## Engine abstraction

The `engine.Engine` interface (spec §7) is the seam that keeps WhatsCore
engine-agnostic:

```go
type Engine interface {
    Name() string
    Connect(ctx context.Context) error
    Disconnect(ctx context.Context) error
    IsConnected() bool
    SendMessage(ctx context.Context, req SendMessageRequest) (*SendMessageResult, error)
    Events() <-chan Event
}

type SessionFactory interface {
    Create(ctx context.Context, sessionID string) (Engine, error)
    Restore(ctx context.Context, sessionID string) (Engine, error)
    Remove(ctx context.Context, sessionID string) error
}
```

**Session ownership:** every session has exactly one owner. Two goroutines
(or two server instances) must never open the same device simultaneously.
For the MVP (single instance) this is enforced by an in-process session
registry with mutexes; multi-instance deployments will require a distributed
ownership/lease mechanism before they are supported.

## Database strategy

One PostgreSQL server, two owners:

- **whatscore schema** — `sessions`, `api_keys`, `messages`, `events`,
  `webhook_endpoints`, `webhook_deliveries`, `idempotency_keys`. Owned by
  WhatsCore's migrations.
- **whatsmeow tables** — device credentials, encryption keys, protocol
  state. Owned by whatsmeow's own SQL store and its lifecycle migrations.
  WhatsCore never modifies them directly.

Other properties:

- UUID primary keys, UTC timestamps, foreign keys for consistency.
- Message payloads are normalized, not raw engine objects.
- Media binaries go to the filesystem; only metadata goes to PostgreSQL.
- QR codes are never persisted — they are transient credentials.
- Retention policy for `messages`, `events`, `webhook_deliveries` is
  required before production (tracked for v0.1.1).

## Event flow and the transactional outbox

```
WhatsApp event
   → Engine adapter (whatsmeow)         [rule 3]
   → Event normalizer                   [rule 4]
   → PostgreSQL: events + webhook_deliveries in ONE transaction
   → Background delivery workers        [rule 5]
   → External webhook URL (HMAC-SHA256 signature)
```

The single-transaction write is a **transactional outbox**: if the process
crashes after an event is stored, the delivery record survives and workers
retry with exponential backoff (max 10 attempts by default, 10s request
timeout, HTTP 2xx = success). Every event has a unique id so receivers can
deduplicate.

## HTTP conventions

- Base path `/api/v1`; system probes (`/health`, `/ready`, `/version`) at
  the root so orchestrators don't need version knowledge.
- Authentication: `Authorization: Bearer wc_live_...`; keys stored as
  SHA-256 hashes only.
- Error envelope everywhere:

  ```json
  { "error": { "code": "not_found", "message": "..." } }
  ```

- `/ready` starts failing during graceful shutdown so load balancers drain
  the instance before sockets close.

## Log hygiene

Never log: API keys, QR values, pairing codes, session credentials, webhook
signing secrets. The logger lives in `internal/observability`; anything that
touches secrets passes through the engine adapter without logging.

## Open design questions

- **Session deletion cascades:** `messages`/`events` reference `sessions`
  without `ON DELETE CASCADE` (per spec §4). Session deletion must
  orchestrate cleanup explicitly; whether to add cascades is tracked for
  Milestone 2 when the session service lands.
- **Migration ownership on shared databases** where operators pre-apply
  migrations instead of auto-running them (`DB_MIGRATE_ON_STARTUP=false`).

## Technical decisions (v0.1 baseline)

| Component | Decision |
|-----------|----------|
| Language | Go |
| Architecture | Modular monolith |
| Engine | whatsmeow |
| Router | Chi |
| Database | PostgreSQL 16+ |
| Session storage | whatsmeow SQL store |
| Query layer | pgx (sqlc planned for Milestone 2 repositories) |
| Queue | PostgreSQL + goroutines |
| API | REST v1 |
| QR streaming | SSE |
| Webhook delivery | Transactional outbox |
| Deployment | Docker Compose |
| License | Apache-2.0 |
