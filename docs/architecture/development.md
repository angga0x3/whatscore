# Development

## Prerequisites

- Go 1.26+
- Docker (integration tests, full stack)
- [golangci-lint](https://golangci-lint.run/welcome/install/) v2 (for `make lint`)

## Repository layout

```
whatscore/
├── cmd/whatscore/          # entrypoint: main.go, app.go, engine.go, sessions.go, shutdown.go
├── cmd/whatscore-probe/    # read-only live transport probe
├── cmd/tokendict/          # token-table policy CLI
├── buildinfo/
├── config/
├── observability/
├── protocol/               # transport, noise, binary, protobuf, auth, pairing, messaging, media, signal, sync
├── server/                 # http/{router,handlers}, api (v1 sessions), webhook, middleware, auth
├── storage/                # interface.go, credentials/, envelope/, sqlite/, postgres/{...}
├── core/                   # events, session, engine, credentials, prekeys, signalsession, messaging, media, contacts, groups, client
├── docs/                   # architecture/, api/, protocol/, reverse-engineering/
├── examples/               # rest-api/ (curl scripts)
├── tests/                  # integration/, architecture/, protocol/, fixtures/
├── deployments/docker/
└── .github/                # workflows, ISSUE_TEMPLATE
```

Dependency direction and the architectural rules are documented in
[technical-specification.md](technical-specification.md) — read it before
your first PR.

## Day-to-day commands

| Command | What it does |
|---------|--------------|
| `make build` | Compile `bin/whatscore` with version ldflags |
| `make run` | Run locally, loading `.env` when present |
| `make test` | Unit tests with `-race` |
| `make test-integration` | Spin up a throwaway PostgreSQL and run migration tests |
| `make fmt` | `gofmt -s -w .` |
| `make lint` | golangci-lint (same as CI) |
| `make check` | fmt + vet + lint + test — what CI expects green |
| `go test -run=XXX -bench=. -benchmem ./protocol/signal/` | Crypto hot-path numbers (see performance.md) |
| `make docker-up` | Full stack via Docker Compose |

## Local run without Docker

You need a reachable PostgreSQL:

```bash
export DATABASE_URL="postgres://whatscore:password@localhost:5432/whatscore?sslmode=disable"
go run ./cmd/whatscore
```

Migrations apply automatically on startup (`DB_MIGRATE_ON_STARTUP=true`).

## Running with a live engine

`cmd/whatscore` builds a real `core/session` for every `POST /api/v1/sessions`.
The old behaviour — a session that only flipped an in-memory status string to
`CONNECTED` — is gone: `POST /api/v1/sessions/{id}/connect` now dials
`transport.DefaultEndpoint()` and runs the Noise handshake through
`core/engine`, so `CONNECTED` means an encrypted channel exists on the wire.

Two caveats on that status. The session's connector returns as soon as the
handshake finishes, and `engine.Connector` deliberately does not call
`Conn.WaitAuth` (see [engine.md](engine.md)), so `CONNECTED` does **not** mean
the server accepted the device's `ClientPayload`; that verdict arrives as the
first inbound stanza and nothing reads it yet. And the status is per-process:
`api.Manager` is in-memory.

Relevant environment variables:

| Variable | Effect |
|---|---|
| `ENCRYPTION_KEY` | Base64 of 32 bytes (`openssl rand -base64 32`). The key that seals the per-session credential record, prekeys and signing seed (AES-256-GCM through `storage/credentials.Vault`). Required in production; `config.Load` refuses to start without it. |
| `APP_ENV` | `production` disables the development fallback below. |
| `DATABASE_URL` | Where the sealed records live (`credentials` table). |
| `WHATSAPP_SESSION_LIMIT` | Parsed and validated at startup, but not enforced yet: nothing rejects a create past the limit. |

Development without `ENCRYPTION_KEY` still works: the server logs a warning and
seals records with an ephemeral in-memory key. Device identities then do not
survive a restart, and a second replica cannot read the first one's records —
that mode exists so `docker compose up` works with no configuration, and
production configuration rejects it outright rather than running unencrypted.

What a created session actually has:

- a Noise static key pair, a Signal identity key pair, a Signal registration ID,
  a 32-byte adv secret and a signed prekey, generated on first use and loaded
  afterwards, so a restart resumes the same device;
- the pinned server root key from `internal/waref` (PF-009), shared with
  `cmd/whatscore-probe` so the two cannot pin different values;
- a `core/engine` connector that rebuilds the `ClientPayload` on every dial, so
  a rotated signed prekey is picked up without recreating the session.

What still cannot work end to end:

- **Pairing cannot complete.** `StartPairing` verifies the server's
  `pair-success` container and then returns `engine.ErrSignerRequired`, because
  the device-identity signature needs an XEdDSA signer that does not exist yet
  (ADR 0001). The factory therefore leaves `engine.Config.Signer` nil instead of
  fabricating a signature.
- **There is no token/credential table in the REST layer.** A session created
  through the API is registered for this process only; `api.Manager` is
  in-memory, so the sealed device identity outlives the process but the session
  list does not. A durable session table has to land before "create, pair,
  restart, send" works as one flow.
- **Inbound frames are discarded.** The factory installs no `FrameHandler`, so
  the session reads (and therefore detects drops) but nothing decodes messages
  or publishes message events. The lifecycle event stream
  (`GET /api/v1/sessions/{id}/events`) is mounted, but a session only ever
  produces connect/disconnect events; the message and media routes still answer
  501 because no store is wired.

In one sentence: the transport, handshake and device identity are real; pairing
completion, the server's auth verdict, and the durable session/token layer are
not.

## Testing

- **Unit tests** live next to the code; they never touch the network or a
  database.
- **Architecture tests** (`tests/architecture/`) parse every package's
  imports and fail when a layer dependency from the technical specification
  §3.1 is crossed. They run with plain `go test ./...`.
- **Integration tests** are behind the `integration` build tag and live in
  `tests/integration/`. The migration test creates a scratch database,
  applies all migrations **up**, verifies the schema, rolls them **down**,
  verifies the schema is gone, and applies them **up** again; the fake-server
  test runs a real WebSocket dial → Noise handshake → encrypted frames with
  no database at all:

  ```bash
  TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable \
      go test -race -tags=integration ./tests/integration/...
  ```

  `TEST_DATABASE_URL` must point at a disposable database — the test creates
  and drops a scratch database inside that instance.

## Migrations

- Files: `migrations/NNNNNN_description.{up,down}.sql`, embedded via
  `go:embed` — the binary always brings its own schema.
- Every migration needs a working `down`; the integration test enforces it.
- **Released migrations are immutable.** Fix forward with a new migration.
- golang-migrate takes a PostgreSQL advisory lock, so concurrent startup
  instances serialize safely.

## Versioning and releases

- Version info is injected with `-ldflags` (`make build`, Docker build args,
  goreleaser). `go run` reports `dev`.
- Releases are cut by pushing a tag `vX.Y.Z`; the release workflow publishes
  binaries (goreleaser) and multi-arch images to GHCR.

## Renaming the module (forks)

The Go module is `github.com/angga0x3/whatscore`. If you fork under another
GitHub username:

```bash
grep -rl "github.com/angga0x3/whatscore" --include="*.go" --include="go.mod" | \
    xargs sed -i 's|github.com/angga0x3/whatscore|github.com/YOURNAME/whatscore|g'
go mod tidy
```

## CI

- `ci.yml` — tests (with PostgreSQL service), lint, and a Docker build on
  main pushes. The test step includes `tests/architecture`, which enforces
  the §3.1 import rules.
- `release.yml` — tag-triggered binary + container release.
