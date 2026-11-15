# Development

## Prerequisites

- Go 1.26+
- Docker (integration tests, full stack)
- [golangci-lint](https://golangci-lint.run/welcome/install/) v2 (for `make lint`)

## Repository layout

```
whatscore/
├── cmd/whatscore/          # entrypoint: main.go, app.go, shutdown.go
├── buildinfo/
├── config/
├── observability/
├── protocol/               # transport, noise, binary, protobuf, auth, pairing, messaging, media, signal, sync
├── server/                 # http/{router,handlers}, api (v1 sessions), middleware, auth
├── storage/                # interface.go, credentials/, envelope/, postgres/{...}
├── core/                   # events, session, credentials, signalsession, messaging, media, contacts, groups, client
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
