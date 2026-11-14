# Development

## Prerequisites

- Go 1.25+
- Docker (integration tests, full stack)
- [golangci-lint](https://golangci-lint.run/welcome/install/) v2 (for `make lint`)

## Repository layout

```
whatscore/
├── cmd/whatscore/          # entrypoint
├── internal/               # application code (not importable by others)
│   ├── app/                # composition root + lifecycle
│   ├── auth/               # API key handling
│   ├── buildinfo/          # ldflags version info
│   ├── config/             # env config
│   ├── observability/      # logging setup
│   ├── storage/postgres/   # pool + migrations runner
│   └── transport/http/     # chi router, middleware, handlers
├── migrations/             # SQL migrations (embedded)
├── api/openapi.yaml        # REST contract
├── docs/                   # you are here
├── deployments/docker/     # Dockerfile
├── test/integration/       # real-PostgreSQL tests
└── examples/               # runnable snippets
```

Dependency direction and the architectural rules are documented in
[architecture.md](architecture.md) — read it before your first PR.

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
- **Integration tests** are behind the `integration` build tag and live in
  `test/integration/`. They create a scratch database, apply all migrations
  **up**, verify the schema, roll them **down**, verify the schema is gone,
  and apply them **up** again:

  ```bash
  TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable \
      go test -tags=integration ./test/integration/...
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
  main pushes.
- `release.yml` — tag-triggered binary + container release.
