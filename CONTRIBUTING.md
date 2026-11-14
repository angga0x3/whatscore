# Contributing to WhatsCore

Thanks for taking the time to contribute. This document keeps the project
consistent: one contract, one architecture, easy review.

## Getting started

```bash
git clone https://github.com/angga0x3/whatscore.git
cd whatscore
cp .env.example .env
make build && make test
```

Prerequisites: Go 1.25+, Docker (for integration tests and the full stack),
and [golangci-lint](https://golangci-lint.run/welcome/install/) for `make lint`.

## How we work

- **The spec is the contract.** Architecture rules live in
  [docs/architecture/technical-specification.md](docs/architecture/technical-specification.md);
  the API contract lives in [docs/api/openapi.yaml](docs/api/openapi.yaml).
  Changes to either must be proposed in an issue first — the REST API is
  meant to be stable once released.
- **Phases over vibes.** Each PR should advance a phase from the roadmap in
  the README.
- **Conventional Commits** (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`,
  `chore:`) — they feed the release changelog.

## Pull request checklist

- [ ] `make check` passes locally (fmt, vet, lint, tests)
- [ ] New behavior has tests; bug fixes have a regression test
- [ ] Protocol claims cite a finding ID from
      [docs/protocol/README.md](docs/protocol/README.md) (Confirmed only)
- [ ] New dependencies pass the dependency policy in the
      [technical specification](docs/architecture/technical-specification.md)
- [ ] Conventional Commits kept (`feat:`, `fix:`, `docs:`, `refactor:`,
      `test:`, `chore:`) — they feed the release changelog
- [ ] Public API changes are reflected in `docs/api/openapi.yaml`
- [ ] New configuration is documented in
      [docs/architecture/configuration.md](docs/architecture/configuration.md)
      and `.env.example`
- [ ] No credentials, QR codes, or tokens in logs or test fixtures —
      synthetic keys only
- [ ] Architectural rules respected (see below)

## Architecture rules (non-negotiable)

1. **`protocol/*` never imports `core/*`, `server/*`, `storage/*`, or
   `config/*`.** The protocol engine stands alone on the standard library.
2. **`core/*` imports `protocol` only through the documented interfaces** in
   [docs/architecture/technical-specification.md](docs/architecture/technical-specification.md).
3. **`server/*` is an adapter over the core.** It never grows a second
   protocol implementation.
4. **One session, one actor.** Exactly one owner per WhatsApp session — two
   goroutines or two instances never drive the same device simultaneously.
5. **Storage backends implement `storage.Store`.** No direct database access
   anywhere else.
6. **Implementation code depends only on Confirmed protocol findings** — see
   [docs/protocol/README.md](docs/protocol/README.md). Folklore and
   unverified observations do not enter the codebase.
7. **No credentials, QR codes, or personal data in fixtures.** Synthetic
   keys only ([tests/fixtures/README.md](tests/fixtures/README.md)).

A PR that violates these gets sent back with pointers to
[docs/architecture/technical-specification.md](docs/architecture/technical-specification.md),
not because we enjoy bureaucracy but because these rules are what keeps the
layers independently testable and the protocol engine trustworthy.

## Code style

- `gofmt`-formatted (CI enforces via golangci-lint)
- Errors are wrapped with context (`fmt.Errorf("...: %w", err)`)
- `log/slog` for logging; structured fields, no `fmt.Println`
- Context flows from the HTTP request down to the engine

## Testing

- Unit tests next to the code (`go test -race ./...`)
- Integration tests in `tests/integration/` behind the `integration` build
  tag, run against real PostgreSQL (`make test-integration`)
- Migrations are always tested up **and** down

## Security

Do not open public issues for security reports — see [SECURITY.md](SECURITY.md)
for the reporting process, scope, expected response time, and safe harbor.
Please do not test against WhatsApp accounts you do not own.
