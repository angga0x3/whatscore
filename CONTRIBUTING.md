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
  [docs/architecture.md](docs/architecture.md); the API contract lives in
  [api/openapi.yaml](api/openapi.yaml). Changes to either must be proposed in
  an issue first — the REST API is meant to be stable once released.
- **Milestones over vibes.** Each PR should advance a milestone from the
  roadmap in the README.
- **Conventional Commits** (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`,
  `chore:`) — they feed the release changelog.

## Pull request checklist

- [ ] `make check` passes locally (fmt, vet, lint, tests)
- [ ] New behavior has tests; bug fixes have a regression test
- [ ] Public API changes are reflected in `api/openapi.yaml`
- [ ] New configuration is documented in `docs/configuration.md` and
      `.env.example`
- [ ] No credentials, QR codes, or tokens in logs or test fixtures
- [ ] Architectural rules respected (see below)

## Architecture rules (non-negotiable)

1. HTTP handlers never call whatsmeow directly.
2. All WhatsApp operations go through application services.
3. The engine only handles WhatsApp communication.
4. Engine events are normalized before processing.
5. Webhooks are asynchronous.
6. Database access goes through repository interfaces.
7. Session credentials never appear in REST responses.

A PR that violates these gets sent back with pointers to
[docs/architecture.md](docs/architecture.md), not because we enjoy
bureaucracy but because these rules are what keeps the engine swappable.

## Code style

- `gofmt`-formatted (CI enforces via golangci-lint)
- Errors are wrapped with context (`fmt.Errorf("...: %w", err)`)
- `log/slog` for logging; structured fields, no `fmt.Println`
- Context flows from the HTTP request down to the engine

## Testing

- Unit tests next to the code (`go test -race ./...`)
- Integration tests in `test/integration/` behind the `integration` build
  tag, run against real PostgreSQL (`make test-integration`)
- Migrations are always tested up **and** down

## Security

Do not open public issues for security reports. Use GitHub's
*Report a vulnerability* (Security → Advisories) on the repository. Include
reproduction steps and affected versions; we aim to respond within a week.
Please do not test against WhatsApp accounts you do not own.
