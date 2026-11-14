<h1 align="center">WhatsCore</h1>

<p align="center">
  <em>Your WhatsApp. Your Infrastructure. Your Control.</em>
</p>

<p align="center">
  <a href="#quickstart">Quickstart</a> ·
  <a href="#api">API</a> ·
  <a href="docs/architecture.md">Architecture</a> ·
  <a href="docs/configuration.md">Configuration</a> ·
  <a href="docs/development.md">Development</a> ·
  <a href="#roadmap">Roadmap</a>
</p>

<p align="center">
  <a href="https://pkg.go.dev/github.com/angga0x3/whatscore"><img alt="Go Reference" src="https://img.shields.io/badge/go-reference-00ADD8?logo=go&logoColor=white"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-blue"></a>
  <img alt="Self-hosted" src="https://img.shields.io/badge/self--hosted-✓-green">
</p>

---

**WhatsCore** is an open-source REST API server that lets your applications
connect to WhatsApp through session management and a messaging engine. One
server handles multiple WhatsApp accounts, self-hosted, on your own
infrastructure.

- **Modular monolith in Go** — one binary, clear module boundaries
- **Stable REST API** — versioned contract, OpenAPI 3.1 (`api/openapi.yaml`)
- **Engine-agnostic** — whatsmeow today, pluggable engines tomorrow
- **Secure by design** — hashed API keys, HMAC-signed webhooks, QR never logged
- **Event-driven** — normalized events, transactional outbox, retry with backoff
- **Easy to run** — `docker compose up -d`, no Redis/Kafka/Kubernetes required

> ⚠️ **Disclaimer** — WhatsCore uses an unofficial WhatsApp protocol
> implementation ([whatsmeow](https://github.com/tulir/whatsmeow)). This may
> break with protocol changes and, in rare cases, can lead to account
> restrictions. Use dedicated numbers for automation, not your personal one.

## Quickstart

```bash
git clone https://github.com/angga0x3/whatscore.git
cd whatscore
cp .env.example .env
docker compose up -d
```

Verify the stack:

```bash
curl http://localhost:8080/health   # {"status":"ok"}
curl http://localhost:8080/ready    # {"status":"ready","checks":{"database":{"status":"up",...}}}
curl http://localhost:8080/version
```

PostgreSQL starts first (healthcheck-gated), WhatsCore connects, applies its
schema migrations, and begins serving. See
[docs/configuration.md](docs/configuration.md) for every environment variable.

## API

Full contract: [api/openapi.yaml](api/openapi.yaml) (OpenAPI 3.1).
Interactive examples: [docs/api-reference.md](docs/api-reference.md).

| Method | Endpoint | Fungsi |
| ------ | -------- | ------ |
| GET | `/health` | Liveness |
| GET | `/ready` | Readiness (checks PostgreSQL) |
| GET | `/version` | Build info |
| POST | `/api/v1/sessions` | Create session |
| GET | `/api/v1/sessions/{id}/qr` | QR auth (SSE) |
| POST | `/api/v1/sessions/{id}/messages/text` | Send text |
| POST | `/webhooks` | Register webhook |

Sending is idempotent via the `Idempotency-Key` header, and every send
returns `202 Accepted` because `QUEUED` does not mean delivered:

```
QUEUED → SENDING → SENT → DELIVERED → READ   (FAILED on error)
```

Webhook payloads are signed with HMAC-SHA256 and carry a unique event `id`
for deduplication on your side.

## Architecture

Modular monolith with strict dependency direction:

```
HTTP Handler → Application Service → Domain Interface → Infrastructure Adapter → External System
```

Highlights: whatsmeow device store owns session credentials (WhatsCore never
sees them), engine events are normalized before processing, webhook delivery
is asynchronous via a transactional outbox, and QR endpoints are
authenticated with QR values excluded from logs. Full write-up:
[docs/architecture.md](docs/architecture.md).

## Roadmap

- [x] **Milestone 1 — Foundation** (this release): Go project, config,
      PostgreSQL, migrations, Chi router, health/readiness endpoints,
      Docker Compose, CI
- [ ] **Milestone 2 — WhatsApp engine**: whatsmeow integration, session
      manager, QR authentication, connection lifecycle, session persistence
- [ ] **Milestone 3 — Messaging**: send/receive text, message persistence,
      status tracking, idempotency
- [ ] **Milestone 4 — Webhooks**: event normalization, outbox, delivery
      workers, HMAC signatures, retries
- [ ] **v0.1.0 release**: OpenAPI docs, integration tests, README, license

## Development

```bash
make build          # bin/whatscore
make test           # unit tests (-race)
make test-integration  # migrations against a throwaway PostgreSQL
make check          # fmt + vet + lint + test
```

See [docs/development.md](docs/development.md) and
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache-2.0](LICENSE). Note that dependencies keep their own licenses —
whatsmeow is MPL-2.0; its distribution requirements are audited before any
binary release.

## Security

Report vulnerabilities privately instead of opening a public issue — see
[CONTRIBUTING.md](CONTRIBUTING.md#security) for the reporting process and
[docs/architecture.md](docs/architecture.md) for the security model.
