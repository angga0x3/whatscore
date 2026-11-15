<h1 align="center">WhatsCore</h1>

<p align="center">
  <em>Your WhatsApp. Your Infrastructure. Your Control.</em>
</p>

<p align="center">
  <a href="https://pkg.go.dev/github.com/angga0x3/whatscore"><img alt="Go Reference" src="https://pkg.go.dev/badge/github.com/angga0x3/whatscore.svg"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-blue"></a>
  <img alt="Self-hosted" src="https://img.shields.io/badge/self--hosted-%E2%9C%93-green">
</p>

---

**WhatsCore** is an independent WhatsApp Web protocol implementation written in
pure Go. The project owns its own protocol engine — WebSocket transport, Noise
handshake, binary node codec, pairing, and Signal-style end-to-end encryption —
and ships two public interfaces on top of the same application core: an
idiomatic **Go SDK** and a **self-hosted REST API server**. It is not a port of
an existing library and not a wrapper around one; the wire protocol is
implemented from first principles, documented in the open.

## Status

> **Phases 3–5 — in progress.** Phase 3 has QR payloads, stanza parsers,
> device-identity authentication, the credential vault, registration
> payloads, and the credential manager; device-signature generation (ADR
> 0001) remains. Phase 4 has the messaging stanza layer, plaintext text send
> inbound text events, and receipts, and the media envelope; Signal X3DH is
> implemented, along with the root/chain/message-key schedule (state machine and
> message encryption pending); sync remains.
> Phase 5 has the event bus, session actor, credentials, and SDK facade;
> orchestration remains. The real token table and live interop are still open.

| Layer | Status |
|-------|--------|
| Protocol engine | Transport, Noise, binary, pairing + auth payloads, messaging stanzas, media envelope; device signature, Signal/sync, token table pending |
| Application core | `core/events`, `core/session`, `core/credentials`, `core/messaging`, `core/client` (plaintext send); inbound events/orchestration pending |
| Storage | Interfaces + migrations; `storage/envelope`, `storage/credentials` vault, PostgreSQL credential backend |
| Application core | Designed — implementation starts in Phase 5 |
| REST server | Foundation implemented — `/health`, `/ready`, `/version` |

This project holds itself to one principle: **no fake feature claims —
demo > promises.** Anything labeled as a target below is design, not a shipped
capability.

> ⚠️ **Disclaimer**
>
> - WhatsCore is an **unofficial** implementation of the WhatsApp Web
>   protocol. It is not affiliated with, endorsed by, or connected to Meta or
>   WhatsApp in any way.
> - The protocol is undocumented and changes without notice. Any
>   implementation can break at any time.
> - Automating WhatsApp carries a real risk of **account restriction or ban**.
> - Use **dedicated accounts you control** for any automation — never your
>   personal number.
> - Reverse-engineering the protocol follows ethics rules documented in
>   [docs/reverse-engineering/README.md](docs/reverse-engineering/README.md).

## Architecture

Three layers, dependencies pointing downward only:

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

- [docs/architecture/technical-specification.md](docs/architecture/technical-specification.md)
  — the detailed architecture, source of truth for every rule.
- [docs/protocol/README.md](docs/protocol/README.md) — the provenance policy:
  every protocol finding carries its source, date, confidence level, and the
  tests that prove it. Implementation code depends on Confirmed findings only.

## Roadmap

| Phase | Milestone | Status |
|-------|-----------|--------|
| 0 | Foundation — server skeleton, config, PostgreSQL, migrations, CI | **Complete** |
| 1 | Transport & Noise — WebSocket transport, Noise handshake | **Complete** (fake-server; live interop pending) |
| 2 | Binary protocol — node encode/decode | **Complete** — codec, vectors, fuzz, protobuf round-trip; token table external |
| 3 | Pairing & authentication — QR / pairing code | **In progress** — QR, stanzas, identity verification, auth payloads, credential vault, credential manager done; device signature (ADR 0001) pending |
| 4 | Messaging (Signal) — send/receive with E2E | **In progress** — plaintext send, inbound text, receipts, X3DH + key schedule done; ratchet state/messages/sync pending |
| 5 | Public SDK — idiomatic Go client | **In progress** — events/session/credentials + client facade + plaintext send; inbound/orchestration pending |
| 6 | API server — sessions, messaging, webhooks over the core | Planned |
| 7 | Release v0.1.0 | Planned |

**v0.0.1 target — protocol foundation preview:**

- [x] WebSocket transport runs
- [x] Noise handshake succeeds
- [x] Binary node encode/decode works
- [x] Fake-server integration test passes
- [x] Protocol docs available

v0.0.1 is not cut yet. The codec and protobuf messages round-trip, but the
real WhatsApp token table is still an open licensing question (technical
specification §10.2), and no compatibility with the live endpoint is claimed
before manual interop is recorded as a protocol finding.

## SDK

A first SDK facade exists in `core/client` (`github.com/angga0x3/whatscore/core/client`):
connect, disconnect, state, events, credential access, plaintext text
sending, inbound text events, and receipts. **End-to-end encryption is not wired yet** —
the text frame is only protected by transport encryption when a Noise connector
is installed; Signal lands next.

**Current API:**

```go
c, _ := client.New("session-1",
    client.WithCredentials(manager),   // optional encrypted credential manager
    client.WithConnector(noiseConnector), // optional transport wrapper
    client.WithFrameHandler(handler),  // optional inbound frame sink
    client.WithLogger(slog.Default()),
)
defer c.Close(ctx)

sub := c.Subscribe()
defer sub.Close()
// ev.Type == events.TypeMessage carries inbound text (Direction=Incoming).

_ = c.Connect(ctx)
state, _ := c.State(ctx)               // CONNECTED
id, err := c.SendMessage(ctx, client.Message{To: "628123456789@s.whatsapp.net", Text: "Hello!"})
_ = c.SendReceipt(ctx, "628123456789@s.whatsapp.net", id, "read")
_ = c.Disconnect(ctx)
```

A root-level `whatscore.NewClient` alias and the full target API land once the
SDK shape freezes (Phase 5).

## Quickstart (works today)

Only the REST server foundation runs today. The protocol engine cannot connect
to WhatsApp yet — see [Status](#status).

```bash
git clone https://github.com/angga0x3/whatscore.git
cd whatscore
cp .env.example .env
docker compose up -d
```

PostgreSQL starts first (healthcheck-gated), WhatsCore connects, applies its
embedded schema migrations, and begins serving. Verify:

```bash
curl -s http://localhost:8080/health
# {"status":"ok"}

curl -s http://localhost:8080/ready
# {"status":"ready","checks":{"database":{"status":"up","latency_ms":0.417}}}

curl -s http://localhost:8080/version
# {"name":"WhatsCore","version":"dev","commit":"none","built_at":"unknown","go_version":"go1.26.0"}
```

Every environment variable is documented in
[docs/architecture/configuration.md](docs/architecture/configuration.md).

## Documentation

| Document | What it covers |
|----------|----------------|
| [docs/architecture/technical-specification.md](docs/architecture/technical-specification.md) | Detailed architecture — the source of truth |
| [docs/architecture/roadmap.md](docs/architecture/roadmap.md) | Execution plan: workstreams, boundaries, acceptance criteria |
| [docs/architecture/overview.md](docs/architecture/overview.md) | Short public architecture overview |
| [docs/protocol/README.md](docs/protocol/README.md) | Protocol provenance policy — source, date, confidence, proving tests |
| [docs/reverse-engineering/README.md](docs/reverse-engineering/README.md) | Reverse-engineering methodology and ethics rules |
| [docs/api/reference.md](docs/api/reference.md) · [docs/api/openapi.yaml](docs/api/openapi.yaml) | REST API reference and OpenAPI 3.1 contract |
| [docs/architecture/configuration.md](docs/architecture/configuration.md) | Configuration reference (all environment variables) |
| [docs/architecture/development.md](docs/architecture/development.md) | Development guide (build, test, release) |

## Contributing

Pull requests are welcome — read [CONTRIBUTING.md](CONTRIBUTING.md) first for
the layer rules, the protocol provenance requirements, and the PR checklist.

## Security

Report vulnerabilities privately, never as public issues — the process, scope,
and safe harbor statement live in [SECURITY.md](SECURITY.md). Never paste
credentials, QR codes, or tokens into any issue.

## License

[Apache-2.0](LICENSE).
