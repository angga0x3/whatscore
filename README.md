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
pure Go. It owns its own protocol engine — transport, Noise, binary codec,
pairing, Signal — plus an idiomatic **Go SDK** and a **self-hosted REST API**.

The transport and Noise layers are verified against the live service. The rest
is implemented, tested against a fake server, and honest about what it has not
proven yet. No port of an existing library, no CGo, one static binary.

## Status

The protocol engine is real, and one part of it is proven against the live
service: **transport and the Noise handshake complete against
`wss://web.whatsapp.com/ws/chat`**, including certificate verification against
the pinned root key (four out of four runs, reproducible with
`go run ./cmd/whatscore-probe`).

Everything after that handshake is still unproven against WhatsApp: binary
encoding needs the token table, pairing needs a signature the project has not
decided how to implement, and no message has been delivered.

| Layer | State |
|-------|-------|
| Transport + Noise | **Live-verified** (`PF-002…PF-009`) |
| Binary codec | Implemented and fuzz-tested; needs the real token table |
| Pairing | QR, stanzas, identity verification, credential vault; **signing undecided** (ADR 0001) |
| Auth payloads | Registration + login implemented and unit-tested; not yet accepted live |
| Signal | X3DH, ratchet, message crypto, prekey bootstrap, persistence — vector-tested |
| Media | Envelope, streaming, range; orchestrated through the SDK |
| App-state sync | Patch parse, mutation decode, LTHash, envelope MACs |
| REST + SDK | Sessions, messages, media, webhooks, SSE; SDK send/receive encrypted |

Two things block live use, and neither is code: the **token table licence**
(spec §10.2, validator ready in `cmd/tokendict`) and the **XEdDSA signer**
(ADR 0001). Until both are settled this project makes no claim of working
against WhatsApp — see [compatibility](docs/architecture/compatibility.md).

## Roadmap

| Phase | Milestone | Status |
|-------|-----------|--------|
| 0 | Foundation — skeleton, config, PostgreSQL, migrations, CI | **Complete** |
| 1 | Transport & Noise | **Complete** — live handshake verified |
| 2 | Binary protocol | **Complete** — token table external (licence pending) |
| 3 | Pairing & authentication | **Blocked** on the signer decision (ADR 0001) |
| 4 | Messaging (Signal) | **Complete** pending live interop |
| 5 | Public SDK | **Complete** pending live interop |
| 6 | API server | **Complete** pending live interop |
| 7 | Release v0.1.0 | **Blocked** on phases 3 and 2 |

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
    client.WithSessionStore(sessions), // optional per-peer Signal persistence
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

// Plaintext stanza (no Signal encryption):
id, err := c.SendMessage(ctx, client.Message{To: "628123456789@s.whatsapp.net", Text: "Hello!"})

// Signal-encrypted, choosing pkmsg vs msg and persisting the ratchet:
id, err = c.SendEncrypted(ctx, client.Message{To: "628123456789@s.whatsapp.net", Text: "Hi!"})

// Contact and group caches (events published on real changes):
_, _ = c.UpsertContact(contacts.Contact{JID: "628123@s.whatsapp.net", Name: "Ani"})
_ = c.UpsertGroup(ctx, groups.Group{ID: "123@g.us", Subject: "Team", Participants: []string{"a@s.whatsapp.net"}})

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
| [docs/architecture/compatibility.md](docs/architecture/compatibility.md) | What is proven, against what, and how to reproduce it |
| [docs/architecture/performance.md](docs/architecture/performance.md) | Measured hot-path numbers and what is *not* claimed |
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
