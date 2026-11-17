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

The transport and Noise layers are verified against the live service, and so is
the rest of the core path: pairing, login, sending, receiving, media receive,
and app-state sync have all run against WhatsApp with a real phone. What has
not been proven is named in [Status](#status) rather than implied. No port of an
existing library, no CGo, one static binary.

## Status

The protocol engine runs against the live service. A real phone has scanned a
WhatsCore QR, the link completed, and the device has since logged in, sent, and
received — with the caveat that every live run used a token table supplied by
the operator, which this repository does not ship.

| Layer | State |
|-------|-------|
| Transport + Noise | **Live-verified** (`PF-002…PF-009`) |
| Binary codec | Live-verified with an operator-supplied table; none ships (spec §10.2) |
| Pairing | **Live-verified** — QR → `pair-success` → `pair-device-sign` → credentials (PF-073…PF-079) |
| Auth payloads | **Live-verified** — registration and login accepted (PF-068, PF-077) |
| Signal | **Live-verified** — pkmsg bootstrap, ratchet continuation, persistence (PF-065, PF-087) |
| Media | **Receive live-verified**; send implemented in the probe, not yet live |
| App-state sync | **Live-verified** — 11 key shares, 15 patches, 39/39 mutations decoded |
| REST + SDK | Implemented and tested against the fake server; not yet run live |

Proven against the live service:

- [x] WebSocket transport, intro header, frame reassembly
- [x] Noise handshake, including certificate verification against the pinned root
- [x] Pairing end to end: QR, `pair-success` verification, `pair-device-sign`, credentials
- [x] Login with paired credentials
- [x] Sending a text message, acknowledged by the server and delivered to the phone
- [x] Receiving: offline queue drain, pkmsg bootstrap, decrypt, delivery receipts
- [x] Receiving media: a sticker decrypted, downloaded, SHA-256 verified, written to disk
- [x] App-state sync, history chunks acknowledged, provisioning banner released

Not proven, and not claimed:

- [ ] Media **send** — implemented in the probe, no live upload recorded
- [ ] The own-device copy of a send (`PF-090`) — implemented, not yet seen on the phone
- [ ] The REST server and SDK against the live service (they are tested against the fake server)
- [ ] Group **sending** — group receive decrypts (sender keys, PF-093); enumeration of a group's devices and the send side are not implemented
- [ ] Newsletters beyond plaintext notifications

Two things still gate a general-purpose deployment, and neither is protocol
code: the **token table** is operator data (spec §10.2, validator in
`cmd/tokendict`), and every live claim above was made with one supplied; the
**XEdDSA signer** was a project decision (ADR 0001), now implemented and in
use. See [compatibility](docs/architecture/compatibility.md) for the row-by-row
state.

## Roadmap

| Phase | Milestone | Status |
|-------|-----------|--------|
| 0 | Foundation — skeleton, config, PostgreSQL, migrations, CI | **Complete** |
| 1 | Transport & Noise | **Complete** — live handshake verified |
| 2 | Binary protocol | **Complete** — token table is operator data |
| 3 | Pairing & authentication | **Complete** — live pairing and login verified |
| 4 | Messaging (Signal) | **Complete** — live send and receive verified |
| 5 | Public SDK | **Complete** pending live interop |
| 6 | API server | **Complete** pending live interop |
| 7 | Release v0.1.0 | **Next** — media send, own-device copy on the phone, live SDK interop |

**v0.0.1 — released 2026-11-15.** A protocol foundation preview. Everything
above landed after it and is recorded in the [changelog](CHANGELOG.md).

## SDK

A first SDK facade exists in `core/client` (`github.com/angga0x3/whatscore/core/client`):
connect, disconnect, state, events, credential access, plaintext and
Signal-encrypted text sending, inbound text events, and receipts. It is tested
against the fake server and has not been run against WhatsApp yet.

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

## Quickstart

The REST server runs against PostgreSQL. Pairing and messaging need an operator
token table (spec §10.2) — the server starts without one, but a session cannot
decode or encode WhatsApp frames until it is supplied. The live path so far is
the probe, documented in [docs/pairing-manual.md](docs/pairing-manual.md).

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
