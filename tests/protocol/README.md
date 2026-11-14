# Protocol tests

Wire-level conformance tests for the protocol engine. Every test corresponds
to a protocol finding in `docs/protocol/` (provenance: source, observation
date, confidence); a test may only assert what a finding records, and a
finding marked Confirmed must have at least one passing test referenced in
its **Proving test** field.

## Where the tests live

- **Package-local tests** (`protocol/transport/*_test.go`,
  `protocol/noise/*_test.go`) are the primary home: framing tables,
  in-memory `FrameConn` loopbacks, handshake round-trips, certificate
  negatives, and the deterministic vector checks.
- **`tests/integration/`** (build tag `integration`) runs the cross-package
  fake-server test: real WebSocket dial → Noise handshake → encrypted frame
  exchange. It must never contact a real WhatsApp endpoint.
- **This directory** is reserved for cross-package wire tests that do not
  belong to a single package. It is empty today.

## Conventions

- Golden fixtures live in `../fixtures` and carry a finding ID.
- Handshake tests run against the fake server or in-memory `FrameConn`
  pairs — never against real WhatsApp endpoints.
- Synthetic keys only; never commit real credentials, QR codes, or message
  content.
