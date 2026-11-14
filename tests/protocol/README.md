# Protocol tests

Wire-level conformance tests for the protocol engine, organized by layer
(transport, noise, binary). Every test here corresponds to a protocol
finding in docs/protocol/ (provenance: source, observation date,
confidence); a test may only assert what a finding records, and a finding
marked Confirmed must have at least one passing test referenced in its
Proving test field.

Conventions:
- Golden fixtures live in ../fixtures (byte-exact hex + JSON mirror) and
  carry a finding ID.
- Handshake tests run against the fake server (tests/integration) or
  in-memory FrameConn pairs — never against real WhatsApp endpoints.
- Synthetic keys only; never commit real credentials, QR codes, or message
  content.

Status: empty — populated from Phase 1 onward.
