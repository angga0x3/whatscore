# Test fixtures

Shared, deterministic test data for the protocol engine and its tests.

Rules:
- Fixtures are SYNTHETIC. Never commit real credentials, QR codes, phone
  numbers, session keys derived from real accounts, or message content.
- Golden wire fixtures are stored as hex-encoded text plus a JSON mirror
  describing the decoded structure, so reviews can see both bytes and
  meaning side by side.
- Every fixture references the protocol finding (docs/protocol/, e.g.
  PF-007) that documents where the byte layout comes from and how confident
  the project is about it.

Status: empty — first fixtures land with the binary codec tests (Phase 2).
