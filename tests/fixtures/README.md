# Test fixtures

Shared, deterministic test data for the protocol engine and its tests.

## Rules

- Fixtures are **SYNTHETIC**. Never commit real credentials, QR codes, phone
  numbers, session keys derived from real accounts, or message content.
- Every fixture references the protocol finding (`docs/protocol/`, e.g.
  PF-007) that documents where the byte layout comes from and how confident
  the project is about it.
- Proven fixtures are immutable: a correction adds a new fixture, never
  edits the old one.

## Current fixtures

| Fixture | Finding(s) | Shape |
|---------|------------|-------|
| `noise_vectors.json` | PF-004…PF-008 | JSON records: hash chain, key schedule after every mix, handshake ciphertexts, final transport keys, one frame per direction |
| `generate_noise_vectors.py` | PF-004…PF-008 | Generator: implements the algorithm from the finding text, independent of the Go code; fixed public seed strings only |

`noise_vectors.json` is regenerated with:

```bash
python3 tests/fixtures/generate_noise_vectors.py > tests/fixtures/noise_vectors.json
```

The script needs the `cryptography` package for AES-256-GCM; X25519 is
cross-checked against a self-contained RFC 7748 ladder. `protocol/noise`
asserts every value byte-for-byte, so a change to either side fails CI.

## Golden wire fixtures (Phase 2)

Once the binary codec lands, byte-exact fixtures use the original
convention: `tests/fixtures/<area>/<id>.hex` for the wire bytes plus a
parallel `.json` describing the decoded node and its `provenance` (`source`,
`observation_date`, `confidence`, `proving_test`). The JSON-vector form used
by the Noise handshake stays for state-machine values that are not a single
byte stream.
