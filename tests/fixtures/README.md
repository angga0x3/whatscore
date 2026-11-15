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
| `binary_vectors.json` | PF-010…PF-014 | JSON records: synthetic token table, one node per vector, exact frame hex |
| `generate_binary_vectors.py` | PF-010…PF-014 | Generator: implements the wire rules from the finding text, independent of the Go code |
| `signal_vectors.json` | PF-050…PF-053 | JSON records: DH1…DH4, root key, chain key for fixed synthetic keys |
| `generate_signal_vectors.py` | PF-050…PF-053 | Generator: X25519 + HKDF-SHA256 ("WhisperText") from the finding text |
| `signal_ratchet_vectors.json` | PF-054…PF-056 | JSON records: root ratchet, three chain steps, message keys |
| `generate_signal_ratchet_vectors.py` | PF-054…PF-056 | Generator: X25519 + HKDF ("WhisperRatchet"/"WhisperMessageKeys") + HMAC |

`noise_vectors.json` is regenerated with:

```bash
python3 tests/fixtures/generate_noise_vectors.py > tests/fixtures/noise_vectors.json
```

The script needs the `cryptography` package for AES-256-GCM; X25519 is
cross-checked against a self-contained RFC 7748 ladder. `protocol/noise`
asserts every value byte-for-byte, so a change to either side fails CI.

## Binary fixtures

`binary_vectors.json` carries the synthetic token table and, per vector, both
the decoded node and the exact frame hex. Regenerate with:

```bash
python3 tests/fixtures/generate_binary_vectors.py > tests/fixtures/binary_vectors.json
```

`protocol/binary` decodes every hex, compares the node, re-encodes it, and
requires byte equality — so the Python and Go encoders must agree.

## Signal fixtures

`signal_vectors.json` pins the X3DH DH order and derivation. Regenerate with:

```bash
python3 tests/fixtures/generate_signal_vectors.py > tests/fixtures/signal_vectors.json
```

`protocol/signal` recomputes every DH and the root/chain keys from fixed
private keys, so the Python and Go implementations must agree.

If a future area needs a byte-blob fixture that is not a JSON node (e.g. a
protobuf message), use the original convention: `tests/fixtures/<area>/<id>.hex`
for the bytes plus a `.json` mirror describing the decoded value and its
`provenance` (`source`, `observation_date`, `confidence`, `proving_test`).
