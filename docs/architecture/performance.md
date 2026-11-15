# Performance notes

Budget notes for the hot paths, with the commands that produce the numbers.
Run benchmarks on the target hardware before drawing conclusions; the values
below are from a 4-core arm64 development machine.

## Signal message crypto

```bash
go test -run=XXX -bench=. -benchtime=300ms -benchmem ./protocol/signal/
go test -run=XXX -bench=. -benchtime=300ms -benchmem -tags=integration ./... 
```

| Benchmark | Time | Memory | Allocs |
|-----------|------|--------|--------|
| EncryptMessage (256 B) | ~3.1 us | 3.7 KB | 19 |
| DecryptMessage (256 B) | ~2.8 us | 2.6 KB | 18 |
| RatchetOutbound | ~4.5 us | 2.8 KB | 41 |
| RatchetReceive | ~9.0 us | 5.6 KB | 82 |
| State round trip | ~15.7 us | 12 KB | 119 |
| State marshal (100 skipped) | ~26 us | 16 KB | 2 |
| State unmarshal | ~13 us | 17 KB | 7 |
| signalsession save+load | ~3.3 us | 3.8 KB | 17 |

Remaining allocations are dominated by stdlib HKDF/HMAC and protobuf, which
are kept deliberately: replacing vetted primitives with hand-rolled encoders
would trade correctness for micro-optimisation.

## Known costs

- `ParseMessage` borrows the input buffer (documented), so callers must not
  mutate a wire slice before decryption finishes.
- `State.Decrypt` parses once and reuses the parsed message.
- Ratchet state serialization sorts map entries to stay deterministic; the
  cost is linear in chain/skipped-key count and bounded by the configured
  limits.

## Regression policy

Benchmarks are not gated in CI yet. When a hot path changes, record before and
after numbers in the PR description; a >20% regression needs justification.
