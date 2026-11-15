# Performance notes

Budget notes for the hot paths, with the commands that produce the numbers.
Run benchmarks on the target hardware before drawing conclusions; the values
below are from a 4-core arm64 development machine with Go 1.26.

## Headline numbers

| Path | Benchmark | Time | Throughput | Allocs |
|------|-----------|------|------------|--------|
| Binary encode (text stanza) | `BenchmarkEncode` | 1.25 us | — | 7 |
| Binary decode (text stanza) | `BenchmarkDecode` | 1.26 us | 62 MB/s | 13 |
| Binary encode (64 KiB payload) | `BenchmarkEncodeLargeMedia` | 10.8 us | 6.0 GB/s | 4 |
| Signal encrypt (256 B) | `BenchmarkEncryptMessage` | 3.1 us | 81 MB/s | 19 |
| Signal decrypt (256 B) | `BenchmarkDecryptMessage` | 2.8 us | 90 MB/s | 18 |
| Ratchet outbound step | `BenchmarkRatchetOutbound` | 4.5 us | — | 41 |
| Ratchet receive step | `BenchmarkRatchetReceive` | 9.3 us | — | 82 |
| Media encrypt (1 MiB, buffered) | `BenchmarkEncrypt1MiB` | 2.43 ms | 431 MB/s | 13 |
| Media decrypt (1 MiB, buffered) | `BenchmarkDecrypt1MiB` | 2.21 ms | 475 MB/s | 11 |
| Media encrypt (1 MiB, streaming) | `BenchmarkEncryptStream1MiB` | 2.03 ms | 518 MB/s | 15 |
| Media key derivation | `BenchmarkDeriveKeys` | 3.1 us | — | 27 |
| Ratchet state marshal (100 skipped) | `BenchmarkStateMarshal` | 26 us | — | 2 |
| Ratchet state unmarshal | `BenchmarkStateUnmarshal` | 13 us | — | 7 |
| Session save+load (vault) | `BenchmarkSaveLoad` | 3.3 us | — | 17 |
| Prekey bundle read | `BenchmarkBundle` | 126 ns | — | 2 |

Reproduce with:

```bash
go test -run=XXX -bench=. -benchtime=300ms -benchmem ./protocol/binary/
go test -run=XXX -bench=. -benchtime=300ms -benchmem ./protocol/signal/
go test -run=XXX -bench=. -benchtime=300ms -benchmem ./protocol/media/
go test -run=XXX -bench=. -benchtime=300ms -benchmem ./core/prekeys/ ./core/signalsession/
```

## Why streaming media is the default choice

`EncryptStream` at 1 MiB is both faster (518 vs 431 MB/s) and far lighter
(122 KB vs 3.1 MB allocated) than the buffered path, because the working set is
one 32 KiB chunk plus one AES block instead of the whole payload. The buffered
`Encrypt` stays for small payloads and for callers that already hold the bytes.

Decryption pays a second pass to authenticate before writing anything — that is
a deliberate security trade, not overhead to optimise away.

## Structural advantages over Node-based implementations

These are architectural, not benchmark results, and they are the reason the
engine is small:

- **No runtime hop.** Baileys runs inside Node; WAHA adds an HTTP layer in front
  of a Node process. WhatsCore is one static Go binary, so a message crosses
  zero process boundaries and zero HTTP calls inside the server.
- **No browser.** WAHA's web-client mode drives Chromium; here the wire protocol
  is implemented directly, so idle memory is the Go runtime, not a browser.
- **Bounded memory.** Codec, decoder, ratchet state, SSE queues, and media
  streams all have explicit caps; a hostile peer cannot make the process
  allocate without bound.
- **Allocation discipline.** Hot paths avoid whole-payload buffers, borrow
  parse input, sort deterministically instead of iterating maps, and reuse
  stack buffers for MAC inputs.

## What is *not* claimed

No head-to-head benchmark against Baileys or WAHA is published, because it
would require running both against a live WhatsApp account and comparing
end-to-end delivery latency — which needs the real token table and manual
interop (see roadmap). Any such comparison must measure the same operation on
the same hardware; until then, only the numbers above are facts.

## Known costs

- `ParseMessage` borrows the input buffer (documented), so callers must not
  mutate a wire slice before decryption finishes.
- `State.Decrypt` parses once and reuses the parsed message.
- Ratchet state serialization sorts map entries to stay deterministic; cost is
  linear in chain/skipped-key count and bounded by the configured limits.
- Signal encrypt/decrypt allocations are dominated by stdlib HKDF/HMAC and
  protobuf. Replacing vetted primitives with hand-rolled encoders would trade
  correctness for micro-optimisation, which this project does not do.

## Regression policy

Benchmarks are not gated in CI yet. When a hot path changes, record before and
after numbers in the PR description; a >20% regression needs justification.
