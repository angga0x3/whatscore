# Running a pairing attempt

This is the operator procedure for linking a dedicated test account. It is
manual on purpose: it touches an account, so it is never automated in CI.

## Before you start

- **Use a dedicated number.** Unofficial clients violate WhatsApp's terms and
  carry a real ban risk. Never use a personal number.
- **A token table is required.** `deployments/tokendict/pairing-minimal.json`
  decodes the pairing stanza; without `-dict` the command refuses to start.
- Understand that a failed attempt can leave a dangling entry under
  Linked devices. Remove it from the phone if that happens.

## Run

```bash
go run ./cmd/whatscore-probe \
  -pair \
  -dict deployments/tokendict/pairing-minimal.json \
  -out ./paired.json \
  -timeout 3m
```

The command:

1. dials and completes the Noise handshake with a fresh registration payload;
2. decodes `pair-device` and shows **one** scannable terminal QR code at a
   time, rotating every 60 s for the first and 20 s for the rest — refs expire,
   so a screen full of six codes is a screen full of dead codes (PF-074);
3. acknowledges the stanza and answers the server's keepalive pings;
4. waits for `pair-success`, verifies the device identity HMAC and signature,
   replies with `pair-device-sign` to finish the link (PF-073), and writes the
   credential record to `-out` with mode `0600`.

Use `-render-only` to stop after printing the payloads, which is useful for
checking the flow without involving a phone.

## What has been verified

| Step | Status |
|------|--------|
| Dial, handshake, registration payload | verified live |
| `pair-device` decoded, 6 refs | verified live |
| Acknowledgement accepted | verified live |
| Keepalive decoded and answered | verified live |
| QR payloads rendered from real refs | verified live |
| QR rotation with per-code validity window | verified live |
| Phone accepts the QR | **refused once**, causes addressed in PF-072/PF-073/PF-074 |
| `pair-success` decode, confirm, credential write | **never observed** |

The single phone attempt was refused with a generic "couldn't link new device".
That message never says why, so the three defects it exposed were found by
auditing the payload and the flow against the reference, not by reading the
phone's screen. If a scan still fails, the raw frames are the evidence:
undecodable stanzas are written to `undecoded/*.bin` so the missing token can be
recovered without another pairing attempt.

## Reading a failed scan

A refused scan is not silent. Check, in this order:

1. **Did the code rotate while you were scanning?** Each code is valid only for
   its window; if the terminal printed "code 2/6" you were scanning a dead one.
2. **Was `pair-device-sign sent` printed?** If `pair-success` arrived and that
   line is absent, the link was verified but never completed.
3. **Were frames written to `undecoded/`?** Each file is a stanza the partial
   token table could not decode. That is the next token to add.

## What will probably fail first

`pair-success` is decoded with the same partial table, and that stanza almost
certainly uses token indices it does not contain. Expect:

```
undecodable stanza (N bytes): binary: unknown token: single-byte index K
```

That message names the next token to add. The method is the same one used for
the pairing stanza: decode the raw bytes structurally, cross-check against a
second walk, and confirm with the server's own behaviour — never trust a mapping
merely because it decodes without error (see `deployments/tokendict/README.md`
for the mistake that taught this).

## Cleaning up

If a pairing attempt leaves an entry on the phone, remove it under
**Linked devices**. The credential file contains private keys: delete it when it
is no longer needed, and never commit it.
