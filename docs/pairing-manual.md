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
| Phone accepts the QR | **verified live** (PF-075) |
| `pair-success` received and its identity verified | **verified live** |
| `pair-success` decoded by the probe | **failed once** on a missing token, since fixed (PF-075) |
| `pair-device-sign` accepted, credentials written | **verified live** |
| Login with those credentials | **verified live** (`-login`, PF-077) |
| Phone finishes linking | **needs the login step** — pairing alone leaves it spinning |

The exchange has now been run twice, and the second run is the interesting one.

The first attempt was refused with a generic "couldn't link new device". That
message never says why, so the three defects it exposed were found by auditing
the payload and the flow against the reference — not by reading the phone's
screen (PF-072…PF-074).

The second attempt **succeeded at the server**: a real 731-byte `pair-success`
arrived, and its account-identity HMAC verified against the adv secret of the
QR that was scanned. The probe still could not use it — its token table could
not decode the stanza — so the link was never confirmed and the server aborted
the stream (PF-076). That frame was saved rather than lost, and the nine tokens
it needed are now in the table.

Both failure modes left evidence on disk. That is why `undecoded/*.bin` exists:
a refused pairing costs a phone scan, and the frame is the only record of it.

## After pairing: log in

A successful pairing writes credentials, and **that is only half the job**. The
phone keeps showing its linking spinner until the same device connects again
with the login payload and the server answers `<success>` (PF-077):

```bash
go run ./cmd/whatscore-probe -login \
  -creds ./paired.json \
  -dict deployments/tokendict/pairing-minimal.json \
  -timeout 60s
```

Expected:

```
handshake: ok — logging in as <user> device <n>
LOGIN OK: the server authenticated this device
  lid=… companion_enc_static=… location=…
ib: edge_routing map[]
ib: dirty map[timestamp:… type:account_sync]
```

If the terminal never prints `LOGIN OK`, the login was not accepted — that is
different from "the stream went quiet", which is normal once `success` arrived.

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

## What the phone shows

Under **Linked devices** the entry reads `<browser> (<os>)`, for example
**"Google Chrome (whatscore)"**. Both parts come from the pairing payload
(PF-079):

- the browser from `DeviceProps.platformType`, which is `CHROME` because a QR
  pairing is the web companion flow;
- the parenthesised text from `DeviceProps.os`, which is free text.

Those fields are sent **only at pairing time** (PF-080). Changing them has no
effect on a device that is already linked: remove it on the phone and pair
again.

## Cleaning up

If a pairing attempt leaves an entry on the phone, remove it under
**Linked devices**. The credential file contains private keys: delete it when it
is no longer needed, and never commit it.
