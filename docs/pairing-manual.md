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
2. decodes `pair-device` and prints six `wa.me/settings/linked_devices#…`
   payloads, each a valid QR string;
3. acknowledges the stanza and answers the server's keepalive pings;
4. waits for `pair-success`, verifies the device identity HMAC and signature,
   and writes the credential record to `-out` with mode `0600`.

Use `-render-only` to stop after printing the payloads, which is useful for
checking the flow without involving a phone.

## What has been verified

| Step | Status |
|------|--------|
| Dial, handshake, registration payload | verified live |
| `pair-device` decoded, 6 refs | verified live |
| Acknowledgement accepted | verified live |
| Keepalive decoded and answered | verified live |
| QR payloads rendered from real refs | verified live (localhost only, not scanned) |
| `pair-success` decode and credential write | **never observed** |

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
