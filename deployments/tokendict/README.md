# Pairing-minimal token dictionary

`pairing-minimal.json` is a **partial** token table whose only purpose is to
decode the `pair-device` stanza the live server sends to an unpaired session.

## Provenance

Derived on 2026-11-15 from a stanza this project's own unpaired session received
from `wss://web.whatsapp.com/ws/chat` (`cmd/whatscore-probe -payload`). The
structural shape is documented independently in PF-016:

```
<iq type="set" id="…" from="…" t="…"><pair-device><ref>…</ref>×6</pair-device></iq>
```

Each index occurs in exactly one position of that shape, so its meaning is
pinned by position rather than guessed. Three consecutive live runs used the
identical index set (7 single-byte indices, 1 dictionary-1 index), which is why
the table is 9 tokens instead of 1,259.

## What is verified

- `pairing.ParsePairDevice` on a live stanza returns **6 refs** — decoded with
  this table, not with a mock.
- `pairing.PairDeviceAck` builds the reply, `codec.Encode` serialises it, and
  the server accepts it and answers.

## What is NOT verified

- Indices noted as *positional* in the table below were placed by structural
  position only. They are enough to decode the reply without an error, but
  their exact spelling is inferred, not observed:
  - `41` — placed as `result` (the value of `type` on the server's reply).
  - `26`, `43` — attribute names/values on that reply that do not appear in the
    `pair-device` stanza.
- Nothing here is claimed to work for any other stanza. A missing index fails
  loudly (`unknown token`), which is the intended behaviour.

## Using it

```bash
go run ./cmd/tokendict -in deployments/tokendict/pairing-minimal.json -check
WHATSAPP_TOKEN_DICTIONARY=deployments/tokendict/pairing-minimal.json go run ./cmd/whatscore
```

`allow_holes` is set because a partial table legitimately has unknown slots. A
complete table must not set it: there, a hole really is a truncation bug.

## Licensing note

This file contains no copied table. It is the minimum set of strings needed to
read stanzas the server sent to this project's own session, plus two positional
placeholders. It is not derived from another client's source, and it makes no
attempt to be complete.
