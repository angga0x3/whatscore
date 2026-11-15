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

## Verified, and only this

- `pairing.ParsePairDevice` on a live stanza returns **6 refs**.
- `pairing.PairDeviceAck` builds the reply, `codec.Encode` serialises it, and the
  server accepts the bytes (it answers with a 20-byte iq result rather than
  closing).
- The server's reply decodes to `iq{from, type=<41>, id=<nibbles>, <26>=<43>}`.
  Its structure is fully readable; the three bracketed values are not.

## Explicitly unverified

Three indices appear **only** on the server's reply, never in a stanza we could
read without them:

| Index | Position | Status |
|-------|----------|--------|
| single `41` | value of `type` on the reply iq | **unknown** — left empty on purpose |
| single `26` | an attribute name on the reply | **unknown** — left empty |
| single `43` | that attribute's value | **unknown** — left empty |

An earlier revision guessed `41 = "xmlns"`. A differential test was run to
confirm it — resending the ack with `type="get"`, with no `type`, and with the
correct value — and **all three produced the same server behaviour** (connection
closed after the ack). The test did not distinguish the meanings, so the guess
was removed rather than kept: a wrong token that happens to decode without error
is worse than an empty slot, because it silently produces a plausible stanza.

Decoding a stanza that uses 26, 41, or 43 therefore fails with `unknown token`,
which is the correct outcome until those meanings are observed.

## Why the connection closes after the ack

Not determined. Three candidate explanations remain open, and no experiment run
so far separates them:

1. the server expects `pair-success` only after the phone scans a QR, and
   closing is the idle timeout;
2. an attribute on our ack is wrong (this is what 26/41/43 encode);
3. the ack itself is pointless and the server is waiting for something else.

Settling this needs either the reply tokens or a longer read window, not another
guess.

## Using it

```bash
go run ./cmd/tokendict -in deployments/tokendict/pairing-minimal.json -check
WHATSAPP_TOKEN_DICTIONARY=deployments/tokendict/pairing-minimal.json go run ./cmd/whatscore
```

`allow_holes` is set because a partial table legitimately has unknown slots. A
complete table must not set it: there, a hole really is a truncation bug.

## Licensing note

This file contains no copied table. It is the minimum set of strings needed to
read stanzas the server sent to this project's own session. It is not derived
from another client's source, and it makes no attempt to be complete.
