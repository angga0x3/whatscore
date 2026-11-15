# Pairing-minimal token dictionary

`pairing-minimal.json` is a **partial** token table: twelve tokens, enough to
read the `pair-device` stanza and the keepalive the live server sends to an
unpaired session.

## Provenance

Derived on 2026-11-15 from stanzas this project's own unpaired session received
from `wss://web.whatsapp.com/ws/chat`. Three consecutive live runs used the
identical index set, and the decode was cross-checked against an independent
structural walk of the raw bytes, which is how a mistake in the first mapping
was caught (see below).

## Verified against the live server

Decoded exactly, with this table:

```
<iq from="@s.whatsapp.net" type="set" id="…" xmlns="md">
  <pair-device><ref>×6</ref></pair-device>
</iq>
```

and, after the acknowledgement:

```
<iq from="@s.whatsapp.net" type="get" t="…" xmlns="urn:xmpp:ping">
```

The second one is a **keepalive**, not a rejection — which changes the story.
Answering it (an `iq result` with the same `id`) keeps the socket open for
another ~30 s window; ignoring it makes the server close with 1006, which is
what earlier runs misinterpreted as a rejected acknowledgement.

## What this table is not

It is **not** complete and does not try to be. Nineteen of the twenty tokens
above are read from stanzas this session received; the rest of the table is
empty, and any stanza using another index fails with `unknown token`. That is
the intended behaviour: a partial table must fail loudly rather than guess.

## The mistake that was caught

The first mapping put `t` at index 22 and `xmlns` at index 26, and marked index
41 as unknown. Decoding with the corrected ordering shows index 22 is `xmlns`,
26 is `t`, and 41 is `get`. The error came from trusting a hand-written walker
that mis-ordered one attribute pair; the independent byte walk and the keepalive
decode both contradicted it. The table now matches the bytes.

The lesson is recorded rather than hidden: a mapping that decodes without error
can still be wrong, which is why the keepalive's `urn:xmpp:ping` value was the
decisive check.

## Using it

```bash
go run ./cmd/tokendict -in deployments/tokendict/pairing-minimal.json -check
WHATSAPP_TOKEN_DICTIONARY=deployments/tokendict/pairing-minimal.json go run ./cmd/whatscore
```

`allow_holes` is set because a partial table legitimately has unknown slots. A
complete table must not set it: there, a hole really is a truncation bug.

## Licensing note

No table was copied. Every string here was read out of traffic this project's
own session received, or is the value needed to answer that traffic. Nothing is
derived from another client's source.
