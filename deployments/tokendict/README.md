# Pairing-minimal token dictionary

`pairing-minimal.json` is a **partial** token table: enough to read the
`pair-device` stanza, the keepalive, and — since a phone scan produced one — a
real `pair-success`. It is still far from the full 236 + 1024 table and is not
meant to be.

## Provenance

Derived on 2026-11-15 from stanzas this project's own unpaired session received
from `wss://web.whatsapp.com/ws/chat`. Three consecutive live runs used the
identical index set, and the decode was cross-checked against an independent
structural walk of the raw bytes, which is how a mistake in the first mapping
was caught (see below).

## Verified against the live server

A **real `pair-success`** also decodes with this table now:

```
<iq from="s.whatsapp.net" type="set" id="…" xmlns="md">
  <pair-success>
    <jurisdiction cc="62" iso="ID"/>
    <encryption-metadata algorithm="aes-256-gcm" version="1">…</encryption-metadata>
    <client-props>…</client-props>
    <platform name="iphone"/>
    <device-identity>…</device-identity>
    <device jid="…:36@s.whatsapp.net" lid="…:36@lid"/>
  </pair-success>
</iq>
```

That frame is 731 bytes and used eight single-byte indices plus one dictionary-0
index beyond the `pair-device` set: `12=jid`, `59=device`, `74=platform`,
`84=version`, `85=1`, `118=lid`, `137=name`, `230=device-identity`, and
`dictionary 0, index 208 = iphone`. Every one of them was present in the
observed frame; none was inferred. Two decoders — this project's and the
reference's — produced the same tree from it, attribute by attribute and byte
for byte, and the account-identity HMAC then verified against the adv secret
from the QR that was scanned.

Earlier in the same exchange, the `pair-device` stanza decoded with the same
table:

```
<iq from="@s.whatsapp.net" type="set" id="…" xmlns="md">
  <pair-device><ref>×6</ref></pair-device>
</iq>
```

and, after the acknowledgement:

```
<iq from="@s.whatsapp.net" type="get" t="…" xmlns="urn:xmpp:ping">
```

The keepalive is **not** a rejection — which changes the story. Answering it (an
`iq result` with the same `id`) keeps the socket open for another ~30 s window;
ignoring it makes the server close with 1006, which is what earlier runs
misinterpreted as a rejected acknowledgement.

What the table could not read on the first successful scan was `pair-success`
itself. The frame was still saved, and reconstructing the tokens from it is what
made the second decoder agree — the failure was recorded rather than lost.

## The login reply

After pairing, reconnecting with the login payload earns:

```
<success abprops="215" companion_enc_static="…" creation="…" lid="…" location="atn" t="…" />
<ib><edge_routing><routing_info>…</routing_info></edge_routing></ib>
<ib><dirty timestamp="…" type="account_sync" /></ib>
```

Those frames added eleven single-byte and four dictionary indices beyond the
pairing set: `26=t`, `39=routing_info`, `40=edge_routing`, `60=creation`,
`61=location`, `75=abprops`, `76=success`, `118=lid`, `130=atn`,
`dictionary0[110]=account_sync`, `dictionary0[154]=timestamp`,
`dictionary0[230]=companion_enc_static`, `dictionary1[1]=dirty`. They were
recovered by instrumenting the reference decoder while it parsed those exact
frames, so each index is one the server really sent.

`location` varies per session — `cln`, `atn`, `lla`, `cco` were all observed —
and it appears both as a token and as a literal string. Only the token was
recorded.

## The offline preview

A `-listen` run produced one stanza the table could not read, kept at
`undecoded/`. Dumping it with the hole-filled decoder (`-dump`) showed its shape
and the three unknown slots at once:

```
<ib from="@s.whatsapp.net">
  <offline_preview count="…" message="…" notification="26" receipt="37"
                   appdata="0" call="0" status="17"/>
</ib>
```

The count of undelivered messages PF-087 reports is this stanza's `message`
attribute — and its value rode on `single[153]`, which the table lacked. The
other two slots resolved the same way: `dictionary0[56]` is the `count` value
and the `notification` value shares `single[153]`. All three were present in
that one frame; none was inferred from elsewhere. The stanza is the queue
announcement PF-087 describes: the server said what it held, in a frame this
table could not yet read, and the receive path discarded it silently.

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
