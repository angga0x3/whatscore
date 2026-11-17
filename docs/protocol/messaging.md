# Messaging findings

Stanza-level shapes for chat messages: the textual JID grammar, its
normalization and rendering, the `<message>` envelope, the text payload
carrier, and the `<receipt>` stanza. Extracted from read-only reference study
of two independent implementations (see Sources); every finding is
**Probable** because no live WhatsApp traffic has been captured and the text
carrier used by this package is not the one the references put on the wire
(PF-034).

## JID form table

Inputs accepted and rejected by `ParseJID` in `protocol/messaging`, with the
reference behavior noted. "server JID" means a JID with a server and an empty
user.

| Input | Result |
|-------|--------|
| `6281234567890@s.whatsapp.net` | user JID, user + server |
| `6281234567890:5@s.whatsapp.net` | device 5; `String` keeps `:5` |
| `6281234567890:0@s.whatsapp.net` | device 0 ≡ no device; `String` drops `:0` |
| `6281234567890:007@s.whatsapp.net` | accepted; canonical `String` is `...:7@...` |
| `6281234567890:65535@s.whatsapp.net` | device at the uint16 boundary |
| `120363021234567890@g.us` | group JID |
| `status@broadcast` | status broadcast |
| `99999999999999@lid` | LID user |
| `120363021234567890@newsletter` | newsletter |
| `6281234567890@c.us` | legacy user server; `Normalize` rewrites to `s.whatsapp.net` |
| `s.whatsapp.net` | server JID (bare token, no `@`) |
| `@s.whatsapp.net` | server JID (empty user before `@`) |
| *(empty string)* | rejected — empty server |
| `6281234567890@` | rejected — empty server |
| `@` | rejected — empty server |
| `a@b@c` | rejected — more than one `@` |
| `user:1:2@server` | rejected — more than one `:` |
| `user:@server` | rejected — empty device |
| `:5@server` | rejected — empty user before `:` |
| `user:abc@server` | rejected — device not decimal |
| `user:-1@server`, `user:+1@server`, `user:0x10@server` | rejected — signed or non-decimal device |
| `user:65536@server` | rejected — device exceeds uint16 |
| `user:1.5@server` | rejected — device not decimal |
| ` user@server`, `user@ser ver`, `user@server\n` | rejected — whitespace |
| `1234.5:2@s.whatsapp.net`, `1234.5@s.whatsapp.net` | rejected — agent-qualified (AD) form, `ErrUnsupportedJIDForm` |

`ParseJID` is stricter than both references on purpose: the reference parsers
are permissive helpers, not validators, and accepting their edge cases would
put malformed addresses on the wire. The deviations are listed in PF-030.

## PF-030: JID textual grammar

| Field | Value |
|-------|-------|
| **ID** | PF-030 |
| **Title** | A JID is `user[:device]@server`; a bare token is a server JID; the device is a decimal in the uint16 range; the agent-qualified AD form is `user.agent[:device]@server` |
| **Layer** | messaging |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/messaging` (JID table, String round-trip) |
| **Related findings** | PF-014, PF-031, PF-032 |
| **Notes** | whatsmeow `types/jid.go` `ParseJID`: splits on `@`; a one-part string becomes a server JID (`NewJID("", parts[0])`); a `.` in the user part starts the agent form (`user.agent[:device]`, agent/device via `strconv.Atoi`); otherwise a `:` splits `user:device`; the device is cast to uint16 without a range check, and empty user, empty server, extra `@`, and whitespace are all accepted silently. Baileys `src/WABinary/jid-utils.ts` `jidDecode`: only the first `@` separates (`indexOf('@')`), no `@` returns undefined, the user is everything before, server everything after, the device is split on `:` and coerced with unary `+`, and an `_agent` suffix is split off the user. WhatsCore accepts the same two textual forms plus the bare-server form and rejects empty input, empty server, repeated `@`/`:`, whitespace, non-decimal or out-of-range devices, and the AD form (this type has no agent/domain field; `binary` carries AD_JID separately, PF-014). Device 0 is accepted and means "no device" — both references omit a zero device when rendering. |

## PF-031: JID normalization

| Field | Value |
|-------|-------|
| **ID** | PF-031 |
| **Title** | Normalization rewrites the legacy user server `c.us` to `s.whatsapp.net` and drops the device; other servers are preserved verbatim |
| **Layer** | messaging |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/messaging` (normalization table, idempotence) |
| **Related findings** | PF-030 |
| **Notes** | Baileys `jidNormalizedUser` decodes and re-encodes with `jidEncode(user, server === 'c.us' ? 's.whatsapp.net' : server)`, which drops both device and agent. whatsmeow has no normalize function; `JID.ToNonAD` clears `RawAgent` and `Device` but keeps `Server` as-is, so `c.us` survives there (`types.LegacyUserServer = "c.us"`). WhatsCore follows Baileys on both points, is idempotent, and does not fold server case — neither reference lowercases. Normalization is *not* applied implicitly by `String` or `ParseJID`; callers choose when to canonicalize. |

## PF-032: JID rendering

| Field | Value |
|-------|-------|
| **ID** | PF-032 |
| **Title** | Rendering: empty server → empty string; empty user → bare server; device > 0 → `user:device@server`; device 0 is omitted |
| **Layer** | messaging |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/messaging` (String table, parse-render-parse round-trip) |
| **Related findings** | PF-030 |
| **Notes** | whatsmeow `JID.String` branch order: empty server → `""`; `RawAgent > 0` → `user.agent:device@server`; `Device > 0` → `user:device@server`; non-empty user → `user@server`; else the server alone. Baileys `jidEncode` is `\`${user || ''}${agent ? '_'+agent : ''}${device ? ':'+device : ''}@${server}\``, so it always writes `@server` and omits falsy devices. WhatsCore's `String` never emits `:0` and renders a device-only JID (no user) as the bare server, so every non-empty output re-parses to the same value. |

## PF-033: `<message>` envelope

| Field | Value |
|-------|-------|
| **ID** | PF-033 |
| **Title** | A message stanza is `<message id type to>`; `type` is `text` for conversation and extended-text payloads; `to` is a full chat JID and a device-qualified recipient is refused outside the peer path |
| **Layer** | messaging |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/messaging` (attribute assertions, binary codec round-trip) |
| **Related findings** | PF-014, PF-034 |
| **Notes** | whatsmeow `send.go` `prepareMessageNode` sets `id`, `type` (`getTypeFromMessage` → `"text"` for `Conversation`, `ExtendedTextMessage`, `ProtocolMessage`), `to`; `sendNewsletter` uses the same three attributes. Baileys `Socket/messages-send.ts` `relayMessage` builds `{ tag: 'message', attrs: { id, to, type: getMessageType(message) } }` with `'text'` as the fallback type. Attributes also observed but out of scope for this stanza builder: `participant`, `recipient`, `phash`, `addressing_mode`, `peer_recipient_pn`, `edit`, `category`, `push_priority`, `privacy_sensitive`, `device_fanout`, `server_id`, `t`. whatsmeow `SendMessage` returns `ErrRecipientADJID` when `to.Device > 0 && !req.Peer`, which is why `BuildTextMessage` rejects a device-qualified `to` while `ParseTextMessage` accepts one (an inbound stanza's `to` is our own device JID). |

## PF-034: Text payload carrier

| Field | Value |
|-------|-------|
| **ID** | PF-034 |
| **Title** | Reference text messages carry the text as protobuf `Message.conversation` inside `<enc v="2" type="msg\|pkmsg\|skmsg">` (newsletters: `<plaintext>`); the `<body>` child built here is a WhatsCore pre-encryption carrier, not an observed wire shape |
| **Layer** | messaging |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/messaging` (build-parse round-trips, negative table) |
| **Related findings** | PF-033 |
| **Notes** | whatsmeow documents text as `waE2E.Message{Conversation: proto.String("...")}` and `send.go` marshals that to plaintext, encrypts per device, and emits `<enc v="2" type="msg\|pkmsg">` (group: `type="skmsg"`) under `<participants><to jid="...">`; `sendNewsletter` sends the raw protobuf in `<plaintext>`. Baileys `createParticipantNodes` likewise emits `<to jid><enc v="2" type="pkmsg\|msg">ciphertext</enc></to>`. **Neither reference emits a `<body>` child inside `<message>`.** WhatsCore's `BuildTextMessage`/`ParseTextMessage` implement the plaintext carrier defined by the §4.8 scope so the binary stanza layer can be tested before `protocol/signal` exists: the node is `<message to="..." type="text" id="..."><body>text bytes</body></message>`, children other than `<body>` are ignored on parse, and `type` other than `text`, a missing/child-bearing/contentless `<body>`, an empty `id`, or a server-only `to` are rejected. No live-server compatibility is claimed for this shape; when Signal lands, the body value becomes the protobuf `Conversation` input and the `<enc>` children are added around it. |

## PF-035: `<receipt>` stanza

| Field | Value |
|-------|-------|
| **ID** | PF-035 |
| **Title** | A receipt is `<receipt id to [type] [t] [participant]>`; plain delivery omits `type`; read receipts add unix-seconds `t`; batched ids go in a `<list><item id>` child |
| **Layer** | messaging |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/messaging` (receipt round-trip, type vocabulary, negative table) |
| **Related findings** | PF-033 |
| **Notes** | whatsmeow `receipt.go` `MarkRead` builds `id`, `type`, `to`, `t` (unix seconds), adds `participant` for non-user chats, and puts ids after the first in `<list><item id="..."/>`; `sendMessageReceipt`/`buildBaseReceipt` use `id` + `to` (copied from `from`) and add `type` only for `sender`/`inactive`/`peer_msg`. Baileys `sendReceipt` does the same: `id` = first message id, `t` only for `read`/`read-self`, `type` only when truthy, `participant` for group chats, and remaining ids in `<list><item>`. Type vocabulary (`types/presence.go`): `""` = delivered, `sender`, `retry`, `read`, `read-self`, `played`, `played-self`, `server-error`, `inactive`, `peer_msg`, `hist_sync`. WhatsCore builds/parses the single-id outbound shape, refuses a `<list>` child instead of dropping ids, parses `t` as unix seconds into UTC, and ignores `recipient` (used when a LID chat is addressed by phone number) and receipt `from` (inbound receipts belong to the event layer). |

---

Status: findings recorded 2026-11-15 from reference study (whatsmeow `main`:
`types/jid.go`, `send.go`, `receipt.go`, `types/presence.go`; Baileys
`master`: `src/WABinary/jid-utils.ts`, `src/Socket/messages-send.ts`).
`protocol/messaging` is Verified-by-test against these records — JID table,
normalization, and stanza round-trips through `protocol/binary` — but no
claim of live compatibility is made. PF-034 in particular documents a
deliberate deviation: the reference wire carries protobuf inside `<enc>`,
while this package builds the plaintext `<body>` carrier until
`protocol/signal` exists. Live interop and the `<enc>` wrapping reopen
PF-033/PF-034 when they land.

## PF-036: Encrypted payload envelope

| Field | Value |
|-------|-------|
| **ID** | PF-036 |
| **Title** | A text message may carry `<enc v="2" type="msg|pkmsg|skmsg">` with Signal ciphertext bytes instead of a plaintext `<body>` child |
| **Layer** | messaging |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/messaging` (build/parse round-trip, negative table) |
| **Related findings** | PF-033, PF-034 |
| **Notes** | whatsmeow `send.go` builds `<message id type to><enc v="2" type="msg">ciphertext</enc></message>`; the carrier is `pkmsg` for a PreKeySignalMessage, `msg` for an established session, and `skmsg` for group sender-key messages. WhatsCore implements the envelope only; choosing the carrier and producing the ciphertext belongs to `core/messaging`. |

---

Status update: the encrypted text carrier is implemented as a stanza shape;
plaintext `<body>` remains for unencrypted runs until core wiring lands.


## PF-083: The payload inside <enc> is a protobuf Message

| Field | Value |
|-------|-------|
| **ID** | PF-083 |
| **Title** | A text message's plaintext is a protobuf `Message` with `conversation` (field 1) or `extendedTextMessage.text` (field 6, then 1), not a raw string |
| **Layer** | messaging |
| **Source** | reference study of whatsmeow `proto/waE2E`, confirmed by a live sent message the server acknowledged |
| **Observed date** | 2026-11-15 |
| **Confidence** | Confirmed |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/messaging` (`TestEncodeTextMessageIsConversation`, both-carrier decode, negative table) |
| **Related findings** | PF-034, PF-082 |
| **Notes** | This replaces PF-034's `<body>` placeholder carrier, which no reference emits. Sending raw text bytes inside `<enc>` is accepted by the server — it acknowledges the stanza — but a phone renders nothing, because the plaintext is not a parseable `Message`. `EncodeTextMessage`/`DecodeTextMessage` implement the real shape; the minimal `message.proto` declares only the two fields this project needs, because declaring a hundred unverified fields would be a claim it cannot support. |

## PF-082: Publishing prekeys, and why a repeat is refused

| Field | Value |
|-------|-------|
| **ID** | PF-082 |
| **Title** | Prekeys are published with `iq{type=set, xmlns=encrypt}` carrying `registration`, `type=0x05`, `identity`, `list` of `<key id value>`, and one `skey id value signature`; the server accepts this **once per device** and does not answer a repeat |
| **Layer** | messaging |
| **Source** | direct observation of own session, plus reference study of whatsmeow `prekeys.go` |
| **Observed date** | 2026-11-15 |
| **Confidence** | Confirmed for the first upload; **inferred** that repeats are refused |
| **Status** | Verified-by-test |
| **Proving test** | `cmd/whatscore-probe` live runs: first upload answered `<iq type="result">`; every later upload got no reply, then the socket closed |
| **Related findings** | PF-060, PF-065, PF-083, PF-085 |
| **Notes** | The first upload was acknowledged and the keys worked. Subsequent uploads — including with fresh ids — produced no reply within 45 s, and one closed the connection outright. The most likely reading is that a device's prekey set is fixed at registration and later `set` requests are ignored, but this is **not proven**: the server never sent an error. What is proven is the operational consequence: a client must persist the set it registered and must not treat an unacknowledged repeat upload as fatal, because aborting there loses a session that can still send and receive. |

## PF-085: Losing the signed prekey loses the messages addressed to it

| Field | Value |
|-------|-------|
| **ID** | PF-085 |
| **Title** | A peer encrypts to the signed prekey that was in the registration payload; that private half must be persisted, or every message sent before the next rotation is permanently unreadable |
| **Layer** | messaging |
| **Source** | direct observation: a live inbound message named `signedPreKeyID=1`, and decryption with our own key failed with `bad message MAC` |
| **Observed date** | 2026-11-15 |
| **Confidence** | Confirmed |
| **Status** | Verified-by-test |
| **Proving test** | `cmd/whatscore-probe` (`TestKeyFileRoundTripsSignedPreKey`, `TestSeedFromRecordAdoptsThePairingKey`, `TestInboundPreKeyMessageBecomesText`) |
| **Related findings** | PF-065, PF-082, PF-083 |
| **Notes** | The pairing run generated a signed prekey, put its public half and signature into the registration payload, and **discarded the private half**. The server handed that public key to peers, so inbound messages were encrypted to a key nobody held. A real inbound message decoded cleanly as `registrationID=1388247345 preKeyID=0 signedPreKeyID=1`, and attempting it with a different signed prekey produced `signal: bad message MAC` — not a parse error, which is why the symptom looked like corruption rather than a missing key. The probe now writes the signed prekey into the credentials file and adopts it on every later run. **The messages already queued before that fix cannot be recovered**: their key existed only in the memory of a process that has exited. |

## PF-086: One connection per device, enforced with a stream conflict

| Field | Value |
|-------|-------|
| **ID** | PF-086 |
| **Title** | A second connection using the same device credentials makes the server send `<stream:error><conflict type="replaced"/></stream:error>` to the first and close it |
| **Layer** | transport |
| **Source** | direct observation of own session, reproduced |
| **Observed date** | 2026-11-15 |
| **Confidence** | Confirmed |
| **Status** | Verified-by-test |
| **Proving test** | `cmd/whatscore-probe` live runs: a `-listen` session was replaced twice, once by `-send` and once by `-login` |
| **Related findings** | PF-077, PF-082 |
| **Notes** | This is a hard constraint on the design, not an inconvenience. Sending and receiving cannot be tested from two processes sharing one credentials file: whichever connects second silently evicts the first, and the evicted process only sees a 13-byte `stream:error`. A client must therefore own one long-lived connection and multiplex sends and receives over it. The probe's separate `-send` and `-listen` modes are a testing affordance that works **only because** each run ends before the next begins. A production client with this shape would drop messages. |

### What this changes

A real client must:

- hold one connection open, reconnect on its own, and route sends through it;
- treat `conflict type="replaced"` as "another instance took over", not as a
  protocol error to retry into;
- never open a second socket for a send while the read loop is live.

## PF-087: The server can hold a queue and never deliver it

| Field | Value |
|-------|-------|
| **ID** | PF-087 |
| **Title** | After login the server reports pending messages with `<ib><offline_preview message="N" …/></ib>` and then **may not send any of them**; a receive path that only waits will report success while nothing arrives |
| **Layer** | transport |
| **Source** | direct observation of own session, repeated |
| **Observed date** | 2026-11-15 |
| **Confidence** | Confirmed; root cause found and fixed the same day |
| **Status** | Closed — live receive demonstrated end to end on 2026-11-15: queue drain, pkmsg bootstrap, decrypt, text render, delivery receipt, persisted ratchet |
| **Proving test** | `cmd/whatscore-probe -listen` live runs. Before the fix: `offline_preview` announced `message=24` (and later `count=107 message=26 receipt=37`), the socket stayed up, zero `message` stanzas arrived. After the fix, the 2026-11-15 drain session answered the announcement and the backlog streamed — 21 `message` stanzas, one delivery receipt each, plus notifications, statuses and newsletter plaintexts; Signal sessions bootstrapped from live `pkmsg` and decrypted. |
| **Related findings** | PF-086, PF-088 |
| **Notes** | The failure was a chain, and every link was ours, not the server's. (1) The announcement itself rode on tokens the partial table lacked, landed in `undecoded/`, and was silently discarded — "announced" and "delivered" were indistinguishable. (2) After that was decoded, the *same kind of stanza* still failed whole, because its counter values grow with the queue and come as dictionary refs (`message=¿d1[158]`, `receipt=¿d2[126]`, `status=¿d1[209]`) the table has never observed; the listen path now routes an `<ib>` by its shape with the holes printed, since `<ib>` is server-state routing and its values are diagnostics. (3) The queue stayed frozen until the client answered the announcement with `<ib><offline_batch count="100"/>`; ignoring it is a client the server never delivers to. (4) The backlog then decrypted to wire-format errors: the service pads v2 plaintexts with N copies of the byte N (whatsmeow `unpadMessage`), and the trailing pad bytes are not protobuf. Each link is pinned by a test (TestUndecodableIbRoutesByShape, TestOfflineBatchRequestShape, TestPadUnpadRoundTrip). The same run proved the rest of the chain live: with the token table completed from the canonical dictionary, two queued text messages from a real contact (a third-party sender, not this project's own phone) bootstrapped pkmsg sessions, decrypted, rendered their text, and earned delivery receipts — and a message sent while the listener was connected arrived and decrypted live. The receiver's session observer persisted the ratchet to disk mid-run. Residual and deliberately not closed: the probe's own queued note-to-self messages are encrypted to a one-time prekey an earlier run consumed, and the phone answers retry receipts by re-encrypting with its cached bundle — so those stay unreadable until the phone either honours the inline keys block or the device re-accounts for itself; and the drain marker `<ib><offline/>` has not yet been observed on the wire, so the post-drain grace path runs unproven against the live service. |

## PF-089: The stanza type attr gates nothing about the payload

| Field | Value |
|-------|-------|
| **ID** | PF-089 |
| **Title** | The live service stamps `type="media"` on encrypted media stanzas and `type="text"` on everything else; gating the envelope parser on `"text"` rejects every media message before decryption |
| **Layer** | messaging |
| **Source** | direct observation of own session (2026-11-15): a contact's sticker and image messages arrived as `<message type="media"><enc type="pkmsg" v="2">…` |
| **Observed date** | 2026-11-15 |
| **Confidence** | Confirmed |
| **Status** | Verified-by-test |
| **Proving test** | `TestParseEncryptedTextAcceptsMediaType` — a `type="media"` stanza parses; an unobserved type still fails loudly |
| **Related findings** | PF-083, PF-087 |
| **Notes** | The type attr names the transport class, not the payload kind; what a decrypted payload actually carries is decided by its protobuf content. whatsmeow does not gate inbound messages on the attribute at all. This project keeps a gate — loud failure is part of its design — but it now accepts the two types the live service has been observed to send with an `<enc>` child. |

## PF-088: Silent logging hides a broken receive path

| Field | Value |
|-------|-------|
| **ID** | PF-088 |
| **Title** | A dropped decryption failure is indistinguishable from "no message arrived", so a receive path must log its failures or it cannot be diagnosed |
| **Layer** | messaging |
| **Source** | direct observation of own debugging |
| **Observed date** | 2026-11-15 |
| **Confidence** | Confirmed |
| **Status** | Verified-by-test |
| **Proving test** | `cmd/whatscore-probe` — `NewReceiver` defaults to `slog.DiscardHandler`, and the probe now passes a debug handler |
| **Related findings** | PF-087 |
| **Notes** | `core/messaging.NewReceiver` discards its logger by default, which is reasonable for a library and wrong for an operator-facing tool: `bad message MAC`, a missing prekey, and a malformed envelope all became the same observable — nothing. The probe now logs at debug level, and the listen path reports a closed connection as an error instead of waiting out the timeout and printing "window ended". Both changes exist because the first live receive attempt produced a log that could not distinguish success from silent failure. |

## PF-090: Every 1:1 send is two plaintexts — the recipient's and the own-device copy

| Field | Value |
|-------|-------|
| **ID** | PF-090 |
| **Title** | A direct message is encrypted twice: once as the payload itself for the recipient, and once as `DeviceSentMessage{destinationJID, message}` for the account's other devices; the copy is what makes a linked device's send appear on the phone |
| **Layer** | messaging |
| **Source** | inferred — reference study of whatsmeow `send.go` `marshalMessage` and `encryptMessageForDevices` |
| **Observed date** | 2026-11-16 |
| **Confidence** | Probable |
| **Status** | Verified live on receive (2026-11-17); the send side is implemented and not yet observed on the phone |
| **Proving test** | `TestEncodeDeviceSentMessageWrapsTheDestination`, `TestDecodePayloadUnwrapsDeviceSentMessage`, `TestReceiverPublishesOwnDeviceCopyInItsDestinationChat`, live listen run 2026-11-17 |
| **Related findings** | PF-083, PF-086 |
| **Notes** | whatsmeow builds the copy for every non-group, non-newsletter send and selects it per device: devices of the sender's own account (matched by JID user, PN or LID) get the wrapped plaintext, everyone else gets the bare one. The wrapper is `Message.deviceSentMessage` (field 31) with `destinationJID` (1) and `message` (2). Receivers unwrap it before classifying content, and the chat is the destination — the sending device is the sender, not the chat. A retry of a message the account itself sent re-wraps it the same way (whatsmeow `retry.go`), which is why the unwrap belongs in the payload decoder rather than in one send path. The copy is addressed to one device, not to an account: its `to` is the phone's device-qualified JID and the stanza carries `device_fanout="false"`, because there is nothing left to fan out. Every other outbound message keeps the account-addressed shape and the server does the fan-out. Both the probe (`-send`) and the server (`DeliverText`) send the copy only when a session with the phone already exists. (An own-account bundle *is* served by phone number — a note-to-self send on 2026-11-17 fetched one — but the copy needs the phone's device session specifically, which only its own messages create.) This is why a note-to-self sent from a linked device reaches the phone but never echoes back to the sending device (2026-11-15 observation) — and why the phone must speak first for the copy to become possible. The copy shares the recipient copy's message id so the phone renders one message rather than two. Live on receive (2026-11-17): during a queue drain, messages from the account's own LID (`266988689592415:35@lid`) were published as outgoing in their destination chats and correctly drew no delivery receipt — the unwrap and the "one of ours" decision both worked on live traffic. |

## PF-091: The msg carrier carries every payload kind, not just text

| Field | Value |
|-------|-------|
| **ID** | PF-091 |
| **Title** | After the first message a conversation continues with `type="msg"` carriers, and those carry the same protobuf `Message` kinds as `pkmsg`; a receive path that decodes text only drops every image, sticker and voice note |
| **Layer** | messaging |
| **Source** | inferred — the carrier only names how the session was established; the payload is opaque to it |
| **Observed date** | 2026-11-16 |
| **Confidence** | Confirmed by construction (both carriers hold the same protobuf) |
| **Status** | Verified-by-test and live (2026-11-17) |
| **Proving test** | `TestReceiverDecryptsMediaOnEstablishedSession`, live listen run 2026-11-17 |
| **Related findings** | PF-083, PF-089 |
| **Notes** | The two receive paths had drifted: `pkmsg` classified the plaintext with `DecodePayload` (text, media, protocol), while `msg` called `DecodeTextMessage` and dropped anything without text as "no text payload". A sticker that arrived on a continued session therefore decrypted cleanly, advanced the ratchet, and produced no event — the same silent-loss shape as PF-088. Both paths now classify identically. Live: a queue drain on 2026-11-17 downloaded and stored a 7.2 MB video and a 93 KB image — attachments that arrive after the first message in their conversations. |

## PF-092: Outbound media is an upload plus a message that names it

| Field | Value |
|-------|-------|
| **ID** | PF-092 |
| **Title** | Sending an attachment is two steps: POST the encrypted blob to the CDN host named by `<media_conn>`, then send a message whose protobuf names the resulting URL/direct path and the envelope's digests and key |
| **Layer** | media |
| **Source** | inferred — reference study of whatsmeow `upload.go`, `mediaconn.go`; envelope from PF-040…PF-045 |
| **Observed date** | 2026-11-17 |
| **Confidence** | Confirmed for the query, the upload and the message acceptance; Probable for the phone rendering it |
| **Status** | Partially proven live |
| **Proving test** | `internal/mediaupload` (request shape, media connection parse), `TestEncodeMediaMessageImage`, `TestEncodeMediaMessageDocument`, `TestEncodeMediaMessageRejectsIncomplete`, live run 2026-11-17 |
| **Related findings** | PF-040, PF-043, PF-045, PF-089 |
| **Notes** | The media connection is an iq with `xmlns="w:m"`, `type="set"`, `to="s.whatsapp.net"` and a `<media_conn/>` child; the reply carries `auth`, `ttl` and a list of `<host hostname="…"/>`. The upload is `POST https://{host}/mms/{type}/{token}?auth=…&token=…`, where the token is the URL-safe base64 of the encrypted blob's SHA-256, the body is the blob exactly as `core/media` produced it (ciphertext ‖ MAC), and `Origin`/`Referer` name the web client. The reply names `url` and `direct_path`. The message then carries `fileSHA256` (plaintext), `fileEncSHA256` (blob as uploaded), `mediaKey`, `fileLength`, the MIME type and the location; the stanza's type attr is `media` (PF-089). The probe sends images and documents (`-send -file …`) and wraps the same inner message for the own-device copy (PF-090). Live on 2026-11-17: the media connection query answered, the 166-byte PNG upload was accepted (HTTP 200 with `url` and `direct_path`), and a media-class message naming it was accepted by the server (`ack class="message"`). Deliberately unproven: whether the phone renders the attachment — no device observation was recorded, so the claim stops at "the server accepted the stanza". |
