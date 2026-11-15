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

