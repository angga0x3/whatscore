# Auth findings

Findings for the post-handshake `ClientPayload` that a companion device sends
inside the Noise `clientFinish` message (PF-007), plus the `DeviceProps`
message it carries. Extracted from read-only reference study of whatsmeow
`store/clientpayload.go`, `proto/waWa6/WAWebProtobufsWa6.proto`, and
`proto/waCompanionReg/WACompanionReg.proto` on 2026-11-15. The registration
form (PF-020…PF-025) and the paired-device login form (PF-026, PF-027) are
both covered; ADVSignedDeviceIdentity signing and other registration crypto
are out of scope. (The reference repository names the schema files
`WAWebProtobufsWa6.proto` and `WACompanionReg.proto`; the older paths
`Wa6.proto` and `CompanionReg.proto` no longer resolve.)

## PF-020: Registration ClientPayload envelope

| Field | Value |
|-------|-------|
| **ID** | PF-020 |
| **Title** | A registration `ClientPayload` uses `passive=3`, `userAgent=5`, `webInfo=6`, `connectType=12`, `connectReason=13`, `devicePairingData=19`, and `pull=33`; login-only fields are not emitted |
| **Layer** | auth |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/auth` (round-trip, malformed table), `protocol/protobuf` (wire field numbers) |
| **Related findings** | PF-007, PF-021, PF-022, PF-023, PF-025 |
| **Notes** | Field numbers verified against whatsmeow `proto/waWa6/WAWebProtobufsWa6.proto` (`ClientPayload`). The registration builder in whatsmeow `store/clientpayload.go` (`getRegistrationPayload`) starts from `BaseClientPayload`, sets `devicePairingData`, and explicitly sets `passive=false` and `pull=false`; proto2 keeps both zero-valued fields on the wire because the pointers are present. Login-only fields — `username=1`, `device=18`, `product=20`, `lidDbMigrated=41` — are intentionally absent. The protobuf is serialized deterministically and becomes the plaintext encrypted into Noise `msg3.payload` (PF-007). |

## PF-021: ClientPayload.UserAgent schema

| Field | Value |
|-------|-------|
| **ID** | PF-021 |
| **Title** | `UserAgent` uses `platform=1`, `appVersion=2`, `mcc=3`, `mnc=4`, `osVersion=5`, `manufacturer=6`, `device=7`, `osBuildNumber=8`, `releaseChannel=10`, `localeLanguageIso6391=11`, `localeCountryIso31661Alpha2=12`; `AppVersion` uses `primary=1`…`quinary=5` |
| **Layer** | auth |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/auth` (round-trip, build validation), `protocol/protobuf` (wire field numbers, enum values) |
| **Related findings** | PF-020 |
| **Notes** | Field numbers and types from `ClientPayload.UserAgent` in `proto/waWa6/WAWebProtobufsWa6.proto`. Enum values used by the reference base payload: `Platform.WEB=14`, `ReleaseChannel.RELEASE=0`. Reference base values: `mcc="000"`, `mnc="000"`, `osVersion="0.1"`, `manufacturer=""`, `device="Desktop"`, `osBuildNumber="0.1"`, `localeLanguageIso6391="en"`, `localeCountryIso31661Alpha2="US"`; the app version is the dotted WhatsApp Web version (`2.3000.1052556849` at study time). Fields outside this subset — `phoneID=9`, `deviceBoard=13`, `deviceExpID=14`, `deviceType=15`, `deviceModelType=16`, `distributionChannel=17` — are not emitted. |

## PF-022: WebInfo and connection metadata

| Field | Value |
|-------|-------|
| **ID** | PF-022 |
| **Title** | `WebInfo` carries `webSubPlatform=4` (`WEB_BROWSER=0`); registration sets `connectType=12` to `WIFI_UNKNOWN=1` and `connectReason=13` to `USER_ACTIVATED=1` |
| **Layer** | auth |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/auth` (round-trip, malformed table), `protocol/protobuf` (wire field numbers) |
| **Related findings** | PF-020, PF-021 |
| **Notes** | `WebInfo.webSubPlatform=4` and `WebSubPlatform.WEB_BROWSER=0` verified in `proto/waWa6/WAWebProtobufsWa6.proto`. The reference base payload sets `ConnectType.WIFI_UNKNOWN=1` and `ConnectReason.USER_ACTIVATED=1`; `ConnectType` also defines cellular values `100`…`112` and `ConnectReason` defines `PUSH=0`, `SCHEDULED=2`, `ERROR_RECONNECT=3`, `NETWORK_SWITCH=4`, `PING_RECONNECT=5`, `UNKNOWN=6`. `WebInfo` fields `refToken=1`, `version=2`, `webdPayload=3`, `browser=5`, and `browserVersion=6` exist in the reference schema but are not emitted by the registration path. |

## PF-023: DevicePairingRegistrationData encoding

| Field | Value |
|-------|-------|
| **ID** | PF-023 |
| **Title** | `DevicePairingRegistrationData` uses `eRegid=1`, `eKeytype=2`, `eIdent=3`, `eSkeyID=4`, `eSkeyVal=5`, `eSkeySig=6`, `buildHash=7`, `deviceProps=8`; IDs are big-endian, `eKeytype` is `0x05`, and `buildHash` is the MD5 of the dotted version |
| **Layer** | auth |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/auth` (round-trip byte assertions, build validation), `protocol/protobuf` (wire field numbers) |
| **Related findings** | PF-021, PF-024 |
| **Notes** | Field numbers from `ClientPayload.DevicePairingRegistrationData` in `proto/waWa6/WAWebProtobufsWa6.proto`; construction from whatsmeow `store/clientpayload.go` (`getRegistrationPayload`). `eRegid` is the 4-byte big-endian registration ID. `eKeytype` is `[]byte{ecc.DjbType}`, and libsignal defines `Curve.DJB_TYPE = 0x05` (`signalapp/libsignal-protocol-java`, `ecc/Curve.java`). `eIdent` is the 32-byte identity public key. `eSkeyID` is the low three bytes of the big-endian 32-bit signed-prekey ID (reference: `preKeyID[1:]`), so IDs above `0xFFFFFF` cannot be represented and are rejected. `eSkeyVal` is the 32-byte signed prekey and `eSkeySig` its 64-byte signature. `buildHash` is `MD5("<primary>.<secondary>.<tertiary>")` (16 bytes), i.e. `WAVersionContainer.Hash()`. `deviceProps` is the serialized `DeviceProps` message (PF-024). |

## PF-024: DeviceProps schema

| Field | Value |
|-------|-------|
| **ID** | PF-024 |
| **Title** | `DeviceProps` uses `os=1`, `version=2` (`AppVersion` `primary=1`…`quinary=5`), `platformType=3`, and `requireFullSync=4`; `historySyncConfig=5` is not emitted |
| **Layer** | auth |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/auth` (round-trip, malformed table), `protocol/protobuf` (wire field numbers, enum values) |
| **Related findings** | PF-023 |
| **Notes** | Field numbers from `DeviceProps` in whatsmeow `proto/waCompanionReg/WACompanionReg.proto`. `PlatformType` values used or verified: `UNKNOWN=0`, `CHROME=1`, `FIREFOX=2`, `IE=3`, `OPERA=4`, `SAFARI=5`, `EDGE=6`, `DESKTOP=7`, `IPAD=8`, `ANDROID_TABLET=9`, `IOS_PHONE=14`, `IOS_CATALYST=15`, `ANDROID_PHONE=16`, `UWP=21`, `CLOUD_API=23`, `SMARTGLASSES=24`. The reference base value is `os="whatsmeow"`, version `0.1.0`, `platformType=UNKNOWN`, `requireFullSync=false`, plus a large `historySyncConfig=5`. WhatsCore emits only fields 1–4; the omission of `historySyncConfig` is a deliberate minimal subset and server acceptance is unverified, so the finding stays Probable. |

## PF-025: Registration versus login payloads

| Field | Value |
|-------|-------|
| **ID** | PF-025 |
| **Title** | Device pairing sends the registration form (`devicePairingData=19` present, `passive=false`, `pull=false`); a paired-device login instead sets `username=1` and `device=18` with `passive=true` and `pull=true` and carries no `devicePairingData` |
| **Layer** | auth |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/auth` (round-trip, rejection of passive/pull and missing registration data) |
| **Related findings** | PF-007, PF-020, PF-023 |
| **Notes** | whatsmeow `store/clientpayload.go` selects `getRegistrationPayload` when no JID is stored and `getLoginPayload` afterwards: registration sets `DevicePairingData`, `passive=false`, `pull=false`; login sets `username` to the user part, `device` to the device ID, `passive=true`, `pull=true`, `lidDbMigrated=true`. The registration payload is the plaintext encrypted into Noise `msg3.payload` (PF-007). WhatsCore implements both forms: `ParseClientPayload` rejects `passive=true`/`pull=true`, a missing `devicePairingData`, and a missing connection/WebInfo envelope; the login form is covered by PF-026 and the cross-form discrimination by PF-027. |

## PF-026: Login ClientPayload envelope

| Field | Value |
|-------|-------|
| **ID** | PF-026 |
| **Title** | A paired-device login `ClientPayload` sets `username=1`, `passive=3`, `userAgent=5`, `webInfo=6`, `connectType=12`, `connectReason=13`, `device=18`, `pull=33` and `lidDbMigrated=41`; `devicePairingData=19` is absent |
| **Layer** | auth |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/auth` (`TestBuildParseLoginRoundTrip`, `TestLoginWireFieldPresence`, `TestParseLoginMalformed`) |
| **Related findings** | PF-007, PF-020, PF-021, PF-022, PF-025, PF-027 |
| **Notes** | Field numbers verified against whatsmeow `proto/waWa6/WAWebProtobufsWa6.proto` (`ClientPayload`: `optional uint64 username = 1`, `optional uint32 device = 18`, `optional bool lidDbMigrated = 41`, alongside `passive=3`, `userAgent=5`, `webInfo=6`, `connectType=12`, `connectReason=13`, `pull=33`). Construction verified against whatsmeow `store/clientpayload.go` (`getLoginPayload`), which starts from `BaseClientPayload` and sets `username` to `device.ID.UserInt()` (the user part of the account JID), `device` to `device.ID.Device`, `passive=true`, `pull=true`, `lidDbMigrated=true`. `BaseClientPayload` supplies `userAgent`, `webInfo`, `connectType=WIFI_UNKNOWN=1`, and `connectReason=USER_ACTIVATED=1`. The reference also sets `lc=24` to `1` when unset; WhatsCore does not model field 24 and omits it, so server acceptance without `lc` is unverified. `device` is a `uint16` in the reference (`types.JID.Device`), so WhatsCore rejects IDs above `0xFFFF`; `username` is a `uint64` and zero is rejected. |

## PF-027: Registration versus login discrimination

| Field | Value |
|-------|-------|
| **ID** | PF-027 |
| **Title** | The two `ClientPayload` forms are discriminated by the presence of `devicePairingData=19` (registration) versus `username=1`/`device=18` (login); each parser rejects the other form |
| **Layer** | auth |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/auth` (`TestRegistrationLoginMutualRejection`, `TestParseLoginMalformed`, `TestParseMalformed`) |
| **Related findings** | PF-020, PF-025, PF-026 |
| **Notes** | whatsmeow `store/clientpayload.go` (`Device.GetClientPayload`) selects `getLoginPayload` when a JID is stored and `getRegistrationPayload` otherwise, so the two forms never carry each other's discriminator fields: registration sets `devicePairingData=19` with `passive=false`/`pull=false` and no `username`/`device`; login sets `username=1`/`device=18` with `passive=true`/`pull=true`/`lidDbMigrated=41` and no `devicePairingData`. WhatsCore enforces this in both directions: `ParseClientPayload` rejects any payload carrying `username` or `device` as a login form, and `ParseLoginPayload` rejects any payload carrying `devicePairingData` or lacking `username`/`device`. A payload carrying both discriminators is rejected by both parsers as ambiguous; parsing fails closed rather than guessing (§8). |

## PF-028: Post-handshake success stanza

| Field | Value |
|-------|-------|
| **ID** | PF-028 |
| **Title** | After the `ClientPayload`, the server accepts the connection with a bare `<success/>` stanza whose `lid` and `t` attributes are the only fields the reference clients read |
| **Layer** | auth |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `core/engine` (`TestWaitAuthSuccess`, `TestWaitAuthSkipsAck`) |
| **Related findings** | PF-007, PF-029 |
| **Notes** | Verified against whatsmeow `client.go`: the `nodeHandlers` map dispatches tag `"success"` to `handleConnectSuccess`, and `connectionevents.go` (`handleConnectSuccess`), which reads `lid` (`ag.JID("lid")`) and `t` (`ag.UnixTime("t")`, a Unix-seconds server timestamp) and nothing else. Baileys `Socket/socket.ts` (`ws.on('CB:success')`) likewise reads only `node.attrs.lid` and calls `updateServerTimeOffset(node)`, which reads `attrs.t`. Both clients treat the absent-tag/attribute set as the whole contract: `success` has no required attributes and no children the reference reads. whatsmeow additionally ignores `success` when the client was not paired (`if !cli.paired.Load()` warns and returns), i.e. a registration session's first accepted stanza is not necessarily `success`. WhatsCore treats `success` as success regardless of pairing form and logs `lid` at debug; it does not yet surface `t` or advance a server-time offset, so those two uses are **unverified** here. Children of `success` are **unverified** (neither reference reads any). |

## PF-029: Post-handshake failure and stream:error stanzas

| Field | Value |
|-------|-------|
| **ID** | PF-029 |
| **Title** | Rejection arrives as `<failure reason=int message=… code=…/>` or `<stream:error code=string><conflict type=…/></stream:error>`; `reason` is a decimal `ConnectFailureReason`, `code` on `stream:error` is a string compared to `"401"`/`"503"`/`"515"` |
| **Layer** | auth |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `core/engine` (`TestWaitAuthFailureCarriesCode`, `TestWaitAuthFailureRequiresCode`, `TestWaitAuthStreamError`, `TestWaitAuthUnexpectedStanza`, `TestWaitAuthTimeout`, `TestWaitAuthReaderOwnership`, `TestWaitAuthSanitizesServerText`) |
| **Related findings** | PF-007, PF-028 |
| **Notes** | Tags verified in whatsmeow `client.go` (`nodeHandlers`: `"failure"`, `"stream:error"`). `<failure>`: `connectionevents.go` (`handleConnectFailure`) reads `reason` as an integer via `ag.Int("reason")` and casts it to `events.ConnectFailureReason`, whose values are `400`, `401`, `402`, `403` (LOCKED), `405`, `406` (BANNED), `409`, `413`, `414`, `415`, `418`, `500`, `501`, `503`; it also reads `message`, plus `code` and `expire` for `reason==402` (temporary ban) and `logout_message_header`/`logout_message_subtext` for `reason==403`. Baileys (`ws.on('CB:failure')`) uses `+(node.attrs.reason || 500)`. `<stream:error>`: `handleStreamError` reads `code` with a **string** type assertion (`node.Attrs["code"].(string)`) and inspects only the `conflict` child's `type` attribute (`"device_removed"` with `code=="401"`, `"replaced"`); Baileys (`getErrorCodeFromStreamError`) instead derives the reason from the first child's tag and falls back to `code` with a default of `500`. WhatsCore parses `code`, `reason`, and `message` for `failure` and `code` plus `conflict@type` for `stream:error`, and caps/sanitizes all server text (120 runes) before it can reach a log or error. **Unverified:** `stream:error` child tags other than `conflict` (their presence is implied by both clients reading only the first child, but the tag set is not established), `<error code=479>` (mentioned only in a comment in whatsmeow's `nodeHandlers`), the full `ConnectFailureReason` semantics for each code (e.g. which reasons delete the session), and whether `success` can follow `failure` on one connection. WhatsCore maps any other stanza to `ErrUnexpectedStanza` and fails closed rather than routing like the reference's handler queue. |

---

Status: registration `ClientPayload` construction/parsing and its embedded
`DeviceProps` are implemented, and login `ClientPayload` construction/parsing
is implemented alongside it, proven with synthetic key material
(`protocol/auth`) and wire field-number tests (`protocol/protobuf`). The
post-handshake outcome is now parsed (`core/engine`, PF-028/PF-029) but only
against a fake server: no live registration, pairing, or login run is
recorded, so findings stay Probable. ADVSignedDeviceIdentity signing and
credential provisioning remain out of scope.

## PF-068: The server closes the connection after msg3 when the payload is incomplete

| Field | Value |
|-------|-------|
| **ID** | PF-068 |
| **Title** | After a valid Noise handshake, the real server closes the WebSocket (1006) as soon as it reads a ClientPayload that lacks a complete `DevicePairingRegistrationData`; it sends no `<success>`, `<failure>`, or `stream:error` first |
| **Layer** | auth |
| **Source** | direct observation of own session |
| **Observed date** | 2026-11-15 |
| **Confidence** | Confirmed |
| **Status** | Verified-by-test |
| **Proving test** | `cmd/whatscore-probe` live runs (handshake completes, then read fails with close 1006) |
| **Related findings** | PF-007, PF-020, PF-023 |
| **Notes** | Two payloads were tried against `wss://web.whatsapp.com/ws/chat`: an opaque byte string, and a minimal valid protobuf (`passive=false`, `pull=true`). Both completed the handshake and were then followed by an immediate 1006 close with zero bytes of application data. This is a real result, not a test gap: it means the registration payload must carry the full prekey material (`eRegid`, `eKeytype`, `eIdent`, `eSkeyID`, `eSkeyVal`, `eSkeySig`, `buildHash`, `deviceProps`) before the server will respond. It also means a connection that reports `CONNECTED` after handshake alone is reporting nothing — which is why `AuthConnector` now gates on the verdict. |

---

Status: both payload forms are implemented, signed-prekey material is generated, and
the live server's behaviour on an incomplete payload is recorded (PF-068). The
next live step needs a complete registration payload, which in turn needs the
token table for the stanza layer.
