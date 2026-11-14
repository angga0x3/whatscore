# Auth findings

Findings for the post-handshake `ClientPayload` that a companion device sends
inside the Noise `clientFinish` message (PF-007), plus the `DeviceProps`
message it carries. Extracted from read-only reference study of whatsmeow
`store/clientpayload.go`, `proto/waWa6/WAWebProtobufsWa6.proto`, and
`proto/waCompanionReg/WACompanionReg.proto` on 2026-11-15. Only the
registration subset is covered; ADVSignedDeviceIdentity signing and other
registration crypto are out of scope. (The reference repository names the
schema files `WAWebProtobufsWa6.proto` and `WACompanionReg.proto`; the older
paths `Wa6.proto` and `CompanionReg.proto` no longer resolve.)

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
| **Notes** | whatsmeow `store/clientpayload.go` selects `getRegistrationPayload` when no JID is stored and `getLoginPayload` afterwards: registration sets `DevicePairingData`, `passive=false`, `pull=false`; login sets `username` to the user part, `device` to the device ID, `passive=true`, `pull=true`, `lidDbMigrated=true`. The registration payload is the plaintext encrypted into Noise `msg3.payload` (PF-007). WhatsCore currently implements the registration form only: `ParseClientPayload` rejects `passive=true`/`pull=true`, a missing `devicePairingData`, and a missing connection/WebInfo envelope. Login payload support is future work. |

---

Status: registration `ClientPayload` construction/parsing and its embedded
`DeviceProps` are implemented and proven with synthetic key material
(`protocol/auth`) and wire field-number tests (`protocol/protobuf`). No live
registration or pairing run is recorded, so findings stay Probable.
ADVSignedDeviceIdentity signing, credential provisioning, and login-form
payloads remain out of scope.
