# Sync findings

Encrypted application-state ("app state") patch decoding: the `<sync>` stanza
shape, the `SyncdPatch` protobuf schema, the per-record value framing, the
value MAC, and the order in which snapshots and patches are applied. Extracted
from read-only reference study of three independent, known-working
implementations (see Sources); cross-validated between whatsmeow
`appstate/` + `proto/waServerSync/`, Baileys `src/Utils/chat-utils.ts`, and
whatsapp-rust `wacore/appstate/`.

`protocol/sync` owns parsing and the value-MAC check only. Key expansion
(HKDF-SHA256, info `"WhatsApp Mutation Keys"`, five 32-byte keys), AES-256-CBC
payload decryption, external-blob downloads, and the LTHash/snapshotMAC/
patchMAC bookkeeping stay with the caller. No live sync traffic is recorded, so
structural findings are **Probable**; the value MAC is deterministic and
pinned by an independently recomputed vector, so it is **Confirmed**.

## PF-070: App-state patch list stanza

| Field | Value |
|-------|-------|
| **ID** | PF-070 |
| **Title** | Patches arrive as `<iq xmlns="w:sync:app:state"><sync><collection name=…>` where each `<collection>` holds `<patch>` children (protobuf bytes) either under a `<patches>` wrapper or directly under the collection, alongside an optional `<snapshot>` child that is an `ExternalBlobReference` protobuf, not inline records |
| **Layer** | sync |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/sync` (round-trip through `binary.Codec`, collection/patches variants, snapshot sibling, malformed-stanza table) |
| **Related findings** | PF-011, PF-071 |
| **Notes** | Request shape (whatsmeow `appstate.go` `fetchAppStatePatches`): `<iq type="set" xmlns="w:sync:app:state"><sync><collection name=… return_snapshot=… version=fromVersion/></sync></iq>` — `version` is omitted when a snapshot is requested. Response walk (whatsmeow `appstate/decode.go` `ParsePatchList`): `sync → collection`, attributes `name` (the collection, e.g. `critical_block`, `critical_unblock_low`, `regular`, `regular_high`, `regular_low`) and `has_more_patches`; `snapshot` child → `ExternalBlobReference{mediaKey=1, directPath=2, handle=3, fileSizeBytes=4, fileSHA256=5, fileEncSHA256=6}` → downloaded blob unmarshals as `SyncdSnapshot`. Baileys `chat-utils.ts` `extractSyncdPatches` accepts `<patch>` under `<patches>` **or** directly under `<collection>` and treats `has_more_patches === 'true'`; whatsapp-rust `patch_decode.rs` also handles bare `<sync>`/`<collection>` roots and a per-collection `<collection type="error"><error code=… text=…/>` (409 conflict, 400/404 fatal, else retry). WhatsCore accepts a `<sync>` or `<collection>` root, both patch placements, and fails closed on `type="error"` (`ErrInvalidPatch`) instead of modelling the server error classes. Snapshot payloads are not parsed here: `protocol/sync` never downloads, so a snapshot-only collection yields zero patches and the caller owns the snapshot path. Both references skip `<patch>` children without content in some paths (whatsmeow `continue`s, Baileys skips empty content); WhatsCore skips them too rather than failing the whole collection. `has_more_patches` (and `return_snapshot`/`version` on the request side) is a paging hint WhatsCore does not surface: the attribute stays on the caller's node, and `ParsePatches` returns only the patches, so the caller decides whether to fetch another page. Wrapper handling is a documented divergence: whatsmeow and whatsapp-rust read `<patch>` children only from `<patches>`, while Baileys falls back to the collection when `<patches>` is absent (`getBinaryNodeChildren(patchesNode \|\| collectionNode, 'patch')`). WhatsCore implements the fallback (a `<collection>` whose patches sit directly beneath it parses) and prefers `<patches>` when both are present; a response using the bare form is therefore accepted rather than silently yielding zero patches — the failure mode whatsmeow would have. |

## PF-071: SyncdPatch and SyncdMutation schema

| Field | Value |
|-------|-------|
| **ID** | PF-071 |
| **Title** | `<patch>` content is `SyncdPatch{version=1, mutations=2, externalMutations=3, snapshotMAC=4, patchMAC=5, keyID=6, exitCode=7, deviceIndex=8, clientDebugData=9}`; each mutation is `SyncdMutation{operation=1, record=2}` with `SyncdOperation` `SET=0`/`REMOVE=1`; each record is `SyncdRecord{index=1, value=2, keyID=3}` wrapping `{blob=1}` byte messages, and `SyncdVersion`/`KeyId` reuse `version=1`/`ID=1` |
| **Layer** | sync |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/sync` (field-by-field decode of a synthetic patch, unknown-field skip table, absent-operation default, mutation-without-record negative) |
| **Related findings** | PF-070, PF-072 |
| **Notes** | Field numbers and the enum values are read from the proto2 schema whatsmeow ships (`proto/waServerSync/WAWebProtobufsServerSync.proto`): `message SyncdMutation { enum SyncdOperation { SET = 0; REMOVE = 1; } optional SyncdOperation operation = 1; optional SyncdRecord record = 2; }`, `SyncdRecord { SyncdIndex index = 1; SyncdValue value = 2; KeyId keyID = 3; }`, `SyncdSnapshot { SyncdVersion version = 1; repeated SyncdRecord records = 2; bytes mac = 3; KeyId keyID = 4; }`, `SyncdMutations { repeated SyncdMutation mutations = 1; }`. Field 8/9 (`deviceIndex`, `clientDebugData`) appear only in the newer schema; both references ignore unknown fields, and so does WhatsCore. A mutation with an absent `operation` is decoded as SET — proto2 enum default 0, and both references rely on this (`whatsapp-rust` `processor.rs` `match mutation.operation { None => SET, … }`, Baileys `decodeSyncdMutations` `'operation' in msgMutation ? … : SET`). An unknown enum value (≥2) fails the patch (`ErrInvalidPatch`); whatsapp-rust does the same (`UnsupportedSyncdOperation`), while Baileys maps anything that is not SET to 0x02 in the MAC. `externalMutations` is only a *presence* flag: when set, the mutation list must be downloaded as a `SyncdMutations` blob and appended to `mutations`, so WhatsCore reports `Patch.ExternalMutations` and leaves the download to the caller. |

## PF-072: Mutation record and value blob framing

| Field | Value |
|-------|-------|
| **ID** | PF-072 |
| **Title** | `record.value.blob` is `iv(16) ‖ AES-256-CBC(PKCS#7) ciphertext ‖ valueMAC(32)`, so the plaintext starts at offset 16 plus a whole number of 16-byte blocks; `record.index.blob` is a separate 32-byte HMAC-SHA256; every reference requires the value blob on SET and REMOVE alike, and WhatsCore additionally tolerates a REMOVE with no payload |
| **Layer** | sync |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/sync` (value/MAC split, 48-byte and IV-only values, `SET`/`REMOVE` minimum-length table, removal-without-payload round-trip) |
| **Related findings** | PF-071, PF-073 |
| **Notes** | whatsmeow `appstate/decode.go` `decodeMutation`: `content := bytes.Clone(blob); content, valueMAC = content[:len(content)-32], content[len(content)-32:]; iv, content = content[:16], content[16:]` → `cbcutil.Decrypt(keys.ValueEncryption, iv, content)`; the encoder produces the same shape by calling `cbcutil.Encrypt(keys.ValueEncryption, nil, content)`, which prepends a random 16-byte IV. Baileys `decodeSyncdMutations` splits at `-32` and hands `encContent` to `aesDecrypt(…, valueEncryptionKey)` (Node `aes-256-cbc`, IV = first 16 bytes). whatsapp-rust `decode.rs` `decode_record` requires a `value.blob` and rejects `len < 16 + 32` (`MissingValueBlob`, `ValueBlobTooShort`) for **every** record, SET and REMOVE alike; whatsmeow slices `blob[:len-32]` unconditionally, which panics on a missing value; Baileys skips a record whose MAC cannot verify. So no reference accepts a REMOVE without a payload — WhatsCore does (documented divergence, `Patch.ExternalMutations`-grade caller concern): a REMOVE is identified by its index MAC alone, so `PatchMutation.Value`/`ValueMAC` are simply nil for a zero-length blob, and a non-empty REMOVE blob must still meet `MinValueSize`. That tolerance is an inference about server behaviour, not an observation, and it is the one part of this finding with no reference backing. Block alignment is deliberately **not** enforced at parse time: CBC ciphertext validity belongs to the caller's decrypt step, and the one reference that checks it (`cbcutil.Decrypt`) checks it after the MAC. The index side is out of scope: `indexMAC = HMAC-SHA256(indexKey, indexJSON)` where `indexJSON` is the JSON string array also echoed inside the decrypted `SyncActionData.index`; WhatsCore carries `IndexMAC` verbatim and does not compute it, so `VerifyValueMAC` covers the value only. |

## PF-073: Value MAC

| Field | Value |
|-------|-------|
| **ID** | PF-073 |
| **Title** | `valueMAC = HMAC-SHA512(valueMACKey, opByte ‖ keyID ‖ value ‖ uint64be(len(keyID)+1))[:32]` with `opByte` 0x01 for SET and 0x02 for REMOVE, `value = iv ‖ ciphertext` (the MAC is excluded from its own input), and the trailing 32 bytes of `record.value.blob` as the transmitted tag |
| **Layer** | sync |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Confirmed |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/sync` (independent vectors for SET, REMOVE-with-value and REMOVE-empty — recomputed in-test from the stdlib; negatives: tampered value/MAC, wrong key, wrong key id, wrong operation, short/long MAC, short key, empty key id) |
| **Related findings** | PF-072, PF-074 |
| **Notes** | Three-way agreement on the HMAC input order: whatsmeow `appstate/hash.go` `generateContentMAC` — `operationBytes = []byte{byte(operation) + 1}`, `keyDataLength = uint64ToBytes(uint64(len(keyID) + 1))`, then `concatAndHMAC(sha512.New, key, operationBytes, keyID, data, keyDataLength)[:32]`; Baileys `chat-utils.ts` `generateMac` — `opByte = SET ? 0x01 : 0x02`, `keyData = opByte ‖ keyIdBuffer`, `last[7] = keyData.length`, `hmacSign(total, key, 'sha512').subarray(0, 32)`; whatsapp-rust `hash.rs` `generate_content_mac` — `key_data_length[7] = (key_id.len() + 1) & 0xff` with `Hmac<Sha512>` and `out[..32]`. `data` is the whole `iv ‖ ciphertext` prefix, never the plaintext. The length field is eight big-endian bytes holding `len(keyID)+1` (the key id plus the operation byte); it is written as a full uint64 by whatsmeow/whatsapp-rust and only through `keyData.length` by Baileys, which is identical for key ids shorter than 255 bytes. Note the +1: it counts the operation byte, not the key id. `operation + 1` is why an unknown enum value 2 would MAC as 0x03 in whatsmeow; WhatsCore rejects it at parse time instead. Verified vectors with a synthetic 32-byte key `0x00…0x1f`, key id `0x010203040506`, value `0x10…0x4f`: SET `108c5179…a09cc0de`, REMOVE-with-value `91b2fb9f…9445fabb`, REMOVE-empty `6bbe8b44…0787c97a`. |

## PF-074: Snapshot/patch ordering and envelope MACs

| Field | Value |
|-------|-------|
| **ID** | PF-074 |
| **Title** | A collection is applied as "snapshot first (when present, replacing local state), then every patch in wire order"; patch versions are expected to ascend by exactly one (enforced fatally by whatsapp-rust, only used as a trust condition by whatsmeow); the envelope MACs are `snapshotMAC = HMAC-SHA256(snapshotMACKey, lthash(128) ‖ uint64be(version) ‖ collectionName)` and `patchMAC = HMAC-SHA256(patchMACKey, snapshotMAC ‖ valueMAC₁…valueMACₙ ‖ uint64be(version) ‖ collectionName)` — neither is checked by `protocol/sync` |
| **Layer** | sync |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/sync` (patch and mutation order preserved over a 5-patch list, versions carried verbatim, envelope MAC bytes round-tripped untouched) |
| **Related findings** | PF-071, PF-073 |
| **Notes** | whatsmeow `appstate/decode.go` `DecodePatches` decodes the snapshot first (records are treated as implicit SET mutations) and then loops `list.Patches` in slice order, carrying `HashState.Version` forward; Baileys `decodePatches` iterates `syncds` in order, sets `newState.version = patchVersion`, and breaks out of the loop on a snapshotMAC mismatch. Neither sorts, so wire order **is** application order. A patch with no `version` sub-message yields 0 in WhatsCore and in whatsmeow (`patch.GetVersion().GetVersion()`); Baileys instead substitutes `collection.attrs.version + 1`, which is a client-side convenience WhatsCore does not copy. Version continuity is treated differently: whatsapp-rust `processor.rs` `process_patch` fails with `PatchVersionMismatch` unless `patch_version == state.version + 1` (skipped only when there is no prior state), while whatsmeow tolerates a skipped version and only refuses to ignore an LTHash mismatch unless `version == currentState.Version+1` — i.e. a gap forces a snapshot re-request rather than being repaired. `protocol/sync` preserves order and version verbatim and never reorders, dedupes or gap-checks: duplicate-index detection (whatsapp-rust `detect_duplicate_index_in_patch`, WA Web `validateNoSameIndexForMultipleMutations` — fatal for a repeat within one operation, allowed across SET and REMOVE) and the LTHash fold are caller responsibilities. MAC coverage, for the eventual verifier: `generateSnapshotMAC` (whatsmeow) / `generateSnapshotMac` (Baileys) hash `lthash ‖ uint64be(version) ‖ name`; `generatePatchMAC` hashes `snapshotMAC ‖ each mutation's trailing 32 value bytes ‖ uint64be(version) ‖ name` and **includes REMOVE mutations' blobs** (whatsapp-rust documents that narrowing it to SET would change the MAC of every patch containing a removal). Baileys' `to64BitNetworkOrder` writes the version as a uint32 into the low four bytes of an eight-byte buffer, so versions above 2³²−1 collide; whatsmeow and whatsapp-rust write a true uint64 (whatsapp-rust logs a warning instead of refusing). Observed collection versions are small, but a future verifier must pick a side — recorded here as an open divergence. The `snapshotMAC` comparison is treated as non-fatal by all three once a patch's own `patchMAC` verifies (whatsmeow ignores the LTHash mismatch on a consecutive version, whatsapp-rust latches `mac_mismatch_fatal`, Baileys warns and breaks the loop); WhatsCore implements none of this yet. |

---

Status: app-state patch parsing and the value MAC are implemented in
`protocol/sync` (PF-070…PF-074) and proven by synthetic stanza round-trips
through `protocol/binary` plus an independently recomputed MAC vector. Key
expansion, AES-256-CBC record decryption, snapshot/external blob downloads,
index MACs, and the LTHash + snapshotMAC/patchMAC checks remain out of scope
and stay Probable until they land with a caller. `docs/protocol/README.md` is
owned by the integrating session: index rows for PF-070…PF-074 and the
Probable wire/payload exception for them still need to be added there.
