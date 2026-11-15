# Media findings

Encrypted-media envelope of the multi-device protocol: HKDF media-key
expansion, AES-256-CBC payload encryption and the truncated HMAC-SHA256
integrity tag. Extracted from read-only reference study of two independent,
known-working implementations (see Sources); cross-validated between
whatsmeow `download.go`/`upload.go`/`util/cbcutil` and Baileys
`src/Utils/messages-media.ts` on 2026-11-15. No live media upload or download
is recorded yet, so findings stay **Probable** even where algorithm-internal
values are pinned by deterministic vectors.

Transports, direct paths, MMS host selection and message-protobuf plumbing are
out of scope here; this package owns the byte-level envelope only.

## PF-040: Media key expansion and key layout

| Field | Value |
|-------|-------|
| **ID** | PF-040 |
| **Title** | `expanded = HKDF-SHA256(ikm=mediaKey, salt=nil, info="WhatsApp <Type> Keys", L=112)`; `iv = expanded[0:16]`, `cipherKey = expanded[16:48]`, `macKey = expanded[48:80]`, `expanded[80:112]` unused |
| **Layer** | media |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/media` (key vectors for image/video/document; length table: 0, 80 and 112 select the same key set) |
| **Related findings** | PF-041, PF-043, PF-045 |
| **Notes** | whatsmeow `download.go` `getMediaKeys`: `hkdfutil.SHA256(mediaKey, nil, []byte(appInfo), 112)` then slices `[:16]`, `[16:48]`, `[48:80]`, `[80:]`. Baileys `messages-media.ts` `getMediaKeys`: `hkdf(buffer, 112, { info: hkdfInfoKey(mediaType) })` with the same three slices (tail dropped). Both use RFC 5869 extract-then-expand with SHA-256, an **empty/absent salt** and the media type string as `info`. Input `mediaKey` is exactly 32 bytes (`random.Bytes(32)` in whatsmeow `Upload`, `Crypto.randomBytes(32)` in Baileys `encryptedStream`). The IV is therefore deterministic per media key and media type — it is not random per file and is not transmitted with the payload. |

## PF-041: Media-type HKDF info strings

| Field | Value |
|-------|-------|
| **ID** | PF-041 |
| **Title** | The HKDF `info` is `"WhatsApp <Class> Keys"` with class `Image`, `Video`, `Audio`, `Document`, `History`, `App State`, `Sticker Pack`, `Link Thumbnail`, `Image Thumbnail`, `Video Thumbnail`, `Document Thumbnail` or `Payment Background`; stickers/GIFs/voice notes reuse Image/Video/Audio |
| **Layer** | media |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/media` (per-type key vectors; all 12 accepted types derive distinct key sets; unknown-string negatives) |
| **Related findings** | PF-040 |
| **Notes** | whatsmeow `download.go`: `MediaImage = "WhatsApp Image Keys"`, `MediaVideo`, `MediaAudio`, `MediaDocument`, `MediaHistory`, `MediaAppState`, `MediaStickerPack = "WhatsApp Sticker Pack Keys"`, `MediaLinkThumbnail = "WhatsApp Link Thumbnail Keys"`; its `classToMediaType` maps `StickerMessage` and `StickerMetadata` to **Image**, not Sticker Pack. Baileys `Defaults/index.ts` `MEDIA_HKDF_KEY_MAPPING` uses `audio/ptt → Audio`, `image/sticker/product/biz-cover-photo → Image`, `video/gif/ptv → Video`, `document`, `md-msg-hist → History`, `md-app-state → App State`, `thumbnail-image/video/document/link → * Thumbnail`, `payment-bg-image → Payment Background`. Strings present in only one reference (Sticker Pack, Link Thumbnail, the three thumbnails, Payment Background) are documented as such in the package constants. Both references treat the type as an opaque string; WhatsCore instead accepts only the exact table and returns `ErrUnknownMediaType` otherwise, so a typo fails closed. Baileys' empty mappings (`ppic`, `product-catalog-image`) would yield `"WhatsApp  Keys"` with a double space — excluded as unverified. |

## PF-042: AES-256-CBC with always-on PKCS#7 padding

| Field | Value |
|-------|-------|
| **ID** | PF-042 |
| **Title** | Payload encryption is AES-256-CBC under `cipherKey` with `iv`, PKCS#7 padding always applied (`padLen = 16 − len%16`, so a full block gains a whole `0x10` block), no AAD and no per-file IV |
| **Layer** | media |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/media` (ciphertext vectors for 36-byte and empty plaintext; size table 0…100000; padding table incl. non-canonical final blocks) |
| **Related findings** | PF-040, PF-043 |
| **Notes** | whatsmeow `util/cbcutil/cbc.go` `Encrypt`: `sizeOfLastBlock := len(plaintext) % aes.BlockSize; paddingLen := aes.BlockSize - sizeOfLastBlock`, then `bytes.Repeat([]byte{byte(paddingLen)}, paddingLen)`; `cipher.NewCBCEncrypter(block, iv).CryptBlocks`. `Decrypt` inverts with `NewCBCDecrypter` and `unpad`. Baileys `encryptedStream` uses Node `aes-256-cbc` with default auto-padding (PKCS#7) and the derived `iv`; no AAD is possible in CBC. Deviation: WhatsCore's `unpad` requires every padding byte to equal `padLen`; the reference helper only rejects `padLen > len(src)`, so a malformed authentic blob would silently truncate there. Stricter validation cannot reject any blob produced by a conforming encryptor. |

## PF-043: Truncated HMAC-SHA256 over IV and ciphertext

| Field | Value |
|-------|-------|
| **ID** | PF-043 |
| **Title** | `mac = HMAC-SHA256(macKey, iv ‖ ciphertext)[:10]`; the uploaded blob is `ciphertext ‖ mac`, the MAC excludes plaintext and itself, and the IV is authenticated but not transmitted |
| **Layer** | media |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/media` (MAC vectors, independent HMAC recomputation, IV-dependence check, bit-flip sweep over all 42 blob bytes) |
| **Related findings** | PF-040, PF-044 |
| **Notes** | whatsmeow `download.go` `const mediaHMACLength = 10`; `validateMedia(iv, file, macKey, mac)` does `h := hmac.New(sha256.New, macKey); h.Write(iv); h.Write(file); hmac.Equal(h.Sum(nil)[:10], mac)`. `upload.go` `Upload` mirrors it: `h.Write(iv); h.Write(ciphertext); dataToUpload := append(ciphertext, h.Sum(nil)[:10]...)`. Baileys `encryptedStream`: `Crypto.createHmac('sha256', macKey).update(iv)`, `hmac.update` per ciphertext chunk, `.digest().slice(0, 10)`, written after `aes.final()`. Only the first 10 bytes of the 32-byte tag are kept; the tag is appended, not prefixed, and no length field is emitted. WhatsCore computes the full HMAC-SHA256 and compares the truncated 10-byte value with `hmac.Equal`, so the comparison is constant time. |

## PF-044: Download framing and verification order

| Field | Value |
|-------|-------|
| **ID** | PF-044 |
| **Title** | A download splits the last 10 bytes off as the MAC, verifies it over `iv ‖ ciphertext` before any CBC decryption, then unpads; the smallest valid blob is 26 bytes (one padded block + MAC) and the ciphertext must be a positive multiple of 16 |
| **Layer** | media |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/media` (round-trip incl. empty plaintext, tamper sweep, size-mismatch table) |
| **Related findings** | PF-042, PF-043 |
| **Notes** | whatsmeow `downloadEncryptedMedia` rejects `len(data) <= 10` (`ErrTooShortFile`) and returns `file = data[:len-10]`, `mac = data[len-10:]`; `downloadAndDecrypt` calls `validateMedia` **before** `cbcutil.Decrypt`, so tampering fails closed before padding is inspected. Baileys `downloadEncryptedContent` streams the body straight into `aes-256-cbc` and does not perform a separate HMAC check in that helper; its `final()` rejects bad padding. WhatsCore follows the whatsmeow order and additionally requires `len(ciphertext) > 0` and block alignment, which whatsmeow's `cbcutil.Decrypt` also enforces. Because the MAC is checked first, `ErrInvalidCiphertext` on padding means the blob was authentic but malformed — there is no padding oracle for an attacker without the MAC key. Empty plaintext is valid and yields exactly 26 bytes. |

## PF-045: Media key size, unused expansion tail, companion hashes

| Field | Value |
|-------|-------|
| **ID** | PF-045 |
| **Title** | The media key is 32 random bytes; expansion bytes `[80:112]` are unused by the upload/download envelope, while `fileSHA256 = SHA-256(plaintext)` and `fileEncSHA256 = SHA-256(ciphertext ‖ mac)` travel beside it in the message protobuf |
| **Layer** | media |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/media` (key-size constants, expansion-length equivalence, envelope vectors pin the exact bytes the hashes would cover) |
| **Related findings** | PF-040, PF-043 |
| **Notes** | whatsmeow `getMediaKeys` returns the tail as `refKey`, but `downloadAndDecrypt` and `Upload` discard it (`_`); Baileys slices only 80 bytes. Both request `L=112` regardless. `Upload` sets `resp.FileSHA256 = SHA256(plaintext)`, `resp.FileEncSHA256 = SHA256(ciphertext ‖ mac)`, `resp.FileLength = len(plaintext)`; Baileys `encryptedStream` hashes plaintext with `sha256Plain` and every ciphertext chunk plus the MAC with `sha256Enc`. Those hashes are checked by callers against the protobuf fields (`fileSHA256`, `fileEncSHA256`) and are **not** part of this package; WhatsCore leaves that bookkeeping to `core/media`, and their exact byte coverage is observed in the reference study rather than proven here. Not implemented and deliberately recorded as open: media-path/MMS host construction, streaming uploads, the 64 KiB video streaming sidecar (`makeStreamingSidecar`), and the media-retry key (`HKDF-SHA256(mediaKey, info="WhatsApp Media Retry Notification", L=32)` with AES-256-GCM and message-id AAD, Baileys `getMediaRetryKey`). |

## PF-046: Streaming encrypt/decrypt with verify-before-write

| Field | Value |
|-------|-------|
| **ID** | PF-046 |
| **Title** | A media payload can be encrypted and decrypted in bounded memory without changing the envelope: encryption reads plaintext in chunks, emits `ciphertext ‖ mac[10]` with the MAC accumulated as blocks are produced, and decryption authenticates `iv ‖ ciphertext` in a first pass before writing any plaintext in a later pass |
| **Layer** | media |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/media/stream_test.go` (sizes 0, 1, 16, 17, 1 MiB and 8 MiB; streamed blob byte-identical to `Encrypt`; incremental-write and per-write-bound checks; first/middle/last/MAC byte flips and authentic bad padding leave `dst` empty; truncation, read/write failures, nil endpoints, `MaxStreamBytes` table) |
| **Related findings** | PF-042, PF-043, PF-044 |
| **Notes** | Reference behaviour, from the same study as PF-043/PF-044: the MAC is updated per ciphertext chunk and written only after the final block, and a download reads the whole ciphertext, splits the last 10 bytes, and calls the MAC check **before** CBC decryption — so the tag is never computed in the same forward pass that decrypts. WhatsCore encodes that order in `protocol/media` as `EncryptStream`/`DecryptStream` (`protocol/media/stream.go`). Encryption reads through an `io.Reader` in 32 KiB chunks, holds back only the trailing partial block, always applies a whole PKCS#7 padding block, and writes each encrypted chunk before reading more, so the working set is a chunk plus one block. Decryption takes an `io.ReaderAt` plus the total blob size instead of a byte slice and reads the source in three passes: (1) HMAC-SHA256 over `iv ‖ ciphertext[0:size-10]`, compared in constant time with the trailing tag via `hmac.Equal`; (2) the final ciphertext block plus its predecessor (or the IV when only one block exists), decrypted alone to validate every PKCS#7 byte; (3) the body again, chunk by chunk, decrypting and truncating the padding. Nothing reaches `dst` until (1) and (2) succeed, which is what makes the streaming path fail closed on tampering rather than after writing a prefix — the property a single forward pass cannot provide. `MaxStreamBytes` (512 MiB default, `0` disables) is a placement policy, not a wire constant: it caps per-call work, and exceeding it returns a `*StreamLimitError` wrapping `ErrStreamLimit`. The ciphertext is byte-identical to `Encrypt` for the same key set, so streaming and buffered callers interoperate in both directions. Not modelled: ranged/resumed downloads, and decrypting into a destination that must be transactional on a mid-stream write error (the MAC and padding are already known at that point, so a failed write leaves an authenticated but partial prefix). |

## PF-047: Video sidecar hash (SHA-256 over the plaintext)

| Field | Value |
|-------|-------|
| **ID** | PF-047 |
| **Title** | The media sidecar's `fileSHA256` is `SHA-256(plaintext)` over the unencrypted payload, computed in one streaming pass over the source and independent of the media key, IV and envelope bytes |
| **Layer** | media |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/media/stream_test.go` (vectors for empty, one zero byte, 17 bytes and 1 MiB against hex digests computed with python3 `hashlib`; cross-check against `sha256.Sum256`; plaintext-vs-ciphertext separation) |
| **Related findings** | PF-043, PF-045 |
| **Notes** | Both references hash the plaintext as it is produced: `Upload` sets `resp.FileSHA256 = SHA256(plaintext)` and Baileys `encryptedStream` feeds every plaintext chunk to a `sha256Plain` hash, while the ciphertext-side companion `fileEncSHA256` covers `ciphertext ‖ mac` (PF-045). For videos the plaintext hash is the value recorded in the media sidecar that travels beside the message and is what a receiver recomputes after decryption to confirm it reassembled the same bytes. WhatsCore exposes the primitive as `SidecarHash(io.Reader)` (`protocol/media/stream.go`) so large payloads are digested in 32 KiB chunks; digesting the ciphertext instead yields a different value and is not a substitute. The digest is corroboration, not authentication: it can be recomputed over mangled bytes, so the envelope MAC (PF-043) remains the trust decision and comparisons against a remembered digest should be constant time. Verified vectors (hex): empty `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`; `00` `6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d`; the 17-byte pattern `b6ff0191041cc77b1ef514adaed53fdd247fd43221a629d3d7c91d14e21038a3`; the 1 MiB pattern `06b7bbfb7824aa03382051691630eb26de85102d1b08a81e907ec0744cd8a286`. Not implemented and deliberately recorded as open: the surrounding 64 KiB video streaming-sidecar envelope (`makeStreamingSidecar`) and where its fields are placed in the protobuf; this finding covers only the digest those bytes carry. |

---

Status: media-key expansion, AES-256-CBC/PKCS#7 encryption, truncated
HMAC-SHA256 authentication and fail-closed decryption are implemented in
`protocol/media` and proven with synthetic vectors generated independently of
the package (Python HKDF + AES). Streaming encrypt/decrypt with
verify-before-write (PF-046) and the plaintext sidecar digest (PF-047) are
implemented in `protocol/media/stream.go` and proven there, with streamed
ciphertext cross-checked byte-for-byte against the buffered `Encrypt` and the
sidecar vectors computed with Python `hashlib`. Live upload/download, the
ciphertext-side companion hash, media paths, the 64 KiB video streaming-sidecar
envelope and media retry remain open; their findings stay Probable until manual
interop.
