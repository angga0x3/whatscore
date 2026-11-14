# Binary findings

Wire format of the application-layer node tree, carried inside Noise-encrypted
frames. Extracted from read-only reference study of whatsmeow (`binary/`) and
Baileys (`src/WABinary/`) on 2026-11-15. No live capture is recorded yet, so
every finding here is **Probable**; "Verified-by-test" means a deterministic
test proves our implementation matches *this record*, not that WhatsApp still
sends these bytes today.

## PF-010: Frame flag and compression

| Field | Value |
|-------|-------|
| **ID** | PF-010 |
| **Title** | Every node payload starts with a one-byte flag; bit `0x02` means the rest is zlib-deflate of the node, otherwise the rest is the raw node |
| **Layer** | binary |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/binary` (compressed frame test, golden vectors) |
| **Related findings** | PF-011 |
| **Notes** | Baileys `decompressingIfRequired`: `flag & 2` → `inflate(buffer[1:])`, else `buffer.slice(1)`. WhatsCore always *encodes* flag `0x00` and accepts both forms on decode. |

## PF-011: Node layout and list encoding

| Field | Value |
|-------|-------|
| **ID** | PF-011 |
| **Title** | A node is a list of `1 + 2*len(attrs) + hasContent` items: tag, attribute key/value pairs, then optional content; odd size means no content, even size means a child list or a byte payload |
| **Layer** | binary |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/binary` (round-trip, golden vectors) |
| **Related findings** | PF-012, PF-014 |
| **Notes** | List start is `0x00` (empty), `0xF8` + u8, or `0xF9` + u16, both big-endian. Content: if the next tag is a list tag, it is a child list of that size; otherwise it is one string/bytes value. Reference implementations iterate attributes in map/object order; WhatsCore sorts keys lexicographically so encoding is deterministic (spec §4.3 invariant). |

## PF-012: String and byte encodings

| Field | Value |
|-------|-------|
| **ID** | PF-012 |
| **Title** | Strings are encoded by priority: single-byte token, double-byte token, packed nibble, packed hex, JID pair, raw bytes; byte lengths use BINARY_8/20/32 |
| **Layer** | binary |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/binary` (golden vectors, large values) |
| **Related findings** | PF-011, PF-013, PF-014 |
| **Notes** | Structural tags: `0x00` empty, `1..235` single tokens, `236..239` double dictionary + index byte, `245..247` special JIDs, `248/249` list, `250` JID pair, `251` hex, `252/253/254` binary 8/20/32, `255` nibble. `BINARY_8` carries a u8 length (<256), `BINARY_20` a 20-bit length in three bytes (<2^20), `BINARY_32` a u32 length. Tags, attribute keys, and attribute values all use the same encoder. Empty strings encode as `BINARY_8` length 0; `0x00` decodes as the empty string. |

## PF-013: Packed nibble and hex strings

| Field | Value |
|-------|-------|
| **ID** | PF-013 |
| **Title** | NIBBLE_8/HEX_8 pack two characters per byte; the length byte is `ceil(n/2)` with `0x80` set for odd lengths, and odd strings trim the trailing pad |
| **Layer** | binary |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/binary` (packed odd-length test, golden vectors) |
| **Related findings** | PF-012 |
| **Notes** | Nibble alphabet: `0-9`, `-` = 10, `.` = 11, pad = 15. Hex alphabet: `0-9`, `A-F` = 10-15, pad = 15. Encoder uses nibble when every character is a digit, `-`, or `.`, and hex when every character is a digit or uppercase `A-F`; both require length ≤ 127. |

## PF-014: JID wire forms

| Field | Value |
|-------|-------|
| **ID** | PF-014 |
| **Title** | JIDs travel as JID_PAIR (user + server), AD_JID (domain/device/user), FB_JID (user/device/server), or INTEROP_JID (user/device/integrator/server) |
| **Layer** | binary |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Verified-by-test |
| **Proving test** | `protocol/binary` (JID wire-form table) |
| **Related findings** | PF-012 |
| **Notes** | JID_PAIR is `0xFA`, then user (empty = `0x00`), then server. AD_JID `0xF7`: domain (0 = `s.whatsapp.net`, 1 = `lid`, 2 = `hosted`, 3 = `hosted.lid`), device, user. FB_JID `0xF6`: user, u16 device, server. INTEROP_JID `0xF5`: user, u16 device, u16 integrator, optional server (default `interop`). Device > 0 renders as `user:device@server`. WhatsCore's encoder only emits JID_PAIR; the other three are decode-only, so re-encoding a decoded node may change bytes but never the node value. |

## Token dictionary

The **contents** of WhatsApp's token tables are deliberately not reproduced
here: spec §10.2 records the clean-room/licensing question as unresolved.
`protocol/binary` therefore takes an injected `Dictionary`; tests and fixtures
use a small synthetic table (`tests/fixtures/binary_vectors.json`, generated by
`generate_binary_vectors.py`). A vetted dictionary can be supplied without
touching the codec.

---

Status: findings recorded 2026-11-15 from reference study; the codec is
Verified-by-test against independently generated synthetic vectors. Live
WhatsApp traffic is not decoded yet — that needs the real token table and a
manual interop observation.
