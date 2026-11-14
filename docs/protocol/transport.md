# Transport findings

Wire-layer findings: WebSocket endpoint, connection headers, and frame
format. Extracted from read-only reference study of two independent,
known-working implementations (see Sources); live-server confirmation is
pending manual interop, so these stay **Probable / Observed-only** even
though our own codec passes its round-trip tests — a self-test proves our
implementation matches this record, not that the record matches the live
protocol.

## PF-002: WebSocket endpoint and dial headers

| Field | Value |
|-------|-------|
| **ID** | PF-002 |
| **Title** | WebSocket endpoint is `wss://web.whatsapp.com/ws/chat` with Origin/Cache-Control/Pragma headers |
| **Layer** | transport |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Observed-only |
| **Proving test** | — (cannot be proven without a live connection; manual interop pending) |
| **Related findings** | PF-003 |
| **Notes** | Identical constants in two independent implementations, read on 2026-11-15: whatsmeow `socket/framesocket.go` (`URL`, `Origin` header, `Cache-Control: no-cache`, `Pragma: no-cache`) and Baileys `src/Socket/socket.ts` (`WS_URL`, `WA_WEB_HEADER` set). Neither value has been verified by a WhatsCore live connection yet. |

## PF-003: Connection intro header and frame format

| Field | Value |
|-------|-------|
| **ID** | PF-003 |
| **Title** | One-time 4-byte intro header `[0x57 0x41 0x06 0x03]`, then every frame is 3-byte big-endian length + payload, streamed across WebSocket binary messages |
| **Layer** | transport |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Probable |
| **Status** | Observed-only |
| **Proving test** | `tests/integration` handshake round-trip (proves our codec implements this format end-to-end); `protocol/transport` framing tests (stream reassembly, frame-per-message and frame-spanning-messages cases) |
| **Related findings** | PF-002, PF-008 |
| **Notes** | The intro header is `"WA"` (0x57 0x41) + magic value `0x06` + token dictionary version `0x03`, sent exactly once, prefixed to the first frame of a connection (whatsmeow `WAConnHeader` = `{'W','A',6,token.DictVersion}`, Baileys `NOISE_WA_HEADER = [87, 65, 6, DICT_VERSION]` with `DICT_VERSION = 3`). Frames do NOT align with WebSocket message boundaries: a frame may span multiple WS messages and one WS message may carry multiple frames — receivers must reassemble a byte stream (whatsmeow `FrameSocket.processData`). Maximum frame size is 2^24 bytes (24-bit length field); larger frames are rejected. whatsmeow additionally forces a close on oversized reads (`conn.SetReadLimit(1<<24)`). |

---

Status: first transport findings recorded 2026-11-15 from reference study;
live-server confirmation pending (manual interop, Phase 3 pairing runs).
