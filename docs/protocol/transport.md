# Transport findings

Wire-layer findings: WebSocket endpoint, connection headers, and frame
format. Extracted from read-only reference study of two independent,
known-working implementations, then **confirmed against the live endpoint on
2026-11-15** by `cmd/whatscore-probe`: a real dial completed the Noise
handshake with `wss://web.whatsapp.com/ws/chat`, reproduced across four
consecutive runs. That proves this endpoint, this intro header, and this
framing reach a peer that completes the recorded key schedule; it does not
prove pairing or messaging, which remain untested.

## PF-002: WebSocket endpoint and dial headers

| Field | Value |
|-------|-------|
| **ID** | PF-002 |
| **Title** | WebSocket endpoint is `wss://web.whatsapp.com/ws/chat` with Origin/Cache-Control/Pragma headers |
| **Layer** | transport |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Confirmed |
| **Status** | Verified-by-test |
| **Proving test** | `cmd/whatscore-probe` (live dial + Noise handshake, 4/4 runs); `protocol/transport` (endpoint/dialer tests) |
| **Related findings** | PF-003 |
| **Notes** | Identical constants in two independent implementations, read on 2026-11-15: whatsmeow `socket/framesocket.go` (`URL`, `Origin` header, `Cache-Control: no-cache`, `Pragma: no-cache`) and Baileys `src/Socket/socket.ts` (`WS_URL`, `WA_WEB_HEADER` set). **Live confirmation 2026-11-15:** `whatscore-probe` dialled this URL with these headers and completed the Noise handshake (`handshake-completed`), so the endpoint and header set are accepted by the real server. Origin/Cache-Control/Pragma are sent but their individual necessity is not isolated: the probe sends the full recorded set, and no run omitted one to test it. |

## PF-003: Connection intro header and frame format

| Field | Value |
|-------|-------|
| **ID** | PF-003 |
| **Title** | One-time 4-byte intro header `[0x57 0x41 0x06 0x03]`, then every frame is 3-byte big-endian length + payload, streamed across WebSocket binary messages |
| **Layer** | transport |
| **Source** | inferred — reference study |
| **Observed date** | 2026-11-15 |
| **Confidence** | Confirmed |
| **Status** | Verified-by-test |
| **Proving test** | `cmd/whatscore-probe` (live dial + handshake using this framing, 4/4 runs); `tests/integration` handshake round-trip; `protocol/transport` framing tests |
| **Related findings** | PF-002, PF-008 |
| **Notes** | The intro header is `"WA"` (0x57 0x41) + magic value `0x06` + token dictionary version `0x03`, sent exactly once, prefixed to the first frame of a connection (whatsmeow `WAConnHeader` = `{'W','A',6,token.DictVersion}`, Baileys `NOISE_WA_HEADER = [87, 65, 6, DICT_VERSION]` with `DICT_VERSION = 3`). Frames do NOT align with WebSocket message boundaries: a frame may span multiple WS messages and one WS message may carry multiple frames — receivers must reassemble a byte stream (whatsmeow `FrameSocket.processData`). Maximum frame size is 2^24 bytes (24-bit length field); larger frames are rejected. whatsmeow additionally forces a close on oversized reads (`conn.SetReadLimit(1<<24)`). **Live confirmation 2026-11-15:** the probe sent this intro header once and the subsequent length-prefixed handshake frames were accepted and answered by the real server. The 2^24 rejection path remains test-only, since a live run never approached the limit. |

---

Status: PF-002 and PF-003 confirmed against the live endpoint on 2026-11-15 by
`cmd/whatscore-probe` (dial → intro header → Noise handshake, 4/4 runs). The
probe deliberately stops at the handshake: pairing, authentication, and
messaging are still unproven against the real service.
