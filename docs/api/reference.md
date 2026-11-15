# API Reference

The full, versioned contract lives in [`openapi.yaml`](openapi.yaml)
(OpenAPI 3.1). This page documents what is **implemented today**
with runnable examples, and points at the contract for everything else.

## Conventions

- Base URL: `http://localhost:8080` (local default).
- REST endpoints use prefix `/api/v1` and Bearer authentication:
  `Authorization: Bearer wc_live_...`
- System probes sit at the root and need no auth.
- Every error uses one envelope:

  ```json
  { "error": { "code": "not_found", "message": "the requested resource does not exist" } }
  ```

- Responses always include `Content-Type: application/json` and an
  `X-Request-Id` header for support/tracing.

## System endpoints (implemented)

### GET /health — liveness

```bash
curl -s http://localhost:8080/health
```

```json
{ "status": "ok" }
```

Always `200` while the process can answer. Deliberately dependency-free.

### GET /ready — readiness

```bash
curl -s http://localhost:8080/ready
```

```json
{
  "status": "ready",
  "checks": {
    "database": { "status": "up", "latency_ms": 0.417 }
  }
}
```

- `200` — all dependencies reachable.
- `503` with `"status": "unavailable"` — a check failed (body includes the
  error per dependency).
- `503` with `"status": "shutting_down"` — instance is draining after a
  termination signal; stop routing to it.

### GET /version — build info

```bash
curl -s http://localhost:8080/version
```

```json
{
  "name": "WhatsCore",
  "version": "dev",
  "commit": "none",
  "built_at": "unknown",
  "go_version": "go1.26.0"
}
```

## Sessions (implemented)

`/api/v1/sessions` is live over the in-process session manager:

| Method | Path | Behavior |
|--------|------|----------|
| `GET` | `/api/v1/sessions` | list, optional `?status=` filter, `{"data": [...]}`
| `POST` | `/api/v1/sessions` | create from `{"name":"..."}`, `201`
| `GET` | `/api/v1/sessions/{id}` | one session
| `DELETE` | `/api/v1/sessions/{id}` | stop and delete, `204`
| `POST` | `/api/v1/sessions/{id}/connect` | start, `202`
| `POST` | `/api/v1/sessions/{id}/disconnect` | stop, `202`

```bash
curl -s -X POST http://localhost:8080/api/v1/sessions \
  -H 'Content-Type: application/json' -d '{"name":"primary"}'
# {"id":"<uuid>","name":"primary","status":"STOPPED",...}
```

Session payloads carry `id`, `name`, `status`, `created_at`, `updated_at`;
status values follow the OpenAPI enum.

The server binary mounts these routes, so `docker compose up` exposes them as
soon as `/ready` reports the database up. Sessions are managed in memory:
restarting the process clears them.

## Webhooks (implemented)

`/api/v1/webhooks` is live over an in-memory endpoint registry. Delivering
payloads (signing, retries, delivery records) is documented in
[`webhooks.md`](webhooks.md) and still needs a worker; registrations live
in process memory, so restarting the server clears them.

| Method | Path | Behavior |
|--------|------|----------|
| `GET` | `/api/v1/webhooks` | list all endpoints, bare JSON array
| `POST` | `/api/v1/webhooks` | register from `{"url":"...","events":[...]}`, `201`
| `GET` | `/api/v1/webhooks/{id}` | one endpoint
| `PATCH` | `/api/v1/webhooks/{id}` | partial update of `url`, `events`, `secret`, `enabled`
| `DELETE` | `/api/v1/webhooks/{id}` | remove, `204`
| `GET` | `/api/v1/webhooks/{id}/deliveries` | delivery history, `[]` until a worker records attempts

```bash
curl -s -X POST http://localhost:8080/api/v1/webhooks \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com/hooks/whatscore","events":["message.received"]}'
# {"id":"<uuid>","url":"https://example.com/hooks/whatscore",
#  "events":["message.received"],"enabled":true,
#  "created_at":"...","updated_at":"...","secret":"whsec_..."}
```

Rules enforced on create and update:

- `url` must be absolute `http`/`https` with a non-empty host.
- `events` must be a non-empty subset of the OpenAPI `EventType` enum;
  duplicates are collapsed.
- `secret` is optional — omit it and a 256-bit `whsec_...` value is
  generated. A supplied secret must be at least 16 bytes.
- `enabled` defaults to `true`.
- `session_id` is not supported yet: a non-empty value is a `400`, because
  every endpoint in this registry is global.

The signing secret is **returned only by the `201` create response**. Reads,
lists, and updates omit it entirely, so store it right after creating an
endpoint. Webhook payloads carry `id`, `url`, `events`, `enabled`,
`created_at`, and `updated_at`.

## Messaging (implemented)

`/api/v1/sessions/{id}/messages*` is live over an in-memory, per-session store
bounded at 1000 messages: the oldest message of a session is evicted once that
limit is reached. Restarting the process clears it. The routes mount when the
host wires a message store (`Handler.SetMessages`); without one, these paths
keep answering `501`.

| Method | Path | Behavior |
|--------|------|----------|
| `POST` | `/api/v1/sessions/{id}/messages/text` | queue a text message, `202` |
| `GET` | `/api/v1/sessions/{id}/messages` | newest-first page, `?limit=` (1–100, default 20), `?cursor=` |
| `GET` | `/api/v1/sessions/{id}/messages/{messageId}` | one message, `200`/`404` |

```bash
curl -s -X POST http://localhost:8080/api/v1/sessions/$SESSION_ID/messages/text \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: 6b1f0c2e-...' \
  -d '{"to":"6281234567890@s.whatsapp.net","text":"Halo WhatsCore!"}'
# {"message_id":"<uuid>","status":"queued"}
```

```bash
curl -s "http://localhost:8080/api/v1/sessions/$SESSION_ID/messages?limit=2"
# {"data":[{"id":"<uuid>","session_id":"<uuid>",
#           "chat_id":"6281234567890@s.whatsapp.net","sender":"",
#           "direction":"OUTBOUND","type":"text","text":"Halo WhatsCore!",
#           "created_at":"..."}],
#  "next_cursor":"<opaque>"}
```

Rules enforced on send:

- `to` is a JID: exactly one `@` with a non-empty user and server
  (`6281234567890@s.whatsapp.net`), at most 255 bytes, no whitespace or
  control characters.
- `text` is required and capped at 65536 bytes.
- Unknown sessions answer `404 not_found`.
- A session that exists but is not `CONNECTED` answers
  `503 session_not_connected`. Connect it first, then retry.
- `Idempotency-Key` is scoped per session and capped at 255 bytes. The same key
  with the same `to`/`text` replays the original `202` body (no second append);
  the same key with a different body answers `409 idempotency_conflict`. Failed
  requests release the key, so a retry after connecting can succeed.

**Delivery is not implemented yet.** `202 {"status":"queued"}` is a queue
acknowledgement — the message is recorded and visible on the read endpoints,
but no WhatsApp frame leaves the process. `direction` is always `OUTBOUND` for
this route, `type` is always `text`, and `sender` is empty.

`next_cursor` is opaque: pass it back as `?cursor=` to continue. It keeps
working while new messages arrive and while old ones are evicted. `data` is
newest first. The contract's `?direction=` filter is not applied yet: every
message stored by this route is `OUTBOUND`, so filter client-side for now.

## Streaming (implemented)

Two Server-Sent Events endpoints share the in-process event bus. They mount
when the host wires a bus (`Handler.SetBus`); without one they answer `501`, so
a process that does not publish events does not pretend to stream them.

| Method | Path | Behavior |
|--------|------|----------|
| `GET` | `/api/v1/sessions/{id}/qr` | `qr` event per pairing code, `connected` once paired, then the stream ends; `409` when already connected |
| `GET` | `/api/v1/sessions/{id}/events` | every normalized event of that session |

```bash
curl -N http://localhost:8080/api/v1/sessions/$SESSION_ID/qr
# event: qr
# data: {"qr":"2@xxxxxxxx","expires_at":"..."}
#
# event: connected
# data: {"status":"CONNECTED"}
```

```bash
curl -N http://localhost:8080/api/v1/sessions/$SESSION_ID/events
# event: message.received
# data: {"id":"evt_42","event":"message.received","session_id":"<uuid>",
#        "timestamp":"...","seq":42,
#        "data":{"message_id":"ABC123","chat_id":"6281234567890@s.whatsapp.net",
#                "sender":"6281234567890","direction":"INBOUND","type":"text",
#                "text":"Halo WhatsCore!","is_group":false,"timestamp":"..."}}
```

Wire format and guarantees:

- Headers: `Content-Type: text/event-stream`, `Cache-Control: no-cache`,
  `Connection: keep-alive`, `X-Accel-Buffering: no`.
- Every frame is `event: <name>\ndata: <json>\n\n` and flushed immediately.
- A `heartbeat` frame (`data: {"timestamp":"..."}`) arrives every 15s on an
  idle connection. Comment lines are not used, so proxies and clients that
  only understand `event:`/`data:` still see liveness.
- `event:` names follow the OpenAPI event catalog: `session.qr`,
  `session.connected`, `session.disconnected`, `message.received`,
  `message.sent`, `message.delivered`, `message.read`, `message.receipt`
  (played), `group.update`, and `error`. The `/qr` stream uses the short names
  from the contract's QR example instead: `qr`, `connected`, `disconnected`,
  `error`.
- `/events` only forwards events for the path's session and drops a slow
  client's frames for that connection instead of buffering without bound. Gaps
  in `seq` mean frames (or bus events) were dropped; re-read state with the
  REST endpoints rather than assuming a complete stream.
- Unknown sessions answer `404 not_found`. Both streams answer
  `501 not_implemented` when the process has no event bus wired.
- Cancelling the request (client disconnect, shutdown) ends the stream; no
  goroutines are left behind.

## Media (implemented)

`/api/v1/sessions/{id}/messages/image`, `/messages/document`, and the media
read endpoints are live over an in-memory, per-session store. The routes mount
when the host wires a media store (`Handler.SetMedia`); without one, these
paths keep answering `501`.

Uploads are `multipart/form-data`. The payload is encrypted with the
`core/media` envelope (AES-256-CBC plus a truncated HMAC over a fresh 32-byte
media key) **before** it is stored: the store holds only the encrypted blob and
the plaintext SHA-256, never the plaintext.

| Method | Path | Behavior |
|--------|------|----------|
| `POST` | `/api/v1/sessions/{id}/messages/image` | upload an image, `202` |
| `POST` | `/api/v1/sessions/{id}/messages/document` | upload a document, `202` |
| `GET` | `/api/v1/sessions/{id}/media` | list attachments, newest first, no keys |
| `GET` | `/api/v1/sessions/{id}/media/{mediaId}` | one attachment's metadata, `200`/`404`, no key |

Multipart fields:

| Field | Required | Notes |
|-------|----------|-------|
| `to` | yes | JID, same rule as `messages/text` (`user@server`) |
| `file` | yes | the payload; exactly one part is read |
| `caption` | no | validated (≤ 65536 bytes) but not persisted yet |
| `file_name` | no | defaults to the part's filename, then the kind; path components are stripped |
| `mime_type` | no | explicit type; otherwise the part header, then a content sniff |

```bash
curl -s -X POST \
  "http://localhost:8080/api/v1/sessions/$SESSION_ID/messages/image" \
  -H 'Authorization: Bearer wc_live_...' \
  -F 'to=6281234567890@s.whatsapp.net' \
  -F 'caption=Halo WhatsCore!' \
  -F 'file=@photo.png;type=image/png'
```

```json
{
  "message_id": "<uuid>",
  "media_id": "<uuid>",
  "status": "queued",
  "size": 48213,
  "sha256": "9f2c...",
  "media_key": "BASE64+32+BYTES="
}
```

```bash
curl -s -X POST \
  "http://localhost:8080/api/v1/sessions/$SESSION_ID/messages/document" \
  -H 'Authorization: Bearer wc_live_...' \
  -F 'to=6281234567890@s.whatsapp.net' \
  -F 'file_name=invoice.pdf' \
  -F 'file=@invoice.pdf;type=application/pdf'
```

```bash
curl -s "http://localhost:8080/api/v1/sessions/$SESSION_ID/media"
# {"data":[{"id":"<uuid>","session_id":"<uuid>","message_id":"<uuid>",
#           "kind":"document","file_name":"invoice.pdf",
#           "mime_type":"application/pdf","size":182734,
#           "sha256":"...","created_at":"..."}]}

curl -s "http://localhost:8080/api/v1/sessions/$SESSION_ID/media/<media_id>"
# the same object, without "media_key"
```

Limits and rules enforced on upload:

- **Request cap:** 64 MiB payload plus 4 MiB of multipart overhead (68 MiB
  total), enforced with `http.MaxBytesReader`. A body over the cap is
  `413 payload_too_large` before anything is stored.
- **File cap:** 64 MiB (`core/media.MaxMediaSize`).
- **Image types:** `image/png`, `image/jpeg`, `image/webp`. Anything else —
  including `image/gif` and `image/svg+xml` — is `415 unsupported_media_type`.
  Documents accept any MIME type.
- **Empty `file`:** `400 validation_failed`.
- **Invalid `to`:** `400 validation_failed` (same JID rule as text).
- **Unknown session:** `404 not_found`, checked before the body is parsed.
- **Not connected:** `503 session_not_connected`; reads still work while
  disconnected.
- **Store bounds:** 32 attachments per session and 128 MiB of encrypted blobs
  overall. Both evict **oldest first** (the session's oldest for the
  per-session bound, the globally oldest for the byte cap), so a later `GET`
  for an evicted id is `404`. Restarting the process clears everything. A
  single blob larger than the entire 128 MiB store cap is rejected with
  `413 payload_too_large` rather than flushing the store; with a smaller
  store, an otherwise-valid upload can therefore answer `413`.

The `media_key` is returned **only by the `202` create response**. It is a
write-once value: every list and `GET` response omits the field entirely, so a
reader can never leak it. Store it if you intend to decrypt the blob — losing
it makes that attachment permanently unreadable, because the server keeps only
the ciphertext.

Media messages are recorded in the media store, not the message log: they do
not appear in `GET /messages` yet, and no WhatsApp frame leaves the process.
`sha256` is the digest of the plaintext, so a client can verify a download. The
blob is not served back over HTTP yet: `MediaStore.Get` returns it, but no
download route exists, and the `EncSHA256` (ciphertext) descriptor hash is not
persisted — the envelope MAC authenticates the blob on decrypt.

Divergences from [`openapi.yaml`](openapi.yaml):

- The contract describes `SendImageRequest` / `SendDocumentRequest` as JSON
  bodies with `image_url` / `document_url`. These routes take the bytes
  directly as `multipart/form-data`, so a client never has to host the file
  first.
- The contract only lists `400`; these routes also answer `404`, `413`, `415`,
  and `503 session_not_connected` (the same choice as `messages/text`).
- `media_key`, `media_id`, and the `/media` read paths are additions: the
  contract has no media read surface yet.
- `Idempotency-Key` is **not** implemented here. A retry uploads and stores a
  second attachment; do not rely on replay protection for media.
- `caption` is accepted and validated but not stored.

## Not implemented yet (contract defined)

Paths under `/api/v1` that are not mounted answer `501 Not Implemented` with:

```json
{ "error": { "code": "not_implemented", "message": "this endpoint is defined by the v1 API contract (docs/api/openapi.yaml) and ships in an upcoming milestone" } }
```

This is intentional: clients can distinguish "endpoint not shipped yet"
from "wrong URL" (`404`). Send rate limiting and actual WhatsApp delivery are
still contract-only in [`openapi.yaml`](openapi.yaml).

## Webhook payload contract (Milestone 4)

Events arrive as `HTTP POST` with `X-Whatscore-Signature` =
`HMAC-SHA256(secret, body)` and a unique `id` for deduplication:

```json
{
  "id": "evt_01J...",
  "event": "message.received",
  "timestamp": "2026-11-15T00:00:00Z",
  "session_id": "e8b8c2c0-0f6b-4a88-a4b1-1f1a12345678",
  "data": {
    "message_id": "ABC123",
    "from": "6281234567890",
    "chat_id": "6281234567890@s.whatsapp.net",
    "type": "text",
    "text": "Halo WhatsCore!"
  }
}
```

Delivery rules: exponential backoff, max 10 attempts, 10s timeout, HTTP 2xx
counts as success — see [docs/architecture/overview.md](../architecture/overview.md).

## Examples

`examples/curl/system_endpoints.sh` runs all three implemented endpoints
against a running server.
