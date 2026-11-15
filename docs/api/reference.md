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

## Not implemented yet (contract defined)

Paths under `/api/v1` that are not mounted answer `501 Not Implemented` with:

```json
{ "error": { "code": "not_implemented", "message": "this endpoint is defined by the v1 API contract (docs/api/openapi.yaml) and ships in an upcoming milestone" } }
```

This is intentional: clients can distinguish "endpoint not shipped yet"
from "wrong URL" (`404`). Messaging and the QR SSE stream — including the
`Idempotency-Key` behavior — are fully specified in
[`openapi.yaml`](openapi.yaml) and land with later milestones.

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
