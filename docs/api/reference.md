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

## Not implemented yet (contract defined)

Every path under `/api/v1` currently answers `501 Not Implemented` with:

```json
{ "error": { "code": "not_implemented", "message": "this endpoint is defined by the v1 API contract (docs/api/openapi.yaml) and ships in an upcoming milestone" } }
```

This is intentional: clients can distinguish "endpoint not shipped yet"
from "wrong URL" (`404`). The sessions, messaging, and webhook endpoints —
including the QR SSE stream and the `Idempotency-Key` behavior — are fully
specified in [`openapi.yaml`](openapi.yaml) and land with
Milestones 2–4.

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
