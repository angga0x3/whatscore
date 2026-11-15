# Webhook delivery

Outbound webhooks are signed JSON `POST` requests sent by `server/webhook`
to the endpoint URLs registered under `/api/v1/webhooks`. This page covers
what a receiver sees on the wire; the endpoint CRUD contract lives in
[`openapi.yaml`](openapi.yaml).

## Envelope

Every delivery body is one event envelope (OpenAPI `Event` schema):

```json
{
  "id": "evt_01JQ8Z6K3W4T9V0B2C5D7E9F1G",
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

- `id` is unique per event. Retries of the same event reuse it, so key your
  deduplication on `id`.
- `timestamp` is RFC 3339 in UTC.
- `data` is always a JSON object; its fields depend on `event`. The catalog
  is `EventType` in the OpenAPI document.

## Headers

| Header | Value |
|--------|-------|
| `Content-Type` | `application/json` |
| `X-Whatscore-Signature` | hex `HMAC-SHA256(secret, raw request body)` |
| `X-Whatscore-Event` | the `event` field, e.g. `message.received` |
| `X-Whatscore-Delivery` | delivery id, stable across retries of one event |

Verify against the **raw bytes** you received, before parsing and before
acting on the payload:

```go
mac := hmac.New(sha256.New, []byte(secret))
mac.Write(rawBody)
expected := hex.EncodeToString(mac.Sum(nil))
if !hmac.Equal([]byte(expected), []byte(r.Header.Get("X-Whatscore-Signature"))) {
    http.Error(w, "bad signature", http.StatusUnauthorized)
    return
}
```

The signature carries no prefix or timestamp; there is no replay window
beyond `id` deduplication. Respond `2xx` only after you have durably
accepted the event — anything else is retried.

## Retries and backoff

- **Success is any `2xx` response.** `3xx`, `4xx`, and `5xx` are failures;
  a receiver that answers `404` or `410` still gets retried until attempts
  run out.
- **At most 10 attempts**, including the first.
- **Per-attempt timeout is 10 s.**
- **Backoff is deterministic exponential**: 1 s, 2 s, 4 s, … capped at
  60 s, applied between attempts. There is no jitter.
- Retries stop early only when the worker's context is cancelled (shutdown).
  A per-attempt timeout (10 s) is an ordinary failed attempt: the next
  attempt is scheduled with backoff.

Each attempt yields a delivery record with status code, error, and duration;
only the successful attempt sets `delivered_at`. The worker persists those
records and moves the delivery to `DELIVERED` (2xx) or `EXHAUSTED` after the
last failed attempt. History is available at
`GET /api/v1/webhooks/{webhookId}/deliveries`.

## Redirects and size limits

- **Redirects are never followed.** A `3xx` response is recorded and retried
  like any other failure. This keeps a registered target from bouncing the
  server to another host (technical specification §9).
- **Request bodies are capped at 256 KiB** (encoded envelope). Larger events
  are rejected before any request is sent.
- **Response bodies are capped at 64 KiB** and discarded; a large response
  cannot stall or exhaust the worker.
- Only `http` and `https` URLs with a non-empty host are accepted. Host
  range policy (loopback, link-local, cloud metadata) is enforced when the
  endpoint is registered, not by the delivery primitive.

## Example

Register an endpoint (the signing secret is returned once, at creation):

```bash
curl -s -X POST http://localhost:8080/api/v1/webhooks \
  -H "Authorization: Bearer $WHATSCORE_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com/hooks/whatscore","events":["message.received"]}'
```

Then replay the same signed request a worker sends against your receiver
(`localhost:9000` here):

```bash
SECRET='whsec_returned_once'
BODY='{"id":"evt_01JQ8Z6K3W4T9V0B2C5D7E9F1G","event":"message.received","timestamp":"2026-11-15T00:00:00Z","session_id":"e8b8c2c0-0f6b-4a88-a4b1-1f1a12345678","data":{"text":"Halo WhatsCore!"}}'
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$SECRET" -r | cut -d' ' -f1)

curl -s -X POST http://localhost:9000/hook \
  -H 'Content-Type: application/json' \
  -H "X-Whatscore-Signature: $SIG" \
  -H 'X-Whatscore-Event: message.received' \
  -H 'X-Whatscore-Delivery: 3f0b1c62-9a4d-4a2e-9f3b-1c2d3e4f5a6b' \
  --data-binary "$BODY"
```

A receiving stub only has to answer `2xx` and compare the signature; for
example with `socat`:

```bash
socat TCP-LISTEN:9000,fork,reuseaddr SYSTEM:'printf "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"; cat >/dev/null'
```
