-- Idempotency for message sending. A client that retries with the same
-- Idempotency-Key (per session) gets the stored response back instead of
-- triggering a duplicate send.
CREATE TABLE idempotency_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    idempotency_key VARCHAR(255) NOT NULL,
    session_id UUID NOT NULL REFERENCES sessions(id),
    request_hash BYTEA NOT NULL,
    response JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,

    UNIQUE(session_id, idempotency_key)
);
