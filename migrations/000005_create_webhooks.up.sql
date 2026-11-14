-- Webhook endpoints may be bound to a single session (session_id set) or
-- receive events from all sessions (session_id NULL = global webhook).
CREATE TABLE webhook_endpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID REFERENCES sessions(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    secret_encrypted BYTEA,
    events TEXT[] NOT NULL DEFAULT '{}',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One delivery record per (endpoint, event) pair. The background worker
-- claims and updates these rows; 2xx responses mark DELIVERED, everything
-- else is retried with exponential backoff up to the configured maximum.
CREATE TABLE webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id UUID NOT NULL
        REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
    event_id UUID NOT NULL REFERENCES events(id),
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ,
    response_code INTEGER,
    last_error TEXT,
    delivered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(endpoint_id, event_id)
);
