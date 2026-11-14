-- Append-only event log. Events are persisted together with their webhook
-- delivery records in a single transaction (transactional outbox, see
-- docs/architecture.md).
CREATE TABLE events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES sessions(id),
    event_type VARCHAR(100) NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_events_session_created
ON events(session_id, created_at DESC);
