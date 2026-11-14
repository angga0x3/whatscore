-- Normalized message log for both inbound and outbound traffic. The payload
-- column holds the normalized WhatsCore representation, never the raw
-- engine-internal object.
CREATE TABLE messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES sessions(id),
    direction VARCHAR(10) NOT NULL,
    chat_jid VARCHAR(100) NOT NULL,
    provider_message_id VARCHAR(150),
    message_type VARCHAR(30) NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}',
    status VARCHAR(30) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (direction IN ('INBOUND', 'OUTBOUND'))
);

CREATE INDEX idx_messages_session_created
ON messages(session_id, created_at DESC);

CREATE UNIQUE INDEX idx_messages_provider_id
ON messages(session_id, provider_message_id)
WHERE provider_message_id IS NOT NULL;
