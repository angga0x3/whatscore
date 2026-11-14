-- Sessions store the identity and lifecycle of every WhatsApp account
-- managed by WhatsCore. Credential material itself lives in the engine
-- credential store (protocol/auth), never here.
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    engine VARCHAR(50) NOT NULL DEFAULT 'builtin',
    status VARCHAR(30) NOT NULL DEFAULT 'STOPPED',
    phone_number VARCHAR(30),
    device_jid VARCHAR(100),
    last_connected_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT sessions_status_check
    CHECK (status IN (
        'STOPPED',
        'CONNECTING',
        'QR_PENDING',
        'CONNECTED',
        'DISCONNECTED',
        'LOGGED_OUT',
        'ERROR'
    ))
);

CREATE INDEX idx_sessions_status ON sessions(status);
