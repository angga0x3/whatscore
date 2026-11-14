-- API keys authenticate REST clients. Only the SHA-256 hash of the key is
-- stored; the plaintext value is shown exactly once at creation time.
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    key_prefix VARCHAR(16) NOT NULL,
    key_hash BYTEA NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Scoped permissions attached to an API key.
CREATE TABLE api_key_scopes (
    api_key_id UUID NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    scope VARCHAR(50) NOT NULL,

    PRIMARY KEY (api_key_id, scope)
);
