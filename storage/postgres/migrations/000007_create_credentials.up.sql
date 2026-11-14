-- Encrypted engine credential blobs. Values are opaque envelope ciphertext
-- (storage/envelope); plaintext credentials never reach this table.
CREATE TABLE credentials (
    key TEXT PRIMARY KEY,
    blob BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
