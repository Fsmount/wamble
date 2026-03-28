CREATE TABLE IF NOT EXISTS global_identity_handles (
    global_identity_id BIGINT PRIMARY KEY,
    handle VARCHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_global_identity_handles_handle
ON global_identity_handles(handle);
