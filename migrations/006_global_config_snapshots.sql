CREATE TABLE IF NOT EXISTS global_runtime_config_blobs (
    content_hash VARCHAR(32) PRIMARY KEY,
    config_text TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS global_runtime_config_revisions (
    id BIGSERIAL PRIMARY KEY,
    profile_key VARCHAR(128) NOT NULL,
    content_hash VARCHAR(32) NULL REFERENCES global_runtime_config_blobs(content_hash),
    source VARCHAR(32) NOT NULL DEFAULT 'file',
    result VARCHAR(16) NOT NULL,
    error_text TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    activated_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_runtime_config_revisions_profile_created
ON global_runtime_config_revisions(profile_key, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_runtime_config_revisions_profile_result_created
ON global_runtime_config_revisions(profile_key, result, created_at DESC);

DROP TABLE IF EXISTS global_runtime_config_heads;
