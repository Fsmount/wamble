CREATE TABLE IF NOT EXISTS global_identity_tags (
    global_identity_id BIGINT NOT NULL,
    tag VARCHAR(128) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (global_identity_id, tag)
);

CREATE INDEX IF NOT EXISTS idx_global_identity_tags_tag
ON global_identity_tags(tag, global_identity_id);
