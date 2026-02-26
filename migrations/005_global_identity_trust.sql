CREATE TABLE IF NOT EXISTS global_identities (
    id BIGSERIAL PRIMARY KEY,
    public_key BYTEA UNIQUE CHECK (LENGTH(public_key) = 32),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS global_policy_rules (
    id BIGSERIAL PRIMARY KEY,
    global_identity_id BIGINT NOT NULL,
    action VARCHAR(128) NOT NULL,
    resource VARCHAR(256) NOT NULL,
    effect VARCHAR(8) NOT NULL CHECK (effect IN ('allow', 'deny')),
    permission_level INTEGER NOT NULL DEFAULT 0,
    policy_version VARCHAR(64) NOT NULL DEFAULT 'v1',
    reason TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_identity_trust_identity
ON global_policy_rules(global_identity_id);

CREATE INDEX IF NOT EXISTS idx_identity_trust_scope
ON global_policy_rules(action, resource);
