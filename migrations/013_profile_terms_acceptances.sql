CREATE TABLE IF NOT EXISTS profile_terms_acceptances (
  id BIGSERIAL PRIMARY KEY,
  session_id BIGINT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  global_identity_id BIGINT,
  profile_name VARCHAR(256) NOT NULL,
  tos_hash BYTEA NOT NULL CHECK (OCTET_LENGTH(tos_hash) = 32),
  tos_text TEXT NOT NULL,
  config_revision_id BIGINT,
  policy_snapshot_revision_id BIGINT,
  accepted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_profile_terms_acceptances_unique
ON profile_terms_acceptances(session_id, profile_name, tos_hash);

CREATE INDEX IF NOT EXISTS idx_profile_terms_acceptances_session
ON profile_terms_acceptances(session_id, accepted_at DESC);

CREATE INDEX IF NOT EXISTS idx_profile_terms_acceptances_identity
ON profile_terms_acceptances(global_identity_id, accepted_at DESC);
