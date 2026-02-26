ALTER TABLE sessions
  ADD COLUMN IF NOT EXISTS global_identity_id BIGINT;

ALTER TABLE sessions
  ADD COLUMN IF NOT EXISTS config_revision_id BIGINT;

ALTER TABLE sessions
  ADD COLUMN IF NOT EXISTS policy_snapshot_revision_id BIGINT;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'sessions_global_identity_nonzero'
  ) THEN
    ALTER TABLE sessions
      ADD CONSTRAINT sessions_global_identity_nonzero
      CHECK (global_identity_id IS NULL OR global_identity_id > 0);
  END IF;
END $$;

ALTER TABLE sessions
  DROP COLUMN IF EXISTS trust_level;

CREATE INDEX IF NOT EXISTS idx_sessions_identity_id
ON sessions(global_identity_id);

CREATE INDEX IF NOT EXISTS idx_sessions_config_revision_id
ON sessions(config_revision_id);
