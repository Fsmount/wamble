ALTER TABLE sessions
  ADD COLUMN IF NOT EXISTS treatment_group_key VARCHAR(128),
  ADD COLUMN IF NOT EXISTS treatment_rule_id BIGINT,
  ADD COLUMN IF NOT EXISTS treatment_snapshot_revision_id BIGINT,
  ADD COLUMN IF NOT EXISTS treatment_assigned_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_sessions_treatment_group
ON sessions(treatment_group_key);

ALTER TABLE boards
  ADD COLUMN IF NOT EXISTS last_mover_treatment_group VARCHAR(128);
