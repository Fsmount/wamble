CREATE TABLE IF NOT EXISTS session_treatment_assignments (
  session_id BIGINT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  profile_name VARCHAR(256) NOT NULL,
  treatment_group_key VARCHAR(128) NOT NULL,
  treatment_rule_id BIGINT,
  treatment_snapshot_revision_id BIGINT,
  treatment_assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY(session_id, profile_name)
);

CREATE INDEX IF NOT EXISTS idx_session_treatment_assignments_profile
  ON session_treatment_assignments(profile_name, treatment_group_key);
