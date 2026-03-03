CREATE TABLE IF NOT EXISTS global_treatment_groups (
  id BIGSERIAL PRIMARY KEY,
  group_key VARCHAR(128) NOT NULL,
  priority INTEGER NOT NULL,
  is_default BOOLEAN NOT NULL DEFAULT FALSE,
  source VARCHAR(32) NOT NULL DEFAULT 'config',
  snapshot_revision_id BIGINT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_treatment_group_key_source
ON global_treatment_groups(group_key, source, COALESCE(snapshot_revision_id, 0));

CREATE TABLE IF NOT EXISTS global_treatment_assignment_rules (
  id BIGSERIAL PRIMARY KEY,
  global_identity_id BIGINT NOT NULL,
  profile_scope VARCHAR(256) NOT NULL DEFAULT '*',
  group_key VARCHAR(128) NOT NULL,
  priority INTEGER NOT NULL,
  source VARCHAR(32) NOT NULL DEFAULT 'config',
  snapshot_revision_id BIGINT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_treatment_assignment_lookup
ON global_treatment_assignment_rules(global_identity_id, profile_scope, priority, group_key);

CREATE TABLE IF NOT EXISTS global_treatment_assignment_predicates (
  rule_id BIGINT NOT NULL REFERENCES global_treatment_assignment_rules(id) ON DELETE CASCADE,
  fact_key VARCHAR(128) NOT NULL,
  op VARCHAR(16) NOT NULL,
  value_type INTEGER NOT NULL,
  value_text VARCHAR(256),
  value_num DOUBLE PRECISION,
  value_bool BOOLEAN,
  value_fact_ref VARCHAR(128)
);

CREATE TABLE IF NOT EXISTS global_treatment_group_edges (
  source_group_key VARCHAR(128) NOT NULL,
  target_group_key VARCHAR(128) NOT NULL,
  source VARCHAR(32) NOT NULL DEFAULT 'config',
  snapshot_revision_id BIGINT,
  PRIMARY KEY (source_group_key, target_group_key, source, snapshot_revision_id)
);

CREATE TABLE IF NOT EXISTS global_treatment_group_outputs (
  id BIGSERIAL PRIMARY KEY,
  group_key VARCHAR(128) NOT NULL,
  hook_name VARCHAR(64) NOT NULL DEFAULT '*',
  output_kind VARCHAR(32) NOT NULL,
  output_key VARCHAR(128) NOT NULL,
  value_type INTEGER NOT NULL,
  value_text VARCHAR(256),
  value_num DOUBLE PRECISION,
  value_bool BOOLEAN,
  value_fact_ref VARCHAR(128),
  source VARCHAR(32) NOT NULL DEFAULT 'config',
  snapshot_revision_id BIGINT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_treatment_outputs_unique
ON global_treatment_group_outputs(group_key, hook_name, output_kind, output_key, source, COALESCE(snapshot_revision_id, 0));
