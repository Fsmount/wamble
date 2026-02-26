ALTER TABLE global_policy_rules
  ADD COLUMN IF NOT EXISTS scope VARCHAR(256) NOT NULL DEFAULT '*';

ALTER TABLE global_policy_rules
  ADD COLUMN IF NOT EXISTS source VARCHAR(32) NOT NULL DEFAULT 'manual';

ALTER TABLE global_policy_rules
  ADD COLUMN IF NOT EXISTS snapshot_revision_id BIGINT;

ALTER TABLE global_policy_rules
  ADD COLUMN IF NOT EXISTS not_before_at TIMESTAMPTZ;

ALTER TABLE global_policy_rules
  ADD COLUMN IF NOT EXISTS not_after_at TIMESTAMPTZ;

ALTER TABLE global_policy_rules
  ADD COLUMN IF NOT EXISTS context_key VARCHAR(128);

ALTER TABLE global_policy_rules
  ADD COLUMN IF NOT EXISTS context_value VARCHAR(256);

UPDATE global_policy_rules
SET scope = resource,
    resource = 'tier'
WHERE action = 'trust.tier'
  AND scope = '*'
  AND (resource = '*' OR resource LIKE 'profile:%' OR resource LIKE 'profile_group:%');

CREATE INDEX IF NOT EXISTS idx_policy_identity_action_scope
ON global_policy_rules(global_identity_id, action, scope, resource);

CREATE INDEX IF NOT EXISTS idx_policy_source_snapshot
ON global_policy_rules(source, snapshot_revision_id);
