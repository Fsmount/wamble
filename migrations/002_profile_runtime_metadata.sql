ALTER TABLE sessions
  ADD COLUMN IF NOT EXISTS experiment_arm INTEGER;

UPDATE sessions
SET experiment_arm = 0
WHERE experiment_arm IS NULL;

ALTER TABLE sessions
  ALTER COLUMN experiment_arm SET DEFAULT 0;

ALTER TABLE sessions
  ALTER COLUMN experiment_arm SET NOT NULL;

ALTER TABLE boards
  ADD COLUMN IF NOT EXISTS last_move_time TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS last_mover_arm INTEGER,
  ADD COLUMN IF NOT EXISTS reservation_started_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS reserved_for_white BOOLEAN;

ALTER TABLE reservations
  ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ DEFAULT NOW(),
  ADD COLUMN IF NOT EXISTS reserved_for_white BOOLEAN DEFAULT TRUE;

UPDATE reservations
SET reserved_for_white = TRUE
WHERE reserved_for_white IS NULL;

ALTER TABLE reservations
  ALTER COLUMN reserved_for_white SET NOT NULL;

ALTER TABLE game_results
  ADD COLUMN IF NOT EXISTS move_count INTEGER,
  ADD COLUMN IF NOT EXISTS duration_seconds INTEGER,
  ADD COLUMN IF NOT EXISTS termination_reason VARCHAR(32);

CREATE INDEX IF NOT EXISTS idx_sessions_experiment_arm ON sessions(experiment_arm);
CREATE INDEX IF NOT EXISTS idx_boards_last_mover_arm ON boards(last_mover_arm);
