ALTER TABLE boards
  ADD COLUMN IF NOT EXISTS last_move_time TIMESTAMPTZ,
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
