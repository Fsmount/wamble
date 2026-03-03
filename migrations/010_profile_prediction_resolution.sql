ALTER TABLE sessions
  ADD COLUMN IF NOT EXISTS total_prediction_score DECIMAL(10, 4) NOT NULL DEFAULT 0.0;

ALTER TABLE predictions
  ADD COLUMN IF NOT EXISTS move_number INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS parent_prediction_id BIGINT REFERENCES predictions(id),
  ADD COLUMN IF NOT EXISTS correct_streak INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS points_awarded DECIMAL(10, 4) NOT NULL DEFAULT 0.0,
  ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ;

UPDATE sessions s
SET total_prediction_score = COALESCE(agg.total_prediction_score, 0.0)
FROM (
  SELECT p.session_id,
         SUM(p.points_awarded)::DECIMAL(10, 4) AS total_prediction_score
  FROM predictions p
  GROUP BY p.session_id
) agg
WHERE agg.session_id = s.id;

CREATE INDEX IF NOT EXISTS idx_predictions_board_status_move
ON predictions(board_id, status, move_number);

CREATE INDEX IF NOT EXISTS idx_predictions_session_status
ON predictions(session_id, status, created_at DESC);
