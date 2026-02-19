ALTER TABLE sessions
  ADD COLUMN IF NOT EXISTS total_score DECIMAL(10, 4) NOT NULL DEFAULT 0.0,
  ADD COLUMN IF NOT EXISTS games_played INTEGER NOT NULL DEFAULT 0;

UPDATE sessions s
SET total_score = COALESCE(agg.total_score, 0.0)
FROM (
  SELECT p.session_id, SUM(p.points_awarded)::DECIMAL(10, 4) AS total_score
  FROM payouts p
  GROUP BY p.session_id
) agg
WHERE agg.session_id = s.id;

UPDATE sessions s
SET games_played = COALESCE(agg.games_played, 0)
FROM (
  SELECT m.session_id, COUNT(DISTINCT m.board_id)::INTEGER AS games_played
  FROM moves m
  GROUP BY m.session_id
) agg
WHERE agg.session_id = s.id;

CREATE OR REPLACE FUNCTION bump_session_total_score_on_payout()
RETURNS TRIGGER AS $$
BEGIN
  UPDATE sessions
  SET total_score = total_score + NEW.points_awarded
  WHERE id = NEW.session_id;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_payouts_bump_session_total_score ON payouts;
CREATE TRIGGER trg_payouts_bump_session_total_score
AFTER INSERT ON payouts
FOR EACH ROW
EXECUTE PROCEDURE bump_session_total_score_on_payout();

CREATE OR REPLACE FUNCTION bump_session_games_played_on_first_move()
RETURNS TRIGGER AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM moves m
    WHERE m.board_id = NEW.board_id
      AND m.session_id = NEW.session_id
      AND m.id <> NEW.id
  ) THEN
    UPDATE sessions
    SET games_played = games_played + 1
    WHERE id = NEW.session_id;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_moves_bump_session_games_played ON moves;
CREATE TRIGGER trg_moves_bump_session_games_played
AFTER INSERT ON moves
FOR EACH ROW
EXECUTE PROCEDURE bump_session_games_played_on_first_move();

CREATE INDEX IF NOT EXISTS idx_sessions_total_score_id
ON sessions(total_score DESC, id);
