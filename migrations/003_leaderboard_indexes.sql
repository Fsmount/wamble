CREATE INDEX IF NOT EXISTS idx_sessions_player_id
ON sessions(player_id)
WHERE player_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_players_rating_id
ON players(rating DESC, id);

CREATE INDEX IF NOT EXISTS idx_payouts_session_points
ON payouts(session_id, points_awarded);

CREATE INDEX IF NOT EXISTS idx_payouts_session_created_at
ON payouts(session_id, created_at DESC);
