CREATE INDEX IF NOT EXISTS idx_sessions_player_id_all
ON sessions(player_id)
WHERE player_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_players_rating_id
ON players(rating DESC, id);

CREATE INDEX IF NOT EXISTS idx_payouts_session_points_all
ON payouts(session_id, points_awarded);

CREATE INDEX IF NOT EXISTS idx_payouts_session_created_at_all
ON payouts(session_id, created_at DESC);
