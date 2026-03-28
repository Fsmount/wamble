ALTER TABLE boards
  DROP COLUMN IF EXISTS last_move_shown_uci;

CREATE TABLE IF NOT EXISTS board_last_move_shown_events (
    id BIGSERIAL PRIMARY KEY,
    board_id BIGINT NOT NULL REFERENCES boards(id) ON DELETE CASCADE,
    session_id BIGINT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    shown_uci VARCHAR(6) NOT NULL,
    emitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_board_last_move_shown_events_board
ON board_last_move_shown_events(board_id, emitted_at DESC);

CREATE INDEX IF NOT EXISTS idx_board_last_move_shown_events_session
ON board_last_move_shown_events(session_id, emitted_at DESC);
