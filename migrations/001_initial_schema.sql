CREATE TABLE players (
    id BIGSERIAL PRIMARY KEY,
    public_key BYTEA UNIQUE NOT NULL CHECK (LENGTH(public_key) = 32),
    rating DECIMAL(10, 4) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE sessions (
    id BIGSERIAL PRIMARY KEY,
    token BYTEA UNIQUE NOT NULL CHECK (LENGTH(token) = 16),
    player_id BIGINT NULL REFERENCES players(id),
    trust_level INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE boards (
    id BIGSERIAL PRIMARY KEY,
    fen VARCHAR(90) NOT NULL,
    status VARCHAR(16) NOT NULL CHECK (status IN ('ACTIVE', 'RESERVED', 'DORMANT', 'ARCHIVED')),
    last_assignment_time TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE moves (
    id BIGSERIAL PRIMARY KEY,
    board_id BIGINT NOT NULL REFERENCES boards(id),
    session_id BIGINT NOT NULL REFERENCES sessions(id),
    move_uci VARCHAR(6) NOT NULL,
    move_number INTEGER NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE reservations (
    board_id BIGINT PRIMARY KEY REFERENCES boards(id),
    session_id BIGINT NOT NULL REFERENCES sessions(id),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE game_results (
    board_id BIGINT PRIMARY KEY REFERENCES boards(id),
    winning_side CHAR(1) NOT NULL CHECK (winning_side IN ('w', 'b', 'd')),
    finished_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE payouts (
    id BIGSERIAL PRIMARY KEY,
    board_id BIGINT NOT NULL REFERENCES boards(id),
    session_id BIGINT NOT NULL REFERENCES sessions(id),
    points_awarded DECIMAL(10, 4) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE predictions (
    id BIGSERIAL PRIMARY KEY,
    board_id BIGINT NOT NULL REFERENCES boards(id),
    session_id BIGINT NOT NULL REFERENCES sessions(id),
    predicted_move_uci VARCHAR(6) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'CORRECT', 'INCORRECT', 'EXPIRED')),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_sessions_token ON sessions(token);
CREATE INDEX idx_boards_status ON boards(status);
CREATE INDEX idx_moves_board_id ON moves(board_id);
CREATE INDEX idx_moves_session_id ON moves(session_id);
CREATE INDEX idx_moves_board_session ON moves(board_id, session_id);
CREATE INDEX idx_reservations_expires_at ON reservations(expires_at);
CREATE INDEX idx_payouts_session_id ON payouts(session_id);

CREATE OR REPLACE FUNCTION update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
   NEW.updated_at = NOW();
   RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER trigger_boards_updated_at
BEFORE UPDATE ON boards
FOR EACH ROW
EXECUTE PROCEDURE update_timestamp();
