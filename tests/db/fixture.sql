-- Deterministic seed data for tests
-- Assumes schema already created and search_path set appropriately

-- Players (one player with stable rating)
INSERT INTO players (public_key, rating)
VALUES (decode('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex'), 1200.0000)
ON CONFLICT DO NOTHING;

-- Sessions (linked to player)
INSERT INTO sessions (token, player_id, trust_level)
VALUES (
  decode('00112233445566778899aabbccddeeff', 'hex'),
  (SELECT id FROM players LIMIT 1),
  10
)
ON CONFLICT DO NOTHING;

-- Boards (one dormant starting position)
INSERT INTO boards (fen, status)
VALUES ('rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1', 'DORMANT')
ON CONFLICT DO NOTHING;

