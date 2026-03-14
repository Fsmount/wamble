DO $$ BEGIN
  CREATE TYPE board_game_mode AS ENUM ('chess960');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS board_mode_variants (
    board_id BIGINT PRIMARY KEY REFERENCES boards(id),
    game_mode board_game_mode NOT NULL,
    mode_variant_id INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_board_mode_variants_mode_variant_id
ON board_mode_variants(game_mode, mode_variant_id);
