#ifdef TEST_MOVE_ENGINE

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "../include/wamble/wamble.h"
#include "../move_engine.c"

void update_player_ratings(WambleBoard *board) {}

void archive_board(uint64_t board_id) {}

typedef struct {
  const char *name;
  const char *start_fen;
  const char *uci;
  const char *expected_fen_prefix;
  int expect_ok;
  GameResult expected_result;
} Case;

static const Case cases[] = {
    {"legal pawn push",
     "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1", "e2e4",
     "rnbqkbnr/pppppppp/8/8/4P3/8/PPPP1PPP/RNBQKBNR b KQkq e3", 1,
     GAME_RESULT_IN_PROGRESS},
    {"illegal hop",
     "rnbqkbnr/pppppppp/8/8/4P3/8/PPPP1PPP/RNBQKBNR b KQkq e3 0 1", "e7e9", "",
     0, GAME_RESULT_IN_PROGRESS},
    {"white kingside castling",
     "r3k2r/pppppppp/8/8/8/8/PPPPPPPP/R3K2R w KQkq - 0 1", "e1g1",
     "r3k2r/pppppppp/8/8/8/8/PPPPPPPP/R4RK1 b kq -", 1,
     GAME_RESULT_IN_PROGRESS},
    {"move into check", "4k3/8/8/8/8/8/4q3/4K3 w - - 0 1", "d2d4", "", 0,
     GAME_RESULT_IN_PROGRESS},
    {"promotion to queen with checkmate", "8/P7/8/8/8/8/8/k1K5 w - - 0 1",
     "a7a8q", "Q7/8/8/8/8/8/8/k1K5 b - -", 1, GAME_RESULT_WHITE_WINS},
    {"en passant capture",
     "rnbqkbnr/pppppppp/8/8/3pP3/8/PPPP1PPP/RNBQKBNR b KQkq e3 0 3", "d4e3",
     "rnbqkbnr/pppppppp/8/8/8/4p3/PPPP1PPP/RNBQKBNR w KQkq -", 1,
     GAME_RESULT_IN_PROGRESS},
    {"rook capture revokes castling", "r3k2r/8/8/8/8/8/8/R3K2R w KQkq - 0 1",
     "a1a8", "R3k2r/8/8/8/8/8/8/4K2R b Kk - 0 1", 1, GAME_RESULT_IN_PROGRESS},
    {"invalid en passant (no pawn)",
     "rnbqkbnr/pppp1ppp/8/4P3/8/8/PPPP1PPP/RNBQKBNR w KQkq e6 0 1", "e5d6", "",
     0, GAME_RESULT_IN_PROGRESS},
    {"sliding piece blocked",
     "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1", "f1a6", "", 0,
     GAME_RESULT_IN_PROGRESS},
    {"discovery check", "4k3/8/8/3B4/8/8/8/4RK2 w - - 0 1", "d5c4",
     "4k3/8/8/8/2B5/8/8/4RK2 b - -", 1, GAME_RESULT_IN_PROGRESS},
    {"pinned piece can't move", "4r3/8/8/8/8/8/4N3/4K3 w - - 0 1", "e2d4", "",
     0, GAME_RESULT_IN_PROGRESS},
    {"edge squares invalid", "8/8/8/8/8/8/8/R3K2R wKQ - 0 1", "a1a0", "", 0,
     GAME_RESULT_IN_PROGRESS},
    {"queen cannot jump pieces", "4Q3/4p3/8/8/8/8/8/5K2 w - - 0 1", "e8e4", "",
     0, GAME_RESULT_IN_PROGRESS},
    {"fools mate",
     "rnbqkbnr/pppp1ppp/8/4p3/6P1/5P2/PPPPP2P/RNBQKBNR b KQkq - 0 1", "d8h4",
     "rnb1kbnr/pppp1ppp/8/4p3/6Pq/5P2/PPPPP2P/RNBQKBNR w KQkq - 1 2", 1,
     GAME_RESULT_BLACK_WINS},
    {"stalemate by queen", "k7/8/8/8/8/8/1Q6/K7 w - - 0 1", "b2b6",
     "k7/8/1Q6/8/8/8/8/K7 b - - 1 1", 1, GAME_RESULT_DRAW},
    {"50 move rule draw", "k7/8/8/8/8/8/8/K7 w - - 99 50", "a1b1",
     "k7/8/8/8/8/8/8/1K6 b - - 100 50", 1, GAME_RESULT_DRAW},
};

static int run_case(const Case *c) {
  WambleBoard wamble_board;
  memset(&wamble_board, 0, sizeof(WambleBoard));
  wamble_board.result = GAME_RESULT_IN_PROGRESS;
  wamble_board.id = 1;
  wamble_board.state = BOARD_STATE_RESERVED;

  WamblePlayer test_player;
  test_player.score = 1200;
  test_player.games_played = 0;
  test_player.has_persistent_identity = false;
  test_player.last_seen_time = 0;

  memset(test_player.token, 0, TOKEN_LENGTH);
  test_player.token[0] = 1;
  memcpy(wamble_board.reservation_player_token, test_player.token,
         TOKEN_LENGTH);
  wamble_board.reserved_for_white = true;

  parse_fen_to_bitboard(c->start_fen, &wamble_board.board);

  wamble_board.reserved_for_white = (wamble_board.board.turn == 'w');

  int rc = validate_and_apply_move(&wamble_board, &test_player, c->uci);

  if (rc != 0 && c->expect_ok) {
    printf("%s FAILED: engine returned %d (expected 0)\n", c->name, rc);
    return 0;
  }
  if (rc == 0 && !c->expect_ok) {
    printf("%s FAILED: expected rejection but engine accepted the move\n",
           c->name);
    return 0;
  }

  if (c->expect_ok) {
    char final_fen[FEN_MAX_LENGTH];
    bitboard_to_fen(&wamble_board.board, final_fen);
    if (c->expected_fen_prefix && *c->expected_fen_prefix &&
        strncmp(final_fen, c->expected_fen_prefix,
                strlen(c->expected_fen_prefix)) != 0) {
      printf("%s FAILED: FEN mismatch\n  expected: %s\n  actual:   %s\n",
             c->name, c->expected_fen_prefix, final_fen);
      return 0;
    }
    if (wamble_board.result != c->expected_result) {
      printf("%s FAILED: GameResult mismatch\n  expected: %d\n  actual:   %d\n",
             c->name, c->expected_result, wamble_board.result);
      return 0;
    }
  }
  return 1;
}

int main(int argc, char **argv) {
  const char *filter = (argc > 1 ? argv[1] : "");
  int pass = 0, total = 0;

  for (size_t i = 0; i < (sizeof(cases) / sizeof((cases)[0])); ++i) {
    if (*filter && !strstr(cases[i].name, filter))
      continue;

    ++total;
    if (run_case(&cases[i])) {
      printf("%s PASSED\n", cases[i].name);
      ++pass;
    }
  }
  printf("%d/%d passed\n", pass, total);
  return (pass == total) ? 0 : 1;
}

#endif