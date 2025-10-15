#include "common/wamble_test.h"
#include "wamble/wamble.h"

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
    {"underpromotion to rook", "7k/P7/8/8/8/8/8/K7 w - - 0 1", "a7a8r", "R6k/",
     1, GAME_RESULT_IN_PROGRESS},
    {"underpromotion to bishop", "7k/P7/8/8/8/8/8/K7 w - - 0 1", "a7a8b",
     "B6k/", 1, GAME_RESULT_IN_PROGRESS},
    {"underpromotion to knight", "7k/P7/8/8/8/8/8/K7 w - - 0 1", "a7a8n",
     "N6k/", 1, GAME_RESULT_IN_PROGRESS},
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

static int move_engine_apply_not_reserved(void);
static int move_engine_apply_not_turn(void);
static int move_engine_apply_bad_uci(void);
static int move_engine_apply_illegal(void);
static int move_engine_fen_after_pawn_move(void);
static int move_engine_legal_moves_invalid_square(void);
static int move_engine_speed_movegen_startpos(void);
static int move_engine_perf_apply_sequences(void);
static int move_engine_stress_concurrent_movegen(void);
static int move_engine_promotion_missing_letter_illegal(void);
static int move_engine_promotion_invalid_letter_illegal(void);
static int move_engine_generator_promotions_listed(void);
static int move_engine_castling_through_attacked_square_illegal(void);
static int move_engine_castling_while_in_check_illegal(void);
static int move_engine_status_move_ok_on_success(void);
static int move_engine_clocks_increment_and_reset(void);

WAMBLE_PARAM_TEST(Case, apply_move_case) {
  const Case *c = tc;

  WambleBoard wb;
  memset(&wb, 0, sizeof(wb));
  wb.result = GAME_RESULT_IN_PROGRESS;
  wb.id = 1;
  wb.state = BOARD_STATE_RESERVED;

  WamblePlayer player;
  memset(&player, 0, sizeof(player));
  player.score = 1200;
  player.games_played = 0;
  player.has_persistent_identity = false;
  player.last_seen_time = 0;
  player.token[0] = 1;

  memcpy(wb.reservation_player_token, player.token, TOKEN_LENGTH);
  wb.reserved_for_white = true;

  T_ASSERT_STATUS_OK(parse_fen_to_bitboard(c->start_fen, &wb.board));

  wb.reserved_for_white = (wb.board.turn == 'w');

  int rc = validate_and_apply_move_status(&wb, &player, c->uci, NULL);
  if (c->expect_ok) {
    T_ASSERT_STATUS_OK(rc);
    if (c->expected_fen_prefix && *c->expected_fen_prefix) {
      size_t n = strlen(c->expected_fen_prefix);
      T_ASSERT(strncmp(wb.fen, c->expected_fen_prefix, n) == 0);
    }
    T_ASSERT_EQ_INT(wb.result, c->expected_result);
  } else {
    T_ASSERT(rc != 0);
  }
  return 0;
}

WAMBLE_TEST(move_engine_legal_moves_basic) {
  Board board;
  const char *fen = "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1";
  T_ASSERT_STATUS_OK(parse_fen_to_bitboard(fen, &board));

  Move moves[WAMBLE_MAX_LEGAL_MOVES];
  int square = square_to_index(4, 1);
  int count = get_legal_moves_for_square(&board, square, moves, 16);
  T_ASSERT_EQ_INT(count, 2);

  int found_single = 0;
  int found_double = 0;
  for (int i = 0; i < count; i++) {
    T_ASSERT(moves[i].promotion == 0);
    if (moves[i].to == square + 8)
      found_single = 1;
    else if (moves[i].to == square + 16)
      found_double = 1;
  }
  T_ASSERT(found_single && found_double);
  return 0;
}

WAMBLE_TEST(move_engine_legal_moves_enemy_turn) {
  Board board;
  const char *fen = "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1";
  T_ASSERT_STATUS_OK(parse_fen_to_bitboard(fen, &board));

  Move moves[WAMBLE_MAX_LEGAL_MOVES];
  int square = square_to_index(4, 6);
  int count = get_legal_moves_for_square(&board, square, moves, 16);
  T_ASSERT_EQ_INT(count, 0);
  return 0;
}

WAMBLE_TESTS_BEGIN_NAMED(wamble_register_tests_move_engine)
WAMBLE_PARAM_REGISTER_SM(Case, apply_move_case, "move_engine_apply_move",
                         WAMBLE_SUITE_FUNCTIONAL, "move_engine", cases, 0);
WAMBLE_TESTS_ADD_SM(move_engine_legal_moves_basic, WAMBLE_SUITE_FUNCTIONAL,
                    "move_engine");
WAMBLE_TESTS_ADD_SM(move_engine_legal_moves_enemy_turn, WAMBLE_SUITE_FUNCTIONAL,
                    "move_engine");
WAMBLE_TESTS_ADD_SM(move_engine_apply_not_reserved, WAMBLE_SUITE_FUNCTIONAL,
                    "move_engine");
WAMBLE_TESTS_ADD_SM(move_engine_apply_not_turn, WAMBLE_SUITE_FUNCTIONAL,
                    "move_engine");
WAMBLE_TESTS_ADD_SM(move_engine_apply_bad_uci, WAMBLE_SUITE_FUNCTIONAL,
                    "move_engine");
WAMBLE_TESTS_ADD_SM(move_engine_apply_illegal, WAMBLE_SUITE_FUNCTIONAL,
                    "move_engine");
WAMBLE_TESTS_ADD_SM(move_engine_fen_after_pawn_move, WAMBLE_SUITE_FUNCTIONAL,
                    "move_engine");
WAMBLE_TESTS_ADD_SM(move_engine_legal_moves_invalid_square,
                    WAMBLE_SUITE_FUNCTIONAL, "move_engine");
WAMBLE_TESTS_ADD_SM(move_engine_promotion_missing_letter_illegal,
                    WAMBLE_SUITE_FUNCTIONAL, "move_engine");
WAMBLE_TESTS_ADD_SM(move_engine_promotion_invalid_letter_illegal,
                    WAMBLE_SUITE_FUNCTIONAL, "move_engine");
WAMBLE_TESTS_ADD_SM(move_engine_generator_promotions_listed,
                    WAMBLE_SUITE_FUNCTIONAL, "move_engine");
WAMBLE_TESTS_ADD_SM(move_engine_castling_through_attacked_square_illegal,
                    WAMBLE_SUITE_FUNCTIONAL, "move_engine");
WAMBLE_TESTS_ADD_SM(move_engine_castling_while_in_check_illegal,
                    WAMBLE_SUITE_FUNCTIONAL, "move_engine");
WAMBLE_TESTS_ADD_SM(move_engine_status_move_ok_on_success,
                    WAMBLE_SUITE_FUNCTIONAL, "move_engine");
WAMBLE_TESTS_ADD_SM(move_engine_clocks_increment_and_reset,
                    WAMBLE_SUITE_FUNCTIONAL, "move_engine");
WAMBLE_TESTS_ADD_EX_SM(move_engine_speed_movegen_startpos, WAMBLE_SUITE_SPEED,
                       "move_engine", NULL, NULL, 5000);
WAMBLE_TESTS_ADD_EX_SM(move_engine_perf_apply_sequences,
                       WAMBLE_SUITE_PERFORMANCE, "move_engine", NULL, NULL,
                       10000);
WAMBLE_TESTS_ADD_EX_SM(move_engine_stress_concurrent_movegen,
                       WAMBLE_SUITE_STRESS, "move_engine", NULL, NULL, 30000);
WAMBLE_TESTS_END()

WAMBLE_TEST(move_engine_apply_not_reserved) {
  WambleBoard wb;
  memset(&wb, 0, sizeof(wb));
  wb.id = 1;
  wb.state = BOARD_STATE_RESERVED;
  T_ASSERT_STATUS_OK(parse_fen_to_bitboard(
      "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1", &wb.board));
  wb.reserved_for_white = (wb.board.turn == 'w');
  memset(wb.reservation_player_token, 0, TOKEN_LENGTH);

  WamblePlayer player;
  memset(&player, 0, sizeof(player));
  player.token[0] = 1;

  MoveApplyStatus st = MOVE_OK;
  int rc = validate_and_apply_move_status(&wb, &player, "e2e4", &st);
  T_ASSERT(rc != 0);
  T_ASSERT_STATUS(st, MOVE_ERR_NOT_RESERVED);
  return 0;
}

WAMBLE_TEST(move_engine_promotion_missing_letter_illegal) {
  WambleBoard wb;
  memset(&wb, 0, sizeof(wb));
  wb.id = 1;
  wb.state = BOARD_STATE_RESERVED;
  T_ASSERT_STATUS_OK(
      parse_fen_to_bitboard("7k/P7/8/8/8/8/8/K7 w - - 0 1", &wb.board));
  wb.reserved_for_white = true;
  WamblePlayer player;
  memset(&player, 0, sizeof(player));
  memcpy(wb.reservation_player_token, player.token, TOKEN_LENGTH);

  MoveApplyStatus st = MOVE_OK;
  int rc = validate_and_apply_move_status(&wb, &player, "a7a8", &st);
  T_ASSERT(rc != 0);
  T_ASSERT_STATUS(st, MOVE_ERR_ILLEGAL);
  return 0;
}

WAMBLE_TEST(move_engine_promotion_invalid_letter_illegal) {
  WambleBoard wb;
  memset(&wb, 0, sizeof(wb));
  wb.id = 1;
  wb.state = BOARD_STATE_RESERVED;
  T_ASSERT_STATUS_OK(
      parse_fen_to_bitboard("7k/P7/8/8/8/8/8/K7 w - - 0 1", &wb.board));
  wb.reserved_for_white = true;
  WamblePlayer player;
  memset(&player, 0, sizeof(player));
  memcpy(wb.reservation_player_token, player.token, TOKEN_LENGTH);

  MoveApplyStatus st = MOVE_OK;
  int rc = validate_and_apply_move_status(&wb, &player, "a7a8x", &st);
  T_ASSERT(rc != 0);
  T_ASSERT_STATUS(st, MOVE_ERR_ILLEGAL);
  return 0;
}

WAMBLE_TEST(move_engine_generator_promotions_listed) {
  Board board;
  T_ASSERT_STATUS_OK(
      parse_fen_to_bitboard("7k/P7/8/8/8/8/8/K7 w - - 0 1", &board));
  Move mv[8];
  int a7 = square_to_index(0, 6);
  int n = get_legal_moves_for_square(&board, a7, mv, 8);
  T_ASSERT_EQ_INT(n, 4);
  int has_q = 0, has_r = 0, has_b = 0, has_n = 0;
  for (int i = 0; i < n; i++) {
    if (mv[i].to == square_to_index(0, 7)) {
      if (mv[i].promotion == 'q')
        has_q = 1;
      else if (mv[i].promotion == 'r')
        has_r = 1;
      else if (mv[i].promotion == 'b')
        has_b = 1;
      else if (mv[i].promotion == 'n')
        has_n = 1;
    }
  }
  T_ASSERT(has_q && has_r && has_b && has_n);
  return 0;
}

WAMBLE_TEST(move_engine_castling_through_attacked_square_illegal) {
  WambleBoard wb;
  memset(&wb, 0, sizeof(wb));
  wb.id = 1;
  wb.state = BOARD_STATE_RESERVED;
  T_ASSERT_STATUS_OK(
      parse_fen_to_bitboard("6r1/8/8/8/8/8/8/4K2R w K - 0 1", &wb.board));
  wb.reserved_for_white = true;
  WamblePlayer player;
  memset(&player, 0, sizeof(player));
  memcpy(wb.reservation_player_token, player.token, TOKEN_LENGTH);
  MoveApplyStatus st = MOVE_OK;
  int rc = validate_and_apply_move_status(&wb, &player, "e1g1", &st);
  T_ASSERT(rc != 0);
  T_ASSERT_STATUS(st, MOVE_ERR_ILLEGAL);
  return 0;
}

WAMBLE_TEST(move_engine_castling_while_in_check_illegal) {
  WambleBoard wb;
  memset(&wb, 0, sizeof(wb));
  wb.id = 1;
  wb.state = BOARD_STATE_RESERVED;
  T_ASSERT_STATUS_OK(
      parse_fen_to_bitboard("4r3/8/8/8/8/8/8/4K2R w K - 0 1", &wb.board));
  wb.reserved_for_white = true;
  WamblePlayer player;
  memset(&player, 0, sizeof(player));
  memcpy(wb.reservation_player_token, player.token, TOKEN_LENGTH);
  MoveApplyStatus st = MOVE_OK;
  int rc = validate_and_apply_move_status(&wb, &player, "e1g1", &st);
  T_ASSERT(rc != 0);
  T_ASSERT_STATUS(st, MOVE_ERR_ILLEGAL);
  return 0;
}

WAMBLE_TEST(move_engine_status_move_ok_on_success) {
  WambleBoard wb;
  memset(&wb, 0, sizeof(wb));
  wb.id = 1;
  wb.state = BOARD_STATE_RESERVED;
  T_ASSERT_STATUS_OK(parse_fen_to_bitboard(
      "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1", &wb.board));
  wb.reserved_for_white = true;
  WamblePlayer player;
  memset(&player, 0, sizeof(player));
  memcpy(wb.reservation_player_token, player.token, TOKEN_LENGTH);
  MoveApplyStatus st = MOVE_ERR_INVALID_ARGS;
  int rc = validate_and_apply_move_status(&wb, &player, "g1f3", &st);
  T_ASSERT_STATUS_OK(rc);
  T_ASSERT_STATUS(st, MOVE_OK);
  return 0;
}

WAMBLE_TEST(move_engine_clocks_increment_and_reset) {
  WambleBoard wb;
  memset(&wb, 0, sizeof(wb));
  wb.id = 1;
  wb.state = BOARD_STATE_RESERVED;
  T_ASSERT_STATUS_OK(parse_fen_to_bitboard(
      "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1", &wb.board));
  wb.reserved_for_white = true;
  WamblePlayer player;
  memset(&player, 0, sizeof(player));
  memcpy(wb.reservation_player_token, player.token, TOKEN_LENGTH);

  MoveApplyStatus st = MOVE_OK;
  T_ASSERT_STATUS_OK(validate_and_apply_move_status(&wb, &player, "g1f3", &st));
  T_ASSERT_EQ_INT(wb.board.halfmove_clock, 1);
  T_ASSERT_EQ_INT(wb.board.fullmove_number, 1);
  T_ASSERT(wb.board.turn == 'b');

  wb.reserved_for_white = false;
  T_ASSERT_STATUS_OK(validate_and_apply_move_status(&wb, &player, "b8c6", &st));
  T_ASSERT_EQ_INT(wb.board.halfmove_clock, 2);
  T_ASSERT_EQ_INT(wb.board.fullmove_number, 2);
  T_ASSERT(wb.board.turn == 'w');

  wb.reserved_for_white = true;
  T_ASSERT_STATUS_OK(validate_and_apply_move_status(&wb, &player, "e2e4", &st));
  T_ASSERT_EQ_INT(wb.board.halfmove_clock, 0);
  T_ASSERT_EQ_INT(wb.board.fullmove_number, 2);
  T_ASSERT(wb.board.turn == 'b');
  return 0;
}

WAMBLE_TEST(move_engine_apply_not_turn) {
  WambleBoard wb;
  memset(&wb, 0, sizeof(wb));
  wb.id = 1;
  wb.state = BOARD_STATE_RESERVED;
  T_ASSERT_STATUS_OK(parse_fen_to_bitboard(
      "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1", &wb.board));

  wb.reserved_for_white = false;
  WamblePlayer player;
  memset(&player, 0, sizeof(player));
  player.token[0] = 1;
  memcpy(wb.reservation_player_token, player.token, TOKEN_LENGTH);

  MoveApplyStatus st = MOVE_OK;
  int rc = validate_and_apply_move_status(&wb, &player, "e2e4", &st);
  T_ASSERT(rc != 0);
  T_ASSERT_STATUS(st, MOVE_ERR_NOT_TURN);
  return 0;
}

WAMBLE_TEST(move_engine_apply_bad_uci) {
  WambleBoard wb;
  memset(&wb, 0, sizeof(wb));
  wb.id = 1;
  wb.state = BOARD_STATE_RESERVED;
  T_ASSERT_STATUS_OK(parse_fen_to_bitboard(
      "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1", &wb.board));
  wb.reserved_for_white = true;
  WamblePlayer player;
  memset(&player, 0, sizeof(player));
  player.token[0] = 1;
  memcpy(wb.reservation_player_token, player.token, TOKEN_LENGTH);

  MoveApplyStatus st = MOVE_OK;
  int rc = validate_and_apply_move_status(&wb, &player, "e2e", &st);
  T_ASSERT(rc != 0);
  T_ASSERT_STATUS(st, MOVE_ERR_BAD_UCI);

  st = MOVE_OK;
  rc = validate_and_apply_move_status(&wb, &player, "e2e9", &st);
  T_ASSERT(rc != 0);
  T_ASSERT_STATUS(st, MOVE_ERR_BAD_UCI);
  return 0;
}

WAMBLE_TEST(move_engine_apply_illegal) {
  WambleBoard wb;
  memset(&wb, 0, sizeof(wb));
  wb.id = 1;
  wb.state = BOARD_STATE_RESERVED;
  T_ASSERT_STATUS_OK(parse_fen_to_bitboard(
      "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1", &wb.board));
  wb.reserved_for_white = true;
  WamblePlayer player;
  memset(&player, 0, sizeof(player));
  player.token[0] = 1;
  memcpy(wb.reservation_player_token, player.token, TOKEN_LENGTH);

  MoveApplyStatus st = MOVE_OK;
  int rc = validate_and_apply_move_status(&wb, &player, "e2e5", &st);
  T_ASSERT(rc != 0);
  T_ASSERT_STATUS(st, MOVE_ERR_ILLEGAL);
  return 0;
}

WAMBLE_TEST(move_engine_fen_after_pawn_move) {
  WambleBoard wb;
  memset(&wb, 0, sizeof(wb));
  wb.id = 1;
  wb.state = BOARD_STATE_RESERVED;
  T_ASSERT_STATUS_OK(parse_fen_to_bitboard(
      "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1", &wb.board));
  wb.reserved_for_white = true;
  WamblePlayer player;
  memset(&player, 0, sizeof(player));
  player.token[0] = 1;
  memcpy(wb.reservation_player_token, player.token, TOKEN_LENGTH);
  MoveApplyStatus st = MOVE_OK;
  T_ASSERT_STATUS_OK(validate_and_apply_move_status(&wb, &player, "e2e4", &st));
  T_ASSERT_STREQ(wb.fen,
                 "rnbqkbnr/pppppppp/8/8/4P3/8/PPPP1PPP/RNBQKBNR b KQkq e3 0 1");
  return 0;
}

WAMBLE_TEST(move_engine_legal_moves_invalid_square) {
  Board board;
  T_ASSERT_STATUS_OK(parse_fen_to_bitboard(
      "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1", &board));
  Move moves[8];
  T_ASSERT(get_legal_moves_for_square(&board, -1, moves, 8) == -1);
  T_ASSERT(get_legal_moves_for_square(&board, 64, moves, 8) == -1);
  return 0;
}

WAMBLE_TEST(move_engine_speed_movegen_startpos) {
  Board board;
  T_ASSERT_STATUS_OK(parse_fen_to_bitboard(
      "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1", &board));
  const int iters = 1000;
  uint64_t total_moves = 0;
  uint64_t start_ns = wamble_now_nanos();
  Move buf[WAMBLE_MAX_LEGAL_MOVES];
  for (int i = 0; i < iters; i++) {
    for (int s = 0; s < 64; s++) {
      int n =
          get_legal_moves_for_square(&board, s, buf, WAMBLE_MAX_LEGAL_MOVES);
      if (n > 0)
        total_moves += (uint64_t)n;
    }
  }
  uint64_t end_ns = wamble_now_nanos();
  uint64_t elapsed_ns = end_ns - start_ns;
  double iters_per_sec =
      (elapsed_ns > 0) ? ((double)iters * 1e9 / (double)elapsed_ns) : 0.0;
  wamble_metric("speed_movegen_startpos",
                "iters=%d elapsed_ns=%llu total_moves=%llu iters_per_sec=%.2f",
                iters, (unsigned long long)elapsed_ns,
                (unsigned long long)total_moves, iters_per_sec);
  T_ASSERT(elapsed_ns < (uint64_t)2e9);
  return 0;
}

typedef struct {
  const char *name;
  const char *moves[32];
  int count;
} Line;

static const Line perf_lines[] = {
    {"short_opening",
     {"e2e4", "e7e5", "g1f3", "b8c6", "f1b5", "a7a6", "b5a4", "g8f6", NULL},
     8},
    {"short_french",
     {"e2e4", "e7e6", "d2d4", "d7d5", "b1c3", "g8f6", "c1g5", NULL},
     7},
};

WAMBLE_TEST(move_engine_perf_apply_sequences) {
  const int outer = 100;
  uint64_t start_ns = wamble_now_nanos();
  uint64_t applied = 0;
  for (int it = 0; it < outer; it++) {
    for (int l = 0; l < (int)(sizeof(perf_lines) / sizeof(perf_lines[0]));
         l++) {
      WambleBoard wb;
      memset(&wb, 0, sizeof(wb));
      wb.id = 1;
      wb.state = BOARD_STATE_RESERVED;
      T_ASSERT_STATUS_OK(parse_fen_to_bitboard(
          "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1",
          &wb.board));
      wb.reserved_for_white = (wb.board.turn == 'w');
      WamblePlayer pl;
      memset(&pl, 0, sizeof(pl));
      pl.token[0] = 1;
      memcpy(wb.reservation_player_token, pl.token, TOKEN_LENGTH);
      for (int m = 0; m < perf_lines[l].count; m++) {
        MoveApplyStatus st = MOVE_OK;
        int rc = validate_and_apply_move_status(&wb, &pl,
                                                perf_lines[l].moves[m], &st);
        T_ASSERT_STATUS_OK(rc);
        applied++;
        wb.reserved_for_white = (wb.board.turn == 'w');
      }
    }
  }
  uint64_t end_ns = wamble_now_nanos();
  uint64_t elapsed_ns = end_ns - start_ns;
  double moves_per_sec =
      (elapsed_ns > 0) ? ((double)applied * 1e9 / (double)elapsed_ns) : 0.0;
  wamble_metric("perf_apply_uci_sequences",
                "reps=%d applied=%llu elapsed_ns=%llu mps=%.2f", outer,
                (unsigned long long)applied, (unsigned long long)elapsed_ns,
                moves_per_sec);
  T_ASSERT(elapsed_ns < (uint64_t)4e9);
  return 0;
}

typedef struct {
  int iters;
  int done;
} ThreadCtx;

static void *stress_movegen_worker(void *arg) {
  ThreadCtx *ctx = (ThreadCtx *)arg;
  Board board;
  parse_fen_to_bitboard(
      "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1", &board);
  Move buf[WAMBLE_MAX_LEGAL_MOVES];
  for (int i = 0; i < ctx->iters; i++) {
    for (int s = 0; s < 64; s++) {
      (void)get_legal_moves_for_square(&board, s, buf, WAMBLE_MAX_LEGAL_MOVES);
    }
  }
  ctx->done = 1;
  return NULL;
}

WAMBLE_TEST(move_engine_stress_concurrent_movegen) {
  const int threads = 4;
  const int iters_per_thread = 300;
  wamble_thread_t th[threads];
  ThreadCtx ctx[threads];
  memset(ctx, 0, sizeof(ctx));
  uint64_t start_ns = wamble_now_nanos();
  for (int i = 0; i < threads; i++) {
    ctx[i].iters = iters_per_thread;
    T_ASSERT(wamble_thread_create(&th[i], stress_movegen_worker, &ctx[i]) == 0);
  }
  for (int i = 0; i < threads; i++)
    T_ASSERT_STATUS_OK(wamble_thread_join(th[i], NULL));
  uint64_t end_ns = wamble_now_nanos();
  uint64_t elapsed_ns = end_ns - start_ns;
  int total_iters = threads * iters_per_thread;
  double iters_per_sec =
      (elapsed_ns > 0) ? ((double)total_iters * 1e9 / (double)elapsed_ns) : 0.0;
  int all_done = 1;
  for (int i = 0; i < threads; i++)
    all_done = all_done && ctx[i].done;
  wamble_metric("stress_concurrent_movegen",
                "threads=%d iters_per_thread=%d total_iters=%d elapsed_ns=%llu "
                "iters_per_sec=%.2f",
                threads, iters_per_thread, total_iters,
                (unsigned long long)elapsed_ns, iters_per_sec);
  T_ASSERT(all_done);
  T_ASSERT(elapsed_ns < (uint64_t)5e9);
  return 0;
}
