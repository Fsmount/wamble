#include "common/wamble_test.h"
#include "wamble/wamble.h"
#include <math.h>

extern ScoringStatus
calculate_and_distribute_pot_for_moves(WambleBoard *board,
                                       const WambleMove *moves, int num_moves);

static int nearly_equal(double a, double b) { return fabs(a - b) < 0.001; }

static int setup_scoring_env(void) {
  char msg[128];
  (void)config_load(NULL, NULL, msg, sizeof(msg));
  player_manager_init();
  return 0;
}

WAMBLE_TEST(scoring_win_proportional_payout_logic) {
  T_ASSERT_EQ_INT(setup_scoring_env(), 0);

  WamblePlayer *pA = create_new_player();
  WamblePlayer *pB = create_new_player();
  WamblePlayer *pC = create_new_player();
  T_ASSERT(pA && pB && pC);

  WambleBoard board;
  memset(&board, 0, sizeof(board));
  board.id = 1;
  board.result = GAME_RESULT_WHITE_WINS;

  WambleMove moves[40];
  int n = 0;
  for (int i = 0; i < 18; i++) {
    memset(&moves[n], 0, sizeof(moves[n]));
    moves[n].board_id = board.id;
    memcpy(moves[n].player_token, pA->token, TOKEN_LENGTH);
    moves[n].is_white_move = true;
    n++;
  }
  for (int i = 0; i < 2; i++) {
    memset(&moves[n], 0, sizeof(moves[n]));
    moves[n].board_id = board.id;
    memcpy(moves[n].player_token, pB->token, TOKEN_LENGTH);
    moves[n].is_white_move = true;
    n++;
  }
  for (int i = 0; i < 20; i++) {
    memset(&moves[n], 0, sizeof(moves[n]));
    moves[n].board_id = board.id;
    memcpy(moves[n].player_token, pC->token, TOKEN_LENGTH);
    moves[n].is_white_move = false;
    n++;
  }

  T_ASSERT_EQ_INT(calculate_and_distribute_pot_for_moves(&board, moves, n),
                  SCORING_OK);

  T_ASSERT(nearly_equal(pA->score, 18.0));
  T_ASSERT(nearly_equal(pB->score, 2.0));
  T_ASSERT(nearly_equal(pC->score, 0.0));
  return 0;
}

WAMBLE_TEST(scoring_draw_split_payout_logic) {
  T_ASSERT_EQ_INT(setup_scoring_env(), 0);

  WamblePlayer *pA = create_new_player();
  WamblePlayer *pB = create_new_player();
  T_ASSERT(pA && pB);

  WambleBoard board;
  memset(&board, 0, sizeof(board));
  board.id = 2;
  board.result = GAME_RESULT_DRAW;

  WambleMove moves[20];
  int n = 0;
  for (int i = 0; i < 10; i++) {
    memset(&moves[n], 0, sizeof(moves[n]));
    moves[n].board_id = board.id;
    memcpy(moves[n].player_token, pA->token, TOKEN_LENGTH);
    moves[n].is_white_move = true;
    n++;
  }
  for (int i = 0; i < 10; i++) {
    memset(&moves[n], 0, sizeof(moves[n]));
    moves[n].board_id = board.id;
    memcpy(moves[n].player_token, pB->token, TOKEN_LENGTH);
    moves[n].is_white_move = false;
    n++;
  }

  T_ASSERT_EQ_INT(calculate_and_distribute_pot_for_moves(&board, moves, n),
                  SCORING_OK);

  double half_pot = get_config()->max_pot / 2.0;
  T_ASSERT(nearly_equal(pA->score, half_pot));
  T_ASSERT(nearly_equal(pB->score, half_pot));
  return 0;
}

WAMBLE_TEST(scoring_dual_side_halved_logic) {
  T_ASSERT_EQ_INT(setup_scoring_env(), 0);

  WamblePlayer *pA = create_new_player();
  WamblePlayer *pB = create_new_player();
  T_ASSERT(pA && pB);

  WambleBoard board;
  memset(&board, 0, sizeof(board));
  board.id = 3;
  board.result = GAME_RESULT_WHITE_WINS;

  WambleMove moves[30];
  int n = 0;
  for (int i = 0; i < 10; i++) {
    memset(&moves[n], 0, sizeof(moves[n]));
    moves[n].board_id = board.id;
    memcpy(moves[n].player_token, pA->token, TOKEN_LENGTH);
    moves[n].is_white_move = true;
    n++;
  }
  for (int i = 0; i < 10; i++) {
    memset(&moves[n], 0, sizeof(moves[n]));
    moves[n].board_id = board.id;
    memcpy(moves[n].player_token, pA->token, TOKEN_LENGTH);
    moves[n].is_white_move = false;
    n++;
  }
  for (int i = 0; i < 10; i++) {
    memset(&moves[n], 0, sizeof(moves[n]));
    moves[n].board_id = board.id;
    memcpy(moves[n].player_token, pB->token, TOKEN_LENGTH);
    moves[n].is_white_move = true;
    n++;
  }

  T_ASSERT_EQ_INT(calculate_and_distribute_pot_for_moves(&board, moves, n),
                  SCORING_OK);

  T_ASSERT(nearly_equal(pA->score, 5.0));
  T_ASSERT(nearly_equal(pB->score, 10.0));
  return 0;
}

WAMBLE_TESTS_BEGIN_NAMED(scoring_tests) {
  WAMBLE_TESTS_ADD_FM(scoring_win_proportional_payout_logic, "scoring");
  WAMBLE_TESTS_ADD_FM(scoring_draw_split_payout_logic, "scoring");
  WAMBLE_TESTS_ADD_FM(scoring_dual_side_halved_logic, "scoring");
}
WAMBLE_TESTS_END()
