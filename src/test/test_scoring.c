#ifdef TEST_SCORING

#include <assert.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/wamble/wamble.h"

uint64_t db_get_session_by_token(const uint8_t *token) {
  (void)token;
  return 1;
}
int db_record_payout(uint64_t board_id, uint64_t session_id, double points) {
  (void)board_id;
  (void)session_id;
  (void)points;
  return 0;
}

#include "../scoring.c"

#define MAX_TEST_PLAYERS 10
#define MAX_TEST_MOVES 50

static WamblePlayer test_players[MAX_TEST_PLAYERS];
static int num_test_players = 0;

static WambleMove test_moves[MAX_TEST_MOVES];
static int num_test_moves = 0;

static WambleBoard test_board;

int db_get_moves_for_board(uint64_t board_id, WambleMove *moves_out,
                           int max_moves) {
  int count = 0;
  for (int i = 0; i < num_test_moves && count < max_moves; i++) {
    if (test_moves[i].board_id == board_id) {
      moves_out[count++] = test_moves[i];
    }
  }
  return count;
}

WamblePlayer *get_player_by_token(const uint8_t *token) {
  for (int i = 0; i < num_test_players; i++) {
    int tokens_match = 1;
    for (int j = 0; j < TOKEN_LENGTH; j++) {
      if (test_players[i].token[j] != token[j]) {
        tokens_match = 0;
        break;
      }
    }
    if (tokens_match) {
      return &test_players[i];
    }
  }
  return NULL;
}

WambleBoard *get_board_by_id(uint64_t board_id) {
  if (test_board.id == board_id) {
    return &test_board;
  }
  return NULL;
}

int get_moves_for_board(uint64_t board_id, WambleMove **moves) {
  static WambleMove move_buffer[1000];
  int count = 0;
  for (int i = 0; i < num_test_moves; i++) {
    if (test_moves[i].board_id == board_id && count < 1000) {
      move_buffer[count++] = test_moves[i];
    }
  }

  if (count == 0) {
    *moves = NULL;
    return 0;
  }

  *moves = move_buffer;
  return count;
}

typedef struct {
  const char *name;
  bool (*run)(void);
} TestCase;

static void setup_test_players() {
  num_test_players = 4;
  for (int i = 0; i < num_test_players; i++) {
    test_players[i].score = 0.0;

    memset(test_players[i].token, 0, TOKEN_LENGTH);
    test_players[i].token[0] = i + 1;
    test_players[i].has_persistent_identity = false;
    test_players[i].last_seen_time = 0;
    test_players[i].games_played = 0;
  }
}

static void add_move(uint64_t board_id, int player_index, bool is_white_move) {
  if (num_test_moves < MAX_TEST_MOVES && player_index < num_test_players) {
    WambleMove *move = &test_moves[num_test_moves++];
    move->board_id = board_id;
    memcpy(move->player_token, test_players[player_index].token, TOKEN_LENGTH);
    move->is_white_move = is_white_move;
    strcpy(move->uci_move, is_white_move ? "e2e4" : "e7e5");
  }
}

static void reset_test_data() {
  num_test_moves = 0;
  memset(test_moves, 0, sizeof(test_moves));
  memset(&test_board, 0, sizeof(test_board));
  setup_test_players();
}

static bool scores_are_close(double a, double b) { return fabs(a - b) < 0.001; }

static bool test_win_proportional_payout() {
  reset_test_data();
  test_board.id = 1;
  test_board.result = GAME_RESULT_WHITE_WINS;

  for (int i = 0; i < 18; i++)
    add_move(1, 0, true);
  for (int i = 0; i < 2; i++)
    add_move(1, 1, true);
  for (int i = 0; i < 20; i++)
    add_move(1, 2, false);

  calculate_and_distribute_pot(1);

  return scores_are_close(test_players[0].score, 18.0) &&
         scores_are_close(test_players[1].score, 2.0) &&
         scores_are_close(test_players[2].score, 0.0);
}

static bool test_draw_proportional_payout() {
  reset_test_data();
  test_board.id = 1;
  test_board.result = GAME_RESULT_DRAW;

  for (int i = 0; i < 10; i++)
    add_move(1, 0, true);
  for (int i = 0; i < 10; i++)
    add_move(1, 1, false);

  calculate_and_distribute_pot(1);

  return scores_are_close(test_players[0].score, 10.0) &&
         scores_are_close(test_players[1].score, 10.0);
}

static bool test_dual_side_contribution_halved_payout() {
  reset_test_data();
  test_board.id = 1;
  test_board.result = GAME_RESULT_WHITE_WINS;

  for (int i = 0; i < 10; i++)
    add_move(1, 0, true);
  for (int i = 0; i < 10; i++)
    add_move(1, 0, false);
  for (int i = 0; i < 10; i++)
    add_move(1, 1, true);

  calculate_and_distribute_pot(1);

  return scores_are_close(test_players[0].score, 5.0) &&
         scores_are_close(test_players[1].score, 10.0);
}

static bool test_no_payout_for_zero_contribution() {
  reset_test_data();
  test_board.id = 1;
  test_board.result = GAME_RESULT_WHITE_WINS;

  for (int i = 0; i < 10; i++)
    add_move(1, 0, true);
  for (int i = 0; i < 10; i++)
    add_move(1, 2, false);

  calculate_and_distribute_pot(1);

  return scores_are_close(test_players[0].score, 20.0) &&
         scores_are_close(test_players[1].score, 0.0) &&
         scores_are_close(test_players[2].score, 0.0);
}

static const TestCase cases[] = {
    {"win proportional payout", test_win_proportional_payout},
    {"draw proportional payout", test_draw_proportional_payout},
    {"dual side contribution halved payout",
     test_dual_side_contribution_halved_payout},
    {"no payout for zero contribution", test_no_payout_for_zero_contribution},
};

static int run_case(const TestCase *c) {
  if (c->run()) {
    return 1;
  }
  return 0;
}

int main(int argc, char **argv) {
  const char *filter = (argc > 1 ? argv[1] : "");
  int pass = 0, total = 0;

  for (size_t i = 0; i < (sizeof(cases) / sizeof((cases)[0])); ++i) {
    if (*filter && !strstr(cases[i].name, filter))
      continue;

    total++;
    if (run_case(&cases[i])) {
      printf("%s PASSED\n", cases[i].name);
      pass++;
    } else {
      printf("%s FAILED\n", cases[i].name);
    }
  }
  printf("%d/%d passed\n", pass, total);
  return (pass == total) ? 0 : 1;
}

#endif