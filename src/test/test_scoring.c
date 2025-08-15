#ifdef TEST_SCORING

#include <assert.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/wamble/wamble.h"
#include "../scoring.c"

#define MAX_TEST_PLAYERS 10
#define MAX_TEST_MOVES 50

static WamblePlayer test_players[MAX_TEST_PLAYERS];
static int num_test_players = 0;

static WambleMove test_moves[MAX_TEST_MOVES];
static int num_test_moves = 0;

static WambleBoard test_board;

WambleBoard *get_board_by_id(uint64_t board_id) {
  if (test_board.id == board_id) {
    return &test_board;
  }
  return NULL;
}

WamblePlayer *get_player_by_id(uint64_t player_id) {
  for (int i = 0; i < num_test_players; i++) {
    if (test_players[i].id == player_id) {
      return &test_players[i];
    }
  }
  return NULL;
}

int get_moves_for_board(uint64_t board_id, WambleMove **moves) {
  *moves = malloc(sizeof(WambleMove) * num_test_moves);
  int count = 0;
  for (int i = 0; i < num_test_moves; i++) {
    if (test_moves[i].board_id == board_id) {
      (*moves)[count++] = test_moves[i];
    }
  }
  return count;
}

typedef struct {
  const char *name;
  bool (*run)(void);
} TestCase;

static void setup_test_players() {
  num_test_players = 4;
  for (int i = 0; i < num_test_players; i++) {
    test_players[i].id = i + 1;
    test_players[i].score = 0.0;
  }
}

static void add_move(uint64_t board_id, uint64_t player_id,
                     bool is_white_move) {
  if (num_test_moves < MAX_TEST_MOVES) {
    WambleMove *move = &test_moves[num_test_moves++];
    move->board_id = board_id;
    move->player_id = player_id;
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
    add_move(1, 1, true);
  for (int i = 0; i < 2; i++)
    add_move(1, 2, true);
  for (int i = 0; i < 20; i++)
    add_move(1, 3, false);

  calculate_and_distribute_pot(1);

  return scores_are_close(get_player_by_id(1)->score, 18.0) &&
         scores_are_close(get_player_by_id(2)->score, 2.0) &&
         scores_are_close(get_player_by_id(3)->score, 0.0);
}

static bool test_draw_proportional_payout() {
  reset_test_data();
  test_board.id = 1;
  test_board.result = GAME_RESULT_DRAW;

  for (int i = 0; i < 10; i++)
    add_move(1, 1, true);
  for (int i = 0; i < 10; i++)
    add_move(1, 2, false);

  calculate_and_distribute_pot(1);

  return scores_are_close(get_player_by_id(1)->score, 10.0) &&
         scores_are_close(get_player_by_id(2)->score, 10.0);
}

static bool test_dual_side_contribution_halved_payout() {
  reset_test_data();
  test_board.id = 1;
  test_board.result = GAME_RESULT_WHITE_WINS;

  for (int i = 0; i < 10; i++)
    add_move(1, 1, true);
  for (int i = 0; i < 10; i++)
    add_move(1, 1, false);
  for (int i = 0; i < 10; i++)
    add_move(1, 2, true);

  calculate_and_distribute_pot(1);

  return scores_are_close(get_player_by_id(1)->score, 5.0) &&
         scores_are_close(get_player_by_id(2)->score, 10.0);
}

static bool test_no_payout_for_zero_contribution() {
  reset_test_data();
  test_board.id = 1;
  test_board.result = GAME_RESULT_WHITE_WINS;

  for (int i = 0; i < 10; i++)
    add_move(1, 1, true);
  for (int i = 0; i < 10; i++)
    add_move(1, 3, false);

  calculate_and_distribute_pot(1);

  return scores_are_close(get_player_by_id(1)->score, 20.0) &&
         scores_are_close(get_player_by_id(2)->score, 0.0) &&
         scores_are_close(get_player_by_id(3)->score, 0.0);
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