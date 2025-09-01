#ifdef TEST_SCORING

#include "../../include/wamble/wamble.h"
#include <assert.h>
#include <math.h>

void dbstub_reset_moves(void);
void dbstub_add_move(uint64_t board_id, const uint8_t *player_token,
                     bool is_white, const char *uci);

#include "../scoring.c"

#define MAX_TEST_PLAYERS 10

static WamblePlayer test_players[MAX_TEST_PLAYERS];
static int num_test_players = 0;
static WambleBoard test_board;

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
  if (player_index < num_test_players) {
    dbstub_add_move(board_id, test_players[player_index].token, is_white_move,
                    is_white_move ? "e2e4" : "e7e5");
  }
}

static void reset_test_data() {
  dbstub_reset_moves();
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
  config_load(NULL, NULL);
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
